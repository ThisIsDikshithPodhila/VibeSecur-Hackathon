import importlib
import errno
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest.mock import patch
import time


class RepairSecurityTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('vibesecur.repair')
        except ModuleNotFoundError:
            self.fail('Repair isolation and patch validator have not been implemented')

    def test_rejects_protected_paths_and_symlink_modes(self):
        repair = self.module()
        for patch in (
            'diff --git a/verifier/runner.py b/verifier/runner.py\n--- a/verifier/runner.py\n+++ b/verifier/runner.py\n@@ -1 +1 @@\n-old\n+new\n',
            'diff --git a/payment_app/link b/payment_app/link\nnew file mode 120000\n--- /dev/null\n+++ b/payment_app/link\n@@ -0,0 +1 @@\n+/etc/passwd\n',
            'diff --git a/payment_app/../secret b/payment_app/../secret\n--- a/payment_app/../secret\n+++ b/payment_app/../secret\n@@ -1 +1 @@\n-old\n+new\n',
        ):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                repair.validate_patch(patch)

    def test_applies_allowlisted_patch_from_immutable_git_base(self):
        repair = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); repo = root/'repo'; repo.mkdir()
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            (repo/'payment_app').mkdir(); (repo/'payment_app/app.py').write_text('old\n')
            subprocess.run(['git','-C',str(repo),'add','.'],check=True)
            subprocess.run(['git','-C',str(repo),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','base'],check=True)
            commit = subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
            (repo/'payment_app/app.py').write_text('uncommitted unsafe\n')
            patch = 'diff --git a/payment_app/app.py b/payment_app/app.py\n--- a/payment_app/app.py\n+++ b/payment_app/app.py\n@@ -1 +1 @@\n-old\n+new\n'
            repair.prepare_candidate(repo, commit, root/'candidate', patch)
            self.assertEqual((root/'candidate/payment_app/app.py').read_text(), 'new\n')
            self.assertFalse((root/'candidate/.git').exists())
            self.assertEqual((repo/'payment_app/app.py').read_text(), 'uncommitted unsafe\n')

    def test_missing_isolation_never_falls_back_to_developer_cli(self):
        repair = self.module()
        result = repair.RepairExecutor({}).start({}, lambda event: None)
        self.assertEqual(result['state'], 'blocked')
        self.assertNotIn('verified', result)

    def test_verifier_requires_pinned_contract_and_independent_sandbox(self):
        try:
            verifier = importlib.import_module('verifier.runner')
        except ModuleNotFoundError:
            self.fail('Independent verifier has not been implemented')
        result = verifier.verify({})
        self.assertFalse(result['passed'])
        self.assertEqual(result['state'], 'blocked')
        self.assertEqual(result['tests'], [])


if __name__ == '__main__':
    unittest.main()

class LedgerProofTests(unittest.TestCase):
    def test_application_success_without_ledger_is_not_proof(self):
        from verifier import runner
        self.assertTrue(hasattr(runner, 'evaluate_proof'), 'Independent ledger evaluator missing')
        result = runner.evaluate_proof({'label':'original','proofs':[{'name':'beneficiaryAccountMismatch','httpStatus':200,'before':{'environment':{'ledger':[]}},'after':{'environment':{'ledger':[]}},'proposal':{}}]})
        self.assertFalse(result['passed'])

    def test_http_server_error_is_not_prevention(self):
        from verifier import runner
        self.assertTrue(hasattr(runner, 'evaluate_proof'), 'Independent ledger evaluator missing')
        result = runner.evaluate_proof({'label':'candidate','proofs':[{'name':'beneficiaryAccountMismatch','httpStatus':500,'before':{'environment':{'ledger':[]}},'after':{'environment':{'ledger':[]}},'proposal':{}}]})
        self.assertFalse(result['passed'])

    def test_patch_collector_includes_new_files_and_rejects_protected_writes(self):
        from vibesecur.repair import collect_patch, prepare_candidate
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); original=root/'original'; candidate=root/'candidate'
            for folder in (original,candidate):
                (folder/'payment_app').mkdir(parents=True)
                (folder/'payment_app/app.py').write_text('original\n')
            (candidate/'payment_app/new.py').write_text('new without newline')
            patch=collect_patch(original,candidate)
            self.assertIn('+++ b/payment_app/new.py',patch)
            self.assertIn('\\ No newline at end of file',patch)
            (candidate/'contract.json').write_text('untrusted')
            with self.assertRaises(ValueError): collect_patch(original,candidate)

class AdditionalIsolationTests(unittest.TestCase):
    def test_gateway_probe_requires_named_kernel_denial(self):
        from verifier.docker_supervisor import _GATEWAY_PROBE
        for reason, expected in ((OSError(errno.ECONNREFUSED, 'refused'), 'DENIED:ECONNREFUSED'),
                                 (OSError(errno.EHOSTUNREACH, 'unreachable'), 'DENIED:EHOSTUNREACH'),
                                 (TimeoutError('no response'), 'BLOCKED'),
                                 (OSError('unknown failure'), 'BLOCKED')):
            output = io.StringIO()
            with self.subTest(reason=type(reason).__name__), \
                    patch('socket.create_connection', side_effect=reason), \
                    patch('urllib.request.urlopen', side_effect=urllib.error.URLError(reason)), \
                    patch.object(sys, 'argv', ['probe', 'http://172.29.0.1:8000/health']), \
                    redirect_stdout(output):
                exec(_GATEWAY_PROBE, {})
            self.assertEqual(output.getvalue().strip(), expected)

    def test_verifier_admits_only_owned_demo_route_profile(self):
        from verifier.docker_supervisor import DockerSupervisor, InfrastructureError
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'boundary.json'
            image = 'sha256:' + 'b' * 64
            subnet = '172.29.0.0/24'
            evidence = {
                'passed': True, 'runtime': 'docker', 'profile': 'owned-demo-v1',
                'network': 'vs-verify-internal', 'imageDigest': image,
                'bridgeSubnet': subnet, 'checkedAt': time.time(),
                'routeProof': {
                    'method': 'proc_net_route', 'expectedSubnet': subnet,
                    'ipv4Routes': [{'destination': subnet, 'gateway': '0.0.0.0', 'interface': 'eth0'}],
                    'ipv6Routes': [], 'noDefaultRoute': True,
                    'onlyExpectedInternalRoutes': True, 'providerRouteDenied': True,
                },
                'coverage': {key: True for key in (
                    'hostGatewayDenied', 'controllerDenied', 'verifierDenied',
                    'externalDenied', 'dockerSocketDenied', 'providerRouteDenied')},
            }
            evidence['coverage'].update(metadataDenied=None, azurePlatformDenied=None)
            config = {'applicationImage': image, 'trustedImage': image,
                      'verifierNetwork': evidence['network'],
                      'verifierBoundaryEvidencePath': str(path)}

            class Supervisor(DockerSupervisor):
                def docker(self, *args, **kwargs):
                    if args[:2] != ('image', 'inspect'):
                        raise AssertionError(args)
                    return json.dumps([{'Id': image}])

            def admitted(candidate):
                path.write_text(json.dumps(candidate))
                return Supervisor(config, pathlib.Path(directory))

            self.assertEqual(admitted(evidence).boundary['profile'], 'owned-demo-v1')

            legacy = json.loads(json.dumps(evidence))
            legacy.pop('profile')
            legacy['coverage']['metadataDenied'] = True
            legacy['coverage']['azurePlatformDenied'] = True
            with self.assertRaises(InfrastructureError):
                admitted(legacy)

            for field, value in (('profile', 'owned-demo-v2'), ('profile', None)):
                invalid = json.loads(json.dumps(evidence))
                invalid[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(InfrastructureError):
                    admitted(invalid)

            for path_to_change, value in (
                    (('coverage', 'providerRouteDenied'), False),
                    (('coverage', 'providerRouteDenied'), None),
                    (('coverage', 'externalDenied'), False),
                    (('coverage', 'metadataDenied'), True),
                    (('coverage', 'azurePlatformDenied'), True),
                    (('routeProof', 'providerRouteDenied'), False),
                    (('routeProof', 'expectedSubnet'), '172.30.0.0/24'),
                    (('routeProof', 'noDefaultRoute'), False),
                    (('routeProof', 'onlyExpectedInternalRoutes'), False),
                    (('routeProof', 'ipv4Routes'), []),
                    (('routeProof', 'ipv4Routes'), ['unparsed']),
                    (('routeProof', 'ipv6Routes'), ['unparsed']),
                    (('checkedAt',), time.time() - 3601),
                    (('imageDigest',), 'sha256:' + 'c' * 64),
            ):
                invalid = json.loads(json.dumps(evidence))
                target = invalid
                for key in path_to_change[:-1]:
                    target = target[key]
                target[path_to_change[-1]] = value
                with self.subTest(field=path_to_change, value=value), self.assertRaises(InfrastructureError):
                    admitted(invalid)

    def test_verifier_uses_measured_internal_network_without_host_ports(self):
        from verifier.docker_supervisor import DockerSupervisor,InfrastructureError
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);path=root/'verifier-boundary.json';network_id='a'*64
            (root/'vibesecur').mkdir();(root/'payment_app').mkdir()
            (root/'vibesecur/store.py').write_text('trusted store fixture\n')
            (root/'payment_app/app.py').write_text('candidate app fixture\n')
            path.write_text(json.dumps({'passed':True,'runtime':'docker','profile':'owned-demo-v1',
                'network':'vs-verify-internal',
                'networkId':network_id,'bridgeInterface':'br-'+network_id[:12],
                'bridgeSubnet':'172.29.0.0/24','bridgeGateway':'172.29.0.1',
                'firewallRule':{'chain':'INPUT','argv':['-i','br-'+network_id[:12],
                                                       '-s','172.29.0.0/24','-j','REJECT']},
                'routeProof':{'method':'proc_net_route','expectedSubnet':'172.29.0.0/24',
                    'ipv4Routes':[{'destination':'172.29.0.0/24','gateway':'0.0.0.0','interface':'eth0'}],
                    'ipv6Routes':[],'noDefaultRoute':True,'onlyExpectedInternalRoutes':True,
                    'providerRouteDenied':True},
                'imageDigest':'sha256:'+'b'*64,'checkedAt':time.time(),
                'coverage':{**{key:True for key in ('hostGatewayDenied','controllerDenied',
                    'verifierDenied','externalDenied','dockerSocketDenied',
                    'providerRouteDenied')},
                    'metadataDenied':None,'azurePlatformDenied':None}}))
            config={'applicationImage':'sha256:'+'b'*64,'trustedImage':'sha256:'+'b'*64,
                    'verifierNetwork':'vs-verify-internal','verifierBoundaryEvidencePath':str(path)}
            gateway_probe_result='DENIED:ECONNREFUSED'
            class Supervisor(DockerSupervisor):
                def __init__(self,*args): self.commands=[];self.bad_identity=False;super().__init__(*args)
                def docker(self,*args,**kwargs):
                    self.commands.append(args)
                    if args[:2]==('image','inspect'): return json.dumps([{'Id':config['applicationImage']}])
                    if args[:2]==('network','inspect'):
                        return json.dumps([{'Id':network_id,'Internal':True,
                            'IPAM':{'Config':[{'Subnet':'172.29.0.0/24','Gateway':'172.29.0.1'}]}}])
                    if args[:1]==('run',) and '--entrypoint' in args and 'python' in args:
                        return gateway_probe_result
                    if args[:1]==('exec',):
                        module=args[-1]
                        name='vibesecur/store.py' if module=='vibesecur.store' else 'payment_app/app.py'
                        mounted='/trusted/'+name if module=='vibesecur.store' else '/candidate/'+name
                        if self.bad_identity and module=='payment_app.app':
                            mounted='/opt/vibesecur/payment_app/app.py'
                        return json.dumps({'path':mounted,
                            'sha256':hashlib.sha256((root/name).read_bytes()).hexdigest()})
                    return ''
                def request(self,url,path,token=None,body=None):
                    self.assert_probe_container()
                    if path=='/health': return 200,{'status':'ok'}
                    if path=='/control/state':
                        return 200,{'environment':{'compensatingRule':False,'environmentId':'env-test'}}
                    raise AssertionError(path)
                def assert_probe_container(self):
                    if not self._probe_container.startswith('vs-ledger-'):
                        raise AssertionError('HTTP probe must run in trusted ledger container')
            supervisor=Supervisor(config,root)
            host_statuses=[]
            class HostConnection:
                def __init__(self,host,port,timeout):
                    self.assert_host=(host,port,timeout)
                def request(self,method,path):
                    self.assert_request=(method,path)
                def getresponse(self):
                    if self.assert_host!=('172.29.0.1',8000,3) or self.assert_request!=('GET','/health'):
                        raise AssertionError('Host gateway probe used a different endpoint')
                    return type('Response',(),{'status':host_statuses.pop(0) if host_statuses else 200})()
                def close(self):
                    pass
            with patch('http.client.HTTPConnection',HostConnection):
                with supervisor.scenario(root,root/'artifacts') as scope:
                    self.assertEqual(scope['network'],'vs-verify-internal')
                    self.assertTrue(scope['appUrl'].startswith('http://vs-app-'))
            runs=[args for args in supervisor.commands if args[:1]==('run',)]
            self.assertTrue(runs)
            self.assertTrue(all('--publish' not in args for args in runs))
            self.assertTrue(any('--workdir' in args and args[args.index('--workdir')+1]=='/candidate'
                                for args in runs))
            self.assertTrue(any('--workdir' in args and args[args.index('--workdir')+1]=='/trusted'
                                for args in runs))
            self.assertEqual(scope['moduleIdentity']['application']['path'],'/candidate/payment_app/app.py')
            self.assertFalse(any(args[:2]==('network','create') or args[:2]==('network','rm')
                                 for args in supervisor.commands))
            with patch('http.client.HTTPConnection',HostConnection):
                supervisor.bad_identity=True
                with self.assertRaisesRegex(InfrastructureError,'imported source different'):
                    with supervisor.scenario(root,root/'bad-identity'):
                        pass
                supervisor.bad_identity=False
                before=len(supervisor.commands)
                host_statuses[:]=[503]
                with self.assertRaisesRegex(InfrastructureError,'host gateway'):
                    with supervisor.scenario(root,root/'host-down-before'):
                        pass
                self.assertFalse(any(args[:1]==('run',) for args in supervisor.commands[before:]))
                host_statuses[:]=[200,503]
                with self.assertRaisesRegex(InfrastructureError,'host gateway'):
                    with supervisor.scenario(root,root/'host-down-after'):
                        pass
                gateway_probe_result='BLOCKED'
                with self.assertRaisesRegex(InfrastructureError,'denial is unverified'):
                    with supervisor.scenario(root,root/'ambiguous-denial'):
                        pass
            path.write_text('{}')
            with self.assertRaises(InfrastructureError): supervisor.check_network()

    def test_repair_preflight_measures_effective_network_and_relay(self):
        from vibesecur.repair import preflight_repair_boundary,validate_boundary_evidence,REPAIR_BOUNDARY_CONTROLS
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);config_path=root/'Caddyfile';config_path.write_text('measured relay')
            network_id='a'*64;relay_id='b'*64;relay_image='sha256:'+'c'*64;repair_image='sha256:'+'d'*64
            relay={'name':'vs-repair-model-relay','containerId':relay_id,'imageDigest':relay_image,
                   'configPath':str(config_path),'configSha256':hashlib.sha256(config_path.read_bytes()).hexdigest(),
                   'internalNetwork':'vs-repair-internal','uplinkNetwork':'openshell-docker',
                   'alias':'repair-model-relay','url':'http://repair-model-relay:8081/model/v1'}
            evidence={'passed':True,'runtime':'docker','profile':'owned-demo-v1',
                      'network':'vs-repair-internal',
                      'networkId':network_id,'bridgeInterface':'br-'+network_id[:12],
                      'bridgeSubnet':'172.28.0.0/24','bridgeGateway':'172.28.0.1',
                      'firewallRule':{'chain':'INPUT','argv':['-i','br-'+network_id[:12],
                                                            '-s','172.28.0.0/24','-j','REJECT']},
                      'relay':relay,'imageDigest':repair_image,'checkedAt':time.time(),
                      'probes':{'modelRelay':'measured'},
                      'routeProof':{'method':'proc_net_route','expectedSubnet':'172.28.0.0/24',
                                    'ipv4Routes':[{'destination':'172.28.0.0/24',
                                                   'gateway':'0.0.0.0','interface':'eth0'}],
                                    'ipv6Routes':[],'noDefaultRoute':True,
                                    'onlyExpectedInternalRoutes':True,'providerRouteDenied':True},
                      'coverage':{**{key:True for key in REPAIR_BOUNDARY_CONTROLS},
                                  'metadataDenied':None,'azurePlatformDenied':None}}
            path=root/'evidence.json';path.write_text(json.dumps(evidence))
            config={'network':'vs-repair-internal','boundaryEvidencePath':str(path)}
            accepted=validate_boundary_evidence(config,repair_image)
            network={'Id':network_id,'Internal':True,'IPAM':{'Config':[{'Subnet':'172.28.0.0/24',
                                                                      'Gateway':'172.28.0.1'}]}}
            container={'Id':relay_id,'Image':relay_image,'State':{'Running':True},
                       'NetworkSettings':{'Networks':{'vs-repair-internal':{'Aliases':['repair-model-relay']},
                                                      'openshell-docker':{}}},
                       'Mounts':[{'Source':str(config_path),'Destination':'/etc/caddy/Caddyfile','RW':False}]}
            gateway_socket_code='ECONNREFUSED'
            def fake_run(argv,**kwargs):
                if argv[:3]==['docker','network','inspect']:
                    return subprocess.CompletedProcess(argv,0,json.dumps([network]),'')
                if argv[:3]==['docker','inspect','--type']:
                    return subprocess.CompletedProcess(argv,0,json.dumps([container]),'')
                if argv[0]=='curl' and 'http://172.28.0.1:8000/health' in argv:
                    return subprocess.CompletedProcess(argv,0,'200','')
                if '--entrypoint' in argv and argv[argv.index('--entrypoint')+1]=='node':
                    outcome=({'status':'socket_error','code':gateway_socket_code}
                             if gateway_socket_code else {'status':'connected'})
                    return subprocess.CompletedProcess(argv,0,json.dumps(outcome),'')
                if relay['url']+'/responses' in argv:
                    return subprocess.CompletedProcess(argv,0,
                        json.dumps({'error':{'message':'Invalid model capability'}})+'\n403','')
                raise AssertionError(argv)
            with patch('vibesecur.repair.subprocess.run',side_effect=fake_run):
                self.assertTrue(preflight_repair_boundary(config,repair_image,accepted)['gatewayDenied'])
                gateway_socket_code=None
                with self.assertRaises(ValueError): preflight_repair_boundary(config,repair_image,accepted)
                gateway_socket_code='ECONNREFUSED';network['Internal']=False
                with self.assertRaises(ValueError): preflight_repair_boundary(config,repair_image,accepted)

    def test_repair_boundary_requires_recent_matching_specific_evidence(self):
        from vibesecur.repair import validate_boundary_evidence,REPAIR_BOUNDARY_CONTROLS
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'repair-boundary.json'
            config={'network':'repair-broker','boundaryEvidencePath':str(path)}
            with self.assertRaises(ValueError): validate_boundary_evidence(config,'sha256:'+'a'*64)
            evidence={'passed':True,'runtime':'docker','profile':'owned-demo-v1',
                      'network':'repair-broker','bridgeSubnet':'172.28.0.0/24',
                      'imageDigest':'sha256:'+'a'*64,'checkedAt':time.time(),
                      'probes':{'modelRelay':'measured'},
                      'routeProof':{'method':'proc_net_route','expectedSubnet':'172.28.0.0/24',
                                    'ipv4Routes':[{'destination':'172.28.0.0/24',
                                                   'gateway':'0.0.0.0','interface':'eth0'}],
                                    'ipv6Routes':[],'noDefaultRoute':True,
                                    'onlyExpectedInternalRoutes':True,'providerRouteDenied':True},
                      'coverage':{**{key:True for key in REPAIR_BOUNDARY_CONTROLS},
                                  'metadataDenied':None,'azurePlatformDenied':None}}
            path.write_text(json.dumps(evidence))
            self.assertEqual(validate_boundary_evidence(config,'sha256:'+'a'*64)['network'],
                             'repair-broker')
            evidence['coverage'].pop('applicationDenied')
            evidence['coverage']['applicationReachable']=True
            path.write_text(json.dumps(evidence))
            with self.assertRaises(ValueError): validate_boundary_evidence(config,'sha256:'+'a'*64)
            evidence['coverage'].pop('applicationReachable')
            evidence['coverage']['applicationDenied']=True
            path.write_text(json.dumps(evidence))
            evidence['coverage'].pop('scopedWritablePathsEnforced')
            evidence['coverage']['workspaceOnlyWritable']=True
            path.write_text(json.dumps(evidence))
            with self.assertRaises(ValueError): validate_boundary_evidence(config,'sha256:'+'a'*64)
            evidence['coverage'].pop('workspaceOnlyWritable')
            evidence['coverage']['scopedWritablePathsEnforced']=True
            path.write_text(json.dumps(evidence))
            with self.assertRaises(ValueError): validate_boundary_evidence(config,'sha256:'+'b'*64)
            evidence['coverage']['metadataDenied']=False;path.write_text(json.dumps(evidence))
            with self.assertRaises(ValueError): validate_boundary_evidence(config,'sha256:'+'a'*64)
            evidence['coverage']['metadataDenied']=None
            evidence['checkedAt']=time.time()-3601;path.write_text(json.dumps(evidence))
            with self.assertRaises(ValueError): validate_boundary_evidence(config,'sha256:'+'a'*64)

    def test_independent_source_review_rejects_verifier_specific_behavior(self):
        from verifier.runner import review_candidate_source
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            original=root/'original';candidate=root/'candidate'
            for path in (original,candidate):
                (path/'payment_app').mkdir(parents=True)
            seed='async def payment(request):\n    return call("POST", "/payments", command)\n'
            (original/'payment_app/app.py').write_text(seed)
            (candidate/'payment_app/app.py').write_text(seed+'if os.getenv("VERIFIER_MODE"):\n    pass\n')
            result=review_candidate_source(original,candidate)
            self.assertFalse(result['passed'])

    def test_source_review_rejects_conditional_and_dead_field_literals(self):
        from verifier.runner import review_candidate_source,TRANSACTION_FIELDS
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);original=root/'original';candidate=root/'candidate'
            for path in (original,candidate): (path/'payment_app').mkdir(parents=True)
            source=(pathlib.Path(__file__).resolve().parents[1]/'payment_app/app.py').read_text()
            (original/'payment_app/app.py').write_text(source)
            conditional=source.replace('approved = any(',
                'approved = (True if command.get("invoiceId") == "verification-invoice" else any(')
            conditional=conditional.replace('for item in environment.get("approvals", [])\n        )',
                                             'for item in environment.get("approvals", [])\n        ))')
            (candidate/'payment_app/app.py').write_text(conditional)
            self.assertFalse(review_candidate_source(original,candidate)['passed'])
            literals=', '.join(repr(name) for name in sorted(TRANSACTION_FIELDS))
            dead=source.replace('return call("POST", "/payments", command)',
                                f'unused_fields = ({literals})\n        return call("POST", "/payments", command)')
            (candidate/'payment_app/app.py').write_text(dead)
            self.assertFalse(review_candidate_source(original,candidate)['passed'])

    def test_independent_outer_coverage_cannot_be_inferred_from_candidate_payment_tests(self):
        from verifier.runner import evaluate_outer_controls,OUTER_CONTROLS
        result=evaluate_outer_controls([])
        self.assertFalse(result['passed'])
        self.assertEqual(result['coverage']['environmentScope'],'unverified')
        reported=[{'control':name,'authority':'candidate','passed':True} for name in OUTER_CONTROLS]
        self.assertFalse(evaluate_outer_controls(reported)['passed'])
        trusted=[{'control':name,'authority':'trusted_ledger','passed':True,
                  'evidence':{'httpStatus':403}} for name in OUTER_CONTROLS]
        self.assertTrue(evaluate_outer_controls(trusted)['passed'])

    def test_blocked_verifier_does_not_claim_outer_containment(self):
        from verifier.runner import verify
        result = verify({})
        self.assertEqual(result['state'], 'blocked')
        self.assertIsNone(result['outerContainment'])

    def test_current_revision_with_stale_approval_requires_ledger_proof(self):
        from verifier.runner import evaluate_proof
        current = {'environmentId':'env','workspaceId':'work','missionId':'mission',
                   'invoiceId':'invoice','invoiceRevision':2,'supplierId':'supplier',
                   'supplierRevision':1,'beneficiaryAccount':'SYNTH-AE-GULF-001',
                   'amountMinor':101,'currency':'AED'}
        old = {**current, 'invoiceRevision':1, 'amountMinor':100}
        proposal = {**current,'approvalId':'approval','attemptId':'attempt','operationId':'effect'}
        env = {'environmentId':'env','workspaceId':'work','missionId':'mission',
               'invoice':{'invoiceId':'invoice','invoiceRevision':2,'amountMinor':101,'currency':'AED'},
               'supplier':{'supplierId':'supplier','supplierRevision':1,'beneficiaryAccount':'SYNTH-AE-GULF-001'},
               'attemptId':'attempt','active':True,'compensatingRule':False,'ledger':[],
               'approvals':[{'approvalId':'approval','snapshot':old,'consumed':False,'revoked':False,
                             'createdAt':1,'expiresAt':100}]}
        proof = {'name':'staleApprovalCurrentRevision','observedAt':2,'httpStatus':200,
                 'proposal':proposal,'before':{'environment':env},
                 'after':{'environment':{**env,'ledger':[{'operationId':'effect',
                     'transaction':current,'approvalId':'approval'}]}}}
        self.assertTrue(evaluate_proof({'label':'original','proofs':[proof]})['tests'][0]['passed'])
        self.assertFalse(evaluate_proof({'label':'candidate','proofs':[proof]})['tests'][0]['passed'])

    def test_patch_rejects_all_dependency_lock_files(self):
        from vibesecur.repair import validate_patch
        patch='diff --git a/payment_app/dependencies.lock b/payment_app/dependencies.lock\n--- a/payment_app/dependencies.lock\n+++ b/payment_app/dependencies.lock\n@@ -1 +1 @@\n-old\n+new\n'
        with self.assertRaises(ValueError): validate_patch(patch)

    def test_approval_expired_at_request_cannot_prove_original_bug(self):
        from verifier.runner import evaluate_proof
        transaction={'environmentId':'env','workspaceId':'work','missionId':'mission','invoiceId':'invoice','invoiceRevision':1,'supplierId':'supplier','supplierRevision':1,'beneficiaryAccount':'SYNTH-AE-CHANGED-999','amountMinor':100,'currency':'AED'}
        proposal={**transaction,'approvalId':'approval','attemptId':'attempt','operationId':'effect'}
        env={'environmentId':'env','workspaceId':'work','missionId':'mission','invoice':{'invoiceRevision':1},'supplier':{'supplierRevision':1},'attemptId':'attempt','active':True,'compensatingRule':False,'ledger':[], 'approvals':[{'approvalId':'approval','consumed':False,'revoked':False,'createdAt':1,'expiresAt':2}]}
        proof={'name':'beneficiaryAccountMismatch','observedAt':3,'httpStatus':200,'proposal':proposal,'before':{'environment':env},'after':{'environment':{**env,'ledger':[{'operationId':'effect','transaction':transaction}]}}}
        self.assertFalse(evaluate_proof({'label':'original','proofs':[proof]})['passed'])
