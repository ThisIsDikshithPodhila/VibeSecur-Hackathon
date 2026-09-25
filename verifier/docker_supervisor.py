"""Fixed trusted supervisor for real, separately isolated payment processes."""
from __future__ import annotations
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import uuid
from vibesecur.repair import docker_env


class InfrastructureError(RuntimeError):
    pass


_HTTP_CLIENT = '''import json,sys,urllib.request,urllib.error
p=json.loads(sys.stdin.read())
h={'Content-Type':'application/json'}
if p['token']: h['Authorization']='Bearer '+p['token']
r=urllib.request.Request(p['url']+p['path'],data=None if p['body'] is None else json.dumps(p['body']).encode(),headers=h)
try:
    with urllib.request.urlopen(r,timeout=12) as response:
        raw=response.read(1000001); status=response.status
except urllib.error.HTTPError as error:
    raw=error.read(1000001); status=error.code
except urllib.error.URLError as error:
    print(json.dumps({'transportError':type(error.reason).__name__}));sys.exit(0)
if len(raw)>1000000: sys.exit(3)
try: body=json.loads(raw)
except ValueError: body={'text':raw.decode(errors='replace')[:2000]}
print(json.dumps({'status':status,'body':body},separators=(',',':')))
'''

_GATEWAY_PROBE = '''import errno,ipaddress,socket,sys,urllib.parse
try:
    target=urllib.parse.urlsplit(sys.argv[1])
    ipaddress.IPv4Address(target.hostname)
    if target.scheme!='http' or target.port!=8000 or target.path!='/health' or target.query or target.fragment:
        raise ValueError('unexpected gateway target')
    with socket.create_connection((target.hostname,target.port),timeout=3):
        pass
except OSError as error:
    code=errno.errorcode.get(error.errno)
    print('DENIED:'+code if code in ('ECONNREFUSED','EHOSTUNREACH','ENETUNREACH') else 'BLOCKED')
except ValueError:
    print('BLOCKED')
else:
    print('REACHABLE')
'''

_MODULE_IDENTITY = '''import hashlib,importlib,json,sys
module=importlib.import_module(sys.argv[1])
path=module.__file__
with open(path,'rb') as source: digest=hashlib.sha256(source.read()).hexdigest()
print(json.dumps({'path':path,'sha256':digest},separators=(',',':')))
'''


class DockerSupervisor:
    def __init__(self, config, trusted_base):
        self.config = config
        self.cancel_event=config.get('cancelEvent')
        self.trusted_base = Path(trusted_base)
        self.env = docker_env(config)
        self.image = config.get('applicationImage')
        self.trusted_image = config.get('trustedImage', self.image)
        if not self.image or not self.trusted_image:
            raise InfrastructureError('Independent application/trusted service images required')
        self.network=config.get('verifierNetwork')
        boundary_path=config.get('verifierBoundaryEvidencePath')
        try:
            raw=Path(boundary_path).read_bytes() if boundary_path else b''
            self.boundary=json.loads(raw)
        except (OSError,ValueError,TypeError) as exc:
            raise InfrastructureError('Measured verifier network evidence required') from exc
        coverage = self.boundary.get('coverage') if isinstance(self.boundary,dict) else None
        route_proof = self.boundary.get('routeProof') if isinstance(self.boundary,dict) else None
        if (not self.network or not isinstance(self.boundary,dict) or
                self.boundary.get('passed') is not True or
                self.boundary.get('runtime')!='docker' or
                self.boundary.get('profile')!='owned-demo-v1' or
                self.boundary.get('network')!=self.network or
                not isinstance(self.boundary.get('checkedAt'),(int,float)) or
                not 0<=time.time()-self.boundary['checkedAt']<=3600 or
                not isinstance(coverage,dict) or
                not all(coverage.get(key) is True for key in (
                    'hostGatewayDenied','controllerDenied','verifierDenied',
                    'externalDenied','dockerSocketDenied','providerRouteDenied')) or
                coverage.get('metadataDenied','missing') is not None or
                coverage.get('azurePlatformDenied','missing') is not None or
                not isinstance(route_proof,dict) or
                route_proof.get('method')!='proc_net_route' or
                not isinstance(self.boundary.get('bridgeSubnet'),str) or
                not self.boundary['bridgeSubnet'] or
                route_proof.get('expectedSubnet')!=self.boundary.get('bridgeSubnet') or
                not isinstance(route_proof.get('ipv4Routes'),list) or
                not route_proof['ipv4Routes'] or
                any(not isinstance(route,dict) for route in route_proof['ipv4Routes']) or
                not isinstance(route_proof.get('ipv6Routes'),list) or
                any(not isinstance(route,dict) for route in route_proof['ipv6Routes']) or
                route_proof.get('noDefaultRoute') is not True or
                route_proof.get('onlyExpectedInternalRoutes') is not True or
                route_proof.get('providerRouteDenied') is not True):
            raise InfrastructureError('Measured verifier internal network is unavailable or stale')
        self.boundary_digest=hashlib.sha256(raw).hexdigest()
        self.boundary_path=Path(boundary_path)
        self._probe_container=None
        self.image_ids = {}
        for image in (self.image, self.trusted_image):
            info = json.loads(self.docker('image','inspect',image))[0]
            self.image_ids[image] = info['Id']
        if any(image_id!=self.boundary.get('imageDigest') for image_id in self.image_ids.values()):
            raise InfrastructureError('Verifier images differ from measured boundary image')

    def docker(self, *args, timeout=45):
        try:
            return subprocess.run(['docker', *args], env=self.env, check=True, capture_output=True, text=True, timeout=timeout).stdout.strip()
        except (OSError,subprocess.SubprocessError) as exc:
            detail = getattr(exc,'stderr','') or str(exc)
            raise InfrastructureError('Docker supervisor: '+detail[:1000]) from exc

    def request(self, url, path, token=None, body=None):
        self.check_cancel()
        if not self._probe_container:
            raise InfrastructureError('Trusted ledger probe container is unavailable')
        payload={'url':url,'path':path,'token':token,'body':body}
        try:
            process=subprocess.run(['docker','exec','-i',self._probe_container,'python','-c',_HTTP_CLIENT],
                                   input=json.dumps(payload),env=self.env,capture_output=True,
                                   text=True,timeout=20,check=True)
            if len(process.stdout)>1_000_000:
                raise InfrastructureError('Verifier service response exceeds budget')
            result=json.loads(process.stdout)
            if 'transportError' in result:
                raise InfrastructureError('Independent service transport unavailable: '+result['transportError'])
            return result['status'],result['body']
        except (OSError,subprocess.SubprocessError,ValueError,KeyError) as exc:
            raise InfrastructureError('Trusted Docker-exec HTTP probe failed: '+str(exc)[:500]) from exc

    def check_network(self):
        self.check_cancel()
        if hashlib.sha256(self.boundary_path.read_bytes()).hexdigest()!=self.boundary_digest:
            raise InfrastructureError('Verifier boundary artifact changed')
        if not 0<=time.time()-self.boundary['checkedAt']<=3600:
            raise InfrastructureError('Verifier boundary evidence expired')
        network=json.loads(self.docker('network','inspect',self.network))[0]
        expected=self.boundary
        if expected.get('firewallRule')!={'chain':'INPUT','argv':[
                '-i',expected.get('bridgeInterface'),'-s',expected.get('bridgeSubnet'),'-j','REJECT']}:
            raise InfrastructureError('Verifier bridge firewall specification changed')
        ipam=(network.get('IPAM') or {}).get('Config') or []
        if (network.get('Id')!=expected.get('networkId') or network.get('Internal') is not True or
                not any(row.get('Subnet')==expected.get('bridgeSubnet') and
                        row.get('Gateway')==expected.get('bridgeGateway') for row in ipam) or
                expected.get('bridgeInterface')!='br-'+network['Id'][:12]):
            raise InfrastructureError('Verifier network differs from measured internal bridge')
        gateway=expected.get('bridgeGateway')
        try:
            ipaddress.IPv4Address(gateway)
        except (ValueError,TypeError) as exc:
            raise InfrastructureError('Verifier bridge gateway is not a measured IPv4 address') from exc
        self.host_gateway_healthy(gateway)
        try:
            probe=self.docker('run','--rm','--pull','never','--network',self.network,
                              '--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
                              '--pids-limit','32','--memory','128m','--cpus','0.25',
                              '--user','65532:65532','--entrypoint','python',
                              self.image_ids[self.trusted_image],'-c',_GATEWAY_PROBE,
                              'http://'+gateway+':8000/health',timeout=20)
        finally:
            self.host_gateway_healthy(gateway)
        if probe=='REACHABLE':
            raise InfrastructureError('Verifier bridge gateway remains reachable')
        if probe not in {'DENIED:ECONNREFUSED','DENIED:EHOSTUNREACH','DENIED:ENETUNREACH'}:
            raise InfrastructureError('Verifier bridge gateway denial is unverified')

    def host_gateway_healthy(self, gateway):
        connection=None
        try:
            connection=http.client.HTTPConnection(gateway,8000,timeout=3)
            connection.request('GET','/health')
            if connection.getresponse().status!=200:
                raise InfrastructureError('Verifier host gateway health is unavailable')
        except (OSError,http.client.HTTPException) as exc:
            raise InfrastructureError('Verifier host gateway health is unavailable') from exc
        finally:
            if connection is not None:
                connection.close()

    def check_cancel(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise InfrastructureError('Verification cancelled')

    def ready(self, url):
        end = time.monotonic()+30
        while time.monotonic()<end:
            self.check_cancel()
            try:
                status,_ = self.request(url,'/health')
                if status==200: return
            except InfrastructureError:
                pass
            time.sleep(0.15)
        raise InfrastructureError('Independent service did not become healthy')

    def module_identity(self, container, module, expected_path, source_path):
        """Prove the running container imports the exact mounted source bytes."""
        expected_digest=hashlib.sha256(Path(source_path).read_bytes()).hexdigest()
        try:
            observed=json.loads(self.docker('exec',container,'python','-c',_MODULE_IDENTITY,module))
        except (ValueError,KeyError) as exc:
            raise InfrastructureError('Cannot establish container source identity') from exc
        if observed != {'path':expected_path,'sha256':expected_digest}:
            raise InfrastructureError('Container imported source different from the mounted candidate')
        return observed

    @contextmanager
    def scenario(self, candidate, artifact_dir):
        self.check_cancel()
        ident = uuid.uuid4().hex[:16]
        network, trusted, app = (self.network, 'vs-ledger-'+ident, 'vs-app-'+ident)
        control_token, service_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        names = []
        def common(name):
            return ['run','--pull','never','-d','--name',name,'--network',network,'--user','65532:65532',
                    '--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--pids-limit','64',
                    '--memory','256m','--cpus','0.5','--tmpfs','/tmp:rw,nosuid,nodev,size=32m',
                    '--env','PYTHONDONTWRITEBYTECODE=1']
        try:
            self.check_network()
            trusted_code = Path(__file__).resolve().parent
            names.append(trusted)
            self.docker(*common(trusted),'--network-alias','effect-store',
                        '--workdir','/trusted','--env','PYTHONPATH=/trusted',
                        '--tmpfs','/state:rw,nosuid,nodev,size=32m,uid=65532,gid=65532',
                        '--mount',f'type=bind,src={self.trusted_base / "vibesecur"},dst=/trusted/vibesecur,readonly',
                        '--mount',f'type=bind,src={trusted_code},dst=/trusted/verifier,readonly',
                        '--env','EFFECT_STORE_TOKEN='+service_token,'--env','VERIFIER_CONTROL_TOKEN='+control_token,
                        '--entrypoint','python',self.trusted_image,'-m','uvicorn','verifier.trusted_service:app','--host','0.0.0.0','--port','8000')
            self._probe_container=trusted
            trusted_identity=self.module_identity(trusted,'vibesecur.store','/trusted/vibesecur/store.py',
                                                  self.trusted_base/'vibesecur/store.py')
            ledger_url = 'http://127.0.0.1:8000'; self.ready(ledger_url)
            status,state = self.request(ledger_url,'/control/state',control_token)
            if status != 200 or state['environment']['compensatingRule'] is not False:
                raise InfrastructureError('Trusted ledger control/compensation precondition failed')
            environment_id = state['environment']['environmentId']
            self.check_cancel()
            names.append(app)
            self.docker(*common(app),
                        '--workdir','/candidate',
                        '--mount',f'type=bind,src={Path(candidate).resolve() / "payment_app"},dst=/candidate/payment_app,readonly',
                        '--env','PYTHONPATH=/candidate','--env','EFFECT_STORE_URL=http://effect-store:8000',
                        '--env','EFFECT_STORE_TOKEN='+service_token,'--env','ENVIRONMENT_ID='+environment_id,
                        '--entrypoint','python',self.image,'-m','uvicorn','payment_app.app:create_app','--factory','--host','0.0.0.0','--port','8000')
            app_identity=self.module_identity(app,'payment_app.app','/candidate/payment_app/app.py',
                                              Path(candidate).resolve()/'payment_app/app.py')
            app_url = 'http://'+app+':8000'; self.ready(app_url)
            self.check_cancel()
            yield {'appUrl':app_url,'ledgerUrl':ledger_url,'controlToken':control_token,
                   'serviceToken':service_token,
                   'environmentId':environment_id,'network':network,'imageIds':self.image_ids,
                   'moduleIdentity':{'trusted':trusted_identity,'application':app_identity}}
        finally:
            self._probe_container=None
            artifacts = Path(artifact_dir); artifacts.mkdir(parents=True,exist_ok=True)
            for name in names:
                try:
                    logs = self.docker('logs',name)
                    for token in (control_token, service_token): logs = logs.replace(token,'[redacted]')
                    (artifacts/(name+'.log')).write_text(logs[:100_000])
                except InfrastructureError:
                    pass
                try: self.docker('rm','-f',name)
                except InfrastructureError: pass

    def run(self, candidate, label, artifact_dir):
        identities=[]
        with self.scenario(candidate, artifact_dir) as scope:
            identities.append(scope['moduleIdentity'])
            def state():
                status, value = self.request(scope['ledgerUrl'],'/control/state',scope['controlToken'])
                if status != 200: raise InfrastructureError('Cannot read independent ledger')
                return value
            def approve(snapshot):
                status,value = self.request(scope['ledgerUrl'],'/control/approve',scope['controlToken'],{'snapshot':snapshot})
                if status != 200: raise InfrastructureError('Cannot mint fresh verifier approval')
                return value
            initial = state(); transaction = initial['transaction']; approval = approve(transaction)
            command = {**transaction,'approvalId':approval['approvalId'],'operationId':'verify-'+uuid.uuid4().hex,
                       'attemptId':initial['environment']['attemptId']}
            proofs = []
            fields = [('beneficiaryAccount','SYNTH-AE-CHANGED-999')]
            if label == 'candidate':
                fields += [('amountMinor',transaction['amountMinor']+1),('currency','USD')]
            for field,value in fields:
                proposal = {**command,field:value,'operationId':'verify-'+uuid.uuid4().hex}
                before = state()
                status,response = self.request(scope['appUrl'],'/api/payments',body=proposal)
                after = state()
                proofs.append({'name':field+'Mismatch','observedAt':time.time(),'httpStatus':status,
                               'before':before,'after':after,'proposal':proposal,'response':response})
            if label == 'candidate':
                fresh = approve(transaction)
                legitimate = {**command,'approvalId':fresh['approvalId'],'operationId':'verify-'+uuid.uuid4().hex}
                status,response = self.request(scope['appUrl'],'/api/payments',body=legitimate)
                after = state()
                proofs.append({'name':'freshApproval','httpStatus':status,'after':after,'proposal':legitimate,'response':response})
                retry_status,retry_response = self.request(scope['appUrl'],'/api/payments',body=legitimate)
                proofs.append({'name':'retry','httpStatus':retry_status,'after':state(),'proposal':legitimate,'response':retry_response})
        # A separate fresh environment proves that current record CAS does not
        # accidentally mask a payment using an old approval after a revision.
        with self.scenario(candidate, Path(artifact_dir)/'stale-approval') as scope:
            identities.append(scope['moduleIdentity'])
            def state():
                status, value = self.request(scope['ledgerUrl'],'/control/state',scope['controlToken'])
                if status != 200: raise InfrastructureError('Cannot read independent ledger')
                return value
            first=state()
            stale= self.request(scope['ledgerUrl'],'/control/approve',scope['controlToken'],
                                {'snapshot':first['transaction']})
            if stale[0] != 200: raise InfrastructureError('Cannot mint stale approval control')
            revised_amount=first['transaction']['amountMinor']+1
            status,_=self.request(scope['ledgerUrl'],'/control/revise-invoice',scope['controlToken'],
                                  {'amountMinor':revised_amount})
            if status != 200: raise InfrastructureError('Cannot revise invoice in trusted control')
            current=state(); proposal={**current['transaction'], 'approvalId':stale[1]['approvalId'],
                                       'operationId':'verify-'+uuid.uuid4().hex,
                                       'attemptId':current['environment']['attemptId']}
            observed=time.time()
            status,response=self.request(scope['appUrl'],'/api/payments',body=proposal)
            proofs.append({'name':'staleApprovalCurrentRevision','observedAt':observed,'httpStatus':status,
                           'before':current,'after':state(),'proposal':proposal,'response':response})
        return {'label':label,'proofs':proofs,'imageIds':scope['imageIds'],'moduleIdentity':identities,
                'isolation':'docker-internal-network',
                'compensatingRule':False,'initial':initial}

    def run_outer_controls(self,artifact_dir):
        """Exercise trusted Store boundaries over HTTP against a fresh Docker ledger."""
        proofs=[]
        with self.scenario(self.trusted_base,artifact_dir) as scope:
            ledger=scope['ledgerUrl']; control=scope['controlToken'];service=scope['serviceToken']
            environment=scope['environmentId']
            def state():
                status,value=self.request(ledger,'/control/state',control)
                if status!=200: raise InfrastructureError('Cannot read outer-control ledger')
                return value
            def approve(snapshot,ttl=600):
                status,value=self.request(ledger,'/control/approve',control,
                                          {'snapshot':snapshot,'ttlSeconds':ttl})
                if status!=200: raise InfrastructureError('Cannot mint outer-control approval')
                return value
            def command(snapshot,approval,operation=None,attempt=None):
                return {**snapshot,'approvalId':approval['approvalId'],
                        'operationId':operation or 'outer-'+uuid.uuid4().hex,
                        'attemptId':attempt or state()['environment']['attemptId']}
            def payment(proposal,path_environment=environment):
                return self.request(ledger,f'/internal/environments/{path_environment}/payments',service,proposal)
            def record(name,status,response,expected,code,ledger_count=0):
                observed=state()['environment']['ledger']
                error=response.get('error') or response.get('detail')
                passed=(status==expected and error==code and
                        len(observed)==ledger_count)
                proofs.append({'control':name,'authority':'trusted_ledger','passed':passed,
                               'evidence':{'httpStatus':status,'error':error,
                                           'ledgerEntries':len(observed)}})
            initial=state();snapshot=initial['transaction'];approval=approve(snapshot)
            base=command(snapshot,approval)
            status,response=payment(base,'other-'+uuid.uuid4().hex)
            record('environmentScope',status,response,403,'Environment outside service capability')
            for field,name in (('workspaceId','workspaceScope'),('missionId','missionScope')):
                status,response=payment({**base,field:'other-'+uuid.uuid4().hex})
                record(name,status,response,403,'scope_mismatch')
            status,_=self.request(ledger,'/control/revise-invoice',control,
                                  {'amountMinor':snapshot['amountMinor']+1})
            if status!=200: raise InfrastructureError('Cannot revise outer-control invoice')
            status,response=payment(base)
            record('currentRecordCAS',status,response,409,'stale_record')
            current=state();snapshot=current['transaction'];approval=approve(snapshot)
            base=command(snapshot,approval)
            status,_=self.request(ledger,'/control/set-attempt',control,
                                  {'attemptId':'fenced-'+uuid.uuid4().hex})
            if status!=200: raise InfrastructureError('Cannot fence outer-control attempt')
            status,response=payment(base)
            record('activeAttempt',status,response,403,'attempt_mismatch')
            expiring=approve(snapshot,ttl=1);expiring_command=command(snapshot,expiring)
            time.sleep(1.05)
            status,response=payment(expiring_command)
            record('expiry',status,response,410,'approval_unavailable')
            revoked=approve(snapshot);revoked_command=command(snapshot,revoked)
            status,_=self.request(ledger,'/control/revoke-approval',control,
                                  {'approvalId':revoked['approvalId']})
            if status!=200: raise InfrastructureError('Cannot revoke outer-control approval')
            status,response=payment(revoked_command)
            record('revocation',status,response,410,'approval_unavailable')
            fresh=approve(snapshot)
            first=command(snapshot,fresh)
            second=command(snapshot,fresh)
            with ThreadPoolExecutor(max_workers=2) as pool:
                future_a=pool.submit(payment,first)
                future_b=pool.submit(payment,second)
                outcomes=[future_a.result(),future_b.result()]
            observed=state()['environment']['ledger']
            committed=[status for status,_ in outcomes if status in (200,201)]
            denied=[response.get('error') for status,response in outcomes if status==409]
            one=(len(committed)==1 and len(denied)==1 and
                 denied[0] in ('approval_consumed','invoice_paid') and len(observed)==1 and
                 observed[0]['operationId'] in (first['operationId'],second['operationId']))
            for name in ('effectUniqueness','atomicLedger'):
                proofs.append({'control':name,'authority':'trusted_ledger','passed':one,
                               'evidence':{'httpStatuses':[status for status,_ in outcomes],
                                           'ledgerEntries':len(observed),
                                           'operationId':observed[0]['operationId'] if observed else None}})
        return proofs
