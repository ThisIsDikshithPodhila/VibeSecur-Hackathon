"""Repair job admission for the owned synthetic boundary profile."""
import json
import hashlib
import subprocess
import time

import pytest

from vibesecur.repair import (REPAIR_BOUNDARY_CONTROLS, validate_boundary_evidence,
                             preflight_repair_boundary)


IMAGE = 'sha256:' + 'a' * 64
NETWORK = 'vs-repair-internal'
SUBNET = '172.28.0.0/24'


def evidence():
    coverage = {key: True for key in REPAIR_BOUNDARY_CONTROLS}
    coverage.update(metadataDenied=None, azurePlatformDenied=None)
    return {
        'passed': True, 'runtime': 'docker', 'profile': 'owned-demo-v1',
        'network': NETWORK, 'imageDigest': IMAGE, 'checkedAt': time.time(),
        'bridgeSubnet': SUBNET, 'probes': {'route': 'measured'},
        'coverage': coverage,
        'routeProof': {
            'method': 'proc_net_route', 'expectedSubnet': SUBNET,
            'ipv4Routes': [{'destination': SUBNET, 'gateway': '0.0.0.0', 'interface': 'eth0'}],
            'ipv6Routes': [], 'noDefaultRoute': True,
            'onlyExpectedInternalRoutes': True, 'providerRouteDenied': True,
        },
    }


def admit(tmp_path, artifact, *, image=IMAGE, network=NETWORK):
    path = tmp_path / 'repair-boundary.json'
    path.write_text(json.dumps(artifact))
    return validate_boundary_evidence({'network': network, 'boundaryEvidencePath': str(path)}, image)


def test_owned_demo_profile_is_admitted_with_unknown_provider_checks(tmp_path):
    artifact = evidence()
    result = admit(tmp_path, artifact)
    assert result['profile'] == 'owned-demo-v1'
    assert result['network'] == NETWORK and result['imageDigest'] == IMAGE
    assert len(result['evidenceSha256']) == 64


@pytest.mark.parametrize('section,key,value', [
    ('root', 'profile', 'legacy'),
    ('root', 'profile', None),
    ('coverage', 'providerRouteDenied', False),
    ('coverage', 'metadataDenied', True),
    ('coverage', 'azurePlatformDenied', True),
    ('coverage', 'applicationDenied', False),
    ('routeProof', 'method', 'unmeasured'),
    ('routeProof', 'providerRouteDenied', False),
    ('routeProof', 'noDefaultRoute', False),
    ('routeProof', 'onlyExpectedInternalRoutes', False),
    ('routeProof', 'expectedSubnet', '172.29.0.0/24'),
    ('routeProof', 'ipv4Routes', []),
    ('routeProof', 'ipv6Routes', 'unmeasured'),
])
def test_legacy_or_incomplete_route_profile_is_rejected(tmp_path, section, key, value):
    artifact = evidence()
    target = artifact if section == 'root' else artifact[section]
    target[key] = value
    with pytest.raises(ValueError, match='boundary evidence'):
        admit(tmp_path, artifact)


def test_legacy_live_provider_booleans_do_not_substitute_for_profile(tmp_path):
    artifact = evidence()
    artifact.pop('profile')
    artifact.pop('routeProof')
    artifact['coverage'].pop('providerRouteDenied')
    artifact['coverage'].update(metadataDenied=True, azurePlatformDenied=True)
    with pytest.raises(ValueError):
        admit(tmp_path, artifact)


@pytest.mark.parametrize('change', ['image', 'network', 'expired'])
def test_existing_identity_and_freshness_checks_remain(tmp_path, change):
    artifact = evidence()
    options = {}
    if change == 'image':
        options['image'] = 'sha256:' + 'b' * 64
    elif change == 'network':
        options['network'] = 'other-network'
    else:
        artifact['checkedAt'] = time.time() - 3601
    with pytest.raises(ValueError):
        admit(tmp_path, artifact, **options)


@pytest.mark.parametrize('failure', ['none', 'missing_firewall', 'host_down_before',
                                      'host_down_after', 'gateway_timeout', 'ambiguous_error'])
def test_preflight_requires_host_control_and_explicit_kernel_denial(tmp_path, monkeypatch, failure):
    artifact=evidence()
    network_id='b'*64
    relay_id='c'*64
    relay_image='sha256:'+'d'*64
    relay_config=tmp_path/'Caddyfile';relay_config.write_text('measured relay')
    artifact.update(networkId=network_id,bridgeInterface='br-'+network_id[:12],
                    bridgeGateway='172.28.0.1',
                    firewallRule={'chain':'INPUT','argv':['-i','br-'+network_id[:12],
                        '-s',SUBNET,'-j','REJECT']},
                    relay={'name':'vs-repair-model-relay','containerId':relay_id,
                           'imageDigest':relay_image,'configPath':str(relay_config),
                           'configSha256':hashlib.sha256(relay_config.read_bytes()).hexdigest(),
                           'internalNetwork':NETWORK,'uplinkNetwork':'openshell-docker',
                           'alias':'repair-model-relay',
                           'url':'http://repair-model-relay:8081/model/v1'})
    path=tmp_path/'repair-boundary.json';path.write_text(json.dumps(artifact))
    config={'network':NETWORK,'boundaryEvidencePath':str(path)}
    accepted=validate_boundary_evidence(config,IMAGE)
    network={'Id':network_id,'Internal':True,'IPAM':{'Config':[
        {'Subnet':SUBNET,'Gateway':'172.28.0.1'}]}}
    relay={'Id':relay_id,'Image':relay_image,'State':{'Running':True},
           'NetworkSettings':{'Networks':{NETWORK:{'Aliases':['repair-model-relay']},
                                          'openshell-docker':{}}},
           'Mounts':[{'Source':str(relay_config),'Destination':'/etc/caddy/Caddyfile',
                      'RW':False}]}
    commands=[]
    host_checks=0
    def fake_run(argv,**kwargs):
        nonlocal host_checks
        commands.append(argv)
        if argv[:3]==['docker','network','inspect']:
            return subprocess.CompletedProcess(argv,0,json.dumps([network]),'')
        if argv[:3]==['docker','inspect','--type']:
            return subprocess.CompletedProcess(argv,0,json.dumps([relay]),'')
        if argv[0]=='curl':
            host_checks+=1
            down=(failure=='host_down_before' and host_checks==1 or
                  failure=='host_down_after' and host_checks==2)
            return subprocess.CompletedProcess(argv,7 if down else 0,
                                               '000' if down else '200','')
        if '--entrypoint' in argv and argv[argv.index('--entrypoint')+1]=='node':
            outcome=({'status':'connected'} if failure=='missing_firewall' else
                     {'status':'timeout'} if failure=='gateway_timeout' else
                     {'status':'socket_error','code':'EAI_AGAIN'} if failure=='ambiguous_error' else
                     {'status':'socket_error','code':'ECONNREFUSED'})
            return subprocess.CompletedProcess(argv,0,json.dumps(outcome)+'\n','')
        if 'http://172.28.0.1:8000/health' in argv:
            return subprocess.CompletedProcess(argv,7,'\n000','refused')
        if artifact['relay']['url']+'/responses' in argv:
            return subprocess.CompletedProcess(argv,0,
                json.dumps({'error':{'message':'Invalid model capability'}})+'\n403','')
        raise AssertionError(argv)
    monkeypatch.setattr('vibesecur.repair.subprocess.run',fake_run)
    if failure=='none':
        result=preflight_repair_boundary(config,IMAGE,accepted)
        assert result['gatewayDenied'] is True
        assert host_checks==2
        assert any('--entrypoint' in argv and argv[argv.index('--entrypoint')+1]=='node'
                   and '172.28.0.1' in ' '.join(argv) for argv in commands)
    else:
        with pytest.raises(ValueError):
            preflight_repair_boundary(config,IMAGE,accepted)
