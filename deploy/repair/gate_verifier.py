#!/usr/bin/env python3
"""Measure the fixed verifier bridge before any candidate is executed on it."""
from __future__ import annotations

import argparse
import errno
import json
from pathlib import Path
import socket
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

try:
    from .route_proof import route_proof
except ImportError:
    from route_proof import route_proof

OWNED_PUBLIC_HEALTH_URL = 'https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com/health'
OWNED_PUBLIC_IP_URL = 'https://40.81.234.48/health'
OWNED_PUBLIC_HOST = 'vibesecur-demo-20260925.centralindia.cloudapp.azure.com'
OWNED_PUBLIC_IP = '40.81.234.48'


def explicit_public_route_denial(result: dict, *, default_route_present: bool) -> bool:
    return (result.get('reachable') is False and result.get('errorErrno') == errno.ENETUNREACH
            and default_route_present is False)


def explicit_bridge_denial(result: dict) -> bool:
    return (result.get('reachable') is False and
            result.get('errorType') in ('ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH'))


PROBE = r'''
import errno,json,os,urllib.request,urllib.error
targets=json.loads(os.environ['VIBESECUR_TARGETS'])
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
result={}
for name,url in targets.items():
 try:
  with opener.open(urllib.request.Request(url,headers={'Metadata':'true'}),timeout=3) as response:
   result[name]={'reachable':True,'httpStatus':response.status}
 except urllib.error.HTTPError as error:
  result[name]={'reachable':True,'httpStatus':error.code}
 except Exception as error:
  reason=getattr(error,'reason',error)
  result[name]={'reachable':False,'errorType':errno.errorcode.get(getattr(reason,'errno',None),type(reason).__name__),
                'errorErrno':getattr(reason,'errno',None)}
result['routeTables']={name:open(path).read() for name,path in
                       [('ipv4','/proc/net/route'),('ipv6','/proc/net/ipv6_route')]}
result['dockerSocket']={'present':os.path.exists('/var/run/docker.sock')}
print(json.dumps(result,separators=(',',':')))
'''


def host_get(url: str, headers: dict | None = None) -> dict:
    try:
        with build_opener(ProxyHandler({})).open(Request(url, headers=headers or {}), timeout=4) as response:
            return {'reachable': True, 'httpStatus': response.status}
    except HTTPError as error:
        return {'reachable': True, 'httpStatus': error.code}
    except (URLError, OSError):
        return {'reachable': False}


def gate(config: dict) -> dict:
    name, image = config['network'], config['trustedImage']
    public_target_check = host_get(OWNED_PUBLIC_HEALTH_URL)
    if not (public_target_check.get('reachable') and public_target_check.get('httpStatus') == 200):
        return {'passed': False, 'status': 'blocked', 'reason': 'owned_public_target_unavailable',
                'externalProbeUrl': OWNED_PUBLIC_HEALTH_URL,
                'hostChecks': {'external': public_target_check}}
    try:
        if socket.gethostbyname(OWNED_PUBLIC_HOST) != OWNED_PUBLIC_IP:
            raise ValueError('Owned demo DNS changed')
    except (OSError, ValueError):
        return {'passed': False, 'status': 'blocked', 'reason': 'owned_public_ip_unverified'}
    network_result = subprocess.run(['docker', 'network', 'inspect', name], capture_output=True,
                                    text=True, timeout=15, check=True)
    network = json.loads(network_result.stdout)[0]
    image_result = subprocess.run(['docker', 'image', 'inspect', image], capture_output=True,
                                  text=True, timeout=15, check=True)
    image_id = json.loads(image_result.stdout)[0]['Id']
    ipam = network['IPAM']['Config'][0]
    network_id, subnet, gateway = network['Id'], ipam['Subnet'], ipam['Gateway']
    interface = 'br-' + network_id[:12]
    firewall_rule = {'chain': 'INPUT', 'argv': ['-i', interface, '-s', subnet, '-j', 'REJECT']}
    firewall = subprocess.run(['sudo', '-n', 'iptables', '-C', 'INPUT', *firewall_rule['argv']],
                              capture_output=True, text=True, timeout=10)
    bridge_url = f'http://{gateway}:8000/health'
    bridge_before = host_get(bridge_url)
    if bridge_before.get('httpStatus') != 200:
        return {'passed': False, 'status': 'blocked', 'reason': 'host_bridge_unavailable',
                'hostChecks': {'bridgeBefore': bridge_before}}
    targets = {
        'hostGateway': f'http://{gateway}:8000/health',
        'controller': 'http://172.20.0.1:8000/health',
        'verifier': f'http://{gateway}:8000/internal/verifier/health',
        'external': OWNED_PUBLIC_IP_URL,
    }
    probe = subprocess.run(['docker', 'run', '--rm', '--pull', 'never', '--network', name,
                            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                            '--pids-limit', '32', '--memory', '128m', '--cpus', '0.25',
                            '--user', '65532:65532', '--env', 'VIBESECUR_TARGETS='+json.dumps(targets),
                            '--entrypoint', 'python', image_id, '-c', PROBE],
                           capture_output=True, text=True, timeout=30)
    if probe.returncode:
        return {'passed': False, 'status': 'blocked', 'reason': 'probe_execution_failed',
                'stderrTail': probe.stderr[-400:]}
    probes = json.loads(probe.stdout)
    route = route_proof(probes['routeTables']['ipv4'], probes['routeTables']['ipv6'], subnet)
    bridge_after = host_get(bridge_url)
    bridge_healthy = bridge_before.get('httpStatus') == 200 and bridge_after.get('httpStatus') == 200
    host_checks = {
        'controller': host_get('http://127.0.0.1:8000/health'),
        'bridgeBefore': bridge_before, 'bridgeAfter': bridge_after,
        'otherBridge': host_get('http://172.20.0.1:8000/health'),
        'external': public_target_check,
    }
    coverage = {
        'hostGatewayDenied': bridge_healthy and explicit_bridge_denial(probes['hostGateway']),
        'controllerDenied': (bridge_healthy and explicit_bridge_denial(probes['controller']) and
                             host_checks['controller'].get('httpStatus') == 200 and
                             host_checks['otherBridge'].get('httpStatus') == 200),
        'verifierDenied': bridge_healthy and explicit_bridge_denial(probes['verifier']),
        'metadataDenied': None,
        'azurePlatformDenied': None,
        'providerRouteDenied': route['providerRouteDenied'],
        'externalDenied': explicit_public_route_denial(probes['external'],
            default_route_present=not route['noDefaultRoute']),
        'dockerSocketDenied': probes['dockerSocket']['present'] is False,
    }
    prerequisites = (name == 'vs-verify-internal' and network['Internal'] is True
                     and firewall.returncode == 0 and
                     network_id == '0d88e0a4cda48d25135dc67f0bdfe9e992f6d91e3168f517efdd5e27555e8e3d'
                     and subnet == '172.29.0.0/24' and gateway == '172.29.0.1')
    measured = (value for key, value in coverage.items()
                if key not in ('metadataDenied', 'azurePlatformDenied'))
    passed = prerequisites and all(measured)
    return {'passed': passed, 'status': 'passed' if passed else 'failed',
            'runtime': 'docker', 'profile': 'owned-demo-v1',
            'checkedAt': time.time(), 'network': name,
            'networkId': network_id, 'bridgeSubnet': subnet, 'bridgeGateway': gateway,
            'bridgeInterface': interface, 'imageDigest': image_id, 'firewallRule': firewall_rule,
            'firewallRulePresent': firewall.returncode == 0, 'probes': probes,
            'hostChecks': host_checks, 'coverage': coverage,
            'externalProbeUrl': OWNED_PUBLIC_IP_URL, 'routeProof': route,
            'unmeasuredControls': ['metadataDenied', 'azurePlatformDenied'],
            'limitations': ['This gate measures the verifier network before candidate execution.',
                            'The supervisor must repeat gateway denial for the actual scenario.',
                            'Provider endpoints were not contacted; only static route isolation was measured.']}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    result = gate(config)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'status': result['status'], 'output': str(output)}))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
