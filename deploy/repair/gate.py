#!/usr/bin/env python3
"""Measure the actual isolated Codex repair topology on the demo host."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
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
    return (result.get('reachable') is False and result.get('errorType') == 'ENETUNREACH'
            and default_route_present is False)


def explicit_bridge_denial(result: dict) -> bool:
    return (result.get('reachable') is False and
            result.get('errorType') in ('ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH'))


NODE_PROBE = r'''
const fs = require('fs');
const http = require('http');
const https = require('https');
const targets = JSON.parse(process.env.VIBESECUR_TARGETS);
function request(target) {
  return new Promise(resolve => {
    const client = target.url.startsWith('https:') ? https : http;
    const req = client.request(target.url, {method:target.method || 'GET',
      headers:target.method === 'POST' ? {'Content-Type':'application/json',
        'Authorization':'Bearer invalid-repair-gate'} : {}, timeout:3000}, response => {
      let body = '';
      response.on('data', chunk => {if (body.length < 600) body += chunk.toString();});
      response.on('end', () => resolve({reachable:true,httpStatus:response.statusCode,
        body:body.slice(0,300)}));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', error => resolve({reachable:false,errorType:error.code || error.name}));
    if (target.method === 'POST') req.write('{}');
    req.end();
  });
}
function write(path) {
  try {fs.writeFileSync(path, 'gate\n');return {writable:true};}
  catch (error) {return {writable:false,errorType:error.code || error.name};}
}
(async () => {
  const entries = await Promise.all(Object.entries(targets).map(async ([name,target]) =>
    [name,await request(target)]));
  const filesystem = {
    paymentApp:write('/workspace/payment_app/gate.txt'),
    repairHome:write('/home/repair/gate.txt'),
    tmp:write('/tmp/gate.txt'),
    outsidePaymentApp:write('/workspace/README.md'),
    etc:write('/etc/passwd'),
    hostPath:write('/srv/vibesecur/gate.txt'),
    dockerSocketPresent:fs.existsSync('/var/run/docker.sock')
  };
  const routeTables = {ipv4:fs.readFileSync('/proc/net/route','utf8'),
    ipv6:fs.readFileSync('/proc/net/ipv6_route','utf8')};
  process.stdout.write(JSON.stringify({network:Object.fromEntries(entries),filesystem,routeTables}));
})().catch(error => {process.stderr.write(error.message);process.exit(2)});
'''


def run(*argv: str, timeout: int = 20, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=input_text, text=True, capture_output=True,
                          timeout=timeout, check=False)


def inspect(*argv: str) -> dict:
    result = run('docker', 'inspect', *argv)
    if result.returncode:
        raise RuntimeError('Docker inspect failed')
    rows = json.loads(result.stdout)
    if len(rows) != 1:
        raise RuntimeError('Unexpected Docker inspect result')
    return rows[0]


def host_get(url: str, headers: dict | None = None) -> dict:
    try:
        response = build_opener(ProxyHandler({})).open(Request(url, headers=headers or {}), timeout=4)
        with response:
            return {'reachable': True, 'httpStatus': response.status}
    except HTTPError as error:
        return {'reachable': True, 'httpStatus': error.code}
    except (URLError, OSError):
        return {'reachable': False}


def gate(config: dict) -> dict:
    image, network_name = config['image'], config['network']
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('Repair image must be an immutable image ID')
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
    image_info = inspect('--type', 'image', image)
    if image_info['Id'] != image:
        raise ValueError('Repair image identity mismatch')
    network_result = run('docker', 'network', 'inspect', network_name)
    if network_result.returncode:
        raise RuntimeError('Repair network unavailable')
    network = json.loads(network_result.stdout)[0]
    network_id = network['Id']
    ipam = network['IPAM']['Config'][0]
    subnet, gateway = ipam['Subnet'], ipam['Gateway']
    interface = 'br-' + network_id[:12]
    firewall_rule = {'chain': 'INPUT',
                     'argv': ['-i', interface, '-s', subnet, '-j', 'REJECT']}
    firewall = run('sudo', '-n', 'iptables', '-C', 'INPUT', *firewall_rule['argv'])
    relay_info = inspect('--type', 'container', 'vs-repair-model-relay')
    relay_config = Path(config['relayConfigPath']).resolve()
    relay = {'name': 'vs-repair-model-relay', 'containerId': relay_info['Id'],
             'imageDigest': relay_info['Image'], 'configPath': str(relay_config),
             'configSha256': hashlib.sha256(relay_config.read_bytes()).hexdigest(),
             'internalNetwork': network_name, 'uplinkNetwork': config['uplinkNetwork'],
             'alias': 'repair-model-relay', 'url': 'http://repair-model-relay:8081/model/v1'}
    attached = relay_info['NetworkSettings']['Networks']
    mounts = relay_info['Mounts']
    relay_identity = (relay_info['State']['Running'] is True
                      and network_name in attached and config['uplinkNetwork'] in attached
                      and 'repair-model-relay' in (attached[network_name].get('Aliases') or [])
                      and any(m['Source'] == str(relay_config) and
                              m['Destination'] == '/etc/caddy/Caddyfile' and m['RW'] is False
                              for m in mounts)
                      and relay_info['HostConfig']['Privileged'] is False)
    payment = config['paymentHost']
    if not re.fullmatch(r'payment-[a-z0-9-]{1,80}', payment):
        raise ValueError('Invalid payment service host')
    payment_info = inspect('--type', 'container', payment)
    payment_networks = payment_info['NetworkSettings']['Networks']
    payment_separate = (payment_info['State']['Running'] is True and
                        config['uplinkNetwork'] in payment_networks and
                        network_name not in payment_networks)
    payment_ip = payment_networks[config['uplinkNetwork']]['IPAddress']
    bridge_url = f'http://{gateway}:8000/health'
    bridge_before = host_get(bridge_url)
    if bridge_before.get('httpStatus') != 200:
        return {'passed': False, 'status': 'blocked', 'reason': 'host_bridge_unavailable',
                'hostChecks': {'bridgeBefore': bridge_before}}
    targets = {
        'modelRelay': {'url': relay['url'] + '/responses', 'method': 'POST'},
        'relayOtherPath': {'url': 'http://repair-model-relay:8081/health'},
        'application': {'url': f'http://{payment}:8000/portal'},
        'applicationDirect': {'url': f'http://{payment_ip}:8000/portal'},
        'effectStore': {'url': f'http://{gateway}:8000/internal/environments/test'},
        'effectStoreAlias': {'url': 'http://effect-store:8000/internal/environments/test'},
        'controller': {'url': f'http://{gateway}:8000/health'},
        'verifier': {'url': f'http://{gateway}:8000/internal/verifier/health'},
        'hostGateway': {'url': f'http://{gateway}:8000/api/runs'},
        'otherBridge': {'url': 'http://172.20.0.1:8000/health'},
        'external': {'url': OWNED_PUBLIC_IP_URL},
    }
    with tempfile.TemporaryDirectory(prefix='vs-repair-gate-', dir=config['artifactDir']) as temp:
        root = Path(temp)
        root.chmod(0o755)
        workspace = root/'workspace'; workspace.mkdir(mode=0o755)
        (workspace/'README.md').write_text('trusted gate source\n')
        writable = workspace/'payment_app'; writable.mkdir(); writable.chmod(0o777)
        home = root/'home'; home.mkdir(); home.chmod(0o777)
        command = ['docker', 'run', '--rm', '--pull', 'never', '--network', network_name,
                   '--user', '65532:65532', '--cap-drop=ALL',
                   '--security-opt=no-new-privileges', '--read-only', '--pids-limit', '128',
                   '--memory', '768m', '--cpus', '0.75',
                   '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
                   '--mount', f'type=bind,src={workspace},dst=/workspace,readonly',
                   '--mount', f'type=bind,src={writable},dst=/workspace/payment_app',
                   '--mount', f'type=bind,src={home},dst=/home/repair',
                   '--env', 'HOME=/home/repair', '--env', 'VIBESECUR_TARGETS='+json.dumps(targets),
                   '-w', '/workspace', '--entrypoint', 'node', image, '-e', NODE_PROBE]
        executed = run(*command, timeout=45)
    if executed.returncode:
        return {'passed': False, 'status': 'blocked', 'runtime': 'docker',
                'reason': 'repair_probe_failed', 'stderrTail': executed.stderr[-400:]}
    probes = json.loads(executed.stdout)
    network_probes, fs = probes['network'], probes['filesystem']
    route = route_proof(probes['routeTables']['ipv4'], probes['routeTables']['ipv6'], subnet)
    bridge_after = host_get(bridge_url)
    bridge_healthy = bridge_before.get('httpStatus') == 200 and bridge_after.get('httpStatus') == 200
    relay_ok = (network_probes['modelRelay'].get('httpStatus') == 403 and
                'Invalid model capability' in network_probes['modelRelay'].get('body', ''))
    host_checks = {
        'controller': host_get('http://127.0.0.1:8000/health'),
        'bridgeBefore': bridge_before, 'bridgeAfter': bridge_after,
        'otherBridge': host_get('http://172.20.0.1:8000/health'),
        'external': public_target_check,
    }
    payment_check = run('docker', 'run', '--rm', '--pull', 'never', '--network', config['uplinkNetwork'],
                        '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                        '--memory', '128m', '--cpus', '0.25', '--user', '65532:65532',
                        '--entrypoint', 'curl', image, '--noproxy', '*', '--silent',
                        '--max-time', '4', '--output', '/dev/null', '--write-out', '%{http_code}',
                        f'http://{payment}:8000/portal')
    host_checks['application'] = {'reachable': payment_check.returncode == 0,
                                  'httpStatus': int(payment_check.stdout) if payment_check.stdout.isdigit() else None}
    coverage = {
        'applicationDenied': (payment_separate and
                              explicit_bridge_denial(network_probes['applicationDirect']) and
                              network_probes['application']['reachable'] is False and
                              host_checks['application']['httpStatus'] == 200),
        'effectStoreDenied': bridge_healthy and explicit_bridge_denial(network_probes['effectStore']) and
                             network_probes['effectStoreAlias']['reachable'] is False,
        'modelRelayReachable': relay_ok,
        'controllerDenied': bridge_healthy and explicit_bridge_denial(network_probes['controller']) and
                            explicit_bridge_denial(network_probes['otherBridge']) and
                            host_checks['controller'].get('httpStatus') == 200 and
                            host_checks['otherBridge'].get('httpStatus') == 200,
        'verifierDenied': bridge_healthy and explicit_bridge_denial(network_probes['verifier']) and
                          network_probes['relayOtherPath'].get('httpStatus') == 403,
        'hostGatewayDenied': bridge_healthy and
                             explicit_bridge_denial(network_probes['hostGateway']) and
                             explicit_bridge_denial(network_probes['controller']),
        'metadataDenied': None,
        'azurePlatformDenied': None,
        'providerRouteDenied': route['providerRouteDenied'],
        'externalDenied': explicit_public_route_denial(network_probes['external'],
            default_route_present=not route['noDefaultRoute']),
        'dockerSocketDenied': fs['dockerSocketPresent'] is False,
        'scopedWritablePathsEnforced': all(fs[k]['writable'] is True for k in
                                           ('paymentApp', 'repairHome', 'tmp')) and
                                       all(fs[k]['writable'] is False for k in
                                           ('outsidePaymentApp', 'etc', 'hostPath')),
    }
    prerequisites = (network['Internal'] is True and firewall.returncode == 0
                     and relay_identity and relay_info['Image'] == config['relayImage'])
    measured = (value for key, value in coverage.items()
                if key not in ('metadataDenied', 'azurePlatformDenied'))
    passed = prerequisites and all(measured)
    return {'passed': passed, 'status': 'passed' if passed else 'failed',
            'runtime': 'docker', 'profile': 'owned-demo-v1',
            'checkedAt': time.time(), 'imageDigest': image,
            'network': network_name, 'networkId': network_id, 'bridgeInterface': interface,
            'bridgeSubnet': subnet, 'bridgeGateway': gateway, 'firewallRule': firewall_rule,
            'relay': relay, 'firewallRulePresent': firewall.returncode == 0,
            'relayIdentityMatched': relay_identity, 'paymentSeparate': payment_separate,
            'hostChecks': host_checks,
            'probes': probes, 'coverage': coverage,
            'externalProbeUrl': OWNED_PUBLIC_IP_URL, 'routeProof': route,
            'unmeasuredControls': ['metadataDenied', 'azurePlatformDenied'],
            'limitations': ['Docker internal network alone permits host bridge access; this gate also requires a host INPUT REJECT rule.',
                            'The effective gateway denial is rechecked before each repair job.',
                            'Provider endpoints were not contacted; only static route isolation was measured.',
                            'This is hardened Docker containment, not OpenShell L7 or Landlock.']}


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
    print(json.dumps({'passed': result['passed'], 'status': result['status'],
                      'output': str(output)}))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
