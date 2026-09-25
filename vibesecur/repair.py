"""Bounded repair execution. This module never certifies its own candidate."""
from __future__ import annotations
import difflib
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import subprocess
import tarfile
import threading
import time
import uuid

MAX_PATCH_BYTES = 2_000_000
REPAIR_BOUNDARY_CONTROLS = ('applicationDenied','effectStoreDenied','modelRelayReachable','controllerDenied',
    'verifierDenied','hostGatewayDenied','providerRouteDenied',
    'externalDenied','dockerSocketDenied','scopedWritablePathsEnforced')
GATEWAY_SOCKET_PROBE = (
    "const net=require('node:net');"
    "let done=false;"
    "const socket=net.createConnection({host:process.argv.at(-1),port:8000});"
    "function finish(status,code){if(done)return;done=true;"
    "console.log(JSON.stringify({status,code}));socket.destroy();}"
    "socket.setTimeout(2000,()=>finish('timeout',null));"
    "socket.once('connect',()=>finish('connected',null));"
    "socket.once('error',error=>finish('socket_error',error.code||null));"
)
SAFE_ENV = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'C.UTF-8', 'DOCKER_CONFIG': '/nonexistent-vibesecur-docker-config'}


def _git(repo, *args, **kwargs):
    return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-C', str(repo), *args], env={**SAFE_ENV, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}, check=True, capture_output=True, **kwargs)


def _path(value):
    path = PurePosixPath(value)
    if (path.is_absolute() or '..' in path.parts or not path.parts or
            any(part.startswith('.') for part in path.parts) or '\\' in value or '\x00' in value):
        raise ValueError('Unsafe path in source or patch')
    return path


def validate_patch(patch: str) -> list[str]:
    if not patch.strip() or len(patch.encode()) > MAX_PATCH_BYTES:
        raise ValueError('Patch empty or oversized')
    paths = set()
    for line in patch.splitlines():
        if line.startswith('diff --git '):
            match = re.fullmatch(r'diff --git a/([^\s]+) b/([^\s]+)', line)
            if not match or match[1] != match[2]:
                raise ValueError('Renames and quoted paths are not allowed')
            path = _path(match[1])
            if path.parts[0] != 'payment_app' or len(path.parts) < 2:
                raise ValueError('Patch outside payment_app allowlist')
            if path.suffix == '.lock' or path.name in {'requirements.lock', 'package-lock.json', 'uv.lock', 'poetry.lock', 'AGENTS.md'} or 'tests' in path.parts:
                raise ValueError('Protected acceptance or dependency file')
            paths.add(str(path))
        elif line.startswith(('old mode ', 'new mode ', 'new file mode ', 'deleted file mode ')):
            if line.rsplit(' ', 1)[-1] not in {'100644', '100755'}:
                raise ValueError('Symlinks and special file modes are forbidden')
        elif line.startswith(('rename ', 'copy ', 'GIT binary patch', 'Binary files ')):
            raise ValueError('Only textual, non-renaming patches accepted')
        elif line.startswith(('--- ', '+++ ')):
            value = line[4:]
            if value != '/dev/null':
                if not value.startswith(('a/', 'b/')) or str(_path(value[2:])) not in paths:
                    raise ValueError('Patch header mismatch')
    if not paths:
        raise ValueError('No git patch paths')
    return sorted(paths)


def prepare_candidate(repo, base_commit, destination, patch=None):
    """Extract immutable regular files; never copy worktree config, symlinks or hooks."""
    if not re.fullmatch(r'[0-9a-f]{40}', base_commit):
        raise ValueError('A full immutable Git commit is required')
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    raw = _git(repo, 'archive', '--format=tar', base_commit).stdout
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for member in archive:
            # Hidden metadata is never needed by the repair runtime.
            if any(part.startswith('.') for part in PurePosixPath(member.name).parts):
                continue
            path = _path(member.name)
            if not (member.isfile() or member.isdir()):
                raise ValueError('Immutable base contains a symlink or special file')
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                if member.size > 20_000_000:
                    raise ValueError('Base source file exceeds limit')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    if patch is not None:
        validate_patch(patch)
        _git(destination, 'apply', '--check', '-', input=patch.encode())
        _git(destination, 'apply', '--whitespace=nowarn', '-', input=patch.encode())
    return destination


def source_files(root):
    result = {}
    for p in sorted(Path(root).rglob('*')):
        if p.is_symlink():
            raise ValueError('Candidate contains symlink')
        if p.is_file():
            if p.stat().st_size > MAX_PATCH_BYTES:
                raise ValueError('Candidate file oversized')
            result[p.relative_to(root).as_posix()] = p.read_bytes()
        elif not p.is_dir():
            raise ValueError('Candidate contains special file')
    return result


def collect_patch(original, candidate):
    before, after = source_files(original), source_files(candidate)
    parts = []
    for path in sorted(before.keys() | after.keys()):
        if before.get(path) == after.get(path):
            continue
        _path(path)
        if not path.startswith('payment_app/'):
            raise ValueError('Repair modified protected source')
        old = before.get(path, b'').decode('utf-8').splitlines(keepends=True)
        new = after.get(path, b'').decode('utf-8').splitlines(keepends=True)
        parts.append(f'diff --git a/{path} b/{path}\n')
        if path not in before:
            parts.append('new file mode 100644\n')
        elif path not in after:
            parts.append('deleted file mode 100644\n')
        for line in difflib.unified_diff(old, new, fromfile=f'a/{path}' if path in before else '/dev/null', tofile=f'b/{path}' if path in after else '/dev/null'):
            parts.append(line if line.endswith('\n') else line + '\n\\ No newline at end of file\n')
    patch = ''.join(parts)
    validate_patch(patch)
    return patch


def docker_env(config):
    env = dict(SAFE_ENV)
    if config.get('dockerHost'):
        env['DOCKER_HOST'] = config['dockerHost']
    return env


def validate_boundary_evidence(config, image_id):
    """A config switch cannot stand in for a recent repair-specific fault gate."""
    path=config.get('boundaryEvidencePath')
    try:
        raw=Path(path).read_bytes() if path else b''
        evidence=json.loads(raw) if raw else None
    except (OSError,ValueError,TypeError):
        evidence=None
    now=time.time()
    coverage=evidence.get('coverage') if isinstance(evidence,dict) else None
    route_proof=evidence.get('routeProof') if isinstance(evidence,dict) else None
    required=REPAIR_BOUNDARY_CONTROLS+(
        ('policyEnforced','landlockEnforced') if isinstance(evidence,dict) and evidence.get('runtime')=='openshell'
        else ())
    if (not isinstance(evidence,dict) or evidence.get('passed') is not True or
            evidence.get('profile')!='owned-demo-v1' or
            evidence.get('runtime') not in ('docker','openshell') or
            evidence.get('network')!=config.get('network') or
            evidence.get('imageDigest')!=image_id or
            not isinstance(evidence.get('probes'),dict) or not evidence['probes'] or
            not isinstance(coverage,dict) or any(coverage.get(key) is not True for key in required) or
            'metadataDenied' not in coverage or coverage['metadataDenied'] is not None or
            'azurePlatformDenied' not in coverage or coverage['azurePlatformDenied'] is not None or
            not isinstance(route_proof,dict) or route_proof.get('method')!='proc_net_route' or
            not isinstance(evidence.get('bridgeSubnet'),str) or not evidence['bridgeSubnet'] or
            route_proof.get('expectedSubnet')!=evidence['bridgeSubnet'] or
            route_proof.get('noDefaultRoute') is not True or
            route_proof.get('onlyExpectedInternalRoutes') is not True or
            route_proof.get('providerRouteDenied') is not True or
            not isinstance(route_proof.get('ipv4Routes'),list) or not route_proof['ipv4Routes'] or
            any(not isinstance(route,dict) for route in route_proof['ipv4Routes']) or
            not isinstance(route_proof.get('ipv6Routes'),list) or
            any(not isinstance(route,dict) for route in route_proof['ipv6Routes']) or
            not isinstance(evidence.get('checkedAt'),(int,float)) or
            not 0<=now-evidence['checkedAt']<=3600):
        raise ValueError('Repair requires recent image/network-bound boundary evidence')
    return {'checkedAt':evidence['checkedAt'],'runtime':evidence['runtime'],
            'profile':evidence['profile'],
            'imageDigest':image_id,'network':evidence['network'],
            'evidenceSha256':hashlib.sha256(raw).hexdigest()}


def preflight_repair_boundary(config, image_id, accepted):
    """Recheck the live Docker topology and effective egress before each repair job."""
    raw=Path(config['boundaryEvidencePath']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=accepted['evidenceSha256']:
        raise ValueError('Repair boundary evidence changed after admission')
    evidence=json.loads(raw)
    if evidence.get('runtime')!='docker':
        raise ValueError('This repair executor requires a measured Docker boundary')
    network_id=evidence.get('networkId','')
    interface=evidence.get('bridgeInterface','')
    subnet=evidence.get('bridgeSubnet','')
    gateway=evidence.get('bridgeGateway','')
    rule=evidence.get('firewallRule') or {}
    relay=evidence.get('relay') or {}
    if (not re.fullmatch(r'[0-9a-f]{64}',network_id) or
            interface!='br-'+network_id[:12] or
            rule!={'chain':'INPUT','argv':['-i',interface,'-s',subnet,'-j','REJECT']}):
        raise ValueError('Repair bridge firewall identity is incomplete')
    try:
        parsed_subnet=ipaddress.ip_network(subnet,strict=True)
        parsed_gateway=ipaddress.ip_address(gateway)
    except ValueError:
        raise ValueError('Repair bridge address is invalid') from None
    if parsed_subnet.version!=4 or parsed_gateway not in parsed_subnet:
        raise ValueError('Repair bridge gateway is outside its subnet')
    if (relay.get('internalNetwork')!=config['network'] or
            not re.fullmatch(r'[0-9a-f]{64}',relay.get('containerId','')) or
            not re.fullmatch(r'sha256:[0-9a-f]{64}',relay.get('imageDigest','')) or
            not re.fullmatch(r'[0-9a-f]{64}',relay.get('configSha256','')) or
            relay.get('name')!='vs-repair-model-relay' or
            relay.get('alias')!='repair-model-relay' or
            relay.get('url')!='http://repair-model-relay:8081/model/v1' or
            not isinstance(relay.get('uplinkNetwork'),str) or
            not relay['uplinkNetwork']):
        raise ValueError('Repair relay identity is incomplete')
    config_path=Path(relay.get('configPath',''))
    if (not config_path.is_absolute() or
            hashlib.sha256(config_path.read_bytes()).hexdigest()!=relay['configSha256']):
        raise ValueError('Repair relay configuration differs from measured content')
    def inspect(*args):
        process=subprocess.run(['docker','inspect',*args],env=docker_env(config),
                               capture_output=True,text=True,timeout=15,check=True)
        rows=json.loads(process.stdout)
        if not isinstance(rows,list) or len(rows)!=1:
            raise ValueError('Unexpected Docker inspect result')
        return rows[0]
    network=subprocess.run(['docker','network','inspect',config['network']],env=docker_env(config),
                           capture_output=True,text=True,timeout=15,check=True)
    rows=json.loads(network.stdout)
    if not isinstance(rows,list) or len(rows)!=1:
        raise ValueError('Unexpected repair network inspection')
    actual=rows[0]
    ipam=(actual.get('IPAM') or {}).get('Config') or []
    if (actual.get('Id')!=network_id or actual.get('Internal') is not True or
            not any(row.get('Subnet')==subnet and row.get('Gateway')==gateway for row in ipam) or
            (actual.get('Options') or {}).get('com.docker.network.bridge.name',interface)!=interface):
        raise ValueError('Repair network differs from measured internal bridge')
    container=inspect('--type','container',relay['name'])
    attached=(container.get('NetworkSettings') or {}).get('Networks') or {}
    mounts=container.get('Mounts') or []
    if (container.get('Id')!=relay['containerId'] or container.get('Image')!=relay['imageDigest'] or
            (container.get('State') or {}).get('Running') is not True or
            not all(name in attached for name in (config['network'],relay['uplinkNetwork'])) or
            relay['alias'] not in (attached[config['network']].get('Aliases') or []) or
            not any(m.get('Source')==str(config_path) and
                    m.get('Destination')=='/etc/caddy/Caddyfile' and m.get('RW') is False
                    for m in mounts)):
        raise ValueError('Repair relay differs from measured container and read-only config')
    sandbox=['docker','run','--rm','--pull','never','--network',config['network'],
            '--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
            '--pids-limit','32','--memory','128m','--cpus','0.25',
            '--user','65532:65532']
    host_probe=['curl','--noproxy','*','--silent','--show-error','--max-time','3',
                '--connect-timeout','2','--output','/dev/null','--write-out','%{http_code}',
                'http://'+gateway+':8000/health']
    def require_host_gateway_healthy():
        result=subprocess.run(host_probe,env=docker_env(config),capture_output=True,
                              text=True,timeout=8)
        if result.returncode!=0 or result.stdout.strip()!='200':
            raise ValueError('Repair bridge gateway host positive control is unavailable')
    require_host_gateway_healthy()
    denied=subprocess.run([*sandbox,'--entrypoint','node',image_id,'-e',
                           GATEWAY_SOCKET_PROBE,gateway],env=docker_env(config),
                          capture_output=True,text=True,timeout=20)
    try:
        result=json.loads(denied.stdout.strip()) if denied.returncode==0 else None
    except ValueError:
        result=None
    if (not isinstance(result,dict) or result.get('status')!='socket_error' or
            result.get('code') not in {'ECONNREFUSED','EHOSTUNREACH','ENETUNREACH'}):
        raise ValueError('Repair bridge gateway socket denial is not established')
    require_host_gateway_healthy()
    common=[*sandbox,'--entrypoint','curl',image_id,
            '--noproxy','*','--silent','--show-error','--max-time','3',
            '--connect-timeout','2','--output','-','--write-out','\n%{http_code}']
    reached=subprocess.run([*common,'--header','Content-Type: application/json',
                            '--header','Authorization: Bearer invalid-preflight',
                            '--data','{}',relay['url']+'/responses'],env=docker_env(config),
                           capture_output=True,text=True,timeout=20)
    if reached.returncode!=0 or not reached.stdout.endswith('\n403'):
        raise ValueError('Repair model relay is not reachable through its measured path')
    try:
        body=json.loads(reached.stdout.rsplit('\n',1)[0])
    except ValueError:
        raise ValueError('Repair model relay did not return broker JSON') from None
    if body.get('error',{}).get('message')!='Invalid model capability':
        raise ValueError('Repair model relay did not reach the task broker')
    return {'networkId':network_id,'relayContainerId':relay['containerId'],
            'gatewayDenied':True,'gatewaySocketError':result['code'],
            'hostGatewayHealthyBeforeAndAfter':True,'modelRelayReachable':True}


class RepairExecutor:
    def __init__(self, config):
        self.config = config
        self.jobs = {}
        self._lock = threading.Lock()

    def start(self, mission, on_event):
        job_id = uuid.uuid4().hex
        state = {'jobId': job_id, 'state': 'preparing', 'executor': 'isolated-codex', 'startedAt': time.time()}
        self.jobs[job_id] = state
        process = None
        try:
            image = self.config.get('image')
            network = self.config.get('network')
            if not image or not network or not self.config.get('networkVerified'):
                raise ValueError('Measured isolated repair image and broker-only network required')
            if not mission.get('approvalId') or mission.get('allowedPaths') != ['payment_app/']:
                raise ValueError('Presenter repair approval and exact allowlist required')
            if float(mission['expiresAt']) <= time.time():
                raise ValueError('Repair authority expired')
            if not re.fullmatch(r'[a-f0-9]{64}', mission.get('verificationContractDigest', '')):
                raise ValueError('Pinned verification contract required')
            image_info = subprocess.run(['docker', 'image', 'inspect', image], env=docker_env(self.config), check=True, capture_output=True, text=True, timeout=20)
            state['imageId'] = json.loads(image_info.stdout)[0]['Id']
            state['boundaryEvidence']=validate_boundary_evidence(self.config,state['imageId'])
            state['boundaryPreflight']=preflight_repair_boundary(self.config,state['imageId'],state['boundaryEvidence'])
            root = Path(mission['artifactDir']).resolve() / job_id
            root.mkdir(parents=True, mode=0o700)
            original = prepare_candidate(mission['repoPath'], mission['baseCommit'], root/'base')
            workspace = prepare_candidate(mission['repoPath'], mission['baseCommit'], root/'workspace')
            # Development orchestration is never inherited by the runtime agent.
            for tree in (original, workspace):
                for instructions in tree.rglob('AGENTS.md'):
                    instructions.unlink()
            writable = workspace/'payment_app'
            if not writable.is_dir():
                raise ValueError('Base commit lacks payment application')
            for path in [writable, *writable.rglob('*')]:
                path.chmod(0o777 if path.is_dir() else 0o666)
            home = root/'home'; home.mkdir(mode=0o777); home.chmod(0o777)
            codex = home/'.codex'; codex.mkdir(mode=0o777); codex.chmod(0o777)
            # All config is new. No developer auth.json, plugins, MCP or skills are mounted.
            config = ('model = '+json.dumps(mission.get('model', 'gpt-6-sol'))+'\nmodel_provider = "broker"\n'
                      'model_reasoning_effort = "medium"\nweb_search = "disabled"\n'
                      '[model_providers.broker]\nname = "Task broker"\n'
                      'base_url = '+json.dumps(mission['modelBaseUrl'])+'\nwire_api = "responses"\nenv_key = "VIBESECUR_MODEL_TOKEN"\n')
            (codex/'config.toml').write_text(config)
            env_file = root/'lease.env'
            token = mission['modelToken']
            if '\n' in token or '\r' in token:
                raise ValueError('Invalid task lease')
            env_file.write_text('VIBESECUR_MODEL_TOKEN='+token+'\n'); env_file.chmod(0o600)
            name = 'vs-repair-'+job_id
            state.update(containerName=name, artifactDir=str(root), eventsPath=str(root/'events.jsonl'))
            prompt = ('Repair the seeded payment API approval snapshot defect. Only edit payment_app/app.py. '
                      'Keep the patch confined to the approved = any(...) expression inside payment(). '
                      'Compare every one of the ten approved Transaction fields to the command there, '
                      'using an inline tuple of those field names. Add no helper, import, network call, '
                      'environment-dependent branch, or unrelated edit. Preserve valid payments and retries. '
                      'The trusted effect store remains authoritative. Do not edit dependencies, tests, contracts or infrastructure. '
                      'Produce the source fix; the independent supervisor verifies it separately.\n'
                      + str(mission.get('instructions', '')))
            budget = max(1, min(int(self.config.get('timeoutSeconds',600)),600,int(float(mission['expiresAt'])-time.time())))
            argv = ['docker','run','--pull','never','--init','--stop-timeout','5','--rm','--name',name,'--network',network,'--user','65532:65532',
                    '--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--pids-limit','128',
                    '--memory',self.config.get('memory','768m'),'--cpus','0.75',
                    '--tmpfs','/tmp:rw,nosuid,nodev,size=128m',
                    '--mount',f'type=bind,src={workspace},dst=/workspace,readonly',
                    '--mount',f'type=bind,src={writable},dst=/workspace/payment_app',
                    '--mount',f'type=bind,src={home},dst=/home/repair',
                    '--env','HOME=/home/repair','--env','CODEX_HOME=/home/repair/.codex',
                    '--env','PYTHONDONTWRITEBYTECODE=1','--env-file',str(env_file),'-w','/workspace',image,
                    'timeout','--signal=TERM','--kill-after=5s',str(budget),'codex','exec','--json','--skip-git-repo-check','--sandbox','danger-full-access',prompt]
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=docker_env(self.config))
            state.update(state='running', pid=process.pid)
            on_event({'kind':'repair.started','jobId':job_id,'executor':'isolated-codex','pid':process.pid})
            selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
            deadline = min(time.monotonic()+min(int(self.config.get('timeoutSeconds',600)),600), time.monotonic()+float(mission['expiresAt'])-time.time())
            buffer = b''; written = 0
            with (root/'events.jsonl').open('w') as events:
                while process.poll() is None or selector.get_map():
                    if state.get('state') == 'cancelled' or time.monotonic() >= deadline:
                        self._kill(name)
                        state['state'] = 'cancelled' if state.get('state') == 'cancelled' else 'timed_out'
                        break
                    for key, _ in selector.select(timeout=0.25):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj); continue
                        buffer += chunk
                        if len(buffer) > 2_000_000:
                            raise ValueError('Runtime event line exceeds budget')
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n',1)
                            clean = line.decode(errors='replace').replace(token,'[task lease redacted]')
                            try: payload = json.loads(clean)
                            except ValueError: payload = {'type':'runtime.output','text':clean}
                            event = {'kind':'repair.runtime','jobId':job_id,'source':'codex-jsonl','data':payload}
                            encoded = json.dumps(event)+'\n'; written += len(encoded)
                            if written > 10_000_000:
                                raise ValueError('Runtime event artifact exceeds budget')
                            events.write(encoded); events.flush(); on_event(event)
                process.wait(timeout=15)
            selector.close()
            env_file.unlink(missing_ok=True)
            state['exitCode'] = process.returncode
            if state['state'] in {'cancelled','timed_out'}:
                return dict(state)
            if process.returncode != 0:
                state.update(state='failed', reason='Isolated Codex exited unsuccessfully')
                return dict(state)
            patch = collect_patch(original,workspace)
            if token in patch:
                raise ValueError('Candidate contains its task lease')
            patch_path = root/'patch.diff'; patch_path.write_text(patch)
            state.update(state='candidate',patchPath=str(patch_path),artifactDigest=hashlib.sha256(patch.encode()).hexdigest())
        except (ValueError,KeyError,OSError,subprocess.SubprocessError) as exc:
            if state.get('containerName'):
                self._kill(state['containerName'])
            state.update(state='blocked' if process is None else 'failed', reason=str(exc)[:1000])
        finally:
            if state.get('artifactDir'):
                (Path(state['artifactDir'])/'lease.env').unlink(missing_ok=True)
            state['finishedAt'] = time.time()
        return dict(state)

    def _kill(self, name):
        subprocess.run(['docker','rm','-f',name], env=docker_env(self.config), capture_output=True, timeout=20)

    def status(self, job_id):
        return dict(self.jobs[job_id])

    def cancel(self, job_id):
        state = self.jobs[job_id]
        state['state'] = 'cancelled'
        if state.get('containerName'):
            self._kill(state['containerName'])

    def collect_artifacts(self, job_id):
        return {k:v for k,v in self.jobs[job_id].items() if k in {'jobId','artifactDir','patchPath','eventsPath','artifactDigest','state','exitCode'}}
