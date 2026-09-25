#!/usr/bin/env python3
"""Build only the existing verified patch with the promotion operator's argv.

Run as a transient unit with the API service's filesystem and privilege
restrictions. This never replaces a payment container or changes compensation.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from vibesecur.repair import prepare_candidate, validate_patch


BASE = '9e161acb3609e55a8e3823deaf29e29b81f60c90'
BASE_IMAGE = 'sha256:01910ba6d1a5dc0a8fac9b62a8985ca24651098fb597b8074277c4888da22f91'
PATCH = Path('/srv/vibesecur/data/artifacts/93daf47ad072432cb539c49d7864147f/patch.diff')
PATCH_SHA = '6bf95a3cc990fa5d7ba0ca77a6501faeb5416427c0e4ab43433d55cdd02f3a08'
EXPECTED_SOURCE = '117259a70c41a35b05e6d0f6e99ca53ac464a1b047be00d71f289cb06f353462'
OUTPUT = Path('/srv/vibesecur/data/artifacts/promotion-build-diagnostic-run43-fixed')


def run(stage, argv, *, timeout=30, docker_config=None):
    started = time.monotonic()
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
    if docker_config is not None:
        environment['DOCKER_CONFIG'] = str(docker_config)
    process = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                             env=environment)
    (OUTPUT / (stage + '.stdout.log')).write_text(process.stdout)
    (OUTPUT / (stage + '.stderr.log')).write_text(process.stderr)
    return {'stage': stage, 'exitCode': process.returncode,
            'elapsedSeconds': round(time.monotonic()-started, 3),
            'stdoutSha256': hashlib.sha256(process.stdout.encode()).hexdigest(),
            'stderrSha256': hashlib.sha256(process.stderr.encode()).hexdigest()}


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = {'runId': 'run-43f6cd527523477082f9156ef413470d',
              'jobId': '93daf47ad072432cb539c49d7864147f',
              'baseCommit': BASE, 'baseImageDigest': BASE_IMAGE,
              'artifactDigest': PATCH_SHA, 'sourceSha256': EXPECTED_SOURCE,
              'serviceMutation': False, 'stages': []}
    try:
        patch_bytes = PATCH.read_bytes()
        assert hashlib.sha256(patch_bytes).hexdigest() == PATCH_SHA
        patch = patch_bytes.decode('utf-8')
        assert validate_patch(patch) == ['payment_app/app.py']
        with tempfile.TemporaryDirectory(prefix='build-', dir='/srv/vibesecur/data/promotions') as scratch:
            work = Path(scratch)
            candidate = prepare_candidate('/srv/vibesecur/app', BASE, work / 'candidate', patch)
            source = hashlib.sha256((candidate / 'payment_app' / 'app.py').read_bytes()).hexdigest()
            assert source == EXPECTED_SOURCE
            context = work / 'context'
            shutil.copytree(candidate / 'payment_app', context / 'payment_app')
            base_tag = 'vibesecur-payment-base:' + BASE_IMAGE.removeprefix('sha256:')[:24]
            outcome = run('tag', ['docker', 'tag', BASE_IMAGE, base_tag])
            output['stages'].append(outcome)
            if outcome['exitCode']:
                raise RuntimeError('tag_failed')
            base_info = json.loads(subprocess.check_output(
                ['docker', 'image', 'inspect', base_tag],
                env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')}))[0]
            assert base_info['Id'] == BASE_IMAGE
            dockerfile = context / 'Dockerfile'
            dockerfile.write_text('FROM ' + base_tag + '\n'
                                  'COPY --chown=65532:65532 payment_app/ /opt/vibesecur/payment_app/\n')
            image_file = work / 'image-id'
            tag = 'vibesecur-payment-' + PATCH_SHA[:24]
            docker_config = work / 'docker-config'
            docker_config.mkdir(mode=0o700)
            outcome = run('build', ['docker', 'build', '--pull=false', '--network=none',
                                    '--iidfile', str(image_file),
                                    '--label', 'vibesecur.artifact-digest=' + PATCH_SHA,
                                    '--label', 'vibesecur.source-sha256=' + source,
                                    '--label', 'vibesecur.base-commit=' + BASE,
                                    '-f', str(dockerfile), '-t', tag, str(context)], timeout=300,
                          docker_config=docker_config)
            output['stages'].append(outcome)
            if outcome['exitCode']:
                raise RuntimeError('build_failed')
            image_id = image_file.read_text().strip()
            inspected = json.loads(subprocess.check_output(
                ['docker', 'image', 'inspect', image_id],
                env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')}))[0]
            labels = inspected['Config']['Labels']
            output['imageDigest'] = image_id
            output['identityMatched'] = (
                inspected['Id'] == image_id and
                inspected['RootFS']['Layers'][:len(base_info['RootFS']['Layers'])] ==
                base_info['RootFS']['Layers'] and
                labels.get('vibesecur.artifact-digest') == PATCH_SHA and
                labels.get('vibesecur.source-sha256') == source and
                labels.get('vibesecur.base-commit') == BASE)
            output['passed'] = output['identityMatched']
    except Exception as exc:
        output['passed'] = False
        output['errorType'] = type(exc).__name__
        output['errorCode'] = str(exc)[:100] if isinstance(exc, RuntimeError) else 'preflight_failed'
    (OUTPUT / 'result.json').write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({'passed': output['passed'], 'stages': output['stages'],
                      'errorCode': output.get('errorCode'), 'output': str(OUTPUT)}), flush=True)
    raise SystemExit(0 if output['passed'] else 2)


if __name__ == '__main__':
    main()
