#!/usr/bin/env python3
"""Exercise hosted broker admission functions without a lease or provider call."""
import hashlib
import json
from pathlib import Path

from vibesecur.auth import SecurityError
from vibesecur.model_broker import local_tools_only, validate_external_features, validate_tool_features


def rejected(operation):
    try:
        operation()
    except SecurityError:
        return True
    return False


def main():
    local = {'type': 'namespace', 'name': 'functions', 'tools': [
        {'type': 'function', 'name': 'shell', 'parameters': {'type': 'object',
            'properties': {'image_url': {'type': 'string'}}}}]}
    remote_tool = {'type': 'namespace', 'name': 'functions', 'tools': [
        {'type': 'web_search', 'name': 'hosted_search'}]}
    metadata = {'type': 'function', 'name': 'local_editor',
                'metadata': {'file_url': 'https://outside.example/file'}}
    checks = {
        'localNamespaceAccepted': local_tools_only([local]),
        'localSchemaAccepted': not rejected(lambda: validate_tool_features(local)),
        'hostedToolDenied': not local_tools_only([remote_tool]),
        'remoteMetadataDenied': rejected(lambda: validate_tool_features(metadata)),
        'remoteInputImageDenied': rejected(lambda: validate_external_features(
            {'input': [{'type': 'input_image',
                        'image_url': 'https://untrusted.example/image.png'}]})),
    }
    source = Path('/srv/vibesecur/app/vibesecur/model_broker.py')
    result = {'passed': all(checks.values()), 'mode': 'hosted_local_admission_only',
              'providerCalls': 0, 'brokerSha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'checks': checks}
    output = Path('/srv/vibesecur/app/artifacts/gates/broker-local-admission.json')
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    raise SystemExit(0 if result['passed'] else 2)


if __name__ == '__main__':
    main()
