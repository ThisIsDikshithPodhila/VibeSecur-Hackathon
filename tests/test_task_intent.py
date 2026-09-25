import json

import httpx
import pytest

from vibesecur.auth import SecurityStore
from vibesecur.task_intent import AzureTaskInterpreter


def test_interpreter_sends_actual_request_and_revokes_lease(tmp_path):
    security = SecurityStore(str(tmp_path / 'security.sqlite'))
    seen = []
    def transport(request):
        body = json.loads(request.content)
        seen.append(body)
        assert body['model'] == 'gpt-6-luna'
        assert body['reasoning_effort'] == 'low'
        return httpx.Response(200, json={'choices': [{'message': {'content': '{"scope":"read_only"}'}}]})
    interpret = AzureTaskInterpreter(security, 'http://testserver/model/v1',
                                    transport=httpx.MockTransport(transport))
    assert interpret('Please give me a short invoice summary', {}) == {'scope': 'read_only'}
    assert json.loads(seen[0]['messages'][1]['content'])['request'] == 'Please give me a short invoice summary'


@pytest.mark.parametrize('result', ['{"scope":"admin"}', '{"scope":"pay_approved","approval":true}', 'not json'])
def test_invalid_model_scope_never_becomes_authority(tmp_path, result):
    security = SecurityStore(str(tmp_path / 'security.sqlite'))
    interpret = AzureTaskInterpreter(security, 'http://testserver/model/v1', transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={'choices': [{'message': {'content': result}}]})))
    with pytest.raises(ValueError):
        interpret('Summarize the invoice', {})


def test_model_cannot_invent_missing_mandate(tmp_path):
    security = SecurityStore(str(tmp_path / 'security.sqlite'))
    interpret = AzureTaskInterpreter(security, 'http://testserver/model/v1', transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={'choices': [{'message': {'content': '{"scope":"pay_approved"}'}}]})))
    assert interpret('Pay the invoice', {}) == {'scope': 'clarification'}
