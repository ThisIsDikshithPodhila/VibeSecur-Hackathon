from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
import pytest

from vibesecur.auth import SecurityStore
from vibesecur.model_broker import ModelBroker


@pytest.fixture
def setup(tmp_path):
    security = SecurityStore(str(tmp_path/'security.db'))
    observed = []
    def upstream(request):
        observed.append(request)
        return httpx.Response(200, json={'id': 'provider-1', 'output': [], 'usage': {'total_tokens': 10}})
    app = FastAPI()
    broker = ModelBroker(security, 'https://demo.openai.azure.com/openai/v1', 'server-secret',
                         transport=httpx.MockTransport(upstream))
    app.include_router(broker.router)
    return TestClient(app), security, observed


def test_model_proxy_rejects_invalid_capability_before_network(setup):
    client, security, observed = setup
    response = client.post('/model/v1/responses', json={'model': 'gpt-6-sol', 'input': 'test'})
    assert response.status_code == 403
    assert observed == []


def test_model_proxy_limits_provider_and_keeps_key_server_side(setup):
    client, security, observed = setup
    token = security.issue_model_lease('task', 'gpt-6-sol')
    response = client.post('/model/v1/responses', headers={'Authorization': 'Bearer '+token},
                           json={'model': 'gpt-6-sol', 'input': 'test', 'store': True})
    assert response.status_code == 200
    assert 'server-secret' not in response.text
    assert observed[0].headers['api-key'] == 'server-secret'
    assert str(observed[0].url) == 'https://demo.openai.azure.com/openai/v1/responses'
    import json
    assert json.loads(observed[0].content)['store'] is False


def test_builtin_remote_tools_are_not_an_egress_bypass(setup):
    client, security, observed = setup
    token = security.issue_model_lease('task', 'gpt-6-sol')
    response = client.post('/model/v1/responses', headers={'Authorization': 'Bearer '+token},
                           json={'model': 'gpt-6-sol', 'input': 'test', 'tools': [{'type': 'web_search'}]})
    assert response.status_code == 403
    assert observed == []


def test_local_tool_schema_image_url_name_is_not_an_external_image(setup):
    client, security, observed = setup
    token = security.issue_model_lease('repair', 'gpt-6-sol')
    response = client.post('/model/v1/responses', headers={'Authorization': 'Bearer '+token},
                           json={'model':'gpt-6-sol','input':'repair local source',
                                 'tools':[{'type':'function','name':'local_editor',
                                           'parameters':{'type':'object','properties':{
                                               'items':{'type':'array','items':{'type':'object',
                                                   'properties':{'image_url':{'type':'string'}}}}}}}]})
    assert response.status_code == 200
    assert len(observed) == 1


def test_real_remote_image_input_remains_blocked_with_local_tool_schema(setup):
    client, security, observed = setup
    token = security.issue_model_lease('repair', 'gpt-6-sol')
    response = client.post('/model/v1/responses', headers={'Authorization': 'Bearer '+token},
                           json={'model':'gpt-6-sol',
                                 'input':[{'role':'user','content':[{'type':'input_image',
                                     'image_url':'https://untrusted.example/image.png'}]}],
                                 'tools':[{'type':'function','name':'local_editor',
                                           'parameters':{'type':'object','properties':{
                                               'image_url':{'type':'string'}}}}]})
    assert response.status_code == 403
    assert observed == []


def test_local_namespace_tools_allowed_but_nested_remote_tool_rejected(setup):
    client, security, observed = setup
    token = security.issue_model_lease('repair', 'gpt-6-sol')
    local={'type':'namespace','name':'functions','tools':[
        {'type':'function','name':'shell','parameters':{'type':'object','properties':{
            'image_url':{'type':'string'}}}}]}
    headers={'Authorization':'Bearer '+token}
    allowed=client.post('/model/v1/responses',headers=headers,
                        json={'model':'gpt-6-sol','input':'repair','tools':[local]})
    assert allowed.status_code==200
    assert len(observed)==1
    denied=client.post('/model/v1/responses',headers=headers,
                       json={'model':'gpt-6-sol','input':'repair','tools':[
                           {'type':'namespace','name':'functions','tools':[
                               {'type':'web_search','name':'hosted_search'}]}]})
    assert denied.status_code==403
    assert len(observed)==1


@pytest.mark.parametrize('tool',[
    {'type':'function','name':'local_editor','file_url':'https://outside.example/file'},
    {'type':'function','name':'local_editor',
     'metadata':{'file_url':'https://outside.example/file'}},
    {'type':'namespace','name':'functions','metadata':{'file_url':'https://outside.example/file'},
     'tools':[{'type':'function','name':'shell'}]},
    {'type':'namespace','name':'functions','tools':[
        {'type':'function','name':'shell','metadata':{'file_url':'https://outside.example/file'}}]},
    {'type':'function','name':'local_editor','parameters':{
        'type':'object','properties':{'file_url':{'type':'string'}},
        'default':{'file_url':'https://outside.example/file'}}},
])
def test_remote_locator_in_tool_metadata_is_blocked_before_upstream(setup,tool):
    client, security, observed=setup
    token=security.issue_model_lease('repair','gpt-6-sol')
    response=client.post('/model/v1/responses',
                         headers={'Authorization':'Bearer '+token},
                         json={'model':'gpt-6-sol','input':'repair local source','tools':[tool]})
    assert response.status_code==403
    assert observed==[]
