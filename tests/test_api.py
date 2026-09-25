import tempfile

from fastapi.testclient import TestClient

from vibesecur.api import create_app


def test_live_worker_requires_full_measured_configuration(monkeypatch, tmp_path):
    import pytest
    import vibesecur.worker as worker_module
    names = {
        'RUNTIME':'openshell', 'IMAGE':'sha256:'+'a'*64,
        'IMAGE_REF':'vibesecur-worker:1.49.5', 'NETWORK':'openshell-docker',
        'NETWORK_VERIFIED':'1', 'BOUNDARY_EVIDENCE':'/tmp/measured-boundary.json',
        'POLICY_TEMPLATE':'/tmp/measured-policy.yaml', 'ARTIFACT_DIR':str(tmp_path/'workers'),
        'APP_URL_TEMPLATE':'http://payment-{environmentId}:8000',
        'MODEL_BASE_URL':'http://host.openshell.internal:8000/model/v1',
        'MODEL':'openai/gpt-6-sol', 'OPENSHELL_CLI':'/usr/local/bin/openshell',
    }
    monkeypatch.setenv('VIBESECUR_WORKER_RUNTIME','openshell')
    with pytest.raises(ValueError,match='separate provisioned payment gateway'):
        create_app(data_dir=str(tmp_path),access_code='test-presenter-code',
                   public_origin='http://testserver')
    gateway=object()
    with pytest.raises(ValueError,match='Incomplete live worker configuration'):
        create_app(data_dir=str(tmp_path),access_code='test-presenter-code',
                   public_origin='http://testserver',payment_gateway=gateway)
    for suffix,value in names.items():
        monkeypatch.setenv('VIBESECUR_WORKER_'+suffix,value)
    monkeypatch.setenv('VIBESECUR_WORKER_NETWORK_VERIFIED','0')
    with pytest.raises(ValueError,match='measured OpenShell'):
        create_app(data_dir=str(tmp_path),access_code='test-presenter-code',
                   public_origin='http://testserver',payment_gateway=gateway)
    monkeypatch.setenv('VIBESECUR_WORKER_NETWORK_VERIFIED','1')
    captured=[]
    class Adapter:
        def __init__(self,config):
            self.config=config;captured.append(config)
    monkeypatch.setattr(worker_module,'WorkerAdapter',Adapter)
    app=create_app(data_dir=str(tmp_path),access_code='test-presenter-code',
                   public_origin='http://testserver',payment_gateway=gateway)
    assert isinstance(app.state.controller.worker,Adapter)
    assert captured[0]['runtime']=='openshell'
    assert captured[0]['image']==names['IMAGE']
    assert captured[0]['networkVerified'] is True
    assert callable(captured[0]['leaseFactory'])


def test_payment_provisioning_requires_complete_explicit_configuration(monkeypatch, tmp_path):
    import pytest
    monkeypatch.setenv('VIBESECUR_PAYMENT_IMAGE','sha256:'+'a'*64)
    monkeypatch.delenv('PAYMENT_URL_TEMPLATE',raising=False)
    monkeypatch.delenv('VIBESECUR_PAYMENT_NETWORK',raising=False)
    with pytest.raises(ValueError,match='URL template'):
        create_app(data_dir=str(tmp_path),access_code='test-presenter-code',
                   public_origin='http://testserver')
    monkeypatch.setenv('PAYMENT_URL_TEMPLATE','http://payment-{environmentId}:8000')
    with pytest.raises(ValueError,match='image and network'):
        create_app(data_dir=str(tmp_path),access_code='test-presenter-code',
                   public_origin='http://testserver')
    monkeypatch.setenv('VIBESECUR_PAYMENT_NETWORK','openshell-docker')
    import vibesecur.worker as worker
    class Provisioner:
        def __init__(self,config,security):
            self.config=config;self.security=security
    class Gateway:
        def __init__(self,template,provisioner):
            self.template=template;self.provisioner=provisioner
    monkeypatch.setattr(worker,'PaymentServiceProvisioner',Provisioner)
    monkeypatch.setattr(worker,'PaymentGateway',Gateway)
    app=create_app(data_dir=str(tmp_path),access_code='test-presenter-code',
                   public_origin='http://testserver')
    gateway=app.state.controller.payment_gateway
    assert gateway.template=='http://payment-{environmentId}:8000'
    assert gateway.provisioner.config['network']=='openshell-docker'

ORIGIN = 'http://testserver'


def _login(client, code='test-presenter-code'):
    response = client.post('/api/session', json={'accessCode': code}, headers={'Origin': ORIGIN, 'Idempotency-Key': 'login-key'})
    assert response.status_code == 200, response.text
    session = client.get('/api/session').json()
    assert session['authenticated'] is True
    return {'Origin': ORIGIN, 'X-CSRF-Token': session['csrfToken'], 'Idempotency-Key': 'mutation-key'}


def test_presenter_auth_origin_csrf_and_persisted_idempotency():
    with tempfile.TemporaryDirectory() as directory:
        app = create_app(data_dir=directory, access_code='test-presenter-code', public_origin=ORIGIN)
        with TestClient(app) as client:
            assert client.get('/api/session').json() == {'authenticated': False, 'csrfToken': None}
            assert client.post('/api/session', json={'accessCode': 'test-presenter-code'}).status_code == 403
            headers = _login(client)
            assert client.post('/api/runs', json={'mode': 'replay'}, headers={**headers, 'X-CSRF-Token': ''}).status_code == 403
            assert client.post('/api/runs', json={'mode': 'replay'}, headers={**headers, 'Origin': 'https://evil.example'}).status_code == 403
            assert client.post('/api/runs', json={'mode': 'replay'}, headers={k:v for k,v in headers.items() if k != 'Idempotency-Key'}).status_code == 400
            first = client.post('/api/runs', json={'mode': 'replay'}, headers=headers)
            assert first.status_code == 200, first.text
            second = client.post('/api/runs', json={'mode': 'replay'}, headers=headers)
            assert second.status_code == 200 and second.json()['runId'] == first.json()['runId']
            assert len(client.get('/api/runs').json()) == 1
            assert client.get('/api/runs/'+first.json()['runId']).json()['state'] == 'created'


def test_owner_and_internal_service_scope():
    with tempfile.TemporaryDirectory() as directory:
        app = create_app(data_dir=directory, access_code='test-presenter-code', public_origin=ORIGIN)
        other = app.state.store.create_run('different-owner')
        run = app.state.store.create_run('kae')
        token = app.state.security.issue_service_token(run['baseline']['environmentId'])
        with TestClient(app) as client:
            _login(client)
            assert client.get('/api/runs/'+other['runId']).status_code == 403
            env = run['baseline']['environmentId']
            assert client.get('/internal/environments/'+env).status_code == 403
            response = client.get('/internal/environments/'+env, headers={'Authorization': 'Bearer '+token})
            assert response.status_code == 200 and response.json()['environmentId'] == env
            assert client.get('/internal/environments/'+run['protected']['environmentId'], headers={'Authorization': 'Bearer '+token}).status_code == 403


def test_run_start_requires_presenter_approval_for_attack():
    with tempfile.TemporaryDirectory() as directory:
        app = create_app(data_dir=directory, access_code='test-presenter-code', public_origin=ORIGIN)
        with TestClient(app) as client:
            headers = _login(client)
            created = client.post('/api/runs', json={'mode': 'replay'}, headers=headers).json()
            headers['Idempotency-Key'] = 'start-key'
            started = client.post('/api/runs/'+created['runId']+'/commands/start', json={}, headers=headers)
            assert started.status_code == 200, started.text
            assert started.json()['run']['state'] == 'prepared'
            headers['Idempotency-Key'] = 'attack-key'
            attack = client.post('/api/runs/'+created['runId']+'/commands/attack', json={}, headers=headers)
            assert attack.status_code == 409
            assert app.state.store.get_run(created['runId'])['baseline']['ledger'] == []


def test_deterministic_attack_uses_payment_http_and_trusted_ledgers():
    with tempfile.TemporaryDirectory() as directory:
        app = create_app(data_dir=directory, access_code='test-presenter-code', public_origin=ORIGIN)
        with TestClient(app) as client:
            headers = _login(client)
            run = client.post('/api/runs', json={'mode': 'replay'}, headers=headers).json()
            rid = run['runId']
            headers['Idempotency-Key'] = 'start-attack'
            assert client.post(f'/api/runs/{rid}/commands/start', json={}, headers=headers).status_code == 200
            for name in ('baseline', 'protected'):
                headers['Idempotency-Key'] = f'approve-{name}'
                snapshot = app.state.store.transaction(run[name]['environmentId'])
                approved = client.post(f'/api/runs/{rid}/approve-payment',
                                       json={'environment': name, 'snapshot': snapshot}, headers=headers)
                assert approved.status_code == 200, approved.text
            headers['Idempotency-Key'] = 'attack-payment-http'
            attacked = client.post(f'/api/runs/{rid}/commands/attack', json={}, headers=headers)
            assert attacked.status_code == 200, attacked.text
            result = attacked.json()['run']
            assert result['state'] == 'contained'
            assert result['incident']['status'] == 'reproduced'
            assert result['baseline']['ledger'][0]['transaction']['beneficiaryAccount'] == 'SYNTH-AE-CHANGED-999'
            assert result['protected']['ledger'] == []
            assert {e['data']['environment'] for e in result['events']
                    if e['kind'] == 'deterministic_replay.payment_http'} == {'baseline', 'protected'}
            source = [e for e in result['events'] if e['kind'] == 'source.document_http']
            assert source and source[0]['data']['sha256']
            assert source[0]['data']['provenance'] == 'untrusted_supplier_document'


def test_configured_payment_service_selects_separate_http_gateway(monkeypatch):
    from vibesecur.worker import PaymentGateway
    monkeypatch.setenv('PAYMENT_URL_TEMPLATE','http://payment-{environmentId}:8000')
    with tempfile.TemporaryDirectory() as directory:
        app = create_app(data_dir=directory, access_code='test-presenter-code', public_origin=ORIGIN)
        assert isinstance(app.state.controller.payment_gateway,PaymentGateway)


def test_login_rate_limit_uses_forwarded_client_only_from_trusted_proxy(monkeypatch, tmp_path):
    monkeypatch.setenv('VIBESECUR_TRUSTED_PROXIES', 'testclient')
    app = create_app(data_dir=str(tmp_path), access_code='test-presenter-code',
                     public_origin='http://testserver')

    def attempt(client, forwarded, index):
        return client.post('/api/session', json={'accessCode': 'wrong'},
                           headers={'Origin': 'http://testserver', 'Idempotency-Key': f'login-{index}',
                                    'X-Forwarded-For': forwarded}).status_code

    with TestClient(app) as client:
        assert [attempt(client, '203.0.113.9, 198.51.100.1', i) for i in range(6)] == [401] * 5 + [429]
        assert attempt(client, '198.51.100.2', 6) == 401
    monkeypatch.delenv('VIBESECUR_TRUSTED_PROXIES')
    untrusted = create_app(data_dir=str(tmp_path / 'untrusted'), access_code='test-presenter-code',
                           public_origin='http://testserver')
    with TestClient(untrusted) as client:
        assert [attempt(client, f'198.51.100.{i}', i) for i in range(6)] == [401] * 5 + [429]
