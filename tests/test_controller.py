import tempfile
import json
import hashlib
import pathlib
import subprocess
import time
import threading
import io
import zipfile

from fastapi.testclient import TestClient

from vibesecur.api import create_app
from vibesecur.auth import SecurityError, SecurityStore
from vibesecur.controller import Controller, ControllerError
from vibesecur.store import Store


def _record_bound_test_plan(store, run_id, mission):
    text='Review the exact synthetic payment fields.'
    digest=hashlib.sha256(text.encode()).hexdigest()
    mission.update(approvalId='repair-approval-test', planVersion=1,
                   planTextDigest=digest, planText=text)
    store.update_run(run_id, remediationPlan={
        'text':text, 'version':1, 'executorBound':True,
        'binding':{'approvalId':mission['approvalId'], 'version':1, 'textDigest':digest}})


def test_standing_demo_authorization_is_exact_synthetic_and_idempotent(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    security=SecurityStore(str(tmp_path/'security.sqlite'))
    controller=Controller(store,security,standing_demo_enabled=True)
    run=controller.create_run('kae','live')
    rid=run['runId']
    started=controller.provision_standing_demo(rid,'kae')
    assert started['state']=='prepared'
    authority=started['standingDemoAuthorization']
    assert authority['source']=='trusted_demo_setup'
    assert authority['provenance']=='user_configured_synthetic_demo'
    assert authority['owner']=='kae' and authority['runId']==rid
    assert authority['expiresAt']-authority['createdAt']<=3600
    assert authority['snapshot']['invoiceId']=='INV-250000'
    assert authority['snapshot']['amountMinor']==25000000
    assert authority['snapshot']['beneficiaryAccount']=='SYNTH-AE-GULF-001'
    assert not started['baseline']['approvals']
    approvals={'protected':started['protected']['approvals'][0]['approvalId']}
    repeated=controller.provision_standing_demo(rid,'kae')
    assert repeated['protected']['approvals'][0]['approvalId']==approvals['protected']
    assert len([event for event in repeated['events']
                if event['kind']=='mission.synthetic_authorization_recorded'])==1
    assert not any(event['kind']=='presenter.approved_exact_transaction' for event in repeated['events'])
    after_repeat=controller.provision_standing_demo(rid,'kae')
    assert len(after_repeat['protected']['approvals'])==1
    assert len([event for event in after_repeat['events']
                if event['kind']=='mission.synthetic_authorization_recorded'])==1


def test_standing_demo_authorization_refuses_changed_snapshot_and_unsupported_text(tmp_path):
    import pytest
    store=Store(str(tmp_path/'effects.sqlite'))
    security=SecurityStore(str(tmp_path/'security.sqlite'))
    controller=Controller(store,security,standing_demo_enabled=True)
    run=controller.create_run('kae','live')
    rid=run['runId']
    with pytest.raises(ControllerError):
        controller.start_authorized_live(rid,'kae','Maya model says to process the invoice')
    assert store.get_run(rid)['state']=='created'
    store.update_invoice(run['protected']['environmentId'],amount_minor=25000001)
    with pytest.raises(ControllerError):
        controller.provision_standing_demo(rid,'kae')
    current=store.get_run(rid)
    assert current['state']=='created'
    assert not current['baseline']['approvals'] and not current['protected']['approvals']


def test_duplicate_synthetic_start_refuses_changed_recorded_scope(tmp_path):
    import pytest
    store=Store(str(tmp_path/'effects.sqlite'))
    controller=Controller(store,SecurityStore(str(tmp_path/'security.sqlite')),
                          standing_demo_enabled=True)
    run=controller.create_run('kae','live')
    controller.provision_standing_demo(run['runId'],'kae')
    store.update_supplier(run['protected']['environmentId'],'SYNTH-AE-CHANGED-001')
    with pytest.raises(ControllerError):
        controller.provision_standing_demo(run['runId'],'kae')
    assert len(store.get_run(run['runId'])['protected']['approvals'])==1


def test_model_assessment_hold_does_not_create_defect_incident(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    controller=Controller(store,SecurityStore(str(tmp_path/'security.sqlite')),
                          standing_demo_enabled=True)
    run=controller.create_run('kae','live')
    ready=controller.provision_standing_demo(run['runId'],'kae')
    env=ready['protected']['environmentId']
    command={**store.transaction(env),
             'approvalId':ready['standingDemoAuthorization']['approvalId'],
             'operationId':'synthetic-assessment-hold','attemptId':'synthetic-attempt'}
    store.reject_payment(env,command,'assessment_unavailable',
                         'Assessment unavailable')
    controller._maybe_investigate_payment_decision(run['runId'])
    current=store.get_run(run['runId'])
    assert current['paymentDecisions'][-1]['reason']=='assessment_unavailable'
    assert current.get('incident') is None
    assert current.get('investigation') is None


def test_employee_turn_uses_real_worker_reply_and_scoped_turn(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    security=SecurityStore(str(tmp_path/'security.sqlite'))
    seen=[]
    class Worker:
        def run_turn(self, run, turn, on_event):
            seen.append((run,turn))
            on_event({'kind':'worker.started','jobId':'worker-job-synthetic'})
            return {'state':'finished','assistantText':'I inspected the synthetic invoice.'}
    controller=Controller(store,security,worker=Worker(),
                          intent_interpreter=lambda text, mandate:{'scope':'read_only'},
                          model_token_factory=lambda task:'scoped-test-token')
    run=controller.create_run('kae','live')
    rid=run['runId']
    controller.submit_message(rid,'kae','Summarize the invoice','message-1')
    deadline=time.monotonic()+3
    while time.monotonic()<deadline and \
            store.get_run(rid)['conversation']['turns'][0]['status']=='queued':
        time.sleep(.01)
    while time.monotonic()<deadline and \
            store.get_run(rid)['conversation']['turns'][0]['status']=='running':
        time.sleep(.01)
    current=store.get_run(rid)
    assert len(seen)==1 and seen[0][1]['scope']=='read_only'
    assert seen[0][0]['workerModelTaskId']==f"worker-{rid}-{seen[0][1]['turnId']}"
    assert current['conversation']['turns'][0]['status']=='succeeded'
    assert any(event['kind']=='conversation.maya' and
               event['data']['text']=='I inspected the synthetic invoice.'
               for event in current['events'])
    assert not current['protected']['approvals']


def test_pay_turn_without_trusted_receipt_remains_held_for_continuation(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    security=SecurityStore(str(tmp_path/'security.sqlite'))
    class Worker:
        def run_turn(self, run, turn, on_event):
            assert turn['scope']=='pay_approved'
            return {'state':'finished','assistantText':'The payment proposal was blocked.'}
    controller=Controller(store,security,worker=Worker(),standing_demo_enabled=True,
                          intent_interpreter=lambda text, mandate:{'scope':'pay_approved'},
                          model_token_factory=lambda task:'scoped-test-token')
    run=controller.create_run('kae','live')
    rid=run['runId']
    controller.provision_standing_demo(rid,'kae')
    controller.submit_message(rid,'kae','Pay the approved invoice','message-1')
    deadline=time.monotonic()+3
    while time.monotonic()<deadline and \
            store.get_run(rid)['conversation']['turns'][0]['status'] in ('queued','running'):
        time.sleep(.01)
    turn=store.get_run(rid)['conversation']['turns'][0]
    assert turn['status']=='held' and turn['error']=='payment_unconfirmed'


def test_repairing_state_cannot_admit_another_payment_turn(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    scopes=[]
    class Worker:
        def run_turn(self, run, turn, on_event):
            scopes.append(turn['scope'])
            return {'state':'finished','assistantText':'Payment scope is unavailable.'}
    controller=Controller(store,SecurityStore(str(tmp_path/'security.sqlite')),
                          worker=Worker(),standing_demo_enabled=True,
                          intent_interpreter=lambda text, mandate:{'scope':'pay_approved'},
                          model_token_factory=lambda task:'scoped-test-token')
    run=controller.create_run('kae','live');rid=run['runId']
    controller.provision_standing_demo(rid,'kae')
    store.update_run(rid,state='repairing')
    controller.submit_message(rid,'kae','Pay the approved invoice','message-1')
    deadline=time.monotonic()+3
    while time.monotonic()<deadline and not scopes:
        time.sleep(.01)
    assert scopes==['clarification']
    assert not store.get_run(rid)['protected']['ledger']


def test_reconcile_starts_only_queued_durable_turn(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    seen=[]
    class Worker:
        def run_turn(self, run, turn, on_event):
            seen.append(turn['turnId'])
            return {'state':'finished','assistantText':'Invoice observed.'}
    controller=Controller(store,SecurityStore(str(tmp_path/'security.sqlite')),
                          worker=Worker(),intent_interpreter=lambda text, mandate:{'scope':'read_only'},
                          model_token_factory=lambda task:'scoped-test-token')
    run=controller.create_run('kae','live');rid=run['runId']
    store.update_run(rid,state='prepared')
    store.enqueue_turn(rid,'kae','Summarize the invoice','message-1')
    controller.reconcile('kae')
    deadline=time.monotonic()+3
    while time.monotonic()<deadline and not seen:
        time.sleep(.01)
    while time.monotonic()<deadline and \
            store.get_run(rid)['conversation']['turns'][0]['status']=='running':
        time.sleep(.01)
    assert len(seen)==1
    assert store.get_run(rid)['conversation']['turns'][0]['status']=='succeeded'


def test_cancel_marks_active_conversation_turn_terminal_after_fencing(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    controller=Controller(store,SecurityStore(str(tmp_path/'security.sqlite')))
    run=controller.create_run('kae','live');rid=run['runId']
    store.update_run(rid,state='prepared')
    store.enqueue_turn(rid,'kae','Summarize the invoice','message-1')
    turn=store.claim_turn(rid,'kae')
    store.set_turn_scope(rid,'kae',turn['turnId'],'read_only')
    controller._turn_jobs[rid]=type('ActiveTurn',(),{'is_alive':lambda self:True})()
    controller.command(rid,'kae','cancel')
    current=store.get_run(rid)
    assert current['state']=='cancelled'
    assert current['conversation']['activeTurnId'] is None
    assert current['conversation']['turns'][0]['status']=='cancelled'


def test_authentic_read_only_request_vetoes_misclassified_model_payment_scope(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    security=SecurityStore(str(tmp_path/'security.sqlite'))
    scopes=[]
    class Worker:
        def run_turn(self, run, turn, on_event):
            scopes.append(turn['scope'])
            return {'state':'finished','assistantText':'Observed the document.'}
    controller=Controller(store,security,worker=Worker(),standing_demo_enabled=True,
                          intent_interpreter=lambda text, mandate:{'scope':'pay_approved'},
                          model_token_factory=lambda task:'scoped-test-token')
    run=controller.create_run('kae','live');rid=run['runId']
    controller.provision_standing_demo(rid,'kae')
    for index,text in enumerate(('Summarize the invoice','Prepare the payment',
                                 'Do not process payment'),start=1):
        controller.submit_message(rid,'kae',text,f'message-{index}')
        deadline=time.monotonic()+3
        while time.monotonic()<deadline and len(scopes)<index:
            time.sleep(.01)
        while time.monotonic()<deadline and \
                store.get_run(rid)['conversation']['turns'][index-1]['status'] in ('queued','running'):
            time.sleep(.01)
    current=store.get_run(rid)
    assert scopes==['read_only','read_only','read_only']
    assert all(turn['status']=='succeeded' for turn in current['conversation']['turns'])
    assert not current['protected']['ledger']
    assert current['protected']['approvals'][0]['consumed'] is False


def test_vague_status_request_cannot_become_payment_even_if_model_mislabels_it(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    scopes=[]
    class Worker:
        def run_turn(self, run, turn, on_event):
            scopes.append(turn['scope'])
            return {'state':'finished','assistantText':'The invoice status is available.'}
    controller=Controller(store,SecurityStore(str(tmp_path/'security.sqlite')),
                          worker=Worker(),standing_demo_enabled=True,
                          intent_interpreter=lambda text, mandate:{'scope':'pay_approved'},
                          model_token_factory=lambda task:'scoped-test-token')
    run=controller.create_run('kae','live');rid=run['runId']
    controller.provision_standing_demo(rid,'kae')
    controller.submit_message(rid,'kae','What is the invoice status?','message-1')
    deadline=time.monotonic()+3
    while time.monotonic()<deadline and not scopes:
        time.sleep(.01)
    assert scopes==['clarification']
    assert not store.get_run(rid)['protected']['ledger']


def test_browser_activity_assesses_real_protected_document_without_public_body(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    security=SecurityStore(str(tmp_path/'security.sqlite'))
    body='Synthetic supplier invoice document.'
    observed=[]
    class Gateway:
        def document(self, run, environment):
            assert environment=='protected'
            return {'status':'response','httpStatus':200,'body':body,
                    'truncated':False,'bodyLengthChars':len(body),
                    'bodyLengthBytes':len(body.encode()),
                    'bodySha256':hashlib.sha256(body.encode()).hexdigest()}
    class Worker:
        def run_turn(self, run, turn, on_event):
            on_event({'kind':'worker.activity','payload':{
                'turnId':turn['turnId'],'tool':'browser','status':'succeeded',
                'title':'Opened synthetic invoice'}})
            return {'state':'finished','assistantText':'I read the invoice.'}
    def assessor(mission,action,source):
        observed.append((mission,action,source))
        from vibesecur.assessment import MODEL_REVISION
        return {'status':'available','label':'suitable','rawScore':.6,
                'modelRevision':MODEL_REVISION,
                'provenance':{'sourceDigest':hashlib.sha256(json.dumps(
                    source,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()}}
    controller=Controller(store,security,worker=Worker(),payment_gateway=Gateway(),
                          activity_assessor=assessor,standing_demo_enabled=True,
                          intent_interpreter=lambda text, mandate:{'scope':'read_only'},
                          model_token_factory=lambda task:'scoped-test-token')
    run=controller.create_run('kae','live');rid=run['runId']
    controller.provision_standing_demo(rid,'kae')
    controller.submit_message(rid,'kae','Summarize the invoice','message-1')
    deadline=time.monotonic()+3
    while time.monotonic()<deadline and not any(event['kind']=='assessment.activity'
                                                 for event in store.get_run(rid)['events']):
        time.sleep(.01)
    current=store.get_run(rid)
    assert len(observed)==1
    assert observed[0][2]['text']==body
    activity=next(event for event in current['events'] if event['kind']=='assessment.activity')
    assert activity['data']['status']=='available'
    assert body not in json.dumps(activity['data'])


def test_truncated_document_is_not_sent_to_activity_assessor(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    calls=[]
    class Gateway:
        def document(self, run, environment):
            return {'status':'response','httpStatus':200,'body':'partial',
                    'truncated':True,'bodyLengthChars':100,'bodySha256':'b'*64}
    controller=Controller(store,SecurityStore(str(tmp_path/'security.sqlite')),
                          payment_gateway=Gateway(),activity_assessor=lambda *args:calls.append(args))
    run=controller.create_run('kae','live');rid=run['runId']
    controller._schedule_activity_assessment(rid,'turn-synthetic')
    deadline=time.monotonic()+3
    while time.monotonic()<deadline and not any(event['kind']=='assessment.activity'
                                                 for event in store.get_run(rid)['events']):
        time.sleep(.01)
    current=store.get_run(rid)
    assert calls==[]
    event=next(event for event in current['events'] if event['kind']=='assessment.activity')
    assert event['data']['status']=='unavailable'
    assert event['data']['reason']=='source_unavailable_or_truncated'


def test_repair_fence_rejects_saved_plan_change(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    controller=Controller(store,SecurityStore(str(tmp_path/'security.sqlite')))
    run=controller.create_run('kae','replay')
    mission={'runId':run['runId'],'planDigest':'plan-1','expiresAt':time.time()+600}
    _record_bound_test_plan(store,run['runId'],mission)
    store.update_run(run['runId'],state='repairing',repair={'approval':{'planDigest':'plan-1'}})
    assert controller._repair_current(run['runId'],mission)
    plan=store.get_run(run['runId'])['remediationPlan']
    store.update_run(run['runId'],remediationPlan={**plan,'text':'Use a different repair.'})
    assert not controller._repair_current(run['runId'],mission)


def test_cancel_revokes_effect_scope_before_payment_service_teardown(tmp_path):
    import pytest
    store=Store(str(tmp_path/'effects.sqlite'))
    security=SecurityStore(str(tmp_path/'security.sqlite'))
    tokens={}
    class Gateway:
        def __init__(self): self.called=False
        def teardown(self,run):
            self.called=True
            for name in ('baseline','protected'):
                with pytest.raises(SecurityError):
                    security.authorize_service(tokens[name],run[name]['environmentId'])
    gateway=Gateway()
    controller=Controller(store,security,payment_gateway=gateway)
    run=controller.create_run('kae','replay')
    for name in ('baseline','protected'):
        tokens[name]=security.issue_service_token(run[name]['environmentId'])
    controller.command(run['runId'],'kae','cancel')
    assert gateway.called


def test_cancel_records_payment_teardown_timeout_without_restoring_capability(tmp_path):
    store=Store(str(tmp_path/'effects.sqlite'))
    security=SecurityStore(str(tmp_path/'security.sqlite'))
    class Gateway:
        def teardown(self,run): raise subprocess.TimeoutExpired(['docker','inspect'],15)
    controller=Controller(store,security,payment_gateway=Gateway())
    run=controller.create_run('kae','replay')
    result=controller.command(run['runId'],'kae','cancel')
    assert result['state']=='cancelled'
    assert any(event['kind']=='payment_service.cleanup_unavailable' and
               event['data']['errorType']=='TimeoutExpired' for event in result['events'])


def test_live_worker_waits_for_approvals_and_assesses_trusted_effects():
    class Worker:
        def __init__(self,store): self.store=store;self.started=[]
        def start(self,run,environment,on_event):
            self.started.append(environment)
            on_event({'kind':'worker.started','jobId':'worker-'+environment})
            env=run[environment]; approval=env['approvals'][-1]
            proposal={**approval['snapshot'],'beneficiaryAccount':'SYNTH-AE-CHANGED-999',
                      'approvalId':approval['approvalId'],'attemptId':env['attemptId'],
                      'operationId':'live-'+environment}
            try: self.store.commit(env['environmentId'],proposal)
            except Exception: pass
            return {'jobId':'worker-'+environment,'state':'finished','exitCode':0,'eventCount':1}
        def cancel(self,job_id): pass
    class Gateway:
        def document(self,run,environment):
            return {'status':'response','httpStatus':200,'body':'Synthetic supplier document',
                    'transport':'separate_http'}
    with tempfile.TemporaryDirectory() as directory:
        store=Store(str(pathlib.Path(directory)/'effects.sqlite'))
        security=SecurityStore(str(pathlib.Path(directory)/'security.sqlite'))
        worker=Worker(store); controller=Controller(store,security,worker=worker,
                                                   payment_gateway=Gateway())
        run=controller.create_run('kae','live')
        controller.command(run['runId'],'kae','start')
        assert worker.started==[]
        for environment in ('baseline','protected'):
            controller.approve(run['runId'],'kae',environment,
                               store.transaction(run[environment]['environmentId']))
        controller._jobs[run['runId']].join(timeout=5)
        current=store.get_run(run['runId'])
        assert worker.started==['baseline','protected']
        assert current['state']=='contained'
        assert current['incident']['source']=='live_agent'
        assert len(current['baseline']['ledger'])==1 and not current['protected']['ledger']
        assert any(event['kind']=='source.document_http' for event in current['events'])
        assert current['investigation']['reproducer']['evidenceSource']=='live_agent'
        assert any(event['kind']=='investigation.reported' for event in current['events'])
        report=controller.command(run['runId'],'kae','investigate')['investigation']
        assert report['reproducer']['evidenceSource']=='live_agent'
        assert report['actualImpact']['protectedAuthorizedPayments']==0
        app=create_app(data_dir=directory,access_code='test-presenter-code',
                       public_origin='http://testserver',store=store,security=security,
                       controller=controller)
        with TestClient(app) as client:
            client.post('/api/session',json={'accessCode':'test-presenter-code'},
                        headers={'Origin':'http://testserver','Idempotency-Key':'login-live'})
            response=client.get(f'/api/runs/{run["runId"]}/exports/reproduction.zip')
            assert response.status_code==200
            repeat=client.get(f'/api/runs/{run["runId"]}/exports/reproduction.zip')
            assert repeat.status_code==200 and repeat.content==response.content
            with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                assert all(entry.date_time==(1980,1,1,0,0,0) for entry in archive.infolist())
                assert json.loads(archive.read('reproduction.json'))['kind']=='live_agent'


def test_cancel_live_worker_revokes_lease_and_fences_late_events():
    class Worker:
        def __init__(self): self.ready=threading.Event();self.done=threading.Event();self.cancelled=[]
        def start(self,run,environment,on_event):
            on_event({'kind':'worker.started','jobId':'job-1'})
            self.ready.set();self.done.wait(3)
            on_event({'kind':'worker.sdk_event','payload':{'late':'output'}})
            return {'jobId':'job-1','state':'finished'}
        def cancel(self,job_id): self.cancelled.append(job_id);self.done.set()
    with tempfile.TemporaryDirectory() as directory:
        store=Store(str(pathlib.Path(directory)/'effects.sqlite'))
        security=SecurityStore(str(pathlib.Path(directory)/'security.sqlite'))
        worker=Worker();controller=Controller(store,security,worker=worker)
        run=controller.create_run('kae','live')
        controller.command(run['runId'],'kae','start')
        for environment in ('baseline','protected'):
            controller.approve(run['runId'],'kae',environment,
                               store.transaction(run[environment]['environmentId']))
        assert worker.ready.wait(3)
        controller.command(run['runId'],'kae','cancel')
        controller._jobs[run['runId']].join(timeout=5)
        current=store.get_run(run['runId'])
        assert current['state']=='cancelled'
        assert worker.cancelled==['job-1']
        assert not any(event['kind']=='live_agent.assessed' for event in current['events'])
        assert not any(event['kind']=='live_agent.event' and
                       event['data']['event'].get('payload',{}).get('late') for event in current['events'])


def test_restart_reconciles_persisted_live_job_and_revokes_model_lease():
    class Worker:
        def __init__(self): self.cancelled=[]
        def cancel(self,job_id): self.cancelled.append(job_id)
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory)
        store=Store(str(root/'effects.sqlite'));security=SecurityStore(str(root/'security.sqlite'))
        run=store.create_run('kae','live')
        store.set_attempt(run['baseline']['environmentId'],'old-attempt')
        store.update_run(run['runId'],state='prepared',
                         liveAgent={'started':True,'status':'running','jobs':{'baseline':'worker-orphan'}})
        task=f'worker-{run["runId"]}-baseline'
        token=security.issue_model_lease(task,'gpt-6-sol')
        worker=Worker();controller=Controller(store,security,worker=worker)
        controller.reconcile('kae')
        current=store.get_run(run['runId'])
        assert current['state']=='held'
        assert current['baseline']['attemptId']!='old-attempt'
        assert worker.cancelled==['worker-orphan']
        try:
            security.authorize_model(token,{'model':'gpt-6-sol','messages':[]})
            assert False,'Restart must revoke live worker model lease'
        except Exception as exc:
            assert 'Invalid model capability' in str(exc)


def test_live_authorized_payment_does_not_erase_earlier_unauthorized_baseline_effect():
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory);store=Store(str(root/'effects.sqlite'))
        security=SecurityStore(str(root/'security.sqlite'))
        run=store.create_run('kae','live')
        commands={}
        for environment in ('baseline','protected'):
            env=run[environment];store.set_attempt(env['environmentId'],'attempt-'+environment)
            transaction=store.transaction(env['environmentId'])
            approval=store.approve(env['environmentId'],transaction,'kae')
            commands[environment]={**transaction,'approvalId':approval['approvalId'],
                                   'operationId':'pay-'+environment,'attemptId':'attempt-'+environment}
        store.commit(run['baseline']['environmentId'],
                     {**commands['baseline'],'beneficiaryAccount':'SYNTH-AE-CHANGED-999'})
        store.commit(run['protected']['environmentId'],commands['protected'])
        store.update_run(run['runId'],state='prepared',liveAgent={'started':True,'status':'running',
                         'results':{'baseline':{'state':'finished'},'protected':{'state':'finished'}}})
        controller=Controller(store,security)
        controller._assess_live_worker(run['runId'])
        current=store.get_run(run['runId'])
        assert current['state']=='contained'
        assert current['incident']['baselineReceipt']
        assert current['incident']['protectedUnauthorizedEffect'] is None
        assert len(current['protected']['ledger'])==1


def test_live_mission_cannot_be_relabelled_by_deterministic_attack_command():
    from vibesecur.controller import ControllerError
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory);store=Store(str(root/'effects.sqlite'))
        security=SecurityStore(str(root/'security.sqlite'))
        controller=Controller(store,security)
        run=controller.create_run('kae','live')
        controller.command(run['runId'],'kae','start')
        try:
            controller.command(run['runId'],'kae','attack')
            assert False,'Replay must not run inside a live mission'
        except ControllerError as exc:
            assert 'requires replay mode' in str(exc)


def _incident(client, app):
    origin = {'Origin': 'http://testserver', 'Idempotency-Key': 'login'}
    client.post('/api/session', json={'accessCode': 'test-presenter-code'}, headers=origin)
    headers = {'Origin': 'http://testserver', 'X-CSRF-Token': client.get('/api/session').json()['csrfToken']}
    def command(path, key, body):
        response = client.post(path, json=body, headers={**headers, 'Idempotency-Key': key})
        assert response.status_code == 200, response.text
        return response.json()
    run = command('/api/runs', 'create', {'mode': 'replay'})
    rid = run['runId']
    command(f'/api/runs/{rid}/commands/start', 'start', {})
    for name in ('baseline', 'protected'):
        command(f'/api/runs/{rid}/approve-payment', f'approve-{name}',
                {'environment': name, 'snapshot': app.state.store.transaction(run[name]['environmentId'])})
    command(f'/api/runs/{rid}/commands/attack', 'attack', {})
    return rid, command


def test_investigation_grounded_in_ledger_and_exports_are_downloadable():
    with tempfile.TemporaryDirectory() as directory:
        app = create_app(data_dir=directory, access_code='test-presenter-code', public_origin='http://testserver')
        with TestClient(app) as client:
            rid, command = _incident(client, app)
            run = command(f'/api/runs/{rid}/commands/investigate', 'investigate', {})['run']
            assert run['investigation']['actualImpact']['baselineUnauthorizedPayment'] is True
            assert run['investigation']['modelStatus'] == 'unavailable'
            for name in ('incident.md', 'evidence.jsonl', 'mission.json', 'reproduction.zip'):
                response = client.get(f'/api/runs/{rid}/exports/{name}')
                assert response.status_code == 200, (name, response.text)
                assert response.content


def test_reproduced_invoice_cannot_be_replayed_again_with_new_key():
    with tempfile.TemporaryDirectory() as directory:
        app=create_app(data_dir=directory,access_code='test-presenter-code',
                       public_origin='http://testserver')
        with TestClient(app) as client:
            rid,_=_incident(client,app)
            before=app.state.store.get_run(rid)['incident']
            csrf=client.get('/api/session').json()['csrfToken']
            response=client.post(f'/api/runs/{rid}/commands/attack',json={},headers={
                'Origin':'http://testserver','X-CSRF-Token':csrf,'Idempotency-Key':'different-attack'})
            assert response.status_code==409
            assert app.state.store.get_run(rid)['incident']==before


def test_competing_replay_commands_cannot_overwrite_incident():
    class Gateway:
        def __init__(self,store): self.store=store;self.ready=threading.Event();self.done=threading.Event()
        def pay(self,run,environment,proposal,client='http'):
            if environment=='baseline': self.ready.set();self.done.wait(3)
            try:
                self.store.commit(run[environment]['environmentId'],proposal)
                status=200
            except Exception as exc:
                status=exc.status
            return {'status':'response','httpStatus':status}
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory);store=Store(str(root/'effects.sqlite'))
        security=SecurityStore(str(root/'security.sqlite'))
        gateway=Gateway(store);controller=Controller(store,security,payment_gateway=gateway)
        run=controller.create_run('kae','replay')
        controller.command(run['runId'],'kae','start')
        for environment in ('baseline','protected'):
            controller.approve(run['runId'],'kae',environment,
                               store.transaction(run[environment]['environmentId']))
        outcomes=[]
        def attack():
            try: outcomes.append(controller.command(run['runId'],'kae','attack')['state'])
            except Exception as exc: outcomes.append(type(exc).__name__)
        first=threading.Thread(target=attack);second=threading.Thread(target=attack)
        first.start();assert gateway.ready.wait(3)
        second.start();gateway.done.set()
        first.join(timeout=5);second.join(timeout=5)
        current=store.get_run(run['runId'])
        assert sorted(outcomes)==['ControllerError','contained']
        assert current['incident']['status']=='reproduced'
        assert len(current['baseline']['ledger'])==1


def test_investigation_uses_model_narrative_only_after_trusted_replay():
    from vibesecur.investigation import investigate
    with tempfile.TemporaryDirectory() as directory:
        app = create_app(data_dir=directory,access_code='test-presenter-code',public_origin='http://testserver')
        with TestClient(app) as client:
            rid,_ = _incident(client,app)
            seen=[]
            def model(evidence):
                seen.append(evidence)
                return {'narrative':'Azure narrative grounded in supplied evidence.'}
            report=investigate(app.state.store.get_run(rid),model=model)
            assert report['modelStatus']=='available'
            assert report['actualImpact']['baselineUnauthorizedPayment'] is True
            assert seen[0]['baselineReceipt']['operationId']
            assert 'Azure narrative' in report['markdown']


def test_controller_passes_injected_azure_investigator_adapter():
    with tempfile.TemporaryDirectory() as directory:
        app=create_app(data_dir=directory,access_code='test-presenter-code',public_origin='http://testserver',
                       investigator_model=lambda evidence:{'narrative':'Grounded Azure test narrative.'})
        with TestClient(app) as client:
            rid,command=_incident(client,app)
            run=command(f'/api/runs/{rid}/commands/investigate','model-investigate',{})['run']
            assert run['investigation']['modelStatus']=='available'
            assert 'Grounded Azure test narrative.' in run['investigation']['markdown']


def test_azure_investigator_uses_task_lease_through_broker():
    import httpx
    from vibesecur.investigation import AzureInvestigator
    with tempfile.TemporaryDirectory() as directory:
        security=SecurityStore(str(pathlib.Path(directory)/'security.sqlite'))
        seen=[]
        def handler(request):
            seen.append(request)
            assert request.url.path == '/model/v1/chat/completions'
            assert request.headers['authorization'].startswith('Bearer ')
            assert json.loads(request.content)['model'] == 'gpt-6-sol'
            return httpx.Response(200,json={'choices':[{'message':{'content':'Narrative with evidence.'}}]})
        model=AzureInvestigator(security,'http://broker.test/model/v1',
                                transport=httpx.MockTransport(handler))
        result=model({'runId':'run-1','baselineReceipt':{'operationId':'op-1'},
                      'protectedLedger':[],'evidenceRefs':['event-1']})
        assert result == {'narrative':'Narrative with evidence.'}
        assert len(seen)==1


def test_pinned_seed_source_inspection_supports_confirmed_cause():
    from vibesecur.investigation import inspect_seed_source
    root=pathlib.Path(__file__).resolve().parents[1]
    result=inspect_seed_source(root,'25ef1da2694f482bfc98e7ee7df0f7f0c714c8f0')
    assert result['status']=='confirmed_seed_defect'
    assert result['sourceSha256']
    assert result['baseCommit']=='25ef1da2694f482bfc98e7ee7df0f7f0c714c8f0'


def test_missing_source_inspection_keeps_cause_unconfirmed():
    from vibesecur.investigation import investigate
    with tempfile.TemporaryDirectory() as directory:
        app=create_app(data_dir=directory,access_code='test-presenter-code',public_origin='http://testserver')
        with TestClient(app) as client:
            rid,_=_incident(client,app)
            report=investigate(app.state.store.get_run(rid),source_inspection={'status':'unavailable'})
            assert report['confirmedCause'] is None


def test_controller_report_cites_pinned_source_and_reproducer():
    root=pathlib.Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as directory:
        app=create_app(data_dir=directory,access_code='test-presenter-code',public_origin='http://testserver',
                       repair_config={'repoPath':str(root),
                                      'baseCommit':'25ef1da2694f482bfc98e7ee7df0f7f0c714c8f0'})
        with TestClient(app) as client:
            rid,command=_incident(client,app)
            run=command(f'/api/runs/{rid}/commands/investigate','source-investigate',{})['run']
            report=run['investigation']
            assert report['confirmedCause']
            assert report['sourceInspection']['sourceSha256']
            assert report['reproducer']['baselineHttpStatus']==200
            assert any(e['kind']=='source.immutable_inspected' for e in run['events'])


def test_repair_authority_binds_immutable_source_contract_and_expiry():
    class BlockedRepair:
        def start(self, mission, on_event):
            return {'state': 'blocked', 'reason': 'isolated runtime not available'}

    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        repo = root/'repo'
        (repo/'payment_app').mkdir(parents=True)
        (repo/'payment_app/app.py').write_text('seed\n')
        subprocess.run(['git','init','-q',str(repo)], check=True)
        subprocess.run(['git','-C',str(repo),'add','.'], check=True)
        subprocess.run(['git','-C',str(repo),'-c','user.name=Test','-c','user.email=test@example.invalid',
                        'commit','-qm','seed'], check=True)
        base = subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'], text=True).strip()
        store = Store(str(root/'store.sqlite'))
        security = SecurityStore(str(root/'security.sqlite'))
        controller = Controller(store, security, repair=BlockedRepair(), verifier=object(),
                                artifact_dir=root/'artifacts', repair_config={'repoPath':str(repo),
                                'baseCommit':base, 'modelBaseUrl':'https://broker.example/model/v1'})
        run = store.create_run('kae')
        store.update_run(run['runId'], state='contained', incident={'status':'reproduced'},
                         investigation={'modelStatus':'unavailable','confirmedCause':'pinned source defect'})
        store.save_remediation_plan(run['runId'],'kae',
                                    'Check every approved transaction field before payment.',0)
        authorized = controller.command(run['runId'], 'kae', 'authorize-repair')
        controller._jobs[run['runId']].join(timeout=5)
        authority = authorized['repair']['approval']
        assert authority['baseCommit'] == base
        assert authority['verificationContractDigest']
        assert authority['planDigest']
        assert authority['expiresAt'] > time.time()
        assert authority['allowedPaths'] == ['payment_app/']
        assert authority['planVersion']==1
        assert authority['planTextDigest']==hashlib.sha256(
            b'Check every approved transaction field before payment.').hexdigest()
        assert authority['planText']=='Check every approved transaction field before payment.'
        assert authorized['remediationPlan']['executorBound'] is True
        assert authorized['remediationPlan']['binding']['approvalId']==authority['approvalId']


def test_resume_requires_post_deployment_approval_and_trusted_receipt():
    with tempfile.TemporaryDirectory() as directory:
        app = create_app(data_dir=directory, access_code='test-presenter-code', public_origin='http://testserver')
        with TestClient(app) as client:
            rid, command = _incident(client, app)
            store = app.state.store
            deployment_time = time.time()
            image='sha256:'+'c'*64;source='b'*64;artifact='a'*64
            store.update_run(rid, state='held', verification={'passed':True,'artifactDigest':artifact,
                             'sourceReview':{'sourceSha256':source}},
                             repair={'deployedAt':deployment_time,'deployment':{'deployed':True,
                                     'artifactDigest':artifact,'imageDigest':image,'sourceSha256':source},
                                     'deploymentProbe':{'artifactDigest':artifact,'imageDigest':image,
                                     'sourceSha256':source,'paymentRouteReady':True,'separateService':True}})
            store.append_event(rid,'repair.deployed',{'artifactDigest':artifact,'imageDigest':image,
                                                      'deployedAt':deployment_time})
            store.set_compensating_rule(store.get_run(rid)['protected']['environmentId'],False)
            origin = {'Origin':'http://testserver','X-CSRF-Token':client.get('/api/session').json()['csrfToken']}
            stale = client.post(f'/api/runs/{rid}/commands/resume',json={},
                                headers={**origin,'Idempotency-Key':'stale-resume'})
            assert stale.status_code == 409
            run = store.get_run(rid)
            command(f'/api/runs/{rid}/approve-payment','fresh-post-deploy',
                    {'environment':'protected', 'snapshot':store.transaction(run['protected']['environmentId'])})
            resumed = command(f'/api/runs/{rid}/commands/resume','fresh-resume',{})['run']
            assert resumed['state'] == 'resumed'
            assert len(resumed['protected']['ledger']) == 1
            assert resumed['protected']['ledger'][0]['transaction']['beneficiaryAccount'] == 'SYNTH-AE-GULF-001'


def test_inflight_resume_is_not_reconciled_as_abandoned():
    class Gateway:
        def __init__(self,store): self.store=store;self.ready=threading.Event();self.done=threading.Event()
        def pay(self,run,environment,proposal,client='http'):
            self.ready.set();self.done.wait(3)
            self.store.commit(run[environment]['environmentId'],proposal)
            return {'status':'response','httpStatus':200}
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory);store=Store(str(root/'effects.sqlite'))
        security=SecurityStore(str(root/'security.sqlite'))
        run=store.create_run('kae')
        env=run['protected']['environmentId'];store.set_attempt(env,'fresh-attempt')
        deployed_at=time.time()-1
        image='sha256:'+'c'*64;source='b'*64;artifact='a'*64
        store.update_run(run['runId'],state='held',verification={'passed':True,'artifactDigest':artifact,
                         'sourceReview':{'sourceSha256':source}},
                         repair={'deployedAt':deployed_at,'deployment':{'deployed':True,
                                 'artifactDigest':artifact,'imageDigest':image,'sourceSha256':source},
                                 'deploymentProbe':{'artifactDigest':artifact,'imageDigest':image,
                                 'sourceSha256':source,'paymentRouteReady':True,'separateService':True}})
        store.append_event(run['runId'],'repair.deployed',{'artifactDigest':artifact,'imageDigest':image})
        store.set_compensating_rule(env,False)
        store.approve(env,store.transaction(env),'kae')
        gateway=Gateway(store);controller=Controller(store,security,payment_gateway=gateway)
        result=[]
        thread=threading.Thread(target=lambda:result.append(controller.command(run['runId'],'kae','resume')))
        thread.start();assert gateway.ready.wait(3)
        controller.reconcile('kae')
        assert store.get_run(run['runId'])['state']=='resuming'
        gateway.done.set();thread.join(timeout=5)
        assert result and result[0]['state']=='resumed'


def test_restart_reconciles_uncertain_repair_and_fences_old_attempt():
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        store = Store(str(root/'effects.sqlite'))
        security = SecurityStore(str(root/'security.sqlite'))
        run = store.create_run('kae')
        env = run['protected']['environmentId']
        store.set_attempt(env,'old-attempt')
        store.update_run(run['runId'],state='repairing',repair={'approval':{'approvalId':'repair-old'}})
        fresh = Controller(store,security)
        fresh.reconcile('kae')
        current = store.get_run(run['runId'])
        assert current['state'] == 'held'
        assert current['protected']['attemptId'] != 'old-attempt'
        assert any(e['kind'] == 'mission.reconciled_after_restart' for e in current['events'])


def test_ui_only_negative_control_is_recorded_separately_from_repair_proof():
    class BlockedVerifier:
        def verify(self, config):
            return {'state':'blocked','passed':False,'reason':'Docker host unavailable',
                    'artifactDigest':config['artifactDigest']}

    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        store = Store(str(root/'effects.sqlite'))
        security = SecurityStore(str(root/'security.sqlite'))
        run = store.create_run('kae')
        store.update_run(run['runId'],state='contained',incident={'status':'reproduced'})
        controller = Controller(store,security,verifier=BlockedVerifier(),artifact_dir=root/'artifacts',
                                repair_config={'repoPath':directory,'baseCommit':'a'*40})
        controller.command(run['runId'],'kae','verify-bad-patch')
        controller._jobs[run['runId']+':negative'].join(timeout=5)
        current = store.get_run(run['runId'])
        assert current['state'] == 'contained'
        assert current['verification'] is None
        assert current['negativeControl']['state'] == 'blocked'


def test_negative_control_duplicate_and_late_result_are_fenced():
    from vibesecur.controller import ControllerError
    class SlowVerifier:
        def __init__(self): self.ready=threading.Event();self.done=threading.Event()
        def verify(self,config):
            self.cancel_event=config['cancelEvent']
            self.ready.set();self.done.wait(3)
            return {'state':'rejected','passed':False,'artifactDigest':config['artifactDigest'],'tests':[]}
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory);store=Store(str(root/'effects.sqlite'))
        security=SecurityStore(str(root/'security.sqlite'))
        run=store.create_run('kae');store.update_run(run['runId'],state='contained',
                                               incident={'status':'reproduced'})
        verifier=SlowVerifier()
        controller=Controller(store,security,verifier=verifier,artifact_dir=root/'artifacts',
                              repair_config={'repoPath':directory,'baseCommit':'a'*40})
        controller.command(run['runId'],'kae','verify-bad-patch')
        assert verifier.ready.wait(3)
        try:
            controller.command(run['runId'],'kae','verify-bad-patch')
            assert False,'Duplicate verifier job must be rejected'
        except ControllerError as exc:
            assert 'already started' in str(exc)
        controller.command(run['runId'],'kae','cancel')
        assert verifier.cancel_event.is_set()
        verifier.done.set();controller._jobs[run['runId']+':negative'].join(timeout=5)
        current=store.get_run(run['runId'])
        assert current['state']=='cancelled'
        assert current['negativeControl']['state']=='cancelled'
        assert not any(event['kind']=='negative_control.assessed' for event in current['events'])


def test_expired_authority_during_promotion_never_disables_rule():
    import hashlib
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory)
        patch=root/'patch.diff';patch.write_text('candidate bytes')
        digest=hashlib.sha256(patch.read_bytes()).hexdigest()
        store=Store(str(root/'effects.sqlite'))
        security=SecurityStore(str(root/'security.sqlite'))
        run=store.create_run('kae')
        mission={'runId':run['runId'],'planDigest':'plan-1','expiresAt':time.time()+600,
                 'verificationContractDigest':'contract-1','baseCommit':'a'*40}
        source_digest='b'*64
        store.update_run(run['runId'],state='held',repair={'approval':{'planDigest':'plan-1'}},
                         verification={'passed':True,'artifactDigest':digest,'contractDigest':'contract-1',
                                       'outerContainment':True,'compensatingRule':False,
                                       'sourceReview':{'passed':True,'sourceSha256':source_digest}})
        class Gateway:
            def promote_verified(self, run, patch_path, artifact_digest, base_commit):
                mission['expiresAt']=time.time()-1
                return {'deployed':True,'artifactDigest':artifact_digest,
                        'imageDigest':'sha256:example','sourceSha256':source_digest}
            def probe_promoted(self, run, artifact_digest, image_digest):
                return {'artifactDigest':artifact_digest,'imageDigest':image_digest,
                        'sourceSha256':source_digest,'paymentRouteReady':True,'separateService':True}
        controller=Controller(store,security,payment_gateway=Gateway())
        controller._promote_verified(run['runId'],mission,
                                     {'patchPath':str(patch),'artifactDigest':digest},
                                      {'passed':True,'outerContainment':True,'compensatingRule':False,
                                      'contractDigest':'contract-1','artifactDigest':digest,
                                      'sourceReview':{'passed':True,'sourceSha256':source_digest}})
        current=store.get_run(run['runId'])
        assert current['protected']['compensatingRule'] is True
        assert not any(e['kind']=='repair.deployed' for e in current['events'])


def test_promoted_source_must_match_verified_candidate_before_rule_change():
    import hashlib
    for mismatch in ('deployment', 'probe'):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);patch=root/'patch.diff';patch.write_text('candidate bytes')
            digest=hashlib.sha256(patch.read_bytes()).hexdigest()
            source_digest='b'*64
            store=Store(str(root/'effects.sqlite'))
            security=SecurityStore(str(root/'security.sqlite'))
            run=store.create_run('kae');run_id=run['runId']
            mission={'runId':run_id,'planDigest':'plan-1','expiresAt':time.time()+600,
                     'verificationContractDigest':'contract-1','baseCommit':'a'*40}
            proof={'passed':True,'artifactDigest':digest,'contractDigest':'contract-1',
                   'outerContainment':True,'compensatingRule':False,
                   'sourceReview':{'passed':True,'sourceSha256':source_digest}}
            store.update_run(run_id,state='held',repair={'approval':{'planDigest':'plan-1'}},
                             verification=proof)
            class Gateway:
                def promote_verified(self, run, patch_path, artifact_digest, base_commit):
                    return {'deployed':True,'artifactDigest':artifact_digest,
                            'imageDigest':'sha256:'+'c'*64,
                            'sourceSha256':'a'*64 if mismatch=='deployment' else source_digest}
                def probe_promoted(self, run, artifact_digest, image_digest):
                    return {'artifactDigest':artifact_digest,'imageDigest':image_digest,
                            'sourceSha256':'a'*64 if mismatch=='probe' else source_digest,
                            'paymentRouteReady':True,'separateService':True}
            controller=Controller(store,security,payment_gateway=Gateway())
            controller._promote_verified(run_id,mission,
                                         {'patchPath':str(patch),'artifactDigest':digest},proof)
            current=store.get_run(run_id)
            assert current['protected']['compensatingRule'] is True
            assert not any(event['kind']=='repair.deployed' for event in current['events'])


def test_reconcile_restores_rule_after_incomplete_promotion_record():
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory)
        store=Store(str(root/'effects.sqlite'))
        security=SecurityStore(str(root/'security.sqlite'))
        run=store.create_run('kae');run_id=run['runId']
        protected_id=run['protected']['environmentId']
        store.update_run(run_id,state='held',
                         verification={'passed':True,'artifactDigest':'a'*64,
                                       'sourceReview':{'passed':True,'sourceSha256':'b'*64}},
                         repair={'status':'candidate'})
        store.set_compensating_rule(protected_id,False)
        Controller(store,security).reconcile('kae')
        current=store.get_run(run_id)
        assert current['protected']['compensatingRule'] is True
        assert any(event['kind']=='repair.incomplete_promotion_reconciled' for event in current['events'])


def test_gateway_promotion_error_is_recorded_while_compensation_stays_on():
    import hashlib
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory);patch=root/'patch.diff';patch.write_text('candidate bytes')
        digest=hashlib.sha256(patch.read_bytes()).hexdigest()
        store=Store(str(root/'effects.sqlite'))
        security=SecurityStore(str(root/'security.sqlite'))
        run=store.create_run('kae');run_id=run['runId']
        mission={'runId':run_id,'planDigest':'plan-1','expiresAt':time.time()+600,
                 'verificationContractDigest':'contract-1','baseCommit':'a'*40}
        proof={'passed':True,'artifactDigest':digest,'contractDigest':'contract-1',
               'outerContainment':True,'compensatingRule':False,
               'sourceReview':{'passed':True,'sourceSha256':'b'*64}}
        store.update_run(run_id,state='held',repair={'approval':{'planDigest':'plan-1'}},
                         verification=proof)
        _record_bound_test_plan(store,run_id,mission)
        class Gateway:
            def promote_verified(self,*args):
                raise RuntimeError('Expired service capability')
            def probe_promoted(self,*args):
                raise AssertionError('probe must not run')
        controller=Controller(store,security,payment_gateway=Gateway())
        controller._promote_verified(run_id,mission,{'patchPath':str(patch),'artifactDigest':digest},proof)
        current=store.get_run(run_id)
        assert current['protected']['compensatingRule'] is True
        assert any(event['kind']=='repair.deployment_unavailable' and
                   event['data']['reason']=='Separate service promotion raised RuntimeError'
                   for event in current['events'])


def test_verified_live_promotion_resumes_only_with_unchanged_standing_demo_scope(tmp_path):
    import hashlib
    store=Store(str(tmp_path/'effects.sqlite'))
    security=SecurityStore(str(tmp_path/'security.sqlite'))
    patch=tmp_path/'patch.diff';patch.write_text('verified synthetic patch')
    artifact=hashlib.sha256(patch.read_bytes()).hexdigest()
    source='b'*64;image='sha256:'+'c'*64
    class Gateway:
        def promote_verified(self,run,*args):
            return {'deployed':True,'artifactDigest':artifact,'sourceSha256':source,
                    'imageDigest':image}
        def probe_promoted(self,run,*args):
            return {'artifactDigest':artifact,'sourceSha256':source,'imageDigest':image,
                    'paymentRouteReady':True,'separateService':True}
        def pay(self,run,environment,command,client='http'):
            store.commit(run[environment]['environmentId'],command)
            return {'status':'committed','httpStatus':200}
    controller=Controller(store,security,payment_gateway=Gateway(),standing_demo_enabled=True)
    run=controller.create_run('kae','live')
    started=controller.provision_standing_demo(run['runId'],'kae')
    rid=run['runId']
    mission={'runId':rid,'planDigest':'plan-1','expiresAt':time.time()+600,
             'verificationContractDigest':'contract-1','baseCommit':'a'*40}
    proof={'passed':True,'artifactDigest':artifact,'contractDigest':'contract-1',
           'outerContainment':True,'compensatingRule':False,
           'sourceReview':{'passed':True,'sourceSha256':source}}
    store.update_run(rid,state='held',repair={'approval':{'planDigest':'plan-1'}},
                     verification=proof)
    _record_bound_test_plan(store,rid,mission)
    controller._promote_verified(rid,mission,{'patchPath':str(patch),'artifactDigest':artifact},proof)
    current=store.get_run(rid)
    assert current['state']=='resumed'
    assert len(current['protected']['ledger'])==1
    assert current['protected']['ledger'][0]['transaction']==started['standingDemoAuthorization']['snapshot']
    assert any(event['kind']=='resume.synthetic_exact_approval_recorded' for event in current['events'])

    changed=controller.create_run('kae','live')
    controller.provision_standing_demo(changed['runId'],'kae')
    store.update_invoice(changed['protected']['environmentId'],amount_minor=25000001)
    second=changed['runId'];second_mission={**mission,'runId':second}
    store.update_run(second,state='held',repair={'approval':{'planDigest':'plan-1'}},
                     verification=proof)
    _record_bound_test_plan(store,second,second_mission)
    controller._promote_verified(second,second_mission,
                                 {'patchPath':str(patch),'artifactDigest':artifact},proof)
    stale=store.get_run(second)
    assert stale['state']=='held' and not stale['protected']['ledger']
    assert not any(event['kind']=='resume.synthetic_exact_approval_recorded' for event in stale['events'])


def test_gateway_promotion_stage_is_allowlisted_without_exception_text():
    import hashlib
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory);patch=root/'patch.diff';patch.write_text('candidate bytes')
        digest=hashlib.sha256(patch.read_bytes()).hexdigest()
        store=Store(str(root/'effects.sqlite'))
        security=SecurityStore(str(root/'security.sqlite'))
        run=store.create_run('kae');run_id=run['runId']
        mission={'runId':run_id,'planDigest':'plan-1','expiresAt':time.time()+600,
                 'verificationContractDigest':'contract-1','baseCommit':'a'*40}
        proof={'passed':True,'artifactDigest':digest,'contractDigest':'contract-1',
               'outerContainment':True,'compensatingRule':False,
               'sourceReview':{'passed':True,'sourceSha256':'b'*64}}
        store.update_run(run_id,state='held',repair={'approval':{'planDigest':'plan-1'}},
                         verification=proof)
        _record_bound_test_plan(store,run_id,mission)
        class Gateway:
            def promote_verified(self,*args):
                error=RuntimeError('private-token-marker')
                error.stage='image_build'
                raise error
            def probe_promoted(self,*args):
                raise AssertionError('probe must not run')
        Controller(store,security,payment_gateway=Gateway())._promote_verified(
            run_id,mission,{'patchPath':str(patch),'artifactDigest':digest},proof)
        current=store.get_run(run_id)
        event=next(event for event in current['events'] if event['kind']=='repair.deployment_unavailable')
        assert event['data']=={'reason':'Separate service promotion raised RuntimeError',
                               'stage':'image_build'}
        assert 'private-token-marker' not in json.dumps(event)
        assert current['protected']['compensatingRule'] is True
