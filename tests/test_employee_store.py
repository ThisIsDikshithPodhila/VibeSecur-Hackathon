"""Atomic employee turn, payment decision, and repair binding regressions."""
import concurrent.futures
import hashlib

import pytest

from vibesecur.store import Store, StoreError


@pytest.fixture
def live(tmp_path):
    store = Store(str(tmp_path / 'effects.sqlite'), clock=lambda: 1000.0)
    run = store.create_run('kae', 'live')
    store.transition(run['runId'], ['created'], 'prepared')
    return store, run['runId']


def error_code(call):
    with pytest.raises(StoreError) as caught:
        call()
    return caught.value.code


def test_duplicate_message_is_single_durable_turn_and_event(live):
    store, rid = live
    first = store.enqueue_turn(rid, 'kae', 'Review invoice', 'message-1')
    assert first['conversation']['turns'][0]['status'] == 'queued'
    assert store.enqueue_turn(rid, 'kae', 'Review invoice', 'message-1') == first
    assert error_code(lambda: store.enqueue_turn(rid, 'kae', 'Pay invoice', 'message-1')) == 'message_conflict'
    assert [event['kind'] for event in store.get_run(rid)['events']] == ['conversation.user']
    assert first['events'][0]['data']['turnId'] == first['conversation']['turns'][0]['turnId']


def test_concurrent_claims_allow_only_one_active_turn(live):
    store, rid = live
    for index in range(2):
        store.enqueue_turn(rid, 'kae', f'Message {index}', f'message-{index}')
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        claimed = list(pool.map(lambda _: store.claim_turn(rid, 'kae'), range(8)))
    turns = [turn for turn in claimed if turn]
    assert len(turns) == 1
    assert turns[0]['status'] == 'running'
    assert store.get_run(rid)['conversation']['activeTurnId'] == turns[0]['turnId']
    assert error_code(lambda: store.set_turn_scope(rid, 'kae', turns[0]['turnId'], 'pending')) == 'invalid_scope'
    store.set_turn_scope(rid, 'kae', turns[0]['turnId'], 'read_only')
    assert error_code(lambda: store.set_turn_scope(rid, 'kae', turns[0]['turnId'], 'pay_approved')) == 'scope_conflict'
    finished = store.finish_turn(rid, 'kae', turns[0]['turnId'], 'succeeded')
    assert finished['conversation']['activeTurnId'] is None
    assert store.finish_turn(rid, 'kae', turns[0]['turnId'], 'succeeded') == finished
    assert store.claim_turn(rid, 'kae')['turnId'] != turns[0]['turnId']


def _authorized_turn(store, rid, scope='pay_approved'):
    run = store.get_run(rid)
    env = run['protected']['environmentId']
    tx = store.transaction(env)
    approval = store.approve(env, tx, 'synthetic-demo-standing:kae')
    authority = {'source': 'trusted_demo_setup', 'provenance': 'user_configured_synthetic_demo',
                 'owner': 'kae', 'runId': rid, 'workspaceId': tx['workspaceId'],
                 'missionId': tx['missionId'], 'snapshot': tx, 'approvalId': approval['approvalId'],
                 'createdAt': 1000.0, 'expiresAt': 2000.0}
    store.update_run(rid, standingDemoAuthorization=authority)
    store.set_attempt(env, 'attempt-1')
    store.enqueue_turn(rid, 'kae', 'Pay the approved invoice', 'message-1')
    turn = store.claim_turn(rid, 'kae')
    if scope != 'pending':
        store.set_turn_scope(rid, 'kae', turn['turnId'], scope)
    return env, tx, approval, turn


def test_denial_is_durable_and_corrected_operation_links_it(live):
    store, rid = live
    env, tx, approval, turn = _authorized_turn(store, rid)
    changed = {**tx, 'beneficiaryAccount': 'SYNTH-AE-CHANGED-999'}
    attempted = {**changed, 'approvalId': approval['approvalId'],
                 'operationId': 'bad-operation', 'attemptId': 'attempt-1'}
    assert error_code(lambda: store.commit(env, attempted)) == 'transaction_mismatch'
    denied = store.get_run(rid)['paymentDecisions'][0]
    assert denied['decision'] == 'denied'
    assert denied['attemptedTransaction'] == changed
    assert denied['authorizedTransaction'] == tx
    assert denied['turnId'] == turn['turnId']
    assert store.get_run(rid)['events'][-1]['kind'] == 'payment.decision'
    assert error_code(lambda: store.commit(env, {**attempted, 'beneficiaryAccount': tx['beneficiaryAccount']})) == 'operation_conflict'
    assert len(store.get_run(rid)['paymentDecisions']) == 1
    good = {**tx, 'approvalId': approval['approvalId'],
            'operationId': 'corrected-operation', 'attemptId': 'attempt-1'}
    assert store.commit(env, good)['status'] == 'committed'
    decisions = store.get_run(rid)['paymentDecisions']
    assert decisions[-1]['priorDecisionId'] == denied['decisionId']
    assert decisions[-1]['decision'] == 'committed'
    assert len(store.environment(env)['ledger']) == 1


def test_corrected_operation_links_denial_after_fresh_approval(live):
    store, rid = live
    env, tx, approval, _ = _authorized_turn(store, rid)
    wrong = {**tx, 'beneficiaryAccount': 'SYNTH-AE-CHANGED-999',
             'approvalId': approval['approvalId'], 'operationId': 'wrong',
             'attemptId': 'attempt-1'}
    assert error_code(lambda: store.commit(env, wrong)) == 'transaction_mismatch'
    denied_id = store.get_run(rid)['paymentDecisions'][-1]['decisionId']
    fresh = store.approve(env, tx, 'synthetic-demo-standing:kae')
    authority = store.get_run(rid)['standingDemoAuthorization']
    store.update_run(rid, standingDemoAuthorization={**authority, 'approvalId': fresh['approvalId']})
    store.commit(env, {**tx, 'approvalId': fresh['approvalId'],
                       'operationId': 'corrected', 'attemptId': 'attempt-1'})
    assert store.get_run(rid)['paymentDecisions'][-1]['priorDecisionId'] == denied_id


@pytest.mark.parametrize('scope', ['pending', 'read_only', 'clarification'])
def test_employee_scope_blocks_alternative_payment_client(live, scope):
    store, rid = live
    env, tx, approval, _ = _authorized_turn(store, rid, scope)
    proposal = {**tx, 'approvalId': approval['approvalId'],
                'operationId': f'operation-{scope}', 'attemptId': 'attempt-1'}
    assert error_code(lambda: store.commit(env, proposal)) == 'turn_scope_denied'
    assert store.get_run(rid)['paymentDecisions'][-1]['decision'] == 'denied'
    assert store.environment(env)['ledger'] == []


def test_employee_baseline_lane_and_finished_turn_are_blocked(live):
    store, rid = live
    env, tx, approval, turn = _authorized_turn(store, rid)
    baseline = store.get_run(rid)['baseline']['environmentId']
    baseline_tx = store.transaction(baseline)
    baseline_approval = store.approve(baseline, baseline_tx, 'synthetic-demo-standing:kae')
    store.set_attempt(baseline, 'attempt-1')
    assert error_code(lambda: store.commit(baseline, {**baseline_tx, 'approvalId': baseline_approval['approvalId'],
                      'operationId': 'baseline-op', 'attemptId': 'attempt-1'})) == 'employee_baseline_denied'
    store.finish_turn(rid, 'kae', turn['turnId'], 'succeeded')
    assert error_code(lambda: store.commit(env, {**tx, 'approvalId': approval['approvalId'],
                      'operationId': 'late-op', 'attemptId': 'attempt-1'})) == 'turn_scope_denied'


def test_plan_binding_is_atomic_and_rejects_stale_or_nonrepair_incident(live):
    store, rid = live
    text = 'Validate the exact transaction at payment execution.'
    digest = hashlib.sha256(text.encode()).hexdigest()
    store.update_run(rid, state='contained', incident={'status': 'reproduced', 'disposition': 'recovery_required'},
                     investigation={'confirmedCause': 'Missing exact comparison'},
                     remediationPlan={'text': text, 'version': 1, 'executorBound': False})
    approval_id = 'repair-approval-1'
    intent = {'approval': {'approvalId': approval_id, 'planVersion': 1, 'planTextDigest': digest},
              'mission': {'approvalId': approval_id, 'planTextDigest': digest}, 'status': 'authorized'}
    assert error_code(lambda: store.bind_remediation_plan(rid, 'kae', 1, '0' * 64, approval_id,
                      repair_intent=intent)) == 'plan_conflict'
    assert store.get_run(rid)['state'] == 'contained'
    store.update_run(rid, investigation={'confirmedCause': 'Missing exact comparison',
                                         'disposition': 'course_corrected_no_repair'})
    assert error_code(lambda: store.bind_remediation_plan(rid, 'kae', 1, digest, approval_id,
                      repair_intent=intent)) == 'repair_unavailable'
    store.update_run(rid, investigation={'confirmedCause': 'Missing exact comparison',
                                         'disposition': 'recovery_required'})
    bound = store.bind_remediation_plan(rid, 'kae', 1, digest, approval_id, repair_intent=intent)
    assert bound['state'] == 'repairing'
    assert bound['repair'] == intent
    assert bound['remediationPlan']['binding']['textDigest'] == digest
    assert store.bind_remediation_plan(rid, 'kae', 1, digest, approval_id, repair_intent=intent) == bound
    assert len([event for event in bound['events'] if event['kind'] == 'repair.authorized']) == 1
    store.update_run(rid, state='verifying', repair={**intent, 'status': 'candidate'})
    assert store.bind_remediation_plan(rid, 'kae', 1, digest, approval_id,
                                       repair_intent=intent)['state'] == 'verifying'
    assert error_code(lambda: store.bind_remediation_plan(rid, 'kae', 1, digest, 'different',
                      repair_intent=intent)) == 'plan_conflict'


def test_trusted_external_rejection_binds_operation_and_returns_record(live):
    store, rid = live
    env, tx, approval, turn = _authorized_turn(store, rid)
    command = {**tx, 'approvalId': approval['approvalId'],
               'operationId': 'laya-held', 'attemptId': 'attempt-1'}
    assert store.run_for_environment(env)['runId'] == rid
    first = store.reject_payment(env, command, 'assessment_unavailable',
                                 'Assessment unavailable')
    assert first['decision'] == 'denied' and first['turnId'] == turn['turnId']
    assert store.reject_payment(env, command, 'assessment_unavailable',
                                'Assessment unavailable') == first
    assert len(store.get_run(rid)['paymentDecisions']) == 1
    assert error_code(lambda: store.commit(env, command)) == 'assessment_unavailable'
    assert error_code(lambda: store.reject_payment(env, {**command, 'amountMinor': 1},
                      'assessment_unavailable', 'Assessment unavailable')) == 'operation_conflict'
    assert store.environment(env)['ledger'] == []


def test_trusted_denial_repair_requires_confirmed_cause_and_no_active_turn(live):
    store, rid = live
    store.enqueue_turn(rid, 'kae', 'Investigate', 'investigate-1')
    turn = store.claim_turn(rid, 'kae')
    text = 'Correct exact payment validation.'
    digest = hashlib.sha256(text.encode()).hexdigest()
    intent = {'approval': {'approvalId': 'repair-1', 'planVersion': 1,
                           'planTextDigest': digest},
              'mission': {'approvalId': 'repair-1', 'planTextDigest': digest}}
    store.update_run(rid, state='contained',
                     incident={'status': 'detected', 'source': 'trusted_payment_decision',
                               'decisionId': 'decision-1'},
                     investigation={'confirmedCause': 'Source comparison missing',
                                    'disposition': 'course_corrected_no_repair',
                                    'decisionId': 'decision-1'},
                     remediationPlan={'text': text, 'version': 1, 'executorBound': False})
    bind = lambda: store.bind_remediation_plan(rid, 'kae', 1, digest, 'repair-1',
                                                repair_intent=intent)
    assert error_code(bind) == 'repair_unavailable'
    store.update_run(rid, investigation={'confirmedCause': 'Source comparison missing',
                                         'disposition': 'recovery_required',
                                         'decisionId': 'decision-1'})
    assert error_code(bind) == 'repair_unavailable'
    store.finish_turn(rid, 'kae', turn['turnId'], 'held')
    assert bind()['state'] == 'repairing'


def test_verified_continuation_queues_original_payment_work_once(live):
    store, rid = live
    env, tx, approval, source = _authorized_turn(store, rid)
    store.finish_turn(rid, 'kae', source['turnId'], 'held')
    artifact = 'a' * 64
    source_hash = 'b' * 64
    image = 'sha256:' + 'c' * 64
    store.update_run(rid, state='held', verification={'passed': True,
                     'artifactDigest': artifact, 'sourceReview': {'sourceSha256': source_hash}},
                     repair={'deployment': {'deployed': True, 'artifactDigest': artifact,
                                           'sourceSha256': source_hash, 'imageDigest': image},
                             'deploymentProbe': {'artifactDigest': artifact, 'sourceSha256': source_hash,
                                                 'imageDigest': image, 'paymentRouteReady': True,
                                                 'separateService': True}})
    store.set_compensating_rule(env, False)
    key = f'{artifact}:{source["turnId"]}'
    assert error_code(lambda: store.enqueue_continuation(rid, 'kae', source['turnId'], key)) == 'continuation_unavailable'
    store.append_event(rid, 'repair.deployed', {'artifactDigest': artifact, 'imageDigest': image})
    first = store.enqueue_continuation(rid, 'kae', source['turnId'], key)
    assert len(first['conversation']['turns']) == 2
    continued = first['conversation']['turns'][-1]
    assert continued['text'] == source['text']
    assert continued['sourceTurnId'] == source['turnId']
    assert continued['continuationContext'] == 'The independently verified repair was deployed. Reconcile the payment receipt and continue the original authorized task.'
    assert first['events'][-1]['kind'] == 'conversation.continuation_queued'
    assert store.enqueue_continuation(rid, 'kae', source['turnId'], key) == first
    assert error_code(lambda: store.enqueue_continuation(rid, 'kae', source['turnId'], 'other-key')) == 'continuation_conflict'
    assert store.claim_turn(rid, 'kae')['turnId'] == continued['turnId']


def test_verified_continuation_does_not_queue_after_exact_receipt(live):
    store, rid = live
    env, tx, approval, source = _authorized_turn(store, rid)
    store.commit(env, {**tx, 'approvalId': approval['approvalId'],
                       'operationId': 'already-paid', 'attemptId': 'attempt-1'})
    store.finish_turn(rid, 'kae', source['turnId'], 'succeeded')
    before = store.get_run(rid)
    after = store.enqueue_continuation(rid, 'kae', source['turnId'],
                                       f'{"a" * 64}:{source["turnId"]}')
    assert after == before
    assert len(after['conversation']['turns']) == 1
