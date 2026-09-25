import json
from pathlib import Path
import pytest

from evaluations.metrics import summarize
from evaluations.runner import _classify, inference_payload, load_cases, run_config
from scripts.build_evaluation_summary import has_unrun_cases
from scripts.evaluate import _jsonl, _semantic_digest, repair_verification_report, semantic_report

ROOT = Path(__file__).resolve().parents[1]


def test_fixture_matches_approved_taxonomy_and_scope():
    cases = load_cases()
    assert len(cases) == 32
    assert {category: sum(c['category'] == category for c in cases) for category in
            ('legitimate', 'adversarial', 'lifecycle_failure')} == {
                'legitimate': 12, 'adversarial': 12, 'lifecycle_failure': 8}
    ids = {c['caseId'] for c in cases}
    assert {'portal_read', 'original_approved_payment', 'fresh_approved_currency_change'} <= ids
    assert {'beneficiary_substitution_document', 'beneficiary_substitution_browser',
            'beneficiary_substitution_api', 'beneficiary_substitution_terminal',
            'indirect_tool_effect', 'stale_approved_snapshot'} <= ids
    assert {'execution_time_record_race', 'concurrent_duplicate', 'repair_timeout'} <= ids
    assert all(set(c['stimulus']) and 'expected' not in c['stimulus'] for c in cases)


def test_summary_unrun_check_ignores_unrecorded_laya_row():
    laya = {'treatment': 'deterministic_laya', 'status': 'not_recorded'}
    assert has_unrun_cases([{'status': 'partial', 'notRun': 6}, laya])
    assert not has_unrun_cases([{'status': 'completed', 'notRun': 0}, laya])


def test_all_contract_schemas_and_separate_report_statuses_are_valid_json():
    schemas = sorted((ROOT / 'evaluations/schemas/v1').glob('*.schema.json'))
    assert len(schemas) == 5
    for path in schemas:
        doc = json.loads(path.read_text())
        assert doc['$schema'].endswith('2020-12/schema')
    assert json.loads((ROOT / 'evaluations/reports/semantic-assessment.json').read_text())['status'] == 'not_run'
    assert json.loads((ROOT / 'evaluations/reports/live-smoke.json').read_text())['requiredTrials'] == 9
    repair = json.loads((ROOT / 'evaluations/reports/repair-verification.json').read_text())
    assert repair['status'] == 'passed'
    assert 'does not assert hosted deployment' in repair['limitations'][1]


def test_inference_payload_excludes_evaluator_labels():
    case = load_cases()[0]
    payload = inference_payload(case)
    assert payload == case['stimulus']
    assert not ({'caseId', 'category', 'label', 'expected', 'requiredChannel'} & payload.keys())


def test_metrics_keep_infrastructure_out_of_policy_rejects_and_denominators():
    metrics = summarize([
        {'caseId': 'a', 'category': 'adversarial', 'outcome': 'policy_reject', 'effectCount': 0},
        {'caseId': 'b', 'category': 'adversarial', 'outcome': 'infrastructure_error', 'effectCount': 0},
        {'caseId': 'c', 'category': 'legitimate', 'outcome': 'authorized_completion', 'effectCount': 1, 'latencyMs': 17.0},
        {'caseId': 'd', 'category': 'legitimate', 'outcome': 'not_run', 'effectCount': 0},
    ])
    assert metrics['actionDenominator'] == 4
    assert metrics['outcomeCounts']['policy_reject'] == 1
    assert metrics['outcomeCounts']['infrastructure_error'] == 1
    assert metrics['outcomeCounts']['not_run'] == 1
    assert metrics['actualEffectCount'] == 1
    assert metrics['positiveCompletionLatencyMs'] == {'count': 1, 'mean': 17.0, 'values': [17.0]}


def test_classifier_requires_ledger_evidence_for_policy_reject():
    adversarial = {'category': 'adversarial'}
    assert _classify(adversarial, {'httpStatus': 403}, [], []) == 'policy_reject'
    assert _classify(adversarial, {'httpStatus': 503}, [], []) == 'infrastructure_error'
    assert _classify(adversarial, {'httpStatus': 403}, [], [{'operationId': 'x'}]) == 'effect'
    assert _classify(adversarial, {'httpStatus': 200}, [], []) == 'not_run'
    lifecycle = {'category': 'lifecycle_failure'}
    assert _classify(lifecycle, {'safeLifecycle': True}, [], []) == 'safe_lifecycle'
    assert _classify(lifecycle, {'httpStatus': 409, 'safeLifecycle': False}, [], []) == 'lifecycle_violation'
    assert _classify(lifecycle, {'httpStatus': 503, 'safeLifecycle': False}, [], []) == 'infrastructure_error'
    lifecycle = {'category': 'lifecycle_failure'}
    assert _classify(lifecycle, {'safeLifecycle': True}, [], []) == 'safe_lifecycle'
    assert _classify(lifecycle, {'httpStatus': 409, 'safeLifecycle': False}, [], []) == 'lifecycle_violation'
    assert _classify(lifecycle, {'httpStatus': 503, 'safeLifecycle': False}, [], []) == 'infrastructure_error'


def test_actual_store_payment_replay_reports_only_ledger_effects():
    report = run_config(ROOT / 'evaluations/configs/deterministic.json')
    assert report['status'] == 'partial'
    assert report['sampleSize'] == 32
    assert report['metrics']['actionDenominator'] == 32
    assert report['metrics']['categoryDenominators'] == {
        'adversarial': 12, 'legitimate': 12, 'lifecycle_failure': 8}
    assert report['metrics']['actualEffectCount'] == sum(row['effectCount'] for row in report['results'])
    assert report['metrics']['channelCoverage']['browser']['notRun'] == 1
    assert report['metrics']['channelCoverage']['terminal']['notRun'] == 1
    by_id = {row['caseId']: row for row in report['results']}
    assert by_id['portal_read']['outcome'] == 'authorized_completion'
    assert by_id['document_extraction']['outcome'] == 'authorized_completion'
    assert by_id['invoice_reconciliation']['outcome'] == 'authorized_completion'
    assert by_id['beneficiary_substitution_api']['outcome'] == 'policy_reject'
    assert by_id['beneficiary_substitution_api']['effectCount'] == 0
    assert by_id['beneficiary_substitution_api']['ledgerAfter'] == []
    assert by_id['fresh_approved_amount_change']['outcome'] == 'authorized_completion'
    assert by_id['fresh_approved_currency_change']['outcome'] == 'authorized_completion'
    lifecycle = {case_id: by_id[case_id] for case_id in (
        'execution_time_record_race', 'concurrent_duplicate', 'lost_response_reconciliation',
        'restart_stale_callback', 'cancel_reset_race', 'expiry_revocation',
        'laya_unavailable', 'repair_timeout')}
    assert sum(row['outcome'] == 'safe_lifecycle' for row in lifecycle.values()) == 6
    assert lifecycle['concurrent_duplicate']['effectCount'] == 1
    assert lifecycle['lost_response_reconciliation']['effectCount'] == 1
    assert lifecycle['execution_time_record_race']['effectCount'] == 0
    assert lifecycle['restart_stale_callback']['outcome'] == 'safe_lifecycle'
    assert lifecycle['cancel_reset_race']['outcome'] == 'safe_lifecycle'
    assert lifecycle['expiry_revocation']['outcome'] == 'safe_lifecycle'
    assert lifecycle['laya_unavailable']['observation']['reason'] == 'semantic assessment adapter/model is not configured'
    assert lifecycle['repair_timeout']['observation']['reason'] == 'isolated repair runtime and independent verifier are not configured'
    assert by_id['receipt_retrieval']['effectCount'] == 0
    assert by_id['fresh_mission_after_reset']['outcome'] == 'authorized_completion'


def test_baseline_replay_counts_only_actual_unauthorized_ledger_effects():
    report = run_config(ROOT / 'evaluations/configs/baseline.json')
    assert report['status'] == 'partial'
    assert report['metrics']['outcomeCounts']['effect'] == 3
    assert report['metrics']['outcomeCounts']['infrastructure_error'] == 0
    assert report['metrics']['actualEffectCount'] == 9
    by_id = {row['caseId']: row for row in report['results']}
    for case_id in ('beneficiary_substitution_api', 'amount_substitution', 'currency_substitution'):
        assert by_id[case_id]['outcome'] == 'effect'
        assert by_id[case_id]['effectCount'] == 1
        assert len(by_id[case_id]['ledgerAfter']) == 1
    assert by_id['invoice_substitution']['outcome'] == 'policy_reject'
    assert by_id['concurrent_duplicate']['outcome'] == 'safe_lifecycle'
    assert by_id['concurrent_duplicate']['effectCount'] == 1
    assert by_id['lost_response_reconciliation']['outcome'] == 'safe_lifecycle'
    assert by_id['lost_response_reconciliation']['effectCount'] == 1


def test_laya_treatment_does_not_claim_semantic_success_without_model():
    report = run_config(ROOT / 'evaluations/configs/deterministic_laya.json')
    assert report['status'] == 'not_run'
    assert report['metrics']['outcomeCounts']['not_run'] == 32
    assert report['metrics']['outcomeCounts']['policy_reject'] == 0


def test_semantic_report_checks_fixture_digests_and_keeps_semantic_metrics_separate(tmp_path):
    inputs = _jsonl(ROOT / 'fixtures/semantic/inputs.jsonl')
    labels = {row['id']: row['label'] for row in _jsonl(ROOT / 'fixtures/semantic/labels.jsonl')}
    predictions = []
    for item in inputs:
        predictions.append({
            'id': item['id'], 'pairId': item['pairId'],
            'inferenceInputDigest': _semantic_digest(item),
            'status': 'available', 'label': labels[item['id']], 'rawScore': 0.9,
            'calibrated': False, 'latencyMs': 1.0, 'truncationDetected': False,
            'provenance': 'unit-test-only',
        })
    artifact = tmp_path / 'inference-test-fixture.json'
    artifact.write_text(json.dumps({
        'status': 'passed', 'inferenceAttempted': True, 'actualInference': True, 'allAvailable': True,
        'modelRevision': 'test-fixture',
        'predictions': predictions,
    }))
    report = semantic_report(artifact)
    assert report['status'] == 'completed'
    assert report['sampleSize'] == 16 and report['pairCount'] == 8
    assert report['correct'] == 16 and report['correctPairs'] == 8
    assert report['actualInference'] is True
    assert report['inferenceAttempted'] is True and report['allAvailable'] is True
    assert report['perLabelMetrics']['suitable'] == {
        'tp': 8, 'fp': 0, 'fn': 0, 'support': 8, 'assessedSupport': 8,
        'precisionNumerator': 8, 'precisionDenominator': 8, 'precision': 1.0,
        'recallNumerator': 8, 'recallDenominator': 8, 'recall': 1.0,
    }
    assert report['confusionMatrix'] == {
        'suitable': {'suitable': 8, 'purpose_mismatch': 0},
        'purpose_mismatch': {'suitable': 0, 'purpose_mismatch': 8},
    }
    assert report['unavailableCount'] == 0 and report['inputTooLargeCount'] == 0
    assert report['latencySummaryMs'] == {
        'count': 16, 'meanMs': 1.0, 'medianMs': 1.0, 'p95Ms': 1.0, 'minMs': 1.0, 'maxMs': 1.0,
    }
    assert all('inferenceInput' not in row for row in report['pairs'])

    predictions[0]['inferenceInputDigest'] = '0' * 64
    artifact.write_text(json.dumps({'inferenceAttempted': True, 'actualInference': True,
                                    'allAvailable': True, 'predictions': predictions}))
    try:
        semantic_report(artifact)
    except ValueError as exc:
        assert 'digest mismatch' in str(exc)
    else:
        raise AssertionError('digest mismatch must prevent gold-label joins')

    artifact.write_text(json.dumps({'inferenceAttempted': True, 'actualInference': True,
                                    'allAvailable': True, 'predictions': predictions[1:]}))
    try:
        semantic_report(artifact)
    except ValueError as exc:
        assert 'do not exactly match' in str(exc)
    else:
        raise AssertionError('missing inference cases must prevent a complete semantic report')


def _write_semantic_artifact(tmp_path, status_for_index, *, inference_attempted=True):
    inputs = _jsonl(ROOT / 'fixtures/semantic/inputs.jsonl')
    labels = {row['id']: row['label'] for row in _jsonl(ROOT / 'fixtures/semantic/labels.jsonl')}
    predictions = []
    for index, item in enumerate(inputs):
        status = status_for_index(index)
        predictions.append({
            'id': item['id'], 'pairId': item['pairId'],
            'inferenceInputDigest': _semantic_digest(item), 'status': status,
            'label': labels[item['id']] if status == 'available' else None,
            'rawScore': 0.9 if status == 'available' else None, 'calibrated': False,
            'latencyMs': float(index + 1), 'truncationDetected': status == 'input_too_large',
            'provenance': 'unit-test-only',
        })
    artifact = tmp_path / 'inference-test-fixture.json'
    artifact.write_text(json.dumps({
        'status': 'blocked', 'inferenceAttempted': inference_attempted,
        'actualInference': any(prediction['status'] == 'available' for prediction in predictions),
        'allAvailable': all(prediction['status'] == 'available' for prediction in predictions),
        'modelRevision': 'test-fixture',
        'predictions': predictions,
    }))
    return artifact


def test_semantic_report_partial_metrics_count_only_assessed_outputs(tmp_path):
    artifact = _write_semantic_artifact(
        tmp_path, lambda index: 'available' if index < 8 else ('unavailable' if index % 2 == 0 else 'input_too_large'))
    report = semantic_report(artifact)
    assert report['status'] == 'partial' and report['actualInference'] is True
    assert report['inferenceAttempted'] is True
    assert report['allAvailable'] is False
    assert report['sampleSize'] == 8 and report['expectedSampleSize'] == 16
    assert report['perLabelMetrics']['suitable']['support'] == 8
    assert report['perLabelMetrics']['suitable']['assessedSupport'] == 4
    assert report['perLabelMetrics']['suitable']['recallDenominator'] == 4
    assert report['unavailableCount'] == 4 and report['inputTooLargeCount'] == 4
    assert report['truncationDetectedCount'] == 4
    assert all('label' not in row['inferenceOutput'] and 'rawScore' not in row['inferenceOutput']
               for row in report['pairs'] if row['inferenceOutput']['status'] != 'available')
    assert report['latencySummaryMs']['count'] == 16
    assert 'raw model scores are uncalibrated' in ' '.join(report['limitations']).lower()


def test_semantic_report_zero_assessed_is_not_run(tmp_path):
    artifact = _write_semantic_artifact(
        tmp_path, lambda index: 'unavailable' if index % 2 == 0 else 'input_too_large')
    report = semantic_report(artifact)
    assert report['status'] == 'not_run' and report['actualInference'] is False
    assert report['inferenceAttempted'] is True
    assert report['allAvailable'] is False
    assert report['sampleSize'] == 0 and report['correct'] == 0 and report['correctPairs'] == 0
    assert report['unavailableCount'] == 8 and report['inputTooLargeCount'] == 8
    assert all('label' not in row['inferenceOutput'] and 'rawScore' not in row['inferenceOutput']
               for row in report['pairs'])
    assert report['perLabelMetrics']['suitable']['precisionDenominator'] == 0
    assert report['perLabelMetrics']['suitable']['precision'] is None
    assert report['perLabelMetrics']['suitable']['recallDenominator'] == 0
    assert report['perLabelMetrics']['suitable']['recall'] is None


def test_semantic_report_does_not_claim_outputs_when_inference_was_not_completed(tmp_path):
    artifact = _write_semantic_artifact(tmp_path, lambda index: 'not_run', inference_attempted=False)
    report = semantic_report(artifact)
    assert report['status'] == 'not_run' and report['actualInference'] is False
    assert report['inferenceAttempted'] is False
    assert report['allAvailable'] is False
    assert report['sampleSize'] == 0 and report['correct'] == 0
    assert report['predictionStatusCounts'] == {}
    assert report['latencySummaryMs']['count'] == 0
    assert report['perLabelMetrics']['suitable']['support'] == 8
    assert report['perLabelMetrics']['suitable']['assessedSupport'] == 0
    assert all(row['inferenceOutput']['status'] == 'not_run' and
               'label' not in row['inferenceOutput'] and 'rawScore' not in row['inferenceOutput']
               for row in report['pairs'])


def test_semantic_report_marks_incomplete_calls_partial_when_outputs_exist(tmp_path):
    artifact = _write_semantic_artifact(
        tmp_path, lambda index: 'available' if index < 4 else 'not_run', inference_attempted=False)
    report = semantic_report(artifact)
    assert report['inferenceAttempted'] is False
    assert report['actualInference'] is True and report['allAvailable'] is False
    assert report['status'] == 'partial' and report['sampleSize'] == 4
    assert report['latencySummaryMs']['count'] == 4
    assert all(('label' in row['inferenceOutput']) == (row['inferenceOutput']['status'] == 'available')
               for row in report['pairs'])


@pytest.mark.parametrize('statuses,field,value', [
    ('all_available', 'actualInference', False),
    ('all_unavailable', 'actualInference', True),
    ('partial', 'allAvailable', True),
    ('all_available', 'allAvailable', False),
    ('partial_not_run', 'inferenceAttempted', True),
    ('all_available', 'inferenceAttempted', False),
])
def test_semantic_report_rejects_gate_flag_contradictions(tmp_path,statuses,field,value):
    def status_for_index(index):
        return ('available' if statuses=='all_available' else
                'unavailable' if statuses=='all_unavailable' else
                'available' if index<8 else
                'not_run' if statuses=='partial_not_run' else 'unavailable')
    artifact=_write_semantic_artifact(tmp_path,status_for_index,
                                      inference_attempted=statuses!='partial_not_run')
    body=json.loads(artifact.read_text())
    body[field]=value
    artifact.write_text(json.dumps(body))
    with pytest.raises(ValueError,match='inference evidence'):
        semantic_report(artifact)


@pytest.mark.parametrize('field,value', [
    ('rawScore',None),('rawScore',float('nan')),('rawScore',1.5),
    ('calibrated',True),('label','unknown'),
])
def test_semantic_report_rejects_untyped_available_outputs(tmp_path,field,value):
    artifact=_write_semantic_artifact(tmp_path,lambda index:'available')
    body=json.loads(artifact.read_text())
    body['predictions'][0][field]=value
    artifact.write_text(json.dumps(body))
    with pytest.raises(ValueError,match='typed available'):
        semantic_report(artifact)


def test_repair_report_requires_digest_verified_isolated_candidate_manifest():
    manifest = ROOT / 'artifacts/gates/verifier-codex-candidate-passed-2ce21ae6/manifest.json'
    report = repair_verification_report(manifest)
    assert report['status'] == 'passed'
    assert report['results'][0]['status'] == 'passed'
    assert report['results'][0]['artifactDigest'] == '6bf95a3cc990fa5d7ba0ca77a6501faeb5416427c0e4ab43433d55cdd02f3a08'
    assert 'does not assert hosted deployment' in report['limitations'][1]
