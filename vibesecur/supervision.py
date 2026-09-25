"""Trusted live-payment preflight; model assessments never create authority."""
from __future__ import annotations

import hashlib
import json
import math

from vibesecur.store import StoreError, TRANSACTION_KEYS
from vibesecur.assessment import MODEL_REVISION


def _valid_assessment(value, source):
    """Accept a complete advisory observation bound to these exact input bytes."""
    if not isinstance(value, dict) or source is None:
        return False
    digest = hashlib.sha256(json.dumps(source, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    provenance = value.get('provenance')
    latency = value.get('latencyMs')
    if (value.get('modelRevision') != MODEL_REVISION or value.get('calibrated') is not False
            or type(value.get('truncationDetected')) is not bool
            or type(latency) not in (int, float) or not math.isfinite(latency) or latency < 0
            or not isinstance(provenance, dict) or provenance.get('sourceDigest') != digest
            or any(provenance.get(key) != source.get(key) for key in ('sourceId', 'kind', 'origin'))):
        return False
    if value.get('status') == 'available':
        score = value.get('rawScore')
        return (value.get('label') in ('suitable', 'purpose_mismatch')
                and type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 1
                and value['truncationDetected'] is False)
    return value.get('status') in ('unavailable', 'input_too_large')


def supervised_payment(store, gateway, assessor, environment_id, command):
    run = store.run_for_environment(environment_id)
    if not run.get('conversation'):
        # Replay and independent verification use their separately scoped
        # effect contracts. Temporary semantic enforcement must not mask defects.
        return store.commit(environment_id, command)
    if not isinstance(command, dict) or set(command) != set(TRANSACTION_KEYS) | {
            'approvalId', 'operationId', 'attemptId'}:
        return store.commit(environment_id, command)
    conversation = run['conversation']
    turn = next((item for item in conversation['turns']
                 if item['turnId'] == conversation.get('activeTurnId')), {})
    if turn.get('scope') != 'pay_approved' or turn.get('status') != 'running':
        return store.commit(environment_id, command)  # mandatory deterministic turn fence
    if store.receipt(environment_id, command['operationId']):
        return store.commit(environment_id, command)  # reconcile, never repeat the effect
    snapshot = (run.get('standingDemoAuthorization') or {}).get('snapshot') or {}
    proposal = {key: command[key] for key in TRANSACTION_KEYS}
    source = None
    try:
        document = gateway.document(run, 'protected') if gateway is not None else {}
        body = document.get('body')
        body_bytes = body.encode('utf-8') if isinstance(body, str) else b''
        digest = hashlib.sha256(body_bytes).hexdigest()
        if (document.get('httpStatus') == 200 and isinstance(body, str)
                and document.get('transport') == 'separate_http'
                and document.get('truncated') is False and len(body) <= 16384
                and document.get('bodyLengthChars') == len(body)
                and document.get('bodyLengthBytes') == len(body_bytes)
                and document.get('bodySha256') == digest):
            source = {'sourceId': snapshot.get('invoiceId'), 'kind': 'supplier_document',
                      'origin': '/documents/invoice', 'text': body, 'bodySha256': digest}
            store.append_event(run['runId'], 'source.document_http', {
                'environment': 'protected', 'turnId': turn['turnId'],
                'urlPath': '/documents/invoice', 'httpStatus': 200,
                'provenance': 'untrusted_supplier_document', 'sha256': digest,
                'bodyLengthBytes': len(body_bytes), 'truncated': False,
                'observer': 'trusted_payment_preflight'})
        if source is None:
            assessment = {'status': 'unavailable', 'reason': 'source_unavailable',
                          'calibrated': False}
        else:
            mission = {'purpose': turn['text'], 'invoice': snapshot.get('invoiceId'),
                       'approvedAccount': snapshot.get('beneficiaryAccount'),
                       'invoiceRevision': snapshot.get('invoiceRevision'),
                       'supplierRevision': snapshot.get('supplierRevision')}
            action = {'tool': 'payments.create', 'account': command['beneficiaryAccount'],
                      'amountMinor': command['amountMinor'], 'currency': command['currency']}
            assessment = assessor(mission, action, source)
            if not _valid_assessment(assessment, source):
                assessment = {'status': 'unavailable', 'reason': 'invalid_assessment',
                              'calibrated': False}
    except Exception:
        assessment = {'status': 'unavailable', 'reason': 'assessment_failed', 'calibrated': False}
    store.append_event(run['runId'], 'assessment.payment', {
        'environmentId': environment_id, 'turnId': turn['turnId'],
        'operationId': command['operationId'], 'assessment': assessment,
        'transactionDigest': hashlib.sha256(json.dumps(
            proposal, sort_keys=True, separators=(',', ':')).encode()).hexdigest()})
    if proposal != snapshot:
        # Attribute exact-transaction rejection to its deterministic check,
        # even if Laya is unavailable or agrees with the proposed action.
        return store.commit(environment_id, command)
    code = None
    if assessment.get('status') != 'available' or assessment.get('truncationDetected'):
        code = ('assessment_input_too_large' if assessment.get('status') == 'input_too_large'
                else 'assessment_unavailable')
    elif assessment.get('label') != 'suitable':
        code = 'assessment_purpose_mismatch'
    if code:
        message = ('Payment held while its context is checked. No permission was changed; '
                   'independently authorized read-only work can continue.')
        decision = store.reject_payment(environment_id, command, code, message, status=409)
        raise StoreError(decision['reason'], decision['status'], message)
    # Rereads records/mandate/turn and commits atomically after inference.
    return store.commit(environment_id, command)
