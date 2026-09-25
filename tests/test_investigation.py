from vibesecur.investigation import investigate
import pytest


def _run():
    approved={'invoiceId':'INV-1','beneficiaryAccount':'SYNTH-APPROVED-001',
              'amountMinor':100,'currency':'AED'}
    proposed={**approved,'beneficiaryAccount':'SYNTH-CHANGED-002'}
    receipt={'operationId':'op-1','approvalId':'approval-1','transaction':proposed}
    return {'runId':'run-fixture','baseline':{'approvals':[{'approvalId':'approval-1',
             'snapshot':approved}],'ledger':[receipt]},
            'protected':{'approvals':[],'ledger':[]},
            'incident':{'status':'reproduced','baselineReceipt':receipt,
                        'source':'deterministic_http_replay'},
            'events':[
                {'eventId':'event-baseline','kind':'deterministic_replay.payment_http',
                 'data':{'environment':'baseline','httpStatus':200}},
                {'eventId':'event-protected','kind':'deterministic_replay.payment_http',
                 'data':{'environment':'protected','httpStatus':403}},
                {'eventId':'event-effect','kind':'effect_committed',
                 'data':{'operationId':'op-1'}},
                {'eventId':'event-source','kind':'source.immutable_inspected',
                 'data':{'sourceSha256':'a'*64}}]}


def test_markdown_cites_trusted_observations_and_immutable_source():
    inspected={'status':'confirmed_seed_defect','sourcePath':'payment_app/app.py',
               'baseCommit':'b'*40,'sourceSha256':'a'*64,
               'evidence':{'paymentFunctionLine':42}}
    report=investigate(_run(),source_inspection=inspected)
    markdown=report['markdown']
    assert report['confirmedCause']
    assert 'event-effect' in markdown and 'event-source' in markdown
    assert 'baseline 200, protected 403' in markdown
    assert 'SYNTH-APPROVED-001 to SYNTH-CHANGED-002' in markdown
    assert f"payment_app/app.py at {'b'*40}, SHA-256 {'a'*64}" in markdown
    assert 'payment function line 42' in markdown
    assert report['uncertainty'] in markdown


def test_unconfirmed_source_is_not_cited_as_proof():
    report=investigate(_run(),source_inspection={'status':'unavailable'})
    assert report['confirmedCause'] is None
    assert 'Pinned source:' not in report['markdown']
    assert 'Pinned source inspection is unavailable' in report['markdown']


@pytest.mark.parametrize('defect', ['approved_payment','no_matching_approval',
                                    'not_reproduced','missing_status'])
def test_investigation_rejects_unproven_unauthorized_effect(defect):
    run=_run()
    if defect=='approved_payment':
        run['baseline']['approvals'][0]['snapshot']=dict(
            run['incident']['baselineReceipt']['transaction'])
    elif defect=='no_matching_approval':
        run['baseline']['approvals'][0]['approvalId']='other-approval'
    elif defect=='not_reproduced':
        run['incident']['status']='inconclusive'
    else:
        del run['incident']['status']
    with pytest.raises(ValueError):
        investigate(run)


def test_report_describes_actual_mismatch_field_without_inventing_beneficiary_change():
    run=_run()
    approved=run['baseline']['approvals'][0]['snapshot']
    receipt=run['incident']['baselineReceipt']
    receipt['transaction']={**approved,'amountMinor':101}
    report=investigate(run,source_inspection={'status':'confirmed_seed_defect',
        'sourcePath':'payment_app/app.py','baseCommit':'b'*40,'sourceSha256':'a'*64,
        'evidence':{'paymentFunctionLine':42}})
    assert report['actualImpact']['baselineUnauthorizedPayment'] is True
    assert 'amountMinor' in report['markdown']
    assert 'after changing amountMinor from 100 to 101' in report['markdown']
    assert 'after changing beneficiaryAccount' not in report['markdown']


@pytest.mark.parametrize('reason', ['assessment_unavailable', 'input_too_large',
                                    'purpose_mismatch'])
def test_assessment_hold_is_not_a_system_incident(reason):
    run=_run()
    run['protected']['environmentId']='env-protected'
    run['incident']={'status':'detected','source':'trusted_payment_decision',
                     'decisionId':'decision-held'}
    run['paymentDecisions']=[{'decisionId':'decision-held','environmentId':'env-protected',
                              'decision':'denied','reason':reason,
                              'attemptedTransaction':{'invoiceId':'INV-1'},
                              'authorizedTransaction':{'invoiceId':'INV-1'}}]
    with pytest.raises(ValueError, match='Trusted protected payment denial'):
        investigate(run, source_inspection={'status':'confirmed_seed_defect',
                     'sourceSha256':'a'*64})


def test_distinct_exact_receipt_needs_healthy_source_for_no_repair_disposition():
    run=_run()
    approved=run['baseline']['approvals'][0]['snapshot']
    run['baseline']['ledger']=[]
    run['protected']={'environmentId':'env-protected',
                      'approvals':[{'approvalId':'approval-1','snapshot':approved}],
                      'ledger':[{'operationId':'op-corrected','approvalId':'approval-1',
                                 'transaction':approved}]}
    run['incident']={'status':'detected','source':'trusted_payment_decision',
                     'decisionId':'decision-1'}
    run['paymentDecisions']=[{'decisionId':'decision-1','environmentId':'env-protected',
                              'decision':'denied','reason':'transaction_mismatch',
                              'operationId':'op-wrong','attemptedTransaction':
                                  {**approved,'beneficiaryAccount':'SYNTH-CHANGED-002'},
                              'authorizedTransaction':approved}]
    assert investigate(run,source_inspection={'status':'unavailable'})['disposition']=='unresolved'
    healthy=investigate(run,source_inspection={
        'status':'confirmed_healthy_payment','sourceSha256':'a'*64})
    assert healthy['disposition']=='course_corrected_no_repair'
    assert healthy['actualImpact']['protectedAuthorizedPayments']==1
    run['baseline']['ledger']=[run['incident'].get('baselineReceipt') or
                              {'operationId':'op-baseline','approvalId':'approval-1',
                               'transaction':{**approved,'beneficiaryAccount':'SYNTH-CHANGED-002'}}]
    vulnerable=investigate(run,source_inspection=healthy['sourceInspection'])
    assert vulnerable['disposition']=='recovery_required'
