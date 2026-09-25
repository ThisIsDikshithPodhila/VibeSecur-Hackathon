"""Independent proof orchestration; no candidate imports in this process."""
from __future__ import annotations
from pathlib import Path
import ast
import difflib
import hashlib
import json
import re
import uuid
from vibesecur.repair import prepare_candidate, validate_patch,source_files
from verifier.docker_supervisor import DockerSupervisor, InfrastructureError

CONTRACT = Path(__file__).with_name('verification-contract.json')
FIXTURE = Path(__file__).resolve().parents[1]/'fixtures'/'patches'/'ui-only.diff'
TRANSACTION_FIELDS={'environmentId','workspaceId','missionId','invoiceId','invoiceRevision',
                    'supplierId','supplierRevision','beneficiaryAccount','amountMinor','currency'}
OUTER_CONTROLS=('environmentScope','workspaceScope','missionScope','currentRecordCAS',
                'activeAttempt','expiry','revocation','effectUniqueness','atomicLedger')


def evaluate_outer_controls(proofs):
    """Only independent, named, passing control proofs establish outer coverage."""
    coverage={name:'unverified' for name in OUTER_CONTROLS}
    evidence={}
    for proof in proofs:
        name=proof.get('control') if isinstance(proof,dict) else None
        if name in coverage and proof.get('passed') is True and proof.get('authority')=='trusted_ledger':
            coverage[name]='verified'
            evidence[name]=proof.get('evidence')
    return {'passed':all(value=='verified' for value in coverage.values()),
            'coverage':coverage,'evidence':evidence}


def review_candidate_source(original,candidate):
    """Conservative independent scope review in addition to dynamic ledger proof."""
    before,after=source_files(original),source_files(candidate)
    changed=sorted(path for path in set(before)|set(after) if before.get(path)!=after.get(path))
    findings=[]
    if changed!=['payment_app/app.py']:
        findings.append('Candidate must change only payment_app/app.py for this incident')
    try:
        original_text=before['payment_app/app.py'].decode('utf-8')
        candidate_text=after['payment_app/app.py'].decode('utf-8')
        added='\n'.join(line[2:] for line in difflib.ndiff(original_text.splitlines(),candidate_text.splitlines())
                        if line.startswith('+ '))
        if re.search(r'(?i)verifier|pytest|test[_-]?mode|hostname|docker|os\.environ|os\.getenv|EFFECT_STORE_URL',added):
            findings.append('Candidate adds environment or verifier-specific behavior')
        original_tree=ast.parse(original_text)
        tree=ast.parse(candidate_text)
        def approval_value(module):
            payment=next(node for node in ast.walk(module) if isinstance(node,ast.AsyncFunctionDef)
                         and node.name=='payment')
            assignment=next(node for node in payment.body if isinstance(node,ast.Assign)
                            and any(isinstance(target,ast.Name) and target.id=='approved'
                                    for target in node.targets))
            value=assignment.value
            assignment.value=ast.Constant(value=None)
            return value
        original_value=approval_value(original_tree)
        value=approval_value(tree)
        if ast.dump(original_tree,include_attributes=False)!=ast.dump(tree,include_attributes=False):
            findings.append('Changes outside the payment approval expression require independent manual review')
        literals={node.value for node in ast.walk(value) if isinstance(node,ast.Constant)
                  and isinstance(node.value,str)}
        if not TRANSACTION_FIELDS.issubset(literals):
            findings.append('Payment comparison does not explicitly cover every approved Transaction field')
        for node in ast.walk(value):
            if isinstance(node,(ast.IfExp,ast.NamedExpr,ast.Lambda,ast.Await)):
                findings.append('Conditional or dynamic approval expression requires manual review')
                break
            if (isinstance(node,ast.BoolOp) and isinstance(node.op,ast.Or) or
                    isinstance(node,(ast.BinOp,ast.UnaryOp)) or
                    isinstance(node,ast.Compare) and
                    (len(node.ops)!=1 or not isinstance(node.ops[0],ast.Eq))):
                findings.append('Approval expression includes a bypassable alternative or unreviewed operator')
                break
            if isinstance(node,ast.comprehension) and node.ifs:
                findings.append('Conditional approval generator requires manual review')
                break
            if isinstance(node,ast.Call):
                receiver=node.func.value if isinstance(node.func,ast.Attribute) else None
                allowed=(isinstance(node.func,ast.Name) and node.func.id in ('any','all') or
                         isinstance(node.func,ast.Attribute) and node.func.attr=='get' and
                         (isinstance(receiver,ast.Name) and receiver.id in ('item','command','snapshot') or
                          isinstance(receiver,ast.Name) and receiver.id=='environment' and
                          len(node.args)==2 and isinstance(node.args[0],ast.Constant) and
                          node.args[0].value=='approvals' or
                          isinstance(receiver,ast.Call) and
                          isinstance(receiver.func,ast.Attribute) and
                          isinstance(receiver.func.value,ast.Name) and
                          receiver.func.value.id=='item' and receiver.func.attr=='get'))
                if not allowed:
                    findings.append('Approval expression adds an unrelated call or probe')
                    break
        comparisons=[node for node in ast.walk(value) if isinstance(node,ast.Compare)
                     and len(node.ops)==1 and isinstance(node.ops[0],ast.Eq)]
        direct=all(any(field in ast.unparse(node) and 'snapshot' in ast.unparse(node)
                       and 'command' in ast.unparse(node) for node in comparisons)
                   for field in TRANSACTION_FIELDS)
        generated=any(isinstance(node,ast.GeneratorExp) and
                      any(isinstance(comp.iter,(ast.Tuple,ast.List)) and
                          {value.value for value in comp.iter.elts if isinstance(value,ast.Constant)}==TRANSACTION_FIELDS
                          for comp in node.generators) and
                      any('snapshot' in ast.unparse(eq) and 'command' in ast.unparse(eq)
                          for eq in ast.walk(node.elt) if isinstance(eq,ast.Compare))
                      for node in ast.walk(value))
        if not (direct or generated):
            findings.append('All ten fields must participate in snapshot-to-command equality')
    except (KeyError,UnicodeError,SyntaxError,StopIteration):
        findings.append('Candidate payment handler could not be parsed')
    return {'passed':not findings,'changedPaths':changed,'findings':findings,
            'sourceSha256':hashlib.sha256(after.get('payment_app/app.py',b'')).hexdigest(),
            'scope':'conservative_source_review_not_complete_behavioral_proof'}


def acceptance_manifest():
    """Digest every local acceptance asset, including trusted ledger code."""
    root = Path(__file__).resolve().parents[1]
    paths = [path for path in (root/'verifier').rglob('*') if path.is_file()
             and '__pycache__' not in path.parts and path.suffix in ('.py', '.json')]
    paths += [FIXTURE, root/'vibesecur'/'store.py', root/'vibesecur'/'repair.py',
              root/'contracts'/'v1.md']
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.relative_to(root).as_posix().encode()+b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def contract_digest():
    return hashlib.sha256(CONTRACT.read_bytes()).hexdigest()


def _valid_preconditions(proof):
    try:
        env = proof['before']['environment']; proposal = proof['proposal']
        approval = next(a for a in env['approvals'] if a['approvalId'] == proposal['approvalId'])
        return (env['compensatingRule'] is False and env['active'] is True and
                env['attemptId'] == proposal['attemptId'] and not approval['consumed'] and not approval['revoked'] and
                approval['expiresAt'] > proof['observedAt'] >= approval['createdAt'] and
                env['invoice']['invoiceRevision'] == proposal['invoiceRevision'] and
                env['supplier']['supplierRevision'] == proposal['supplierRevision'] and
                all(env[key] == proposal[key] for key in ('environmentId','workspaceId','missionId')))
    except (KeyError, StopIteration, TypeError):
        return False


def evaluate_proof(evidence):
    """Evaluate trusted snapshots only. Application narratives have no authority."""
    tests=[]; label=evidence['label']
    proofs=evidence.get('proofs',[])
    for proof in proofs:
        name=proof['name']; after=proof.get('after',{}).get('environment',{})
        ledger=after.get('ledger',[]); proposal=proof.get('proposal',{})
        passed=False
        if name == 'staleApprovalCurrentRevision':
            valid = _valid_preconditions(proof)
            before = proof['before']['environment']
            old = next((a for a in before['approvals'] if a['approvalId']==proposal['approvalId']), None)
            changed = (old is not None and old.get('snapshot') != {
                key: proposal[key] for key in ('environmentId','workspaceId','missionId','invoiceId',
                'invoiceRevision','supplierId','supplierRevision','beneficiaryAccount','amountMinor','currency')})
            if label in ('original','ui-only'):
                passed=(valid and changed and proof['httpStatus'] in (200,201) and len(ledger)==1 and
                        ledger[0].get('operationId')==proposal['operationId'] and
                        ledger[0].get('approvalId')==proposal['approvalId'])
            else:
                matching=[a for a in after.get('approvals',[]) if a['approvalId']==proposal['approvalId']]
                passed=(valid and changed and proof['httpStatus'] in (400,403,409,422) and len(ledger)==0 and
                        len(matching)==1 and matching[0]['consumed'] is False)
        elif name.endswith('Mismatch'):
            valid=_valid_preconditions(proof)
            if label in ('original','ui-only'):
                passed=(valid and proof['httpStatus'] in (200,201) and len(ledger)==1 and
                        ledger[0].get('operationId')==proposal['operationId'] and
                        ledger[0].get('transaction',{}).get('beneficiaryAccount')=='SYNTH-AE-CHANGED-999')
            else:
                matching=[a for a in after.get('approvals',[]) if a['approvalId']==proposal.get('approvalId')]
                passed=(valid and proof['httpStatus'] in (400,403,409,422) and len(ledger)==0 and
                        len(matching)==1 and matching[0]['consumed'] is False)
        elif name in ('freshApproval','retry'):
            transaction={key:proposal[key] for key in ('environmentId','workspaceId','missionId','invoiceId','invoiceRevision','supplierId','supplierRevision','beneficiaryAccount','amountMinor','currency')}
            passed=(proof['httpStatus'] in (200,201) and len(ledger)==1 and
                    ledger[0].get('operationId')==proposal['operationId'] and
                    ledger[0].get('approvalId')==proposal['approvalId'] and ledger[0].get('transaction')==transaction)
        tests.append({'name':label+'.'+name,'passed':bool(passed),'httpStatus':proof.get('httpStatus'), 'ledgerEntries':len(ledger)})
    required = ({'beneficiaryAccountMismatch','staleApprovalCurrentRevision'} if label in ('original','ui-only')
                else {'beneficiaryAccountMismatch','amountMinorMismatch','currencyMismatch',
                      'staleApprovalCurrentRevision','freshApproval','retry'})
    return {'passed':required=={p['name'] for p in proofs} and all(t['passed'] for t in tests),'tests':tests}


def verify(config):
    digest=contract_digest()
    result={'passed':False,'state':'blocked','tests':[], 'artifactDigest':None,
            'contractDigest':digest,'artifacts':{},'compensatingRule':None,'outerContainment':None,
            'outerControls':evaluate_outer_controls([])}
    if config.get('verificationContractDigest') != digest:
        result['reason']='Missing or changed independent verification contract digest'
        return result
    try:
        if config.get('cancelEvent') is not None and config['cancelEvent'].is_set():
            raise InfrastructureError('Verification cancelled')
        manifest_before=acceptance_manifest()
        result['acceptanceManifestDigest']=manifest_before
        patch_bytes=Path(config['patchPath']).read_bytes()
        artifact_digest=hashlib.sha256(patch_bytes).hexdigest()
        result['artifactDigest']=artifact_digest
        if config.get('artifactDigest') and config['artifactDigest']!=artifact_digest:
            raise ValueError('Candidate patch changed after collection')
        patch=patch_bytes.decode('utf-8'); validate_patch(patch)
        root=Path(config['artifactDir']).resolve()/('verify-'+uuid.uuid4().hex)
        root.mkdir(parents=True,mode=0o700)
        # Persist the exact accepted input once; external patch changes cannot affect execution.
        (root/'candidate.diff').write_bytes(patch_bytes)
        original=prepare_candidate(config['repoPath'],config['baseCommit'],root/'original')
        ui_patch=FIXTURE.read_text(); validate_patch(ui_patch)
        ui=prepare_candidate(config['repoPath'],config['baseCommit'],root/'ui-only',ui_patch)
        candidate=prepare_candidate(config['repoPath'],config['baseCommit'],root/'candidate',patch)
        source_review=review_candidate_source(original,candidate)
        result['sourceReview']=source_review
        supervisor=DockerSupervisor(config,original)
        result['imageIds']=supervisor.image_ids
        for label,source in (('original',original),('ui-only',ui),('candidate',candidate)):
            evidence=supervisor.run(source,label,root/label/'evidence')
            if acceptance_manifest()!=manifest_before:
                raise ValueError('Protected acceptance assets changed during execution')
            path=root/(label+'.json'); path.write_text(json.dumps(evidence,indent=2))
            result['artifacts'][label]=str(path)
            evaluated=evaluate_proof(evidence); result['tests']+=evaluated['tests']
            if not evaluated['passed']:
                result.update(state='rejected',reason='Independent ledger acceptance failed: '+label)
                break
            if label=='candidate' and not source_review['passed']:
                result.update(state='rejected',reason='Independent candidate source review failed')
                break
        else:
            if contract_digest()!=digest:
                raise ValueError('Verification contract changed during execution')
            if acceptance_manifest()!=manifest_before:
                raise ValueError('Protected acceptance assets changed during execution')
            outer=evaluate_outer_controls(supervisor.run_outer_controls(root/'outer-controls'))
            result['outerControls']=outer
            if acceptance_manifest()!=manifest_before or contract_digest()!=digest:
                raise ValueError('Protected acceptance assets changed during outer-control execution')
            if outer['passed']:
                result.update(passed=True,state='passed',compensatingRule=False,outerContainment=True)
            else:
                result.update(state='held',reason='Independent outer containment controls remain unverified')
        result['artifacts']['patch']=str(root/'candidate.diff')
        result['artifacts']['report']=str(root/'verification.json')
        (root/'verification.json').write_text(json.dumps(result,indent=2))
    except (InfrastructureError,OSError,KeyError,ValueError) as exc:
        result.update(state='blocked',reason=str(exc)[:1200])
    return result
