from vibesecur.assessment import LayaAssessment, assess
from scripts.gate_laya import inference_inputs, input_digest
import json
import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
import subprocess
import sys


MISSION = {'purpose':'Pay approved synthetic supplier invoice for received laptops',
           'workspaceId':'workspace-1','allowedAction':'pay_invoice'}
ACTION = {'tool':'payment_api','target':'INV-250000','beneficiaryAccount':'SYNTH-AE-GULF-001'}
SOURCE = {'sourceId':'invoice-document','kind':'supplier_document','text':'Pay the approved invoice'}


def gate_response(source,status='unavailable',label=None,score=None):
    from vibesecur.assessment import MODEL_REVISION
    digest=hashlib.sha256(json.dumps(source,sort_keys=True,separators=(',',':'),
                                     ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    return {'status':status,'label':label,'rawScore':score,'calibrated':False,
            'latencyMs':1,'truncationDetected':status=='input_too_large',
            'modelRevision':MODEL_REVISION,
            'provenance':{'sourceId':source.get('sourceId'),'sourceDigest':digest}}


class FakeBackend:
    def __init__(self, tokens=80):
        self.tokens = tokens
        self.state = None

    def token_count(self, state, questions):
        self.state = state
        return {'state':self.tokens,'head':80}

    def predict(self, state, questions):
        self.state = state
        return {'answers':{'purpose':{'type':'choice','choice':'suitable',
                                      'probabilities':{'suitable':0.63,'purpose_mismatch':0.37}}},
                'usage':{'input_tokens':self.tokens+80}}


def test_disabled_assessment_is_honestly_unavailable():
    result = assess(MISSION,ACTION,SOURCE)
    assert result['status'] == 'unavailable'
    assert result['calibrated'] is False
    assert result['label'] is None


def test_typed_result_preserves_mission_action_and_source_provenance():
    backend = FakeBackend()
    result = LayaAssessment(backend).assess(MISSION,ACTION,SOURCE)
    assert result['status'] == 'available'
    assert result['label'] == 'suitable'
    assert result['rawScore'] == 0.63
    assert result['calibrated'] is False
    assert result['provenance']['sourceId'] == SOURCE['sourceId']
    assert backend.state['mission'] == MISSION
    assert backend.state['action'] == ACTION
    assert backend.state['source'] == SOURCE


def test_count_and_predict_share_one_ten_second_assessment_budget():
    import time
    class BudgetBackend(FakeBackend):
        def __init__(self):
            super().__init__();self.inside=False;self.deadline=None
        @contextmanager
        def budget(self,deadline):
            self.inside=True;self.deadline=deadline
            try: yield
            finally: self.inside=False
        def token_count(self,state,questions):
            assert self.inside
            return super().token_count(state,questions)
        def predict(self,state,questions):
            assert self.inside
            return super().predict(state,questions)
    backend=BudgetBackend()
    started=time.monotonic()
    assert LayaAssessment(backend).assess(MISSION,ACTION,SOURCE)['status']=='available'
    assert started+9.9 <= backend.deadline <= started+10.1


def test_token_budget_rejects_oversize_without_inference_or_truncation():
    backend = FakeBackend(tokens=301)
    result = LayaAssessment(backend).assess(MISSION,ACTION,SOURCE)
    assert result['status'] == 'input_too_large'
    assert result['truncationDetected'] is True
    assert result['label'] is None


def test_unserializable_source_is_unavailable_with_json_safe_provenance():
    source={'sourceId':'supplier-note','kind':'supplier_document','text':object()}
    result=LayaAssessment(FakeBackend()).assess(MISSION,ACTION,source)
    assert result['status']=='unavailable'
    assert result['provenance']['sourceId']=='supplier-note'
    assert result['provenance']['sourceDigest'] is None
    json.dumps(result,allow_nan=False)


def test_inference_input_validation_does_not_read_gold_labels(monkeypatch):
    import scripts.gate_laya as gate
    original=gate.read_jsonl
    def read(path):
        if path.name=='labels.jsonl':
            raise AssertionError('Gold labels were read before inference')
        return original(path)
    monkeypatch.setattr(gate,'read_jsonl',read)
    inputs=inference_inputs()
    assert len(inputs)==16
    assert input_digest(inputs[0])==input_digest(inputs[0])
    assert input_digest(inputs[0])!=input_digest(inputs[1])


def test_semantic_gate_contract_keeps_gold_labels_out_of_inference_inputs():
    root = Path(__file__).resolve().parents[1]
    process = subprocess.run([sys.executable,str(root/'scripts/gate_laya.py'),'--mode','contract'],
                             cwd=root,text=True,capture_output=True)
    assert process.returncode == 0, process.stderr
    report = json.loads(process.stdout)
    assert report['pairCount'] == 8
    assert report['inputCount'] == 16
    assert report['actualInference'] is False
    assert report['inferenceAttempted'] is False
    assert report['allAvailable'] is None
    for line in (root/'fixtures/semantic/inputs.jsonl').read_text().splitlines():
        assert '"label"' not in line


def test_infer_attempt_is_recorded_even_when_all_model_results_unavailable(monkeypatch,tmp_path):
    import scripts.gate_laya as gate
    import vibesecur.assessment as assessment
    calls=[]
    original_contract=gate.fixture_contract
    def fixture_contract_after_inference():
        assert len(calls)==16
        return original_contract()
    def unavailable(mission,action,source):
        calls.append(source['sourceId'])
        return gate_response(source)
    monkeypatch.setattr(gate,'fixture_contract',fixture_contract_after_inference)
    monkeypatch.setattr(assessment,'assess',unavailable)
    monkeypatch.setattr(gate,'checkpoint_manifest',lambda remote:{'revision':assessment.MODEL_REVISION})
    output=tmp_path/'laya-infer.json'
    monkeypatch.setattr(sys,'argv',['gate_laya.py','--mode','infer','--output',str(output)])
    assert gate.main()==2
    report=json.loads(output.read_text())
    assert report['inferenceAttempted'] is True
    assert report['actualInference'] is False
    assert report['allAvailable'] is False
    assert report['status']=='blocked'
    assert report['availableCount']==0
    assert report['unavailableCount']==16
    assert report['inputTooLargeCount']==0
    assert len(report['predictions'])==16


def test_partial_inference_keeps_availability_denominators_separate(monkeypatch,tmp_path):
    import scripts.gate_laya as gate
    import vibesecur.assessment as assessment
    calls=[]
    def partial(mission,action,source):
        calls.append(source['sourceId'])
        status='available' if len(calls)==1 else ('input_too_large' if len(calls)==2 else 'unavailable')
        return gate_response(source,status,'suitable' if status=='available' else None,
                             0.6 if status=='available' else None)
    monkeypatch.setattr(assessment,'assess',partial)
    monkeypatch.setattr(gate,'checkpoint_manifest',lambda remote:{'revision':assessment.MODEL_REVISION})
    output=tmp_path/'partial.json'
    monkeypatch.setattr(sys,'argv',['gate_laya.py','--mode','infer','--output',str(output)])
    assert gate.main()==2
    report=json.loads(output.read_text())
    assert report['inferenceAttempted'] is True
    assert report['actualInference'] is True and report['allAvailable'] is False
    assert (report['availableCount'],report['inputTooLargeCount'],report['unavailableCount'])==(1,1,14)
    assert report['status']=='blocked'
    assert report['correct'] in (0,1)


def test_checkpoint_manifest_rejects_unpinned_or_modified_cache(monkeypatch,tmp_path):
    import scripts.gate_laya as gate
    from vibesecur.assessment import MODEL_REVISION
    snapshot=tmp_path/MODEL_REVISION
    snapshot.mkdir()
    for name in gate.EXPECTED_CHECKPOINT_FILES:
        path=snapshot/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(b'wrong checkpoint bytes')
    monkeypatch.setattr(gate,'download_checkpoint',lambda remote:snapshot)
    try:
        gate.checkpoint_manifest(remote=False)
    except ValueError as exc:
        assert 'checksum' in str(exc)
    else:
        raise AssertionError('Modified cached checkpoint was accepted')
    renamed=tmp_path/'unrelated-revision'
    snapshot.rename(renamed)
    monkeypatch.setattr(gate,'download_checkpoint',lambda remote:renamed)
    try:
        gate.checkpoint_manifest(remote=False)
    except ValueError as exc:
        assert 'revision' in str(exc)
    else:
        raise AssertionError('Wrong checkpoint revision was accepted')


def test_checkpoint_manifest_records_only_verified_files(monkeypatch,tmp_path):
    import scripts.gate_laya as gate
    from vibesecur.assessment import MODEL_REVISION
    snapshot=tmp_path/MODEL_REVISION
    snapshot.mkdir()
    contents={name:name.encode() for name in gate.EXPECTED_CHECKPOINT_FILES}
    monkeypatch.setattr(gate,'EXPECTED_CHECKPOINT_FILES',
                        {name:hashlib.sha256(data).hexdigest() for name,data in contents.items()})
    for name,data in contents.items():
        path=snapshot/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
    monkeypatch.setattr(gate,'download_checkpoint',lambda remote:snapshot)
    manifest=gate.checkpoint_manifest(remote=False)
    assert manifest['revision']==MODEL_REVISION
    assert manifest['fileCount']==len(contents)
    assert {item['path'] for item in manifest['files']}==set(contents)
    assert len(manifest['snapshotSha256'])==64


def test_infer_rejects_malformed_available_output(monkeypatch,tmp_path):
    import scripts.gate_laya as gate
    import vibesecur.assessment as assessment
    monkeypatch.setattr(gate,'checkpoint_manifest',lambda remote:{'revision':assessment.MODEL_REVISION})
    def malformed(mission,action,source):
        return {'status':'available','label':'suitable','rawScore':1.5,
                'calibrated':False,'latencyMs':1,'truncationDetected':False,
                'modelRevision':assessment.MODEL_REVISION,
                'provenance':{'sourceId':source['sourceId'],
                              'sourceDigest':hashlib.sha256(json.dumps(source,sort_keys=True,
                              separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()}}
    monkeypatch.setattr(assessment,'assess',malformed)
    output=tmp_path/'invalid.json'
    monkeypatch.setattr(sys,'argv',['gate_laya.py','--mode','infer','--output',str(output)])
    assert gate.main()==2
    report=json.loads(output.read_text())
    assert report['status']=='blocked'
    assert report['actualInference'] is False
    assert report['availableCount']==0
    assert report['invalidOutputCount']==16


def test_infer_blocks_before_model_or_labels_when_checkpoint_is_unavailable(monkeypatch,tmp_path):
    import scripts.gate_laya as gate
    import vibesecur.assessment as assessment
    monkeypatch.setattr(gate,'checkpoint_manifest',lambda remote:(_ for _ in ()).throw(
        ValueError('Checkpoint checksum mismatch')))
    monkeypatch.setattr(assessment,'assess',lambda *args:(_ for _ in ()).throw(
        AssertionError('Model must not be called')))
    monkeypatch.setattr(gate,'fixture_contract',lambda:(_ for _ in ()).throw(
        AssertionError('Gold labels must not be opened')))
    output=tmp_path/'blocked.json'
    monkeypatch.setattr(sys,'argv',['gate_laya.py','--mode','infer','--output',str(output)])
    assert gate.main()==2
    report=json.loads(output.read_text())
    assert report['status']=='blocked'
    assert report['reason']=='checkpoint_unavailable_or_mismatch'
    assert report['inferenceAttempted'] is False
    assert report['actualInference'] is False


def test_prefetch_records_verified_checkpoint_without_inference(monkeypatch,tmp_path):
    import scripts.gate_laya as gate
    from vibesecur.assessment import MODEL_REVISION
    calls=[]
    def manifest(remote):
        calls.append(remote)
        return {'repo':'convaiinnovations/laya','revision':MODEL_REVISION,
                'fileCount':5,'snapshotSha256':'a'*64}
    monkeypatch.setattr(gate,'checkpoint_manifest',manifest)
    monkeypatch.setattr(gate,'fixture_contract',lambda:(_ for _ in ()).throw(
        AssertionError('Prefetch must not read gold labels')))
    output=tmp_path/'prefetch.json'
    monkeypatch.setattr(sys,'argv',['gate_laya.py','--mode','prefetch','--output',str(output)])
    assert gate.main()==0
    report=json.loads(output.read_text())
    assert calls==[True]
    assert report['status']=='prefetched'
    assert report['checkpoint']['revision']==MODEL_REVISION
    assert report['actualInference'] is False


def test_vm_gate_requires_explicit_slot_and_reviewed_lock():
    script=Path(__file__).resolve().parents[1]/'deploy/azure/gate-laya-vm.sh'
    syntax=subprocess.run(['bash','-n',str(script)],text=True,capture_output=True)
    assert syntax.returncode==0,syntax.stderr
    help_result=subprocess.run(['bash',str(script),'--help'],text=True,capture_output=True)
    assert help_result.returncode==0
    assert 'MemoryMax=5G' in help_result.stdout
    missing_slot=subprocess.run(['bash',str(script),'resolve'],text=True,capture_output=True)
    assert missing_slot.returncode!=0
    assert 'serial slot' in missing_slot.stderr.lower()
    missing_lock=subprocess.run(['bash',str(script),'prefetch','--slot-granted'],
                                text=True,capture_output=True)
    assert missing_lock.returncode!=0
    assert 'lock' in missing_lock.stderr.lower()


def test_vm_gate_rejects_spoofed_systemd_invocation_id():
    script=Path(__file__).resolve().parents[1]/'deploy/azure/gate-laya-vm.sh'
    environment=dict(os.environ,INVOCATION_ID='spoofed-systemd-id',HF_TOKEN='synthetic-secret')
    result=subprocess.run(['bash',str(script),'__inside','resolve','',
                           'vibesecur-laya-resolve-123.service'],
                          text=True,capture_output=True,env=environment)
    assert result.returncode!=0
    assert 'bounded systemd cgroup' in result.stderr.lower()


def test_vm_gate_rejects_unsafe_omission_and_ambiguous_index(tmp_path):
    script=Path(__file__).resolve().parents[1]/'deploy/azure/gate-laya-vm.sh'
    lock=tmp_path/'candidate.lock'
    package=('setuptools==84.0.0 '+chr(92)+'\n    --hash=sha256:'+
             '51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670'+'\n')
    lock.write_text('--only-binary :all:\n'+package+
                    '# WARNING: The following packages were not pinned\n')
    result=subprocess.run(['bash',str(script),'check-candidate-lock',str(lock)],
                          text=True,capture_output=True)
    assert result.returncode!=0
    assert 'unsafe' in result.stderr.lower() or 'warning' in result.stderr.lower()
    lock.write_text('--only-binary :all:\n'+package)
    result=subprocess.run(['bash',str(script),'check-candidate-lock',str(lock)],
                          text=True,capture_output=True)
    assert result.returncode!=0
    assert 'index' in result.stderr.lower()


def test_vm_gate_accepts_explicit_hashed_setuptools_with_index(tmp_path):
    script=Path(__file__).resolve().parents[1]/'deploy/azure/gate-laya-vm.sh'
    lock=tmp_path/'candidate.lock'
    package=('setuptools==84.0.0 '+chr(92)+'\n    --hash=sha256:'+
             '51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670'+'\n')
    lock.write_text('--index-url https://pypi.org/simple\n--only-binary :all:\n'+package)
    result=subprocess.run(['bash',str(script),'check-candidate-lock',str(lock)],
                          text=True,capture_output=True)
    assert result.returncode==0,result.stderr
    lock.write_text('--index-url https://pypi.org/simple\n--only-binary :all:\n'
                    'setuptools==84.0.0\n')
    result=subprocess.run(['bash',str(script),'check-candidate-lock',str(lock)],
                          text=True,capture_output=True)
    assert result.returncode!=0
    assert 'hashed setuptools' in result.stderr.lower()
    lock.write_text('--index-url https://pypi.org/simple\n# --no-index\n'+package)
    result=subprocess.run(['bash',str(script),'check-candidate-lock',str(lock)],
                          text=True,capture_output=True)
    assert result.returncode!=0
    assert 'no-index' in result.stderr.lower()


def test_vm_gate_normalizes_suppressed_default_index_with_provenance(tmp_path):
    script=Path(__file__).resolve().parents[1]/'deploy/azure/gate-laya-vm.sh'
    raw=tmp_path/'raw.lock';lock=tmp_path/'normalized.lock'
    provenance=tmp_path/'provenance.json';source=tmp_path/'requirements.in'
    source.write_text('setuptools==84.0.0\n')
    raw.write_text('--only-binary :all:\n\nsetuptools==84.0.0 '+chr(92)+'\n'
                   '    --hash=sha256:51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670\n')
    result=subprocess.run(['bash',str(script),'normalize-candidate-lock',str(raw),
                           str(lock),str(provenance),str(source)],
                          text=True,capture_output=True)
    assert result.returncode==0,result.stderr
    assert lock.read_text().startswith('--index-url https://pypi.org/simple\n')
    recorded=json.loads(provenance.read_text())
    assert recorded['indexLineSource']=='explicit install-policy normalization'
    assert recorded['compilerBodySha256']==hashlib.sha256(raw.read_bytes()).hexdigest()
    assert recorded['normalizedLockSha256']==hashlib.sha256(lock.read_bytes()).hexdigest()
    raw.write_text('--only-binary :all:\n--extra-index-url https://other.invalid/simple\n')
    result=subprocess.run(['bash',str(script),'normalize-candidate-lock',str(raw),
                           str(lock),str(provenance),str(source)],
                          text=True,capture_output=True)
    assert result.returncode!=0
