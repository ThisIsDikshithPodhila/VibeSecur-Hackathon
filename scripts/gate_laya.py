#!/usr/bin/env python3
"""Separate fixture contract from actual pinned Laya semantic inference."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

# SHA-256 of the five files at the pinned Hub commit. The weight digest is the
# Hub LFS object digest; the small-file digests were measured from resolve URLs
# at that same commit. The gate hashes its local cache before any model call.
EXPECTED_CHECKPOINT_FILES={
    'encoder/config.json':'bf3ab80598fdccf414855a2ce80f22859e4492d06ca8a62ddd1cfb63972f8979',
    'model.safetensors':'891102d372688fc2a094dac56a384bc537b87c63f21f9f3dac0be2b7cbc8d86c',
    'rl_agent_config.json':'ae287b56bbcf5f8c4f4541ae9dfd00c914c4c48b940b8398c3058af37ba92bbd',
    'tokenizer/tokenizer.json':'6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30',
    'tokenizer/tokenizer_config.json':'50044de60daaa73df97d262e15a40d4faf0160e7d742df64b377877a1320dd12',
}


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def inference_inputs():
    """Validate exactly what crosses the Laya boundary, without opening labels."""
    inputs=read_jsonl(ROOT/'fixtures/semantic/inputs.jsonl')
    if len(inputs)!=16 or len({item.get('id') for item in inputs})!=16:
        raise ValueError('Expected 16 unique semantic inference inputs')
    for item in inputs:
        if (set(item)!={'id','pairId','mission','action','source'} or
                not isinstance(item['id'],str) or not isinstance(item['pairId'],str) or
                not all(isinstance(item[key],dict) for key in ('mission','action','source'))):
            raise ValueError('Inference input leaked a label or omitted a required field')
    return inputs


def input_digest(item):
    payload={key:item[key] for key in ('mission','action','source')}
    canonical=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False,
                         allow_nan=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def download_checkpoint(remote):
    from huggingface_hub import snapshot_download
    from vibesecur.assessment import MODEL_REPO,MODEL_REVISION
    return Path(snapshot_download(MODEL_REPO,revision=MODEL_REVISION,
                                  local_files_only=not remote,
                                  allow_patterns=list(EXPECTED_CHECKPOINT_FILES)))


def checkpoint_manifest(remote):
    """Verify the pinned cache without importing or loading the model."""
    from vibesecur.assessment import MODEL_REPO,MODEL_REVISION
    snapshot=Path(download_checkpoint(remote))
    if snapshot.name!=MODEL_REVISION:
        raise ValueError('Checkpoint cache revision differs from pin')
    files=[]
    for name,expected in sorted(EXPECTED_CHECKPOINT_FILES.items()):
        path=snapshot/name
        if not path.is_file():
            raise ValueError('Checkpoint file missing: '+name)
        digest=hashlib.sha256()
        size=0
        with path.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''):
                digest.update(chunk)
                size+=len(chunk)
        if digest.hexdigest()!=expected:
            raise ValueError('Checkpoint checksum mismatch: '+name)
        files.append({'path':name,'sha256':expected,'bytes':size})
    canonical=json.dumps(files,sort_keys=True,separators=(',',':'))
    return {'repo':MODEL_REPO,'revision':MODEL_REVISION,'fileCount':len(files),
            'files':files,'snapshotSha256':hashlib.sha256(canonical.encode()).hexdigest()}


def source_digest(source):
    canonical=json.dumps(source,sort_keys=True,separators=(',',':'),
                         ensure_ascii=False,allow_nan=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def typed_response_valid(item,response):
    from vibesecur.assessment import MODEL_REVISION
    if not isinstance(response,dict) or response.get('status') not in (
            'available','unavailable','input_too_large'):
        return False
    provenance=response.get('provenance')
    if (response.get('modelRevision')!=MODEL_REVISION or response.get('calibrated') is not False or
            not isinstance(provenance,dict) or
            provenance.get('sourceId')!=item['source'].get('sourceId') or
            provenance.get('sourceDigest')!=source_digest(item['source']) or
            type(response.get('truncationDetected')) is not bool):
        return False
    latency=response.get('latencyMs')
    if type(latency) not in (int,float) or not math.isfinite(latency) or latency<0:
        return False
    status=response['status']
    if status=='available':
        score=response.get('rawScore')
        return (response.get('label') in ('suitable','purpose_mismatch') and
                type(score) in (int,float) and math.isfinite(score) and 0<=score<=1 and
                response['truncationDetected'] is False)
    return (response.get('label') is None and response.get('rawScore') is None and
            response['truncationDetected'] is (status=='input_too_large'))


def fixture_contract():
    inputs=inference_inputs()
    labels=read_jsonl(ROOT/'fixtures/semantic/labels.jsonl')
    if len(labels)!=16:
        raise ValueError('Expected exactly 16 separate semantic inputs and labels')
    by_id={item['id']:item for item in labels}
    if len(by_id)!=16:
        raise ValueError('Duplicate semantic case identifiers')
    pairs={}
    for item in inputs:
        if item['id'] not in by_id:
            raise ValueError('Inference input lacks a separate gold label')
        label=by_id[item['id']]
        if set(label)!={'id','pairId','label'} or label['pairId']!=item['pairId']:
            raise ValueError('Gold label shape or pair mismatch')
        if label['label'] not in ('suitable','purpose_mismatch'):
            raise ValueError('Unknown gold label')
        pairs.setdefault(item['pairId'],[]).append((item,label))
    if len(pairs)!=8 or any(len(items)!=2 or {gold['label'] for _,gold in items}!=
                            {'suitable','purpose_mismatch'} for items in pairs.values()):
        raise ValueError('Expected eight opposite-label procurement pairs')
    for items in pairs.values():
        if items[0][0]['mission']!=items[1][0]['mission'] or items[0][0]['source']!=items[1][0]['source']:
            raise ValueError('Paired cases must share mission and source')
    return inputs,by_id,pairs


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--mode',choices=['contract','infer','prefetch'],required=True)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.mode=='prefetch':
        from vibesecur.assessment import MODEL_REVISION
        try:
            manifest=checkpoint_manifest(remote=True)
        except (OSError,ValueError,ImportError) as exc:
            result={'status':'blocked','reason':'checkpoint_unavailable_or_mismatch',
                    'checkpointError':type(exc).__name__,'modelRevision':MODEL_REVISION,
                    'inferenceAttempted':False,'actualInference':False,'allAvailable':None}
            code=2
        else:
            result={'status':'prefetched','modelRevision':manifest['revision'],'checkpoint':manifest,
                    'inferenceAttempted':False,'actualInference':False,'allAvailable':None}
            code=0
    else:
        inputs=inference_inputs() if args.mode=='infer' else fixture_contract()[0]
        from vibesecur.assessment import MODEL_REVISION
        from vibesecur.assessment import MAX_LEN,HEAD_LEN,STATE_LIMIT
        result={'status':'contract_valid','pairCount':8,'inputCount':len(inputs),
                'modelRevision':MODEL_REVISION,'inferenceAttempted':False,
                'actualInference':False,
                'allAvailable':None,
                'goldLabelsExcludedFromInputs':True,'calibrated':False,
                'inputBudget':{'maxModelTokens':MAX_LEN,'maxHeadTokens':HEAD_LEN,
                               'maxStateTokens':STATE_LIMIT}}
        code=0
        if args.mode=='infer':
            from vibesecur.assessment import assess
            try:
                result['checkpoint']=checkpoint_manifest(remote=False)
            except (OSError,ValueError,ImportError) as exc:
                result.update(status='blocked',reason='checkpoint_unavailable_or_mismatch',
                              checkpointError=type(exc).__name__)
                code=2
                rendered=json.dumps(result,indent=2,sort_keys=True)
                if args.output:
                    args.output.parent.mkdir(parents=True,exist_ok=True)
                    args.output.write_text(rendered+'\n')
                print(rendered)
                return code
            os.environ['VIBESECUR_LAYA_ENABLED']='1'
            predictions=[]
            invalid_outputs=0
            for item in inputs:
                response=assess(item['mission'],item['action'],item['source'])
                if not typed_response_valid(item,response):
                    invalid_outputs+=1
                    response={'status':'unavailable','label':None,'rawScore':None,
                              'latencyMs':None,'truncationDetected':False,
                              'provenance':{},'modelRevision':None}
                predictions.append({'id':item['id'],'pairId':item['pairId'],'status':response['status'],
                                    'inferenceInputDigest':input_digest(item),
                                    'label':response['label'],'rawScore':response['rawScore'],
                                    'calibrated':False,'latencyMs':response['latencyMs'],
                                    'truncationDetected':response['truncationDetected'],
                                    'modelRevision':response['modelRevision'],
                                    'provenance':response['provenance']})
            _,labels,pairs=fixture_contract()  # Gold labels are opened only after all inference calls.
            result['fixtureSha256']={
                name:hashlib.sha256((ROOT/'fixtures/semantic'/name).read_bytes()).hexdigest()
                for name in ('inputs.jsonl','labels.jsonl')}
            available=all(p['status']=='available' for p in predictions)
            status_counts={status:sum(p['status']==status for p in predictions)
                           for status in ('available','unavailable','input_too_large')}
            correct=sum(p['label']==labels[p['id']]['label'] for p in predictions if p['status']=='available')
            pair_correct=sum(all(p['status']=='available' and p['label']==labels[p['id']]['label']
                                 for p in predictions if p['pairId']==pair_id) for pair_id in pairs)
            result.update(status=('passed' if available and correct>=12 and pair_correct>=6 else
                                  'failed' if available else 'blocked'),
                          inferenceAttempted=True,
                          actualInference=status_counts['available']>0,
                          allAvailable=available,
                          availableCount=status_counts['available'],
                          invalidOutputCount=invalid_outputs,
                          unavailableCount=status_counts['unavailable'],
                          inputTooLargeCount=status_counts['input_too_large'],
                          correct=correct,correctPairs=pair_correct,predictions=predictions,
                          acceptance={'minimumCorrect':12,'minimumCorrectPairs':6})
            code=0 if result['status']=='passed' else 2
    rendered=json.dumps(result,indent=2,sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(rendered+'\n')
    print(rendered)
    return code


if __name__=='__main__':
    raise SystemExit(main())
