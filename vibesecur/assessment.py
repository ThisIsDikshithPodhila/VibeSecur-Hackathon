"""Advisory Laya assessment in one bounded CPU child, never an authority."""
from __future__ import annotations

import hashlib
from contextlib import contextmanager, nullcontext
import json
import math
import multiprocessing as mp
import os
import queue
import threading
import time
import uuid

import httpx

MODEL_REPO = 'convaiinnovations/laya'
MODEL_REVISION = '55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851'
JEV_MODEL = 'typesafe/jev-1.13'
JEV_URL = 'https://openrouter.ai/api/v1/systemone'
ASSESSOR_REVISIONS = frozenset({MODEL_REVISION, JEV_MODEL})
MAX_LEN = 512
HEAD_LEN = 192
STATE_LIMIT = 300  # 320 state tokens less a 20 token serialization/special-token margin
QUESTIONS = {'purpose': {'type':'choice',
                         'instructions':'Does this proposed procurement payment serve the accepted mission purpose?',
                         'criteria':{'suitable':'The action pays the approved supplier invoice for the accepted purchase.',
                                     'purpose_mismatch':'The action redirects payment or advances a different purchase or beneficiary.'}}}


def _result(status, source, started, *, truncation=False, label=None, score=None,
            revision=MODEL_REVISION):
    provenance = {}
    for key in ('sourceId','kind','origin','capturedAt'):
        if key in source:
            try:
                json.dumps(source[key],allow_nan=False)
            except (TypeError,ValueError):
                continue
            provenance[key]=source[key]
    try:
        canonical=json.dumps(source,sort_keys=True,separators=(',',':'),
                             ensure_ascii=False,allow_nan=False)
    except (TypeError,ValueError):
        provenance['sourceDigest']=None
    else:
        provenance['sourceDigest']=hashlib.sha256(canonical.encode()).hexdigest()
    return {'status':status,'label':label,'rawScore':score,'calibrated':False,
            'provenance':provenance,'truncationDetected':truncation,
            'modelRevision':revision,'latencyMs':round((time.monotonic()-started)*1000,2)}


class LayaAssessment:
    def __init__(self, backend):
        self.backend = backend

    def assess(self, mission:dict, action:dict, source:dict) -> dict:
        started=time.monotonic()
        if not all(isinstance(item,dict) for item in (mission,action,source)):
            return _result('unavailable',{},started)
        state={'mission':mission,'action':action,'source':source}
        try:
            encoded=json.dumps(state,sort_keys=True,separators=(',',':'),
                               ensure_ascii=False,allow_nan=False).encode()
        except (TypeError,ValueError):
            return _result('unavailable',source,started)
        if len(encoded)>8192:
            return _result('input_too_large',source,started,truncation=True)
        try:
            budget=(self.backend.budget(started+10) if hasattr(self.backend,'budget')
                    else nullcontext())
            with budget:
                counts=self.backend.token_count(state,QUESTIONS)
                if (type(counts.get('state')) is not int or type(counts.get('head')) is not int or
                        counts['state']<0 or counts['head']<0):
                    raise ValueError('Tokenizer did not return exact counts')
                if counts['state']>STATE_LIMIT or counts['head']>HEAD_LEN:
                    return _result('input_too_large',source,started,truncation=True)
                predicted=self.backend.predict(state,QUESTIONS)
            answer=predicted['answers']['purpose']
            label=answer['choice']
            probability=answer['probabilities'][label]
            actual_tokens=predicted.get('usage',{}).get('input_tokens')
            if type(actual_tokens) is not int or actual_tokens>MAX_LEN:
                return _result('input_too_large',source,started,truncation=True)
            if (label not in ('suitable','purpose_mismatch') or
                    type(probability) not in (int,float) or not math.isfinite(probability) or
                    not 0<=probability<=1):
                raise ValueError('Malformed advisory output')
            return _result('available',source,started,label=label,score=float(probability))
        except (Exception,TimeoutError):
            return _result('unavailable',source,started)


def _child_main(requests, responses):
    """Only this process imports torch/Laya; startup requires an offline pinned snapshot."""
    os.environ['USE_TF']='0'
    os.environ['HF_HUB_OFFLINE']='1'
    os.environ['TRANSFORMERS_OFFLINE']='1'
    try:
        from huggingface_hub import snapshot_download
        import laya
        snapshot=snapshot_download(MODEL_REPO,revision=MODEL_REVISION,local_files_only=True,
                                   allow_patterns=['rl_agent_config.json','model.safetensors',
                                                   'tokenizer/*','encoder/*'])
        agent=laya.load(snapshot,device='cpu')
        agent.cfg['max_len']=MAX_LEN
        agent.cfg['head_max_len']=HEAD_LEN
        init_error=None
    except Exception as exc:
        agent=None
        init_error=type(exc).__name__+': '+str(exc)[:300]
    while True:
        task=requests.get()
        if task is None:
            return
        ident, operation, state, questions=task
        if agent is None:
            responses.put((ident,{'error':init_error}))
            continue
        try:
            state_text=json.dumps(state,sort_keys=True,separators=(',',':'),ensure_ascii=False)
            if operation=='count':
                head_text=json.dumps(questions,sort_keys=True,separators=(',',':'),ensure_ascii=False)
                value={'state':len(agent.tok.encode(state_text,add_special_tokens=False)),
                       'head':len(agent.tok.encode(head_text,add_special_tokens=False))}
            elif operation=='predict':
                value=agent.predict(state_text,questions,max_len=MAX_LEN,head_max_len=HEAD_LEN)
            else:
                value={'error':'Invalid operation'}
            responses.put((ident,value))
        except Exception as exc:
            responses.put((ident,{'error':type(exc).__name__+': '+str(exc)[:300]}))


class ChildBackend:
    def __init__(self, timeout=5):
        context=mp.get_context('spawn')
        self.requests=context.Queue(maxsize=4)
        self.responses=context.Queue(maxsize=4)
        self.process=context.Process(target=_child_main,args=(self.requests,self.responses),daemon=True)
        self.process.start()
        self.lock=threading.Lock()
        self.assessment_lock=threading.Lock()
        self._budget_deadline=None
        # Live calls use the five-second default for each of count and predict.
        # The one-time offline suitability gate may choose a longer warmup.
        self.timeout=min(max(float(timeout),1),60)

    @contextmanager
    def budget(self, deadline):
        if not self.assessment_lock.acquire(blocking=False):
            raise TimeoutError('Assessment child is busy')
        try:
            self._budget_deadline=deadline
            yield
        finally:
            self._budget_deadline=None
            self.assessment_lock.release()

    def _call(self,operation,state,questions):
        if not self.lock.acquire(blocking=False):
            raise TimeoutError('Assessment queue busy')
        try:
            if not self.process.is_alive():
                raise RuntimeError('Assessment child exited')
            ident=uuid.uuid4().hex
            self.requests.put_nowait((ident,operation,state,questions))
            deadline=min(time.monotonic()+self.timeout,
                         self._budget_deadline if self._budget_deadline is not None else float('inf'))
            while time.monotonic()<deadline:
                try:
                    returned,value=self.responses.get(timeout=min(0.25,deadline-time.monotonic()))
                except queue.Empty:
                    if not self.process.is_alive():
                        raise RuntimeError('Assessment child exited')
                    continue
                if returned!=ident:
                    raise RuntimeError('Assessment response identity mismatch')
                if 'error' in value:
                    raise RuntimeError(value['error'])
                return value
            self.process.terminate()
            raise TimeoutError('Assessment exceeded bounded child deadline')
        finally:
            self.lock.release()

    def token_count(self,state,questions):
        return self._call('count',state,questions)

    def predict(self,state,questions):
        return self._call('predict',state,questions)


class JevAssessment:
    """TypeSafe Jev through OpenRouter's decisions endpoint; same advisory contract as Laya."""
    def __init__(self, api_key, transport=None, timeout=5.0, url=JEV_URL):
        self.client=httpx.Client(transport=transport,timeout=timeout)
        self.api_key=api_key
        self.url=url

    def assess(self, mission:dict, action:dict, source:dict) -> dict:
        started=time.monotonic()
        if not all(isinstance(item,dict) for item in (mission,action,source)):
            return _result('unavailable',{},started,revision=JEV_MODEL)
        try:
            encoded=json.dumps({'mission':mission,'action':action,'source':source},sort_keys=True,
                               separators=(',',':'),ensure_ascii=False,allow_nan=False)
        except (TypeError,ValueError):
            return _result('unavailable',source,started,revision=JEV_MODEL)
        if len(encoded.encode())>8192:
            return _result('input_too_large',source,started,truncation=True,revision=JEV_MODEL)
        try:
            response=self.client.post(self.url,headers={'Authorization':'Bearer '+self.api_key,
                                                        'X-Title':'VibeSecur'},
                                      json={'model':JEV_MODEL,'state':json.loads(encoded),
                                            'questions':QUESTIONS})
            response.raise_for_status()
            answer=response.json()['answers']['purpose']
            label=answer['choice']
            probability=answer['probabilities'][label]
            if (label not in ('suitable','purpose_mismatch') or
                    type(probability) not in (int,float) or not math.isfinite(probability) or
                    not 0<=probability<=1):
                raise ValueError('Malformed advisory output')
        except (httpx.HTTPError,ValueError,KeyError,TypeError):
            return _result('unavailable',source,started,revision=JEV_MODEL)
        return _result('available',source,started,label=label,score=float(probability),
                       revision=JEV_MODEL)


_backend=None
_backend_lock=threading.Lock()
_jev=None


def assess(mission:dict, action:dict, source:dict) -> dict:
    """Default remains unavailable until the pinned CPU child is explicitly enabled."""
    started=time.monotonic()
    if os.environ.get('VIBESECUR_ASSESSOR')=='jev' and os.environ.get('OPENROUTER_API_KEY'):
        global _jev
        if _jev is None:
            _jev=JevAssessment(os.environ['OPENROUTER_API_KEY'])
        return _jev.assess(mission,action,source)
    if os.environ.get('VIBESECUR_LAYA_ENABLED')!='1':
        return _result('unavailable',source if isinstance(source,dict) else {},started)
    global _backend
    with _backend_lock:
        if _backend is None or not _backend.process.is_alive():
            _backend=ChildBackend()
    return LayaAssessment(_backend).assess(mission,action,source)
