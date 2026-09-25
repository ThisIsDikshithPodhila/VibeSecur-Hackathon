"""Verifier-owned ledger service. Never loaded from the candidate checkout."""
import hmac
import os
import uuid
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from vibesecur.store import Store, StoreError

app = FastAPI()
store = Store(os.environ.get('VERIFIER_STORE_PATH', '/state/effects.sqlite'))
run = store.create_run('independent-verifier', 'replay')
environment_id = run['baseline']['environmentId']
store.set_compensating_rule(environment_id, False)
store.set_attempt(environment_id, 'verification-attempt-' + uuid.uuid4().hex)


def authorize(value, expected):
    if not value or not hmac.compare_digest(value, 'Bearer ' + expected):
        raise HTTPException(403, 'Invalid verifier capability')


def service_auth(environment, authorization):
    authorize(authorization, os.environ['EFFECT_STORE_TOKEN'])
    if environment != environment_id:
        raise HTTPException(403, 'Environment outside service capability')


@app.exception_handler(StoreError)
async def store_error(request, exc):
    return JSONResponse(status_code=exc.status, content={'error':exc.code,'message':exc.message})


@app.get('/health')
def health():
    return {'status':'ok'}


@app.get('/control/state')
def state(authorization: str | None = Header(default=None)):
    authorize(authorization, os.environ['VERIFIER_CONTROL_TOKEN'])
    return {'environment':store.environment(environment_id),'transaction':store.transaction(environment_id)}


@app.post('/control/approve')
def approve(body:dict, authorization: str | None = Header(default=None)):
    authorize(authorization, os.environ['VERIFIER_CONTROL_TOKEN'])
    return store.approve(environment_id, body['snapshot'], 'independent-verifier', int(body.get('ttlSeconds',600)))


@app.post('/control/revise-invoice')
def revise_invoice(body:dict, authorization: str | None = Header(default=None)):
    authorize(authorization, os.environ['VERIFIER_CONTROL_TOKEN'])
    return store.update_invoice(environment_id, amount_minor=body['amountMinor'])


@app.post('/control/set-attempt')
def set_attempt(body:dict, authorization: str | None = Header(default=None)):
    authorize(authorization, os.environ['VERIFIER_CONTROL_TOKEN'])
    store.set_attempt(environment_id, body['attemptId'])
    return {'status':'set'}


@app.post('/control/revoke-approval')
def revoke_approval(body:dict, authorization: str | None = Header(default=None)):
    authorize(authorization, os.environ['VERIFIER_CONTROL_TOKEN'])
    store.revoke_approval(environment_id, body['approvalId'])
    return {'status':'revoked'}


@app.get('/internal/environments/{environment}')
def environment(environment:str, authorization: str | None = Header(default=None)):
    service_auth(environment, authorization)
    return store.environment(environment)


@app.post('/internal/environments/{environment}/payments')
def commit(environment:str, body:dict, authorization: str | None = Header(default=None)):
    service_auth(environment, authorization)
    return store.commit(environment, body)
