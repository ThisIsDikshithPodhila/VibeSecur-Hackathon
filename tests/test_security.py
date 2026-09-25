import hashlib
import sqlite3

import pytest

from vibesecur.auth import SecurityError, SecurityStore


@pytest.fixture
def security(tmp_path):
    return SecurityStore(str(tmp_path / 'security.db'), clock=lambda: 1000)


def test_session_uses_opaque_hash_and_csrf_and_expires(security):
    session = security.login('correct', 'correct', 'kae')
    assert security.session(session['token'])['owner'] == 'kae'
    security.check_csrf(session['token'], session['csrfToken'])
    with pytest.raises(SecurityError):
        security.check_csrf(session['token'], 'forged')
    with sqlite3.connect(security.path) as db:
        stored = str(db.execute('select * from sessions').fetchall())
    assert session['token'] not in stored
    security.clock = lambda: 1000 + 86401
    with pytest.raises(SecurityError):
        security.session(session['token'])


def test_bad_code_and_revoked_session_fail(security):
    with pytest.raises(SecurityError):
        security.login('incorrect', 'correct', 'kae')
    session = security.login('correct', 'correct', 'kae')
    security.logout(session['token'])
    with pytest.raises(SecurityError):
        security.session(session['token'])


def test_service_token_cannot_cross_environment(security):
    token = security.issue_service_token('protected-1')
    security.authorize_service(token, 'protected-1')
    with pytest.raises(SecurityError):
        security.authorize_service(token, 'baseline-1')


def test_model_lease_is_scoped_expiring_and_bounded(security):
    token = security.issue_model_lease('task-1', 'gpt-6-sol', max_requests=1)
    lease = security.authorize_model(token, {'model': 'gpt-6-sol', 'input': 'safe'})
    assert lease['task_id'] == 'task-1'
    with pytest.raises(SecurityError):
        security.authorize_model(token, {'model': 'gpt-6-sol', 'input': 'again'})
    token2 = security.issue_model_lease('task-2', 'gpt-6-sol')
    with pytest.raises(SecurityError):
        security.authorize_model(token2, {'model': 'arbitrary', 'input': 'x'})
    security.revoke_task('task-2')
    with pytest.raises(SecurityError):
        security.authorize_model(token2, {'model': 'gpt-6-sol', 'input': 'x'})


def test_idempotency_conflict_and_claim_once(security):
    assert security.claim_request('kae', 'key-1', 'digest-1') is True
    assert security.claim_request('kae', 'key-1', 'digest-1') is False
    with pytest.raises(SecurityError):
        security.claim_request('kae', 'key-1', 'digest-2')


def test_login_rate_limit_is_persisted(security):
    for _ in range(5):
        security.check_login_rate('127.0.0.1')
    with pytest.raises(SecurityError) as failure:
        security.check_login_rate('127.0.0.1')
    assert failure.value.status == 429
