"""Persistent, opaque capabilities. Only the trusted controller issues these."""
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sqlite3
import time
from contextlib import contextmanager


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class SecurityError(Exception):
    def __init__(self, message='Unauthorized', status=403):
        super().__init__(message)
        self.message = message
        self.status = status


class SecurityStore:
    def __init__(self, path, clock=time.time):
        self.path, self.clock = path, clock
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS sessions (
                hash TEXT PRIMARY KEY, owner TEXT NOT NULL, csrf TEXT NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS service_tokens (
                hash TEXT PRIMARY KEY, environment TEXT NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS leases (
                hash TEXT PRIMARY KEY, task_id TEXT NOT NULL, model TEXT NOT NULL, expires REAL NOT NULL,
                requests INTEGER NOT NULL DEFAULT 0, max_requests INTEGER NOT NULL,
                reserved INTEGER NOT NULL DEFAULT 0, budget INTEGER NOT NULL, max_output INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS requests (
                owner TEXT NOT NULL, key TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(owner,key));
            CREATE TABLE IF NOT EXISTS login_attempts (source TEXT NOT NULL, timestamp REAL NOT NULL);
            ''')

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def check_login_rate(self, source):
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM login_attempts WHERE timestamp<?', (self.clock()-60,))
            n = db.execute('SELECT count(*) FROM login_attempts WHERE source=?', (source,)).fetchone()[0]
            if n >= 5:
                raise SecurityError('Too many login attempts; try again in one minute', 429)
            db.execute('INSERT INTO login_attempts VALUES (?,?)', (source, self.clock()))

    def login(self, supplied, expected, owner='kae'):
        if not expected or not hmac.compare_digest(digest(supplied), digest(expected)):
            raise SecurityError('Invalid presenter code', 401)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self._db() as db:
            db.execute('INSERT INTO sessions VALUES (?,?,?,?)',
                       (digest(token), owner, csrf, self.clock()+86400))
        return {'token': token, 'csrfToken': csrf, 'owner': owner}

    def session(self, token):
        with self._db() as db:
            row = db.execute('SELECT * FROM sessions WHERE hash=? AND expires>?',
                             (digest(token or ''), self.clock())).fetchone()
        if row is None:
            raise SecurityError('Presenter session required', 401)
        return dict(row)

    def check_csrf(self, token, csrf):
        if not hmac.compare_digest(self.session(token)['csrf'], csrf or ''):
            raise SecurityError('Invalid CSRF token')

    def logout(self, token):
        with self._db() as db:
            db.execute('DELETE FROM sessions WHERE hash=?', (digest(token or ''),))

    def issue_service_token(self, environment, ttl=86400):
        token = secrets.token_urlsafe(32)
        with self._db() as db:
            db.execute('INSERT INTO service_tokens VALUES (?,?,?)',
                       (digest(token), environment, self.clock()+ttl))
        return token

    def authorize_service(self, token, environment):
        with self._db() as db:
            row = db.execute('SELECT environment FROM service_tokens WHERE hash=? AND expires>?',
                             (digest(token or ''), self.clock())).fetchone()
        if row is None or not hmac.compare_digest(row['environment'], environment):
            raise SecurityError('Invalid environment capability')

    def revoke_environment(self, environment):
        with self._db() as db:
            db.execute('DELETE FROM service_tokens WHERE environment=?', (environment,))

    def issue_model_lease(self, task_id, model, ttl=600, max_requests=40,
                          max_output_tokens=4096, budget=1000000):
        token = secrets.token_urlsafe(32)
        with self._db() as db:
            db.execute('INSERT INTO leases(hash,task_id,model,expires,max_requests,budget,max_output) VALUES (?,?,?,?,?,?,?)',
                       (digest(token), task_id, model, self.clock()+ttl, max_requests, budget, max_output_tokens))
        return token

    def authorize_model(self, token, payload):
        # UTF8 input bytes + output cap is a conservative per-request token reservation.
        # Reservations survive timeout and never refund uncertain provider effects.
        size = len(json.dumps(payload, ensure_ascii=False).encode())
        if size > 256000:
            raise SecurityError('Model request exceeds input budget', 413)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM leases WHERE hash=? AND expires>?',
                             (digest(token or ''), self.clock())).fetchone()
            if row is None or payload.get('model') != row['model']:
                raise SecurityError('Invalid model capability')
            reserve = size + row['max_output']
            if row['requests'] >= row['max_requests'] or row['reserved'] + reserve > row['budget']:
                raise SecurityError('Task model budget exhausted', 429)
            db.execute('UPDATE leases SET requests=requests+1,reserved=reserved+? WHERE hash=?',
                       (reserve, digest(token)))
        return dict(row)

    def revoke_task(self, task_id):
        with self._db() as db:
            db.execute('DELETE FROM leases WHERE task_id=?', (task_id,))

    def claim_request(self, owner, key, payload_digest):
        if not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise SecurityError('Idempotency-Key must contain 1 to 128 characters', 400)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT digest FROM requests WHERE owner=? AND key=?', (owner, key)).fetchone()
            if row:
                if row['digest'] != payload_digest:
                    raise SecurityError('Idempotency key reused for another request', 409)
                return False
            db.execute('INSERT INTO requests VALUES (?,?,?)', (owner, key, payload_digest))
        return True
