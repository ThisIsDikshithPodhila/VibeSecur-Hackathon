"""Transactional synthetic payment effects and durable demo runs.

Only the trusted control plane exposes this store. A worker never gets its path.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import re
import sqlite3
import time
import uuid
from typing import Callable


TRANSACTION_KEYS = (
    "environmentId", "workspaceId", "missionId", "invoiceId", "invoiceRevision",
    "supplierId", "supplierRevision", "beneficiaryAccount", "amountMinor", "currency",
)


class StoreError(Exception):
    def __init__(self, code: str, status: int, message: str):
        super().__init__(message)
        self.code, self.status, self.message = code, status, message


def _fail(code: str, status: int, message: str):
    raise StoreError(code, status, message)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(snapshot):
    return "vibesecur:transaction:v1:" + hashlib.sha256(_json(snapshot).encode("utf-8")).hexdigest()


def _transaction(data):
    if not isinstance(data, dict) or set(data) != set(TRANSACTION_KEYS):
        _fail("invalid_transaction", 400, "Exact transaction fields required")
    for key in ("invoiceRevision", "supplierRevision", "amountMinor"):
        if type(data[key]) is not int or data[key] <= 0:
            _fail("invalid_transaction", 400, f"{key} must be a positive integer")
    for key in set(TRANSACTION_KEYS) - {"invoiceRevision", "supplierRevision", "amountMinor"}:
        if not isinstance(data[key], str) or not data[key]:
            _fail("invalid_transaction", 400, f"{key} must be a nonempty string")
    return {key: data[key] for key in TRANSACTION_KEYS}


class Store:
    def __init__(self, path: str, clock: Callable = time.time):
        self.path, self.clock = str(path), clock
        with self._connection(write=True) as db:
            db.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, owner TEXT NOT NULL, data TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS environments (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, data TEXT NOT NULL)")

    @contextmanager
    def _connection(self, write=False):
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=15000")
        try:
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _read(self, db, table, identifier):
        row = db.execute(f"SELECT data FROM {table} WHERE id=?", (identifier,)).fetchone()
        if row is None:
            _fail("not_found", 404, f"{table[:-1]} not found")
        return json.loads(row["data"])

    def _save(self, db, table, identifier, data):
        db.execute(f"UPDATE {table} SET data=? WHERE id=?", (_json(data), identifier))

    def _view(self, db, run):
        result = dict(run)
        result["baseline"] = self._read(db, "environments", run["baselineId"])
        result["protected"] = self._read(db, "environments", run["protectedId"])
        result.pop("baselineId")
        result.pop("protectedId")
        return result

    def create_run(self, owner: str, mode: str = "replay") -> dict:
        if not isinstance(owner, str) or not owner:
            _fail("invalid_owner", 400, "Run owner required")
        if mode not in ("replay", "live"):
            _fail("invalid_mode", 400, "Mode must be replay or live")
        run_id = "run-" + uuid.uuid4().hex
        workspace = "workspace-" + uuid.uuid4().hex
        mission = "mission-" + uuid.uuid4().hex
        environments = []
        for label, rule in (("baseline", False), ("protected", True)):
            environments.append({
                "environmentId": "env-" + uuid.uuid4().hex,
                "workspaceId": workspace,
                "missionId": mission,
                "invoice": {"invoiceId": "INV-250000", "invoiceRevision": 1,
                            "amountMinor": 25000000, "currency": "AED"},
                "supplier": {"supplierId": "SUP-GULF", "supplierRevision": 1,
                             "beneficiaryAccount": "SYNTH-AE-GULF-001"},
                "approvals": [], "ledger": [], "compensatingRule": rule,
                "attemptId": None, "active": True,
            })
        run = {"runId": run_id, "owner": owner, "mode": mode, "state": "created",
               "createdAt": self.clock(), "baselineId": environments[0]["environmentId"],
               "protectedId": environments[1]["environmentId"], "events": [],
               "incident": None, "repair": None, "verification": None}
        with self._connection(write=True) as db:
            db.execute("INSERT INTO runs VALUES (?,?,?)", (run_id, owner, _json(run)))
            for env in environments:
                db.execute("INSERT INTO environments VALUES (?,?,?)",
                           (env["environmentId"], run_id, _json(env)))
            return self._view(db, run)

    def get_run(self, run_id: str, owner: str | None = None) -> dict:
        with self._connection() as db:
            run = self._read(db, "runs", run_id)
            if owner is not None and run["owner"] != owner:
                _fail("forbidden", 403, "Run belongs to another owner")
            return self._view(db, run)

    def list_runs(self, owner: str) -> list[dict]:
        with self._connection() as db:
            rows = db.execute("SELECT data FROM runs WHERE owner=? ORDER BY rowid DESC", (owner,)).fetchall()
            return [self._view(db, json.loads(row["data"])) for row in rows]

    def environment(self, environment_id: str) -> dict:
        with self._connection() as db:
            return self._read(db, "environments", environment_id)

    def run_for_environment(self, environment_id: str) -> dict:
        """Trusted control-plane lookup for a payment proposal's owning run."""
        with self._connection() as db:
            row = db.execute("SELECT run_id FROM environments WHERE id=?", (environment_id,)).fetchone()
            if row is None:
                _fail("not_found", 404, "Environment not found")
            return self._view(db, self._read(db, "runs", row["run_id"]))

    def transaction(self, environment_id: str) -> dict:
        env = self.environment(environment_id)
        return {
            "environmentId": env["environmentId"], "workspaceId": env["workspaceId"],
            "missionId": env["missionId"],
            **env["invoice"], **env["supplier"],
        }

    def approve(self, environment_id: str, snapshot: dict, principal: str, ttl_seconds: int = 600) -> dict:
        snapshot = _transaction(snapshot)
        if type(ttl_seconds) is not int or ttl_seconds <= 0 or not isinstance(principal, str) or not principal:
            _fail("invalid_approval", 400, "Principal and positive TTL required")
        with self._connection(write=True) as db:
            env = self._read(db, "environments", environment_id)
            if not env["active"]:
                _fail("inactive", 410, "Environment cancelled")
            current = self._current(env)
            if snapshot != current:
                _fail("stale_snapshot", 409, "Approval snapshot is not current")
            created = self.clock()
            approval = {"approvalId": "approval-" + uuid.uuid4().hex,
                        "snapshot": snapshot, "snapshotDigest": _digest(snapshot),
                        "principal": principal, "createdAt": created,
                        "expiresAt": created + ttl_seconds, "consumed": False, "revoked": False}
            env["approvals"].append(approval)
            self._save(db, "environments", environment_id, env)
            return approval

    @staticmethod
    def _current(env):
        return {"environmentId": env["environmentId"], "workspaceId": env["workspaceId"],
                "missionId": env["missionId"], **env["invoice"], **env["supplier"]}

    def commit(self, environment_id: str, command: dict) -> dict:
        if not isinstance(command, dict) or set(command) != set(TRANSACTION_KEYS) | {"approvalId", "operationId", "attemptId"}:
            _fail("invalid_command", 400, "Exact payment command fields required")
        transaction = _transaction({key: command[key] for key in TRANSACTION_KEYS})
        if any(not isinstance(command[key], str) or not command[key] for key in ("approvalId", "operationId", "attemptId")):
            _fail("invalid_command", 400, "Payment identifiers required")
        denied = None
        receipt = None
        with self._connection(write=True) as db:
            env = self._read(db, "environments", environment_id)
            run_id = db.execute("SELECT run_id FROM environments WHERE id=?", (environment_id,)).fetchone()["run_id"]
            run = self._read(db, "runs", run_id)
            prior_decisions = run.get("paymentDecisions") or []
            previous = next((item for item in env["ledger"] if item["operationId"] == command["operationId"]), None)
            if previous:
                if previous["transaction"] == transaction and previous["approvalId"] == command["approvalId"]:
                    return previous
                _fail("operation_conflict", 409, "Operation identity already used")
            approval = next((item for item in env["approvals"] if item["approvalId"] == command["approvalId"]), None)
            earlier = next((item for item in prior_decisions
                            if item["environmentId"] == environment_id and
                            item["operationId"] == command["operationId"]), None)
            if earlier:
                if (earlier["attemptedTransaction"] != transaction or
                        earlier["approvalId"] != command["approvalId"]):
                    _fail("operation_conflict", 409, "Operation identity already used")
                _fail(earlier["reason"], earlier.get("status", 403), "Payment operation was denied")
            try:
                if not env["active"]:
                    _fail("inactive", 410, "Environment cancelled")
                if transaction["environmentId"] != environment_id or any(
                        transaction[key] != env[key] for key in ("workspaceId", "missionId")):
                    _fail("scope_mismatch", 403, "Payment outside environment scope")
                if command["attemptId"] != env["attemptId"]:
                    _fail("attempt_mismatch", 403, "Payment attempt is not live")
                conversation = run.get("conversation") if run["mode"] == "live" else None
                if conversation is not None:
                    if environment_id != run["protectedId"]:
                        _fail("employee_baseline_denied", 403, "Employee payment uses protected environment")
                    active_id = conversation.get("activeTurnId")
                    turn = next((item for item in conversation.get("turns", [])
                                 if item["turnId"] == active_id), None)
                    if not turn or turn["status"] != "running" or turn["scope"] != "pay_approved":
                        _fail("turn_scope_denied", 403, "Active approved payment turn required")
                    mandate = run.get("standingDemoAuthorization") or {}
                    if (mandate.get("source") != "trusted_demo_setup" or
                            mandate.get("provenance") != "user_configured_synthetic_demo" or
                            mandate.get("owner") != run["owner"] or mandate.get("runId") != run_id or
                            mandate.get("workspaceId") != transaction["workspaceId"] or
                            mandate.get("missionId") != transaction["missionId"] or
                            mandate.get("approvalId") != command["approvalId"] or
                            self.clock() >= mandate.get("expiresAt", 0)):
                        _fail("mandate_unavailable", 403, "Trusted payment mandate unavailable")
                    if mandate.get("snapshot") != transaction:
                        _fail("transaction_mismatch", 403, "Payment differs from trusted mandate")
                if approval is None:
                    _fail("approval_missing", 403, "Payment approval not found")
                if approval["revoked"] or self.clock() >= approval["expiresAt"]:
                    _fail("approval_unavailable", 410, "Approval revoked or expired")
                if approval["consumed"]:
                    _fail("approval_consumed", 409, "Approval already consumed")
                if any(item["transaction"]["invoiceId"] == transaction["invoiceId"] for item in env["ledger"]):
                    _fail("invoice_paid", 409, "Invoice already paid")
                current = self._current(env)
                for key in ("invoiceId", "invoiceRevision", "supplierId", "supplierRevision"):
                    if transaction[key] != current[key]:
                        _fail("stale_record", 409, "Invoice or supplier record changed")
                if env["compensatingRule"] and transaction != approval["snapshot"]:
                    _fail("transaction_mismatch", 403, "Payment differs from exact approval")
            except StoreError as error:
                denied = error
                self._record_payment_decision(db, run, env, command, transaction,
                                              approval, "denied", error.code, error.status)
            else:
                approval["consumed"] = True
                receipt = {"operationId": command["operationId"], "environmentId": environment_id,
                           "transaction": transaction, "approvalId": command["approvalId"],
                           "committedAt": self.clock(), "status": "committed"}
                env["ledger"].append(receipt)
                self._save(db, "environments", environment_id, env)
                self._record_payment_decision(db, run, env, command, transaction,
                                              approval, "committed", "approved", 200)
                self._append_event(db, run_id, "effect_committed", {
                    "environmentId": environment_id, "operationId": command["operationId"],
                    "approvalId": command["approvalId"],
                    "receiptDigest": hashlib.sha256(_json(receipt).encode()).hexdigest(),
                })
        if denied is not None:
            raise denied
        return receipt

    def reject_payment(self, environment_id: str, command: dict, code: str,
                       message: str, status: int = 403) -> dict:
        """Persist a trusted preflight denial before the service returns it."""
        if (not isinstance(command, dict) or
                set(command) != set(TRANSACTION_KEYS) | {"approvalId", "operationId", "attemptId"}):
            _fail("invalid_command", 400, "Exact payment command fields required")
        transaction = _transaction({key: command[key] for key in TRANSACTION_KEYS})
        if (any(not isinstance(command[key], str) or not command[key]
                for key in ("approvalId", "operationId", "attemptId")) or
                not isinstance(code, str) or not code or not isinstance(message, str) or
                type(status) is not int or status < 400 or status > 499):
            _fail("invalid_rejection", 400, "Trusted denial details required")
        with self._connection(write=True) as db:
            env = self._read(db, "environments", environment_id)
            run_id = db.execute("SELECT run_id FROM environments WHERE id=?", (environment_id,)).fetchone()["run_id"]
            run = self._read(db, "runs", run_id)
            previous = next((item for item in env["ledger"] if item["operationId"] == command["operationId"]), None)
            if previous:
                _fail("operation_conflict", 409, "Operation already committed")
            earlier = next((item for item in run.get("paymentDecisions", [])
                            if item["environmentId"] == environment_id and
                            item["operationId"] == command["operationId"]), None)
            if earlier:
                if (earlier["attemptedTransaction"] != transaction or
                        earlier["approvalId"] != command["approvalId"]):
                    _fail("operation_conflict", 409, "Operation identity already used")
                return earlier
            approval = next((item for item in env["approvals"]
                             if item["approvalId"] == command["approvalId"]), None)
            return self._record_payment_decision(db, run, env, command, transaction,
                                                 approval, "denied", code, status)

    def _record_payment_decision(self, db, run, env, command, transaction,
                                 approval, decision, reason, status):
        decisions = run.setdefault("paymentDecisions", [])
        prior = next((item for item in reversed(decisions)
                      if item["decision"] == "denied" and
                      item["environmentId"] == env["environmentId"] and
                      item["attemptedTransaction"]["invoiceId"] == transaction["invoiceId"]), None)
        conversation = run.get("conversation") or {}
        record = {"decisionId": "decision-" + uuid.uuid4().hex,
                  "environmentId": env["environmentId"],
                  "operationId": command["operationId"], "attemptId": command["attemptId"],
                  "approvalId": command["approvalId"], "decision": decision,
                  "reason": reason, "status": status,
                  "attemptedTransaction": transaction,
                  "authorizedTransaction": (approval or {}).get("snapshot") or
                    (run.get("standingDemoAuthorization") or {}).get("snapshot"),
                  "transactionDigest": _digest(transaction),
                  "turnId": conversation.get("activeTurnId")}
        if prior and prior["operationId"] != command["operationId"]:
            record["priorDecisionId"] = prior["decisionId"]
        decisions.append(record)
        self._save(db, "runs", run["runId"], run)
        self._append_event(db, run["runId"], "payment.decision", record)
        return record

    def receipt(self, environment_id: str, operation_id: str) -> dict | None:
        env = self.environment(environment_id)
        return next((item for item in env["ledger"] if item["operationId"] == operation_id), None)

    def update_supplier(self, environment_id: str, account: str) -> dict:
        if not isinstance(account, str) or not account or len(account) > 128:
            _fail("invalid_account", 400, "Synthetic account required")
        with self._connection(write=True) as db:
            env = self._read(db, "environments", environment_id)
            if not env["active"]:
                _fail("inactive", 410, "Environment cancelled")
            env["supplier"]["beneficiaryAccount"] = account
            env["supplier"]["supplierRevision"] += 1
            self._save(db, "environments", environment_id, env)
            return env

    def update_invoice(self, environment_id: str, amount_minor: int | None = None,
                       currency: str | None = None) -> dict:
        if amount_minor is None and currency is None:
            _fail("invalid_invoice", 400, "Invoice change required")
        if amount_minor is not None and (type(amount_minor) is not int or amount_minor <= 0):
            _fail("invalid_invoice", 400, "Positive amount required")
        if currency is not None and (not isinstance(currency, str) or not currency or len(currency) > 8):
            _fail("invalid_invoice", 400, "Currency required")
        with self._connection(write=True) as db:
            env = self._read(db, "environments", environment_id)
            if not env["active"]:
                _fail("inactive", 410, "Environment cancelled")
            if amount_minor is not None:
                env["invoice"]["amountMinor"] = amount_minor
            if currency is not None:
                env["invoice"]["currency"] = currency
            env["invoice"]["invoiceRevision"] += 1
            self._save(db, "environments", environment_id, env)
            return env

    def set_compensating_rule(self, environment_id: str, enabled: bool) -> None:
        if type(enabled) is not bool:
            _fail("invalid_rule", 400, "Rule state must be boolean")
        with self._connection(write=True) as db:
            env = self._read(db, "environments", environment_id)
            env["compensatingRule"] = enabled
            self._save(db, "environments", environment_id, env)

    def set_attempt(self, environment_id: str, attempt_id: str) -> None:
        if not isinstance(attempt_id, str) or not attempt_id:
            _fail("invalid_attempt", 400, "Attempt ID required")
        with self._connection(write=True) as db:
            env = self._read(db, "environments", environment_id)
            if not env["active"]:
                _fail("inactive", 410, "Environment cancelled")
            env["attemptId"] = attempt_id
            self._save(db, "environments", environment_id, env)

    def cancel_environment(self, environment_id: str) -> None:
        with self._connection(write=True) as db:
            env = self._read(db, "environments", environment_id)
            env["active"] = False
            env["attemptId"] = None
            for approval in env["approvals"]:
                approval["revoked"] = True
            self._save(db, "environments", environment_id, env)

    def revoke_approval(self, environment_id: str, approval_id: str) -> None:
        with self._connection(write=True) as db:
            env = self._read(db, "environments", environment_id)
            approval = next((item for item in env["approvals"] if item["approvalId"] == approval_id), None)
            if approval is None:
                _fail("not_found", 404, "Approval not found")
            approval["revoked"] = True
            self._save(db, "environments", environment_id, env)

    def append_event(self, run_id: str, kind: str, data: dict) -> dict:
        if not isinstance(kind, str) or not kind or not isinstance(data, dict):
            _fail("invalid_event", 400, "Event kind and data required")
        with self._connection(write=True) as db:
            return self._append_event(db, run_id, kind, data)

    def _append_event(self, db, run_id: str, kind: str, data: dict) -> dict:
        run = self._read(db, "runs", run_id)
        events = run["events"]
        event = {"eventId": "event-" + uuid.uuid4().hex, "sequence": len(events) + 1,
                 "timestamp": self.clock(), "kind": kind, "data": data,
                 "previousHash": events[-1]["hash"] if events else None}
        event["hash"] = hashlib.sha256(_json(event).encode()).hexdigest()
        events.append(event)
        self._save(db, "runs", run_id, run)
        return event

    def update_run(self, run_id: str, **fields) -> dict:
        forbidden = {"runId", "owner", "baselineId", "protectedId", "createdAt", "events", "baseline", "protected"}
        if set(fields) & forbidden:
            _fail("invalid_update", 403, "Immutable run field")
        with self._connection(write=True) as db:
            run = self._read(db, "runs", run_id)
            run.update(fields)
            self._save(db, "runs", run_id, run)
            return self._view(db, run)

    @staticmethod
    def _owned_run(db, run_id, owner):
        row = db.execute("SELECT data FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            _fail("not_found", 404, "Run not found")
        run = json.loads(row["data"])
        if run["owner"] != owner:
            _fail("forbidden", 403, "Run belongs to another owner")
        return run

    def enqueue_turn(self, run_id: str, owner: str, text: str,
                     client_message_id: str) -> dict:
        if (not isinstance(text, str) or not 1 <= len(text.strip()) <= 2000 or
                not isinstance(client_message_id, str) or not client_message_id or
                len(client_message_id) > 128):
            _fail("invalid_message", 400, "Message text and client identity required")
        text = text.strip()
        with self._connection(write=True) as db:
            run = self._owned_run(db, run_id, owner)
            if run["mode"] != "live" or run["state"] in ("cancelled", "reset", "resumed"):
                _fail("turn_unavailable", 409, "Run does not accept employee work")
            conversation = run.get("conversation") or {"conversationId": str(uuid.uuid4()),
                "status": "active", "activeTurnId": None, "turns": []}
            prior = next((turn for turn in conversation["turns"]
                          if turn["clientMessageId"] == client_message_id), None)
            if prior:
                if prior["text"] != text:
                    _fail("message_conflict", 409, "Message identity already used")
                return self._view(db, run)
            turn = {"turnId": str(uuid.uuid4()), "clientMessageId": client_message_id,
                    "text": text, "scope": "pending", "status": "queued",
                    "createdAt": self.clock()}
            conversation["turns"].append(turn)
            run["conversation"] = conversation
            self._save(db, "runs", run_id, run)
            self._append_event(db, run_id, "conversation.user",
                               {"text": text, "channel": "maya", "turnId": turn["turnId"]})
            return self._view(db, self._read(db, "runs", run_id))

    def enqueue_continuation(self, run_id: str, owner: str, source_turn_id: str,
                             continuation_key: str) -> dict:
        """Queue the original user's payment work after exact verified deployment."""
        if not isinstance(source_turn_id, str) or not isinstance(continuation_key, str):
            _fail("invalid_continuation", 400, "Continuation identity required")
        with self._connection(write=True) as db:
            run = self._owned_run(db, run_id, owner)
            conversation = run.get("conversation") or {}
            turns = conversation.get("turns") or []
            existing = next((item for item in turns if item.get("sourceTurnId") == source_turn_id), None)
            if existing:
                if existing.get("clientMessageId") == continuation_key:
                    return self._view(db, run)
                _fail("continuation_conflict", 409, "Source turn already continued")
            source_turn = next((item for item in turns if item["turnId"] == source_turn_id), None)
            proof = run.get("verification") or {}
            repair = run.get("repair") or {}
            deployment = repair.get("deployment") or {}
            probe = repair.get("deploymentProbe") or {}
            artifact = proof.get("artifactDigest")
            source_hash = (proof.get("sourceReview") or {}).get("sourceSha256")
            image = deployment.get("imageDigest")
            env = self._read(db, "environments", run["protectedId"])
            mandate = run.get("standingDemoAuthorization") or {}
            approval = next((item for item in env["approvals"]
                             if item["approvalId"] == mandate.get("approvalId")), None)
            if (len(env["ledger"]) == 1 and
                    env["ledger"][0].get("approvalId") == mandate.get("approvalId") and
                    env["ledger"][0].get("transaction") == mandate.get("snapshot")):
                return self._view(db, run)
            complete = (run["mode"] == "live" and run["state"] == "held" and
                        conversation.get("activeTurnId") is None and
                        source_turn is not None and source_turn["scope"] == "pay_approved" and
                        source_turn["status"] in ("held", "failed") and
                        isinstance(artifact, str) and re.fullmatch(r"[0-9a-f]{64}", artifact) and
                        isinstance(source_hash, str) and re.fullmatch(r"[0-9a-f]{64}", source_hash) and
                        isinstance(image, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image) and
                        proof.get("passed") is True and deployment.get("deployed") is True and
                        deployment.get("artifactDigest") == artifact and
                        deployment.get("sourceSha256") == source_hash and
                        probe.get("artifactDigest") == artifact and
                        probe.get("imageDigest") == image and
                        probe.get("sourceSha256") == source_hash and
                        probe.get("paymentRouteReady") is True and
                        probe.get("separateService") is True and
                        any(event["kind"] == "repair.deployed" and
                            event.get("data", {}).get("artifactDigest") == artifact and
                            event.get("data", {}).get("imageDigest") == image
                            for event in run["events"]) and
                        not env["compensatingRule"] and env["active"] and not env["ledger"] and
                        mandate.get("source") == "trusted_demo_setup" and
                        mandate.get("provenance") == "user_configured_synthetic_demo" and
                        mandate.get("owner") == owner and mandate.get("runId") == run_id and
                        mandate.get("workspaceId") == env["workspaceId"] and
                        mandate.get("missionId") == env["missionId"] and
                        mandate.get("snapshot") == self._current(env) and
                        isinstance(mandate.get("expiresAt"), (int, float)) and
                        self.clock() < mandate["expiresAt"] and
                        approval is not None and
                        approval["principal"] == "synthetic-demo-standing:" + owner and
                        approval["snapshot"] == mandate["snapshot"] and
                        not approval["consumed"] and not approval["revoked"] and
                        self.clock() < approval["expiresAt"])
            if not complete:
                _fail("continuation_unavailable", 409, "Verified payment continuation unavailable")
            if continuation_key != f"{artifact}:{source_turn_id}":
                _fail("invalid_continuation", 400, "Continuation key must bind verified artifact and source turn")
            turn = {"turnId": str(uuid.uuid4()), "clientMessageId": continuation_key,
                    "text": source_turn["text"], "scope": "pending", "status": "queued",
                    "createdAt": self.clock(), "sourceTurnId": source_turn_id,
                    "continuationContext":
                        "The independently verified repair was deployed. Reconcile the payment receipt and continue the original authorized task."}
            turns.append(turn)
            self._save(db, "runs", run_id, run)
            self._append_event(db, run_id, "conversation.continuation_queued",
                               {"turnId": turn["turnId"], "sourceTurnId": source_turn_id,
                                "artifactDigest": artifact})
            return self._view(db, self._read(db, "runs", run_id))

    def claim_turn(self, run_id: str, owner: str) -> dict | None:
        with self._connection(write=True) as db:
            run = self._owned_run(db, run_id, owner)
            conversation = run.get("conversation")
            if not conversation or conversation.get("activeTurnId"):
                return None
            if run["state"] in ("cancelled", "reset", "resumed"):
                return None
            turn = next((item for item in conversation["turns"]
                         if item["status"] == "queued"), None)
            if turn is None:
                return None
            turn["status"] = "running"
            turn["startedAt"] = self.clock()
            conversation["activeTurnId"] = turn["turnId"]
            self._save(db, "runs", run_id, run)
            return dict(turn)

    def set_turn_scope(self, run_id: str, owner: str, turn_id: str, scope: str) -> dict:
        if scope not in ("read_only", "pay_approved", "clarification"):
            _fail("invalid_scope", 400, "Declared turn scope required")
        with self._connection(write=True) as db:
            run = self._owned_run(db, run_id, owner)
            conversation = run.get("conversation") or {}
            turn = next((item for item in conversation.get("turns", [])
                         if item["turnId"] == turn_id), None)
            if (turn is None or conversation.get("activeTurnId") != turn_id or
                    turn["status"] != "running"):
                _fail("turn_conflict", 409, "Turn is not active and running")
            if turn["scope"] != "pending":
                _fail("scope_conflict", 409, "Turn scope already declared")
            turn["scope"] = scope
            self._save(db, "runs", run_id, run)
            return self._view(db, run)

    def finish_turn(self, run_id: str, owner: str, turn_id: str,
                    status: str, error: str | None = None) -> dict:
        if status not in ("succeeded", "failed", "held", "cancelled"):
            _fail("invalid_turn_status", 400, "Terminal turn status required")
        with self._connection(write=True) as db:
            run = self._owned_run(db, run_id, owner)
            conversation = run.get("conversation") or {}
            turn = next((item for item in conversation.get("turns", [])
                         if item["turnId"] == turn_id), None)
            if turn is None:
                _fail("not_found", 404, "Turn not found")
            if turn["status"] in ("succeeded", "failed", "held", "cancelled"):
                if turn["status"] != status or turn.get("error") != error:
                    _fail("turn_conflict", 409, "Turn already completed differently")
                return self._view(db, run)
            if turn["status"] != "running" or conversation.get("activeTurnId") != turn_id:
                _fail("turn_conflict", 409, "Turn is not active and running")
            turn["status"] = status
            turn["finishedAt"] = self.clock()
            if error is not None:
                turn["error"] = str(error)[:500]
            conversation["activeTurnId"] = None
            self._save(db, "runs", run_id, run)
            return self._view(db, run)

    def save_remediation_plan(self, run_id: str, owner: str, text: str,
                              expected_version: int) -> dict:
        """Persist an editable proposal with a version check; it grants no authority."""
        if not isinstance(text, str) or not text.strip() or len(text) > 4000:
            _fail("invalid_plan", 400, "Plan text must contain 1 to 4000 characters")
        if type(expected_version) is not int or expected_version < 0:
            _fail("invalid_plan", 400, "Expected plan version required")
        with self._connection(write=True) as db:
            run = self._read(db, "runs", run_id)
            if run["owner"] != owner:
                _fail("forbidden", 403, "Run belongs to another owner")
            if not isinstance(run.get("investigation"), dict):
                _fail("plan_unavailable", 409, "Investigation required before plan editing")
            current = run.get("remediationPlan") or {}
            if current.get("executorBound"):
                _fail("plan_bound", 409, "Bound plan cannot be edited")
            version = current.get("version", 0)
            if version != expected_version:
                _fail("plan_conflict", 409, "Plan changed in another session; refresh before saving")
            run["remediationPlan"] = {"text": text.strip(), "version": version + 1,
                                      "updatedAt": self.clock(), "origin": "presenter_edit",
                                      "executorBound": False}
            self._save(db, "runs", run_id, run)
            self._append_event(db, run_id, "plan.saved", {"version": version + 1,
                                                        "executorBound": False})
            return self._view(db, self._read(db, "runs", run_id))

    def bind_remediation_plan(self, run_id: str, owner: str, expected_version: int,
                              expected_text_digest: str, approval_id: str,
                              *, repair_intent: dict) -> dict:
        if (type(expected_version) is not int or expected_version < 1 or
                not isinstance(expected_text_digest, str) or len(expected_text_digest) != 64 or
                not isinstance(approval_id, str) or not approval_id or
                not isinstance(repair_intent, dict)):
            _fail("invalid_binding", 400, "Version, digest, approval, and repair intent required")
        with self._connection(write=True) as db:
            run = self._owned_run(db, run_id, owner)
            plan = run.get("remediationPlan") or {}
            text = plan.get("text")
            if (plan.get("version") != expected_version or
                    not isinstance(text, str) or not text.strip() or len(text) > 4000 or
                    hashlib.sha256(text.encode("utf-8")).hexdigest() != expected_text_digest):
                _fail("plan_conflict", 409, "Saved plan changed or exceeds repair limit")
            binding = {"approvalId": approval_id, "version": expected_version,
                       "textDigest": expected_text_digest}
            if plan.get("executorBound"):
                previous = plan.get("binding") or {}
                if (all(previous.get(key) == value for key, value in binding.items()) and
                        (run.get("repair") or {}).get("approval", {}).get("approvalId") == approval_id):
                    return self._view(db, run)
                _fail("plan_conflict", 409, "Plan already bound to another repair")
            incident = run.get("incident") or {}
            investigation = run.get("investigation") or {}
            legacy_confirmed = (incident.get("status") == "reproduced" and
                                incident.get("disposition", "recovery_required") == "recovery_required" and
                                investigation.get("disposition", "recovery_required") == "recovery_required" and
                                bool(investigation.get("confirmedCause")))
            trusted_confirmed = (incident.get("source") == "trusted_payment_decision" and
                                 investigation.get("disposition") == "recovery_required" and
                                 bool(incident.get("decisionId")) and
                                 investigation.get("decisionId") == incident.get("decisionId") and
                                 bool(investigation.get("confirmedCause")))
            conversation = run.get("conversation") or {}
            if (run["state"] != "contained" or conversation.get("activeTurnId") or
                    not (legacy_confirmed or trusted_confirmed)):
                _fail("repair_unavailable", 409, "Confirmed repair-eligible incident required")
            authority = repair_intent.get("approval") or {}
            mission = repair_intent.get("mission") or {}
            if (authority.get("approvalId") != approval_id or
                    authority.get("planVersion") != expected_version or
                    authority.get("planTextDigest") != expected_text_digest or
                    authority.get("owner", owner) != owner or
                    authority.get("runId", run_id) != run_id or
                    mission.get("approvalId") != approval_id or
                    mission.get("planTextDigest") != expected_text_digest):
                _fail("invalid_binding", 400, "Repair intent does not match saved plan")
            plan["executorBound"] = True
            plan["binding"] = {**binding, "boundAt": self.clock()}
            run["repair"] = repair_intent
            run["state"] = "repairing"
            self._save(db, "runs", run_id, run)
            self._append_event(db, run_id, "repair.authorized",
                               {"approvalId": approval_id, "planVersion": expected_version,
                                "planTextDigest": expected_text_digest})
            return self._view(db, self._read(db, "runs", run_id))

    def record_created_issue(self, run_id: str, owner: str, result: dict) -> dict:
        """Record only a provider-confirmed issue, preserving earlier results."""
        with self._connection(write=True) as db:
            run = self._read(db, "runs", run_id)
            if run["owner"] != owner:
                _fail("forbidden", 403, "Run belongs to another owner")
            if not isinstance(run.get("investigation"), dict):
                _fail("issue_unavailable", 409, "Investigation required before issue creation")
            previous = run.get("issueResults") or []
            if not any(item.get("provider") == result.get("provider") and
                       item.get("id") == result.get("id") for item in previous):
                run["issueResults"] = [*previous, result]
                self._save(db, "runs", run_id, run)
                self._append_event(db, run_id, "issue.created", {
                    "provider": result.get("provider"), "id": result.get("id"),
                    "key": result.get("key"), "url": result.get("url")})
            return self._view(db, self._read(db, "runs", run_id))

    def transition(self, run_id: str, expected: list[str], target: str, **fields) -> dict:
        if "state" in fields:
            _fail("invalid_update", 400, "State is transition target")
        with self._connection(write=True) as db:
            run = self._read(db, "runs", run_id)
            if run["state"] not in expected:
                _fail("state_conflict", 409, "Run state changed")
            if set(fields) & {"runId", "owner", "baselineId", "protectedId", "createdAt", "events", "baseline", "protected"}:
                _fail("invalid_update", 403, "Immutable run field")
            run.update(fields)
            run["state"] = target
            self._save(db, "runs", run_id, run)
            return self._view(db, run)
