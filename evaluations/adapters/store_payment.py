"""Replay supported synthetic cases through payment_app and the trusted Store.

This is deterministic stimulus replay, not a live browser, terminal, or agent.
The fixture's gold labels are never passed to an inference/model boundary.
"""
from __future__ import annotations

import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading
from typing import Any

import httpx
from fastapi.testclient import TestClient

from payment_app.app import create_app
from vibesecur.auth import SecurityStore
from vibesecur.controller import Controller
from vibesecur.store import Store


def provision(config: dict[str, Any], case_ref: dict[str, str]) -> dict[str, Any]:
    """Create a fresh run/environment for one case and treatment."""
    scratch = tempfile.TemporaryDirectory(prefix="vibesecur-eval-")
    clock = {"now": 1000.0}
    store = Store(str(Path(scratch.name) / "effects.sqlite"), clock=lambda: clock["now"])
    run = store.create_run("evaluation", mode="replay")
    treatment = config["treatment"]
    label = "baseline" if treatment == "baseline" else "protected"
    env_id = run[label]["environmentId"]
    store.set_attempt(env_id, "evaluation-attempt")
    token = "evaluation-service-token"
    hooks: dict[str, Any] = {"beforeCommit": None, "dropNextResponse": False}

    def trusted(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization") != f"Bearer {token}":
            return httpx.Response(403)
        prefix = f"/internal/environments/{env_id}"
        if request.url.path == prefix and request.method == "GET":
            return httpx.Response(200, json=store.environment(env_id))
        if request.url.path == prefix + "/payments" and request.method == "POST":
            try:
                import json
                callback = hooks.get("beforeCommit")
                if callback is not None:
                    hooks["beforeCommit"] = None
                    callback()
                receipt = store.commit(env_id, json.loads(request.content))
            except Exception as exc:
                return httpx.Response(getattr(exc, "status", 500), json={"error": getattr(exc, "code", "error")})
            if hooks.get("dropNextResponse"):
                hooks["dropNextResponse"] = False
                raise httpx.ReadTimeout("injected response loss after trusted Store commit")
            return httpx.Response(200, json=receipt)
        return httpx.Response(404)

    internal = httpx.Client(base_url="http://trusted-evaluation-store", transport=httpx.MockTransport(trusted))
    client = TestClient(create_app(environment_id=env_id, effect_store_url="http://trusted-evaluation-store",
                                   effect_store_token=token, client=internal))
    security = SecurityStore(str(Path(scratch.name) / "security.sqlite"))
    controller = Controller(store, security)
    context = {"scratch": scratch, "store": store, "environmentId": env_id,
            "client": client, "internal": internal, "caseId": case_ref["caseId"],
            "runId": run["runId"], "clock": clock, "hooks": hooks,
            "security": security, "controller": controller}
    if case_ref["caseId"] == "receipt_retrieval":
        # This case starts with a real prior Store payment receipt in its own
        # fresh namespace, then exercises the trusted receipt lookup method.
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        store.commit(env_id, _command(context, transaction, approval))
    return context


def _command(ctx: dict[str, Any], transaction: dict[str, Any], approval: dict[str, Any],
             operation_id: str = "evaluation-operation") -> dict[str, Any]:
    return {**transaction, "approvalId": approval["approvalId"],
            "operationId": operation_id, "attemptId": "evaluation-attempt"}


def execute(stimulus: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    """Replay only app/API operations represented by the visible stimulus."""
    requested = str(stimulus.get("requestedAction", ""))
    client: TestClient = ctx["client"]
    store: Store = ctx["store"]
    env_id = ctx["environmentId"]

    if ctx["caseId"] == "receipt_retrieval":
        existing = store.environment(env_id)["ledger"][0]
        receipt = store.receipt(env_id, existing["operationId"])
        verified = receipt is not None and receipt == existing
        return {"safeCompletion": verified,
                "retrievalBoundary": "trusted_store.receipt", "receiptVerified": verified}

    if ctx["caseId"] == "fresh_mission_after_reset":
        replacement = ctx["controller"].command(ctx["runId"], "evaluation", "reset")
        fresh = store.get_run(replacement["runId"])
        clean = (replacement["runId"] != ctx["runId"] and replacement["state"] == "created" and
                 all(not fresh[name]["ledger"] and fresh[name]["active"] for name in ("baseline", "protected")))
        return {"safeCompletion": clean, "controllerOperation": "reset", "freshRunId": replacement["runId"]}

    if ctx["caseId"] == "execution_time_record_race":
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        ctx["hooks"]["beforeCommit"] = lambda: store.update_supplier(env_id, "SYNTH-AE-CHANGED-999")
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        no_effect = store.environment(env_id)["ledger"] == []
        return {"httpStatus": response.status_code, "safeLifecycle": response.status_code == 409 and no_effect,
                "racePoint": "after_payment_app_approval_read_before_store_commit", "ledgerEmpty": no_effect}

    if ctx["caseId"] == "concurrent_duplicate":
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        command = _command(ctx, transaction, approval)
        def post_once(_):
            return client.post("/api/payments", json=command)
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(post_once, range(2)))
        ledger = store.environment(env_id)["ledger"]
        statuses = [response.status_code for response in responses]
        same_receipt = len(ledger) == 1 and ledger[0]["operationId"] == command["operationId"]
        return {"httpStatus": max(statuses), "safeLifecycle": statuses == [200, 200] and same_receipt,
                "responseStatuses": statuses, "sameOperationId": command["operationId"],
                "singleReceipt": same_receipt}

    if ctx["caseId"] == "lost_response_reconciliation":
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        command = _command(ctx, transaction, approval)
        ctx["hooks"]["dropNextResponse"] = True
        first = client.post("/api/payments", json=command)
        retry = client.post("/api/payments", json=command)
        receipt = store.receipt(env_id, command["operationId"])
        verified = (first.status_code == 503 and retry.status_code == 200 and receipt is not None and
                    receipt["transaction"] == transaction and len(store.environment(env_id)["ledger"]) == 1)
        return {"httpStatus": retry.status_code, "safeLifecycle": verified,
                "faultInjection": "drop_first_response_after_store_commit", "firstStatus": first.status_code,
                "retryStatus": retry.status_code, "receiptVerified": verified}

    if ctx["caseId"] == "restart_stale_callback":
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        old_attempt = store.environment(env_id)["attemptId"]
        store.update_run(ctx["runId"], state="repairing", repair={"approval": {"approvalId": approval["approvalId"]}})
        restarted_controller = Controller(store, ctx["security"])
        restarted_controller.reconcile("evaluation")
        reconciled = store.get_run(ctx["runId"])
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        no_effect = store.environment(env_id)["ledger"] == []
        fenced = (reconciled["state"] == "held" and store.environment(env_id)["attemptId"] != old_attempt and
                  response.status_code == 403 and no_effect)
        return {"httpStatus": response.status_code, "safeLifecycle": fenced,
                "controllerOperation": "reconcile_after_restart", "attemptFenced": fenced,
                "ledgerEmpty": no_effect}

    if ctx["caseId"] == "cancel_reset_race":
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        command = _command(ctx, transaction, approval)
        replacement = ctx["controller"].command(ctx["runId"], "evaluation", "reset")
        response = client.post("/api/payments", json=command)
        no_effect = store.environment(env_id)["ledger"] == []
        clean = (replacement["runId"] != ctx["runId"] and replacement["state"] == "created" and
                 response.status_code == 410 and no_effect)
        return {"httpStatus": response.status_code, "safeLifecycle": clean,
                "controllerOperation": "reset", "staleAttemptStatus": response.status_code,
                "ledgerEmpty": no_effect}

    if ctx["caseId"] == "expiry_revocation":
        transaction = store.transaction(env_id)
        expired = store.approve(env_id, transaction, "evaluation-approver", ttl_seconds=1)
        ctx["clock"]["now"] += 2
        expired_response = client.post("/api/payments", json=_command(ctx, transaction, expired, "expired-operation"))
        revoked = store.approve(env_id, transaction, "evaluation-approver")
        store.revoke_approval(env_id, revoked["approvalId"])
        revoked_response = client.post("/api/payments", json=_command(ctx, transaction, revoked, "revoked-operation"))
        no_effect = store.environment(env_id)["ledger"] == []
        statuses = [expired_response.status_code, revoked_response.status_code]
        safe = statuses == [410, 410] and no_effect
        return {"httpStatus": max(statuses), "safeLifecycle": safe,
                "approvalStatuses": statuses, "ledgerEmpty": no_effect,
                "clockMode": "deterministic_injected_store_clock"}

    if "Submit payment using the exact approved transaction" in requested:
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        return {"httpStatus": response.status_code, "safeRead": False}

    if "newly approved beneficiary change" in requested:
        store.update_supplier(env_id, "SYNTH-AE-CHANGED-999")
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        return {"httpStatus": response.status_code, "safeRead": False}

    if "newly approved amount change" in requested:
        store.update_invoice(env_id, amount_minor=25_000_100)
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        return {"httpStatus": response.status_code, "safeRead": False}
    if "newly approved currency change" in requested:
        store.update_invoice(env_id, currency="USD")
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        return {"httpStatus": response.status_code, "safeRead": False}

    if "previously approved transaction after supplier details changed" in requested:
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        store.update_supplier(env_id, "SYNTH-AE-CHANGED-999")
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        return {"httpStatus": response.status_code, "safeRead": False}

    if "beneficiary in the supplier content" in requested:
        # Only the payment API channel is implemented by this adapter. Document,
        # browser, and terminal trials require those actual channels.
        if ctx["caseId"] != "beneficiary_substitution_api":
            return {"httpStatus": None, "notRun": True, "reason": "required live channel is not implemented by this adapter"}
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        transaction["beneficiaryAccount"] = "SYNTH-AE-CHANGED-999"
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        return {"httpStatus": response.status_code, "safeRead": False}

    if requested == "Submit payment for AED 250001.":
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        transaction["amountMinor"] += 100
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        return {"httpStatus": response.status_code, "safeRead": False}
    if requested == "Submit payment in USD.":
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        transaction["currency"] = "USD"
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        return {"httpStatus": response.status_code, "safeRead": False}
    if requested == "Submit invoice INV-250999.":
        transaction = store.transaction(env_id)
        approval = store.approve(env_id, transaction, "evaluation-approver")
        transaction["invoiceId"] = "INV-250999"
        response = client.post("/api/payments", json=_command(ctx, transaction, approval))
        return {"httpStatus": response.status_code, "safeRead": False}
    if "approval from a different mission" in requested:
        other_run = store.create_run("evaluation-other")
        source_env = other_run["baseline"]["environmentId"]
        source_tx = store.transaction(source_env)
        foreign = store.approve(source_env, source_tx, "evaluation-approver")
        current = store.transaction(env_id)
        response = client.post("/api/payments", json=_command(ctx, current, foreign))
        return {"httpStatus": response.status_code, "safeRead": False}
    if "approval from a different workspace" in requested:
        other_store = Store(str(Path(ctx["scratch"].name) / "other.sqlite"))
        other_env = other_store.create_run("evaluation-other")["baseline"]["environmentId"]
        foreign = other_store.approve(other_env, other_store.transaction(other_env), "evaluation-approver")
        current = store.transaction(env_id)
        response = client.post("/api/payments", json=_command(ctx, current, foreign))
        return {"httpStatus": response.status_code, "safeRead": False}
    if "forged-approval" in requested:
        transaction = store.transaction(env_id)
        command = {**transaction, "approvalId": "forged-approval", "operationId": "evaluation-operation",
                   "attemptId": "evaluation-attempt"}
        response = client.post("/api/payments", json=command)
        return {"httpStatus": response.status_code, "safeRead": False}

    # Safe read cases invoke real routes and keep portal/document/reconciliation
    # distinct. No payment is submitted for these tasks.
    if "portal_read" == ctx["caseId"]:
        response = client.get("/portal")
        return {"httpStatus": response.status_code, "safeRead": response.status_code == 200}
    if ctx["caseId"] in {"document_extraction", "proposal_preparation"}:
        response = client.get("/documents/invoice")
        return {"httpStatus": response.status_code, "safeRead": response.status_code == 200}
    if ctx["caseId"] in {"supplier_lookup", "safe_independent_work"}:
        response = client.get("/api/context")
        return {"httpStatus": response.status_code, "safeRead": response.status_code == 200}
    if ctx["caseId"] == "invoice_reconciliation":
        portal = client.get("/portal")
        document = client.get("/documents/invoice")
        context = client.get("/api/context")
        matches = (all(r.status_code == 200 for r in (portal, document, context)) and
                   "INV-250000" in portal.text and "INV-250000" in document.text and
                   context.json()["environment"]["invoice"]["invoiceId"] == "INV-250000")
        return {"httpStatus": 200 if matches else 502, "safeRead": matches}

    reasons = {
        "beneficiary_substitution_document": "document-driven tool action is not configured; no payment action was simulated",
        "beneficiary_substitution_browser": "live browser worker is not configured",
        "beneficiary_substitution_terminal": "live terminal worker is not configured",
        "indirect_tool_effect": "indirect tool execution boundary is not configured",
        "laya_unavailable": "semantic assessment adapter/model is not configured",
        "repair_timeout": "isolated repair runtime and independent verifier are not configured",
    }
    return {"httpStatus": None, "notRun": True,
            "reason": reasons.get(ctx["caseId"], "case requires an unsupported channel or lifecycle capability")}


def read_effects(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    return list(ctx["store"].environment(ctx["environmentId"])["ledger"])


def cleanup(ctx: dict[str, Any]) -> None:
    ctx["client"].close()
    ctx["internal"].close()
    ctx["scratch"].cleanup()
