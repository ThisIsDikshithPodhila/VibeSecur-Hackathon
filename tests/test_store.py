import concurrent.futures
import hashlib
import json
import tempfile

import pytest

from vibesecur.store import Store, StoreError


@pytest.fixture
def setup_store():
    with tempfile.TemporaryDirectory() as directory:
        now = [1000.0]
        store = Store(f"{directory}/effects.sqlite", clock=lambda: now[0])
        run = store.create_run("owner")
        env = run["baseline"]["environmentId"]
        store.set_attempt(env, "attempt-1")
        yield store, run, env, now


def command(transaction, approval, operation="effect-1", attempt="attempt-1"):
    return {**transaction, "approvalId": approval["approvalId"], "operationId": operation, "attemptId": attempt}


def test_seed_and_independent_environments(setup_store):
    store, run, env, _ = setup_store
    assert run["baseline"]["compensatingRule"] is False
    assert run["protected"]["compensatingRule"] is True
    assert run["baseline"]["environmentId"] != run["protected"]["environmentId"]
    assert store.transaction(env)["amountMinor"] == 25000000
    assert store.transaction(env)["beneficiaryAccount"] == "SYNTH-AE-GULF-001"
    assert store.get_run(run["runId"], "owner")["runId"] == run["runId"]
    with pytest.raises(StoreError) as error:
        store.get_run(run["runId"], "another-owner")
    assert error.value.status == 403


def test_seeded_baseline_defect_and_protected_rule(setup_store):
    store, run, baseline, _ = setup_store
    protected = run["protected"]["environmentId"]
    store.set_attempt(protected, "attempt-1")
    for env in (baseline, protected):
        original = store.transaction(env)
        approval = store.approve(env, original, "presenter")
        changed = {**original, "beneficiaryAccount": "SYNTH-AE-CHANGED-999"}
        if env == baseline:
            receipt = store.commit(env, command(changed, approval))
            assert receipt["transaction"]["beneficiaryAccount"] == "SYNTH-AE-CHANGED-999"
            assert len(store.environment(env)["ledger"]) == 1
        else:
            with pytest.raises(StoreError) as error:
                store.commit(env, command(changed, approval))
            assert error.value.status == 403
            assert store.environment(env)["ledger"] == []
            assert store.environment(env)["approvals"][0]["consumed"] is False


def test_old_approval_current_changed_supplier_command_exposes_baseline_only(setup_store):
    store, run, baseline, _ = setup_store
    protected = run["protected"]["environmentId"]
    for env in (baseline, protected):
        store.set_attempt(env, "attempt-1")
        original = store.transaction(env)
        approval = store.approve(env, original, "presenter")
        store.update_supplier(env, "SYNTH-AE-CHANGED-999")
        current = store.transaction(env)
        if env == baseline:
            assert store.commit(env, command(current, approval))["status"] == "committed"
        else:
            with pytest.raises(StoreError) as error:
                store.commit(env, command(current, approval))
            assert error.value.status == 403


def test_effect_commit_appends_audited_event(setup_store):
    store, run, env, _ = setup_store
    tx = store.transaction(env)
    approval = store.approve(env, tx, "presenter")
    store.commit(env, command(tx, approval))
    events = store.get_run(run["runId"])["events"]
    assert events[-1]["kind"] == "effect_committed"
    assert events[-1]["data"]["operationId"] == "effect-1"
    assert events[-1]["hash"]


def test_approval_digest_is_versioned_canonical_snapshot(setup_store):
    store, _, env, _ = setup_store
    snapshot = store.transaction(env)
    approval = store.approve(env, snapshot, "presenter")
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert approval["snapshotDigest"] == "vibesecur:transaction:v1:" + hashlib.sha256(canonical).hexdigest()


def test_invoice_update_increments_revision_and_requires_fresh_snapshot(setup_store):
    store, _, env, _ = setup_store
    original = store.transaction(env)
    store.approve(env, original, "presenter")
    changed = store.update_invoice(env, amount_minor=25000001, currency="AED")
    assert changed["invoice"]["invoiceRevision"] == 2
    assert store.transaction(env)["amountMinor"] == 25000001
    with pytest.raises(StoreError) as error:
        store.approve(env, original, "presenter")
    assert error.value.status == 409


def test_scope_attempt_expiry_revoke_and_stale_revision(setup_store):
    store, _, env, now = setup_store
    tx = store.transaction(env)
    approval = store.approve(env, tx, "presenter", ttl_seconds=5)
    variants = [({**tx, "workspaceId": "other"}, "attempt-1", 403),
                (tx, "other-attempt", 403)]
    for index, (variant, attempt, expected) in enumerate(variants):
        with pytest.raises(StoreError) as error:
            store.commit(env, command(variant, approval, operation=f"effect-scope-{index}", attempt=attempt))
        assert error.value.status == expected
    store.update_supplier(env, "SYNTH-AE-CHANGED-999")
    with pytest.raises(StoreError) as error:
        store.commit(env, command(tx, approval, operation="effect-stale"))
    assert error.value.status == 409
    assert store.environment(env)["ledger"] == []
    fresh = store.transaction(env)
    expired = store.approve(env, fresh, "presenter", ttl_seconds=1)
    now[0] += 2
    with pytest.raises(StoreError) as error:
        store.commit(env, command(fresh, expired, operation="effect-expired"))
    assert error.value.status == 410
    current = store.approve(env, fresh, "presenter")
    store.revoke_approval(env, current["approvalId"])
    with pytest.raises(StoreError) as error:
        store.commit(env, command(fresh, current, operation="effect-revoked"))
    assert error.value.status == 410


def test_exact_replay_is_idempotent_and_conflicting_replay_rejected(setup_store):
    store, _, env, _ = setup_store
    tx = store.transaction(env)
    approval = store.approve(env, tx, "presenter")
    proposal = command(tx, approval)
    first = store.commit(env, proposal)
    assert store.commit(env, proposal) == first
    assert store.receipt(env, "effect-1") == first
    with pytest.raises(StoreError) as error:
        store.commit(env, {**proposal, "amountMinor": 1})
    assert error.value.status == 409
    with pytest.raises(StoreError) as error:
        store.commit(env, {**proposal, "operationId": "effect-2"})
    assert error.value.status == 409
    assert len(store.environment(env)["ledger"]) == 1


def test_concurrent_commit_creates_one_effect(setup_store):
    store, _, env, _ = setup_store
    tx = store.transaction(env)
    approval = store.approve(env, tx, "presenter")
    proposal = command(tx, approval)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        receipts = list(executor.map(lambda _: store.commit(env, proposal), range(8)))
    assert all(receipt == receipts[0] for receipt in receipts)
    assert len(store.environment(env)["ledger"]) == 1


def test_competing_operation_ids_cannot_double_pay(setup_store):
    store, _, env, _ = setup_store
    tx = store.transaction(env)
    approval = store.approve(env, tx, "presenter")
    commands = [command(tx, approval, operation=f"effect-{index}") for index in range(8)]
    def try_commit(proposal):
        try:
            return store.commit(env, proposal)
        except StoreError as error:
            return error.status
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(try_commit, commands))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert len(store.environment(env)["ledger"]) == 1


def test_supplier_change_serializes_against_commit(setup_store):
    store, _, env, _ = setup_store
    tx = store.transaction(env)
    approval = store.approve(env, tx, "presenter")
    proposal = command(tx, approval)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_commit = executor.submit(lambda: store.commit(env, proposal))
        future_change = executor.submit(lambda: store.update_supplier(env, "SYNTH-AE-CHANGED-999"))
        try:
            future_commit.result()
        except StoreError as error:
            assert error.status == 409
        future_change.result()
    ledger = store.environment(env)["ledger"]
    assert len(ledger) <= 1
    if ledger:
        assert ledger[0]["transaction"]["supplierRevision"] == 1


def test_run_transition_and_event_chain(setup_store):
    store, run, _, _ = setup_store
    run_id = run["runId"]
    assert store.transition(run_id, ["created"], "running")["state"] == "running"
    with pytest.raises(StoreError) as error:
        store.transition(run_id, ["created"], "contained")
    assert error.value.status == 409
    first = store.append_event(run_id, "start", {"ok": True})
    second = store.append_event(run_id, "attack", {"ok": False})
    assert second["sequence"] == first["sequence"] + 1
    assert second["previousHash"] == first["hash"]
    assert len(store.get_run(run_id)["events"]) == 2
