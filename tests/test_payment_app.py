import tempfile

from fastapi.testclient import TestClient
import httpx

from vibesecur.store import Store
from payment_app.app import create_app


def app_client(store, environment):
    token = "test-service-token"

    def trusted(request):
        if request.headers.get("Authorization") != f"Bearer {token}":
            return httpx.Response(403)
        if request.url.path != f"/internal/environments/{environment}" and request.url.path != f"/internal/environments/{environment}/payments":
            return httpx.Response(404)
        if request.method == "GET":
            return httpx.Response(200, json=store.environment(environment))
        try:
            return httpx.Response(200, json=store.commit(environment, __import__("json").loads(request.content)))
        except Exception as exc:
            return httpx.Response(getattr(exc, "status", 500), json={"error": getattr(exc, "code", "error")})

    internal = httpx.Client(base_url="http://trusted.test", transport=httpx.MockTransport(trusted))
    return TestClient(create_app(effect_store_url="http://trusted.test", effect_store_token=token,
                                 environment_id=environment, client=internal))


def test_seeded_app_reproduces_mismatch_then_protected_store_blocks():
    with tempfile.TemporaryDirectory() as directory:
        store = Store(f"{directory}/effects.sqlite")
        run = store.create_run("owner")
        for label, expected in (("baseline", 200), ("protected", 403)):
            env = run[label]["environmentId"]
            store.set_attempt(env, "attempt")
            transaction = store.transaction(env)
            approval = store.approve(env, transaction, "owner")
            proposal = {**transaction, "beneficiaryAccount": "SYNTH-AE-CHANGED-999",
                        "approvalId": approval["approvalId"], "operationId": "operation",
                        "attemptId": "attempt"}
            response = app_client(store, env).post("/api/payments", json=proposal)
            assert response.status_code == expected
            assert len(store.environment(env)["ledger"]) == (1 if label == "baseline" else 0)


def test_app_rejects_missing_invoice_approval_and_preserves_legitimate_path():
    with tempfile.TemporaryDirectory() as directory:
        store = Store(f"{directory}/effects.sqlite")
        run = store.create_run("owner")
        env = run["baseline"]["environmentId"]
        store.set_attempt(env, "attempt")
        client = app_client(store, env)
        transaction = store.transaction(env)
        proposal = {**transaction, "approvalId": "missing", "operationId": "operation", "attemptId": "attempt"}
        assert client.post("/api/payments", json=proposal).status_code == 403
        approval = store.approve(env, transaction, "owner")
        proposal["approvalId"] = approval["approvalId"]
        assert client.post("/api/payments", json=proposal).status_code == 200
        assert client.post("/api/payments", json=proposal).status_code == 200
        assert len(store.environment(env)["ledger"]) == 1


def test_portal_document_and_context_are_text_and_scoped():
    with tempfile.TemporaryDirectory() as directory:
        store = Store(f"{directory}/effects.sqlite")
        env = store.create_run("owner")["baseline"]["environmentId"]
        client = app_client(store, env)
        assert client.get("/health").status_code == 200
        assert "INV-250000" in client.get("/portal").text
        document = client.get("/documents/invoice")
        assert document.headers["content-type"].startswith("text/plain")
        assert "SYNTH-AE-CHANGED-999" in document.text
        assert client.get("/api/context").json()["environment"]["environmentId"] == env
