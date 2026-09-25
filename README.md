# VibeSecur

An AI employee workspace for synthetic procurement, governed tool execution, incident investigation, and independently verified repair.

Maya handles supplier work through OpenHands and Azure inference. VibeSecur combines deterministic authorization with Laya contextual assessment. The React employee chat and Control Panel display persisted application events. A separately scoped Codex executor produces repair candidates for an independent verifier.

## Snapshot status

This is an in-progress source snapshot, not a completed release or a claim that every integration passes. No credentials, runtime databases, private execution traces, or development-session notes are included. Existing evaluation summaries describe their recorded configurations; they do not certify this snapshot. Run the required gates in your own synthetic environment before presenting live execution.

## Local setup

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
cp .env.example .env
# Configure the trusted backend environment privately before starting it.
make api
```

The environment file is a template; export its configured values into the backend process environment. Azure credentials belong only in the trusted backend. Never mount developer credentials into workers, repair executors, or verification jobs.

```sh
make ui-build
make test
make contracts
make evaluate TREATMENT=baseline
make evaluate TREATMENT=deterministic
```

Run expensive browser, inference, repair, and verification jobs serially on the small demo host. Missing infrastructure is a failed or unmeasured gate, not a successful prevention result.

## Structure

- `apps/presenter/`: React/Vite employee chat, Control Panel, and work views.
- `vibesecur/`: FastAPI controller, persistence, authority, assessment, investigation, and adapters.
- `worker_runtime/`: OpenHands tool execution.
- `payment_app/`: deliberately vulnerable synthetic payment service used for bounded repair.
- `verifier/`: independently controlled verification contract and runner.
- `deploy/`: Azure, Docker/Caddy, OpenShell, and isolated repair deployment tooling.
- `evaluations/`, `tests/`, `fixtures/`: regression suites and synthetic fixtures.
- `contracts/`: versioned integration contracts.

## Repair baseline

The `repair-baseline` tag preserves the original deliberately vulnerable payment service. Resolve `git rev-parse repair-baseline` and use that full hash for the repair configuration's `baseCommit`. Keep the verifier outside the repairer's writable scope. Functional Codex references identify the configured runtime repair executor.

## Deployment and presentation

See [deployment notes](docs/DEPLOYMENT.md) and [tablet runbook](docs/PRESENTER_RUNBOOK.md). Provision only infrastructure you own and use synthetic data. This application has no real banking connection.
