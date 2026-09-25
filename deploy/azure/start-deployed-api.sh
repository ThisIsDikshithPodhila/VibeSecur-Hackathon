#!/usr/bin/env bash
set -euo pipefail
if ! /srv/vibesecur/.venv/bin/python - <<'PY'
import json, os, time
try:
    with open(os.environ['VIBESECUR_WORKER_BOUNDARY_EVIDENCE']) as f: record=json.load(f)
    assert record['passed'] is True and 0 <= time.time()-record['checkedAt'] <= 3600
except (OSError, KeyError, ValueError, AssertionError):
    raise SystemExit(1)
PY
then
  export VIBESECUR_EMPLOYEE_WORKER_ENABLED=0
fi
exec /srv/vibesecur/.venv/bin/uvicorn vibesecur.api:create_app --factory --host 0.0.0.0 --port 8000 --workers 1
