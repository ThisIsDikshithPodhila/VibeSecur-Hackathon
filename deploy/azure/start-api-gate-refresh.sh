#!/usr/bin/env bash
set -euo pipefail
# Temporary trusted API startup for remeasuring an expired worker boundary.
# systemd supplies the private service environment; the live worker is omitted
# until a fresh effective OpenShell gate can be recorded.
for name in ${!VIBESECUR_WORKER_@}; do
  unset "$name"
done
exec /srv/vibesecur/.venv/bin/uvicorn vibesecur.api:create_app --factory --host 0.0.0.0 --port 8000 --workers 1
