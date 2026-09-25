#!/usr/bin/env bash
# Publish only additive employee conversation/plan/issue API modules.
# The controller, payment service, repair executor and verifier are untouched.
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
demo_host=${VIBESECUR_DEPLOY_HOST:-demo@40.81.234.48}
demo_key=${VIBESECUR_SSH_KEY:?Set VIBESECUR_SSH_KEY to your private SSH key path}
stage=/srv/vibesecur/staged-employee-ui-api

ssh -i "$demo_key" -o BatchMode=yes "$demo_host" "mkdir -p '$stage'"
scp -q -i "$demo_key" -- \
  "$repo_dir/vibesecur/api.py" \
  "$repo_dir/vibesecur/store.py" \
  "$repo_dir/vibesecur/employee.py" \
  "$repo_dir/vibesecur/issue_connectors.py" \
  "$demo_host:$stage/"

ssh -i "$demo_key" -o BatchMode=yes "$demo_host" 'bash -s' <<'REMOTE'
set -euo pipefail
stage=/srv/vibesecur/staged-employee-ui-api
live=/srv/vibesecur/app/vibesecur
backup=/srv/vibesecur/backups/employee-ui-api-$(date -u +%Y%m%dT%H%M%SZ)
names=(api.py store.py employee.py issue_connectors.py)
python3 -m py_compile "$stage/${names[0]}" "$stage/${names[1]}" "$stage/${names[2]}" "$stage/${names[3]}"
mkdir -p "$backup"
for name in "${names[@]}"; do
  if test -f "$live/$name"; then cp -p "$live/$name" "$backup/$name"; fi
done
restore() {
  for name in "${names[@]}"; do
    if test -f "$backup/$name"; then cp "$backup/$name" "$live/$name"; else rm -f "$live/$name"; fi
  done
  sudo -n systemctl restart vibesecur-api.service
}
for name in "${names[@]}"; do cp "$stage/$name" "$live/$name"; done
if ! sudo -n systemctl restart vibesecur-api.service || \
   ! curl -fsS --retry 6 --retry-delay 1 --max-time 10 http://127.0.0.1:8000/health >/dev/null; then
  restore
  echo 'Employee API deployment failed and was rolled back.' >&2
  exit 1
fi
python3 - <<'PY'
import hashlib, json
from pathlib import Path
root=Path('/srv/vibesecur/app/vibesecur')
names=('api.py','store.py','employee.py','issue_connectors.py')
print(json.dumps({'deployed': True, 'files': {name: hashlib.sha256((root/name).read_bytes()).hexdigest()
                                         for name in names}}))
PY
REMOTE

curl -fsS --max-time 15 https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com/health >/dev/null
