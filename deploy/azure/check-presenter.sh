#!/usr/bin/env bash
# Read-only presenter UX checks on the existing VM, using persisted runs.
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
demo_host=${VIBESECUR_DEPLOY_HOST:-demo@40.81.234.48}
demo_key=${VIBESECUR_SSH_KEY:?Set VIBESECUR_SSH_KEY to your private SSH key path}
ssh -i "$demo_key" -o BatchMode=yes "$demo_host" 'mkdir -p /srv/vibesecur/ui-check/scripts /srv/vibesecur/ui-check/docs/design/browser-check /srv/vibesecur/ui-check/apps/presenter'
scp -q -i "$demo_key" -- "$repo_dir/scripts/tablet_check.mjs" "$demo_host:/srv/vibesecur/ui-check/scripts/tablet_check.mjs"
set +e
ssh -i "$demo_key" -o BatchMode=yes "$demo_host" 'bash -s' <<'REMOTE'
set -euo pipefail
# Read just the presenter code, with no provider credentials in the browser container.
PRESENTER_ACCESS_CODE=$(python3 - <<'PY'
from pathlib import Path
for line in Path('/srv/vibesecur/.env.private').read_text().splitlines():
    if line.startswith('PRESENTER_ACCESS_CODE='):
        print(line.split('=',1)[1].strip().strip("\"'"))
        break
else:
    raise SystemExit('Presenter access code is absent')
PY
)
export PRESENTER_ACCESS_CODE
set +e
docker run --rm --name vibesecur-ui-check --cpus 1 --memory 1024m --shm-size 256m \
  --user "$(id -u):$(id -g)" --volume /srv/vibesecur/ui-check:/workspace \
  --volume /srv/vibesecur/presenter-ui:/workspace/apps/presenter:ro --workdir /workspace \
  --env PRESENTER_ACCESS_CODE \
  --env PRESENTER_URL=https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com \
  mcr.microsoft.com/playwright@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27 \
  node scripts/tablet_check.mjs > /srv/vibesecur/ui-check/results.jsonl 2>&1
result=$?
unset PRESENTER_ACCESS_CODE
cat /srv/vibesecur/ui-check/results.jsonl
exit "$result"
REMOTE
result=$?
set -e
scp -q -i "$demo_key" "$demo_host:/srv/vibesecur/ui-check/results.jsonl" "$repo_dir/docs/design/browser-check/results.jsonl"
scp -q -i "$demo_key" "$demo_host:/srv/vibesecur/ui-check/docs/design/browser-check/*.png" "$repo_dir/docs/design/browser-check/"
exit "$result"
