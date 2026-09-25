#!/usr/bin/env bash
# Bounded deployed employee UX check; live chat smoke is opt-in and separately recorded.
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
demo_host=${VIBESECUR_DEPLOY_HOST:-demo@40.81.234.48}
demo_key=${VIBESECUR_SSH_KEY:?Set VIBESECUR_SSH_KEY to your private SSH key path}
remote_root=/srv/vibesecur/ui-check

case "${1:-employee-ux}" in
  employee-ux)
    script_name=check-employee-ux.mjs
    artifact_dir="$repo_dir/artifacts/ui/employee-ux"
    remote_output="$remote_root/employee-ux-output"
    container_name=vibesecur-employee-ux-check
    result_name=employee-ux-results.json
    log_name=employee-ux-container.log
    label='Employee UX browser check'
    ;;
  live-chat-smoke)
    script_name=check-employee-live-chat.mjs
    artifact_dir="$repo_dir/artifacts/ui/employee-live-chat-smoke"
    remote_output="$remote_root/employee-live-chat-smoke-output"
    container_name=vibesecur-employee-live-chat-smoke
    result_name=employee-live-chat-smoke-results.json
    log_name=employee-live-chat-smoke-container.log
    label='Employee live chat transport and persistence smoke'
    ;;
  *)
    echo "Usage: $0 [employee-ux|live-chat-smoke]" >&2
    exit 2
    ;;
esac
mkdir -p "$artifact_dir"

ssh -i "$demo_key" -o BatchMode=yes "$demo_host" \
  "mkdir -p '$remote_root/scripts' '$remote_root/apps/presenter' '$remote_output'"
scp -q -i "$demo_key" -- "$repo_dir/scripts/$script_name" \
  "$demo_host:$remote_root/scripts/$script_name"

set +e
ssh -i "$demo_key" -o BatchMode=yes "$demo_host" 'bash -s' <<REMOTE
set -euo pipefail
output='$remote_output'
log='$remote_root/$log_name'
rm -f "\$output"/*.png "\$output"/*.json
PRESENTER_ACCESS_CODE=\$(python3 - <<'PY'
from pathlib import Path
for line in Path('/srv/vibesecur/.env.private').read_text().splitlines():
    if line.startswith('PRESENTER_ACCESS_CODE='):
        print(line.split('=', 1)[1].strip().strip("\"'"))
        break
else:
    raise SystemExit('Presenter access code is absent')
PY
)
export PRESENTER_ACCESS_CODE
set +e
timeout --signal=TERM --kill-after=15s 360s docker run --rm --name '$container_name' \
  --cpus 1 --memory 1024m --shm-size 256m --user "\$(id -u):\$(id -g)" \
  --volume /srv/vibesecur/ui-check:/workspace \
  --volume /srv/vibesecur/presenter-ui:/workspace/apps/presenter:ro \
  --volume "\$output:/output" --workdir /workspace \
  --env PRESENTER_ACCESS_CODE \
  --env PRESENTER_URL=https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com \
  mcr.microsoft.com/playwright@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27 \
  node "scripts/$script_name" > "\$log" 2>&1
result=\$?
unset PRESENTER_ACCESS_CODE
cat "\$log"
exit "\$result"
REMOTE
run_status=$?
set -e

set +e
ssh -i "$demo_key" -o BatchMode=yes "$demo_host" \
  "cat '$remote_root/$log_name'" > "$artifact_dir/$log_name"
log_collect_status=$?
set -e
if (( log_collect_status != 0 )); then
  echo "Could not collect the Azure $label log into $artifact_dir" >&2
  if (( run_status == 0 )); then exit "$log_collect_status"; fi
fi

set +e
ssh -i "$demo_key" -o BatchMode=yes "$demo_host" \
  "tar -C '$remote_output' -cf - ." | tar -C "$artifact_dir" -xf -
collect_status=$?
set -e
if (( collect_status != 0 )); then
  echo "Could not collect Azure $label artifacts into $artifact_dir" >&2
  exit "$collect_status"
fi
if (( run_status != 0 )); then
  echo "$label failed (exit $run_status); artifacts: $artifact_dir" >&2
  exit "$run_status"
fi
echo "$label passed; results: $artifact_dir/$result_name"
