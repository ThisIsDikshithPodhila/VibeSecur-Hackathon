#!/usr/bin/env bash
# Publish only presenter static assets; leaves the running API and its state intact.
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
demo_host=${VIBESECUR_DEPLOY_HOST:-demo@40.81.234.48}
demo_key=${VIBESECUR_SSH_KEY:?Set VIBESECUR_SSH_KEY to your private SSH key path}
archive=$(mktemp /tmp/vibesecur-presenter.XXXXXX.tar)
trap 'rm -f -- "$archive"' EXIT

python3 - "$repo_dir" "$archive" <<'PY'
from pathlib import Path
import sys, tarfile
root = Path(sys.argv[1]) / 'apps/presenter'
with tarfile.open(sys.argv[2], 'w') as archive:
    for name in ('package.json', 'package-lock.json', 'index.html', 'vite.config.ts', 'tsconfig.json'):
        archive.add(root / name, arcname=name)
    for path in (root / 'src').rglob('*'):
        if path.is_file() and not path.is_symlink():
            archive.add(path, arcname=path.relative_to(root))
PY
scp -q -i "$demo_key" -- "$archive" "$demo_host:/srv/vibesecur/presenter-src.tar"
ssh -i "$demo_key" -o BatchMode=yes "$demo_host" 'bash -s' <<'REMOTE'
set -euo pipefail
stage=/srv/vibesecur/presenter-ui
live=/srv/vibesecur/app/apps/presenter/dist
mkdir -p "$stage"
tar -xf /srv/vibesecur/presenter-src.tar -C "$stage"
docker run --rm --name vibesecur-ui-build --cpus 1 --memory 768m \
  --user "$(id -u):$(id -g)" --volume "$stage:/app" --workdir /app \
  --env npm_config_cache=/tmp/npm-cache \
  node@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c \
  sh -c 'npm ci --no-audit --no-fund && npm run build' \
  > /srv/vibesecur/ui-build.log 2>&1
test -s "$stage/dist/index.html"
mkdir -p "$live/assets"
# Retain hashed assets required by already-open tabs. Publish the new index last.
cp -a "$stage/dist/assets/." "$live/assets/"
cp "$stage/dist/index.html" "$live/index.html.next"
mv "$live/index.html.next" "$live/index.html"
python3 - <<'PY'
import hashlib, json
from pathlib import Path
import urllib.request
local = Path('/srv/vibesecur/app/apps/presenter/dist/index.html').read_bytes()
with urllib.request.urlopen('https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com/', timeout=15) as response:
    hosted = response.read()
if local != hosted:
    raise SystemExit('Hosted HTML does not match the published presenter build')
print(json.dumps({'published': True, 'indexSha256': hashlib.sha256(local).hexdigest(),
                  'url': 'https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com/',
                  'apiRestarted': False}))
PY
REMOTE
