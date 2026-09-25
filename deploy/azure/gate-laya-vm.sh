#!/usr/bin/env bash
# Run only on the existing VibeSecur demo VM after the principal grants its
# serial heavy-job slot. No phase loads a model on the operator's PC.
set -euo pipefail

APP=/srv/vibesecur/app
DATA=/srv/vibesecur/data/laya
LOCK=$DATA/requirements-laya.full.lock
PY=$DATA/runtime-venv/bin/python
MIN_AVAILABLE_KIB=1048576
MIN_DISK_KIB=6291456

usage() {
  cat <<'EOF'
Usage:
  bash deploy/azure/gate-laya-vm.sh resolve --slot-granted
  bash deploy/azure/gate-laya-vm.sh prefetch --slot-granted --lock-sha256 HEX
  bash deploy/azure/gate-laya-vm.sh infer --slot-granted --lock-sha256 HEX
  bash deploy/azure/gate-laya-vm.sh check-candidate-lock PATH

Existing demo VM only. Root must grant the serial slot before each invocation.
The local flock covers Laya phases only; root coordinates other heavy jobs.
Resolve writes a candidate full transitive hash lock and stops for review.
Prefetch and infer require the reviewed lock's exact SHA-256.
Each phase: MemoryMax=5G, CPUQuota=100%, TasksMax=128, RuntimeMaxSec=1800.
The host watchdog stops the unit if MemAvailable <1 GiB or API routes fail.
No phase trains Laya or changes Azure resources.
EOF
}

die() { printf 'Laya VM gate: %s\n' "$*" >&2; exit 2; }

host_guard() {
  [[ $(hostname -s) == vibesecur-demo-vm ]] || die 'wrong VM hostname'
  [[ $(id -un) == demo ]] || die 'run as demo on the existing VM'
  [[ -f $APP/scripts/gate_laya.py && -d /srv/vibesecur/data ]] || die 'demo source/data missing'
  [[ $(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') == 3.12 ]] ||
    die 'target Python must be 3.12'
}

available_kib() { awk '/^MemAvailable:/ {print $2}' /proc/meminfo; }

api_ok() {
  local route
  for route in /health /api/session /; do
    curl --disable --fail --silent --show-error --noproxy '*' --max-time 2 \
      "http://127.0.0.1:8000$route" >/dev/null || return 1
  done
}

bounded_cgroup_guard() {
  local phase=$1 unit=$2 path dir mem swap pids quota period control runtime runtime_us
  [[ $phase == resolve || $phase == prefetch || $phase == infer ]] ||
    die 'bounded systemd cgroup phase invalid'
  [[ $unit =~ ^vibesecur-laya-${phase}-[0-9]+\.service$ ]] || die 'bounded systemd cgroup unit mismatch'
  path=$(awk -F: '$1=="0" {print $3}' /proc/self/cgroup)
  [[ $path == "/system.slice/$unit" ]] || die 'bounded systemd cgroup missing or mismatched'
  dir=/sys/fs/cgroup$path
  [[ -d $dir ]] || die 'bounded systemd cgroup path missing'
  read -r mem <"$dir/memory.max"
  read -r swap <"$dir/memory.swap.max"
  read -r pids <"$dir/pids.max"
  read -r quota period <"$dir/cpu.max"
  [[ $mem == 5368709120 && $swap == 0 && $pids == 128 &&
     $quota =~ ^[0-9]+$ && $period =~ ^[0-9]+$ && $quota == "$period" ]] ||
    die 'bounded systemd cgroup effective memory/CPU/tasks limits differ'
  control=$(systemctl show --no-pager --value -p ControlGroup "$unit")
  [[ $control == "$path" ]] || die 'bounded systemd cgroup control group differs'
  [[ $(systemctl show --no-pager --value -p Transient "$unit") == yes &&
     $(systemctl show --no-pager --value -p User "$unit") == demo ]] ||
    die 'bounded systemd cgroup transient user differs'
  runtime=$(systemctl show --no-pager --value -p RuntimeMaxUSec "$unit")
  runtime_us=$(systemd-analyze timespan "$runtime" | awk 'NR==2 {print $2}')
  [[ $runtime_us == 1800000000 ]] || die 'bounded systemd runtime limit differs'
}

preflight() {
  local free_kib
  [[ $(available_kib) -ge $MIN_AVAILABLE_KIB ]] || die 'less than 1 GiB available memory'
  free_kib=$(df -Pk "$DATA" | awk 'NR==2 {print $4}')
  [[ $free_kib -ge $MIN_DISK_KIB ]] || die 'less than 6 GiB free disk'
  api_ok || die 'API health/session/static preflight failed'
  sudo -n true >/dev/null || die 'noninteractive sudo unavailable for bounded systemd unit'
}

check_lock() {
  local expected=$1 actual
  [[ -f $LOCK ]] || die 'reviewed full lock missing'
  actual=$(sha256sum "$LOCK" | awk '{print $1}')
  [[ $actual == "$expected" ]] || die 'reviewed lock SHA-256 mismatch'
  check_generated_lock "$LOCK"
  pinned_hashes_present
}

check_generated_lock() {
  local candidate=$1
  [[ -s $candidate ]] || die 'candidate full lock missing or empty'
  if grep -Eq '^# WARNING:|^# setuptools([[:space:]]|$)|allow-unsafe flag' "$candidate"; then
    die 'candidate lock contains unsafe-package omission warning'
  fi
  grep -Fqx -- '--index-url https://pypi.org/simple' "$candidate" ||
    die 'candidate lock lacks explicit PyPI index provenance'
  if grep -Fq -- '--no-index' "$candidate"; then
    die 'candidate lock contains ambiguous --no-index provenance'
  fi
  python3 - "$candidate" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
pattern = r'(?m)^setuptools==84\.0\.0[ \t]+\\\r?\n[ \t]+--hash=sha256:[0-9a-f]{64}(?:[ \t]*\\)?(?:\r?\n|$)'
if not re.search(pattern, text):
    raise SystemExit('Laya VM gate: candidate lock lacks hashed setuptools==84.0.0')
if 'sha256:51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670' not in text:
    raise SystemExit('Laya VM gate: candidate lock lacks pinned setuptools wheel hash')
PY
}

normalize_compiler_lock() {
  local raw=$1 normalized=$2 provenance=$3 input=$4
  shift 4
  python3 - "$raw" "$normalized" "$provenance" "$input" "$@" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

raw_path, lock_path, provenance_path, input_path = map(Path, sys.argv[1:5])
command = sys.argv[5:]
raw = raw_path.read_text()
if (not raw.startswith('--only-binary :all:\n') or
        any(option in raw for option in ('--index-url', '--extra-index-url',
                                          '--no-index', '--trusted-host'))):
    raise SystemExit('Laya VM gate: compiler body has unexpected index or source options')
if not raw.strip() or not command or '--index-url=https://pypi.org/simple' not in command:
    raise SystemExit('Laya VM gate: explicit resolver index provenance missing')
lock = '--index-url https://pypi.org/simple\n' + raw
lock_path.write_text(lock)
digest = lambda data: hashlib.sha256(data).hexdigest()
provenance = {
    'phase': 'resolve', 'indexPolicy': 'https://pypi.org/simple',
    'indexLineSource': 'explicit install-policy normalization',
    'reason': 'pip-tools suppresses its default PyPI index URL',
    'compilerArgs': command,
    'compilerBodySha256': digest(raw.encode()),
    'normalizedLockSha256': digest(lock.encode()),
    'inputSha256': digest(input_path.read_bytes()),
    'pythonVersion': '.'.join(map(str, sys.version_info[:3])),
}
provenance_path.write_text(json.dumps(provenance, sort_keys=True, indent=2)+'\n')
PY
}

pinned_hashes_present() {
  grep -Fq '6039e802fa5effb8dd492061cd7ad39a43087beadc4a4fa4a649614e77eb83d4' "$LOCK" ||
    die 'full lock lacks the pinned Laya wheel hash'
  grep -Fq '7417d8c565f219d3455654cb431c6d892a3eb40246055e14d645422de13b9ea1' "$LOCK" ||
    die 'full lock lacks the pinned PyTorch CPU wheel hash'
}

installed_versions() {
  "$PY" -I - <<'PY'
from importlib.metadata import version
if version('laya') != '0.3.20':
    raise SystemExit('Laya release differs from pin')
if version('torch') != '2.9.1+cpu':
    raise SystemExit('PyTorch CPU release differs from pin')
print('laya=0.3.20 torch=2.9.1+cpu')
PY
}

inside_phase() {
  local phase=$1 lock_sha=${2:-} unit=${3:-} resolver raw provenance
  bounded_cgroup_guard "$phase" "$unit"
  host_guard
  cd "$APP"
  mkdir -p "$DATA" "$DATA/hf" "$DATA/pip" "$DATA/home"
  chmod 700 "$DATA"
  export HF_HOME=$DATA/hf PIP_CACHE_DIR=$DATA/pip HOME=$DATA/home
  export OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 TOKENIZERS_PARALLELISM=false
  export HF_HUB_DISABLE_TELEMETRY=1 PIP_ONLY_BINARY=:all:
  export PIP_INDEX_URL=https://pypi.org/simple PIP_EXTRA_INDEX_URL= PIP_CONFIG_FILE=/dev/null
  export HF_ENDPOINT=https://huggingface.co
  unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONINSPECT
  case "$phase" in
    resolve)
      [[ ! -e $LOCK ]] || die 'candidate full lock already exists; review or archive it first'
      resolver=$DATA/resolve-venv/bin/python
      raw=$DATA/requirements-laya.piptools.lock
      provenance=$DATA/requirements-laya.resolve-provenance.json
      [[ ! -e $raw && ! -e $provenance ]] || die 'prior compiler output or provenance must be archived first'
      python3 -m venv "$DATA/resolve-venv"
      "$resolver" -m pip install --no-input --only-binary=:all: pip-tools==7.5.2
      local -a compile_args=(--generate-hashes --allow-unsafe --no-config --no-header
        --index-url=https://pypi.org/simple --emit-index-url --resolver=backtracking
        --pip-args=--only-binary=:all: -o "$raw" "$APP/requirements-laya.in")
      "$resolver" -m piptools compile "${compile_args[@]}"
      normalize_compiler_lock "$raw" "$LOCK" "$provenance" \
        "$APP/requirements-laya.in" "${compile_args[@]}"
      check_generated_lock "$LOCK"
      pinned_hashes_present
      sha256sum "$raw" "$LOCK" "$provenance" "$APP/requirements-laya.in"
      printf 'STOP: review the full transitive lock before prefetch.\n'
      ;;
    prefetch)
      check_lock "$lock_sha"
      python3 -m venv "$DATA/runtime-venv"
      "$PY" -m pip install --no-input --require-hashes --only-binary=:all: -r "$LOCK"
      "$PY" -m pip check
      installed_versions
      "$PY" -I "$APP/scripts/gate_laya.py" --mode prefetch --output "$DATA/laya-prefetch.json"
      sha256sum "$LOCK" "$APP/scripts/gate_laya.py" "$DATA/laya-prefetch.json"
      ;;
    infer)
      check_lock "$lock_sha"
      [[ -x $PY && -f $DATA/laya-prefetch.json ]] || die 'prefetch/runtime environment missing'
      "$PY" -m pip check
      installed_versions
      "$PY" -I "$APP/scripts/gate_laya.py" --mode infer --output "$DATA/laya-suitability.json"
      sha256sum "$LOCK" "$APP/scripts/gate_laya.py" "$DATA/laya-suitability.json"
      ;;
    *) die 'invalid bounded phase' ;;
  esac
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
if [[ ${1:-} == check-candidate-lock ]]; then
  [[ $# == 2 ]] || die 'check-candidate-lock requires one path'
  check_generated_lock "$2"
  exit
fi
if [[ ${1:-} == normalize-candidate-lock ]]; then
  [[ $# == 5 ]] || die 'normalize-candidate-lock requires raw, normalized, provenance and input paths'
  normalize_compiler_lock "$2" "$3" "$4" "$5" --index-url=https://pypi.org/simple
  check_generated_lock "$3"
  exit
fi
if [[ ${1:-} == __inside ]]; then
  inside_phase "${2:-}" "${3:-}" "${4:-}"
  exit
fi

phase=${1:-}
[[ $phase == resolve || $phase == prefetch || $phase == infer ]] || { usage >&2; die 'mode required'; }
shift
slot=0
lock_sha=
while (($#)); do
  case "$1" in
    --slot-granted) slot=1; shift ;;
    --lock-sha256) (($# >= 2)) || die 'lock SHA-256 value missing'; lock_sha=$2; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ $slot == 1 ]] || die 'principal has not granted the serial slot'
if [[ $phase != resolve ]]; then
  [[ $lock_sha =~ ^[0-9a-f]{64}$ ]] || die 'reviewed lock SHA-256 required'
fi
host_guard
mkdir -p "$DATA"
chmod 700 "$DATA"
preflight

exec 9>"$DATA/slot.lock"
flock -n 9 || die 'another Laya gate phase holds the local slot'
unit="vibesecur-laya-${phase}-$$"
log="$DATA/${unit}.log"
sudo -n /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/systemd-run \
  --quiet --wait --collect --pipe --unit="$unit" \
  -p User=demo -p WorkingDirectory="$APP" -p MemoryMax=5G -p MemorySwapMax=0 \
  -p CPUQuota=100% -p TasksMax=128 -p RuntimeMaxSec=1800 \
  -p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=yes \
  -p PrivateTmp=yes -p ReadWritePaths="$DATA" -p UMask=0077 \
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$DATA/home" \
  /bin/bash "$APP/deploy/azure/gate-laya-vm.sh" __inside "$phase" "$lock_sha" \
  "$unit.service" >"$log" 2>&1 &
launcher=$!
stopped=0
stop_unit() {
  local attempt
  for attempt in 1 2 3 4 5; do
    if sudo -n systemctl stop "$unit" >/dev/null 2>&1; then return 0; fi
    kill -0 "$launcher" 2>/dev/null || return 0
    sleep 1
  done
  return 1
}
trap 'stop_unit || true; exit 130' INT
trap 'stop_unit || true; exit 143' TERM
while kill -0 "$launcher" 2>/dev/null; do
  if [[ $(available_kib) -lt $MIN_AVAILABLE_KIB ]] || ! api_ok; then
    stopped=1
    stop_unit || die "could not stop $unit after health/memory alert"
    break
  fi
  sleep 2
done
phase_exit=0
wait "$launcher" || phase_exit=$?
[[ $stopped == 0 ]] || die "bounded $phase phase stopped for memory or API health"
if [[ $phase_exit != 0 ]]; then
  tail -n 30 "$log" >&2 || true
  die "bounded $phase phase failed; log: $log"
fi
trap - INT TERM
printf 'Bounded %s phase completed; log: %s\n' "$phase" "$log"
