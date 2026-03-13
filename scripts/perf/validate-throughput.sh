#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage:
  scripts/perf/validate-throughput.sh <interface> <trace.pcap> [packets]

Examples:
  scripts/perf/validate-throughput.sh lo0 trace.pcap
  scripts/perf/validate-throughput.sh en0 trace.pcap 6000000

Environment overrides:
  PPS=100000
  CONFIG=scripts/perf/perf-throughput.toml
  BINARY=./target/release/netscope
  TCPREPLAY_BIN=$(command -v tcpreplay)
  LOG_DIR=tmp/perf
EOF
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

IFACE="$1"
TRACE="$2"
PACKETS="${3:-6000000}"

PPS="${PPS:-100000}"
CONFIG="${CONFIG:-scripts/perf/perf-throughput.toml}"
BINARY="${BINARY:-./target/release/netscope}"
TCPREPLAY_BIN="${TCPREPLAY_BIN:-$(command -v tcpreplay || true)}"
LOG_DIR="${LOG_DIR:-tmp/perf}"

if [[ "$BINARY" != /* ]]; then
  BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
fi

if [[ ! -f "$TRACE" ]]; then
  echo "error: trace file not found: $TRACE" >&2
  exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "error: config file not found: $CONFIG" >&2
  exit 1
fi

if [[ ! -x "$BINARY" ]]; then
  echo "info: release binary missing, building..."
  cargo build --release
fi

if [[ -z "$TCPREPLAY_BIN" ]]; then
  echo "error: tcpreplay is required for throughput validation" >&2
  exit 1
fi

mkdir -p "$LOG_DIR"
STAMP="$(date +"%Y%m%d-%H%M%S")"
APP_LOG="$LOG_DIR/${STAMP}.throughput.netscope.log"
REPLAY_LOG="$LOG_DIR/${STAMP}.throughput.tcpreplay.log"

echo "== Throughput Validation (Target 1) =="
echo "interface: $IFACE"
echo "trace:     $TRACE"
echo "pps:       $PPS"
echo "packets:   $PACKETS"
echo "config:    $CONFIG"
echo "logs:      $APP_LOG"
echo "           $REPLAY_LOG"

replay_pid=""
stop_replay() {
  if [[ -n "$replay_pid" ]] && kill -0 "$replay_pid" >/dev/null 2>&1; then
    kill -INT "$replay_pid" >/dev/null 2>&1 || true
    wait "$replay_pid" 2>/dev/null || true
    replay_pid=""
  fi
}

cleanup() {
  stop_replay
}
trap cleanup EXIT

sudo "$TCPREPLAY_BIN" --intf1="$IFACE" --pps="$PPS" --loop=0 "$TRACE" >"$REPLAY_LOG" 2>&1 &
replay_pid="$!"

# Give the replay process a brief head-start.
sleep 1

sudo "$BINARY" \
  --config "$CONFIG" \
  --interface "$IFACE" \
  --pipeline \
  --quiet \
  --stats \
  --count "$PACKETS" \
  | tee "$APP_LOG"

stop_replay

echo
echo "Validation run complete."

python3 - "$APP_LOG" "$PPS" <<'PY'
import pathlib
import re
import statistics
import sys

log_path = pathlib.Path(sys.argv[1])
target_pps = int(sys.argv[2])
text = log_path.read_text()

periodic_drops = [int(m.group(1)) for m in re.finditer(r"drops=(\d+) \(total=\d+\)", text)]
pps_values = [int(m.group(1)) for m in re.finditer(r"\|\s+(\d+) pps \|", text)]

def extract(pattern: str):
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None

dispatch = extract(r"Dispatch drops:\s+(\d+)")
kernel = extract(r"Kernel dropped:\s+(\d+)")
iface = extract(r"Interface dropped:\s+(\d+)")

median_pps = statistics.median(pps_values) if pps_values else None
avg_pps = (sum(pps_values) / len(pps_values)) if pps_values else None
pps_threshold = int(target_pps * 0.95)

checks = {
    "periodic drops": bool(periodic_drops) and all(v == 0 for v in periodic_drops),
    "dispatch drops": dispatch == 0,
    "kernel drops": kernel == 0,
    "interface drops": iface == 0,
    "median pps": median_pps is not None and median_pps >= pps_threshold,
}

print(f"Log:                {log_path}")
print(f"Periodic samples:   {len(pps_values)}")
if avg_pps is not None:
    print(f"Average pps:        {avg_pps:.0f}")
if median_pps is not None:
    print(f"Median pps:         {median_pps:.0f} (target >= {pps_threshold})")
if pps_values:
    print(f"Pps range:          {min(pps_values)} .. {max(pps_values)}")
print(f"Dispatch drops:     {dispatch if dispatch is not None else 'missing'}")
print(f"Kernel dropped:     {kernel if kernel is not None else 'missing'}")
print(f"Interface dropped:  {iface if iface is not None else 'missing'}")

failed = [name for name, ok in checks.items() if not ok]
if failed:
    print("Result:             FAIL")
    print("Failed checks:      " + ", ".join(failed))
    sys.exit(2)

print("Result:             PASS")
PY
