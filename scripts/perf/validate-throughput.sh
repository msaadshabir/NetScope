#!/usr/bin/env bash
set -euo pipefail

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
cleanup() {
  if [[ -n "$replay_pid" ]] && kill -0 "$replay_pid" >/dev/null 2>&1; then
    kill "$replay_pid" >/dev/null 2>&1 || true
    wait "$replay_pid" 2>/dev/null || true
  fi
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

echo
echo "Validation run complete."
echo "Check acceptance in $APP_LOG:"
echo "  - periodic lines show drops=0"
echo "  - final summary shows Dispatch drops: 0"
echo "  - kernel stats show dropped=0 and if_dropped=0"
