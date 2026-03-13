#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage:
  scripts/perf/validate-web.sh [interface] [trace.pcap]

Examples:
  scripts/perf/validate-web.sh
  scripts/perf/validate-web.sh lo0 trace.pcap

If interface+trace are provided, tcpreplay is started automatically.
If omitted, start traffic separately and keep this script running.

Environment overrides:
  PPS=100000
  CONFIG=scripts/perf/perf-web.toml
  BINARY=./target/release/netscope
  TCPREPLAY_BIN=$(command -v tcpreplay)
  LOG_DIR=tmp/perf
EOF
}

if [[ $# -gt 2 ]]; then
  usage
  exit 1
fi

IFACE="${1:-}"
TRACE="${2:-}"

PPS="${PPS:-100000}"
CONFIG="${CONFIG:-scripts/perf/perf-web.toml}"
BINARY="${BINARY:-./target/release/netscope}"
TCPREPLAY_BIN="${TCPREPLAY_BIN:-$(command -v tcpreplay || true)}"
LOG_DIR="${LOG_DIR:-tmp/perf}"

if [[ "$BINARY" != /* ]]; then
  BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "error: config file not found: $CONFIG" >&2
  exit 1
fi

if [[ -n "$TRACE" && ! -f "$TRACE" ]]; then
  echo "error: trace file not found: $TRACE" >&2
  exit 1
fi

if [[ ! -x "$BINARY" ]]; then
  echo "info: release binary missing, building..."
  cargo build --release
fi

if [[ -n "$TRACE" && -z "$IFACE" ]]; then
  echo "error: interface is required when trace path is provided" >&2
  exit 1
fi

if [[ -n "$IFACE" && -z "$TRACE" ]]; then
  echo "error: trace path is required when interface is provided" >&2
  exit 1
fi

if [[ -n "$IFACE" && -z "$TCPREPLAY_BIN" ]]; then
  echo "error: tcpreplay is required when interface/trace are provided" >&2
  exit 1
fi

mkdir -p "$LOG_DIR"
STAMP="$(date +"%Y%m%d-%H%M%S")"
APP_LOG="$LOG_DIR/${STAMP}.web.netscope.log"
REPLAY_LOG="$LOG_DIR/${STAMP}.web.tcpreplay.log"

echo "== Web Validation (Target 3) =="
echo "config: $CONFIG"
echo "log:    $APP_LOG"
if [[ -n "$IFACE" ]]; then
  echo "replay: iface=$IFACE trace=$TRACE pps=$PPS"
  echo "replay log: $REPLAY_LOG"
fi

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

if [[ -n "$IFACE" ]]; then
  sudo "$TCPREPLAY_BIN" --intf1="$IFACE" --pps="$PPS" --loop=0 "$TRACE" >"$REPLAY_LOG" 2>&1 &
  replay_pid="$!"
  sleep 1
fi

echo
echo "Starting NetScope web run. Open: http://127.0.0.1:8080/?perf=1"
echo "Quick spot-check target: ~30fps, p99 < 100ms, drop 0."
echo "Accepted reference: tmp/perf/20260313-151454.web.*.log -> 29.3 fps | p99 31.5ms | drop 0"
echo "Let the overlay settle for ~30s; use a longer soak only when regression-testing."

args=(
  --config "$CONFIG"
  --pipeline
  --quiet
  --web
)

if [[ -n "$IFACE" ]]; then
  args+=(--interface "$IFACE")
fi

sudo "$BINARY" "${args[@]}" | tee "$APP_LOG"

stop_replay
