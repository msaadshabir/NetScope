#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="$ROOT_DIR/tmp/perf"
mkdir -p "$OUT_DIR"
STAMP="$(date +"%Y%m%d-%H%M%S")"
LOG_PREFIX="$OUT_DIR/$STAMP"

echo "== NetScope performance validation =="
echo "Root: $ROOT_DIR"
echo "Logs: ${LOG_PREFIX}.*"

echo
echo "[1/5] Build release"
cargo build --release | tee "${LOG_PREFIX}.build.log"

echo
echo "[2/5] Layout guard"
cargo test layout_sizes_phase4 -- --nocapture | tee "${LOG_PREFIX}.layout.log"

echo
echo "[3/5] Handshake benchmark"
cargo bench --bench hot_path -- handshake_sequence | tee "${LOG_PREFIX}.bench.log"

echo
echo "[4/5] Memory validation (CLI synthetic flows)"
/usr/bin/time -l ./target/release/netscope --synthetic-flows 1000000 \
  2>&1 | tee "${LOG_PREFIX}.memory-cli.log"

echo
echo "[5/5] Memory validation (ignored test)"
cargo test --release memory_scale_1m -- --ignored --nocapture \
  | tee "${LOG_PREFIX}.memory-test.log"

cat <<EOF

Completed local automated checks.

Manual acceptance runs still required:
1) Throughput/no-loss (target 1)
   sudo tcpreplay --intf1=<iface> --pps=100000 --loop=0 <trace.pcap>
   sudo ./target/release/netscope --config scripts/perf/perf-throughput.toml --pipeline --quiet --stats --count 6000000

2) Web fps/latency (target 3)
   sudo ./target/release/netscope --config scripts/perf/perf-web.toml --pipeline --quiet --web
   Open http://127.0.0.1:8080/?perf=1

Artifacts:
  ${LOG_PREFIX}.build.log
  ${LOG_PREFIX}.layout.log
  ${LOG_PREFIX}.bench.log
  ${LOG_PREFIX}.memory-cli.log
  ${LOG_PREFIX}.memory-test.log
EOF
