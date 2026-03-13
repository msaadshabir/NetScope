# Performance Validation Runbook

This runbook executes the acceptance checks from `perf-plan.md` against the current implementation.

## Prerequisites

- Build dependencies installed (`cargo`, `libpcap` headers).
- `sudo` access for live capture/replay.
- `tcpreplay` installed for traffic replay checks.
- A replay trace file for throughput/web checks (for example: `trace.pcap`).

## Quick Start

Run local automated checks (build, layout guard, benchmark, memory checks):

```bash
scripts/perf/validate.sh
```

This covers:

- target 2 benchmark evidence (`handshake_sequence`),
- target 4 memory checks (`--synthetic-flows` and ignored `memory_scale_1m` test),
- layout regression guard.

## Target 1: 100k pps, no loss

Use the perf config:

- `scripts/perf/perf-throughput.toml`

Run validation:

```bash
scripts/perf/validate-throughput.sh <interface> <trace.pcap> [packet_count]
```

Example:

```bash
scripts/perf/validate-throughput.sh lo0 trace.pcap 6000000
```

Acceptance criteria:

- periodic stats lines show `drops=0`,
- final summary shows `Dispatch drops: 0`,
- kernel stats show `Kernel dropped: 0` and `Interface dropped: 0`,
- median periodic packet rate stays within 95% of the target replay rate.

The helper script now prints a PASS/FAIL summary automatically from the captured log.

## Target 2: handshake hot path latency

```bash
cargo bench --bench hot_path -- handshake_sequence
```

Acceptance criteria:

- median `< 1000 ns/pkt`.

## Target 3: web 30fps and p99 < 100ms

Current accepted evidence:

- `tmp/perf/20260313-151454.web.netscope.log`
- `tmp/perf/20260313-151454.web.tcpreplay.log`
- Live overlay result: `29.3 fps | lat p50 13.6ms p95 28.6ms p99 31.5ms | drop 0 | offset 0.2ms`

Use the perf config:

- `scripts/perf/perf-web.toml`

Run with optional replay:

```bash
scripts/perf/validate-web.sh [interface] [trace.pcap]
```

Example:

```bash
scripts/perf/validate-web.sh lo0 trace.pcap
```

Then open:

```text
http://127.0.0.1:8080/?perf=1
```

Spot-check acceptance criteria:

- fps ~30,
- p99 latency < 100ms,
- stable frame continuity.

Use a longer soak only when regression-testing changes to the live render or websocket path.

Optional frame-sequence continuity check:

```bash
wscat -c ws://127.0.0.1:8080/ws | jq -r 'select(.type=="frame") | .frame_seq' | awk 'NR>1{print $0-prev} {prev=$0}' | awk '{s+=$1; n++} END {print "avg_seq_gap=" s/n}'
```

## Target 4: memory < 500MB @ 1M flows

CLI synthetic path:

```bash
/usr/bin/time -l ./target/release/netscope --synthetic-flows 1000000
```

Ignored integration test:

```bash
cargo test --release memory_scale_1m -- --ignored --nocapture
```

Acceptance criteria:

- CLI output reports `Budget check: PASS (< 500 MB)`,
- ignored test passes.

The CLI memory path now reads RSS from `/proc/self/status` on Linux and falls back to `ps`
elsewhere, so the same command works across supported development platforms.

## Notes

- Logs from helper scripts are written to `tmp/perf/`.
- Keep perf runs in `--quiet` mode; avoid exports and per-packet terminal output.
- For web performance measurements, keep `sample_rate = 0` to isolate stats/render latency.
