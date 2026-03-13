# Performance

NetScope is designed for high-throughput packet processing. This page covers benchmark results, how to run benchmarks, and tuning guidance.

## Optimizations

The hot path uses several performance-focused design choices:

- **Zero-copy parsing** -- protocol headers are parsed as views over the original byte slice, with no allocations or copies.
- **ahash** -- `AHashMap` and `AHashSet` replace `std::HashMap` in the flow table and anomaly detector maps, reducing per-lookup hashing cost.
- **Partial top-N selection** -- uses `select_nth_unstable_by` to partition the top-N elements in O(F) time, then sorts only that slice. Avoids a full O(F log F) sort of the entire flow table each tick.
- **Streaming heavy-hitters for web ticks** -- pipeline workers use a fixed-size SpaceSaving-style tracker to keep top-flow candidate selection bounded per packet, then resolve exact deltas only for those candidates before sending the dashboard payload.
- **Merged websocket frames** -- the web server batches each tick with sampled packets and alerts into one live frame, reducing websocket wakeups and making lag recovery resend the latest state instead of replaying backlog.
- **Minimal shard routing** -- the capture thread extracts the 5-tuple from raw packet bytes at fixed offsets (no full protocol parse) to keep the dispatch path as lean as possible.
- **Lock-free workers** -- each pipeline worker owns its own `FlowTracker` and `AnomalyDetector`, eliminating contention on the hot path.
- **Bounded channels** -- crossbeam bounded channels provide backpressure without allocations on the fast path.
- **Flow table pre-sizing** -- `FlowTracker` reserves hash map capacity based on `flow.max_flows` to avoid rehashing/resizes during steady-state capture.
- **Scale-mode storage** -- when RTT, retransmission, and out-of-order analysis are all disabled, `FlowTracker` switches to compact split IPv4/IPv6 flow tables backed by `ScaleFlowEntry`, avoiding TCP sequence-tracker allocation in that mode.

## Benchmark Results

Criterion benchmarks measured on Apple M-series (`cargo bench`):

| Benchmark | Latency | Throughput |
|---|---|---|
| `parse_packet` (54B TCP SYN) | ~5.8 ns | ~172M pkt/s |
| `parse_packet` (1454B TCP data) | ~5.8 ns | ~173M pkt/s |
| `flow_observe` (existing flow) | ~25 ns | ~40M pkt/s |
| `flow_observe` (new flow, cold setup) | ~7.7 us | ~130k pkt/s |
| `shard_routing` (4 shards) | ~4.1 ns | ~246M pkt/s |
| `handshake_sequence` (SYN → SYN-ACK → ACK) | ~105 ns/pkt | ~9.6M pkt/s |

These numbers reflect isolated function-level performance measured by Criterion and will vary by CPU, compiler version, and background load.
The `flow_observe (new flow, cold setup)` benchmark includes flow tracker setup and is intended to represent a cold-path baseline rather than steady-state capture.
Actual capture throughput depends on the OS, NIC driver, libpcap configuration, and workload.

## Running Benchmarks

```bash
cargo bench
```

This runs the Criterion benchmarks defined in `benches/hot_path.rs`. Results are written to `target/criterion/` with HTML reports.

To run a specific benchmark:

```bash
cargo bench -- parse_packet
cargo bench -- flow_observe
cargo bench -- shard_routing
cargo bench -- handshake_sequence
```

## Tuning Checklist

### Reducing kernel drops

- Use a BPF filter (`-f "..."`) to reduce the volume of traffic entering the capture pipeline.
- Increase libpcap buffer size via config: `capture.buffer_size_mb = 8` (or higher for bursty traffic).
- Consider `capture.immediate_mode = true` (best-effort; depends on libpcap support).
- Enable pipeline mode (`--pipeline`) to parallelize processing.

Example perf-oriented capture config:

```toml
[capture]
timeout_ms = 1
buffer_size_mb = 8
immediate_mode = true
```

### Reducing dispatch drops (pipeline mode)

- Increase `channel_capacity` in the `[pipeline]` config section (default: 4096). Higher values use more memory.
- Add more workers (`--workers N`).
- Apply a BPF filter to reduce packet volume.

### Reducing web dashboard load

- Increase `sample_rate` (e.g., `sample_rate = 10` sends every 10th packet).
- Reduce `top_n` (fewer flows per tick).
- Increase `tick_ms` (less frequent stats updates). Use `33` for roughly 30fps when you want smooth live updates.
- Reduce `payload_bytes` (smaller hex dumps per packet).
- Use `?perf=1` in the dashboard URL to inspect fps, latency p50/p95/p99, dropped frames, and client/server clock offset while tuning.
- The current accepted Target 3 evidence is the representative replay run in `tmp/perf/20260313-151454.web.*.log` with `29.3 fps`, `p99 31.5ms`, and `drop 0`.

### Reducing memory usage

- Lower `max_flows` to cap the flow table size.
- Reduce `flow.timeout_secs` to expire flows sooner.
- Lower `packet_buffer` to keep fewer packets in the web dashboard ring buffer.
- Note: in pipeline mode, `max_flows` is per-shard, so the effective limit is `max_flows * num_workers`.
- For large flow-count runs, disable deep TCP analysis (`analysis.rtt = false`, `analysis.retrans = false`, `analysis.out_of_order = false`) to activate scale-mode flow storage.

### Memory validation

Use the synthetic flow path to quickly validate scale-mode memory usage:

```bash
cargo run --release -- --synthetic-flows 1000000
```

This prints insertion time, estimated RSS, and a pass/fail check against the 500MB budget.

For a test-target workflow, run the long ignored test:

```bash
cargo test --release -- --ignored memory_scale_1m
```

### CPU usage

- Pipeline mode with auto-detected workers uses half the available CPU cores (clamped 1..8).
- Disable analysis features you don't need: `analysis.rtt = false`, `analysis.retrans = false`, `analysis.out_of_order = false`.
- Disable anomaly detection if not needed: `analysis.anomalies.enabled = false`.
