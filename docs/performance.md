# Performance

NetScope is designed for high-throughput packet processing. This page covers benchmark results, how to run benchmarks, and tuning guidance.

## Optimizations

The hot path uses several performance-focused design choices:

- **Zero-copy parsing** -- protocol headers are parsed as views over the original byte slice, with no allocations or copies.
- **ahash** -- `AHashMap` and `AHashSet` replace `std::HashMap` in the flow table and anomaly detector maps, reducing per-lookup hashing cost.
- **Partial top-N selection** -- uses `select_nth_unstable_by` to partition the top-N elements in O(F) time, then sorts only that slice. Avoids a full O(F log F) sort of the entire flow table each tick.
- **Minimal shard routing** -- the capture thread extracts the 5-tuple from raw packet bytes at fixed offsets (no full protocol parse) to keep the dispatch path as lean as possible.
- **Lock-free workers** -- each pipeline worker owns its own `FlowTracker` and `AnomalyDetector`, eliminating contention on the hot path.
- **Bounded channels** -- crossbeam bounded channels provide backpressure without allocations on the fast path.

## Benchmark Results

Criterion benchmarks measured on Apple M-series (`cargo bench`):

| Benchmark | Latency | Throughput |
|---|---|---|
| `parse_packet` (54B TCP SYN) | ~3.5 ns | ~289M pkt/s |
| `parse_packet` (1454B TCP data) | ~3.5 ns | ~283M pkt/s |
| `flow_observe` (existing flow) | ~13.5 ns | ~74M pkt/s |
| `flow_observe` (new flow) | ~89 ns | ~11M pkt/s |
| `shard_routing` (4 shards) | ~3.9 ns | ~257M pkt/s |

These numbers reflect isolated function-level performance. Actual capture throughput depends on the OS, NIC driver, libpcap configuration, and workload.

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
```

## Tuning Checklist

### Reducing kernel drops

- Use a BPF filter (`-f "..."`) to reduce the volume of traffic entering the capture pipeline.
- Increase pcap buffer size if your platform supports it (NetScope uses libpcap defaults).
- Enable pipeline mode (`--pipeline`) to parallelize processing.

### Reducing dispatch drops (pipeline mode)

- Increase `channel_capacity` in the `[pipeline]` config section (default: 4096). Higher values use more memory.
- Add more workers (`--workers N`).
- Apply a BPF filter to reduce packet volume.

### Reducing web dashboard load

- Increase `sample_rate` (e.g., `sample_rate = 10` sends every 10th packet).
- Reduce `top_n` (fewer flows per tick).
- Increase `tick_ms` (less frequent stats updates).
- Reduce `payload_bytes` (smaller hex dumps per packet).

### Reducing memory usage

- Lower `max_flows` to cap the flow table size.
- Reduce `flow.timeout_secs` to expire flows sooner.
- Lower `packet_buffer` to keep fewer packets in the web dashboard ring buffer.
- Note: in pipeline mode, `max_flows` is per-shard, so the effective limit is `max_flows * num_workers`.

### CPU usage

- Pipeline mode with auto-detected workers uses half the available CPU cores (clamped 1..8).
- Disable analysis features you don't need: `analysis.rtt = false`, `analysis.retrans = false`, `analysis.out_of_order = false`.
- Disable anomaly detection if not needed: `analysis.anomalies.enabled = false`.
