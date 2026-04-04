# NetScope

High-performance packet capture and protocol analysis tool built in Rust. Captures live network traffic, tracks bidirectional flows with TCP state and RTT estimation, detects anomalies, and serves a real-time web dashboard -- all from a single binary.

## Features

- **Live packet capture** via libpcap with BPF filter support
- **Offline pcap analysis** via `--read-pcap` (supports BPF filters; no elevated privileges required)
- **Zero-copy protocol parsing** -- Ethernet, Linux SLL, loopback NULL/LOOP, raw IP, 802.1Q VLAN, IPv4, IPv6, TCP, UDP, ICMP, DNS (UDP/53 decode), TLS ClientHello SNI extraction (best-effort, packet-level)
- **Flow tracking** -- bidirectional counters, TCP state machine, RTT estimation, retransmission and out-of-order detection
- **Scale-mode flow storage** -- compact internal flow tables activate automatically when deep TCP analysis is disabled
- **Sharded pipeline** -- multi-core processing with lock-free per-shard flow tracking
- **Anomaly detection** -- SYN flood and port scan alerts with configurable thresholds
- **Web dashboard** -- real-time browser UI with throughput charts, top flows, packet inspector, alerts, and a perf overlay backed by merged websocket frames
- **Live drop metrics** -- periodic kernel/libpcap drop and interface drop deltas/totals (CLI + dashboard)
- **Export** -- flows to JSON/CSV, alerts to JSONL (inline and pipeline modes), expired/evicted flows to JSONL, packets to pcap
- **TOML configuration** with full CLI override support

## Quickstart

```bash
# Build (Rust toolchain is pinned via rust-toolchain.toml; rustup will auto-install it)
cargo build --release

# List interfaces
sudo ./target/release/netscope --list-interfaces

# Capture on the default interface
sudo ./target/release/netscope

# Analyze an offline pcap (no sudo required)
./target/release/netscope --read-pcap trace.pcap --quiet --stats

# Start the web dashboard (open http://127.0.0.1:8080)
sudo ./target/release/netscope --web --quiet
```

Live capture requires elevated privileges (`sudo` or `CAP_NET_RAW` on Linux). Offline pcap analysis (`--read-pcap`) does not. For more workflows, including exports, anomaly detection, and pipeline mode, see [Usage Examples](docs/usage.md). For dashboard-specific behavior and tuning, see [Web Dashboard](docs/web-dashboard.md).

## Documentation

| Guide                                              | Description                                         |
| -------------------------------------------------- | --------------------------------------------------- |
| **[Getting Started](docs/getting-started.md)**     | Prerequisites, building, permissions, first capture |
| **[Usage Examples](docs/usage.md)**                | Common recipes and workflows                        |
| **[CLI Reference](docs/cli-reference.md)**         | Complete flag and option list                       |
| **[Configuration](docs/configuration.md)**         | TOML config schema and precedence rules             |
| **[Web Dashboard](docs/web-dashboard.md)**         | Real-time browser UI setup and tuning               |
| **[Sharded Pipeline](docs/pipeline.md)**           | Multi-core architecture and tuning                  |
| **[Flow Tracking](docs/flow-tracking.md)**         | Bidirectional flows, TCP state, RTT                 |
| **[Anomaly Detection](docs/anomaly-detection.md)** | SYN flood and port scan detection                   |
| **[Exports](docs/exports.md)**                     | Output formats (JSON, CSV, JSONL, pcap)             |
| **[Performance](docs/performance.md)**             | Benchmarks and tuning checklist                     |
| **[Troubleshooting](docs/troubleshooting.md)**     | Common issues and fixes                             |
| **[Development](docs/development.md)**             | Repo layout, tests, extending protocols             |

## Notes

- Live capture typically requires **root privileges**. Offline pcap analysis (`--read-pcap`) does not. The web dashboard binds to `127.0.0.1` by default. Binding to `0.0.0.0` exposes live traffic data with no authentication.
- IPv6 extension headers are partially supported: common headers are walked to find the effective transport payload and shard routing key.
- Supported datalink types include Ethernet, Linux SLL, loopback NULL/LOOP, and raw IP. Other datalink types are currently reported as unsupported.
- IPv4 non-initial fragments are skipped for flow tracking.
- TLS SNI extraction is packet-level and best-effort. ClientHello messages split across TCP segments may be missed, ECH can hide the real SNI, and SNI is only surfaced when it looks like a valid ASCII hostname (labels `A-Za-z0-9-`).
- Timestamps are formatted as `HH:MM:SS.microseconds` from UNIX-epoch UTC capture times.

## License

MIT License. See [LICENSE](LICENSE).
