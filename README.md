# NetScope

High-performance packet capture and protocol analysis tool built in Rust. Captures live network traffic, tracks bidirectional flows with TCP state and RTT estimation, detects anomalies, and serves a real-time web dashboard -- all from a single binary.

## Features

- **Live packet capture** via libpcap with BPF filter support
- **Zero-copy protocol parsing** -- Ethernet, 802.1Q VLAN, IPv4, IPv6, TCP, UDP, ICMP
- **Flow tracking** -- bidirectional counters, TCP state machine, RTT estimation, retransmission and out-of-order detection
- **Scale-mode flow storage** -- compact internal flow tables activate automatically when deep TCP analysis is disabled
- **Sharded pipeline** -- multi-core processing with lock-free per-shard flow tracking
- **Anomaly detection** -- SYN flood and port scan alerts with configurable thresholds
- **Web dashboard** -- real-time browser UI with throughput charts, top flows, packet inspector, alerts, and a perf overlay backed by merged websocket frames
- **Export** -- flows to JSON/CSV, alerts to JSONL, packets to pcap
- **TOML configuration** with full CLI override support

## Quickstart

```bash
# Build
cargo build --release

# List interfaces
sudo ./target/release/netscope --list-interfaces

# Capture on the default interface
sudo ./target/release/netscope

# Start the web dashboard (open http://127.0.0.1:8080)
sudo ./target/release/netscope --web --quiet
```

Live capture requires elevated privileges (`sudo` or `CAP_NET_RAW` on Linux). For more workflows, including exports, anomaly detection, and pipeline mode, see [Usage Examples](docs/usage.md). For dashboard-specific behavior and tuning, see [Web Dashboard](docs/web-dashboard.md).

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

- Capture typically requires **root privileges**. The web dashboard binds to `127.0.0.1` by default. Binding to `0.0.0.0` exposes live traffic data with no authentication.
- IPv6 extension headers are not parsed (payload starts after the fixed 40-byte header).
- IPv4 non-initial fragments are skipped for flow tracking.
- Timestamps are formatted as `HH:MM:SS.microseconds` from UNIX-epoch UTC capture times.

## License

MIT License. See [LICENSE](LICENSE).
