# Changelog

All notable changes to NetScope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Criterion benchmark `handshake_sequence` to measure the combined hot path for a TCP 3-way handshake (SYN -> SYN-ACK -> ACK).

### Changed

- Flow tracking now pre-sizes the flow table based on `flow.max_flows` to reduce hash map resizes during capture.
- TCP RTT analysis avoids per-call heap allocation by streaming RTT samples from ACK handling without buffering.
- Flow tracking now switches to a compact scale-mode store with split IPv4/IPv6 tables when RTT, retransmission, and out-of-order analysis are all disabled.
- Pipeline heavy-hitter candidate tracking now uses the compact internal flow-key path in scale mode.
- Pipeline-mode web updates now use merged websocket `frame` messages with latest-frame replay on reconnect / lag recovery.
- Pipeline-mode top-flow reporting now decouples CLI `stats.top_flows` from dashboard `web.top_n`.
- Updated documentation for performance benchmarks and flow table sizing behavior.
- Refreshed the docs to reduce overlap between setup, usage, CLI, configuration, and feature guides.

### Removed

- `CONTRIBUTING.md`
- `docs/index.md` as it was fully redundant with the main `README.md` documentation table.
- `docs/perf-validation.md` in favor of keeping evergreen perf guidance in `docs/performance.md` and helper scripts in `scripts/perf/`.

## [0.1.0] - 2026-02-27

### Added

- Live packet capture via libpcap with BPF filter support.
- Zero-copy protocol parsing for Ethernet II, 802.1Q VLAN, IPv4, IPv6, TCP, UDP, ICMP.
- Bidirectional flow tracking with TCP state machine (SYN, SYN-ACK, Established, FIN, RST).
- TCP analysis: RTT estimation (EWMA, alpha=0.125), retransmission detection, out-of-order segment detection.
- Sharded pipeline for multi-core packet processing with lock-free per-shard flow tracking.
- Shard routing via fast 5-tuple extraction from raw bytes (no full parse on capture thread).
- Anomaly detection: SYN flood and port scan alerts with sliding windows and cooldowns.
- Web dashboard with real-time throughput charts, top flows table, packet inspector, and alerts tab.
- WebSocket protocol for live stats, sampled packets, packet detail requests, and alerts.
- Frontend embedded in the binary via `rust-embed` (no external files needed).
- TOML configuration file support with full CLI override (including `--no-*` flag pairs).
- Flow export to JSON and CSV on capture exit.
- Alert export to JSONL file.
- Pcap file output (`--write-pcap`).
- Periodic throughput stats with top-N flows by bandwidth delta.
- Criterion benchmarks for parsing, flow tracking, and shard routing.
- Comprehensive documentation in `docs/`.
