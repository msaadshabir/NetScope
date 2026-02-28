# Changelog

All notable changes to NetScope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
