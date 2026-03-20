# Changelog

All notable changes to NetScope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- `--list-interfaces` no longer depends on successfully loading a config file.
- Web packet detail lookups are resilient to out-of-order `PacketStored` events in pipeline mode.
- Pipeline aggregator waits for all shard shutdown snapshots before exiting (prevents incomplete exports on Ctrl-C).
- Pipeline aggregator stores final snapshots by shard id and replaces duplicate shutdown snapshots deterministically.
- Web ingest flushes buffered packet samples/alerts on shutdown to avoid dropping the final partial interval.
- Static file handler returns 404 for unknown `/api/*` paths instead of serving the SPA fallback.
- IPv6 shard routing walks common extension headers so flows consistently hash to the same shard.
- Pipeline capture now always shuts down worker/aggregator threads before returning, including pcap write/flush error paths.
- IPv6 non-initial fragments are no longer treated as transport-bearing packets for flow/anomaly tracking and shard port hashing.

### Changed
- Clarified configuration fields and streamlined CLI documentation examples.
- Restored technical limitations and prerequisites to project documentation.
- Refined tuning guides regarding web dashboard performance and memory optimization.
- Pcap output now flushes periodically and on shutdown; flush failures abort capture instead of silently continuing.
- IPv6 parsing now walks common extension headers to expose the effective transport protocol and payload offset.
- Packet detail store now uses fixed-size O(1) slot storage keyed by packet id modulo capacity, with stale-id rejection outside the active window.

## [0.2.0] - 2026-03-15

### Added
- Criterion benchmark `handshake_sequence` for TCP 3-way handshake hot path measurement
- Dashboard usability and performance improvements
- Synthetic memory benchmark and scale-mode regression fixes
- Phase 4 scale-mode storage with compact IPv4/IPv6 flow tables
- Frame sequencing, rAF rendering with performance overlay, and streaming heavy-hitters with exact deltas
- PCap configuration knobs, buffer pool, drop statistics, and aggregator deadline
- Pre-sized flow table allocation based on `flow.max_flows` to reduce hash map resizes
- RTT optimization removing per-call heap allocation by streaming samples from ACK handling
- Comprehensive documentation updates and .gitignore improvements

### Changed
- Documentation refresh clarifying web, config, and performance sections
- Updated CLI vs config-only documentation with examples
- Linked Getting Started and Troubleshooting documentation pages
- Removed perf-validation documentation (guidance moved to performance.md and scripts/perf/)
- Closed validation targets and cleaned up related documentation
- Added documentation for scale-mode flow storage and pipeline operation
- Batched per-tick events into merged frame messages; decoupled CLI and web top-flows
- Added documentation for streaming heavy-hitters and performance mode
- Added capture buffer/immediate options and reordered imports
- Honored web.tick_ms configuration; removed 500ms clamp, lowered receive timeout, added minimum validation
- Reformatted documentation tables; removed CONTRIBUTING directory and index.md
- Flow tracking switches to compact scale-mode store with split IPv4/IPv6 tables when advanced analysis disabled
- Pipeline heavy-hitter tracking now uses compact internal flow-key path in scale mode
- Pipeline-mode web updates use merged websocket `frame` messages with latest-frame replay
- Pipeline-mode top-flow reporting decouples CLI `stats.top_flows` from dashboard `web.top_n`
- Updated documentation for performance benchmarks and flow table sizing behavior
- Refreshed documentation to reduce overlap between setup, usage, CLI, configuration, and feature guides

### Removed
- `CONTRIBUTING.md`
- `docs/index.md` (fully redundant with main README.md documentation table)
- `docs/perf-validation.md` (guidance moved to performance.md and scripts/perf/)

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
