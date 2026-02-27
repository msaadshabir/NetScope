# NetScope

High-performance packet capture and protocol analysis tool built in Rust.

## Features

- **Live packet capture** via libpcap with BPF filter support
- **Zero-copy protocol parsing** for Ethernet (+ 802.1Q VLAN), IPv4, IPv6, TCP, UDP, ICMP
- **Sharded pipeline** -- multi-core packet processing with lock-free per-shard flow tracking and anomaly detection
- **Flow tracking** with bidirectional byte/packet counters, TCP state machine, and automatic expiration
- **TCP analysis** -- RTT estimation (EWMA), retransmission detection, out-of-order segment detection
- **Anomaly detection** -- SYN flood and port scan alerts with configurable thresholds and cooldowns
- **Web dashboard** -- real-time browser UI with throughput charts, top flows table, packet inspector, and alerts via WebSocket
- **Export** -- flow table to JSON or CSV, alerts to JSON lines, raw packets to pcap
- **TOML configuration** with full CLI override support (including `--no-*` flags for booleans)
- **Periodic throughput stats** with top-N flows by bandwidth delta
- **Fast hashing** -- ahash-backed flow tables and anomaly maps for reduced per-packet overhead
- **Optimized top-N** -- partial selection (`select_nth_unstable_by`) instead of full table sorts

## Build

Requirements:

- Rust 1.85+ (edition 2024)
- libpcap

Install libpcap:

- **macOS**: ships with the OS (Xcode Command Line Tools recommended)
- **Debian/Ubuntu**: `sudo apt-get install libpcap-dev`
- **Fedora**: `sudo dnf install libpcap-devel`

```bash
cargo build --release
```

## Usage

Live capture usually requires elevated privileges. Use `sudo` if you see permission errors.

List available interfaces:

```bash
sudo cargo run -- --list-interfaces
```

Capture on the default interface (Ctrl-C to stop):

```bash
sudo cargo run
```

Capture 20 packets on a specific interface:

```bash
sudo cargo run -- -i en0 -c 20
```

Capture only HTTP traffic and show hex dumps:

```bash
sudo cargo run -- -f "tcp port 80" --hex-dump
```

Throughput stats with top flows (suppress per-packet output):

```bash
sudo cargo run -- --quiet --stats --top-flows 5
```

Write packets to pcap and export flows on exit:

```bash
sudo cargo run -- --write-pcap capture.pcap --export-json flows.json --export-csv flows.csv
```

Enable anomaly detection and write alerts to a file:

```bash
sudo cargo run -- --anomalies --alerts-jsonl alerts.jsonl
```

Start the web dashboard:

```bash
sudo cargo run -- --web
```

Then open http://127.0.0.1:8080 in a browser. Use `--web-port` to change the port or `--web-bind` to change the bind address.

Combine with other options:

```bash
sudo cargo run -- --web --web-port 9090 --quiet --anomalies
```

Enable the sharded pipeline for multi-core processing (auto-detect worker count):

```bash
sudo cargo run -- --pipeline --quiet --stats --top-flows 5
```

Specify the number of pipeline worker threads:

```bash
sudo cargo run -- --pipeline --workers 4 --quiet --stats
```

Pipeline mode with the web dashboard:

```bash
sudo cargo run -- --pipeline --web --quiet --anomalies
```

Use a configuration file with CLI overrides:

```bash
sudo cargo run -- --config netscope.example.toml --no-promiscuous -c 100
```

Increase verbosity (`-v` info, `-vv` debug with detailed output, `-vvv` trace):

```bash
sudo cargo run -- -vv
```

## CLI Reference

```
Usage: netscope [OPTIONS]

Options:
      --config <PATH>                Path to a TOML configuration file
  -i, --interface <INTERFACE>        Network interface (e.g., "en0", "eth0")
  -f, --filter <FILTER>              BPF filter expression (e.g., "tcp port 80")
  -c, --count <COUNT>                Max packets to capture (0 = unlimited)
  -p, --promiscuous                  Capture in promiscuous mode
      --no-promiscuous               Disable promiscuous mode
  -s, --snaplen <SNAPLEN>            Snapshot length (max bytes per packet)
  -t, --timeout-ms <TIMEOUT_MS>      Read timeout in milliseconds
      --hex-dump                     Show hex dump of packet payload
      --no-hex-dump                  Disable hex dump output
      --quiet                        Suppress per-packet output
      --no-quiet                     Enable per-packet output
  -v, --verbose...                   Verbosity level (-v, -vv, -vvv)
  -l, --list-interfaces              List available network interfaces and exit
      --write-pcap <PATH>            Write captured packets to a pcap file
      --export-json <PATH>           Export flow table to JSON on exit
      --export-csv <PATH>            Export flow table to CSV on exit
      --stats                        Enable periodic throughput stats
      --no-stats                     Disable periodic throughput stats
      --stats-interval-ms <MS>       Stats reporting interval in milliseconds
      --top-flows <N>                Number of top flows per stats tick
      --flow-timeout-s <SECS>        Flow inactivity timeout (0 = disable)
      --max-flows <N>                Max tracked flows (0 = unlimited)
      --anomalies                    Enable anomaly detection alerts
      --no-anomalies                 Disable anomaly detection alerts
      --alerts-jsonl <PATH>          Write anomaly alerts as JSON lines
      --web                          Enable the web dashboard
      --no-web                       Disable the web dashboard
      --web-bind <ADDR>              Web dashboard bind address (default: 127.0.0.1)
      --web-port <PORT>              Web dashboard port (default: 8080)
      --pipeline                     Enable the sharded pipeline for multi-core processing
      --workers <N>                  Number of pipeline worker threads (0 = auto, default: 0)
  -h, --help                         Print help
  -V, --version                      Print version
```

## Configuration

NetScope supports TOML configuration files. CLI flags override config values when explicitly provided.

See `netscope.example.toml` for a complete example.

### Config Reference

| Section | Key | Type | Default | Description |
|---------|-----|------|---------|-------------|
| `[capture]` | `interface` | string | (auto) | Network interface name |
| | `promiscuous` | bool | `true` | Promiscuous mode |
| | `snaplen` | int | `65535` | Max bytes captured per packet |
| | `timeout_ms` | int | `100` | Capture read timeout (ms) |
| | `filter` | string | (none) | BPF filter expression |
| `[run]` | `count` | int | `0` | Packet limit (0 = unlimited) |
| `[output]` | `write_pcap` | path | (none) | Pcap output file |
| | `export_json` | path | (none) | Flow export JSON file |
| | `export_csv` | path | (none) | Flow export CSV file |
| | `hex_dump` | bool | `false` | Show hex dump |
| | `quiet` | bool | `false` | Suppress per-packet output |
| `[flow]` | `timeout_secs` | float | `60.0` | Flow inactivity timeout |
| | `max_flows` | int | `100000` | Max tracked flows (0 = unlimited) |
| `[stats]` | `enabled` | bool | `false` | Enable periodic stats |
| | `interval_ms` | int | `1000` | Stats interval (ms) |
| | `top_flows` | int | `0` | Top-N flows per tick |
| `[analysis]` | `rtt` | bool | `true` | Compute TCP RTT |
| | `retrans` | bool | `true` | Detect retransmissions |
| | `out_of_order` | bool | `true` | Detect out-of-order segments |
| | `alerts_jsonl` | path | (none) | Alert output file |
| `[analysis.anomalies]` | `enabled` | bool | `false` | Enable anomaly detection |
| `[analysis.anomalies.syn_flood]` | `enabled` | bool | `true` | Enable SYN flood detection |
| | `window_secs` | float | `5.0` | Detection window |
| | `syn_threshold` | int | `200` | SYN count threshold |
| | `unique_src_threshold` | int | `50` | Unique source IP threshold |
| | `cooldown_secs` | float | `10.0` | Alert cooldown period |
| `[analysis.anomalies.port_scan]` | `enabled` | bool | `true` | Enable port scan detection |
| | `window_secs` | float | `10.0` | Detection window |
| | `unique_ports_threshold` | int | `25` | Unique ports threshold |
| | `unique_hosts_threshold` | int | `10` | Unique hosts threshold |
| | `cooldown_secs` | float | `30.0` | Alert cooldown period |
| `[web]` | `enabled` | bool | `false` | Enable web dashboard |
| | `bind` | string | `"127.0.0.1"` | HTTP server bind address |
| | `port` | int | `8080` | HTTP server port |
| | `tick_ms` | int | `1000` | Stats push interval (ms) |
| | `top_n` | int | `10` | Top-N flows per tick |
| | `packet_buffer` | int | `2000` | Packets kept for detail inspection |
| | `sample_rate` | int | `1` | Sample every Nth packet (0 = disable feed) |
| | `payload_bytes` | int | `256` | Max payload bytes stored per packet |
| `[pipeline]` | `enabled` | bool | `false` | Enable sharded pipeline |
| | `workers` | int | `0` | Worker threads (0 = auto: half of CPUs, clamped 1..8) |
| | `channel_capacity` | int | `4096` | Bounded channel size per shard |

Empty strings in path fields (e.g., `write_pcap = ""`) are treated as disabled.

## Sharded Pipeline

When enabled (`--pipeline`), NetScope splits packet processing across multiple worker threads for higher throughput on multi-core machines. The capture thread does minimal work -- it reads packets from libpcap, extracts a fast 5-tuple hash from raw bytes, and dispatches each packet to the appropriate shard via bounded crossbeam channels. Each worker shard owns its own `FlowTracker` and `AnomalyDetector`, so the hot path is completely lock-free.

### Architecture

```
pcap capture (main thread)
  |
  |-- extract 5-tuple hash -> shard = hash % N
  |
  +--[bounded channel]---> Worker 0  (parse, flow, anomaly)
  +--[bounded channel]---> Worker 1
  ...
  +--[bounded channel]---> Worker N-1
                              |
Workers --[unbounded channel]---> Aggregator thread
                                    |
                                    +---> CLI stats (merged ticks)
                                    +---> Web dashboard events
```

All packets for the same 5-tuple always land on the same shard, guaranteeing correctness for flow tracking and TCP state. The aggregator merges per-shard tick data into global statistics and forwards events to the CLI and web dashboard.

### Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `workers` | `0` (auto) | Number of shards. Auto mode uses half of CPU count, clamped to 1..8 |
| `channel_capacity` | `4096` | Per-shard bounded channel size. When full, packets are dropped and counted as dispatch drops |

When the pipeline is active, kernel pcap stats (received/dropped/if_dropped) and dispatch drop counts are printed at capture exit.

### Performance

Portable optimizations applied to the hot path:

- **ahash** (`AHashMap`/`AHashSet`) replaces `std::HashMap` in the flow table and anomaly detector maps, reducing per-lookup hashing cost.
- **Partial top-N selection** uses `select_nth_unstable_by` to partition the top-N elements and then sorts only that slice, avoiding a full O(n log n) sort of the entire flow table each tick.
- **Minimal shard routing** extracts the 5-tuple from raw packet bytes at fixed offsets (no full parse) to keep the capture thread lean.

Criterion benchmark baselines (Apple M-series, `cargo bench`):

| Benchmark | Latency | Throughput |
|-----------|---------|------------|
| `parse_packet` (54B TCP SYN) | ~3.5 ns | ~289M pkt/s |
| `parse_packet` (1454B TCP data) | ~3.5 ns | ~283M pkt/s |
| `flow_observe` (existing flow) | ~13.5 ns | ~74M pkt/s |
| `flow_observe` (new flow) | ~89 ns | ~11M pkt/s |
| `shard_routing` (4 shards) | ~3.9 ns | ~257M pkt/s |

Run benchmarks with:

```bash
cargo bench
```

## Web Dashboard

The web dashboard provides a real-time browser interface for monitoring captured traffic. Enable it with `--web` or `[web] enabled = true` in the config file.

### Features

- **Stats cards** -- live throughput (Mbps), packet rate (pps), active flow count, and alert count
- **Time-series chart** -- dual-axis throughput and packet rate history (Chart.js, last 120 ticks)
- **Top flows table** -- ranked by throughput delta per tick, showing protocol, endpoints, rate, total bytes, and TCP state
- **Packet list** -- sampled packets with click-to-inspect
- **Packet inspector** -- full protocol tree (Ethernet, IP, TCP/UDP/ICMP fields) and hex dump, fetched on demand
- **Alerts tab** -- real-time anomaly alerts (SYN flood, port scan)
- **Auto-reconnect** -- WebSocket reconnects automatically after disconnection

### Architecture

In inline mode (default), the capture loop on the main thread pushes events directly through an `mpsc` channel to the web server. In pipeline mode, the aggregator thread merges shard events and forwards them to the same channel. Either way, the web server runs in a dedicated thread with its own tokio runtime and broadcasts to all connected WebSocket clients.

```
Inline mode:                       Pipeline mode:

Capture thread (main)              Capture thread -> Worker shards
  |                                                    |
  |-- mpsc channel -->  Web server   Aggregator --mpsc channel-->  Web server
  |   (Tick, Packet,      |             |                             |
  |    Alert, ...)       broadcast     merges ticks                 broadcast
  |                        |                                          |
  |                      WS clients                                WS clients
```

The frontend is embedded into the binary via `rust-embed`, so `--web` works with no external files or build steps.

### Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `tick_ms` | `1000` | How often stats are pushed to clients |
| `top_n` | `10` | Number of top flows included per tick |
| `packet_buffer` | `2000` | Ring buffer size for packet detail lookups |
| `sample_rate` | `1` | Send every Nth packet to the UI (0 = disable packet feed) |
| `payload_bytes` | `256` | Max raw bytes stored per packet for hex dump |

At high capture rates, the event channel (capacity 4096) applies backpressure -- dropped events are logged at TRACE level. Increase `sample_rate` to reduce load.

## Supported Protocols

| Layer | Protocols |
|-------|-----------|
| Link | Ethernet II, 802.1Q VLAN |
| Network | IPv4 (with checksum verification), IPv6 |
| Transport | TCP, UDP, ICMP |

IPv6 extension headers are not parsed (payload starts after the fixed 40-byte header). IPv4 non-initial fragments are skipped for flow tracking.

## Flow Tracking

Flows are identified by a canonical bidirectional key `(protocol, endpoint_a, endpoint_b)` where endpoints are ordered deterministically. Each flow tracks:

- Bidirectional packet and byte counters
- TCP connection state (SynSent, SynAck, Established, FinWait, Closed, Reset)
- Client direction (which side initiated)
- RTT estimates (last, minimum, EWMA with alpha=0.125)
- Retransmission and out-of-order counters
- First/last seen timestamps

Flows are expired after `timeout_secs` of inactivity. When the flow table exceeds `max_flows`, the oldest flows are evicted.

### Export Formats

**JSON**: Pretty-printed array of flow snapshots with all fields including derived metrics (duration, total bytes/packets, average bps).

**CSV**: One row per flow with columns:
```
protocol, endpoint_a_ip, endpoint_a_port, endpoint_b_ip, endpoint_b_port,
first_seen, last_seen, duration_secs, packets_a_to_b, packets_b_to_a,
bytes_a_to_b, bytes_b_to_a, packets_total, bytes_total, avg_bps,
tcp_state, client, retransmissions, out_of_order,
rtt_last_ms, rtt_min_ms, rtt_ewma_ms, rtt_samples
```

## Anomaly Detection

When enabled (`--anomalies`), NetScope monitors traffic for two classes of anomalies:

**SYN Flood**: Alerts when a destination `(ip, port)` receives more than `syn_threshold` SYN packets from at least `unique_src_threshold` unique source IPs within `window_secs`.

**Port Scan**: Alerts when a single source IP contacts more than `unique_ports_threshold` unique destination ports or `unique_hosts_threshold` unique destination hosts within `window_secs`. Only SYN-only TCP packets and UDP packets are considered.

Alerts are printed to stdout and optionally written as JSON lines to a file (`--alerts-jsonl`). Each alert line contains `ts`, `kind`, and `description` fields. A cooldown period prevents repeated alerts for the same source/target.

## Notes

- VLAN tags (802.1Q) are decoded and surfaced in packet output.
- Hex dumps are limited to the first 256 bytes of each packet.
- Timestamps are formatted as `HH:MM:SS.microseconds` (UTC).
- The web dashboard binds to `127.0.0.1` by default for security (capture typically runs as root).

## License

MIT License. See `LICENSE`.
