# NetScope

High-performance packet capture and protocol analysis tool built in Rust.

## Features

- **Live packet capture** via libpcap with BPF filter support
- **Zero-copy protocol parsing** for Ethernet (+ 802.1Q VLAN), IPv4, IPv6, TCP, UDP, ICMP
- **Flow tracking** with bidirectional byte/packet counters, TCP state machine, and automatic expiration
- **TCP analysis** -- RTT estimation (EWMA), retransmission detection, out-of-order segment detection
- **Anomaly detection** -- SYN flood and port scan alerts with configurable thresholds and cooldowns
- **Export** -- flow table to JSON or CSV, alerts to JSON lines, raw packets to pcap
- **TOML configuration** with full CLI override support (including `--no-*` flags for booleans)
- **Periodic throughput stats** with top-N flows by bandwidth delta

## Build

Requirements:

- Rust 1.70+
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

Empty strings in path fields (e.g., `write_pcap = ""`) are treated as disabled.

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

## License

MIT License. See `LICENSE`.
