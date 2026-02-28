# Configuration

NetScope supports TOML configuration files for persistent settings. Load a config file with `--config`:

```bash
sudo netscope --config netscope.toml
```

A complete example is provided in [`netscope.example.toml`](../netscope.example.toml) at the repository root.

## Precedence Rules

1. **CLI flags** always override config file values when explicitly provided.
2. **Config file values** override compiled defaults.
3. **Compiled defaults** apply when neither CLI nor config file specifies a value.

For boolean options, `--flag` and `--no-flag` pairs let you override in either direction:

```bash
# Config says quiet = true, CLI overrides it back to false:
sudo netscope --config my.toml --no-quiet
```

## Path Fields

Path fields (`write_pcap`, `export_json`, `export_csv`, `alerts_jsonl`) accept file paths. Setting a path to an empty string (`""`) is treated as disabled -- equivalent to omitting the key entirely.

```toml
[output]
write_pcap = ""     # disabled
export_json = ""    # disabled
```

## Config Reference

### `[capture]`

| Key | Type | Default | Description |
|---|---|---|---|
| `interface` | string | (auto) | Network interface name (e.g., `"en0"`). Omit for system default. |
| `promiscuous` | bool | `true` | Capture in promiscuous mode. |
| `snaplen` | int | `65535` | Maximum bytes captured per packet. |
| `timeout_ms` | int | `100` | Capture read timeout in milliseconds. |
| `filter` | string | (none) | BPF filter expression. |

### `[run]`

| Key | Type | Default | Description |
|---|---|---|---|
| `count` | int | `0` | Maximum packets to capture. 0 = unlimited. |

### `[output]`

| Key | Type | Default | Description |
|---|---|---|---|
| `write_pcap` | path | (none) | Write captured packets to a pcap file. |
| `export_json` | path | (none) | Export flow table to JSON on exit. |
| `export_csv` | path | (none) | Export flow table to CSV on exit. |
| `hex_dump` | bool | `false` | Show hex dump of each packet. |
| `quiet` | bool | `false` | Suppress per-packet terminal output. |

### `[flow]`

| Key | Type | Default | Description |
|---|---|---|---|
| `timeout_secs` | float | `60.0` | Flow inactivity timeout in seconds. 0 = never expire. |
| `max_flows` | int | `100000` | Maximum tracked flows. When exceeded, oldest flows are evicted. 0 = unlimited. |

### `[stats]`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable periodic throughput stats on stdout. |
| `interval_ms` | int | `1000` | Stats reporting interval in milliseconds. |
| `top_flows` | int | `0` | Number of top flows to show per stats tick. |

### `[analysis]`

| Key | Type | Default | Description |
|---|---|---|---|
| `rtt` | bool | `true` | Compute TCP RTT estimates. |
| `retrans` | bool | `true` | Detect TCP retransmissions. |
| `out_of_order` | bool | `true` | Detect out-of-order TCP segments. |
| `alerts_jsonl` | path | (none) | Write anomaly alerts as JSON lines to this file. |

### `[analysis.anomalies]`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable anomaly detection. |

### `[analysis.anomalies.syn_flood]`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enable SYN flood detection. |
| `window_secs` | float | `5.0` | Sliding window duration for counting SYNs. |
| `syn_threshold` | int | `200` | SYN count that triggers an alert. |
| `unique_src_threshold` | int | `50` | Minimum unique source IPs required to trigger. |
| `cooldown_secs` | float | `10.0` | Minimum seconds between alerts for the same target. |

### `[analysis.anomalies.port_scan]`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enable port scan detection. |
| `window_secs` | float | `10.0` | Sliding window duration. |
| `unique_ports_threshold` | int | `25` | Unique destination ports that trigger an alert. |
| `unique_hosts_threshold` | int | `10` | Unique destination hosts that trigger an alert. |
| `cooldown_secs` | float | `30.0` | Minimum seconds between alerts for the same source. |

### `[web]`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable the web dashboard. |
| `bind` | string | `"127.0.0.1"` | HTTP server bind address. |
| `port` | int | `8080` | HTTP server port. |
| `tick_ms` | int | `1000` | How often stats are pushed to WebSocket clients (ms). |
| `top_n` | int | `10` | Number of top flows included in each stats tick. |
| `packet_buffer` | int | `2000` | Number of packets kept in the ring buffer for detail inspection. |
| `sample_rate` | int | `1` | Send every Nth packet to the UI. Set to 0 to disable the live packet feed entirely. |
| `payload_bytes` | int | `256` | Maximum raw bytes stored per packet for hex dump display. |

### `[pipeline]`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable the sharded pipeline for multi-core processing. |
| `workers` | int | `0` | Number of worker threads. 0 = auto-detect (half of CPU count, clamped 1..8). |
| `channel_capacity` | int | `4096` | Bounded channel size per worker shard. When full, packets are dropped (counted as dispatch drops). |

## Minimal Config Example

```toml
[capture]
interface = "en0"
filter = "tcp"

[output]
quiet = true

[stats]
enabled = true
top_flows = 5

[web]
enabled = true
```

## Full Example

See [`netscope.example.toml`](../netscope.example.toml) for a complete config file with all keys and defaults.
