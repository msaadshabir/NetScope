# CLI Reference

```
Usage: netscope [OPTIONS]
```

## Capture Options

| Flag | Short | Type | Default | Description |
|---|---|---|---|---|
| `--interface <IFACE>` | `-i` | string | (auto) | Network interface to capture on (e.g., `en0`, `eth0`). If omitted, the system default is used. |
| `--filter <EXPR>` | `-f` | string | (none) | BPF filter expression (e.g., `"tcp port 80"`, `"host 192.168.1.1"`). |
| `--count <N>` | `-c` | int | 0 | Maximum packets to capture. 0 = unlimited (run until Ctrl-C). |
| `--promiscuous` | `-p` | flag | on | Capture in promiscuous mode. |
| `--no-promiscuous` | | flag | | Disable promiscuous mode. |
| `--snaplen <N>` | `-s` | int | 65535 | Maximum bytes captured per packet. |
| `--timeout-ms <MS>` | `-t` | int | 100 | Read timeout in milliseconds for the pcap handle. |
| `--list-interfaces` | `-l` | flag | | List available network interfaces and exit. |

## Output Options

| Flag | Short | Type | Default | Description |
|---|---|---|---|---|
| `--hex-dump` | | flag | off | Show hex dump of each packet. |
| `--no-hex-dump` | | flag | | Disable hex dump output. |
| `--quiet` | | flag | off | Suppress per-packet terminal output. Useful for stats-only or web-only runs. |
| `--no-quiet` | | flag | | Re-enable per-packet output (overrides config file). |
| `--verbose` | `-v` | count | 0 | Increase verbosity. `-v` = INFO, `-vv` = DEBUG, `-vvv` = TRACE. |
| `--write-pcap <PATH>` | | path | (none) | Write captured packets to a pcap file. |
| `--export-json <PATH>` | | path | (none) | Export the flow table to JSON on exit. |
| `--export-csv <PATH>` | | path | (none) | Export the flow table to CSV on exit. |

## Stats Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--stats` | flag | off | Enable periodic throughput stats printed to stdout. |
| `--no-stats` | flag | | Disable periodic stats. |
| `--stats-interval-ms <MS>` | int | 1000 | How often to print stats (milliseconds). |
| `--top-flows <N>` | int | 0 | Number of top flows (by bandwidth delta) to show each stats tick. |

## Flow Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--flow-timeout-s <SECS>` | float | 60.0 | Flow inactivity timeout in seconds. Flows with no traffic for this long are expired. 0 = never expire. |
| `--max-flows <N>` | int | 100000 | Maximum number of tracked flows. When exceeded, the oldest flows are evicted. 0 = unlimited. |

## Anomaly Detection

| Flag | Type | Default | Description |
|---|---|---|---|
| `--anomalies` | flag | off | Enable anomaly detection (SYN flood, port scan). |
| `--no-anomalies` | flag | | Disable anomaly detection. |
| `--alerts-jsonl <PATH>` | path | (none) | Write anomaly alerts as JSON lines to a file. |

See [Anomaly Detection](anomaly-detection.md) for threshold configuration (requires a config file).

## Web Dashboard

| Flag | Type | Default | Description |
|---|---|---|---|
| `--web` | flag | off | Enable the web dashboard. |
| `--no-web` | flag | | Disable the web dashboard. |
| `--web-bind <ADDR>` | string | `127.0.0.1` | HTTP server bind address. |
| `--web-port <PORT>` | int | 8080 | HTTP server port. |

See [Web Dashboard](web-dashboard.md) for full details.

## Pipeline Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--pipeline` | flag | off | Enable the sharded pipeline for multi-core packet processing. |
| `--workers <N>` | int | 0 | Number of pipeline worker threads. 0 = auto-detect (half of CPU count, clamped to 1..8). Setting `--workers` to a non-zero value implicitly enables `--pipeline`. |

See [Sharded Pipeline](pipeline.md) for architecture and tuning details.

## General

| Flag | Short | Description |
|---|---|---|
| `--config <PATH>` | | Load a TOML configuration file. CLI flags override config values. |
| `--help` | `-h` | Print help text. |
| `--version` | `-V` | Print version. |

## Boolean Flag Pairs

Several options come in `--flag` / `--no-flag` pairs. This lets you override config file values in either direction from the CLI:

```bash
# Config file has quiet = true, but you want per-packet output this time:
sudo netscope --config my.toml --no-quiet

# Config file has promiscuous = true, but you want to disable it:
sudo netscope --config my.toml --no-promiscuous
```

Each pair is mutually exclusive -- specifying both `--flag` and `--no-flag` is an error.
