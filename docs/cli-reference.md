# CLI Reference

```
Usage: netscope [OPTIONS]
```

This page lists CLI flags only. Some runtime tuning knobs are config-file only; see [Configuration](configuration.md) for the full schema.

Defaults below refer to the compiled defaults before any `--config` file is loaded. If a config file is present, explicitly provided CLI flags still take precedence.

For boolean flags, the "Default" column describes the resulting default behavior, not that the flag is implicitly passed on the command line.

## Capture Options

| Flag                  | Short | Type   | Default | Description                                                                                      |
| --------------------- | ----- | ------ | ------- | ------------------------------------------------------------------------------------------------ |
| `--interface <IFACE>` | `-i`  | string | (auto)  | Network interface to capture on (e.g., `en0`, `eth0`). If omitted, the system default is used.   |
| `--read-pcap <PATH>`  |       | path   | (none)  | Read packets from an offline pcap file. Conflicts with `--interface` and promiscuous mode flags. |
| `--filter <EXPR>`     | `-f`  | string | (none)  | BPF filter expression (e.g., `"tcp port 80"`, `"host 192.168.1.1"`).                             |
| `--count <N>`         | `-c`  | int    | 0       | Maximum packets to process. 0 = unlimited (live: Ctrl-C; offline: EOF).                          |
| `--promiscuous`       | `-p`  | flag   | on      | Capture in promiscuous mode.                                                                     |
| `--no-promiscuous`    |       | flag   |         | Disable promiscuous mode.                                                                        |
| `--snaplen <N>`       | `-s`  | int    | 65535   | Maximum bytes captured per packet.                                                               |
| `--timeout-ms <MS>`   | `-t`  | int    | 100     | Read timeout in milliseconds for the pcap handle.                                                |
| `--list-interfaces`   | `-l`  | flag   |         | List available network interfaces and exit.                                                      |

libpcap buffer sizing and immediate mode are configured through the `[capture]` section of the config file.

## Output Options

| Flag                           | Short | Type  | Default | Description                                                                                                         |
| ------------------------------ | ----- | ----- | ------- | ------------------------------------------------------------------------------------------------------------------- |
| `--hex-dump`                   |       | flag  | off     | Show detailed per-packet output with a hex-dump preview.                                                            |
| `--no-hex-dump`                |       | flag  |         | Disable hex dump output.                                                                                            |
| `--quiet`                      |       | flag  | off     | Suppress per-packet terminal output. Useful for stats-only or web-only runs.                                        |
| `--no-quiet`                   |       | flag  |         | Re-enable per-packet output (overrides config file).                                                                |
| `--verbose`                    | `-v`  | count | 0       | Increase verbosity. `-v` = INFO, `-vv` = DEBUG, `-vvv` = TRACE.                                                     |
| `--write-pcap <PATH>`          |       | path  | (none)  | Write captured packets to a pcap file.                                                                              |
| `--write-pcap-rotate-mb <MB>`  |       | int   | 0       | Rotate pcap output when a segment reaches this many MiB. Requires `--write-pcap` + `--write-pcap-max-files`.        |
| `--write-pcap-max-files <N>`   |       | int   | 0       | Keep only the newest `N` rotated pcap segments (delete oldest). Requires `--write-pcap` + `--write-pcap-rotate-mb`. |
| `--export-json <PATH>`         |       | path  | (none)  | Export the flow table to JSON on exit.                                                                              |
| `--export-csv <PATH>`          |       | path  | (none)  | Export the flow table to CSV on exit.                                                                               |
| `--expired-flows-jsonl <PATH>` |       | path  | (none)  | Write expired/evicted flow records as JSON lines.                                                                   |

When rotation is enabled, `--write-pcap` is treated as a base template and NetScope writes numbered segments like `capture.000001.pcap`, `capture.000002.pcap`, and so on (the unsuffixed `capture.pcap` file is not created).

Note: verbosity level `-vv` or higher also enables detailed per-packet output even if `--hex-dump` is not set.

## Stats Options

| Flag                       | Type | Default | Description                                                       |
| -------------------------- | ---- | ------- | ----------------------------------------------------------------- |
| `--stats`                  | flag | off     | Enable periodic throughput stats printed to stdout.               |
| `--no-stats`               | flag |         | Disable periodic stats.                                           |
| `--stats-interval-ms <MS>` | int  | 1000    | How often to print stats (milliseconds).                          |
| `--top-flows <N>`          | int  | 0       | Number of top flows (by bandwidth delta) to show each stats tick. |

## Flow Options

| Flag                      | Type  | Default | Description                                                                                            |
| ------------------------- | ----- | ------- | ------------------------------------------------------------------------------------------------------ |
| `--flow-timeout-s <SECS>` | float | 60.0    | Flow inactivity timeout in seconds. Flows with no traffic for this long are expired. 0 = never expire. |
| `--max-flows <N>`         | int   | 100000  | Maximum number of tracked flows. When exceeded, the oldest flows are evicted. 0 = unlimited.           |

## Anomaly Detection

| Flag                    | Type | Default | Description                                                               |
| ----------------------- | ---- | ------- | ------------------------------------------------------------------------- |
| `--anomalies`           | flag | off     | Enable anomaly detection (SYN flood, port scan).                          |
| `--no-anomalies`        | flag |         | Disable anomaly detection.                                                |
| `--alerts-jsonl <PATH>` | path | (none)  | Write anomaly alerts as JSON lines to a file (inline and pipeline modes). |

See [Anomaly Detection](anomaly-detection.md) for threshold configuration (requires a config file).

## Web Dashboard

| Flag                          | Type   | Default     | Description                                |
| ----------------------------- | ------ | ----------- | ------------------------------------------ |
| `--web`                       | flag   | off         | Enable the web dashboard.                  |
| `--no-web`                    | flag   |             | Disable the web dashboard.                 |
| `--web-bind <ADDR>`           | string | `127.0.0.1` | HTTP server bind address.                  |
| `--web-port <PORT>`           | int    | 8080        | HTTP server port.                          |
| `--web-tls`                   | flag   | off         | Enable HTTPS for the web dashboard.        |
| `--no-web-tls`                | flag   |             | Disable HTTPS for the web dashboard.       |
| `--web-tls-cert <PATH>`       | path   | (none)      | PEM certificate path for HTTPS serving.    |
| `--web-tls-key <PATH>`        | path   | (none)      | PEM private key path for HTTPS serving.    |
| `--web-auth`                  | flag   | off         | Enable HTTP Basic auth for the dashboard.  |
| `--no-web-auth`               | flag   |             | Disable HTTP Basic auth for the dashboard. |
| `--web-auth-user <USER>`      | string | (none)      | Username for HTTP Basic auth.              |
| `--web-auth-pass-file <PATH>` | path   | (none)      | File containing HTTP Basic auth password.  |

Tick cadence, packet sampling, packet-buffer sizing, payload truncation, and richer auth/TLS defaults can be configured through the `[web]`, `[web.tls]`, and `[web.auth]` sections.

See [Web Dashboard](web-dashboard.md) for full details.

## Pipeline Options

| Flag            | Type | Default | Description                                                                                                                                                       |
| --------------- | ---- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--pipeline`    | flag | off     | Enable the sharded pipeline for multi-core packet processing.                                                                                                     |
| `--workers <N>` | int  | 0       | Number of pipeline worker threads. 0 = auto-detect (half of CPU count, clamped to 1..8). Setting `--workers` to a non-zero value implicitly enables `--pipeline`. |

Queue sizing (`pipeline.channel_capacity`) is configured through the config file.

See [Sharded Pipeline](pipeline.md) for architecture and tuning details.

## General

| Flag                    | Short | Description                                                                                                   |
| ----------------------- | ----- | ------------------------------------------------------------------------------------------------------------- |
| `--config <PATH>`       |       | Load a TOML configuration file. CLI flags override config values.                                             |
| `--synthetic-flows <N>` |       | Insert `N` synthetic scale-mode flows and print memory stats, then exit. Useful for memory-budget validation. |
| `--help`                | `-h`  | Print help text.                                                                                              |
| `--version`             | `-V`  | Print version.                                                                                                |

## Boolean Flag Pairs

Several options come in `--flag` / `--no-flag` pairs. This lets you override config file values in either direction from the CLI:

```bash
# Config file has quiet = true, but you want per-packet output this time:
sudo netscope --config my.toml --no-quiet

# Config file has promiscuous = true, but you want to disable it:
sudo netscope --config my.toml --no-promiscuous
```

Each pair is mutually exclusive -- specifying both `--flag` and `--no-flag` is an error.
