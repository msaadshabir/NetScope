# Usage Examples

This page shows common NetScope workflows. For the full flag list, see [CLI Reference](cli-reference.md). For persistent configuration, see [Configuration](configuration.md).

All examples assume the binary is on your PATH as `netscope`. Substitute `sudo cargo run --release --` during development.

## Basic Capture

Capture on the default interface (Ctrl-C to stop):

```bash
sudo netscope
```

Capture on a specific interface, limited to 20 packets:

```bash
sudo netscope -i en0 -c 20
```

Capture only HTTP traffic with hex dumps:

```bash
sudo netscope -f "tcp port 80" --hex-dump
```

## Throughput Stats

Show periodic throughput stats with the top 5 flows by bandwidth, suppressing per-packet output:

```bash
sudo netscope --quiet --stats --top-flows 5
```

Change the stats interval to 2 seconds:

```bash
sudo netscope --quiet --stats --stats-interval-ms 2000 --top-flows 10
```

## Flow Exports

Write packets to pcap and export the flow table on exit:

```bash
sudo netscope --write-pcap capture.pcap --export-json flows.json --export-csv flows.csv
```

See [Exports](exports.md) for format details and sample outputs.

## Anomaly Detection

Enable anomaly detection and write alerts to a file:

```bash
sudo netscope --anomalies --alerts-jsonl alerts.jsonl
```

Alerts are also printed to stdout. See [Anomaly Detection](anomaly-detection.md) for threshold tuning.

## Web Dashboard

Start the web dashboard:

```bash
sudo netscope --web
```

Open <http://127.0.0.1:8080>. Customize the bind address and port:

```bash
sudo netscope --web --web-bind 0.0.0.0 --web-port 9090
```

Combine with other features:

```bash
sudo netscope --web --quiet --anomalies --stats --top-flows 5
```

See [Web Dashboard](web-dashboard.md) for full details.

## Pipeline Mode

Enable multi-core processing for high-throughput captures:

```bash
sudo netscope --pipeline --quiet --stats --top-flows 5
```

Specify the number of worker threads:

```bash
sudo netscope --pipeline --workers 4 --quiet --stats
```

Pipeline mode with the web dashboard:

```bash
sudo netscope --pipeline --web --quiet --anomalies
```

See [Sharded Pipeline](pipeline.md) for architecture details and tuning.

## Configuration File

Use a TOML config file with CLI overrides:

```bash
sudo netscope --config netscope.example.toml --no-promiscuous -c 100
```

CLI flags always override config file values when explicitly provided. See [Configuration](configuration.md) for the full schema.

## Verbosity

Control log output with `-v` flags:

| Flag | Level | What you see |
|---|---|---|
| (none) | WARN | Warnings and errors only |
| `-v` | INFO | Capture start/stop, interface info |
| `-vv` | DEBUG | Detailed packet output, config resolution |
| `-vvv` | TRACE | Per-packet trace logs, channel drops |

```bash
sudo netscope -vv
```
