# NetScope Documentation

NetScope is a high-performance packet capture and protocol analysis tool built in Rust. These docs cover everything from first-run setup to internal architecture.

## User Guide

- **[Getting Started](getting-started.md)** -- Prerequisites, building, permissions, and your first capture.
- **[Usage Examples](usage.md)** -- Common recipes for filtering, stats, exports, web dashboard, and pipeline mode.
- **[Troubleshooting](troubleshooting.md)** -- Solutions for permission errors, missing data, high drop rates, and other common issues.

## Reference

- **[CLI Reference](cli-reference.md)** -- Complete list of command-line flags and options.
- **[Configuration](configuration.md)** -- TOML config file schema, precedence rules, and annotated example.
- **[Exports](exports.md)** -- Output formats for flow data (JSON, CSV) and alerts (JSONL), with sample outputs.

## Features

- **[Web Dashboard](web-dashboard.md)** -- Real-time browser UI: setup, endpoints, WebSocket protocol, and tuning.
- **[Flow Tracking](flow-tracking.md)** -- Bidirectional flow keying, TCP state machine, RTT estimation, retransmission detection.
- **[Anomaly Detection](anomaly-detection.md)** -- SYN flood and port scan detection: how it works, configuration, alert schema.

## Architecture

- **[Sharded Pipeline](pipeline.md)** -- Multi-core architecture, shard routing, aggregator, tuning knobs, and known caveats.
- **[Performance](performance.md)** -- Benchmark results, how to run benchmarks, and tuning guidance.

## Contributing

- **[Development Guide](development.md)** -- Repository layout, running tests, adding protocols, logging behavior.
- **[Contributing](../CONTRIBUTING.md)** -- How to contribute to NetScope.
