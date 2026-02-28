# Troubleshooting

## Permission Errors

**Symptom:** `error: pcap error: ...permission denied` or `no interfaces found`.

**Cause:** Packet capture requires elevated privileges.

**Fix:**

```bash
# Run with sudo
sudo netscope

# Or grant capabilities on Linux (persistent)
sudo setcap cap_net_raw=eip target/release/netscope
```

## No Interfaces Listed

**Symptom:** `--list-interfaces` shows no interfaces.

**Fix:** Run with `sudo`. Without root access, libpcap cannot enumerate interfaces on most systems.

## No Packets Captured

Possible causes:

1. **Wrong interface** -- Use `--list-interfaces` to find the correct name, then `-i <name>`.
2. **BPF filter too restrictive** -- Remove the filter temporarily to confirm traffic exists.
3. **No traffic** -- Run `sudo tcpdump -i <interface> -c 10` to verify the interface has traffic.
4. **Firewall** -- Some firewalls block promiscuous mode. Try `--no-promiscuous`.

## High Kernel Drop Rate

**Symptom:** Summary shows high `Kernel dropped` count or drop rate.

**Causes and fixes:**

- **Processing too slow** -- Enable pipeline mode (`--pipeline`).
- **Too much traffic** -- Apply a BPF filter (`-f "tcp port 443"`).
- **Per-packet output** -- Use `--quiet` to skip terminal printing.
- **Hex dump enabled** -- Disable `--hex-dump` in high-traffic captures.

## High Dispatch Drops (Pipeline Mode)

**Symptom:** Summary shows high `Dispatch drops` count.

**Causes and fixes:**

- **Channel too small** -- Increase `channel_capacity` in config (default: 4096).
- **Not enough workers** -- Increase `--workers`.
- **Uneven shard distribution** -- Some 5-tuples may hash to the same shard. This is expected with a small number of active flows. Use a BPF filter to reduce volume.

## Web Dashboard Not Reachable

**Symptom:** Browser shows "connection refused" at `http://127.0.0.1:8080`.

**Fixes:**

1. Verify `--web` flag is present.
2. Check the terminal for `Web dashboard: http://...` confirmation.
3. Check for port conflicts: `lsof -i :8080`.
4. If accessing from another machine, use `--web-bind 0.0.0.0`.

## Web Dashboard Shows No Data

**Symptom:** Dashboard connects but shows `--` for all metrics and no packets.

**Causes:**

1. **No traffic** -- Verify packets are being captured (check terminal output without `--quiet`).
2. **`sample_rate = 0`** -- This disables the packet feed entirely. Set to 1 or higher.
3. **Filter too restrictive** -- Remove the BPF filter temporarily.
4. **Pipeline mode tick delay** -- The aggregator waits for all shards to report. If one shard receives no traffic, ticks are still emitted but may be delayed.

## Web Dashboard Laggy or Dropping Data

**Symptom:** Charts stutter, packet list has gaps, or TRACE logs show `web event channel full`.

**Fixes:**

- Increase `sample_rate` (e.g., 10 or 100) to reduce packet feed volume.
- Reduce `top_n` to send fewer flows per tick.
- Increase `tick_ms` to reduce update frequency.
- Reduce `payload_bytes` to store less data per packet.

## Anomaly Alerts Not Firing

**Causes:**

1. **Anomalies not enabled** -- Ensure `--anomalies` flag is present or `analysis.anomalies.enabled = true`.
2. **Thresholds too high** -- Lower `syn_threshold` or `unique_ports_threshold` for testing.
3. **Cooldown active** -- After an alert fires, subsequent alerts for the same key are suppressed for `cooldown_secs`.
4. **Pipeline mode** -- Thresholds are per-shard. Traffic distributed across shards may not exceed thresholds on any individual shard. See [Pipeline Caveats](pipeline.md#known-caveats).

## Flow Export is Empty

**Causes:**

1. **No flows tracked** -- Only TCP and UDP traffic creates flow entries. ICMP does not.
2. **All flows expired** -- If capture runs long enough with `flow.timeout_secs` set low, flows may expire before export.
3. **Fragmented traffic** -- IPv4 non-initial fragments are skipped for flow tracking.

## Timestamps Show Wrong Time

NetScope formats timestamps as `HH:MM:SS.microseconds` derived from pcap timestamps (seconds since Unix epoch). These are UTC-based. If times look wrong, verify your system clock and consider that pcap timestamps come from the kernel, not application code.

## Build Errors

### `pcap.h not found`

Install libpcap development headers:

```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# Fedora
sudo dnf install libpcap-devel

# macOS
xcode-select --install
```

### Rust version too old

NetScope requires Rust 1.85+ (edition 2024). Update with:

```bash
rustup update stable
```
