# Exports

NetScope can export data in several formats: raw packets to pcap, the flow table to JSON or CSV, and anomaly alerts to JSONL.

## Pcap Output

Write all captured packets to a pcap file:

```bash
sudo netscope --write-pcap capture.pcap
```

The file uses standard pcap format and can be opened with Wireshark, tcpdump, or any pcap-compatible tool. In pipeline mode, pcap writing happens on the capture thread before dispatch, so all packets are written regardless of dispatch drops.

## Flow Table Export

Export the flow table on exit:

```bash
sudo netscope --export-json flows.json --export-csv flows.csv
```

Both formats contain the same data -- a snapshot of all tracked flows at capture exit. In pipeline mode, the export contains merged snapshots from all worker shards, sorted by total bytes (descending).

### JSON Format

Pretty-printed array of flow objects. Example (single flow):

```json
[
  {
    "protocol": "tcp",
    "endpoint_a": { "ip": "192.168.1.42", "port": 54321 },
    "endpoint_b": { "ip": "93.184.216.34", "port": 443 },
    "first_seen": 1706123400.123456,
    "last_seen": 1706123460.654321,
    "duration_secs": 60.530865,
    "packets_a_to_b": 150,
    "packets_b_to_a": 200,
    "bytes_a_to_b": 12400,
    "bytes_b_to_a": 485000,
    "packets_total": 350,
    "bytes_total": 497400,
    "avg_bps": 65712.3,
    "tcp_state": "established",
    "client": "a_to_b",
    "retransmissions": 2,
    "out_of_order": 0,
    "rtt_last_ms": 15.2,
    "rtt_min_ms": 12.8,
    "rtt_ewma_ms": 14.1,
    "rtt_samples": 45
  }
]
```

### CSV Format

One row per flow, with a header row. Columns:

```
protocol, endpoint_a_ip, endpoint_a_port, endpoint_b_ip, endpoint_b_port,
first_seen, last_seen, duration_secs, packets_a_to_b, packets_b_to_a,
bytes_a_to_b, bytes_b_to_a, packets_total, bytes_total, avg_bps,
tcp_state, client, retransmissions, out_of_order,
rtt_last_ms, rtt_min_ms, rtt_ewma_ms, rtt_samples
```

Example row:

```
tcp,192.168.1.42,54321,93.184.216.34,443,1706123400.123456,1706123460.654321,60.530865,150,200,12400,485000,350,497400,65712.300,established,a_to_b,2,0,15.200,12.800,14.100,45
```

Fields containing commas, double-quotes, or newlines are quoted per CSV conventions. IPv6 addresses use colons and do not require quoting.

### Field Reference

| Field | Type | Description |
|---|---|---|
| `protocol` | string | `"tcp"` or `"udp"`. |
| `endpoint_a` / `endpoint_b` | object | IP + port. Endpoint A is the canonically "smaller" endpoint. |
| `first_seen` / `last_seen` | float | Unix timestamps with microsecond precision. |
| `duration_secs` | float | `last_seen - first_seen`. |
| `packets_a_to_b` / `packets_b_to_a` | int | Packet counts per direction. |
| `bytes_a_to_b` / `bytes_b_to_a` | int | Byte counts per direction (wire length). |
| `packets_total` / `bytes_total` | int | Sum of both directions. |
| `avg_bps` | float | Average bits per second over the flow's duration. |
| `tcp_state` | string or null | TCP state: `syn_sent`, `syn_ack`, `established`, `fin_wait`, `closed`, `reset`, `unknown`. Null for UDP. |
| `client` | string or null | Which side initiated: `"a_to_b"` or `"b_to_a"`. Null if no SYN was observed. |
| `retransmissions` | int | Detected TCP retransmissions. |
| `out_of_order` | int | Detected out-of-order segments. |
| `rtt_last_ms` | float or null | Most recent RTT sample (ms). |
| `rtt_min_ms` | float or null | Minimum observed RTT (ms). |
| `rtt_ewma_ms` | float or null | EWMA RTT (ms). |
| `rtt_samples` | int | Number of RTT samples collected. |

## Alert Export (JSONL)

Write anomaly alerts to a JSON Lines file:

```bash
sudo netscope --anomalies --alerts-jsonl alerts.jsonl
```

Each line is a standalone JSON object:

```json
{"ts":1706123456.789,"kind":"syn_flood","description":"SYN flood suspected: 250 syns, 60 sources to 10.0.0.1:443"}
{"ts":1706123470.123,"kind":"port_scan","description":"Port scan suspected: 30 ports, 1 hosts from 10.0.0.99"}
```

See [Anomaly Detection](anomaly-detection.md) for details on alert types and thresholds.
