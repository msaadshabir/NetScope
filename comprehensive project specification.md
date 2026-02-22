comprehensive project specification

---

# **NetScope: High-Performance Protocol Analyzer with Real-Time Flow Visualization**

## Project Overview

Build a network packet capture and analysis tool in Rust that captures raw network traffic, dissects multiple protocol layers, and provides real-time visualization of network flows. This project combines raw socket programming, binary protocol parsing, and high-performance data structures.

---

## Core Requirements

### 1. Packet Capture Engine

- **Raw socket implementation** using `libpcap` or raw sockets (`AF_PACKET` on Linux)
- **Zero-copy packet reception** where possible (mmap ring buffers)
- **Multi-threaded capture**: separate threads for capture, parsing, and analysis
- **Filter engine**: BPF bytecode compilation for kernel-level filtering
- **Target throughput**: 1Gbps+ on consumer hardware

### 2. Protocol Stack Implementation

Implement parsers for these layers:

| Layer | Protocols      | Key Fields to Extract                     |
| ----- | -------------- | ----------------------------------------- |
| L2    | Ethernet       | MAC addresses, EtherType                  |
| L3    | IPv4, IPv6     | Source/dest IP, TTL, fragmentation        |
| L4    | TCP, UDP, ICMP | Ports, sequence numbers, flags, checksums |
| L7    | HTTP/1.1, DNS  | Method, host, query types, responses      |

**Parser requirements:**

- Zero-allocation parsing using Rust lifetimes
- Nom parser combinator library or manual byte slicing
- Graceful handling of malformed packets (no panics)
- Support for VLAN tagging and MPLS encapsulation

### 3. Flow Tracking System

```rust
// Core data structure concept (from your quadtree experience)
struct FlowKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: TransportProtocol,
}

struct FlowState {
    start_time: Instant,
    last_seen: Instant,
    packets_sent: (u64, u64), // (src->dst, dst->src)
    bytes_sent: (u64, u64),
    tcp_state: Option<TcpStateMachine>,
    retransmissions: u32,
    out_of_order: u32,
}
```

- **Hash-map based flow table** with LRU eviction
- **TCP state machine**: track SYN, SYN-ACK, ACK, FIN sequences
- **Automatic flow expiration**: configurable timeout (default 60s inactive)
- **Flow export**: JSON/CSV output for external analysis

### 4. Real-Time Analysis Engine

Implement these analyses:

| Analysis                    | Description                                  |
| --------------------------- | -------------------------------------------- |
| **Throughput calculator**   | Bits/sec per flow, per interface, global     |
| **Latency estimator**       | TCP RTT calculation from timestamps          |
| **Retransmission detector** | Identify packet loss patterns                |
| **Protocol distribution**   | Pie chart of traffic by protocol             |
| **Top talkers**             | Highest bandwidth flows (heap-based ranking) |
| **Anomaly detection**       | SYN flood detection, port scan detection     |

### 5. Visualization Dashboard

**Web-based UI** (extend your WASM experience):

- **Real-time WebSocket streaming** of flow data
- **Time-series charts**: throughput, packet rates, latency
- **Network graph**: force-directed graph of host connections
- **Packet inspector**: hex dump with protocol tree breakdown
- **Filter interface**: BPF-style filter builder

**Tech stack**: Rust backend (actix-web or axum), WebAssembly frontend (yew or leptos), WebGL for network graphs (leverage your pathtracer GPU experience)

---

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Packet Capture │────▶│  Protocol Parser│────▶│  Flow Tracker   │
│  (raw socket)   │     │  (zero-copy)    │     │  (hash map)     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                              ┌───────────────────────┼───────────┐
                              ▼                       ▼           ▼
                        ┌─────────┐              ┌─────────┐  ┌────────┐
                        │ Analyzer│              │ WebSocket│  │ Logger │
                        │ Engine  │              │ Server   │  │ (pcap) │
                        └─────────┘              └─────────┘  └────────┘
                              │                       │
                              ▼                       ▼
                        ┌─────────┐              ┌─────────┐
                        │ Alert   │              │ Web UI  │
                        │ System  │              │ (WASM)  │
                        └─────────┘              └─────────┘
```

---

## Implementation Phases

### Phase 1: Core Capture (ONLY DO PHASE 1 TO START)

- [ ] Raw socket setup with `libc` or `pcap` crate
- [ ] Basic packet buffer management
- [ ] Ethernet + IPv4 parsing
- [ ] CLI tool that prints packet headers

### Phase 2: Transport Layer

- [ ] TCP/UDP parsing with state tracking
- [ ] Flow table implementation
- [ ] Throughput calculation
- [ ] Export to pcap file format

### Phase 3: Analysis Engine

- [ ] RTT estimation
- [ ] Retransmission detection
- [ ] Anomaly detection rules
- [ ] Configuration file support (TOML)

### Phase 4: Web Dashboard

- [ ] WebSocket server for real-time data
- [ ] WASM frontend with your preferred framework
- [ ] Real-time charts (use your pathtracer visualization skills)
- [ ] Packet inspector UI

### Phase 5: Optimization

- [ ] Switch to `io_uring` for async I/O
- [ ] Lock-free data structures for flow table
- [ ] eBPF/XDP probe for kernel bypass (advanced)
- [ ] Benchmark against `tcpdump` + `Wireshark`

---

## Key Libraries

| Purpose          | Crate                 |
| ---------------- | --------------------- |
| Packet capture   | `pcap`, `pnet`        |
| Protocol parsing | `nom`, `deku`         |
| Async runtime    | `tokio`               |
| Web server       | `axum`, `actix-web`   |
| WebAssembly      | `wasm-bindgen`, `yew` |
| Serialization    | `serde`, `bincode`    |
| CLI              | `clap`                |
| Logging          | `tracing`             |

---

## Stretch Goals

1. **Custom Protocol**: Implement a simple reliable UDP protocol on top of raw sockets, then use NetScope to debug it (meta-analysis)
2. **Distributed Capture**: Multiple capture agents feeding a central analyzer (custom binary protocol over TCP)
3. **Hardware Timestamping**: Support NIC hardware timestamps for nanosecond-precision latency
4. **eBPF Integration**: Compile and load eBPF programs for kernel-level filtering

---

## Success Metrics

- Capture and parse 100,000 packets/second without packet loss
- Parse full TCP handshake in <1 microsecond per packet
- Web dashboard updates at 30fps with <100ms latency
- Memory usage <500MB for 1 million concurrent flows

---

## Deliverables

1. **GitHub repository** with full Rust source
2. **README**: architecture diagram, build instructions, performance benchmarks
3. **Demo video**: capturing live traffic with real-time visualization
4. **Blog post**: lessons learned on zero-copy parsing and lock-free structures
