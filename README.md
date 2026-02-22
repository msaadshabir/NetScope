# NetScope

High-performance packet capture and protocol analysis tool in Rust.

Status: Phase 1 (Core Capture) is implemented. This includes libpcap capture, zero-copy Ethernet/IPv4/IPv6 parsing, TCP/UDP/ICMP parsing, and a CLI that prints packet headers.

## Features (Phase 1)

- Live packet capture via libpcap
- BPF filter support
- Zero-copy parsers for Ethernet, VLAN, IPv4, IPv6, TCP, UDP, ICMP
- Human-readable packet summaries and optional hex dumps
- CLI with interface selection, filters, packet count, and verbosity
- Graceful shutdown with capture statistics

## Build

Requirements:

- Rust (1.70+ recommended; current toolchain tested during development)
- libpcap

Install libpcap:

- macOS: ships with the OS (Xcode Command Line Tools recommended)
- Debian/Ubuntu: `sudo apt-get install libpcap-dev`
- Fedora: `sudo dnf install libpcap-devel`

Build the project:

```bash
cargo build
```

## Usage

List available interfaces:

```bash
sudo cargo run -- --list-interfaces
```

Capture on the default interface (Ctrl-C to stop):

```bash
sudo cargo run --
```

Capture 20 packets on a specific interface:

```bash
sudo cargo run -- -i en0 -c 20
```

Capture only HTTP traffic and show hex dumps:

```bash
sudo cargo run -- -f "tcp port 80" --hex-dump
```

Increase verbosity:

```bash
sudo cargo run -- -vv
```

### CLI Options

```
Usage: netscope [OPTIONS]

Options:
  -i, --interface <INTERFACE>    Network interface to capture on (e.g., "en0", "eth0")
  -f, --filter <FILTER>          BPF filter expression (e.g., "tcp port 80", "host 192.168.1.1")
  -c, --count <COUNT>            Maximum number of packets to capture (0 = unlimited)
  -p, --promiscuous              Capture in promiscuous mode
  -s, --snaplen <SNAPLEN>        Snapshot length (max bytes per packet to capture)
  -t, --timeout-ms <TIMEOUT_MS>  Read timeout in milliseconds for the capture handle
      --hex-dump                 Show hex dump of packet payload
  -v, --verbose...               Verbosity level (-v, -vv, -vvv)
  -l, --list-interfaces          List available network interfaces and exit
  -h, --help                     Print help
  -V, --version                  Print version
```

## Notes

- Live capture usually requires elevated privileges. Use `sudo` if you see permission errors.
- VLAN tags are decoded and surfaced in the output.
- IPv6 extension headers are not parsed in Phase 1 (payload starts after the fixed header).

## Roadmap

Phase 2 targets:

- TCP/UDP state tracking and flow table
- Throughput calculations
- Export to pcap/JSON/CSV

## License

MIT License. See `LICENSE`.
