# Getting Started

Commands below assume `netscope` is on your PATH. If you built from source and did not install it, replace `netscope` with `./target/release/netscope`.

## Prerequisites

- **Rust 1.85+** (edition 2024). Install via [rustup](https://rustup.rs/).
- **libpcap** -- the packet capture library.

### Installing libpcap

| Platform        | Command                                                                                                |
| --------------- | ------------------------------------------------------------------------------------------------------ |
| macOS           | Ships with the OS. Install Xcode Command Line Tools (`xcode-select --install`) if headers are missing. |
| Debian / Ubuntu | `sudo apt-get install libpcap-dev`                                                                     |
| Fedora          | `sudo dnf install libpcap-devel`                                                                       |
| Arch Linux      | `sudo pacman -S libpcap`                                                                               |

## Building

From the repository root:

```bash
cargo build --release
```

The binary is at `target/release/netscope`.

This page focuses on first-run setup. For additional workflows, see [Usage Examples](usage.md). If you hit a problem during setup or capture, see [Troubleshooting](troubleshooting.md).

## Permissions

Live packet capture requires access to network interfaces, which typically means **root / sudo** on Linux and macOS. Offline pcap analysis via `--read-pcap` does **not** require elevated privileges.

```bash
# Live capture (requires privileges)
sudo netscope

# Or during development
sudo cargo run --release --

# Offline pcap analysis (no sudo required)
netscope --read-pcap trace.pcap --quiet --stats
```

On Linux, you can often avoid running as root by granting the `CAP_NET_RAW` capability (some setups may also require `CAP_NET_ADMIN`):

```bash
sudo setcap cap_net_raw=eip target/release/netscope
netscope   # no sudo needed
```

> **Security note:** NetScope captures raw network traffic. Be mindful of privacy and compliance requirements when running on shared networks. The web dashboard binds to `127.0.0.1` by default to avoid exposing captured data to the network.

## First Capture

### List available interfaces

```bash
sudo netscope --list-interfaces
```

Output:

```
Available network interfaces:
Name                 Description          Addresses
----------------------------------------------------------------------
en0                                       192.168.1.42, fe80::1
lo0                                       127.0.0.1, ::1
```

### Capture on the default interface

```bash
sudo netscope
```

Packets are printed to the terminal as they arrive. Press **Ctrl-C** to stop.

### Capture with a BPF filter

```bash
sudo netscope -f "tcp port 443"
```

### Start the web dashboard

```bash
sudo netscope --web --quiet
```

Open <http://127.0.0.1:8080> in a browser. The `--quiet` flag suppresses per-packet terminal output, so the dashboard is the primary interface.

For dashboard endpoints, live update behavior, and tuning guidance, see [Web Dashboard](web-dashboard.md).

## Supported Protocols

| Layer     | Protocols                               |
| --------- | --------------------------------------- |
| Link      | Ethernet II, 802.1Q VLAN                |
| Network   | IPv4 (with checksum verification), IPv6 |
| Transport | TCP, UDP, ICMP                          |

**Known limitations:**

- IPv6 extension-header parsing is intentionally limited to common headers (bounded-depth walk) and may not fully decode uncommon chains.
- IPv4 and IPv6 non-initial fragments are skipped for flow tracking (the transport header is only present in the first fragment).

## Next Steps

- [Usage Examples](usage.md) -- Common recipes and workflows.
- [CLI Reference](cli-reference.md) -- Full list of flags and options.
- [Configuration](configuration.md) -- TOML config file for persistent settings.
- [Web Dashboard](web-dashboard.md) -- Endpoints, live update behavior, and tuning.
- [Troubleshooting](troubleshooting.md) -- Common setup and runtime issues.
