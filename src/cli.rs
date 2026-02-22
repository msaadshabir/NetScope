use clap::Parser;

/// NetScope: High-performance network packet capture and protocol analyzer
#[derive(Parser, Debug)]
#[command(name = "netscope", version, about)]
pub struct Cli {
    /// Network interface to capture on (e.g., "en0", "eth0").
    /// If not specified, the default interface is used.
    #[arg(short, long)]
    pub interface: Option<String>,

    /// BPF filter expression (e.g., "tcp port 80", "host 192.168.1.1")
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Maximum number of packets to capture (0 = unlimited)
    #[arg(short = 'c', long, default_value_t = 0)]
    pub count: u64,

    /// Capture in promiscuous mode
    #[arg(short, long, default_value_t = true)]
    pub promiscuous: bool,

    /// Snapshot length (max bytes per packet to capture)
    #[arg(short, long, default_value_t = 65535)]
    pub snaplen: i32,

    /// Read timeout in milliseconds for the capture handle
    #[arg(short = 't', long, default_value_t = 100)]
    pub timeout_ms: i32,

    /// Show hex dump of packet payload
    #[arg(long, default_value_t = false)]
    pub hex_dump: bool,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// List available network interfaces and exit
    #[arg(short, long)]
    pub list_interfaces: bool,
}
