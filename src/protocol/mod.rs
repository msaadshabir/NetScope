pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;
pub mod icmp;

use std::fmt;
use std::net::IpAddr;

/// EtherType constants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86DD,
    Arp = 0x0806,
    VlanTagged = 0x8100,
    Mpls = 0x8847,
    MplsMulticast = 0x8848,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::Ipv4,
            0x86DD => EtherType::Ipv6,
            0x0806 => EtherType::Arp,
            0x8100 => EtherType::VlanTagged,
            0x8847 => EtherType::Mpls,
            0x8848 => EtherType::MplsMulticast,
            other => EtherType::Unknown(other),
        }
    }
}

// Remove repr(u16) since we have a variant with data
impl EtherType {
    pub fn as_u16(&self) -> u16 {
        match self {
            EtherType::Ipv4 => 0x0800,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Arp => 0x0806,
            EtherType::VlanTagged => 0x8100,
            EtherType::Mpls => 0x8847,
            EtherType::MplsMulticast => 0x8848,
            EtherType::Unknown(v) => *v,
        }
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtherType::Ipv4 => write!(f, "IPv4"),
            EtherType::Ipv6 => write!(f, "IPv6"),
            EtherType::Arp => write!(f, "ARP"),
            EtherType::VlanTagged => write!(f, "802.1Q VLAN"),
            EtherType::Mpls => write!(f, "MPLS"),
            EtherType::MplsMulticast => write!(f, "MPLS Multicast"),
            EtherType::Unknown(v) => write!(f, "Unknown(0x{:04x})", v),
        }
    }
}

/// IP Protocol numbers (subset relevant to our use case)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Icmpv6,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            58 => IpProtocol::Icmpv6,
            other => IpProtocol::Unknown(other),
        }
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpProtocol::Icmp => write!(f, "ICMP"),
            IpProtocol::Tcp => write!(f, "TCP"),
            IpProtocol::Udp => write!(f, "UDP"),
            IpProtocol::Icmpv6 => write!(f, "ICMPv6"),
            IpProtocol::Unknown(v) => write!(f, "Proto({})", v),
        }
    }
}

/// Errors from protocol parsing
#[derive(Debug)]
pub enum ParseError {
    /// Not enough bytes to parse the header
    TooShort { expected: usize, actual: usize },
    /// Invalid header values
    InvalidHeader(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort { expected, actual } => {
                write!(f, "packet too short: need {} bytes, got {}", expected, actual)
            }
            ParseError::InvalidHeader(msg) => write!(f, "invalid header: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

/// A fully parsed packet, referencing the original byte slice
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    pub ethernet: ethernet::EthernetHeader<'a>,
    pub vlan: Option<VlanTag>,
    pub network: Option<NetworkHeader<'a>>,
    pub transport: Option<TransportHeader<'a>>,
    pub payload: &'a [u8],
}

/// VLAN tag (802.1Q)
#[derive(Debug, Clone, Copy)]
pub struct VlanTag {
    pub priority: u8,
    pub dei: bool,
    pub vlan_id: u16,
}

/// Network layer header
#[derive(Debug)]
pub enum NetworkHeader<'a> {
    Ipv4(ipv4::Ipv4Header<'a>),
    Ipv6(ipv6::Ipv6Header<'a>),
}

impl<'a> NetworkHeader<'a> {
    pub fn src_ip(&self) -> IpAddr {
        match self {
            NetworkHeader::Ipv4(h) => IpAddr::V4(h.src_addr()),
            NetworkHeader::Ipv6(h) => IpAddr::V6(h.src_addr()),
        }
    }

    pub fn dst_ip(&self) -> IpAddr {
        match self {
            NetworkHeader::Ipv4(h) => IpAddr::V4(h.dst_addr()),
            NetworkHeader::Ipv6(h) => IpAddr::V6(h.dst_addr()),
        }
    }

    pub fn protocol(&self) -> IpProtocol {
        match self {
            NetworkHeader::Ipv4(h) => h.protocol(),
            NetworkHeader::Ipv6(h) => h.next_header(),
        }
    }
}

/// Transport layer header
#[derive(Debug)]
pub enum TransportHeader<'a> {
    Tcp(tcp::TcpHeader<'a>),
    Udp(udp::UdpHeader<'a>),
    Icmp(icmp::IcmpHeader<'a>),
}

/// Parse a complete packet from raw bytes.
/// This is the main entry point for the protocol stack.
pub fn parse_packet(data: &[u8]) -> Result<ParsedPacket<'_>, ParseError> {
    // Layer 2: Ethernet
    let eth = ethernet::EthernetHeader::parse(data)?;
    let mut remaining = eth.payload();
    let mut ether_type = eth.ether_type();
    let mut vlan = None;

    // Handle VLAN tagging (802.1Q)
    if ether_type == EtherType::VlanTagged {
        if remaining.len() < 4 {
            return Err(ParseError::TooShort {
                expected: 4,
                actual: remaining.len(),
            });
        }
        let tci = u16::from_be_bytes([remaining[0], remaining[1]]);
        vlan = Some(VlanTag {
            priority: (tci >> 13) as u8,
            dei: (tci >> 12) & 1 == 1,
            vlan_id: tci & 0x0FFF,
        });
        ether_type = EtherType::from(u16::from_be_bytes([remaining[2], remaining[3]]));
        remaining = &remaining[4..];
    }

    // Layer 3: Network
    let (network, l4_data, ip_proto) = match ether_type {
        EtherType::Ipv4 => {
            let hdr = ipv4::Ipv4Header::parse(remaining)?;
            let proto = hdr.protocol();
            let payload = hdr.payload();
            (Some(NetworkHeader::Ipv4(hdr)), payload, Some(proto))
        }
        EtherType::Ipv6 => {
            let hdr = ipv6::Ipv6Header::parse(remaining)?;
            let proto = hdr.next_header();
            let payload = hdr.payload();
            (Some(NetworkHeader::Ipv6(hdr)), payload, Some(proto))
        }
        _ => (None, remaining, None),
    };

    // Layer 4: Transport
    let (transport, payload) = match ip_proto {
        Some(IpProtocol::Tcp) => {
            match tcp::TcpHeader::parse(l4_data) {
                Ok(hdr) => {
                    let payload = hdr.payload();
                    (Some(TransportHeader::Tcp(hdr)), payload)
                }
                Err(_) => (None, l4_data),
            }
        }
        Some(IpProtocol::Udp) => {
            match udp::UdpHeader::parse(l4_data) {
                Ok(hdr) => {
                    let payload = hdr.payload();
                    (Some(TransportHeader::Udp(hdr)), payload)
                }
                Err(_) => (None, l4_data),
            }
        }
        Some(IpProtocol::Icmp) | Some(IpProtocol::Icmpv6) => {
            match icmp::IcmpHeader::parse(l4_data) {
                Ok(hdr) => {
                    let payload = hdr.payload();
                    (Some(TransportHeader::Icmp(hdr)), payload)
                }
                Err(_) => (None, l4_data),
            }
        }
        _ => (None, l4_data),
    };

    Ok(ParsedPacket {
        ethernet: eth,
        vlan,
        network,
        transport,
        payload,
    })
}
