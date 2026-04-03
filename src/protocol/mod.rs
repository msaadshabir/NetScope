pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod loopback;
pub mod sll;
pub mod tcp;
pub mod tls;
pub mod udp;

use std::fmt;
use std::net::IpAddr;

/// Supported datalink types for packet parsing/routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    LinuxSll,
    LoopbackNull,
    LoopbackLoop,
    RawIp,
    Unsupported(i32),
}

impl LinkType {
    pub fn from_pcap_value(value: i32) -> Self {
        match value {
            1 => LinkType::Ethernet,
            113 => LinkType::LinuxSll,
            0 => LinkType::LoopbackNull,
            108 => LinkType::LoopbackLoop,
            12 | 101 => LinkType::RawIp,
            other => LinkType::Unsupported(other),
        }
    }

    pub fn as_pcap_value(self) -> i32 {
        match self {
            LinkType::Ethernet => 1,
            LinkType::LinuxSll => 113,
            LinkType::LoopbackNull => 0,
            LinkType::LoopbackLoop => 108,
            LinkType::RawIp => 12,
            LinkType::Unsupported(value) => value,
        }
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkType::Ethernet => write!(f, "Ethernet"),
            LinkType::LinuxSll => write!(f, "Linux SLL"),
            LinkType::LoopbackNull => write!(f, "Loopback (NULL)"),
            LinkType::LoopbackLoop => write!(f, "Loopback (LOOP)"),
            LinkType::RawIp => write!(f, "Raw IP"),
            LinkType::Unsupported(value) => write!(f, "Unsupported({})", value),
        }
    }
}

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
    Fragment,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            44 => IpProtocol::Fragment,
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
            IpProtocol::Fragment => write!(f, "IPv6-Fragment"),
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
                write!(
                    f,
                    "packet too short: need {} bytes, got {}",
                    expected, actual
                )
            }
            ParseError::InvalidHeader(msg) => write!(f, "invalid header: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

/// A fully parsed packet, referencing the original byte slice
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    pub link: LinkHeader<'a>,
    pub vlan: Option<VlanTag>,
    pub network: Option<NetworkHeader<'a>>,
    pub transport: Option<TransportHeader<'a>>,
    pub payload: &'a [u8],
}

/// Parsed link-layer header.
#[derive(Debug)]
pub enum LinkHeader<'a> {
    Ethernet(ethernet::EthernetHeader<'a>),
    LinuxSll(sll::LinuxSllHeader<'a>),
    Loopback(loopback::LoopbackHeader<'a>),
    RawIp,
}

impl fmt::Display for LinkHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkHeader::Ethernet(h) => write!(f, "{}", h),
            LinkHeader::LinuxSll(h) => write!(f, "{}", h),
            LinkHeader::Loopback(h) => write!(f, "{}", h),
            LinkHeader::RawIp => write!(f, "Raw IP"),
        }
    }
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
#[inline]
pub fn parse_packet(data: &[u8]) -> Result<ParsedPacket<'_>, ParseError> {
    parse_packet_with_linktype(data, LinkType::Ethernet)
}

/// Parse a complete packet from raw bytes using a specific link type.
#[inline]
pub fn parse_packet_with_linktype(
    data: &[u8],
    link_type: LinkType,
) -> Result<ParsedPacket<'_>, ParseError> {
    let (link, mut remaining, mut ether_type) = match link_type {
        LinkType::Ethernet => {
            let eth = ethernet::EthernetHeader::parse(data)?;
            let payload = eth.payload();
            let ether_type = eth.ether_type();
            (LinkHeader::Ethernet(eth), payload, Some(ether_type))
        }
        LinkType::LinuxSll => {
            let sll = sll::LinuxSllHeader::parse(data)?;
            let payload = sll.payload();
            let ether_type = sll.protocol();
            (LinkHeader::LinuxSll(sll), payload, Some(ether_type))
        }
        LinkType::LoopbackNull => {
            let loopback = loopback::LoopbackHeader::parse_null(data)?;
            let payload = loopback.payload();
            (LinkHeader::Loopback(loopback), payload, None)
        }
        LinkType::LoopbackLoop => {
            let loopback = loopback::LoopbackHeader::parse_loop(data)?;
            let payload = loopback.payload();
            (LinkHeader::Loopback(loopback), payload, None)
        }
        LinkType::RawIp => (LinkHeader::RawIp, data, None),
        LinkType::Unsupported(value) => {
            return Err(ParseError::InvalidHeader(format!(
                "unsupported link type {}",
                value
            )));
        }
    };

    let mut vlan = None;

    // Handle VLAN tagging (802.1Q) for link types that surface EtherType.
    if let Some(EtherType::VlanTagged) = ether_type {
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
        ether_type = Some(EtherType::from(u16::from_be_bytes([
            remaining[2],
            remaining[3],
        ])));
        remaining = &remaining[4..];
    }

    let (network, l4_data, ip_proto) = if let Some(link_ether_type) = ether_type {
        parse_network_from_ether_type(link_ether_type, remaining)?
    } else {
        parse_network_from_ip_payload(remaining)?
    };

    // Layer 4: Transport
    let (transport, payload) = parse_transport(ip_proto, l4_data);

    Ok(ParsedPacket {
        link,
        vlan,
        network,
        transport,
        payload,
    })
}

#[inline]
fn parse_network_from_ether_type<'a>(
    ether_type: EtherType,
    remaining: &'a [u8],
) -> Result<(Option<NetworkHeader<'a>>, &'a [u8], Option<IpProtocol>), ParseError> {
    let parsed = match ether_type {
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

    Ok(parsed)
}

#[inline]
fn parse_network_from_ip_payload<'a>(
    remaining: &'a [u8],
) -> Result<(Option<NetworkHeader<'a>>, &'a [u8], Option<IpProtocol>), ParseError> {
    if remaining.is_empty() {
        return Err(ParseError::TooShort {
            expected: 1,
            actual: 0,
        });
    }

    let parsed = match remaining[0] >> 4 {
        4 => {
            let hdr = ipv4::Ipv4Header::parse(remaining)?;
            let proto = hdr.protocol();
            let payload = hdr.payload();
            (Some(NetworkHeader::Ipv4(hdr)), payload, Some(proto))
        }
        6 => {
            let hdr = ipv6::Ipv6Header::parse(remaining)?;
            let proto = hdr.next_header();
            let payload = hdr.payload();
            (Some(NetworkHeader::Ipv6(hdr)), payload, Some(proto))
        }
        _ => (None, remaining, None),
    };

    Ok(parsed)
}

#[inline]
fn parse_transport<'a>(
    ip_proto: Option<IpProtocol>,
    l4_data: &'a [u8],
) -> (Option<TransportHeader<'a>>, &'a [u8]) {
    match ip_proto {
        Some(IpProtocol::Tcp) => match tcp::TcpHeader::parse(l4_data) {
            Ok(hdr) => {
                let payload = hdr.payload();
                (Some(TransportHeader::Tcp(hdr)), payload)
            }
            Err(_) => (None, l4_data),
        },
        Some(IpProtocol::Udp) => match udp::UdpHeader::parse(l4_data) {
            Ok(hdr) => {
                let payload = hdr.payload();
                (Some(TransportHeader::Udp(hdr)), payload)
            }
            Err(_) => (None, l4_data),
        },
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcp_ipv4_payload(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 20];
        pkt[0] = 0x45; // version + IHL
        pkt[2] = 0x00;
        pkt[3] = 0x28; // total length = 40 bytes
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = 0x50; // TCP data offset = 5 (20-byte header)
        pkt
    }

    #[test]
    fn parse_raw_ip_ipv4_tcp() {
        let raw = make_tcp_ipv4_payload([192, 0, 2, 10], [192, 0, 2, 20], 12000, 443);
        let parsed = parse_packet_with_linktype(&raw, LinkType::RawIp).unwrap();

        assert!(matches!(parsed.link, LinkHeader::RawIp));
        assert!(matches!(parsed.network, Some(NetworkHeader::Ipv4(_))));
        assert!(matches!(parsed.transport, Some(TransportHeader::Tcp(_))));
    }

    #[test]
    fn parse_loopback_null_ipv4_tcp() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&2u32.to_ne_bytes()); // AF_INET
        pkt.extend_from_slice(&make_tcp_ipv4_payload(
            [127, 0, 0, 1],
            [127, 0, 0, 1],
            50000,
            8080,
        ));

        let parsed = parse_packet_with_linktype(&pkt, LinkType::LoopbackNull).unwrap();

        assert!(matches!(parsed.link, LinkHeader::Loopback(_)));
        assert!(matches!(parsed.network, Some(NetworkHeader::Ipv4(_))));
        assert!(matches!(parsed.transport, Some(TransportHeader::Tcp(_))));
    }

    #[test]
    fn parse_linux_sll_ipv4_tcp() {
        let mut pkt = vec![
            0x00, 0x00, // packet type = host
            0x00, 0x01, // ARPHRD = ethernet
            0x00, 0x06, // addr len = 6
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, // addr
            0x08, 0x00, // protocol = IPv4
        ];
        pkt.extend_from_slice(&make_tcp_ipv4_payload(
            [10, 10, 0, 1],
            [10, 10, 0, 2],
            23456,
            80,
        ));

        let parsed = parse_packet_with_linktype(&pkt, LinkType::LinuxSll).unwrap();

        assert!(matches!(parsed.link, LinkHeader::LinuxSll(_)));
        assert!(matches!(parsed.network, Some(NetworkHeader::Ipv4(_))));
        assert!(matches!(parsed.transport, Some(TransportHeader::Tcp(_))));
    }
}
