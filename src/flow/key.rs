use serde::Serialize;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for FlowProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowProtocol::Tcp => write!(f, "tcp"),
            FlowProtocol::Udp => write!(f, "udp"),
        }
    }
}

impl FlowProtocol {
    #[inline]
    fn as_u8(self) -> u8 {
        match self {
            FlowProtocol::Tcp => 6,
            FlowProtocol::Udp => 17,
        }
    }

    #[inline]
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            6 => Some(FlowProtocol::Tcp),
            17 => Some(FlowProtocol::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    AtoB,
    BtoA,
}

impl fmt::Display for FlowDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowDirection::AtoB => write!(f, "a_to_b"),
            FlowDirection::BtoA => write!(f, "b_to_a"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct FlowKey {
    pub protocol: FlowProtocol,
    pub a: Endpoint,
    pub b: Endpoint,
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} <-> {}", self.protocol, self.a, self.b)
    }
}

impl FlowKey {
    pub fn new(protocol: FlowProtocol, src: Endpoint, dst: Endpoint) -> (Self, FlowDirection) {
        let src_key = endpoint_key(&src);
        let dst_key = endpoint_key(&dst);
        if src_key <= dst_key {
            (
                FlowKey {
                    protocol,
                    a: src,
                    b: dst,
                },
                FlowDirection::AtoB,
            )
        } else {
            (
                FlowKey {
                    protocol,
                    a: dst,
                    b: src,
                },
                FlowDirection::BtoA,
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub(crate) struct FlowKeyV4 {
    a_ip: u32,
    b_ip: u32,
    a_port: u16,
    b_port: u16,
    proto: u8,
    _pad: [u8; 3],
}

impl FlowKeyV4 {
    #[inline]
    pub(crate) fn new(
        protocol: FlowProtocol,
        src_ip: std::net::Ipv4Addr,
        src_port: u16,
        dst_ip: std::net::Ipv4Addr,
        dst_port: u16,
    ) -> (Self, FlowDirection) {
        let src = (u32::from_be_bytes(src_ip.octets()), src_port);
        let dst = (u32::from_be_bytes(dst_ip.octets()), dst_port);
        if src <= dst {
            (
                FlowKeyV4 {
                    a_ip: src.0,
                    b_ip: dst.0,
                    a_port: src.1,
                    b_port: dst.1,
                    proto: protocol.as_u8(),
                    _pad: [0; 3],
                },
                FlowDirection::AtoB,
            )
        } else {
            (
                FlowKeyV4 {
                    a_ip: dst.0,
                    b_ip: src.0,
                    a_port: dst.1,
                    b_port: src.1,
                    proto: protocol.as_u8(),
                    _pad: [0; 3],
                },
                FlowDirection::BtoA,
            )
        }
    }

    #[inline]
    pub(crate) fn from_flow_key(key: &FlowKey) -> Option<Self> {
        let (a, b) = match (key.a.ip, key.b.ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => (a, b),
            _ => return None,
        };
        Some(FlowKeyV4 {
            a_ip: u32::from_be_bytes(a.octets()),
            b_ip: u32::from_be_bytes(b.octets()),
            a_port: key.a.port,
            b_port: key.b.port,
            proto: key.protocol.as_u8(),
            _pad: [0; 3],
        })
    }

    #[inline]
    pub(crate) fn to_flow_key(self) -> FlowKey {
        let protocol = FlowProtocol::from_u8(self.proto).unwrap_or(FlowProtocol::Tcp);
        FlowKey {
            protocol,
            a: Endpoint {
                ip: IpAddr::V4(std::net::Ipv4Addr::from(self.a_ip.to_be_bytes())),
                port: self.a_port,
            },
            b: Endpoint {
                ip: IpAddr::V4(std::net::Ipv4Addr::from(self.b_ip.to_be_bytes())),
                port: self.b_port,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub(crate) struct FlowKeyV6 {
    a_ip: [u8; 16],
    b_ip: [u8; 16],
    a_port: u16,
    b_port: u16,
    proto: u8,
    _pad: [u8; 3],
}

impl FlowKeyV6 {
    #[inline]
    pub(crate) fn new(
        protocol: FlowProtocol,
        src_ip: std::net::Ipv6Addr,
        src_port: u16,
        dst_ip: std::net::Ipv6Addr,
        dst_port: u16,
    ) -> (Self, FlowDirection) {
        let src = (src_ip.octets(), src_port);
        let dst = (dst_ip.octets(), dst_port);
        if src <= dst {
            (
                FlowKeyV6 {
                    a_ip: src.0,
                    b_ip: dst.0,
                    a_port: src.1,
                    b_port: dst.1,
                    proto: protocol.as_u8(),
                    _pad: [0; 3],
                },
                FlowDirection::AtoB,
            )
        } else {
            (
                FlowKeyV6 {
                    a_ip: dst.0,
                    b_ip: src.0,
                    a_port: dst.1,
                    b_port: src.1,
                    proto: protocol.as_u8(),
                    _pad: [0; 3],
                },
                FlowDirection::BtoA,
            )
        }
    }

    #[inline]
    pub(crate) fn from_flow_key(key: &FlowKey) -> Option<Self> {
        let (a, b) = match (key.a.ip, key.b.ip) {
            (IpAddr::V6(a), IpAddr::V6(b)) => (a, b),
            _ => return None,
        };
        Some(FlowKeyV6 {
            a_ip: a.octets(),
            b_ip: b.octets(),
            a_port: key.a.port,
            b_port: key.b.port,
            proto: key.protocol.as_u8(),
            _pad: [0; 3],
        })
    }

    #[inline]
    pub(crate) fn to_flow_key(self) -> FlowKey {
        let protocol = FlowProtocol::from_u8(self.proto).unwrap_or(FlowProtocol::Tcp);
        FlowKey {
            protocol,
            a: Endpoint {
                ip: IpAddr::V6(std::net::Ipv6Addr::from(self.a_ip)),
                port: self.a_port,
            },
            b: Endpoint {
                ip: IpAddr::V6(std::net::Ipv6Addr::from(self.b_ip)),
                port: self.b_port,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CompactFlowKey {
    V4(FlowKeyV4),
    V6(FlowKeyV6),
}

impl CompactFlowKey {
    #[inline]
    pub(crate) fn from_flow_key(key: &FlowKey) -> Option<Self> {
        if let Some(v4) = FlowKeyV4::from_flow_key(key) {
            return Some(CompactFlowKey::V4(v4));
        }
        if let Some(v6) = FlowKeyV6::from_flow_key(key) {
            return Some(CompactFlowKey::V6(v6));
        }
        None
    }

    #[inline]
    pub(crate) fn to_flow_key(self) -> FlowKey {
        match self {
            CompactFlowKey::V4(key) => key.to_flow_key(),
            CompactFlowKey::V6(key) => key.to_flow_key(),
        }
    }
}

fn endpoint_key(endpoint: &Endpoint) -> (u8, [u8; 16], u16) {
    let (version, addr) = ip_key(endpoint.ip);
    (version, addr, endpoint.port)
}

fn ip_key(ip: IpAddr) -> (u8, [u8; 16]) {
    match ip {
        IpAddr::V4(addr) => {
            let mut bytes = [0u8; 16];
            bytes[12..].copy_from_slice(&addr.octets());
            (4, bytes)
        }
        IpAddr::V6(addr) => (6, addr.octets()),
    }
}
