//! Zero-copy ICMPv6 header parser.
//!
//! ICMPv6 header layout (8 bytes minimum):
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |     Type      |     Code      |          Checksum             |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                     Rest of Header                           |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::ParseError;
use std::fmt;

/// Minimum ICMPv6 header length.
pub const ICMPV6_HEADER_LEN: usize = 8;

/// Common ICMPv6 types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmpv6Type {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
    EchoRequest,
    EchoReply,
    RouterSolicitation,
    RouterAdvertisement,
    NeighborSolicitation,
    NeighborAdvertisement,
    Redirect,
    Unknown(u8),
}

impl From<u8> for Icmpv6Type {
    fn from(value: u8) -> Self {
        match value {
            1 => Icmpv6Type::DestinationUnreachable,
            2 => Icmpv6Type::PacketTooBig,
            3 => Icmpv6Type::TimeExceeded,
            4 => Icmpv6Type::ParameterProblem,
            128 => Icmpv6Type::EchoRequest,
            129 => Icmpv6Type::EchoReply,
            133 => Icmpv6Type::RouterSolicitation,
            134 => Icmpv6Type::RouterAdvertisement,
            135 => Icmpv6Type::NeighborSolicitation,
            136 => Icmpv6Type::NeighborAdvertisement,
            137 => Icmpv6Type::Redirect,
            other => Icmpv6Type::Unknown(other),
        }
    }
}

impl fmt::Display for Icmpv6Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Icmpv6Type::DestinationUnreachable => write!(f, "Destination Unreachable"),
            Icmpv6Type::PacketTooBig => write!(f, "Packet Too Big"),
            Icmpv6Type::TimeExceeded => write!(f, "Time Exceeded"),
            Icmpv6Type::ParameterProblem => write!(f, "Parameter Problem"),
            Icmpv6Type::EchoRequest => write!(f, "Echo Request"),
            Icmpv6Type::EchoReply => write!(f, "Echo Reply"),
            Icmpv6Type::RouterSolicitation => write!(f, "Router Solicitation"),
            Icmpv6Type::RouterAdvertisement => write!(f, "Router Advertisement"),
            Icmpv6Type::NeighborSolicitation => write!(f, "Neighbor Solicitation"),
            Icmpv6Type::NeighborAdvertisement => write!(f, "Neighbor Advertisement"),
            Icmpv6Type::Redirect => write!(f, "Redirect"),
            Icmpv6Type::Unknown(v) => write!(f, "Type({})", v),
        }
    }
}

/// Zero-copy ICMPv6 header.
#[derive(Debug)]
pub struct Icmpv6Header<'a> {
    data: &'a [u8],
}

impl<'a> Icmpv6Header<'a> {
    /// Parse an ICMPv6 header from a byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < ICMPV6_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: ICMPV6_HEADER_LEN,
                actual: data.len(),
            });
        }
        Ok(Icmpv6Header { data })
    }

    /// ICMPv6 type.
    #[inline]
    pub fn icmp_type(&self) -> Icmpv6Type {
        Icmpv6Type::from(self.data[0])
    }

    /// ICMPv6 type as raw u8.
    #[inline]
    pub fn icmp_type_raw(&self) -> u8 {
        self.data[0]
    }

    /// ICMPv6 code.
    #[inline]
    pub fn code(&self) -> u8 {
        self.data[1]
    }

    /// ICMPv6 checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Rest of header (4 bytes, interpretation depends on type/code).
    #[inline]
    pub fn rest_of_header(&self) -> &'a [u8] {
        &self.data[4..8]
    }

    /// For Echo Request/Reply: identifier.
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// For Echo Request/Reply: sequence number.
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }

    /// Payload after the ICMPv6 header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[ICMPV6_HEADER_LEN..]
    }
}

impl<'a> fmt::Display for Icmpv6Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.icmp_type() {
            Icmpv6Type::EchoRequest | Icmpv6Type::EchoReply => {
                write!(
                    f,
                    "{} id={} seq={}",
                    self.icmp_type(),
                    self.identifier(),
                    self.sequence()
                )
            }
            _ => {
                write!(f, "{} code={}", self.icmp_type(), self.code())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_echo_request() {
        let mut pkt = vec![0u8; 8];
        pkt[0] = 128; // Echo Request
        pkt[1] = 0; // Code
        pkt[4] = 0x00;
        pkt[5] = 0x01; // ID = 1
        pkt[6] = 0x00;
        pkt[7] = 0x0A; // Seq = 10

        let hdr = Icmpv6Header::parse(&pkt).unwrap();
        assert_eq!(hdr.icmp_type(), Icmpv6Type::EchoRequest);
        assert_eq!(hdr.code(), 0);
        assert_eq!(hdr.identifier(), 1);
        assert_eq!(hdr.sequence(), 10);
    }

    #[test]
    fn parse_neighbor_solicitation() {
        let mut pkt = vec![0u8; 8];
        pkt[0] = 135; // Neighbor Solicitation
        pkt[1] = 0; // Code

        let hdr = Icmpv6Header::parse(&pkt).unwrap();
        assert_eq!(hdr.icmp_type(), Icmpv6Type::NeighborSolicitation);
        assert_eq!(hdr.code(), 0);
    }

    #[test]
    fn reject_short_icmpv6() {
        let pkt = [0u8; 7];
        assert!(Icmpv6Header::parse(&pkt).is_err());
    }
}
