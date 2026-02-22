//! Zero-copy ICMP header parser.
//!
//! ICMP header layout (8 bytes minimum):
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |     Type      |     Code      |          Checksum             |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                     Rest of Header                           |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::ParseError;
use std::fmt;

/// Minimum ICMP header length
pub const ICMP_HEADER_LEN: usize = 8;

/// Common ICMP types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    DestinationUnreachable,
    Redirect,
    EchoRequest,
    TimeExceeded,
    Unknown(u8),
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestinationUnreachable,
            5 => IcmpType::Redirect,
            8 => IcmpType::EchoRequest,
            11 => IcmpType::TimeExceeded,
            other => IcmpType::Unknown(other),
        }
    }
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpType::EchoReply => write!(f, "Echo Reply"),
            IcmpType::DestinationUnreachable => write!(f, "Destination Unreachable"),
            IcmpType::Redirect => write!(f, "Redirect"),
            IcmpType::EchoRequest => write!(f, "Echo Request"),
            IcmpType::TimeExceeded => write!(f, "Time Exceeded"),
            IcmpType::Unknown(v) => write!(f, "Type({})", v),
        }
    }
}

/// Zero-copy ICMP header.
#[derive(Debug)]
pub struct IcmpHeader<'a> {
    data: &'a [u8],
}

impl<'a> IcmpHeader<'a> {
    /// Parse an ICMP header from a byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < ICMP_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: ICMP_HEADER_LEN,
                actual: data.len(),
            });
        }
        Ok(IcmpHeader { data })
    }

    /// ICMP type.
    #[inline]
    pub fn icmp_type(&self) -> IcmpType {
        IcmpType::from(self.data[0])
    }

    /// ICMP type as raw u8.
    #[inline]
    pub fn icmp_type_raw(&self) -> u8 {
        self.data[0]
    }

    /// ICMP code.
    #[inline]
    pub fn code(&self) -> u8 {
        self.data[1]
    }

    /// Checksum.
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

    /// Payload after the ICMP header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[ICMP_HEADER_LEN..]
    }
}

impl<'a> fmt::Display for IcmpHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.icmp_type() {
            IcmpType::EchoRequest | IcmpType::EchoReply => {
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
        pkt[0] = 8; // Echo Request
        pkt[1] = 0; // Code
        pkt[4] = 0x00;
        pkt[5] = 0x01; // ID = 1
        pkt[6] = 0x00;
        pkt[7] = 0x0A; // Seq = 10

        let hdr = IcmpHeader::parse(&pkt).unwrap();
        assert_eq!(hdr.icmp_type(), IcmpType::EchoRequest);
        assert_eq!(hdr.code(), 0);
        assert_eq!(hdr.identifier(), 1);
        assert_eq!(hdr.sequence(), 10);
    }

    #[test]
    fn reject_short_icmp() {
        let pkt = [0u8; 7];
        assert!(IcmpHeader::parse(&pkt).is_err());
    }
}
