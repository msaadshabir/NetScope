//! Zero-copy IPv6 header parser.
//!
//! IPv6 fixed header layout (40 bytes):
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |Version| Traffic Class |           Flow Label                  |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |         Payload Length        |  Next Header  |   Hop Limit   |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                         Source Address                        |
//!  |                          (128 bits)                           |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                      Destination Address                      |
//!  |                          (128 bits)                           |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::{IpProtocol, ParseError};
use std::fmt;
use std::net::Ipv6Addr;

/// IPv6 fixed header length
pub const IPV6_HEADER_LEN: usize = 40;

/// Zero-copy IPv6 header.
#[derive(Debug)]
pub struct Ipv6Header<'a> {
    data: &'a [u8],
}

impl<'a> Ipv6Header<'a> {
    /// Parse an IPv6 header from a byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < IPV6_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: IPV6_HEADER_LEN,
                actual: data.len(),
            });
        }

        let version = (data[0] >> 4) & 0x0F;
        if version != 6 {
            return Err(ParseError::InvalidHeader(format!(
                "expected IPv6 (version 6), got version {}",
                version
            )));
        }

        Ok(Ipv6Header { data })
    }

    /// IP version (always 6).
    #[inline]
    pub fn version(&self) -> u8 {
        (self.data[0] >> 4) & 0x0F
    }

    /// Traffic class (8 bits).
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((self.data[0] & 0x0F) << 4) | ((self.data[1] >> 4) & 0x0F)
    }

    /// Flow label (20 bits).
    #[inline]
    pub fn flow_label(&self) -> u32 {
        let b =
            ((self.data[1] & 0x0F) as u32) << 16 | (self.data[2] as u32) << 8 | self.data[3] as u32;
        b
    }

    /// Payload length (not including the 40-byte fixed header).
    #[inline]
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Next header protocol number.
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.data[6])
    }

    /// Next header raw value.
    #[inline]
    pub fn next_header_raw(&self) -> u8 {
        self.data[6]
    }

    /// Hop limit (analogous to IPv4 TTL).
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.data[7]
    }

    /// Source IPv6 address.
    #[inline]
    pub fn src_addr(&self) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&self.data[8..24]);
        Ipv6Addr::from(octets)
    }

    /// Destination IPv6 address.
    #[inline]
    pub fn dst_addr(&self) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&self.data[24..40]);
        Ipv6Addr::from(octets)
    }

    /// Payload after the fixed IPv6 header.
    /// Note: does not handle extension headers (they appear in payload).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let payload_len = self.payload_length() as usize;
        let available = self.data.len() - IPV6_HEADER_LEN;
        let end = IPV6_HEADER_LEN + payload_len.min(available);
        &self.data[IPV6_HEADER_LEN..end]
    }
}

impl<'a> fmt::Display for Ipv6Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {} next_hdr={} hop_limit={} len={}",
            self.src_addr(),
            self.dst_addr(),
            self.next_header(),
            self.hop_limit(),
            self.payload_length()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv6_header() -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // Version=6, TC upper 4 bits = 0
        pkt[1] = 0x00; // TC lower 4 bits = 0, FL upper 4 = 0
        pkt[2] = 0x00;
        pkt[3] = 0x00; // Flow label = 0
        pkt[4] = 0x00;
        pkt[5] = 0x14; // Payload length = 20
        pkt[6] = 6; // Next Header = TCP
        pkt[7] = 64; // Hop Limit

        // Source: ::1
        pkt[23] = 1;
        // Dest: ::2
        pkt[39] = 2;

        // Add payload
        pkt.extend_from_slice(&[0u8; 20]);
        pkt
    }

    #[test]
    fn parse_valid_ipv6() {
        let pkt = make_ipv6_header();
        let hdr = Ipv6Header::parse(&pkt).unwrap();
        assert_eq!(hdr.version(), 6);
        assert_eq!(hdr.payload_length(), 20);
        assert_eq!(hdr.next_header(), IpProtocol::Tcp);
        assert_eq!(hdr.hop_limit(), 64);
        assert_eq!(hdr.src_addr(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(hdr.dst_addr(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));
        assert_eq!(hdr.payload().len(), 20);
    }

    #[test]
    fn reject_too_short_ipv6() {
        let pkt = [0x60; 39]; // one byte short
        assert!(Ipv6Header::parse(&pkt).is_err());
    }
}
