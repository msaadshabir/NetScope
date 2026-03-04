//! Zero-copy UDP header parser.
//!
//! UDP header layout (8 bytes, fixed):
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |          Source Port          |       Destination Port        |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |            Length             |           Checksum            |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::ParseError;
use std::fmt;

/// UDP header is always exactly 8 bytes.
pub const UDP_HEADER_LEN: usize = 8;

/// Zero-copy UDP header.
#[derive(Debug)]
pub struct UdpHeader<'a> {
    data: &'a [u8],
}

impl<'a> UdpHeader<'a> {
    /// Parse a UDP header from a byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < UDP_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: UDP_HEADER_LEN,
                actual: data.len(),
            });
        }
        Ok(UdpHeader { data })
    }

    /// Source port.
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    /// Destination port.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Total length of UDP datagram (header + payload) in bytes.
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }

    /// Payload after the UDP header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let declared_len = self.length() as usize;
        let payload_len = declared_len.saturating_sub(UDP_HEADER_LEN);
        let available = self.data.len() - UDP_HEADER_LEN;
        let end = UDP_HEADER_LEN + payload_len.min(available);
        &self.data[UDP_HEADER_LEN..end]
    }
}

impl<'a> fmt::Display for UdpHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ":{} -> :{} len={}",
            self.src_port(),
            self.dst_port(),
            self.length()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_udp() {
        let mut pkt = vec![0u8; 8];
        pkt[0] = 0x00;
        pkt[1] = 0x35; // src port = 53 (DNS)
        pkt[2] = 0xC0;
        pkt[3] = 0x00; // dst port = 49152
        pkt[4] = 0x00;
        pkt[5] = 0x1C; // length = 28 (8 header + 20 payload)
        // Add payload
        pkt.extend_from_slice(&[0xAB; 20]);

        let hdr = UdpHeader::parse(&pkt).unwrap();
        assert_eq!(hdr.src_port(), 53);
        assert_eq!(hdr.dst_port(), 49152);
        assert_eq!(hdr.length(), 28);
        assert_eq!(hdr.payload().len(), 20);
    }

    #[test]
    fn reject_short_udp() {
        let pkt = [0u8; 7];
        assert!(UdpHeader::parse(&pkt).is_err());
    }
}
