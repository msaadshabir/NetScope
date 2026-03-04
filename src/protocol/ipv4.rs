//! Zero-copy IPv4 header parser.
//!
//! IPv4 header layout (20-60 bytes):
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |Version|  IHL  |Type of Service|          Total Length         |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |         Identification        |Flags|      Fragment Offset    |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |  Time to Live |    Protocol   |         Header Checksum       |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                       Source Address                          |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                    Destination Address                        |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                    Options                    |    Padding    |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::{IpProtocol, ParseError};
use std::fmt;
use std::net::Ipv4Addr;

/// Minimum IPv4 header length (no options)
pub const IPV4_MIN_HEADER_LEN: usize = 20;

/// Zero-copy IPv4 header.
#[derive(Debug)]
pub struct Ipv4Header<'a> {
    data: &'a [u8],
    header_len: usize,
}

impl<'a> Ipv4Header<'a> {
    /// Parse an IPv4 header from a byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < IPV4_MIN_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: IPV4_MIN_HEADER_LEN,
                actual: data.len(),
            });
        }

        let version = (data[0] >> 4) & 0x0F;
        if version != 4 {
            return Err(ParseError::InvalidHeader(format!(
                "expected IPv4 (version 4), got version {}",
                version
            )));
        }

        let ihl = (data[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        if header_len < IPV4_MIN_HEADER_LEN {
            return Err(ParseError::InvalidHeader(format!(
                "IHL too small: {} (min 5)",
                ihl
            )));
        }

        if data.len() < header_len {
            return Err(ParseError::TooShort {
                expected: header_len,
                actual: data.len(),
            });
        }

        Ok(Ipv4Header { data, header_len })
    }

    /// IP version (always 4).
    #[inline]
    pub fn version(&self) -> u8 {
        (self.data[0] >> 4) & 0x0F
    }

    /// Internet Header Length in 32-bit words.
    #[inline]
    pub fn ihl(&self) -> u8 {
        self.data[0] & 0x0F
    }

    /// Header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Type of Service / DSCP + ECN.
    #[inline]
    pub fn tos(&self) -> u8 {
        self.data[1]
    }

    /// Differentiated Services Code Point (upper 6 bits of TOS).
    #[inline]
    pub fn dscp(&self) -> u8 {
        self.data[1] >> 2
    }

    /// Explicit Congestion Notification (lower 2 bits of TOS).
    #[inline]
    pub fn ecn(&self) -> u8 {
        self.data[1] & 0x03
    }

    /// Total length of the IP packet (header + payload) in bytes.
    #[inline]
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Identification field (used for fragmentation reassembly).
    #[inline]
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Flags (3 bits): Reserved, Don't Fragment, More Fragments.
    #[inline]
    pub fn flags(&self) -> u8 {
        (self.data[6] >> 5) & 0x07
    }

    /// Don't Fragment flag.
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        (self.data[6] >> 6) & 1 == 1
    }

    /// More Fragments flag.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        (self.data[6] >> 5) & 1 == 1
    }

    /// Fragment offset in 8-byte units.
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.data[6] & 0x1F, self.data[7]])
    }

    /// Time to Live.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.data[8]
    }

    /// Protocol number.
    #[inline]
    pub fn protocol(&self) -> IpProtocol {
        IpProtocol::from(self.data[9])
    }

    /// Protocol number as raw u8.
    #[inline]
    pub fn protocol_raw(&self) -> u8 {
        self.data[9]
    }

    /// Header checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[10], self.data[11]])
    }

    /// Source IP address.
    #[inline]
    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[12], self.data[13], self.data[14], self.data[15])
    }

    /// Destination IP address.
    #[inline]
    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[16], self.data[17], self.data[18], self.data[19])
    }

    /// Options bytes (if any).
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        &self.data[IPV4_MIN_HEADER_LEN..self.header_len]
    }

    /// Payload after the IPv4 header.
    /// Clamped to `total_length - header_len` to avoid reading trailer bytes.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let total = self.total_length() as usize;
        let payload_len = total.saturating_sub(self.header_len);
        let available = self.data.len() - self.header_len;
        let end = self.header_len + payload_len.min(available);
        &self.data[self.header_len..end]
    }

    /// Verify the header checksum.
    /// Returns true if the checksum is valid (sums to 0).
    pub fn verify_checksum(&self) -> bool {
        let mut sum: u32 = 0;
        for i in (0..self.header_len).step_by(2) {
            let word = u16::from_be_bytes([self.data[i], self.data[i + 1]]);
            sum += word as u32;
        }
        // Fold carry bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum == 0xFFFF
    }
}

impl<'a> fmt::Display for Ipv4Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {} proto={} ttl={} len={}",
            self.src_addr(),
            self.dst_addr(),
            self.protocol(),
            self.ttl(),
            self.total_length()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_header() -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // Version=4, IHL=5
        pkt[1] = 0x00; // TOS
        pkt[2] = 0x00;
        pkt[3] = 0x28; // Total length = 40
        pkt[4] = 0xab;
        pkt[5] = 0xcd; // Identification
        pkt[6] = 0x40;
        pkt[7] = 0x00; // Don't Fragment, offset=0
        pkt[8] = 64; // TTL
        pkt[9] = 6; // Protocol = TCP
        pkt[10] = 0x00;
        pkt[11] = 0x00; // Checksum (set to 0 for test)
        // Source: 192.168.1.100
        pkt[12] = 192;
        pkt[13] = 168;
        pkt[14] = 1;
        pkt[15] = 100;
        // Dest: 10.0.0.1
        pkt[16] = 10;
        pkt[17] = 0;
        pkt[18] = 0;
        pkt[19] = 1;
        // Add some payload
        pkt.extend_from_slice(&[0u8; 20]);
        pkt
    }

    #[test]
    fn parse_valid_ipv4() {
        let pkt = make_ipv4_header();
        let hdr = Ipv4Header::parse(&pkt).unwrap();
        assert_eq!(hdr.version(), 4);
        assert_eq!(hdr.ihl(), 5);
        assert_eq!(hdr.header_len(), 20);
        assert_eq!(hdr.total_length(), 40);
        assert_eq!(hdr.ttl(), 64);
        assert_eq!(hdr.protocol(), IpProtocol::Tcp);
        assert_eq!(hdr.src_addr(), Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(hdr.dst_addr(), Ipv4Addr::new(10, 0, 0, 1));
        assert!(hdr.dont_fragment());
        assert!(!hdr.more_fragments());
        assert_eq!(hdr.payload().len(), 20);
    }

    #[test]
    fn reject_too_short_packet() {
        let pkt = [0u8; 19];
        assert!(Ipv4Header::parse(&pkt).is_err());
    }

    #[test]
    fn reject_wrong_version() {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x65; // version 6, IHL 5
        assert!(Ipv4Header::parse(&pkt).is_err());
    }
}
