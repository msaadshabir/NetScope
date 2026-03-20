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

const MAX_EXTENSION_HEADERS: usize = 8;

/// Located transport payload information for an IPv6 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6PayloadInfo {
    /// Effective protocol after extension-header walking.
    pub next_header: u8,
    /// Offset to transport payload within the IPv6 packet bytes.
    pub transport_offset: usize,
    /// End offset of IPv6 payload (clamped to captured bytes).
    pub payload_end: usize,
    /// Whether a non-initial fragment was encountered.
    pub non_initial_fragment: bool,
}

/// Walk common IPv6 extension headers and locate transport payload.
///
/// Returns `None` when the fixed IPv6 header is missing.
#[inline]
pub fn locate_ipv6_payload(data: &[u8]) -> Option<Ipv6PayloadInfo> {
    if data.len() < IPV6_HEADER_LEN {
        return None;
    }

    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let available = data.len() - IPV6_HEADER_LEN;
    let payload_end = IPV6_HEADER_LEN + payload_len.min(available);

    let mut next_header = data[6];
    let mut transport_offset = IPV6_HEADER_LEN;
    let mut non_initial_fragment = false;
    let mut extension_headers_remaining = MAX_EXTENSION_HEADERS;

    while extension_headers_remaining > 0 && transport_offset < payload_end {
        match next_header {
            // Hop-by-Hop, Routing, Destination Options, Mobility, HIP, Shim6
            0 | 43 | 60 | 135 | 139 | 140 => {
                if payload_end < transport_offset + 2 {
                    break;
                }
                let hdr_next = data[transport_offset];
                let hdr_ext_len = data[transport_offset + 1] as usize;
                let header_len = (hdr_ext_len + 1) * 8;
                if payload_end < transport_offset + header_len {
                    break;
                }
                next_header = hdr_next;
                transport_offset += header_len;
            }
            // Fragment header
            44 => {
                if payload_end < transport_offset + 8 {
                    break;
                }

                let hdr_next = data[transport_offset];
                let fragment_field =
                    u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
                let fragment_offset_units = fragment_field >> 3;

                transport_offset += 8;
                if fragment_offset_units != 0 {
                    // Non-initial fragments do not carry L4 headers.
                    non_initial_fragment = true;
                    next_header = 44;
                    break;
                }

                next_header = hdr_next;
            }
            // Authentication Header (RFC 4302): length is in 32-bit words, minus 2.
            51 => {
                if payload_end < transport_offset + 2 {
                    break;
                }
                let hdr_next = data[transport_offset];
                let payload_len_words = data[transport_offset + 1] as usize;
                let header_len = (payload_len_words + 2) * 4;
                if payload_end < transport_offset + header_len {
                    break;
                }
                next_header = hdr_next;
                transport_offset += header_len;
            }
            // ESP or No Next Header.
            50 | 59 => {
                break;
            }
            _ => {
                break;
            }
        }

        extension_headers_remaining -= 1;
    }

    Some(Ipv6PayloadInfo {
        next_header,
        transport_offset: transport_offset.min(payload_end),
        payload_end,
        non_initial_fragment,
    })
}

/// Zero-copy IPv6 header.
#[derive(Debug)]
pub struct Ipv6Header<'a> {
    data: &'a [u8],
    next_header: u8,
    payload_offset: usize,
    payload_end: usize,
    non_initial_fragment: bool,
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

        let payload_info = locate_ipv6_payload(data).expect("fixed IPv6 header was validated");

        Ok(Ipv6Header {
            data,
            next_header: payload_info.next_header,
            payload_offset: payload_info.transport_offset,
            payload_end: payload_info.payload_end,
            non_initial_fragment: payload_info.non_initial_fragment,
        })
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
        ((self.data[1] & 0x0F) as u32) << 16 | (self.data[2] as u32) << 8 | self.data[3] as u32
    }

    /// Payload length (not including the 40-byte fixed header).
    #[inline]
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Effective next header protocol number after extension-header walking.
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.next_header)
    }

    /// Effective next header raw value.
    #[inline]
    pub fn next_header_raw(&self) -> u8 {
        self.next_header
    }

    /// Whether this packet is a non-initial IPv6 fragment.
    #[inline]
    pub fn is_non_initial_fragment(&self) -> bool {
        self.non_initial_fragment
    }

    /// Offset to transport payload within the IPv6 packet bytes.
    #[inline]
    pub fn transport_offset(&self) -> usize {
        self.payload_offset
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

    /// Payload after extension headers (or after fixed header if no extension
    /// walking was possible).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[self.payload_offset..self.payload_end]
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
        assert_eq!(hdr.next_header_raw(), 6);
        assert!(!hdr.is_non_initial_fragment());
        assert_eq!(hdr.transport_offset(), IPV6_HEADER_LEN);
        assert_eq!(hdr.hop_limit(), 64);
        assert_eq!(hdr.src_addr(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(hdr.dst_addr(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));
        assert_eq!(hdr.payload().len(), 20);
    }

    #[test]
    fn parse_ipv6_hop_by_hop_to_tcp() {
        // Fixed header + Hop-by-Hop(8) + TCP(20)
        let mut pkt = vec![0u8; 40 + 8 + 20];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(28u16).to_be_bytes());
        pkt[6] = 0; // Hop-by-Hop
        pkt[7] = 64;
        pkt[23] = 1;
        pkt[39] = 2;

        let ext = 40;
        pkt[ext] = 6; // TCP
        pkt[ext + 1] = 0; // 8 bytes total

        let hdr = Ipv6Header::parse(&pkt).unwrap();
        assert_eq!(hdr.next_header(), IpProtocol::Tcp);
        assert_eq!(hdr.next_header_raw(), 6);
        assert_eq!(hdr.transport_offset(), 48);
        assert_eq!(hdr.payload().len(), 20);
    }

    #[test]
    fn parse_ipv6_non_initial_fragment() {
        // Fixed header + Fragment(8) + fragment payload(12)
        let mut pkt = vec![0u8; 40 + 8 + 12];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(20u16).to_be_bytes());
        pkt[6] = 44; // Fragment header
        pkt[7] = 64;

        let frag = 40;
        pkt[frag] = 6; // Encapsulated next header would be TCP
        // fragment offset = 1 (non-initial fragment), M flag = 0
        let fragment_field = 1u16 << 3;
        pkt[frag + 2..frag + 4].copy_from_slice(&fragment_field.to_be_bytes());

        let hdr = Ipv6Header::parse(&pkt).unwrap();
        assert!(hdr.is_non_initial_fragment());
        assert_eq!(hdr.next_header_raw(), 44);
        assert_eq!(hdr.transport_offset(), 48);
        assert_eq!(hdr.payload().len(), 12);
    }

    #[test]
    fn locate_payload_handles_truncated_extension_header() {
        // Fixed header with next-header=Hop-by-Hop, but payload is truncated.
        let mut pkt = vec![0u8; 41];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(8u16).to_be_bytes());
        pkt[6] = 0;

        let info = locate_ipv6_payload(&pkt).unwrap();
        assert_eq!(info.next_header, 0);
        assert_eq!(info.transport_offset, 40);
        assert_eq!(info.payload_end, 41);
        assert!(!info.non_initial_fragment);
    }

    #[test]
    fn reject_too_short_ipv6() {
        let pkt = [0x60; 39]; // one byte short
        assert!(Ipv6Header::parse(&pkt).is_err());
    }
}
