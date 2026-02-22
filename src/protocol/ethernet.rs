//! Zero-copy Ethernet frame parser.
//!
//! An Ethernet frame has the following layout:
//!   - Destination MAC: 6 bytes
//!   - Source MAC:      6 bytes
//!   - EtherType:       2 bytes
//!   - Payload:         variable (46-1500 bytes typically)
//!
//! Total header size: 14 bytes (excluding optional VLAN tags, handled by caller)

use super::{EtherType, ParseError};
use std::fmt;

/// Minimum Ethernet header length (no VLAN tags)
pub const ETH_HEADER_LEN: usize = 14;

/// Zero-copy Ethernet header that borrows from the packet buffer.
#[derive(Debug)]
pub struct EthernetHeader<'a> {
    data: &'a [u8],
}

impl<'a> EthernetHeader<'a> {
    /// Parse an Ethernet header from a raw byte slice.
    /// Returns an error if there aren't enough bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < ETH_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: ETH_HEADER_LEN,
                actual: data.len(),
            });
        }
        Ok(EthernetHeader { data })
    }

    /// Destination MAC address as a 6-byte slice.
    #[inline]
    pub fn dst_mac(&self) -> &'a [u8] {
        &self.data[0..6]
    }

    /// Source MAC address as a 6-byte slice.
    #[inline]
    pub fn src_mac(&self) -> &'a [u8] {
        &self.data[6..12]
    }

    /// EtherType field.
    #[inline]
    pub fn ether_type(&self) -> EtherType {
        let raw = u16::from_be_bytes([self.data[12], self.data[13]]);
        EtherType::from(raw)
    }

    /// Raw EtherType as u16.
    #[inline]
    pub fn ether_type_raw(&self) -> u16 {
        u16::from_be_bytes([self.data[12], self.data[13]])
    }

    /// The payload after the Ethernet header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[ETH_HEADER_LEN..]
    }

    /// Total length of the Ethernet frame (header + payload).
    #[inline]
    pub fn total_len(&self) -> usize {
        self.data.len()
    }
}

/// Format a MAC address as xx:xx:xx:xx:xx:xx
pub fn format_mac(mac: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

impl<'a> fmt::Display for EthernetHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {} [{}]",
            format_mac(self.src_mac()),
            format_mac(self.dst_mac()),
            self.ether_type()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_ethernet_frame() {
        // Destination MAC: ff:ff:ff:ff:ff:ff (broadcast)
        // Source MAC: 00:11:22:33:44:55
        // EtherType: 0x0800 (IPv4)
        // Payload: 4 zero bytes
        let frame = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x00, // EtherType = IPv4
            0x00, 0x00, 0x00, 0x00, // payload
        ];

        let eth = EthernetHeader::parse(&frame).unwrap();
        assert_eq!(eth.dst_mac(), &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(eth.src_mac(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(eth.ether_type(), EtherType::Ipv4);
        assert_eq!(eth.payload().len(), 4);
    }

    #[test]
    fn reject_too_short_frame() {
        let frame = [0u8; 13]; // one byte too short
        assert!(EthernetHeader::parse(&frame).is_err());
    }

    #[test]
    fn parse_ipv6_ethertype() {
        let mut frame = [0u8; 14];
        frame[12] = 0x86;
        frame[13] = 0xDD;
        let eth = EthernetHeader::parse(&frame).unwrap();
        assert_eq!(eth.ether_type(), EtherType::Ipv6);
    }
}
