//! Zero-copy ARP packet parser.
//!
//! ARP message layout (variable length):
//!   - Hardware Type:      2 bytes
//!   - Protocol Type:      2 bytes
//!   - Hardware Addr Len:  1 byte
//!   - Protocol Addr Len:  1 byte
//!   - Operation:          2 bytes
//!   - Sender HW Addr:     HLEN bytes
//!   - Sender Proto Addr:  PLEN bytes
//!   - Target HW Addr:     HLEN bytes
//!   - Target Proto Addr:  PLEN bytes

use super::{EtherType, ParseError, ethernet};
use std::fmt;
use std::net::Ipv4Addr;

/// Minimum ARP header length without addresses.
pub const ARP_FIXED_LEN: usize = 8;

/// Common ARP operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
    Unknown(u16),
}

impl From<u16> for ArpOperation {
    fn from(value: u16) -> Self {
        match value {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            other => ArpOperation::Unknown(other),
        }
    }
}

impl fmt::Display for ArpOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpOperation::Request => write!(f, "request"),
            ArpOperation::Reply => write!(f, "reply"),
            ArpOperation::Unknown(value) => write!(f, "op({})", value),
        }
    }
}

/// Zero-copy ARP packet that borrows from the original buffer.
#[derive(Debug)]
pub struct ArpPacket<'a> {
    data: &'a [u8],
    packet_len: usize,
}

impl<'a> ArpPacket<'a> {
    /// Parse an ARP packet from a byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < ARP_FIXED_LEN {
            return Err(ParseError::TooShort {
                expected: ARP_FIXED_LEN,
                actual: data.len(),
            });
        }

        let hlen = data[4] as usize;
        let plen = data[5] as usize;

        let single_side_len = hlen
            .checked_add(plen)
            .ok_or_else(|| ParseError::InvalidHeader("invalid ARP address lengths".to_string()))?;
        let address_block_len = single_side_len
            .checked_mul(2)
            .ok_or_else(|| ParseError::InvalidHeader("invalid ARP address lengths".to_string()))?;
        let packet_len = ARP_FIXED_LEN
            .checked_add(address_block_len)
            .ok_or_else(|| ParseError::InvalidHeader("invalid ARP total length".to_string()))?;

        if data.len() < packet_len {
            return Err(ParseError::TooShort {
                expected: packet_len,
                actual: data.len(),
            });
        }

        Ok(ArpPacket { data, packet_len })
    }

    /// Hardware type (e.g., 1 for Ethernet).
    #[inline]
    pub fn hardware_type(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    /// Protocol type (commonly an EtherType, e.g. 0x0800 for IPv4).
    #[inline]
    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Hardware address length (HLEN).
    #[inline]
    pub fn hardware_len(&self) -> u8 {
        self.data[4]
    }

    /// Protocol address length (PLEN).
    #[inline]
    pub fn protocol_len(&self) -> u8 {
        self.data[5]
    }

    /// ARP operation as a typed enum.
    #[inline]
    pub fn operation(&self) -> ArpOperation {
        ArpOperation::from(self.operation_raw())
    }

    /// ARP operation as raw u16.
    #[inline]
    pub fn operation_raw(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }

    /// Number of bytes consumed by this ARP packet.
    #[inline]
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }

    /// Remaining bytes after the ARP packet.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[self.packet_len..]
    }

    /// Sender hardware address bytes.
    #[inline]
    pub fn sender_hardware_addr(&self) -> &'a [u8] {
        let hlen = self.hardware_len() as usize;
        &self.data[ARP_FIXED_LEN..ARP_FIXED_LEN + hlen]
    }

    /// Sender protocol address bytes.
    #[inline]
    pub fn sender_protocol_addr(&self) -> &'a [u8] {
        let hlen = self.hardware_len() as usize;
        let plen = self.protocol_len() as usize;
        let start = ARP_FIXED_LEN + hlen;
        &self.data[start..start + plen]
    }

    /// Target hardware address bytes.
    #[inline]
    pub fn target_hardware_addr(&self) -> &'a [u8] {
        let hlen = self.hardware_len() as usize;
        let plen = self.protocol_len() as usize;
        let start = ARP_FIXED_LEN + hlen + plen;
        &self.data[start..start + hlen]
    }

    /// Target protocol address bytes.
    #[inline]
    pub fn target_protocol_addr(&self) -> &'a [u8] {
        let hlen = self.hardware_len() as usize;
        let plen = self.protocol_len() as usize;
        let start = ARP_FIXED_LEN + hlen + plen + hlen;
        &self.data[start..start + plen]
    }

    /// Sender IPv4 address when the ARP packet carries IPv4 protocol addresses.
    #[inline]
    pub fn sender_ipv4_addr(&self) -> Option<Ipv4Addr> {
        if self.protocol_type() == 0x0800 && self.protocol_len() == 4 {
            let value = self.sender_protocol_addr();
            return Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
        }
        None
    }

    /// Target IPv4 address when the ARP packet carries IPv4 protocol addresses.
    #[inline]
    pub fn target_ipv4_addr(&self) -> Option<Ipv4Addr> {
        if self.protocol_type() == 0x0800 && self.protocol_len() == 4 {
            let value = self.target_protocol_addr();
            return Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
        }
        None
    }

    /// Human-readable hardware type label.
    #[inline]
    pub fn hardware_type_label(&self) -> &'static str {
        match self.hardware_type() {
            1 => "Ethernet",
            _ => "Unknown",
        }
    }

    /// Human-readable protocol type label.
    #[inline]
    pub fn protocol_type_label(&self) -> String {
        format!("{}", EtherType::from(self.protocol_type()))
    }

    /// Format a hardware address according to its length.
    pub fn format_hardware_addr(&self, addr: &[u8]) -> String {
        if addr.is_empty() {
            return "-".to_string();
        }

        if addr.len() == 6 {
            return ethernet::format_mac(addr);
        }

        format_byte_sequence(addr)
    }

    /// Format a protocol address according to protocol type and length.
    pub fn format_protocol_addr(&self, addr: &[u8]) -> String {
        if addr.is_empty() {
            return "-".to_string();
        }

        if self.protocol_type() == 0x0800 && addr.len() == 4 {
            return Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string();
        }

        format_byte_sequence(addr)
    }

    #[inline]
    pub fn sender_hardware_display(&self) -> String {
        self.format_hardware_addr(self.sender_hardware_addr())
    }

    #[inline]
    pub fn target_hardware_display(&self) -> String {
        self.format_hardware_addr(self.target_hardware_addr())
    }

    #[inline]
    pub fn sender_protocol_display(&self) -> String {
        self.format_protocol_addr(self.sender_protocol_addr())
    }

    #[inline]
    pub fn target_protocol_display(&self) -> String {
        self.format_protocol_addr(self.target_protocol_addr())
    }
}

impl<'a> fmt::Display for ArpPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sender_proto = self.sender_protocol_display();
        let target_proto = self.target_protocol_display();
        let sender_hw = self.sender_hardware_display();

        match self.operation() {
            ArpOperation::Request => {
                write!(
                    f,
                    "who-has {} tell {} ({})",
                    target_proto, sender_proto, sender_hw
                )
            }
            ArpOperation::Reply => {
                write!(f, "{} is-at {}", sender_proto, sender_hw)
            }
            ArpOperation::Unknown(op) => {
                write!(
                    f,
                    "{} {} -> {}",
                    ArpOperation::Unknown(op),
                    sender_proto,
                    target_proto
                )
            }
        }
    }
}

fn format_byte_sequence(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|value| format!("{:02x}", value))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arp_request() -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
        packet.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype = IPv4
        packet.push(6); // hlen
        packet.push(4); // plen
        packet.extend_from_slice(&1u16.to_be_bytes()); // operation = request
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // sha
        packet.extend_from_slice(&[192, 168, 1, 10]); // spa
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // tha
        packet.extend_from_slice(&[192, 168, 1, 1]); // tpa
        packet
    }

    #[test]
    fn parse_valid_arp_request() {
        let packet = make_arp_request();
        let arp = ArpPacket::parse(&packet).unwrap();

        assert_eq!(arp.hardware_type(), 1);
        assert_eq!(arp.protocol_type(), 0x0800);
        assert_eq!(arp.hardware_len(), 6);
        assert_eq!(arp.protocol_len(), 4);
        assert_eq!(arp.operation(), ArpOperation::Request);
        assert_eq!(arp.sender_ipv4_addr(), Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(arp.target_ipv4_addr(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(format!("{}", arp).contains("who-has"));
    }

    #[test]
    fn parse_valid_arp_reply() {
        let mut packet = make_arp_request();
        packet[6] = 0;
        packet[7] = 2; // operation = reply
        packet[8..14].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let arp = ArpPacket::parse(&packet).unwrap();

        assert_eq!(arp.operation(), ArpOperation::Reply);
        assert!(format!("{}", arp).contains("is-at"));
    }

    #[test]
    fn reject_too_short_arp() {
        let packet = [0u8; 7];
        assert!(ArpPacket::parse(&packet).is_err());
    }

    #[test]
    fn reject_truncated_variable_addresses() {
        let packet = [
            0x00, 0x01, // htype
            0x08, 0x00, // ptype
            0x06, // hlen
            0x04, // plen
            0x00, 0x01, // op
            0x00, 0x11, 0x22, // truncated addresses
        ];

        assert!(ArpPacket::parse(&packet).is_err());
    }

    #[test]
    fn parse_non_default_lengths() {
        // hlen=2, plen=3 -> packet len = 8 + 2 * (2 + 3) = 18
        let packet = [
            0x00, 0x01, // htype
            0x12, 0x34, // ptype
            0x02, // hlen
            0x03, // plen
            0x00, 0x03, // op
            0xaa, 0xbb, // sha
            0x01, 0x02, 0x03, // spa
            0xcc, 0xdd, // tha
            0x04, 0x05, 0x06, // tpa
        ];

        let arp = ArpPacket::parse(&packet).unwrap();
        assert_eq!(arp.packet_len(), 18);
        assert_eq!(arp.sender_hardware_addr(), &[0xaa, 0xbb]);
        assert_eq!(arp.target_protocol_addr(), &[0x04, 0x05, 0x06]);
    }
}
