//! Zero-copy parser for loopback link types (NULL/LOOP).
//!
//! Header layout (4 bytes): protocol family followed by payload.

use super::ParseError;
use std::fmt;

pub const LOOPBACK_HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackByteOrder {
    Native,
    BigEndian,
}

#[derive(Debug)]
pub struct LoopbackHeader<'a> {
    data: &'a [u8],
    family: u32,
    byte_order: LoopbackByteOrder,
}

impl<'a> LoopbackHeader<'a> {
    pub fn parse_null(data: &'a [u8]) -> Result<Self, ParseError> {
        Self::parse_with_order(data, LoopbackByteOrder::Native)
    }

    pub fn parse_loop(data: &'a [u8]) -> Result<Self, ParseError> {
        Self::parse_with_order(data, LoopbackByteOrder::BigEndian)
    }

    fn parse_with_order(data: &'a [u8], byte_order: LoopbackByteOrder) -> Result<Self, ParseError> {
        if data.len() < LOOPBACK_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: LOOPBACK_HEADER_LEN,
                actual: data.len(),
            });
        }

        let family = match byte_order {
            LoopbackByteOrder::Native => u32::from_ne_bytes([data[0], data[1], data[2], data[3]]),
            LoopbackByteOrder::BigEndian => {
                u32::from_be_bytes([data[0], data[1], data[2], data[3]])
            }
        };

        Ok(Self {
            data,
            family,
            byte_order,
        })
    }

    #[inline]
    pub fn family_raw(&self) -> u32 {
        self.family
    }

    #[inline]
    pub fn byte_order(&self) -> LoopbackByteOrder {
        self.byte_order
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[LOOPBACK_HEADER_LEN..]
    }

    pub fn family_label(&self) -> &'static str {
        match self.family {
            2 => "AF_INET",
            // AF_INET6 uses different numeric values across platforms in loopback/null
            // headers: 10 on Linux, and 24/28/30 on BSD-derived stacks such as
            // OpenBSD/NetBSD/macOS. Accept all of them as IPv6.
            10 | 24 | 28 | 30 => "AF_INET6",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Display for LoopbackHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoding = match self.byte_order {
            LoopbackByteOrder::Native => "native-endian",
            LoopbackByteOrder::BigEndian => "big-endian",
        };
        write!(
            f,
            "Loopback family={}({}) {}",
            self.family_label(),
            self.family_raw(),
            encoding
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_null_uses_native_endian() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_ne_bytes());
        data.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]);

        let hdr = LoopbackHeader::parse_null(&data).unwrap();
        assert_eq!(hdr.family_raw(), 2);
        assert_eq!(hdr.family_label(), "AF_INET");
        assert_eq!(hdr.payload(), &[0x45, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn parse_loop_uses_big_endian() {
        let mut data = Vec::new();
        data.extend_from_slice(&30u32.to_be_bytes());
        data.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);

        let hdr = LoopbackHeader::parse_loop(&data).unwrap();
        assert_eq!(hdr.family_raw(), 30);
        assert_eq!(hdr.family_label(), "AF_INET6");
        assert_eq!(hdr.payload(), &[0x60, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn reject_too_short_loopback_header() {
        let data = [0u8; 3];
        assert!(LoopbackHeader::parse_null(&data).is_err());
    }
}
