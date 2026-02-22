//! Zero-copy TCP header parser.
//!
//! TCP header layout (20-60 bytes):
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |          Source Port          |       Destination Port        |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                        Sequence Number                       |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                    Acknowledgment Number                     |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |  Data |           |U|A|P|R|S|F|                               |
//!  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//!  |       |           |G|K|H|T|N|N|                               |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |           Checksum            |         Urgent Pointer        |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                    Options                    |    Padding    |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::ParseError;
use std::fmt;

/// Minimum TCP header length (no options)
pub const TCP_MIN_HEADER_LEN: usize = 20;

/// TCP flags bitmask constants
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// Zero-copy TCP header.
#[derive(Debug)]
pub struct TcpHeader<'a> {
    data: &'a [u8],
    header_len: usize,
}

impl<'a> TcpHeader<'a> {
    /// Parse a TCP header from a byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < TCP_MIN_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: TCP_MIN_HEADER_LEN,
                actual: data.len(),
            });
        }

        let data_offset = ((data[12] >> 4) & 0x0F) as usize;
        let header_len = data_offset * 4;

        if header_len < TCP_MIN_HEADER_LEN {
            return Err(ParseError::InvalidHeader(format!(
                "TCP data offset too small: {} (min 5)",
                data_offset
            )));
        }

        if data.len() < header_len {
            return Err(ParseError::TooShort {
                expected: header_len,
                actual: data.len(),
            });
        }

        Ok(TcpHeader { data, header_len })
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

    /// Sequence number.
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        u32::from_be_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    /// Acknowledgment number.
    #[inline]
    pub fn ack_number(&self) -> u32 {
        u32::from_be_bytes([self.data[8], self.data[9], self.data[10], self.data[11]])
    }

    /// Data offset in 32-bit words.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        (self.data[12] >> 4) & 0x0F
    }

    /// Header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Raw flags byte.
    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.data[13]
    }

    /// Check individual flags
    #[inline]
    pub fn fin(&self) -> bool {
        self.data[13] & flags::FIN != 0
    }

    #[inline]
    pub fn syn(&self) -> bool {
        self.data[13] & flags::SYN != 0
    }

    #[inline]
    pub fn rst(&self) -> bool {
        self.data[13] & flags::RST != 0
    }

    #[inline]
    pub fn psh(&self) -> bool {
        self.data[13] & flags::PSH != 0
    }

    #[inline]
    pub fn ack(&self) -> bool {
        self.data[13] & flags::ACK != 0
    }

    #[inline]
    pub fn urg(&self) -> bool {
        self.data[13] & flags::URG != 0
    }

    /// Format flags as a string like "[SYN, ACK]".
    pub fn flags_string(&self) -> String {
        let mut parts = Vec::new();
        if self.syn() {
            parts.push("SYN");
        }
        if self.ack() {
            parts.push("ACK");
        }
        if self.fin() {
            parts.push("FIN");
        }
        if self.rst() {
            parts.push("RST");
        }
        if self.psh() {
            parts.push("PSH");
        }
        if self.urg() {
            parts.push("URG");
        }
        format!("[{}]", parts.join(", "))
    }

    /// Window size.
    #[inline]
    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes([self.data[14], self.data[15]])
    }

    /// Checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[16], self.data[17]])
    }

    /// Urgent pointer.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes([self.data[18], self.data[19]])
    }

    /// TCP options bytes (if any).
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        &self.data[TCP_MIN_HEADER_LEN..self.header_len]
    }

    /// Payload after the TCP header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[self.header_len..]
    }
}

impl<'a> fmt::Display for TcpHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ":{} -> :{} {} seq={} ack={} win={}",
            self.src_port(),
            self.dst_port(),
            self.flags_string(),
            self.sequence_number(),
            self.ack_number(),
            self.window_size()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcp_syn() -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0xC0;
        pkt[1] = 0x00; // src port = 49152
        pkt[2] = 0x00;
        pkt[3] = 0x50; // dst port = 80
        // Sequence number = 1000
        pkt[4] = 0x00;
        pkt[5] = 0x00;
        pkt[6] = 0x03;
        pkt[7] = 0xE8;
        // Ack = 0
        // Data offset = 5 (20 bytes), reserved = 0
        pkt[12] = 0x50;
        // Flags: SYN
        pkt[13] = flags::SYN;
        // Window = 65535
        pkt[14] = 0xFF;
        pkt[15] = 0xFF;
        pkt
    }

    #[test]
    fn parse_tcp_syn() {
        let pkt = make_tcp_syn();
        let hdr = TcpHeader::parse(&pkt).unwrap();
        assert_eq!(hdr.src_port(), 49152);
        assert_eq!(hdr.dst_port(), 80);
        assert_eq!(hdr.sequence_number(), 1000);
        assert_eq!(hdr.ack_number(), 0);
        assert!(hdr.syn());
        assert!(!hdr.ack());
        assert!(!hdr.fin());
        assert!(!hdr.rst());
        assert_eq!(hdr.window_size(), 65535);
        assert_eq!(hdr.flags_string(), "[SYN]");
    }

    #[test]
    fn reject_short_tcp() {
        let pkt = [0u8; 19];
        assert!(TcpHeader::parse(&pkt).is_err());
    }
}
