//! Minimal packet key extraction for shard routing.
//!
//! We need to compute a hash of the canonical flow key (protocol + endpoints)
//! from raw bytes *without* doing a full parse. This keeps the capture thread
//! as lean as possible.

use std::hash::{Hash, Hasher};

/// Compute the shard index for a raw Ethernet frame.
///
/// Returns `shard = hash(5-tuple) % num_shards`. Falls back to a simple
/// byte-based hash if the packet cannot be quickly classified.
#[inline]
pub fn shard_for_packet(data: &[u8], num_shards: usize) -> usize {
    if num_shards == 0 {
        return 0;
    }
    let hash = fast_flow_hash(data);
    (hash as usize) % num_shards
}

/// Extract a hash of the canonical 5-tuple from raw Ethernet frame bytes.
///
/// This intentionally does minimal validation — it just reads fixed offsets
/// and produces a hash. Malformed packets get a non-ideal but still valid
/// hash (worst case: uneven shard distribution, not correctness issues).
#[inline]
fn fast_flow_hash(data: &[u8]) -> u64 {
    // Ethernet header: 14 bytes (6 dst + 6 src + 2 ethertype)
    if data.len() < 14 {
        return byte_hash(data);
    }

    let mut ether_type = u16::from_be_bytes([data[12], data[13]]);
    let mut ip_offset: usize = 14;

    // Skip 802.1Q VLAN tag
    if ether_type == 0x8100 {
        if data.len() < 18 {
            return byte_hash(data);
        }
        ether_type = u16::from_be_bytes([data[16], data[17]]);
        ip_offset = 18;
    }

    match ether_type {
        0x0800 => hash_ipv4(data, ip_offset),
        0x86DD => hash_ipv6(data, ip_offset),
        _ => byte_hash(data),
    }
}

#[inline]
fn hash_ipv4(data: &[u8], offset: usize) -> u64 {
    // IPv4 minimum: 20 bytes. We need: protocol (offset+9), src (offset+12..16), dst (offset+16..20)
    if data.len() < offset + 20 {
        return byte_hash(data);
    }

    let protocol = data[offset + 9];
    let ihl = (data[offset] & 0x0F) as usize * 4;
    let src_ip = &data[offset + 12..offset + 16];
    let dst_ip = &data[offset + 16..offset + 20];

    let transport_offset = offset + ihl;

    let (src_port, dst_port) = extract_ports(data, transport_offset, protocol);

    // Canonical ordering: always hash (min, max) so both directions map to same shard.
    let mut hasher = ahash::AHasher::default();
    protocol.hash(&mut hasher);
    if (src_ip, src_port) <= (dst_ip, dst_port) {
        src_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_ip.hash(&mut hasher);
        dst_port.hash(&mut hasher);
    } else {
        dst_ip.hash(&mut hasher);
        dst_port.hash(&mut hasher);
        src_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
    }
    hasher.finish()
}

#[inline]
fn hash_ipv6(data: &[u8], offset: usize) -> u64 {
    // IPv6 fixed header: 40 bytes. src (offset+8..24), dst (offset+24..40), next_header (offset+6)
    if data.len() < offset + 40 {
        return byte_hash(data);
    }

    let next_header = data[offset + 6];
    let src_ip = &data[offset + 8..offset + 24];
    let dst_ip = &data[offset + 24..offset + 40];

    let transport_offset = offset + 40;
    let (src_port, dst_port) = extract_ports(data, transport_offset, next_header);

    let mut hasher = ahash::AHasher::default();
    next_header.hash(&mut hasher);
    if (src_ip, src_port) <= (dst_ip, dst_port) {
        src_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_ip.hash(&mut hasher);
        dst_port.hash(&mut hasher);
    } else {
        dst_ip.hash(&mut hasher);
        dst_port.hash(&mut hasher);
        src_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
    }
    hasher.finish()
}

/// Extract src/dst ports for TCP (6) and UDP (17). Returns (0,0) otherwise.
#[inline]
fn extract_ports(data: &[u8], transport_offset: usize, ip_protocol: u8) -> (u16, u16) {
    if (ip_protocol == 6 || ip_protocol == 17) && data.len() >= transport_offset + 4 {
        let src = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
        let dst = u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
        (src, dst)
    } else {
        (0, 0)
    }
}

/// Fallback: hash the raw bytes (for non-IP or truncated packets).
#[inline]
fn byte_hash(data: &[u8]) -> u64 {
    let mut hasher = ahash::AHasher::default();
    data.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid TCP/IPv4 Ethernet frame (SYN, no payload).
    fn make_tcp_ipv4_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 20]; // eth + ipv4 + tcp

        // Ethernet: dst mac, src mac, ethertype 0x0800
        frame[12] = 0x08;
        frame[13] = 0x00;

        // IPv4: version=4, ihl=5, protocol=6 (TCP)
        frame[14] = 0x45; // version + IHL
        frame[14 + 9] = 6; // protocol = TCP
        frame[14 + 12..14 + 16].copy_from_slice(&src_ip);
        frame[14 + 16..14 + 20].copy_from_slice(&dst_ip);

        // TCP: src_port, dst_port
        let tcp_offset = 34;
        frame[tcp_offset..tcp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
        frame[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());

        frame
    }

    #[test]
    fn same_flow_same_shard() {
        let frame_ab = make_tcp_ipv4_frame([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80);
        let frame_ba = make_tcp_ipv4_frame([10, 0, 0, 2], [10, 0, 0, 1], 80, 12345);

        let shard_ab = shard_for_packet(&frame_ab, 4);
        let shard_ba = shard_for_packet(&frame_ba, 4);
        assert_eq!(
            shard_ab, shard_ba,
            "both directions of a flow must map to the same shard"
        );
    }

    #[test]
    fn different_flows_can_differ() {
        let frame_a = make_tcp_ipv4_frame([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80);
        let frame_b = make_tcp_ipv4_frame([10, 0, 0, 3], [10, 0, 0, 4], 54321, 443);

        // They *may* collide, but with 1024 shards it's astronomically unlikely.
        let shard_a = shard_for_packet(&frame_a, 1024);
        let shard_b = shard_for_packet(&frame_b, 1024);
        // We can't assert they differ (hash collision is possible) but let's
        // at least verify no panic and both are in range.
        assert!(shard_a < 1024);
        assert!(shard_b < 1024);
    }

    #[test]
    fn short_packet_no_panic() {
        let shard = shard_for_packet(&[0x08, 0x00], 4);
        assert!(shard < 4);
    }
}
