//! Fixed-size ring buffer that stores recent packet details for on-demand
//! retrieval by the web dashboard.

use std::collections::VecDeque;

use super::messages::StoredPacket;

/// A bounded ring buffer of stored packets.
///
/// When capacity is exceeded, the oldest packets are evicted.
#[derive(Debug)]
pub struct PacketStore {
    buf: VecDeque<StoredPacket>,
    capacity: usize,
}

impl PacketStore {
    pub fn new(capacity: usize) -> Self {
        PacketStore {
            buf: VecDeque::with_capacity(capacity.min(8192)),
            capacity,
        }
    }

    /// Push a packet into the ring buffer, evicting the oldest if full.
    pub fn push(&mut self, pkt: StoredPacket) {
        // IDs must be monotonically increasing so binary_search_by_key stays valid.
        debug_assert!(
            self.buf.back().map_or(true, |last| last.id < pkt.id),
            "PacketStore::push: id {} is not greater than last id {}",
            pkt.id,
            self.buf.back().map_or(0, |last| last.id)
        );
        if self.buf.len() >= self.capacity {
            self.buf.pop_front();
        }
        self.buf.push_back(pkt);
    }

    /// Look up a packet by its capture-wide `id`.
    ///
    /// Because IDs are monotonically increasing and the buffer is ordered,
    /// we can binary-search.
    pub fn get(&self, id: u64) -> Option<&StoredPacket> {
        self.buf
            .binary_search_by_key(&id, |p| p.id)
            .ok()
            .map(|idx| &self.buf[idx])
    }
}
