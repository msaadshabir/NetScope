//! Fixed-size ring buffer that stores recent packet details for on-demand
//! retrieval by the web dashboard.

use std::collections::BTreeMap;

use super::messages::StoredPacket;

/// A bounded ring buffer of stored packets.
///
/// When capacity is exceeded, the oldest packets are evicted.
#[derive(Debug)]
pub struct PacketStore {
    buf: BTreeMap<u64, StoredPacket>,
    capacity: usize,
}

impl PacketStore {
    pub fn new(capacity: usize) -> Self {
        PacketStore {
            buf: BTreeMap::new(),
            capacity,
        }
    }

    /// Push a packet into the ring buffer, evicting the oldest if full.
    pub fn push(&mut self, pkt: StoredPacket) {
        if self.capacity == 0 {
            return;
        }

        self.buf.insert(pkt.id, pkt);
        while self.buf.len() > self.capacity {
            let _ = self.buf.pop_first();
        }
    }

    /// Look up a packet by its capture-wide `id`.
    pub fn get(&self, id: u64) -> Option<&StoredPacket> {
        self.buf.get(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(id: u64) -> StoredPacket {
        StoredPacket {
            id,
            ts: id as f64,
            layers: Vec::new(),
            hex_dump: String::new(),
        }
    }

    #[test]
    fn stores_out_of_order_ids() {
        let mut store = PacketStore::new(4);
        store.push(pkt(3));
        store.push(pkt(1));
        store.push(pkt(2));

        assert!(store.get(1).is_some());
        assert!(store.get(2).is_some());
        assert!(store.get(3).is_some());
    }

    #[test]
    fn evicts_lowest_ids_when_capacity_exceeded() {
        let mut store = PacketStore::new(2);
        store.push(pkt(10));
        store.push(pkt(8));
        store.push(pkt(9));

        assert!(store.get(8).is_none());
        assert!(store.get(9).is_some());
        assert!(store.get(10).is_some());
    }

    #[test]
    fn duplicate_id_replaces_existing_packet() {
        let mut store = PacketStore::new(2);
        let mut first = pkt(42);
        first.hex_dump = "old".into();
        store.push(first);

        let mut updated = pkt(42);
        updated.hex_dump = "new".into();
        store.push(updated);
        store.push(pkt(43));

        assert_eq!(store.get(42).map(|p| p.hex_dump.as_str()), Some("new"));
        assert!(store.get(43).is_some());
    }
}
