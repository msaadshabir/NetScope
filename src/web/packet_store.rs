//! Fixed-size packet store for on-demand detail lookups in the web dashboard.

use super::messages::StoredPacket;

/// A bounded packet store keyed by capture-wide packet id.
///
/// Internally this uses a fixed-size slot array keyed by `id % capacity`
/// with id validation on read, giving O(1) insert/lookup while still
/// tolerating out-of-order arrivals within the active id window.
#[derive(Debug)]
pub struct PacketStore {
    slots: Vec<Option<StoredPacket>>,
    capacity: usize,
    max_seen_id: Option<u64>,
}

impl PacketStore {
    pub fn new(capacity: usize) -> Self {
        PacketStore {
            slots: vec![None; capacity],
            capacity,
            max_seen_id: None,
        }
    }

    /// Push a packet into the store.
    pub fn push(&mut self, pkt: StoredPacket) {
        if self.capacity == 0 {
            return;
        }

        let current_max = self.max_seen_id.unwrap_or(pkt.id);
        let window_start = current_max.saturating_sub((self.capacity as u64).saturating_sub(1));

        // Ignore packets that are already outside the active window anchored
        // at the newest id observed so far.
        if self.max_seen_id.is_some() && pkt.id < window_start {
            return;
        }

        self.max_seen_id = Some(current_max.max(pkt.id));
        let idx = (pkt.id % self.capacity as u64) as usize;
        self.slots[idx] = Some(pkt);
    }

    /// Look up a packet by its capture-wide `id`.
    pub fn get(&self, id: u64) -> Option<&StoredPacket> {
        let max_seen_id = self.max_seen_id?;
        let window_start = max_seen_id.saturating_sub((self.capacity as u64).saturating_sub(1));
        if id < window_start {
            return None;
        }

        let idx = (id % self.capacity as u64) as usize;
        match self.slots[idx].as_ref() {
            Some(pkt) if pkt.id == id => Some(pkt),
            _ => None,
        }
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
    fn ignores_packets_outside_active_window() {
        let mut store = PacketStore::new(3);
        store.push(pkt(10));
        store.push(pkt(11));
        store.push(pkt(12));
        store.push(pkt(13));

        // Outside window [11, 13], should be ignored.
        store.push(pkt(7));

        assert!(store.get(10).is_none());
        assert!(store.get(11).is_some());
        assert!(store.get(12).is_some());
        assert!(store.get(13).is_some());
        assert!(store.get(7).is_none());
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
