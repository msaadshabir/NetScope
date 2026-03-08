use ahash::AHashMap;

use crate::flow::CompactFlowKey;

#[derive(Debug, Clone, Copy)]
struct Counter {
    bytes: u64,
}

/// Streaming heavy-hitters tracker for per-tick top-flow estimation.
///
/// This uses a compact SpaceSaving-style counter set with fixed capacity so
/// updates are bounded and do not scale with total active flows.
#[derive(Debug)]
pub struct SpaceSavingTopFlows {
    capacity: usize,
    counters: AHashMap<CompactFlowKey, Counter>,
}

impl SpaceSavingTopFlows {
    pub fn new(top_n: usize) -> Self {
        let capacity = if top_n == 0 {
            0
        } else {
            top_n.saturating_mul(4).max(16)
        };

        SpaceSavingTopFlows {
            capacity,
            counters: AHashMap::with_capacity(capacity),
        }
    }

    /// Record observed bytes for a flow in the current tick window.
    pub(crate) fn observe(&mut self, key: &CompactFlowKey, bytes: u64) {
        if self.capacity == 0 || bytes == 0 {
            return;
        }

        if let Some(counter) = self.counters.get_mut(key) {
            counter.bytes = counter.bytes.saturating_add(bytes);
            return;
        }

        if self.counters.len() < self.capacity {
            self.counters.insert(key.clone(), Counter { bytes });
            return;
        }

        if let Some(min_key) = self
            .counters
            .iter()
            .min_by_key(|(_, counter)| counter.bytes)
            .map(|(key, _)| key.clone())
        {
            let min_bytes = self
                .counters
                .remove(&min_key)
                .map(|counter| counter.bytes)
                .unwrap_or(0);
            self.counters.insert(
                key.clone(),
                Counter {
                    bytes: min_bytes.saturating_add(bytes),
                },
            );
        }
    }

    /// Return top-N candidate flow keys and byte counts, then clear state.
    pub(crate) fn take_top(&mut self, n: usize) -> Vec<(CompactFlowKey, u64)> {
        if n == 0 {
            self.counters.clear();
            return Vec::new();
        }

        let mut top: Vec<(CompactFlowKey, u64)> = self
            .counters
            .iter()
            .map(|(key, counter)| (key.clone(), counter.bytes))
            .collect();

        top.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        top.truncate(n.min(top.len()));
        self.counters.clear();
        top
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{CompactFlowKey, Endpoint, FlowKey, FlowProtocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn key(a: u8, b: u8, src_port: u16, dst_port: u16) -> CompactFlowKey {
        let src = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, a)),
            port: src_port,
        };
        let dst = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, b)),
            port: dst_port,
        };
        let (k, _) = FlowKey::new(FlowProtocol::Tcp, src, dst);
        CompactFlowKey::from_flow_key(&k).unwrap()
    }

    #[test]
    fn tracks_dominant_flow() {
        let mut hh = SpaceSavingTopFlows::new(2);
        let hot = key(1, 2, 12345, 443);
        for _ in 0..100 {
            hh.observe(&hot, 1500);
        }
        for i in 3..20 {
            let cold = key(i, i + 1, 1000 + i as u16, 80);
            hh.observe(&cold, 64);
        }

        let top = hh.take_top(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, hot);
    }

    #[test]
    fn clears_after_snapshot() {
        let mut hh = SpaceSavingTopFlows::new(3);
        let flow = key(1, 2, 1111, 2222);
        hh.observe(&flow, 100);
        assert_eq!(hh.take_top(3).len(), 1);
        assert!(hh.take_top(3).is_empty());
    }
}
