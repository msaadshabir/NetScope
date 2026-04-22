use crate::protocol::{NetworkHeader, ParsedPacket, TransportHeader};
use ahash::{AHashMap, AHashSet};
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt;
use std::net::IpAddr;

mod export;
mod key;

pub use export::{write_flow_csv, write_flow_json};
pub(crate) use key::{CompactFlowKey, FlowKeyV4, FlowKeyV6};
pub use key::{Endpoint, FlowDirection, FlowKey, FlowProtocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    SynSent,
    SynAck,
    Established,
    FinWait,
    Closed,
    Reset,
    Unknown,
}

#[derive(Debug, Clone)]
#[repr(C)]
struct ScaleFlowEntry {
    bytes_a_to_b: u64,
    bytes_b_to_a: u64,
    stats_report_total: u64,
    web_report_total: u64,
    first_seen_ms: u32,
    last_seen_ms: u32,
    packets_a_to_b: u32,
    packets_b_to_a: u32,
    first_seen_sub_ms_us: u16,
    last_seen_sub_ms_us: u16,
    tcp_state: u8,
    client: u8,
    _pad: [u8; 2],
}

const SCALE_TCP_STATE_NONE: u8 = 7;

#[inline]
fn scale_base_ms(ts: f64) -> u64 {
    if ts.is_finite() && ts > 0.0 {
        (ts * 1000.0).floor().min(u64::MAX as f64) as u64
    } else {
        0
    }
}

#[inline]
fn scale_abs_us(ts: f64) -> u64 {
    if ts.is_finite() && ts > 0.0 {
        (ts * 1_000_000.0).round().min(u64::MAX as f64) as u64
    } else {
        0
    }
}

#[inline]
fn scale_encode_ts(ts: f64, time_base_ms: u64) -> (u32, u16) {
    let abs_us = scale_abs_us(ts);
    let base_us = time_base_ms.saturating_mul(1000);
    let offset_us = abs_us.saturating_sub(base_us);
    let offset_ms = (offset_us / 1000).min(u32::MAX as u64) as u32;
    let sub_ms_us = (offset_us % 1000) as u16;
    (offset_ms, sub_ms_us)
}

#[inline]
fn scale_decode_ts(time_base_ms: u64, offset_ms: u32, sub_ms_us: u16) -> f64 {
    let total_us = time_base_ms
        .saturating_mul(1000)
        .saturating_add(offset_ms as u64 * 1000)
        .saturating_add(sub_ms_us as u64);
    total_us as f64 / 1_000_000.0
}

#[inline]
fn scale_sort_key_us(time_base_ms: u64, offset_ms: u32, sub_ms_us: u16) -> u64 {
    time_base_ms
        .saturating_mul(1000)
        .saturating_add(offset_ms as u64 * 1000)
        .saturating_add(sub_ms_us as u64)
}

impl ScaleFlowEntry {
    fn new(ts: f64, protocol: FlowProtocol, time_base_ms: u64) -> Self {
        let (first_seen_ms, first_seen_sub_ms_us) = scale_encode_ts(ts, time_base_ms);
        let tcp_state = match protocol {
            FlowProtocol::Tcp => Some(TcpState::Unknown),
            FlowProtocol::Udp => None,
        };
        ScaleFlowEntry {
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            stats_report_total: 0,
            web_report_total: 0,
            first_seen_ms,
            last_seen_ms: first_seen_ms,
            packets_a_to_b: 0,
            packets_b_to_a: 0,
            first_seen_sub_ms_us,
            last_seen_sub_ms_us: first_seen_sub_ms_us,
            tcp_state: Self::encode_tcp_state(tcp_state),
            client: Self::encode_client(None),
            _pad: [0; 2],
        }
    }

    #[inline]
    fn observe(
        &mut self,
        ts: f64,
        time_base_ms: u64,
        direction: FlowDirection,
        bytes: u64,
        flags: Option<TcpFlags>,
    ) {
        let (last_seen_ms, last_seen_sub_ms_us) = scale_encode_ts(ts, time_base_ms);
        self.last_seen_ms = last_seen_ms;
        self.last_seen_sub_ms_us = last_seen_sub_ms_us;
        match direction {
            FlowDirection::AtoB => {
                self.packets_a_to_b = self.packets_a_to_b.saturating_add(1);
                self.bytes_a_to_b = self.bytes_a_to_b.saturating_add(bytes);
            }
            FlowDirection::BtoA => {
                self.packets_b_to_a = self.packets_b_to_a.saturating_add(1);
                self.bytes_b_to_a = self.bytes_b_to_a.saturating_add(bytes);
            }
        }
        if let Some(flags) = flags {
            let mut tcp_state = self.tcp_state();
            let mut client = self.client();
            update_tcp_state_fields(&mut tcp_state, &mut client, flags, direction);
            self.set_tcp_state(tcp_state);
            self.set_client(client);
        }
    }

    #[inline]
    fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b + self.bytes_b_to_a
    }

    #[inline]
    fn total_packets(&self) -> u64 {
        self.packets_a_to_b as u64 + self.packets_b_to_a as u64
    }

    #[inline]
    fn stats_delta(&self) -> u64 {
        self.total_bytes().saturating_sub(self.stats_report_total)
    }

    #[inline]
    fn web_delta(&self) -> u64 {
        self.total_bytes().saturating_sub(self.web_report_total)
    }

    #[inline]
    fn mark_stats_reported(&mut self) {
        self.stats_report_total = self.total_bytes();
    }

    #[inline]
    fn mark_web_reported(&mut self) {
        self.web_report_total = self.total_bytes();
    }

    #[inline]
    fn first_seen(&self, time_base_ms: u64) -> f64 {
        scale_decode_ts(time_base_ms, self.first_seen_ms, self.first_seen_sub_ms_us)
    }

    #[inline]
    fn last_seen(&self, time_base_ms: u64) -> f64 {
        scale_decode_ts(time_base_ms, self.last_seen_ms, self.last_seen_sub_ms_us)
    }

    #[inline]
    fn last_seen_sort_key(&self, time_base_ms: u64) -> u64 {
        scale_sort_key_us(time_base_ms, self.last_seen_ms, self.last_seen_sub_ms_us)
    }

    #[inline]
    fn tcp_state(&self) -> Option<TcpState> {
        Self::decode_tcp_state(self.tcp_state)
    }

    #[inline]
    fn set_tcp_state(&mut self, state: Option<TcpState>) {
        self.tcp_state = Self::encode_tcp_state(state);
    }

    #[inline]
    fn client(&self) -> Option<FlowDirection> {
        Self::decode_client(self.client)
    }

    #[inline]
    fn set_client(&mut self, client: Option<FlowDirection>) {
        self.client = Self::encode_client(client);
    }

    #[inline]
    fn encode_tcp_state(state: Option<TcpState>) -> u8 {
        match state {
            Some(TcpState::SynSent) => 0,
            Some(TcpState::SynAck) => 1,
            Some(TcpState::Established) => 2,
            Some(TcpState::FinWait) => 3,
            Some(TcpState::Closed) => 4,
            Some(TcpState::Reset) => 5,
            Some(TcpState::Unknown) => 6,
            None => SCALE_TCP_STATE_NONE,
        }
    }

    #[inline]
    fn decode_tcp_state(code: u8) -> Option<TcpState> {
        match code {
            0 => Some(TcpState::SynSent),
            1 => Some(TcpState::SynAck),
            2 => Some(TcpState::Established),
            3 => Some(TcpState::FinWait),
            4 => Some(TcpState::Closed),
            5 => Some(TcpState::Reset),
            6 => Some(TcpState::Unknown),
            _ => None,
        }
    }

    #[inline]
    fn encode_client(client: Option<FlowDirection>) -> u8 {
        match client {
            Some(FlowDirection::AtoB) => 1,
            Some(FlowDirection::BtoA) => 2,
            None => 0,
        }
    }

    #[inline]
    fn decode_client(code: u8) -> Option<FlowDirection> {
        match code {
            1 => Some(FlowDirection::AtoB),
            2 => Some(FlowDirection::BtoA),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowEntry {
    pub first_seen: f64,
    pub last_seen: f64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub tcp_state: Option<TcpState>,
    pub client: Option<FlowDirection>,
    pub retransmissions: u64,
    pub out_of_order: u64,
    pub rtt_last_ms: Option<f64>,
    pub rtt_min_ms: Option<f64>,
    pub rtt_ewma_ms: Option<f64>,
    pub rtt_samples: u64,
    #[serde(skip)]
    last_report_bytes_stats: u64,
    #[serde(skip)]
    last_report_bytes_web: u64,
    #[serde(skip)]
    a_to_b_seq: TcpSeqTracker,
    #[serde(skip)]
    b_to_a_seq: TcpSeqTracker,
}

impl FlowEntry {
    fn new(ts: f64, protocol: FlowProtocol) -> Self {
        FlowEntry {
            first_seen: ts,
            last_seen: ts,
            packets_a_to_b: 0,
            packets_b_to_a: 0,
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            tcp_state: match protocol {
                FlowProtocol::Tcp => Some(TcpState::Unknown),
                FlowProtocol::Udp => None,
            },
            client: None,
            retransmissions: 0,
            out_of_order: 0,
            rtt_last_ms: None,
            rtt_min_ms: None,
            rtt_ewma_ms: None,
            rtt_samples: 0,
            last_report_bytes_stats: 0,
            last_report_bytes_web: 0,
            a_to_b_seq: TcpSeqTracker::new(),
            b_to_a_seq: TcpSeqTracker::new(),
        }
    }

    #[inline]
    fn observe(&mut self, ts: f64, direction: FlowDirection, bytes: u64, flags: Option<TcpFlags>) {
        self.last_seen = ts;
        match direction {
            FlowDirection::AtoB => {
                self.packets_a_to_b += 1;
                self.bytes_a_to_b += bytes;
            }
            FlowDirection::BtoA => {
                self.packets_b_to_a += 1;
                self.bytes_b_to_a += bytes;
            }
        }
        if let Some(flags) = flags {
            self.update_tcp_state(flags, direction);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_tcp(
        &mut self,
        ts: f64,
        direction: FlowDirection,
        seq: u32,
        ack: Option<u32>,
        seq_len: u32,
        track_rtt: bool,
        track_retrans: bool,
        track_out_of_order: bool,
    ) {
        // Accumulate RTT updates and seq-tracker deltas into plain scalars so
        // no heap allocation is needed on the hot path.
        let mut rtt_last: Option<f64> = None;
        let mut rtt_min: Option<f64> = None;
        let mut rtt_ewma: Option<f64> = self.rtt_ewma_ms;
        let mut rtt_count: u64 = 0;
        let mut retrans_delta: u64 = 0;
        let mut ooo_delta: u64 = 0;

        {
            let (sender, receiver) = match direction {
                FlowDirection::AtoB => (&mut self.a_to_b_seq, &mut self.b_to_a_seq),
                FlowDirection::BtoA => (&mut self.b_to_a_seq, &mut self.a_to_b_seq),
            };

            if let Some(ack_no) = ack {
                if track_rtt {
                    // Stream RTT samples via callback — no Vec allocation.
                    let rtt_min_prev = self.rtt_min_ms;
                    receiver.on_ack(ts, ack_no, |rtt_ms| {
                        rtt_last = Some(rtt_ms);
                        rtt_min = Some(match rtt_min_prev.or(rtt_min) {
                            Some(prev_min) => prev_min.min(rtt_ms),
                            None => rtt_ms,
                        });
                        rtt_ewma = Some(match rtt_ewma {
                            Some(prev) => 0.875 * prev + 0.125 * rtt_ms,
                            None => rtt_ms,
                        });
                        rtt_count += 1;
                    });
                }
                if track_retrans || track_out_of_order {
                    receiver.last_ack = Some(ack_no);
                }
            }

            if seq_len > 0 {
                let seq_end = seq.wrapping_add(seq_len);
                let peer_ack = sender.last_ack;
                let status = sender.on_segment(seq_end, peer_ack);
                match status {
                    SeqStatus::Advanced => {
                        if track_rtt {
                            sender.push_sample(seq_end, ts);
                        }
                    }
                    SeqStatus::Retransmission => {
                        if track_retrans {
                            retrans_delta = 1;
                        }
                    }
                    SeqStatus::OutOfOrder => {
                        if track_out_of_order {
                            ooo_delta = 1;
                        }
                    }
                }
            }
        }

        // Write RTT results back to self — no intermediate Vec needed.
        if rtt_count > 0 {
            self.rtt_last_ms = rtt_last;
            if let Some(m) = rtt_min {
                self.rtt_min_ms = Some(self.rtt_min_ms.map_or(m, |prev| prev.min(m)));
            }
            self.rtt_ewma_ms = rtt_ewma;
            self.rtt_samples += rtt_count;
        }
        self.retransmissions += retrans_delta;
        self.out_of_order += ooo_delta;
    }

    fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b + self.bytes_b_to_a
    }

    fn total_packets(&self) -> u64 {
        self.packets_a_to_b + self.packets_b_to_a
    }

    fn update_tcp_state(&mut self, flags: TcpFlags, direction: FlowDirection) {
        update_tcp_state_fields(&mut self.tcp_state, &mut self.client, flags, direction);
    }
}

fn update_tcp_state_fields(
    tcp_state: &mut Option<TcpState>,
    client: &mut Option<FlowDirection>,
    flags: TcpFlags,
    direction: FlowDirection,
) {
    if flags.rst {
        *tcp_state = Some(TcpState::Reset);
        return;
    }
    if flags.syn && !flags.ack {
        if client.is_none() {
            *client = Some(direction);
        }
        *tcp_state = Some(TcpState::SynSent);
        return;
    }
    if flags.syn && flags.ack {
        *tcp_state = Some(TcpState::SynAck);
        return;
    }
    if flags.fin {
        match tcp_state {
            Some(TcpState::FinWait) => {
                // Second FIN seen (other direction) — move to Closed
                *tcp_state = Some(TcpState::Closed);
            }
            _ => {
                *tcp_state = Some(TcpState::FinWait);
            }
        }
        return;
    }
    if flags.ack {
        if !matches!(
            tcp_state,
            Some(TcpState::Reset | TcpState::Closed | TcpState::FinWait)
        ) {
            *tcp_state = Some(TcpState::Established);
        }
        return;
    }
    if tcp_state.is_none() {
        *tcp_state = Some(TcpState::Unknown);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowSnapshot {
    pub protocol: FlowProtocol,
    pub endpoint_a: Endpoint,
    pub endpoint_b: Endpoint,
    pub first_seen: f64,
    pub last_seen: f64,
    pub duration_secs: f64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub packets_total: u64,
    pub bytes_total: u64,
    pub avg_bps: f64,
    pub tcp_state: Option<TcpState>,
    pub client: Option<FlowDirection>,
    pub retransmissions: u64,
    pub out_of_order: u64,
    pub rtt_last_ms: Option<f64>,
    pub rtt_min_ms: Option<f64>,
    pub rtt_ewma_ms: Option<f64>,
    pub rtt_samples: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiredFlowReason {
    Timeout,
    Eviction,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpiredFlowEvent {
    pub ts: f64,
    pub reason: ExpiredFlowReason,
    #[serde(flatten)]
    pub flow: FlowSnapshot,
}

#[derive(Debug, Clone)]
pub struct FlowDelta {
    pub key: FlowKey,
    pub delta_bytes: u64,
}

#[derive(Debug)]
enum FlowStore {
    Full(AHashMap<FlowKey, FlowEntry>),
    Scale {
        time_base_ms: u64,
        flows_v4: AHashMap<FlowKeyV4, ScaleFlowEntry>,
        flows_v6: AHashMap<FlowKeyV6, ScaleFlowEntry>,
    },
}

#[derive(Debug, Clone, Copy)]
enum ParsedFlowIps {
    V4(std::net::Ipv4Addr, std::net::Ipv4Addr),
    V6(std::net::Ipv6Addr, std::net::Ipv6Addr),
}

#[derive(Debug)]
pub struct FlowTracker {
    store: FlowStore,
    timeout_secs: f64,
    max_flows: usize,
    last_prune: f64,
    track_rtt: bool,
    track_retrans: bool,
    track_out_of_order: bool,
}

impl FlowTracker {
    pub fn new(
        timeout_secs: f64,
        max_flows: usize,
        track_rtt: bool,
        track_retrans: bool,
        track_out_of_order: bool,
    ) -> Self {
        // Pre-size the map to avoid rehash churn on the hot path.
        // Add 25% headroom so inserts near `max_flows` don't trigger a resize.
        let initial_capacity = if max_flows > 0 {
            max_flows + max_flows / 4
        } else {
            0
        };
        let scale_mode = !track_rtt && !track_retrans && !track_out_of_order;
        let store = if scale_mode {
            FlowStore::Scale {
                time_base_ms: 0,
                flows_v4: AHashMap::with_capacity(initial_capacity),
                flows_v6: AHashMap::with_capacity(initial_capacity / 8),
            }
        } else {
            FlowStore::Full(AHashMap::with_capacity(initial_capacity))
        };

        FlowTracker {
            store,
            timeout_secs,
            max_flows,
            last_prune: 0.0,
            track_rtt,
            track_retrans,
            track_out_of_order,
        }
    }

    pub fn len(&self) -> usize {
        match &self.store {
            FlowStore::Full(flows) => flows.len(),
            FlowStore::Scale {
                flows_v4, flows_v6, ..
            } => flows_v4.len() + flows_v6.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_scale_mode(&self) -> bool {
        matches!(self.store, FlowStore::Scale { .. })
    }

    /// Insert synthetic IPv4 flows directly into the table.
    ///
    /// This is used by memory verification tooling to stress the storage layer
    /// without protocol parsing overhead.
    pub fn insert_synthetic_ipv4_flows(&mut self, count: usize) {
        #[inline]
        fn ip_from_index(prefix_a: u8, prefix_b: u8, idx: u32) -> std::net::Ipv4Addr {
            std::net::Ipv4Addr::new(
                prefix_a,
                prefix_b,
                ((idx >> 8) & 0xFF) as u8,
                (idx & 0xFF) as u8,
            )
        }

        match &mut self.store {
            FlowStore::Scale {
                time_base_ms,
                flows_v4,
                ..
            } => {
                if *time_base_ms == 0 {
                    *time_base_ms = scale_base_ms(0.0);
                }
                for i in 0..count as u32 {
                    let src_ip = ip_from_index(10, ((i >> 16) & 0xFF) as u8, i);
                    let dst_ip = ip_from_index(172, 16, i);
                    let src_port = 1024 + (i % 48_000) as u16;
                    let dst_port = 80;
                    let (key, _dir) =
                        FlowKeyV4::new(FlowProtocol::Tcp, src_ip, src_port, dst_ip, dst_port);
                    let base = *time_base_ms;
                    flows_v4
                        .entry(key)
                        .or_insert_with(|| ScaleFlowEntry::new(0.0, FlowProtocol::Tcp, base));
                }
            }
            FlowStore::Full(flows) => {
                for i in 0..count as u32 {
                    let src = Endpoint {
                        ip: IpAddr::V4(ip_from_index(10, ((i >> 16) & 0xFF) as u8, i)),
                        port: 1024 + (i % 48_000) as u16,
                    };
                    let dst = Endpoint {
                        ip: IpAddr::V4(ip_from_index(172, 16, i)),
                        port: 80,
                    };
                    let (key, _dir) = FlowKey::new(FlowProtocol::Tcp, src, dst);
                    flows
                        .entry(key)
                        .or_insert_with(|| FlowEntry::new(0.0, FlowProtocol::Tcp));
                }
            }
        }
    }

    #[inline]
    pub fn observe(&mut self, ts: f64, wire_len: u64, packet: &ParsedPacket<'_>) {
        let (ips, skip_flow) = match &packet.network {
            Some(NetworkHeader::Ipv4(hdr)) => {
                let skip = hdr.fragment_offset() != 0;
                (ParsedFlowIps::V4(hdr.src_addr(), hdr.dst_addr()), skip)
            }
            Some(NetworkHeader::Ipv6(hdr)) => (
                ParsedFlowIps::V6(hdr.src_addr(), hdr.dst_addr()),
                hdr.is_non_initial_fragment(),
            ),
            None => return,
        };

        if skip_flow {
            return;
        }

        let (src_port, dst_port, protocol, flags, seq, ack, seq_len) = match &packet.transport {
            Some(TransportHeader::Tcp(hdr)) => (
                hdr.src_port(),
                hdr.dst_port(),
                FlowProtocol::Tcp,
                Some(TcpFlags::from_tcp(hdr)),
                Some(hdr.sequence_number()),
                if hdr.ack() {
                    Some(hdr.ack_number())
                } else {
                    None
                },
                Some(tcp_sequence_len(hdr, packet.network.as_ref())),
            ),
            Some(TransportHeader::Udp(hdr)) => (
                hdr.src_port(),
                hdr.dst_port(),
                FlowProtocol::Udp,
                None,
                None,
                None,
                None,
            ),
            _ => return,
        };

        match &mut self.store {
            FlowStore::Full(flows) => {
                let (src_ip, dst_ip) = match ips {
                    ParsedFlowIps::V4(src, dst) => (IpAddr::V4(src), IpAddr::V4(dst)),
                    ParsedFlowIps::V6(src, dst) => (IpAddr::V6(src), IpAddr::V6(dst)),
                };

                let src = Endpoint {
                    ip: src_ip,
                    port: src_port,
                };
                let dst = Endpoint {
                    ip: dst_ip,
                    port: dst_port,
                };

                let (key, direction) = FlowKey::new(protocol, src, dst);
                let entry = flows
                    .entry(key)
                    .or_insert_with(|| FlowEntry::new(ts, protocol));
                entry.observe(ts, direction, wire_len, flags);
                if protocol == FlowProtocol::Tcp
                    && let (Some(seq), Some(seq_len)) = (seq, seq_len)
                    && (self.track_rtt || self.track_retrans || self.track_out_of_order)
                {
                    entry.observe_tcp(
                        ts,
                        direction,
                        seq,
                        ack,
                        seq_len,
                        self.track_rtt,
                        self.track_retrans,
                        self.track_out_of_order,
                    );
                }
            }
            FlowStore::Scale {
                time_base_ms,
                flows_v4,
                flows_v6,
            } => {
                if *time_base_ms == 0 {
                    *time_base_ms = scale_base_ms(ts);
                }
                let base = *time_base_ms;

                match ips {
                    ParsedFlowIps::V4(src_ip, dst_ip) => {
                        let (key, direction) =
                            FlowKeyV4::new(protocol, src_ip, src_port, dst_ip, dst_port);
                        let entry = flows_v4
                            .entry(key)
                            .or_insert_with(|| ScaleFlowEntry::new(ts, protocol, base));
                        entry.observe(ts, base, direction, wire_len, flags);
                    }
                    ParsedFlowIps::V6(src_ip, dst_ip) => {
                        let (key, direction) =
                            FlowKeyV6::new(protocol, src_ip, src_port, dst_ip, dst_port);
                        let entry = flows_v6
                            .entry(key)
                            .or_insert_with(|| ScaleFlowEntry::new(ts, protocol, base));
                        entry.observe(ts, base, direction, wire_len, flags);
                    }
                }
            }
        }
    }

    pub fn maybe_expire(&mut self, now: f64) -> usize {
        self.maybe_expire_inner(now, None)
    }

    pub fn maybe_expire_collect(&mut self, now: f64, out: &mut Vec<ExpiredFlowEvent>) -> usize {
        self.maybe_expire_inner(now, Some(out))
    }

    fn maybe_expire_inner(
        &mut self,
        now: f64,
        mut out: Option<&mut Vec<ExpiredFlowEvent>>,
    ) -> usize {
        if now < self.last_prune {
            self.last_prune = now;
            return 0;
        }
        if now - self.last_prune < 1.0 {
            return 0;
        }
        self.last_prune = now;

        let mut record_expired = |reason: ExpiredFlowReason, flow: FlowSnapshot| {
            if let Some(buf) = out.as_mut() {
                (**buf).push(ExpiredFlowEvent {
                    ts: now,
                    reason,
                    flow,
                });
            }
        };

        let mut removed = 0;
        match &mut self.store {
            FlowStore::Full(flows) => {
                if self.timeout_secs > 0.0 {
                    let timeout_keys: Vec<FlowKey> = flows
                        .iter()
                        .filter_map(|(key, entry)| {
                            if now - entry.last_seen > self.timeout_secs {
                                Some(key.clone())
                            } else {
                                None
                            }
                        })
                        .collect();

                    for key in timeout_keys {
                        if let Some(entry) = flows.remove(&key) {
                            removed += 1;
                            record_expired(
                                ExpiredFlowReason::Timeout,
                                FlowSnapshot::from_entry(&key, &entry),
                            );
                        }
                    }
                }

                if self.max_flows > 0 && flows.len() > self.max_flows {
                    let mut entries: Vec<(FlowKey, f64)> = flows
                        .iter()
                        .map(|(key, entry)| (key.clone(), entry.last_seen))
                        .collect();
                    entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal));
                    let excess = flows.len() - self.max_flows;
                    for (key, _) in entries.into_iter().take(excess) {
                        if let Some(entry) = flows.remove(&key) {
                            removed += 1;
                            record_expired(
                                ExpiredFlowReason::Eviction,
                                FlowSnapshot::from_entry(&key, &entry),
                            );
                        }
                    }
                }
            }
            FlowStore::Scale {
                time_base_ms,
                flows_v4,
                flows_v6,
            } => {
                if self.timeout_secs > 0.0 {
                    let mut timeout_keys: Vec<CompactFlowKey> =
                        Vec::with_capacity(flows_v4.len() + flows_v6.len());
                    timeout_keys.extend(flows_v4.iter().filter_map(|(key, entry)| {
                        if now - entry.last_seen(*time_base_ms) > self.timeout_secs {
                            Some(CompactFlowKey::V4(*key))
                        } else {
                            None
                        }
                    }));
                    timeout_keys.extend(flows_v6.iter().filter_map(|(key, entry)| {
                        if now - entry.last_seen(*time_base_ms) > self.timeout_secs {
                            Some(CompactFlowKey::V6(*key))
                        } else {
                            None
                        }
                    }));

                    for key in timeout_keys {
                        match key {
                            CompactFlowKey::V4(v4) => {
                                if let Some(entry) = flows_v4.remove(&v4) {
                                    removed += 1;
                                    let flow_key = CompactFlowKey::V4(v4).to_flow_key();
                                    record_expired(
                                        ExpiredFlowReason::Timeout,
                                        FlowSnapshot::from_scale_entry(
                                            &flow_key,
                                            &entry,
                                            *time_base_ms,
                                        ),
                                    );
                                }
                            }
                            CompactFlowKey::V6(v6) => {
                                if let Some(entry) = flows_v6.remove(&v6) {
                                    removed += 1;
                                    let flow_key = CompactFlowKey::V6(v6).to_flow_key();
                                    record_expired(
                                        ExpiredFlowReason::Timeout,
                                        FlowSnapshot::from_scale_entry(
                                            &flow_key,
                                            &entry,
                                            *time_base_ms,
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }

                let total_len = flows_v4.len() + flows_v6.len();
                if self.max_flows > 0 && total_len > self.max_flows {
                    let mut entries: Vec<(CompactFlowKey, u64)> = Vec::with_capacity(total_len);
                    entries.extend(flows_v4.iter().map(|(key, entry)| {
                        (
                            CompactFlowKey::V4(*key),
                            entry.last_seen_sort_key(*time_base_ms),
                        )
                    }));
                    entries.extend(flows_v6.iter().map(|(key, entry)| {
                        (
                            CompactFlowKey::V6(*key),
                            entry.last_seen_sort_key(*time_base_ms),
                        )
                    }));
                    entries.sort_unstable_by(|a, b| a.1.cmp(&b.1));
                    let excess = total_len - self.max_flows;
                    for (key, _) in entries.into_iter().take(excess) {
                        match key {
                            CompactFlowKey::V4(v4) => {
                                if let Some(entry) = flows_v4.remove(&v4) {
                                    removed += 1;
                                    let flow_key = CompactFlowKey::V4(v4).to_flow_key();
                                    record_expired(
                                        ExpiredFlowReason::Eviction,
                                        FlowSnapshot::from_scale_entry(
                                            &flow_key,
                                            &entry,
                                            *time_base_ms,
                                        ),
                                    );
                                }
                            }
                            CompactFlowKey::V6(v6) => {
                                if let Some(entry) = flows_v6.remove(&v6) {
                                    removed += 1;
                                    let flow_key = CompactFlowKey::V6(v6).to_flow_key();
                                    record_expired(
                                        ExpiredFlowReason::Eviction,
                                        FlowSnapshot::from_scale_entry(
                                            &flow_key,
                                            &entry,
                                            *time_base_ms,
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        removed
    }

    pub fn top_flows_by_delta(&mut self, n: usize) -> Vec<FlowDelta> {
        if n == 0 {
            return Vec::new();
        }
        match &mut self.store {
            FlowStore::Full(flows) => {
                let mut deltas: Vec<FlowDelta> = flows
                    .iter()
                    .filter_map(|(key, entry)| {
                        let total = entry.total_bytes();
                        let delta = total.saturating_sub(entry.last_report_bytes_stats);
                        if delta > 0 {
                            Some(FlowDelta {
                                key: key.clone(),
                                delta_bytes: delta,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();

                let top_n = n.min(deltas.len());
                if top_n > 0 && top_n < deltas.len() {
                    deltas.select_nth_unstable_by(top_n - 1, |a, b| {
                        b.delta_bytes.cmp(&a.delta_bytes)
                    });
                    deltas.truncate(top_n);
                }
                deltas.sort_unstable_by(|a, b| b.delta_bytes.cmp(&a.delta_bytes));

                for d in &deltas {
                    if let Some(entry) = flows.get_mut(&d.key) {
                        entry.last_report_bytes_stats = entry.total_bytes();
                    }
                }
                deltas
            }
            FlowStore::Scale {
                flows_v4, flows_v6, ..
            } => {
                let mut deltas: Vec<(CompactFlowKey, u64)> = Vec::new();
                deltas.extend(flows_v4.iter().filter_map(|(key, entry)| {
                    let delta = entry.stats_delta();
                    if delta > 0 {
                        Some((CompactFlowKey::V4(*key), delta))
                    } else {
                        None
                    }
                }));
                deltas.extend(flows_v6.iter().filter_map(|(key, entry)| {
                    let delta = entry.stats_delta();
                    if delta > 0 {
                        Some((CompactFlowKey::V6(*key), delta))
                    } else {
                        None
                    }
                }));

                let top_n = n.min(deltas.len());
                if top_n > 0 && top_n < deltas.len() {
                    deltas.select_nth_unstable_by(top_n - 1, |a, b| b.1.cmp(&a.1));
                    deltas.truncate(top_n);
                }
                deltas.sort_unstable_by(|a, b| b.1.cmp(&a.1));

                for (key, _) in &deltas {
                    match key {
                        CompactFlowKey::V4(k) => {
                            if let Some(entry) = flows_v4.get_mut(k) {
                                entry.mark_stats_reported();
                            }
                        }
                        CompactFlowKey::V6(k) => {
                            if let Some(entry) = flows_v6.get_mut(k) {
                                entry.mark_stats_reported();
                            }
                        }
                    }
                }

                deltas
                    .into_iter()
                    .map(|(key, delta_bytes)| FlowDelta {
                        key: key.to_flow_key(),
                        delta_bytes,
                    })
                    .collect()
            }
        }
    }

    /// Return top-N flows by delta bytes, paired with their full snapshot.
    ///
    /// This resets the delta counters for the returned flows (same as
    /// `top_flows_by_delta`) but also produces the `FlowSnapshot` the web
    /// dashboard needs.
    pub fn top_flows_with_snapshot(&mut self, n: usize) -> Vec<(FlowDelta, FlowSnapshot)> {
        if n == 0 {
            return Vec::new();
        }
        match &mut self.store {
            FlowStore::Full(flows) => {
                let mut deltas: Vec<FlowDelta> = flows
                    .iter()
                    .filter_map(|(key, entry)| {
                        let total = entry.total_bytes();
                        let delta = total.saturating_sub(entry.last_report_bytes_web);
                        if delta > 0 {
                            Some(FlowDelta {
                                key: key.clone(),
                                delta_bytes: delta,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();

                let top_n = n.min(deltas.len());
                if top_n > 0 && top_n < deltas.len() {
                    deltas.select_nth_unstable_by(top_n - 1, |a, b| {
                        b.delta_bytes.cmp(&a.delta_bytes)
                    });
                    deltas.truncate(top_n);
                }
                deltas.sort_unstable_by(|a, b| b.delta_bytes.cmp(&a.delta_bytes));

                let mut result = Vec::with_capacity(deltas.len());
                for d in deltas {
                    if let Some(entry) = flows.get_mut(&d.key) {
                        entry.last_report_bytes_web = entry.total_bytes();
                        let snap = FlowSnapshot::from_entry(&d.key, entry);
                        result.push((d, snap));
                    }
                }
                result
            }
            FlowStore::Scale {
                time_base_ms,
                flows_v4,
                flows_v6,
            } => {
                let mut deltas: Vec<(CompactFlowKey, u64)> = Vec::new();
                deltas.extend(flows_v4.iter().filter_map(|(key, entry)| {
                    let delta = entry.web_delta();
                    if delta > 0 {
                        Some((CompactFlowKey::V4(*key), delta))
                    } else {
                        None
                    }
                }));
                deltas.extend(flows_v6.iter().filter_map(|(key, entry)| {
                    let delta = entry.web_delta();
                    if delta > 0 {
                        Some((CompactFlowKey::V6(*key), delta))
                    } else {
                        None
                    }
                }));

                let top_n = n.min(deltas.len());
                if top_n > 0 && top_n < deltas.len() {
                    deltas.select_nth_unstable_by(top_n - 1, |a, b| b.1.cmp(&a.1));
                    deltas.truncate(top_n);
                }
                deltas.sort_unstable_by(|a, b| b.1.cmp(&a.1));

                let mut result = Vec::with_capacity(deltas.len());
                for (compact_key, delta_bytes) in deltas {
                    match compact_key {
                        CompactFlowKey::V4(key) => {
                            if let Some(entry) = flows_v4.get_mut(&key) {
                                entry.mark_web_reported();
                                let flow_key = CompactFlowKey::V4(key).to_flow_key();
                                let snap =
                                    FlowSnapshot::from_scale_entry(&flow_key, entry, *time_base_ms);
                                result.push((
                                    FlowDelta {
                                        key: flow_key,
                                        delta_bytes,
                                    },
                                    snap,
                                ));
                            }
                        }
                        CompactFlowKey::V6(key) => {
                            if let Some(entry) = flows_v6.get_mut(&key) {
                                entry.mark_web_reported();
                                let flow_key = CompactFlowKey::V6(key).to_flow_key();
                                let snap =
                                    FlowSnapshot::from_scale_entry(&flow_key, entry, *time_base_ms);
                                result.push((
                                    FlowDelta {
                                        key: flow_key,
                                        delta_bytes,
                                    },
                                    snap,
                                ));
                            }
                        }
                    }
                }
                result
            }
        }
    }

    pub fn snapshot(&self) -> Vec<FlowSnapshot> {
        let mut flows: Vec<FlowSnapshot> = match &self.store {
            FlowStore::Full(table) => table
                .iter()
                .map(|(key, entry)| FlowSnapshot::from_entry(key, entry))
                .collect(),
            FlowStore::Scale {
                time_base_ms,
                flows_v4,
                flows_v6,
                ..
            } => {
                let mut out = Vec::with_capacity(flows_v4.len() + flows_v6.len());
                out.extend(flows_v4.iter().map(|(key, entry)| {
                    let flow_key = CompactFlowKey::V4(*key).to_flow_key();
                    FlowSnapshot::from_scale_entry(&flow_key, entry, *time_base_ms)
                }));
                out.extend(flows_v6.iter().map(|(key, entry)| {
                    let flow_key = CompactFlowKey::V6(*key).to_flow_key();
                    FlowSnapshot::from_scale_entry(&flow_key, entry, *time_base_ms)
                }));
                out
            }
        };
        flows.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));
        flows
    }

    /// Build exact web deltas + snapshots for a specific set of candidate keys.
    ///
    /// This keeps the web-path cost proportional to the candidate set size
    /// rather than the full flow table, while preserving exact displayed rates.
    pub fn top_flows_with_snapshot_for_keys(
        &mut self,
        keys: &[FlowKey],
        n: usize,
    ) -> Vec<(FlowDelta, FlowSnapshot)> {
        let compact_keys: Vec<CompactFlowKey> = keys
            .iter()
            .filter_map(CompactFlowKey::from_flow_key)
            .collect();
        self.top_flows_with_snapshot_for_compact_keys(&compact_keys, n)
    }

    pub(crate) fn top_flows_with_snapshot_for_compact_keys(
        &mut self,
        keys: &[CompactFlowKey],
        n: usize,
    ) -> Vec<(FlowDelta, FlowSnapshot)> {
        if n == 0 {
            return Vec::new();
        }

        match &mut self.store {
            FlowStore::Full(flows) => {
                let mut seen = AHashSet::with_capacity(keys.len());
                let mut out = Vec::with_capacity(keys.len());
                for compact_key in keys {
                    if !seen.insert(*compact_key) {
                        continue;
                    }
                    let key = compact_key.to_flow_key();
                    if let Some(entry) = flows.get_mut(&key) {
                        let total = entry.total_bytes();
                        let delta = total.saturating_sub(entry.last_report_bytes_web);
                        if delta > 0 {
                            out.push((
                                FlowDelta {
                                    key: key.clone(),
                                    delta_bytes: delta,
                                },
                                FlowSnapshot::from_entry(&key, entry),
                            ));
                        }
                    }
                }

                out.sort_unstable_by(|a, b| b.0.delta_bytes.cmp(&a.0.delta_bytes));
                out.truncate(n.min(out.len()));

                for (delta, _) in &out {
                    if let Some(entry) = flows.get_mut(&delta.key) {
                        entry.last_report_bytes_web = entry.total_bytes();
                    }
                }

                out
            }
            FlowStore::Scale {
                time_base_ms,
                flows_v4,
                flows_v6,
            } => {
                let mut seen = AHashSet::with_capacity(keys.len());
                let mut out: Vec<(CompactFlowKey, u64, FlowSnapshot)> =
                    Vec::with_capacity(keys.len());

                for compact_key in keys {
                    if !seen.insert(*compact_key) {
                        continue;
                    }

                    match compact_key {
                        CompactFlowKey::V4(k) => {
                            if let Some(entry) = flows_v4.get_mut(k) {
                                let delta = entry.web_delta();
                                if delta > 0 {
                                    let flow_key = CompactFlowKey::V4(*k).to_flow_key();
                                    out.push((
                                        CompactFlowKey::V4(*k),
                                        delta,
                                        FlowSnapshot::from_scale_entry(
                                            &flow_key,
                                            entry,
                                            *time_base_ms,
                                        ),
                                    ));
                                }
                            }
                        }
                        CompactFlowKey::V6(k) => {
                            if let Some(entry) = flows_v6.get_mut(k) {
                                let delta = entry.web_delta();
                                if delta > 0 {
                                    let flow_key = CompactFlowKey::V6(*k).to_flow_key();
                                    out.push((
                                        CompactFlowKey::V6(*k),
                                        delta,
                                        FlowSnapshot::from_scale_entry(
                                            &flow_key,
                                            entry,
                                            *time_base_ms,
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                }

                out.sort_unstable_by(|a, b| b.1.cmp(&a.1));
                out.truncate(n.min(out.len()));

                for (compact_key, _, _) in &out {
                    match compact_key {
                        CompactFlowKey::V4(k) => {
                            if let Some(entry) = flows_v4.get_mut(k) {
                                entry.mark_web_reported();
                            }
                        }
                        CompactFlowKey::V6(k) => {
                            if let Some(entry) = flows_v6.get_mut(k) {
                                entry.mark_web_reported();
                            }
                        }
                    }
                }

                out.into_iter()
                    .map(|(compact_key, delta_bytes, snapshot)| {
                        (
                            FlowDelta {
                                key: compact_key.to_flow_key(),
                                delta_bytes,
                            },
                            snapshot,
                        )
                    })
                    .collect()
            }
        }
    }
}

impl FlowSnapshot {
    fn from_entry(key: &FlowKey, entry: &FlowEntry) -> Self {
        let duration = (entry.last_seen - entry.first_seen).max(0.0);
        let bytes_total = entry.total_bytes();
        let packets_total = entry.total_packets();
        let avg_bps = if duration > 0.0 {
            bytes_total as f64 * 8.0 / duration
        } else {
            0.0
        };

        FlowSnapshot {
            protocol: key.protocol,
            endpoint_a: key.a,
            endpoint_b: key.b,
            first_seen: entry.first_seen,
            last_seen: entry.last_seen,
            duration_secs: duration,
            packets_a_to_b: entry.packets_a_to_b,
            packets_b_to_a: entry.packets_b_to_a,
            bytes_a_to_b: entry.bytes_a_to_b,
            bytes_b_to_a: entry.bytes_b_to_a,
            packets_total,
            bytes_total,
            avg_bps,
            tcp_state: entry.tcp_state,
            client: entry.client,
            retransmissions: entry.retransmissions,
            out_of_order: entry.out_of_order,
            rtt_last_ms: entry.rtt_last_ms,
            rtt_min_ms: entry.rtt_min_ms,
            rtt_ewma_ms: entry.rtt_ewma_ms,
            rtt_samples: entry.rtt_samples,
        }
    }

    fn from_scale_entry(key: &FlowKey, entry: &ScaleFlowEntry, time_base_ms: u64) -> Self {
        let first_seen = entry.first_seen(time_base_ms);
        let last_seen = entry.last_seen(time_base_ms);
        let duration = (last_seen - first_seen).max(0.0);
        let bytes_total = entry.total_bytes();
        let packets_total = entry.total_packets();
        let avg_bps = if duration > 0.0 {
            bytes_total as f64 * 8.0 / duration
        } else {
            0.0
        };

        FlowSnapshot {
            protocol: key.protocol,
            endpoint_a: key.a,
            endpoint_b: key.b,
            first_seen,
            last_seen,
            duration_secs: duration,
            packets_a_to_b: entry.packets_a_to_b as u64,
            packets_b_to_a: entry.packets_b_to_a as u64,
            bytes_a_to_b: entry.bytes_a_to_b,
            bytes_b_to_a: entry.bytes_b_to_a,
            packets_total,
            bytes_total,
            avg_bps,
            tcp_state: entry.tcp_state(),
            client: entry.client(),
            retransmissions: 0,
            out_of_order: 0,
            rtt_last_ms: None,
            rtt_min_ms: None,
            rtt_ewma_ms: None,
            rtt_samples: 0,
        }
    }
}

/// Build a canonical flow key from a parsed packet.
///
/// Returns `None` for packets that are not trackable flows (non-IP,
/// non-initial fragments, or unsupported transport protocols).
pub fn flow_key_from_packet(packet: &ParsedPacket<'_>) -> Option<FlowKey> {
    let (src_ip, dst_ip, skip_flow) = match &packet.network {
        Some(NetworkHeader::Ipv4(hdr)) => {
            let skip = hdr.fragment_offset() != 0;
            (IpAddr::V4(hdr.src_addr()), IpAddr::V4(hdr.dst_addr()), skip)
        }
        Some(NetworkHeader::Ipv6(hdr)) => (
            IpAddr::V6(hdr.src_addr()),
            IpAddr::V6(hdr.dst_addr()),
            hdr.is_non_initial_fragment(),
        ),
        None => return None,
    };

    if skip_flow {
        return None;
    }

    let (src_port, dst_port, protocol) = match &packet.transport {
        Some(TransportHeader::Tcp(hdr)) => (hdr.src_port(), hdr.dst_port(), FlowProtocol::Tcp),
        Some(TransportHeader::Udp(hdr)) => (hdr.src_port(), hdr.dst_port(), FlowProtocol::Udp),
        _ => return None,
    };

    let src = Endpoint {
        ip: src_ip,
        port: src_port,
    };
    let dst = Endpoint {
        ip: dst_ip,
        port: dst_port,
    };

    let (key, _) = FlowKey::new(protocol, src, dst);
    Some(key)
}

pub(crate) fn flow_compact_key_from_packet(packet: &ParsedPacket<'_>) -> Option<CompactFlowKey> {
    flow_key_from_packet(packet).and_then(|key| CompactFlowKey::from_flow_key(&key))
}

#[derive(Debug, Clone, Copy)]
struct TcpFlags {
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

impl TcpFlags {
    fn from_tcp(header: &crate::protocol::tcp::TcpHeader<'_>) -> Self {
        TcpFlags {
            syn: header.syn(),
            ack: header.ack(),
            fin: header.fin(),
            rst: header.rst(),
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpState::SynSent => write!(f, "syn_sent"),
            TcpState::SynAck => write!(f, "syn_ack"),
            TcpState::Established => write!(f, "established"),
            TcpState::FinWait => write!(f, "fin_wait"),
            TcpState::Closed => write!(f, "closed"),
            TcpState::Reset => write!(f, "reset"),
            TcpState::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeqStatus {
    Advanced,
    Retransmission,
    OutOfOrder,
}

#[derive(Debug, Clone)]
struct TcpSeqTracker {
    max_seq_end: Option<u32>,
    last_ack: Option<u32>,
    in_flight: VecDeque<SeqSample>,
}

#[derive(Debug, Clone, Copy)]
struct SeqSample {
    seq_end: u32,
    ts: f64,
}

impl TcpSeqTracker {
    fn new() -> Self {
        TcpSeqTracker {
            max_seq_end: None,
            last_ack: None,
            in_flight: VecDeque::new(),
        }
    }

    fn on_segment(&mut self, seq_end: u32, peer_ack: Option<u32>) -> SeqStatus {
        match self.max_seq_end {
            None => {
                self.max_seq_end = Some(seq_end);
                SeqStatus::Advanced
            }
            Some(max_end) => {
                if seq_end.wrapping_sub(max_end) as i32 > 0 {
                    self.max_seq_end = Some(seq_end);
                    SeqStatus::Advanced
                } else if let Some(ack) = peer_ack {
                    if seq_end.wrapping_sub(ack) as i32 <= 0 {
                        SeqStatus::Retransmission
                    } else {
                        SeqStatus::OutOfOrder
                    }
                } else {
                    SeqStatus::OutOfOrder
                }
            }
        }
    }

    fn on_ack<F: FnMut(f64)>(&mut self, ts: f64, ack_no: u32, mut cb: F) {
        while let Some(front) = self.in_flight.front() {
            if front.seq_end.wrapping_sub(ack_no) as i32 <= 0 {
                let sample = self
                    .in_flight
                    .pop_front()
                    .expect("in_flight.front() returned Some but pop_front() returned None");
                let rtt_ms = (ts - sample.ts).max(0.0) * 1000.0;
                cb(rtt_ms);
            } else {
                break;
            }
        }
    }

    fn push_sample(&mut self, seq_end: u32, ts: f64) {
        if self.in_flight.len() >= 128 {
            self.in_flight.pop_front();
        }
        self.in_flight.push_back(SeqSample { seq_end, ts });
    }
}

fn tcp_sequence_len(
    header: &crate::protocol::tcp::TcpHeader<'_>,
    network: Option<&NetworkHeader<'_>>,
) -> u32 {
    let payload_len = header.payload().len() as u32;
    let mut len = payload_len;
    if header.syn() {
        len = len.saturating_add(1);
    }
    if header.fin() {
        len = len.saturating_add(1);
    }

    if let Some(net) = network {
        match net {
            NetworkHeader::Ipv4(hdr) => {
                let total_len = hdr.total_length() as usize;
                let hdr_len = hdr.header_len();
                if total_len >= hdr_len + header.header_len() {
                    let ip_payload = total_len - hdr_len;
                    let tcp_payload = ip_payload.saturating_sub(header.header_len());
                    len = tcp_payload as u32;
                    if header.syn() {
                        len = len.saturating_add(1);
                    }
                    if header.fin() {
                        len = len.saturating_add(1);
                    }
                }
            }
            NetworkHeader::Ipv6(hdr) => {
                let payload_len = hdr.payload().len();
                if payload_len >= header.header_len() {
                    let tcp_payload = payload_len - header.header_len();
                    len = tcp_payload as u32;
                    if header.syn() {
                        len = len.saturating_add(1);
                    }
                    if header.fin() {
                        len = len.saturating_add(1);
                    }
                }
            }
        }
    }

    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn flow_key_is_directionless() {
        let a = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 1234,
        };
        let b = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            port: 80,
        };
        let (key_ab, dir_ab) = FlowKey::new(FlowProtocol::Tcp, a, b);
        let (key_ba, dir_ba) = FlowKey::new(FlowProtocol::Tcp, b, a);
        assert_eq!(key_ab, key_ba);
        assert_ne!(dir_ab, dir_ba);
    }

    #[test]
    fn flow_key_orders_ipv4_before_ipv6() {
        let v4 = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            port: 443,
        };
        let v6 = Endpoint {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 443,
        };
        let (key, dir) = FlowKey::new(FlowProtocol::Udp, v6, v4);
        assert_eq!(key.a, v4);
        assert_eq!(key.b, v6);
        assert_eq!(dir, FlowDirection::BtoA);
    }

    #[test]
    fn compact_v4_key_matches_canonical_flow_key() {
        let a_ip = Ipv4Addr::new(10, 1, 2, 3);
        let b_ip = Ipv4Addr::new(10, 9, 8, 7);
        let a_port = 44444;
        let b_port = 443;

        let (compact_ab, dir_ab) = FlowKeyV4::new(FlowProtocol::Tcp, a_ip, a_port, b_ip, b_port);
        let (compact_ba, dir_ba) = FlowKeyV4::new(FlowProtocol::Tcp, b_ip, b_port, a_ip, a_port);
        assert_eq!(compact_ab, compact_ba);
        assert_ne!(dir_ab, dir_ba);

        let a = Endpoint {
            ip: IpAddr::V4(a_ip),
            port: a_port,
        };
        let b = Endpoint {
            ip: IpAddr::V4(b_ip),
            port: b_port,
        };
        let (full, _) = FlowKey::new(FlowProtocol::Tcp, a, b);
        assert_eq!(compact_ab.to_flow_key(), full);
    }

    #[test]
    fn compact_v6_key_matches_canonical_flow_key() {
        let a_ip = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let b_ip = Ipv6Addr::new(0x2001, 0xdb8, 9, 8, 7, 6, 5, 4);
        let a_port = 5353;
        let b_port = 443;

        let (compact_ab, dir_ab) = FlowKeyV6::new(FlowProtocol::Udp, a_ip, a_port, b_ip, b_port);
        let (compact_ba, dir_ba) = FlowKeyV6::new(FlowProtocol::Udp, b_ip, b_port, a_ip, a_port);
        assert_eq!(compact_ab, compact_ba);
        assert_ne!(dir_ab, dir_ba);

        let a = Endpoint {
            ip: IpAddr::V6(a_ip),
            port: a_port,
        };
        let b = Endpoint {
            ip: IpAddr::V6(b_ip),
            port: b_port,
        };
        let (full, _) = FlowKey::new(FlowProtocol::Udp, a, b);
        assert_eq!(compact_ab.to_flow_key(), full);
    }

    #[test]
    fn flow_tracker_uses_scale_store_when_deep_tcp_features_disabled() {
        let tracker = FlowTracker::new(60.0, 1000, false, false, false);
        assert!(matches!(tracker.store, FlowStore::Scale { .. }));

        let tracker_full = FlowTracker::new(60.0, 1000, true, false, false);
        assert!(matches!(tracker_full.store, FlowStore::Full(_)));
    }

    #[test]
    fn maybe_expire_collect_reports_timeout_reason() {
        let mut tracker = FlowTracker::new(1.0, 1000, false, false, false);
        tracker.insert_synthetic_ipv4_flows(1);
        tracker.last_prune = 0.0;

        let mut events = Vec::new();
        let removed = tracker.maybe_expire_collect(2.0, &mut events);
        assert_eq!(removed, 1);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, ExpiredFlowReason::Timeout);
    }

    #[test]
    fn maybe_expire_collect_reports_eviction_reason() {
        let mut tracker = FlowTracker::new(0.0, 1, false, false, false);
        tracker.insert_synthetic_ipv4_flows(2);
        tracker.last_prune = 0.0;

        let mut events = Vec::new();
        let removed = tracker.maybe_expire_collect(2.0, &mut events);
        assert_eq!(removed, 1);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, ExpiredFlowReason::Eviction);
    }

    #[test]
    fn scale_flow_entry_tracks_compact_state_and_deltas() {
        let time_base_ms = scale_base_ms(1.0);
        let mut entry = ScaleFlowEntry::new(1.0, FlowProtocol::Tcp, time_base_ms);
        entry.observe(
            2.0,
            time_base_ms,
            FlowDirection::AtoB,
            128,
            Some(TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
            }),
        );

        let total = entry.total_bytes();
        assert_eq!(entry.stats_delta(), 128);
        assert_eq!(entry.web_delta(), 128);
        assert_eq!(entry.tcp_state(), Some(TcpState::SynSent));
        assert_eq!(entry.client(), Some(FlowDirection::AtoB));
        assert_eq!(entry.first_seen(time_base_ms), 1.0);
        assert_eq!(entry.last_seen(time_base_ms), 2.0);

        entry.mark_stats_reported();
        entry.mark_web_reported();

        assert_eq!(entry.total_bytes(), total);
        assert_eq!(entry.stats_delta(), 0);
        assert_eq!(entry.web_delta(), 0);
    }

    #[test]
    fn tcp_state_basic_transitions() {
        let mut entry = FlowEntry::new(0.0, FlowProtocol::Tcp);
        entry.update_tcp_state(
            TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
            },
            FlowDirection::AtoB,
        );
        assert_eq!(entry.tcp_state, Some(TcpState::SynSent));
        entry.update_tcp_state(
            TcpFlags {
                syn: true,
                ack: true,
                fin: false,
                rst: false,
            },
            FlowDirection::BtoA,
        );
        assert_eq!(entry.tcp_state, Some(TcpState::SynAck));
        entry.update_tcp_state(
            TcpFlags {
                syn: false,
                ack: true,
                fin: false,
                rst: false,
            },
            FlowDirection::AtoB,
        );
        assert_eq!(entry.tcp_state, Some(TcpState::Established));
    }

    #[test]
    fn tcp_seq_tracker_detects_retransmission() {
        let mut tracker = TcpSeqTracker {
            max_seq_end: Some(200),
            last_ack: Some(200),
            in_flight: VecDeque::new(),
        };

        let status = tracker.on_segment(150, tracker.last_ack);
        assert_eq!(status, SeqStatus::Retransmission);
    }

    #[test]
    fn tcp_seq_tracker_rtt_sample() {
        let mut tracker = TcpSeqTracker::new();
        tracker.push_sample(1100, 1.0);
        let mut samples = Vec::new();
        tracker.on_ack(1.05, 1100, |rtt| samples.push(rtt));
        assert_eq!(samples.len(), 1);
        assert!(samples[0] >= 50.0);
    }
}
