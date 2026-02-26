use crate::protocol::{NetworkHeader, ParsedPacket, TransportHeader};
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for FlowProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowProtocol::Tcp => write!(f, "tcp"),
            FlowProtocol::Udp => write!(f, "udp"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    AtoB,
    BtoA,
}

impl fmt::Display for FlowDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowDirection::AtoB => write!(f, "a_to_b"),
            FlowDirection::BtoA => write!(f, "b_to_a"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct FlowKey {
    pub protocol: FlowProtocol,
    pub a: Endpoint,
    pub b: Endpoint,
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} <-> {}", self.protocol, self.a, self.b)
    }
}

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
        // Collect RTT samples and update seq trackers first, then apply to self.
        let mut rtt_samples = Vec::new();
        let mut retrans_delta: u64 = 0;
        let mut ooo_delta: u64 = 0;

        {
            let (sender, receiver) = match direction {
                FlowDirection::AtoB => (&mut self.a_to_b_seq, &mut self.b_to_a_seq),
                FlowDirection::BtoA => (&mut self.b_to_a_seq, &mut self.a_to_b_seq),
            };

            if let Some(ack_no) = ack {
                if track_rtt {
                    rtt_samples = receiver.on_ack(ts, ack_no);
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

        for rtt_ms in rtt_samples {
            self.record_rtt(rtt_ms);
        }
        self.retransmissions += retrans_delta;
        self.out_of_order += ooo_delta;
    }

    fn record_rtt(&mut self, rtt_ms: f64) {
        self.rtt_last_ms = Some(rtt_ms);
        self.rtt_min_ms = Some(self.rtt_min_ms.map_or(rtt_ms, |min| min.min(rtt_ms)));
        let ewma = match self.rtt_ewma_ms {
            Some(prev) => 0.875 * prev + 0.125 * rtt_ms,
            None => rtt_ms,
        };
        self.rtt_ewma_ms = Some(ewma);
        self.rtt_samples += 1;
    }

    fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b + self.bytes_b_to_a
    }

    fn total_packets(&self) -> u64 {
        self.packets_a_to_b + self.packets_b_to_a
    }

    fn update_tcp_state(&mut self, flags: TcpFlags, direction: FlowDirection) {
        if flags.rst {
            self.tcp_state = Some(TcpState::Reset);
            return;
        }
        if flags.syn && !flags.ack {
            if self.client.is_none() {
                self.client = Some(direction);
            }
            self.tcp_state = Some(TcpState::SynSent);
            return;
        }
        if flags.syn && flags.ack {
            self.tcp_state = Some(TcpState::SynAck);
            return;
        }
        if flags.fin {
            match self.tcp_state {
                Some(TcpState::FinWait) => {
                    // Second FIN seen (other direction) — move to Closed
                    self.tcp_state = Some(TcpState::Closed);
                }
                _ => {
                    self.tcp_state = Some(TcpState::FinWait);
                }
            }
            return;
        }
        if flags.ack {
            if !matches!(
                self.tcp_state,
                Some(TcpState::Reset | TcpState::Closed | TcpState::FinWait)
            ) {
                self.tcp_state = Some(TcpState::Established);
            }
            return;
        }
        if self.tcp_state.is_none() {
            self.tcp_state = Some(TcpState::Unknown);
        }
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

#[derive(Debug, Clone)]
pub struct FlowDelta {
    pub key: FlowKey,
    pub delta_bytes: u64,
}

#[derive(Debug)]
pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowEntry>,
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
        FlowTracker {
            flows: HashMap::new(),
            timeout_secs,
            max_flows,
            last_prune: 0.0,
            track_rtt,
            track_retrans,
            track_out_of_order,
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn observe(&mut self, ts: f64, wire_len: u64, packet: &ParsedPacket<'_>) {
        let (src_ip, dst_ip, skip_flow) = match &packet.network {
            Some(NetworkHeader::Ipv4(hdr)) => {
                let skip = hdr.fragment_offset() != 0;
                (IpAddr::V4(hdr.src_addr()), IpAddr::V4(hdr.dst_addr()), skip)
            }
            Some(NetworkHeader::Ipv6(hdr)) => (
                IpAddr::V6(hdr.src_addr()),
                IpAddr::V6(hdr.dst_addr()),
                false,
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

        let src = Endpoint {
            ip: src_ip,
            port: src_port,
        };
        let dst = Endpoint {
            ip: dst_ip,
            port: dst_port,
        };

        let (key, direction) = FlowKey::new(protocol, src, dst);
        let entry = self
            .flows
            .entry(key)
            .or_insert_with(|| FlowEntry::new(ts, protocol));
        entry.observe(ts, direction, wire_len, flags);
        if protocol == FlowProtocol::Tcp {
            if let (Some(seq), Some(seq_len)) = (seq, seq_len) {
                if self.track_rtt || self.track_retrans || self.track_out_of_order {
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
        }
    }

    pub fn maybe_expire(&mut self, now: f64) -> usize {
        if now - self.last_prune < 1.0 {
            return 0;
        }
        self.last_prune = now;

        let mut removed = 0;
        if self.timeout_secs > 0.0 {
            self.flows.retain(|_, entry| {
                let keep = now - entry.last_seen <= self.timeout_secs;
                if !keep {
                    removed += 1;
                }
                keep
            });
        }

        if self.max_flows > 0 && self.flows.len() > self.max_flows {
            let mut entries: Vec<(FlowKey, f64)> = self
                .flows
                .iter()
                .map(|(key, entry)| (key.clone(), entry.last_seen))
                .collect();
            entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal));
            let excess = self.flows.len() - self.max_flows;
            for (key, _) in entries.into_iter().take(excess) {
                if self.flows.remove(&key).is_some() {
                    removed += 1;
                }
            }
        }

        removed
    }

    pub fn top_flows_by_delta(&mut self, n: usize) -> Vec<FlowDelta> {
        if n == 0 {
            return Vec::new();
        }
        // Compute deltas without mutating counters
        let mut deltas: Vec<FlowDelta> = self
            .flows
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
        deltas.sort_by(|a, b| b.delta_bytes.cmp(&a.delta_bytes));
        let top: Vec<FlowDelta> = deltas.into_iter().take(n).collect();
        // Only reset counters for the flows we're reporting
        for d in &top {
            if let Some(entry) = self.flows.get_mut(&d.key) {
                entry.last_report_bytes_stats = entry.total_bytes();
            }
        }
        top
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
        let mut deltas: Vec<FlowDelta> = self
            .flows
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
        deltas.sort_by(|a, b| b.delta_bytes.cmp(&a.delta_bytes));
        let top: Vec<FlowDelta> = deltas.into_iter().take(n).collect();

        let mut result = Vec::with_capacity(top.len());
        for d in top {
            if let Some(entry) = self.flows.get_mut(&d.key) {
                entry.last_report_bytes_web = entry.total_bytes();
                let snap = FlowSnapshot::from_entry(&d.key, entry);
                result.push((d, snap));
            }
        }
        result
    }

    pub fn snapshot(&self) -> Vec<FlowSnapshot> {
        let mut flows: Vec<FlowSnapshot> = self
            .flows
            .iter()
            .map(|(key, entry)| FlowSnapshot::from_entry(key, entry))
            .collect();
        flows.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));
        flows
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
}

impl FlowKey {
    pub fn new(protocol: FlowProtocol, src: Endpoint, dst: Endpoint) -> (Self, FlowDirection) {
        let src_key = endpoint_key(&src);
        let dst_key = endpoint_key(&dst);
        if src_key <= dst_key {
            (
                FlowKey {
                    protocol,
                    a: src,
                    b: dst,
                },
                FlowDirection::AtoB,
            )
        } else {
            (
                FlowKey {
                    protocol,
                    a: dst,
                    b: src,
                },
                FlowDirection::BtoA,
            )
        }
    }
}

pub fn write_flow_json(
    path: &Path,
    flows: &[FlowSnapshot],
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, flows)?;
    Ok(())
}

pub fn write_flow_csv(
    path: &Path,
    flows: &[FlowSnapshot],
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    writeln!(
        writer,
        "protocol,endpoint_a_ip,endpoint_a_port,endpoint_b_ip,endpoint_b_port,first_seen,last_seen,duration_secs,packets_a_to_b,packets_b_to_a,bytes_a_to_b,bytes_b_to_a,packets_total,bytes_total,avg_bps,tcp_state,client,retransmissions,out_of_order,rtt_last_ms,rtt_min_ms,rtt_ewma_ms,rtt_samples"
    )?;
    for flow in flows {
        let tcp_state = flow
            .tcp_state
            .map(|state| state.to_string())
            .unwrap_or_default();
        let client = flow.client.map(|dir| dir.to_string()).unwrap_or_default();
        let rtt_last = flow
            .rtt_last_ms
            .map(|value| format!("{:.3}", value))
            .unwrap_or_default();
        let rtt_min = flow
            .rtt_min_ms
            .map(|value| format!("{:.3}", value))
            .unwrap_or_default();
        let rtt_ewma = flow
            .rtt_ewma_ms
            .map(|value| format!("{:.3}", value))
            .unwrap_or_default();
        let endpoint_a_ip = csv_escape(&flow.endpoint_a.ip.to_string());
        let endpoint_b_ip = csv_escape(&flow.endpoint_b.ip.to_string());
        writeln!(
            writer,
            "{},{},{},{},{},{:.6},{:.6},{:.6},{},{},{},{},{},{},{:.3},{},{},{},{},{},{},{},{}",
            flow.protocol,
            endpoint_a_ip,
            flow.endpoint_a.port,
            endpoint_b_ip,
            flow.endpoint_b.port,
            flow.first_seen,
            flow.last_seen,
            flow.duration_secs,
            flow.packets_a_to_b,
            flow.packets_b_to_a,
            flow.bytes_a_to_b,
            flow.bytes_b_to_a,
            flow.packets_total,
            flow.bytes_total,
            flow.avg_bps,
            tcp_state,
            client,
            flow.retransmissions,
            flow.out_of_order,
            rtt_last,
            rtt_min,
            rtt_ewma,
            flow.rtt_samples
        )?;
    }
    Ok(())
}

/// Escape a CSV field: wrap in double quotes if it contains comma, quote, or newline.
fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        let escaped = field.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        field.to_string()
    }
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

fn endpoint_key(endpoint: &Endpoint) -> (u8, [u8; 16], u16) {
    let (version, addr) = ip_key(endpoint.ip);
    (version, addr, endpoint.port)
}

fn ip_key(ip: IpAddr) -> (u8, [u8; 16]) {
    match ip {
        IpAddr::V4(addr) => {
            let mut bytes = [0u8; 16];
            bytes[12..].copy_from_slice(&addr.octets());
            (4, bytes)
        }
        IpAddr::V6(addr) => (6, addr.octets()),
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

    fn on_ack(&mut self, ts: f64, ack_no: u32) -> Vec<f64> {
        let mut samples = Vec::new();
        while let Some(front) = self.in_flight.front() {
            if front.seq_end.wrapping_sub(ack_no) as i32 <= 0 {
                let sample = self.in_flight.pop_front().unwrap();
                let rtt_ms = (ts - sample.ts).max(0.0) * 1000.0;
                samples.push(rtt_ms);
            } else {
                break;
            }
        }
        samples
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
                let payload_len = hdr.payload_length() as usize;
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
        let samples = tracker.on_ack(1.05, 1100);
        assert_eq!(samples.len(), 1);
        assert!(samples[0] >= 50.0);
    }
}
