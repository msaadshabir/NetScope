use crate::protocol::{NetworkHeader, tcp::TcpHeader};
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy)]
pub(crate) struct TcpFlags {
    pub(crate) syn: bool,
    pub(crate) ack: bool,
    pub(crate) fin: bool,
    pub(crate) rst: bool,
}

impl TcpFlags {
    pub(crate) fn from_tcp(header: &TcpHeader<'_>) -> Self {
        TcpFlags {
            syn: header.syn(),
            ack: header.ack(),
            fin: header.fin(),
            rst: header.rst(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeqStatus {
    Advanced,
    Retransmission,
    OutOfOrder,
}

#[derive(Debug, Clone)]
pub(crate) struct TcpSeqTracker {
    pub(crate) max_seq_end: Option<u32>,
    pub(crate) last_ack: Option<u32>,
    pub(crate) in_flight: VecDeque<SeqSample>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SeqSample {
    seq_end: u32,
    ts: f64,
}

impl TcpSeqTracker {
    pub(crate) fn new() -> Self {
        TcpSeqTracker {
            max_seq_end: None,
            last_ack: None,
            in_flight: VecDeque::new(),
        }
    }

    pub(crate) fn on_segment(&mut self, seq_end: u32, peer_ack: Option<u32>) -> SeqStatus {
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

    pub(crate) fn on_ack<F: FnMut(f64)>(&mut self, ts: f64, ack_no: u32, mut cb: F) {
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

    pub(crate) fn push_sample(&mut self, seq_end: u32, ts: f64) {
        if self.in_flight.len() >= 128 {
            self.in_flight.pop_front();
        }
        self.in_flight.push_back(SeqSample { seq_end, ts });
    }
}

pub(crate) fn tcp_sequence_len(header: &TcpHeader<'_>, network: Option<&NetworkHeader<'_>>) -> u32 {
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
            NetworkHeader::Arp(_) => {}
        }
    }

    len
}
