//! Per-shard worker: owns a `FlowTracker` and `AnomalyDetector`, processes
//! packets from a bounded channel, and emits events to the aggregator.

use crossbeam_channel::{Receiver, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::analysis::anomaly::AnomalyDetector;
use crate::config::{AnalysisConfig, FlowConfig, WebConfig};
use crate::flow::{FlowDelta, FlowSnapshot, FlowTracker};
use crate::protocol;
use crate::web::messages::{AlertMsg, PacketSample, StoredPacket};

use super::top_flows::SpaceSavingTopFlows;
use super::{OwnedPacket, PacketBufReturner};

/// Events a worker sends to the aggregator.
#[derive(Debug)]
pub enum WorkerEvent {
    /// Per-tick partial statistics from this shard.
    ShardTick(ShardTick),
    /// A sampled packet summary (for the live packet feed).
    Packet(PacketSample),
    /// A stored packet for the detail ring buffer.
    PacketStored(StoredPacket),
    /// An anomaly alert.
    Alert(AlertMsg),
    /// Worker is shutting down; final flow snapshot from this shard.
    Shutdown(ShardShutdown),
}

/// Partial tick data from one shard.
#[derive(Debug, Clone)]
pub struct ShardTick {
    pub shard_id: usize,
    pub bytes: u64,
    pub packets: u64,
    pub active_flows: usize,
    pub top_flows: Vec<(FlowDelta, FlowSnapshot)>,
}

/// Final state from a shutting-down worker.
#[derive(Debug)]
pub struct ShardShutdown {
    pub shard_id: usize,
    pub flows: Vec<FlowSnapshot>,
}

pub struct Worker {
    shard_id: usize,
    flow_tracker: FlowTracker,
    anomaly_detector: AnomalyDetector,
    analysis_cfg: AnalysisConfig,
    web_cfg: WebConfig,
    heavy_hitter_top_n: usize,
    buffer_returner: PacketBufReturner,
    top_flows_hh: SpaceSavingTopFlows,
    // Per-tick accumulators
    tick_bytes: u64,
    tick_packets: u64,
    tick_last: Instant,
}

impl Worker {
    pub fn new(
        shard_id: usize,
        flow_cfg: FlowConfig,
        analysis_cfg: AnalysisConfig,
        web_cfg: WebConfig,
        heavy_hitter_top_n: usize,
        buffer_returner: PacketBufReturner,
    ) -> Self {
        let flow_tracker = FlowTracker::new(
            flow_cfg.timeout_secs,
            flow_cfg.max_flows,
            analysis_cfg.rtt,
            analysis_cfg.retrans,
            analysis_cfg.out_of_order,
        );
        let anomaly_detector = AnomalyDetector::new(
            analysis_cfg.anomalies.clone(),
            // Workers don't write alert files directly; alerts go through the aggregator.
            None,
        );

        Worker {
            shard_id,
            flow_tracker,
            anomaly_detector,
            analysis_cfg,
            web_cfg,
            heavy_hitter_top_n,
            buffer_returner,
            top_flows_hh: SpaceSavingTopFlows::new(heavy_hitter_top_n),
            tick_bytes: 0,
            tick_packets: 0,
            tick_last: Instant::now(),
        }
    }

    pub fn run(
        &mut self,
        rx: Receiver<OwnedPacket>,
        agg_tx: Sender<WorkerEvent>,
        running: &AtomicBool,
    ) {
        loop {
            // Check for pipeline shutdown
            if !running.load(Ordering::Relaxed) {
                // Drain remaining packets in the channel before shutting down.
                while let Ok(mut pkt) = rx.try_recv() {
                    self.process_packet(&pkt, &agg_tx);
                    let owned = std::mem::take(&mut pkt.data);
                    self.buffer_returner.release(owned);
                }
                break;
            }

            // Use recv_timeout so we still emit ticks during traffic lulls
            // and can check the running flag periodically.
            match rx.recv_timeout(std::time::Duration::from_millis(10)) {
                Ok(mut pkt) => {
                    self.process_packet(&pkt, &agg_tx);
                    let owned = std::mem::take(&mut pkt.data);
                    self.buffer_returner.release(owned);
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }

            // Emit shard tick if interval elapsed.
            self.maybe_emit_tick(&agg_tx);
        }

        // Final tick flush.
        self.emit_tick(&agg_tx);

        // Send shutdown event with final flow snapshot.
        let flows = self.flow_tracker.snapshot();
        let _ = agg_tx.send(WorkerEvent::Shutdown(ShardShutdown {
            shard_id: self.shard_id,
            flows,
        }));

        tracing::debug!(shard = self.shard_id, "worker shut down");
    }

    fn process_packet(&mut self, pkt: &OwnedPacket, agg_tx: &Sender<WorkerEvent>) {
        self.tick_bytes += pkt.wire_len;
        self.tick_packets += 1;

        match protocol::parse_packet(&pkt.data) {
            Ok(parsed) => {
                // Anomaly detection
                if self.analysis_cfg.anomalies.enabled {
                    let alerts =
                        crate::maybe_analyze_anomaly(&mut self.anomaly_detector, pkt.ts, &parsed);
                    for alert in alerts {
                        let _ = agg_tx.send(WorkerEvent::Alert(AlertMsg {
                            ts: alert.ts,
                            kind: format!("{:?}", alert.kind),
                            description: alert.description,
                        }));
                    }
                }

                // Flow tracking
                self.flow_tracker.observe(pkt.ts, pkt.wire_len, &parsed);

                if self.heavy_hitter_top_n > 0 {
                    if let Some(key) = crate::flow::flow_key_from_packet(&parsed) {
                        self.top_flows_hh.observe(&key, pkt.wire_len);
                    }
                }

                // Packet sampling for web dashboard.
                // Use the global packet id (assigned by the capture thread) so
                // that sample_rate controls the global rate across all shards,
                // not a per-shard rate that would produce N*sample_rate samples.
                if self.web_cfg.enabled
                    && self.web_cfg.sample_rate > 0
                    && pkt.id % self.web_cfg.sample_rate == 0
                {
                    let (sample, stored) = crate::build_packet_data(
                        pkt.id,
                        pkt.ts,
                        &pkt.data,
                        &parsed,
                        self.web_cfg.payload_bytes,
                    );
                    let _ = agg_tx.send(WorkerEvent::Packet(sample));
                    let _ = agg_tx.send(WorkerEvent::PacketStored(stored));
                }

                // Flow expiration
                self.flow_tracker.maybe_expire(pkt.ts);
            }
            Err(e) => {
                tracing::trace!(shard = self.shard_id, error = %e, "parse error");
            }
        }
    }

    fn maybe_emit_tick(&mut self, agg_tx: &Sender<WorkerEvent>) {
        let now = Instant::now();
        if now.duration_since(self.tick_last).as_millis() as u64 >= self.web_cfg.tick_ms {
            self.emit_tick(agg_tx);
        }
    }

    fn emit_tick(&mut self, agg_tx: &Sender<WorkerEvent>) {
        let candidates = self.top_flows_hh.take_top(self.heavy_hitter_top_n);
        let candidate_keys: Vec<crate::flow::FlowKey> =
            candidates.iter().map(|(key, _)| key.clone()).collect();
        let top_flows = self
            .flow_tracker
            .top_flows_with_snapshot_for_keys(&candidate_keys, self.heavy_hitter_top_n);

        let tick = ShardTick {
            shard_id: self.shard_id,
            bytes: self.tick_bytes,
            packets: self.tick_packets,
            active_flows: self.flow_tracker.len(),
            top_flows,
        };

        let _ = agg_tx.send(WorkerEvent::ShardTick(tick));

        self.tick_bytes = 0;
        self.tick_packets = 0;
        self.tick_last = Instant::now();
    }
}
