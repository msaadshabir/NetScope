//! Aggregator: collects events from all worker shards, merges per-tick
//! statistics, and forwards results to the CLI and web dashboard.

use crossbeam_channel::Receiver;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;

use crate::flow::{FlowDelta, FlowSnapshot};
use crate::web::messages::{CaptureEvent, FlowInfo, StatsTick};

use super::worker::{ShardTick, WorkerEvent};

/// Aggregated tick data merged from all shards.
#[derive(Debug, Clone)]
pub struct AggregatedTick {
    pub ts: f64,
    pub interval_ms: u64,
    pub bytes: u64,
    pub packets: u64,
    pub mbps: f64,
    pub pps: f64,
    pub active_flows: usize,
    pub top_flows: Vec<(FlowDelta, FlowSnapshot)>,
}

/// Shared state the main thread can read for CLI stats / final snapshot.
#[derive(Clone)]
pub struct AggregatorHandle {
    inner: Arc<Mutex<AggregatorState>>,
}

struct AggregatorState {
    num_workers: usize,
    /// Latest merged tick (main thread reads this for CLI stats).
    latest_tick: Option<AggregatedTick>,
    /// Accumulated alert count.
    alert_count: u64,
    /// Per-shard final snapshots collected on shutdown.
    shard_snapshots: Vec<Vec<FlowSnapshot>>,
}

impl AggregatorHandle {
    pub fn new(num_workers: usize) -> Self {
        AggregatorHandle {
            inner: Arc::new(Mutex::new(AggregatorState {
                num_workers,
                latest_tick: None,
                alert_count: 0,
                shard_snapshots: Vec::new(),
            })),
        }
    }

    /// Take the latest aggregated tick (returns `None` if no new tick since last call).
    pub fn take_tick(&self) -> Option<AggregatedTick> {
        self.inner.lock().unwrap().latest_tick.take()
    }

    /// Current alert count.
    pub fn alert_count(&self) -> u64 {
        self.inner.lock().unwrap().alert_count
    }

    /// Collect all final flow snapshots (call after pipeline shutdown).
    pub fn take_final_snapshots(&self) -> Vec<FlowSnapshot> {
        let mut state = self.inner.lock().unwrap();
        let mut all: Vec<FlowSnapshot> = state
            .shard_snapshots
            .drain(..)
            .flat_map(|v| v.into_iter())
            .collect();
        all.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));
        all
    }
}

/// Run the aggregator loop. This blocks until all worker senders disconnect.
pub fn run(
    rx: Receiver<WorkerEvent>,
    handle: AggregatorHandle,
    web_event_tx: Option<mpsc::Sender<CaptureEvent>>,
    running: &AtomicBool,
    max_top_n: usize,
) {
    let num_workers = handle.inner.lock().unwrap().num_workers;

    // Accumulate partial shard ticks, then merge once all shards have reported.
    let mut pending_ticks: Vec<Option<ShardTick>> = vec![None; num_workers];
    let mut tick_start = Instant::now();

    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(event) => match event {
                WorkerEvent::ShardTick(shard_tick) => {
                    let idx = shard_tick.shard_id;
                    if idx < pending_ticks.len() {
                        pending_ticks[idx] = Some(shard_tick);
                    }

                    // Check if all shards have reported.
                    let all_present = pending_ticks.iter().all(|t| t.is_some());
                    if all_present {
                        let elapsed = tick_start.elapsed().as_secs_f64().max(0.001);
                        let merged = merge_ticks(&mut pending_ticks, elapsed, max_top_n);

                        // Forward to web dashboard.
                        if let Some(tx) = &web_event_tx {
                            let stats_tick = aggregated_to_stats_tick(&merged);
                            let _ = tx.try_send(CaptureEvent::Tick(stats_tick));
                        }

                        // Store for CLI consumption.
                        {
                            let mut state = handle.inner.lock().unwrap();
                            state.latest_tick = Some(merged);
                        }

                        tick_start = Instant::now();
                    }
                }
                WorkerEvent::Packet(sample) => {
                    if let Some(tx) = &web_event_tx {
                        let _ = tx.try_send(CaptureEvent::Packet(sample));
                    }
                }
                WorkerEvent::PacketStored(stored) => {
                    if let Some(tx) = &web_event_tx {
                        let _ = tx.try_send(CaptureEvent::PacketStored(stored));
                    }
                }
                WorkerEvent::Alert(alert) => {
                    {
                        let mut state = handle.inner.lock().unwrap();
                        state.alert_count += 1;
                    }
                    // Print to CLI
                    println!("[alert] {}", alert.description);
                    if let Some(tx) = &web_event_tx {
                        let _ = tx.try_send(CaptureEvent::Alert(alert));
                    }
                }
                WorkerEvent::Shutdown(shutdown) => {
                    let mut state = handle.inner.lock().unwrap();
                    state.shard_snapshots.push(shutdown.flows);
                }
            },
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if !running.load(Ordering::Relaxed) {
                    drain_channel(&rx, &handle, &web_event_tx);
                    break;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                // All workers have dropped their senders — drain whatever
                // remains in the channel before exiting so that Shutdown
                // events (and their flow snapshots) are not lost.
                drain_channel(&rx, &handle, &web_event_tx);
                break;
            }
        }
    }

    tracing::debug!("aggregator shut down");
}

/// Drain all remaining events from the channel, handling each one.
/// Called on both the `Timeout+!running` and `Disconnected` shutdown paths
/// so that final `Shutdown` snapshots and in-flight alerts are never dropped.
fn drain_channel(
    rx: &Receiver<WorkerEvent>,
    handle: &AggregatorHandle,
    web_event_tx: &Option<mpsc::Sender<CaptureEvent>>,
) {
    while let Ok(event) = rx.try_recv() {
        match event {
            WorkerEvent::Shutdown(shutdown) => {
                let mut state = handle.inner.lock().unwrap();
                state.shard_snapshots.push(shutdown.flows);
            }
            WorkerEvent::Alert(alert) => {
                {
                    let mut state = handle.inner.lock().unwrap();
                    state.alert_count += 1;
                }
                println!("[alert] {}", alert.description);
                if let Some(tx) = web_event_tx {
                    let _ = tx.try_send(CaptureEvent::Alert(alert));
                }
            }
            WorkerEvent::Packet(sample) => {
                if let Some(tx) = web_event_tx {
                    let _ = tx.try_send(CaptureEvent::Packet(sample));
                }
            }
            WorkerEvent::PacketStored(stored) => {
                if let Some(tx) = web_event_tx {
                    let _ = tx.try_send(CaptureEvent::PacketStored(stored));
                }
            }
            // ShardTick events at shutdown are not merged into a final tick;
            // the data they contain would produce a misleadingly short interval.
            WorkerEvent::ShardTick(_) => {}
        }
    }
}

fn merge_ticks(
    pending: &mut [Option<ShardTick>],
    elapsed_secs: f64,
    max_top_n: usize,
) -> AggregatedTick {
    let mut total_bytes: u64 = 0;
    let mut total_packets: u64 = 0;
    let mut total_active_flows: usize = 0;
    let mut all_top_flows: Vec<(FlowDelta, FlowSnapshot)> = Vec::new();

    for slot in pending.iter_mut() {
        if let Some(tick) = slot.take() {
            total_bytes += tick.bytes;
            total_packets += tick.packets;
            total_active_flows += tick.active_flows;
            all_top_flows.extend(tick.top_flows);
        }
    }

    // Merge top flows: sort all shard top-flows by delta, take global top-N.
    all_top_flows.sort_unstable_by(|a, b| b.0.delta_bytes.cmp(&a.0.delta_bytes));
    if max_top_n > 0 {
        all_top_flows.truncate(max_top_n);
    }

    let mbps = total_bytes as f64 * 8.0 / elapsed_secs / 1_000_000.0;
    let pps = total_packets as f64 / elapsed_secs;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    AggregatedTick {
        ts,
        interval_ms: (elapsed_secs * 1000.0) as u64,
        bytes: total_bytes,
        packets: total_packets,
        mbps,
        pps,
        active_flows: total_active_flows,
        top_flows: all_top_flows,
    }
}

fn aggregated_to_stats_tick(agg: &AggregatedTick) -> StatsTick {
    let elapsed_secs = (agg.interval_ms as f64 / 1000.0).max(0.001);

    let top_flows: Vec<FlowInfo> = agg
        .top_flows
        .iter()
        .map(|(delta, snap)| {
            let delta_mbps = delta.delta_bytes as f64 * 8.0 / elapsed_secs / 1_000_000.0;
            FlowInfo {
                protocol: format!("{}", snap.protocol),
                src_ip: snap.endpoint_a.ip,
                src_port: snap.endpoint_a.port,
                dst_ip: snap.endpoint_b.ip,
                dst_port: snap.endpoint_b.port,
                bytes_a_to_b: snap.bytes_a_to_b,
                bytes_b_to_a: snap.bytes_b_to_a,
                packets_a_to_b: snap.packets_a_to_b,
                packets_b_to_a: snap.packets_b_to_a,
                bytes_total: snap.bytes_total,
                packets_total: snap.packets_total,
                delta_bytes: delta.delta_bytes,
                delta_mbps,
                duration_secs: snap.duration_secs,
                tcp_state: snap.tcp_state.map(|s| format!("{}", s)),
                rtt_ewma_ms: snap.rtt_ewma_ms,
                retransmissions: snap.retransmissions,
                out_of_order: snap.out_of_order,
            }
        })
        .collect();

    StatsTick {
        ts: agg.ts,
        interval_ms: agg.interval_ms,
        bytes: agg.bytes,
        packets: agg.packets,
        mbps: agg.mbps,
        pps: agg.pps,
        active_flows: agg.active_flows,
        top_flows,
    }
}
