//! Sharded capture pipeline.
//!
//! The pipeline splits packet processing across N worker threads ("shards").
//! Each worker owns its own `FlowTracker` and `AnomalyDetector`, so the
//! hot path is completely lock-free.
//!
//! Architecture:
//!
//! ```text
//! pcap capture (main thread)
//!   |
//!   |-- extract 5-tuple hash → shard = hash % N
//!   |
//!   +--[crossbeam channel]--→ Worker 0  (parse, flow, anomaly)
//!   +--[crossbeam channel]--→ Worker 1
//!   ...
//!   +--[crossbeam channel]--→ Worker N-1
//!
//! Workers --[mpsc]--→ Aggregator thread
//!   |                     |
//!   |                     +--→ CLI stats
//!   |                     +--→ Web dashboard events
//! ```

pub mod aggregator;
pub mod pool;
pub mod router;
pub mod top_flows;
pub mod worker;

use crate::config::{AnalysisConfig, FlowConfig, StatsConfig, WebConfig};
use crate::web;
use crossbeam_channel::{Sender, bounded};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

pub use aggregator::AggregatorHandle;
pub use pool::{PacketBufPool, PacketBufReturner};
pub use worker::WorkerEvent;

#[derive(Debug)]
pub struct PipelineStats {
    dispatch_drops_total: AtomicU64,
    dispatch_drops_interval: AtomicU64,
}

impl PipelineStats {
    pub fn new() -> Self {
        PipelineStats {
            dispatch_drops_total: AtomicU64::new(0),
            dispatch_drops_interval: AtomicU64::new(0),
        }
    }

    pub fn record_dispatch_drop(&self) {
        self.dispatch_drops_total.fetch_add(1, Ordering::Relaxed);
        self.dispatch_drops_interval.fetch_add(1, Ordering::Relaxed);
    }

    pub fn take_dispatch_drops_interval(&self) -> u64 {
        self.dispatch_drops_interval.swap(0, Ordering::Relaxed)
    }

    pub fn dispatch_drops_total(&self) -> u64 {
        self.dispatch_drops_total.load(Ordering::Relaxed)
    }
}

/// An owned packet buffer sent from the capture thread to a worker.
#[derive(Debug)]
pub struct OwnedPacket {
    /// Monotonic capture-wide packet index.
    pub id: u64,
    /// pcap timestamp as seconds since epoch.
    pub ts: f64,
    /// Wire length (from pcap header).
    pub wire_len: u64,
    /// Owned copy of packet bytes.
    pub data: Vec<u8>,
}

/// Configuration for the pipeline.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Number of worker shards (0 = auto-detect from CPU count).
    pub num_workers: usize,
    /// Capacity of each capture → worker channel.
    pub channel_capacity: usize,
    /// Capacity for the packet buffer pool.
    pub buffer_pool_capacity: usize,
    /// Buffer size for packet byte storage.
    pub packet_buf_size: usize,
    /// Flow tracker settings.
    pub flow: FlowConfig,
    /// Analysis settings.
    pub analysis: AnalysisConfig,
    /// CLI stats settings (for top-N truncation).
    pub stats: StatsConfig,
    /// Web dashboard settings (for sampling decisions).
    pub web: WebConfig,
    /// Number of heavy-hitter candidates to track per worker tick.
    pub heavy_hitter_top_n: usize,
}

/// Handle returned by [`spawn`] — the capture thread uses this to dispatch
/// packets and retrieve the aggregator.
pub struct PipelineHandle {
    /// Per-shard senders. The capture thread picks `senders[shard]`.
    pub senders: Vec<Sender<OwnedPacket>>,
    /// The aggregator collects merged results from all workers.
    pub aggregator: AggregatorHandle,
    /// Shared pool for packet byte buffers.
    pub buffer_pool: PacketBufPool,
    /// Shared counters for pipeline drop statistics.
    pub stats: Arc<PipelineStats>,
    /// Worker join handles (for clean shutdown).
    worker_handles: Vec<thread::JoinHandle<()>>,
    /// Aggregator join handle.
    aggregator_handle: Option<thread::JoinHandle<()>>,
}

impl PipelineHandle {
    /// Number of worker shards.
    pub fn num_workers(&self) -> usize {
        self.senders.len()
    }

    /// Signal all workers to stop (by dropping senders) and join threads.
    /// The `aggregator` handle remains valid after this call for reading
    /// final snapshots.
    pub fn shutdown(&mut self) {
        // Drop senders so workers see channel disconnect.
        self.senders.clear();
        for h in self.worker_handles.drain(..) {
            let _ = h.join();
        }
        // Aggregator shuts down once all worker event senders are dropped.
        if let Some(h) = self.aggregator_handle.take() {
            let _ = h.join();
        }
    }
}

/// Spawn the sharded pipeline.
///
/// Returns a `PipelineHandle` the caller uses to dispatch packets (via
/// `senders`) and to read aggregated results (via `aggregator`).
pub fn spawn(
    config: PipelineConfig,
    running: Arc<AtomicBool>,
    web_handle: Option<&web::server::WebHandle>,
) -> PipelineHandle {
    let num_workers = resolve_num_workers(config.num_workers);

    tracing::info!(num_workers, "starting sharded pipeline");

    // Aggregator channel: all workers send events here.
    let (agg_tx, agg_rx) = crossbeam_channel::unbounded::<WorkerEvent>();

    // Spawn workers.
    let mut senders = Vec::with_capacity(num_workers);
    let mut worker_handles = Vec::with_capacity(num_workers);
    let buffer_pool = PacketBufPool::new(config.buffer_pool_capacity, config.packet_buf_size);
    let buffer_returner = buffer_pool.returner();
    let stats = Arc::new(PipelineStats::new());

    for shard_id in 0..num_workers {
        let (pkt_tx, pkt_rx) = bounded::<OwnedPacket>(config.channel_capacity);
        senders.push(pkt_tx);

        let agg_tx = agg_tx.clone();
        let running = running.clone();
        let flow_cfg = config.flow.clone();
        let analysis_cfg = config.analysis.clone();
        let web_cfg = config.web.clone();
        let heavy_hitter_top_n = config.heavy_hitter_top_n;
        let buffer_returner = buffer_returner.clone();

        let handle = thread::Builder::new()
            .name(format!("ns-worker-{}", shard_id))
            .spawn(move || {
                let mut w = worker::Worker::new(
                    shard_id,
                    flow_cfg,
                    analysis_cfg,
                    web_cfg,
                    heavy_hitter_top_n,
                    buffer_returner,
                );
                w.run(pkt_rx, agg_tx, &running);
            })
            .expect("failed to spawn worker thread");

        worker_handles.push(handle);
    }

    // Drop the aggregator sender held by this thread so the aggregator can
    // detect when all workers are done.
    drop(agg_tx);

    // Spawn aggregator.
    let web_event_tx = web_handle.map(|h| h.event_tx.clone());
    let agg_running = running.clone();
    let agg_handle = aggregator::AggregatorHandle::new(num_workers);
    let agg_handle_clone = agg_handle.clone();
    let max_top_n = (config.stats.top_flows as usize).max(config.web.top_n);
    let web_top_n = config.web.top_n;
    let tick_deadline_ms = config.web.tick_ms.saturating_mul(2).max(1);
    let stats_clone = stats.clone();

    let aggregator_thread = thread::Builder::new()
        .name("ns-aggregator".into())
        .spawn(move || {
            aggregator::run(
                agg_rx,
                agg_handle_clone,
                web_event_tx,
                &agg_running,
                max_top_n,
                web_top_n,
                stats_clone,
                tick_deadline_ms,
            );
        })
        .expect("failed to spawn aggregator thread");

    PipelineHandle {
        senders,
        aggregator: agg_handle,
        buffer_pool,
        stats,
        worker_handles,
        aggregator_handle: Some(aggregator_thread),
    }
}

pub fn resolve_num_workers(configured: usize) -> usize {
    if configured == 0 {
        (num_cpus::get() / 2).clamp(1, 8)
    } else {
        configured.max(1)
    }
}
