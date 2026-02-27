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
pub mod router;
pub mod worker;

use crate::config::{AnalysisConfig, FlowConfig, StatsConfig, WebConfig};
use crate::web;
use crossbeam_channel::{bounded, Sender};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

pub use aggregator::AggregatorHandle;
pub use worker::WorkerEvent;

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
    /// Flow tracker settings.
    pub flow: FlowConfig,
    /// Analysis settings.
    pub analysis: AnalysisConfig,
    /// CLI stats settings (for top-N truncation).
    pub stats: StatsConfig,
    /// Web dashboard settings (for sampling decisions).
    pub web: WebConfig,
}

/// Handle returned by [`spawn`] — the capture thread uses this to dispatch
/// packets and retrieve the aggregator.
pub struct PipelineHandle {
    /// Per-shard senders. The capture thread picks `senders[shard]`.
    pub senders: Vec<Sender<OwnedPacket>>,
    /// The aggregator collects merged results from all workers.
    pub aggregator: AggregatorHandle,
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
    let num_workers = if config.num_workers == 0 {
        // Use half the available cores, minimum 1, maximum 8.
        (num_cpus::get() / 2).clamp(1, 8)
    } else {
        config.num_workers.max(1)
    };

    tracing::info!(num_workers, "starting sharded pipeline");

    // Aggregator channel: all workers send events here.
    let (agg_tx, agg_rx) = crossbeam_channel::unbounded::<WorkerEvent>();

    // Spawn workers.
    let mut senders = Vec::with_capacity(num_workers);
    let mut worker_handles = Vec::with_capacity(num_workers);

    for shard_id in 0..num_workers {
        let (pkt_tx, pkt_rx) = bounded::<OwnedPacket>(config.channel_capacity);
        senders.push(pkt_tx);

        let agg_tx = agg_tx.clone();
        let running = running.clone();
        let flow_cfg = config.flow.clone();
        let analysis_cfg = config.analysis.clone();
        let web_cfg = config.web.clone();

        let handle = thread::Builder::new()
            .name(format!("ns-worker-{}", shard_id))
            .spawn(move || {
                let mut w = worker::Worker::new(shard_id, flow_cfg, analysis_cfg, web_cfg);
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
    let max_top_n = config.web.top_n.max(config.stats.top_flows as usize);

    let aggregator_thread = thread::Builder::new()
        .name("ns-aggregator".into())
        .spawn(move || {
            aggregator::run(
                agg_rx,
                agg_handle_clone,
                web_event_tx,
                &agg_running,
                max_top_n,
            );
        })
        .expect("failed to spawn aggregator thread");

    PipelineHandle {
        senders,
        aggregator: agg_handle,
        worker_handles,
        aggregator_handle: Some(aggregator_thread),
    }
}
