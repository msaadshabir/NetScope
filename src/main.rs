mod cli;

use netscope::{analysis, capture, config, display, flow, memory, pipeline, protocol, web};
use netscope::{build_packet_data, maybe_analyze_anomaly};

use clap::Parser;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn main() {
    let args = cli::Cli::parse();

    if let Some(count) = args.synthetic_flows {
        run_synthetic_flow_memory(count);
        return;
    }

    // Initialize tracing/logging
    let log_level = match args.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Handle --list-interfaces
    if args.list_interfaces {
        list_interfaces();
        return;
    }

    let config = match load_config(&args) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {}", err);
            std::process::exit(1);
        }
    };

    // Set up Ctrl-C handler
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    ctrlc::set_handler(move || {
        running_clone.store(false, Ordering::SeqCst);
        eprintln!("\nInterrupt received, stopping capture...");
    })
    .expect("failed to set Ctrl-C handler");

    // Run the capture loop
    if let Err(e) = run_capture(&config, &running) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run_synthetic_flow_memory(count: usize) {
    let start = Instant::now();
    let mut tracker = flow::FlowTracker::new(0.0, count.saturating_add(1), false, false, false);

    if !tracker.is_scale_mode() {
        eprintln!("error: synthetic flow benchmark requires scale mode");
        std::process::exit(1);
    }

    tracker.insert_synthetic_ipv4_flows(count);
    let elapsed = start.elapsed().as_secs_f64();
    let rss_kb = memory::current_rss_kb().unwrap_or(0);

    println!("Synthetic flow benchmark complete.");
    println!("  Flows inserted:     {}", tracker.len());
    println!("  Mode:               scale");
    println!("  Elapsed:            {:.3}s", elapsed);
    if rss_kb > 0 {
        println!("  RSS (estimated):    {:.2} MB", rss_kb as f64 / 1024.0);
        if rss_kb > 500 * 1024 {
            eprintln!("  Budget check:       FAIL (> 500 MB)");
            std::process::exit(2);
        } else {
            println!("  Budget check:       PASS (< 500 MB)");
        }
    } else {
        println!("  RSS (estimated):    unavailable");
    }
}

/// List available network interfaces and print them.
fn list_interfaces() {
    match capture::engine::list_interfaces() {
        Ok(devices) => {
            println!("Available network interfaces:");
            println!("{:<20} {:<20} Addresses", "Name", "Description");
            println!("{}", "-".repeat(70));
            for device in &devices {
                let desc = device.desc.as_deref().unwrap_or("");
                let addrs: Vec<String> = device
                    .addresses
                    .iter()
                    .map(|a| format!("{}", a.addr))
                    .collect();
                println!("{:<20} {:<20} {}", device.name, desc, addrs.join(", "));
            }
            if devices.is_empty() {
                println!("  (no interfaces found — try running with sudo)");
            }
        }
        Err(e) => {
            eprintln!("error listing interfaces: {}", e);
            eprintln!("hint: try running with sudo");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureMode {
    Live,
    Offline,
}

enum CaptureSource {
    Live(pcap::Capture<pcap::Active>),
    Offline(pcap::Capture<pcap::Offline>),
}

enum CaptureRead<'a> {
    Packet(pcap::Packet<'a>),
    Idle,
    Eof,
}

impl CaptureSource {
    fn mode(&self) -> CaptureMode {
        match self {
            CaptureSource::Live(_) => CaptureMode::Live,
            CaptureSource::Offline(_) => CaptureMode::Offline,
        }
    }

    fn get_datalink(&self) -> pcap::Linktype {
        match self {
            CaptureSource::Live(cap) => cap.get_datalink(),
            CaptureSource::Offline(cap) => cap.get_datalink(),
        }
    }

    fn savefile<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
    ) -> Result<pcap::Savefile, pcap::Error> {
        match self {
            CaptureSource::Live(cap) => cap.savefile(path),
            CaptureSource::Offline(cap) => cap.savefile(path),
        }
    }

    fn next_packet(&mut self) -> Result<CaptureRead<'_>, pcap::Error> {
        match self {
            CaptureSource::Live(cap) => match cap.next_packet() {
                Ok(packet) => Ok(CaptureRead::Packet(packet)),
                Err(pcap::Error::TimeoutExpired) => Ok(CaptureRead::Idle),
                Err(err) => Err(err),
            },
            CaptureSource::Offline(cap) => match cap.next_packet() {
                Ok(packet) => Ok(CaptureRead::Packet(packet)),
                Err(pcap::Error::NoMorePackets) => Ok(CaptureRead::Eof),
                Err(err) => Err(err),
            },
        }
    }

    fn stats(&mut self) -> Result<Option<pcap::Stat>, pcap::Error> {
        match self {
            CaptureSource::Live(cap) => cap.stats().map(Some),
            CaptureSource::Offline(_) => Ok(None),
        }
    }
}

/// Main capture loop: open capture, read packets, parse, and display.
fn run_capture(
    config: &RuntimeConfig,
    running: &Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_capture_config(config)?;
    let mut cap = open_capture_source(config)?;
    let link_type = protocol::LinkType::from_pcap_value(cap.get_datalink().0);
    let rotation_policy = PcapRotationPolicy::from_output(&config.output);
    let mut savefile = match &config.output.write_pcap {
        Some(path) => Some(RotatingSavefile::open(&mut cap, path.as_path(), rotation_policy)?),
        None => None,
    };
    let capture_mode = cap.mode();

    // Start web dashboard if enabled.
    let web_handle = start_web_dashboard(config)?;

    print_capture_intro(config, capture_mode)?;
    println!("Datalink: {}", link_type);

    if config.pipeline.enabled {
        run_capture_pipeline(
            config,
            running,
            link_type,
            &mut cap,
            savefile.as_mut(),
            web_handle.as_ref(),
        )?;
    } else {
        run_capture_inline(
            config,
            running,
            link_type,
            &mut cap,
            savefile.as_mut(),
            web_handle.as_ref(),
        )?;
    }

    print_kernel_capture_stats(&mut cap);

    println!("{}", "=".repeat(50));

    Ok(())
}

fn validate_capture_config(config: &RuntimeConfig) -> Result<(), Box<dyn std::error::Error>> {
    if config.capture.interface.is_some() && config.capture.read_pcap.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "configuration error: capture.interface and capture.read_pcap are mutually exclusive",
        )
        .into());
    }

    let rotate_mb = config.output.write_pcap_rotate_mb;
    let max_files = config.output.write_pcap_max_files;
    let rotation_requested = rotate_mb > 0 || max_files > 0;
    if rotation_requested {
        if config.output.write_pcap.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "configuration error: output.write_pcap must be set when pcap rotation is enabled",
            )
            .into());
        }
        if rotate_mb == 0 || max_files == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "configuration error: output.write_pcap_rotate_mb and output.write_pcap_max_files must both be > 0 when rotation is enabled",
            )
            .into());
        }
    }

    Ok(())
}

fn open_capture_source(
    config: &RuntimeConfig,
) -> Result<CaptureSource, Box<dyn std::error::Error>> {
    if let Some(path) = config.capture.read_pcap.as_deref() {
        Ok(CaptureSource::Offline(capture::engine::open_offline(
            path,
            config.capture.filter.as_deref(),
        )?))
    } else {
        let capture_config = capture::engine::CaptureConfig {
            interface: config.capture.interface.clone(),
            promiscuous: config.capture.promiscuous,
            snaplen: config.capture.snaplen,
            timeout_ms: config.capture.timeout_ms,
            buffer_size_mb: config.capture.buffer_size_mb,
            immediate_mode: config.capture.immediate_mode,
            filter: config.capture.filter.clone(),
        };
        Ok(CaptureSource::Live(capture::engine::open_capture(
            &capture_config,
        )?))
    }
}

fn start_web_dashboard(
    config: &RuntimeConfig,
) -> Result<Option<web::server::WebHandle>, Box<dyn std::error::Error>> {
    if !config.web.enabled {
        return Ok(None);
    }

    config.web.validate().map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid web dashboard config: {}", err),
        )
    })?;

    let tls = if config.web.tls.enabled {
        Some(web::server::WebServerTlsConfig {
            cert_path: config
                .web
                .tls
                .cert_path
                .clone()
                .expect("web tls cert_path validated"),
            key_path: config
                .web
                .tls
                .key_path
                .clone()
                .expect("web tls key_path validated"),
        })
    } else {
        None
    };

    let auth = if config.web.auth.enabled {
        let password = config
            .web
            .auth
            .resolve_password()
            .map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid web dashboard config: {}", err),
                )
            })?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid web dashboard config: web auth enabled but no password resolved",
                )
            })?;

        Some(web::server::WebServerAuthConfig {
            username: config.web.auth.username.clone(),
            password,
        })
    } else {
        None
    };

    if auth.is_some() && tls.is_none() {
        eprintln!(
            "warning: web auth is enabled without TLS; credentials will be sent in cleartext"
        );
    }

    let server_config = web::server::WebServerConfig {
        bind: config.web.bind.clone(),
        port: config.web.port,
        tick_ms: config.web.tick_ms,
        packet_buffer: config.web.packet_buffer,
        tls,
        auth,
    };
    let handle = web::server::start(server_config)
        .map_err(|err| std::io::Error::other(format!("error starting web dashboard: {}", err)))?;

    Ok(Some(handle))
}

fn print_capture_intro(
    config: &RuntimeConfig,
    capture_mode: CaptureMode,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("NetScope v{}", env!("CARGO_PKG_VERSION"));
    match capture_mode {
        CaptureMode::Live => {
            let interface_name = config.capture.interface.as_deref().unwrap_or("(default)");
            println!("Capturing on interface: {}", interface_name);
        }
        CaptureMode::Offline => match config.capture.read_pcap.as_ref() {
            Some(path) => println!("Reading packets from pcap: {}", path.display()),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "configuration error: offline capture requires capture.read_pcap path",
                )
                .into());
            }
        },
    }
    if let Some(filter) = &config.capture.filter {
        println!("Filter: {}", filter);
    }
    if config.run.count > 0 {
        println!("Processing {} packets...", config.run.count);
    } else {
        match capture_mode {
            CaptureMode::Live => println!("Capturing packets (Ctrl-C to stop)..."),
            CaptureMode::Offline => println!("Processing packets until EOF..."),
        }
    }
    Ok(())
}

fn print_kernel_capture_stats(cap: &mut CaptureSource) {
    match cap.stats() {
        Ok(Some(stats)) => {
            println!("  Kernel received:   {}", stats.received);
            println!("  Kernel dropped:    {}", stats.dropped);
            println!("  Interface dropped: {}", stats.if_dropped);
            if stats.received > 0 {
                let drop_pct = (stats.dropped as f64 / stats.received as f64) * 100.0;
                println!("  Drop rate:         {:.2}%", drop_pct);
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::debug!(error = %e, "failed to read pcap stats");
        }
    }
}

const SAVEFILE_FLUSH_INTERVAL_PACKETS: u64 = 1024;
const LIVE_PCAP_STATS_POLL_INTERVAL_MS: u64 = 250;
const SAVEFILE_GLOBAL_HEADER_BYTES: u64 = 24;
const SAVEFILE_PACKET_RECORD_BYTES: u64 = 16;

#[derive(Debug, Clone, Copy)]
struct PcapRotationPolicy {
    max_bytes: u64,
    max_files: usize,
}

impl PcapRotationPolicy {
    fn from_output(output: &config::OutputConfig) -> Option<Self> {
        if output.write_pcap_rotate_mb == 0 && output.write_pcap_max_files == 0 {
            return None;
        }
        Some(PcapRotationPolicy {
            max_bytes: output.write_pcap_rotate_mb.saturating_mul(1024 * 1024),
            max_files: output.write_pcap_max_files,
        })
    }
}

struct RotatingSavefile {
    base_path: PathBuf,
    rotation: Option<PcapRotationPolicy>,
    current_segment: u64,
    current_bytes: u64,
    rotate_pending: bool,
    segment_paths: VecDeque<PathBuf>,
    savefile: pcap::Savefile,
}

impl RotatingSavefile {
    fn open(
        cap: &mut CaptureSource,
        base_path: &Path,
        rotation: Option<PcapRotationPolicy>,
    ) -> Result<Self, pcap::Error> {
        if let Some(rotation) = rotation {
            let existing_segments = Self::collect_existing_segments(base_path);
            let first_segment = existing_segments
                .last()
                .map(|(segment, _)| segment.saturating_add(1))
                .unwrap_or(1);
            let path = Self::segment_path(base_path, first_segment);
            let savefile = cap.savefile(&path)?;
            let mut segment_paths: VecDeque<PathBuf> = existing_segments
                .into_iter()
                .map(|(_, path)| path)
                .collect();
            segment_paths.push_back(path);

            let mut writer = Self {
                base_path: base_path.to_path_buf(),
                rotation: Some(rotation),
                current_segment: first_segment,
                current_bytes: SAVEFILE_GLOBAL_HEADER_BYTES,
                rotate_pending: false,
                segment_paths,
                savefile,
            };
            writer.prune_old_segments(rotation.max_files);
            Ok(writer)
        } else {
            let savefile = cap.savefile(base_path)?;
            Ok(Self {
                base_path: base_path.to_path_buf(),
                rotation,
                current_segment: 0,
                current_bytes: 0,
                rotate_pending: false,
                segment_paths: VecDeque::new(),
                savefile,
            })
        }
    }

    fn write_packet(
        &mut self,
        packet: &pcap::Packet<'_>,
        packet_count: u64,
    ) -> Result<(), pcap::Error> {
        self.savefile.write(packet);
        if packet_count.is_multiple_of(SAVEFILE_FLUSH_INTERVAL_PACKETS) {
            self.savefile.flush()?;
        }

        if let Some(rotation) = self.rotation {
            self.current_bytes = self.current_bytes.saturating_add(
                SAVEFILE_PACKET_RECORD_BYTES.saturating_add(packet.data.len() as u64),
            );
            if self.current_bytes >= rotation.max_bytes {
                self.rotate_pending = true;
            }
        }

        Ok(())
    }

    fn rotate_if_needed(&mut self, cap: &mut CaptureSource) -> Result<(), pcap::Error> {
        let Some(rotation) = self.rotation else {
            return Ok(());
        };
        if !self.rotate_pending {
            return Ok(());
        }

        self.savefile.flush()?;
        self.current_segment = self.current_segment.saturating_add(1);
        let next_path = Self::segment_path(&self.base_path, self.current_segment);
        self.savefile = cap.savefile(&next_path)?;
        self.current_bytes = SAVEFILE_GLOBAL_HEADER_BYTES;
        self.rotate_pending = false;
        self.segment_paths.push_back(next_path);
        self.prune_old_segments(rotation.max_files);

        Ok(())
    }

    fn flush(&mut self) -> Result<(), pcap::Error> {
        self.savefile.flush()
    }

    fn segment_path(base_path: &Path, segment: u64) -> PathBuf {
        let parent = base_path.parent().unwrap_or_else(|| Path::new(""));
        let stem = base_path
            .file_stem()
            .or_else(|| base_path.file_name())
            .unwrap_or_else(|| OsStr::new("capture"));

        let mut filename = OsString::from(stem);
        filename.push(format!(".{:06}", segment));
        if let Some(ext) = base_path.extension() {
            filename.push(".");
            filename.push(ext);
        }

        parent.join(filename)
    }

    fn collect_existing_segments(base_path: &Path) -> Vec<(u64, PathBuf)> {
        let parent = base_path.parent().unwrap_or_else(|| Path::new("."));
        let mut segments = Vec::new();

        let entries = match std::fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::debug!(
                    path = %parent.display(),
                    error = %err,
                    "failed to read pcap rotation directory"
                );
                return segments;
            }
        };

        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|file_type| file_type.is_file()) {
                continue;
            }

            let path = entry.path();
            if let Some(segment) = Self::parse_segment_index(base_path, &path) {
                segments.push((segment, path));
            }
        }

        segments.sort_unstable_by_key(|(segment, _)| *segment);
        segments
    }

    fn parse_segment_index(base_path: &Path, path: &Path) -> Option<u64> {
        let file_name = path.file_name()?.to_string_lossy();
        let stem = base_path
            .file_stem()
            .or_else(|| base_path.file_name())
            .unwrap_or_else(|| OsStr::new("capture"))
            .to_string_lossy();

        let with_stem_prefix = format!("{}.", stem);

        let index_str = if let Some(ext) = base_path.extension() {
            let ext_suffix = format!(".{}", ext.to_string_lossy());
            let without_ext = file_name.strip_suffix(&ext_suffix)?;
            without_ext.strip_prefix(&with_stem_prefix)?
        } else {
            file_name.strip_prefix(&with_stem_prefix)?
        };

        index_str.parse().ok()
    }

    fn prune_old_segments(&mut self, max_files: usize) {
        while self.segment_paths.len() > max_files {
            if let Some(old_path) = self.segment_paths.pop_front()
                && let Err(err) = std::fs::remove_file(&old_path)
            {
                tracing::warn!(
                    path = %old_path.display(),
                    error = %err,
                    "failed to remove old rotated pcap file"
                );
            }
        }
    }
}

fn write_packet_to_savefile(
    savefile: &mut Option<&mut RotatingSavefile>,
    packet: &pcap::Packet<'_>,
    packet_count: u64,
) -> Result<(), pcap::Error> {
    if let Some(file) = savefile.as_mut() {
        file.write_packet(packet, packet_count)?;
    }
    Ok(())
}

fn maybe_rotate_savefile(
    cap: &mut CaptureSource,
    savefile: &mut Option<&mut RotatingSavefile>,
) -> Result<(), pcap::Error> {
    if let Some(file) = savefile.as_mut() {
        file.rotate_if_needed(cap)?;
    }
    Ok(())
}

fn flush_savefile(savefile: &mut Option<&mut RotatingSavefile>) -> Result<(), pcap::Error> {
    if let Some(file) = savefile.as_mut() {
        file.flush()?;
    }
    Ok(())
}

#[derive(Debug, Default)]
struct InlineKernelStats {
    dropped_total: u64,
    if_dropped_total: u64,
    dropped_interval_stats: u64,
    if_dropped_interval_stats: u64,
    dropped_interval_web: u64,
    if_dropped_interval_web: u64,
    initialized: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct PcapDropSnapshot {
    dropped_total: u64,
    if_dropped_total: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct PcapDropDelta {
    dropped: u64,
    if_dropped: u64,
}

impl InlineKernelStats {
    fn update_totals(&mut self, dropped_total: u64, if_dropped_total: u64) {
        let dropped_delta = if self.initialized {
            dropped_total.saturating_sub(self.dropped_total)
        } else {
            0
        };
        let if_dropped_delta = if self.initialized {
            if_dropped_total.saturating_sub(self.if_dropped_total)
        } else {
            0
        };
        self.dropped_total = dropped_total;
        self.if_dropped_total = if_dropped_total;
        self.dropped_interval_stats = self.dropped_interval_stats.saturating_add(dropped_delta);
        self.if_dropped_interval_stats = self
            .if_dropped_interval_stats
            .saturating_add(if_dropped_delta);
        self.dropped_interval_web = self.dropped_interval_web.saturating_add(dropped_delta);
        self.if_dropped_interval_web = self
            .if_dropped_interval_web
            .saturating_add(if_dropped_delta);
        self.initialized = true;
    }

    fn take_stats_interval(&mut self) -> (u64, u64) {
        let dropped = self.dropped_interval_stats;
        let if_dropped = self.if_dropped_interval_stats;
        self.dropped_interval_stats = 0;
        self.if_dropped_interval_stats = 0;
        (dropped, if_dropped)
    }

    fn take_web_interval(&mut self) -> (u64, u64) {
        let dropped = self.dropped_interval_web;
        let if_dropped = self.if_dropped_interval_web;
        self.dropped_interval_web = 0;
        self.if_dropped_interval_web = 0;
        (dropped, if_dropped)
    }
}

fn maybe_poll_live_pcap_stats(
    cap: &mut CaptureSource,
    last_poll: &mut Instant,
) -> Option<(u64, u64)> {
    let now = Instant::now();
    if (now.duration_since(*last_poll).as_millis() as u64) < LIVE_PCAP_STATS_POLL_INTERVAL_MS {
        return None;
    }
    *last_poll = now;

    match cap.stats() {
        Ok(Some(stats)) => Some((stats.dropped as u64, stats.if_dropped as u64)),
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(error = %e, "failed to read live pcap stats");
            None
        }
    }
}

#[inline]
fn unix_secs_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn flush_expired_flows_jsonl(
    sink: &mut Option<netscope::jsonl::JsonlSink>,
    events: &mut Vec<flow::ExpiredFlowEvent>,
) {
    if events.is_empty() {
        return;
    }
    let drained = std::mem::take(events);
    if let Some(sink) = sink.as_mut() {
        for event in drained {
            if let Err(err) = sink.write(&event) {
                eprintln!("expired flow write error: {}", err);
            }
        }
        if let Err(err) = sink.flush() {
            eprintln!("expired flow flush error: {}", err);
        }
    }
}

/// Original single-threaded capture loop (no pipeline).
fn run_capture_inline(
    config: &RuntimeConfig,
    running: &Arc<AtomicBool>,
    link_type: protocol::LinkType,
    cap: &mut CaptureSource,
    mut savefile: Option<&mut RotatingSavefile>,
    web_handle: Option<&web::server::WebHandle>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();

    let mut packet_count: u64 = 0;
    let mut parse_errors: u64 = 0;
    let mut flow_tracker = flow::FlowTracker::new(
        config.flow.timeout_secs,
        config.flow.max_flows,
        config.analysis.rtt,
        config.analysis.retrans,
        config.analysis.out_of_order,
    );
    let mut anomaly_detector = analysis::anomaly::AnomalyDetector::new(
        config.analysis.anomalies.clone(),
        config.analysis.alerts_jsonl.as_deref(),
    );
    let mut expired_flow_sink = match config.output.expired_flows_jsonl.as_deref() {
        Some(path) => match netscope::jsonl::JsonlSink::new(path) {
            Ok(sink) => Some(sink),
            Err(err) => {
                eprintln!("expired flow file disabled: {}", err);
                None
            }
        },
        None => None,
    };
    let mut expired_flow_events: Vec<flow::ExpiredFlowEvent> = Vec::new();
    let mut last_expire_check_ts: f64 = 0.0;

    let mut stats_last = Instant::now();
    let mut stats_bytes: u64 = 0;
    let mut stats_packets: u64 = 0;
    let mut kernel_stats = InlineKernelStats::default();
    let mut live_stats_poll_last = if cap.mode() == CaptureMode::Live {
        Some(
            Instant::now()
                .checked_sub(Duration::from_millis(LIVE_PCAP_STATS_POLL_INTERVAL_MS))
                .unwrap_or_else(Instant::now),
        )
    } else {
        None
    };

    // Web dashboard tick state
    let mut web_tick_last = Instant::now();
    let mut web_tick_bytes: u64 = 0;
    let mut web_tick_packets: u64 = 0;
    let mut web_frame_seq: u64 = 0;

    while running.load(Ordering::SeqCst) {
        // Check packet count limit
        if config.run.count > 0 && packet_count >= config.run.count {
            break;
        }

        if let Err(err) = maybe_rotate_savefile(cap, &mut savefile) {
            tracing::error!(error = %err, "pcap rotate error");
            return Err(Box::new(err));
        }

        // Read next packet
        let packet = match cap.next_packet() {
            Ok(CaptureRead::Packet(packet)) => Some(packet),
            Ok(CaptureRead::Idle) => None,
            Ok(CaptureRead::Eof) => break,
            Err(e) => {
                tracing::error!(error = %e, "capture error");
                return Err(Box::new(e));
            }
        };

        if let Some(packet) = packet {
            packet_count += 1;

            let timestamp =
                packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
            let raw_data = packet.data;
            let wire_len = packet.header.len as u64;

            if let Err(err) = write_packet_to_savefile(&mut savefile, &packet, packet_count) {
                tracing::error!(error = %err, "pcap write error");
                return Err(Box::new(err));
            }

            // Parse the packet
            match protocol::parse_packet_with_linktype(raw_data, link_type) {
                Ok(parsed) => {
                    if config.analysis.anomalies.enabled {
                        let alerts =
                            maybe_analyze_anomaly(&mut anomaly_detector, timestamp, &parsed);
                        for alert in &alerts {
                            println!("[alert] {}", alert.description);
                            // Forward alerts to web dashboard
                            if let Some(handle) = web_handle
                                && handle
                                    .event_tx
                                    .try_send(web::messages::CaptureEvent::Alert(
                                        web::messages::AlertMsg {
                                            ts: alert.ts,
                                            kind: format!("{:?}", alert.kind),
                                            description: alert.description.clone(),
                                        },
                                    ))
                                    .is_err()
                            {
                                tracing::trace!("web event channel full, dropping alert");
                            }
                        }
                    }
                    flow_tracker.observe(timestamp, wire_len, &parsed);

                    // Send packet samples to web dashboard.
                    if let Some(handle) = web_handle
                        && config.web.sample_rate > 0
                        && packet_count.is_multiple_of(config.web.sample_rate)
                    {
                        let (sample, stored) = build_packet_data(
                            packet_count,
                            timestamp,
                            raw_data,
                            &parsed,
                            config.web.payload_bytes,
                        );
                        if handle
                            .event_tx
                            .try_send(web::messages::CaptureEvent::Packet(sample))
                            .is_err()
                        {
                            tracing::trace!("web event channel full, dropping packet sample");
                        }
                        if handle
                            .event_tx
                            .try_send(web::messages::CaptureEvent::PacketStored(stored))
                            .is_err()
                        {
                            tracing::trace!("web event channel full, dropping stored packet");
                        }
                    }

                    if config.output.hex_dump || config.verbose_level >= 2 {
                        display::print_packet_detail(packet_count, timestamp, raw_data, &parsed);
                    } else if !config.output.quiet {
                        display::print_packet_summary(packet_count, timestamp, &parsed);
                    }
                }
                Err(e) => {
                    parse_errors += 1;
                    display::print_parse_error(packet_count, timestamp, raw_data.len(), &e);
                    tracing::debug!(error = %e, "parse error on packet #{}", packet_count);
                }
            }

            stats_bytes += wire_len;
            stats_packets += 1;
            web_tick_bytes += wire_len;
            web_tick_packets += 1;

            if timestamp < last_expire_check_ts {
                last_expire_check_ts = timestamp;
            } else if (timestamp - last_expire_check_ts) >= 1.0 {
                last_expire_check_ts = timestamp;
                if expired_flow_sink.is_some() {
                    flow_tracker.maybe_expire_collect(timestamp, &mut expired_flow_events);
                    flush_expired_flows_jsonl(&mut expired_flow_sink, &mut expired_flow_events);
                } else {
                    flow_tracker.maybe_expire(timestamp);
                }
            }
        } else {
            let now_ts = unix_secs_now();
            if now_ts < last_expire_check_ts {
                last_expire_check_ts = now_ts;
            } else if (now_ts - last_expire_check_ts) >= 1.0 {
                last_expire_check_ts = now_ts;
                if expired_flow_sink.is_some() {
                    flow_tracker.maybe_expire_collect(now_ts, &mut expired_flow_events);
                    flush_expired_flows_jsonl(&mut expired_flow_sink, &mut expired_flow_events);
                } else {
                    flow_tracker.maybe_expire(now_ts);
                }
            }
        }

        if let Some(last_poll) = live_stats_poll_last.as_mut()
            && let Some((dropped_total, if_dropped_total)) =
                maybe_poll_live_pcap_stats(cap, last_poll)
        {
            kernel_stats.update_totals(dropped_total, if_dropped_total);
        }

        // Stats printing
        let now = Instant::now();
        if config.stats.enabled
            && now.duration_since(stats_last).as_millis() as u64 >= config.stats.interval_ms
        {
            let elapsed = now.duration_since(stats_last).as_secs_f64().max(0.001);
            let mbps = stats_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
            let pps = stats_packets as f64 / elapsed;
            let active_flows = flow_tracker.len();
            let (kernel_drops, kernel_if_drops) = kernel_stats.take_stats_interval();
            let kernel_snapshot = PcapDropSnapshot {
                dropped_total: kernel_stats.dropped_total,
                if_dropped_total: kernel_stats.if_dropped_total,
            };
            println!(
                "[stats] {:.2} Mbps | {:.0} pps | {} flows | kdrop={} (total={}) ifdrop={} (total={})",
                mbps,
                pps,
                active_flows,
                kernel_drops,
                kernel_snapshot.dropped_total,
                kernel_if_drops,
                kernel_snapshot.if_dropped_total
            );

            if config.stats.top_flows > 0 {
                let top = flow_tracker.top_flows_by_delta(config.stats.top_flows as usize);
                for (rank, entry) in top.iter().enumerate() {
                    let mbps = entry.delta_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
                    println!("  {}. {} {:.2} Mbps", rank + 1, entry.key, mbps);
                }
            }

            stats_last = now;
            stats_bytes = 0;
            stats_packets = 0;
        }

        // Web dashboard tick
        if let Some(handle) = web_handle {
            let now = Instant::now();
            if now.duration_since(web_tick_last).as_millis() as u64 >= config.web.tick_ms {
                let elapsed = now.duration_since(web_tick_last).as_secs_f64().max(0.001);
                let mbps = web_tick_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
                let pps = web_tick_packets as f64 / elapsed;
                let active_flows = flow_tracker.len();

                let top_deltas = flow_tracker.top_flows_with_snapshot(config.web.top_n);
                let top_flows: Vec<web::messages::FlowInfo> = top_deltas
                    .iter()
                    .map(|(delta, snap)| {
                        web::messages::FlowInfo::from_snapshot_delta(
                            snap,
                            delta.delta_bytes,
                            elapsed,
                        )
                    })
                    .collect();
                let (kernel_drops, kernel_if_drops) = kernel_stats.take_web_interval();
                let kernel_snapshot = PcapDropSnapshot {
                    dropped_total: kernel_stats.dropped_total,
                    if_dropped_total: kernel_stats.if_dropped_total,
                };
                let kernel_delta = PcapDropDelta {
                    dropped: kernel_drops,
                    if_dropped: kernel_if_drops,
                };

                let tick = web::messages::StatsTick {
                    ts: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64(),
                    frame_seq: web_frame_seq,
                    server_ts: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    interval_ms: config.web.tick_ms,
                    bytes: web_tick_bytes,
                    packets: web_tick_packets,
                    mbps,
                    pps,
                    active_flows,
                    dispatch_drops: 0,
                    dispatch_drops_total: 0,
                    kernel_drops: kernel_delta.dropped,
                    kernel_drops_total: kernel_snapshot.dropped_total,
                    kernel_if_drops: kernel_delta.if_dropped,
                    kernel_if_drops_total: kernel_snapshot.if_dropped_total,
                    top_flows,
                };

                if handle
                    .event_tx
                    .try_send(web::messages::CaptureEvent::Tick(tick))
                    .is_err()
                {
                    tracing::trace!("web event channel full, dropping stats tick");
                }

                web_frame_seq = web_frame_seq.wrapping_add(1);

                web_tick_last = now;
                web_tick_bytes = 0;
                web_tick_packets = 0;
            }
        }
    }

    flush_expired_flows_jsonl(&mut expired_flow_sink, &mut expired_flow_events);

    if let Err(err) = flush_savefile(&mut savefile) {
        tracing::error!(error = %err, "pcap flush error");
        return Err(Box::new(err));
    }

    // Print summary
    println!();
    println!("{}", "=".repeat(50));
    println!("Capture complete.");
    println!("  Packets captured:  {}", packet_count);
    println!("  Parse errors:      {}", parse_errors);
    println!(
        "  Success rate:      {:.1}%",
        if packet_count > 0 {
            (packet_count - parse_errors) as f64 / packet_count as f64 * 100.0
        } else {
            0.0
        }
    );

    if config.output.export_json.is_some() || config.output.export_csv.is_some() {
        let snapshot = flow_tracker.snapshot();
        if let Some(path) = &config.output.export_json {
            flow::write_flow_json(path.as_ref(), &snapshot)?;
            println!("  Flow export (JSON): {}", path.display());
        }
        if let Some(path) = &config.output.export_csv {
            flow::write_flow_csv(path.as_ref(), &snapshot)?;
            println!("  Flow export (CSV):  {}", path.display());
        }
    }

    Ok(())
}

/// Sharded pipeline capture loop: the main thread only reads from pcap
/// and dispatches owned packet buffers to worker shards.
fn run_capture_pipeline(
    config: &RuntimeConfig,
    running: &Arc<AtomicBool>,
    link_type: protocol::LinkType,
    cap: &mut CaptureSource,
    mut savefile: Option<&mut RotatingSavefile>,
    web_handle: Option<&web::server::WebHandle>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use the full snaplen as the pool buffer size so every captured packet
    // fits without reallocation. Fall back to 65535 if snaplen is 0 (unset).
    let packet_buf_size = match config.capture.snaplen {
        s if s > 0 => s as usize,
        _ => 65535,
    };
    let kernel_stats = Arc::new(pipeline::KernelPcapStats::new());

    let pipeline_cfg = pipeline::PipelineConfig {
        num_workers: config.pipeline.workers,
        channel_capacity: config.pipeline.channel_capacity,
        buffer_pool_capacity: config.pipeline.channel_capacity.saturating_mul(2).max(1),
        packet_buf_size,
        flow: config.flow.clone(),
        analysis: config.analysis.clone(),
        stats: config.stats.clone(),
        web: config.web.clone(),
        heavy_hitter_top_n: config.web.top_n.max(config.stats.top_flows as usize),
        alerts_jsonl: config.analysis.alerts_jsonl.clone(),
        expired_flows_jsonl: config.output.expired_flows_jsonl.clone(),
        kernel_stats: kernel_stats.clone(),
        link_type,
    };

    let mut pipe = pipeline::spawn(pipeline_cfg, running.clone(), web_handle);
    let num_workers = pipe.num_workers();
    println!("Pipeline: {} worker shards", num_workers);
    println!();

    let mut packet_count: u64 = 0;
    let mut stats_last = Instant::now();
    let mut final_kernel_stats: Option<(u64, u64)> = None;
    let mut live_stats_poll_last = if cap.mode() == CaptureMode::Live {
        Some(
            Instant::now()
                .checked_sub(Duration::from_millis(LIVE_PCAP_STATS_POLL_INTERVAL_MS))
                .unwrap_or_else(Instant::now),
        )
    } else {
        None
    };

    let capture_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        while running.load(Ordering::SeqCst) {
            if config.run.count > 0 && packet_count >= config.run.count {
                break;
            }

            if let Err(err) = maybe_rotate_savefile(cap, &mut savefile) {
                tracing::error!(error = %err, "pcap rotate error");
                return Err(Box::new(err));
            }

            let packet = match cap.next_packet() {
                Ok(CaptureRead::Packet(packet)) => Some(packet),
                Ok(CaptureRead::Idle) => None,
                Ok(CaptureRead::Eof) => break,
                Err(e) => {
                    tracing::error!(error = %e, "capture error");
                    return Err(Box::new(e));
                }
            };

            if let Some(packet) = packet {
                packet_count += 1;

                let timestamp =
                    packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
                let raw_data = packet.data;
                let wire_len = packet.header.len as u64;

                // Write to pcap file (still on capture thread — fast sequential I/O)
                if let Err(err) = write_packet_to_savefile(&mut savefile, &packet, packet_count) {
                    tracing::error!(error = %err, "pcap write error");
                    return Err(Box::new(err));
                }

                // Determine shard and dispatch
                let shard = pipeline::router::shard_for_packet_with_linktype(
                    raw_data,
                    num_workers,
                    link_type,
                );
                let mut buf = pipe.buffer_pool.acquire();
                buf.extend_from_slice(raw_data);
                let owned = pipeline::OwnedPacket {
                    id: packet_count,
                    ts: timestamp,
                    wire_len,
                    data: buf,
                };

                match pipe.senders[shard].try_send(owned) {
                    Ok(_) => {}
                    Err(err) => {
                        pipe.stats.record_dispatch_drop();
                        let dropped = err.into_inner();
                        pipe.buffer_pool.release(dropped.data);
                        tracing::trace!(shard, "worker channel full, dropping packet");
                    }
                }
            }

            if let Some(last_poll) = live_stats_poll_last.as_mut()
                && let Some((dropped_total, if_dropped_total)) =
                    maybe_poll_live_pcap_stats(cap, last_poll)
            {
                kernel_stats.update_totals(dropped_total, if_dropped_total);
            }

            // CLI stats from aggregator
            let now = Instant::now();
            if config.stats.enabled
                && now.duration_since(stats_last).as_millis() as u64 >= config.stats.interval_ms
            {
                if let Some(tick) = pipe.aggregator.take_tick() {
                    println!(
                        "[stats] {:.2} Mbps | {:.0} pps | {} flows | drops={} (total={}) | kdrop={} (total={}) ifdrop={} (total={})",
                        tick.mbps,
                        tick.pps,
                        tick.active_flows,
                        tick.dispatch_drops,
                        tick.dispatch_drops_total,
                        tick.kernel_drops,
                        tick.kernel_drops_total,
                        tick.kernel_if_drops,
                        tick.kernel_if_drops_total
                    );
                    if config.stats.top_flows > 0 {
                        let elapsed = (tick.interval_ms as f64 / 1000.0).max(0.001);
                        for (rank, (delta, _snap)) in tick
                            .top_flows
                            .iter()
                            .enumerate()
                            .take(config.stats.top_flows as usize)
                        {
                            let mbps = delta.delta_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
                            println!("  {}. {} {:.2} Mbps", rank + 1, delta.key, mbps);
                        }
                    }
                }
                stats_last = now;
            }
        }

        if let Err(err) = flush_savefile(&mut savefile) {
            tracing::error!(error = %err, "pcap flush error");
            return Err(Box::new(err));
        }

        final_kernel_stats = Some((
            kernel_stats.dropped_total(),
            kernel_stats.if_dropped_total(),
        ));

        Ok(())
    })();

    if final_kernel_stats.is_none() {
        final_kernel_stats = Some((
            kernel_stats.dropped_total(),
            kernel_stats.if_dropped_total(),
        ));
    }

    // Always shut down worker/aggregator threads before returning, including
    // capture/savefile error paths.
    pipe.shutdown();
    capture_result?;

    // Print summary
    println!();
    println!("{}", "=".repeat(50));
    println!("Capture complete (pipeline mode).");
    println!("  Packets captured:  {}", packet_count);
    println!("  Dispatch drops:    {}", pipe.stats.dispatch_drops_total());
    if let Some((kernel_dropped, if_dropped)) = final_kernel_stats {
        println!("  Kernel dropped:    {}", kernel_dropped);
        println!("  Interface dropped: {}", if_dropped);
    }

    // Export flows from aggregated shard snapshots (shutdown() joins all
    // worker threads, so snapshots are guaranteed to be present).
    if config.output.export_json.is_some() || config.output.export_csv.is_some() {
        let snapshot = pipe.aggregator.take_final_snapshots();
        if let Some(path) = &config.output.export_json {
            flow::write_flow_json(path.as_ref(), &snapshot)?;
            println!("  Flow export (JSON): {}", path.display());
        }
        if let Some(path) = &config.output.export_csv {
            flow::write_flow_csv(path.as_ref(), &snapshot)?;
            println!("  Flow export (CSV):  {}", path.display());
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct RuntimeConfig {
    capture: config::CaptureConfig,
    run: config::RunConfig,
    output: config::OutputConfig,
    flow: config::FlowConfig,
    stats: config::StatsConfig,
    analysis: config::AnalysisConfig,
    web: config::WebConfig,
    pipeline: config::PipelineConfig,
    verbose_level: u8,
}

fn load_config(args: &cli::Cli) -> Result<RuntimeConfig, config::ConfigError> {
    let base = match &args.config {
        Some(path) => config::Config::load(path)?,
        None => config::Config::default(),
    };

    let mut capture = base.capture.clone();
    let mut run = base.run.clone();
    let mut output = base.output.clone();
    let mut flow = base.flow.clone();
    let mut stats = base.stats.clone();
    let mut analysis = base.analysis.clone();
    let mut web = base.web.clone();

    if let Some(value) = &args.interface {
        capture.interface = Some(value.clone());
        capture.read_pcap = None;
    }
    if let Some(value) = &args.read_pcap {
        if value.as_os_str().is_empty() {
            capture.read_pcap = None;
        } else {
            capture.read_pcap = Some(value.clone());
            capture.interface = None;
        }
    }
    if let Some(value) = &args.filter {
        capture.filter = Some(value.clone());
    }
    if let Some(value) = args.count {
        run.count = value;
    }
    if let Some(value) = args.snaplen {
        capture.snaplen = value;
    }
    if let Some(value) = args.timeout_ms {
        capture.timeout_ms = value;
    }
    if let Some(value) = args.stats_interval_ms {
        stats.interval_ms = value;
    }
    if let Some(value) = args.top_flows {
        stats.top_flows = value;
    }
    if let Some(value) = args.flow_timeout_s {
        flow.timeout_secs = value;
    }
    if let Some(value) = args.max_flows {
        flow.max_flows = value;
    }
    if let Some(value) = &args.write_pcap {
        output.write_pcap = Some(value.clone());
    }
    if let Some(value) = args.write_pcap_rotate_mb {
        output.write_pcap_rotate_mb = value;
    }
    if let Some(value) = args.write_pcap_max_files {
        output.write_pcap_max_files = value;
    }
    if let Some(value) = &args.export_json {
        output.export_json = Some(value.clone());
    }
    if let Some(value) = &args.export_csv {
        output.export_csv = Some(value.clone());
    }
    if let Some(value) = &args.alerts_jsonl {
        if value.as_os_str().is_empty() {
            analysis.alerts_jsonl = None;
        } else {
            analysis.alerts_jsonl = Some(value.clone());
        }
    }
    if let Some(value) = &args.expired_flows_jsonl {
        if value.as_os_str().is_empty() {
            output.expired_flows_jsonl = None;
        } else {
            output.expired_flows_jsonl = Some(value.clone());
        }
    }

    if args.promiscuous {
        capture.promiscuous = true;
    }
    if args.no_promiscuous {
        capture.promiscuous = false;
    }
    if args.hex_dump {
        output.hex_dump = true;
    }
    if args.no_hex_dump {
        output.hex_dump = false;
    }
    if args.quiet {
        output.quiet = true;
    }
    if args.no_quiet {
        output.quiet = false;
    }
    if args.stats {
        stats.enabled = true;
    }
    if args.no_stats {
        stats.enabled = false;
    }
    if args.anomalies {
        analysis.anomalies.enabled = true;
    }
    if args.no_anomalies {
        analysis.anomalies.enabled = false;
    }
    if args.web {
        web.enabled = true;
    }
    if args.no_web {
        web.enabled = false;
    }
    if let Some(value) = &args.web_bind {
        web.bind = value.clone();
    }
    if let Some(value) = args.web_port {
        web.port = value;
    }
    if args.web_tls {
        web.tls.enabled = true;
    }
    if args.no_web_tls {
        web.tls.enabled = false;
    }
    if let Some(value) = &args.web_tls_cert {
        if value.as_os_str().is_empty() {
            web.tls.cert_path = None;
        } else {
            web.tls.cert_path = Some(value.clone());
        }
    }
    if let Some(value) = &args.web_tls_key {
        if value.as_os_str().is_empty() {
            web.tls.key_path = None;
        } else {
            web.tls.key_path = Some(value.clone());
        }
    }
    if args.web_auth {
        web.auth.enabled = true;
    }
    if args.no_web_auth {
        web.auth.enabled = false;
    }
    if let Some(value) = &args.web_auth_user {
        web.auth.username = value.clone();
    }
    if let Some(value) = &args.web_auth_pass_file {
        if value.as_os_str().is_empty() {
            web.auth.password_file = None;
        } else {
            web.auth.password_file = Some(value.clone());
            web.auth.password = None;
        }
    }
    web.normalize();

    let mut pipeline = base.pipeline.clone();
    if args.pipeline {
        pipeline.enabled = true;
    }
    if args.workers > 0 {
        pipeline.workers = args.workers;
        pipeline.enabled = true;
    }

    Ok(RuntimeConfig {
        capture,
        run,
        output,
        flow,
        stats,
        analysis,
        web,
        pipeline,
        verbose_level: args.verbose,
    })
}
