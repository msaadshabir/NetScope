mod analysis;
mod capture;
mod cli;
mod config;
mod display;
mod flow;
mod protocol;

use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let args = cli::Cli::parse();

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

    let config = match load_config(&args) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {}", err);
            std::process::exit(1);
        }
    };

    // Handle --list-interfaces
    if args.list_interfaces {
        list_interfaces();
        return;
    }

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

/// List available network interfaces and print them.
fn list_interfaces() {
    match capture::engine::list_interfaces() {
        Ok(devices) => {
            println!("Available network interfaces:");
            println!("{:<20} {:<20} {}", "Name", "Description", "Addresses");
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

/// Main capture loop: open capture, read packets, parse, and display.
fn run_capture(
    config: &RuntimeConfig,
    running: &Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_config = capture::engine::CaptureConfig {
        interface: config.capture.interface.clone(),
        promiscuous: config.capture.promiscuous,
        snaplen: config.capture.snaplen,
        timeout_ms: config.capture.timeout_ms,
        filter: config.capture.filter.clone(),
    };

    let mut cap = capture::engine::open_capture(&capture_config)?;
    let mut savefile = match &config.output.write_pcap {
        Some(path) => Some(cap.savefile(path)?),
        None => None,
    };

    let interface_name = config.capture.interface.as_deref().unwrap_or("(default)");

    println!("NetScope v{}", env!("CARGO_PKG_VERSION"));
    println!("Capturing on interface: {}", interface_name);
    if let Some(filter) = &config.capture.filter {
        println!("Filter: {}", filter);
    }
    if config.run.count > 0 {
        println!("Capturing {} packets...", config.run.count);
    } else {
        println!("Capturing packets (Ctrl-C to stop)...");
    }
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

    let mut stats_last = Instant::now();
    let mut stats_bytes: u64 = 0;
    let mut stats_packets: u64 = 0;

    while running.load(Ordering::SeqCst) {
        // Check packet count limit
        if config.run.count > 0 && packet_count >= config.run.count {
            break;
        }

        // Read next packet
        let packet = match cap.next_packet() {
            Ok(packet) => Some(packet),
            Err(pcap::Error::TimeoutExpired) => None,
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

            if let Some(file) = savefile.as_mut() {
                file.write(&packet);
            }

            // Parse the packet
            match protocol::parse_packet(raw_data) {
                Ok(parsed) => {
                    if config.analysis.anomalies.enabled {
                        let alerts =
                            maybe_analyze_anomaly(&mut anomaly_detector, timestamp, &parsed);
                        for alert in alerts {
                            println!("[alert] {}", alert.description);
                        }
                    }
                    flow_tracker.observe(timestamp, wire_len, &parsed);
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

            flow_tracker.maybe_expire(timestamp);
        }

        // Stats printing runs on every loop iteration (including timeouts)
        // so stats are reported even during traffic lulls
        let now = Instant::now();
        if config.stats.enabled
            && now.duration_since(stats_last).as_millis() as u64 >= config.stats.interval_ms
        {
            let elapsed = now.duration_since(stats_last).as_secs_f64().max(0.001);
            let mbps = stats_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
            let pps = stats_packets as f64 / elapsed;
            let active_flows = flow_tracker.len();
            println!(
                "[stats] {:.2} Mbps | {:.0} pps | {} flows",
                mbps, pps, active_flows
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
    }

    // Print summary statistics
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
    println!("{}", "=".repeat(50));

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

#[derive(Debug, Clone)]
struct RuntimeConfig {
    capture: config::CaptureConfig,
    run: config::RunConfig,
    output: config::OutputConfig,
    flow: config::FlowConfig,
    stats: config::StatsConfig,
    analysis: config::AnalysisConfig,
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

    if let Some(value) = &args.interface {
        capture.interface = Some(value.clone());
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

    Ok(RuntimeConfig {
        capture,
        run,
        output,
        flow,
        stats,
        analysis,
        verbose_level: args.verbose,
    })
}

fn maybe_analyze_anomaly(
    detector: &mut analysis::anomaly::AnomalyDetector,
    ts: f64,
    packet: &protocol::ParsedPacket<'_>,
) -> Vec<analysis::anomaly::Alert> {
    let (src_ip, dst_ip, skip_flow) = match &packet.network {
        Some(protocol::NetworkHeader::Ipv4(hdr)) => {
            let skip = hdr.fragment_offset() != 0;
            (
                std::net::IpAddr::V4(hdr.src_addr()),
                std::net::IpAddr::V4(hdr.dst_addr()),
                skip,
            )
        }
        Some(protocol::NetworkHeader::Ipv6(hdr)) => (
            std::net::IpAddr::V6(hdr.src_addr()),
            std::net::IpAddr::V6(hdr.dst_addr()),
            false,
        ),
        None => return Vec::new(),
    };

    if skip_flow {
        return Vec::new();
    }

    let (src_port, dst_port, protocol, tcp_syn, tcp_ack) = match &packet.transport {
        Some(protocol::TransportHeader::Tcp(hdr)) => (
            hdr.src_port(),
            hdr.dst_port(),
            flow::FlowProtocol::Tcp,
            hdr.syn(),
            hdr.ack(),
        ),
        Some(protocol::TransportHeader::Udp(hdr)) => (
            hdr.src_port(),
            hdr.dst_port(),
            flow::FlowProtocol::Udp,
            false,
            false,
        ),
        _ => return Vec::new(),
    };

    let src = flow::Endpoint {
        ip: src_ip,
        port: src_port,
    };
    let dst = flow::Endpoint {
        ip: dst_ip,
        port: dst_port,
    };

    detector.observe(ts, protocol, src, dst, tcp_syn, tcp_ack)
}
