mod analysis;
mod capture;
mod cli;
mod config;
mod display;
mod flow;
mod protocol;
mod web;

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

    // Start web dashboard if enabled
    let web_handle = if config.web.enabled {
        let server_config = web::server::WebServerConfig {
            bind: config.web.bind.clone(),
            port: config.web.port,
            tick_ms: config.web.tick_ms,
            packet_buffer: config.web.packet_buffer,
        };
        match web::server::start(server_config) {
            Ok(handle) => {
                println!(
                    "Web dashboard: http://{}:{}",
                    config.web.bind, config.web.port
                );
                Some(handle)
            }
            Err(err) => {
                eprintln!("error starting web dashboard: {}", err);
                None
            }
        }
    } else {
        None
    };

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

    // Web dashboard tick state
    let mut web_tick_last = Instant::now();
    let mut web_tick_bytes: u64 = 0;
    let mut web_tick_packets: u64 = 0;

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
                        for alert in &alerts {
                            println!("[alert] {}", alert.description);
                            // Forward alerts to web dashboard
                            if let Some(handle) = &web_handle {
                                if handle.event_tx.try_send(
                                    web::messages::CaptureEvent::Alert(
                                        web::messages::AlertMsg {
                                            ts: alert.ts,
                                            kind: format!("{:?}", alert.kind),
                                            description: alert.description.clone(),
                                        },
                                    ),
                                ).is_err() {
                                    tracing::trace!("web event channel full, dropping alert");
                                }
                            }
                        }
                    }
                    flow_tracker.observe(timestamp, wire_len, &parsed);

                    // Send packet samples to web dashboard.
                    // sample_rate=0 disables the live packet feed entirely;
                    // sample_rate=1 sends every packet; N sends every Nth packet.
                    if let Some(handle) = &web_handle {
                        if config.web.sample_rate > 0
                            && packet_count % config.web.sample_rate == 0
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

            // Wire-level counters — intentionally include parse-failed packets so
            // that throughput matches what the NIC actually saw (same as CLI stats).
            stats_bytes += wire_len;
            stats_packets += 1;
            web_tick_bytes += wire_len;
            web_tick_packets += 1;

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

        // Web dashboard tick
        if let Some(handle) = &web_handle {
            let now = Instant::now();
            if now.duration_since(web_tick_last).as_millis() as u64 >= config.web.tick_ms {
                let elapsed = now.duration_since(web_tick_last).as_secs_f64().max(0.001);
                let mbps = web_tick_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
                let pps = web_tick_packets as f64 / elapsed;
                let active_flows = flow_tracker.len();

                let top_deltas =
                    flow_tracker.top_flows_with_snapshot(config.web.top_n);
                let top_flows: Vec<web::messages::FlowInfo> = top_deltas
                    .iter()
                    .map(|(delta, snap)| {
                        let delta_mbps =
                            delta.delta_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
                        web::messages::FlowInfo {
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

                let tick = web::messages::StatsTick {
                    ts: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64(),
                    interval_ms: config.web.tick_ms,
                    bytes: web_tick_bytes,
                    packets: web_tick_packets,
                    mbps,
                    pps,
                    active_flows,
                    top_flows,
                };

                if handle
                    .event_tx
                    .try_send(web::messages::CaptureEvent::Tick(tick))
                    .is_err()
                {
                    tracing::trace!("web event channel full, dropping stats tick");
                }

                web_tick_last = now;
                web_tick_bytes = 0;
                web_tick_packets = 0;
            }
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
    web: config::WebConfig,
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

    Ok(RuntimeConfig {
        capture,
        run,
        output,
        flow,
        stats,
        analysis,
        web,
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

// ---------------------------------------------------------------------------
// Build packet data for the web dashboard
// ---------------------------------------------------------------------------

fn build_packet_data(
    id: u64,
    ts: f64,
    raw_data: &[u8],
    parsed: &protocol::ParsedPacket<'_>,
    max_payload_bytes: usize,
) -> (web::messages::PacketSample, web::messages::StoredPacket) {
    // Build one-line summary fields
    let (proto_str, src_str, dst_str, info_str) = summarise_packet(parsed);

    let sample = web::messages::PacketSample {
        id,
        ts,
        len: raw_data.len(),
        protocol: proto_str,
        src: src_str,
        dst: dst_str,
        info: info_str,
    };

    // Build layer details
    let mut layers = Vec::new();

    // Ethernet
    {
        let eth = &parsed.ethernet;
        layers.push(web::messages::LayerDetail {
            name: "Ethernet".into(),
            fields: vec![
                (
                    "Source".into(),
                    protocol::ethernet::format_mac(eth.src_mac()),
                ),
                (
                    "Destination".into(),
                    protocol::ethernet::format_mac(eth.dst_mac()),
                ),
                ("EtherType".into(), format!("{}", eth.ether_type())),
            ],
        });
    }

    // VLAN
    if let Some(vlan) = &parsed.vlan {
        layers.push(web::messages::LayerDetail {
            name: "VLAN (802.1Q)".into(),
            fields: vec![
                ("VLAN ID".into(), format!("{}", vlan.vlan_id)),
                ("Priority".into(), format!("{}", vlan.priority)),
                ("DEI".into(), format!("{}", vlan.dei)),
            ],
        });
    }

    // Network
    if let Some(net) = &parsed.network {
        match net {
            protocol::NetworkHeader::Ipv4(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "IPv4".into(),
                    fields: vec![
                        ("Source".into(), format!("{}", hdr.src_addr())),
                        ("Destination".into(), format!("{}", hdr.dst_addr())),
                        ("Protocol".into(), format!("{}", hdr.protocol())),
                        ("TTL".into(), format!("{}", hdr.ttl())),
                        ("Total Length".into(), format!("{}", hdr.total_length())),
                        ("ID".into(), format!("0x{:04x}", hdr.identification())),
                        (
                            "Flags".into(),
                            format!(
                                "DF={} MF={}",
                                hdr.dont_fragment(),
                                hdr.more_fragments()
                            ),
                        ),
                        ("Fragment Offset".into(), format!("{}", hdr.fragment_offset())),
                        (
                            "Checksum".into(),
                            format!(
                                "0x{:04x} ({})",
                                hdr.checksum(),
                                if hdr.verify_checksum() {
                                    "valid"
                                } else {
                                    "invalid"
                                }
                            ),
                        ),
                    ],
                });
            }
            protocol::NetworkHeader::Ipv6(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "IPv6".into(),
                    fields: vec![
                        ("Source".into(), format!("{}", hdr.src_addr())),
                        ("Destination".into(), format!("{}", hdr.dst_addr())),
                        ("Next Header".into(), format!("{}", hdr.next_header())),
                        ("Hop Limit".into(), format!("{}", hdr.hop_limit())),
                        ("Payload Length".into(), format!("{}", hdr.payload_length())),
                        (
                            "Flow Label".into(),
                            format!("0x{:05x}", hdr.flow_label()),
                        ),
                    ],
                });
            }
        }
    }

    // Transport
    if let Some(transport) = &parsed.transport {
        match transport {
            protocol::TransportHeader::Tcp(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "TCP".into(),
                    fields: vec![
                        ("Source Port".into(), format!("{}", hdr.src_port())),
                        ("Destination Port".into(), format!("{}", hdr.dst_port())),
                        ("Sequence".into(), format!("{}", hdr.sequence_number())),
                        ("Acknowledgment".into(), format!("{}", hdr.ack_number())),
                        ("Flags".into(), hdr.flags_string()),
                        ("Window".into(), format!("{}", hdr.window_size())),
                        ("Checksum".into(), format!("0x{:04x}", hdr.checksum())),
                    ],
                });
            }
            protocol::TransportHeader::Udp(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "UDP".into(),
                    fields: vec![
                        ("Source Port".into(), format!("{}", hdr.src_port())),
                        ("Destination Port".into(), format!("{}", hdr.dst_port())),
                        ("Length".into(), format!("{}", hdr.length())),
                        ("Checksum".into(), format!("0x{:04x}", hdr.checksum())),
                    ],
                });
            }
            protocol::TransportHeader::Icmp(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "ICMP".into(),
                    fields: vec![
                        ("Type".into(), format!("{}", hdr.icmp_type())),
                        ("Code".into(), format!("{}", hdr.code())),
                        ("Checksum".into(), format!("0x{:04x}", hdr.checksum())),
                    ],
                });
            }
        }
    }

    // Hex dump (truncated)
    let dump_len = raw_data.len().min(max_payload_bytes);
    let hex_dump = format_hex_dump(&raw_data[..dump_len]);

    let stored = web::messages::StoredPacket {
        id,
        ts,
        layers,
        hex_dump,
    };

    (sample, stored)
}

fn summarise_packet(parsed: &protocol::ParsedPacket<'_>) -> (String, String, String, String) {
    let mut proto;
    let mut src = String::new();
    let mut dst = String::new();
    let mut info = String::new();

    if let Some(net) = &parsed.network {
        match net {
            protocol::NetworkHeader::Ipv4(hdr) => {
                proto = "IPv4".to_string();
                src = format!("{}", hdr.src_addr());
                dst = format!("{}", hdr.dst_addr());
            }
            protocol::NetworkHeader::Ipv6(hdr) => {
                proto = "IPv6".to_string();
                src = format!("{}", hdr.src_addr());
                dst = format!("{}", hdr.dst_addr());
            }
        }
    } else {
        proto = format!("{}", parsed.ethernet.ether_type());
    }

    if let Some(transport) = &parsed.transport {
        match transport {
            protocol::TransportHeader::Tcp(hdr) => {
                proto = "TCP".into();
                src.push_str(&format!(":{}", hdr.src_port()));
                dst.push_str(&format!(":{}", hdr.dst_port()));
                info = format!(
                    "{} seq={} ack={} win={}",
                    hdr.flags_string(),
                    hdr.sequence_number(),
                    hdr.ack_number(),
                    hdr.window_size()
                );
            }
            protocol::TransportHeader::Udp(hdr) => {
                proto = "UDP".into();
                src.push_str(&format!(":{}", hdr.src_port()));
                dst.push_str(&format!(":{}", hdr.dst_port()));
                info = format!("len={}", hdr.length());
            }
            protocol::TransportHeader::Icmp(hdr) => {
                proto = "ICMP".into();
                info = format!("{}", hdr);
            }
        }
    }

    (proto, src, dst, info)
}

/// Format raw bytes as a hex dump string suitable for display.
fn format_hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for offset in (0..data.len()).step_by(16) {
        let end = (offset + 16).min(data.len());
        let chunk = &data[offset..end];

        out.push_str(&format!("{:04x}  ", offset));

        for (i, byte) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", byte));
            if i == 7 {
                out.push(' ');
            }
        }
        for i in chunk.len()..16 {
            out.push_str("   ");
            if i == 7 {
                out.push(' ');
            }
        }

        out.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}
