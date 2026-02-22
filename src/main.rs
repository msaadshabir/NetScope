mod capture;
mod cli;
mod display;
mod protocol;

use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
    if let Err(e) = run_capture(&args, &running) {
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
                let desc = device
                    .desc
                    .as_deref()
                    .unwrap_or("");
                let addrs: Vec<String> = device
                    .addresses
                    .iter()
                    .map(|a| format!("{}", a.addr))
                    .collect();
                println!(
                    "{:<20} {:<20} {}",
                    device.name,
                    desc,
                    addrs.join(", ")
                );
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
    args: &cli::Cli,
    running: &Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = capture::engine::CaptureConfig {
        interface: args.interface.clone(),
        promiscuous: args.promiscuous,
        snaplen: args.snaplen,
        timeout_ms: args.timeout_ms,
        filter: args.filter.clone(),
    };

    let mut cap = capture::engine::open_capture(&config)?;

    let interface_name = args
        .interface
        .as_deref()
        .unwrap_or("(default)");

    println!("NetScope v{}", env!("CARGO_PKG_VERSION"));
    println!("Capturing on interface: {}", interface_name);
    if let Some(filter) = &args.filter {
        println!("Filter: {}", filter);
    }
    if args.count > 0 {
        println!("Capturing {} packets...", args.count);
    } else {
        println!("Capturing packets (Ctrl-C to stop)...");
    }
    println!();

    let mut packet_count: u64 = 0;
    let mut parse_errors: u64 = 0;

    while running.load(Ordering::SeqCst) {
        // Check packet count limit
        if args.count > 0 && packet_count >= args.count {
            break;
        }

        // Read next packet
        let packet = match cap.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                tracing::error!(error = %e, "capture error");
                return Err(Box::new(e));
            }
        };

        packet_count += 1;

        let timestamp = packet.header.ts.tv_sec as f64
            + packet.header.ts.tv_usec as f64 / 1_000_000.0;
        let raw_data = packet.data;

        // Parse the packet
        match protocol::parse_packet(raw_data) {
            Ok(parsed) => {
                if args.hex_dump || args.verbose >= 2 {
                    display::print_packet_detail(packet_count, timestamp, raw_data, &parsed);
                } else {
                    display::print_packet_summary(packet_count, timestamp, &parsed);
                }
            }
            Err(e) => {
                parse_errors += 1;
                display::print_parse_error(packet_count, timestamp, raw_data.len(), &e);
                tracing::debug!(error = %e, "parse error on packet #{}", packet_count);
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

    Ok(())
}
