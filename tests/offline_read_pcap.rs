use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("netscope-{}-{}.pcap", name, unique))
}

fn write_test_pcap(path: &Path) {
    let mut file = File::create(path).expect("failed to create temp pcap");

    // pcap global header (little-endian, microsecond resolution)
    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    header.extend_from_slice(&2u16.to_le_bytes()); // major
    header.extend_from_slice(&4u16.to_le_bytes()); // minor
    header.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    header.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    header.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    header.extend_from_slice(&1u32.to_le_bytes()); // linktype Ethernet
    file.write_all(&header)
        .expect("failed to write pcap header");

    // One Ethernet+IPv4 packet (14 + 20 bytes)
    let packet: [u8; 34] = [
        // Ethernet header
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
        0x08, 0x00, // ethertype IPv4
        // IPv4 header (minimal, protocol TCP)
        0x45, // version + ihl
        0x00, // dscp/ecn
        0x00, 0x14, // total length = 20
        0x00, 0x01, // identification
        0x00, 0x00, // flags + fragment offset
        64,   // ttl
        6,    // protocol TCP
        0x00, 0x00, // checksum (not validated by parser)
        192, 168, 1, 10, // src ip
        192, 168, 1, 20, // dst ip
    ];

    // pcap packet record header
    file.write_all(&1u32.to_le_bytes()) // ts_sec
        .expect("failed to write ts_sec");
    file.write_all(&123u32.to_le_bytes()) // ts_usec
        .expect("failed to write ts_usec");
    file.write_all(&(packet.len() as u32).to_le_bytes()) // incl_len
        .expect("failed to write incl_len");
    file.write_all(&(packet.len() as u32).to_le_bytes()) // orig_len
        .expect("failed to write orig_len");
    file.write_all(&packet).expect("failed to write packet");
    file.flush().expect("failed to flush pcap file");
}

fn run_netscope(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_netscope");
    Command::new(bin)
        .args(args)
        .output()
        .expect("failed to run netscope binary")
}

#[test]
fn read_pcap_inline_mode() {
    let pcap_path = temp_path("inline");
    write_test_pcap(&pcap_path);

    let output = run_netscope(&[
        "--read-pcap",
        pcap_path
            .to_str()
            .expect("temp pcap path must be valid utf-8 for cli"),
        "--count",
        "1",
        "--quiet",
    ]);

    if let Err(err) = std::fs::remove_file(&pcap_path) {
        eprintln!(
            "warning: failed to delete temp pcap {}: {}",
            pcap_path.display(),
            err
        );
    }

    assert!(
        output.status.success(),
        "expected success, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Packets captured:  1"),
        "stdout was: {}",
        stdout
    );
}

#[test]
fn read_pcap_pipeline_mode() {
    let pcap_path = temp_path("pipeline");
    write_test_pcap(&pcap_path);

    let output = run_netscope(&[
        "--read-pcap",
        pcap_path
            .to_str()
            .expect("temp pcap path must be valid utf-8 for cli"),
        "--count",
        "1",
        "--quiet",
        "--pipeline",
    ]);

    if let Err(err) = std::fs::remove_file(&pcap_path) {
        eprintln!(
            "warning: failed to delete temp pcap {}: {}",
            pcap_path.display(),
            err
        );
    }

    assert!(
        output.status.success(),
        "expected success, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Packets captured:  1"),
        "stdout was: {}",
        stdout
    );
}
