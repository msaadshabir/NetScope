//! Packet display / pretty-printing for the CLI.
//!
//! Formats parsed packets into human-readable one-line summaries
//! and optional detailed views with hex dumps.

use crate::protocol::{
    self, ethernet, ParsedPacket, NetworkHeader, TransportHeader,
};

/// Print a one-line summary of a parsed packet.
pub fn print_packet_summary(index: u64, timestamp: f64, packet: &ParsedPacket<'_>) {
    let ts = format_timestamp(timestamp);

    // Build the summary line
    let mut summary = format!(
        "#{:<6} {} Eth: {}",
        index, ts, packet.ethernet
    );

    // VLAN info
    if let Some(vlan) = &packet.vlan {
        summary.push_str(&format!(" VLAN:{}", vlan.vlan_id));
    }

    // Network layer
    if let Some(net) = &packet.network {
        match net {
            NetworkHeader::Ipv4(hdr) => {
                summary.push_str(&format!(" | IPv4: {}", hdr));
            }
            NetworkHeader::Ipv6(hdr) => {
                summary.push_str(&format!(" | IPv6: {}", hdr));
            }
        }
    }

    // Transport layer
    if let Some(transport) = &packet.transport {
        match transport {
            TransportHeader::Tcp(hdr) => {
                summary.push_str(&format!(" | TCP {}", hdr));
            }
            TransportHeader::Udp(hdr) => {
                summary.push_str(&format!(" | UDP {}", hdr));
            }
            TransportHeader::Icmp(hdr) => {
                summary.push_str(&format!(" | ICMP {}", hdr));
            }
        }
    }

    // Payload size
    if !packet.payload.is_empty() {
        summary.push_str(&format!(" | payload: {} bytes", packet.payload.len()));
    }

    println!("{}", summary);
}

/// Print a detailed view of a parsed packet, including hex dump.
pub fn print_packet_detail(index: u64, timestamp: f64, raw_data: &[u8], packet: &ParsedPacket<'_>) {
    println!("{}",  "=".repeat(80));
    print_packet_summary(index, timestamp, packet);
    println!("{}", "-".repeat(80));

    // Ethernet details
    println!("  Ethernet:");
    println!(
        "    Source:      {}",
        ethernet::format_mac(packet.ethernet.src_mac())
    );
    println!(
        "    Destination: {}",
        ethernet::format_mac(packet.ethernet.dst_mac())
    );
    println!("    EtherType:   {} (0x{:04x})", packet.ethernet.ether_type(), packet.ethernet.ether_type_raw());

    if let Some(vlan) = &packet.vlan {
        println!("  VLAN:");
        println!("    ID:       {}", vlan.vlan_id);
        println!("    Priority: {}", vlan.priority);
        println!("    DEI:      {}", vlan.dei);
    }

    // Network layer details
    if let Some(net) = &packet.network {
        match net {
            NetworkHeader::Ipv4(hdr) => {
                println!("  IPv4:");
                println!("    Source:       {}", hdr.src_addr());
                println!("    Destination:  {}", hdr.dst_addr());
                println!("    Protocol:     {} ({})", hdr.protocol(), hdr.protocol_raw());
                println!("    TTL:          {}", hdr.ttl());
                println!("    Total Length: {}", hdr.total_length());
                println!("    ID:           0x{:04x}", hdr.identification());
                println!(
                    "    Flags:        DF={} MF={}",
                    hdr.dont_fragment(),
                    hdr.more_fragments()
                );
                println!("    Frag Offset:  {}", hdr.fragment_offset());
                println!("    DSCP:         {}", hdr.dscp());
                println!("    ECN:          {}", hdr.ecn());
                println!("    Checksum:     0x{:04x} (valid: {})", hdr.checksum(), hdr.verify_checksum());
            }
            NetworkHeader::Ipv6(hdr) => {
                println!("  IPv6:");
                println!("    Source:       {}", hdr.src_addr());
                println!("    Destination:  {}", hdr.dst_addr());
                println!("    Next Header:  {} ({})", hdr.next_header(), hdr.next_header_raw());
                println!("    Hop Limit:    {}", hdr.hop_limit());
                println!("    Payload Len:  {}", hdr.payload_length());
                println!("    Traffic Class:{}", hdr.traffic_class());
                println!("    Flow Label:   0x{:05x}", hdr.flow_label());
            }
        }
    }

    // Transport layer details
    if let Some(transport) = &packet.transport {
        match transport {
            TransportHeader::Tcp(hdr) => {
                println!("  TCP:");
                println!("    Source Port:  {}", hdr.src_port());
                println!("    Dest Port:    {}", hdr.dst_port());
                println!("    Seq:          {}", hdr.sequence_number());
                println!("    Ack:          {}", hdr.ack_number());
                println!("    Flags:        {}", hdr.flags_string());
                println!("    Window:       {}", hdr.window_size());
                println!("    Checksum:     0x{:04x}", hdr.checksum());
                println!("    Data Offset:  {} ({} bytes)", hdr.data_offset(), hdr.header_len());
            }
            TransportHeader::Udp(hdr) => {
                println!("  UDP:");
                println!("    Source Port:  {}", hdr.src_port());
                println!("    Dest Port:    {}", hdr.dst_port());
                println!("    Length:       {}", hdr.length());
                println!("    Checksum:     0x{:04x}", hdr.checksum());
            }
            TransportHeader::Icmp(hdr) => {
                println!("  ICMP:");
                println!("    Type:     {} ({})", hdr.icmp_type(), hdr.icmp_type_raw());
                println!("    Code:     {}", hdr.code());
                println!("    Checksum: 0x{:04x}", hdr.checksum());
            }
        }
    }

    // Hex dump of the raw packet
    println!("  Hex Dump ({} bytes):", raw_data.len());
    print_hex_dump(raw_data);
    println!();
}

/// Print a hex dump with offsets, hex values, and ASCII representation.
fn print_hex_dump(data: &[u8]) {
    // Limit hex dump to first 256 bytes for readability
    let display_len = data.len().min(256);

    for offset in (0..display_len).step_by(16) {
        let end = (offset + 16).min(display_len);
        let chunk = &data[offset..end];

        // Offset
        print!("    {:04x}  ", offset);

        // Hex bytes
        for (i, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if i == 7 {
                print!(" ");
            }
        }

        // Padding for incomplete lines
        for i in chunk.len()..16 {
            print!("   ");
            if i == 7 {
                print!(" ");
            }
        }

        // ASCII representation
        print!(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }

    if display_len < data.len() {
        println!("    ... ({} bytes remaining)", data.len() - display_len);
    }
}

/// Format a pcap timestamp (seconds since epoch) into a readable time.
fn format_timestamp(ts: f64) -> String {
    let secs = ts as u64;
    let micros = ((ts - secs as f64) * 1_000_000.0) as u32;

    // Simple HH:MM:SS.microseconds format (UTC-based from epoch)
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    format!("{:02}:{:02}:{:02}.{:06}", hours, minutes, seconds, micros)
}

/// Print a compact one-line summary for a packet that failed to parse.
pub fn print_parse_error(index: u64, timestamp: f64, data_len: usize, error: &protocol::ParseError) {
    let ts = format_timestamp(timestamp);
    println!(
        "#{:<6} {} [PARSE ERROR] {} bytes: {}",
        index, ts, data_len, error
    );
}
