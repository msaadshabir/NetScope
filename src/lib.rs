//! NetScope library crate — re-exports modules for benchmarks and tests.

pub mod analysis;
pub mod capture;
pub mod config;
pub mod display;
pub mod flow;
pub mod jsonl;
pub mod memory;
pub mod pipeline;
pub mod protocol;
pub mod web;

// ---------------------------------------------------------------------------
// Shared helper functions used by both the binary (main.rs) and the pipeline
// workers. Placed here so they're accessible from the library crate.
// ---------------------------------------------------------------------------

/// Extract anomaly-relevant fields from a parsed packet and feed them to the
/// anomaly detector.
pub fn maybe_analyze_anomaly(
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
            hdr.is_non_initial_fragment(),
        ),
        None => return Vec::new(),
    };

    if skip_flow {
        return Vec::new();
    }

    let (src_port, dst_port, proto, tcp_syn, tcp_ack) = match &packet.transport {
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

    detector.observe(ts, proto, src, dst, tcp_syn, tcp_ack)
}

/// Build a `PacketSample` + `StoredPacket` pair for the web dashboard.
pub fn build_packet_data(
    id: u64,
    ts: f64,
    raw_data: &[u8],
    parsed: &protocol::ParsedPacket<'_>,
    max_payload_bytes: usize,
) -> (web::messages::PacketSample, web::messages::StoredPacket) {
    let dns = match &parsed.transport {
        Some(protocol::TransportHeader::Udp(hdr)) => {
            protocol::dns::parse_dns_udp(parsed.payload, hdr.src_port(), hdr.dst_port())
        }
        _ => None,
    };
    let tls = match &parsed.transport {
        Some(protocol::TransportHeader::Tcp(_)) => {
            protocol::tls::parse_client_hello_sni(parsed.payload)
        }
        _ => None,
    };
    let (proto_str, src_str, dst_str, info_str) =
        summarise_packet(parsed, dns.as_ref(), tls.as_ref());

    let sample = web::messages::PacketSample {
        id,
        ts,
        len: raw_data.len(),
        protocol: proto_str,
        src: src_str,
        dst: dst_str,
        info: info_str,
    };

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
                            format!("DF={} MF={}", hdr.dont_fragment(), hdr.more_fragments()),
                        ),
                        (
                            "Fragment Offset".into(),
                            format!("{}", hdr.fragment_offset()),
                        ),
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
                        ("Flow Label".into(), format!("0x{:05x}", hdr.flow_label())),
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

                if let Some(tls) = &tls {
                    layers.push(web::messages::LayerDetail {
                        name: "TLS".into(),
                        fields: vec![
                            ("Type".into(), "ClientHello".into()),
                            (
                                "Legacy Version".into(),
                                format!("0x{:04x}", tls.legacy_version),
                            ),
                            ("SNI".into(), tls.sni.clone()),
                        ],
                    });
                }
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

                if let Some(dns) = dns {
                    let mut fields = vec![
                        ("ID".into(), format!("0x{:04x}", dns.id())),
                        (
                            "Message Type".into(),
                            if dns.is_response() {
                                "Response".to_string()
                            } else {
                                "Query".to_string()
                            },
                        ),
                        ("Opcode".into(), dns.opcode_name().to_string()),
                        ("RCode".into(), dns.rcode_name().to_string()),
                        ("Flags".into(), dns.flags_string()),
                        ("Questions".into(), format!("{}", dns.question_count())),
                        ("Answers".into(), format!("{}", dns.answer_count())),
                        ("Authorities".into(), format!("{}", dns.authority_count())),
                        ("Additionals".into(), format!("{}", dns.additional_count())),
                    ];

                    match dns.parse_sections(2, 2, 1, 1) {
                        Ok(sections) => {
                            if let Some(question) = sections.questions.first() {
                                let qname = question
                                    .name()
                                    .unwrap_or_else(|_| "<invalid-name>".to_string());
                                fields.push((
                                    "Question".into(),
                                    format!("{} {}", question.qtype_label(), qname),
                                ));
                                fields.push(("QClass".into(), question.qclass_label()));
                            }

                            if !sections.answers.is_empty() {
                                let answer_summaries: Vec<String> =
                                    sections.answers.iter().map(|rr| rr.summary()).collect();
                                fields.push((
                                    "Answers (sample)".into(),
                                    answer_summaries.join(" | "),
                                ));
                            }
                        }
                        Err(err) => {
                            fields.push((
                                "Parse Note".into(),
                                format!("section parse failed: {}", err),
                            ));
                        }
                    }

                    layers.push(web::messages::LayerDetail {
                        name: "DNS".into(),
                        fields,
                    });
                }
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

fn summarise_packet(
    parsed: &protocol::ParsedPacket<'_>,
    dns: Option<&protocol::dns::DnsMessage<'_>>,
    tls: Option<&protocol::tls::TlsClientHelloInfo>,
) -> (String, String, String, String) {
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
                if let Some(tls) = tls {
                    proto = "TLS".into();
                    info = format!("ClientHello sni={}", tls.sni);
                } else {
                    proto = "TCP".into();
                    info = format!(
                        "{} seq={} ack={} win={}",
                        hdr.flags_string(),
                        hdr.sequence_number(),
                        hdr.ack_number(),
                        hdr.window_size()
                    );
                }
                src.push_str(&format!(":{}", hdr.src_port()));
                dst.push_str(&format!(":{}", hdr.dst_port()));
            }
            protocol::TransportHeader::Udp(hdr) => {
                if let Some(dns) = dns {
                    proto = "DNS".into();
                    info = protocol::dns::brief_summary(&dns);
                } else {
                    proto = "UDP".into();
                    info = format!("len={}", hdr.length());
                }
                src.push_str(&format!(":{}", hdr.src_port()));
                dst.push_str(&format!(":{}", hdr.dst_port()));
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
