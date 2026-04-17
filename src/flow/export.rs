use super::FlowSnapshot;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

pub fn write_flow_json(
    path: &Path,
    flows: &[FlowSnapshot],
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, flows)?;
    Ok(())
}

pub fn write_flow_csv(
    path: &Path,
    flows: &[FlowSnapshot],
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    write_flow_csv_to_writer(&mut writer, flows)?;
    Ok(())
}

fn write_flow_csv_to_writer<W: Write>(
    writer: &mut W,
    flows: &[FlowSnapshot],
) -> std::io::Result<()> {
    writeln!(
        writer,
        "protocol,endpoint_a_ip,endpoint_a_port,endpoint_b_ip,endpoint_b_port,first_seen,last_seen,duration_secs,packets_a_to_b,packets_b_to_a,bytes_a_to_b,bytes_b_to_a,packets_total,bytes_total,avg_bps,tcp_state,client,retransmissions,out_of_order,rtt_last_ms,rtt_min_ms,rtt_ewma_ms,rtt_samples"
    )?;
    for flow in flows {
        write!(
            writer,
            "{},{},{},{},{},{:.6},{:.6},{:.6},{},{},{},{},{},{},{:.3},",
            flow.protocol,
            flow.endpoint_a.ip,
            flow.endpoint_a.port,
            flow.endpoint_b.ip,
            flow.endpoint_b.port,
            flow.first_seen,
            flow.last_seen,
            flow.duration_secs,
            flow.packets_a_to_b,
            flow.packets_b_to_a,
            flow.bytes_a_to_b,
            flow.bytes_b_to_a,
            flow.packets_total,
            flow.bytes_total,
            flow.avg_bps,
        )?;

        // tcp_state
        if let Some(state) = flow.tcp_state {
            write!(writer, "{}", state)?;
        }
        write!(writer, ",")?;

        // client
        if let Some(dir) = flow.client {
            write!(writer, "{}", dir)?;
        }
        write!(writer, ",")?;

        // retransmissions,out_of_order
        write!(writer, "{},{}", flow.retransmissions, flow.out_of_order)?;
        write!(writer, ",")?;

        // rtt_last_ms
        if let Some(value) = flow.rtt_last_ms {
            write!(writer, "{value:.3}")?;
        }
        write!(writer, ",")?;

        // rtt_min_ms
        if let Some(value) = flow.rtt_min_ms {
            write!(writer, "{value:.3}")?;
        }
        write!(writer, ",")?;

        // rtt_ewma_ms
        if let Some(value) = flow.rtt_ewma_ms {
            write!(writer, "{value:.3}")?;
        }

        // rtt_samples
        writeln!(writer, ",{}", flow.rtt_samples)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Endpoint, FlowDirection, FlowProtocol, TcpState};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn csv_layout_keeps_empty_optional_columns() {
        let flows = vec![FlowSnapshot {
            protocol: FlowProtocol::Udp,
            endpoint_a: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                port: 53000,
            },
            endpoint_b: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                port: 53,
            },
            first_seen: 1.0,
            last_seen: 2.5,
            duration_secs: 1.5,
            packets_a_to_b: 10,
            packets_b_to_a: 8,
            bytes_a_to_b: 1400,
            bytes_b_to_a: 2200,
            packets_total: 18,
            bytes_total: 3600,
            avg_bps: 19200.0,
            tcp_state: None,
            client: None,
            retransmissions: 0,
            out_of_order: 0,
            rtt_last_ms: None,
            rtt_min_ms: None,
            rtt_ewma_ms: None,
            rtt_samples: 0,
        }];

        let mut output = Vec::new();
        write_flow_csv_to_writer(&mut output, &flows).expect("csv write should succeed");

        let csv = String::from_utf8(output).expect("csv should be utf-8");
        let mut lines = csv.lines();
        let header = lines.next().expect("header line");
        let row = lines.next().expect("data row");
        assert!(lines.next().is_none(), "expected a single data row");

        let header_fields: Vec<&str> = header.split(',').collect();
        let row_fields: Vec<&str> = row.split(',').collect();
        assert_eq!(header_fields.len(), 23);
        assert_eq!(row_fields.len(), header_fields.len());

        assert_eq!(row_fields[0], "udp");
        assert_eq!(row_fields[1], "192.0.2.1");
        assert_eq!(row_fields[3], "198.51.100.7");
        assert_eq!(row_fields[15], "");
        assert_eq!(row_fields[16], "");
        assert_eq!(row_fields[19], "");
        assert_eq!(row_fields[20], "");
        assert_eq!(row_fields[21], "");
    }

    #[test]
    fn csv_layout_serializes_present_optional_fields() {
        let flows = vec![FlowSnapshot {
            protocol: FlowProtocol::Tcp,
            endpoint_a: Endpoint {
                ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                port: 443,
            },
            endpoint_b: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                port: 55000,
            },
            first_seen: 10.0,
            last_seen: 12.0,
            duration_secs: 2.0,
            packets_a_to_b: 40,
            packets_b_to_a: 50,
            bytes_a_to_b: 30_000,
            bytes_b_to_a: 42_000,
            packets_total: 90,
            bytes_total: 72_000,
            avg_bps: 288_000.0,
            tcp_state: Some(TcpState::Established),
            client: Some(FlowDirection::AtoB),
            retransmissions: 2,
            out_of_order: 1,
            rtt_last_ms: Some(1.2349),
            rtt_min_ms: Some(0.5),
            rtt_ewma_ms: Some(0.9999),
            rtt_samples: 7,
        }];

        let mut output = Vec::new();
        write_flow_csv_to_writer(&mut output, &flows).expect("csv write should succeed");

        let csv = String::from_utf8(output).expect("csv should be utf-8");
        let row = csv
            .lines()
            .nth(1)
            .expect("csv should contain a data row after header");
        let row_fields: Vec<&str> = row.split(',').collect();

        assert_eq!(row_fields[15], "established");
        assert_eq!(row_fields[16], "a_to_b");
        assert_eq!(row_fields[17], "2");
        assert_eq!(row_fields[18], "1");
        assert_eq!(row_fields[19], "1.235");
        assert_eq!(row_fields[20], "0.500");
        assert_eq!(row_fields[21], "1.000");
        assert_eq!(row_fields[22], "7");
    }
}
