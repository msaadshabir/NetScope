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
    writeln!(
        writer,
        "protocol,endpoint_a_ip,endpoint_a_port,endpoint_b_ip,endpoint_b_port,first_seen,last_seen,duration_secs,packets_a_to_b,packets_b_to_a,bytes_a_to_b,bytes_b_to_a,packets_total,bytes_total,avg_bps,tcp_state,client,retransmissions,out_of_order,rtt_last_ms,rtt_min_ms,rtt_ewma_ms,rtt_samples"
    )?;
    for flow in flows {
        let tcp_state = flow
            .tcp_state
            .map(|state| state.to_string())
            .unwrap_or_default();
        let client = flow.client.map(|dir| dir.to_string()).unwrap_or_default();
        let rtt_last = flow
            .rtt_last_ms
            .map(|value| format!("{:.3}", value))
            .unwrap_or_default();
        let rtt_min = flow
            .rtt_min_ms
            .map(|value| format!("{:.3}", value))
            .unwrap_or_default();
        let rtt_ewma = flow
            .rtt_ewma_ms
            .map(|value| format!("{:.3}", value))
            .unwrap_or_default();
        let endpoint_a_ip = csv_escape(&flow.endpoint_a.ip.to_string());
        let endpoint_b_ip = csv_escape(&flow.endpoint_b.ip.to_string());
        writeln!(
            writer,
            "{},{},{},{},{},{:.6},{:.6},{:.6},{},{},{},{},{},{},{:.3},{},{},{},{},{},{},{},{}",
            flow.protocol,
            endpoint_a_ip,
            flow.endpoint_a.port,
            endpoint_b_ip,
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
            tcp_state,
            client,
            flow.retransmissions,
            flow.out_of_order,
            rtt_last,
            rtt_min,
            rtt_ewma,
            flow.rtt_samples
        )?;
    }
    Ok(())
}

/// Escape a CSV field: wrap in double quotes if it contains comma, quote, or newline.
fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        let escaped = field.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        field.to_string()
    }
}
