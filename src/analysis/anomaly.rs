use crate::config::{AnomalyConfig, PortScanConfig, SynFloodConfig};
use crate::flow::{Endpoint, FlowProtocol};
use ahash::{AHashMap, AHashSet};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
pub enum AlertKind {
    SynFlood,
    PortScan,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub ts: f64,
    pub kind: AlertKind,
    pub description: String,
}

#[derive(Debug)]
pub struct AnomalyDetector {
    config: AnomalyConfig,
    syn_flood: SynFloodState,
    port_scan: PortScanState,
    alert_sink: Option<AlertSink>,
    last_cleanup: f64,
}

/// How often (in seconds) to sweep stale entries from anomaly detector state.
const CLEANUP_INTERVAL_SECS: f64 = 30.0;

impl AnomalyDetector {
    pub fn new(config: AnomalyConfig, alerts_jsonl: Option<&std::path::Path>) -> Self {
        let alert_sink = match alerts_jsonl {
            Some(path) => match AlertSink::new(path) {
                Ok(sink) => Some(sink),
                Err(err) => {
                    eprintln!("alert file disabled: {}", err);
                    None
                }
            },
            None => None,
        };
        AnomalyDetector {
            syn_flood: SynFloodState::new(config.syn_flood.clone()),
            port_scan: PortScanState::new(config.port_scan.clone()),
            config,
            alert_sink,
            last_cleanup: 0.0,
        }
    }

    pub fn observe(
        &mut self,
        ts: f64,
        protocol: FlowProtocol,
        src: Endpoint,
        dst: Endpoint,
        tcp_syn: bool,
        tcp_ack: bool,
    ) -> Vec<Alert> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut alerts = Vec::new();

        let syn_is_new = tcp_syn && !tcp_ack;

        if self.config.syn_flood.enabled && protocol == FlowProtocol::Tcp && syn_is_new {
            if let Some(alert) = self.syn_flood.observe(ts, src.ip, dst.ip, dst.port) {
                alerts.push(alert);
            }
        }

        if self.config.port_scan.enabled {
            if let Some(alert) = self
                .port_scan
                .observe(ts, protocol, src.ip, dst.ip, dst.port, syn_is_new)
            {
                alerts.push(alert);
            }
        }

        if let Some(sink) = &mut self.alert_sink {
            for alert in &alerts {
                if let Err(err) = sink.write(alert) {
                    eprintln!("alert write error: {}", err);
                }
            }
        }

        // Periodically sweep stale entries to prevent unbounded memory growth
        if ts - self.last_cleanup >= CLEANUP_INTERVAL_SECS {
            self.syn_flood.cleanup(ts);
            self.port_scan.cleanup(ts);
            self.last_cleanup = ts;
        }

        alerts
    }
}

#[derive(Debug)]
struct AlertSink {
    writer: BufWriter<File>,
}

impl AlertSink {
    fn new(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let file = File::create(path)?;
        Ok(AlertSink {
            writer: BufWriter::new(file),
        })
    }

    fn write(&mut self, alert: &Alert) -> Result<(), std::io::Error> {
        let record = serde_json::json!({
            "ts": alert.ts,
            "kind": alert.kind.as_str(),
            "description": &alert.description,
        });
        let line = serde_json::to_string(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        writeln!(self.writer, "{}", line)?;
        self.writer.flush()
    }
}

impl AlertKind {
    fn as_str(&self) -> &'static str {
        match self {
            AlertKind::SynFlood => "syn_flood",
            AlertKind::PortScan => "port_scan",
        }
    }
}

#[derive(Debug, Clone)]
struct SynFloodState {
    config: SynFloodConfig,
    events: AHashMap<SynFloodKey, VecDeque<(f64, IpAddr)>>,
    cooldowns: AHashMap<SynFloodKey, f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SynFloodKey {
    dst_ip: IpAddr,
    dst_port: u16,
}

impl SynFloodState {
    fn new(config: SynFloodConfig) -> Self {
        SynFloodState {
            config,
            events: AHashMap::new(),
            cooldowns: AHashMap::new(),
        }
    }

    fn observe(&mut self, ts: f64, src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16) -> Option<Alert> {
        let key = SynFloodKey { dst_ip, dst_port };
        if let Some(until) = self.cooldowns.get(&key) {
            if *until > ts {
                return None;
            }
        }

        let window = self.config.window_secs.max(0.1);
        let events = self.events.entry(key).or_default();
        events.push_back((ts, src_ip));
        while let Some(front) = events.front() {
            if ts - front.0 > window {
                events.pop_front();
            } else {
                break;
            }
        }

        let mut unique = AHashSet::new();
        for (_, ip) in events.iter() {
            unique.insert(*ip);
        }

        if events.len() as u32 >= self.config.syn_threshold
            && unique.len() as u32 >= self.config.unique_src_threshold
        {
            let desc = format!(
                "SYN flood suspected: {} syns, {} sources to {}:{}",
                events.len(),
                unique.len(),
                dst_ip,
                dst_port
            );
            self.cooldowns
                .insert(key, ts + self.config.cooldown_secs.max(0.0));
            return Some(Alert {
                ts,
                kind: AlertKind::SynFlood,
                description: desc,
            });
        }

        None
    }

    /// Remove empty event queues and expired cooldown entries.
    fn cleanup(&mut self, now: f64) {
        self.events.retain(|_, events| !events.is_empty());
        self.cooldowns.retain(|_, until| *until > now);
    }
}

#[derive(Debug, Clone)]
struct PortScanState {
    config: PortScanConfig,
    events: AHashMap<IpAddr, VecDeque<PortScanEvent>>,
    cooldowns: AHashMap<IpAddr, f64>,
}

#[derive(Debug, Clone, Copy)]
struct PortScanEvent {
    ts: f64,
    dst_ip: IpAddr,
    dst_port: u16,
    protocol: FlowProtocol,
    syn_only: bool,
}

impl PortScanState {
    fn new(config: PortScanConfig) -> Self {
        PortScanState {
            config,
            events: AHashMap::new(),
            cooldowns: AHashMap::new(),
        }
    }

    fn observe(
        &mut self,
        ts: f64,
        protocol: FlowProtocol,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        syn_only: bool,
    ) -> Option<Alert> {
        if let Some(until) = self.cooldowns.get(&src_ip) {
            if *until > ts {
                return None;
            }
        }

        if protocol == FlowProtocol::Tcp && !syn_only {
            return None;
        }

        let window = self.config.window_secs.max(0.1);
        let events = self.events.entry(src_ip).or_default();
        events.push_back(PortScanEvent {
            ts,
            dst_ip,
            dst_port,
            protocol,
            syn_only,
        });

        while let Some(front) = events.front() {
            if ts - front.ts > window {
                events.pop_front();
            } else {
                break;
            }
        }

        let mut unique_ports = AHashSet::new();
        let mut unique_hosts = AHashSet::new();
        for evt in events.iter() {
            unique_ports.insert(evt.dst_port);
            unique_hosts.insert(evt.dst_ip);
        }

        if unique_ports.len() as u32 >= self.config.unique_ports_threshold
            || unique_hosts.len() as u32 >= self.config.unique_hosts_threshold
        {
            let desc = format!(
                "Port scan suspected: {} ports, {} hosts from {}",
                unique_ports.len(),
                unique_hosts.len(),
                src_ip
            );
            self.cooldowns
                .insert(src_ip, ts + self.config.cooldown_secs.max(0.0));
            return Some(Alert {
                ts,
                kind: AlertKind::PortScan,
                description: desc,
            });
        }

        None
    }

    /// Remove empty event queues and expired cooldown entries.
    fn cleanup(&mut self, now: f64) {
        self.events.retain(|_, events| !events.is_empty());
        self.cooldowns.retain(|_, until| *until > now);
    }
}
