use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

fn empty_path_none<'de, D>(deserializer: D) -> Result<Option<PathBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<PathBuf>::deserialize(deserializer)?;
    Ok(opt.and_then(|path| {
        if path.as_os_str().is_empty() {
            None
        } else {
            Some(path)
        }
    }))
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "config io error: {}", err),
            ConfigError::Parse(err) => write!(f, "config parse error: {}", err),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub capture: CaptureConfig,
    pub run: RunConfig,
    pub output: OutputConfig,
    pub flow: FlowConfig,
    pub stats: StatsConfig,
    pub analysis: AnalysisConfig,
    pub web: WebConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            capture: CaptureConfig::default(),
            run: RunConfig::default(),
            output: OutputConfig::default(),
            flow: FlowConfig::default(),
            stats: StatsConfig::default(),
            analysis: AnalysisConfig::default(),
            web: WebConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        toml::from_str(&raw).map_err(ConfigError::Parse)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    pub interface: Option<String>,
    pub promiscuous: bool,
    pub snaplen: i32,
    pub timeout_ms: i32,
    pub filter: Option<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            interface: None,
            promiscuous: true,
            snaplen: 65535,
            timeout_ms: 100,
            filter: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RunConfig {
    pub count: u64,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig { count: 0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    #[serde(deserialize_with = "empty_path_none")]
    pub write_pcap: Option<PathBuf>,
    #[serde(deserialize_with = "empty_path_none")]
    pub export_json: Option<PathBuf>,
    #[serde(deserialize_with = "empty_path_none")]
    pub export_csv: Option<PathBuf>,
    pub hex_dump: bool,
    pub quiet: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        OutputConfig {
            write_pcap: None,
            export_json: None,
            export_csv: None,
            hex_dump: false,
            quiet: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FlowConfig {
    pub timeout_secs: f64,
    pub max_flows: usize,
}

impl Default for FlowConfig {
    fn default() -> Self {
        FlowConfig {
            timeout_secs: 60.0,
            max_flows: 100_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StatsConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub top_flows: u32,
}

impl Default for StatsConfig {
    fn default() -> Self {
        StatsConfig {
            enabled: false,
            interval_ms: 1000,
            top_flows: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    pub rtt: bool,
    pub retrans: bool,
    pub out_of_order: bool,
    pub anomalies: AnomalyConfig,
    #[serde(deserialize_with = "empty_path_none")]
    pub alerts_jsonl: Option<PathBuf>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        AnalysisConfig {
            rtt: true,
            retrans: true,
            out_of_order: true,
            anomalies: AnomalyConfig::default(),
            alerts_jsonl: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnomalyConfig {
    pub enabled: bool,
    pub syn_flood: SynFloodConfig,
    pub port_scan: PortScanConfig,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        AnomalyConfig {
            enabled: false,
            syn_flood: SynFloodConfig::default(),
            port_scan: PortScanConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SynFloodConfig {
    pub enabled: bool,
    pub window_secs: f64,
    pub syn_threshold: u32,
    pub unique_src_threshold: u32,
    pub cooldown_secs: f64,
}

impl Default for SynFloodConfig {
    fn default() -> Self {
        SynFloodConfig {
            enabled: true,
            window_secs: 5.0,
            syn_threshold: 200,
            unique_src_threshold: 50,
            cooldown_secs: 10.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PortScanConfig {
    pub enabled: bool,
    pub window_secs: f64,
    pub unique_ports_threshold: u32,
    pub unique_hosts_threshold: u32,
    pub cooldown_secs: f64,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        PortScanConfig {
            enabled: true,
            window_secs: 10.0,
            unique_ports_threshold: 25,
            unique_hosts_threshold: 10,
            cooldown_secs: 30.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    /// Enable the web dashboard.
    pub enabled: bool,
    /// Address to bind the HTTP server to.
    pub bind: String,
    /// Port for the HTTP server.
    pub port: u16,
    /// How often (ms) to push stats ticks to connected clients.
    pub tick_ms: u64,
    /// Number of top flows to include in each tick.
    pub top_n: usize,
    /// Number of packets to keep in the detail ring buffer.
    pub packet_buffer: usize,
    /// Sample every Nth packet for the live packet feed (1 = every packet).
    pub sample_rate: u64,
    /// Max payload bytes to store per packet for hex dump display.
    pub payload_bytes: usize,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            enabled: false,
            bind: "127.0.0.1".into(),
            port: 8080,
            tick_ms: 1000,
            top_n: 10,
            packet_buffer: 2000,
            sample_rate: 1,
            payload_bytes: 256,
        }
    }
}
