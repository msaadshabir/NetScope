//! Core capture engine: opens a pcap handle and yields raw packet data.

use pcap::{Active, Capture, Device};
use std::fmt;

/// Errors from the capture engine.
#[derive(Debug)]
pub enum CaptureError {
    /// Failed to find a suitable network device.
    NoDevice(String),
    /// pcap error.
    Pcap(pcap::Error),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::NoDevice(msg) => write!(f, "no capture device: {}", msg),
            CaptureError::Pcap(e) => write!(f, "pcap error: {}", e),
        }
    }
}

impl std::error::Error for CaptureError {}

impl From<pcap::Error> for CaptureError {
    fn from(e: pcap::Error) -> Self {
        CaptureError::Pcap(e)
    }
}

/// Configuration for opening a capture.
#[derive(Debug, Clone)]
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

/// List all available network interfaces.
pub fn list_interfaces() -> Result<Vec<Device>, CaptureError> {
    Device::list().map_err(CaptureError::Pcap)
}

/// Open a live packet capture with the given configuration.
/// Returns an active `pcap::Capture` handle.
pub fn open_capture(config: &CaptureConfig) -> Result<Capture<Active>, CaptureError> {
    // Select the device
    let device = match &config.interface {
        Some(name) => {
            let devices = Device::list().map_err(CaptureError::Pcap)?;
            devices
                .into_iter()
                .find(|d| d.name == *name)
                .ok_or_else(|| CaptureError::NoDevice(format!("interface '{}' not found", name)))?
        }
        None => Device::lookup()
            .map_err(CaptureError::Pcap)?
            .ok_or_else(|| CaptureError::NoDevice("no default device found".into()))?,
    };

    let device_name = device.name.clone();

    // Open the capture handle
    let mut cap = Capture::from_device(device)
        .map_err(CaptureError::Pcap)?
        .promisc(config.promiscuous)
        .snaplen(config.snaplen)
        .timeout(config.timeout_ms)
        .open()
        .map_err(CaptureError::Pcap)?;

    // Apply BPF filter if specified
    if let Some(filter) = &config.filter {
        cap.filter(filter, true).map_err(CaptureError::Pcap)?;
    }

    tracing::info!(
        interface = %device_name,
        promiscuous = config.promiscuous,
        snaplen = config.snaplen,
        filter = config.filter.as_deref().unwrap_or("none"),
        "capture started"
    );

    Ok(cap)
}
