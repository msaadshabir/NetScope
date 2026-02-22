//! Packet capture engine using libpcap.
//!
//! Provides an abstraction over the `pcap` crate for opening a live capture
//! on a network interface with optional BPF filtering.

pub mod engine;
