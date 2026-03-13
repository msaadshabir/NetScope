use netscope::flow::FlowTracker;
use netscope::memory;

#[test]
#[ignore = "long-running memory validation for performance plan"]
fn memory_scale_1m() {
    let count = 1_000_000usize;
    let mut tracker = FlowTracker::new(0.0, count.saturating_add(1), false, false, false);

    assert!(tracker.is_scale_mode());
    tracker.insert_synthetic_ipv4_flows(count);

    assert_eq!(tracker.len(), count);

    let rss_kb = memory::current_rss_kb().expect("failed to read current RSS");
    assert!(
        rss_kb < 500 * 1024,
        "rss budget exceeded: {:.2} MB",
        rss_kb as f64 / 1024.0
    );
}
