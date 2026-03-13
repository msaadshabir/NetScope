use std::process::Command;

pub fn current_rss_kb() -> Option<u64> {
    linux_proc_status_rss_kb().or_else(ps_rss_kb)
}

#[cfg(target_os = "linux")]
fn linux_proc_status_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_linux_proc_status_rss_kb(&status)
}

#[cfg(not(target_os = "linux"))]
fn linux_proc_status_rss_kb() -> Option<u64> {
    None
}

fn ps_rss_kb() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8(output.stdout).ok()?;
    text.trim().parse::<u64>().ok()
}

#[cfg(any(test, target_os = "linux"))]
fn parse_linux_proc_status_rss_kb(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let value = rest.split_whitespace().next()?;
            return value.parse::<u64>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::parse_linux_proc_status_rss_kb;

    #[test]
    fn parses_linux_proc_status_rss() {
        let status = "Name:\tnetscope\nVmRSS:\t  160268 kB\nThreads:\t1\n";
        assert_eq!(parse_linux_proc_status_rss_kb(status), Some(160268));
    }

    #[test]
    fn returns_none_without_vmrss() {
        let status = "Name:\tnetscope\nThreads:\t1\n";
        assert_eq!(parse_linux_proc_status_rss_kb(status), None);
    }
}
