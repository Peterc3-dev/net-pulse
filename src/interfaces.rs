//! Network interface enumeration and bandwidth tracking via /sys/class/net/.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct Interface {
    pub name: String,
    #[allow(dead_code)]
    pub ip_addrs: Vec<IpAddr>,
    pub state: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate: f64, // bytes/sec
    pub tx_rate: f64,
    pub is_tailscale: bool,
}

/// Historical bandwidth samples per interface.
pub struct BandwidthHistory {
    /// name -> (rx_samples, tx_samples) in bytes/sec, most recent last
    pub history: HashMap<String, (Vec<f64>, Vec<f64>)>,
    pub max_samples: usize,
    prev_bytes: HashMap<String, (u64, u64)>,
}

impl BandwidthHistory {
    pub fn new(max_samples: usize) -> Self {
        Self {
            history: HashMap::new(),
            max_samples,
            prev_bytes: HashMap::new(),
        }
    }

    pub fn update(&mut self, interfaces: &[Interface], dt_secs: f64) {
        for iface in interfaces {
            let (rx_hist, tx_hist) = self
                .history
                .entry(iface.name.clone())
                .or_insert_with(|| (Vec::new(), Vec::new()));

            if let Some((prev_rx, prev_tx)) = self.prev_bytes.get(&iface.name) {
                let rx_rate = if iface.rx_bytes >= *prev_rx {
                    (iface.rx_bytes - *prev_rx) as f64 / dt_secs
                } else {
                    0.0
                };
                let tx_rate = if iface.tx_bytes >= *prev_tx {
                    (iface.tx_bytes - *prev_tx) as f64 / dt_secs
                } else {
                    0.0
                };
                rx_hist.push(rx_rate);
                tx_hist.push(tx_rate);
                if rx_hist.len() > self.max_samples {
                    rx_hist.remove(0);
                }
                if tx_hist.len() > self.max_samples {
                    tx_hist.remove(0);
                }
            }

            self.prev_bytes
                .insert(iface.name.clone(), (iface.rx_bytes, iface.tx_bytes));
        }
        // Remove stale interfaces
        let current_names: Vec<String> = interfaces.iter().map(|i| i.name.clone()).collect();
        self.history.retain(|k, _| current_names.contains(k));
        self.prev_bytes.retain(|k, _| current_names.contains(k));
    }
}

fn read_sysfs_u64(path: &str) -> u64 {
    fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .parse()
        .unwrap_or(0)
}

fn get_interface_ips(name: &str) -> Vec<IpAddr> {
    // Parse from /proc/net/if_inet6 and /proc/net/fib_trie is complex.
    // Use a simpler approach: try ip command output parsing, or read /proc.
    // For robustness, we'll parse both IPv4 from fib_trie and IPv6 from if_inet6.
    let mut addrs = Vec::new();

    // IPv4 from /proc/net/fib_trie - too complex. Use /sys approach or just skip.
    // Simpler: parse `ip -4 addr show <name>` output.
    // But we want no external commands if possible. Let's parse /proc/net/fib_trie.
    // Actually, simplest reliable method: read /proc/net/if_inet6 for v6,
    // and for v4, parse the route info. Let's use ip command as fallback.

    // Try to get IPv4 from a simple /proc parse
    if let Ok(_content) = fs::read_to_string("/proc/net/fib_trie") {
        // fib_trie parsing is complex; IPv4 resolved via `ip` command in get_ipv4_addrs()
    }

    // Parse /proc/net/if_inet6 for IPv6
    if let Ok(content) = fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 6 && fields[5] == name {
                if let Some(addr) = parse_hex_ipv6(fields[0]) {
                    addrs.push(IpAddr::V6(addr));
                }
            }
        }
    }

    addrs
}

fn parse_hex_ipv6(hex: &str) -> Option<std::net::Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for i in 0..16 {
        octets[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(std::net::Ipv6Addr::from(octets))
}

pub fn get_interfaces() -> Vec<Interface> {
    let net_dir = "/sys/class/net";
    let entries = match fs::read_dir(net_dir) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let mut interfaces = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" {
            continue; // skip loopback
        }

        let base = format!("{}/{}", net_dir, name);
        let state = fs::read_to_string(format!("{}/operstate", base))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();

        let rx_bytes = read_sysfs_u64(&format!("{}/statistics/rx_bytes", base));
        let tx_bytes = read_sysfs_u64(&format!("{}/statistics/tx_bytes", base));
        let ip_addrs = get_interface_ips(&name);
        let is_tailscale = name.starts_with("tailscale") || name.starts_with("ts") || name == "wg0";

        interfaces.push(Interface {
            name,
            ip_addrs,
            state,
            rx_bytes,
            tx_bytes,
            rx_rate: 0.0,
            tx_rate: 0.0,
            is_tailscale,
        });
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    interfaces
}

/// Try to read IPv4 addresses by parsing `ip -4 -o addr show` output.
/// Returns a map of interface name -> list of IPv4 addrs.
pub fn get_ipv4_addrs() -> HashMap<String, Vec<IpAddr>> {
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    // Read /proc/net/fib_trie is too complex. Parse ip command output.
    let output = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show"])
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            // Format: "2: wlp1s0    inet 192.168.1.100/24 ..."
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 && fields[2] == "inet" {
                let iface = fields[1].trim_end_matches(':');
                if let Some(ip_str) = fields[3].split('/').next() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        map.entry(iface.to_string()).or_default().push(ip);
                    }
                }
            }
        }
    }
    map
}

pub fn format_bytes(bytes: f64) -> String {
    if bytes >= 1_000_000_000.0 {
        format!("{:.1} GB/s", bytes / 1_000_000_000.0)
    } else if bytes >= 1_000_000.0 {
        format!("{:.1} MB/s", bytes / 1_000_000.0)
    } else if bytes >= 1_000.0 {
        format!("{:.1} KB/s", bytes / 1_000.0)
    } else {
        format!("{:.0} B/s", bytes)
    }
}

pub fn format_total_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, rx: u64, tx: u64) -> Interface {
        Interface {
            name: name.to_string(),
            ip_addrs: Vec::new(),
            state: "up".to_string(),
            rx_bytes: rx,
            tx_bytes: tx,
            rx_rate: 0.0,
            tx_rate: 0.0,
            is_tailscale: false,
        }
    }

    #[test]
    fn format_bytes_picks_unit() {
        assert_eq!(format_bytes(512.0), "512 B/s");
        assert_eq!(format_bytes(1_500.0), "1.5 KB/s");
        assert_eq!(format_bytes(2_000_000.0), "2.0 MB/s");
        assert_eq!(format_bytes(3_000_000_000.0), "3.0 GB/s");
    }

    #[test]
    fn format_total_bytes_picks_unit() {
        assert_eq!(format_total_bytes(0), "0 B");
        assert_eq!(format_total_bytes(999), "999 B");
        assert_eq!(format_total_bytes(1_500), "1.5 KB");
        assert_eq!(format_total_bytes(5_000_000), "5.0 MB");
        assert_eq!(format_total_bytes(7_000_000_000), "7.0 GB");
    }

    #[test]
    fn parse_hex_ipv6_loopback() {
        let addr = parse_hex_ipv6("00000000000000000000000000000001").unwrap();
        assert_eq!(addr, std::net::Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn parse_hex_ipv6_rejects_wrong_length() {
        assert!(parse_hex_ipv6("0001").is_none());
        assert!(parse_hex_ipv6("zz000000000000000000000000000001").is_none());
    }

    #[test]
    fn bandwidth_history_computes_rate_over_two_samples() {
        let mut hist = BandwidthHistory::new(60);
        // First update only records the baseline; no rate yet.
        hist.update(&[iface("eth0", 1_000, 2_000)], 1.0);
        assert!(hist.history["eth0"].0.is_empty());

        // Second update: +1000 rx, +500 tx over 1 second.
        hist.update(&[iface("eth0", 2_000, 2_500)], 1.0);
        assert_eq!(hist.history["eth0"].0, vec![1_000.0]);
        assert_eq!(hist.history["eth0"].1, vec![500.0]);
    }

    #[test]
    fn bandwidth_history_clamps_counter_reset_to_zero() {
        let mut hist = BandwidthHistory::new(60);
        hist.update(&[iface("eth0", 5_000, 5_000)], 1.0);
        // Counter went backwards (interface reset) -> rate floored at 0.
        hist.update(&[iface("eth0", 1_000, 1_000)], 1.0);
        assert_eq!(hist.history["eth0"].0, vec![0.0]);
        assert_eq!(hist.history["eth0"].1, vec![0.0]);
    }

    #[test]
    fn bandwidth_history_caps_samples_and_drops_stale_ifaces() {
        let mut hist = BandwidthHistory::new(2);
        for n in 1..=5u64 {
            hist.update(&[iface("eth0", n * 1_000, n * 1_000)], 1.0);
        }
        assert_eq!(hist.history["eth0"].0.len(), 2);

        // eth0 disappears, wlan0 appears -> stale entry pruned.
        hist.update(&[iface("wlan0", 100, 100)], 1.0);
        assert!(!hist.history.contains_key("eth0"));
        assert!(hist.history.contains_key("wlan0"));
    }
}
