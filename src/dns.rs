//! DNS configuration parsing from /etc/resolv.conf and systemd-resolved.

use std::fs;
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct DnsConfig {
    pub servers: Vec<DnsServer>,
    pub search_domains: Vec<String>,
    pub source: String,
}

#[derive(Clone, Debug)]
pub struct DnsServer {
    pub addr: String,
    pub label: String, // e.g. "Cloudflare", "Google", "Tailscale MagicDNS"
}

fn label_dns(addr: &str) -> String {
    match addr {
        "1.1.1.1" | "1.0.0.1" => "Cloudflare".into(),
        "8.8.8.8" | "8.8.4.4" => "Google".into(),
        "9.9.9.9" | "149.112.112.112" => "Quad9".into(),
        "208.67.222.222" | "208.67.220.220" => "OpenDNS".into(),
        "100.100.100.100" => "Tailscale MagicDNS".into(),
        "127.0.0.53" => "systemd-resolved stub".into(),
        "127.0.0.1" => "localhost".into(),
        _ => {
            if addr.starts_with("192.168.") || addr.starts_with("10.") || addr.starts_with("172.") {
                "LAN/Router".into()
            } else if addr.starts_with("100.") {
                "Tailscale network".into()
            } else {
                "Custom".into()
            }
        }
    }
}

pub fn get_dns_config() -> DnsConfig {
    // Try /etc/resolv.conf first
    let content = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let mut servers = Vec::new();
    let mut search_domains = Vec::new();
    let mut source = "/etc/resolv.conf".to_string();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            // Check for resolvconf/systemd generated markers
            if line.contains("systemd-resolved") {
                source = "systemd-resolved".to_string();
            } else if line.contains("resolvconf") {
                source = "resolvconf".to_string();
            } else if line.contains("NetworkManager") {
                source = "NetworkManager".to_string();
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("nameserver") {
            let addr = rest.trim();
            if !addr.is_empty() {
                let label = label_dns(addr);
                servers.push(DnsServer {
                    addr: addr.to_string(),
                    label,
                });
            }
        } else if let Some(rest) = line.strip_prefix("search") {
            for domain in rest.split_whitespace() {
                search_domains.push(domain.to_string());
            }
        }
    }

    // If systemd-resolved is the stub, try to get real upstream servers
    if servers.iter().any(|s| s.addr == "127.0.0.53") {
        if let Ok(output) = std::process::Command::new("resolvectl")
            .arg("status")
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut in_dns_servers = false;
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("DNS Servers:") || trimmed.starts_with("Current DNS Server:")
                {
                    in_dns_servers = true;
                    if let Some(addr_part) = trimmed.split(':').nth(1) {
                        let addr = addr_part.trim();
                        if !addr.is_empty() && addr.parse::<IpAddr>().is_ok() {
                            let label = label_dns(addr);
                            servers.push(DnsServer {
                                addr: format!("{} (upstream)", addr),
                                label,
                            });
                        }
                    }
                } else if in_dns_servers && trimmed.parse::<IpAddr>().is_ok() {
                    let label = label_dns(trimmed);
                    servers.push(DnsServer {
                        addr: format!("{} (upstream)", trimmed),
                        label,
                    });
                } else {
                    in_dns_servers = false;
                }
            }
            source = "systemd-resolved".to_string();
        }
    }

    DnsConfig {
        servers,
        search_domains,
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_dns_known_resolvers() {
        assert_eq!(label_dns("1.1.1.1"), "Cloudflare");
        assert_eq!(label_dns("8.8.4.4"), "Google");
        assert_eq!(label_dns("9.9.9.9"), "Quad9");
        assert_eq!(label_dns("100.100.100.100"), "Tailscale MagicDNS");
        assert_eq!(label_dns("127.0.0.53"), "systemd-resolved stub");
    }

    #[test]
    fn label_dns_private_ranges() {
        assert_eq!(label_dns("192.168.1.1"), "LAN/Router");
        assert_eq!(label_dns("10.0.0.1"), "LAN/Router");
        assert_eq!(label_dns("100.64.0.1"), "Tailscale network");
    }

    #[test]
    fn label_dns_falls_back_to_custom() {
        assert_eq!(label_dns("203.0.113.7"), "Custom");
    }
}
