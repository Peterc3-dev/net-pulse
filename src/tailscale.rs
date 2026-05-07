//! Tailscale status parsing via `tailscale status` CLI.

use std::process::Command;

#[derive(Clone, Debug)]
pub struct TailscaleStatus {
    pub available: bool,
    pub self_ip: String,
    pub self_name: String,
    pub peers: Vec<TailscalePeer>,
    #[allow(dead_code)]
    pub raw_output: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TailscalePeer {
    pub ip: String,
    pub hostname: String,
    pub os: String,
    pub relay: String, // "direct" or relay name
    pub status: PeerStatus,
    pub is_self: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerStatus {
    Active,
    Idle,
    Offline,
}

impl PeerStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Idle => "idle",
            Self::Offline => "offline",
        }
    }
}

pub fn get_tailscale_status() -> TailscaleStatus {
    let output = Command::new("tailscale").arg("status").output();

    match output {
        Ok(out) => {
            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr).to_string();
                return TailscaleStatus {
                    available: true,
                    self_ip: String::new(),
                    self_name: String::new(),
                    peers: Vec::new(),
                    raw_output: String::new(),
                    error: Some(err),
                };
            }
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            let peers = parse_tailscale_output(&text);
            let (self_ip, self_name) = peers
                .iter()
                .find(|p| p.is_self)
                .map(|p| (p.ip.clone(), p.hostname.clone()))
                .unwrap_or_default();

            TailscaleStatus {
                available: true,
                self_ip,
                self_name,
                peers,
                raw_output: text,
                error: None,
            }
        }
        Err(_) => TailscaleStatus {
            available: false,
            self_ip: String::new(),
            self_name: String::new(),
            peers: Vec::new(),
            raw_output: String::new(),
            error: Some("tailscale CLI not found".into()),
        },
    }
}

fn parse_tailscale_output(text: &str) -> Vec<TailscalePeer> {
    let mut peers = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let ip = fields[0].to_string();
        let hostname = fields[1].to_string();

        // Check if it's self (hostname has trailing space then OS then "-" for relay then status info)
        // Format: IP  HOSTNAME  OS  RELAY  STATUS
        // Self line often ends with status info differently
        let os = if fields.len() > 2 {
            fields[2].to_string()
        } else {
            String::new()
        };

        let mut relay = String::from("direct");
        let mut status = PeerStatus::Idle;
        let mut is_self = false;

        for &field in &fields[3..] {
            match field {
                "active;" => status = PeerStatus::Active,
                "idle;" | "idle" => status = PeerStatus::Idle,
                "offline;" | "offline" => status = PeerStatus::Offline,
                "-" => relay = "direct".into(),
                _ => {
                    if field.contains("relay") || field.contains("derp") {
                        relay = field.to_string();
                    }
                }
            }
        }

        // Tailscale marks self with a trailing indicator in some versions
        if line.contains("# self") || line.ends_with("self") {
            is_self = true;
            status = PeerStatus::Active;
        }
        // Also check for the hostname matching
        if os.is_empty() && fields.len() == 2 {
            continue;
        }

        peers.push(TailscalePeer {
            ip,
            hostname,
            os,
            relay,
            status,
            is_self,
        });
    }
    peers
}
