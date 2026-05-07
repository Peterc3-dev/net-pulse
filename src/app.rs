//! Application state and logic.

use crate::dns::{self, DnsConfig};
use crate::interfaces::{self, BandwidthHistory, Interface};
use crate::procnet::{self, Connection};
use crate::tailscale::{self, TailscaleStatus};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Connections,
    Dns,
    Tailscale,
}

impl Tab {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connections => "1:Connections",
            Self::Dns => "2:DNS",
            Self::Tailscale => "3:Tailscale",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Protocol,
    LocalAddr,
    RemoteAddr,
    State,
    Pid,
    Process,
}

impl SortColumn {
    pub fn next(self) -> Self {
        match self {
            Self::Protocol => Self::LocalAddr,
            Self::LocalAddr => Self::RemoteAddr,
            Self::RemoteAddr => Self::State,
            Self::State => Self::Pid,
            Self::Pid => Self::Process,
            Self::Process => Self::Protocol,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Protocol => "Proto",
            Self::LocalAddr => "Local",
            Self::RemoteAddr => "Remote",
            Self::State => "State",
            Self::Pid => "PID",
            Self::Process => "Process",
        }
    }
}

pub struct App {
    pub tab: Tab,
    pub interfaces: Vec<Interface>,
    pub connections: Vec<Connection>,
    pub dns_config: DnsConfig,
    pub tailscale_status: TailscaleStatus,
    pub bandwidth_history: BandwidthHistory,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    pub filter: String,
    pub filter_active: bool,
    pub scroll_offset: usize,
    pub last_update: Instant,
    prev_bytes: HashMap<String, (u64, u64)>,
    ipv4_addrs: HashMap<String, Vec<std::net::IpAddr>>,
    pub tailscale_refresh_counter: u8,
}

impl App {
    pub fn new() -> Self {
        let interfaces = interfaces::get_interfaces();
        let ipv4_addrs = interfaces::get_ipv4_addrs();
        Self {
            tab: Tab::Connections,
            interfaces,
            connections: procnet::get_all_connections(),
            dns_config: dns::get_dns_config(),
            tailscale_status: TailscaleStatus {
                available: false,
                self_ip: String::new(),
                self_name: String::new(),
                peers: Vec::new(),
                raw_output: String::new(),
                error: Some("Not yet queried".into()),
            },
            bandwidth_history: BandwidthHistory::new(60),
            sort_column: SortColumn::State,
            sort_ascending: true,
            filter: String::new(),
            filter_active: false,
            scroll_offset: 0,
            last_update: Instant::now(),
            prev_bytes: HashMap::new(),
            ipv4_addrs,
            tailscale_refresh_counter: 0,
        }
    }

    pub fn refresh(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        let new_ifaces = interfaces::get_interfaces();

        // Calculate rates
        let mut ifaces_with_rates = new_ifaces;
        for iface in &mut ifaces_with_rates {
            if let Some((prev_rx, prev_tx)) = self.prev_bytes.get(&iface.name) {
                if dt > 0.0 {
                    iface.rx_rate = if iface.rx_bytes >= *prev_rx {
                        (iface.rx_bytes - *prev_rx) as f64 / dt
                    } else {
                        0.0
                    };
                    iface.tx_rate = if iface.tx_bytes >= *prev_tx {
                        (iface.tx_bytes - *prev_tx) as f64 / dt
                    } else {
                        0.0
                    };
                }
            }
            self.prev_bytes
                .insert(iface.name.clone(), (iface.rx_bytes, iface.tx_bytes));
        }

        self.bandwidth_history.update(&ifaces_with_rates, dt);
        self.interfaces = ifaces_with_rates;
        self.ipv4_addrs = interfaces::get_ipv4_addrs();
        self.connections = procnet::get_all_connections();
        self.sort_connections();

        // Refresh tailscale every 10 ticks (~10 seconds) or on first load
        self.tailscale_refresh_counter += 1;
        if self.tailscale_refresh_counter >= 10 || !self.tailscale_status.available {
            self.tailscale_status = tailscale::get_tailscale_status();
            self.tailscale_refresh_counter = 0;
        }
    }

    pub fn sort_connections(&mut self) {
        let asc = self.sort_ascending;
        self.connections.sort_by(|a, b| {
            let ord = match self.sort_column {
                SortColumn::Protocol => a.protocol.cmp(b.protocol),
                SortColumn::LocalAddr => {
                    let la = format!("{}:{}", a.local_addr, a.local_port);
                    let lb = format!("{}:{}", b.local_addr, b.local_port);
                    la.cmp(&lb)
                }
                SortColumn::RemoteAddr => {
                    let ra = format!("{}:{}", a.remote_addr, a.remote_port);
                    let rb = format!("{}:{}", b.remote_addr, b.remote_port);
                    ra.cmp(&rb)
                }
                SortColumn::State => (a.state as u8).cmp(&(b.state as u8)),
                SortColumn::Pid => a.pid.unwrap_or(0).cmp(&b.pid.unwrap_or(0)),
                SortColumn::Process => a.process_name.cmp(&b.process_name),
            };
            if asc {
                ord
            } else {
                ord.reverse()
            }
        });
    }

    pub fn filtered_connections(&self) -> Vec<&Connection> {
        if self.filter.is_empty() {
            return self.connections.iter().collect();
        }
        let f = self.filter.to_lowercase();
        self.connections
            .iter()
            .filter(|c| {
                c.protocol.to_lowercase().contains(&f)
                    || c.local_addr.to_string().contains(&f)
                    || c.local_port.to_string().contains(&f)
                    || c.remote_addr.to_string().contains(&f)
                    || c.remote_port.to_string().contains(&f)
                    || c.state.label().to_lowercase().contains(&f)
                    || c.process_name.to_lowercase().contains(&f)
                    || c.pid
                        .map(|p| p.to_string().contains(&f))
                        .unwrap_or(false)
            })
            .collect()
    }

    pub fn get_interface_ipv4(&self, name: &str) -> Option<String> {
        self.ipv4_addrs
            .get(name)
            .and_then(|addrs| addrs.first())
            .map(|a| a.to_string())
    }

    pub fn total_rx_rate(&self) -> f64 {
        self.interfaces.iter().map(|i| i.rx_rate).sum()
    }

    pub fn total_tx_rate(&self) -> f64 {
        self.interfaces.iter().map(|i| i.tx_rate).sum()
    }

    pub fn cycle_sort(&mut self) {
        self.sort_column = self.sort_column.next();
        self.sort_connections();
    }

    pub fn toggle_sort_order(&mut self) {
        self.sort_ascending = !self.sort_ascending;
        self.sort_connections();
    }

    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        let max = self.filtered_connections().len().saturating_sub(1);
        if self.scroll_offset < max {
            self.scroll_offset += 1;
        }
    }

    pub fn page_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(20);
    }

    pub fn page_down(&mut self) {
        let max = self.filtered_connections().len().saturating_sub(1);
        self.scroll_offset = (self.scroll_offset + 20).min(max);
    }
}
