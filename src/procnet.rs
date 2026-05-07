//! Parse /proc/net/tcp, tcp6, udp, udp6 into connection structs.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


#[derive(Clone, Debug)]
pub struct Connection {
    pub protocol: &'static str,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: TcpState,
    pub inode: u64,
    pub pid: Option<u32>,
    pub process_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown,
}

impl TcpState {
    pub fn from_hex(s: &str) -> Self {
        match s {
            "01" => Self::Established,
            "02" => Self::SynSent,
            "03" => Self::SynRecv,
            "04" => Self::FinWait1,
            "05" => Self::FinWait2,
            "06" => Self::TimeWait,
            "07" => Self::Close,
            "08" => Self::CloseWait,
            "09" => Self::LastAck,
            "0A" => Self::Listen,
            "0B" => Self::Closing,
            _ => Self::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Established => "ESTABLISHED",
            Self::SynSent => "SYN_SENT",
            Self::SynRecv => "SYN_RECV",
            Self::FinWait1 => "FIN_WAIT1",
            Self::FinWait2 => "FIN_WAIT2",
            Self::TimeWait => "TIME_WAIT",
            Self::Close => "CLOSE",
            Self::CloseWait => "CLOSE_WAIT",
            Self::LastAck => "LAST_ACK",
            Self::Listen => "LISTEN",
            Self::Closing => "CLOSING",
            Self::Unknown => "UNKNOWN",
        }
    }
}

fn parse_ipv4_port(hex: &str) -> Option<(IpAddr, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip_u32 = u32::from_str_radix(parts[0], 16).ok()?;
    let port = u16::from_str_radix(parts[1], 16).ok()?;
    let ip = Ipv4Addr::from(ip_u32.to_be());
    Some((IpAddr::V4(ip), port))
}

fn parse_ipv6_port(hex: &str) -> Option<(IpAddr, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let port = u16::from_str_radix(parts[1], 16).ok()?;
    let ip_hex = parts[0];
    if ip_hex.len() != 32 {
        return None;
    }
    // Linux stores IPv6 as 4 little-endian 32-bit words
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&ip_hex[i * 8..(i + 1) * 8], 16).ok()?;
        let bytes = word.to_le_bytes();
        octets[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    let ip = Ipv6Addr::from(octets);
    Some((IpAddr::V6(ip), port))
}

fn parse_proc_net_file(
    path: &str,
    protocol: &'static str,
    is_ipv6: bool,
    is_udp: bool,
) -> Vec<Connection> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut conns = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let parser = if is_ipv6 {
            parse_ipv6_port
        } else {
            parse_ipv4_port
        };
        let (local_addr, local_port) = match parser(fields[1]) {
            Some(v) => v,
            None => continue,
        };
        let (remote_addr, remote_port) = match parser(fields[2]) {
            Some(v) => v,
            None => continue,
        };
        let state = if is_udp {
            // UDP uses 07 for established-like, 0A doesn't apply
            match fields[3] {
                "07" => TcpState::Close,
                "01" => TcpState::Established,
                _ => TcpState::Unknown,
            }
        } else {
            TcpState::from_hex(fields[3])
        };
        let inode = fields[9].parse::<u64>().unwrap_or(0);
        conns.push(Connection {
            protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            inode,
            pid: None,
            process_name: String::new(),
        });
    }
    conns
}

/// Build inode -> (pid, comm) map by scanning /proc/*/fd/
pub fn build_inode_pid_map() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let fd_dir = format!("/proc/{}/fd", pid);
        let fds = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let mut comm = None;
        for fd_entry in fds.flatten() {
            let link = match fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let link_str = link.to_string_lossy().to_string();
            if let Some(rest) = link_str.strip_prefix("socket:[") {
                if let Some(inode_str) = rest.strip_suffix(']') {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        let c = comm.get_or_insert_with(|| {
                            fs::read_to_string(format!("/proc/{}/comm", pid))
                                .unwrap_or_default()
                                .trim()
                                .to_string()
                        });
                        map.insert(inode, (pid, c.clone()));
                    }
                }
            }
        }
    }
    map
}

pub fn get_all_connections() -> Vec<Connection> {
    let mut conns = Vec::new();
    conns.extend(parse_proc_net_file("/proc/net/tcp", "TCP", false, false));
    conns.extend(parse_proc_net_file("/proc/net/tcp6", "TCP6", true, false));
    conns.extend(parse_proc_net_file("/proc/net/udp", "UDP", false, true));
    conns.extend(parse_proc_net_file("/proc/net/udp6", "UDP6", true, true));

    let inode_map = build_inode_pid_map();
    for conn in &mut conns {
        if let Some((pid, comm)) = inode_map.get(&conn.inode) {
            conn.pid = Some(*pid);
            conn.process_name = comm.clone();
        }
    }
    conns
}

/// Format an address for display, converting IPv4-mapped IPv6 to plain IPv4.
pub fn format_addr(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                format!("{}:{}", v4, port)
            } else if v6.is_unspecified() {
                format!("[::]:{}", port)
            } else {
                format!("[{}]:{}", v6, port)
            }
        }
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                format!("0.0.0.0:{}", port)
            } else {
                format!("{}:{}", v4, port)
            }
        }
    }
}
