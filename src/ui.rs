//! TUI rendering with ratatui. Phosphor-green theme.

use crate::app::{App, SortColumn, Tab};
use crate::interfaces::format_bytes;
use crate::procnet::{format_addr, TcpState};
use crate::tailscale::PeerStatus;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table, Tabs, Wrap};
use ratatui::Frame;

// Phosphor-green palette
const GREEN: Color = Color::Rgb(0, 255, 200); // primary cyan-green
const DIM_GREEN: Color = Color::Rgb(0, 128, 100); // dimmed cyan-green
const DARK_GREEN: Color = Color::Rgb(0, 50, 40); // very dim
const BRIGHT: Color = Color::Rgb(160, 255, 230); // bright highlight
const CYAN: Color = Color::Rgb(0, 220, 220);
const YELLOW: Color = Color::Rgb(220, 220, 0);
const RED: Color = Color::Rgb(255, 80, 80);
const BG: Color = Color::Rgb(5, 10, 5); // near-black with green tint
const HEADER_BG: Color = Color::Rgb(0, 30, 15);

pub fn draw(f: &mut Frame, app: &App) {
    let size = f.area();

    // Overall background
    let bg_block = Block::default().style(Style::default().bg(BG));
    f.render_widget(bg_block, size);

    // Main layout: top bar, content, status bar
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // tab bar
            Constraint::Min(10),   // content
            Constraint::Length(1), // status bar
        ])
        .split(size);

    draw_tab_bar(f, app, main_chunks[0]);
    draw_status_bar(f, app, main_chunks[2]);

    match app.tab {
        Tab::Connections => draw_connections_tab(f, app, main_chunks[1]),
        Tab::Dns => draw_dns_tab(f, app, main_chunks[1]),
        Tab::Tailscale => draw_tailscale_tab(f, app, main_chunks[1]),
    }
}

fn draw_tab_bar(f: &mut Frame, app: &App, area: Rect) {
    let tabs = [Tab::Connections, Tab::Dns, Tab::Tailscale];
    let titles: Vec<Line> = tabs
        .iter()
        .map(|t| {
            let style = if *t == app.tab {
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(DIM_GREEN)
            };
            Line::from(Span::styled(t.label(), style))
        })
        .collect();

    let selected = match app.tab {
        Tab::Connections => 0,
        Tab::Dns => 1,
        Tab::Tailscale => 2,
    };

    let tabs_widget = Tabs::new(titles)
        .select(selected)
        .highlight_style(
            Style::default()
                .fg(GREEN)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(Span::styled(" | ", Style::default().fg(DARK_GREEN)))
        .style(Style::default().bg(HEADER_BG));

    f.render_widget(tabs_widget, area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let filter_text = if app.filter_active {
        format!("FILTER: {}_ ", app.filter)
    } else if !app.filter.is_empty() {
        format!("filter: {} ", app.filter)
    } else {
        String::new()
    };

    let conn_count = app.filtered_connections().len();
    let total_count = app.connections.len();

    let status = format!(
        " {}  Sort: {} {}  Conns: {}/{}  RX: {}  TX: {}  [s]ort [S]order [f]ilter [1-3]tab [q]uit",
        filter_text,
        app.sort_column.label(),
        if app.sort_ascending { "▲" } else { "▼" },
        conn_count,
        total_count,
        format_bytes(app.total_rx_rate()),
        format_bytes(app.total_tx_rate()),
    );

    let bar = Paragraph::new(status).style(Style::default().fg(GREEN).bg(HEADER_BG));
    f.render_widget(bar, area);
}

fn draw_connections_tab(f: &mut Frame, app: &App, area: Rect) {
    // Split: interface overview (top), connection table (middle), sparklines (bottom)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(iface_panel_height(app)),
            Constraint::Min(8),
            Constraint::Length(sparkline_panel_height(app)),
        ])
        .split(area);

    draw_interfaces(f, app, chunks[0]);
    draw_connection_table(f, app, chunks[1]);
    draw_sparklines(f, app, chunks[2]);
}

fn iface_panel_height(app: &App) -> u16 {
    // 2 for border + 1 per interface, min 3
    (app.interfaces.len() as u16 + 2).clamp(3, 8)
}

fn sparkline_panel_height(app: &App) -> u16 {
    let active: usize = app
        .interfaces
        .iter()
        .filter(|i| i.state == "up" || i.rx_rate > 0.0 || i.tx_rate > 0.0)
        .count();
    // 2 lines per active interface (rx + tx) + 2 border, min 4
    ((active * 2 + 2) as u16).clamp(4, 14)
}

fn draw_interfaces(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(
            " Interfaces ",
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM_GREEN))
        .style(Style::default().bg(BG));

    let header = Row::new(vec![
        Cell::from("Interface").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Cell::from("State").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Cell::from("IPv4").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Cell::from("RX Rate").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Cell::from("TX Rate").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Cell::from("RX Total").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Cell::from("TX Total").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
    ]);

    let rows: Vec<Row> = app
        .interfaces
        .iter()
        .map(|iface| {
            let name_style = if iface.is_tailscale {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else if iface.state == "up" {
                Style::default().fg(GREEN)
            } else {
                Style::default().fg(DIM_GREEN)
            };

            let state_style = match iface.state.as_str() {
                "up" => Style::default().fg(GREEN),
                "down" => Style::default().fg(RED),
                _ => Style::default().fg(YELLOW),
            };

            let ip_str = app
                .get_interface_ipv4(&iface.name)
                .unwrap_or_else(|| "-".into());

            Row::new(vec![
                Cell::from(iface.name.clone()).style(name_style),
                Cell::from(iface.state.clone()).style(state_style),
                Cell::from(ip_str).style(Style::default().fg(BRIGHT)),
                Cell::from(format_bytes(iface.rx_rate)).style(Style::default().fg(GREEN)),
                Cell::from(format_bytes(iface.tx_rate)).style(Style::default().fg(GREEN)),
                Cell::from(crate::interfaces::format_total_bytes(iface.rx_bytes))
                    .style(Style::default().fg(DIM_GREEN)),
                Cell::from(crate::interfaces::format_total_bytes(iface.tx_bytes))
                    .style(Style::default().fg(DIM_GREEN)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(block);

    f.render_widget(table, area);
}

fn draw_connection_table(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(
            " Connections ",
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM_GREEN))
        .style(Style::default().bg(BG));

    let header_cells = [
        ("Proto", SortColumn::Protocol),
        ("Local Address", SortColumn::LocalAddr),
        ("Remote Address", SortColumn::RemoteAddr),
        ("State", SortColumn::State),
        ("PID", SortColumn::Pid),
        ("Process", SortColumn::Process),
    ];

    let header = Row::new(header_cells.iter().map(|(label, col)| {
        let mut text = label.to_string();
        if *col == app.sort_column {
            text.push(if app.sort_ascending { '▲' } else { '▼' });
        }
        Cell::from(text).style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD))
    }));

    let filtered = app.filtered_connections();
    let visible = filtered
        .iter()
        .skip(app.scroll_offset)
        .take(area.height.saturating_sub(4) as usize);

    let rows: Vec<Row> = visible
        .map(|conn| {
            let state_style = match conn.state {
                TcpState::Established => Style::default().fg(GREEN),
                TcpState::Listen => Style::default().fg(CYAN),
                TcpState::TimeWait => Style::default().fg(DARK_GREEN),
                TcpState::CloseWait => Style::default().fg(YELLOW),
                TcpState::SynSent | TcpState::SynRecv => Style::default().fg(YELLOW),
                TcpState::FinWait1 | TcpState::FinWait2 => Style::default().fg(YELLOW),
                TcpState::Close | TcpState::LastAck | TcpState::Closing => Style::default().fg(RED),
                TcpState::Unknown => Style::default().fg(DIM_GREEN),
            };

            let pid_str = conn
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into());

            let proc_name = if conn.process_name.is_empty() {
                "-"
            } else {
                &conn.process_name
            };

            Row::new(vec![
                Cell::from(conn.protocol).style(Style::default().fg(DIM_GREEN)),
                Cell::from(format_addr(conn.local_addr, conn.local_port))
                    .style(Style::default().fg(BRIGHT)),
                Cell::from(format_addr(conn.remote_addr, conn.remote_port))
                    .style(Style::default().fg(BRIGHT)),
                Cell::from(conn.state.label()).style(state_style),
                Cell::from(pid_str).style(Style::default().fg(DIM_GREEN)),
                Cell::from(proc_name.to_string()).style(Style::default().fg(GREEN)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(block);

    f.render_widget(table, area);
}

fn draw_sparklines(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(
            " Bandwidth History (60s) ",
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM_GREEN))
        .style(Style::default().bg(BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Get active interfaces with history
    let active_ifaces: Vec<&str> = app
        .interfaces
        .iter()
        .filter(|i| i.state == "up" || i.rx_rate > 0.0 || i.tx_rate > 0.0)
        .map(|i| i.name.as_str())
        .collect();

    if active_ifaces.is_empty() || inner.height < 2 {
        let msg = Paragraph::new("  No active interfaces").style(Style::default().fg(DIM_GREEN));
        f.render_widget(msg, inner);
        return;
    }

    let lines_per_iface = 2u16; // RX + TX
    let max_ifaces = (inner.height / lines_per_iface) as usize;
    let show_ifaces: Vec<&&str> = active_ifaces.iter().take(max_ifaces).collect();

    let constraints: Vec<Constraint> = show_ifaces
        .iter()
        .map(|_| Constraint::Length(lines_per_iface))
        .collect();

    let sparkline_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    for (idx, &&iface_name) in show_ifaces.iter().enumerate() {
        if idx >= sparkline_chunks.len() {
            break;
        }
        let chunk = sparkline_chunks[idx];
        if chunk.height < 2 {
            break;
        }

        let (rx_data, tx_data) = match app.bandwidth_history.history.get(iface_name) {
            Some((rx, tx)) => (rx.clone(), tx.clone()),
            None => continue,
        };

        // Convert to u64 for sparkline
        let max_val = rx_data
            .iter()
            .chain(tx_data.iter())
            .cloned()
            .fold(1.0f64, f64::max);

        let rx_u64: Vec<u64> = rx_data
            .iter()
            .map(|v| ((v / max_val) * 100.0) as u64)
            .collect();
        let tx_u64: Vec<u64> = tx_data
            .iter()
            .map(|v| ((v / max_val) * 100.0) as u64)
            .collect();

        let rx_rate = rx_data.last().copied().unwrap_or(0.0);
        let tx_rate = tx_data.last().copied().unwrap_or(0.0);

        // Split chunk into RX and TX rows
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(1)])
            .split(chunk);

        // RX sparkline
        let rx_label = format!("{} RX {}", iface_name, format_bytes(rx_rate));
        let label_width = rx_label.len() as u16 + 1;
        let rx_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(label_width.min(rows[0].width)),
                Constraint::Min(4),
            ])
            .split(rows[0]);
        let rx_lbl = Paragraph::new(rx_label).style(Style::default().fg(GREEN));
        f.render_widget(rx_lbl, rx_cols[0]);
        let rx_spark = Sparkline::default()
            .data(&rx_u64)
            .style(Style::default().fg(GREEN));
        f.render_widget(rx_spark, rx_cols[1]);

        // TX sparkline
        let tx_label = format!("{} TX {}", iface_name, format_bytes(tx_rate));
        let tx_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(label_width.min(rows[1].width)),
                Constraint::Min(4),
            ])
            .split(rows[1]);
        let tx_lbl = Paragraph::new(tx_label).style(Style::default().fg(CYAN));
        f.render_widget(tx_lbl, tx_cols[0]);
        let tx_spark = Sparkline::default()
            .data(&tx_u64)
            .style(Style::default().fg(CYAN));
        f.render_widget(tx_spark, tx_cols[1]);
    }
}

fn draw_dns_tab(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(
            " DNS Configuration ",
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM_GREEN))
        .style(Style::default().bg(BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("Source: ", Style::default().fg(DIM_GREEN)),
            Span::styled(
                &app.dns_config.source,
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
    ];

    lines.push(Line::from(Span::styled(
        "DNS Servers",
        Style::default()
            .fg(GREEN)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )));
    lines.push(Line::from(""));

    if app.dns_config.servers.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No DNS servers configured",
            Style::default().fg(YELLOW),
        )));
    } else {
        for server in &app.dns_config.servers {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(&server.addr, Style::default().fg(BRIGHT)),
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("({})", server.label),
                    Style::default().fg(DIM_GREEN),
                ),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Search Domains",
        Style::default()
            .fg(GREEN)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )));
    lines.push(Line::from(""));

    if app.dns_config.search_domains.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (none)",
            Style::default().fg(DIM_GREEN),
        )));
    } else {
        for domain in &app.dns_config.search_domains {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(domain, Style::default().fg(GREEN)),
            ]));
        }
    }

    let paragraph = Paragraph::new(lines)
        .style(Style::default().bg(BG))
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, inner);
}

fn draw_tailscale_tab(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(
            " Tailscale ",
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM_GREEN))
        .style(Style::default().bg(BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let ts = &app.tailscale_status;

    if !ts.available {
        let msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Tailscale CLI not available",
                Style::default().fg(YELLOW),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Install tailscale to use this panel",
                Style::default().fg(DIM_GREEN),
            )),
        ])
        .style(Style::default().bg(BG));
        f.render_widget(msg, inner);
        return;
    }

    if let Some(ref err) = ts.error {
        let msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("  Error: {}", err),
                Style::default().fg(RED),
            )),
        ])
        .style(Style::default().bg(BG));
        f.render_widget(msg, inner);
        return;
    }

    // Split into info header and peer table
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(4)])
        .split(inner);

    // Self info
    let info_lines = vec![
        Line::from(vec![
            Span::styled("  This node: ", Style::default().fg(DIM_GREEN)),
            Span::styled(
                &ts.self_name,
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Tailscale IP: ", Style::default().fg(DIM_GREEN)),
            Span::styled(
                &ts.self_ip,
                Style::default().fg(BRIGHT).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![Span::styled(
            format!("  Peers: {}", ts.peers.len()),
            Style::default().fg(DIM_GREEN),
        )]),
    ];
    let info = Paragraph::new(info_lines).style(Style::default().bg(BG));
    f.render_widget(info, chunks[0]);

    // Peer table
    let header = Row::new(vec![
        Cell::from("IP").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Cell::from("Hostname").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Cell::from("OS").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Cell::from("Relay").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Cell::from("Status").style(Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
    ]);

    let rows: Vec<Row> = ts
        .peers
        .iter()
        .map(|peer| {
            let status_style = match peer.status {
                PeerStatus::Active => Style::default().fg(GREEN),
                PeerStatus::Idle => Style::default().fg(DIM_GREEN),
                PeerStatus::Offline => Style::default().fg(RED),
            };

            let name_style = if peer.is_self {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(BRIGHT)
            };

            let relay_style = if peer.relay == "direct" {
                Style::default().fg(GREEN)
            } else {
                Style::default().fg(YELLOW)
            };

            Row::new(vec![
                Cell::from(peer.ip.clone()).style(Style::default().fg(BRIGHT)),
                Cell::from(if peer.is_self {
                    format!("{} (self)", peer.hostname)
                } else {
                    peer.hostname.clone()
                })
                .style(name_style),
                Cell::from(peer.os.clone()).style(Style::default().fg(DIM_GREEN)),
                Cell::from(peer.relay.clone()).style(relay_style),
                Cell::from(peer.status.label()).style(status_style),
            ])
        })
        .collect();

    let peer_block = Block::default()
        .title(Span::styled(
            " Peers ",
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::TOP)
        .border_style(Style::default().fg(DIM_GREEN))
        .style(Style::default().bg(BG));

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Percentage(30),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(peer_block);

    f.render_widget(table, chunks[1]);
}
