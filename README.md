# net-pulse

Live network monitor TUI with Tailscale mesh awareness.

## Features

- Real-time connection table parsed from `/proc/net` (TCP/UDP, local/remote, state, PID, process name)
- Per-interface bandwidth rates (RX/TX bytes/sec) with 60-second sparkline history
- DNS configuration viewer (`/etc/resolv.conf`)
- Tailscale peer status tab (IP, hostname, online/offline) with auto-refresh
- Sortable columns (protocol, address, state, PID, process) with ascending/descending toggle
- Live filter — type to narrow connections by any field
- Scrollable with vim keys, page up/down, home/end

## Install

```
cargo build --release
# binary at target/release/net-pulse
```

## Usage

```
net-pulse
```

No arguments needed. Refreshes every second. Tailscale tab requires `tailscale` CLI in PATH.

## Keybindings

| Key | Action |
|-----|--------|
| `1` / `2` / `3` | Switch tab: Connections / DNS / Tailscale |
| `j` / `k` or arrows | Scroll up/down |
| `PgUp` / `PgDn` | Page scroll |
| `Home` / `End` | Jump to top / bottom |
| `s` | Cycle sort column |
| `S` | Toggle sort order (asc/desc) |
| `f` | Enter filter mode |
| `F` | Clear filter |
| `Esc` / `Enter` | Exit filter mode |
| `q` / `Ctrl-C` | Quit |

---
Built with Rust + ratatui
