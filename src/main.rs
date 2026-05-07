mod app;
mod dns;
mod interfaces;
mod procnet;
mod tailscale;
mod ui;

use anyhow::Result;
use app::{App, Tab};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::stdout;
use std::time::{Duration, Instant};

fn main() -> Result<()> {
    // Install panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
        original_hook(info);
    }));

    // Setup terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = run(&mut terminal);

    // Restore terminal
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    result
}

fn run(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
    let mut app = App::new();
    let tick_rate = Duration::from_secs(1);
    let mut last_tick = Instant::now();

    // Initial tailscale fetch
    app.tailscale_status = tailscale::get_tailscale_status();

    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if app.filter_active {
                    // Filter input mode
                    match key.code {
                        KeyCode::Esc => {
                            app.filter_active = false;
                        }
                        KeyCode::Enter => {
                            app.filter_active = false;
                        }
                        KeyCode::Backspace => {
                            app.filter.pop();
                        }
                        KeyCode::Char(c) => {
                            app.filter.push(c);
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(())
                        }
                        KeyCode::Char('1') => {
                            app.tab = Tab::Connections;
                            app.scroll_offset = 0;
                        }
                        KeyCode::Char('2') => app.tab = Tab::Dns,
                        KeyCode::Char('3') => app.tab = Tab::Tailscale,
                        KeyCode::Char('s') => app.cycle_sort(),
                        KeyCode::Char('S') => app.toggle_sort_order(),
                        KeyCode::Char('f') => {
                            app.filter_active = true;
                        }
                        KeyCode::Char('F') => {
                            // Clear filter
                            app.filter.clear();
                            app.filter_active = false;
                        }
                        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                        KeyCode::PageUp => app.page_up(),
                        KeyCode::PageDown => app.page_down(),
                        KeyCode::Home => app.scroll_offset = 0,
                        KeyCode::End => {
                            let max = app.filtered_connections().len().saturating_sub(1);
                            app.scroll_offset = max;
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.refresh();
            last_tick = Instant::now();
        }
    }
}
