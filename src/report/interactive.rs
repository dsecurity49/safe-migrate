use crate::report::violations::Violation;
use crate::analysis::state::Confidence;
use std::io::{stdout, Write};
use terminal_size::{Width, Height, terminal_size};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind},
    execute, queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
};
use anyhow::Result;

pub fn run_interactive(violations: &[Violation], confidence: &Confidence) -> Result<()> {
    if violations.is_empty() {
        println!("No violations found!");
        return Ok(());
    }

    let mut stdout = stdout();
    enable_raw_mode()?;
    execute!(stdout, cursor::Hide, Clear(ClearType::All), cursor::MoveTo(0, 0))?;

    let mut selected = 0;
    
    loop {
        queue!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0))?;
        queue!(
            stdout,
            SetForegroundColor(Color::Cyan),
            Print(format!("Safe-Migrate Interactive Viewer ({} violations) [Confidence: {:?}]\r\n\r\n", violations.len(), confidence)),
            ResetColor,
        )?;

        // Calculate available height for the list dynamically
        let (_w, Height(h)) = terminal_size().unwrap_or((Width(80), Height(24)));
        // Subtract lines for header (2), footer separator (2), detail text (~4), SQL (~4), and quit instructions (2)
        let window_size = (h.saturating_sub(15) as usize).max(5);

        // Render list (sliding window)
        let start = if selected >= window_size / 2 {
            selected - window_size / 2
        } else {
            0
        };
        let end = std::cmp::min(start + window_size, violations.len());

        if start > 0 {
            queue!(stdout, Print("   ...\r\n"))?;
        }

        for i in start..end {
            let v = &violations[i];
            let prefix = if i == selected { " > " } else { "   " };
            let color = match v.tier {
                crate::report::violations::ViolationTier::Tier1 => Color::Red,
                crate::report::violations::ViolationTier::Tier2 => Color::Yellow,
                crate::report::violations::ViolationTier::Tier3 => Color::Green,
            };

            queue!(
                stdout,
                Print(prefix),
                SetForegroundColor(color),
                Print(format!("[{:?}] ", v.tier)),
                ResetColor,
                Print(format!("{} (rule: {})\r\n", v.operation_kind, v.rule_id))
            )?;
        }

        if end < violations.len() {
            queue!(stdout, Print("   ...\r\n"))?;
        }

        queue!(stdout, Print("\r\n------------------------------------------------------------\r\n"))?;
        
        let active = &violations[selected];
        queue!(
            stdout,
            SetForegroundColor(Color::White),
            Print("Reason: "),
            ResetColor,
            Print(format!("{}\r\n", active.reason)),
            SetForegroundColor(Color::White),
            Print("Recipe: "),
            ResetColor,
            Print(format!("{}\r\n", active.recipe)),
        )?;
        
        if let Some(sql) = &active.sql {
            queue!(
                stdout,
                SetForegroundColor(Color::White),
                Print("\r\nSQL Context:\r\n"),
                SetForegroundColor(Color::DarkGrey),
                // Important: replace all \n inside the SQL with \r\n
                Print(format!("{}\r\n", sql.replace('\n', "\r\n"))),
                ResetColor,
            )?;
        }

        queue!(
            stdout,
            Print("\r\n[Up/Down] Navigate  |  [q/Esc] Quit\r\n")
        )?;

        stdout.flush()?;

        // Handle input
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up if selected > 0 => selected -= 1,
                    KeyCode::Down if selected < violations.len() - 1 => selected += 1,
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(stdout, cursor::Show, Clear(ClearType::All), cursor::MoveTo(0, 0))?;
    println!("Exited interactive mode.");
    
    Ok(())
}
