use crate::analysis::state::Confidence;
use crate::report::violations::Violation;
use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind},
    execute, queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{
        Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use std::io::{IsTerminal, Write, stdin, stdout};
use terminal_size::{Height, Width, terminal_size};

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = stdout();
        let _ = execute!(
            stdout,
            cursor::Show,
            Clear(ClearType::All),
            LeaveAlternateScreen,
            cursor::MoveTo(0, 0)
        );
    }
}

pub fn run_interactive(violations: &[Violation], confidence: &Confidence) -> Result<()> {
    if violations.is_empty() {
        println!("No violations found!");
        return Ok(());
    }

    if !stdin().is_terminal() || !stdout().is_terminal() {
        anyhow::bail!(
            "Interactive mode requires a terminal connected to standard input and output"
        );
    }

    enable_raw_mode()?;
    let _guard = TerminalGuard;

    let mut stdout = stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        cursor::Hide,
        Clear(ClearType::All),
        cursor::MoveTo(0, 0)
    )?;

    let mut selected: usize = 0;

    loop {
        queue!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0))?;
        queue!(
            stdout,
            SetForegroundColor(Color::Cyan),
            Print(format!(
                "Safe-Migrate Interactive Viewer ({} violations) [Confidence: {:?}]\r\n\r\n",
                violations.len(),
                confidence
            )),
            ResetColor,
        )?;

        let (_w, Height(h)) = terminal_size().unwrap_or((Width(80), Height(24)));
        // Reserve space for wrapped details without scrolling the alternate screen.
        let window_size = (h.saturating_sub(18) as usize).max(3);

        let start = selected.saturating_sub(window_size / 2);
        let end = std::cmp::min(start + window_size, violations.len());

        if start > 0 {
            queue!(stdout, Print("   ...\r\n"))?;
        }

        for (i, v) in violations.iter().enumerate().take(end).skip(start) {
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

        queue!(
            stdout,
            Print("\r\n------------------------------------------------------------\r\n")
        )?;

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
            // Bound detail height so navigation remains visible.
            let mut sql_lines: Vec<&str> = sql.lines().collect();
            let mut truncated = false;
            if sql_lines.len() > 5 {
                sql_lines.truncate(5);
                truncated = true;
            }

            queue!(
                stdout,
                SetForegroundColor(Color::White),
                Print("\r\nSQL Context:\r\n"),
                SetForegroundColor(Color::DarkGrey),
                // Raw terminal output uses CRLF line endings.
                Print(format!("{}\r\n", sql_lines.join("\r\n"))),
            )?;

            if truncated {
                queue!(stdout, Print("... (truncated)\r\n"))?;
            }
            queue!(stdout, ResetColor)?;
        }

        queue!(stdout, Print("\r\n[Up/Down] Navigate  |  [q/Esc] Quit\r\n"))?;

        stdout.flush()?;

        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Up if selected > 0 => selected -= 1,
                KeyCode::Down if selected < violations.len() - 1 => selected += 1,
                _ => {}
            }
        }
    }

    drop(_guard);
    println!("Exited interactive mode.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};

    #[test]
    fn interactive_mode_explains_when_no_terminal_is_available() {
        let violation = Violation {
            source_range: None,
            rule_id: "test-rule",
            operation_kind: OperationKind::Other("test".to_string()),
            object_kind: ObjectKind::Unknown,
            object_name: "test".to_string(),
            tier: ViolationTier::Tier3,
            reason: "test".to_string(),
            recipe: "test",
            dedup_key: None,
            sql: None,
            fk_dependency_related: false,
        };

        let error = run_interactive(&[violation], &Confidence::Exact).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires a terminal connected to standard input and output")
        );
    }
}
