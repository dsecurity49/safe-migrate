// FILE: src/report/reporter.rs
use crate::analysis::state::Confidence;
use crate::report::violations::{Violation, ViolationTier};
use owo_colors::{OwoColorize, Style};

/// Four-way verdict classification based on violation tiers.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Halt,         // any Tier 1
    Cautious,     // Tier 2 present, no Tier 1
    SafeWithRisk, // Tier 3 irreversible present, no Tier 1 or 2
    Safe,         // all Tier 3 non-irreversible or no findings
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Halt => "HALT",
            Verdict::Cautious => "CAUTIOUS",
            Verdict::SafeWithRisk => "SAFE WITH RISK",
            Verdict::Safe => "SAFE",
        }
    }

    pub fn recommendation(&self) -> &'static str {
        match self {
            Verdict::Halt => "do not deploy",
            Verdict::Cautious => "review warnings before deploy",
            Verdict::SafeWithRisk => "irreversible operations present — ensure backups exist",
            Verdict::Safe => "safe to deploy",
        }
    }
}

/// Compute the overall verdict from a set of violations.
pub fn compute_verdict(violations: &[Violation]) -> Verdict {
    let has_tier1 = violations.iter().any(|v| v.tier == ViolationTier::Tier1);
    let has_tier2 = violations.iter().any(|v| v.tier == ViolationTier::Tier2);
    let has_irreversible_tier3 = violations.iter().any(|v| {
        v.tier == ViolationTier::Tier3 && v.rule_id == "irreversible-migration"
    });

    match (has_tier1, has_tier2, has_irreversible_tier3) {
        (true, _, _) => Verdict::Halt,
        (false, true, _) => Verdict::Cautious,
        (false, false, true) => Verdict::SafeWithRisk,
        (false, false, false) => Verdict::Safe,
    }
}

fn no_color() -> bool {
    std::env::var("NO_COLOR").is_ok()
}

fn tier_label_colored(tier: &ViolationTier) -> String {
    let label = match tier {
        ViolationTier::Tier1 => "HALT",
        ViolationTier::Tier2 => "WARN",
        ViolationTier::Tier3 => "SAFE",
    };
    if no_color() {
        label.to_string()
    } else {
        match tier {
            ViolationTier::Tier1 => label.style(Style::new().red().bold()).to_string(),
            ViolationTier::Tier2 => label.style(Style::new().yellow().bold()).to_string(),
            ViolationTier::Tier3 => label.style(Style::new().green().bold()).to_string(),
        }
    }
}

fn terminal_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(80)
        .max(60)
}

/// Build a fixed-width box border of exactly `width` chars (including corners).
fn hline(width: usize) -> String {
    "─".repeat(width.saturating_sub(2))
}

/// Pad a string to fit inside a box of `width` chars (including borders and 1 space each side).
fn box_line(content: &str, width: usize) -> String {
    let inner = width.saturating_sub(4); // 2 for borders + 2 for spaces
    format!("│ {:<inner$} │", &content[..content.len().min(inner)], inner = inner)
}

pub struct Reporter;

impl Reporter {
    pub fn print_json_report(violations: &[Violation], confidence: &Confidence) {
        let verdict = compute_verdict(violations);
        let output = serde_json::json!({
            "confidence": match confidence {
                Confidence::Exact => "Exact",
                Confidence::Tainted => "Tainted",
            },
            "verdict": verdict.label(),
            "violations": violations,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    }

    pub fn print_report(violations: &[Violation], confidence: &Confidence) -> bool {
        let mut tier1 = 0usize;
        let mut tier2 = 0usize;
        let mut tier3 = 0usize;

        for v in violations {
            match v.tier {
                ViolationTier::Tier1 => tier1 += 1,
                ViolationTier::Tier2 => tier2 += 1,
                ViolationTier::Tier3 => tier3 += 1,
            }
        }

        let verdict = compute_verdict(violations);
        let conf_str = match confidence {
            Confidence::Exact => "Exact",
            Confidence::Tainted => "Tainted",
        };

        let width = terminal_width();
        let border = hline(width);

        // Header box
        println!("┌{}┐", border);
        println!("{}", box_line("safe-migrate lint", width));
        let verdict_line = format!(
            "Verdict: {:<16} Confidence: {:<13}",
            verdict.label(),
            conf_str
        );
        println!("{}", box_line(&verdict_line, width));
        let counts_line = format!("HALT: {:<6} WARN: {:<6} SAFE: {:<6}", tier1, tier2, tier3);
        println!("{}", box_line(&counts_line, width));
        println!("└{}┘", border);

        if violations.is_empty() {
            println!("\n  No violations detected.\n");
            return false;
        }

        println!();

        // Separator width: ~77% of terminal width
        let sep_width = (width as f32 * 0.77) as usize;

        // Group violations by sql key (same sql text + same object_name = same statement)
        // Each group is (primary_idx, Vec<secondary_idxs>)
        let mut groups: Vec<(usize, Vec<usize>)> = Vec::new();
        let mut used = vec![false; violations.len()];

        for i in 0..violations.len() {
            if used[i] {
                continue;
            }
            used[i] = true;
            let mut secondaries = Vec::new();
            // Find other violations with identical sql (if sql is Some)
            if let Some(sql_i) = &violations[i].sql {
                for j in (i + 1)..violations.len() {
                    if !used[j] {
                        if let Some(sql_j) = &violations[j].sql {
                            if sql_i == sql_j
                                && violations[j].object_name == violations[i].object_name
                            {
                                used[j] = true;
                                secondaries.push(j);
                            }
                        }
                    }
                }
            }
            groups.push((i, secondaries));
        }

        for (gi, (primary_idx, secondary_idxs)) in groups.iter().enumerate() {
            let v = &violations[*primary_idx];
            let tier_str = tier_label_colored(&v.tier);

            println!(" [{}] {}", tier_str, v.rule_id);
            println!("   object : {} {}", v.object_kind, v.object_name);
            println!("   reason : {}", v.reason);

            // recipe: clean up multi-line strings
            let clean_recipe = v
                .recipe
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            println!("   recipe : {}", clean_recipe);

            if let Some(sql) = &v.sql {
                let sql_trimmed = sql.trim();
                if !sql_trimmed.is_empty() {
                    println!("   sql    : {}", sql_trimmed);
                }
            }

            // Print 'also :' for secondary violations on same statement
            for &sec_idx in secondary_idxs {
                let sv = &violations[sec_idx];
                println!(
                    "   also   : [{}] {} — {}",
                    tier_label_colored(&sv.tier),
                    sv.rule_id,
                    sv.reason
                );
            }

            if gi < groups.len() - 1 {
                println!();
                println!(" {}", "─".repeat(sep_width));
                println!();
            }
        }

        println!();

        // Summary box
        let sum_label = "SUMMARY";
        let inner = width
            .saturating_sub(4)
            .saturating_sub(sum_label.len() + 4);
        let pad_left = inner / 2;
        let pad_right = inner.saturating_sub(pad_left);
        println!(
            "┌{}─ {} ─{}┐",
            "─".repeat(pad_left),
            sum_label,
            "─".repeat(pad_right)
        );
        let val_width = width.saturating_sub(22);
        println!("│ Verdict        : {:<val_width$} │", verdict.label(), val_width = val_width);
        println!(
            "│ Recommendation : {:<val_width$} │",
            verdict.recommendation(),
            val_width = val_width
        );
        println!("│ HALT (Tier 1)  : {:<val_width$} │", tier1, val_width = val_width);
        println!("│ WARN (Tier 2)  : {:<val_width$} │", tier2, val_width = val_width);
        println!("│ SAFE (Tier 3)  : {:<val_width$} │", tier3, val_width = val_width);
        println!("└{}┘", border);

        tier1 > 0
    }
}
