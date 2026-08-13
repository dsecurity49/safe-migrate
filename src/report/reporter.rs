// FILE: src/report/reporter.rs
use crate::analysis::state::Confidence;
use crate::report::violations::{ReportFinding, Violation, ViolationTier};
use crate::rules::destructive::IRREVERSIBLE_MIGRATION_RULE_ID;
use crate::rules::registry;
use comfy_table::Table;
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

    pub fn recommendation(&self, confidence: &Confidence) -> &'static str {
        if confidence == &Confidence::Tainted {
            return match self {
                Verdict::Halt => "do not deploy",
                Verdict::SafeWithRisk => {
                    "irreversible operations present and baseline evidence is uncertain — ensure backups exist and review before deploying"
                }
                _ => {
                    "no blocking finding, but baseline evidence is uncertain — review before deploying"
                }
            };
        }
        match self {
            Verdict::Halt => "do not deploy",
            Verdict::Cautious => "review warnings before deploy",
            Verdict::SafeWithRisk => "irreversible operations present — ensure backups exist",
            Verdict::Safe => "no modeled blocking findings",
        }
    }
}

/// Compute the overall verdict from a set of violations.
pub fn compute_verdict(violations: &[Violation]) -> Verdict {
    let has_tier1 = violations.iter().any(|v| v.tier == ViolationTier::Tier1);
    let has_tier2 = violations.iter().any(|v| v.tier == ViolationTier::Tier2);
    let has_irreversible_tier3 = violations
        .iter()
        .any(|v| v.tier == ViolationTier::Tier3 && v.rule_id == IRREVERSIBLE_MIGRATION_RULE_ID);

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
pub(crate) fn tier_label_colored(tier: &ViolationTier) -> String {
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

pub struct Reporter;

impl Reporter {
    pub const JSON_SCHEMA_VERSION: u32 = 1;

    pub fn json_report(violations: &[Violation], confidence: &Confidence) -> serde_json::Value {
        let verdict = compute_verdict(violations);
        let tier1 = violations
            .iter()
            .filter(|violation| violation.tier == ViolationTier::Tier1)
            .count();
        let tier2 = violations
            .iter()
            .filter(|violation| violation.tier == ViolationTier::Tier2)
            .count();
        let tier3 = violations
            .iter()
            .filter(|violation| violation.tier == ViolationTier::Tier3)
            .count();
        serde_json::json!({
            "schema_version": Self::JSON_SCHEMA_VERSION,
            "confidence": match confidence {
                Confidence::Exact => "Exact",
                Confidence::Tainted => "Tainted",
            },
            "verdict": verdict.label(),
            "summary": {
                "total": violations.len(),
                "tier1": tier1,
                "tier2": tier2,
                "tier3": tier3,
            },
            "violations": violations,
        })
    }

    /// Additive JSON rendering that includes file/line locations when analysis
    /// was invoked with source-aware reporting.
    pub fn json_report_with_locations(
        findings: &[ReportFinding],
        confidence: &Confidence,
    ) -> serde_json::Value {
        let violations: Vec<_> = findings
            .iter()
            .map(|finding| finding.violation.clone())
            .collect();
        let mut report = Self::json_report(&violations, confidence);
        report["violations"] = serde_json::Value::Array(
            findings
                .iter()
                .map(|finding| {
                    let mut value = serde_json::to_value(finding)
                        .expect("Report findings must always serialize to JSON");
                    if let Some(descriptor) = registry::find_primary_rule(finding.violation.rule_id)
                        && let Some(object) = value.as_object_mut()
                    {
                        object.insert("rule_title".into(), descriptor.title.into());
                        object.insert("rule_summary".into(), descriptor.summary.into());
                        object.insert("impact".into(), descriptor.impact.into());
                    }
                    value
                })
                .collect(),
        );
        report
    }

    /// Deterministic Markdown rendering for pull-request artifacts. It uses
    /// the same verdict, confidence, tier, and finding data as JSON output.
    pub fn markdown_report(findings: &[ReportFinding], confidence: &Confidence) -> String {
        let violations: Vec<_> = findings
            .iter()
            .map(|finding| finding.violation.clone())
            .collect();
        let verdict = compute_verdict(&violations);
        let confidence = match confidence {
            Confidence::Exact => "Exact",
            Confidence::Tainted => "Tainted",
        };
        let tier1 = violations
            .iter()
            .filter(|violation| violation.tier == ViolationTier::Tier1)
            .count();
        let tier2 = violations
            .iter()
            .filter(|violation| violation.tier == ViolationTier::Tier2)
            .count();
        let tier3 = violations
            .iter()
            .filter(|violation| violation.tier == ViolationTier::Tier3)
            .count();

        let mut output = format!(
            "# safe-migrate report\n\n**Verdict:** {}  \n**Confidence:** {}\n\n| Severity | Findings |\n| --- | ---: |\n| HALT (Tier 1) | {} |\n| WARN (Tier 2) | {} |\n| SAFE (Tier 3) | {} |\n",
            verdict.label(),
            confidence,
            tier1,
            tier2,
            tier3
        );

        if findings.is_empty() {
            output.push_str("\nNo findings detected.\n");
            return output;
        }

        output.push_str("\n## Findings\n");
        for finding in findings {
            let violation = &finding.violation;
            output.push_str(&format!(
                "\n### {} — {} (`{}`)\n\n",
                markdown_tier_label(&violation.tier),
                registry::find_primary_rule(violation.rule_id)
                    .map(|descriptor| descriptor.title)
                    .unwrap_or(violation.rule_id),
                markdown_code(violation.rule_id)
            ));
            if let Some(descriptor) = registry::find_primary_rule(violation.rule_id) {
                output.push_str(&format!(
                    "**Impact:** {}  \n**Rule summary:** {}  \n",
                    markdown_escape(descriptor.impact),
                    markdown_escape(descriptor.summary)
                ));
            }
            if let Some(location) = &finding.location {
                output.push_str(&format!(
                    "**Location:** `{}:{}:{}`  \n",
                    markdown_code(&location.file),
                    location.line,
                    location.column
                ));
            }
            if let Some(statement_index) = finding.statement_index {
                output.push_str(&format!("**Statement:** {}  \n", statement_index));
            }
            output.push_str(&format!(
                "**Object:** {} {}  \n**Reason:** {}  \n**Recommendation:** {}\n",
                violation.object_kind,
                markdown_escape(&violation.object_name),
                markdown_escape(&violation.reason),
                markdown_escape(
                    &violation
                        .recipe
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            ));
            if let Some(sql) = &violation.sql
                && !sql.trim().is_empty()
            {
                output.push_str(&markdown_sql_block(sql.trim()));
            }
        }
        output
    }

    pub fn should_halt(violations: &[Violation]) -> bool {
        compute_verdict(violations) == Verdict::Halt
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

        // Header box using comfy-table
        let mut header_table = Table::new();
        header_table.load_preset(comfy_table::presets::UTF8_BORDERS_ONLY);
        header_table.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);
        header_table.set_width(width as u16);
        header_table.set_header(vec!["safe-migrate lint"]);
        header_table.add_row(vec![format!(
            "Verdict: {}   Confidence: {}",
            verdict.label(),
            conf_str
        )]);
        header_table.add_row(vec![format!(
            "HALT: {}   WARN: {}   SAFE: {}",
            tier1, tier2, tier3
        )]);
        println!("{}", header_table);

        if violations.is_empty() {
            println!("\n  No violations detected.\n");
            return false;
        }

        println!();

        // Separator width: 80-85% of terminal width
        let sep_width = (width as f32 * 0.82) as usize;

        // Group violations by sql key (same sql text + same object_name = same statement)
        // Each group is (primary_idx, Vec<secondary_idxs>)
        let mut groups: Vec<(usize, Vec<usize>)> = Vec::new();
        let mut sql_to_group_idx: std::collections::HashMap<(&str, &str), usize> =
            std::collections::HashMap::new();

        for (i, v) in violations.iter().enumerate() {
            if let Some(sql) = &v.sql {
                let key = (sql.as_str(), v.object_name.as_str());
                if let Some(&gi) = sql_to_group_idx.get(&key) {
                    groups[gi].1.push(i);
                    continue;
                }

                let new_gi = groups.len();
                groups.push((i, Vec::new()));
                sql_to_group_idx.insert(key, new_gi);
            } else {
                // If sql is None, it never groups
                groups.push((i, Vec::new()));
            }
        }

        for (gi, (primary_idx, secondary_idxs)) in groups.iter().enumerate() {
            let v = &violations[*primary_idx];
            let tier_str = tier_label_colored(&v.tier);

            let descriptor = registry::find_primary_rule(v.rule_id);
            let rule_label = descriptor
                .map(|descriptor| format!("{} ({})", descriptor.title, v.rule_id))
                .unwrap_or_else(|| v.rule_id.to_string());
            println!(" [{}] {}", tier_str, rule_label);
            if let Some(descriptor) = descriptor {
                println!("   impact : {}", descriptor.impact);
                println!("   summary: {}", descriptor.summary);
            }

            let display_name = match &v.object_kind {
                crate::report::violations::ObjectKind::Database
                | crate::report::violations::ObjectKind::Role
                | crate::report::violations::ObjectKind::Publication
                | crate::report::violations::ObjectKind::Subscription => {
                    let step1 = if let Some(idx) = v.object_name.find('.') {
                        &v.object_name[idx + 1..]
                    } else {
                        &v.object_name
                    };
                    step1
                        .strip_suffix(" (inferred)")
                        .unwrap_or(step1)
                        .to_string()
                }
                _ => v.object_name.clone(),
            };

            if v.object_kind == crate::report::violations::ObjectKind::Unknown {
                println!("   object : {}", display_name);
            } else {
                println!("   object : {} {}", v.object_kind, display_name);
            }

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
                    "   also   : [{}] {}",
                    tier_label_colored(&sv.tier),
                    sv.rule_id
                );
            }

            if gi < groups.len() - 1 {
                println!();
                println!(" {}", "─".repeat(sep_width));
                println!();
            }
        }

        println!();

        // Summary box using comfy-table
        let mut summary_table = Table::new();
        summary_table.load_preset(comfy_table::presets::UTF8_BORDERS_ONLY);
        summary_table.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);
        summary_table.set_width(width as u16);
        summary_table.set_header(vec!["SUMMARY", ""]);
        summary_table.add_row(vec!["Verdict", &format!(": {}", verdict.label())]);
        summary_table.add_row(vec![
            "Recommendation",
            &format!(": {}", verdict.recommendation(confidence)),
        ]);
        summary_table.add_row(vec!["HALT (Tier 1)", &format!(": {}", tier1)]);
        summary_table.add_row(vec!["WARN (Tier 2)", &format!(": {}", tier2)]);
        summary_table.add_row(vec!["SAFE (Tier 3)", &format!(": {}", tier3)]);
        println!("{}", summary_table);

        Self::should_halt(violations)
    }
}

fn markdown_tier_label(tier: &ViolationTier) -> &'static str {
    match tier {
        ViolationTier::Tier1 => "HALT",
        ViolationTier::Tier2 => "WARN",
        ViolationTier::Tier3 => "SAFE",
    }
}

fn markdown_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('|', "\\|")
}

fn markdown_code(value: &str) -> String {
    value.replace('`', "'")
}

fn markdown_sql_block(sql: &str) -> String {
    let longest_backtick_run = sql
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(longest_backtick_run.max(2) + 1);
    format!("\n{fence}sql\n{sql}\n{fence}\n")
}
