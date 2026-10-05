use crate::_internal::analysis::evidence::EvidenceRecord;
use crate::_internal::analysis::outcome::AnalysisOutcome;
use crate::_internal::analysis::state::Confidence;
use crate::_internal::report::violations::{ReportFinding, Violation, ViolationTier};
use crate::_internal::rules::destructive::IRREVERSIBLE_MIGRATION_RULE_ID;
use crate::_internal::rules::registry;
use crate::api::Certainty;
use comfy_table::Table;
use owo_colors::{OwoColorize, Style};
use std::io::IsTerminal;

/// Four-way verdict classification based on violation tiers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Halt,         // any Tier 1
    Cautious,     // Tier 2 present, no Tier 1
    SafeWithRisk, // Tier 3 irreversible present, no Tier 1 or 2
    Safe,         // all Tier 3 non-irreversible or no findings
}

impl Verdict {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Verdict::Halt => "HALT",
            Verdict::Cautious => "CAUTIOUS",
            Verdict::SafeWithRisk => "SAFE WITH RISK",
            Verdict::Safe => "SAFE",
        }
    }

    pub(crate) fn recommendation(&self, confidence: &Confidence) -> &'static str {
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
pub(crate) fn compute_verdict(violations: &[Violation]) -> Verdict {
    compute_verdict_with(violations, &[])
}

/// As [`compute_verdict`], but a verdict may not read SAFE while a
/// blocking-capable rule did not run: SAFE must mean every check happened.
pub(crate) fn compute_verdict_with(
    violations: &[Violation],
    not_evaluated: &[crate::_internal::report::violations::NotEvaluated],
) -> Verdict {
    let verdict = verdict_from_violations(violations);
    let blocked_by_gap = verdict == Verdict::Safe
        && not_evaluated
            .iter()
            .any(|entry| entry.tier == ViolationTier::Tier1);
    if blocked_by_gap {
        Verdict::Cautious
    } else {
        verdict
    }
}

fn verdict_from_violations(violations: &[Violation]) -> Verdict {
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

/// Whether the human report may emit ANSI styling.
///
/// Honours the `NO_COLOR` convention and never styles output that is not going
/// to a terminal, so redirected or piped reports stay free of escape codes.
pub(crate) fn color_enabled(no_color_env: bool, stdout_is_terminal: bool) -> bool {
    !no_color_env && stdout_is_terminal
}

fn no_color() -> bool {
    !color_enabled(
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    )
}

pub(super) fn tier_label_with_color(tier: &ViolationTier, color: bool) -> String {
    let label = match tier {
        ViolationTier::Tier1 => "HALT",
        ViolationTier::Tier2 => "WARN",
        ViolationTier::Tier3 => "SAFE",
    };
    if color {
        match tier {
            ViolationTier::Tier1 => label.style(Style::new().red().bold()).to_string(),
            ViolationTier::Tier2 => label.style(Style::new().yellow().bold()).to_string(),
            ViolationTier::Tier3 => label.style(Style::new().green().bold()).to_string(),
        }
    } else {
        label.to_string()
    }
}

fn terminal_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(80)
        .max(60)
}

/// Rule titles for exactly the rules a report cites. Kept out of each finding
/// because it is identical for every occurrence of a rule.
fn rules_catalogue<'a>(rule_ids: impl Iterator<Item = &'a str>) -> serde_json::Value {
    let mut catalogue = serde_json::Map::new();
    for rule_id in rule_ids {
        if catalogue.contains_key(rule_id) {
            continue;
        }
        if let Some(descriptor) = registry::find_primary_rule(rule_id) {
            catalogue.insert(rule_id.to_string(), serde_json::json!(descriptor.title));
        }
    }
    serde_json::Value::Object(catalogue)
}

pub(crate) struct Reporter;

impl Reporter {
    // v3 adds the top-level `not_evaluated` object, whose entries carry an
    // optional `missing_schemas` list.
    pub(crate) const JSON_SCHEMA_VERSION: u32 = 3;

    pub(crate) fn json_report(
        violations: &[Violation],
        confidence: &Confidence,
    ) -> serde_json::Value {
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
            "evidence": [],
            "rules": rules_catalogue(violations.iter().map(|violation| violation.rule_id)),
            "violations": violations,
        })
    }

    /// Serialize a complete immutable analysis outcome. Schema v2 adds stable
    /// evidence alongside the existing finding contract.
    pub(crate) fn json_outcome_with_locations(
        outcome: &AnalysisOutcome<ReportFinding>,
    ) -> serde_json::Value {
        let mut report = Self::json_report_with_locations(&outcome.findings, &outcome.confidence);
        report["evidence"] = serde_json::to_value(&outcome.evidence)
            .expect("analysis evidence is always serializable");
        report
    }

    /// Additive JSON rendering that includes file/line locations when analysis
    /// was invoked with source-aware reporting.
    pub(crate) fn json_report_with_locations(
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
                    serde_json::to_value(finding).unwrap_or_else(|error| {
                        serde_json::json!({
                            "rule_id": finding.violation.rule_id,
                            "message": "Failed to serialize report finding",
                            "serialization_error": error.to_string(),
                        })
                    })
                })
                .collect(),
        );
        report["rules"] = rules_catalogue(findings.iter().map(|finding| finding.violation.rule_id));
        report
    }

    /// Deterministic Markdown rendering for pull-request artifacts. It uses
    /// the same verdict, confidence, tier, and finding data as JSON output.
    pub(crate) fn markdown_report(
        findings: &[ReportFinding],
        confidence: &Confidence,
        not_evaluated: &[crate::_internal::report::violations::NotEvaluated],
    ) -> String {
        let violations: Vec<_> = findings
            .iter()
            .map(|finding| finding.violation.clone())
            .collect();
        let verdict = compute_verdict_with(&violations, not_evaluated);
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
            if finding.certainty != Certainty::Exact {
                output.push_str(&format!(
                    "**Certainty:** {}  \n",
                    markdown_escape(&finding.certainty.to_string())
                ));
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
        output.push_str(&Self::markdown_rules_catalogue(
            findings.iter().map(|finding| finding.violation.rule_id),
        ));
        output
    }

    /// Rule titles for the cited rules, listed once rather than under every
    /// occurrence of the rule.
    fn markdown_rules_catalogue<'a>(rule_ids: impl Iterator<Item = &'a str>) -> String {
        let mut seen = std::collections::BTreeSet::new();
        let mut output = String::new();
        for rule_id in rule_ids {
            if !seen.insert(rule_id) {
                continue;
            }
            let Some(descriptor) = registry::find_primary_rule(rule_id) else {
                continue;
            };
            output.push_str(&format!(
                "- `{}` — {}\n",
                markdown_code(rule_id),
                markdown_escape(descriptor.title)
            ));
        }
        if output.is_empty() {
            return output;
        }
        format!("\n## Rules\n\n{output}")
    }

    /// Render findings and structured conservative-analysis evidence.
    pub(crate) fn markdown_outcome(
        outcome: &AnalysisOutcome<ReportFinding>,
        not_evaluated: &[crate::_internal::report::violations::NotEvaluated],
    ) -> String {
        let mut output =
            Self::markdown_report(&outcome.findings, &outcome.confidence, not_evaluated);
        append_markdown_evidence(&mut output, &outcome.evidence);
        append_markdown_not_evaluated(&mut output, not_evaluated);
        output
    }

    pub(crate) fn should_halt(violations: &[Violation]) -> bool {
        compute_verdict(violations) == Verdict::Halt
    }

    pub(crate) fn print_report(
        violations: &[Violation],
        confidence: &Confidence,
        not_evaluated: &[crate::_internal::report::violations::NotEvaluated],
    ) -> bool {
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

        let verdict = compute_verdict_with(violations, not_evaluated);
        let conf_str = match confidence {
            Confidence::Exact => "Exact",
            Confidence::Tainted => "Tainted",
        };

        let width = terminal_width();

        // Three borderless columns so the fields spread evenly instead of
        // bunching left; UTF8_BORDERS_ONLY keeps the edges clean.
        let mut header_table = Table::new();
        header_table.load_preset(comfy_table::presets::UTF8_BORDERS_ONLY);
        header_table.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);
        header_table.set_width(width as u16);
        header_table.set_header(vec!["safe-migrate lint", "", ""]);
        header_table.add_row(vec![
            format!("Verdict: {}", verdict.label()),
            format!("Confidence: {}", conf_str),
            String::new(),
        ]);
        header_table.add_row(vec![
            format!("HALT: {}", tier1),
            format!("WARN: {}", tier2),
            format!("SAFE: {}", tier3),
        ]);
        println!("{}", header_table);

        if violations.is_empty() {
            println!("\n  No violations detected.\n");
            return false;
        }

        println!();

        let sep_width = (width as f32 * 0.82) as usize;

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
                groups.push((i, Vec::new()));
            }
        }

        // Resolve styling once; asking the terminal per finding would repeat the
        // syscall for every row.
        let color = !no_color();

        for (gi, (primary_idx, secondary_idxs)) in groups.iter().enumerate() {
            let v = &violations[*primary_idx];
            let tier_str = tier_label_with_color(&v.tier, color);

            let descriptor = registry::find_primary_rule(v.rule_id);
            let rule_label = descriptor
                .map(|descriptor| format!("{} ({})", descriptor.title, v.rule_id))
                .unwrap_or_else(|| v.rule_id.to_string());
            println!(" [{}] {}", tier_str, rule_label);

            let display_name = match &v.object_kind {
                crate::_internal::report::violations::ObjectKind::Database
                | crate::_internal::report::violations::ObjectKind::Role
                | crate::_internal::report::violations::ObjectKind::Publication => {
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

            if v.object_kind == crate::_internal::report::violations::ObjectKind::Unknown {
                println!("   object : {}", terminal_inline(&display_name));
            } else {
                println!(
                    "   object : {} {}",
                    v.object_kind,
                    terminal_inline(&display_name)
                );
            }

            println!("   reason : {}", terminal_inline(&v.reason));

            let clean_recipe = v
                .recipe
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            println!("   recipe : {}", terminal_inline(&clean_recipe));

            if let Some(sql) = &v.sql {
                let sql_trimmed = sql.trim();
                if !sql_trimmed.is_empty() {
                    println!("   sql    : {}", terminal_block(sql_trimmed));
                }
            }

            for &sec_idx in secondary_idxs {
                let sv = &violations[sec_idx];
                println!(
                    "   also   : [{}] {}",
                    tier_label_with_color(&sv.tier, color),
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

    /// Print findings and a compact, deterministic evidence summary.
    pub(crate) fn print_outcome(
        outcome: &AnalysisOutcome<ReportFinding>,
        not_evaluated: &[crate::_internal::report::violations::NotEvaluated],
    ) -> bool {
        let violations: Vec<_> = outcome
            .findings
            .iter()
            .map(|finding| finding.violation.clone())
            .collect();
        let should_halt = Self::print_report(&violations, &outcome.confidence, not_evaluated);
        if !outcome.evidence.is_empty() {
            println!("Analysis evidence:");
            for evidence in &outcome.evidence {
                let location = evidence
                    .location
                    .as_ref()
                    .map_or_else(String::new, |location| {
                        format!(
                            " ({} statement {})",
                            terminal_inline(&location.file),
                            location.statement_index
                        )
                    });
                println!("  - {}{}", terminal_inline(evidence.summary), location);
            }
            println!();
        }
        should_halt
    }
}

fn append_markdown_not_evaluated(
    output: &mut String,
    not_evaluated: &[crate::_internal::report::violations::NotEvaluated],
) {
    if not_evaluated.is_empty() {
        return;
    }
    output.push_str("\n## Not evaluated\n\n");
    output.push_str(
        "These checks did not run because the required evidence was unavailable.\n\n\
         | Rule | Tier | Cause | Remedy |\n| --- | --- | --- | --- |\n",
    );
    for entry in not_evaluated {
        output.push_str(&format!(
            "| `{}` | {:?} | `{}` | {} |\n",
            entry.rule_id,
            entry.tier,
            entry.cause.as_str(),
            markdown_escape(&entry.recipe)
        ));
    }
}

fn append_markdown_evidence(output: &mut String, evidence: &[EvidenceRecord]) {
    if evidence.is_empty() {
        return;
    }
    output.push_str("\n## Analysis evidence\n");
    for record in evidence {
        output.push_str(&format!(
            "\n- `{}`: {}",
            record.code.as_str(),
            record.summary
        ));
        if let Some(location) = &record.location {
            output.push_str(&format!(
                " ({} statement {})",
                markdown_code(&location.file),
                location.statement_index
            ));
        }
    }
    output.push('\n');
}

fn markdown_tier_label(tier: &ViolationTier) -> &'static str {
    match tier {
        ViolationTier::Tier1 => "HALT",
        ViolationTier::Tier2 => "WARN",
        ViolationTier::Tier3 => "SAFE",
    }
}

fn markdown_escape(value: &str) -> String {
    markdown_inline_text(value)
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('<', "\\<")
        .replace('>', "\\>")
}

fn markdown_code(value: &str) -> String {
    markdown_inline_text(value).replace('`', "'")
}

fn markdown_inline_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\r' | '\n' => output.push(' '),
            character if character.is_control() => output.extend(character.escape_default()),
            character => output.push(character),
        }
    }
    output
}

fn markdown_sql_block(sql: &str) -> String {
    let sql = markdown_block_text(sql);
    let longest_backtick_run = sql
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(longest_backtick_run.max(2) + 1);
    format!("\n{fence}sql\n{sql}\n{fence}\n")
}

fn markdown_block_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\n' | '\t') {
            output.push(character);
        } else if character.is_control() {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}

pub(super) fn terminal_inline(value: &str) -> String {
    terminal_text(value, false)
}

pub(super) fn terminal_block(value: &str) -> String {
    terminal_text(value, true)
}

fn terminal_text(value: &str, preserve_layout: bool) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if preserve_layout && matches!(character, '\n' | '\t') {
            output.push(character);
        } else if character.is_control() {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}
