use crate::analysis::mutations::Mutation;
use crate::analysis::resolver::Resolver;
use crate::analysis::state::AnalysisState;
use crate::ast::visitor::AstVisitor;
use crate::engine::config::Config;
use crate::report::violations::{ReportFinding, SourceLocation, Violation};
use crate::rules::Rule;
use crate::rules::registry;
use squawk_syntax::{
    Parse, SyntaxKind,
    ast::{AstNode, SourceFile},
};
use std::collections::HashSet;

pub struct SafeMigrateEngine {
    config: Config,
    rules: Vec<Box<dyn Rule>>,
}

impl SafeMigrateEngine {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            rules: registry::build_primary_rules(),
        }
    }

    /// Returns primary rule IDs in evaluation order.
    pub fn primary_rule_ids(&self) -> Vec<&'static str> {
        registry::primary_rule_ids().collect()
    }

    pub fn analyze_chain(
        &self,
        files: &[(String, String)],
        state: &mut AnalysisState,
    ) -> Result<Vec<Violation>, Vec<String>> {
        let mut all_violations = Vec::new();
        for (filename, sql) in files {
            let violations = self.analyze_single_file(filename, sql, state)?;
            all_violations.extend(violations);
        }
        // Stable ordering keeps reports reproducible across files.
        all_violations.sort_by(|a, b| {
            a.tier
                .cmp(&b.tier)
                .then_with(|| match (&a.source_range, &b.source_range) {
                    (Some(ar), Some(br)) => ar
                        .start()
                        .cmp(&br.start())
                        .then_with(|| ar.end().cmp(&br.end())),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                })
                .then_with(|| a.object_name.cmp(&b.object_name))
                .then_with(|| a.rule_id.cmp(b.rule_id))
        });
        Ok(all_violations)
    }

    pub fn analyze(
        &self,
        sql: &str,
        state: &mut AnalysisState,
    ) -> Result<Vec<Violation>, Vec<String>> {
        self.analyze_chain(&[("<inline>".to_string(), sql.to_string())], state)
    }

    /// Analyze ordered files and retain reportable source locations for every
    /// finding. The original `analyze_chain` API remains available to callers
    /// that only need violations.
    pub fn analyze_chain_with_locations(
        &self,
        files: &[(String, String)],
        state: &mut AnalysisState,
    ) -> Result<Vec<ReportFinding>, Vec<String>> {
        let mut findings = Vec::new();

        for (file_index, (filename, sql)) in files.iter().enumerate() {
            let normalized_sql = Self::normalize_execute(sql);
            let parsed = SourceFile::parse(&normalized_sql);
            let statement_ranges: Vec<_> = parsed
                .tree()
                .stmts()
                .map(|statement| statement.syntax().text_range())
                .collect();
            let violations = self.analyze_parsed_file(filename, &normalized_sql, &parsed, state)?;
            findings.extend(
                violations
                    .into_iter()
                    .map(|violation| ReportFinding {
                        location: Self::source_location(
                            filename,
                            &normalized_sql,
                            violation.source_range,
                        ),
                        statement_index: violation.source_range.and_then(|range| {
                            statement_ranges
                                .iter()
                                .position(|statement| statement.contains_range(range))
                                .map(|index| index + 1)
                        }),
                        violation,
                    })
                    .map(|finding| (file_index, finding)),
            );
        }

        findings.sort_by(|(a_index, a), (b_index, b)| {
            a.violation
                .tier
                .cmp(&b.violation.tier)
                .then_with(|| a_index.cmp(b_index))
                .then_with(|| match (&a.location, &b.location) {
                    (Some(a_location), Some(b_location)) => a_location
                        .line
                        .cmp(&b_location.line)
                        .then_with(|| a_location.column.cmp(&b_location.column)),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                })
                .then_with(|| a.violation.object_name.cmp(&b.violation.object_name))
                .then_with(|| a.violation.rule_id.cmp(b.violation.rule_id))
        });

        Ok(findings.into_iter().map(|(_, finding)| finding).collect())
    }

    pub fn analyze_with_locations(
        &self,
        filename: String,
        sql: String,
        state: &mut AnalysisState,
    ) -> Result<Vec<ReportFinding>, Vec<String>> {
        self.analyze_chain_with_locations(&[(filename, sql)], state)
    }

    fn analyze_single_file(
        &self,
        filename: &str,
        sql: &str,
        state: &mut AnalysisState,
    ) -> Result<Vec<Violation>, Vec<String>> {
        let sql = Self::normalize_execute(sql);
        self.analyze_normalized_file(filename, &sql, state)
    }

    fn analyze_normalized_file(
        &self,
        filename: &str,
        sql: &str,
        state: &mut AnalysisState,
    ) -> Result<Vec<Violation>, Vec<String>> {
        let parsed = SourceFile::parse(sql);
        self.analyze_parsed_file(filename, sql, &parsed, state)
    }

    fn analyze_parsed_file(
        &self,
        _filename: &str,
        sql: &str,
        parsed: &Parse<SourceFile>,
        state: &mut AnalysisState,
    ) -> Result<Vec<Violation>, Vec<String>> {
        let errors: Vec<String> = parsed.errors().iter().map(|e| e.to_string()).collect();
        if !errors.is_empty() {
            return Err(errors);
        }

        let mut all_violations = Vec::new();
        let mut warned_keys = HashSet::new();

        let mut file_ignores = HashSet::new();
        for token in parsed
            .tree()
            .syntax()
            .descendants_with_tokens()
            .filter_map(|it| it.into_token())
            .filter(|token| token.kind() == SyntaxKind::COMMENT)
        {
            let mut dummy = HashSet::new();
            Self::parse_directives(token.text(), &mut file_ignores, &mut dummy);
        }

        for stmt in parsed.tree().stmts() {
            let mut stmt_ignores = HashSet::new();

            let mut prev = stmt.syntax().prev_sibling_or_token();
            while let Some(element) = prev {
                if element.as_node().is_some() {
                    break;
                }
                if let Some(token) = element.as_token()
                    && token.kind() == SyntaxKind::COMMENT
                {
                    let mut dummy = HashSet::new();
                    Self::parse_directives(token.text(), &mut dummy, &mut stmt_ignores);
                }
                prev = element.prev_sibling_or_token();
            }

            for token in stmt
                .syntax()
                .descendants_with_tokens()
                .filter_map(|it| it.into_token())
                .filter(|token| token.kind() == SyntaxKind::COMMENT)
            {
                let mut dummy = HashSet::new();
                Self::parse_directives(token.text(), &mut dummy, &mut stmt_ignores);
            }

            // Capture raw statement text for sql field on violations (strip leading comments)
            let stmt_text = Self::strip_sql_leading_comments(&stmt.syntax().text().to_string());

            // PostgreSQL executes a statement atomically. Keep both state
            // and diagnostics local until all resolved actions succeed so an
            // earlier action in a failed compound statement cannot leak
            // state, findings, or deduplication keys. A parsed statement
            // without a typed extractor is explicitly opaque: silently
            // ignoring it would claim exact confidence for later SQL.
            let statement_checkpoint = state.clone();
            let statement_confidence = state.local.confidence.clone();
            let mut statement_violations = Vec::new();
            let mut statement_warned_keys = HashSet::new();
            let mut mutations = match AstVisitor::extract(&stmt) {
                Some(fact) => Resolver::resolve(&fact, state),
                None => vec![Mutation::Opaque(
                    crate::analysis::mutations::OpaqueMutation::UnsupportedStatement,
                )],
            };
            if squawk_linter::analyze::possibly_slow_stmt(&stmt) {
                mutations.push(Mutation::CheckTimeouts);
            }

            for mutation in mutations {
                let pre_cascade = match &mutation {
                    Mutation::DropTable(d) if d.cascade => Some(state.get_cascade_closure(&d.id)),
                    _ => None,
                };

                let pre_state = state.capture_pre_state();
                let result = state.apply(&mutation, pre_cascade.as_ref());

                let statement_failed = matches!(
                    result,
                    crate::analysis::state::MutationResult::Conflict { .. }
                );
                if statement_failed {
                    let transaction_aborted = state.local.transaction_aborted;
                    *state = statement_checkpoint.clone();
                    if transaction_aborted && !state.local.transactions.is_empty() {
                        state.local.transaction_aborted = true;
                    }
                    statement_violations.clear();
                    statement_warned_keys.clear();
                }

                if result == crate::analysis::state::MutationResult::NotExecuted {
                    continue;
                }

                for rule in &self.rules {
                    if file_ignores.contains(rule.id())
                        || stmt_ignores.contains(rule.id())
                        || self.config.is_rule_disabled(rule.id())
                    {
                        continue;
                    }

                    let violations = rule.evaluate(
                        &mutation,
                        &result,
                        &pre_state,
                        state,
                        &self.config,
                        pre_cascade.as_ref(),
                    );

                    for v in violations {
                        if let Some(key) = &v.dedup_key
                            && (warned_keys.contains(key)
                                || !statement_warned_keys.insert(key.clone()))
                        {
                            continue;
                        }
                        let mut v = v;
                        if v.source_range.is_none() {
                            let start = stmt
                                .syntax()
                                .descendants_with_tokens()
                                .filter_map(|element| element.into_token())
                                .find(|token| {
                                    let text = token.text().trim();
                                    !text.is_empty()
                                        && !text.starts_with("--")
                                        && !text.starts_with("/*")
                                })
                                .map(|token| token.text_range().start())
                                .unwrap_or_else(|| stmt.syntax().text_range().start());
                            let end = stmt.syntax().text_range().end();
                            v.source_range = Some(rowan::TextRange::new(start, end));
                        }
                        if v.sql.is_none() {
                            if let Some(range) = v.source_range {
                                let start = usize::from(range.start());
                                let end = usize::from(range.end());
                                if start < sql.len() && end <= sql.len() {
                                    v.sql = Some(sql[start..end].trim().to_string());
                                } else {
                                    v.sql = Some(stmt_text.trim().to_string());
                                }
                            } else {
                                v.sql = Some(stmt_text.trim().to_string());
                            }
                        }
                        // A taint produced by this statement must not
                        // downgrade that same statement's findings.
                        if statement_confidence == crate::analysis::state::Confidence::Tainted
                            && v.tier == crate::report::violations::ViolationTier::Tier1
                        {
                            v.tier = crate::report::violations::ViolationTier::Tier2;
                        }
                        statement_violations.push(v);
                    }
                }

                if statement_failed {
                    break;
                }
            }

            warned_keys.extend(statement_warned_keys);
            all_violations.extend(statement_violations);
        }

        Ok(all_violations)
    }

    fn source_location(
        filename: &str,
        sql: &str,
        source_range: Option<rowan::TextRange>,
    ) -> Option<SourceLocation> {
        let start = usize::from(source_range?.start());
        if start > sql.len() || !sql.is_char_boundary(start) {
            return None;
        }

        let before = &sql[..start];
        let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let column = before
            .rsplit_once('\n')
            .map_or(before, |(_, final_line)| final_line)
            .chars()
            .count()
            + 1;
        Some(SourceLocation {
            file: filename.to_string(),
            line,
            column,
        })
    }

    /// Pre-process SQL to handle EXECUTE '...' which Squawk's parser does not
    /// recognize (top-level EXECUTE expects a prepared-statement name, not a
    /// string literal). Rewriting to DO lets the parser produce a proper
    /// DoBlock node. Keep the replacement byte-for-byte the same length so
    /// source ranges still point into the original migration text.
    fn normalize_execute(sql: &str) -> String {
        let mut out = String::with_capacity(sql.len());
        for line in sql.split_inclusive('\n') {
            let trimmed = line.trim_start();
            let bytes = trimmed.as_bytes();
            if bytes.len() > 9 && bytes[..9].eq_ignore_ascii_case(b"EXECUTE '") {
                let indent = &line[..line.len() - trimmed.len()];
                out.push_str(indent);
                out.push_str("DO      '");
                out.push_str(&trimmed[9..]);
            } else if bytes.len() > 10 && bytes[..10].eq_ignore_ascii_case(b"EXECUTE $$") {
                let indent = &line[..line.len() - trimmed.len()];
                out.push_str(indent);
                out.push_str("DO      $$");
                out.push_str(&trimmed[10..]);
            } else {
                out.push_str(line);
            }
        }
        out
    }

    fn parse_directives(
        text: &str,
        file_ignores: &mut HashSet<String>,
        stmt_ignores: &mut HashSet<String>,
    ) {
        let marker = "safe-migrate:";
        let mut pos = 0;

        while let Some(start) = text[pos..].find(marker) {
            let after = text[pos + start + marker.len()..].trim_start();

            if let Some(rest) = after.strip_prefix("ignore-file") {
                let rest = rest.trim_start();
                if let Some(inner) = rest
                    .strip_prefix('(')
                    .and_then(|s| s.find(')').map(|e| &s[..e]))
                {
                    file_ignores.insert(inner.trim().to_string());
                }
            } else if let Some(rest) = after.strip_prefix("ignore") {
                let rest = rest.trim_start();
                if let Some(inner) = rest
                    .strip_prefix('(')
                    .and_then(|s| s.find(')').map(|e| &s[..e]))
                {
                    stmt_ignores.insert(inner.trim().to_string());
                }
            }

            pos = pos + start + marker.len();
        }
    }

    fn strip_sql_leading_comments(s: &str) -> String {
        let mut pos = 0;
        let bytes = s.as_bytes();
        while pos < bytes.len() {
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos + 1 < bytes.len() && bytes[pos] == b'-' && bytes[pos + 1] == b'-' {
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
                continue;
            }
            if pos + 1 < bytes.len() && bytes[pos] == b'/' && bytes[pos + 1] == b'*' {
                pos += 2;
                while pos + 1 < bytes.len() && !(bytes[pos] == b'*' && bytes[pos + 1] == b'/') {
                    pos += 1;
                }
                if pos + 1 < bytes.len() {
                    pos += 2;
                }
                continue;
            }
            break;
        }
        s[pos..].to_string()
    }
}
