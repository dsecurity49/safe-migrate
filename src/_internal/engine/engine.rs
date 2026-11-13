use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceLocation, EvidenceScope};
use crate::_internal::analysis::mutations::Mutation;
use crate::_internal::analysis::outcome::AnalysisOutcome;
use crate::_internal::analysis::resolver::Resolver;
#[cfg(test)]
use crate::_internal::analysis::state::PreStateReadSet;
use crate::_internal::analysis::state::{AnalysisState, PreState};
use crate::_internal::analysis::transaction::TransactionFrameKind;
use crate::_internal::ast::visitor::AstVisitor;
use crate::_internal::engine::pre_state_footprint;
use crate::_internal::report::violations::{ReportFinding, SourceLocation, Violation};
use crate::_internal::rules::registry;
use crate::_internal::rules::{Rule, RuleContext, TransitionRecord};
use crate::api::config::Config;
use squawk_syntax::{
    Parse, SyntaxKind,
    ast::{AstNode, SourceFile},
};
use std::collections::HashSet;

/// Byte-offset to line/column lookup built once per source file.
struct LineIndex<'a> {
    sql: &'a str,
    line_starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    fn new(sql: &'a str) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(
            sql.bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        );
        Self { sql, line_starts }
    }

    fn location(&self, start: usize) -> Option<(usize, usize)> {
        if start > self.sql.len() || !self.sql.is_char_boundary(start) {
            return None;
        }
        let line = self.line_starts.partition_point(|offset| *offset <= start);
        let line_start = self.line_starts[line.saturating_sub(1)];
        Some((line, self.sql[line_start..start].chars().count() + 1))
    }
}

enum StatementCheckpoint {
    Full(Option<Box<AnalysisState>>),
    TransactionUndo {
        transaction_depth: usize,
        undo_len: usize,
    },
    StatementUndo,
    TransactionControl {
        shape: Vec<(TransactionFrameKind, usize)>,
    },
}

fn is_transaction_control(mutation: &Mutation) -> bool {
    matches!(
        mutation,
        Mutation::BeginTransaction
            | Mutation::CommitTransaction
            | Mutation::CommitAndChain
            | Mutation::RollbackTransaction
            | Mutation::RollbackAndChain
            | Mutation::RollbackToSavepoint(_)
            | Mutation::Savepoint(_)
            | Mutation::ReleaseSavepoint(_)
    )
}

fn is_pure_transaction_control(mutations: &[Mutation]) -> bool {
    let mut control = false;
    for mutation in mutations {
        if is_transaction_control(mutation) {
            if control {
                return false;
            }
            control = true;
        } else if !matches!(mutation, Mutation::CheckTimeouts { .. }) {
            return false;
        }
    }
    control
}

impl StatementCheckpoint {
    fn capture(
        state: &mut AnalysisState,
        mutations: &[Mutation],
        force_full: bool,
        transaction_control: bool,
    ) -> Self {
        debug_assert!(
            state.local.statement_undo_log.is_none(),
            "the previous statement's undo journal must be closed before the next checkpoint"
        );
        state.local.statement_snapshot_ids.clear();
        if !force_full {
            if is_pure_transaction_control(mutations) {
                let shape = state.transaction_shape();
                state.begin_statement_undo();
                return Self::TransactionControl { shape };
            }
            if !transaction_control {
                if let Some((transaction_depth, undo_len)) = state.transaction_undo_checkpoint() {
                    return Self::TransactionUndo {
                        transaction_depth,
                        undo_len,
                    };
                }
                state.begin_statement_undo();
                return Self::StatementUndo;
            }
        }
        Self::Full(Some(Box::new(state.clone())))
    }

    fn restore(&mut self, state: &mut AnalysisState) -> Result<(), String> {
        match self {
            Self::Full(checkpoint) => {
                let Some(checkpoint) = checkpoint.take() else {
                    return Err("statement checkpoint was already restored".to_string());
                };
                *state = *checkpoint;
                Ok(())
            }
            Self::TransactionUndo {
                transaction_depth,
                undo_len,
            } => state
                .rollback_to_transaction_undo_checkpoint(*transaction_depth, *undo_len)
                .map_err(str::to_string),
            Self::StatementUndo => state.rollback_statement_undo().map_err(str::to_string),
            Self::TransactionControl { shape } => {
                if state.transaction_shape() != *shape {
                    return Err(
                        "transaction-control statement changed transaction structure before failing"
                            .to_string(),
                    );
                }
                state.rollback_statement_undo().map_err(str::to_string)
            }
        }
    }

    fn finish(self, state: &mut AnalysisState) {
        if matches!(self, Self::StatementUndo | Self::TransactionControl { .. }) {
            state.commit_statement_undo();
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum StatementCheckpointMode {
    Journal,
    Full,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
enum PreStateCaptureMode {
    Selective,
    Full,
}

pub(crate) struct SafeMigrateEngine {
    config: Config,
    rules: Vec<Box<dyn Rule>>,
    #[cfg(test)]
    pre_state_mode: PreStateCaptureMode,
    #[cfg(test)]
    statement_checkpoint_mode: StatementCheckpointMode,
}

impl SafeMigrateEngine {
    pub(crate) fn new(config: Config) -> Self {
        Self {
            config,
            rules: registry::build_primary_rules(),
            #[cfg(test)]
            pre_state_mode: PreStateCaptureMode::Selective,
            #[cfg(test)]
            statement_checkpoint_mode: StatementCheckpointMode::Journal,
        }
    }

    /// Verifies selective capture against the full snapshot in tests.
    #[cfg(test)]
    pub(crate) fn with_full_pre_state_for_tests(mut self) -> Self {
        self.pre_state_mode = PreStateCaptureMode::Full;
        self
    }

    /// Verifies the statement undo journal against the full checkpoint in tests.
    #[cfg(test)]
    pub(crate) fn with_full_statement_checkpoint_for_tests(mut self) -> Self {
        self.statement_checkpoint_mode = StatementCheckpointMode::Full;
        self
    }

    fn force_full_statement_checkpoint(&self) -> bool {
        #[cfg(test)]
        {
            self.statement_checkpoint_mode == StatementCheckpointMode::Full
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Returns primary rule IDs in evaluation order.
    #[cfg(test)]
    pub(crate) fn primary_rule_ids(&self) -> Vec<&'static str> {
        registry::primary_rule_ids().collect()
    }

    #[cfg(test)]
    pub(crate) fn analyze_chain(
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

    #[cfg(test)]
    pub(crate) fn analyze(
        &self,
        sql: &str,
        state: &mut AnalysisState,
    ) -> Result<Vec<Violation>, Vec<String>> {
        self.analyze_chain(&[("inline".to_string(), sql.to_string())], state)
    }

    /// Analyze ordered files and retain reportable source locations for every
    /// finding. The original `analyze_chain` API remains available to callers
    /// that only need violations.
    pub(crate) fn analyze_chain_with_locations(
        &self,
        files: &[(String, String)],
        state: &mut AnalysisState,
    ) -> Result<Vec<ReportFinding>, Vec<String>> {
        let mut findings = Vec::new();
        let file_order: Vec<String> = files.iter().map(|(name, _)| name.clone()).collect();

        for (file_index, (filename, sql)) in files.iter().enumerate() {
            let normalized_sql = Self::normalize_execute(sql);
            let parsed = SourceFile::parse(&normalized_sql);
            let statement_ranges: Vec<_> = parsed
                .tree()
                .stmts()
                .map(|statement| statement.syntax().text_range())
                .collect();
            let violations =
                self.analyze_parsed_file(filename, &normalized_sql, sql, &parsed, state)?;
            let line_index = LineIndex::new(&normalized_sql);
            findings.extend(
                violations
                    .into_iter()
                    .map(|violation| {
                        let statement_index = violation.source_range.and_then(|range| {
                            // Statement ranges are sorted and non-overlapping; use
                            // partition_point to find the candidate in O(log n).
                            let i =
                                statement_ranges.partition_point(|s| s.start() <= range.start());
                            i.checked_sub(1)
                                .filter(|&i| statement_ranges[i].contains_range(range))
                                .map(|i| i + 1)
                        });
                        let certainty =
                            crate::_internal::report::violations::certainty_for_statement(
                                state.evidence(),
                                &file_order,
                                file_index,
                                statement_index,
                                state.pg_version().is_asserted(),
                            );
                        ReportFinding {
                            location: Self::source_location(
                                filename,
                                &line_index,
                                violation.source_range,
                            ),
                            statement_index,
                            certainty,
                            violation,
                        }
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

    #[cfg(test)]
    pub(crate) fn analyze_with_locations(
        &self,
        filename: String,
        sql: String,
        state: &mut AnalysisState,
    ) -> Result<Vec<ReportFinding>, Vec<String>> {
        self.analyze_chain_with_locations(&[(filename, sql)], state)
    }

    /// Analyze a migration chain and return immutable findings, confidence, and
    /// conservative-analysis evidence together.
    pub(crate) fn analyze_chain_outcome_with_locations(
        &self,
        files: &[(String, String)],
        state: &mut AnalysisState,
    ) -> Result<AnalysisOutcome<ReportFinding>, Vec<String>> {
        let findings = self.analyze_chain_with_locations(files, state)?;
        Ok(AnalysisOutcome::new(
            findings,
            state.confidence().clone(),
            state.evidence().to_vec(),
        ))
    }

    /// Analyze one migration and return immutable findings, confidence, and
    /// conservative-analysis evidence together.
    #[cfg(test)]
    pub(crate) fn analyze_outcome_with_locations(
        &self,
        filename: String,
        sql: String,
        state: &mut AnalysisState,
    ) -> Result<AnalysisOutcome<ReportFinding>, Vec<String>> {
        self.analyze_chain_outcome_with_locations(&[(filename, sql)], state)
    }

    #[cfg(test)]
    fn analyze_single_file(
        &self,
        filename: &str,
        sql: &str,
        state: &mut AnalysisState,
    ) -> Result<Vec<Violation>, Vec<String>> {
        let sql = Self::normalize_execute(sql);
        self.analyze_normalized_file(filename, &sql, state)
    }

    #[cfg(test)]
    fn analyze_normalized_file(
        &self,
        filename: &str,
        sql: &str,
        state: &mut AnalysisState,
    ) -> Result<Vec<Violation>, Vec<String>> {
        let parsed = SourceFile::parse(sql);
        self.analyze_parsed_file(filename, sql, sql, &parsed, state)
    }

    fn analyze_parsed_file(
        &self,
        filename: &str,
        sql: &str,
        original_sql: &str,
        parsed: &Parse<SourceFile>,
        state: &mut AnalysisState,
    ) -> Result<Vec<Violation>, Vec<String>> {
        // The state machine needs the deployment's identity to judge statements
        // about it, and the configuration is where that is stated. Every
        // analysis path funnels through here, so the fact is applied once
        // rather than by each caller.
        state.set_target_database(self.config.target_database().map(str::to_owned));
        let errors: Vec<String> = parsed.errors().iter().map(|e| e.to_string()).collect();
        if !errors.is_empty() {
            return Err(errors);
        }

        let mut all_violations = Vec::new();
        let mut warned_keys = HashSet::new();
        let mut pre_state = PreState::default();

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

        for (statement_offset, stmt) in parsed.tree().stmts().enumerate() {
            state.set_evidence_location(Some(EvidenceLocation {
                file: filename.to_string(),
                statement_index: statement_offset + 1,
            }));
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
            // Use original_sql to preserve EXECUTE '...' instead of normalized DO block
            let raw_start = usize::from(stmt.syntax().text_range().start());
            let raw_end = usize::from(stmt.syntax().text_range().end());
            let raw_stmt = if raw_start < original_sql.len() && raw_end <= original_sql.len() {
                &original_sql[raw_start..raw_end]
            } else {
                // Fallback (should not occur since lengths are preserved byte-for-byte)
                sql.get(raw_start..raw_end).unwrap_or("")
            };
            let stmt_text = Self::strip_sql_leading_comments(raw_stmt);

            // PostgreSQL executes a statement atomically. Keep both state
            // and diagnostics local until all resolved actions succeed so an
            // earlier action in a failed compound statement cannot leak
            // state, findings, or deduplication keys. A parsed statement
            // without a typed extractor is explicitly opaque: silently
            // ignoring it would claim exact confidence for later SQL.
            let mut statement_violations = Vec::new();
            let mut statement_warned_keys = HashSet::new();
            let mut fallback_source_range: Option<rowan::TextRange> = None;
            let mut mutations = match AstVisitor::extract(&stmt) {
                Some(fact) => Resolver::resolve(&fact, state),
                None => vec![Mutation::Opaque(
                    crate::_internal::analysis::mutations::OpaqueMutation::UnsupportedStatement,
                )],
            };
            if squawk_linter::analyze::possibly_slow_stmt(&stmt) {
                // Name the object the statement acts on. Diagnostic mutations
                // have no subject, so they are never mistaken for one.
                let subject = mutations.iter().find_map(|m| m.primary_object());
                mutations.push(Mutation::CheckTimeouts { subject });
            }
            let started_in_transaction = state.in_transaction();
            let transaction_control = mutations.iter().any(is_transaction_control);
            let force_full = self.force_full_statement_checkpoint();
            let mut statement_checkpoint =
                StatementCheckpoint::capture(state, &mutations, force_full, transaction_control);
            let mut statement_failed = false;

            for mutation in mutations {
                let pre_cascade = match &mutation {
                    Mutation::DropTable(d) if d.cascade => {
                        Some(state.cascade_for_relations(&d.ids))
                    }
                    _ => None,
                };

                #[cfg(not(test))]
                let reads =
                    pre_state_footprint::for_mutation(state, &mutation, pre_cascade.as_ref());
                #[cfg(test)]
                let reads = match self.pre_state_mode {
                    PreStateCaptureMode::Selective => {
                        pre_state_footprint::for_mutation(state, &mutation, pre_cascade.as_ref())
                    }
                    PreStateCaptureMode::Full => PreStateReadSet::full(),
                };
                state.capture_pre_state_into(&mut pre_state, &reads);
                let result = state.apply(&mutation, pre_cascade.as_ref());

                statement_failed = matches!(
                    result,
                    crate::_internal::analysis::state::MutationResult::Conflict(_)
                );
                if statement_failed {
                    let transaction_aborted = state.transaction_is_aborted();
                    if let Err(error) = statement_checkpoint.restore(state) {
                        return Err(vec![format!(
                            "failed to restore PostgreSQL statement atomicity: {error}"
                        )]);
                    }
                    if transaction_aborted && state.in_transaction() {
                        state.mark_transaction_aborted();
                    }
                    statement_violations.clear();
                    statement_warned_keys.clear();
                }

                if result == crate::_internal::analysis::state::MutationResult::NotExecuted {
                    if state.transaction_is_aborted() {
                        state.taint(EvidenceCode::TransactionAborted, EvidenceScope::Chain);
                        for rule in &self.rules {
                            state.record_not_evaluated(
                                crate::_internal::report::violations::NotEvaluated {
                                    rule_id: rule.id(),
                                    tier: rule.default_tier(),
                                    cause: EvidenceCode::TransactionAborted,
                                    sql: Some(stmt_text.trim().to_string()),
                                    recipe:
                                        crate::_internal::report::violations::NotEvaluated::recipe_with_scope(
                                            EvidenceCode::TransactionAborted,
                                            &[],
                                            None,
                                        ),
                                    missing_schemas: Vec::new(),
                                },
                            );
                        }
                    }
                    continue;
                }

                let transition =
                    TransitionRecord::new(&mutation, &result, &pre_state, pre_cascade.as_ref());
                let mut unresolved_context: Option<(Vec<String>, String)> = None;

                for rule in &self.rules {
                    let is_inline_ignored =
                        file_ignores.contains(rule.id()) || stmt_ignores.contains(rule.id());

                    if is_inline_ignored && !self.config.allow_inline_suppressions {
                        statement_violations.push(crate::_internal::report::violations::Violation {
                            source_range: None,
                            rule_id: "inline-suppression-disabled",
                            object_kind: crate::_internal::report::violations::ObjectKind::Unknown,
                            object_name: "".to_string(),
                            tier: crate::_internal::report::violations::ViolationTier::Tier1,
                            reason: format!("Inline suppression of rule '{}' is not allowed by configuration", rule.id()),
                            recipe: "Remove the inline directive. To bypass a rule, explicitly disable it in safe-migrate.toml.",
                            dedup_key: Some(format!("inline-suppression-disabled:{}", rule.id())),
                            sql: None,

                        });
                        // Skip evaluating the rule since it was requested to be ignored,
                        // but the build will fail anyway due to the Tier1 config violation.
                        continue;
                    }

                    if self.config.is_rule_disabled(rule.id()) || is_inline_ignored {
                        continue;
                    }

                    if let Some(cause) = result.unresolved_cause()
                        && !rule.evaluates_when_unresolved(&transition)
                    {
                        let (missing_schemas, recipe) =
                            unresolved_context.get_or_insert_with(|| {
                                let mut missing_schemas = state.external_referenced_schemas();
                                if let Some((_, obj_name)) = mutation.primary_object()
                                    && let Some(schema) =
                                        state.baseline_scope_omits_displayed_object(&obj_name)
                                    && !missing_schemas.iter().any(|s| s == schema)
                                {
                                    missing_schemas.push(schema.to_string());
                                }

                                let configured_or_synced_scope =
                                    self.config.schema_scope().map(|s| s.to_vec()).or_else(|| {
                                        state
                                            .baseline_schemas
                                            .as_ref()
                                            .map(|s| s.iter().cloned().collect::<Vec<_>>())
                                    });

                                let recipe =
                                    crate::_internal::report::violations::NotEvaluated::recipe_with_scope(
                                        cause,
                                        &missing_schemas,
                                        configured_or_synced_scope.as_deref(),
                                    );
                                (missing_schemas, recipe)
                            });

                        state.record_not_evaluated(
                            crate::_internal::report::violations::NotEvaluated {
                                rule_id: rule.id(),
                                tier: rule.default_tier(),
                                cause,
                                sql: Some(stmt_text.trim().to_string()),
                                recipe: recipe.clone(),
                                missing_schemas: missing_schemas.clone(),
                            },
                        );
                        continue;
                    }

                    let rule_context =
                        RuleContext::from_transition(transition, state, &self.config);
                    let violations = rule.evaluate(&rule_context);

                    // A capability is relevant only when this rule actually
                    // produces a finding for the current mutation. Recording
                    // it for every unrelated statement would taint an
                    // otherwise exact chain (for example, DROP DATABASE does
                    // not need relation statistics).
                    if !violations.is_empty() {
                        for capability in rule.required_capabilities() {
                            if !capability.available_for(state, &mutation, &pre_state) {
                                let code = if state.baseline_is_available() {
                                    capability.evidence_code()
                                } else {
                                    crate::_internal::analysis::evidence::EvidenceCode::BaselineUnavailable
                                };
                                state.taint(
                                    code,
                                    crate::_internal::analysis::evidence::EvidenceScope::Statement,
                                );
                            }
                        }
                    }

                    for v in violations {
                        if let Some(key) = &v.dedup_key
                            && (warned_keys.contains(key)
                                || !statement_warned_keys.insert(key.clone()))
                        {
                            continue;
                        }
                        let mut v = v;
                        if v.source_range.is_none() {
                            let fallback = *fallback_source_range.get_or_insert_with(|| {
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
                                rowan::TextRange::new(start, end)
                            });
                            v.source_range = Some(fallback);
                        }
                        if v.sql.is_none() {
                            if let Some(range) = v.source_range {
                                let start = usize::from(range.start());
                                let end = usize::from(range.end());
                                if start < original_sql.len() && end <= original_sql.len() {
                                    v.sql = Some(original_sql[start..end].trim().to_string());
                                } else {
                                    v.sql = Some(stmt_text.trim().to_string());
                                }
                            } else {
                                v.sql = Some(stmt_text.trim().to_string());
                            }
                        }
                        // Severity belongs to the rule alone; certainty is
                        // derived per finding from the evidence log.
                        statement_violations.push(v);
                    }
                }

                if statement_failed {
                    break;
                }
            }

            statement_checkpoint.finish(state);

            if !statement_failed
                && !started_in_transaction
                && !transaction_control
                && !state.in_transaction()
            {
                state.apply_implicit_commit_actions();
            }

            warned_keys.extend(statement_warned_keys);
            all_violations.extend(statement_violations);
        }

        state.set_evidence_location(None);
        Ok(all_violations)
    }

    fn source_location(
        filename: &str,
        line_index: &LineIndex<'_>,
        source_range: Option<rowan::TextRange>,
    ) -> Option<SourceLocation> {
        let (line, column) = line_index.location(usize::from(source_range?.start()))?;
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
    ///
    /// The scan is lexical rather than line-based so string literals, quoted
    /// identifiers, dollar-quoted bodies, and comments cannot be mistaken for
    /// statement starts.
    fn normalize_execute<'a>(sql: &'a str) -> std::borrow::Cow<'a, str> {
        let bytes = sql.as_bytes();
        let mut index = 0;
        let mut at_statement_start = true;
        let mut rewrite_offsets = Vec::new();

        while index < bytes.len() {
            match bytes[index] {
                b'\'' => {
                    index = skip_quoted_string(bytes, index);
                    at_statement_start = false;
                }
                b'"' => {
                    index = skip_quoted_identifier(bytes, index);
                    at_statement_start = false;
                }
                b'-' if bytes.get(index + 1) == Some(&b'-') => {
                    index = skip_line_comment(bytes, index);
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    index = skip_block_comment(bytes, index);
                }
                b'$' if !preceded_by_identifier(bytes, index) => {
                    if let Some(end) = dollar_quote_end(bytes, index) {
                        index = end;
                        at_statement_start = false;
                    } else {
                        index += 1;
                        at_statement_start = false;
                    }
                }
                b';' => {
                    index += 1;
                    at_statement_start = true;
                }
                byte if byte.is_ascii_whitespace() => index += 1,
                _ => {
                    if at_statement_start
                        && starts_with_keyword(bytes, index, b"EXECUTE")
                        && next_token_is_string(bytes, index + b"EXECUTE".len())
                    {
                        rewrite_offsets.push(index);
                    }
                    index += 1;
                    at_statement_start = false;
                }
            }
        }

        if rewrite_offsets.is_empty() {
            return std::borrow::Cow::Borrowed(sql);
        }

        let mut mutated = bytes.to_vec();
        for offset in rewrite_offsets {
            mutated[offset..offset + b"EXECUTE".len()].copy_from_slice(b"DO     ");
        }
        std::borrow::Cow::Owned(
            String::from_utf8(mutated)
                .expect("normalization replaces ASCII bytes with ASCII bytes"),
        )
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

    fn strip_sql_leading_comments(s: &str) -> &str {
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
        &s[pos..]
    }
}

fn starts_with_keyword(bytes: &[u8], start: usize, word: &[u8]) -> bool {
    let end = start + word.len();
    end <= bytes.len()
        && bytes[start..end].eq_ignore_ascii_case(word)
        && bytes.get(end).is_none_or(|byte| !is_identifier_byte(*byte))
}

fn next_token_is_string(bytes: &[u8], mut index: usize) -> bool {
    loop {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) == Some(&b'-') && bytes.get(index + 1) == Some(&b'-') {
            index = skip_line_comment(bytes, index);
            continue;
        }
        if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
            index = skip_block_comment(bytes, index);
            continue;
        }
        break;
    }

    match bytes.get(index) {
        Some(b'\'') => true,
        Some(b'$') => dollar_quote_end(bytes, index).is_some(),
        _ => false,
    }
}

fn skip_quoted_string(bytes: &[u8], start: usize) -> usize {
    let backslash_escapes = is_escape_string_quote(bytes, start);
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' if backslash_escapes => index += 2,
            b'\'' if bytes.get(index + 1) == Some(&b'\'') => index += 2,
            b'\'' => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

fn is_escape_string_quote(bytes: &[u8], quote: usize) -> bool {
    if quote == 0 {
        return false;
    }
    quote > 0
        && bytes[quote - 1].eq_ignore_ascii_case(&b'E')
        && (quote < 2 || !is_identifier_byte(bytes[quote - 2]))
}

fn skip_quoted_identifier(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            if bytes.get(index + 1) == Some(&b'"') {
                index += 2;
            } else {
                return index + 1;
            }
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn skip_line_comment(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |offset| start + offset)
}

fn skip_block_comment(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut index = start;
    while index + 1 < bytes.len() {
        if bytes[index] == b'/' && bytes[index + 1] == b'*' {
            depth += 1;
            index += 2;
        } else if bytes[index] == b'*' && bytes[index + 1] == b'/' {
            depth = depth.saturating_sub(1);
            index += 2;
            if depth == 0 {
                return index;
            }
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn dollar_quote_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'$') {
        return None;
    }
    let mut tag_end = start + 1;
    if bytes.get(tag_end).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    while tag_end < bytes.len() && is_dollar_tag_byte(bytes[tag_end]) {
        tag_end += 1;
    }
    if bytes.get(tag_end) != Some(&b'$') {
        return None;
    }
    let tag = &bytes[start..=tag_end];
    let mut index = tag_end + 1;
    while index + tag.len() <= bytes.len() {
        if &bytes[index..index + tag.len()] == tag {
            return Some(index + tag.len());
        }
        index += 1;
    }
    Some(bytes.len())
}

fn is_dollar_tag_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || !byte.is_ascii()
}

fn preceded_by_identifier(bytes: &[u8], index: usize) -> bool {
    index > 0 && is_identifier_byte(bytes[index - 1])
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || !byte.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::SafeMigrateEngine;

    #[test]
    fn normalize_execute_rewrites_statement_after_same_line_statement() {
        let sql = "SELECT 1; EXECUTE 'DROP TABLE x';";
        assert_eq!(
            SafeMigrateEngine::normalize_execute(sql),
            "SELECT 1; DO      'DROP TABLE x';"
        );
    }

    #[test]
    fn normalize_execute_leaves_execute_text_inside_multiline_literal() {
        let sql = "INSERT INTO logs (msg) VALUES ('first line\nEXECUTE ''second line'');";
        assert_eq!(SafeMigrateEngine::normalize_execute(sql), sql);
    }

    #[test]
    fn normalize_execute_leaves_execute_text_inside_comments() {
        let sql = "/*\nEXECUTE 'DROP TABLE x';\n-- EXECUTE 'DROP TABLE y';\n*/\nSELECT 1;";
        assert_eq!(SafeMigrateEngine::normalize_execute(sql), sql);
    }

    #[test]
    fn normalize_execute_rewrites_after_preceding_comment() {
        let sql = "-- leading comment\nEXECUTE 'DROP TABLE x';";
        assert_eq!(
            SafeMigrateEngine::normalize_execute(sql),
            "-- leading comment\nDO      'DROP TABLE x';"
        );
    }

    #[test]
    fn normalize_execute_rewrites_dollar_quoted_body_with_tag() {
        let sql = "EXECUTE $body$SELECT 'EXECUTE ''x'';'$body$;";
        assert_eq!(
            SafeMigrateEngine::normalize_execute(sql),
            "DO      $body$SELECT 'EXECUTE ''x'';'$body$;"
        );
    }

    #[test]
    fn normalize_execute_leaves_prepared_statement_and_identifier_dollars() {
        let sql = "EXECUTE my_plan; SELECT a$b$ FROM t; EXECUTE format('SELECT 1');";
        assert_eq!(SafeMigrateEngine::normalize_execute(sql), sql);
    }

    #[test]
    fn normalize_execute_respects_escape_string_quotes() {
        let sql = "SELECT E'it\\'s; EXECUTE ''x'''; EXECUTE 'DROP TABLE t';";
        assert_eq!(
            SafeMigrateEngine::normalize_execute(sql),
            "SELECT E'it\\'s; EXECUTE ''x'''; DO      'DROP TABLE t';"
        );
    }

    #[test]
    fn normalize_execute_preserves_byte_length_and_non_ascii_text() {
        let sql = "SELECT 'é'; EXECUTE 'DROP TABLE x';";
        let normalized = SafeMigrateEngine::normalize_execute(sql);
        assert_eq!(normalized.len(), sql.len());
        assert_eq!(normalized, "SELECT 'é'; DO      'DROP TABLE x';");
    }

    #[test]
    fn normalize_execute_borrows_when_no_rewrite_needed() {
        let sql = "SELECT 1; INSERT INTO t VALUES ('EXECUTE');";
        let res = SafeMigrateEngine::normalize_execute(sql);
        assert!(matches!(res, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn normalize_execute_owns_when_rewrite_performed() {
        let sql = "EXECUTE 'DROP TABLE x';";
        let res = SafeMigrateEngine::normalize_execute(sql);
        assert!(matches!(res, std::borrow::Cow::Owned(_)));
    }
}
