// FILE: src/engine/engine.rs
use crate::analysis::mutations::Mutation;
use crate::analysis::resolver::Resolver;
use crate::analysis::state::AnalysisState;
use crate::ast::visitor::AstVisitor;
use crate::engine::config::Config;
use crate::report::violations::Violation;
use crate::rules::Rule;
use crate::rules::conflict::ConflictRule;
use crate::rules::constraints::BlockingConstraintRule;
use crate::rules::destructive::{
    CascadingDropRule, CreateTableAsSelectRule, DropDatabaseRule, DropSchemaCascadeRule,
    GeneralCascadeRule, ReversibilityRule, SizeAwareAddColumnRule, TypeChangeRewriteRule,
};
use crate::rules::drift::DriftDetectionRule;
use crate::rules::expressions::VolatileDefaultRule;
use crate::rules::functions::{BrokenComputeRule, FunctionVolatilityRule};
use crate::rules::idempotency::IdempotencyRule;
use crate::rules::indexes::ConcurrentIndexRule;
use crate::rules::opaque::OpaqueDynamicSqlRule;
use crate::rules::partitions::{PartitionLockRule, PartitionStrategyMismatchRule};
use crate::rules::policies::RestrictivePolicyRule;
use crate::rules::security::OverbroadGrantRule;
use crate::rules::transactions::{
    AlterTypeAddValueRule, ConcurrentInsideTransactionRule, VacuumFullRule,
};
use crate::rules::triggers::DisableTriggerRule;
use crate::rules::views::MaterializedViewRefreshRule;
use squawk_syntax::ast::{AstNode, SourceFile};
use std::collections::HashSet;

pub struct SafeMigrateEngine {
    config: Config,
    rules: Vec<Box<dyn Rule>>,
}

impl SafeMigrateEngine {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            rules: vec![
                Box::new(ReversibilityRule),
                Box::new(DropDatabaseRule),
                Box::new(DropSchemaCascadeRule),
                Box::new(GeneralCascadeRule),
                Box::new(CascadingDropRule),
                Box::new(CreateTableAsSelectRule),
                Box::new(SizeAwareAddColumnRule),
                Box::new(TypeChangeRewriteRule),
                Box::new(BlockingConstraintRule),
                Box::new(ConcurrentIndexRule),
                Box::new(MaterializedViewRefreshRule),
                Box::new(PartitionLockRule),
                Box::new(PartitionStrategyMismatchRule),
                Box::new(RestrictivePolicyRule),
                Box::new(DisableTriggerRule),
                Box::new(BrokenComputeRule),
                Box::new(FunctionVolatilityRule),
                Box::new(IdempotencyRule),
                Box::new(ConcurrentInsideTransactionRule),
                Box::new(AlterTypeAddValueRule),
                Box::new(VacuumFullRule),
                Box::new(OpaqueDynamicSqlRule),
                Box::new(VolatileDefaultRule),
                Box::new(OverbroadGrantRule),
                Box::new(DriftDetectionRule),
                Box::new(ConflictRule),
            ],
        }
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
        // Phase 10.6: Deterministic violation ordering
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

    fn analyze_single_file(
        &self,
        _filename: &str,
        sql: &str,
        state: &mut AnalysisState,
    ) -> Result<Vec<Violation>, Vec<String>> {
        let parsed = SourceFile::parse(sql);
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
                if let Some(token) = element.as_token() {
                    let mut dummy = HashSet::new();
                    Self::parse_directives(token.text(), &mut dummy, &mut stmt_ignores);
                }
                prev = element.prev_sibling_or_token();
            }

            for token in stmt
                .syntax()
                .descendants_with_tokens()
                .filter_map(|it| it.into_token())
            {
                let mut dummy = HashSet::new();
                Self::parse_directives(token.text(), &mut dummy, &mut stmt_ignores);
            }

            // Capture raw statement text for sql field on violations
            let stmt_text = stmt.syntax().text().to_string();

            if let Some(fact) = AstVisitor::extract(&stmt) {
                let mutations = Resolver::resolve(&fact, state);

                for mutation in mutations {
                    let pre_cascade = match &mutation {
                        Mutation::DropTable(d) if d.cascade => {
                            Some(state.get_cascade_closure(&d.id))
                        }
                        _ => None,
                    };

                    let pre_state = state.capture_pre_state();
                    let result = state.apply(&mutation, pre_cascade.as_ref());

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
                                && !warned_keys.insert(key.clone())
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
                            // Downgrade tier at push time if confidence was already tainted
                            // BEFORE this mutation was applied.
                            if state.local.confidence == crate::analysis::state::Confidence::Tainted
                                && v.tier == crate::report::violations::ViolationTier::Tier1
                            {
                                v.tier = crate::report::violations::ViolationTier::Tier2;
                            }
                            all_violations.push(v);
                        }
                    }
                }
            }
        }

        Ok(all_violations)
    }

    fn parse_directives(
        text: &str,
        file_ignores: &mut HashSet<String>,
        stmt_ignores: &mut HashSet<String>,
    ) {
        let mut search = text;
        while let Some(idx) = search.find("safe-migrate: ignore-file(") {
            let start = idx + "safe-migrate: ignore-file(".len();
            if let Some(end) = search[start..].find(')') {
                file_ignores.insert(search[start..start + end].trim().to_string());
                search = &search[start + end + 1..];
            } else {
                break;
            }
        }

        let mut search = text;
        while let Some(idx) = search.find("safe-migrate: ignore(") {
            let start = idx + "safe-migrate: ignore(".len();
            if let Some(end) = search[start..].find(')') {
                stmt_ignores.insert(search[start..start + end].trim().to_string());
                search = &search[start + end + 1..];
            } else {
                break;
            }
        }
    }
}
