// FILE: src/engine/engine.rs
use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::resolver::Resolver;
use crate::analysis::state::AnalysisState;
use crate::ast::identifiers::ObjectId;
use crate::ast::visitor::AstVisitor;
use crate::engine::config::Config;
use crate::model::relation::{RelationOverlay, RelationState};
use crate::report::violations::Violation;
use crate::rules::Rule;
use crate::rules::constraints::BlockingConstraintRule;
use crate::rules::destructive::{CascadingDropRule, SizeAwareAddColumnRule, TypeChangeRewriteRule};
use crate::rules::expressions::VolatileDefaultRule;
use crate::rules::idempotency::IdempotencyRule;
use crate::rules::indexes::ConcurrentIndexRule;
use crate::rules::opaque::OpaqueDynamicSqlRule;
use crate::rules::partitions::PartitionLockRule;
use crate::rules::transactions::{ConcurrentInsideTransactionRule, VacuumFullRule};
use crate::rules::views::MaterializedViewRefreshRule;
use squawk_syntax::ast::{AstNode, SourceFile};
use std::collections::{HashMap, HashSet};

pub struct SafeMigrateEngine {
    config: Config,
    rules: Vec<Box<dyn Rule>>,
}

impl SafeMigrateEngine {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            rules: vec![
                Box::new(CascadingDropRule),
                Box::new(SizeAwareAddColumnRule),
                Box::new(TypeChangeRewriteRule),
                Box::new(BlockingConstraintRule),
                Box::new(ConcurrentIndexRule),
                Box::new(MaterializedViewRefreshRule),
                Box::new(PartitionLockRule),
                Box::new(IdempotencyRule),
                Box::new(ConcurrentInsideTransactionRule),
                Box::new(VacuumFullRule),
                Box::new(OpaqueDynamicSqlRule),
                Box::new(VolatileDefaultRule),
            ],
        }
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

    pub fn analyze(
        &self,
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

            if let Some(fact) = AstVisitor::extract(&stmt) {
                let mutations = Resolver::resolve(&fact, state);

                for mutation in mutations {
                    let pre_relations: HashMap<ObjectId, RelationState> = match &mutation {
                        Mutation::AlterTable(a) => {
                            let mut snapshot = HashMap::new();
                            if let Some(RelationOverlay::Present(r)) =
                                state.local.relations.get(&a.id)
                            {
                                snapshot.insert(a.id.clone(), r.clone());
                            }

                            if let AlterTableActionMutation::AddForeignKey { to_table, .. } =
                                &a.action
                                && let Some(RelationOverlay::Present(parent_rel)) =
                                    state.local.relations.get(to_table)
                            {
                                snapshot.insert(to_table.clone(), parent_rel.clone());
                            }
                            snapshot
                        }
                        Mutation::CreateIndex(c) => state
                            .local
                            .relations
                            .get(&c.table)
                            .and_then(|o| {
                                if let RelationOverlay::Present(r) = o {
                                    Some((c.table.clone(), r.clone()))
                                } else {
                                    None
                                }
                            })
                            .into_iter()
                            .collect(),
                        Mutation::RefreshMaterializedView(r) => state
                            .local
                            .relations
                            .get(&r.id)
                            .and_then(|o| {
                                if let RelationOverlay::Present(rel) = o {
                                    Some((r.id.clone(), rel.clone()))
                                } else {
                                    None
                                }
                            })
                            .into_iter()
                            .collect(),
                        Mutation::DropIndex(d) => state
                            .local
                            .graph
                            .is_referenced_by_index(&d.id)
                            .into_iter()
                            .filter_map(|tid| {
                                state.local.relations.get(tid).and_then(|o| {
                                    if let RelationOverlay::Present(r) = o {
                                        Some((tid.clone(), r.clone()))
                                    } else {
                                        None
                                    }
                                })
                            })
                            .collect(),
                        _ => HashMap::new(),
                    };

                    let pre_cascade = match &mutation {
                        Mutation::DropTable(d) if d.cascade => {
                            Some(state.get_cascade_closure(&d.id))
                        }
                        _ => None,
                    };

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
                            &pre_relations,
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
                            all_violations.push(v);
                        }
                    }
                }
            }
        }

        Ok(all_violations)
    }
}
