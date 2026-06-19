// FILE: ./src/engine/engine.rs

use squawk_syntax::ast::SourceFile;
use std::collections::{HashMap, HashSet};
use crate::ast::visitor::AstVisitor;
use crate::ast::identifiers::ObjectId;
use crate::analysis::resolver::Resolver;
use crate::analysis::state::AnalysisState;
use crate::analysis::mutations::Mutation;
use crate::model::relation::{RelationState, RelationOverlay};
use crate::engine::config::Config;
use crate::report::violations::Violation;
use crate::rules::Rule;
use crate::rules::destructive::{CascadingDropRule, SizeAwareAddColumnRule};
use crate::rules::constraints::BlockingConstraintRule;
use crate::rules::indexes::ConcurrentIndexRule;
use crate::rules::views::MaterializedViewRefreshRule;
use crate::rules::partitions::PartitionLockRule;
use crate::rules::idempotency::IdempotencyRule;
use crate::rules::transactions::ConcurrentInsideTransactionRule;
use crate::rules::opaque::OpaqueDynamicSqlRule;
use crate::rules::expressions::VolatileDefaultRule;

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
                Box::new(BlockingConstraintRule),
                Box::new(ConcurrentIndexRule),
                Box::new(MaterializedViewRefreshRule),
                Box::new(PartitionLockRule),
                Box::new(IdempotencyRule),
                Box::new(ConcurrentInsideTransactionRule),
                Box::new(OpaqueDynamicSqlRule),
                Box::new(VolatileDefaultRule),
            ],
        }
    }

    /// Executes the deterministic simulation loop statement-by-statement.
    pub fn analyze(&self, sql: &str, state: &mut AnalysisState) -> Result<Vec<Violation>, Vec<String>> {
        let parsed = SourceFile::parse(sql);
        let errors: Vec<String> = parsed.errors().iter().map(|e| e.to_string()).collect();
        if !errors.is_empty() {
            return Err(errors);
        }

        let mut all_violations = Vec::new();
        let mut warned_keys = HashSet::new();

        for stmt in parsed.tree().stmts() {
            if let Some(fact) = AstVisitor::extract(&stmt) {
                let mutations = Resolver::resolve(&fact, state);

                for mutation in mutations {
                    // 1. O(1) Pre-State Clone targeted to specific mutation bounds
                    let pre_relations: HashMap<ObjectId, RelationState> = match &mutation {
                        Mutation::AlterTable(a) => state.local.relations.get(&a.id)
                            .and_then(|o| if let RelationOverlay::Present(r) = o { Some((a.id.clone(), r.clone())) } else { None })
                            .into_iter().collect(),
                        Mutation::CreateIndex(c) => state.local.relations.get(&c.table)
                            .and_then(|o| if let RelationOverlay::Present(r) = o { Some((c.table.clone(), r.clone())) } else { None })
                            .into_iter().collect(),
                        Mutation::RefreshMaterializedView(r) => state.local.relations.get(&r.id)
                            .and_then(|o| if let RelationOverlay::Present(rel) = o { Some((r.id.clone(), rel.clone())) } else { None })
                            .into_iter().collect(),
                        Mutation::DropIndex(d) => state.local.graph.is_referenced_by_index(&d.id)
                            .into_iter()
                            .filter_map(|tid| {
                                state.local.relations.get(&tid)
                                    .and_then(|o| if let RelationOverlay::Present(r) = o { Some((tid.clone(), r.clone())) } else { None })
                            })
                            .collect(),
                        _ => HashMap::new(),
                    };

                    // 2. State Mutation
                    let result = state.apply(&mutation);

                    // 3. Rule Evaluation
                    for rule in &self.rules {
                        let violations = rule.evaluate(&mutation, &result, &pre_relations, &state.local, &self.config);
                        
                        for v in violations {
                            // Engine-level deduplication via namespaced keys
                            if let Some(key) = &v.dedup_key {
                                if !warned_keys.insert(key.clone()) {
                                    continue; // Skip appending duplicate
                                }
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
