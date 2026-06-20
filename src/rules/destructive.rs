// FILE: src/rules/destructive.rs
use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::model::relation::RelationState;
use crate::rules::Rule;
use crate::analysis::mutations::{Mutation, AlterTableActionMutation};
use crate::analysis::state::{AnalysisState, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};

pub struct CascadingDropRule;

impl Rule for CascadingDropRule {
    fn id(&self) -> &'static str { "destructive-cascade" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "Avoid CASCADE on DROP TABLE in production. Handle dependencies explicitly." }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        _pre_relations: &HashMap<ObjectId, RelationState>,
        state: &AnalysisState,
        _config: &Config
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::DropTable(drop) = mutation {
            if drop.cascade {
                let closure = state.get_cascade_closure(&drop.id);
                let mut affects_baseline = false;

                // 1. Check if the cascade destroys any pre-existing live DB relations
                for rel_id in &closure.dropped_relations {
                    if rel_id != &drop.id && state.baseline_relations.contains(rel_id) {
                        affects_baseline = true;
                        break;
                    }
                }

                // 2. Check if the cascade destroys any pre-existing live DB foreign key constraints
                if !affects_baseline {
                    for constraint in &closure.dropped_constraints {
                        if state.baseline_foreign_keys.contains(constraint) {
                            affects_baseline = true;
                            break;
                        }
                    }
                }

                if affects_baseline {
                    violations.push(Violation {
                        rule_id: self.id(),
                        title: format!("DROP TABLE {} CASCADE silently destroys pre-existing database dependencies", drop.id),
                        tier: self.default_tier(),
                        recipe: self.recipe(),
                        dedup_key: None,
                    });
                }
            }
        }
        violations
    }
}

pub struct SizeAwareAddColumnRule;

impl Rule for SizeAwareAddColumnRule {
    fn id(&self) -> &'static str { "size-aware-add-column" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "Adding a column with a default requires a table rewrite. For PG11+, constant defaults are safe. For volatiles or <PG11, use a multi-step backfill." }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        pre_relations: &HashMap<ObjectId, RelationState>,
        state: &AnalysisState,
        config: &Config
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();
        // Fallback to ancient version if offline (Fail Closed)
        let pg_version = state.pg_version_num.unwrap_or(100000);

        if let Mutation::AlterTable(alter) = mutation {
            if let AlterTableActionMutation::AddColumn { default: Some(def), .. } = &alter.action {
                let is_volatile = def.is_volatile();

                // CORE LOGIC: PG11+ makes CONSTANT defaults safe. Volatile defaults always rewrite.
                let requires_rewrite = is_volatile || pg_version < 110000;

                if requires_rewrite {
                    if let Some(rel) = pre_relations.get(&alter.id) {

                        // 1. Independent Staleness Check
                        if rel.is_stale() {
                            let key = format!("{}_stale_{}", self.id(), alter.id);
                            violations.push(Violation {
                                rule_id: self.id(),
                                title: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", alter.id),
                                tier: ViolationTier::Tier2,
                                recipe: "Run ANALYZE to ensure accurate TOAST width and row estimates before structural changes.",
                                dedup_key: Some(key),
                            });
                        }

                        // 2. Size and TOAST Evaluation
                        let has_wide_columns = rel.columns.iter()
                            .any(|c| c.avg_width.unwrap_or(0) >= config.toast_width_threshold_bytes as i32);

                        let mut tier = match rel.estimated_rows {
                            None => ViolationTier::Tier1, // Unknown -> Fail closed
                            Some(r) if r >= config.tier1_threshold_rows => ViolationTier::Tier1,
                            Some(r) if r >= config.tier2_threshold_rows => ViolationTier::Tier2,
                            _ => ViolationTier::Tier3,
                        };

                        // Escalate severity if TOAST reconstruction is likely
                        if has_wide_columns && tier == ViolationTier::Tier2 {
                            tier = ViolationTier::Tier1;
                        }

                        if tier != ViolationTier::Tier3 {
                            let mut title = if is_volatile {
                                format!("Adding column with volatile DEFAULT to {} triggers a table rewrite", alter.id)
                            } else {
                                format!("Adding column with DEFAULT to {} triggers a table rewrite on Postgres < 11", alter.id)
                            };

                            if has_wide_columns && tier == ViolationTier::Tier1 {
                                title.push_str(" (Escalated due to wide TOAST columns)");
                            }
                            if rel.is_stale() {
                                title.push_str(" [WARNING: Based on stale statistics]");
                            }

                            violations.push(Violation {
                                rule_id: self.id(),
                                title,
                                tier,
                                recipe: self.recipe(),
                                dedup_key: None,
                            });
                        }
                    }
                }
            }
        }
        violations
    }
}

pub struct TypeChangeRewriteRule;

impl TypeChangeRewriteRule {
    /// Static Compatibility Matrix for identifying rewrite-free binary coercions
    fn is_type_change_safe(old_type: &str, new_type: &str, pg_version: u32) -> bool {
        let old = old_type.to_lowercase();
        let new = new_type.to_lowercase();
        if old == new { return true; }

        let old_base = old.split('(').next().unwrap_or(&old).trim();
        let new_base = new.split('(').next().unwrap_or(&new).trim();

        // 1. VARCHAR length expansion (Safe since Postgres 9.2)
        if (old_base == "varchar" || old_base == "character varying") &&
           (new_base == "varchar" || new_base == "character varying" || new_base == "text") {
            // Unbounded text/varchar is always a safe expansion
            if new == "text" || new == "varchar" || new == "character varying" {
                return true;
            }
        }

        // 2. NUMERIC precision expansion (Safe since Postgres 12.0)
        if pg_version >= 120000 &&
           (old_base == "numeric" || old_base == "decimal") &&
           (new_base == "numeric" || new_base == "decimal") {
            if !new.contains('(') {
                return true; // Expansion to unbounded precision
            }
        }

        // Default to unsafe (e.g. INT -> BIGINT always rewrites)
        false
    }
}

impl Rule for TypeChangeRewriteRule {
    fn id(&self) -> &'static str { "type-change-rewrite" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "Changing this column type requires an ACCESS EXCLUSIVE table rewrite. Add a new column, backfill, and swap." }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        pre_relations: &HashMap<ObjectId, RelationState>,
        state: &AnalysisState,
        config: &Config
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = mutation {
            // FIX: AlterTableActionMutation::SetType now carries `has_using`.
            // The rule doesn't need the value (the static compatibility matrix
            // judges safety from the type pair + pg_version alone, independent
            // of whether the author supplied an explicit USING clause), so it's
            // bound and explicitly discarded rather than silently dropped.
            if let AlterTableActionMutation::SetType { column, ty, has_using: _ } = &alter.action {
                let pg_version = state.pg_version_num.unwrap_or(100000);

                // Extract previous type from the pre-mutation state
                if let Some(rel) = pre_relations.get(&alter.id) {
                    if let Some(col) = rel.columns.iter().find(|c| c.name == *column) {
                        if let Some(old_type) = &col.data_type {

                            // Check compatibility matrix
                            if !Self::is_type_change_safe(old_type, ty, pg_version) {

                                let tier = match rel.estimated_rows {
                                    None => ViolationTier::Tier1, // Fail Closed
                                    Some(r) if r >= config.tier1_threshold_rows => ViolationTier::Tier1,
                                    Some(r) if r >= config.tier2_threshold_rows => ViolationTier::Tier2,
                                    _ => ViolationTier::Tier3,
                                };

                                if tier != ViolationTier::Tier3 {
                                    violations.push(Violation {
                                        rule_id: self.id(),
                                        title: format!("Changing column {}.{} type from {} to {} causes a table rewrite", alter.id, column, old_type, ty),
                                        tier,
                                        recipe: self.recipe(),
                                        dedup_key: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        violations
    }
}
