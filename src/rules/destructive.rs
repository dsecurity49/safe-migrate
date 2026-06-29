// FILE: src/rules/destructive.rs
use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};
use crate::rules::Rule;

pub struct CascadingDropRule;

impl Rule for CascadingDropRule {
    fn id(&self) -> &'static str {
        "destructive-cascade"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Avoid CASCADE on DROP TABLE in production. Handle dependencies explicitly."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        _config: &Config,
        cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::DropTable(drop) = mutation
            && drop.cascade
            && let Some(closure) = cascade_closure
        {
            let mut affects_baseline = false;

            for rel_id in &closure.dropped_relations {
                if rel_id != &drop.id && state.baseline_relations.contains(rel_id) {
                    affects_baseline = true;
                    break;
                }
            }

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
        violations
    }
}

pub struct SizeAwareAddColumnRule;

impl Rule for SizeAwareAddColumnRule {
    fn id(&self) -> &'static str {
        "size-aware-add-column"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Adding a column with a default requires a table rewrite. For PG11+, constant defaults are safe. For volatiles or <PG11, use a multi-step backfill."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        config: &Config,
        _cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();
        let pg_version = state.pg_version_num.unwrap_or(config.assume_pg_version);

        if let Mutation::AlterTable(alter) = mutation
            && let AlterTableActionMutation::AddColumn {
                default: Some(def), ..
            } = &alter.action
        {
            let is_volatile = def.is_volatile();
            let requires_rewrite = is_volatile || pg_version < 110000;

            if requires_rewrite {
                let (has_wide_columns, is_stale, rows) = match pre_state.relations.get(&alter.id) {
                    Some(rel) => {
                        let wide = rel.columns.iter().any(|c| {
                            c.avg_width.unwrap_or(0) >= config.toast_width_threshold_bytes
                        });
                        // BUG FIX: Only mark as stale if it actually existed in the baseline database!
                        // Tables created in this migration script are 0-rows fresh, not stale.
                        let stale = rel.is_stale() && state.baseline_relations.contains(&alter.id);
                        (
                            wide,
                            stale,
                            rel.estimated_rows.unwrap_or(config.default_rows),
                        )
                    }
                    None => {
                        // Table is completely unknown (not in cache, not in migration). We are guessing. Mark as stale.
                        (false, true, config.default_rows)
                    }
                };

                if is_stale {
                    let key = format!("{}_stale_{}", self.id(), alter.id);
                    violations.push(Violation {
                        rule_id: self.id(),
                        title: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", alter.id),
                        tier: ViolationTier::Tier2,
                        recipe: "Run ANALYZE to ensure accurate TOAST width and row estimates before structural changes.",
                        dedup_key: Some(key),
                    });
                }

                let tier1_threshold = config.rule_tier1_threshold(self.id());
                let mut tier = if rows >= tier1_threshold {
                    ViolationTier::Tier1
                } else {
                    ViolationTier::Tier2
                };

                if has_wide_columns && tier == ViolationTier::Tier2 {
                    tier = ViolationTier::Tier1;
                }

                let mut title = if is_volatile {
                    format!(
                        "Adding column with volatile DEFAULT to {} triggers a table rewrite",
                        alter.id
                    )
                } else {
                    format!(
                        "Adding column with DEFAULT to {} triggers a table rewrite on Postgres < 11",
                        alter.id
                    )
                };

                if has_wide_columns && tier == ViolationTier::Tier1 {
                    title.push_str(" (Escalated due to wide TOAST columns)");
                }
                if is_stale {
                    title.push_str(" [WARNING: Based on unknown offline statistics]");
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
        violations
    }
}

pub struct DropDatabaseRule;

impl Rule for DropDatabaseRule {
    fn id(&self) -> &'static str {
        "drop-database"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "DROP DATABASE is an irreversible, high-blast-radius operation that destroys the entire database context."
    }

    fn evaluate(
        &self,
        _mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        _state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        vec![Violation {
            rule_id: self.id(),
            title: "DROP DATABASE detected".to_string(),
            tier: self.default_tier(),
            recipe: self.recipe(),
            dedup_key: None,
        }]
    }
}

pub struct DropSchemaCascadeRule;

impl Rule for DropSchemaCascadeRule {
    fn id(&self) -> &'static str {
        "drop-schema-cascade"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "DROP SCHEMA ... CASCADE recursively destroys every object in the schema. Handle dependencies explicitly."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        _state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Mutation::DropSchema(drop) = mutation && drop.cascade {
            violations.push(Violation {
                rule_id: self.id(),
                title: format!("DROP SCHEMA {} CASCADE detected", drop.names.join(", ")),
                tier: self.default_tier(),
                recipe: self.recipe(),
                dedup_key: None,
            });
        }

        violations
    }
}

pub struct CreateTableAsSelectRule;

impl Rule for CreateTableAsSelectRule {
    fn id(&self) -> &'static str {
        "create-table-as-select"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier2
    }
    fn recipe(&self) -> &'static str {
        "CREATE TABLE AS SELECT can be extremely slow and resource-intensive on large datasets. Consider creating the table first and using INSERT INTO ... SELECT in batches."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        _state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if let Mutation::CreateTable(c) = mutation && c.as_select {
            return vec![Violation {
                rule_id: self.id(),
                title: format!("CREATE TABLE AS SELECT detected for {}", c.id),
                tier: self.default_tier(),
                recipe: self.recipe(),
                dedup_key: None,
            }];
        }
        vec![]
    }
}

pub struct GeneralCascadeRule;

impl Rule for GeneralCascadeRule {
    fn id(&self) -> &'static str {
        "destructive-general-cascade"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Using CASCADE on DROP operations can silently delete dependent objects. Explicitly drop dependencies to avoid accidental data loss."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        _state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        let is_cascade = match mutation {
            Mutation::DropView(d) => d.cascade,
            Mutation::DropMaterializedView(d) => d.cascade,
            Mutation::DropSequence(d) => d.cascade,
            Mutation::DropDomain(d) => d.cascade,
            Mutation::DropFunction(d) => d.cascade,
            Mutation::DropProcedure(d) => d.cascade,
            Mutation::DropPublication(d) => d.cascade,
            _ => false,
        };

        if is_cascade {
            return vec![Violation {
                rule_id: self.id(),
                title: "Destructive CASCADE operation detected".to_string(),
                tier: self.default_tier(),
                recipe: self.recipe(),
                dedup_key: None,
            }];
        }
        vec![]
    }
}

pub struct TypeChangeRewriteRule;

impl TypeChangeRewriteRule {
    fn is_type_change_safe(old_type: &str, new_type: &str, pg_version: u32) -> bool {
        let old = old_type.to_lowercase();
        let new = new_type.to_lowercase();
        if old == new {
            return true;
        }

        let old_base = old.split('(').next().unwrap_or(&old).trim();
        let new_base = new.split('(').next().unwrap_or(&new).trim();

        if (old_base == "varchar" || old_base == "character varying")
            && (new_base == "varchar" || new_base == "character varying" || new_base == "text")
            && (new == "text" || new == "varchar" || new == "character varying")
        {
            return true;
        }

        if pg_version >= 120000
            && (old_base == "numeric" || old_base == "decimal")
            && (new_base == "numeric" || new_base == "decimal")
            && !new.contains('(')
        {
            return true;
        }

        false
    }
}

impl Rule for TypeChangeRewriteRule {
    fn id(&self) -> &'static str {
        "type-change-rewrite"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Changing this column type requires an ACCESS EXCLUSIVE table rewrite. Add a new column, backfill, and swap."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        config: &Config,
        _cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = mutation
            && let AlterTableActionMutation::SetType {
                column,
                ty,
                has_using: _,
            } = &alter.action
        {
            let pg_version = state.pg_version_num.unwrap_or(config.assume_pg_version);

            let (is_safe, rows, old_type_str) = match pre_state.relations.get(&alter.id) {
                Some(rel) => {
                    let old_ty = rel
                        .columns
                        .iter()
                        .find(|c| c.name == *column)
                        .and_then(|col| col.data_type.as_ref());

                    let safe = old_ty
                        .map(|o| Self::is_type_change_safe(o, ty, pg_version))
                        .unwrap_or(false);
                    (
                        safe,
                        rel.estimated_rows.unwrap_or(config.default_rows),
                        old_ty.cloned().unwrap_or_else(|| "unknown".to_string()),
                    )
                }
                None => (false, config.default_rows, "unknown".to_string()),
            };

            if !is_safe {
                let tier1_threshold = config.rule_tier1_threshold(self.id());

                let tier = if rows >= tier1_threshold {
                    ViolationTier::Tier1
                } else {
                    ViolationTier::Tier2
                };

                violations.push(Violation {
                    rule_id: self.id(),
                    title: format!(
                        "Changing column {}.{} type from {} to {} causes a table rewrite",
                        alter.id, column, old_type_str, ty
                    ),
                    tier,
                    recipe: self.recipe(),
                    dedup_key: None,
                });
            }
        }
        violations
    }
}
