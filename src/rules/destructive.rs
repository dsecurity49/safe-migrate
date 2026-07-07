// FILE: src/rules/destructive.rs
use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
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
                    operation_kind: OperationKind::DropTable,
                    object_kind: ObjectKind::Table,
                    object_name: drop.id.to_string(),
                    tier: self.default_tier(),
                    reason: format!(
                        "DROP TABLE {} CASCADE silently destroys pre-existing database dependencies",
                        drop.id
                    ),
                    recipe: self.recipe(),
                    dedup_key: None,
                            sql: None,
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
                        let stale =
                            rel.is_stale() && state.baseline_relations.contains(&alter.id);
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
                        operation_kind: OperationKind::AddColumn,
                        object_kind: ObjectKind::Table,
                        object_name: alter.id.to_string(),
                        tier: ViolationTier::Tier2,
                        reason: format!(
                            "Table {} statistics are stale. Lock evaluations may be inaccurate.",
                            alter.id
                        ),
                        recipe: "Run ANALYZE to ensure accurate TOAST width and row estimates before structural changes.",
                        dedup_key: Some(key),
                                    sql: None,
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

                let mut reason = if is_volatile {
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
                    reason.push_str(" (Escalated due to wide TOAST columns)");
                }
                if is_stale {
                    reason.push_str(" [WARNING: Based on unknown offline statistics]");
                }

                violations.push(Violation {
                    rule_id: self.id(),
                    operation_kind: OperationKind::AddColumn,
                    object_kind: ObjectKind::Table,
                    object_name: alter.id.to_string(),
                    tier,
                    reason,
                    recipe: self.recipe(),
                    dedup_key: None,
                            sql: None,
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
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        _state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if let Mutation::DropDatabase(d) = mutation {
            return vec![Violation {
                rule_id: self.id(),
                operation_kind: OperationKind::DropDatabase,
                object_kind: ObjectKind::Database,
                object_name: d.id.to_string(),
                tier: self.default_tier(),
                reason: "DROP DATABASE detected".to_string(),
                recipe: self.recipe(),
                dedup_key: None,
                    sql: None,
            }];
        }
        vec![]
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
                operation_kind: OperationKind::DropSchema,
                object_kind: ObjectKind::Schema,
                object_name: drop.names.join(", "),
                tier: self.default_tier(),
                reason: format!("DROP SCHEMA {} CASCADE detected", drop.names.join(", ")),
                recipe: self.recipe(),
                dedup_key: None,
                    sql: None,
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
        _cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if let Mutation::CreateTable(c) = mutation && c.as_select {
            return vec![Violation {
                rule_id: self.id(),
                operation_kind: OperationKind::CreateTable,
                object_kind: ObjectKind::Table,
                object_name: c.id.to_string(),
                tier: self.default_tier(),
                reason: format!("CREATE TABLE AS SELECT detected for {}", c.id),
                recipe: self.recipe(),
                dedup_key: None,
                    sql: None,
            }];
        }
        vec![]
    }
}

pub enum Reversibility {
    Reversible,
    ConditionallyReversible,
    Irreversible,
}

pub fn classify(mutation: &Mutation) -> Reversibility {
    match mutation {
        Mutation::Rename(_) => Reversibility::Reversible,
        Mutation::CreateIndex(_) | Mutation::CreateTable(_) => Reversibility::Reversible,
        Mutation::AlterTable(a) => match &a.action {
            AlterTableActionMutation::AddColumn { .. } => Reversibility::Reversible,
            AlterTableActionMutation::DropColumn { .. } => Reversibility::Irreversible,
            AlterTableActionMutation::SetType { .. } => Reversibility::ConditionallyReversible,
            _ => Reversibility::Reversible,
        },
        Mutation::DropTable(_) | Mutation::DropDatabase(_) => Reversibility::Irreversible,
        _ => Reversibility::ConditionallyReversible,
    }
}

pub struct ReversibilityRule;

impl Rule for ReversibilityRule {
    fn id(&self) -> &'static str {
        "irreversible-migration"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "This operation is irreversible. Ensure backups are available."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        config: &Config,
        _cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Mutation::AlterTable(a) = mutation
            && let AlterTableActionMutation::SetType { column, ty, .. } = &a.action
            && let Some(rel) = pre_state.relations.get(&a.id)
            && let Some(old_ty) = rel.get_column(column).and_then(|c| c.data_type.as_ref())
        {
            // Only flag as "conditionally reversible" if there's actual data loss risk
            // (e.g., narrowing, not widening). Table rewrites are handled by TypeChangeRewriteRule.
            if is_type_change_lossy(old_ty, ty) {
                let rows = rel.estimated_rows.unwrap_or(config.default_rows);
                let tier = if rows >= config.rule_tier1_threshold(self.id()) {
                    ViolationTier::Tier1
                } else {
                    ViolationTier::Tier2
                };
                violations.push(Violation {
                    rule_id: self.id(),
                    operation_kind: OperationKind::AlterColumnType,
                    object_kind: ObjectKind::Table,
                    object_name: a.id.to_string(),
                    tier,
                    reason: "Conditionally reversible type change detected".to_string(),
                    recipe: "This type change may be lossy. Verify data compatibility.",
                    dedup_key: None,
                            sql: None,
                });
            }
        }

        if let Reversibility::Irreversible = classify(mutation) {
            let mut rows = if let Mutation::AlterTable(a) = mutation {
                pre_state
                    .relations
                    .get(&a.id)
                    .and_then(|r| r.estimated_rows)
                    .unwrap_or(config.default_rows)
            } else if let Mutation::DropTable(d) = mutation {
                pre_state
                    .relations
                    .get(&d.id)
                    .and_then(|r| r.estimated_rows)
                    .unwrap_or(config.default_rows)
            } else {
                config.default_rows
            };

            if let Mutation::AlterTable(a) = mutation
                && let AlterTableActionMutation::DropColumn { name, .. } = &a.action
                && state.column_was_added_in_transaction(&a.id, name)
            {
                rows = 0;
            }

            let tier = if rows == 0 {
                ViolationTier::Tier3
            } else {
                ViolationTier::Tier1
            };

            // Determine operation_kind and object_name from the mutation
            let (operation_kind, object_kind, object_name) = match mutation {
                Mutation::AlterTable(a) => match &a.action {
                    AlterTableActionMutation::DropColumn { .. } => (
                        OperationKind::DropColumn,
                        ObjectKind::Table,
                        a.id.to_string(),
                    ),
                    _ => (
                        OperationKind::Other("irreversible".to_string()),
                        ObjectKind::Table,
                        a.id.to_string(),
                    ),
                },
                Mutation::DropTable(d) => {
                    (OperationKind::DropTable, ObjectKind::Table, d.id.to_string())
                }
                Mutation::DropDatabase(d) => (
                    OperationKind::DropDatabase,
                    ObjectKind::Database,
                    d.id.to_string(),
                ),
                _ => (
                    OperationKind::Other("irreversible".to_string()),
                    ObjectKind::Unknown,
                    "unknown".to_string(),
                ),
            };

            violations.push(Violation {
                rule_id: self.id(),
                operation_kind,
                object_kind,
                object_name,
                tier,
                reason: "Irreversible data-destructive operation detected".to_string(),
                recipe: self.recipe(),
                dedup_key: None,
                    sql: None,
            });
        }
        violations
    }
}

/// Checks if a type change represents actual data loss (narrowing), not just a rewrite.
/// This is used by ReversibilityRule to distinguish between "safe widening" (e.g., INT->BIGINT)
/// and genuinely lossy changes (e.g., BIGINT->INT, VARCHAR(255)->VARCHAR(50)).
fn is_type_change_lossy(old_type: &str, new_type: &str) -> bool {
    let old = old_type.to_lowercase().trim().to_string();
    let new = new_type.to_lowercase().trim().to_string();

    // Same type is trivially safe
    if old == new {
        return false;
    }

    // Extract base types (without parameters)
    let old_base = old.split('(').next().unwrap_or(&old).trim();
    let new_base = new.split('(').next().unwrap_or(&new).trim();

    // VARCHAR narrowing check
    if let (Some(old_lim), Some(new_lim)) =
        (extract_varchar_limit(&old), extract_varchar_limit(&new))
    {
        // Both are varchar - check if narrowing
        return new_lim < old_lim;
    }

    // Varchar to something smaller/narrower - check if target type can hold all values
    let old_varchar_limit = extract_varchar_limit(&old);
    if old_varchar_limit.is_some() {
        // varchar -> text is safe (widening)
        if new == "text" || new == "varchar" || new == "character varying" {
            return false;
        }
        // varchar -> other types might be lossy
        return true;
    }

    // Widening integer types are safe (though they require a rewrite)
    // int2 (smallint) -> int4 -> int8 (bigint) are all safe
    if let (Some(old_sz), Some(new_sz)) = (
        integer_type_size_bits(old_base),
        integer_type_size_bits(new_base),
    ) {
        // Narrowing is unsafe
        return new_sz < old_sz;
    }

    // For other types, assume safe unless we have specific knowledge
    false
}

/// Extracts the character limit from a varchar type string.
/// Returns the limit in bytes (for comparison purposes).
fn extract_varchar_limit(ty: &str) -> Option<i32> {
    if ty.starts_with("varchar(") || ty.starts_with("character varying(") {
        let paren_start = ty.find('(')?;
        let paren_end = ty[paren_start..].find(')')?;
        let num_str = &ty[paren_start + 1..paren_start + paren_end];
        let limit: i32 = num_str.parse().ok()?;
        Some(limit)
    } else if ty == "varchar" || ty == "character varying" {
        // VARCHAR without limit is like TEXT - unbounded
        None
    } else {
        None
    }
}

/// Returns the size of integer types in bits.
fn integer_type_size_bits(ty: &str) -> Option<i32> {
    match ty {
        "smallint" | "int2" => Some(16),
        "integer" | "int4" | "int" => Some(32),
        "bigint" | "int8" => Some(64),
        _ => None,
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
        let cascade_info: Option<(OperationKind, ObjectKind, String)> = match mutation {
            Mutation::DropView(d) if d.cascade => Some((
                OperationKind::DropView,
                ObjectKind::View,
                d.ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", "),
            )),
            Mutation::DropMaterializedView(d) if d.cascade => Some((
                OperationKind::DropMaterializedView,
                ObjectKind::MaterializedView,
                d.ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", "),
            )),
            Mutation::DropSequence(d) if d.cascade => Some((
                OperationKind::DropSequence,
                ObjectKind::Sequence,
                d.ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", "),
            )),
            Mutation::DropDomain(d) if d.cascade => Some((
                OperationKind::DropDomain,
                ObjectKind::Domain,
                d.ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", "),
            )),
            Mutation::DropFunction(d) if d.cascade => Some((
                OperationKind::DropFunction,
                ObjectKind::Function,
                "function".to_string(),
            )),
            Mutation::DropProcedure(d) if d.cascade => Some((
                OperationKind::DropProcedure,
                ObjectKind::Procedure,
                "procedure".to_string(),
            )),
            Mutation::DropPublication(d) if d.cascade => Some((
                OperationKind::DropPublication,
                ObjectKind::Publication,
                d.names.join(", "),
            )),
            _ => None,
        };

        if let Some((operation_kind, object_kind, object_name)) = cascade_info {
            return vec![Violation {
                rule_id: self.id(),
                operation_kind,
                object_kind,
                object_name,
                tier: self.default_tier(),
                reason: "Destructive CASCADE operation detected".to_string(),
                recipe: self.recipe(),
                dedup_key: None,
                    sql: None,
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
        {
            if new == "text" || new == "varchar" || new == "character varying" {
                return true;
            }
            if let Some(old_mod) = extract_type_modifier_from_type_string(&old)
                && let Some(new_mod) = extract_type_modifier_from_type_string(&new)
                && old_mod <= new_mod
            {
                return true;
            }
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

    /// Detects whether a type change narrows a VARCHAR(n) column
    /// using type_modifier values from the cache.
    ///
    /// atttypmod for VARCHAR(n) encodes the length limit:
    ///   typmod = (limit + 4) for VARCHAR, so limit = typmod - 4
    ///
    /// A smaller typmod means a smaller limit, which is lossy.
    /// Returns true if the new modifier represents a smaller limit than the old.
    pub fn is_lossy_varchar_narrowing(old_modifier: Option<i32>, new_modifier: Option<i32>) -> bool {
        match (old_modifier, new_modifier) {
            (Some(old), Some(new)) => new < old,
            (None, Some(_)) => true,
            _ => false,
        }
    }
}

/// Extracts a synthetic type_modifier-like value from a type string.
/// Used when the new type comes from the migration SQL (not from the cache).
/// For varchar(N) types, approximates the atttypmod value.
pub fn extract_type_modifier_from_type_string(ty: &str) -> Option<i32> {
    let lower = ty.to_lowercase().trim().to_string();
    // Check for varchar(N) or character varying(N)
    if lower.starts_with("varchar(") || lower.starts_with("character varying(") {
        let paren_start = lower.find('(')?;
        let paren_end = lower[paren_start..].find(')')?;
        let num_str = &lower[paren_start + 1..paren_start + paren_end];
        let limit: i32 = num_str.parse().ok()?;
        // atttypmod = limit + 4 for varchar
        Some(limit + 4)
    } else {
        None
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

            let (is_safe, rows, old_type_str, old_modifier) =
                match pre_state.relations.get(&alter.id) {
                    Some(rel) => {
                        let col_info = rel.columns.iter().find(|c| c.name == *column);
                        let old_ty = col_info.and_then(|col| col.data_type.as_ref());

                        let safe = old_ty
                            .map(|o| Self::is_type_change_safe(o, ty, pg_version))
                            .unwrap_or(false);
                        (
                            safe,
                            rel.estimated_rows.unwrap_or(config.default_rows),
                            old_ty.cloned().unwrap_or_else(|| "unknown".to_string()),
                            col_info.and_then(|col| col.type_modifier),
                        )
                    }
                    None => (false, config.default_rows, "unknown".to_string(), None),
                };

            if !is_safe {
                let tier1_threshold = config.rule_tier1_threshold(self.id());

                let tier = if rows >= tier1_threshold {
                    ViolationTier::Tier1
                } else {
                    ViolationTier::Tier2
                };

                let new_modifier = extract_type_modifier_from_type_string(ty);

                if Self::is_lossy_varchar_narrowing(old_modifier, new_modifier) {
                    violations.push(Violation {
                        rule_id: self.id(),
                        operation_kind: OperationKind::AlterColumnType,
                        object_kind: ObjectKind::Table,
                        object_name: format!("{}.{}", alter.id, column),
                        tier,
                        reason: format!(
                            "Changing column {}.{} type from {} to {} narrows VARCHAR precision (lossy)",
                            alter.id, column, old_type_str, ty
                        ),
                        recipe: "Narrowing VARCHAR(n) precision may cause data truncation. Consider adding a new column, backfilling, and then dropping the old one.",
                        dedup_key: None,
                                    sql: None,
                    });
                } else {
                    violations.push(Violation {
                        rule_id: self.id(),
                        operation_kind: OperationKind::AlterColumnType,
                        object_kind: ObjectKind::Table,
                        object_name: format!("{}.{}", alter.id, column),
                        tier,
                        reason: format!(
                            "Changing column {}.{} type from {} to {} causes a table rewrite",
                            alter.id, column, old_type_str, ty
                        ),
                        recipe: self.recipe(),
                        dedup_key: None,
                                    sql: None,
                    });
                }
            }
        }
        violations
    }
}
