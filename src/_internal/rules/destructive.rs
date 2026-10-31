use crate::_internal::analysis::mutations::{
    AlterTableActionMutation, AlterTypeActionMutation, Mutation,
};
use crate::_internal::analysis::state::MutationResult;
use crate::_internal::model::builtin_type::BuiltinTypeCatalogue;
use crate::_internal::model::data_type::{ParsedDataType, TypeIdentity};
use crate::_internal::model::types::TypeKind;
use crate::_internal::report::violations::{ObjectKind, Violation, ViolationTier};
use crate::_internal::rules::{
    BASELINE_RELATION_CAPABILITIES, BASELINE_STATS_CAPABILITIES, Rule, RuleCapability, RuleContext,
};

pub(crate) const IRREVERSIBLE_MIGRATION_RULE_ID: &str = "irreversible-migration";

pub(crate) struct CascadingDropRule;

impl Rule for CascadingDropRule {
    fn id(&self) -> &'static str {
        "destructive-cascade"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Avoid CASCADE on DROP in production. Handle dependencies explicitly."
    }

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        BASELINE_RELATION_CAPABILITIES
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let mutation = context.mutation();
        let result = context.result();
        let pre_state = context.pre_state();
        let state = context.state();
        let cascade_closure = context.cascade_closure();
        let mut violations = Vec::new();

        if let Mutation::DropType(drop) = mutation
            && drop.cascade
        {
            for id in &drop.ids {
                violations.push(Violation {
                    source_range: None,
                    rule_id: self.id(),

                    object_kind: ObjectKind::Type,
                    object_name: id.to_string(),
                    tier: self.default_tier(),
                    reason: format!(
                        "DROP TYPE {} CASCADE destroys all columns using this type",
                        id
                    ),
                    recipe: self.recipe(),
                    dedup_key: None,
                    sql: None,
                });
            }
        }

        if !matches!(result, MutationResult::Conflict(_))
            && let Mutation::DropTable(drop) = mutation
            && drop.cascade
            && let Some(closure) = cascade_closure
        {
            let mut affects_baseline = false;
            let mut has_fk_pulled = false;

            let roots = drop.ids.iter().collect::<std::collections::HashSet<_>>();
            for rel_id in &closure.dropped_relations {
                if !roots.contains(rel_id) && state.baseline_relation_is_known(rel_id) {
                    affects_baseline = true;
                    if state.baseline_fk_dependency_is_known(rel_id) {
                        has_fk_pulled = true;
                    }
                }
            }

            if !affects_baseline {
                for (from_table, cname) in &closure.dropped_constraints {
                    if pre_state
                        .baseline_foreign_keys
                        .contains(&(from_table.clone(), cname.clone()))
                    {
                        affects_baseline = true;
                        break;
                    }
                }
            }

            for (from_table, _cname) in &closure.dropped_constraints {
                if state.baseline_fk_dependency_is_known(from_table) {
                    has_fk_pulled = true;
                }
            }

            if affects_baseline {
                let mut reason = format!(
                    "DROP TABLE {} CASCADE silently destroys pre-existing database dependencies",
                    drop.ids
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                if has_fk_pulled {
                    reason.push_str(
                        " (includes FK-pulled tables from other schemas — cross-team impact)",
                    );
                }
                violations.push(Violation {
                    source_range: None,
                    rule_id: self.id(),

                    object_kind: ObjectKind::Table,
                    object_name: drop
                        .ids
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                    tier: self.default_tier(),
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

pub(crate) struct SizeAwareAddColumnRule;

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

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        BASELINE_STATS_CAPABILITIES
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        // The statement was skipped, so no column was added and nothing is rewritten.
        if context.result().is_noop() {
            return vec![];
        }
        let mutation = context.mutation();
        let pre_state = context.pre_state();
        let state = context.state();
        let config = context.config();

        let mut violations = Vec::new();
        let pg_version = state.pg_version().conservative_num();

        if let Mutation::AlterTable(alter) = mutation
            && let AlterTableActionMutation::AddColumn {
                default,
                generation,
                ..
            } = &alter.action
        {
            let is_volatile = default.as_ref().is_some_and(|def| def.is_volatile());
            let is_stored_generated = matches!(
                generation,
                crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
            );
            let is_identity = matches!(
                generation,
                crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
                    | crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault
            );

            let requires_rewrite = is_volatile
                || is_stored_generated
                || is_identity
                || (default.is_some() && pg_version < 110000);

            if requires_rewrite {
                let (has_wide_columns, is_stale, rows) = match pre_state.relations.get(&alter.id) {
                    Some(rel) => {
                        let wide = rel.columns.iter().any(|c| {
                            c.avg_width.unwrap_or(0) >= config.toast_width_threshold_bytes
                        });
                        // Only cache-backed relations have meaningful statistics age.
                        let stale = rel.is_stale() && state.baseline_relation_is_known(&alter.id);
                        (
                            wide,
                            stale,
                            rel.estimated_rows.unwrap_or(config.default_rows),
                        )
                    }
                    None => {
                        // Missing relation metadata uses the conservative fallback.
                        (false, true, config.default_rows)
                    }
                };

                if is_stale {
                    let key = format!("{}_stale_{}", self.id(), alter.id);
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),

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
                } else if is_stored_generated {
                    format!(
                        "Adding a STORED generated column to {} triggers a table rewrite",
                        alter.id
                    )
                } else if is_identity {
                    format!(
                        "Adding an identity column to {} triggers a table rewrite",
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
                    source_range: None,
                    rule_id: self.id(),

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

pub(crate) struct DropDatabaseRule;

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

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let mutation = context.mutation();
        if let Mutation::DropDatabase(d) = mutation {
            return vec![Violation {
                source_range: None,
                rule_id: self.id(),

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

pub(crate) struct DropSchemaCascadeRule;

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

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let mutation = context.mutation();
        let mut violations = Vec::new();

        if let Mutation::DropSchema(drop) = mutation
            && drop.cascade
        {
            violations.push(Violation {
                source_range: None,
                rule_id: self.id(),

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

pub(crate) struct CreateTableAsSelectRule;

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

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let mutation = context.mutation();
        let result = context.result();
        if result.is_noop() {
            return vec![];
        }
        if let Mutation::CreateTable(c) = mutation
            && c.as_select
        {
            return vec![Violation {
                source_range: None,
                rule_id: self.id(),

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

pub(crate) enum Reversibility {
    Reversible,
    ConditionallyReversible,
    Irreversible,
}

pub(crate) fn classify(mutation: &Mutation) -> Reversibility {
    match mutation {
        Mutation::Rename(_) => Reversibility::Reversible,
        Mutation::CreateIndex(_) | Mutation::CreateTable(_) => Reversibility::Reversible,
        Mutation::AlterTable(a) => match &a.action {
            AlterTableActionMutation::AddColumn { .. } => Reversibility::Reversible,
            AlterTableActionMutation::DropColumn { .. } => Reversibility::Irreversible,
            AlterTableActionMutation::SetType { .. } => Reversibility::ConditionallyReversible,
            _ => Reversibility::Reversible,
        },
        Mutation::DropTable(_) | Mutation::DropDatabase(_) | Mutation::Truncate(_) => {
            Reversibility::Irreversible
        }
        _ => Reversibility::ConditionallyReversible,
    }
}

pub(crate) struct ReversibilityRule;

impl Rule for ReversibilityRule {
    fn id(&self) -> &'static str {
        IRREVERSIBLE_MIGRATION_RULE_ID
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "This operation is irreversible. Ensure backups are available."
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let mutation = context.mutation();
        let result = context.result();
        let pre_state = context.pre_state();
        let state = context.state();
        let config = context.config();
        let skipped_known_drop_column = result.is_unresolved()
            && matches!(
                mutation,
                Mutation::AlterTable(crate::_internal::analysis::mutations::AlterTable {
                    id: _,
                    action: AlterTableActionMutation::DropColumn { .. },
                    ..
                })
            )
            && matches!(
                mutation,
                Mutation::AlterTable(alter)
                    if pre_state.relations.get(&alter.id).is_some_and(|relation| {
                        matches!(
                            &alter.action,
                            AlterTableActionMutation::DropColumn { name, .. }
                                if relation.has_column(name)
                        )
                    })
            );
        if *result != MutationResult::Applied && !skipped_known_drop_column {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::AlterTable(a) = mutation
            && let AlterTableActionMutation::SetType { column, ty, .. } = &a.action
            && let Some(rel) = pre_state.relations.get(&a.id)
            && let Some(old_ty) = rel.get_column(column).and_then(|c| c.data_type.as_ref())
        {
            // Only flag as "conditionally reversible" if there's actual data loss risk
            // (e.g., narrowing, not widening). Table rewrites are handled by TypeChangeRewriteRule.
            if is_type_change_lossy(old_ty, ty, state.builtin_types()) {
                let rows = rel.estimated_rows.unwrap_or(config.default_rows);
                let tier = if rows >= config.rule_tier1_threshold(self.id()) {
                    ViolationTier::Tier1
                } else {
                    ViolationTier::Tier2
                };
                violations.push(Violation {
                    source_range: None,
                    rule_id: self.id(),

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
            // DropDatabaseRule owns this finding.
            if matches!(mutation, Mutation::DropDatabase(_)) {
                return violations;
            }
            let mut rows = if let Mutation::AlterTable(a) = mutation {
                pre_state
                    .relations
                    .get(&a.id)
                    .and_then(|r| r.estimated_rows)
                    .unwrap_or(config.default_rows)
            } else if let Mutation::DropTable(d) = mutation {
                d.ids
                    .iter()
                    .filter_map(|id| pre_state.relations.get(id).and_then(|r| r.estimated_rows))
                    .max()
                    .unwrap_or(config.default_rows)
            } else if let Mutation::Truncate(truncate) = mutation {
                truncate
                    .targets
                    .iter()
                    .filter_map(|target| {
                        pre_state
                            .relations
                            .get(&target.id)
                            .and_then(|relation| relation.estimated_rows)
                    })
                    .max()
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

            // Determine object_kind and object_name from the mutation
            let (object_kind, object_name) = match mutation {
                Mutation::AlterTable(a) => match &a.action {
                    AlterTableActionMutation::DropColumn { .. } => {
                        (ObjectKind::Table, a.id.to_string())
                    }
                    _ => (ObjectKind::Table, a.id.to_string()),
                },
                Mutation::DropTable(d) => (
                    ObjectKind::Table,
                    d.ids
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                Mutation::DropDatabase(d) => (ObjectKind::Database, d.id.to_string()),
                Mutation::Truncate(truncate) => (
                    ObjectKind::Table,
                    truncate
                        .targets
                        .iter()
                        .map(|target| target.id.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                _ => (ObjectKind::Table, "unknown".to_string()),
            };

            violations.push(Violation {
                source_range: None,
                rule_id: self.id(),
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
/// and genuinely lossy changes (e.g., BIGINT->INT, VARCHAR(255)->VARCHAR(50), TEXT->VARCHAR(n)).
fn is_type_change_lossy(old_type: &str, new_type: &str, catalogue: &BuiltinTypeCatalogue) -> bool {
    let old_parsed = ParsedDataType::parse(old_type, catalogue);
    let new_parsed = ParsedDataType::parse(new_type, catalogue);
    old_parsed.is_lossy_narrowing_to(&new_parsed)
}

pub(crate) struct GeneralCascadeRule;

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

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let mutation = context.mutation();
        let cascade_info: Option<(ObjectKind, String)> = match mutation {
            Mutation::DropView(d) if d.cascade => Some((
                ObjectKind::View,
                d.ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
            Mutation::DropMaterializedView(d) if d.cascade => Some((
                ObjectKind::MaterializedView,
                d.ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
            Mutation::DropSequence(d) if d.cascade => Some((
                ObjectKind::Sequence,
                d.ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
            Mutation::DropDomain(d) if d.cascade => Some((
                ObjectKind::Domain,
                d.ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
            Mutation::DropFunction(d) if d.cascade => {
                Some((ObjectKind::Function, "function".to_string()))
            }
            Mutation::DropProcedure(d) if d.cascade => {
                Some((ObjectKind::Procedure, "procedure".to_string()))
            }
            Mutation::DropPublication(d) if d.cascade => {
                Some((ObjectKind::Publication, d.names.join(", ")))
            }
            Mutation::DropExtension(d) if d.cascade => {
                Some((ObjectKind::Extension, d.names.join(", ")))
            }
            Mutation::AlterType(a) => match &a.action {
                crate::_internal::analysis::mutations::AlterTypeActionMutation::DropAttribute {
                    cascade,
                    ..
                }
                | crate::_internal::analysis::mutations::AlterTypeActionMutation::AlterAttributeType {
                    cascade,
                    ..
                } if *cascade => Some((ObjectKind::Type, a.id.to_string())),
                _ => None,
            },
            _ => None,
        };

        if let Some((object_kind, object_name)) = cascade_info {
            return vec![Violation {
                source_range: None,
                rule_id: self.id(),
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

pub(crate) struct TypeChangeRewriteRule;

impl TypeChangeRewriteRule {
    fn is_type_change_safe(
        old_type: &str,
        new_type: &str,
        pg_version: u32,
        catalogue: &BuiltinTypeCatalogue,
    ) -> bool {
        let old_dt = ParsedDataType::parse(old_type, catalogue);
        let new_dt = ParsedDataType::parse(new_type, catalogue);

        // Two spellings of one catalog type carrying one modifier are one type. An
        // array renders with a single `[]` whatever the declaration carried.
        if TypeIdentity::from_syntax(&old_dt).render()
            == TypeIdentity::from_syntax(&new_dt).render()
            && old_dt.raw_typmods() == new_dt.raw_typmods()
        {
            return true;
        }

        // Only a variable-length target can lengthen without a rewrite. `char`
        // is blank-padded and its length coercion has no support function, so
        // every `character(n)` change re-encodes each value.
        let fixed_char = |parsed: &ParsedDataType| parsed.is_named("bpchar");
        if old_dt.is_text_like()
            && new_dt.is_text_like()
            && !fixed_char(&old_dt)
            && !fixed_char(&new_dt)
        {
            if new_dt.is_named("text") || !new_dt.has_typmod() {
                return true;
            }
            if let (Some(old_limit), Some(new_limit)) =
                (old_dt.character_limit(), new_dt.character_limit())
                && old_limit <= new_limit
            {
                return true;
            }
        }

        // A numeric keeps its digits when precision rises and the scale is
        // unchanged, or when the constraint is dropped entirely. Changing the
        // scale re-encodes every value.
        if pg_version >= 120_000 && old_dt.is_exact_numeric() && new_dt.is_exact_numeric() {
            match (old_dt.numeric_params(), new_dt.numeric_params()) {
                (_, None) => return true,
                (Some((old_p, old_s)), Some((new_p, new_s)))
                    if new_p >= old_p && new_s == old_s =>
                {
                    return true;
                }
                _ => {}
            }
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

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        BASELINE_STATS_CAPABILITIES
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let mutation = context.mutation();
        let result = context.result();
        let pre_state = context.pre_state();
        let state = context.state();
        let config = context.config();
        // A skipped type change against a present relation can mean that the
        // baseline did not expose enough column/type evidence to mutate state.
        // Keep the rewrite warning conservative in that case; silently
        // dropping it would turn an uncertain ACCESS EXCLUSIVE operation into
        // a false clean result. Other skipped mutations remain non-events.
        if result.is_unresolved()
            && !matches!(
                mutation,
                Mutation::AlterTable(crate::_internal::analysis::mutations::AlterTable {
                    action: AlterTableActionMutation::SetType { .. },
                    ..
                }) | Mutation::AlterType(
                    crate::_internal::analysis::mutations::AlterTypeMutation {
                        action: AlterTypeActionMutation::AlterAttributeType { .. },
                        ..
                    }
                )
            )
        {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = mutation
            && let AlterTableActionMutation::SetType {
                column,
                ty,
                has_using,
            } = &alter.action
        {
            let pg_version = state.pg_version().conservative_num();

            let (is_safe, rows, old_type_str) = match pre_state.relations.get(&alter.id) {
                Some(rel) => {
                    let col_info = rel.columns.iter().find(|c| c.name == *column);
                    let old_ty = col_info.and_then(|col| col.data_type.as_ref());

                    // A USING expression always forces a full table rewrite.
                    let safe = !has_using
                        && old_ty
                            .map(|o| {
                                Self::is_type_change_safe(o, ty, pg_version, state.builtin_types())
                            })
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

                if is_type_change_lossy(&old_type_str, ty, state.builtin_types()) {
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),

                        object_kind: ObjectKind::Table,
                        object_name: alter.id.column_name(column),
                        tier,
                        reason: format!(
                            "Changing column {}.{} type from {} to {} truncates data (lossy narrowing)",
                            alter.id, column, old_type_str, ty
                        ),
                        recipe: "Narrowing a data type may cause data truncation. Consider adding a new column, backfilling, and then dropping the old one.",
                        dedup_key: None,
                                    sql: None,

                    });
                } else {
                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),

                        object_kind: ObjectKind::Table,
                        object_name: alter.id.column_name(column),
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

        if let Mutation::AlterType(alter) = mutation
            && let AlterTypeActionMutation::AlterAttributeType {
                name, data_type, ..
            } = &alter.action
        {
            let field_type = pre_state
                .types
                .get(&alter.id)
                .and_then(|ty| match &ty.kind {
                    TypeKind::Composite { fields } => fields
                        .iter()
                        .find(|field| field.name == *name)
                        .map(|field| field.data_type.as_str()),
                    _ => None,
                });
            let mut rows: Option<u64> = None;
            let mut rewrites_typed_table = false;
            if let Some(old_type) = field_type {
                for relation in pre_state.relations.values() {
                    if relation.of_type.as_ref() == Some(&alter.id) && relation.has_column(name) {
                        rewrites_typed_table = true;
                        let table_rows = relation.estimated_rows.unwrap_or(config.default_rows);
                        rows = Some(rows.map_or(table_rows, |current| current.max(table_rows)));
                    }
                }
                if rewrites_typed_table
                    && !Self::is_type_change_safe(
                        old_type,
                        data_type,
                        state.pg_version().conservative_num(),
                        state.builtin_types(),
                    )
                {
                    let rows = rows.unwrap_or(config.default_rows);
                    let tier = if rows >= config.rule_tier1_threshold(self.id()) {
                        ViolationTier::Tier1
                    } else {
                        ViolationTier::Tier2
                    };
                    let lossy = is_type_change_lossy(old_type, data_type, state.builtin_types());
                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        object_kind: ObjectKind::Type,
                        object_name: format!("{}.{}", alter.id, name),
                        tier,
                        reason: if lossy {
                            format!(
                                "Changing composite field {}.{} type from {} to {} truncates data (lossy narrowing) and rewrites every typed table",
                                alter.id, name, old_type, data_type
                            )
                        } else {
                            format!(
                                "Changing composite field {}.{} type from {} to {} rewrites every typed table",
                                alter.id, name, old_type, data_type
                            )
                        },
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
