use super::{AnalysisState, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterSequenceActionMutation, AlterSequenceMutation, CreateSequenceMutation,
    DropSequenceMutation, SequenceOptionMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::sequence::{
    SequenceKind, SequenceOverlay, SequencePersistence, SequenceState,
};
use std::collections::HashSet;

type SequenceLookup = ObjectLookup;

/// The canonical name and value range of a sequence data type.
pub(super) fn sequence_type(data_type: &str) -> Option<(&'static str, i64, i64)> {
    match data_type.trim().to_ascii_lowercase().as_str() {
        "smallint" | "int2" => Some(("smallint", i16::MIN as i64, i16::MAX as i64)),
        "integer" | "int" | "int4" => Some(("integer", i32::MIN as i64, i32::MAX as i64)),
        "bigint" | "int8" => Some(("bigint", i64::MIN, i64::MAX)),
        _ => None,
    }
}

/// Whether the merged bounds exclude values the old bounds admitted.
fn sequence_bounds_narrowed(
    current: &crate::_internal::model::sequence::SequenceParameters,
    merged: &crate::_internal::model::sequence::SequenceParameters,
) -> bool {
    merged.min_value > current.min_value || merged.max_value < current.max_value
}

/// The runtime check PostgreSQL performs after merging sequence parameters.
///
/// `RESTART` is checked separately by `init_sequence_parameters`; this covers
/// the current value when the statement does not restart the sequence.
fn sequence_runtime_bounds_conflict(
    runtime: &crate::_internal::model::sequence::SequenceRuntime,
    parameters: &crate::_internal::model::sequence::SequenceParameters,
) -> Option<MutationResult> {
    let last_value = runtime.last_value?;
    if last_value < parameters.min_value {
        return Some(MutationResult::conflict(format!(
            "RESTART value ({last_value}) cannot be less than MINVALUE ({})",
            parameters.min_value
        )));
    }
    if last_value > parameters.max_value {
        return Some(MutationResult::conflict(format!(
            "RESTART value ({last_value}) cannot be greater than MAXVALUE ({})",
            parameters.max_value
        )));
    }
    None
}

/// The option bag of a `CREATE`/`ALTER SEQUENCE` statement, keyed the way
/// PostgreSQL keys the underlying `DefElem`s.
#[derive(Default)]
pub(super) struct SequenceOptionSet {
    pub(super) as_type: Option<String>,
    pub(super) increment: Option<i64>,
    pub(super) cycle: Option<bool>,
    pub(super) max_value: Option<Option<i64>>,
    pub(super) min_value: Option<Option<i64>>,
    pub(super) start: Option<i64>,
    pub(super) restart: Option<Option<i64>>,
    pub(super) cache: Option<i64>,
    pub(super) logged: Option<bool>,
}

impl SequenceOptionSet {
    /// The shared shape of `CREATE SEQUENCE` and identity-column options.
    pub(super) fn from_identity_options(
        options: &crate::_internal::analysis::mutations::IdentitySequenceOptionsMutation,
    ) -> Self {
        Self {
            as_type: options.data_type.clone(),
            increment: options.increment,
            cycle: options.cycle,
            max_value: options.max_value,
            min_value: options.min_value,
            start: options.start_value,
            restart: None,
            cache: options.cache_size,
            logged: options.persistence,
        }
    }

    /// The persistence a `LOGGED`/`UNLOGGED` option selects, if any.
    pub(super) fn persistence(&self) -> Option<SequencePersistence> {
        self.logged.map(|logged| {
            if logged {
                SequencePersistence::Permanent
            } else {
                SequencePersistence::Unlogged
            }
        })
    }
}

/// Reject a repeated option and collect the bag by name, as PostgreSQL does
/// before it applies anything.
pub(super) fn sequence_option_set(
    options: &[SequenceOptionMutation],
) -> Result<SequenceOptionSet, MutationResult> {
    let mut seen = std::collections::BTreeSet::new();
    let mut set = SequenceOptionSet::default();
    for option in options {
        if !seen.insert(option.name()) {
            return Err(MutationResult::conflict(format!(
                "conflicting or redundant options: \"{}\" specified more than once",
                option.name()
            )));
        }
        match option {
            SequenceOptionMutation::As(data_type) => set.as_type = Some(data_type.clone()),
            SequenceOptionMutation::Cache(value) => set.cache = Some(*value),
            SequenceOptionMutation::Cycle(value) => set.cycle = Some(*value),
            SequenceOptionMutation::Increment(value) => set.increment = Some(*value),
            SequenceOptionMutation::Logged(value) => set.logged = Some(*value),
            SequenceOptionMutation::MaxValue(value) => set.max_value = Some(*value),
            SequenceOptionMutation::MinValue(value) => set.min_value = Some(*value),
            SequenceOptionMutation::Start(value) => set.start = Some(*value),
            SequenceOptionMutation::Restart(value) => set.restart = Some(*value),
            // Ownership is a graph transition and the sequence name is
            // documentation, neither a sequence parameter.
            SequenceOptionMutation::OwnedBy(_) | SequenceOptionMutation::SequenceName(_) => {}
        }
    }
    Ok(set)
}

/// A literal port of PostgreSQL's `init_params` (`sequence.c`).
///
/// The options form one bag, not a clause sequence: PostgreSQL walks it once
/// to reject a repeated option, then applies the values in a fixed order — data
/// type, increment, cycle, bounds, start, restart, cache — so the textual order
/// of the clauses cannot change the result. `is_init` covers `CREATE SEQUENCE`
/// (and the sequence an identity column generates), where omitted options take
/// defaults; `ALTER SEQUENCE` keeps the current values instead.
pub(super) fn init_sequence_parameters(
    current: &crate::_internal::model::sequence::SequenceParameters,
    options: &SequenceOptionSet,
    is_init: bool,
) -> Result<crate::_internal::model::sequence::SequenceParameters, MutationResult> {
    let mut merged = current.clone();
    // A bare `AS` re-derives a bound that still sat at the old type's limit;
    // an explicit bound always wins.
    let mut reset_max_value = false;
    let mut reset_min_value = false;

    if let Some(data_type) = options.as_type.as_deref() {
        let Some((name, _, _)) = sequence_type(data_type) else {
            return Err(MutationResult::conflict(
                "sequence type must be smallint, integer, or bigint".to_string(),
            ));
        };
        if !is_init && let Some((_, old_min, old_max)) = sequence_type(&current.data_type) {
            reset_max_value = current.max_value == old_max;
            reset_min_value = current.min_value == old_min;
        }
        merged.data_type = name.to_string();
    }
    let Some((_, type_min, type_max)) = sequence_type(&merged.data_type) else {
        return Err(MutationResult::conflict(format!(
            "sequence data type \"{}\" is invalid",
            merged.data_type
        )));
    };

    if let Some(increment) = options.increment {
        if increment == 0 {
            return Err(MutationResult::conflict(
                "INCREMENT must not be zero".to_string(),
            ));
        }
        merged.increment = increment;
    } else if is_init {
        merged.increment = 1;
    }

    if let Some(cycle) = options.cycle {
        merged.cycle = cycle;
    } else if is_init {
        merged.cycle = false;
    }

    match options.max_value {
        Some(Some(maximum)) => merged.max_value = maximum,
        Some(None) if merged.increment > 0 || reset_max_value => merged.max_value = type_max,
        Some(None) => merged.max_value = -1,
        None if is_init || reset_max_value => {
            merged.max_value = if merged.increment > 0 || reset_max_value {
                type_max
            } else {
                -1
            };
        }
        None => {}
    }
    if merged.max_value < type_min || merged.max_value > type_max {
        return Err(MutationResult::conflict(format!(
            "MAXVALUE ({}) is out of range for sequence data type {}",
            merged.max_value, merged.data_type
        )));
    }

    match options.min_value {
        Some(Some(minimum)) => merged.min_value = minimum,
        Some(None) if merged.increment < 0 || reset_min_value => merged.min_value = type_min,
        Some(None) => merged.min_value = 1,
        None if is_init || reset_min_value => {
            merged.min_value = if merged.increment < 0 || reset_min_value {
                type_min
            } else {
                1
            };
        }
        None => {}
    }
    if merged.min_value < type_min || merged.min_value > type_max {
        return Err(MutationResult::conflict(format!(
            "MINVALUE ({}) is out of range for sequence data type {}",
            merged.min_value, merged.data_type
        )));
    }

    if merged.min_value >= merged.max_value {
        return Err(MutationResult::conflict(format!(
            "MINVALUE ({}) must be less than MAXVALUE ({})",
            merged.min_value, merged.max_value
        )));
    }

    if let Some(start) = options.start {
        merged.start_value = start;
    } else if is_init {
        merged.start_value = if merged.increment > 0 {
            merged.min_value
        } else {
            merged.max_value
        };
    }
    if merged.start_value < merged.min_value {
        return Err(MutationResult::conflict(format!(
            "START value ({}) cannot be less than MINVALUE ({})",
            merged.start_value, merged.min_value
        )));
    }
    if merged.start_value > merged.max_value {
        return Err(MutationResult::conflict(format!(
            "START value ({}) cannot be greater than MAXVALUE ({})",
            merged.start_value, merged.max_value
        )));
    }

    // PostgreSQL also cross-checks the sequence's current value after merging.
    // The caller performs that check because it depends on runtime state.
    if let Some(restart) = options.restart {
        let restart = restart.unwrap_or(merged.start_value);
        if restart < merged.min_value {
            return Err(MutationResult::conflict(format!(
                "RESTART value ({restart}) cannot be less than MINVALUE ({})",
                merged.min_value
            )));
        }
        if restart > merged.max_value {
            return Err(MutationResult::conflict(format!(
                "RESTART value ({restart}) cannot be greater than MAXVALUE ({})",
                merged.max_value
            )));
        }
    }

    if let Some(cache) = options.cache {
        if cache <= 0 {
            return Err(MutationResult::conflict(format!(
                "CACHE ({cache}) must be greater than zero"
            )));
        }
        merged.cache_size = cache;
    } else if is_init {
        merged.cache_size = 1;
    }
    Ok(merged)
}

impl AnalysisState {
    fn sequence_literal_matches(raw: &str, sequence: &ObjectId) -> bool {
        let trimmed = raw.trim();
        let value = if let Some(rest) = trimmed.strip_prefix('\'') {
            let mut value = String::new();
            let mut chars = rest.chars();
            while let Some(ch) = chars.next() {
                match ch {
                    '\'' if chars.as_str().starts_with('\'') => {
                        value.push('\'');
                        chars.next();
                    }
                    '\'' => break,
                    other => value.push(other),
                }
            }
            value
        } else {
            trimmed
                .split_once("::")
                .map_or(trimmed, |(value, _)| value)
                .trim_matches('"')
                .to_string()
        };
        let quote = |identifier: &str| format!("\"{}\"", identifier.replace('"', "\"\""));
        [
            format!("{}.{}", sequence.schema, sequence.name),
            format!("{}.{}", quote(&sequence.schema), quote(&sequence.name)),
            format!("{}.{}", sequence.schema, quote(&sequence.name)),
            format!("{}.{}", quote(&sequence.schema), sequence.name),
            sequence.name.clone(),
            quote(&sequence.name),
        ]
        .iter()
        .any(|candidate| candidate == &value)
    }

    pub(super) fn expression_references_sequence(expression: &ExprIr, sequence: &ObjectId) -> bool {
        match expression {
            ExprIr::FunctionCall { name, args } => {
                let is_nextval = name
                    .rsplit('.')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("nextval"));
                (is_nextval
                    && args.first().is_some_and(|argument| {
                        Self::expression_references_sequence(argument, sequence)
                    }))
                    || args
                        .iter()
                        .any(|argument| Self::expression_references_sequence(argument, sequence))
            }
            ExprIr::Literal(value) => Self::sequence_literal_matches(value, sequence),
            ExprIr::BinaryOp { left, right, .. } => {
                Self::expression_references_sequence(left, sequence)
                    || Self::expression_references_sequence(right, sequence)
            }
            ExprIr::Cast { expr, .. } | ExprIr::UnaryOp { expr, .. } => {
                Self::expression_references_sequence(expr, sequence)
            }
            ExprIr::ColumnRef(_) | ExprIr::Sentinel(_) | ExprIr::Omitted => false,
        }
    }

    pub(super) fn expression_contains_nextval(expression: &ExprIr) -> bool {
        match expression {
            ExprIr::FunctionCall { name, args } => {
                name.rsplit('.')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("nextval"))
                    || args.iter().any(Self::expression_contains_nextval)
            }
            ExprIr::BinaryOp { left, right, .. } => {
                Self::expression_contains_nextval(left) || Self::expression_contains_nextval(right)
            }
            ExprIr::Cast { expr, .. } | ExprIr::UnaryOp { expr, .. } => {
                Self::expression_contains_nextval(expr)
            }
            ExprIr::Literal(_) | ExprIr::ColumnRef(_) | ExprIr::Sentinel(_) | ExprIr::Omitted => {
                false
            }
        }
    }

    fn raw_default_references_sequence(raw: &str, sequence: &ObjectId) -> bool {
        let function_present = raw
            .to_ascii_lowercase()
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|token| token == "nextval");
        if !function_present {
            return false;
        }
        let qualified = format!("'{}.{}'", sequence.schema, sequence.name);
        let unqualified = format!("'{}'", sequence.name);
        let quoted_qualified = format!("'\"{}\".\"{}\"'", sequence.schema, sequence.name);
        let quoted_unqualified = format!("'\"{}\"'", sequence.name);
        raw.contains(&qualified)
            || raw.contains(&unqualified)
            || raw.contains(&quoted_qualified)
            || raw.contains(&quoted_unqualified)
            || raw
                .to_ascii_lowercase()
                .contains(&qualified.to_ascii_lowercase())
    }

    pub(super) fn clear_sequence_defaults_on_cascade(
        &mut self,
        sequence: &ObjectId,
        kind: SequenceKind,
        owned_by: Option<(ObjectId, String)>,
    ) {
        // Synchronized defaults carry an exact catalog dependency. Prefer it
        // over rendering-dependent `pg_get_expr` text: an unqualified
        // `regclass` literal can name a same-named sequence in a different
        // schema under the recorded search path.
        let typed_default_columns = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                matches!(edge.kind, DependencyKind::ColumnDefaultOnSequence { .. })
                    && self.local.graph.resolve_rename(&edge.referenced) == sequence
            })
            .map(|edge| match &edge.kind {
                DependencyKind::ColumnDefaultOnSequence { column } => (
                    self.local.graph.resolve_rename(&edge.dependent),
                    column.clone(),
                ),
                _ => unreachable!("filtered default dependency"),
            })
            .collect::<Vec<_>>();
        let typed_default_relation_columns = self
            .local
            .graph
            .edges()
            .iter()
            .filter_map(|edge| match &edge.kind {
                DependencyKind::ColumnDefaultOnSequence { column } => Some((
                    self.local.graph.resolve_rename(&edge.dependent).clone(),
                    column.clone(),
                )),
                _ => None,
            })
            .collect::<HashSet<_>>();

        let relation_ids = self
            .local
            .relations
            .iter()
            .filter_map(|(id, overlay)| {
                matches!(overlay, RelationOverlay::Present(_)).then_some(id.clone())
            })
            .collect::<Vec<_>>();
        let mut columns_to_clear = Vec::new();
        for relation_id in relation_ids {
            let Some(RelationOverlay::Present(relation)) = self.local.relations.get(&relation_id)
            else {
                continue;
            };
            for column in &relation.columns {
                let generated_default = kind == SequenceKind::SerialLike
                    && owned_by
                        .as_ref()
                        .is_some_and(|(table, name)| table == &relation_id && name == &column.name);
                let typed_dependency = typed_default_columns
                    .iter()
                    .any(|(table, name)| *table == &relation_id && name == &column.name);
                let references_sequence = !typed_default_relation_columns
                    .contains(&(relation_id.clone(), column.name.clone()))
                    && (column.default.as_ref().is_some_and(|default| {
                        Self::expression_references_sequence(default, sequence)
                    }) || column.default_expr_text.as_deref().is_some_and(|default| {
                        Self::raw_default_references_sequence(default, sequence)
                    }));
                if generated_default || typed_dependency || references_sequence {
                    columns_to_clear.push((relation_id.clone(), column.name.clone()));
                }
            }
        }
        for (relation_id, column_name) in columns_to_clear {
            self.snapshot_relation(&relation_id);
            if let Some(RelationOverlay::Present(relation)) =
                self.local.relations.get_mut(&relation_id)
                && let Some(column) = relation
                    .columns
                    .iter_mut()
                    .find(|column| column.name == column_name)
            {
                column.default = None;
                column.default_expr_text = None;
            }
        }
    }

    fn sequence_lookup(&self, id: &ObjectId) -> SequenceLookup {
        if self.lookup_shadowed(id) {
            return SequenceLookup::Unknown;
        }
        match self.local.sequences.get(id) {
            Some(SequenceOverlay::Present(_)) => SequenceLookup::Present,
            Some(SequenceOverlay::Dropped) => SequenceLookup::Tombstone,
            None if self.baseline_covers_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Sequences,
            ) =>
            {
                SequenceLookup::AuthoritativelyAbsent
            }
            None => SequenceLookup::Unknown,
        }
    }

    pub(super) fn apply_create_sequence(
        &mut self,
        create: &CreateSequenceMutation,
    ) -> MutationResult {
        if let Err(result) = self.ensure_creation_target(&create.id) {
            return result;
        }
        if create.if_not_exists && self.relation_namespace_is_taken(&create.id) {
            return MutationResult::NoOp;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::conflict(format!("relation '{}' already exists", create.id));
        }
        if let Some((table_id, column)) = &create.owned_by {
            if table_id.schema != create.id.schema {
                return MutationResult::conflict(
                    "sequence must be in the same schema as its owning table".to_string(),
                );
            }
            if let Err(result) = self.ensure_relation_target(
                table_id,
                |kind| *kind == crate::_internal::model::relation::RelationKind::Table,
                format!("relation '{}' does not exist", table_id),
                format!("sequence owner '{}' is not a table", table_id),
            ) {
                return result;
            }
            match self.local.relations.get(table_id) {
                Some(RelationOverlay::Present(table)) => {
                    if !table.has_column(column) {
                        return MutationResult::conflict(format!(
                            "column '{}.{}' does not exist",
                            table_id, column
                        ));
                    }
                    if self.local.current_role_known && table.owner.name != self.local.current_role
                    {
                        return MutationResult::conflict(
                            "sequence and table must have the same owner".to_string(),
                        );
                    }
                }
                _ if self.baseline_covers_family_object(
                    table_id,
                    crate::_internal::db::cache::CatalogFamily::Relations,
                ) =>
                {
                    return MutationResult::conflict(format!(
                        "relation '{}' does not exist",
                        table_id
                    ));
                }
                _ => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
            }
        }
        self.snapshot_sequence(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        let option_set = SequenceOptionSet::from_identity_options(&create.options);
        let mut parameters = match init_sequence_parameters(
            &crate::_internal::model::sequence::SequenceParameters {
                persistence: create.persistence,
                ..Default::default()
            },
            &option_set,
            true,
        ) {
            Ok(parameters) => parameters,
            Err(result) => return result,
        };
        if let Some(persistence) = option_set.persistence() {
            parameters.persistence = persistence;
        }
        let runtime =
            crate::_internal::model::sequence::SequenceRuntime::fresh(parameters.start_value);
        self.local.sequences.insert(
            create.id.clone(),
            SequenceOverlay::Present(SequenceState {
                id: create.id.clone(),
                owner: ObjectId::new("", self.local.current_role.clone()),
                owned_by: create.owned_by.clone(),
                kind: if create.owned_by.is_some() {
                    SequenceKind::Owned
                } else {
                    SequenceKind::Standalone
                },
                parameters,
                runtime,
                runtime_exact: true,
                generation,
            }),
        );
        if let Some((table_id, column)) = &create.owned_by {
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                table_id.clone(),
                DependencyKind::SequenceOwnedBy {
                    column: column.clone(),
                },
            ));
        }
        MutationResult::Applied
    }

    pub(super) fn apply_alter_sequence(&mut self, alter: &AlterSequenceMutation) -> MutationResult {
        match self.sequence_lookup(&alter.id) {
            SequenceLookup::Present => {}
            SequenceLookup::AuthoritativelyAbsent if alter.if_exists => {
                return MutationResult::NoOp;
            }
            SequenceLookup::AuthoritativelyAbsent => {
                return MutationResult::conflict(format!("sequence '{}' does not exist", alter.id));
            }
            SequenceLookup::Tombstone
                if self.baseline_covers_family_object(
                    &alter.id,
                    crate::_internal::db::cache::CatalogFamily::Sequences,
                ) =>
            {
                return MutationResult::conflict(format!("sequence '{}' does not exist", alter.id));
            }
            SequenceLookup::Tombstone if alter.if_exists => return MutationResult::NoOp,
            SequenceLookup::Tombstone | SequenceLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
            SequenceLookup::WrongKind => unreachable!("sequence lookup has no kind predicate"),
        }
        let current = match self.local.sequences.get(&alter.id) {
            Some(SequenceOverlay::Present(sequence)) => sequence.clone(),
            _ => unreachable!("presence checked above"),
        };

        // The value options merge into one parameter set first: a conflict
        // there must be found before the statement's other effects land.
        let option_set = match sequence_option_set(&alter.options) {
            Ok(option_set) => option_set,
            Err(result) => return result,
        };
        let mut merged = match init_sequence_parameters(&current.parameters, &option_set, false) {
            Ok(merged) => merged,
            Err(result) => return result,
        };
        if let Some(logged) = option_set.logged {
            merged.persistence = if logged {
                SequencePersistence::Permanent
            } else {
                SequencePersistence::Unlogged
            };
        }
        let owned_by = alter.options.iter().find_map(|option| match option {
            SequenceOptionMutation::OwnedBy(owned_by) => Some(owned_by),
            _ => None,
        });

        let restart_runtime = option_set.restart.map(|restart| {
            crate::_internal::model::sequence::SequenceRuntime::fresh(
                restart.unwrap_or(merged.start_value),
            )
        });
        if restart_runtime.is_none() {
            if let Some(conflict) = sequence_runtime_bounds_conflict(&current.runtime, &merged) {
                return conflict;
            }
            if sequence_bounds_narrowed(&current.parameters, &merged) && !current.runtime_exact {
                // A synchronized runtime may have advanced past the new bound
                // before this migration ran. The statement still applies, but
                // its success cannot be asserted exactly.
                self.taint(EvidenceCode::BaselineStale, EvidenceScope::Chain);
            }
        }

        if merged != current.parameters || restart_runtime.is_some() {
            self.snapshot_sequence(&alter.id);
            if let Some(SequenceOverlay::Present(sequence)) =
                self.local.sequences.get_mut(&alter.id)
            {
                sequence.parameters = merged;
                if let Some(runtime) = restart_runtime {
                    sequence.runtime = runtime;
                    sequence.runtime_exact = true;
                }
            }
        }

        if let Some(owned_by) = owned_by {
            return self.apply_alter_sequence_owned_by(alter, &current, owned_by);
        }
        match &alter.action {
            Some(AlterSequenceActionMutation::OwnerTo(owner)) => {
                if current.kind == SequenceKind::Identity {
                    return MutationResult::conflict(
                        "cannot alter an identity sequence independently".to_string(),
                    );
                }
                let Some((owner_name, known)) = self.role_fact_identity(owner) else {
                    return self.unresolved(EvidenceCode::UnresolvedReference);
                };
                if known && self.local.roles_known && self.present_role(&owner_name).is_none() {
                    return MutationResult::conflict(format!(
                        "role '{}' does not exist",
                        owner_name
                    ));
                }
                if known && !self.local.roles_known {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
                if let Some((table_id, _)) = &current.owned_by {
                    if let Err(result) = self.ensure_relation_target(
                        table_id,
                        |kind| *kind == crate::_internal::model::relation::RelationKind::Table,
                        format!("relation '{}' does not exist", table_id),
                        format!("sequence owner '{}' is not a table", table_id),
                    ) {
                        return result;
                    }
                    let Some(RelationOverlay::Present(table)) = self.local.relations.get(table_id)
                    else {
                        unreachable!("sequence owner presence checked above");
                    };
                    if table.owner.name != owner_name {
                        return MutationResult::conflict(
                            "sequence and table must have the same owner".to_string(),
                        );
                    }
                }
                self.snapshot_sequence(&alter.id);
                if let Some(SequenceOverlay::Present(sequence)) =
                    self.local.sequences.get_mut(&alter.id)
                {
                    sequence.owner = ObjectId::new("", owner_name);
                }
                MutationResult::Applied
            }
            Some(AlterSequenceActionMutation::RenameTo(new_id))
            | Some(AlterSequenceActionMutation::SetSchema(new_id)) => {
                if current.kind == SequenceKind::Identity {
                    return MutationResult::conflict(
                        "cannot alter an identity sequence independently".to_string(),
                    );
                }
                if let Err(result) = self.ensure_schema_target(&new_id.schema) {
                    return result;
                }
                if self.relation_namespace_is_taken(new_id) {
                    return MutationResult::conflict(format!(
                        "relation '{}' already exists",
                        new_id
                    ));
                }
                if let Some((table_id, _)) = &current.owned_by
                    && table_id.schema != new_id.schema
                {
                    return MutationResult::conflict(
                        "sequence must be in the same schema as its owning table".to_string(),
                    );
                }
                self.snapshot_namespace();
                let mut moved = match self.local.sequences.get(&alter.id) {
                    Some(SequenceOverlay::Present(sequence)) => sequence.clone(),
                    _ => unreachable!("sequence presence checked above"),
                };
                moved.id = new_id.clone();
                self.local.sequences.remove(&alter.id);
                self.local
                    .sequences
                    .insert(new_id.clone(), SequenceOverlay::Present(moved));
                self.local
                    .graph
                    .propagate_sequence_rename(&alter.id, new_id);
                self.local.graph.add_edge(DependencyEdge::new(
                    alter.id.clone(),
                    new_id.clone(),
                    DependencyKind::RenameTo,
                ));
                if self.baseline_sequences.remove(&alter.id) {
                    self.baseline_sequences.insert(new_id.clone());
                }
                MutationResult::Applied
            }
            None => MutationResult::Applied,
        }
    }

    /// The `OWNED BY` option of an `ALTER SEQUENCE`.
    ///
    /// PostgreSQL runs this after the parameter options, so it observes the
    /// sequence as the rest of the statement left it.
    fn apply_alter_sequence_owned_by(
        &mut self,
        alter: &AlterSequenceMutation,
        current: &SequenceState,
        owned_by: &Option<(ObjectId, String)>,
    ) -> MutationResult {
        if current.kind == SequenceKind::Identity {
            return MutationResult::conflict(
                "cannot change ownership of an identity sequence".to_string(),
            );
        }
        if let Some((table_id, column)) = owned_by {
            if table_id.schema != alter.id.schema {
                return MutationResult::conflict(
                    "sequence must be in the same schema as its owning table".to_string(),
                );
            }
            if let Err(result) = self.ensure_relation_target(
                table_id,
                |kind| *kind == crate::_internal::model::relation::RelationKind::Table,
                format!("relation '{}' does not exist", table_id),
                format!("sequence owner '{}' is not a table", table_id),
            ) {
                return result;
            }
            let Some(RelationOverlay::Present(table)) = self.local.relations.get(table_id) else {
                unreachable!("relation target presence checked above");
            };
            if !table.has_column(column) {
                return MutationResult::conflict(format!(
                    "column '{}.{}' does not exist",
                    table_id, column
                ));
            }
            if table.owner != current.owner {
                return MutationResult::conflict(
                    "sequence and table must have the same owner".to_string(),
                );
            }
        }
        self.snapshot_sequence(&alter.id);
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !(matches!(edge.kind, DependencyKind::SequenceOwnedBy { .. })
                && edge.dependent == alter.id)
        });
        if let Some(SequenceOverlay::Present(sequence)) = self.local.sequences.get_mut(&alter.id) {
            sequence.owned_by = owned_by.clone();
            sequence.kind = if owned_by.is_some() {
                SequenceKind::Owned
            } else {
                SequenceKind::Standalone
            };
        }
        if let Some((table_id, column)) = owned_by {
            self.local.graph.add_edge(DependencyEdge::new(
                alter.id.clone(),
                table_id.clone(),
                DependencyKind::SequenceOwnedBy {
                    column: column.clone(),
                },
            ));
        }
        MutationResult::Applied
    }

    pub(super) fn apply_drop_sequence(&mut self, drop: &DropSequenceMutation) -> MutationResult {
        for id in &drop.ids {
            if let Some(result) = self.extension_member_drop_conflict(
                crate::_internal::model::extension::ExtensionMemberKind::Sequence,
                id,
                "sequence",
            ) {
                return result;
            }
        }
        for id in &drop.ids {
            match self.sequence_lookup(id) {
                SequenceLookup::Present => {}
                SequenceLookup::AuthoritativelyAbsent | SequenceLookup::Tombstone
                    if drop.if_exists => {}
                SequenceLookup::AuthoritativelyAbsent | SequenceLookup::Tombstone => {
                    return MutationResult::conflict(format!("sequence '{}' does not exist", id));
                }
                SequenceLookup::Unknown => {
                    // IF EXISTS cannot prove that an out-of-scope object is
                    // absent.  Do not apply the other targets and then claim
                    // an exact state transition.
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
                SequenceLookup::WrongKind => {
                    unreachable!("sequence lookup has no kind predicate")
                }
            }
        }
        let present: Vec<ObjectId> = drop
            .ids
            .iter()
            .filter(|id| self.sequence_is_present(id))
            .cloned()
            .collect();
        if present.is_empty() {
            return MutationResult::NoOp;
        }
        if present.iter().any(|id| {
            self.baseline_sequences.contains(id)
                && (!self.baseline_has_coverage(
                    crate::_internal::db::cache::CatalogFamily::Dependencies,
                ) || self.baseline_scoped_family_object(
                    id,
                    crate::_internal::db::cache::CatalogFamily::Sequences,
                ))
        }) {
            return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
        }
        for id in &present {
            let Some(SequenceOverlay::Present(sequence)) = self.local.sequences.get(id) else {
                continue;
            };
            if sequence.kind == SequenceKind::Identity {
                return MutationResult::conflict(format!(
                    "cannot drop identity sequence '{}' independently",
                    id
                ));
            }
            let has_default_dependencies = self.local.graph.edges().iter().any(|edge| {
                edge.referenced == *id
                    && matches!(edge.kind, DependencyKind::ColumnDefaultOnSequence { .. })
                    && !self
                        .co_dropped_objects
                        .contains(self.local.graph.resolve_rename(&edge.dependent))
            });
            if (sequence.kind == SequenceKind::SerialLike || has_default_dependencies)
                && !drop.cascade
            {
                return MutationResult::conflict(format!(
                    "sequence '{}' still has dependent defaults",
                    id
                ));
            }
        }
        if drop.cascade {
            let sequences = present
                .iter()
                .filter_map(|id| {
                    self.local
                        .sequences
                        .get(id)
                        .and_then(|overlay| match overlay {
                            SequenceOverlay::Present(sequence) => {
                                Some((id.clone(), sequence.kind.clone(), sequence.owned_by.clone()))
                            }
                            SequenceOverlay::Dropped => None,
                        })
                })
                .collect::<Vec<_>>();
            for (id, kind, owned_by) in sequences {
                self.clear_sequence_defaults_on_cascade(&id, kind, owned_by);
            }
        }
        for id in &present {
            self.snapshot_sequence(id);
            self.local
                .sequences
                .insert(id.clone(), SequenceOverlay::Dropped);
        }
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| !match edge.kind {
            DependencyKind::SequenceOwnedBy { .. } => present.contains(&edge.dependent),
            DependencyKind::ColumnDefaultOnSequence { .. } => present.contains(&edge.referenced),
            _ => false,
        });
        MutationResult::Applied
    }
}
