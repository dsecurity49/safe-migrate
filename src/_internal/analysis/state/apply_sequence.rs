use super::{AnalysisState, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterSequenceActionMutation, AlterSequenceMutation, CreateSequenceMutation,
    DropSequenceMutation, SequenceOptionMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::sequence::{SequenceKind, SequenceOverlay, SequenceState};
use std::collections::HashSet;

type SequenceLookup = ObjectLookup;

/// The value range a sequence data type admits, which is what bounds an
/// omitted `MINVALUE` or `MAXVALUE`.
fn sequence_type_bounds(data_type: &str) -> Option<(i64, i64)> {
    match data_type.trim().to_ascii_lowercase().as_str() {
        "smallint" | "int2" => Some((i16::MIN as i64, i16::MAX as i64)),
        "integer" | "int" | "int4" => Some((i32::MIN as i64, i32::MAX as i64)),
        "bigint" | "int8" => Some((i64::MIN, i64::MAX)),
        _ => None,
    }
}

/// The parameter set an `ALTER SEQUENCE` statement produces.
///
/// PostgreSQL merges every option into one parameter set and then cross-checks
/// the result, so the options are not independent clauses: a repeated option is
/// rejected, and an omitted bound follows the increment's sign.
fn merged_sequence_parameters(
    current: &crate::_internal::model::sequence::SequenceParameters,
    options: &[SequenceOptionMutation],
) -> Result<crate::_internal::model::sequence::SequenceParameters, MutationResult> {
    use crate::_internal::model::sequence::SequencePersistence;

    let mut seen = std::collections::BTreeSet::new();
    for option in options {
        if !seen.insert(option.name()) {
            return Err(MutationResult::conflict(format!(
                "conflicting or redundant options: \"{}\" specified more than once",
                option.name()
            )));
        }
    }

    let mut merged = current.clone();
    // A changed data type re-derives bounds that still sat at the old type's
    // limits, which is what PostgreSQL's reset_max_value/reset_min_value do.
    let mut reset_bounds = false;
    for option in options {
        match option {
            SequenceOptionMutation::As(data_type) => {
                let Some(new_bounds) = sequence_type_bounds(data_type) else {
                    return Err(MutationResult::conflict(format!(
                        "sequence data type \"{}\" is invalid",
                        data_type
                    )));
                };
                if let Some((_, old_max)) = sequence_type_bounds(&current.data_type)
                    && current.max_value == old_max
                {
                    reset_bounds = true;
                }
                if let Some((old_min, _)) = sequence_type_bounds(&current.data_type)
                    && current.min_value == old_min
                {
                    reset_bounds = true;
                }
                merged.data_type = data_type.clone();
                let _ = new_bounds;
            }
            SequenceOptionMutation::Cache(value) => {
                if *value <= 0 {
                    return Err(MutationResult::conflict(
                        "CACHE must be greater than zero".to_string(),
                    ));
                }
                merged.cache_size = *value;
            }
            SequenceOptionMutation::Cycle(value) => merged.cycle = *value,
            SequenceOptionMutation::Increment(value) => {
                if *value == 0 {
                    return Err(MutationResult::conflict(
                        "INCREMENT must not be zero".to_string(),
                    ));
                }
                merged.increment = *value;
            }
            SequenceOptionMutation::Logged(value) => {
                merged.persistence = if *value {
                    SequencePersistence::Permanent
                } else {
                    SequencePersistence::Unlogged
                };
            }
            SequenceOptionMutation::MaxValue(value) => {
                merged.max_value = match value {
                    Some(maximum) => *maximum,
                    None if merged.increment > 0 || reset_bounds => {
                        let (_, max) =
                            sequence_type_bounds(&merged.data_type).ok_or_else(|| {
                                MutationResult::conflict(format!(
                                    "sequence data type \"{}\" is invalid",
                                    merged.data_type
                                ))
                            })?;
                        max
                    }
                    None => -1,
                };
            }
            SequenceOptionMutation::MinValue(value) => {
                merged.min_value = match value {
                    Some(minimum) => *minimum,
                    None if merged.increment < 0 || reset_bounds => {
                        let (min, _) =
                            sequence_type_bounds(&merged.data_type).ok_or_else(|| {
                                MutationResult::conflict(format!(
                                    "sequence data type \"{}\" is invalid",
                                    merged.data_type
                                ))
                            })?;
                        min
                    }
                    None => 1,
                };
            }
            // Ownership is a graph transition rather than a parameter, and the
            // sequence name is documentation.
            SequenceOptionMutation::OwnedBy(_) | SequenceOptionMutation::SequenceName(_) => {}
            SequenceOptionMutation::Start(value) => merged.start_value = *value,
            // RESTART moves the current value rather than the parameters.
            SequenceOptionMutation::Restart(_) => {}
        }
    }

    if let Some((min, max)) = sequence_type_bounds(&merged.data_type) {
        if !(min..=max).contains(&merged.min_value) {
            return Err(MutationResult::conflict(format!(
                "MINVALUE ({}) is out of range for sequence data type {}",
                merged.min_value, merged.data_type
            )));
        }
        if !(min..=max).contains(&merged.max_value) {
            return Err(MutationResult::conflict(format!(
                "MAXVALUE ({}) is out of range for sequence data type {}",
                merged.max_value, merged.data_type
            )));
        }
    }
    if merged.min_value >= merged.max_value {
        return Err(MutationResult::conflict(format!(
            "MINVALUE ({}) must be less than MAXVALUE ({})",
            merged.min_value, merged.max_value
        )));
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
    if let Some(restart) = options.iter().find_map(|option| match option {
        SequenceOptionMutation::Restart(value) => Some(*value),
        _ => None,
    }) {
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
        let Some(parameters) = Self::apply_identity_sequence_options(
            crate::_internal::model::sequence::SequenceParameters {
                persistence: create.persistence,
                ..Default::default()
            },
            &create.options,
        ) else {
            return MutationResult::conflict("invalid sequence parameters".to_string());
        };
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
        let merged = match merged_sequence_parameters(&current.parameters, &alter.options) {
            Ok(merged) => merged,
            Err(result) => return result,
        };
        let owned_by = alter.options.iter().find_map(|option| match option {
            SequenceOptionMutation::OwnedBy(owned_by) => Some(owned_by),
            _ => None,
        });

        if merged != current.parameters {
            self.snapshot_sequence(&alter.id);
            if let Some(SequenceOverlay::Present(sequence)) =
                self.local.sequences.get_mut(&alter.id)
            {
                sequence.parameters = merged;
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
                let mut moved = current;
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
