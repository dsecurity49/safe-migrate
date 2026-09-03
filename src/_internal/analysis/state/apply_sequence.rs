use super::{AnalysisState, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterSequenceActionMutation, AlterSequenceMutation, CreateSequenceMutation,
    DropSequenceMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::sequence::{SequenceKind, SequenceOverlay, SequenceState};
use std::collections::HashSet;

type SequenceLookup = ObjectLookup;

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
            ExprIr::Cast { expr, .. } => Self::expression_references_sequence(expr, sequence),
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
            ExprIr::Cast { expr, .. } => Self::expression_contains_nextval(expr),
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
        match self.local.sequences.get(id) {
            Some(SequenceOverlay::Present(_)) => SequenceLookup::Present,
            Some(SequenceOverlay::Dropped) => SequenceLookup::Tombstone,
            None if self
                .baseline_covers_family_object(id, crate::_internal::db::cache::CatalogFamily::Sequences) =>
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
        if let Err(result) = self.ensure_schema_target(&create.id.schema) {
            return result;
        }
        if create.if_not_exists && self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Skipped;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", create.id),
            };
        }
        if let Some((table_id, column)) = &create.owned_by {
            if table_id.schema != create.id.schema {
                return MutationResult::Conflict {
                    reason: "sequence must be in the same schema as its owning table".to_string(),
                };
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
                        return MutationResult::Conflict {
                            reason: format!("column '{}.{}' does not exist", table_id, column),
                        };
                    }
                    if self.local.current_role_known && table.owner.name != self.local.current_role
                    {
                        return MutationResult::Conflict {
                            reason: "sequence and table must have the same owner".to_string(),
                        };
                    }
                }
                _ if self.baseline_covers_family_object(
                    table_id,
                    crate::_internal::db::cache::CatalogFamily::Relations,
                ) =>
                {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' does not exist", table_id),
                    };
                }
                _ => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
            }
        }
        self.snapshot_sequence(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
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
                return MutationResult::Skipped;
            }
            SequenceLookup::AuthoritativelyAbsent => {
                return MutationResult::Conflict {
                    reason: format!("sequence '{}' does not exist", alter.id),
                };
            }
            SequenceLookup::Tombstone
                if self.baseline_covers_family_object(
                    &alter.id,
                    crate::_internal::db::cache::CatalogFamily::Sequences,
                ) =>
            {
                return MutationResult::Conflict {
                    reason: format!("sequence '{}' does not exist", alter.id),
                };
            }
            SequenceLookup::Tombstone if alter.if_exists => return MutationResult::Skipped,
            SequenceLookup::Tombstone | SequenceLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
            SequenceLookup::WrongKind => unreachable!("sequence lookup has no kind predicate"),
        }
        let current = match self.local.sequences.get(&alter.id) {
            Some(SequenceOverlay::Present(sequence)) => sequence.clone(),
            _ => unreachable!("presence checked above"),
        };
        match &alter.action {
            AlterSequenceActionMutation::OwnedBy(owned_by) => {
                if current.kind == SequenceKind::Identity {
                    return MutationResult::Conflict {
                        reason: "cannot change ownership of an identity sequence".to_string(),
                    };
                }
                if let Some((table_id, column)) = owned_by {
                    if table_id.schema != alter.id.schema {
                        return MutationResult::Conflict {
                            reason: "sequence must be in the same schema as its owning table"
                                .to_string(),
                        };
                    }
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
                        unreachable!("relation target presence checked above");
                    };
                    if !table.has_column(column) {
                        return MutationResult::Conflict {
                            reason: format!("column '{}.{}' does not exist", table_id, column),
                        };
                    }
                    if table.owner != current.owner {
                        return MutationResult::Conflict {
                            reason: "sequence and table must have the same owner".to_string(),
                        };
                    }
                }
                self.snapshot_sequence(&alter.id);
                self.snapshot_graph_full();
                self.local.graph.retain_edges(|edge| {
                    !(matches!(edge.kind, DependencyKind::SequenceOwnedBy { .. })
                        && edge.dependent == alter.id)
                });
                if let Some(SequenceOverlay::Present(sequence)) =
                    self.local.sequences.get_mut(&alter.id)
                {
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
            AlterSequenceActionMutation::OwnerTo(owner) => {
                if current.kind == SequenceKind::Identity {
                    return MutationResult::Conflict {
                        reason: "cannot alter an identity sequence independently".to_string(),
                    };
                }
                let Some((owner_name, known)) = self.role_fact_identity(owner) else {
                    self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                };
                if known && self.local.roles_known && self.present_role(&owner_name).is_none() {
                    return MutationResult::Conflict {
                        reason: format!("role '{}' does not exist", owner_name),
                    };
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
                        return MutationResult::Conflict {
                            reason: "sequence and table must have the same owner".to_string(),
                        };
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
            AlterSequenceActionMutation::RenameTo(new_id)
            | AlterSequenceActionMutation::SetSchema(new_id) => {
                if current.kind == SequenceKind::Identity {
                    return MutationResult::Conflict {
                        reason: "cannot alter an identity sequence independently".to_string(),
                    };
                }
                if let Err(result) = self.ensure_schema_target(&new_id.schema) {
                    return result;
                }
                if self.relation_namespace_is_taken(new_id) {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' already exists", new_id),
                    };
                }
                if let Some((table_id, _)) = &current.owned_by
                    && table_id.schema != new_id.schema
                {
                    return MutationResult::Conflict {
                        reason: "sequence must be in the same schema as its owning table"
                            .to_string(),
                    };
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
            AlterSequenceActionMutation::Other => {
                // No typed state transition exists for this Squawk action;
                // retaining Applied would make subsequent analysis look exact.
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                MutationResult::Skipped
            }
        }
    }

    pub(super) fn apply_drop_sequence(&mut self, drop: &DropSequenceMutation) -> MutationResult {
        for id in &drop.ids {
            match self.sequence_lookup(id) {
                SequenceLookup::Present => {}
                SequenceLookup::AuthoritativelyAbsent | SequenceLookup::Tombstone
                    if drop.if_exists => {}
                SequenceLookup::AuthoritativelyAbsent | SequenceLookup::Tombstone => {
                    return MutationResult::Conflict {
                        reason: format!("sequence '{}' does not exist", id),
                    };
                }
                SequenceLookup::Unknown => {
                    // IF EXISTS cannot prove that an out-of-scope object is
                    // absent.  Do not apply the other targets and then claim
                    // an exact state transition.
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
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
            return MutationResult::Skipped;
        }
        if present.iter().any(|id| {
            self.baseline_sequences.contains(id)
                && (!self.baseline_has_coverage(crate::_internal::db::cache::CatalogFamily::Dependencies)
                    || self.baseline_scoped_family_object(
                        id,
                        crate::_internal::db::cache::CatalogFamily::Sequences,
                    ))
        }) {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
            return MutationResult::Skipped;
        }
        for id in &present {
            let Some(SequenceOverlay::Present(sequence)) = self.local.sequences.get(id) else {
                continue;
            };
            if sequence.kind == SequenceKind::Identity {
                return MutationResult::Conflict {
                    reason: format!("cannot drop identity sequence '{}' independently", id),
                };
            }
            let has_default_dependencies = self.local.graph.edges().iter().any(|edge| {
                edge.referenced == *id
                    && matches!(edge.kind, DependencyKind::ColumnDefaultOnSequence { .. })
            });
            if (sequence.kind == SequenceKind::SerialLike || has_default_dependencies)
                && !drop.cascade
            {
                return MutationResult::Conflict {
                    reason: format!("sequence '{}' still has dependent defaults", id),
                };
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
