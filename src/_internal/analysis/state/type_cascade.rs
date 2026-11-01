//! The deletion closure of `DROP TYPE ... CASCADE`.
//!
//! PostgreSQL removes far more than the type itself: domains and ranges built
//! on it, a range's multirange companion, composite fields, whole typed
//! tables, table columns, routines whose signature names it, and every view
//! those removals take down. The engine applies those removals so a later
//! statement sees the state PostgreSQL would have.

use super::{AnalysisState, MutationResult, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::graph::DependencyKind;
use crate::_internal::analysis::mutations::{AlterTable, AlterTableActionMutation};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::function::FunctionOverlay;
use crate::_internal::model::relation::RelationKind;
use crate::_internal::model::types::{TypeKind, TypeOverlay};
use std::collections::HashSet;

impl AnalysisState {
    /// Apply the closure of a CASCADE drop of `victims` and their companions.
    ///
    /// Returns whether the closure was enumerated completely; `false` means a
    /// dependency could not be proved (a scoped baseline, an unknown column
    /// set) and the chain must taint even though the drop applied.
    pub(super) fn apply_type_cascade(&mut self, victims: &[ObjectId]) -> bool {
        let mut complete = true;
        let (dropped_types, removed_fields) = self.type_cascade_closure(victims);

        // A composite survives the loss of a field; only the field goes.
        for (composite, field) in &removed_fields {
            if dropped_types.contains(composite) {
                continue;
            }
            let Some(TypeOverlay::Present(state)) = self.local.types.get(composite) else {
                continue;
            };
            let TypeKind::Composite { fields } = &state.kind else {
                continue;
            };
            if fields.iter().all(|existing| existing.name != *field) {
                continue;
            }
            self.snapshot_type(composite);
            if let Some(TypeOverlay::Present(state)) = self.local.types.get_mut(composite)
                && let TypeKind::Composite { fields } = &mut state.kind
            {
                fields.retain(|existing| existing.name != *field);
            }
        }

        let dropped_routines = self.routine_cascade_victims(&dropped_types);
        let dropped_ids: HashSet<ObjectId> = dropped_routines.iter().cloned().collect();
        let mut surviving_reference = false;
        for id in &dropped_routines {
            if self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Routines,
            ) {
                complete = false;
            }
            let dependent_triggers: Vec<(ObjectId, ObjectId)> = self
                .local
                .graph
                .edges()
                .iter()
                .filter_map(|edge| {
                    let DependencyKind::TriggerOnTable { function_id, .. } = &edge.kind else {
                        return None;
                    };
                    (function_id == id).then(|| (edge.dependent.clone(), edge.referenced.clone()))
                })
                .collect();
            let dependent_views: Vec<(ObjectId, Option<ObjectId>)> = self
                .local
                .graph
                .views_for_function(id)
                .into_iter()
                .filter_map(|edge| {
                    let DependencyKind::ViewUsesRoutine { unresolved_name } = &edge.kind else {
                        return None;
                    };
                    Some((edge.dependent.clone(), unresolved_name.clone()))
                })
                .collect();
            if self.apply_routine_cascade_drop(
                id,
                &dependent_triggers,
                &dependent_views,
                &dropped_ids,
            ) {
                surviving_reference = true;
            }
        }
        if surviving_reference {
            self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
        }

        let typed_tables: Vec<ObjectId> = self
            .local
            .relations
            .iter()
            .filter_map(|(id, overlay)| {
                let RelationOverlay::Present(relation) = overlay else {
                    return None;
                };
                relation
                    .of_type
                    .as_ref()
                    .is_some_and(|of_type| dropped_types.contains(of_type))
                    .then(|| id.clone())
            })
            .collect();
        if !typed_tables.is_empty()
            && !matches!(
                self.apply_drop_relation_family(&typed_tables, true, "table"),
                MutationResult::Applied
            )
        {
            complete = false;
        }

        let mut view_seeds: Vec<ObjectId> = Vec::new();
        for id in &dropped_types {
            for probe in [id.clone(), Self::array_type_id(id)] {
                for edge in self.local.graph.views_for_type(&probe) {
                    if matches!(
                        self.local.relations.get(&edge.dependent),
                        Some(RelationOverlay::Present(_))
                    ) && !view_seeds.contains(&edge.dependent)
                    {
                        view_seeds.push(edge.dependent.clone());
                    }
                }
            }
        }
        if !view_seeds.is_empty() {
            let _ = self.apply_drop_relation_family(&view_seeds, true, "view");
        }

        for (relation_id, column) in self.type_cascade_columns(&dropped_types, &removed_fields) {
            if !matches!(
                self.local.relations.get(&relation_id),
                Some(RelationOverlay::Present(_))
            ) {
                continue;
            }
            let alter = AlterTable {
                id: relation_id,
                only: false,
                action: AlterTableActionMutation::DropColumn {
                    name: column,
                    if_exists: true,
                    cascade: true,
                },
            };
            let result = self.apply_alter_table(&alter);
            match result {
                MutationResult::Applied | MutationResult::NoOp => {}
                _ => complete = false,
            }
        }

        for id in &dropped_types {
            if self.type_is_present(id) {
                self.snapshot_type(id);
                self.local.types.insert(id.clone(), TypeOverlay::Dropped);
            }
        }
        complete
    }

    /// The type tier of the closure: every present type a victim takes with it.
    ///
    /// A domain or range built on a dropped type goes, a range takes its
    /// multirange companion, and a composite survives with the offending
    /// field removed rather than being dropped.
    fn type_cascade_closure(
        &self,
        victims: &[ObjectId],
    ) -> (HashSet<ObjectId>, HashSet<(ObjectId, String)>) {
        let mut dropped: HashSet<ObjectId> = victims.iter().cloned().collect();
        let mut removed_fields: HashSet<(ObjectId, String)> = HashSet::new();
        loop {
            let mut grew = false;
            for victim in dropped.clone() {
                if let Some(TypeOverlay::Present(state)) = self.local.types.get(&victim) {
                    if let TypeKind::Range {
                        multirange: Some(ref mr),
                        ..
                    } = state.kind
                    {
                        if self.type_is_present(mr) && dropped.insert(mr.clone()) {
                            grew = true;
                        }
                    } else if self.type_is_range(&victim) {
                        let companion = Self::multirange_companion_id(&victim);
                        if self.type_is_present(&companion) && dropped.insert(companion) {
                            grew = true;
                        }
                    }
                }
            }
            let present: Vec<(ObjectId, TypeKind)> = self
                .local
                .types
                .iter()
                .filter_map(|(id, overlay)| match overlay {
                    TypeOverlay::Present(state) => Some((id.clone(), state.kind.clone())),
                    TypeOverlay::Dropped => None,
                })
                .collect();
            for (id, kind) in present {
                if dropped.contains(&id) {
                    continue;
                }
                match kind {
                    TypeKind::Domain { base_type_id, .. } => {
                        if Self::type_reference_matches_victims(base_type_id.as_ref(), &dropped) {
                            dropped.insert(id);
                            grew = true;
                        }
                    }
                    TypeKind::Range {
                        subtype_id,
                        multirange,
                        ..
                    } => {
                        if Self::type_reference_matches_victims(subtype_id.as_ref(), &dropped) {
                            dropped.insert(id.clone());
                            if let Some(ref mr) = multirange {
                                dropped.insert(mr.clone());
                            }
                            grew = true;
                        }
                    }
                    TypeKind::Multirange { range } => {
                        if let Some(ref r) = range
                            && dropped.contains(r)
                        {
                            dropped.insert(id);
                            grew = true;
                        }
                    }
                    TypeKind::Composite { fields } => {
                        for field in fields {
                            if Self::type_reference_matches_victims(
                                field.data_type_id.as_ref(),
                                &dropped,
                            ) && removed_fields.insert((id.clone(), field.name.clone()))
                            {
                                grew = true;
                            }
                        }
                    }
                    TypeKind::Base { options, .. } => {
                        if let Some(ref elem) = options.element {
                            let elem_id = ObjectId::new(&id.schema, elem);
                            if dropped.contains(&elem_id) {
                                dropped.insert(id);
                                grew = true;
                            }
                        }
                    }
                    TypeKind::Enum { .. } => {}
                }
            }
            if !grew {
                break;
            }
        }
        (dropped, removed_fields)
    }

    /// Present routines that reference a dropped type: an explicit argument or
    /// return type, or the internal ownership link PostgreSQL records for a
    /// range constructor.
    pub(super) fn routine_cascade_victims(
        &self,
        dropped_types: &HashSet<ObjectId>,
    ) -> Vec<ObjectId> {
        self.local
            .functions
            .iter()
            .filter_map(|(id, overlay)| {
                let FunctionOverlay::Present(function) = overlay else {
                    return None;
                };
                let owner_dropped = function
                    .internal_type_owner
                    .as_ref()
                    .is_some_and(|owner| dropped_types.contains(owner));
                let signature_references = function.arg_type_ids.iter().flatten().any(|type_id| {
                    Self::type_reference_matches_victims(Some(type_id), dropped_types)
                }) || Self::type_reference_matches_victims(
                    function.return_type_id.as_ref(),
                    dropped_types,
                );
                (owner_dropped || signature_references).then(|| id.clone())
            })
            .collect()
    }

    /// Columns the closure removes from surviving relations: ordinary columns
    /// typed by a victim, and typed-table columns whose composite field the
    /// closure removed.
    fn type_cascade_columns(
        &self,
        dropped_types: &HashSet<ObjectId>,
        removed_fields: &HashSet<(ObjectId, String)>,
    ) -> Vec<(ObjectId, String)> {
        let mut targets = Vec::new();
        for (relation_id, overlay) in &self.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            if !matches!(
                relation.kind,
                RelationKind::Table | RelationKind::ForeignTable
            ) {
                continue;
            }
            for column in &relation.columns {
                if Self::type_reference_matches_victims(column.type_id.as_ref(), dropped_types) {
                    targets.push((relation_id.clone(), column.name.clone()));
                }
            }
            if let Some(of_type) = &relation.of_type {
                for (composite, field) in removed_fields {
                    if composite == of_type && relation.has_column(field) {
                        targets.push((relation_id.clone(), field.clone()));
                    }
                }
            }
        }
        targets
    }

    fn type_is_range(&self, id: &ObjectId) -> bool {
        matches!(
            self.local.types.get(id),
            Some(TypeOverlay::Present(state)) if matches!(state.kind, TypeKind::Range { .. })
        )
    }
}
