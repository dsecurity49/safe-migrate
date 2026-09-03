use super::{AnalysisState, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterDomainMutation, AlterTypeActionMutation, AlterTypeMutation, CreateDomainMutation,
    CreateTypeMutation, DropDomainMutation, DropTypeMutation, Rename,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::function::FunctionOverlay;
use crate::_internal::model::types::{TypeKind, TypeOverlay, TypeState};
use std::collections::HashSet;

type TypeLookup = ObjectLookup;

impl AnalysisState {
    pub(super) fn apply_create_type(&mut self, create: &CreateTypeMutation) -> MutationResult {
        if let Err(result) = self.ensure_schema_target(&create.id.schema) {
            return result;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Conflict {
                reason: format!("type '{}' already exists", create.id),
            };
        }
        self.snapshot_type(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        self.local.types.insert(
            create.id.clone(),
            TypeOverlay::Present(TypeState {
                id: create.id.clone(),
                generation,
                kind: create.kind.clone(),
            }),
        );
        MutationResult::Applied
    }

    pub(super) fn apply_rename_type(&mut self, rename: &Rename) -> MutationResult {
        match self.type_lookup(&rename.old_id, |_| true) {
            TypeLookup::Present => {}
            _ if self.baseline_covers_family_object(
                &rename.old_id,
                crate::_internal::db::cache::CatalogFamily::Types,
            ) =>
            {
                return MutationResult::Conflict {
                    reason: format!("type '{}' does not exist", rename.old_id),
                };
            }
            TypeLookup::Tombstone | TypeLookup::AuthoritativelyAbsent | TypeLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
            TypeLookup::WrongKind => unreachable!("all present type kinds are accepted"),
        }
        if rename.old_id != rename.new_id && self.relation_namespace_is_taken(&rename.new_id) {
            return MutationResult::Conflict {
                reason: format!("type '{}' already exists", rename.new_id),
            };
        }
        if rename.old_id.schema != rename.new_id.schema
            && !self.schema_is_present(&rename.new_id.schema)
        {
            if self.schema_absence_is_authoritative(&rename.new_id.schema) {
                return MutationResult::Conflict {
                    reason: format!("schema '{}' does not exist", rename.new_id.schema),
                };
            }
            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            return MutationResult::Skipped;
        }

        let mut remapped_functions = Vec::new();
        for (function_id, overlay) in &self.local.functions {
            let FunctionOverlay::Present(function) = overlay else {
                continue;
            };
            let new_arg_types = function
                .arg_types
                .iter()
                .enumerate()
                .map(|(index, raw)| {
                    if function.arg_type_ids.get(index) == Some(&Some(rename.old_id.clone())) {
                        Self::remapped_type_display(
                            raw,
                            &rename.new_id,
                            rename.old_id.schema != rename.new_id.schema,
                        )
                    } else {
                        raw.clone()
                    }
                })
                .collect::<Vec<_>>();
            let new_return_type = if function.return_type_id == Some(rename.old_id.clone()) {
                Self::remapped_type_display(
                    &function.return_type,
                    &rename.new_id,
                    rename.old_id.schema != rename.new_id.schema,
                )
            } else {
                function.return_type.clone()
            };
            let base_name = function_id
                .name
                .split_once('(')
                .map(|(name, _)| name)
                .unwrap_or(&function_id.name);
            let mut new_function_id = ObjectId::new(
                &function_id.schema,
                format!("{}({})", base_name, new_arg_types.join(",")),
            );
            new_function_id.inferred_schema = function_id.inferred_schema;
            if new_function_id != *function_id
                || new_arg_types != function.arg_types
                || new_return_type != function.return_type
            {
                remapped_functions.push((
                    function_id.clone(),
                    new_function_id,
                    new_arg_types,
                    new_return_type,
                ));
            }
        }
        let moved_function_ids = remapped_functions
            .iter()
            .map(|(old_id, _, _, _)| old_id)
            .collect::<HashSet<_>>();
        let mut destinations = HashSet::new();
        for (_, new_id, _, _) in &remapped_functions {
            if !destinations.insert(new_id)
                || (self.local.functions.contains_key(new_id)
                    && !moved_function_ids.contains(new_id))
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "routine '{}' already exists after renaming type '{}'",
                        new_id, rename.old_id
                    ),
                };
            }
        }

        self.snapshot_namespace();
        if let Some(TypeOverlay::Present(mut state)) = self.local.types.remove(&rename.old_id) {
            state.id = rename.new_id.clone();
            self.local
                .types
                .insert(rename.new_id.clone(), TypeOverlay::Present(state));
        }
        for overlay in self.local.relations.values_mut() {
            if let RelationOverlay::Present(relation) = overlay {
                for column in &mut relation.columns {
                    if column.type_id == Some(rename.old_id.clone()) {
                        column.data_type = Some(Self::remapped_type_display(
                            column.data_type.as_deref().unwrap_or_default(),
                            &rename.new_id,
                            rename.old_id.schema != rename.new_id.schema,
                        ));
                        column.type_id = Some(rename.new_id.clone());
                    }
                }
            }
        }
        for overlay in self.local.types.values_mut() {
            if let TypeOverlay::Present(TypeState {
                kind:
                    TypeKind::Domain {
                        base_type,
                        base_type_id,
                    },
                ..
            }) = overlay
                && *base_type_id == Some(rename.old_id.clone())
            {
                *base_type = Self::remapped_type_display(
                    base_type,
                    &rename.new_id,
                    rename.old_id.schema != rename.new_id.schema,
                );
                *base_type_id = Some(rename.new_id.clone());
            }
        }
        for (old_id, new_id, arg_types, return_type) in remapped_functions {
            if let Some(FunctionOverlay::Present(mut function)) =
                self.local.functions.remove(&old_id)
            {
                function.id = new_id.clone();
                function.arg_types = arg_types;
                for type_id in &mut function.arg_type_ids {
                    if *type_id == Some(rename.old_id.clone()) {
                        *type_id = Some(rename.new_id.clone());
                    }
                }
                function.return_type = return_type;
                if function.return_type_id == Some(rename.old_id.clone()) {
                    function.return_type_id = Some(rename.new_id.clone());
                }
                self.local
                    .functions
                    .insert(new_id.clone(), FunctionOverlay::Present(function));
                if old_id != new_id {
                    self.local.graph.propagate_function_rename(&old_id, &new_id);
                    self.local.graph.add_edge(DependencyEdge::new(
                        old_id,
                        new_id,
                        DependencyKind::RenameTo,
                    ));
                }
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_alter_type(&mut self, alter: &AlterTypeMutation) -> MutationResult {
        match self.type_lookup(&alter.id, |_| true) {
            TypeLookup::Present => {}
            TypeLookup::WrongKind => unreachable!("all present type kinds are accepted"),
            TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone => {
                return MutationResult::Conflict {
                    reason: format!("type '{}' does not exist", alter.id),
                };
            }
            TypeLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
        }
        if matches!(&alter.action, AlterTypeActionMutation::AddValue { .. })
            && !matches!(
                self.local.types.get(&alter.id),
                Some(TypeOverlay::Present(TypeState {
                    kind: TypeKind::Enum { .. },
                    ..
                }))
            )
        {
            return MutationResult::Conflict {
                reason: format!("type '{}' is not an enum", alter.id),
            };
        }
        self.snapshot_type(&alter.id);
        if let Some(TypeOverlay::Present(existing)) = self.local.types.get_mut(&alter.id) {
            match &alter.action {
                AlterTypeActionMutation::AddValue {
                    new_value,
                    neighbor,
                    before,
                } => {
                    if let TypeKind::Enum { variants } = &mut existing.kind {
                        if variants.contains(new_value) {
                            return MutationResult::Skipped;
                        }
                        let insertion_index = if let Some(neighbor) = neighbor {
                            let Some(index) = variants.iter().position(|value| value == neighbor)
                            else {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "enum label '{}' does not exist on type '{}'",
                                        neighbor, alter.id
                                    ),
                                };
                            };
                            if *before { index } else { index + 1 }
                        } else {
                            variants.len()
                        };
                        variants.insert(insertion_index, new_value.clone());
                    }
                }
                AlterTypeActionMutation::RenameValue {
                    old_value,
                    new_value,
                } => {
                    let TypeKind::Enum { variants } = &mut existing.kind else {
                        return MutationResult::Conflict {
                            reason: format!("type '{}' is not an enum", alter.id),
                        };
                    };
                    let Some(old_index) = variants.iter().position(|value| value == old_value)
                    else {
                        return MutationResult::Conflict {
                            reason: format!(
                                "'{}' is not an existing label of enum '{}'",
                                old_value, alter.id
                            ),
                        };
                    };
                    if variants.iter().any(|value| value == new_value) {
                        return MutationResult::Conflict {
                            reason: format!(
                                "enum label '{}' already exists on type '{}'",
                                new_value, alter.id
                            ),
                        };
                    }
                    variants[old_index] = new_value.clone();
                }
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_create_domain(&mut self, create: &CreateDomainMutation) -> MutationResult {
        if let Err(result) = self.ensure_schema_target(&create.id.schema) {
            return result;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Conflict {
                reason: format!("type '{}' already exists", create.id),
            };
        }
        self.snapshot_type(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        self.local.types.insert(
            create.id.clone(),
            TypeOverlay::Present(TypeState {
                id: create.id.clone(),
                generation,
                kind: TypeKind::Domain {
                    base_type: create.base_type.clone(),
                    base_type_id: self.resolve_type_reference(&create.base_type),
                },
            }),
        );
        MutationResult::Applied
    }

    pub(super) fn apply_alter_domain(&mut self, alter: &AlterDomainMutation) -> MutationResult {
        match self.type_lookup(&alter.id, |kind| matches!(kind, TypeKind::Domain { .. })) {
            TypeLookup::Present => {
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                MutationResult::Skipped
            }
            TypeLookup::WrongKind => MutationResult::Conflict {
                reason: format!("type '{}' is not a domain", alter.id),
            },
            TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone => MutationResult::Conflict {
                reason: format!("domain '{}' does not exist", alter.id),
            },
            TypeLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                MutationResult::Skipped
            }
        }
    }

    pub(super) fn apply_drop_domain(&mut self, drop: &DropDomainMutation) -> MutationResult {
        let mut present = Vec::new();
        for id in &drop.ids {
            match self.type_lookup(id, |kind| matches!(kind, TypeKind::Domain { .. })) {
                TypeLookup::Present => present.push(id.clone()),
                TypeLookup::WrongKind => {
                    return MutationResult::Conflict {
                        reason: format!("type '{}' is not a domain", id),
                    };
                }
                TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone if drop.if_exists => {}
                TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone => {
                    return MutationResult::Conflict {
                        reason: format!("domain '{}' does not exist", id),
                    };
                }
                TypeLookup::Unknown => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
            }
        }
        if present.is_empty() {
            return MutationResult::Skipped;
        }
        if present.iter().any(|id| {
            self.baseline_scoped_family_object(id, crate::_internal::db::cache::CatalogFamily::Types)
        }) {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
            return MutationResult::Skipped;
        }
        if let Some(dependent) = present.iter().find(|id| self.has_type_dependents(id)) {
            if !drop.cascade {
                return MutationResult::Conflict {
                    reason: format!("domain '{}' has dependent objects; use CASCADE", dependent),
                };
            }
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            return MutationResult::Skipped;
        }
        for id in &present {
            self.snapshot_type(id);
            self.local.types.insert(id.clone(), TypeOverlay::Dropped);
        }
        MutationResult::Applied
    }

    pub(super) fn apply_drop_type(&mut self, drop: &DropTypeMutation) -> MutationResult {
        let mut present = Vec::new();
        for id in &drop.ids {
            match self.type_lookup(id, |kind| !matches!(kind, TypeKind::Domain { .. })) {
                TypeLookup::Present => present.push(id.clone()),
                TypeLookup::WrongKind => {
                    return MutationResult::Conflict {
                        reason: format!("type '{}' is a domain; use DROP DOMAIN", id),
                    };
                }
                TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone if drop.if_exists => {}
                TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone => {
                    return MutationResult::Conflict {
                        reason: format!("type '{}' does not exist", id),
                    };
                }
                TypeLookup::Unknown => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
            }
        }
        if present.is_empty() {
            return MutationResult::Skipped;
        }
        if present.iter().any(|id| {
            self.baseline_scoped_family_object(id, crate::_internal::db::cache::CatalogFamily::Types)
        }) {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
            return MutationResult::Skipped;
        }
        if let Some(dependent) = present.iter().find(|id| self.has_type_dependents(id)) {
            if !drop.cascade {
                return MutationResult::Conflict {
                    reason: format!("type '{}' has dependent objects; use CASCADE", dependent),
                };
            }
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            return MutationResult::Skipped;
        }
        for id in &present {
            self.snapshot_type(id);
            self.local.types.insert(id.clone(), TypeOverlay::Dropped);
        }
        MutationResult::Applied
    }

    fn has_type_dependents(&self, id: &ObjectId) -> bool {
        self.local.relations.values().any(|overlay| {
            matches!(overlay, RelationOverlay::Present(relation)
                if relation.columns.iter().any(|column| column.type_id.as_ref() == Some(id)))
        }) || self.local.functions.values().any(|overlay| {
            matches!(overlay, FunctionOverlay::Present(function)
                if function.arg_type_ids.iter().flatten().any(|type_id| type_id == id)
                    || function.return_type_id.as_ref() == Some(id))
        }) || self.local.types.values().any(|overlay| {
            matches!(overlay, TypeOverlay::Present(TypeState {
                kind: TypeKind::Domain { base_type_id: Some(base), .. },
                ..
            }) if base == id)
        })
    }
}
