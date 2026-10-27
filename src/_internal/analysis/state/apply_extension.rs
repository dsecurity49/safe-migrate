use super::{AnalysisState, MutationResult};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::{AlterFunctionAction, FunctionSigFact};
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterAggregateMutation, AlterExtensionActionMutation, AlterExtensionMutation,
    AlterFunctionMutation, AlterProcedureMutation, AlterSequenceActionMutation,
    AlterSequenceMutation, AlterTable, AlterTableActionMutation, CreateExtensionMutation,
    DropAggregateMutation, DropExtensionMutation, DropFunctionMutation, DropIndex,
    DropMaterializedViewMutation, DropProcedureMutation, DropSchemaMutation, DropSequenceMutation,
    DropTable, DropTriggerMutation, DropViewMutation, Rename,
};
use crate::_internal::ast::identifiers::{Ident, ObjectId, QualifiedName};
use crate::_internal::db::cache::CatalogFamily;
use crate::_internal::model::extension::{
    ExtensionMember, ExtensionMemberKind, ExtensionOverlay, ExtensionState,
};
use crate::_internal::model::function::{FunctionOverlay, RoutineKind};
use crate::_internal::model::index::KeyCollation;
use crate::_internal::model::relation::{RelationKind, RelationOverlay};
use crate::_internal::model::sequence::SequenceOverlay;
use crate::_internal::model::trigger::TriggerOverlay;
use crate::_internal::model::types::{TypeKind, TypeOverlay};
use std::collections::{BTreeSet, HashMap, HashSet};

macro_rules! extension_try {
    ($expr:expr) => {
        match $expr {
            MutationResult::Applied | MutationResult::NoOp => {}
            other => return other,
        }
    };
}

impl AnalysisState {
    pub(super) fn apply_create_extension(
        &mut self,
        create: &CreateExtensionMutation,
    ) -> MutationResult {
        match self.local.extensions.get(&create.name) {
            Some(ExtensionOverlay::Present(_)) => {
                return if create.if_not_exists {
                    MutationResult::NoOp
                } else {
                    MutationResult::conflict(format!(
                        "extension \"{}\" already exists",
                        create.name
                    ))
                };
            }
            Some(ExtensionOverlay::Dropped) | None => {}
        }
        if let Some(schema) = &create.schema
            && let Err(result) = self.ensure_schema_target(schema)
        {
            return result;
        }
        if self.baseline_is_available() && !self.baseline_has_coverage(CatalogFamily::Extensions) {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        let owner = ObjectId::new("", self.local.current_role.clone());
        if !self.local.current_role_known {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        let schema = create.schema.clone().or_else(|| {
            self.creation_schema().map(str::to_string).or_else(|| {
                self.local
                    .search_path
                    .first()
                    .and_then(|entry| entry.name())
                    .map(str::to_string)
            })
        });
        if schema.is_none() {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        self.snapshot_extension(&create.name);
        self.local.extensions.insert(
            create.name.clone(),
            ExtensionOverlay::Present(ExtensionState {
                name: create.name.clone(),
                schema,
                version: create.version.clone(),
                relocatable: None,
                owner,
                members: Default::default(),
                members_complete: false,
                config_tables: Vec::new(),
                generation,
            }),
        );
        // The extension script creates arbitrary objects that the analyzer
        // cannot reproduce, so the installation is never exact.
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        MutationResult::Applied
    }

    pub(super) fn apply_alter_extension(
        &mut self,
        alter: &AlterExtensionMutation,
    ) -> MutationResult {
        let Some(ExtensionOverlay::Present(extension)) =
            self.local.extensions.get(&alter.name).cloned()
        else {
            return MutationResult::conflict(format!(
                "extension \"{}\" does not exist",
                alter.name
            ));
        };
        match &alter.action {
            AlterExtensionActionMutation::Add(member) => {
                let member = self.resolve_extension_member(member);
                if extension
                    .members
                    .iter()
                    .any(|existing| self.resolve_extension_member(existing) == member)
                {
                    return MutationResult::conflict(format!(
                        "{} {} is already a member of extension \"{}\"",
                        extension_member_kind_name(&member.kind),
                        member.id,
                        alter.name
                    ));
                }
                if let Some(other) = self.extension_containing(&member) {
                    return MutationResult::conflict(format!(
                        "{} {} is already a member of extension \"{}\"",
                        extension_member_kind_name(&member.kind),
                        member.id,
                        other
                    ));
                }
                match self.extension_member_presence(&member) {
                    ExtensionMemberPresence::Present => {}
                    ExtensionMemberPresence::Absent => {
                        return MutationResult::conflict(format!(
                            "{} {} does not exist",
                            extension_member_kind_name(&member.kind),
                            member.id
                        ));
                    }
                    ExtensionMemberPresence::Unknown => {
                        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                    }
                }
                let unmodeled = matches!(member.kind, ExtensionMemberKind::Unmodeled(_));
                self.snapshot_extension(&alter.name);
                if let Some(ExtensionOverlay::Present(extension)) =
                    self.local.extensions.get_mut(&alter.name)
                {
                    extension.members.insert(member);
                    if unmodeled {
                        extension.members_complete = false;
                    }
                }
                if unmodeled {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                }
                MutationResult::Applied
            }
            AlterExtensionActionMutation::Drop(member) => {
                let member = self.resolve_extension_member(member);
                let Some(stored) = extension
                    .members
                    .iter()
                    .find(|existing| self.resolve_extension_member(existing) == member)
                    .cloned()
                else {
                    return MutationResult::conflict(format!(
                        "{} {} is not a member of extension \"{}\"",
                        extension_member_kind_name(&member.kind),
                        member.id,
                        alter.name
                    ));
                };
                let unmodeled = matches!(member.kind, ExtensionMemberKind::Unmodeled(_));
                self.snapshot_extension(&alter.name);
                if let Some(ExtensionOverlay::Present(extension)) =
                    self.local.extensions.get_mut(&alter.name)
                {
                    extension.members.remove(&stored);
                }
                if unmodeled {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                }
                MutationResult::Applied
            }
            AlterExtensionActionMutation::Update { version } => {
                if version == &extension.version {
                    return MutationResult::NoOp;
                }
                self.snapshot_extension(&alter.name);
                if let Some(ExtensionOverlay::Present(extension)) =
                    self.local.extensions.get_mut(&alter.name)
                {
                    extension.version = version.clone();
                }
                // The update script may replace or add arbitrary objects.
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                MutationResult::Applied
            }
            AlterExtensionActionMutation::SetSchema { new_schema } => {
                self.apply_alter_extension_set_schema(&alter.name, new_schema)
            }
        }
    }

    fn apply_alter_extension_set_schema(&mut self, name: &str, new_schema: &str) -> MutationResult {
        // PostgreSQL moves every namespace-bearing member through
        // AlterObjectNamespace_oid. Apply on a clone so a late collision leaves
        // the whole statement unapplied.
        let Some(ExtensionOverlay::Present(extension)) = self.local.extensions.get(name).cloned()
        else {
            return MutationResult::conflict(format!("extension \"{name}\" does not exist"));
        };
        if extension.relocatable == Some(false) {
            return MutationResult::conflict(format!("extension \"{name}\" is not relocatable"));
        }
        if let Err(result) = self.ensure_schema_target(new_schema) {
            return result;
        }
        if extension.members.iter().any(|member| {
            member.kind == ExtensionMemberKind::Schema && member.id.name == new_schema
        }) {
            return MutationResult::conflict(format!(
                "cannot move extension \"{name}\" into schema \"{new_schema}\" because the extension contains the schema"
            ));
        }
        let old_schema = extension.schema.clone();
        if old_schema.as_deref() == Some(new_schema) {
            return MutationResult::NoOp;
        }
        let members = extension
            .members
            .iter()
            .map(|member| self.resolve_extension_member(member))
            .collect::<BTreeSet<_>>();
        let members_complete = extension.members_complete;
        let relocatable_unknown = extension.relocatable.is_none();
        let Some(old_schema) = old_schema else {
            if members.is_empty() {
                let mut working = self.clone();
                working.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                if let Some(ExtensionOverlay::Present(extension)) =
                    working.local.extensions.get_mut(name)
                {
                    extension.schema = Some(new_schema.to_string());
                }
                *self = working;
                return MutationResult::Applied;
            }
            return self.unresolved(EvidenceCode::UnmodeledState);
        };

        for member in &members {
            // SET SCHEMA requires every relocatable member to already live in
            // the extension's schema; PostgreSQL does not move it from elsewhere.
            if extension_member_is_namespace_bearing(&member.kind) && member.id.schema != old_schema
            {
                return MutationResult::conflict(format!(
                    "extension \"{name}\" does not support SET SCHEMA: {} is not in the extension's schema \"{old_schema}\"",
                    member.id
                ));
            }
        }

        let mut working = self.clone();
        if relocatable_unknown || !members_complete {
            working.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        }

        for member in &members {
            if member.kind != ExtensionMemberKind::Relation || member.id.schema != old_schema {
                continue;
            }
            if !working.relation_is_present(&member.id) {
                continue;
            }
            let new_id = ObjectId::new(new_schema, member.id.name.clone());
            extension_try!(working.apply_rename_relation(&Rename {
                old_id: member.id.clone(),
                new_id,
            }));
        }

        for member in &members {
            if member.kind != ExtensionMemberKind::Index || member.id.schema != old_schema {
                continue;
            }
            if *working.local.graph.resolve_rename(&member.id) != member.id {
                continue;
            }
            if !working.index_is_present(&member.id) {
                continue;
            }
            let new_id = ObjectId::new(new_schema, member.id.name.clone());
            extension_try!(working.apply_rename_relation(&Rename {
                old_id: member.id.clone(),
                new_id,
            }));
        }

        for member in &members {
            if member.kind != ExtensionMemberKind::Sequence || member.id.schema != old_schema {
                continue;
            }
            if *working.local.graph.resolve_rename(&member.id) != member.id {
                continue;
            }
            if !working.sequence_is_present(&member.id) {
                continue;
            }
            let new_id = ObjectId::new(new_schema, member.id.name.clone());
            extension_try!(working.apply_alter_sequence(&AlterSequenceMutation {
                id: member.id.clone(),
                if_exists: false,
                options: Vec::new(),
                action: Some(AlterSequenceActionMutation::SetSchema(new_id)),
            }));
        }

        for member in &members {
            if member.kind != ExtensionMemberKind::Type || member.id.schema != old_schema {
                continue;
            }
            if *working.local.graph.resolve_rename(&member.id) != member.id {
                continue;
            }
            if !working.type_is_present(&member.id) {
                continue;
            }
            let new_id = ObjectId::new(new_schema, member.id.name.clone());
            extension_try!(working.apply_rename_type(&Rename {
                old_id: member.id.clone(),
                new_id,
            }));
        }

        for member in &members {
            if member.kind != ExtensionMemberKind::Routine || member.id.schema != old_schema {
                continue;
            }
            let current_id = working.local.graph.resolve_rename(&member.id).clone();
            if current_id.schema != old_schema
                || !matches!(
                    working.local.functions.get(&current_id),
                    Some(FunctionOverlay::Present(_))
                )
            {
                continue;
            }
            extension_try!(working.move_extension_routine(&current_id, new_schema));
        }

        let mut moved_collation = false;
        for member in &members {
            if member.kind != ExtensionMemberKind::Collation || member.id.schema != old_schema {
                continue;
            }
            if !working.local.collations.has(&old_schema, &member.id.name) {
                working.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                continue;
            }
            if working.local.collations.has(new_schema, &member.id.name) {
                return MutationResult::conflict(format!(
                    "collation \"{}\" already exists in schema \"{}\"",
                    member.id.name, new_schema
                ));
            }
            if !moved_collation {
                working.snapshot_namespace();
                moved_collation = true;
            }
            let new_id = ObjectId::new(new_schema, member.id.name.clone());
            working.local.collations =
                working
                    .local
                    .collations
                    .move_one(&old_schema, &member.id.name, new_schema);
            // Type and index definitions cache the collation's resolved name,
            // so move those references before recording the RenameTo edge.
            working.remap_type_collation(&member.id, &new_id);
            working.local.graph.remap_index_collation(
                &old_schema,
                &member.id.name,
                new_schema,
                &member.id.name,
            );
            working.local.graph.add_edge(DependencyEdge::new(
                member.id.clone(),
                new_id,
                DependencyKind::RenameTo,
            ));
        }

        working.remap_extension_members(name, &old_schema, new_schema, &members);
        if let Some(ExtensionOverlay::Present(extension)) = working.local.extensions.get_mut(name) {
            extension.schema = Some(new_schema.to_string());
            for config in &mut extension.config_tables {
                let resolved = working.local.graph.resolve_rename(&config.table).clone();
                if resolved != config.table {
                    config.table = resolved;
                } else if config.table.schema == old_schema {
                    config.table = ObjectId::new(new_schema, config.table.name.clone());
                }
            }
        }
        if members
            .iter()
            .any(|member| matches!(member.kind, ExtensionMemberKind::Unmodeled(_)))
        {
            working.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        }
        *self = working;
        MutationResult::Applied
    }

    fn remap_type_collation(&mut self, old: &ObjectId, new: &ObjectId) {
        for overlay in self.local.types.values_mut() {
            let TypeOverlay::Present(state) = overlay else {
                continue;
            };
            match &mut state.kind {
                TypeKind::Domain { collation_id, .. } | TypeKind::Range { collation_id, .. } => {
                    if collation_id.as_ref() == Some(old) {
                        *collation_id = Some(new.clone());
                    }
                }
                TypeKind::Composite { fields } => {
                    for field in fields {
                        if field.collation_id.as_ref() == Some(old) {
                            field.collation_id = Some(new.clone());
                        }
                    }
                }
                TypeKind::Enum { .. } | TypeKind::Base { .. } | TypeKind::Multirange { .. } => {}
            }
        }
    }

    fn move_extension_routine(&mut self, id: &ObjectId, new_schema: &str) -> MutationResult {
        let Some(FunctionOverlay::Present(routine)) = self.local.functions.get(id) else {
            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            return MutationResult::Applied;
        };
        let kind = routine.routine_kind;
        let action = AlterFunctionAction::SchemaChange {
            new_schema: new_schema.to_string(),
        };
        match kind {
            RoutineKind::Function | RoutineKind::Window => {
                self.apply_alter_function(&AlterFunctionMutation {
                    id: id.clone(),
                    action,
                })
            }
            RoutineKind::Procedure => self.apply_alter_procedure(&AlterProcedureMutation {
                id: id.clone(),
                action,
            }),
            RoutineKind::Aggregate => self.apply_alter_aggregate(&AlterAggregateMutation {
                id: id.clone(),
                action,
            }),
        }
    }

    fn remap_extension_members(
        &mut self,
        name: &str,
        old_schema: &str,
        new_schema: &str,
        original: &BTreeSet<ExtensionMember>,
    ) {
        // RenameTo edges are the authority. The old-schema fallback only covers
        // members whose object state is not modeled, and it taints that claim.
        let mut remapped = BTreeSet::new();
        for member in original {
            let new_member = match member.kind {
                ExtensionMemberKind::Schema => member.clone(),
                ExtensionMemberKind::Constraint | ExtensionMemberKind::Trigger => {
                    self.remap_attached_extension_member(member)
                }
                _ => {
                    let resolved = self.local.graph.resolve_rename(&member.id);
                    if *resolved != member.id {
                        ExtensionMember {
                            kind: member.kind.clone(),
                            id: resolved.clone(),
                        }
                    } else if member.id.schema == old_schema
                        && extension_member_is_namespace_bearing(&member.kind)
                    {
                        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                        ExtensionMember {
                            kind: member.kind.clone(),
                            id: ObjectId::new(new_schema, member.id.name.clone()),
                        }
                    } else {
                        member.clone()
                    }
                }
            };
            remapped.insert(new_member);
        }
        if let Some(ExtensionOverlay::Present(extension)) = self.local.extensions.get_mut(name) {
            extension.members = remapped;
        }
    }

    fn resolve_extension_member(&self, member: &ExtensionMember) -> ExtensionMember {
        match member.kind {
            ExtensionMemberKind::Constraint | ExtensionMemberKind::Trigger => {
                self.remap_attached_extension_member(member)
            }
            ExtensionMemberKind::Schema => member.clone(),
            _ => {
                let id = self.local.graph.resolve_rename(&member.id).clone();
                ExtensionMember {
                    kind: member.kind.clone(),
                    id,
                }
            }
        }
    }

    fn remap_attached_extension_member(&self, member: &ExtensionMember) -> ExtensionMember {
        // Constraint and trigger members are stored as schema.table.object, so
        // resolve the table prefix to carry them through a table move.
        let Some((table_name, object_name)) = member.id.name.rsplit_once('.') else {
            return member.clone();
        };
        let table = ObjectId::new(member.id.schema.clone(), table_name);
        let resolved = self.local.graph.resolve_rename(&table);
        if *resolved == table {
            return member.clone();
        }
        ExtensionMember {
            kind: member.kind.clone(),
            id: ObjectId::new(
                resolved.schema.clone(),
                format!("{}.{}", resolved.name, object_name),
            ),
        }
    }

    pub(super) fn apply_drop_extension(&mut self, drop: &DropExtensionMutation) -> MutationResult {
        for name in &drop.names {
            let present = matches!(
                self.local.extensions.get(name),
                Some(ExtensionOverlay::Present(_))
            );
            if !present && !drop.if_exists {
                return MutationResult::conflict(format!("extension \"{name}\" does not exist"));
            }
        }
        let mut working = self.clone();
        // A multi-extension DROP resolves all targets before dropping any of
        // them, so member dependencies across those extensions are internal.
        let mut statement_co_dropped = HashSet::new();
        for name in &drop.names {
            let Some(ExtensionOverlay::Present(extension)) =
                working.local.extensions.get(name).cloned()
            else {
                continue;
            };
            let members = extension
                .members
                .iter()
                .map(|member| working.resolve_extension_member(member))
                .collect::<BTreeSet<_>>();
            statement_co_dropped.extend(working.extension_member_co_dropped(&members));
            for config in &extension.config_tables {
                statement_co_dropped
                    .insert(working.local.graph.resolve_rename(&config.table).clone());
            }
        }
        let mut changed = false;
        for name in &drop.names {
            let Some(ExtensionOverlay::Present(extension)) =
                working.local.extensions.get(name).cloned()
            else {
                continue;
            };
            working.snapshot_extension(name);
            // Mark the extension gone first so its own member guards do not
            // reject the internal member drops that follow.
            working
                .local
                .extensions
                .insert(name.clone(), ExtensionOverlay::Dropped);
            changed = true;
            extension_try!(working.drop_extension_members(
                &extension,
                drop.cascade,
                &statement_co_dropped,
            ));
        }
        *self = working;
        if changed {
            MutationResult::Applied
        } else {
            MutationResult::NoOp
        }
    }

    fn extension_has_external_dependents(
        &self,
        members: &BTreeSet<ExtensionMember>,
        co_dropped: &HashSet<ObjectId>,
    ) -> bool {
        members.iter().any(|member| match member.kind {
            ExtensionMemberKind::Relation => {
                self.relation_has_external_dependents(&member.id, co_dropped)
            }
            ExtensionMemberKind::Type => self.has_type_dependents(&member.id),
            ExtensionMemberKind::Routine => {
                self.routine_has_external_dependents(&member.id, co_dropped)
            }
            ExtensionMemberKind::Sequence => {
                self.sequence_has_external_dependents(&member.id, co_dropped)
            }
            ExtensionMemberKind::Collation => {
                self.collation_has_external_dependents(&member.id, co_dropped)
            }
            ExtensionMemberKind::Schema => {
                self.schema_has_external_objects(&member.id.name, co_dropped)
            }
            ExtensionMemberKind::Index
            | ExtensionMemberKind::Constraint
            | ExtensionMemberKind::Trigger
            | ExtensionMemberKind::Cast
            | ExtensionMemberKind::Unmodeled(_) => false,
        })
    }

    fn relation_has_external_dependents(
        &self,
        relation: &ObjectId,
        co_dropped: &HashSet<ObjectId>,
    ) -> bool {
        self.local.graph.edges().iter().any(|edge| {
            self.dependency_edge_is_current(edge)
                && !matches!(edge.kind, DependencyKind::RenameTo)
                && self.local.graph.resolve_rename(&edge.referenced) == relation
                && !co_dropped.contains(self.local.graph.resolve_rename(&edge.dependent))
                && matches!(
                    edge.kind,
                    DependencyKind::ViewDependency { .. }
                        | DependencyKind::ForeignKey { .. }
                        | DependencyKind::InheritanceOf
                        | DependencyKind::PartitionOf
                        | DependencyKind::PartitionDetachPending
                )
        })
    }

    fn routine_has_external_dependents(
        &self,
        routine: &ObjectId,
        co_dropped: &HashSet<ObjectId>,
    ) -> bool {
        self.local.graph.edges().iter().any(|edge| {
            matches!(
                &edge.kind,
                DependencyKind::TriggerOnTable { function_id, .. }
                    if function_id == routine
                        && !co_dropped.contains(&edge.dependent)
                        && matches!(
                            self.local.triggers.get(&edge.dependent),
                            Some(TriggerOverlay::Present(_))
                        )
            )
        }) || self
            .local
            .graph
            .views_for_function(routine)
            .iter()
            .any(|edge| {
                !co_dropped.contains(&edge.dependent)
                    && matches!(
                        self.local.relations.get(&edge.dependent),
                        Some(RelationOverlay::Present(_))
                    )
            })
    }

    fn sequence_has_external_dependents(
        &self,
        sequence: &ObjectId,
        co_dropped: &HashSet<ObjectId>,
    ) -> bool {
        self.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::ColumnDefaultOnSequence { .. })
                && self.local.graph.resolve_rename(&edge.referenced) == sequence
                && !co_dropped.contains(self.local.graph.resolve_rename(&edge.dependent))
        })
    }

    fn collation_has_external_dependents(
        &self,
        collation: &ObjectId,
        co_dropped: &HashSet<ObjectId>,
    ) -> bool {
        self.local.types.iter().any(|(type_id, overlay)| {
            if co_dropped.contains(type_id) {
                return false;
            }
            let TypeOverlay::Present(state) = overlay else {
                return false;
            };
            match &state.kind {
                TypeKind::Domain { collation_id, .. } | TypeKind::Range { collation_id, .. } => {
                    collation_id.as_ref() == Some(collation)
                }
                TypeKind::Composite { fields } => fields
                    .iter()
                    .any(|field| field.collation_id.as_ref() == Some(collation)),
                TypeKind::Enum { .. } | TypeKind::Base { .. } | TypeKind::Multirange { .. } => {
                    false
                }
            }
        }) || self.local.graph.edges().iter().any(|edge| {
            let DependencyKind::IndexOnRelation { definition, .. } = &edge.kind else {
                return false;
            };
            !co_dropped.contains(&edge.dependent)
                && definition
                    .keys
                    .iter()
                    .chain(&definition.included)
                    .any(|key| {
                        matches!(
                            &key.collation,
                            KeyCollation::Resolved(resolved)
                                if resolved.schema == collation.schema
                                    && resolved.name == collation.name
                        )
                    })
        })
    }

    fn schema_has_external_objects(&self, schema: &str, co_dropped: &HashSet<ObjectId>) -> bool {
        let present = |id: &ObjectId| id.schema == schema && !co_dropped.contains(id);
        self.local
            .relations
            .iter()
            .any(|(id, overlay)| present(id) && matches!(overlay, RelationOverlay::Present(_)))
            || self
                .local
                .types
                .iter()
                .any(|(id, overlay)| present(id) && matches!(overlay, TypeOverlay::Present(_)))
            || self
                .local
                .functions
                .iter()
                .any(|(id, overlay)| present(id) && matches!(overlay, FunctionOverlay::Present(_)))
            || self
                .local
                .sequences
                .iter()
                .any(|(id, overlay)| present(id) && matches!(overlay, SequenceOverlay::Present(_)))
            || self
                .local
                .triggers
                .iter()
                .any(|(id, overlay)| present(id) && matches!(overlay, TriggerOverlay::Present(_)))
    }

    fn extension_member_co_dropped(
        &self,
        members: &BTreeSet<ExtensionMember>,
    ) -> HashSet<ObjectId> {
        let mut co_dropped = HashSet::new();
        let mut member_types = HashSet::new();
        for member in members {
            match member.kind {
                ExtensionMemberKind::Schema => {}
                ExtensionMemberKind::Type => {
                    member_types.insert(member.id.clone());
                }
                ExtensionMemberKind::Constraint => {
                    if let Some((table_name, _)) = member.id.name.rsplit_once('.') {
                        co_dropped.insert(ObjectId::new(member.id.schema.clone(), table_name));
                    }
                }
                ExtensionMemberKind::Trigger => {
                    if let Some((table_name, trigger_name)) = member.id.name.rsplit_once('.') {
                        let table = ObjectId::new(member.id.schema.clone(), table_name);
                        co_dropped.insert(table.clone());
                        co_dropped.insert(Self::trigger_key(&table, trigger_name));
                    }
                }
                _ => {
                    co_dropped.insert(member.id.clone());
                }
            }
        }
        // Range constructors are internal parts of their type, not extension
        // members, but they disappear with it.
        for (id, overlay) in &self.local.functions {
            let FunctionOverlay::Present(function) = overlay else {
                continue;
            };
            if function
                .internal_type_owner
                .as_ref()
                .is_some_and(|owner| member_types.contains(owner))
            {
                co_dropped.insert(id.clone());
            }
        }
        co_dropped
    }

    fn drop_extension_members(
        &mut self,
        extension: &ExtensionState,
        cascade: bool,
        statement_co_dropped: &HashSet<ObjectId>,
    ) -> MutationResult {
        if !extension.members_complete {
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        }

        let members = extension
            .members
            .iter()
            .map(|member| self.resolve_extension_member(member))
            .collect::<BTreeSet<_>>();
        // Dependencies between members dropped by this statement are not
        // external, so seed the co-drop set before the preflight checks run.
        let mut co_dropped = statement_co_dropped.clone();
        co_dropped.extend(self.extension_member_co_dropped(&members));
        for config in &extension.config_tables {
            co_dropped.insert(self.local.graph.resolve_rename(&config.table).clone());
        }
        self.co_dropped_objects = co_dropped;
        if !cascade && self.extension_has_external_dependents(&members, &self.co_dropped_objects) {
            self.co_dropped_objects.clear();
            return MutationResult::conflict(format!(
                "cannot drop extension {} because other objects depend on it",
                extension.name
            ));
        }

        let mut relations = Vec::new();
        let mut indexes = Vec::new();
        let mut sequences = Vec::new();
        let mut types = Vec::new();
        let mut routines = Vec::new();
        let mut schemas = Vec::new();
        let mut triggers = Vec::new();
        let mut constraints = Vec::new();
        let mut collations = Vec::new();
        for member in &members {
            match member.kind {
                ExtensionMemberKind::Relation => relations.push(member.id.clone()),
                ExtensionMemberKind::Index => indexes.push(member.id.clone()),
                ExtensionMemberKind::Sequence => sequences.push(member.id.clone()),
                ExtensionMemberKind::Type => types.push(member.id.clone()),
                ExtensionMemberKind::Routine => routines.push(member.id.clone()),
                ExtensionMemberKind::Schema => schemas.push(member.id.name.clone()),
                ExtensionMemberKind::Trigger => triggers.push(member.id.clone()),
                ExtensionMemberKind::Constraint => constraints.push(member.id.clone()),
                ExtensionMemberKind::Collation => collations.push(member.id.clone()),
                ExtensionMemberKind::Cast | ExtensionMemberKind::Unmodeled(_) => {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                }
            }
        }
        for config in &extension.config_tables {
            if !relations.contains(&config.table) {
                relations.push(config.table.clone());
            }
        }

        let mut views = Vec::new();
        let mut materialized_views = Vec::new();
        let mut tables = Vec::new();
        let mut other_relations = Vec::new();
        // Drop dependents before their dependencies. This mirrors PostgreSQL's
        // dependency pass and keeps member drops from colliding with each other.
        for id in relations {
            let Some(RelationOverlay::Present(relation)) = self.local.relations.get(&id) else {
                continue;
            };
            match relation.kind {
                RelationKind::View => views.push(id),
                RelationKind::MaterializedView => materialized_views.push(id),
                RelationKind::Table => tables.push(id),
                RelationKind::ForeignTable => other_relations.push(id),
            }
        }
        if !views.is_empty() {
            extension_try!(self.apply_drop_view(&DropViewMutation {
                ids: views,
                if_exists: false,
                cascade,
            }));
        }
        if !materialized_views.is_empty() {
            extension_try!(
                self.apply_drop_materialized_view(&DropMaterializedViewMutation {
                    ids: materialized_views,
                    if_exists: false,
                    cascade,
                })
            );
        }
        if !tables.is_empty() {
            extension_try!(self.apply_drop_table(
                &DropTable {
                    ids: tables,
                    if_exists: false,
                    cascade,
                },
                None,
            ));
        }
        if !other_relations.is_empty() {
            extension_try!(self.apply_drop_relation_family(&other_relations, cascade, "relation"));
        }

        let remaining_indexes = indexes
            .into_iter()
            .filter(|id| self.index_is_present(id))
            .collect::<Vec<_>>();
        if !remaining_indexes.is_empty() {
            extension_try!(self.apply_drop_index(&DropIndex {
                ids: remaining_indexes,
                if_exists: false,
                concurrently: false,
                cascade,
            }));
        }

        let remaining_sequences = sequences
            .into_iter()
            .filter(|id| self.sequence_is_present(id))
            .collect::<Vec<_>>();
        if !remaining_sequences.is_empty() {
            extension_try!(self.apply_drop_sequence(&DropSequenceMutation {
                ids: remaining_sequences,
                if_exists: false,
                cascade,
            }));
        }

        let (functions, procedures, aggregates, mut internal_routines) =
            self.partition_extension_routines(routines);
        extension_try!(
            self.drop_extension_routines(&functions, &procedures, &aggregates, cascade,)
        );

        let type_order = self.extension_type_drop_order(&types);
        for id in type_order {
            if !self.type_is_present(&id) {
                continue;
            }
            let is_domain = matches!(
                self.local.types.get(&id),
                Some(TypeOverlay::Present(
                    crate::_internal::model::types::TypeState {
                        kind: TypeKind::Domain { .. },
                        ..
                    }
                ))
            );
            let result = if is_domain {
                self.apply_drop_domain(&crate::_internal::analysis::mutations::DropDomainMutation {
                    ids: vec![id.clone()],
                    if_exists: false,
                    cascade,
                })
            } else {
                self.apply_drop_type(&crate::_internal::analysis::mutations::DropTypeMutation {
                    ids: vec![id.clone()],
                    if_exists: false,
                    cascade,
                })
            };
            extension_try!(result);
        }

        let member_types = types.iter().cloned().collect::<HashSet<_>>();
        internal_routines.extend(self.local.functions.iter().filter_map(|(id, overlay)| {
            let FunctionOverlay::Present(function) = overlay else {
                return None;
            };
            function
                .internal_type_owner
                .as_ref()
                .is_some_and(|owner| member_types.contains(owner))
                .then(|| id.clone())
        }));
        internal_routines.sort();
        internal_routines.dedup();
        internal_routines.retain(|id| {
            matches!(
                self.local.functions.get(id),
                Some(FunctionOverlay::Present(_))
            )
        });
        if !internal_routines.is_empty() {
            let internal_functions = internal_routines
                .into_iter()
                .filter(|id| {
                    matches!(
                        self.local.functions.get(id),
                        Some(FunctionOverlay::Present(function))
                            if matches!(function.routine_kind, RoutineKind::Function | RoutineKind::Window)
                    )
                })
                .collect::<Vec<_>>();
            extension_try!(self.drop_extension_routines(&internal_functions, &[], &[], cascade,));
        }

        for trigger_id in triggers {
            let Some((table_name, trigger_name)) = trigger_id.name.rsplit_once('.') else {
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                continue;
            };
            let table = ObjectId::new(trigger_id.schema.clone(), table_name);
            if !self.relation_is_present(&table) {
                continue;
            }
            let key = Self::trigger_key(&table, trigger_name);
            if !matches!(
                self.local.triggers.get(&key),
                Some(TriggerOverlay::Present(_))
            ) {
                continue;
            }
            extension_try!(self.apply_drop_trigger(&DropTriggerMutation {
                name: trigger_name.to_string(),
                table,
                if_exists: false,
            }));
        }

        for constraint_id in constraints {
            let Some((table_name, constraint_name)) = constraint_id.name.rsplit_once('.') else {
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                continue;
            };
            let table = ObjectId::new(constraint_id.schema.clone(), table_name);
            if !self.relation_is_present(&table) {
                continue;
            }
            if !self
                .local
                .constraints
                .contains_key(&(table.clone(), constraint_name.to_string()))
            {
                continue;
            }
            extension_try!(self.apply_alter_table(&AlterTable {
                id: table,
                only: false,
                action: AlterTableActionMutation::DropConstraint {
                    name: constraint_name.to_string(),
                    if_exists: false,
                    cascade,
                },
            }));
        }

        if !collations.is_empty() {
            self.snapshot_namespace();
            for id in collations {
                self.local.collations = self.local.collations.drop_one(&id.schema, &id.name);
            }
            // Collation dependents are not modeled, so a drop that PostgreSQL
            // performs may remove more than the simulator can see.
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        }

        if !schemas.is_empty() {
            extension_try!(self.apply_drop_schema(&DropSchemaMutation {
                names: schemas,
                if_exists: false,
                cascade,
            }));
        }
        self.co_dropped_objects.clear();
        MutationResult::Applied
    }

    fn partition_extension_routines(
        &self,
        routines: Vec<ObjectId>,
    ) -> (Vec<ObjectId>, Vec<ObjectId>, Vec<ObjectId>, Vec<ObjectId>) {
        let mut functions = Vec::new();
        let mut procedures = Vec::new();
        let mut aggregates = Vec::new();
        let mut internal = Vec::new();
        for id in routines {
            let Some(FunctionOverlay::Present(routine)) = self.local.functions.get(&id) else {
                continue;
            };
            if routine.internal_type_owner.is_some() {
                internal.push(id);
                continue;
            }
            match routine.routine_kind {
                RoutineKind::Function | RoutineKind::Window => functions.push(id),
                RoutineKind::Procedure => procedures.push(id),
                RoutineKind::Aggregate => aggregates.push(id),
            }
        }
        (functions, procedures, aggregates, internal)
    }

    fn drop_extension_routines(
        &mut self,
        functions: &[ObjectId],
        procedures: &[ObjectId],
        aggregates: &[ObjectId],
        cascade: bool,
    ) -> MutationResult {
        if !functions.is_empty() {
            let signatures = functions
                .iter()
                .filter_map(Self::routine_signature_fact)
                .collect::<Vec<_>>();
            if signatures.len() != functions.len() {
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            }
            if !signatures.is_empty() {
                extension_try!(self.apply_drop_function(&DropFunctionMutation {
                    signatures,
                    if_exists: false,
                    cascade,
                }));
            }
        }
        if !procedures.is_empty() {
            let signatures = procedures
                .iter()
                .filter_map(Self::routine_signature_fact)
                .collect::<Vec<_>>();
            if signatures.len() != procedures.len() {
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            }
            if !signatures.is_empty() {
                extension_try!(self.apply_drop_procedure(&DropProcedureMutation {
                    signatures,
                    if_exists: false,
                    cascade,
                }));
            }
        }
        if !aggregates.is_empty() {
            let signatures = aggregates
                .iter()
                .filter_map(Self::routine_signature_fact)
                .collect::<Vec<_>>();
            if signatures.len() != aggregates.len() {
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            }
            if !signatures.is_empty() {
                extension_try!(self.apply_drop_aggregate(&DropAggregateMutation {
                    signatures,
                    if_exists: false,
                    cascade,
                }));
            }
        }
        MutationResult::Applied
    }

    fn routine_signature_fact(id: &ObjectId) -> Option<FunctionSigFact> {
        let (name, arguments) = id.name.split_once('(')?;
        let arguments = arguments.strip_suffix(')')?;
        let params = if arguments.is_empty() {
            Vec::new()
        } else {
            arguments.split(',').map(str::to_string).collect()
        };
        Some(FunctionSigFact {
            name: QualifiedName::new(
                Some(Ident::new(id.schema.clone(), true)),
                Ident::new(name, true),
            ),
            params,
        })
    }

    fn extension_type_drop_order(&self, types: &[ObjectId]) -> Vec<ObjectId> {
        let members = types.iter().cloned().collect::<HashSet<_>>();
        let mut indegree = types
            .iter()
            .map(|id| (id.clone(), 0usize))
            .collect::<HashMap<_, _>>();
        let mut dependencies = HashMap::<ObjectId, Vec<ObjectId>>::new();
        for id in types {
            for dependency in self.extension_type_dependencies(id) {
                if !members.contains(&dependency) {
                    continue;
                }
                dependencies
                    .entry(id.clone())
                    .or_default()
                    .push(dependency.clone());
                *indegree.entry(dependency).or_default() += 1;
            }
        }
        let mut ready = types
            .iter()
            .filter(|id| indegree.get(*id) == Some(&0))
            .cloned()
            .collect::<Vec<_>>();
        ready.sort_unstable_by_key(ToString::to_string);
        let mut order = Vec::new();
        while let Some(id) = ready.pop() {
            order.push(id.clone());
            for dependency in dependencies.remove(&id).unwrap_or_default() {
                if let Some(count) = indegree.get_mut(&dependency) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        ready.push(dependency);
                    }
                }
            }
        }
        if order.len() != types.len() {
            return types.to_vec();
        }
        order
    }

    fn extension_type_dependencies(&self, id: &ObjectId) -> Vec<ObjectId> {
        let Some(TypeOverlay::Present(state)) = self.local.types.get(id) else {
            return Vec::new();
        };
        match &state.kind {
            TypeKind::Domain { base_type_id, .. } => base_type_id.iter().cloned().collect(),
            TypeKind::Range { subtype_id, .. } => subtype_id.iter().cloned().collect(),
            TypeKind::Multirange { range } => range.iter().cloned().collect(),
            TypeKind::Composite { fields } => fields
                .iter()
                .filter_map(|field| field.data_type_id.clone())
                .collect(),
            TypeKind::Enum { .. } | TypeKind::Base { .. } => Vec::new(),
        }
    }

    fn extension_containing(&self, member: &ExtensionMember) -> Option<&str> {
        self.local.extensions.iter().find_map(|(name, overlay)| {
            let ExtensionOverlay::Present(extension) = overlay else {
                return None;
            };
            extension
                .members
                .iter()
                .any(|existing| self.resolve_extension_member(existing) == *member)
                .then_some(name.as_str())
        })
    }

    fn extension_member_presence(&self, member: &ExtensionMember) -> ExtensionMemberPresence {
        let member = self.resolve_extension_member(member);
        match &member.kind {
            ExtensionMemberKind::Relation | ExtensionMemberKind::Index => {
                if self.local.relations.contains_key(&member.id) {
                    ExtensionMemberPresence::Present
                } else {
                    self.absent_or_unknown(&member.id, CatalogFamily::Relations)
                }
            }
            ExtensionMemberKind::Sequence => {
                if self.local.sequences.contains_key(&member.id) {
                    ExtensionMemberPresence::Present
                } else {
                    self.absent_or_unknown(&member.id, CatalogFamily::Sequences)
                }
            }
            ExtensionMemberKind::Type => {
                if self.local.types.contains_key(&member.id) {
                    ExtensionMemberPresence::Present
                } else {
                    self.absent_or_unknown(&member.id, CatalogFamily::Types)
                }
            }
            ExtensionMemberKind::Routine => {
                if self.local.functions.contains_key(&member.id) {
                    ExtensionMemberPresence::Present
                } else {
                    self.absent_or_unknown(&member.id, CatalogFamily::Routines)
                }
            }
            ExtensionMemberKind::Schema => {
                if matches!(
                    self.schema_lookup(&member.id.name),
                    super::ObjectLookup::Present
                ) {
                    ExtensionMemberPresence::Present
                } else {
                    ExtensionMemberPresence::Absent
                }
            }
            ExtensionMemberKind::Constraint => {
                if self
                    .constraint_key(&member.id)
                    .is_some_and(|key| self.local.constraints.contains_key(&key))
                {
                    ExtensionMemberPresence::Present
                } else {
                    ExtensionMemberPresence::Unknown
                }
            }
            ExtensionMemberKind::Trigger => {
                let Some((table_name, trigger_name)) = member.id.name.rsplit_once('.') else {
                    return ExtensionMemberPresence::Unknown;
                };
                let table = ObjectId::new(member.id.schema.clone(), table_name);
                let key = Self::trigger_key(&table, trigger_name);
                if matches!(
                    self.local.triggers.get(&key),
                    Some(TriggerOverlay::Present(_))
                ) {
                    ExtensionMemberPresence::Present
                } else {
                    ExtensionMemberPresence::Unknown
                }
            }
            ExtensionMemberKind::Collation => {
                if self
                    .local
                    .collations
                    .has(&member.id.schema, &member.id.name)
                {
                    ExtensionMemberPresence::Present
                } else {
                    ExtensionMemberPresence::Unknown
                }
            }
            ExtensionMemberKind::Cast | ExtensionMemberKind::Unmodeled(_) => {
                ExtensionMemberPresence::Unknown
            }
        }
    }

    fn absent_or_unknown(&self, id: &ObjectId, family: CatalogFamily) -> ExtensionMemberPresence {
        if self.baseline_covers_family_object(id, family) {
            ExtensionMemberPresence::Absent
        } else {
            ExtensionMemberPresence::Unknown
        }
    }

    fn constraint_key(&self, id: &ObjectId) -> Option<(ObjectId, String)> {
        let (table, name) = id.name.rsplit_once('.')?;
        Some((ObjectId::new(id.schema.clone(), table), name.to_string()))
    }
}

enum ExtensionMemberPresence {
    Present,
    Absent,
    Unknown,
}

fn extension_member_is_namespace_bearing(kind: &ExtensionMemberKind) -> bool {
    matches!(
        kind,
        ExtensionMemberKind::Relation
            | ExtensionMemberKind::Sequence
            | ExtensionMemberKind::Index
            | ExtensionMemberKind::Type
            | ExtensionMemberKind::Routine
            | ExtensionMemberKind::Collation
    )
}

fn extension_member_kind_name(kind: &ExtensionMemberKind) -> &str {
    match kind {
        ExtensionMemberKind::Schema => "schema",
        ExtensionMemberKind::Relation => "relation",
        ExtensionMemberKind::Sequence => "sequence",
        ExtensionMemberKind::Index => "index",
        ExtensionMemberKind::Type => "type",
        ExtensionMemberKind::Routine => "routine",
        ExtensionMemberKind::Constraint => "constraint",
        ExtensionMemberKind::Trigger => "trigger",
        ExtensionMemberKind::Collation => "collation",
        ExtensionMemberKind::Cast => "cast",
        ExtensionMemberKind::Unmodeled(_) => "object",
    }
}
