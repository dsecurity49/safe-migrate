use super::*;

impl AnalysisState {
    /// Return the key definitions that can be proved for a relation.
    /// `None` means a key exists but its columns (or index eligibility) are
    /// not represented by the current cache/model; callers must taint rather
    /// than invent a matching foreign-key target in that case.
    pub(super) fn unique_keys_for_relation(
        &self,
        id: &ObjectId,
    ) -> Option<Vec<(Vec<String>, bool)>> {
        let resolved = self.local.graph.resolve_rename(id);
        if self.baseline_relation_is_known(resolved)
            && self
                .local
                .relations
                .get(resolved)
                .is_some_and(|overlay| {
                    matches!(overlay, RelationOverlay::Present(relation) if relation.columns.is_empty())
                })
        {
            return None;
        }
        let mut keys = Vec::new();
        let mut unknown = false;
        for edge in self.local.graph.edges() {
            if edge.dependent != *resolved {
                continue;
            }
            match &edge.kind {
                DependencyKind::ConstraintOnRelation {
                    columns,
                    is_primary,
                    ..
                } => {
                    if columns.is_empty() {
                        unknown = true;
                    } else {
                        keys.push((columns.clone(), *is_primary));
                    }
                }
                DependencyKind::IndexOnRelation {
                    definition: IndexDefinition { unique: true, .. },
                    ..
                } => unknown = true,
                _ => {}
            }
        }
        if !keys.is_empty() {
            return Some(keys);
        }
        if unknown
            || self
                .local
                .constraints
                .iter()
                .any(|((table, _), constraint)| {
                    table == resolved
                        && matches!(
                            constraint.kind,
                            ConstraintKind::PrimaryKey | ConstraintKind::Unique
                        )
                })
        {
            None
        } else {
            Some(Vec::new())
        }
    }

    pub(in crate::_internal::analysis::state) fn apply_rename_relation(
        &mut self,
        rename: &Rename,
    ) -> MutationResult {
        let renames_relation = self.relation_is_present(&rename.old_id);
        let renames_index = self.index_is_present(&rename.old_id);
        if renames_index && rename.old_id.name != rename.new_id.name {
            for constraint in self.local.constraints.values().filter(|constraint| {
                constraint.backing_index.as_ref() == Some(&rename.old_id)
                    && matches!(
                        constraint.kind,
                        ConstraintKind::PrimaryKey
                            | ConstraintKind::Unique
                            | ConstraintKind::Exclusion
                    )
            }) {
                if constraint.name != rename.new_id.name
                    && self
                        .local
                        .constraints
                        .contains_key(&(constraint.table_id.clone(), rename.new_id.name.clone()))
                {
                    return MutationResult::conflict(format!(
                        "constraint '{}' already exists on relation '{}'",
                        rename.new_id.name, constraint.table_id
                    ));
                }
            }
        }
        match self.relation_or_index_lookup(&rename.old_id) {
            RelationLookup::Present => {}
            _ if self.baseline_covers_family_object(
                &rename.old_id,
                crate::_internal::db::cache::CatalogFamily::Relations,
            ) || self.baseline_covers_family_object(
                &rename.old_id,
                crate::_internal::db::cache::CatalogFamily::Indexes,
            ) =>
            {
                return MutationResult::conflict(format!(
                    "relation '{}' does not exist",
                    rename.old_id
                ));
            }
            RelationLookup::Tombstone
            | RelationLookup::AuthoritativelyAbsent
            | RelationLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
            RelationLookup::WrongKind => {
                unreachable!("relation renames accept every modeled relation kind")
            }
        }
        if rename.old_id != rename.new_id && self.relation_namespace_is_taken(&rename.new_id) {
            return MutationResult::conflict(format!(
                "relation '{}' already exists",
                rename.new_id
            ));
        }
        if rename.old_id.schema != rename.new_id.schema
            && !self.schema_is_present(&rename.new_id.schema)
        {
            if self.schema_absence_is_authoritative(&rename.new_id.schema) {
                return MutationResult::conflict(format!(
                    "schema '{}' does not exist",
                    rename.new_id.schema
                ));
            }
            return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
        }

        let schema_move = rename.old_id.schema != rename.new_id.schema;
        let associated_sequence_moves: Vec<(ObjectId, ObjectId)> = if schema_move {
            self.local
                .sequences
                .iter()
                .filter_map(|(id, overlay)| {
                    let SequenceOverlay::Present(sequence) = overlay else {
                        return None;
                    };
                    sequence
                        .owned_by
                        .as_ref()
                        .is_some_and(|(table, _)| table == &rename.old_id)
                        .then(|| {
                            (
                                id.clone(),
                                ObjectId::new(rename.new_id.schema.clone(), id.name.clone()),
                            )
                        })
                })
                .collect()
        } else {
            Vec::new()
        };
        let associated_index_moves: Vec<(ObjectId, ObjectId)> = if schema_move {
            self.local
                .graph
                .edges()
                .iter()
                .filter(|edge| {
                    matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                        && edge.referenced == rename.old_id
                })
                .map(|edge| {
                    (
                        edge.dependent.clone(),
                        ObjectId::new(rename.new_id.schema.clone(), edge.dependent.name.clone()),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        for (old_id, new_id) in associated_sequence_moves
            .iter()
            .chain(&associated_index_moves)
        {
            if old_id != new_id && self.relation_namespace_is_taken(new_id) {
                return MutationResult::conflict(format!(
                    "associated object '{}' already exists",
                    new_id
                ));
            }
        }

        let publication_scope_updates: Vec<(String, Vec<usize>)> = self
            .local
            .publications
            .iter()
            .filter_map(|(publication_name, overlay)| {
                let crate::_internal::model::replication::PublicationOverlay::Present(publication) =
                    overlay
                else {
                    return None;
                };
                let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                    &publication.scope
                else {
                    return None;
                };
                let indexes = objects
                    .iter()
                    .enumerate()
                    .filter_map(|(index, object)| {
                        let crate::_internal::analysis::facts::PublicationObjectFact::Table {
                            name,
                            ..
                        } = object
                        else {
                            return None;
                        };
                        (self.resolve_relation_id(name) == rename.old_id).then_some(index)
                    })
                    .collect::<Vec<_>>();
                (!indexes.is_empty()).then(|| (publication_name.clone(), indexes))
            })
            .collect();

        self.snapshot_namespace();
        if let Some(RelationOverlay::Present(mut state)) =
            self.local.relations.remove(&rename.old_id)
        {
            state.id = rename.new_id.clone();
            self.local
                .relations
                .insert(rename.new_id.clone(), RelationOverlay::Present(state));
        }
        let owned_sequence_ids: Vec<ObjectId> = self
            .local
            .sequences
            .iter()
            .filter_map(|(id, overlay)| match overlay {
                SequenceOverlay::Present(sequence)
                    if sequence
                        .owned_by
                        .as_ref()
                        .is_some_and(|(table, _)| table == &rename.old_id) =>
                {
                    Some(id.clone())
                }
                _ => None,
            })
            .collect();
        for sequence_id in owned_sequence_ids {
            self.snapshot_sequence(&sequence_id);
            if let Some(SequenceOverlay::Present(sequence)) =
                self.local.sequences.get_mut(&sequence_id)
                && let Some((table, _)) = &mut sequence.owned_by
            {
                *table = rename.new_id.clone();
            }
        }
        for (old_sequence_id, new_sequence_id) in &associated_sequence_moves {
            self.snapshot_sequence(old_sequence_id);
            self.snapshot_sequence(new_sequence_id);
            let Some(SequenceOverlay::Present(mut sequence)) =
                self.local.sequences.remove(old_sequence_id)
            else {
                continue;
            };
            sequence.id = new_sequence_id.clone();
            if let Some((table, _)) = &mut sequence.owned_by {
                *table = rename.new_id.clone();
            }
            self.local
                .sequences
                .insert(new_sequence_id.clone(), SequenceOverlay::Present(sequence));
            self.local
                .graph
                .propagate_sequence_rename(old_sequence_id, new_sequence_id);
            self.local.graph.add_edge(DependencyEdge::new(
                old_sequence_id.clone(),
                new_sequence_id.clone(),
                DependencyKind::RenameTo,
            ));
        }
        for (old_index_id, new_index_id) in &associated_index_moves {
            self.local
                .graph
                .propagate_index_rename(old_index_id, new_index_id);
            self.rename_index_catalog_references(old_index_id, new_index_id);
            self.local.graph.add_edge(DependencyEdge::new(
                old_index_id.clone(),
                new_index_id.clone(),
                DependencyKind::RenameTo,
            ));
        }
        let triggers_to_move: Vec<(ObjectId, crate::_internal::model::trigger::TriggerState)> =
            self.local
                .triggers
                .iter()
                .filter_map(|(id, overlay)| match overlay {
                    TriggerOverlay::Present(trigger) if trigger.table_id == rename.old_id => {
                        Some((id.clone(), trigger.clone()))
                    }
                    _ => None,
                })
                .collect();
        for (old_trigger_id, mut trigger) in triggers_to_move {
            let new_trigger_id = Self::trigger_key(&rename.new_id, &trigger.name);
            self.local.triggers.remove(&old_trigger_id);
            trigger.id = new_trigger_id.clone();
            trigger.table_id = rename.new_id.clone();
            self.local
                .triggers
                .insert(new_trigger_id.clone(), TriggerOverlay::Present(trigger));
            self.local
                .graph
                .propagate_trigger_rename(&old_trigger_id, &new_trigger_id);
            self.local.graph.add_edge(DependencyEdge::new(
                old_trigger_id,
                new_trigger_id,
                DependencyKind::RenameTo,
            ));
        }
        let constraints_to_move: Vec<(String, ConstraintState)> = self
            .local
            .constraints
            .iter()
            .filter(|((table_id, _), _)| table_id == &rename.old_id)
            .map(|((_, name), constraint)| (name.clone(), constraint.clone()))
            .collect();
        for (name, mut constraint) in constraints_to_move {
            self.snapshot_constraint(&rename.old_id, &name);
            self.snapshot_constraint(&rename.new_id, &name);
            self.local
                .constraints
                .remove(&(rename.old_id.clone(), name.clone()));
            constraint.table_id = rename.new_id.clone();
            self.local
                .constraints
                .insert((rename.new_id.clone(), name), constraint);
        }

        for (publication_name, object_indexes) in publication_scope_updates {
            self.snapshot_publication(&publication_name);
            if let Some(crate::_internal::model::replication::PublicationOverlay::Present(
                publication,
            )) = self.local.publications.get_mut(&publication_name)
                && let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                    &mut publication.scope
            {
                for index in object_indexes {
                    let Some(crate::_internal::analysis::facts::PublicationObjectFact::Table {
                        name,
                        ..
                    }) = objects.get_mut(index)
                    else {
                        continue;
                    };
                    let name_quoted = name.name.quoted;
                    let schema_quoted = name.schema.as_ref().is_some_and(|schema| schema.quoted);
                    name.name = crate::_internal::ast::identifiers::Ident::new(
                        rename.new_id.name.clone(),
                        name_quoted,
                    );
                    if name.schema.is_some() || rename.old_id.schema != rename.new_id.schema {
                        name.schema = Some(crate::_internal::ast::identifiers::Ident::new(
                            rename.new_id.schema.clone(),
                            schema_quoted,
                        ));
                    }
                }
            }
        }
        self.local.pending_validation = std::mem::take(&mut self.local.pending_validation)
            .into_iter()
            .map(|(table, name)| {
                if table == rename.old_id {
                    (rename.new_id.clone(), name)
                } else {
                    (table, name)
                }
            })
            .collect();
        self.local.graph.add_edge(DependencyEdge::new(
            rename.old_id.clone(),
            rename.new_id.clone(),
            DependencyKind::RenameTo,
        ));
        if renames_relation {
            self.local
                .graph
                .propagate_relation_rename(&rename.old_id, &rename.new_id);
        }
        if renames_index {
            self.local
                .graph
                .propagate_index_rename(&rename.old_id, &rename.new_id);
            self.rename_index_catalog_references(&rename.old_id, &rename.new_id);
        }

        if renames_relation {
            if self.baseline_relations.remove(&rename.old_id) {
                self.baseline_relations.insert(rename.new_id.clone());
            }
            if self.baseline_fk_dependencies.remove(&rename.old_id) {
                self.baseline_fk_dependencies.insert(rename.new_id.clone());
            }
            self.baseline_foreign_keys = std::mem::take(&mut self.baseline_foreign_keys)
                .into_iter()
                .map(|(table, name)| {
                    if table == rename.old_id {
                        (rename.new_id.clone(), name)
                    } else {
                        (table, name)
                    }
                })
                .collect();
        }
        if renames_index && self.baseline_indexes.remove(&rename.old_id) {
            self.baseline_indexes.insert(rename.new_id.clone());
        }
        for (old_sequence_id, new_sequence_id) in &associated_sequence_moves {
            if self.baseline_sequences.remove(old_sequence_id) {
                self.baseline_sequences.insert(new_sequence_id.clone());
            }
        }
        for (old_index_id, new_index_id) in &associated_index_moves {
            if self.baseline_indexes.remove(old_index_id) {
                self.baseline_indexes.insert(new_index_id.clone());
            }
        }

        MutationResult::Applied
    }

    // The caller takes a namespace snapshot before changing these coupled identities.
    pub(super) fn rename_index_catalog_references(&mut self, old: &ObjectId, new: &ObjectId) {
        let constraints = self
            .local
            .constraints
            .values()
            .filter(|constraint| constraint.backing_index.as_ref() == Some(old))
            .cloned()
            .collect::<Vec<_>>();
        for mut constraint in constraints {
            let old_name = constraint.name.clone();
            let owns_index = matches!(
                constraint.kind,
                ConstraintKind::PrimaryKey | ConstraintKind::Unique | ConstraintKind::Exclusion
            );
            if owns_index && old.name != new.name {
                constraint.name = new.name.clone();
            }
            self.local
                .constraints
                .remove(&(constraint.table_id.clone(), old_name.clone()));
            constraint.backing_index = Some(new.clone());
            if old_name != constraint.name {
                self.local.graph.rename_constraint(
                    &constraint.table_id,
                    &old_name,
                    &constraint.name,
                );
            }
            self.local.constraints.insert(
                (constraint.table_id.clone(), constraint.name.clone()),
                constraint,
            );
        }
        if old.name == new.name {
            return;
        }
        let old_replica = format!("USING INDEX {}", old.name);
        for (id, overlay) in &mut self.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            if id.schema != old.schema {
                continue;
            }
            if relation.cluster_index.as_deref() == Some(old.name.as_str()) {
                relation.cluster_index = Some(new.name.clone());
            }
            if relation.replica_identity.as_deref() == Some(old_replica.as_str()) {
                relation.replica_identity = Some(format!("USING INDEX {}", new.name));
            }
        }
    }

    pub(in crate::_internal::analysis::state) fn apply_change_relation_owner(
        &mut self,
        id: &ObjectId,
        new_owner: &crate::_internal::analysis::facts::RoleFact,
    ) -> MutationResult {
        let Some((owner, known)) = self.role_fact_identity(new_owner) else {
            return self.unresolved(EvidenceCode::UnresolvedReference);
        };
        if !known {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        if known && self.local.roles_known && self.present_role(&owner).is_none() {
            return MutationResult::conflict(format!("role '{}' does not exist", owner));
        }
        if known && !self.local.roles_known {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        match self.relation_lookup(id, |_| true) {
            RelationLookup::Present => {
                let owner_id = ObjectId::new("", owner.clone());
                self.snapshot_relation(id);
                {
                    let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(id)
                    else {
                        unreachable!("relation lookup established presence")
                    };
                    relation.owner = owner_id.clone();
                }
                self.transfer_owned_sequence_owners(id, &owner_id);
                MutationResult::Applied
            }
            RelationLookup::WrongKind => {
                unreachable!("all present relation kinds accept owner changes")
            }
            RelationLookup::Tombstone | RelationLookup::AuthoritativelyAbsent => {
                MutationResult::conflict(format!("relation '{}' does not exist", id))
            }
            RelationLookup::Unknown => self.unresolved(EvidenceCode::UnknownObjectState),
        }
    }

    /// PostgreSQL transfers ownership of sequences owned by table columns
    /// together with the table. Keep this dependent metadata synchronized for
    /// both ALTER TABLE OWNER and the direct relation-owner mutation path.
    pub(super) fn transfer_owned_sequence_owners(&mut self, table: &ObjectId, owner: &ObjectId) {
        let owned_sequence_ids: Vec<ObjectId> = self
            .local
            .sequences
            .iter()
            .filter_map(|(sequence_id, overlay)| {
                let SequenceOverlay::Present(sequence) = overlay else {
                    return None;
                };
                sequence
                    .owned_by
                    .as_ref()
                    .is_some_and(|(owned_table, _)| owned_table == table)
                    .then_some(sequence_id.clone())
            })
            .collect();
        for sequence_id in owned_sequence_ids {
            self.snapshot_sequence(&sequence_id);
            if let Some(SequenceOverlay::Present(sequence)) =
                self.local.sequences.get_mut(&sequence_id)
            {
                sequence.owner = owner.clone();
            }
        }
    }
}
