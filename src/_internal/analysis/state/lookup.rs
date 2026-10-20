use super::*;

impl AnalysisState {
    /// Whether an inferred identity cannot be relied on: an unresolved path
    /// entry precedes the schema the search resolved to, so PostgreSQL may
    /// have answered from a schema the model cannot see.
    pub(super) fn lookup_shadowed(&self, id: &ObjectId) -> bool {
        id.inferred_schema && self.path_shadows(&id.schema)
    }

    pub(super) fn relation_lookup(
        &self,
        id: &ObjectId,
        expected: impl FnOnce(&RelationKind) -> bool,
    ) -> ObjectLookup {
        if self.lookup_shadowed(id) {
            return ObjectLookup::Unknown;
        }
        match self.local.relations.get(id) {
            Some(RelationOverlay::Present(relation)) if expected(&relation.kind) => {
                ObjectLookup::Present
            }
            Some(RelationOverlay::Present(_)) => ObjectLookup::WrongKind,
            Some(RelationOverlay::Dropped) => ObjectLookup::Tombstone,
            None if self.sequence_is_present(id) || self.index_is_present(id) => {
                ObjectLookup::WrongKind
            }
            None if self.baseline_covers_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Relations,
            ) =>
            {
                ObjectLookup::AuthoritativelyAbsent
            }
            None => ObjectLookup::Unknown,
        }
    }

    /// Validate a relation reference before a mutation creates a dependent
    /// object.  A scoped baseline cannot prove anything about an omitted
    /// schema, so leave the state conservative instead of inventing an edge.
    pub(super) fn ensure_relation_target<F>(
        &mut self,
        id: &ObjectId,
        expected: F,
        missing_reason: String,
        wrong_kind_reason: String,
    ) -> Result<(), MutationResult>
    where
        F: FnOnce(&RelationKind) -> bool,
    {
        match self.relation_lookup(id, expected) {
            ObjectLookup::Present => Ok(()),
            ObjectLookup::WrongKind => Err(MutationResult::conflict(wrong_kind_reason)),
            ObjectLookup::AuthoritativelyAbsent | ObjectLookup::Tombstone => {
                Err(MutationResult::conflict(missing_reason))
            }
            ObjectLookup::Unknown => Err(self.unresolved(EvidenceCode::UnknownObjectState)),
        }
    }

    pub(super) fn type_lookup(
        &self,
        id: &ObjectId,
        expected: impl FnOnce(&TypeKind) -> bool,
    ) -> ObjectLookup {
        if self.lookup_shadowed(id) {
            return ObjectLookup::Unknown;
        }
        match self.local.types.get(id) {
            Some(TypeOverlay::Present(state)) if expected(&state.kind) => ObjectLookup::Present,
            Some(TypeOverlay::Present(_)) => ObjectLookup::WrongKind,
            Some(TypeOverlay::Dropped) => ObjectLookup::Tombstone,
            None if self.baseline_covers_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Types,
            ) =>
            {
                ObjectLookup::AuthoritativelyAbsent
            }
            None => ObjectLookup::Unknown,
        }
    }

    pub(super) fn ensure_routine_target(
        &mut self,
        id: &ObjectId,
        expected: crate::_internal::model::function::RoutineKind,
        missing_reason: String,
        wrong_kind_reason: String,
    ) -> Result<(), MutationResult> {
        if self.lookup_shadowed(id) {
            return Err(self.unresolved(EvidenceCode::UnknownObjectState));
        }
        match self.local.functions.get(id) {
            Some(FunctionOverlay::Present(function)) if function.routine_kind == expected => Ok(()),
            Some(FunctionOverlay::Present(_)) => Err(MutationResult::conflict(wrong_kind_reason)),
            Some(FunctionOverlay::Dropped) => Err(MutationResult::conflict(missing_reason)),
            None if self.baseline_covers_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Routines,
            ) =>
            {
                Err(MutationResult::conflict(missing_reason))
            }
            None => Err(self.unresolved(EvidenceCode::UnknownObjectState)),
        }
    }

    /// Validate the namespace a creation targets, where an unqualified target
    /// was inferred from the search path.
    ///
    /// An unresolved entry before the chosen schema means PostgreSQL may have
    /// picked a different target entirely, which is uncertain — not a conflict.
    pub(super) fn ensure_creation_target(&mut self, id: &ObjectId) -> Result<(), MutationResult> {
        if is_session_temp_schema(&id.schema) {
            return Ok(());
        }
        if self.lookup_shadowed(id) {
            return Err(self.unresolved(EvidenceCode::UnknownObjectState));
        }
        self.ensure_schema_target(&id.schema)
    }

    /// Validate the namespace in which a newly-created object will live.
    ///
    /// A full baseline (or an explicit schema creation earlier in the chain)
    /// can prove that a schema exists.  An omitted scoped schema is unknown;
    /// do not manufacture an object there while claiming an exact result.
    pub(super) fn ensure_schema_target(&mut self, schema: &str) -> Result<(), MutationResult> {
        // The session temporary schema is created on first use, so it is always
        // a valid target and never something the catalog can prove absent.
        if is_session_temp_schema(schema) {
            return Ok(());
        }
        match self.schema_lookup(schema) {
            ObjectLookup::Present => Ok(()),
            ObjectLookup::Tombstone | ObjectLookup::AuthoritativelyAbsent => {
                Err(MutationResult::conflict(if schema.is_empty() {
                    "no schema has been selected to create in".to_string()
                } else {
                    format!("schema '{}' does not exist", schema)
                }))
            }
            ObjectLookup::Unknown => Err(self.unresolved(EvidenceCode::UnknownObjectState)),
            ObjectLookup::WrongKind => {
                unreachable!("schemas do not share an overlay with other object kinds")
            }
        }
    }

    pub(super) fn snapshot_baseline_foreign_keys(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame
                .undo_log
                .push(StateChange::BaselineForeignKeysSnapshot {
                    previous: self.baseline_foreign_keys.clone(),
                });
        }
    }

    /// Remove constraint metadata and baseline FK identities for objects that
    /// PostgreSQL drops as part of a relation dependency operation.
    pub(super) fn remove_dropped_constraints(
        &mut self,
        dropped_relations: &HashSet<ObjectId>,
        dropped_constraints: &HashSet<(ObjectId, String)>,
    ) {
        let resolution_graph = self.local.graph.clone();
        let should_remove = |table_id: &ObjectId, name: &str| {
            let resolved_table = resolution_graph.resolve_rename(table_id);
            dropped_relations.contains(resolved_table)
                || dropped_constraints.contains(&(resolved_table.clone(), name.to_string()))
        };

        let constraint_keys: Vec<(ObjectId, String)> = self
            .local
            .constraints
            .keys()
            .filter(|(table_id, name)| should_remove(table_id, name))
            .cloned()
            .collect();
        for (table_id, name) in constraint_keys {
            self.snapshot_constraint(&table_id, &name);
            self.local.constraints.remove(&(table_id, name));
        }

        let pending_changed = self
            .local
            .pending_validation
            .iter()
            .any(|(table_id, name)| should_remove(table_id, name));
        if pending_changed {
            self.snapshot_pending_validation();
            self.local
                .pending_validation
                .retain(|(table_id, name)| !should_remove(table_id, name));
        }

        if self
            .baseline_foreign_keys
            .iter()
            .any(|(table_id, name)| should_remove(table_id, name))
        {
            self.snapshot_baseline_foreign_keys();
            self.baseline_foreign_keys
                .retain(|(table_id, name)| !should_remove(table_id, name));
        }
    }

    pub(crate) fn baseline_scope_omits_displayed_object<'a>(
        &self,
        object_name: &'a str,
    ) -> Option<&'a str> {
        let schemas = self.baseline_schemas.as_ref()?;

        // Avoid falsely extracting "a" from "a.b" when a schema contains a dot.
        // If the object name is prefixed by a known scope, it is covered.
        for schema in schemas {
            if object_name.starts_with(schema)
                && object_name.as_bytes().get(schema.len()) == Some(&b'.')
            {
                return None;
            }
        }

        let (schema, _) = object_name.split_once('.')?;
        Some(schema)
    }

    pub(crate) fn sequence_is_present(&self, id: &ObjectId) -> bool {
        matches!(
            self.local.sequences.get(id),
            Some(SequenceOverlay::Present(_))
        )
    }

    pub(crate) fn type_is_present(&self, id: &ObjectId) -> bool {
        matches!(self.local.types.get(id), Some(TypeOverlay::Present(_)))
    }

    pub(crate) fn routine_is_present(&self, id: &ObjectId) -> bool {
        matches!(
            self.local.functions.get(id),
            Some(FunctionOverlay::Present(_))
        )
    }

    /// Whether any overload of `id`'s name is present in `id`'s schema, for a
    /// routine reference that carries no argument types.
    pub(crate) fn routine_named_is_present(&self, id: &ObjectId) -> bool {
        self.local.functions.iter().any(|(candidate, overlay)| {
            matches!(overlay, FunctionOverlay::Present(_))
                && candidate.schema == id.schema
                && bare_routine_name(&candidate.name) == id.name
        })
    }
}
