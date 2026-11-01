use super::*;

impl AnalysisState {
    pub(super) fn snapshot_relation(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.relations.get(id).cloned();
            frame.undo_log.push(StateChange::RelationSnapshot {
                id: id.clone(),
                previous: Box::new(previous),
            });
        }
    }

    pub(super) fn snapshot_schema(&mut self, name: &str) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::SchemaSnapshot {
                name: name.to_string(),
                previous: self.local.schemas.get(name).cloned(),
            });
        }
    }

    pub(super) fn snapshot_namespace(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::NamespaceSnapshot(Box::new(
                NamespaceSnapshot {
                    schemas: self.local.schemas.clone(),
                    relations: self.local.relations.clone(),
                    types: self.local.types.clone(),
                    functions: self.local.functions.clone(),
                    sequences: self.local.sequences.clone(),
                    collations: self.local.collations.clone(),
                    extensions: self.local.extensions.clone(),
                    publications: self.local.publications.clone(),
                    triggers: self.local.triggers.clone(),
                    constraints: self.local.constraints.clone(),
                    graph: self.local.graph.edges().to_vec(),
                    pending_validation: self.local.pending_validation.clone(),
                    baseline_relations: self.baseline_relations.clone(),
                    baseline_indexes: self.baseline_indexes.clone(),
                    baseline_foreign_keys: self.baseline_foreign_keys.clone(),
                    baseline_fk_dependencies: self.baseline_fk_dependencies.clone(),
                    baseline_sequences: self.baseline_sequences.clone(),
                    scoped_external_dependencies: self.scoped_external_dependencies.clone(),
                    baseline_schemas: self.baseline_schemas.clone(),
                    search_path: self.local.search_path.clone(),
                    search_path_template: self.local.search_path_template.clone(),
                    session_search_path_template: self.local.session_search_path_template.clone(),
                },
            )));
        }
    }

    pub(super) fn snapshot_type(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.types.get(id).cloned();
            frame.undo_log.push(StateChange::TypeSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    pub(super) fn snapshot_sequence(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.sequences.get(id).cloned();
            frame.undo_log.push(StateChange::SequenceSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    pub(super) fn snapshot_extension(&mut self, name: &str) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::ExtensionSnapshot {
                name: name.to_string(),
                previous: self.local.extensions.get(name).cloned(),
            });
        }
    }

    pub(super) fn move_function(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        self.snapshot_function(old_id);
        self.snapshot_function(new_id);
        if let Some(crate::_internal::model::function::FunctionOverlay::Present(mut function)) =
            self.local.functions.remove(old_id)
        {
            function.id = new_id.clone();
            self.local.functions.insert(
                new_id.clone(),
                crate::_internal::model::function::FunctionOverlay::Present(function),
            );
        }

        self.snapshot_graph_full();
        self.local.graph.propagate_function_rename(old_id, new_id);
        self.remap_range_routine_reference(old_id, new_id);
        self.local.graph.add_edge(DependencyEdge::new(
            old_id.clone(),
            new_id.clone(),
            DependencyKind::RenameTo,
        ));

        // A name-only view reference follows the move only when the whole
        // written name moved. If an overload of the old name remains, the
        // reference may name either routine, so the chain stops being exact.
        let (old_schema, old_name) = DependencyGraph::split_routine_signature(old_id);
        let old_written_name = ObjectId::new(old_schema, old_name.to_string());
        if self
            .local
            .graph
            .has_view_reference_to_name(&old_written_name)
        {
            if self.routine_overloads_under(&old_written_name).count() > 0 {
                self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
            } else {
                let (new_schema, new_name) = DependencyGraph::split_routine_signature(new_id);
                self.local.graph.propagate_view_reference_rename(
                    &old_written_name,
                    &ObjectId::new(new_schema, new_name.to_string()),
                );
            }
        }
    }

    pub(super) fn validate_function_move(
        &mut self,
        old_id: &ObjectId,
        new_id: &ObjectId,
    ) -> Result<(), MutationResult> {
        if old_id == new_id {
            return Ok(());
        }
        self.ensure_schema_target(&new_id.schema)?;
        match self.local.functions.get(new_id) {
            Some(crate::_internal::model::function::FunctionOverlay::Present(_)) => Err(
                MutationResult::conflict(format!("routine '{}' already exists", new_id)),
            ),
            // A prior DROP in this migration leaves a tombstone but the
            // namespace is available again, just as it is in PostgreSQL.
            Some(crate::_internal::model::function::FunctionOverlay::Dropped) => Ok(()),
            None => Ok(()),
        }
    }

    pub(super) fn snapshot_function(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.functions.get(id).cloned();
            frame.undo_log.push(StateChange::FunctionSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    pub(super) fn snapshot_publication(&mut self, name: &str) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.publications.get(name).cloned();
            frame.undo_log.push(StateChange::PublicationSnapshot {
                id: ObjectId::new("", name),
                previous,
            });
        }
    }

    pub(super) fn snapshot_subscription(&mut self, name: &str) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.subscriptions.get(name).cloned();
            frame.undo_log.push(StateChange::SubscriptionSnapshot {
                id: ObjectId::new("", name),
                previous,
            });
        }
    }

    pub(super) fn snapshot_role(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.roles.get(id).cloned();
            frame.undo_log.push(StateChange::RoleSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    pub(super) fn snapshot_role_membership_grantors(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame
                .undo_log
                .push(StateChange::RoleMembershipGrantorsSnapshot {
                    previous: self.local.role_membership_grantors.clone(),
                    previous_complete: self.local.role_membership_grantors_complete,
                });
        }
    }

    pub(super) fn snapshot_trigger(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.triggers.get(id).cloned();
            frame.undo_log.push(StateChange::TriggerSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    pub(super) fn snapshot_constraint(&mut self, table_id: &ObjectId, name: &str) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let key = (table_id.clone(), name.to_string());
            let previous = self.local.constraints.get(&key).cloned();
            frame.undo_log.push(StateChange::ConstraintSnapshot {
                table_id: table_id.clone(),
                name: name.to_string(),
                previous,
            });
        }
    }

    pub(super) fn snapshot_role_context(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::RoleContextSnapshot {
                current_role: self.local.current_role.clone(),
                current_role_known: self.local.current_role_known,
                persistent_current_role: self.local.persistent_current_role.clone(),
                persistent_current_role_known: self.local.persistent_current_role_known,
                session_role: self.local.session_role.clone(),
                session_role_known: self.local.session_role_known,
                persistent_session_role: self.local.persistent_session_role.clone(),
                persistent_session_role_known: self.local.persistent_session_role_known,
            });
        }
    }

    pub(super) fn snapshot_search_path(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::SearchPathSnapshot {
                previous: self.local.search_path.clone(),
                previous_template: self.local.search_path_template.clone(),
                previous_session_template: self.local.session_search_path_template.clone(),
            });
        }
    }

    pub(super) fn snapshot_timeout_settings(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::TimeoutSettingsSnapshot {
                lock_timeout: self.local.lock_timeout.clone(),
                statement_timeout: self.local.statement_timeout.clone(),
            });
        }
    }

    pub(super) fn snapshot_generation_counter(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::GenerationCounterSnapshot {
                previous: self.local.generation_counter,
            });
        }
    }

    pub(super) fn snapshot_pending_validation(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::PendingValidationSnapshot {
                previous: self.local.pending_validation.clone(),
            });
        }
    }

    pub(super) fn snapshot_confidence(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::ConfidenceSnapshot {
                previous: self.local.confidence.clone(),
            });
        }
    }

    pub(super) fn snapshot_evidence(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::EvidenceSnapshot {
                previous: self.local.evidence.clone(),
            });
        }
    }
}
