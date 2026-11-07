use super::*;

impl LocalState {
    pub(super) fn records_undo(&self) -> bool {
        self.statement_undo_log.is_some() || !self.transactions.is_empty()
    }

    pub(super) fn push_undo(&mut self, change: StateChange) {
        // A statement journal takes precedence so a failing transaction-control
        // statement cannot rewrite an enclosing frame's undo history.
        if let Some(log) = self.statement_undo_log.as_mut() {
            log.push(change);
        } else if let Some(frame) = self.transactions.last_mut() {
            frame.undo_log.push(change);
        } else {
            debug_assert!(false, "undo change recorded without an undo target");
        }
    }
}

impl AnalysisState {
    pub(super) fn snapshot_relation(&mut self, id: &ObjectId) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.relations.get(id).cloned();
        self.local.push_undo(StateChange::RelationSnapshot {
            id: id.clone(),
            previous: Box::new(previous),
        });
    }

    pub(super) fn snapshot_relation_rename(&mut self, old: &ObjectId, new: &ObjectId) {
        if !self.local.records_undo() || old == new {
            return;
        }
        debug_assert!(
            !matches!(
                self.local.relations.get(new),
                Some(RelationOverlay::Present(_))
            ),
            "rename target must be absent or a tombstone"
        );
        let previous_new = self.local.relations.get(new).cloned();
        self.local.push_undo(StateChange::RelationRename {
            old_id: old.clone(),
            new_id: new.clone(),
            previous_new: Box::new(previous_new),
        });
    }

    pub(super) fn snapshot_schema(&mut self, name: &str) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.schemas.get(name).cloned();
        self.local.push_undo(StateChange::SchemaSnapshot {
            name: name.to_string(),
            previous,
        });
    }

    pub(super) fn snapshot_namespace(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let snapshot = NamespaceSnapshot {
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
        };
        self.local
            .push_undo(StateChange::NamespaceSnapshot(Box::new(snapshot)));
    }

    pub(super) fn snapshot_type(&mut self, id: &ObjectId) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.types.get(id).cloned();
        self.local.push_undo(StateChange::TypeSnapshot {
            id: id.clone(),
            previous,
        });
    }

    pub(super) fn snapshot_sequence_rename(&mut self, old: &ObjectId, new: &ObjectId) {
        if !self.local.records_undo() || old == new {
            return;
        }
        debug_assert!(
            !matches!(
                self.local.sequences.get(new),
                Some(SequenceOverlay::Present(_))
            ),
            "rename target must be absent or a tombstone"
        );
        let previous_new = self.local.sequences.get(new).cloned();
        self.local.push_undo(StateChange::SequenceRename {
            old_id: old.clone(),
            new_id: new.clone(),
            previous_new: Box::new(previous_new),
        });
    }

    pub(super) fn snapshot_sequence(&mut self, id: &ObjectId) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.sequences.get(id).cloned();
        self.local.push_undo(StateChange::SequenceSnapshot {
            id: id.clone(),
            previous,
        });
    }

    pub(super) fn snapshot_extension(&mut self, name: &str) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.extensions.get(name).cloned();
        self.local.push_undo(StateChange::ExtensionSnapshot {
            name: name.to_string(),
            previous,
        });
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
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.functions.get(id).cloned();
        self.local.push_undo(StateChange::FunctionSnapshot {
            id: id.clone(),
            previous,
        });
    }

    pub(super) fn snapshot_publication(&mut self, name: &str) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.publications.get(name).cloned();
        self.local.push_undo(StateChange::PublicationSnapshot {
            id: ObjectId::new("", name),
            previous,
        });
    }

    pub(super) fn snapshot_subscription(&mut self, name: &str) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.subscriptions.get(name).cloned();
        self.local.push_undo(StateChange::SubscriptionSnapshot {
            id: ObjectId::new("", name),
            previous,
        });
    }

    pub(super) fn snapshot_role(&mut self, id: &ObjectId) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.roles.get(id).cloned();
        self.local.push_undo(StateChange::RoleSnapshot {
            id: id.clone(),
            previous,
        });
    }

    pub(super) fn snapshot_role_membership_grantors(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.role_membership_grantors.clone();
        let previous_complete = self.local.role_membership_grantors_complete;
        self.local
            .push_undo(StateChange::RoleMembershipGrantorsSnapshot {
                previous,
                previous_complete,
            });
    }

    pub(super) fn snapshot_trigger(&mut self, id: &ObjectId) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.triggers.get(id).cloned();
        self.local.push_undo(StateChange::TriggerSnapshot {
            id: id.clone(),
            previous,
        });
    }

    pub(super) fn snapshot_constraint(&mut self, table_id: &ObjectId, name: &str) {
        if !self.local.records_undo() {
            return;
        }
        let key = (table_id.clone(), name.to_string());
        let previous = self.local.constraints.get(&key).cloned();
        self.local.push_undo(StateChange::ConstraintSnapshot {
            table_id: table_id.clone(),
            name: name.to_string(),
            previous,
        });
    }

    pub(super) fn snapshot_role_context(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        self.local.push_undo(StateChange::RoleContextSnapshot {
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

    pub(super) fn snapshot_temp_namespace(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.temp_namespace_created;
        let previous_search_path = self.local.search_path.clone();
        self.local.push_undo(StateChange::TempNamespaceSnapshot {
            previous,
            previous_search_path,
        });
    }

    pub(super) fn snapshot_search_path(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.search_path.clone();
        let previous_template = self.local.search_path_template.clone();
        let previous_session_template = self.local.session_search_path_template.clone();
        self.local.push_undo(StateChange::SearchPathSnapshot {
            previous,
            previous_template,
            previous_session_template,
        });
    }

    pub(super) fn snapshot_timeout_settings(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let lock_timeout = self.local.lock_timeout.clone();
        let statement_timeout = self.local.statement_timeout.clone();
        self.local.push_undo(StateChange::TimeoutSettingsSnapshot {
            lock_timeout,
            statement_timeout,
        });
    }

    pub(super) fn snapshot_generation_counter(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.generation_counter;
        self.local
            .push_undo(StateChange::GenerationCounterSnapshot { previous });
    }

    pub(super) fn snapshot_pending_validation(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.pending_validation.clone();
        self.local
            .push_undo(StateChange::PendingValidationSnapshot { previous });
    }

    pub(super) fn snapshot_baseline_set_rename(
        &mut self,
        set: BaselineSet,
        old: &ObjectId,
        new: &ObjectId,
    ) {
        if !self.local.records_undo() {
            return;
        }
        let (old_present, new_present) = match set {
            BaselineSet::Relations => (
                self.baseline_relations.contains(old),
                self.baseline_relations.contains(new),
            ),
            BaselineSet::Indexes => (
                self.baseline_indexes.contains(old),
                self.baseline_indexes.contains(new),
            ),
            BaselineSet::FkDependencies => (
                self.baseline_fk_dependencies.contains(old),
                self.baseline_fk_dependencies.contains(new),
            ),
            BaselineSet::Sequences => (
                self.baseline_sequences.contains(old),
                self.baseline_sequences.contains(new),
            ),
        };
        self.local
            .push_undo(StateChange::BaselineSetRenameSnapshot {
                set,
                old: old.clone(),
                new: new.clone(),
                old_present,
                new_present,
            });
    }

    pub(super) fn snapshot_confidence(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.local.confidence.clone();
        self.local
            .push_undo(StateChange::ConfidenceSnapshot { previous });
    }

    pub(super) fn snapshot_evidence(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let len = self.local.evidence.records().len();
        self.local
            .push_undo(StateChange::EvidenceLengthMarker { len });
    }

    pub(super) fn snapshot_not_evaluated(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.not_evaluated.clone();
        self.local
            .push_undo(StateChange::NotEvaluatedSnapshot { previous });
    }

    pub(super) fn snapshot_co_dropped_objects(&mut self) {
        if !self.local.records_undo() {
            return;
        }
        let previous = self.co_dropped_objects.clone();
        self.local
            .push_undo(StateChange::CoDroppedObjectsSnapshot { previous });
    }
}
