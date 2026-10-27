use super::*;

impl AnalysisState {
    pub(super) fn snapshot_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::GraphLengthMarker {
                len: self.local.graph.edge_count(),
            });
        }
    }

    pub(super) fn snapshot_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::GraphSnapshot {
                previous: self.local.graph.edges().to_vec(),
            });
        }
    }

    pub(super) fn rollback_frame(&mut self, mut frame: TransactionFrame) {
        self.rollback_undo_log(std::mem::take(&mut frame.undo_log));
    }

    pub(super) fn rollback_undo_log(&mut self, mut undo_log: Vec<StateChange>) {
        while let Some(change) = undo_log.pop() {
            match change {
                StateChange::SchemaSnapshot { name, previous } => match previous {
                    Some(overlay) => {
                        self.local.schemas.insert(name, overlay);
                    }
                    None => {
                        self.local.schemas.remove(&name);
                    }
                },
                StateChange::NamespaceSnapshot(snapshot) => {
                    self.local.schemas = snapshot.schemas;
                    self.local.relations = snapshot.relations;
                    self.local.types = snapshot.types;
                    self.local.functions = snapshot.functions;
                    self.local.sequences = snapshot.sequences;
                    self.local.extensions = snapshot.extensions;
                    self.local.publications = snapshot.publications;
                    self.local.triggers = snapshot.triggers;
                    self.local.constraints = snapshot.constraints;
                    self.local.graph.replace_edges(snapshot.graph);
                    self.local.pending_validation = snapshot.pending_validation;
                    self.baseline_relations = snapshot.baseline_relations;
                    self.baseline_indexes = snapshot.baseline_indexes;
                    self.baseline_foreign_keys = snapshot.baseline_foreign_keys;
                    self.baseline_fk_dependencies = snapshot.baseline_fk_dependencies;
                    self.baseline_sequences = snapshot.baseline_sequences;
                    self.scoped_external_dependencies = snapshot.scoped_external_dependencies;
                    self.baseline_schemas = snapshot.baseline_schemas;
                    self.local.search_path = snapshot.search_path;
                    self.local.search_path_template = snapshot.search_path_template;
                    self.local.session_search_path_template = snapshot.session_search_path_template;
                }
                StateChange::RelationSnapshot { id, previous } => {
                    if let Some(prev) = *previous {
                        self.local.relations.insert(id, prev);
                    } else {
                        self.local.relations.remove(&id);
                    }
                }
                StateChange::TypeSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.types.insert(id, prev);
                    } else {
                        self.local.types.remove(&id);
                    }
                }
                StateChange::SequenceSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.sequences.insert(id, prev);
                    } else {
                        self.local.sequences.remove(&id);
                    }
                }
                StateChange::ExtensionSnapshot { name, previous } => {
                    if let Some(prev) = previous {
                        self.local.extensions.insert(name, prev);
                    } else {
                        self.local.extensions.remove(&name);
                    }
                }
                StateChange::FunctionSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.functions.insert(id, prev);
                    } else {
                        self.local.functions.remove(&id);
                    }
                }
                StateChange::PublicationSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.publications.insert(id.name, prev);
                    } else {
                        self.local.publications.remove(&id.name);
                    }
                }
                StateChange::SubscriptionSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.subscriptions.insert(id.name, prev);
                    } else {
                        self.local.subscriptions.remove(&id.name);
                    }
                }
                StateChange::RoleSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.roles.insert(id, prev);
                    } else {
                        self.local.roles.remove(&id);
                    }
                }
                StateChange::RoleMembershipGrantorsSnapshot {
                    previous,
                    previous_complete,
                } => {
                    self.local.role_membership_grantors = previous;
                    self.local.role_membership_grantors_complete = previous_complete;
                }
                StateChange::TriggerSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.triggers.insert(id, prev);
                    } else {
                        self.local.triggers.remove(&id);
                    }
                }
                StateChange::ConstraintSnapshot {
                    table_id,
                    name,
                    previous,
                } => {
                    let key = (table_id, name);
                    if let Some(previous) = previous {
                        self.local.constraints.insert(key, previous);
                    } else {
                        self.local.constraints.remove(&key);
                    }
                }
                StateChange::BaselineForeignKeysSnapshot { previous } => {
                    self.baseline_foreign_keys = previous;
                }
                StateChange::GraphLengthMarker { len } => {
                    self.local.graph.truncate(len);
                }
                StateChange::GraphSnapshot { previous } => {
                    self.local.graph.replace_edges(previous);
                }
                StateChange::RoleContextSnapshot {
                    current_role,
                    current_role_known,
                    persistent_current_role,
                    persistent_current_role_known,
                    session_role,
                    session_role_known,
                    persistent_session_role,
                    persistent_session_role_known,
                } => {
                    self.local.current_role = current_role;
                    self.local.current_role_known = current_role_known;
                    self.local.persistent_current_role = persistent_current_role;
                    self.local.persistent_current_role_known = persistent_current_role_known;
                    self.local.session_role = session_role;
                    self.local.session_role_known = session_role_known;
                    self.local.persistent_session_role = persistent_session_role;
                    self.local.persistent_session_role_known = persistent_session_role_known;
                }
                StateChange::SearchPathSnapshot {
                    previous,
                    previous_template,
                    previous_session_template,
                } => {
                    self.local.search_path = previous;
                    self.local.search_path_template = previous_template;
                    self.local.session_search_path_template = previous_session_template;
                }
                StateChange::TimeoutSettingsSnapshot {
                    lock_timeout,
                    statement_timeout,
                } => {
                    self.local.lock_timeout = lock_timeout;
                    self.local.statement_timeout = statement_timeout;
                }
                StateChange::GenerationCounterSnapshot { previous } => {
                    self.local.generation_counter = previous;
                }
                StateChange::PendingValidationSnapshot { previous } => {
                    self.local.pending_validation = previous;
                }
                StateChange::ConfidenceSnapshot { previous } => {
                    self.local.confidence = previous;
                }
                StateChange::EvidenceSnapshot { previous } => {
                    self.local.evidence = previous;
                }
            }
        }
        debug_assert!(self.local.graph.indexes_are_valid());
    }

    pub(crate) fn transaction_undo_checkpoint(&self) -> Option<(usize, usize)> {
        self.local
            .transactions
            .last()
            .map(|frame| (self.local.transactions.len(), frame.undo_log.len()))
    }

    pub(crate) fn rollback_to_transaction_undo_checkpoint(
        &mut self,
        transaction_depth: usize,
        undo_len: usize,
    ) -> Result<(), &'static str> {
        if self.local.transactions.len() != transaction_depth {
            return Err("statement changed transaction depth while using an undo checkpoint");
        }
        let Some(frame) = self.local.transactions.last_mut() else {
            return Err("statement undo checkpoint lost its transaction frame");
        };
        if frame.undo_log.len() < undo_len {
            return Err("statement shortened the transaction undo log unexpectedly");
        }
        let statement_undo = frame.undo_log.split_off(undo_len);
        self.rollback_undo_log(statement_undo);
        debug_assert!(self.local.graph.indexes_are_valid());
        Ok(())
    }
}
