use super::*;

impl AnalysisState {
    pub(crate) fn column_was_added_in_transaction(
        &self,
        table_id: &ObjectId,
        column: &str,
    ) -> bool {
        if self.local.transactions.is_empty() {
            return false;
        }

        // Search from the oldest transaction frame to the newest
        for frame in &self.local.transactions {
            for change in &frame.undo_log {
                if let StateChange::RelationSnapshot { id, previous } = change
                    && id == table_id
                {
                    match previous.as_ref() {
                        None | Some(RelationOverlay::Dropped) => {
                            return true;
                        }
                        Some(RelationOverlay::Present(r)) => {
                            let col_existed = r.columns.iter().any(|c| c.name == column);
                            return !col_existed;
                        }
                    }
                }
            }
        }
        false
    }

    #[cfg(test)]
    pub(crate) fn capture_pre_state(&self) -> PreState {
        let mut pre_state = PreState::default();
        self.capture_pre_state_into(&mut pre_state);
        pre_state
    }

    pub(crate) fn capture_pre_state_into(&self, pre_state: &mut PreState) {
        let PreState {
            relations,
            functions,
            roles,
            publications,
            subscriptions,
            sequences,
            types,
            indexes,
            baseline_foreign_keys,
        } = pre_state;

        sync_present_map(relations, &self.local.relations, |overlay| match overlay {
            RelationOverlay::Present(state) => Some(state),
            RelationOverlay::Dropped => None,
        });
        sync_present_map(functions, &self.local.functions, |overlay| match overlay {
            crate::_internal::model::function::FunctionOverlay::Present(state) => Some(state),
            crate::_internal::model::function::FunctionOverlay::Dropped => None,
        });
        sync_present_map(roles, &self.local.roles, |overlay| match overlay {
            crate::_internal::model::role::RoleOverlay::Present(state) => Some(state),
            crate::_internal::model::role::RoleOverlay::Dropped => None,
        });
        sync_present_map(
            publications,
            &self.local.publications,
            |overlay| match overlay {
                crate::_internal::model::replication::PublicationOverlay::Present(state) => {
                    Some(state)
                }
                crate::_internal::model::replication::PublicationOverlay::Dropped => None,
            },
        );
        sync_present_map(
            subscriptions,
            &self.local.subscriptions,
            |overlay| match overlay {
                crate::_internal::model::replication::SubscriptionOverlay::Present(state) => {
                    Some(state)
                }
                crate::_internal::model::replication::SubscriptionOverlay::Dropped => None,
            },
        );
        sync_present_map(sequences, &self.local.sequences, |overlay| match overlay {
            SequenceOverlay::Present(state) => Some(state),
            SequenceOverlay::Dropped => None,
        });
        sync_present_map(types, &self.local.types, |overlay| match overlay {
            TypeOverlay::Present(state) => Some(state),
            TypeOverlay::Dropped => None,
        });

        let mut index = 0;
        for edge in self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| matches!(edge.kind, DependencyKind::IndexOnRelation { .. }))
        {
            if let Some(existing) = indexes.get_mut(index) {
                if existing != edge {
                    existing.clone_from(edge);
                }
            } else {
                indexes.push(edge.clone());
            }
            index += 1;
        }
        indexes.truncate(index);
        baseline_foreign_keys.clone_from(&self.baseline_foreign_keys);
    }
}
