use super::{AnalysisState, MutationResult};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::mutations::{
    DropTable, ReleaseSavepointMutation, RollbackToSavepointMutation, SavepointMutation,
};
use crate::_internal::analysis::transaction::TransactionFrame;
use crate::_internal::model::relation::{OnCommitAction, Persistence, RelationOverlay};

impl AnalysisState {
    pub(super) fn apply_begin_transaction(&mut self) -> MutationResult {
        if self.local.transactions.is_empty() {
            self.local.transactions.push(TransactionFrame::root());
            MutationResult::Applied
        } else {
            MutationResult::Skipped
        }
    }

    pub(super) fn apply_commit_transaction(&mut self, chain: bool) -> MutationResult {
        if chain && self.local.transactions.is_empty() {
            self.taint(EvidenceCode::TransactionStateUnknown, EvidenceScope::Chain);
            return MutationResult::Conflict {
                reason: "COMMIT AND CHAIN can only be used in transaction blocks".to_string(),
            };
        }

        if self.local.transaction_aborted {
            while let Some(frame) = self.local.transactions.pop() {
                self.rollback_frame(frame);
            }
        } else {
            while self.local.transactions.pop().is_some() {}
            self.restore_persistent_role_context();
            self.apply_on_commit_actions();
        }
        self.local.transaction_aborted = false;
        if chain {
            self.local.transactions.push(TransactionFrame::root());
        }
        MutationResult::Applied
    }

    fn apply_on_commit_actions(&mut self) {
        let actions = self
            .local
            .relations
            .iter()
            .filter_map(|(id, overlay)| match overlay {
                RelationOverlay::Present(relation)
                    if relation.persistence == Persistence::Temporary =>
                {
                    relation.on_commit.map(|action| (id.clone(), action))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        for (id, action) in actions {
            match action {
                OnCommitAction::PreserveRows => {}
                OnCommitAction::DeleteRows => {
                    if let Some(RelationOverlay::Present(relation)) =
                        self.local.relations.get_mut(&id)
                    {
                        relation.estimated_rows = Some(0);
                        relation.relpages = Some(0);
                    }
                }
                OnCommitAction::Drop => {
                    // PostgreSQL removes the temporary relation and all of
                    // its dependent local objects at commit.
                    let _ = self.apply_drop_table(
                        &DropTable {
                            ids: vec![id],
                            if_exists: false,
                            cascade: true,
                        },
                        None,
                    );
                }
            }
        }
    }

    /// PostgreSQL wraps each statement outside an explicit transaction in its
    /// own transaction, so ON COMMIT actions run after that statement.
    pub(crate) fn apply_implicit_commit_actions(&mut self) {
        if self.local.transactions.is_empty() && !self.local.transaction_aborted {
            self.apply_on_commit_actions();
        }
    }

    pub(super) fn apply_rollback_transaction(&mut self, chain: bool) -> MutationResult {
        if chain && self.local.transactions.is_empty() {
            self.taint(EvidenceCode::TransactionStateUnknown, EvidenceScope::Chain);
            return MutationResult::Conflict {
                reason: "ROLLBACK AND CHAIN can only be used in transaction blocks".to_string(),
            };
        }
        while let Some(frame) = self.local.transactions.pop() {
            self.rollback_frame(frame);
        }
        self.local.transaction_aborted = false;
        if chain {
            self.local.transactions.push(TransactionFrame::root());
        }
        MutationResult::Applied
    }

    pub(super) fn apply_rollback_to_savepoint(
        &mut self,
        rollback: &RollbackToSavepointMutation,
    ) -> MutationResult {
        let Some(position) = self
            .local
            .transactions
            .iter()
            .rposition(|frame| frame.is_named_savepoint(&rollback.name))
        else {
            self.taint(EvidenceCode::TransactionStateUnknown, EvidenceScope::Chain);
            if !self.local.transactions.is_empty() {
                self.local.transaction_aborted = true;
            }
            return MutationResult::Conflict {
                reason: format!("savepoint '{}' does not exist", rollback.name),
            };
        };
        let rolled_back = self.local.transactions.split_off(position + 1);
        for frame in rolled_back.into_iter().rev() {
            self.rollback_frame(frame);
        }
        let undo_log = std::mem::take(&mut self.local.transactions[position].undo_log);
        self.rollback_undo_log(undo_log);
        self.local.transaction_aborted = false;
        MutationResult::Applied
    }

    pub(super) fn apply_savepoint(&mut self, savepoint: &SavepointMutation) -> MutationResult {
        if self.local.transactions.is_empty() {
            self.taint(EvidenceCode::TransactionStateUnknown, EvidenceScope::Chain);
            return MutationResult::Conflict {
                reason: "SAVEPOINT can only be used in transaction blocks".to_string(),
            };
        }
        self.local
            .transactions
            .push(TransactionFrame::savepoint(savepoint.name.clone()));
        MutationResult::Applied
    }

    pub(super) fn apply_release_savepoint(
        &mut self,
        release: &ReleaseSavepointMutation,
    ) -> MutationResult {
        let Some(position) = self
            .local
            .transactions
            .iter()
            .rposition(|frame| frame.is_named_savepoint(&release.name))
        else {
            self.taint(EvidenceCode::TransactionStateUnknown, EvidenceScope::Chain);
            if !self.local.transactions.is_empty() {
                self.local.transaction_aborted = true;
            }
            return MutationResult::Conflict {
                reason: format!("savepoint '{}' does not exist", release.name),
            };
        };
        if position == 0 {
            self.taint(EvidenceCode::TransactionStateUnknown, EvidenceScope::Chain);
            return MutationResult::Conflict {
                reason: format!("savepoint '{}' is not inside a transaction", release.name),
            };
        }

        let released = self.local.transactions.split_off(position);
        let Some(outer) = self.local.transactions.last_mut() else {
            self.taint(EvidenceCode::TransactionStateUnknown, EvidenceScope::Chain);
            return MutationResult::Conflict {
                reason: format!("savepoint '{}' is not inside a transaction", release.name),
            };
        };
        for frame in released {
            outer.undo_log.extend(frame.undo_log);
        }
        MutationResult::Applied
    }
}
