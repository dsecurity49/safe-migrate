use super::{AnalysisState, MutationResult};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::mutations::{
    AlterDatabaseMutation, CreateDatabaseMutation, DropDatabaseMutation, LockTableMutation,
    TruncateMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::relation::RelationKind;

impl AnalysisState {
    pub(super) fn apply_lock_table(&mut self, lock: &LockTableMutation) -> MutationResult {
        for target in &lock.targets {
            if let Err(result) = self.ensure_relation_target(
                &target.id,
                |kind| *kind == RelationKind::Table,
                format!("locked relation '{}' does not exist", target.id),
                format!("locked relation '{}' is not a table", target.id),
            ) {
                return result;
            }
        }
        // Locks are transaction-scoped runtime state.  Validating each target
        // is exact; retaining them in the schema snapshot would incorrectly
        // make a lock survive COMMIT or ROLLBACK.
        MutationResult::Applied
    }

    pub(super) fn apply_truncate(&mut self, truncate: &TruncateMutation) -> MutationResult {
        for target in &truncate.targets {
            if let Err(result) = self.ensure_relation_target(
                &target.id,
                |kind| *kind == RelationKind::Table,
                format!("truncated relation '{}' does not exist", target.id),
                format!("truncated relation '{}' is not a table", target.id),
            ) {
                return result;
            }
        }
        // Row contents and sequence counters are runtime data rather than
        // schema catalog state.  The operation remains fully typed for rules;
        // no invented relation or sequence metadata is written here.
        MutationResult::Applied
    }

    pub(super) fn apply_check_timeouts(&mut self) -> MutationResult {
        MutationResult::Applied
    }

    pub(super) fn apply_create_database(
        &mut self,
        _create_database: &CreateDatabaseMutation,
    ) -> MutationResult {
        // Database objects are outside the current-database schema model.
        // Keep the mutation available to database-specific rules, but do not
        // claim an exact catalog state transition.
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        MutationResult::Applied
    }

    pub(super) fn apply_alter_database(
        &mut self,
        _alter_database: &AlterDatabaseMutation,
    ) -> MutationResult {
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        MutationResult::Applied
    }

    pub(super) fn apply_drop_database(
        &mut self,
        _drop_database: &DropDatabaseMutation,
    ) -> MutationResult {
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        MutationResult::Applied
    }

    pub(super) fn apply_vacuum(
        &mut self,
        _table_id: &Option<ObjectId>,
        _is_full: bool,
    ) -> MutationResult {
        // VACUUM changes physical visibility/storage state and may refresh
        // planner statistics, neither of which is represented in the
        // normalized relation model. Keep the statement available to rules,
        // but do not claim an exact post-VACUUM catalog state.
        self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
        MutationResult::Applied
    }
}
