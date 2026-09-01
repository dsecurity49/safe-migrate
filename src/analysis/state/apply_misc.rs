use super::{AnalysisState, MutationResult};
use crate::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::analysis::mutations::{
    AlterDatabaseMutation, CreateDatabaseMutation, DropDatabaseMutation,
};
use crate::ast::identifiers::ObjectId;

impl AnalysisState {
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
