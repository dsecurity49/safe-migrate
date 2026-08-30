use super::{AnalysisState, Confidence, MutationResult};
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
        self.snapshot_confidence();
        self.local.confidence = Confidence::Tainted;
        MutationResult::Applied
    }

    pub(super) fn apply_alter_database(
        &mut self,
        _alter_database: &AlterDatabaseMutation,
    ) -> MutationResult {
        self.snapshot_confidence();
        self.local.confidence = Confidence::Tainted;
        MutationResult::Applied
    }

    pub(super) fn apply_drop_database(
        &mut self,
        _drop_database: &DropDatabaseMutation,
    ) -> MutationResult {
        self.snapshot_confidence();
        self.local.confidence = Confidence::Tainted;
        MutationResult::Applied
    }

    pub(super) fn apply_vacuum(
        &mut self,
        _table_id: &Option<ObjectId>,
        _is_full: bool,
    ) -> MutationResult {
        MutationResult::Applied
    }
}
