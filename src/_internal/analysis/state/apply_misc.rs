use super::{AnalysisState, MutationResult};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::mutations::{
    AlterDatabaseMutation, AlterIndexActionMutation, AlterIndexAllInTablespaceMutation,
    AlterIndexMutation, CreateDatabaseMutation, DropDatabaseMutation, LockTableMutation,
    ReindexTargetMutation, Rename, TruncateMutation,
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

    pub(super) fn apply_reindex(
        &mut self,
        target: &Option<ReindexTargetMutation>,
        _concurrently: bool,
    ) -> MutationResult {
        if let Some(target) = target {
            match target {
                ReindexTargetMutation::Database(_)
                | ReindexTargetMutation::Schema(_)
                | ReindexTargetMutation::System(_) => {
                    // System/Database/Schema reindexes are generally admin tasks.
                    // REINDEX SYSTEM cannot be concurrent.
                }
                ReindexTargetMutation::Table(id) => {
                    if let Err(result) = self.ensure_relation_target(
                        id,
                        |_| true,
                        format!("reindexed relation '{}' does not exist", id),
                        format!("reindexed relation '{}' is invalid", id),
                    ) {
                        return result;
                    }
                }
                ReindexTargetMutation::Index(id) => {
                    if !self.index_is_present(id) {
                        // If we can prove it doesn't exist, we could return a conflict.
                        // For simplicity, we just taint if it's missing and we have coverage.
                        if self.baseline_covers_family_object(
                            id,
                            crate::_internal::db::cache::CatalogFamily::Constraints,
                        ) {
                            return MutationResult::Conflict {
                                reason: format!("reindexed index '{}' does not exist", id),
                            };
                        }
                    }
                }
            }
        } else {
            // Missing target implies parsing issue or unsupported target resolution.
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
        }

        // Reindex does not change relation metadata (columns, constraints, etc.) directly.
        // The rule engine checks for concurrency.
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

    pub(super) fn apply_alter_index(&mut self, alter: &AlterIndexMutation) -> MutationResult {
        // Validate the index exists before applying any actions.
        if !self.index_is_present(&alter.index_id) {
            if alter.if_exists {
                return MutationResult::Applied;
            }
            if self.baseline_covers_family_object(
                &alter.index_id,
                crate::_internal::db::cache::CatalogFamily::Indexes,
            ) {
                return MutationResult::Conflict {
                    reason: format!("index '{}' does not exist", alter.index_id),
                };
            }
            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            return MutationResult::Skipped;
        }

        for action in &alter.actions {
            match action {
                AlterIndexActionMutation::RenameTo { new_id } => {
                    let result = self.apply_rename_relation(&Rename {
                        old_id: alter.index_id.clone(),
                        new_id: new_id.clone(),
                    });
                    if !matches!(result, MutationResult::Applied) {
                        return result;
                    }
                }
                // Tablespace, statistics targets, and storage options are
                // physical/advisory metadata not tracked in the schema model.
                AlterIndexActionMutation::SetTablespace { .. }
                | AlterIndexActionMutation::SetStatistics { .. }
                | AlterIndexActionMutation::SetOptions { .. }
                | AlterIndexActionMutation::ResetOptions { .. } => {}
                AlterIndexActionMutation::AttachPartition { partition_id } => {
                    // The partition index must exist for the attach to succeed.
                    if !self.index_is_present(partition_id) {
                        if self.baseline_covers_family_object(
                            partition_id,
                            crate::_internal::db::cache::CatalogFamily::Indexes,
                        ) {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "partition index '{}' does not exist",
                                    partition_id
                                ),
                            };
                        }
                        self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                        return MutationResult::Skipped;
                    }
                }
                // Extension dependencies are managed by PostgreSQL's extension
                // machinery, which lives outside the schema catalog model.
                AlterIndexActionMutation::DependsOnExtension { .. }
                | AlterIndexActionMutation::NoDependsOnExtension { .. } => {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
                }
            }
        }

        MutationResult::Applied
    }

    pub(super) fn apply_alter_index_all_in_tablespace(
        &mut self,
        all: &AlterIndexAllInTablespaceMutation,
    ) -> MutationResult {
        // `ALTER INDEX ALL IN TABLESPACE src SET TABLESPACE dst` relocates every
        // index in a tablespace. Index tablespace is advisory planner metadata
        // the model does not track, so relocation never drifts the model; there
        // is no single index_id to validate.
        let _ = (&all.source_tablespace, &all.target_tablespace);
        MutationResult::Applied
    }
}
