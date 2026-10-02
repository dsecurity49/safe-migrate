use super::{AnalysisState, MutationResult};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::{IndexStatisticsColumn, StatisticsTarget};
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterDatabaseMutation, AlterIndexActionMutation, AlterIndexAllInTablespaceMutation,
    AlterIndexMutation, CreateDatabaseMutation, DropDatabaseMutation, LockTableMutation,
    ReindexTargetMutation, Rename, TruncateMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::relation::RelationKind;

/// Smallest statistics target PostgreSQL accepts; -1 means the server default.
const SET_STATISTICS_MIN: i32 = -1;
/// Largest statistics target PostgreSQL stores without clamping.
const SET_STATISTICS_MAX: i32 = 10_000;

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
    ) -> MutationResult {
        if let Some(target) = target {
            match target {
                ReindexTargetMutation::Database(_)
                | ReindexTargetMutation::Schema(_)
                | ReindexTargetMutation::System(_) => {
                    // System/Database/Schema reindexes affect many relations at once.
                    // Tracking exact concurrent/transaction state for all of them
                    // is not currently modeled, so we taint the statement.
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
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
                        // When the baseline covers indexes for this schema we
                        // can be certain the named index does not exist; return
                        // a hard conflict rather than silently tainting.
                        if self.baseline_covers_family_object(
                            id,
                            crate::_internal::db::cache::CatalogFamily::Indexes,
                        ) {
                            return MutationResult::conflict(format!(
                                "reindexed index '{}' does not exist",
                                id
                            ));
                        }
                        // No baseline coverage — we cannot prove it is absent.
                        self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
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
                return MutationResult::conflict(format!(
                    "index '{}' does not exist",
                    alter.index_id
                ));
            }
            return self.unresolved(EvidenceCode::UnknownObjectState);
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
                // Tablespace, storage options and reloptions are physical or
                // advisory metadata not tracked in the schema model.
                AlterIndexActionMutation::SetTablespace { .. }
                | AlterIndexActionMutation::SetOptions { .. }
                | AlterIndexActionMutation::ResetOptions { .. } => {}
                AlterIndexActionMutation::SetStatistics { column, target } => {
                    let result =
                        self.apply_alter_index_set_statistics(&alter.index_id, column, target);
                    if !matches!(result, MutationResult::Applied) {
                        return result;
                    }
                }
                AlterIndexActionMutation::AttachPartition { partition_id } => {
                    // The partition index must exist for the attach to succeed.
                    if !self.index_is_present(partition_id) {
                        if self.baseline_covers_family_object(
                            partition_id,
                            crate::_internal::db::cache::CatalogFamily::Indexes,
                        ) {
                            return MutationResult::conflict(format!(
                                "partition index '{}' does not exist",
                                partition_id
                            ));
                        }
                        return self.unresolved(EvidenceCode::UnknownObjectState);
                    }
                    // Record the link so dropping the parent also drops the
                    // child, which PostgreSQL does.
                    self.snapshot_graph();
                    self.local.graph.add_edge(DependencyEdge::new(
                        partition_id.clone(),
                        alter.index_id.clone(),
                        DependencyKind::IndexPartitionOf,
                    ));
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

    /// PostgreSQL checks the range, then clamps above 10000, then the column.
    pub(super) fn apply_alter_index_set_statistics(
        &mut self,
        index: &ObjectId,
        column: &IndexStatisticsColumn,
        target: &StatisticsTarget,
    ) -> MutationResult {
        let StatisticsTarget::Value(value) = target else {
            return MutationResult::Applied;
        };
        if *value < SET_STATISTICS_MIN {
            return MutationResult::conflict(format!("statistics target {value} is too low"));
        }
        if *value > SET_STATISTICS_MAX {
            // Accepted and stored as 10000, so it does not match what was written.
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
        } else if self.index_has_expression_keys(index) == Some(false) {
            return MutationResult::conflict(format!(
                "cannot alter statistics on non-expression column \"{column}\" of index \"{index}\""
            ));
        }
        MutationResult::Applied
    }

    /// Whether the index is known to have expression keys, or `None` when that
    /// is not established.
    fn index_has_expression_keys(&self, index: &ObjectId) -> Option<bool> {
        self.local
            .graph
            .edges()
            .iter()
            .find(|edge| {
                matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                    && edge.dependent == *index
            })
            .map(|edge| match &edge.kind {
                DependencyKind::IndexOnRelation {
                    has_expression_keys,
                    ..
                } => *has_expression_keys,
                _ => unreachable!("index lookup matched an IndexOnRelation edge"),
            })
    }

    pub(super) fn apply_alter_index_all_in_tablespace(
        &mut self,
        _all: &AlterIndexAllInTablespaceMutation,
    ) -> MutationResult {
        // `ALTER INDEX ALL IN TABLESPACE src SET TABLESPACE dst` bulk-relocates
        // every index currently residing in tablespace `src` to tablespace `dst`.
        // Index tablespace is advisory planner metadata (pg_class.reltablespace);
        // this engine does not model tablespace placement in its relation state,
        // so this operation never drifts the catalog model and requires no
        // state mutation. The source/target tablespace names are preserved in
        // the mutation for rule authors and future diagnostics, but the apply
        // layer correctly treats this as a no-op against the schema model.
        MutationResult::Applied
    }
}
