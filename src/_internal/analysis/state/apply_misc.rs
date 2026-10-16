use super::index_topology::AttachRefusal;
use super::{AnalysisState, MutationResult};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::{IndexStatisticsColumn, StatisticsTarget};
use crate::_internal::analysis::graph::DependencyKind;
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
                |kind| kind.is_table_like(),
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
        concurrently: bool,
    ) -> MutationResult {
        let reindex_is_concurrent = concurrently;
        if let Some(target) = target {
            // PostgreSQL gives `REINDEX SCHEMA`, `DATABASE` and `SYSTEM`
            // separate commit points per relation, so none of them can run
            // inside a transaction block. `CONCURRENTLY` is checked first and
            // names the form the user wrote.
            if matches!(
                target,
                ReindexTargetMutation::Database(_)
                    | ReindexTargetMutation::Schema(_)
                    | ReindexTargetMutation::System(_)
            ) {
                let form = match target {
                    ReindexTargetMutation::Schema(_) => "REINDEX SCHEMA",
                    ReindexTargetMutation::System(_) => "REINDEX SYSTEM",
                    _ => "REINDEX DATABASE",
                };
                // `PreventInTransactionBlock` only rejects inside an explicit
                // block, so a statement outside one is legal whatever its form.
                if self.in_transaction() {
                    return MutationResult::conflict(format!(
                        "{form} cannot run inside a transaction block"
                    ));
                }
                // Outside a block PostgreSQL still refuses a concurrent
                // system-catalog reindex, which is the form's own rule rather
                // than a transaction rule.
                if matches!(target, ReindexTargetMutation::System(_)) && reindex_is_concurrent {
                    return MutationResult::conflict(
                        "cannot reindex system catalogs concurrently".to_string(),
                    );
                }
                // The catalog scope of these forms is not modeled, so which
                // relations they touch remains unknown.
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
            }
            // A catalog relation named directly cannot be rebuilt concurrently.
            if matches!(
                target,
                ReindexTargetMutation::Table(_) | ReindexTargetMutation::Index(_)
            ) && reindex_is_concurrent
                && self.target_is_catalog(target)
            {
                return MutationResult::conflict(
                    "cannot reindex system catalogs concurrently".to_string(),
                );
            }
            match target {
                ReindexTargetMutation::Database(_)
                | ReindexTargetMutation::Schema(_)
                | ReindexTargetMutation::System(_) => {}
                ReindexTargetMutation::Table(id) => {
                    if let Err(result) = self.ensure_relation_target(
                        id,
                        // PostgreSQL accepts a table, a materialized view, or a
                        // partitioned table, and refuses anything else.
                        |kind| {
                            // A partitioned table is modeled as a table, so
                            // the kind predicate is the same as PostgreSQL's.
                            matches!(
                                kind,
                                crate::_internal::model::relation::RelationKind::Table
                                    | crate::_internal::model::relation::RelationKind::MaterializedView
                            )
                        },
                        format!("reindexed relation '{}' does not exist", id),
                        format!("\"{}\" is not a table or materialized view", id),
                    ) {
                        return result;
                    }
                    // A partitioned table has no storage of its own, so its
                    // partitions are reindexed across commit points.
                    if self.relation_is_partitioned(id) && self.in_transaction() {
                        return MutationResult::conflict(
                            "REINDEX TABLE cannot run inside a transaction block".to_string(),
                        );
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
                    } else {
                        // REINDEX rebuilds a broken index; a partitioned parent
                        // only becomes valid once its partitions are attached.
                        self.mark_index_valid(id);
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
                    let parent_name = alter.index_id.name.as_str();
                    let child_name = partition_id.name.as_str();
                    match self.index_attach_refusal(&alter.index_id, partition_id) {
                        None => self.record_index_partition(&alter.index_id, partition_id),
                        Some(AttachRefusal::AttachedElsewhere) => {
                            return MutationResult::conflict(format!(
                                "cannot attach index \"{child_name}\" as partition of index \"{parent_name}\""
                            ));
                        }
                        Some(AttachRefusal::NotAPartition) => {
                            let parent_table = self
                                .index_table_of(&alter.index_id)
                                .map(|table| table.to_string())
                                .unwrap_or_else(|| alter.index_id.to_string());
                            return MutationResult::conflict(format!(
                                "index \"{child_name}\" is not an index on any partition of table \"{parent_table}\""
                            ));
                        }
                        Some(AttachRefusal::ConstraintMismatch) => {
                            return MutationResult::conflict(format!(
                                "parent index \"{parent_name}\" has a constraint but partition index \"{child_name}\" does not"
                            ));
                        }
                        Some(AttachRefusal::DefinitionsDiffer) => {
                            return MutationResult::conflict(format!(
                                "cannot attach index \"{child_name}\" as partition of index \"{parent_name}\": the index definitions do not match"
                            ));
                        }
                        Some(AttachRefusal::EquivalenceUnknown) => {
                            return self.unresolved(EvidenceCode::UnmodeledState);
                        }
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
                DependencyKind::IndexOnRelation { definition, .. } => {
                    definition.has_expression_keys()
                }
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
