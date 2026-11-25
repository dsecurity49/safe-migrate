use crate::_internal::analysis::facts::{
    AlterDomainActionFact, DetachPartitionMode, DomainConstraintFact, LockModeFact,
};
use crate::_internal::analysis::graph::DependencyKind;
use crate::_internal::analysis::mutations::{
    AlterTableActionMutation, Mutation, ReindexTargetMutation,
};
use crate::_internal::analysis::state::{AnalysisState, PreState};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::constraint::ConstraintKind;
use crate::_internal::model::relation::Persistence;
use crate::_internal::report::violations::{ObjectKind, Violation, ViolationTier};
use crate::_internal::rules::{Rule, RuleContext};
use std::collections::HashSet;

/// A lock a statement is expected to hold. Kept separate from scan/rewrite
/// cost so the lock warning survives even when row statistics say the table is
/// small.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LockTarget {
    pub relation: ObjectId,
    pub mode: LockModeFact,
    pub role: LockTargetRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockTargetRole {
    Subject,
    Referenced,
    Referencing,
    Parent,
    Child,
    DefaultPartition,
    Index,
    MaterializedView,
}

impl LockTargetRole {
    fn label(self) -> &'static str {
        match self {
            Self::Subject => "table",
            Self::Referenced => "referenced table",
            Self::Referencing => "referencing table",
            Self::Parent => "parent table",
            Self::Child => "partition",
            Self::DefaultPartition => "default partition",
            Self::Index => "index",
            Self::MaterializedView => "materialized view",
        }
    }
}

/// Work PostgreSQL performs while it holds the predicted locks. The lock itself
/// lasts until the end of the transaction, so this only explains why the
/// statement is slow, not how long the lock is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockWork {
    MetadataOnly,
    TableScan,
    ConditionalTableScan,
    TableRewrite,
    IndexBuild,
}

impl LockWork {
    fn phrase(self) -> &'static str {
        match self {
            Self::MetadataOnly => "",
            Self::TableScan => ", scanning the table",
            Self::ConditionalTableScan => {
                ", scanning the table if the indexed columns are not already NOT NULL"
            }
            Self::TableRewrite => ", rewriting the table",
            Self::IndexBuild => ", building the index",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LockPrediction {
    pub object_kind: ObjectKind,
    pub object_name: String,
    pub operation: &'static str,
    pub work: LockWork,
    pub targets: Vec<LockTarget>,
}

const SET_STORAGE_OPERATION: &str = "Changing a column storage parameter";

pub(crate) struct LockRiskRule;

impl Rule for LockRiskRule {
    fn id(&self) -> &'static str {
        "lock-risk"
    }

    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier3
    }

    fn recipe(&self) -> &'static str {
        "Set a bounded lock_timeout, run during a low-traffic window, and prefer concurrent or NOT VALID alternatives where PostgreSQL supports them."
    }

    fn evaluates_when_unresolved(
        &self,
        _transition: &crate::_internal::rules::TransitionRecord<'_>,
    ) -> bool {
        true
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if context.result().is_noop() || context.result().is_conflict() {
            return Vec::new();
        }

        predict_locks(context.mutation(), context.pre_state(), context.state())
            .into_iter()
            .filter_map(|prediction| {
                let targets = prediction
                    .targets
                    .into_iter()
                    .filter(|target| !target_is_temporary(context.pre_state(), &target.relation))
                    .collect::<Vec<_>>();
                if targets.is_empty() {
                    return None;
                }

                let rule_id = if prediction.operation == SET_STORAGE_OPERATION {
                    "set-storage-lock"
                } else {
                    self.id()
                };
                Some(Violation {
                    source_range: None,
                    rule_id,
                    object_kind: prediction.object_kind,
                    object_name: prediction.object_name,
                    tier: self.default_tier(),
                    reason: format_reason(prediction.operation, prediction.work, &targets),
                    recipe: self.recipe(),
                    dedup_key: None,
                    sql: None,
                })
            })
            .collect()
    }

    fn not_evaluated_cause(
        &self,
        context: &RuleContext<'_>,
    ) -> Option<crate::_internal::analysis::evidence::EvidenceCode> {
        if context.result().is_noop() || context.result().is_conflict() {
            return None;
        }
        let predictions = predict_locks(context.mutation(), context.pre_state(), context.state());
        if !predictions.is_empty() {
            return None;
        }
        if mutation_targets_only_temporary_relations(context.mutation(), context.pre_state()) {
            return None;
        }
        lock_prediction_expected(context.mutation()).then_some(
            crate::_internal::analysis::evidence::EvidenceCode::LockPredictionUnavailable,
        )
    }
}

/// Whether every relation this mutation names is known to be temporary.
///
/// Temporary relations do not warrant a coverage gap: their locks are local to
/// the session and cannot block production traffic.
fn mutation_targets_only_temporary_relations(mutation: &Mutation, pre_state: &PreState) -> bool {
    let ids: Vec<&ObjectId> = match mutation {
        Mutation::DropTable(drop) => drop.ids.iter().collect(),
        Mutation::DropView(drop) => drop.ids.iter().collect(),
        Mutation::DropMaterializedView(drop) => drop.ids.iter().collect(),
        Mutation::AlterViewFamily(alter) => vec![&alter.id],
        Mutation::ChangeRelationOwner { id, .. }
        | Mutation::SetReloptions { id, .. }
        | Mutation::ResetReloptions { id, .. } => vec![id],
        Mutation::CreatePolicy(policy) => vec![&policy.table],
        Mutation::DropPolicy(policy) => vec![&policy.table],
        Mutation::CreateTrigger(trigger) => vec![&trigger.table],
        Mutation::DropTrigger(trigger) => vec![&trigger.table],
        Mutation::RenameTrigger(trigger) => vec![&trigger.table],
        Mutation::Rename(rename) => vec![&rename.old_id],
        Mutation::Grant(grant) => match &grant.target {
            crate::_internal::analysis::mutations::ResolvedGrantTarget::Tables(ids) => {
                ids.iter().collect()
            }
            _ => return false,
        },
        Mutation::Revoke(revoke) => match &revoke.target {
            crate::_internal::analysis::mutations::ResolvedGrantTarget::Tables(ids) => {
                ids.iter().collect()
            }
            _ => return false,
        },
        _ => return false,
    };
    !ids.is_empty()
        && ids.iter().all(|id| {
            pre_state
                .relations
                .get(*id)
                .is_some_and(|relation| relation.persistence == Persistence::Temporary)
        })
}

/// Whether PostgreSQL can take a relation lock for this mutation.
///
/// Any prediction means the curated predictor covers the operation, including
/// temporary-only targets. This is the fallback for operations it does not
/// model at all.
fn lock_prediction_expected(mutation: &Mutation) -> bool {
    match mutation {
        Mutation::CreateTable(create) => create.partition_of.is_some(),
        Mutation::AlterTable(alter) => !alter_table_action_is_known_metadata_only(&alter.action),
        Mutation::CreateIndex(create) => !create.concurrently,
        Mutation::DropIndex(drop) => !drop.concurrently,
        Mutation::RefreshMaterializedView(refresh) => !refresh.concurrently,
        Mutation::Reindex { concurrently, .. } => !concurrently,
        Mutation::Vacuum { is_full, .. } => *is_full,
        Mutation::DropTable(_)
        | Mutation::DropView(_)
        | Mutation::DropMaterializedView(_)
        | Mutation::DropType(_)
        | Mutation::DropDomain(_)
        | Mutation::DropExtension(_)
        | Mutation::AlterViewFamily(_)
        | Mutation::AlterIndex(_)
        | Mutation::AlterIndexAllInTablespace(_)
        | Mutation::AlterType(_)
        | Mutation::ChangeRelationOwner { .. }
        | Mutation::SetReloptions { .. }
        | Mutation::ResetReloptions { .. }
        | Mutation::CreatePolicy(_)
        | Mutation::DropPolicy(_)
        | Mutation::CreateTrigger(_)
        | Mutation::DropTrigger(_)
        | Mutation::RenameTrigger(_)
        | Mutation::Grant(_)
        | Mutation::Revoke(_)
        | Mutation::Rename(_) => true,
        Mutation::CreateSchema(_)
        | Mutation::AlterSchema(_)
        | Mutation::DropSchema(_)
        | Mutation::CreateView(_)
        | Mutation::CreateMaterializedView(_)
        | Mutation::CreateType(_)
        | Mutation::RenameType(_)
        | Mutation::CreateExtension(_)
        | Mutation::AlterExtension(_)
        | Mutation::CreateDomain(_)
        | Mutation::AlterDomain(_)
        | Mutation::RenameDomain(_)
        | Mutation::CreateSequence(_)
        | Mutation::AlterSequence(_)
        | Mutation::DropSequence(_)
        | Mutation::LockTable(_)
        | Mutation::Truncate(_)
        | Mutation::NoStateChange { .. }
        | Mutation::SetColumnDefault { .. }
        | Mutation::SearchPath(_)
        | Mutation::TimeoutSetting(_)
        | Mutation::ResetSettings(_)
        | Mutation::CheckTimeouts { .. }
        | Mutation::BeginTransaction
        | Mutation::CommitTransaction
        | Mutation::CommitAndChain
        | Mutation::RollbackTransaction
        | Mutation::RollbackAndChain
        | Mutation::RollbackToSavepoint(_)
        | Mutation::Savepoint(_)
        | Mutation::ReleaseSavepoint(_)
        | Mutation::CreateFunction(_)
        | Mutation::AlterFunction(_)
        | Mutation::DropFunction(_)
        | Mutation::CreateProcedure(_)
        | Mutation::AlterProcedure(_)
        | Mutation::DropProcedure(_)
        | Mutation::CreateAggregate(_)
        | Mutation::AlterAggregate(_)
        | Mutation::DropAggregate(_)
        | Mutation::AlterRoutine(_)
        | Mutation::DropRoutine(_)
        | Mutation::CreateCast(_)
        | Mutation::DropCast(_)
        | Mutation::CreateStatistics(_)
        | Mutation::AlterStatistics(_)
        | Mutation::DropStatistics(_)
        | Mutation::Analyze(_)
        | Mutation::CreatePublication(_)
        | Mutation::AlterPublication(_)
        | Mutation::DropPublication(_)
        | Mutation::CreateSubscription(_)
        | Mutation::AlterSubscription(_)
        | Mutation::DropSubscription(_)
        | Mutation::CreateRole(_)
        | Mutation::AlterRole(_)
        | Mutation::DropRole(_)
        | Mutation::CreateDatabase(_)
        | Mutation::AlterDatabase(_)
        | Mutation::DropDatabase(_)
        | Mutation::SwitchRole { .. }
        | Mutation::Opaque(_) => false,
    }
}

/// Catalog-only actions that the lock predictor deliberately leaves silent.
/// They take brief locks but do not scan or rewrite table data.
fn alter_table_action_is_known_metadata_only(action: &AlterTableActionMutation) -> bool {
    matches!(
        action,
        AlterTableActionMutation::AddColumn { .. }
            | AlterTableActionMutation::AddIdentity { .. }
            | AlterTableActionMutation::DropColumn { .. }
            | AlterTableActionMutation::RenameColumn { .. }
            | AlterTableActionMutation::SetDefault { .. }
            | AlterTableActionMutation::SetColumnOptions { .. }
            | AlterTableActionMutation::ResetColumnOptions { .. }
            | AlterTableActionMutation::SetTableOptions { .. }
            | AlterTableActionMutation::ResetTableOptions { .. }
            | AlterTableActionMutation::SetStatistics { .. }
            | AlterTableActionMutation::SetCompression { .. }
            | AlterTableActionMutation::DropGeneratedExpression { .. }
            | AlterTableActionMutation::AlterConstraint { .. }
            | AlterTableActionMutation::RenameConstraint { .. }
            | AlterTableActionMutation::SetRowSecurity { .. }
            | AlterTableActionMutation::SetForceRowSecurity { .. }
            | AlterTableActionMutation::SetReplicaIdentity { .. }
            | AlterTableActionMutation::SetRuleMode { .. }
            | AlterTableActionMutation::SetTriggerMode { .. }
            | AlterTableActionMutation::EnableTrigger { .. }
            | AlterTableActionMutation::DisableTrigger { .. }
            | AlterTableActionMutation::SetCluster { .. }
            | AlterTableActionMutation::OwnerTo { .. }
            | AlterTableActionMutation::DropNotNull { .. }
            | AlterTableActionMutation::AlterColumnInheritance
            | AlterTableActionMutation::SetOfType { .. }
    )
}

fn target_is_temporary(pre_state: &PreState, id: &ObjectId) -> bool {
    is_temporary(pre_state, id)
        || relation_for_index(pre_state, id)
            .is_some_and(|relation| is_temporary(pre_state, &relation))
}

fn is_temporary(pre_state: &PreState, id: &ObjectId) -> bool {
    pre_state
        .relations
        .get(id)
        .is_some_and(|relation| relation.persistence == Persistence::Temporary)
}

fn format_reason(operation: &str, work: LockWork, targets: &[LockTarget]) -> String {
    let mut groups: Vec<(LockModeFact, Vec<String>)> = Vec::new();
    for target in targets {
        let label = format!("{} {}", target.role.label(), target.relation);
        if let Some((_, labels)) = groups.iter_mut().find(|(mode, _)| *mode == target.mode) {
            labels.push(label);
        } else {
            groups.push((target.mode, vec![label]));
        }
    }

    let locks = groups
        .iter()
        .map(|(mode, labels)| format!("{} on {}", mode.sql_name(), labels.join(" and ")))
        .collect::<Vec<_>>()
        .join(", ");
    let impact = if targets.iter().any(|target| target.mode.blocks_reads()) {
        "This blocks reads and writes."
    } else if targets.iter().any(|target| target.mode.blocks_writes()) {
        "This blocks writes."
    } else {
        "This blocks concurrent DDL."
    };

    format!(
        "{operation} takes {locks}{}. {impact} The lock is held until the transaction ends.",
        work.phrase()
    )
}

/// Translate a mutation into the locks PostgreSQL would take.
fn predict_locks(
    mutation: &Mutation,
    pre_state: &PreState,
    state: &AnalysisState,
) -> Vec<LockPrediction> {
    match mutation {
        Mutation::AlterTable(alter) => {
            predict_alter_table(&alter.id, &alter.action, pre_state, state)
        }
        Mutation::AlterDomain(alter) => {
            let Some(action) = &alter.action else {
                return Vec::new();
            };
            if !domain_action_takes_share_lock(action) {
                return Vec::new();
            }
            // Validating a domain constraint scans every table using the domain.
            let targets = state
                .relations_using_domain(&alter.id)
                .into_iter()
                .map(|relation| LockTarget {
                    relation: relation.id.clone(),
                    mode: LockModeFact::Share,
                    role: LockTargetRole::Subject,
                })
                .collect();
            vec![LockPrediction {
                object_kind: ObjectKind::Domain,
                object_name: alter.id.to_string(),
                operation: "Adding or validating a domain constraint",
                work: LockWork::TableScan,
                targets,
            }]
        }
        Mutation::CreateIndex(create) if !create.concurrently => vec![LockPrediction {
            object_kind: ObjectKind::Index,
            object_name: create.id.to_string(),
            operation: "Creating an index without CONCURRENTLY",
            work: LockWork::IndexBuild,
            targets: vec![LockTarget {
                relation: create.table.clone(),
                mode: LockModeFact::Share,
                role: LockTargetRole::Subject,
            }],
        }],
        Mutation::DropIndex(drop) if !drop.concurrently => drop
            .ids
            .iter()
            .filter_map(|index| {
                // The lock lands on the table, so resolve the owning relation
                // from the pre-state graph.
                let table = relation_for_index(pre_state, index)?;
                Some(LockPrediction {
                    object_kind: ObjectKind::Index,
                    object_name: index.to_string(),
                    operation: "Dropping an index without CONCURRENTLY",
                    work: LockWork::MetadataOnly,
                    targets: vec![LockTarget {
                        relation: table,
                        mode: LockModeFact::AccessExclusive,
                        role: LockTargetRole::Subject,
                    }],
                })
            })
            .collect(),
        Mutation::Reindex {
            target: Some(target),
            concurrently: false,
        } => predict_reindex(target, pre_state, state),
        Mutation::RefreshMaterializedView(refresh) if !refresh.concurrently => {
            vec![LockPrediction {
                object_kind: ObjectKind::MaterializedView,
                object_name: refresh.id.to_string(),
                operation: "Refreshing a materialized view without CONCURRENTLY",
                work: LockWork::MetadataOnly,
                targets: vec![LockTarget {
                    relation: refresh.id.clone(),
                    mode: LockModeFact::AccessExclusive,
                    role: LockTargetRole::MaterializedView,
                }],
            }]
        }
        Mutation::Vacuum {
            table_id: Some(table),
            is_full: true,
        } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: table.to_string(),
            operation: "Running VACUUM FULL",
            work: LockWork::TableRewrite,
            targets: vec![LockTarget {
                relation: table.clone(),
                mode: LockModeFact::AccessExclusive,
                role: LockTargetRole::Subject,
            }],
        }],
        Mutation::Truncate(truncate) => truncate
            .targets
            .iter()
            .map(|target| LockPrediction {
                object_kind: ObjectKind::Table,
                object_name: target.id.to_string(),
                operation: "Truncating a table",
                work: LockWork::MetadataOnly,
                targets: vec![LockTarget {
                    relation: target.id.clone(),
                    mode: LockModeFact::AccessExclusive,
                    role: LockTargetRole::Subject,
                }],
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Predict the locks for one ALTER TABLE action and its referenced tables.
fn predict_alter_table(
    subject: &ObjectId,
    action: &AlterTableActionMutation,
    pre_state: &PreState,
    state: &AnalysisState,
) -> Vec<LockPrediction> {
    let subject_target = |mode| LockTarget {
        relation: subject.clone(),
        mode,
        role: LockTargetRole::Subject,
    };

    match action {
        AlterTableActionMutation::AddCheckConstraint { not_valid, .. } => {
            let (operation, work) = if *not_valid {
                (
                    "Adding a CHECK constraint as NOT VALID",
                    LockWork::MetadataOnly,
                )
            } else {
                ("Adding a valid CHECK constraint", LockWork::TableScan)
            };
            vec![LockPrediction {
                object_kind: ObjectKind::Table,
                object_name: subject.to_string(),
                operation,
                work,
                targets: vec![subject_target(LockModeFact::AccessExclusive)],
            }]
        }
        AlterTableActionMutation::AddForeignKey {
            not_valid,
            to_table,
            ..
        } => {
            let (operation, work) = if *not_valid {
                (
                    "Adding a FOREIGN KEY constraint as NOT VALID",
                    LockWork::MetadataOnly,
                )
            } else {
                ("Adding a valid FOREIGN KEY constraint", LockWork::TableScan)
            };
            vec![LockPrediction {
                object_kind: ObjectKind::Table,
                object_name: subject.to_string(),
                operation,
                work,
                targets: vec![
                    subject_target(LockModeFact::ShareRowExclusive),
                    LockTarget {
                        relation: to_table.clone(),
                        mode: LockModeFact::ShareRowExclusive,
                        role: LockTargetRole::Referenced,
                    },
                ],
            }]
        }
        AlterTableActionMutation::SetNotNull { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Setting a column NOT NULL",
            work: LockWork::MetadataOnly,
            targets: vec![subject_target(LockModeFact::AccessExclusive)],
        }],
        AlterTableActionMutation::AddUniqueConstraint {
            using_index: None, ..
        }
        | AlterTableActionMutation::AddPrimaryKeyConstraint {
            using_index: None, ..
        } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Adding a UNIQUE or PRIMARY KEY constraint",
            work: LockWork::IndexBuild,
            targets: vec![
                subject_target(LockModeFact::AccessExclusive),
                subject_target(LockModeFact::Share),
            ],
        }],
        AlterTableActionMutation::AddUniqueConstraint {
            using_index: Some(_),
            ..
        } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Adding a UNIQUE constraint using an existing index",
            work: LockWork::MetadataOnly,
            targets: vec![subject_target(LockModeFact::AccessExclusive)],
        }],
        AlterTableActionMutation::AddPrimaryKeyConstraint {
            constraint_name,
            columns,
            using_index: Some(index),
        } => {
            // PostgreSQL adds NOT NULL to each indexed column that is still
            // nullable, which scans the table. Resolved columns with no
            // nullable member keep the ALTER metadata-only.
            let key_columns = if columns.is_empty() {
                index_columns_for_constraint(state, subject, index, constraint_name.as_deref())
            } else {
                Some(columns.clone())
            };
            let nullable = key_columns
                .as_deref()
                .and_then(|columns| columns_are_nullable(pre_state, subject, columns));
            let work = match nullable {
                Some(true) => LockWork::TableScan,
                Some(false) => LockWork::MetadataOnly,
                None => LockWork::ConditionalTableScan,
            };
            vec![LockPrediction {
                object_kind: ObjectKind::Table,
                object_name: subject.to_string(),
                operation: "Adding a PRIMARY KEY constraint using an existing index",
                work,
                targets: vec![subject_target(LockModeFact::AccessExclusive)],
            }]
        }
        AlterTableActionMutation::AddExcludeConstraint { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Adding an EXCLUDE constraint",
            work: LockWork::IndexBuild,
            targets: vec![
                subject_target(LockModeFact::AccessExclusive),
                subject_target(LockModeFact::Share),
            ],
        }],
        AlterTableActionMutation::ValidateConstraint { constraint_name } => {
            let mut targets = vec![subject_target(LockModeFact::ShareUpdateExclusive)];
            if is_foreign_key(state, subject, constraint_name)
                && let Some(referenced) = foreign_key_target(state, subject, constraint_name)
            {
                targets.push(LockTarget {
                    relation: referenced,
                    mode: LockModeFact::RowShare,
                    role: LockTargetRole::Referenced,
                });
            }
            vec![LockPrediction {
                object_kind: ObjectKind::Table,
                object_name: subject.to_string(),
                operation: "Validating a constraint",
                work: LockWork::TableScan,
                targets,
            }]
        }
        AlterTableActionMutation::SetStorage { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: SET_STORAGE_OPERATION,
            work: LockWork::MetadataOnly,
            targets: vec![subject_target(LockModeFact::AccessExclusive)],
        }],
        AlterTableActionMutation::SetAccessMethod { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Changing a table access method",
            work: LockWork::TableRewrite,
            targets: vec![subject_target(LockModeFact::AccessExclusive)],
        }],
        AlterTableActionMutation::SetPersistence { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Changing table persistence",
            work: LockWork::TableRewrite,
            targets: vec![subject_target(LockModeFact::AccessExclusive)],
        }],
        AlterTableActionMutation::SetGeneratedExpression { column, .. } => {
            let work = match pre_state.relations.get(subject) {
                Some(relation) => match relation.generated_columns.get(column) {
                    Some(generated)
                        if generated.kind
                            == crate::_internal::model::relation::GeneratedColumnKind::Virtual =>
                    {
                        if relation
                            .get_column(column)
                            .is_some_and(|col| !col.is_nullable)
                        {
                            LockWork::TableScan
                        } else {
                            LockWork::MetadataOnly
                        }
                    }
                    _ => LockWork::TableRewrite,
                },
                None => LockWork::TableRewrite,
            };
            vec![LockPrediction {
                object_kind: ObjectKind::Table,
                object_name: subject.to_string(),
                operation: "Changing a generated column expression",
                work,
                targets: vec![subject_target(LockModeFact::AccessExclusive)],
            }]
        }
        AlterTableActionMutation::SetType { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Changing a column type",
            work: LockWork::MetadataOnly,
            targets: vec![subject_target(LockModeFact::AccessExclusive)],
        }],
        AlterTableActionMutation::AttachPartition { child, .. } => {
            let mut targets = vec![
                LockTarget {
                    relation: subject.clone(),
                    mode: LockModeFact::ShareUpdateExclusive,
                    role: LockTargetRole::Parent,
                },
                LockTarget {
                    relation: child.clone(),
                    mode: LockModeFact::AccessExclusive,
                    role: LockTargetRole::Child,
                },
            ];
            let mut seen = HashSet::from([child.clone()]);
            for descendant in state.local.graph.partition_descendants(child) {
                push_partition_target(&mut targets, &mut seen, descendant, LockTargetRole::Child);
            }
            for default in state.default_partitions_of(subject) {
                for descendant in std::iter::once(default.clone())
                    .chain(state.local.graph.partition_descendants(&default))
                {
                    push_partition_target(
                        &mut targets,
                        &mut seen,
                        descendant,
                        LockTargetRole::DefaultPartition,
                    );
                }
            }
            vec![LockPrediction {
                object_kind: ObjectKind::Table,
                object_name: subject.to_string(),
                operation: "Attaching a partition",
                work: LockWork::MetadataOnly,
                targets,
            }]
        }
        AlterTableActionMutation::DetachPartition { child, mode } => {
            // DETACH PARTITION CONCURRENTLY and FINALIZE were added in PG 14.
            // CONCURRENTLY/FINALIZE hold SHARE UPDATE EXCLUSIVE on the parent;
            // immediate DETACH holds ACCESS EXCLUSIVE on both sides.
            let parent_mode = match mode {
                DetachPartitionMode::Immediate => LockModeFact::AccessExclusive,
                DetachPartitionMode::Concurrently | DetachPartitionMode::Finalize => {
                    LockModeFact::ShareUpdateExclusive
                }
            };
            let mut targets = vec![
                LockTarget {
                    relation: subject.clone(),
                    mode: parent_mode,
                    role: LockTargetRole::Parent,
                },
                LockTarget {
                    relation: child.clone(),
                    mode: LockModeFact::AccessExclusive,
                    role: LockTargetRole::Child,
                },
            ];
            for referencing in referencing_tables(state, subject) {
                targets.push(LockTarget {
                    relation: referencing,
                    mode: LockModeFact::Share,
                    role: LockTargetRole::Referencing,
                });
            }
            vec![LockPrediction {
                object_kind: ObjectKind::Table,
                object_name: subject.to_string(),
                operation: "Detaching a partition",
                work: LockWork::MetadataOnly,
                targets,
            }]
        }
        _ => Vec::new(),
    }
}

fn predict_reindex(
    target: &ReindexTargetMutation,
    pre_state: &PreState,
    state: &AnalysisState,
) -> Vec<LockPrediction> {
    match target {
        ReindexTargetMutation::Table(table) => {
            // PostgreSQL rebuilds every index of the table, including indexes
            // on its partitions, and takes ACCESS EXCLUSIVE on each one.
            let mut tables = HashSet::from([table.clone()]);
            tables.extend(state.local.graph.partition_descendants(table));
            let predictions = pre_state
                .indexes
                .iter()
                .filter(|edge| tables.contains(&edge.referenced))
                .map(|edge| predict_reindexed_index(pre_state, &edge.dependent))
                .collect::<Vec<_>>();
            if predictions.is_empty() {
                vec![LockPrediction {
                    object_kind: ObjectKind::Table,
                    object_name: table.to_string(),
                    operation: "Reindexing a table without CONCURRENTLY",
                    work: LockWork::IndexBuild,
                    targets: vec![LockTarget {
                        relation: table.clone(),
                        mode: LockModeFact::Share,
                        role: LockTargetRole::Subject,
                    }],
                }]
            } else {
                predictions
            }
        }
        ReindexTargetMutation::Index(index) => {
            vec![predict_reindexed_index(pre_state, index)]
        }
        ReindexTargetMutation::Schema(schema) => pre_state
            .indexes
            .iter()
            .filter(|edge| edge.dependent.schema.as_str() == schema.as_str())
            .map(|edge| predict_reindexed_index(pre_state, &edge.dependent))
            .collect(),
        ReindexTargetMutation::Database(_) => pre_state
            .indexes
            .iter()
            .map(|edge| predict_reindexed_index(pre_state, &edge.dependent))
            .collect(),
        // REINDEX SYSTEM cannot run inside a transaction block and is not
        // modeled as a migration statement with an advisory.
        ReindexTargetMutation::System(_) => Vec::new(),
    }
}

fn predict_reindexed_index(pre_state: &PreState, index: &ObjectId) -> LockPrediction {
    let mut targets = Vec::new();
    if let Some(table) = relation_for_index(pre_state, index) {
        targets.push(LockTarget {
            relation: table,
            mode: LockModeFact::Share,
            role: LockTargetRole::Subject,
        });
    }
    targets.push(LockTarget {
        relation: index.clone(),
        mode: LockModeFact::AccessExclusive,
        role: LockTargetRole::Index,
    });
    LockPrediction {
        object_kind: ObjectKind::Index,
        object_name: index.to_string(),
        operation: "Reindexing an index without CONCURRENTLY",
        work: LockWork::IndexBuild,
        targets,
    }
}

fn push_partition_target(
    targets: &mut Vec<LockTarget>,
    seen: &mut HashSet<ObjectId>,
    relation: ObjectId,
    role: LockTargetRole,
) {
    if seen.insert(relation.clone()) {
        targets.push(LockTarget {
            relation,
            mode: LockModeFact::AccessExclusive,
            role,
        });
    }
}

fn referencing_tables(state: &AnalysisState, target: &ObjectId) -> Vec<ObjectId> {
    let mut tables = Vec::new();
    for edge in state.local.graph.edges() {
        if !matches!(edge.kind, DependencyKind::ForeignKey { .. }) {
            continue;
        }
        if edge.referenced != *target {
            continue;
        }
        let dependent = state.local.graph.resolve_rename(&edge.dependent).clone();
        if !tables.contains(&dependent) {
            tables.push(dependent);
        }
    }
    tables
}

fn is_foreign_key(state: &AnalysisState, table: &ObjectId, constraint_name: &str) -> bool {
    state
        .local
        .constraints
        .get(&(table.clone(), constraint_name.to_string()))
        .is_some_and(|constraint| constraint.kind == ConstraintKind::ForeignKey)
}

fn foreign_key_target(
    state: &AnalysisState,
    table: &ObjectId,
    constraint_name: &str,
) -> Option<ObjectId> {
    state.local.graph.edges().iter().find_map(|edge| {
        if edge.dependent != *table {
            return None;
        }
        match &edge.kind {
            DependencyKind::ForeignKey {
                constraint_name: Some(name),
                ..
            } if name == constraint_name => Some(edge.referenced.clone()),
            _ => None,
        }
    })
}

fn index_columns_for_constraint(
    state: &AnalysisState,
    subject: &ObjectId,
    index: &ObjectId,
    constraint_name: Option<&str>,
) -> Option<Vec<String>> {
    let adopted = ObjectId::new(&index.schema, constraint_name.unwrap_or(&index.name));
    state.local.graph.edges().iter().find_map(|edge| {
        let dependent = state.local.graph.resolve_rename(&edge.dependent);
        if *dependent != *index && *dependent != adopted {
            return None;
        }
        if edge.referenced != *subject {
            return None;
        }
        match &edge.kind {
            DependencyKind::IndexOnRelation {
                dependency_columns,
                dependency_columns_known: true,
                ..
            } => Some(dependency_columns.clone()),
            _ => None,
        }
    })
}

fn columns_are_nullable(
    pre_state: &PreState,
    subject: &ObjectId,
    columns: &[String],
) -> Option<bool> {
    let relation = pre_state.relations.get(subject)?;
    if !relation.columns_complete {
        return None;
    }
    let mut nullable = false;
    for name in columns {
        let column = relation
            .columns
            .iter()
            .find(|column| column.name == *name)?;
        nullable |= column.is_nullable;
    }
    Some(nullable)
}

fn domain_action_takes_share_lock(action: &AlterDomainActionFact) -> bool {
    match action {
        AlterDomainActionFact::AddConstraint(DomainConstraintFact::Check(check)) => {
            !check.not_valid
        }
        AlterDomainActionFact::AddConstraint(DomainConstraintFact::NotNull { .. })
        | AlterDomainActionFact::SetNotNull
        | AlterDomainActionFact::ValidateConstraint { .. } => true,
        _ => false,
    }
}

fn relation_for_index(pre_state: &PreState, index: &ObjectId) -> Option<ObjectId> {
    pre_state
        .indexes
        .iter()
        .find(|edge| edge.dependent == *index)
        .map(|edge| edge.referenced.clone())
}
