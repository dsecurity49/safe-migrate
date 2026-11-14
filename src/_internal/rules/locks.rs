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
use crate::_internal::model::relation::{Persistence, RelationOverlay};
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
    TableRewrite,
    IndexBuild,
}

impl LockWork {
    fn phrase(self) -> &'static str {
        match self {
            Self::MetadataOnly => "",
            Self::TableScan => ", scanning the table",
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
        } => predict_reindex(target, pre_state),
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
            let work = if nullable == Some(true) {
                LockWork::TableScan
            } else {
                LockWork::MetadataOnly
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
            for descendant in partition_descendants(state, child) {
                push_partition_target(&mut targets, &mut seen, descendant, LockTargetRole::Child);
            }
            for default in default_partitions(state, subject) {
                for descendant in
                    std::iter::once(default.clone()).chain(partition_descendants(state, &default))
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

fn predict_reindex(target: &ReindexTargetMutation, pre_state: &PreState) -> Vec<LockPrediction> {
    match target {
        ReindexTargetMutation::Table(table) => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: table.to_string(),
            operation: "Reindexing a table without CONCURRENTLY",
            work: LockWork::IndexBuild,
            targets: vec![LockTarget {
                relation: table.clone(),
                mode: LockModeFact::Share,
                role: LockTargetRole::Subject,
            }],
        }],
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

fn partition_descendants(state: &AnalysisState, root: &ObjectId) -> Vec<ObjectId> {
    let mut descendants = Vec::new();
    let mut queue = state
        .local
        .graph
        .partitions_of(root)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    while let Some(child) = queue.pop() {
        if descendants.contains(&child) {
            continue;
        }
        queue.extend(state.local.graph.partitions_of(&child).into_iter().cloned());
        descendants.push(child);
    }
    descendants
}

fn default_partitions(state: &AnalysisState, parent: &ObjectId) -> Vec<ObjectId> {
    state
        .local
        .graph
        .partitions_of(parent)
        .into_iter()
        .filter(|child| {
            matches!(
                state.local.relations.get(child),
                Some(RelationOverlay::Present(relation))
                    if relation
                        .partition_bound
                        .as_deref()
                        .is_some_and(|bound| bound.eq_ignore_ascii_case("DEFAULT"))
            )
        })
        .map(|child| (*child).clone())
        .collect()
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
