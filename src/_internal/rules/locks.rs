use crate::_internal::analysis::facts::{
    AlterDomainActionFact, DetachPartitionMode, DomainConstraintFact, LockModeFact,
};
use crate::_internal::analysis::mutations::{
    AlterTableActionMutation, Mutation, ReindexTargetMutation,
};
use crate::_internal::analysis::state::{AnalysisState, PreState};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::relation::Persistence;
use crate::_internal::report::violations::{ObjectKind, Violation, ViolationTier};
use crate::_internal::rules::{Rule, RuleContext};

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
    Parent,
    Child,
    Index,
    MaterializedView,
}

impl LockTargetRole {
    fn label(self) -> &'static str {
        match self {
            Self::Subject => "table",
            Self::Referenced => "referenced table",
            Self::Parent => "parent table",
            Self::Child => "partition",
            Self::Index => "index",
            Self::MaterializedView => "materialized view",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockScope {
    Statement,
    Scan,
    Rewrite,
    IndexBuild,
}

impl LockScope {
    fn phrase(self) -> &'static str {
        match self {
            Self::Statement => "for the statement",
            Self::Scan => "while scanning the table",
            Self::Rewrite => "while rewriting the table",
            Self::IndexBuild => "while building the index",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LockPrediction {
    pub object_kind: ObjectKind,
    pub object_name: String,
    pub operation: &'static str,
    pub scope: LockScope,
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
                    reason: format_reason(prediction.operation, prediction.scope, &targets),
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

fn format_reason(operation: &str, scope: LockScope, targets: &[LockTarget]) -> String {
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
        "blocking reads and writes"
    } else if targets.iter().any(|target| target.mode.blocks_writes()) {
        "blocking writes"
    } else {
        "blocking concurrent DDL"
    };

    format!("{operation} takes {locks} {}, {impact}.", scope.phrase())
}

fn predict_locks(
    mutation: &Mutation,
    pre_state: &PreState,
    state: &AnalysisState,
) -> Vec<LockPrediction> {
    match mutation {
        Mutation::AlterTable(alter) => predict_alter_table(&alter.id, &alter.action),
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
                scope: LockScope::Scan,
                targets,
            }]
        }
        Mutation::CreateIndex(create) if !create.concurrently => vec![LockPrediction {
            object_kind: ObjectKind::Index,
            object_name: create.id.to_string(),
            operation: "Creating an index without CONCURRENTLY",
            scope: LockScope::IndexBuild,
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
                    scope: LockScope::Statement,
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
        } => predict_reindex(target),
        Mutation::RefreshMaterializedView(refresh) if !refresh.concurrently => {
            vec![LockPrediction {
                object_kind: ObjectKind::MaterializedView,
                object_name: refresh.id.to_string(),
                operation: "Refreshing a materialized view without CONCURRENTLY",
                scope: LockScope::Statement,
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
            scope: LockScope::Rewrite,
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
                scope: LockScope::Statement,
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
) -> Vec<LockPrediction> {
    let subject_target = |mode| LockTarget {
        relation: subject.clone(),
        mode,
        role: LockTargetRole::Subject,
    };

    match action {
        AlterTableActionMutation::AddCheckConstraint {
            not_valid: false, ..
        } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Adding a valid CHECK constraint",
            scope: LockScope::Scan,
            targets: vec![subject_target(LockModeFact::AccessExclusive)],
        }],
        AlterTableActionMutation::AddForeignKey {
            not_valid: false,
            to_table,
            ..
        } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Adding a valid FOREIGN KEY constraint",
            scope: LockScope::Scan,
            targets: vec![
                subject_target(LockModeFact::ShareRowExclusive),
                LockTarget {
                    relation: to_table.clone(),
                    mode: LockModeFact::ShareRowExclusive,
                    role: LockTargetRole::Referenced,
                },
            ],
        }],
        AlterTableActionMutation::SetNotNull { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Setting a column NOT NULL",
            scope: LockScope::Statement,
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
            scope: LockScope::IndexBuild,
            targets: vec![
                subject_target(LockModeFact::AccessExclusive),
                subject_target(LockModeFact::Share),
            ],
        }],
        AlterTableActionMutation::AddExcludeConstraint { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Adding an EXCLUDE constraint",
            scope: LockScope::IndexBuild,
            targets: vec![
                subject_target(LockModeFact::AccessExclusive),
                subject_target(LockModeFact::Share),
            ],
        }],
        AlterTableActionMutation::ValidateConstraint { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Validating a constraint",
            scope: LockScope::Scan,
            targets: vec![subject_target(LockModeFact::ShareUpdateExclusive)],
        }],
        AlterTableActionMutation::SetStorage { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: SET_STORAGE_OPERATION,
            scope: LockScope::Statement,
            targets: vec![subject_target(LockModeFact::AccessExclusive)],
        }],
        AlterTableActionMutation::SetAccessMethod { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Changing a table access method",
            scope: LockScope::Rewrite,
            targets: vec![subject_target(LockModeFact::AccessExclusive)],
        }],
        AlterTableActionMutation::SetType { .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Changing a column type",
            scope: LockScope::Statement,
            targets: vec![subject_target(LockModeFact::AccessExclusive)],
        }],
        AlterTableActionMutation::AttachPartition { child, .. } => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: subject.to_string(),
            operation: "Attaching a partition",
            scope: LockScope::Statement,
            targets: vec![
                LockTarget {
                    relation: child.clone(),
                    mode: LockModeFact::AccessExclusive,
                    role: LockTargetRole::Child,
                },
                LockTarget {
                    relation: subject.clone(),
                    mode: LockModeFact::ShareUpdateExclusive,
                    role: LockTargetRole::Parent,
                },
            ],
        }],
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
            vec![LockPrediction {
                object_kind: ObjectKind::Table,
                object_name: subject.to_string(),
                operation: "Detaching a partition",
                scope: LockScope::Statement,
                targets: vec![
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
                ],
            }]
        }
        _ => Vec::new(),
    }
}

fn predict_reindex(target: &ReindexTargetMutation) -> Vec<LockPrediction> {
    match target {
        ReindexTargetMutation::Table(table) => vec![LockPrediction {
            object_kind: ObjectKind::Table,
            object_name: table.to_string(),
            operation: "Reindexing a table without CONCURRENTLY",
            scope: LockScope::IndexBuild,
            targets: vec![LockTarget {
                relation: table.clone(),
                mode: LockModeFact::Share,
                role: LockTargetRole::Subject,
            }],
        }],
        ReindexTargetMutation::Index(index) => vec![LockPrediction {
            object_kind: ObjectKind::Index,
            object_name: index.to_string(),
            operation: "Reindexing an index without CONCURRENTLY",
            scope: LockScope::IndexBuild,
            targets: vec![LockTarget {
                relation: index.clone(),
                mode: LockModeFact::AccessExclusive,
                role: LockTargetRole::Index,
            }],
        }],
        ReindexTargetMutation::Database(_)
        | ReindexTargetMutation::Schema(_)
        | ReindexTargetMutation::System(_) => Vec::new(),
    }
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
