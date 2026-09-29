//! Resolving the catalog object a mutation most directly concerns.
//!
//! Synthetic mutations such as the timeout check carry no payload of their
//! own, so rules reporting on them need the subject of the statement they were
//! raised for. Keeping that mapping in one place stops each rule from
//! inventing its own placeholder name.

use crate::_internal::analysis::mutations::{
    CreatePolicyMutation, Mutation, ReindexTargetMutation, RelationTargetMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::report::violations::ObjectKind;

impl Mutation {
    /// The single object a mutation acts on, when it has exactly one.
    ///
    /// Returns `None` for control flow, settings, and synthetic mutations, and
    /// for statements naming several targets. Callers must then report an
    /// unknown subject rather than guessing one.
    pub(crate) fn primary_object(&self) -> Option<(ObjectKind, String)> {
        let one = |kind: ObjectKind, id: &ObjectId| Some((kind, id.to_string()));
        let many = |kind: ObjectKind, ids: &[ObjectId]| match ids {
            [id] => Some((kind, id.to_string())),
            _ => None,
        };

        match self {
            Mutation::CreateSchema(m) => Some((ObjectKind::Schema, m.name.clone())),
            Mutation::CreateTable(m) => one(ObjectKind::Table, &m.id),
            Mutation::CreateView(m) => one(ObjectKind::View, &m.id),
            Mutation::CreateMaterializedView(m) => one(ObjectKind::MaterializedView, &m.id),
            Mutation::CreateIndex(m) => one(ObjectKind::Index, &m.id),
            Mutation::CreateType(m) => one(ObjectKind::Type, &m.id),
            Mutation::CreateDomain(m) => one(ObjectKind::Domain, &m.id),
            Mutation::CreateSequence(m) => one(ObjectKind::Sequence, &m.id),
            Mutation::CreateFunction(m) => one(ObjectKind::Function, &m.id),
            Mutation::CreateProcedure(m) => one(ObjectKind::Procedure, &m.id),
            Mutation::CreateAggregate(m) => one(ObjectKind::Type, &m.id),
            Mutation::CreatePublication(m) => Some((ObjectKind::Publication, m.name.clone())),
            Mutation::CreateSubscription(m) => {
                Some((ObjectKind::Publication, m.name.clone().unwrap_or_default()))
            }
            Mutation::CreateRole(m) => Some((ObjectKind::Role, m.name.clone())),
            Mutation::CreatePolicy(m) => Some((ObjectKind::Policy, policy_name(m))),
            Mutation::CreateTrigger(m) => Some((ObjectKind::Trigger, m.name.clone())),

            Mutation::AlterTable(m) => one(ObjectKind::Table, &m.id),
            Mutation::AlterIndex(m) => one(ObjectKind::Index, &m.index_id),
            Mutation::AlterIndexAllInTablespace(m) => {
                Some((ObjectKind::Index, m.source_tablespace.clone()))
            }
            Mutation::Rename(m) => one(ObjectKind::Table, &m.old_id),

            Mutation::DropTable(m) => many(ObjectKind::Table, &m.ids),
            Mutation::DropView(m) => many(ObjectKind::View, &m.ids),
            Mutation::DropIndex(m) => many(ObjectKind::Index, &m.ids),
            Mutation::DropType(m) => many(ObjectKind::Type, &m.ids),
            Mutation::DropDomain(m) => many(ObjectKind::Domain, &m.ids),
            Mutation::DropSequence(m) => many(ObjectKind::Sequence, &m.ids),
            Mutation::DropTrigger(m) => Some((ObjectKind::Trigger, m.name.clone())),

            Mutation::Reindex { target, .. } => Some(match target.as_ref()? {
                ReindexTargetMutation::Database(name) => (ObjectKind::Database, name.clone()),
                ReindexTargetMutation::Schema(name) => (ObjectKind::Schema, name.clone()),
                ReindexTargetMutation::System(name) => (
                    ObjectKind::Unknown,
                    name.clone().unwrap_or_else(|| "system".to_string()),
                ),
                ReindexTargetMutation::Table(id) => (ObjectKind::Table, id.to_string()),
                ReindexTargetMutation::Index(id) => (ObjectKind::Index, id.to_string()),
            }),
            Mutation::Vacuum { table_id, .. } => table_id
                .as_ref()
                .map(|id| (ObjectKind::Table, id.to_string())),
            Mutation::LockTable(m) => relation_target(&m.targets),
            Mutation::Truncate(m) => relation_target(&m.targets),

            _ => None,
        }
    }
}

/// A policy is reported as `table.policy`, matching how PostgreSQL names it.
fn policy_name(m: &CreatePolicyMutation) -> String {
    format!("{}.{}", m.table.name, m.name)
}

/// Locking or truncating several relations has no single subject.
fn relation_target(targets: &[RelationTargetMutation]) -> Option<(ObjectKind, String)> {
    match targets {
        [RelationTargetMutation { id, .. }] => Some((ObjectKind::Table, id.to_string())),
        _ => None,
    }
}
