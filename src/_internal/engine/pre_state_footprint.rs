use crate::_internal::analysis::mutations::{
    AlterTableActionMutation, AlterTypeActionMutation, Mutation,
};
use crate::_internal::analysis::state::{AnalysisState, CascadeResult, PreStateReadSet, ReadScope};
use std::collections::HashSet;

/// Pre-state reads exercised by the rule set for one transition.
///
/// The match is exhaustive so a new mutation forces an explicit footprint
/// decision instead of silently inheriting a narrow snapshot. Whole-family
/// reads use `require_all` when a rule scans every object of that family.
pub(crate) fn for_mutation(
    state: &AnalysisState,
    mutation: &Mutation,
    cascade: Option<&CascadeResult>,
) -> PreStateReadSet {
    let mut reads = PreStateReadSet::none();

    match mutation {
        Mutation::CreateTable(create) => {
            if let Some(parent) = &create.partition_of {
                reads.relations.insert(parent.clone());
            }
        }
        Mutation::AlterTable(alter) => {
            reads.relations.insert(alter.id.clone());
            match &alter.action {
                AlterTableActionMutation::AddForeignKey { to_table, .. } => {
                    reads.relations.insert(to_table.clone());
                }
                AlterTableActionMutation::AttachPartition { child, .. }
                | AlterTableActionMutation::DetachPartition { child, .. } => {
                    reads.relations.insert(child.clone());
                }
                AlterTableActionMutation::SetNotNull { .. } => {
                    for (table_id, name) in state.local.constraints.keys() {
                        if table_id == &alter.id {
                            reads.constraints.insert((table_id.clone(), name.clone()));
                        }
                    }
                }
                _ => {}
            }
        }
        Mutation::CreateIndex(create) => {
            reads.relations.insert(create.table.clone());
        }
        Mutation::RefreshMaterializedView(refresh) => {
            reads.relations.insert(refresh.id.clone());
        }
        Mutation::DropTable(drop) => {
            for id in &drop.ids {
                reads.relations.insert(id.clone());
            }
            if let Some(closure) = cascade {
                reads.baseline_foreign_keys =
                    ReadScope::selected(closure.dropped_constraints.iter().cloned());
            }
        }
        Mutation::DropView(drop) => {
            for id in &drop.ids {
                reads.relations.insert(id.clone());
            }
        }
        Mutation::DropMaterializedView(drop) => {
            for id in &drop.ids {
                reads.relations.insert(id.clone());
            }
        }
        Mutation::Truncate(truncate) => {
            for target in &truncate.targets {
                reads.relations.insert(target.id.clone());
            }
        }
        Mutation::DropIndex(drop) => {
            let dropped = drop.ids.iter().cloned().collect::<HashSet<_>>();
            reads.indexes = ReadScope::selected(drop.ids.iter().cloned());
            for edge in state.local.graph.edges_for_dependents(&dropped) {
                if matches!(
                    edge.kind,
                    crate::_internal::analysis::graph::DependencyKind::IndexOnRelation { .. }
                ) {
                    reads.relations.insert(edge.referenced.clone());
                }
            }
        }
        Mutation::Rename(rename) => {
            reads.relations.insert(rename.old_id.clone());
            reads.types.insert(rename.old_id.clone());
            reads.sequences.insert(rename.old_id.clone());
            reads.indexes.insert(rename.old_id.clone());
        }
        Mutation::AlterType(alter) => match &alter.action {
            AlterTypeActionMutation::DropAttribute { .. }
            | AlterTypeActionMutation::AlterAttributeType { .. } => {
                reads.relations.require_all();
                reads.types.require_all();
            }
            _ => {
                reads.types.insert(alter.id.clone());
            }
        },
        Mutation::AlterDomain(alter) => {
            reads.types.insert(alter.id.clone());
            for relation in state.relations_using_domain(&alter.id) {
                reads.relations.insert(relation.id.clone());
            }
        }
        Mutation::DropDomain(drop) => {
            for id in &drop.ids {
                reads.types.insert(id.clone());
            }
        }
        Mutation::DropType(drop) => {
            for id in &drop.ids {
                reads.types.insert(id.clone());
            }
        }
        Mutation::AlterSequence(alter) => {
            reads.sequences.insert(alter.id.clone());
        }
        Mutation::DropSequence(drop) => {
            for id in &drop.ids {
                reads.sequences.insert(id.clone());
            }
        }
        Mutation::AlterExtension(alter) => {
            reads.extensions.insert(alter.name.clone());
        }
        Mutation::DropExtension(drop) => {
            for name in &drop.names {
                reads.extensions.insert(name.clone());
            }
        }
        Mutation::CreateFunction(create) if create.or_replace => {
            reads.functions.insert(create.id.clone());
        }
        Mutation::CreateFunction(_) => {}
        Mutation::AlterFunction(alter) => {
            reads.functions.insert(alter.id.clone());
        }
        Mutation::DropFunction(_) => {
            // Drift resolves an unqualified signature after the drop removed
            // the routine, so the searched schema can differ from the
            // pre-transition resolution. Keep the whole family rather than
            // guessing which identity the rule will address.
            reads.functions.require_all();
        }
        Mutation::AlterProcedure(alter) => {
            reads.functions.insert(alter.id.clone());
        }
        Mutation::DropProcedure(_) => {
            reads.functions.require_all();
        }
        Mutation::CreateSchema(_)
        | Mutation::AlterSchema(_)
        | Mutation::DropSchema(_)
        | Mutation::CreateView(_)
        | Mutation::CreateMaterializedView(_)
        | Mutation::AlterViewFamily(_)
        | Mutation::CreatePolicy(_)
        | Mutation::DropPolicy(_)
        | Mutation::CreateTrigger(_)
        | Mutation::DropTrigger(_)
        | Mutation::RenameTrigger(_)
        | Mutation::CreateExtension(_)
        | Mutation::CreateDomain(_)
        | Mutation::CreateSequence(_)
        | Mutation::CreateType(_)
        | Mutation::RenameType(_)
        | Mutation::RenameDomain(_)
        | Mutation::AlterIndex(_)
        | Mutation::AlterIndexAllInTablespace(_)
        | Mutation::LockTable(_)
        | Mutation::ChangeRelationOwner { .. }
        | Mutation::SetReloptions { .. }
        | Mutation::ResetReloptions { .. }
        | Mutation::SetColumnDefault { .. }
        | Mutation::NoStateChange { .. }
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
        | Mutation::CreateProcedure(_)
        | Mutation::CreateAggregate(_)
        | Mutation::AlterAggregate(_)
        | Mutation::DropAggregate(_)
        | Mutation::CreatePublication(_)
        | Mutation::AlterPublication(_)
        | Mutation::DropPublication(_)
        | Mutation::CreateSubscription(_)
        | Mutation::AlterSubscription(_)
        | Mutation::DropSubscription(_)
        | Mutation::CreateRole(_)
        | Mutation::AlterRole(_)
        | Mutation::DropRole(_)
        | Mutation::Grant(_)
        | Mutation::Revoke(_)
        | Mutation::CreateDatabase(_)
        | Mutation::AlterDatabase(_)
        | Mutation::DropDatabase(_)
        | Mutation::SwitchRole { .. }
        | Mutation::Opaque(_)
        | Mutation::Reindex { .. }
        | Mutation::Vacuum { .. } => {}
    }

    reads
}
