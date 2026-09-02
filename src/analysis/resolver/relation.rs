use super::Resolver;
use crate::analysis::facts::{
    AlterTableActionFact, ColumnFact, FkFact, PersistenceFact, TableConstraintFact,
};
use crate::analysis::mutations::{
    AlterTable, AlterTableActionMutation, ColumnMutation, CreateTable, DropIndex,
    DropMaterializedViewMutation, DropTable, DropViewMutation, FkMutation, Mutation,
    PersistenceMutation, Rename,
};
use crate::analysis::state::AnalysisState;
use crate::ast::identifiers::{ObjectId, QualifiedName};

impl Resolver {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn resolve_create_table(
        name: &QualifiedName,
        if_not_exists: bool,
        as_select: bool,
        persistence: &PersistenceFact,
        columns: &[ColumnFact],
        foreign_keys: &[FkFact],
        table_constraints: &[TableConstraintFact],
        partition_by: &Option<String>,
        partition_of: &Option<QualifiedName>,
        partition_type: &Option<String>,
        state: &AnalysisState,
    ) -> Mutation {
        let persistence = match persistence {
            PersistenceFact::Permanent => PersistenceMutation::Permanent,
            PersistenceFact::Temporary => PersistenceMutation::Temporary,
            PersistenceFact::Unlogged => PersistenceMutation::Unlogged,
        };
        let columns = columns
            .iter()
            .map(|column| ColumnMutation {
                name: column.name.clone(),
                ty: column.ty.clone(),
                not_null: column.not_null,
                is_primary_key: column.is_primary_key,
                primary_key_constraint_name: column.primary_key_constraint_name.clone(),
                is_unique: column.is_unique,
                unique_constraint_name: column.unique_constraint_name.clone(),
                default: column.default.clone(),
                generation: column.generation,
            })
            .collect();
        let foreign_keys = foreign_keys
            .iter()
            .map(|foreign_key| FkMutation {
                constraint_name: foreign_key.constraint_name.clone(),
                to_table: Self::resolve_relation_lookup_name(&foreign_key.references, state),
                from_columns: foreign_key.from_columns.clone(),
                to_columns: foreign_key.to_columns.clone(),
            })
            .collect();
        Mutation::CreateTable(CreateTable {
            id: Self::resolve_creation_name(name, state),
            if_not_exists,
            as_select,
            persistence,
            columns,
            foreign_keys,
            table_constraints: table_constraints.to_vec(),
            partition_by: partition_by.clone(),
            partition_of: partition_of
                .as_ref()
                .map(|parent| Self::resolve_relation_lookup_name(parent, state)),
            partition_type: partition_type.clone(),
        })
    }

    pub(super) fn resolve_alter_table(
        name: &QualifiedName,
        actions: &[AlterTableActionFact],
        state: &AnalysisState,
    ) -> Vec<Mutation> {
        let id = Self::resolve_relation_lookup_name(name, state);
        let mut mutations = Vec::with_capacity(actions.len());
        for action_fact in actions {
            let action = match action_fact {
                AlterTableActionFact::AddColumn {
                    name,
                    ty,
                    if_not_exists,
                    not_null,
                    default,
                    generation,
                } => AlterTableActionMutation::AddColumn {
                    name: name.clone(),
                    ty: ty.clone(),
                    if_not_exists: *if_not_exists,
                    not_null: *not_null,
                    default: default.clone(),
                    depends_on: None,
                    generation: *generation,
                },
                AlterTableActionFact::DropColumn {
                    name,
                    if_exists,
                    cascade,
                } => AlterTableActionMutation::DropColumn {
                    name: name.clone(),
                    if_exists: *if_exists,
                    cascade: *cascade,
                },
                AlterTableActionFact::RenameColumn { from, to } => {
                    AlterTableActionMutation::RenameColumn {
                        from: from.resolve(),
                        to: to.resolve(),
                    }
                }
                AlterTableActionFact::RenameTo { new_name } => {
                    let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                    new_id.inferred_schema = id.inferred_schema;
                    mutations.push(Mutation::Rename(Rename {
                        old_id: id.clone(),
                        new_id,
                    }));
                    continue;
                }
                AlterTableActionFact::SetSchema { new_schema } => {
                    mutations.push(Mutation::Rename(Rename {
                        old_id: id.clone(),
                        new_id: ObjectId::new(new_schema, &id.name),
                    }));
                    continue;
                }
                AlterTableActionFact::AddForeignKey {
                    constraint_name,
                    references,
                    from_columns,
                    to_columns,
                    not_valid,
                } => {
                    let to_table = Self::resolve_relation_lookup_name(references, state);
                    AlterTableActionMutation::AddForeignKey {
                        constraint_name: constraint_name.clone(),
                        to_table,
                        from_columns: from_columns.clone(),
                        to_columns: to_columns.clone(),
                        not_valid: *not_valid,
                    }
                }
                AlterTableActionFact::AlterConstraint { name, deferrable } => {
                    AlterTableActionMutation::AlterConstraint {
                        name: name.clone(),
                        deferrable: *deferrable,
                    }
                }
                AlterTableActionFact::RenameConstraint { old_name, new_name } => {
                    AlterTableActionMutation::RenameConstraint {
                        old_name: old_name.clone(),
                        new_name: new_name.clone(),
                    }
                }
                AlterTableActionFact::DropConstraint {
                    name,
                    if_exists,
                    cascade,
                } => AlterTableActionMutation::DropConstraint {
                    name: name.clone(),
                    if_exists: *if_exists,
                    cascade: *cascade,
                },
                AlterTableActionFact::AddCheckConstraint {
                    constraint_name,
                    columns,
                    columns_complete,
                    not_valid,
                } => AlterTableActionMutation::AddCheckConstraint {
                    constraint_name: constraint_name.clone(),
                    columns: columns.clone(),
                    columns_complete: *columns_complete,
                    not_valid: *not_valid,
                },
                AlterTableActionFact::AddUniqueConstraint {
                    constraint_name,
                    columns,
                    using_index,
                } => AlterTableActionMutation::AddUniqueConstraint {
                    constraint_name: constraint_name.clone(),
                    columns: columns.clone(),
                    using_index: using_index
                        .as_ref()
                        .map(|name| Self::resolve_constraint_index_name(name, &id)),
                },
                AlterTableActionFact::AddPrimaryKeyConstraint {
                    constraint_name,
                    columns,
                    using_index,
                } => AlterTableActionMutation::AddPrimaryKeyConstraint {
                    constraint_name: constraint_name.clone(),
                    columns: columns.clone(),
                    using_index: using_index
                        .as_ref()
                        .map(|name| Self::resolve_constraint_index_name(name, &id)),
                },
                AlterTableActionFact::AddExcludeConstraint {
                    constraint_name,
                    columns,
                    columns_complete,
                } => AlterTableActionMutation::AddExcludeConstraint {
                    constraint_name: constraint_name.clone(),
                    columns: columns.clone(),
                    columns_complete: *columns_complete,
                },
                AlterTableActionFact::SetNotNull { column } => {
                    AlterTableActionMutation::SetNotNull {
                        column: column.clone(),
                    }
                }
                AlterTableActionFact::DropNotNull { column } => {
                    AlterTableActionMutation::DropNotNull {
                        column: column.clone(),
                    }
                }
                AlterTableActionFact::SetType {
                    column,
                    ty,
                    has_using,
                } => AlterTableActionMutation::SetType {
                    column: column.clone(),
                    ty: ty.clone(),
                    has_using: *has_using,
                },
                AlterTableActionFact::SetDefault { column, default } => {
                    AlterTableActionMutation::SetDefault {
                        column: column.clone(),
                        default: default.clone(),
                    }
                }
                AlterTableActionFact::ValidateConstraint { constraint_name } => {
                    AlterTableActionMutation::ValidateConstraint {
                        constraint_name: constraint_name.clone(),
                    }
                }
                AlterTableActionFact::AttachPartition { child, strategy } => {
                    AlterTableActionMutation::AttachPartition {
                        child: Self::resolve_relation_lookup_name(child, state),
                        strategy: strategy.clone(),
                    }
                }
                AlterTableActionFact::DetachPartition { child } => {
                    AlterTableActionMutation::DetachPartition {
                        child: Self::resolve_relation_lookup_name(child, state),
                    }
                }
                AlterTableActionFact::SetStorage { column } => {
                    AlterTableActionMutation::SetStorage {
                        column: column.clone(),
                    }
                }
                AlterTableActionFact::SetAccessMethod => AlterTableActionMutation::SetAccessMethod,
                AlterTableActionFact::DisableTrigger { trigger_name } => {
                    AlterTableActionMutation::DisableTrigger {
                        trigger_name: trigger_name.clone(),
                    }
                }
                AlterTableActionFact::EnableTrigger { trigger_name } => {
                    AlterTableActionMutation::EnableTrigger {
                        trigger_name: trigger_name.clone(),
                    }
                }
                AlterTableActionFact::SetExpression { .. }
                | AlterTableActionFact::SetOptions { .. }
                | AlterTableActionFact::Inherit { .. }
                | AlterTableActionFact::NoInherit { .. }
                | AlterTableActionFact::ClusterOn { .. }
                | AlterTableActionFact::InheritTable { .. }
                | AlterTableActionFact::NoInheritTable { .. }
                | AlterTableActionFact::MergePartitions { .. }
                | AlterTableActionFact::SplitPartition
                | AlterTableActionFact::SetTablespace { .. }
                | AlterTableActionFact::SetLogged
                | AlterTableActionFact::SetUnlogged
                | AlterTableActionFact::ReplicaIdentity { .. }
                | AlterTableActionFact::ForceRls
                | AlterTableActionFact::EnableRls
                | AlterTableActionFact::DisableRls
                | AlterTableActionFact::EnableAlwaysTrigger { .. }
                | AlterTableActionFact::EnableReplicaTrigger { .. } => {
                    AlterTableActionMutation::Opaque
                }
                AlterTableActionFact::OwnerTo { new_owner } => AlterTableActionMutation::OwnerTo {
                    new_owner: new_owner.clone(),
                },
            };
            mutations.push(Mutation::AlterTable(AlterTable {
                id: id.clone(),
                action,
            }));
        }
        mutations
    }

    pub(super) fn resolve_drop_table(
        names: &[QualifiedName],
        if_exists: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropTable(DropTable {
            ids: names
                .iter()
                .map(|name| Self::resolve_relation_lookup_name(name, state))
                .collect(),
            if_exists,
            cascade,
        })
    }

    pub(super) fn resolve_drop_view(
        names: &[QualifiedName],
        if_exists: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropView(DropViewMutation {
            ids: names
                .iter()
                .map(|name| Self::resolve_relation_lookup_name(name, state))
                .collect(),
            if_exists,
            cascade,
        })
    }

    pub(super) fn resolve_drop_materialized_view(
        names: &[QualifiedName],
        if_exists: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropMaterializedView(DropMaterializedViewMutation {
            ids: names
                .iter()
                .map(|name| Self::resolve_relation_lookup_name(name, state))
                .collect(),
            if_exists,
            cascade,
        })
    }

    pub(super) fn resolve_drop_indexes(
        names: &[QualifiedName],
        if_exists: bool,
        concurrently: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropIndex(DropIndex {
            ids: names
                .iter()
                .map(|name| Self::resolve_relation_lookup_name(name, state))
                .collect(),
            if_exists,
            concurrently,
            cascade,
        })
    }
}
