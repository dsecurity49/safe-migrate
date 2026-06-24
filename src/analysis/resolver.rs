// FILE: src/analysis/resolver.rs
use crate::analysis::facts::{
    AlterIndexActionFact, AlterTableActionFact, PersistenceFact, StatementFact, TypeCreationKind,
};
use crate::analysis::mutations::{
    AlterDomainMutation, AlterSequenceMutation, AlterTable, AlterTableActionMutation,
    AlterTypeActionMutation, AlterTypeMutation, ColumnMutation, CreateDomainMutation, CreateIndex,
    CreateMaterializedView, CreatePolicyMutation, CreateSchemaMutation, CreateSequenceMutation,
    CreateTable, CreateTriggerMutation, CreateTypeMutation, CreateView, DropDomainMutation,
    DropIndex, DropMaterializedViewMutation, DropPolicyMutation, DropSchemaMutation,
    DropSequenceMutation, DropTable, DropTriggerMutation, DropViewMutation, FkMutation, Mutation,
    OpaqueMutation, PersistenceMutation, RefreshMaterializedViewMutation, ReleaseSavepointMutation,
    Rename, RollbackToSavepointMutation, SavepointMutation, SearchPathChange,
};
use crate::analysis::state::AnalysisState;
use crate::ast::identifiers::{ObjectId, QualifiedName};
use crate::model::types::TypeKind;

pub struct Resolver;

impl Resolver {
    fn resolve_creation_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        let schema = name
            .schema
            .as_ref()
            .map(|i| i.resolve())
            .unwrap_or_else(|| {
                state
                    .local
                    .search_path
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("public")
                    .to_string()
            });

        ObjectId {
            schema,
            name: name.name.resolve(),
        }
    }

    fn resolve_lookup_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        if let Some(schema_ident) = &name.schema {
            return ObjectId {
                schema: schema_ident.resolve(),
                name: name.name.resolve(),
            };
        }

        let resolved_name = name.name.resolve();

        for schema in &state.local.search_path {
            let candidate = ObjectId {
                schema: schema.clone(),
                name: resolved_name.clone(),
            };
            if state.local.relations.contains_key(&candidate)
                || state.local.types.contains_key(&candidate)
                || state.local.sequences.contains_key(&candidate)
            {
                return candidate;
            }
        }

        let schema = state
            .local
            .search_path
            .first()
            .map(|s| s.as_str())
            .unwrap_or("public")
            .to_string();
        ObjectId {
            schema,
            name: resolved_name,
        }
    }

    pub fn resolve(fact: &StatementFact, state: &AnalysisState) -> Vec<Mutation> {
        let mut mutations = Vec::new();
        match fact {
            StatementFact::CreateSchema {
                name,
                if_not_exists,
            } => {
                mutations.push(Mutation::CreateSchema(CreateSchemaMutation {
                    name: name.name.resolve(),
                    if_not_exists: *if_not_exists,
                }));
            }
            StatementFact::AlterSchema { .. } => {
                mutations.push(Mutation::Opaque(OpaqueMutation::DynamicSql));
            }
            StatementFact::DropSchema {
                names,
                if_exists,
                cascade,
            } => {
                mutations.push(Mutation::DropSchema(DropSchemaMutation {
                    names: names.iter().map(|n| n.name.resolve()).collect(),
                    if_exists: *if_exists,
                    cascade: *cascade,
                }));
            }
            StatementFact::CreateTable {
                name,
                if_not_exists,
                as_select,
                persistence,
                columns,
                foreign_keys,
                table_constraints,
                partition_by,
                partition_of,
            } => {
                let id = Self::resolve_creation_name(name, state);

                if !*if_not_exists
                    && (state.relation_is_present(&id)
                        || matches!(
                            state.local.types.get(&id),
                            Some(crate::model::types::TypeOverlay::Present(_))
                        )
                        || matches!(
                            state.local.sequences.get(&id),
                            Some(crate::model::sequence::SequenceOverlay::Present(_))
                        ))
                {
                    return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                }

                let resolved_persistence = match persistence {
                    PersistenceFact::Permanent => PersistenceMutation::Permanent,
                    PersistenceFact::Temporary => PersistenceMutation::Temporary,
                    PersistenceFact::Unlogged => PersistenceMutation::Unlogged,
                };

                let col_mutations: Vec<ColumnMutation> = columns
                    .iter()
                    .map(|c| ColumnMutation {
                        name: c.name.clone(),
                        ty: c.ty.clone(),
                        not_null: c.not_null,
                        is_primary_key: c.is_primary_key,
                        default: c.default.clone(),
                    })
                    .collect();

                let mut fk_mutations = Vec::new();
                for fk in foreign_keys {
                    let to_table = Self::resolve_lookup_name(&fk.references, state);
                    if !state.relation_is_present(&to_table) {
                        return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                    }
                    fk_mutations.push(FkMutation {
                        constraint_name: fk.constraint_name.clone(),
                        to_table,
                        from_columns: fk.from_columns.clone(),
                        to_columns: fk.to_columns.clone(),
                    });
                }

                let partition_of_id = partition_of
                    .as_ref()
                    .map(|n| Self::resolve_lookup_name(n, state));

                if let Some(p_id) = &partition_of_id
                    && !state.relation_is_present(p_id)
                {
                    return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                }

                mutations.push(Mutation::CreateTable(CreateTable {
                    id,
                    if_not_exists: *if_not_exists,
                    as_select: *as_select,
                    persistence: resolved_persistence,
                    columns: col_mutations,
                    foreign_keys: fk_mutations,
                    table_constraints: table_constraints.clone(),
                    partition_by: partition_by.clone(),
                    partition_of: partition_of_id,
                }));
            }
            StatementFact::CreateView {
                name,
                or_replace,
                depends_on,
            } => {
                let id = Self::resolve_creation_name(name, state);

                if !*or_replace && state.relation_is_present(&id) {
                    return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                }

                let resolved_depends = depends_on
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();

                mutations.push(Mutation::CreateView(CreateView {
                    id,
                    or_replace: *or_replace,
                    depends_on: resolved_depends,
                }));
            }
            StatementFact::AlterView { name, new_name } => {
                if let Some(new_name) = new_name {
                    let id = Self::resolve_lookup_name(name, state);
                    let new_id = ObjectId {
                        schema: id.schema.clone(),
                        name: new_name.resolve(),
                    };
                    mutations.push(Mutation::Rename(Rename { old_id: id, new_id }));
                }
            }
            StatementFact::CreateMaterializedView { name, depends_on } => {
                let id = Self::resolve_creation_name(name, state);

                if state.relation_is_present(&id) {
                    return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                }

                let resolved_depends = depends_on
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();

                mutations.push(Mutation::CreateMaterializedView(CreateMaterializedView {
                    id,
                    depends_on: resolved_depends,
                }));
            }
            StatementFact::AlterMaterializedView { name, new_name } => {
                if let Some(new_name) = new_name {
                    let id = Self::resolve_lookup_name(name, state);
                    let new_id = ObjectId {
                        schema: id.schema.clone(),
                        name: new_name.resolve(),
                    };
                    mutations.push(Mutation::Rename(Rename { old_id: id, new_id }));
                }
            }
            StatementFact::RefreshMaterializedView { name, concurrently } => {
                mutations.push(Mutation::RefreshMaterializedView(
                    RefreshMaterializedViewMutation {
                        id: Self::resolve_lookup_name(name, state),
                        concurrently: *concurrently,
                    },
                ));
            }
            StatementFact::CreateIndex {
                name,
                relation,
                if_not_exists,
                concurrently,
                using_method,
                has_predicate,
            } => {
                let id = Self::resolve_creation_name(name, state);

                if !*if_not_exists && state.local.graph.indexes.iter().any(|ix| ix.index_id == id) {
                    return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                }

                mutations.push(Mutation::CreateIndex(CreateIndex {
                    id,
                    table: Self::resolve_lookup_name(relation, state),
                    if_not_exists: *if_not_exists,
                    concurrently: *concurrently,
                    using_method: using_method.clone(),
                    has_predicate: *has_predicate,
                }));
            }
            StatementFact::CreatePolicy { name, table } => {
                mutations.push(Mutation::CreatePolicy(CreatePolicyMutation {
                    name: name.clone(),
                    table: Self::resolve_lookup_name(table, state),
                }));
            }
            StatementFact::DropPolicy {
                name,
                table,
                if_exists,
            } => {
                mutations.push(Mutation::DropPolicy(DropPolicyMutation {
                    name: name.clone(),
                    table: Self::resolve_lookup_name(table, state),
                    if_exists: *if_exists,
                }));
            }
            StatementFact::CreateTrigger { name, table } => {
                mutations.push(Mutation::CreateTrigger(CreateTriggerMutation {
                    name: name.clone(),
                    table: Self::resolve_lookup_name(table, state),
                }));
            }
            StatementFact::DropTrigger {
                name,
                table,
                if_exists,
            } => {
                mutations.push(Mutation::DropTrigger(DropTriggerMutation {
                    name: name.clone(),
                    table: Self::resolve_lookup_name(table, state),
                    if_exists: *if_exists,
                }));
            }
            StatementFact::AlterIndex { name, actions } => {
                let id = Self::resolve_lookup_name(name, state);
                for action in actions {
                    match action {
                        AlterIndexActionFact::RenameTo { new_name } => {
                            let new_id = ObjectId {
                                schema: id.schema.clone(),
                                name: new_name.resolve(),
                            };
                            mutations.push(Mutation::Rename(Rename {
                                old_id: id.clone(),
                                new_id,
                            }));
                        }
                    }
                }
            }
            StatementFact::CreateType(create_type) => {
                let id = Self::resolve_creation_name(&create_type.name, state);

                if matches!(
                    state.local.types.get(&id),
                    Some(crate::model::types::TypeOverlay::Present(_))
                ) || state.relation_is_present(&id)
                {
                    return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                }

                let mapped_kind = match create_type.kind {
                    TypeCreationKind::Enum => TypeKind::Enum { variants: vec![] },
                    TypeCreationKind::Range => TypeKind::Range,
                    TypeCreationKind::Composite => TypeKind::Composite,
                    TypeCreationKind::Base => TypeKind::Base,
                };

                mutations.push(Mutation::CreateType(CreateTypeMutation {
                    id,
                    kind: mapped_kind,
                }));
            }
            StatementFact::AlterType(alter_type) => {
                let id = Self::resolve_lookup_name(&alter_type.name, state);
                for action_fact in &alter_type.actions {
                    match action_fact {
                        crate::analysis::facts::AlterTypeActionFact::AddValue { new_value } => {
                            mutations.push(Mutation::AlterType(AlterTypeMutation {
                                id: id.clone(),
                                action: AlterTypeActionMutation::AddValue {
                                    new_value: new_value.clone(),
                                },
                            }));
                        }
                    }
                }
            }
            StatementFact::CreateDomain { name, base_type } => {
                let id = Self::resolve_creation_name(name, state);

                if matches!(
                    state.local.types.get(&id),
                    Some(crate::model::types::TypeOverlay::Present(_))
                ) || state.relation_is_present(&id)
                {
                    return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                }

                mutations.push(Mutation::CreateDomain(CreateDomainMutation {
                    id,
                    base_type: base_type.clone(),
                }));
            }
            StatementFact::AlterDomain { name } => {
                mutations.push(Mutation::AlterDomain(AlterDomainMutation {
                    id: Self::resolve_lookup_name(name, state),
                }));
            }
            StatementFact::DropDomain { names, if_exists } => {
                let ids = names
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();
                mutations.push(Mutation::DropDomain(DropDomainMutation {
                    ids,
                    if_exists: *if_exists,
                }));
            }
            StatementFact::CreateSequence {
                name,
                if_not_exists,
                owned_by,
            } => {
                let id = Self::resolve_creation_name(name, state);

                if !*if_not_exists
                    && matches!(
                        state.local.sequences.get(&id),
                        Some(crate::model::sequence::SequenceOverlay::Present(_))
                    )
                {
                    return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                }

                let resolved_owned_by = owned_by.as_ref().map(|(table_name, col)| {
                    (Self::resolve_lookup_name(table_name, state), col.clone())
                });
                mutations.push(Mutation::CreateSequence(CreateSequenceMutation {
                    id,
                    if_not_exists: *if_not_exists,
                    owned_by: resolved_owned_by,
                }));
            }
            StatementFact::AlterSequence { name, owned_by } => {
                let resolved_owned_by = owned_by.as_ref().map(|(table_name, col)| {
                    (Self::resolve_lookup_name(table_name, state), col.clone())
                });
                mutations.push(Mutation::AlterSequence(AlterSequenceMutation {
                    id: Self::resolve_lookup_name(name, state),
                    owned_by: resolved_owned_by,
                }));
            }
            StatementFact::DropSequence { names, if_exists } => {
                let ids = names
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();
                mutations.push(Mutation::DropSequence(DropSequenceMutation {
                    ids,
                    if_exists: *if_exists,
                }));
            }
            StatementFact::AlterTable { name, actions } => {
                let id = Self::resolve_lookup_name(name, state);
                for action_fact in actions {
                    let action = match action_fact {
                        AlterTableActionFact::AddColumn {
                            name: col_name,
                            ty,
                            if_not_exists,
                            not_null,
                            default,
                        } => AlterTableActionMutation::AddColumn {
                            name: col_name.clone(),
                            ty: ty.clone(),
                            if_not_exists: *if_not_exists,
                            not_null: *not_null,
                            default: default.clone(),
                        },
                        AlterTableActionFact::DropColumn {
                            name: col_name,
                            if_exists,
                        } => AlterTableActionMutation::DropColumn {
                            name: col_name.clone(),
                            if_exists: *if_exists,
                        },
                        AlterTableActionFact::RenameColumn { from, to } => {
                            AlterTableActionMutation::RenameColumn {
                                from: from.resolve(),
                                to: to.resolve(),
                            }
                        }
                        AlterTableActionFact::RenameTo { new_name } => {
                            let new_id = ObjectId {
                                schema: id.schema.clone(),
                                name: new_name.resolve(),
                            };
                            mutations.push(Mutation::Rename(Rename {
                                old_id: id.clone(),
                                new_id,
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
                            let to_table = Self::resolve_lookup_name(references, state);
                            if !state.relation_is_present(&to_table) {
                                return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                            }
                            AlterTableActionMutation::AddForeignKey {
                                constraint_name: constraint_name.clone(),
                                to_table,
                                from_columns: from_columns.clone(),
                                to_columns: to_columns.clone(),
                                not_valid: *not_valid,
                            }
                        }
                        AlterTableActionFact::AlterConstraint {
                            name: c_name,
                            deferrable,
                        } => AlterTableActionMutation::AlterConstraint {
                            name: c_name.clone(),
                            deferrable: *deferrable,
                        },
                        AlterTableActionFact::RenameConstraint { old_name, new_name } => {
                            AlterTableActionMutation::RenameConstraint {
                                old_name: old_name.clone(),
                                new_name: new_name.clone(),
                            }
                        }
                        AlterTableActionFact::DropConstraint { name: c_name } => {
                            AlterTableActionMutation::DropConstraint {
                                name: c_name.clone(),
                            }
                        }
                        AlterTableActionFact::AddCheckConstraint {
                            constraint_name,
                            not_valid,
                        } => AlterTableActionMutation::AddCheckConstraint {
                            constraint_name: constraint_name.clone(),
                            not_valid: *not_valid,
                        },
                        AlterTableActionFact::AddUniqueConstraint => {
                            AlterTableActionMutation::AddUniqueConstraint
                        }
                        AlterTableActionFact::AddPrimaryKeyConstraint => {
                            AlterTableActionMutation::AddPrimaryKeyConstraint
                        }
                        AlterTableActionFact::AddExcludeConstraint => {
                            AlterTableActionMutation::AddExcludeConstraint
                        }
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
                        AlterTableActionFact::AttachPartition { child } => {
                            let child_id = Self::resolve_lookup_name(child, state);
                            if state.local.graph.check_partition_cycle(&id, &child_id) {
                                return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                            }
                            AlterTableActionMutation::AttachPartition { child: child_id }
                        }
                        AlterTableActionFact::DetachPartition { child } => {
                            AlterTableActionMutation::DetachPartition {
                                child: Self::resolve_lookup_name(child, state),
                            }
                        }
                        AlterTableActionFact::SetStorage { column } => {
                            AlterTableActionMutation::SetStorage {
                                column: column.clone(),
                            }
                        }
                        AlterTableActionFact::SetAccessMethod => {
                            AlterTableActionMutation::SetAccessMethod
                        }
                    };
                    mutations.push(Mutation::AlterTable(AlterTable {
                        id: id.clone(),
                        action,
                    }));
                }
            }
            StatementFact::DropTable {
                name,
                if_exists,
                cascade,
            } => {
                mutations.push(Mutation::DropTable(DropTable {
                    id: Self::resolve_lookup_name(name, state),
                    if_exists: *if_exists,
                    cascade: *cascade,
                }));
            }
            StatementFact::DropView { names, if_exists } => {
                let ids = names
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();
                mutations.push(Mutation::DropView(DropViewMutation {
                    ids,
                    if_exists: *if_exists,
                }));
            }
            StatementFact::DropMaterializedView { names, if_exists } => {
                let ids = names
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();
                mutations.push(Mutation::DropMaterializedView(
                    DropMaterializedViewMutation {
                        ids,
                        if_exists: *if_exists,
                    },
                ));
            }
            StatementFact::DropIndex {
                names,
                if_exists,
                concurrently,
            } => {
                for name in names {
                    mutations.push(Mutation::DropIndex(DropIndex {
                        id: Self::resolve_lookup_name(name, state),
                        if_exists: *if_exists,
                        concurrently: *concurrently,
                    }));
                }
            }
            StatementFact::SetSearchPath { target } => {
                mutations.push(Mutation::SearchPath(SearchPathChange {
                    target: target.clone(),
                }))
            }
            StatementFact::BeginTransaction => mutations.push(Mutation::BeginTransaction),
            StatementFact::CommitTransaction => mutations.push(Mutation::CommitTransaction),
            StatementFact::RollbackTransaction => mutations.push(Mutation::RollbackTransaction),
            StatementFact::RollbackToSavepoint { name } => {
                if !state.local.transactions.iter().any(|t| t.name == *name) {
                    return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                }
                mutations.push(Mutation::RollbackToSavepoint(RollbackToSavepointMutation {
                    name: name.clone(),
                }))
            }
            StatementFact::Savepoint { name } => {
                mutations.push(Mutation::Savepoint(SavepointMutation {
                    name: name.clone(),
                }))
            }
            StatementFact::ReleaseSavepoint { name } => {
                if !state.local.transactions.iter().any(|t| t.name == *name) {
                    return vec![Mutation::Opaque(OpaqueMutation::DynamicSql)];
                }
                mutations.push(Mutation::ReleaseSavepoint(ReleaseSavepointMutation {
                    name: name.clone(),
                }))
            }
            StatementFact::PrepareTransaction { .. } => {
                mutations.push(Mutation::Opaque(OpaqueMutation::PrepareTransaction))
            }
            StatementFact::SetTransaction => {
                mutations.push(Mutation::Opaque(OpaqueMutation::SetTransaction))
            }
            StatementFact::SetConstraints => {
                mutations.push(Mutation::Opaque(OpaqueMutation::SetConstraints))
            }
            StatementFact::OpaqueBlock => mutations.push(Mutation::Opaque(OpaqueMutation::DoBlock)),
            StatementFact::Execute => mutations.push(Mutation::Opaque(OpaqueMutation::Execute)),
            StatementFact::Vacuum { is_full } => {
                mutations.push(Mutation::Vacuum { is_full: *is_full })
            }
        }
        mutations
    }
}
