// FILE: ./src/analysis/resolver.rs
use crate::analysis::facts::{AlterTableActionFact, AlterIndexActionFact, StatementFact, PersistenceFact}; 
use crate::analysis::mutations::{
    AlterTable, AlterTableActionMutation, ColumnMutation, CreateIndex, CreateTable, CreateView,
    DropIndex, DropTable, FkMutation, Mutation, OpaqueMutation, ReleaseSavepointMutation,
    RollbackToSavepointMutation, SavepointMutation, SearchPathChange, CreateTypeMutation,                     
    AlterTypeMutation, AlterTypeActionMutation, CreateDomainMutation, AlterDomainMutation,                    
    DropDomainMutation, CreateSequenceMutation, AlterSequenceMutation, DropSequenceMutation,
    CreateMaterializedView, RefreshMaterializedViewMutation, DropViewMutation,                                
    DropMaterializedViewMutation, Rename, PersistenceMutation,                                                
    CreatePolicyMutation, DropPolicyMutation, CreateTriggerMutation, DropTriggerMutation                  
};
use crate::analysis::state::AnalysisState;
use crate::ast::identifiers::{ObjectId, QualifiedName};

pub struct Resolver;

impl Resolver {
    fn resolve_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        let schema = name
            .schema
            .as_ref()
            .map(|i| i.resolve())
            .unwrap_or_else(|| {
                state.local.search_path.first().map(|s| s.as_str())
                    .unwrap_or("public").to_string()
            });

        ObjectId {
            schema,
            name: name.name.resolve(),
        }
    }

    pub fn resolve(fact: &StatementFact, state: &AnalysisState) -> Vec<Mutation> {
        let mut mutations = Vec::new();
        match fact {
            StatementFact::CreateTable {
                name,
                if_not_exists,
                as_select,
                persistence,
                columns,
                foreign_keys,
                table_constraints,
            } => {
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
                let fk_mutations: Vec<FkMutation> = foreign_keys
                    .iter()
                    .map(|fk| FkMutation {
                        constraint_name: fk.constraint_name.clone(),
                        to_table: Self::resolve_name(&fk.references, state),
                        from_columns: fk.from_columns.clone(),
                        to_columns: fk.to_columns.clone(),
                    })
                    .collect();
                mutations.push(Mutation::CreateTable(CreateTable {
                    id: Self::resolve_name(name, state),
                    if_not_exists: *if_not_exists,
                    as_select: *as_select,
                    persistence: resolved_persistence,
                    columns: col_mutations,
                    foreign_keys: fk_mutations,
                    table_constraints: table_constraints.clone(),
                }));
            }
            StatementFact::CreateView { name, or_replace, depends_on } => {
                let resolved_depends = depends_on.iter()
                    .map(|n| Self::resolve_name(n, state))
                    .collect();

                mutations.push(Mutation::CreateView(CreateView {
                    id: Self::resolve_name(name, state),
                    or_replace: *or_replace,
                    depends_on: resolved_depends,
                }));
            }
            StatementFact::CreateMaterializedView { name, depends_on } => {
                let resolved_depends = depends_on.iter()
                    .map(|n| Self::resolve_name(n, state))
                    .collect();

                mutations.push(Mutation::CreateMaterializedView(CreateMaterializedView {
                    id: Self::resolve_name(name, state),
                    depends_on: resolved_depends,
                }));
            }
            StatementFact::RefreshMaterializedView { name, concurrently } => {
                mutations.push(Mutation::RefreshMaterializedView(RefreshMaterializedViewMutation {
                    id: Self::resolve_name(name, state),
                    concurrently: *concurrently,
                }));
            }
            StatementFact::CreateIndex { name, relation, if_not_exists, concurrently, using_method, has_predicate } => {
                mutations.push(Mutation::CreateIndex(CreateIndex {
                    id: Self::resolve_name(name, state),
                    table: Self::resolve_name(relation, state),
                    if_not_exists: *if_not_exists,
                    concurrently: *concurrently,
                    using_method: using_method.clone(),
                    has_predicate: *has_predicate,
                }));
            }
            StatementFact::CreatePolicy { name, table } => {
                mutations.push(Mutation::CreatePolicy(CreatePolicyMutation {
                    name: name.clone(),
                    table: Self::resolve_name(table, state),
                }));
            }
            StatementFact::DropPolicy { name, table, if_exists } => {
                mutations.push(Mutation::DropPolicy(DropPolicyMutation {
                    name: name.clone(),
                    table: Self::resolve_name(table, state),
                    if_exists: *if_exists,
                }));
            }
            StatementFact::CreateTrigger { name, table } => {
                mutations.push(Mutation::CreateTrigger(CreateTriggerMutation {
                    name: name.clone(),
                    table: Self::resolve_name(table, state),
                }));
            }
            StatementFact::DropTrigger { name, table, if_exists } => {
                mutations.push(Mutation::DropTrigger(DropTriggerMutation {
                    name: name.clone(),
                    table: Self::resolve_name(table, state),
                    if_exists: *if_exists,
                }));
            }
            StatementFact::AlterIndex { name, actions } => {
                let id = Self::resolve_name(name, state);
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
                mutations.push(Mutation::CreateType(CreateTypeMutation {
                    id: Self::resolve_name(&create_type.name, state),
                    is_enum: create_type.is_enum,
                }));
            }
            StatementFact::AlterType(alter_type) => {
                let id = Self::resolve_name(&alter_type.name, state);
                for action_fact in &alter_type.actions {
                    match action_fact {
                        crate::analysis::facts::AlterTypeActionFact::AddValue { new_value } => {
                            mutations.push(Mutation::AlterType(AlterTypeMutation {
                                id: id.clone(),
                                action: AlterTypeActionMutation::AddValue { new_value: new_value.clone() },
                            }));
                        }
                    }
                }
            }
            StatementFact::CreateDomain { name, base_type } => {
                mutations.push(Mutation::CreateDomain(CreateDomainMutation {
                    id: Self::resolve_name(name, state),
                    base_type: base_type.clone(),
                }));
            }
            StatementFact::AlterDomain { name } => {
                mutations.push(Mutation::AlterDomain(AlterDomainMutation {
                    id: Self::resolve_name(name, state),
                }));
            }
            StatementFact::DropDomain { names, if_exists } => {
                let ids = names.iter().map(|n| Self::resolve_name(n, state)).collect();
                mutations.push(Mutation::DropDomain(DropDomainMutation {
                    ids,
                    if_exists: *if_exists,
                }));
            }
            StatementFact::CreateSequence { name, if_not_exists, owned_by } => {
                let resolved_owned_by = owned_by.as_ref().map(|(table_name, col)| {
                    (Self::resolve_name(table_name, state), col.clone())
                });
                mutations.push(Mutation::CreateSequence(CreateSequenceMutation {
                    id: Self::resolve_name(name, state),
                    if_not_exists: *if_not_exists,
                    owned_by: resolved_owned_by,
                }));
            }
            StatementFact::AlterSequence { name, owned_by } => {
                let resolved_owned_by = owned_by.as_ref().map(|(table_name, col)| {
                    (Self::resolve_name(table_name, state), col.clone())
                });
                mutations.push(Mutation::AlterSequence(AlterSequenceMutation {
                    id: Self::resolve_name(name, state),
                    owned_by: resolved_owned_by,
                }));
            }
            StatementFact::DropSequence { names, if_exists } => {
                let ids = names.iter().map(|n| Self::resolve_name(n, state)).collect();
                mutations.push(Mutation::DropSequence(DropSequenceMutation {
                    ids,
                    if_exists: *if_exists,
                }));
            }
            StatementFact::AlterTable { name, actions } => {
                let id = Self::resolve_name(name, state);
                for action_fact in actions {
                    let action = match action_fact {
                        AlterTableActionFact::AddColumn { name: col_name, ty, if_not_exists, not_null, default } => {
                            AlterTableActionMutation::AddColumn {
                                name: col_name.clone(),
                                ty: ty.clone(),
                                if_not_exists: *if_not_exists,
                                not_null: *not_null,
                                default: default.clone(),
                            }
                        }
                        AlterTableActionFact::DropColumn { name: col_name, if_exists } => {
                            AlterTableActionMutation::DropColumn { name: col_name.clone(), if_exists: *if_exists }
                        }
                        AlterTableActionFact::RenameColumn { from, to } => {
                            AlterTableActionMutation::RenameColumn { from: from.resolve(), to: to.resolve() }
                        }
                        AlterTableActionFact::RenameTo { new_name } => {
                            let new_id = ObjectId { schema: id.schema.clone(), name: new_name.resolve() };
                            mutations.push(Mutation::Rename(Rename { old_id: id.clone(), new_id }));
                            continue;
                        }
                        AlterTableActionFact::AddForeignKey { constraint_name, references, from_columns, to_columns, not_valid } => {
                            AlterTableActionMutation::AddForeignKey {
                                constraint_name: constraint_name.clone(),
                                to_table: Self::resolve_name(references, state),
                                from_columns: from_columns.clone(),
                                to_columns: to_columns.clone(),
                                not_valid: *not_valid,
                            }
                        }
                        AlterTableActionFact::AlterConstraint { name: c_name, deferrable } => AlterTableActionMutation::AlterConstraint { name: c_name.clone(), deferrable: *deferrable },
                        AlterTableActionFact::DropConstraint { name: c_name } => AlterTableActionMutation::DropConstraint { name: c_name.clone() },
                        AlterTableActionFact::AddCheckConstraint { not_valid } => AlterTableActionMutation::AddCheckConstraint { not_valid: *not_valid },
                        AlterTableActionFact::AddUniqueConstraint => AlterTableActionMutation::AddUniqueConstraint,
                        AlterTableActionFact::AddPrimaryKeyConstraint => AlterTableActionMutation::AddPrimaryKeyConstraint,
                        AlterTableActionFact::AddExcludeConstraint => AlterTableActionMutation::AddExcludeConstraint,
                        AlterTableActionFact::SetNotNull { column } => AlterTableActionMutation::SetNotNull { column: column.clone() },
                        AlterTableActionFact::DropNotNull { column } => AlterTableActionMutation::DropNotNull { column: column.clone() },
                        AlterTableActionFact::SetType { column, ty, has_using } => AlterTableActionMutation::SetType { column: column.clone(), ty: ty.clone(), has_using: *has_using },
                        AlterTableActionFact::SetDefault { column, default } => AlterTableActionMutation::SetDefault { column: column.clone(), default: default.clone() },
                        AlterTableActionFact::ValidateConstraint { constraint_name } => AlterTableActionMutation::ValidateConstraint { constraint_name: constraint_name.clone() },
                        AlterTableActionFact::AttachPartition { child } => AlterTableActionMutation::AttachPartition { child: Self::resolve_name(child, state) },
                        AlterTableActionFact::DetachPartition { child } => AlterTableActionMutation::DetachPartition { child: Self::resolve_name(child, state) },
                        AlterTableActionFact::SetStorage { column } => AlterTableActionMutation::SetStorage { column: column.clone() },
                        AlterTableActionFact::SetAccessMethod => AlterTableActionMutation::SetAccessMethod,
                    };
                    mutations.push(Mutation::AlterTable(AlterTable { id: id.clone(), action }));
                }
            }
            StatementFact::DropTable { name, if_exists, cascade } => {
                mutations.push(Mutation::DropTable(DropTable {
                    id: Self::resolve_name(name, state),
                    if_exists: *if_exists,
                    cascade: *cascade,
                }));
            }
            StatementFact::DropView { names, if_exists } => {
                let ids = names.iter().map(|n| Self::resolve_name(n, state)).collect();
                mutations.push(Mutation::DropView(DropViewMutation { ids, if_exists: *if_exists }));
            }
            StatementFact::DropMaterializedView { names, if_exists } => {
                let ids = names.iter().map(|n| Self::resolve_name(n, state)).collect();
                mutations.push(Mutation::DropMaterializedView(DropMaterializedViewMutation { ids, if_exists: *if_exists }));
            }
            StatementFact::DropIndex { names, if_exists, concurrently } => {
                for name in names {
                    mutations.push(Mutation::DropIndex(DropIndex {
                        id: Self::resolve_name(name, state),
                        if_exists: *if_exists,
                        concurrently: *concurrently,
                    }));
                }
            }
            StatementFact::SetSearchPath { schemas } => mutations.push(Mutation::SearchPath(SearchPathChange { schemas: schemas.clone() })),
            StatementFact::BeginTransaction => mutations.push(Mutation::BeginTransaction),
            StatementFact::CommitTransaction => mutations.push(Mutation::CommitTransaction),
            StatementFact::RollbackTransaction => mutations.push(Mutation::RollbackTransaction),
            StatementFact::RollbackToSavepoint { name } => mutations.push(Mutation::RollbackToSavepoint(RollbackToSavepointMutation { name: name.clone() })),
            StatementFact::Savepoint { name } => mutations.push(Mutation::Savepoint(SavepointMutation { name: name.clone() })),
            StatementFact::ReleaseSavepoint { name } => mutations.push(Mutation::ReleaseSavepoint(ReleaseSavepointMutation { name: name.clone() })),
            StatementFact::OpaqueBlock => mutations.push(Mutation::Opaque(OpaqueMutation::DoBlock)),
            StatementFact::Execute => mutations.push(Mutation::Opaque(OpaqueMutation::Execute)),
            StatementFact::Vacuum { is_full } => mutations.push(Mutation::Vacuum { is_full: *is_full }),
        }
        mutations
    }
}
