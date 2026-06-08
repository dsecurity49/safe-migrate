use crate::analysis::facts::{AlterTableActionFact, StatementFact};
use crate::analysis::mutations::{
    AlterTable, AlterTableActionMutation, ColumnMutation, CreateIndex, CreateTable, CreateView,
    DropIndex, DropTable, FkMutation, Mutation, OpaqueMutation, ReleaseSavepointMutation,
    RollbackToSavepointMutation, SavepointMutation, SearchPathChange,
};
use crate::analysis::state::AnalysisState;
use crate::ast::identifiers::{ObjectId, QualifiedName};

pub struct Resolver;

impl Resolver {
    // ─────────────────────────────────────────────
    // Name resolution — single point where
    // QualifiedName → ObjectId via search_path.
    // ─────────────────────────────────────────────

    fn resolve_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        let schema = name.schema.clone().unwrap_or_else(|| {
            state
                .local
                .search_path
                .first()
                .cloned()
                .unwrap_or_else(|| "public".to_string())
        });
        ObjectId { schema, name: name.name.clone() }
    }

    pub fn resolve(fact: &StatementFact, state: &AnalysisState) -> Vec<Mutation> {
        let mut mutations = Vec::new();

        match fact {
            // ── Schema definition ─────────────────

            StatementFact::CreateTable { name, if_not_exists, columns, foreign_keys } => {
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
                        to_table: Self::resolve_name(&fk.references, state),
                        from_columns: fk.from_columns.clone(),
                        to_columns: fk.to_columns.clone(),
                    })
                    .collect();

                mutations.push(Mutation::CreateTable(CreateTable {
                    id: Self::resolve_name(name, state),
                    if_not_exists: *if_not_exists,
                    columns: col_mutations,
                    foreign_keys: fk_mutations,
                }));
            }

            StatementFact::CreateView { name, or_replace } => {
                mutations.push(Mutation::CreateView(CreateView {
                    id: Self::resolve_name(name, state),
                    or_replace: *or_replace,
                    depends_on: Vec::new(),
                }));
            }

            StatementFact::CreateIndex { name, relation, if_not_exists, concurrently } => {
                mutations.push(Mutation::CreateIndex(CreateIndex {
                    id: Self::resolve_name(name, state),
                    table: Self::resolve_name(relation, state),
                    if_not_exists: *if_not_exists,
                    concurrently: *concurrently,
                }));
            }

            // ── Schema mutation ───────────────────

            StatementFact::AlterTable { name, actions } => {
                let id = Self::resolve_name(name, state);

                for action_fact in actions {
                    let action = match action_fact {
                        AlterTableActionFact::AddColumn { name: col_name, ty, if_not_exists, default } => {
                            AlterTableActionMutation::AddColumn {
                                name: col_name.clone(),
                                ty: ty.clone(),
                                if_not_exists: *if_not_exists,
                                default: default.clone(),
                            }
                        }

                        AlterTableActionFact::DropColumn { name: col_name, if_exists } => {
                            AlterTableActionMutation::DropColumn {
                                name: col_name.clone(),
                                if_exists: *if_exists,
                            }
                        }

                        AlterTableActionFact::RenameColumn { from, to } => {
                            AlterTableActionMutation::RenameColumn {
                                from: from.clone(),
                                to: to.clone(),
                            }
                        }

                        // RenameTo produces a Mutation::Rename, not an AlterTable.
                        AlterTableActionFact::RenameTo { new_name } => {
                            let new_id = ObjectId {
                                schema: id.schema.clone(),
                                name: new_name.clone(),
                            };
                            mutations.push(Mutation::Rename(
                                crate::analysis::mutations::Rename {
                                    old_id: id.clone(),
                                    new_id,
                                }
                            ));
                            continue;
                        }

                        AlterTableActionFact::AddForeignKey {
                            references,
                            from_columns,
                            to_columns,
                            not_valid,
                        } => {
                            AlterTableActionMutation::AddForeignKey {
                                to_table: Self::resolve_name(references, state),
                                from_columns: from_columns.clone(),
                                to_columns: to_columns.clone(),
                                not_valid: *not_valid,
                            }
                        }

                        AlterTableActionFact::SetNotNull { column } => {
                            AlterTableActionMutation::SetNotNull { column: column.clone() }
                        }

                        AlterTableActionFact::DropNotNull { column } => {
                            AlterTableActionMutation::DropNotNull { column: column.clone() }
                        }

                        AlterTableActionFact::SetType { column, ty } => {
                            AlterTableActionMutation::SetType {
                                column: column.clone(),
                                ty: ty.clone(),
                            }
                        }

                        AlterTableActionFact::SetDefault { column, default } => {
                            AlterTableActionMutation::SetDefault {
                                column: column.clone(),
                                default: default.clone(),
                            }
                        }

                        // ValidateConstraint — constraint names are not schema-qualified,
                        // no ObjectId resolution needed.
                        AlterTableActionFact::ValidateConstraint { constraint_name } => {
                            AlterTableActionMutation::ValidateConstraint {
                                constraint_name: constraint_name.clone(),
                            }
                        }
                    };

                    mutations.push(Mutation::AlterTable(AlterTable {
                        id: id.clone(),
                        action,
                    }));
                }
            }

            // ── Schema removal ────────────────────

            StatementFact::DropTable { name, if_exists } => {
                mutations.push(Mutation::DropTable(DropTable {
                    id: Self::resolve_name(name, state),
                    if_exists: *if_exists,
                }));
            }

            StatementFact::DropIndex { names, if_exists } => {
                for name in names {
                    mutations.push(Mutation::DropIndex(DropIndex {
                        id: Self::resolve_name(name, state),
                        if_exists: *if_exists,
                    }));
                }
            }

            // ── Session state ─────────────────────

            StatementFact::SetSearchPath { schemas } => {
                mutations.push(Mutation::SearchPath(SearchPathChange {
                    schemas: schemas.clone(),
                }));
            }

            // ── Transaction control ───────────────

            StatementFact::BeginTransaction => {
                mutations.push(Mutation::BeginTransaction);
            }
            StatementFact::CommitTransaction => {
                mutations.push(Mutation::CommitTransaction);
            }
            StatementFact::RollbackTransaction => {
                mutations.push(Mutation::RollbackTransaction);
            }
            StatementFact::RollbackToSavepoint { name } => {
                mutations.push(Mutation::RollbackToSavepoint(RollbackToSavepointMutation {
                    name: name.clone(),
                }));
            }
            StatementFact::Savepoint { name } => {
                mutations.push(Mutation::Savepoint(SavepointMutation { name: name.clone() }));
            }
            StatementFact::ReleaseSavepoint { name } => {
                mutations.push(Mutation::ReleaseSavepoint(ReleaseSavepointMutation {
                    name: name.clone(),
                }));
            }

            // ── Opaque / procedural ───────────────

            StatementFact::OpaqueBlock => {
                mutations.push(Mutation::Opaque(OpaqueMutation::DoBlock));
            }
            StatementFact::Execute => {
                mutations.push(Mutation::Opaque(OpaqueMutation::Execute));
            }
        }

        mutations
    }
}
