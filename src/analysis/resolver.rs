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

    /// Resolve a QualifiedName to a canonical ObjectId.
    ///
    /// Bug 3 fix: apply .to_lowercase() to both schema and name components.
    ///
    /// PostgreSQL folds unquoted identifiers to lowercase. QualifiedName
    /// carries raw AST text — which for unquoted identifiers is already
    /// stripped of quotes but preserves the original case as typed. We
    /// normalise at this single resolution boundary rather than at each
    /// extraction site in the visitor.
    ///
    /// Quoted identifiers (e.g. "MyTable") preserve case in PostgreSQL; the
    /// squawk parser already strips the surrounding quotes and preserves the
    /// inner text. Applying .to_lowercase() here would incorrectly fold quoted
    /// identifiers — this is a known limitation. Full correctness requires the
    /// visitor to tag whether each identifier was quoted; that is deferred.
    fn resolve_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        let schema = name
            .schema
            .as_deref()
            .unwrap_or_else(|| {
                state.local.search_path.first().map(|s| s.as_str())
                    .unwrap_or("public")
            })
            .to_lowercase();

        ObjectId {
            schema,
            name: name.name.to_lowercase(),
        }
    }

    pub fn resolve(fact: &StatementFact, state: &AnalysisState) -> Vec<Mutation> {
        let mut mutations = Vec::new();

        match fact {
            // ── Schema definition ─────────────────

            StatementFact::CreateTable {
                name,
                if_not_exists,
                columns,
                foreign_keys,
                table_constraints,      // Bug 9
            } => {
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
                    // Bug 9: forward table constraints so apply() can post-process PK columns.
                    table_constraints: table_constraints.clone(),
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
                        // Bug 11: thread not_null through.
                        AlterTableActionFact::AddColumn {
                            name: col_name,
                            ty,
                            if_not_exists,
                            not_null,
                            default,
                        } => {
                            AlterTableActionMutation::AddColumn {
                                name: col_name.clone(),
                                ty: ty.clone(),
                                if_not_exists: *if_not_exists,
                                not_null: *not_null,
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
                                name: new_name.to_lowercase(),
                            };
                            mutations.push(Mutation::Rename(
                                crate::analysis::mutations::Rename {
                                    old_id: id.clone(),
                                    new_id,
                                }
                            ));
                            continue;
                        }

                        // Bug 10: thread constraint_name through.
                        AlterTableActionFact::AddForeignKey {
                            constraint_name,
                            references,
                            from_columns,
                            to_columns,
                            not_valid,
                        } => {
                            AlterTableActionMutation::AddForeignKey {
                                constraint_name: constraint_name.clone(),
                                to_table: Self::resolve_name(references, state),
                                from_columns: from_columns.clone(),
                                to_columns: to_columns.clone(),
                                not_valid: *not_valid,
                            }
                        }

                        AlterTableActionFact::AddCheckConstraint { not_valid } => {
                            AlterTableActionMutation::AddCheckConstraint {
                                not_valid: *not_valid,
                            }
                        }

                        AlterTableActionFact::AddUniqueConstraint => {
                            AlterTableActionMutation::AddUniqueConstraint
                        }

                        AlterTableActionFact::AddPrimaryKeyConstraint => {
                            AlterTableActionMutation::AddPrimaryKeyConstraint
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

            StatementFact::DropIndex { names, if_exists, concurrently } => {
                for name in names {
                    mutations.push(Mutation::DropIndex(DropIndex {
                        id: Self::resolve_name(name, state),
                        if_exists: *if_exists,
                        concurrently: *concurrently,
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
