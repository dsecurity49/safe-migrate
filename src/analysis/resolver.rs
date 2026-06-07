use crate::analysis::facts::{AlterTableActionFact, StatementFact};
use crate::analysis::mutations::{
    AlterTable, AlterTableActionMutation, ColumnMutation, CreateIndex, CreateTable, CreateView,
    DropIndex, DropTable, FkMutation, Mutation, OpaqueMutation, ReleaseSavepointMutation,
    SavepointMutation, SearchPathChange,
};
use crate::analysis::state::AnalysisState;
use crate::ast::identifiers::{ObjectId, QualifiedName};

pub struct Resolver;

impl Resolver {
    // ─────────────────────────────────────────────
    // Name resolution
    //
    // INVARIANT: QualifiedName is NEVER used for
    // state lookups. This function is the single
    // point where AST form → canonical form.
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
        ObjectId {
            schema,
            name: name.name.clone(),
        }
    }

    // ─────────────────────────────────────────────
    // resolve()
    //
    // Converts one StatementFact into zero or more
    // Mutations. Returns a Vec because a single
    // statement can produce multiple mutations
    // (e.g. ALTER TABLE with many actions, or
    // DROP INDEX with many index names).
    // ─────────────────────────────────────────────

    pub fn resolve(fact: &StatementFact, state: &AnalysisState) -> Vec<Mutation> {
        let mut mutations = Vec::new();

        match fact {
            // ── Schema definition ─────────────────

            StatementFact::CreateTable { name, if_not_exists, columns, foreign_keys } => {
                // Thread columns through as-is — names are local, no resolution needed.
                let col_mutations: Vec<ColumnMutation> = columns
                    .iter()
                    .map(|c| ColumnMutation {
                        name: c.name.clone(),
                        ty: c.ty.clone(),
                        not_null: c.not_null,
                        is_primary_key: c.is_primary_key,
                    })
                    .collect();

                // Resolve FK target table names using current search_path.
                let fk_mutations: Vec<FkMutation> = foreign_keys
                    .iter()
                    .map(|fk| FkMutation {
                        to_table: Self::resolve_name(&fk.references, state),
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
                    // Query-level dependency analysis not yet implemented.
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
                        AlterTableActionFact::AddColumn { name: col_name, ty, if_not_exists } => {
                            AlterTableActionMutation::AddColumn {
                                name: col_name.clone(),
                                ty: ty.clone(),
                                if_not_exists: *if_not_exists,
                            }
                        }
                        AlterTableActionFact::DropColumn { name: col_name, if_exists } => {
                            AlterTableActionMutation::DropColumn {
                                name: col_name.clone(),
                                if_exists: *if_exists,
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

            // One DropIndex mutation per named index — squawk's paths() is plural.
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

            StatementFact::Savepoint { name } => {
                mutations.push(Mutation::Savepoint(SavepointMutation {
                    name: name.clone(),
                }));
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
