use crate::analysis::facts::{AlterTableActionFact, StatementFact};
use crate::analysis::mutations::{
    AlterTable, AlterTableActionMutation, CreateIndex, CreateTable, CreateView, DropIndex,
    DropTable, Mutation, OpaqueMutation, ReleaseSavepointMutation, SavepointMutation,
    SearchPathChange,
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
    //
    // NOTE: state is &mut only to allow future
    // within-statement resolution (e.g. resolving
    // a rename mid-statement). Currently read-only.
    // ─────────────────────────────────────────────

    pub fn resolve(fact: &StatementFact, state: &AnalysisState) -> Vec<Mutation> {
        let mut mutations = Vec::new();

        match fact {
            // ── Schema definition ─────────────────

            StatementFact::CreateTable { name, if_not_exists } => {
                mutations.push(Mutation::CreateTable(CreateTable {
                    id: Self::resolve_name(name, state),
                    if_not_exists: *if_not_exists,
                }));
            }

            StatementFact::CreateView { name, or_replace } => {
                mutations.push(Mutation::CreateView(CreateView {
                    id: Self::resolve_name(name, state),
                    or_replace: *or_replace,
                    // Query-level dependency analysis is not yet implemented.
                    // The view edge will have an empty depends_on list until
                    // the expression visitor is wired up.
                    depends_on: Vec::new(),
                }));
            }

            StatementFact::CreateIndex { name, relation, if_not_exists } => {
                mutations.push(Mutation::CreateIndex(CreateIndex {
                    id: Self::resolve_name(name, state),
                    table: Self::resolve_name(relation, state),
                    if_not_exists: *if_not_exists,
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

            // DropIndex fact carries a Vec<QualifiedName> because one
            // DROP INDEX statement can name multiple indexes.
            // Each name becomes its own DropIndex mutation so the rule
            // engine and apply phase handle one index at a time.
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
            // Savepoint and ReleaseSavepoint are NOT opaque — they are
            // well-defined transaction control statements with names.
            // They get their own mutations so state.apply() can correctly
            // manage the TransactionFrame stack.

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
