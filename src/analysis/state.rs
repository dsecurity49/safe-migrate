use std::collections::{HashMap, HashSet};

use crate::analysis::graph::{DependencyGraph, FkEdge, IndexEdge, RenameEdge, ViewEdge};
use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::transaction::{StateChange, TransactionFrame};
use crate::db::cache::DbCache;
use crate::model::relation::{ColumnAction, ObjectId, RelationOverlay, RelationState};

// ─────────────────────────────────────────────
// Confidence — tracks whether the simulation
// is still deterministic or has been tainted
// by an opaque execution block (DO $$, EXECUTE).
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    Exact,
    Tainted,
}

// ─────────────────────────────────────────────
// LocalState — the live simulated schema.
//
// This is the single source of truth for what
// the database looks like at the current point
// in the migration file. DbCache is the
// read-only baseline before the migration runs.
// ─────────────────────────────────────────────

pub struct LocalState {
    pub relations: HashMap<ObjectId, RelationOverlay>,
    pub graph: DependencyGraph,
    pub search_path: Vec<String>,
    pub confidence: Confidence,
    pub transactions: Vec<TransactionFrame>,
    /// Tracks (table_id, constraint_name) pairs from ADD CONSTRAINT ... NOT VALID
    /// that have not yet been cleared by a VALIDATE CONSTRAINT statement.
    /// At end-of-migration any remaining entries fire MissingValidateConstraintRule.
    pub pending_validation: HashSet<(ObjectId, String)>,
}

// ─────────────────────────────────────────────
// AnalysisState — the full engine state.
// ─────────────────────────────────────────────

pub struct AnalysisState {
    pub cache: DbCache,
    pub local: LocalState,
}

impl AnalysisState {
    pub fn new(cache: DbCache) -> Self {
        Self {
            cache,
            local: LocalState {
                relations: HashMap::new(),
                graph: DependencyGraph::new(),
                search_path: vec!["public".to_string()],
                confidence: Confidence::Exact,
                transactions: Vec::new(),
                pending_validation: HashSet::new(),
            },
        }
    }

    /// Read the current overlay for a relation — used by rules (read-only).
    pub fn get_relation(&self, id: &ObjectId) -> Option<&RelationOverlay> {
        self.local.relations.get(id)
    }

    /// Returns true if the relation exists and is not tombstoned.
    pub fn relation_is_present(&self, id: &ObjectId) -> bool {
        matches!(
            self.local.relations.get(id),
            Some(RelationOverlay::Present(_))
        )
    }

    // ─────────────────────────────────────────
    // apply()
    //
    // INVARIANT: Rules are evaluated BEFORE this
    // is called. apply() only mutates state — it
    // never emits violations.
    // ─────────────────────────────────────────

    pub fn apply(&mut self, mutation: Mutation) {
        match mutation {
            // ── Schema definition ─────────────

            Mutation::CreateTable(create) => {
                self.snapshot_relation(&create.id);

                // Build the initial RelationState with columns pre-populated
                // from the table body extraction. This means has_column() and
                // column type checks work immediately after CREATE TABLE,
                // not only after subsequent ADD COLUMN statements.
                let mut rel_state = RelationState::new(create.id.clone());
                for col in &create.columns {
                    rel_state.apply_column_action(&ColumnAction::Add {
                        name: col.name.clone(),
                        data_type: col.ty.clone(),
                        not_null: col.not_null,
                        default: col.default.clone(),
                    });
                }

                self.local.relations.insert(
                    create.id.clone(),
                    RelationOverlay::Present(rel_state),
                );

                // Insert an FkEdge for each FK constraint declared in the
                // table body. from_columns is empty — squawk doesn't expose
                // the source column list from FK nodes.
                for fk in &create.foreign_keys {
                    self.local.graph.foreign_keys.push(FkEdge {
                        from_table: create.id.clone(),
                        from_columns: fk.from_columns.clone(),
                        to_table: fk.to_table.clone(),
                        to_columns: fk.to_columns.clone(),
                    });
                }
            }

            Mutation::CreateView(create_view) => {
                self.snapshot_relation(&create_view.id);
                // Insert the relation overlay so the view is visible as a
                // schema object for subsequent DROP / ALTER checks.
                self.local.relations.insert(
                    create_view.id.clone(),
                    RelationOverlay::Present(RelationState::new(create_view.id.clone())),
                );
                // Insert a ViewEdge so dependency rules can detect
                // DROP TABLE on a table this view depends on.
                self.local.graph.views.push(ViewEdge {
                    view_id: create_view.id,
                    depends_on: create_view.depends_on,
                });
            }

            Mutation::CreateIndex(create_index) => {
                // FIX: IndexEdge field is relation_id not table_id.
                self.local.graph.indexes.push(IndexEdge {
                    index_id: create_index.id,
                    relation_id: create_index.table,
                });
            }

            // ── Schema mutation ───────────────

            Mutation::AlterTable(alter) => {
                self.snapshot_relation(&alter.id);

                match &alter.action {
                    // ── Column mutations → RelationState ──────────────

                    AlterTableActionMutation::AddColumn { name, ty, default, .. } => {
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            rel.apply_column_action(&ColumnAction::Add {
                                name: name.clone(),
                                data_type: ty.clone(),
                                not_null: false,
                                default: default.clone(),
                            });
                        }
                    }

                    AlterTableActionMutation::DropColumn { name, .. } => {
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            rel.apply_column_action(&ColumnAction::Drop { name: name.clone() });
                        }
                    }

                    AlterTableActionMutation::RenameColumn { from, to } => {
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            rel.apply_column_action(&ColumnAction::Rename {
                                from: from.clone(),
                                to: to.clone(),
                            });
                        }
                    }

                    AlterTableActionMutation::SetNotNull { column } => {
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            rel.apply_column_action(&ColumnAction::SetNotNull {
                                name: column.clone(),
                            });
                        }
                    }

                    AlterTableActionMutation::DropNotNull { column } => {
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            rel.apply_column_action(&ColumnAction::DropNotNull {
                                name: column.clone(),
                            });
                        }
                    }

                    AlterTableActionMutation::SetType { column, ty } => {
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            rel.apply_column_action(&ColumnAction::SetType {
                                name: column.clone(),
                                data_type: ty.clone(),
                            });
                        }
                    }

                    AlterTableActionMutation::SetDefault { column, default } => {
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            rel.apply_column_action(&ColumnAction::SetDefault {
                                name: column.clone(),
                                default: default.clone(),
                            });
                        }
                    }

                    // ── FK graph mutations ─────────────────────────────

                    AlterTableActionMutation::AddForeignKey {
                        to_table,
                        from_columns,
                        to_columns,
                        not_valid,
                    } => {
                        self.local.graph.foreign_keys.push(FkEdge {
                            from_table: alter.id.clone(),
                            from_columns: from_columns.clone(),
                            to_table: to_table.clone(),
                            to_columns: to_columns.clone(),
                        });
                        // Track NOT VALID constraints for MissingValidateConstraintRule.
                        // We use a synthetic constraint name since ADD CONSTRAINT without
                        // an explicit name uses a PostgreSQL-generated name. For named
                        // constraints the name comes from the SQL; for unnamed ones we
                        // use a placeholder that can't match a VALIDATE CONSTRAINT stmt.
                        if *not_valid {
                            self.local.pending_validation.insert((
                                alter.id.clone(),
                                format!("__fk__{}", to_table),
                            ));
                        }
                    }

                    // ── Constraint validation ──────────────────────────

                    AlterTableActionMutation::ValidateConstraint { constraint_name } => {
                        // Remove from pending_validation — the constraint is now
                        // enforced for all rows. We try both the exact name and
                        // any synthetic FK placeholder for this table.
                        self.local.pending_validation
                            .remove(&(alter.id.clone(), constraint_name.clone()));
                    }
                }
            }

            Mutation::Rename(rename) => {
                // Insert a RenameEdge so the graph can resolve the old name
                // to the new canonical identity in subsequent statements.
                // Also move the RelationOverlay to the new key so lookups
                // by new name work immediately.
                self.snapshot_relation(&rename.old_id);
                self.snapshot_relation(&rename.new_id);

                if let Some(overlay) = self.local.relations.remove(&rename.old_id) {
                    self.local.relations.insert(rename.new_id.clone(), overlay);
                }

                self.local.graph.renames.push(RenameEdge {
                    from: rename.old_id,
                    to: rename.new_id,
                });
            }

            // ── Schema removal ────────────────

            Mutation::DropTable(drop) => {
                // Blueprint §13: Tombstones are mandatory.
                // Never remove — only shadow as Dropped.
                self.snapshot_relation(&drop.id);
                self.local.relations.insert(drop.id, RelationOverlay::Dropped);
            }

            Mutation::DropIndex(drop_index) => {
                self.local
                    .graph
                    .indexes
                    .retain(|idx| idx.index_id != drop_index.id);
            }

            // ── Session state ─────────────────

            Mutation::SearchPath(change) => {
                // Snapshot search path for rollback.
                self.snapshot_search_path();
                self.local.search_path = change.schemas;
            }

            // ── Transaction control ───────────

            Mutation::BeginTransaction => {
                // Push a new anonymous transaction frame.
                self.local
                    .transactions
                    .push(TransactionFrame::new("__transaction__"));
            }

            Mutation::CommitTransaction => {
                // Discard the undo log — changes are permanent.
                self.local.transactions.pop();
            }

            Mutation::RollbackTransaction => {
                // Replay the undo log in reverse to revert state.
                if let Some(frame) = self.local.transactions.pop() {
                    self.replay_undo_log(frame);
                }
            }

            Mutation::Savepoint(sp) => {
                // Push a named savepoint frame on top of the current transaction.
                self.local
                    .transactions
                    .push(TransactionFrame::new(sp.name));
            }

            Mutation::ReleaseSavepoint(rsp) => {
                // Find the named savepoint frame and discard its undo log,
                // merging its changes into the parent frame.
                if let Some(pos) = self
                    .local
                    .transactions
                    .iter()
                    .rposition(|f| f.name == rsp.name)
                {
                    self.local.transactions.remove(pos);
                }
            }

            Mutation::RollbackToSavepoint(rsp) => {
                // Find the named savepoint frame by scanning from the top.
                // Replay its undo log — but leave outer transaction frames intact.
                // PostgreSQL semantics: only changes after the savepoint are undone.
                if let Some(pos) = self
                    .local
                    .transactions
                    .iter()
                    .rposition(|f| f.name == rsp.name)
                {
                    // Remove the savepoint frame and everything above it,
                    // replay their undo logs in reverse order.
                    let frames: Vec<_> = self.local.transactions.drain(pos..).collect();
                    for frame in frames.into_iter().rev() {
                        self.replay_undo_log(frame);
                    }
                    // Re-push an empty frame with the same savepoint name
                    // so the savepoint can still be used again.
                    self.local
                        .transactions
                        .push(TransactionFrame::new(rsp.name));
                }
            }

            // ── Opaque / procedural ───────────

            Mutation::Opaque(_) => {
                // Blueprint §12: Do not simulate execution.
                // Only downgrade confidence.
                self.local.confidence = Confidence::Tainted;
            }
        }
    }

    // ─────────────────────────────────────────
    // Undo log helpers
    //
    // Called by apply() before any mutation that
    // touches a relation or the search path, so
    // RollbackTransaction can restore prior state.
    // Only snapshots when inside a transaction.
    // ─────────────────────────────────────────

    fn snapshot_relation(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.relations.get(id).cloned();
            frame.undo_log.push(StateChange::RelationSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    fn snapshot_search_path(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::SearchPathSnapshot {
                previous: self.local.search_path.clone(),
            });
        }
    }

    fn replay_undo_log(&mut self, frame: TransactionFrame) {
        // Replay in reverse order — last change is undone first.
        for change in frame.undo_log.into_iter().rev() {
            match change {
                StateChange::RelationSnapshot { id, previous } => {
                    match previous {
                        Some(overlay) => {
                            self.local.relations.insert(id, overlay);
                        }
                        None => {
                            self.local.relations.remove(&id);
                        }
                    }
                }
                StateChange::SearchPathSnapshot { previous } => {
                    self.local.search_path = previous;
                }
            }
        }
    }
}
