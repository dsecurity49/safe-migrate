use std::collections::{HashMap, HashSet};

use crate::analysis::facts::TableConstraintFact;
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
// ─────────────────────────────────────────────

pub struct LocalState {
    pub relations: HashMap<ObjectId, RelationOverlay>,
    pub graph: DependencyGraph,
    pub search_path: Vec<String>,
    pub confidence: Confidence,
    pub transactions: Vec<TransactionFrame>,
    pub pending_validation: HashSet<(ObjectId, String)>,
    /// Monotonically increasing counter — incremented each time a new
    /// relation incarnation is created. Used to stamp graph edges so
    /// ABA name-reuse scenarios don't cause phantom dependencies.
    pub generation_counter: u64,
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
        // Bug 2 fix: seed local state from the baseline cache so rules see
        // pre-existing objects without any separate DbCache lookup path.
        //
        // Previously get_relation() read only local.relations — any object
        // present only in DbCache was invisible to all rules and state lookups.
        // Seeding at construction means the first-class read path (local.relations)
        // covers both baseline and migration-created objects.
        //
        // DbCache remains immutable — this is a clone into LocalState.
        let mut relations: HashMap<ObjectId, RelationOverlay> = HashMap::new();
        for (id, rel_state) in cache.baseline_relations() {
            relations.insert(id.clone(), RelationOverlay::Present(rel_state.clone()));
        }

        Self {
            cache,
            local: LocalState {
                relations,
                graph: DependencyGraph::new(),
                search_path: vec!["public".to_string()],
                confidence: Confidence::Exact,
                transactions: Vec::new(),
                pending_validation: HashSet::new(),
                generation_counter: 0,
            },
        }
    }

    /// Read the current overlay for a relation — used by rules (read-only).
    ///
    /// Bug 2 fix: because new() now seeds local.relations from DbCache,
    /// this single lookup covers both baseline and migration-created objects.
    /// No separate cache fallback branch needed.
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
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                // Bug 9 fix: build the set of column names that are part of a
                // table-level PRIMARY KEY constraint. These are implicitly NOT NULL
                // per SQL spec §11.7 even when the column definition omits the keyword.
                let pk_columns: HashSet<&str> = create
                    .table_constraints
                    .iter()
                    .filter_map(|tc| {
                        if let TableConstraintFact::PrimaryKey { columns } = tc {
                            Some(columns.iter().map(|s| s.as_str()))
                        } else {
                            None
                        }
                    })
                    .flatten()
                    .collect();

                let mut rel_state = RelationState::new(create.id.clone(), generation);
                for col in &create.columns {
                    let is_pk = col.is_primary_key || pk_columns.contains(col.name.as_str());
                    rel_state.apply_column_action(&ColumnAction::Add {
                        name: col.name.clone(),
                        data_type: col.ty.clone(),
                        // Bug 9 fix: not_null is true for PK columns even when
                        // the column definition omits the NOT NULL keyword.
                        not_null: col.not_null || is_pk,
                        default: col.default.clone(),
                    });
                }

                self.local.relations.insert(
                    create.id.clone(),
                    RelationOverlay::Present(rel_state),
                );

                if !create.foreign_keys.is_empty() {
                    self.snapshot_fk_graph();
                }
                for fk in &create.foreign_keys {
                    self.local.graph.foreign_keys.push(FkEdge {
                        from_table: create.id.clone(),
                        from_columns: fk.from_columns.clone(),
                        to_table: fk.to_table.clone(),
                        to_columns: fk.to_columns.clone(),
                        from_generation: generation,
                    });
                }
            }

            Mutation::CreateView(create_view) => {
                self.snapshot_relation(&create_view.id);
                self.snapshot_view_graph();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;
                self.local.relations.insert(
                    create_view.id.clone(),
                    RelationOverlay::Present(RelationState::new(create_view.id.clone(), generation)),
                );
                self.local.graph.views.push(ViewEdge {
                    view_id: create_view.id,
                    depends_on: create_view.depends_on,
                    view_generation: generation,
                });
            }

            Mutation::CreateIndex(create_index) => {
                self.snapshot_index_graph();
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

                    // Bug 11 fix: use the extracted not_null instead of hardcoded false.
                    AlterTableActionMutation::AddColumn { name, ty, not_null, default, .. } => {
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            rel.apply_column_action(&ColumnAction::Add {
                                name: name.clone(),
                                data_type: ty.clone(),
                                not_null: *not_null,
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

                    // ── Constraint mutations (graph-only, no RelationState change) ─

                    AlterTableActionMutation::AddCheckConstraint { .. } => {}

                    AlterTableActionMutation::AddUniqueConstraint => {}

                    AlterTableActionMutation::AddPrimaryKeyConstraint => {}

                    // ── FK graph mutations ─────────────────────────────

                    // Bug 10 fix: use the authored constraint_name for the
                    // pending_validation key instead of a synthetic placeholder.
                    // The synthetic placeholder is only used as a fallback for
                    // unnamed FK constraints (which cannot be matched by VALIDATE
                    // CONSTRAINT anyway, so the pending entry survives to finalize).
                    AlterTableActionMutation::AddForeignKey {
                        constraint_name,
                        to_table,
                        from_columns,
                        to_columns,
                        not_valid,
                    } => {
                        self.snapshot_fk_graph();
                        let from_generation = self.local.relations.get(&alter.id)
                            .and_then(|o| {
                                if let RelationOverlay::Present(r) = o { Some(r.generation) }
                                else { None }
                            })
                            .unwrap_or(0);
                        self.local.graph.foreign_keys.push(FkEdge {
                            from_table: alter.id.clone(),
                            from_columns: from_columns.clone(),
                            to_table: to_table.clone(),
                            to_columns: to_columns.clone(),
                            from_generation,
                        });
                        if *not_valid {
                            // Bug 10 fix: use the real constraint name when available.
                            // Fall back to a synthetic key only for unnamed FKs.
                            let key = constraint_name
                                .clone()
                                .unwrap_or_else(|| format!("__fk__{}", to_table));
                            self.local.pending_validation.insert((alter.id.clone(), key));
                        }
                    }

                    // ── Constraint validation ──────────────────────────

                    AlterTableActionMutation::ValidateConstraint { constraint_name } => {
                        self.local.pending_validation
                            .remove(&(alter.id.clone(), constraint_name.clone()));
                    }
                }
            }

            Mutation::Rename(rename) => {
                self.snapshot_relation(&rename.old_id);
                self.snapshot_relation(&rename.new_id);
                // Bug 5 fix: snapshot the rename graph BEFORE pushing the new edge.
                // Previously this was missing — RenameEdge was pushed inside a
                // transaction with no undo entry, so ROLLBACK left phantom edges.
                self.snapshot_rename_graph();

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
                self.snapshot_relation(&drop.id);
                self.local.relations.insert(drop.id, RelationOverlay::Dropped);
            }

            Mutation::DropIndex(drop_index) => {
                // Bug 6 fix: snapshot the full index list BEFORE retain().
                //
                // retain() removes an element from an arbitrary position, breaking
                // the append-only invariant needed by the length-marker pattern.
                // We use IndexGraphSnapshot (full clone) instead of
                // IndexGraphLengthMarker. Cost: O(N) clone, but DROP INDEX is rare
                // and index lists are small.
                //
                // Note: snapshot_index_graph() (length marker) is still used for
                // CreateIndex because that operation only appends.
                self.snapshot_index_graph_full();
                self.local
                    .graph
                    .indexes
                    .retain(|idx| idx.index_id != drop_index.id);
            }

            // ── Session state ─────────────────

            Mutation::SearchPath(change) => {
                self.snapshot_search_path();
                self.local.search_path = change.schemas;
            }

            // ── Transaction control ───────────

            Mutation::BeginTransaction => {
                self.local
                    .transactions
                    .push(TransactionFrame::new("__transaction__"));
            }

            // Bug 4 fix: COMMIT flattens the entire transaction stack.
            // PostgreSQL's nested-BEGIN model means there is exactly one real
            // transaction — the outermost BEGIN. COMMIT commits it and all
            // savepoints inside it. Previously only one frame was popped.
            Mutation::CommitTransaction => {
                self.local.transactions.clear();
            }

            // Bug 4 fix: ROLLBACK must unwind the entire stack, not just the
            // innermost frame. Drain all frames and replay their undo logs in
            // reverse order (most-recently-pushed fires first).
            Mutation::RollbackTransaction => {
                let frames: Vec<_> = self.local.transactions.drain(..).collect();
                for frame in frames.into_iter().rev() {
                    self.replay_undo_log(frame);
                }
            }

            Mutation::Savepoint(sp) => {
                self.local
                    .transactions
                    .push(TransactionFrame::new(sp.name));
            }

            Mutation::ReleaseSavepoint(rsp) => {
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
                if let Some(pos) = self
                    .local
                    .transactions
                    .iter()
                    .rposition(|f| f.name == rsp.name)
                {
                    let frames: Vec<_> = self.local.transactions.drain(pos..).collect();
                    for frame in frames.into_iter().rev() {
                        self.replay_undo_log(frame);
                    }
                    self.local
                        .transactions
                        .push(TransactionFrame::new(rsp.name));
                }
            }

            // ── Opaque / procedural ───────────

            Mutation::Opaque(_) => {
                self.local.confidence = Confidence::Tainted;
            }
        }
    }

    // ─────────────────────────────────────────
    // Undo log helpers
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

    /// O(1) snapshot for the FK edge list.
    /// On rollback we truncate to this length.
    fn snapshot_fk_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::FkGraphLengthMarker {
                len: self.local.graph.foreign_keys.len(),
            });
        }
    }

    /// O(1) snapshot for the view edge list.
    fn snapshot_view_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::ViewGraphLengthMarker {
                len: self.local.graph.views.len(),
            });
        }
    }

    /// O(1) snapshot for the index edge list.
    /// Used for CreateIndex (appends to tail). NOT used for DropIndex.
    fn snapshot_index_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::IndexGraphLengthMarker {
                len: self.local.graph.indexes.len(),
            });
        }
    }

    /// Bug 6 fix: full clone snapshot for DropIndex.
    ///
    /// retain() removes from an arbitrary position, so the length-marker
    /// truncation trick doesn't apply. Full clone is necessary.
    fn snapshot_index_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::IndexGraphSnapshot {
                previous: self.local.graph.indexes.clone(),
            });
        }
    }

    /// Bug 5 fix: O(1) snapshot for the rename edge list.
    /// On rollback we truncate to this length.
    fn snapshot_rename_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::RenameGraphLengthMarker {
                len: self.local.graph.renames.len(),
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
        for change in frame.undo_log.into_iter().rev() {
            match change {
                StateChange::RelationSnapshot { id, previous } => {
                    match previous {
                        Some(overlay) => { self.local.relations.insert(id, overlay); }
                        None => { self.local.relations.remove(&id); }
                    }
                }
                StateChange::SearchPathSnapshot { previous } => {
                    self.local.search_path = previous;
                }
                StateChange::FkGraphLengthMarker { len } => {
                    self.local.graph.foreign_keys.truncate(len);
                }
                StateChange::ViewGraphLengthMarker { len } => {
                    self.local.graph.views.truncate(len);
                }
                // IndexGraphLengthMarker: used for CreateIndex (append-only).
                StateChange::IndexGraphLengthMarker { len } => {
                    self.local.graph.indexes.truncate(len);
                }
                // Bug 5 fix: truncate rename edges appended since snapshot.
                StateChange::RenameGraphLengthMarker { len } => {
                    self.local.graph.renames.truncate(len);
                }
                // Bug 6 fix: restore the full index list from snapshot.
                StateChange::IndexGraphSnapshot { previous } => {
                    self.local.graph.indexes = previous;
                }
            }
        }
    }
}
