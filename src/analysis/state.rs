// FILE: src/analysis/state.rs
use std::collections::{HashMap, HashSet};
use crate::analysis::facts::TableConstraintFact;
use crate::analysis::graph::{DependencyGraph, FkEdge, IndexEdge, RenameEdge, ViewEdge, SequenceEdge, PartitionEdge};
use crate::analysis::mutations::{AlterTableActionMutation, Mutation, AlterTypeActionMutation, PersistenceMutation};
use crate::analysis::transaction::{StateChange, TransactionFrame};
use crate::db::cache::DbCache;
use crate::ast::identifiers::ObjectId;
use crate::model::relation::{ColumnAction, RelationOverlay, RelationState, RelationKind, Persistence};
use crate::model::types::{TypeOverlay, TypeState, TypeKind};
use crate::model::sequence::{SequenceOverlay, SequenceState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    Exact,
    Tainted,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MutationResult {
    Applied,
    Skipped,
}

#[derive(Debug, Default)]
pub struct CascadeResult {
    pub dropped_relations: HashSet<ObjectId>,
    pub dropped_indexes: HashSet<ObjectId>,
    pub dropped_constraints: HashSet<(ObjectId, String)>,
}

pub struct LocalState {
    pub relations: HashMap<ObjectId, RelationOverlay>,
    pub types: HashMap<ObjectId, TypeOverlay>,
    pub sequences: HashMap<ObjectId, SequenceOverlay>,
    pub graph: DependencyGraph,
    pub search_path: Vec<String>,
    pub confidence: Confidence,
    pub transactions: Vec<TransactionFrame>,
    pub pending_validation: HashSet<(ObjectId, String)>,
    pub generation_counter: u64,
}

pub struct AnalysisState {
    pub pg_version_num: Option<u32>,
    pub baseline_relations: HashSet<ObjectId>,
    pub baseline_foreign_keys: HashSet<(ObjectId, String)>,
    pub local: LocalState,
}

impl AnalysisState {
    pub fn new(cache: DbCache) -> Self {
        let mut relations: HashMap<ObjectId, RelationOverlay> = HashMap::new();
        let mut baseline_relations = HashSet::new();
        let mut baseline_foreign_keys = HashSet::new();
        let mut graph = DependencyGraph::new();

        // Load relations and populate the baseline snapshot
        for (id, rel_state) in cache.baseline_relations() {
            relations.insert(id.clone(), RelationOverlay::Present(rel_state.clone()));
            baseline_relations.insert(id.clone());
        }

        // Load foreign keys from DB into the graph as native edges
        for fk in cache.foreign_keys {
            baseline_foreign_keys.insert((fk.from_table.clone(), fk.constraint_name.clone()));
            graph.foreign_keys.push(FkEdge {
                constraint_name: Some(fk.constraint_name),
                from_table: fk.from_table,
                from_columns: Vec::new(), // Not needed for cascade dropping
                to_table: fk.to_table,
                to_columns: Vec::new(),   // Not needed for cascade dropping
                from_generation: 0,
            });
        }

        // Load indexes from DB into the graph
        for idx in cache.indexes {
            baseline_relations.insert(idx.index_id.clone());
            graph.indexes.push(IndexEdge {
                index_id: idx.index_id,
                relation_id: idx.table_id,
                using_method: None,
                has_predicate: false,
                is_concurrent: false,
            });
        }

        Self {
            pg_version_num: cache.pg_version_num,
            baseline_relations,
            baseline_foreign_keys,
            local: LocalState {
                relations,
                types: HashMap::new(),
                sequences: HashMap::new(),
                graph,
                search_path: vec!["public".to_string()],
                confidence: Confidence::Exact,
                transactions: Vec::new(),
                pending_validation: HashSet::new(),
                generation_counter: 0,
            },
        }
    }

    pub fn get_relation(&self, id: &ObjectId) -> Option<&RelationOverlay> {
        self.local.relations.get(id)
    }

    pub fn relation_is_present(&self, id: &ObjectId) -> bool {
        matches!(
            self.local.relations.get(id),
            Some(RelationOverlay::Present(_))
        )
    }

    /// Recursively computes the closure of objects destroyed by dropping the target.
    /// Cycle-safe via `visited` HashSet.
    pub fn get_cascade_closure(&self, target_oid: &ObjectId) -> CascadeResult {
        let mut result = CascadeResult::default();
        let mut visited = HashSet::new();
        self.walk_cascade(target_oid, &mut visited, &mut result);
        result
    }

    fn walk_cascade(&self, current: &ObjectId, visited: &mut HashSet<ObjectId>, result: &mut CascadeResult) {
        if !visited.insert(current.clone()) {
            return; // Cycle detected, stop traversal
        }

        result.dropped_relations.insert(current.clone());

        // 1. Traverse Transitive Views (Views depending on `current`)
        for view_edge in &self.local.graph.views {
            if view_edge.depends_on.contains(current) && !visited.contains(&view_edge.view_id) {
                self.walk_cascade(&view_edge.view_id, visited, result);
            }
        }

        // 2. Traverse Indexes attached to `current`
        for index_edge in &self.local.graph.indexes {
            if index_edge.relation_id == *current {
                result.dropped_indexes.insert(index_edge.index_id.clone());
                // Indexes don't cascade further, just mark them dropped
            }
        }

        // 3. Traverse Foreign Keys pointing TO `current`
        // NOTE: Postgres drops the CONSTRAINT on the referencing table, not the referencing table itself.
        for fk_edge in &self.local.graph.foreign_keys {
            if fk_edge.to_table == *current {
                if let Some(cname) = &fk_edge.constraint_name {
                    result.dropped_constraints.insert((fk_edge.from_table.clone(), cname.clone()));
                }
            }
        }
    }

    pub fn apply(&mut self, mutation: &Mutation) -> MutationResult {
        match mutation {
            Mutation::DropTable(drop) => {
                if drop.if_exists && !self.relation_is_present(&drop.id) {
                    return MutationResult::Skipped;
                }

                // If cascade: true, we walk the graph to find all collateral damage
                if drop.cascade {
                    let closure = self.get_cascade_closure(&drop.id);

                    // 1. Tombstone all transitively dropped relations (Views, MatViews, etc)
                    for dropped_rel_id in &closure.dropped_relations {
                        self.snapshot_relation(dropped_rel_id);
                        self.local.relations.insert(dropped_rel_id.clone(), RelationOverlay::Dropped);
                    }

                    // 2. Prune collateral indexes
                    self.snapshot_index_graph_full();
                    self.local.graph.indexes.retain(|idx| !closure.dropped_indexes.contains(&idx.index_id));

                    // 3. Prune collateral foreign key constraints pointing to the dropped relations
                    self.snapshot_fk_graph_full();
                    self.local.graph.foreign_keys.retain(|fk| {
                        if let Some(cname) = &fk.constraint_name {
                            !closure.dropped_constraints.contains(&(fk.from_table.clone(), cname.clone()))
                        } else {
                            true
                        }
                    });

                    // 4. Prune the views that were tombstoned
                    self.snapshot_view_graph_full();
                    self.local.graph.views.retain(|v| !closure.dropped_relations.contains(&v.view_id));
                } else {
                    // Non-cascade just drops the single table
                    self.snapshot_relation(&drop.id);
                    self.local.relations.insert(drop.id.clone(), RelationOverlay::Dropped);
                }

                MutationResult::Applied
            }
            Mutation::CreateTable(create) => {
                if create.if_not_exists && self.relation_is_present(&create.id) {
                    return MutationResult::Skipped;
                }

                self.snapshot_relation(&create.id);
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

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

                let estimated_rows = if create.as_select { None } else { Some(0) };

                let persistence = match &create.persistence {
                    PersistenceMutation::Permanent => Persistence::Permanent,
                    PersistenceMutation::Temporary => Persistence::Temporary,
                    PersistenceMutation::Unlogged => Persistence::Unlogged,
                };

                let mut rel_state = RelationState::new(create.id.clone(), generation, estimated_rows, RelationKind::Table, persistence);

                for col in &create.columns {
                    let is_pk = col.is_primary_key || pk_columns.contains(col.name.as_str());
                    rel_state.apply_column_action(&ColumnAction::Add {
                        name: col.name.clone(),
                        data_type: col.ty.clone(),
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
                        constraint_name: fk.constraint_name.clone(),
                        from_table: create.id.clone(),
                        from_columns: fk.from_columns.clone(),
                        to_table: fk.to_table.clone(),
                        to_columns: fk.to_columns.clone(),
                        from_generation: generation,
                    });
                }
                MutationResult::Applied
            }
            Mutation::CreateView(create_view) => {
                self.snapshot_relation(&create_view.id);
                self.snapshot_view_graph();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.relations.insert(
                    create_view.id.clone(),
                    RelationOverlay::Present(RelationState::new(create_view.id.clone(), generation, Some(0), RelationKind::View, Persistence::Permanent)),
                );

                self.local.graph.views.push(ViewEdge {
                    view_id: create_view.id.clone(),
                    depends_on: create_view.depends_on.clone(),
                    view_generation: generation,
                });
                MutationResult::Applied
            }
            Mutation::CreateMaterializedView(create_mat) => {
                self.snapshot_relation(&create_mat.id);
                self.snapshot_view_graph();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.relations.insert(
                    create_mat.id.clone(),
                    RelationOverlay::Present(RelationState::new(create_mat.id.clone(), generation, None, RelationKind::MaterializedView, Persistence::Permanent)),
                );

                self.local.graph.views.push(ViewEdge {
                    view_id: create_mat.id.clone(),
                    depends_on: create_mat.depends_on.clone(),
                    view_generation: generation,
                });
                MutationResult::Applied
            }
            Mutation::RefreshMaterializedView(refresh) => {
                self.snapshot_relation(&refresh.id);
                if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&refresh.id) {
                    self.local.generation_counter += 1;
                    rel.generation = self.local.generation_counter;
                }
                MutationResult::Applied
            }
            Mutation::CreateIndex(create_index) => {
                if create_index.if_not_exists && self.local.graph.indexes.iter().any(|idx| idx.index_id == create_index.id) {
                    return MutationResult::Skipped;
                }
                self.snapshot_index_graph();
                self.local.graph.indexes.push(IndexEdge {
                    index_id: create_index.id.clone(),
                    relation_id: create_index.table.clone(),
                    using_method: create_index.using_method.clone(),
                    has_predicate: create_index.has_predicate,
                    is_concurrent: create_index.concurrently,
                });
                MutationResult::Applied
            }
            Mutation::CreatePolicy(policy) => {
                self.snapshot_relation(&policy.table);
                if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&policy.table) {
                    rel.policies.insert(policy.name.clone());
                    self.local.generation_counter += 1;
                    rel.generation = self.local.generation_counter;
                }
                MutationResult::Applied
            }
            Mutation::DropPolicy(policy) => {
                if policy.if_exists {
                    let exists = self.local.relations.get(&policy.table)
                        .map(|o| if let RelationOverlay::Present(rel) = o { rel.policies.contains(&policy.name) } else { false })
                        .unwrap_or(false);
                    if !exists { return MutationResult::Skipped; }
                }
                self.snapshot_relation(&policy.table);
                if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&policy.table) {
                    rel.policies.remove(&policy.name);
                    self.local.generation_counter += 1;
                    rel.generation = self.local.generation_counter;
                }
                MutationResult::Applied
            }
            Mutation::CreateTrigger(trigger) => {
                self.snapshot_relation(&trigger.table);
                if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&trigger.table) {
                    rel.triggers.insert(trigger.name.clone());
                    self.local.generation_counter += 1;
                    rel.generation = self.local.generation_counter;
                }
                MutationResult::Applied
            }
            Mutation::DropTrigger(trigger) => {
                if trigger.if_exists {
                    let exists = self.local.relations.get(&trigger.table)
                        .map(|o| if let RelationOverlay::Present(rel) = o { rel.triggers.contains(&trigger.name) } else { false })
                        .unwrap_or(false);
                    if !exists { return MutationResult::Skipped; }
                }
                self.snapshot_relation(&trigger.table);
                if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&trigger.table) {
                    rel.triggers.remove(&trigger.name);
                    self.local.generation_counter += 1;
                    rel.generation = self.local.generation_counter;
                }
                MutationResult::Applied
            }
            Mutation::CreateType(create_type) => {
                self.snapshot_type(&create_type.id);
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                if create_type.is_enum {
                    self.local.types.insert(
                        create_type.id.clone(),
                        TypeOverlay::Present(TypeState {
                            id: create_type.id.clone(),
                            generation,
                            kind: TypeKind::Enum { variants: Vec::new() },
                        })
                    );
                }
                MutationResult::Applied
            }
            Mutation::AlterType(alter) => {
                self.snapshot_type(&alter.id);
                if let Some(TypeOverlay::Present(t)) = self.local.types.get_mut(&alter.id) {
                    match &alter.action {
                        AlterTypeActionMutation::AddValue { new_value } => {
                            if let TypeKind::Enum { variants } = &mut t.kind {
                                variants.push(new_value.clone());
                            }
                        }
                    }
                }
                MutationResult::Applied
            }
            Mutation::CreateDomain(create) => {
                self.snapshot_type(&create.id);
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.types.insert(
                    create.id.clone(),
                    TypeOverlay::Present(TypeState {
                        id: create.id.clone(),
                        generation,
                        kind: TypeKind::Domain { base_type: create.base_type.clone() },
                    })
                );
                MutationResult::Applied
            }
            Mutation::AlterDomain(alter) => {
                self.snapshot_type(&alter.id);
                if let Some(TypeOverlay::Present(t)) = self.local.types.get_mut(&alter.id) {
                    self.local.generation_counter += 1;
                    t.generation = self.local.generation_counter;
                }
                MutationResult::Applied
            }
            Mutation::DropDomain(drop) => {
                let mut any_applied = false;
                for id in &drop.ids {
                    if drop.if_exists && !self.local.types.contains_key(id) {
                        continue;
                    }
                    self.snapshot_type(id);
                    self.local.types.insert(id.clone(), TypeOverlay::Dropped);
                    any_applied = true;
                }
                if !any_applied && !drop.ids.is_empty() { return MutationResult::Skipped; }
                MutationResult::Applied
            }
            Mutation::CreateSequence(create) => {
                if create.if_not_exists && self.local.sequences.contains_key(&create.id) {
                    return MutationResult::Skipped;
                }
                self.snapshot_sequence(&create.id);
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.sequences.insert(
                    create.id.clone(),
                    SequenceOverlay::Present(SequenceState {
                        id: create.id.clone(),
                        generation,
                    })
                );

                if let Some((table_id, col)) = &create.owned_by {
                    self.snapshot_sequence_graph();
                    self.local.graph.sequences.push(SequenceEdge {
                        sequence_id: create.id.clone(),
                        table_id: table_id.clone(),
                        column: col.clone(),
                    });
                }
                MutationResult::Applied
            }
            Mutation::AlterSequence(alter) => {
                self.snapshot_sequence(&alter.id);
                self.local.generation_counter += 1;

                if let Some((table_id, col)) = &alter.owned_by {
                    self.snapshot_sequence_graph_full();
                    self.local.graph.sequences.retain(|s| s.sequence_id != alter.id);
                    self.local.graph.sequences.push(SequenceEdge {
                        sequence_id: alter.id.clone(),
                        table_id: table_id.clone(),
                        column: col.clone(),
                    });
                }
                MutationResult::Applied
            }
            Mutation::DropSequence(drop) => {
                let mut any_applied = false;
                for id in &drop.ids {
                    if drop.if_exists && !self.local.sequences.contains_key(id) {
                        continue;
                    }
                    self.snapshot_sequence(id);
                    self.local.sequences.insert(id.clone(), SequenceOverlay::Dropped);
                    self.snapshot_sequence_graph_full();
                    self.local.graph.sequences.retain(|s| s.sequence_id != *id);
                    any_applied = true;
                }
                if !any_applied && !drop.ids.is_empty() { return MutationResult::Skipped; }
                MutationResult::Applied
            }
            Mutation::AlterTable(alter) => {
                match &alter.action {
                    AlterTableActionMutation::AddColumn { name, if_not_exists, .. } => {
                        if *if_not_exists {
                            if let Some(RelationOverlay::Present(rel)) = self.local.relations.get(&alter.id) {
                                if rel.has_column(name) {
                                    return MutationResult::Skipped;
                                }
                            }
                        }
                    }
                    AlterTableActionMutation::DropColumn { name, if_exists, .. } => {
                        if *if_exists {
                            if let Some(RelationOverlay::Present(rel)) = self.local.relations.get(&alter.id) {
                                if !rel.has_column(name) {
                                    return MutationResult::Skipped;
                                }
                            }
                        }
                    }
                    _ => {}
                }

                self.snapshot_relation(&alter.id);

                match &alter.action {
                    AlterTableActionMutation::AddColumn { name, ty, not_null, default, .. } => {
                        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&alter.id) {
                            rel.apply_column_action(&ColumnAction::Add {
                                name: name.clone(),
                                data_type: ty.clone(),
                                not_null: *not_null,
                                default: default.clone(),
                            });
                        }
                    }
                    AlterTableActionMutation::DropColumn { name, .. } => {
                        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&alter.id) {
                            rel.apply_column_action(&ColumnAction::Drop { name: name.clone() });
                        }
                    }
                    AlterTableActionMutation::RenameColumn { from, to } => {
                        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&alter.id) {
                            rel.apply_column_action(&ColumnAction::Rename {
                                from: from.clone(),
                                to: to.clone(),
                            });
                        }
                    }
                    AlterTableActionMutation::SetNotNull { column } => {
                        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&alter.id) {
                            rel.apply_column_action(&ColumnAction::SetNotNull { name: column.clone() });
                        }
                    }
                    AlterTableActionMutation::DropNotNull { column } => {
                        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&alter.id) {
                            rel.apply_column_action(&ColumnAction::DropNotNull { name: column.clone() });
                        }
                    }
                    // FIX: pattern now binds `has_using` to match AlterTableActionMutation::SetType's
                    // actual field set. Discarded here (`_`) -- ColumnAction::SetType has no use for
                    // it, and TypeChangeRewriteRule (not this state-mutation path) is the consumer
                    // that reads it for the safe/unsafe coercion judgment.
                    AlterTableActionMutation::SetType { column, ty, has_using: _ } => {
                        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&alter.id) {
                            rel.apply_column_action(&ColumnAction::SetType {
                                name: column.clone(),
                                data_type: ty.clone(),
                            });
                        }
                    }
                    AlterTableActionMutation::SetDefault { column, default } => {
                        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(&alter.id) {
                            rel.apply_column_action(&ColumnAction::SetDefault {
                                name: column.clone(),
                                default: default.clone(),
                            });
                        }
                    }
                    AlterTableActionMutation::AddForeignKey { constraint_name, to_table, from_columns, to_columns, not_valid } => {
                        self.snapshot_fk_graph();
                        let from_generation = self.local.relations.get(&alter.id)
                            .and_then(|o| {
                                if let RelationOverlay::Present(r) = o { Some(r.generation) }
                                else { None }
                            })
                            .unwrap_or(0);

                        self.local.graph.foreign_keys.push(FkEdge {
                            constraint_name: constraint_name.clone(),
                            from_table: alter.id.clone(),
                            from_columns: from_columns.clone(),
                            to_table: to_table.clone(),
                            to_columns: to_columns.clone(),
                            from_generation,
                        });

                        if *not_valid {
                            let key = constraint_name
                                .clone()
                                .unwrap_or_else(|| format!("__fk__{}", to_table));
                            self.local.pending_validation.insert((alter.id.clone(), key));
                        }
                    }
                    AlterTableActionMutation::DropConstraint { name } => {
                        self.local.pending_validation.remove(&(alter.id.clone(), name.clone()));
                        self.snapshot_fk_graph_full();
                        self.local.graph.foreign_keys.retain(|fk| fk.constraint_name.as_deref() != Some(name.as_str()));
                    }
                    AlterTableActionMutation::ValidateConstraint { constraint_name } => {
                        self.local.pending_validation.remove(&(alter.id.clone(), constraint_name.clone()));
                    }
                    AlterTableActionMutation::AttachPartition { child } => {
                        self.snapshot_partition_graph();
                        self.local.graph.partitions.push(PartitionEdge {
                            parent: alter.id.clone(),
                            child: child.clone(),
                        });
                    }
                    AlterTableActionMutation::DetachPartition { child } => {
                        self.snapshot_partition_graph_full();
                        self.local.graph.partitions.retain(|p| !(p.parent == alter.id && p.child == *child));
                    }
                    AlterTableActionMutation::AlterConstraint { .. } |
                    AlterTableActionMutation::AddCheckConstraint { .. } |
                    AlterTableActionMutation::AddUniqueConstraint |
                    AlterTableActionMutation::AddPrimaryKeyConstraint |
                    AlterTableActionMutation::AddExcludeConstraint |
                    AlterTableActionMutation::SetStorage { .. } |
                    AlterTableActionMutation::SetAccessMethod => {
                        // Tracking only. Can trigger lock evaluation but does not modify topology natively beyond locks.
                    }
                }
                MutationResult::Applied
            }
            Mutation::Rename(rename) => {
                self.snapshot_relation(&rename.old_id);
                self.snapshot_relation(&rename.new_id);
                self.snapshot_rename_graph();
                if let Some(overlay) = self.local.relations.remove(&rename.old_id) {
                    self.local.relations.insert(rename.new_id.clone(), overlay);
                }

                self.snapshot_index_graph_full();
                for idx in &mut self.local.graph.indexes {
                    if idx.index_id == rename.old_id {
                        idx.index_id = rename.new_id.clone();
                    }
                }

                self.snapshot_sequence(&rename.old_id);
                self.snapshot_sequence(&rename.new_id);
                if let Some(overlay) = self.local.sequences.remove(&rename.old_id) {
                    self.local.sequences.insert(rename.new_id.clone(), overlay);
                }

                self.snapshot_type(&rename.old_id);
                self.snapshot_type(&rename.new_id);
                if let Some(overlay) = self.local.types.remove(&rename.old_id) {
                    self.local.types.insert(rename.new_id.clone(), overlay);
                }

                self.local.graph.renames.push(RenameEdge {
                    from: rename.old_id.clone(),
                    to: rename.new_id.clone(),
                });
                MutationResult::Applied
            }
            Mutation::DropView(drop) => {
                let mut any_applied = false;
                for id in &drop.ids {
                    if drop.if_exists && !self.relation_is_present(id) {
                        continue;
                    }
                    self.snapshot_relation(id);
                    self.local.relations.insert(id.clone(), RelationOverlay::Dropped);
                    self.snapshot_view_graph_full();
                    self.local.graph.views.retain(|v| v.view_id != *id);
                    any_applied = true;
                }
                if !any_applied && !drop.ids.is_empty() { return MutationResult::Skipped; }
                MutationResult::Applied
            }
            Mutation::DropMaterializedView(drop) => {
                let mut any_applied = false;
                for id in &drop.ids {
                    if drop.if_exists && !self.relation_is_present(id) {
                        continue;
                    }
                    self.snapshot_relation(id);
                    self.local.relations.insert(id.clone(), RelationOverlay::Dropped);
                    self.snapshot_view_graph_full();
                    self.local.graph.views.retain(|v| v.view_id != *id);
                    any_applied = true;
                }
                if !any_applied && !drop.ids.is_empty() { return MutationResult::Skipped; }
                MutationResult::Applied
            }
            Mutation::DropIndex(drop_index) => {
                if drop_index.if_exists && !self.local.graph.indexes.iter().any(|idx| idx.index_id == drop_index.id) {
                    return MutationResult::Skipped;
                }
                self.snapshot_index_graph_full();
                self.local.graph.indexes.retain(|idx| idx.index_id != drop_index.id);
                MutationResult::Applied
            }
            Mutation::SearchPath(change) => {
                self.snapshot_search_path();
                self.local.search_path = change.schemas.clone();
                MutationResult::Applied
            }
            Mutation::BeginTransaction => {
                self.local.transactions.push(TransactionFrame::new("__transaction__"));
                MutationResult::Applied
            }
            Mutation::CommitTransaction => {
                self.local.transactions.clear();
                MutationResult::Applied
            }
            Mutation::RollbackTransaction => {
                let frames: Vec<_> = self.local.transactions.drain(..).collect();
                for frame in frames.into_iter().rev() {
                    self.replay_undo_log(frame);
                }
                MutationResult::Applied
            }
            Mutation::Savepoint(sp) => {
                self.local.transactions.push(TransactionFrame::new(sp.name.clone()));
                MutationResult::Applied
            }
            Mutation::ReleaseSavepoint(rsp) => {
                if let Some(pos) = self.local.transactions.iter().rposition(|f| f.name == rsp.name) {
                    self.local.transactions.remove(pos);
                }
                MutationResult::Applied
            }
            Mutation::RollbackToSavepoint(rsp) => {
                if let Some(pos) = self.local.transactions.iter().rposition(|f| f.name == rsp.name) {
                    let frames: Vec<_> = self.local.transactions.drain(pos..).collect();
                    for frame in frames.into_iter().rev() {
                        self.replay_undo_log(frame);
                    }
                    self.local.transactions.push(TransactionFrame::new(rsp.name.clone()));
                }
                MutationResult::Applied
            }
            Mutation::Opaque(_) => {
                self.local.confidence = Confidence::Tainted;
                MutationResult::Applied
            }
            // ADDED: Mutation::Vacuum had no match arm in the version of this file
            // I have on record, which would fail to compile (non-exhaustive match)
            // the moment the resolver started actually emitting this variant.
            // Tracking only -- VacuumFullRule reads `is_full` directly off the
            // Mutation in its own evaluate(), so there's no LocalState to mutate here.
            // VERIFY: if your real, current state.rs already has this arm, diff it
            // against this one rather than pasting over it blindly.
            Mutation::Vacuum { .. } => {
                MutationResult::Applied
            }
        }
    }

    fn snapshot_relation(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.relations.get(id).cloned();
            frame.undo_log.push(StateChange::RelationSnapshot { id: id.clone(), previous });
        }
    }

    fn snapshot_type(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.types.get(id).cloned();
            frame.undo_log.push(StateChange::TypeSnapshot { id: id.clone(), previous });
        }
    }

    fn snapshot_sequence(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.sequences.get(id).cloned();
            frame.undo_log.push(StateChange::SequenceSnapshot { id: id.clone(), previous });
        }
    }

    fn snapshot_fk_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::FkGraphLengthMarker { len: self.local.graph.foreign_keys.len() });
        }
    }

    fn snapshot_fk_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::FkGraphSnapshot { previous: self.local.graph.foreign_keys.clone() });
        }
    }

    fn snapshot_view_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::ViewGraphLengthMarker { len: self.local.graph.views.len() });
        }
    }

    fn snapshot_view_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::ViewGraphSnapshot { previous: self.local.graph.views.clone() });
        }
    }

    fn snapshot_index_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::IndexGraphLengthMarker { len: self.local.graph.indexes.len() });
        }
    }

    fn snapshot_index_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::IndexGraphSnapshot { previous: self.local.graph.indexes.clone() });
        }
    }

    fn snapshot_rename_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::RenameGraphLengthMarker { len: self.local.graph.renames.len() });
        }
    }

    fn snapshot_sequence_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::SequenceGraphLengthMarker { len: self.local.graph.sequences.len() });
        }
    }

    fn snapshot_sequence_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::SequenceGraphSnapshot { previous: self.local.graph.sequences.clone() });
        }
    }

    fn snapshot_partition_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::PartitionGraphLengthMarker { len: self.local.graph.partitions.len() });
        }
    }

    fn snapshot_partition_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::PartitionGraphSnapshot { previous: self.local.graph.partitions.clone() });
        }
    }

    fn snapshot_search_path(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::SearchPathSnapshot { previous: self.local.search_path.clone() });
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
                StateChange::TypeSnapshot { id, previous } => {
                    match previous {
                        Some(overlay) => { self.local.types.insert(id, overlay); }
                        None => { self.local.types.remove(&id); }
                    }
                }
                StateChange::SequenceSnapshot { id, previous } => {
                    match previous {
                        Some(overlay) => { self.local.sequences.insert(id, overlay); }
                        None => { self.local.sequences.remove(&id); }
                    }
                }
                StateChange::SearchPathSnapshot { previous } => {
                    self.local.search_path = previous;
                }
                StateChange::FkGraphLengthMarker { len } => {
                    self.local.graph.foreign_keys.truncate(len);
                }
                StateChange::FkGraphSnapshot { previous } => {
                    self.local.graph.foreign_keys = previous;
                }
                StateChange::ViewGraphLengthMarker { len } => {
                    self.local.graph.views.truncate(len);
                }
                StateChange::ViewGraphSnapshot { previous } => {
                    self.local.graph.views = previous;
                }
                StateChange::IndexGraphLengthMarker { len } => {
                    self.local.graph.indexes.truncate(len);
                }
                StateChange::IndexGraphSnapshot { previous } => {
                    self.local.graph.indexes = previous;
                }
                StateChange::RenameGraphLengthMarker { len } => {
                    self.local.graph.renames.truncate(len);
                }
                StateChange::SequenceGraphLengthMarker { len } => {
                    self.local.graph.sequences.truncate(len);
                }
                StateChange::SequenceGraphSnapshot { previous } => {
                    self.local.graph.sequences = previous;
                }
                StateChange::PartitionGraphLengthMarker { len } => {
                    self.local.graph.partitions.truncate(len);
                }
                StateChange::PartitionGraphSnapshot { previous } => {
                    self.local.graph.partitions = previous;
                }
            }
        }
    }
}
