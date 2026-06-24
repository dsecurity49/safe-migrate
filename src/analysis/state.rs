// FILE: src/analysis/state.rs
use crate::analysis::facts::{SearchPathTarget, TableConstraintFact};
use crate::analysis::graph::{
    DependencyGraph, FkEdge, IndexEdge, PartitionEdge, RenameEdge, SequenceEdge, ViewEdge,
};
use crate::analysis::mutations::{
    AlterTableActionMutation, AlterTypeActionMutation, Mutation, PersistenceMutation,
};
use crate::analysis::transaction::{StateChange, TransactionFrame};
use crate::ast::identifiers::ObjectId;
use crate::db::cache::DbCache;
use crate::model::relation::{
    ColumnAction, Persistence, RelationKind, RelationOverlay, RelationState,
};
use crate::model::sequence::{SequenceOverlay, SequenceState};
use crate::model::types::{TypeKind, TypeOverlay, TypeState};
use std::collections::{HashMap, HashSet};

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

#[derive(Debug, Default, Clone)]
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

        for (id, rel_state) in cache.baseline_relations() {
            relations.insert(id.clone(), RelationOverlay::Present(rel_state.clone()));
            baseline_relations.insert(id.clone());
        }

        for fk in cache.foreign_keys {
            baseline_foreign_keys.insert((fk.from_table.clone(), fk.constraint_name.clone()));
            graph.foreign_keys.push(FkEdge {
                constraint_name: Some(fk.constraint_name),
                from_table: fk.from_table,
                from_columns: Vec::new(),
                to_table: fk.to_table,
                to_columns: Vec::new(),
                from_generation: 0,
            });
        }

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

    pub fn get_cascade_closure(&self, target_oid: &ObjectId) -> CascadeResult {
        let mut result = CascadeResult::default();
        let mut visited = HashSet::new();
        self.walk_cascade(target_oid, &mut visited, &mut result);
        result
    }

    fn walk_cascade(
        &self,
        current: &ObjectId,
        visited: &mut HashSet<ObjectId>,
        result: &mut CascadeResult,
    ) {
        let resolved_current = self.local.graph.resolve_rename(current).clone();

        if !visited.insert(resolved_current.clone()) {
            return;
        }

        result.dropped_relations.insert(resolved_current.clone());

        for view_edge in &self.local.graph.views {
            if view_edge
                .depends_on
                .iter()
                .any(|dep| self.local.graph.resolve_rename(dep) == &resolved_current)
            {
                let resolved_view_id = self.local.graph.resolve_rename(&view_edge.view_id).clone();
                if !visited.contains(&resolved_view_id) {
                    self.walk_cascade(&resolved_view_id, visited, result);
                }
            }
        }

        for index_edge in &self.local.graph.indexes {
            if self.local.graph.resolve_rename(&index_edge.relation_id) == &resolved_current {
                result.dropped_indexes.insert(
                    self.local
                        .graph
                        .resolve_rename(&index_edge.index_id)
                        .clone(),
                );
            }
        }

        for fk_edge in &self.local.graph.foreign_keys {
            if self.local.graph.resolve_rename(&fk_edge.to_table) == &resolved_current
                && let Some(cname) = &fk_edge.constraint_name
            {
                result.dropped_constraints.insert((
                    self.local.graph.resolve_rename(&fk_edge.from_table).clone(),
                    cname.clone(),
                ));
            }
        }

        for partition_edge in &self.local.graph.partitions {
            if self.local.graph.resolve_rename(&partition_edge.parent) == &resolved_current {
                let resolved_child = self
                    .local
                    .graph
                    .resolve_rename(&partition_edge.child)
                    .clone();
                if !visited.contains(&resolved_child) {
                    self.walk_cascade(&resolved_child, visited, result);
                }
            }
        }
    }

    pub fn apply(
        &mut self,
        mutation: &Mutation,
        precomputed_cascade: Option<&CascadeResult>,
    ) -> MutationResult {
        match mutation {
            Mutation::CreateSchema(_) => MutationResult::Applied,
            Mutation::DropSchema(drop_schema) => {
                if drop_schema.cascade {
                    let renames = self.local.graph.renames.clone();
                    let resolve = |id: &ObjectId| -> ObjectId {
                        let mut current = id;
                        loop {
                            match renames.iter().find(|r| &r.from == current) {
                                Some(edge) => current = &edge.to,
                                None => return current.clone(),
                            }
                        }
                    };

                    let mut relations_to_drop = Vec::new();
                    for id in self.local.relations.keys() {
                        if drop_schema.names.contains(&id.schema) {
                            relations_to_drop.push(id.clone());
                        }
                    }
                    for id in relations_to_drop {
                        self.snapshot_relation(&id);
                        self.local.relations.insert(id, RelationOverlay::Dropped);
                    }

                    let mut types_to_drop = Vec::new();
                    for id in self.local.types.keys() {
                        if drop_schema.names.contains(&id.schema) {
                            types_to_drop.push(id.clone());
                        }
                    }
                    for id in types_to_drop {
                        self.snapshot_type(&id);
                        self.local.types.insert(id, TypeOverlay::Dropped);
                    }

                    let mut seqs_to_drop = Vec::new();
                    for id in self.local.sequences.keys() {
                        if drop_schema.names.contains(&id.schema) {
                            seqs_to_drop.push(id.clone());
                        }
                    }
                    for id in seqs_to_drop {
                        self.snapshot_sequence(&id);
                        self.local.sequences.insert(id, SequenceOverlay::Dropped);
                    }

                    self.snapshot_fk_graph_full();
                    self.snapshot_view_graph_full();
                    self.snapshot_index_graph_full();
                    self.snapshot_partition_graph_full();
                    self.snapshot_sequence_graph_full();
                    self.snapshot_rename_graph_full();

                    let g = &mut self.local.graph;
                    g.foreign_keys.retain(|fk| {
                        !drop_schema.names.contains(&resolve(&fk.from_table).schema)
                            && !drop_schema.names.contains(&resolve(&fk.to_table).schema)
                    });
                    g.views
                        .retain(|v| !drop_schema.names.contains(&resolve(&v.view_id).schema));
                    g.indexes
                        .retain(|idx| !drop_schema.names.contains(&resolve(&idx.index_id).schema));
                    g.partitions.retain(|p| {
                        !drop_schema.names.contains(&resolve(&p.parent).schema)
                            && !drop_schema.names.contains(&resolve(&p.child).schema)
                    });
                    g.sequences
                        .retain(|s| !drop_schema.names.contains(&resolve(&s.sequence_id).schema));
                    g.renames.retain(|r| {
                        !drop_schema.names.contains(&resolve(&r.from).schema)
                            && !drop_schema.names.contains(&resolve(&r.to).schema)
                    });
                }
                MutationResult::Applied
            }
            Mutation::DropTable(drop_table) => {
                if !self.relation_is_present(&drop_table.id) {
                    if drop_table.if_exists {
                        return MutationResult::Skipped;
                    } else {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                }

                let renames = self.local.graph.renames.clone();
                let resolve = |id: &ObjectId| -> ObjectId {
                    let mut current = id;
                    loop {
                        match renames.iter().find(|r| &r.from == current) {
                            Some(edge) => current = &edge.to,
                            None => return current.clone(),
                        }
                    }
                };

                let resolved_drop = resolve(&drop_table.id);

                if drop_table.cascade {
                    let local_closure;
                    let closure = match precomputed_cascade {
                        Some(c) => c,
                        None => {
                            local_closure = self.get_cascade_closure(&drop_table.id);
                            &local_closure
                        }
                    };

                    for dropped_rel_id in &closure.dropped_relations {
                        self.snapshot_relation(dropped_rel_id);
                        self.local
                            .relations
                            .insert(dropped_rel_id.clone(), RelationOverlay::Dropped);
                    }

                    self.snapshot_index_graph_full();
                    self.local
                        .graph
                        .indexes
                        .retain(|idx| !closure.dropped_indexes.contains(&resolve(&idx.index_id)));

                    self.snapshot_fk_graph_full();
                    self.local.graph.foreign_keys.retain(|fk| {
                        let from_dropped =
                            closure.dropped_relations.contains(&resolve(&fk.from_table));
                        let to_dropped = closure.dropped_relations.contains(&resolve(&fk.to_table));
                        let constraint_explicitly_dropped = if let Some(cname) = &fk.constraint_name
                        {
                            closure
                                .dropped_constraints
                                .contains(&(resolve(&fk.from_table), cname.clone()))
                        } else {
                            false
                        };
                        !(from_dropped || to_dropped || constraint_explicitly_dropped)
                    });

                    self.snapshot_view_graph_full();
                    self.local
                        .graph
                        .views
                        .retain(|v| !closure.dropped_relations.contains(&resolve(&v.view_id)));
                } else {
                    let has_view_deps = self
                        .local
                        .graph
                        .views
                        .iter()
                        .any(|v| v.depends_on.iter().any(|dep| resolve(dep) == resolved_drop));
                    let has_fk_deps = self.local.graph.foreign_keys.iter().any(|fk| {
                        resolve(&fk.to_table) == resolved_drop
                            && resolve(&fk.from_table) != resolved_drop
                    });
                    let has_partition_deps = self
                        .local
                        .graph
                        .partitions
                        .iter()
                        .any(|p| resolve(&p.parent) == resolved_drop);

                    if has_view_deps || has_fk_deps || has_partition_deps {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }

                    self.snapshot_relation(&drop_table.id);
                    self.local
                        .relations
                        .insert(drop_table.id.clone(), RelationOverlay::Dropped);
                }

                self.snapshot_partition_graph_full();
                self.local.graph.partitions.retain(|p| {
                    resolve(&p.parent) != resolved_drop && resolve(&p.child) != resolved_drop
                });

                MutationResult::Applied
            }
            Mutation::CreateTable(create) => {
                if create.if_not_exists && self.relation_is_present(&create.id) {
                    return MutationResult::Skipped;
                }

                self.snapshot_relation(&create.id);

                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;
                let tx_depth = self.local.transactions.len();

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

                let mut rel_state = RelationState::new(
                    create.id.clone(),
                    generation,
                    estimated_rows,
                    RelationKind::Table,
                    persistence,
                    tx_depth,
                );

                for col in &create.columns {
                    let is_pk = col.is_primary_key || pk_columns.contains(col.name.as_str());
                    rel_state.apply_column_action(&ColumnAction::Add {
                        name: col.name.clone(),
                        data_type: col.ty.clone(),
                        not_null: col.not_null || is_pk,
                        default: col.default.clone(),
                    });
                }

                self.local
                    .relations
                    .insert(create.id.clone(), RelationOverlay::Present(rel_state));

                if let Some(parent_id) = &create.partition_of {
                    self.snapshot_partition_graph();
                    self.local.graph.partitions.push(PartitionEdge {
                        parent: parent_id.clone(),
                        child: create.id.clone(),
                    });
                }

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
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;
                let tx_depth = self.local.transactions.len();

                self.local.relations.insert(
                    create_view.id.clone(),
                    RelationOverlay::Present(RelationState::new(
                        create_view.id.clone(),
                        generation,
                        Some(0),
                        RelationKind::View,
                        Persistence::Permanent,
                        tx_depth,
                    )),
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
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;
                let tx_depth = self.local.transactions.len();

                self.local.relations.insert(
                    create_mat.id.clone(),
                    RelationOverlay::Present(RelationState::new(
                        create_mat.id.clone(),
                        generation,
                        None,
                        RelationKind::MaterializedView,
                        Persistence::Permanent,
                        tx_depth,
                    )),
                );

                self.local.graph.views.push(ViewEdge {
                    view_id: create_mat.id.clone(),
                    depends_on: create_mat.depends_on.clone(),
                    view_generation: generation,
                });
                MutationResult::Applied
            }
            Mutation::RefreshMaterializedView(refresh) => {
                if !self.relation_is_present(&refresh.id) {
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }

                self.snapshot_relation(&refresh.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let new_gen = self.local.generation_counter;

                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&refresh.id)
                {
                    rel.generation = new_gen;
                }
                MutationResult::Applied
            }
            Mutation::CreateIndex(create_index) => {
                if create_index.if_not_exists
                    && self
                        .local
                        .graph
                        .indexes
                        .iter()
                        .any(|idx| idx.index_id == create_index.id)
                {
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
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let new_gen = self.local.generation_counter;

                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&policy.table)
                {
                    rel.policies.insert(policy.name.clone());
                    rel.generation = new_gen;
                }
                MutationResult::Applied
            }
            Mutation::DropPolicy(policy) => {
                if policy.if_exists {
                    let exists = self
                        .local
                        .relations
                        .get(&policy.table)
                        .map(|o| {
                            if let RelationOverlay::Present(rel) = o {
                                rel.policies.contains(&policy.name)
                            } else {
                                false
                            }
                        })
                        .unwrap_or(false);
                    if !exists {
                        return MutationResult::Skipped;
                    }
                }
                self.snapshot_relation(&policy.table);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let new_gen = self.local.generation_counter;

                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&policy.table)
                {
                    rel.policies.remove(&policy.name);
                    rel.generation = new_gen;
                }
                MutationResult::Applied
            }
            Mutation::CreateTrigger(trigger) => {
                self.snapshot_relation(&trigger.table);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let new_gen = self.local.generation_counter;

                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&trigger.table)
                {
                    rel.triggers.insert(trigger.name.clone());
                    rel.generation = new_gen;
                }
                MutationResult::Applied
            }
            Mutation::DropTrigger(trigger) => {
                if trigger.if_exists {
                    let exists = self
                        .local
                        .relations
                        .get(&trigger.table)
                        .map(|o| {
                            if let RelationOverlay::Present(rel) = o {
                                rel.triggers.contains(&trigger.name)
                            } else {
                                false
                            }
                        })
                        .unwrap_or(false);
                    if !exists {
                        return MutationResult::Skipped;
                    }
                }
                self.snapshot_relation(&trigger.table);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let new_gen = self.local.generation_counter;

                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&trigger.table)
                {
                    rel.triggers.remove(&trigger.name);
                    rel.generation = new_gen;
                }
                MutationResult::Applied
            }
            Mutation::CreateType(create_type) => {
                self.snapshot_type(&create_type.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.types.insert(
                    create_type.id.clone(),
                    TypeOverlay::Present(TypeState {
                        id: create_type.id.clone(),
                        generation,
                        kind: create_type.kind.clone(),
                    }),
                );
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
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.types.insert(
                    create.id.clone(),
                    TypeOverlay::Present(TypeState {
                        id: create.id.clone(),
                        generation,
                        kind: TypeKind::Domain {
                            base_type: create.base_type.clone(),
                        },
                    }),
                );
                MutationResult::Applied
            }
            Mutation::AlterDomain(alter) => {
                self.snapshot_type(&alter.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let new_gen = self.local.generation_counter;

                if let Some(TypeOverlay::Present(t)) = self.local.types.get_mut(&alter.id) {
                    t.generation = new_gen;
                }
                MutationResult::Applied
            }
            Mutation::DropDomain(drop_domain) => {
                for id in &drop_domain.ids {
                    if !self.local.types.contains_key(id) && !drop_domain.if_exists {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                }
                let mut any_applied = false;
                for id in &drop_domain.ids {
                    if !self.local.types.contains_key(id) {
                        continue;
                    }
                    self.snapshot_type(id);
                    self.local.types.insert(id.clone(), TypeOverlay::Dropped);
                    any_applied = true;
                }
                if !any_applied && !drop_domain.ids.is_empty() {
                    return MutationResult::Skipped;
                }
                MutationResult::Applied
            }
            Mutation::CreateSequence(create) => {
                if create.if_not_exists && self.local.sequences.contains_key(&create.id) {
                    return MutationResult::Skipped;
                }
                self.snapshot_sequence(&create.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.sequences.insert(
                    create.id.clone(),
                    SequenceOverlay::Present(SequenceState {
                        id: create.id.clone(),
                        generation,
                    }),
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
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;

                if let Some((table_id, col)) = &alter.owned_by {
                    self.snapshot_sequence_graph_full();
                    self.local
                        .graph
                        .sequences
                        .retain(|s| s.sequence_id != alter.id);
                    self.local.graph.sequences.push(SequenceEdge {
                        sequence_id: alter.id.clone(),
                        table_id: table_id.clone(),
                        column: col.clone(),
                    });
                }
                MutationResult::Applied
            }
            Mutation::DropSequence(drop_seq) => {
                for id in &drop_seq.ids {
                    if !self.local.sequences.contains_key(id) && !drop_seq.if_exists {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                }
                let mut any_applied = false;
                for id in &drop_seq.ids {
                    if !self.local.sequences.contains_key(id) {
                        continue;
                    }
                    self.snapshot_sequence(id);
                    self.local
                        .sequences
                        .insert(id.clone(), SequenceOverlay::Dropped);
                    self.snapshot_sequence_graph_full();
                    self.local.graph.sequences.retain(|s| s.sequence_id != *id);
                    any_applied = true;
                }
                if !any_applied && !drop_seq.ids.is_empty() {
                    return MutationResult::Skipped;
                }
                MutationResult::Applied
            }
            Mutation::AlterTable(alter) => {
                if !self.relation_is_present(&alter.id) {
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }

                match &alter.action {
                    AlterTableActionMutation::AddColumn {
                        name,
                        if_not_exists,
                        ..
                    } if *if_not_exists => {
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get(&alter.id)
                            && rel.has_column(name)
                        {
                            return MutationResult::Skipped;
                        }
                    }
                    AlterTableActionMutation::DropColumn {
                        name, if_exists, ..
                    } if *if_exists => {
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get(&alter.id)
                            && !rel.has_column(name)
                        {
                            return MutationResult::Skipped;
                        }
                    }
                    _ => {}
                }

                self.snapshot_relation(&alter.id);

                match &alter.action {
                    AlterTableActionMutation::AddColumn {
                        name,
                        ty,
                        not_null,
                        default,
                        ..
                    } => {
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
                    AlterTableActionMutation::SetType {
                        column,
                        ty,
                        has_using: _,
                    } => {
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
                    AlterTableActionMutation::AddForeignKey {
                        constraint_name,
                        to_table,
                        from_columns,
                        to_columns,
                        not_valid,
                    } => {
                        self.snapshot_fk_graph();
                        let from_generation = self
                            .local
                            .relations
                            .get(&alter.id)
                            .and_then(|o| {
                                if let RelationOverlay::Present(r) = o {
                                    Some(r.generation)
                                } else {
                                    None
                                }
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
                            self.snapshot_pending_validation();
                            self.local
                                .pending_validation
                                .insert((alter.id.clone(), key));
                        }
                    }
                    AlterTableActionMutation::RenameConstraint { old_name, new_name } => {
                        self.snapshot_fk_graph_full();
                        for fk in &mut self.local.graph.foreign_keys {
                            if fk.from_table == alter.id
                                && fk.constraint_name.as_deref() == Some(old_name.as_str())
                            {
                                fk.constraint_name = Some(new_name.clone());
                            }
                        }
                    }
                    AlterTableActionMutation::DropConstraint { name } => {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .remove(&(alter.id.clone(), name.clone()));
                        self.snapshot_fk_graph_full();
                        self.local
                            .graph
                            .foreign_keys
                            .retain(|fk| fk.constraint_name.as_deref() != Some(name.as_str()));
                    }
                    AlterTableActionMutation::ValidateConstraint { constraint_name } => {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .remove(&(alter.id.clone(), constraint_name.clone()));
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
                        self.local
                            .graph
                            .partitions
                            .retain(|p| !(p.parent == alter.id && p.child == *child));
                    }
                    AlterTableActionMutation::AlterConstraint { .. }
                    | AlterTableActionMutation::AddCheckConstraint { .. }
                    | AlterTableActionMutation::AddUniqueConstraint
                    | AlterTableActionMutation::AddPrimaryKeyConstraint
                    | AlterTableActionMutation::AddExcludeConstraint
                    | AlterTableActionMutation::SetStorage { .. }
                    | AlterTableActionMutation::SetAccessMethod => {
                        // Tracking only
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
            Mutation::DropView(drop_view) => {
                for id in &drop_view.ids {
                    if !self.relation_is_present(id) && !drop_view.if_exists {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                }

                let renames = self.local.graph.renames.clone();
                let resolve = |id: &ObjectId| -> ObjectId {
                    let mut current = id;
                    loop {
                        match renames.iter().find(|r| &r.from == current) {
                            Some(edge) => current = &edge.to,
                            None => return current.clone(),
                        }
                    }
                };

                let mut any_applied = false;
                for id in &drop_view.ids {
                    if !self.relation_is_present(id) {
                        continue;
                    }

                    let resolved_id = resolve(id);
                    let has_dependents = self.local.graph.views.iter().any(|v| {
                        v.depends_on.iter().any(|dep| resolve(dep) == resolved_id)
                            && !drop_view.ids.contains(&resolve(&v.view_id))
                    });
                    if has_dependents {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }

                    self.snapshot_relation(id);
                    self.local
                        .relations
                        .insert(id.clone(), RelationOverlay::Dropped);
                    self.snapshot_view_graph_full();
                    self.local
                        .graph
                        .views
                        .retain(|v| resolve(&v.view_id) != resolved_id);
                    any_applied = true;
                }
                if !any_applied && !drop_view.ids.is_empty() {
                    return MutationResult::Skipped;
                }
                MutationResult::Applied
            }
            Mutation::DropMaterializedView(drop_mat_view) => {
                for id in &drop_mat_view.ids {
                    if !self.relation_is_present(id) && !drop_mat_view.if_exists {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                }

                let renames = self.local.graph.renames.clone();
                let resolve = |id: &ObjectId| -> ObjectId {
                    let mut current = id;
                    loop {
                        match renames.iter().find(|r| &r.from == current) {
                            Some(edge) => current = &edge.to,
                            None => return current.clone(),
                        }
                    }
                };

                let mut any_applied = false;
                for id in &drop_mat_view.ids {
                    if !self.relation_is_present(id) {
                        continue;
                    }

                    let resolved_id = resolve(id);
                    let has_dependents = self.local.graph.views.iter().any(|v| {
                        v.depends_on.iter().any(|dep| resolve(dep) == resolved_id)
                            && !drop_mat_view.ids.contains(&resolve(&v.view_id))
                    });
                    if has_dependents {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }

                    self.snapshot_relation(id);
                    self.local
                        .relations
                        .insert(id.clone(), RelationOverlay::Dropped);
                    self.snapshot_view_graph_full();
                    self.local
                        .graph
                        .views
                        .retain(|v| resolve(&v.view_id) != resolved_id);
                    any_applied = true;
                }
                if !any_applied && !drop_mat_view.ids.is_empty() {
                    return MutationResult::Skipped;
                }
                MutationResult::Applied
            }
            Mutation::DropIndex(drop_index) => {
                let present = self
                    .local
                    .graph
                    .indexes
                    .iter()
                    .any(|idx| idx.index_id == drop_index.id);
                if !present {
                    if drop_index.if_exists {
                        return MutationResult::Skipped;
                    } else {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                }
                self.snapshot_index_graph_full();
                self.local
                    .graph
                    .indexes
                    .retain(|idx| idx.index_id != drop_index.id);
                MutationResult::Applied
            }
            Mutation::SearchPath(change) => {
                self.snapshot_search_path();
                match &change.target {
                    SearchPathTarget::Default => {
                        self.local.search_path = vec!["public".to_string()];
                    }
                    SearchPathTarget::Schemas(schemas) => {
                        self.local.search_path = schemas.clone();
                    }
                }
                MutationResult::Applied
            }
            Mutation::BeginTransaction => {
                self.local
                    .transactions
                    .push(TransactionFrame::new("__transaction__"));
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
                self.local
                    .transactions
                    .push(TransactionFrame::new(sp.name.clone()));
                MutationResult::Applied
            }
            Mutation::ReleaseSavepoint(rsp) => {
                if let Some(pos) = self
                    .local
                    .transactions
                    .iter()
                    .rposition(|f| f.name == rsp.name)
                {
                    let mut released_frame = self.local.transactions.remove(pos);
                    if let Some(parent_frame) = self.local.transactions.last_mut() {
                        parent_frame.undo_log.append(&mut released_frame.undo_log);
                    }
                }
                MutationResult::Applied
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
                        .push(TransactionFrame::new(rsp.name.clone()));
                }
                MutationResult::Applied
            }
            Mutation::Opaque(_) => {
                self.local.confidence = Confidence::Tainted;
                MutationResult::Applied
            }
            Mutation::Vacuum { .. } => MutationResult::Applied,
        }
    }

    fn snapshot_relation(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.relations.get(id).cloned();
            frame.undo_log.push(StateChange::RelationSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    fn snapshot_type(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.types.get(id).cloned();
            frame.undo_log.push(StateChange::TypeSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    fn snapshot_sequence(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.sequences.get(id).cloned();
            frame.undo_log.push(StateChange::SequenceSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    fn snapshot_fk_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::FkGraphLengthMarker {
                len: self.local.graph.foreign_keys.len(),
            });
        }
    }

    fn snapshot_fk_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::FkGraphSnapshot {
                previous: self.local.graph.foreign_keys.clone(),
            });
        }
    }

    fn snapshot_view_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::ViewGraphLengthMarker {
                len: self.local.graph.views.len(),
            });
        }
    }

    fn snapshot_view_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::ViewGraphSnapshot {
                previous: self.local.graph.views.clone(),
            });
        }
    }

    fn snapshot_index_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::IndexGraphLengthMarker {
                len: self.local.graph.indexes.len(),
            });
        }
    }

    fn snapshot_index_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::IndexGraphSnapshot {
                previous: self.local.graph.indexes.clone(),
            });
        }
    }

    fn snapshot_rename_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::RenameGraphLengthMarker {
                len: self.local.graph.renames.len(),
            });
        }
    }

    fn snapshot_rename_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::RenameGraphSnapshot {
                previous: self.local.graph.renames.clone(),
            });
        }
    }

    fn snapshot_sequence_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::SequenceGraphLengthMarker {
                len: self.local.graph.sequences.len(),
            });
        }
    }

    fn snapshot_sequence_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::SequenceGraphSnapshot {
                previous: self.local.graph.sequences.clone(),
            });
        }
    }

    fn snapshot_partition_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame
                .undo_log
                .push(StateChange::PartitionGraphLengthMarker {
                    len: self.local.graph.partitions.len(),
                });
        }
    }

    fn snapshot_partition_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::PartitionGraphSnapshot {
                previous: self.local.graph.partitions.clone(),
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

    fn snapshot_generation_counter(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::GenerationCounterSnapshot {
                previous: self.local.generation_counter,
            });
        }
    }

    fn snapshot_pending_validation(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::PendingValidationSnapshot {
                previous: self.local.pending_validation.clone(),
            });
        }
    }

    fn replay_undo_log(&mut self, frame: TransactionFrame) {
        for change in frame.undo_log.into_iter().rev() {
            match change {
                StateChange::RelationSnapshot { id, previous } => match previous {
                    Some(overlay) => {
                        self.local.relations.insert(id, overlay);
                    }
                    None => {
                        self.local.relations.remove(&id);
                    }
                },
                StateChange::TypeSnapshot { id, previous } => match previous {
                    Some(overlay) => {
                        self.local.types.insert(id, overlay);
                    }
                    None => {
                        self.local.types.remove(&id);
                    }
                },
                StateChange::SequenceSnapshot { id, previous } => match previous {
                    Some(overlay) => {
                        self.local.sequences.insert(id, overlay);
                    }
                    None => {
                        self.local.sequences.remove(&id);
                    }
                },
                StateChange::SearchPathSnapshot { previous } => {
                    self.local.search_path = previous;
                }
                StateChange::GenerationCounterSnapshot { previous } => {
                    self.local.generation_counter = previous;
                }
                StateChange::PendingValidationSnapshot { previous } => {
                    self.local.pending_validation = previous;
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
                StateChange::RenameGraphSnapshot { previous } => {
                    self.local.graph.renames = previous;
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
