// FILE: src/analysis/state.rs
use crate::analysis::facts::{SearchPathTarget, TableConstraintFact};
use crate::analysis::graph::{
    DependencyGraph, FkEdge, IndexEdge, PartitionEdge, PublicationEdge, RenameEdge, SequenceEdge,
    ViewEdge,
};
use crate::analysis::mutations::{
    AlterTableActionMutation, AlterTypeActionMutation, Mutation, PersistenceMutation,
};
use crate::analysis::transaction::{StateChange, TransactionFrame};
use crate::ast::identifiers::ObjectId;
use crate::db::cache::DbCache;
pub use crate::model::relation::RelationOverlay;
use crate::model::relation::{ColumnAction, Persistence, Privilege, RelationKind, RelationState};
use crate::model::sequence::{SequenceOverlay, SequenceState};
use crate::model::trigger::TriggerOverlay;
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
    Conflict { reason: String },
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
    pub functions: HashMap<ObjectId, crate::model::function::FunctionOverlay>,
    pub sequences: HashMap<ObjectId, SequenceOverlay>,
    pub publications: HashMap<String, crate::model::replication::PublicationOverlay>,
    pub subscriptions: HashMap<String, crate::model::replication::SubscriptionOverlay>,
    pub roles: HashMap<ObjectId, crate::model::role::RoleOverlay>,
    pub triggers: HashMap<ObjectId, TriggerOverlay>,
    pub graph: DependencyGraph,
    pub search_path: Vec<String>,
    pub current_role: String,
    pub confidence: Confidence,
    pub transactions: Vec<TransactionFrame>,
    pub pending_validation: HashSet<(ObjectId, String)>,
    pub generation_counter: u64,
}

#[derive(Clone, Debug)]
pub struct PreState {
    pub relations: HashMap<ObjectId, crate::model::relation::RelationState>,
    pub functions: HashMap<ObjectId, crate::model::function::FunctionState>,
    pub roles: HashMap<ObjectId, crate::model::role::RoleState>,
    pub publications: HashMap<String, crate::model::replication::PublicationState>,
    pub subscriptions: HashMap<String, crate::model::replication::SubscriptionState>,
    pub sequences: HashMap<ObjectId, crate::model::sequence::SequenceState>,
    pub types: HashMap<ObjectId, crate::model::types::TypeState>,
    pub indexes: Vec<crate::analysis::graph::IndexEdge>,
}

pub struct AnalysisState {
    pub pg_version_num: Option<u32>,
    pub baseline_relations: HashSet<ObjectId>,
    pub baseline_indexes: HashSet<ObjectId>,
    pub baseline_foreign_keys: HashSet<(ObjectId, String)>,
    pub baseline_fk_dependencies: HashSet<ObjectId>,
    pub local: LocalState,
}

impl AnalysisState {
    pub fn new(cache: DbCache) -> Self {
        let mut relations: HashMap<ObjectId, RelationOverlay> = HashMap::new();
        let mut baseline_relations = HashSet::new();
        let mut baseline_indexes = HashSet::new();
        let mut baseline_foreign_keys = HashSet::new();
        let mut baseline_fk_dependencies = HashSet::new();
        let mut graph = DependencyGraph::new();

        for (id, rel_state) in cache.baseline_relations() {
            if rel_state.is_fk_dependency {
                baseline_fk_dependencies.insert(id.clone());
            }
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
            // BUG-008: index ObjectIds go into baseline_indexes, not baseline_relations
            baseline_indexes.insert(idx.index_id.clone());
            graph.indexes.push(IndexEdge {
                index_id: idx.index_id,
                relation_id: idx.table_id,
                using_method: None,
                has_predicate: false,
                is_concurrent: false,
                is_unique: false,
            });
        }

        for t in cache.triggers {
            graph
                .trigger_dependencies
                .push(crate::analysis::graph::TriggerEdge {
                    trigger_id: t.trigger_id,
                    table_id: t.table_id,
                    function_id: t.function_id,
                });
        }

        let mut functions: HashMap<ObjectId, crate::model::function::FunctionOverlay> =
            HashMap::new();
        for (id, func_state) in &cache.functions {
            functions.insert(
                id.clone(),
                crate::model::function::FunctionOverlay::Present(func_state.clone()),
            );
        }

        Self {
            pg_version_num: cache.pg_version_num,
            baseline_relations,
            baseline_indexes,
            baseline_foreign_keys,
            baseline_fk_dependencies,
            local: LocalState {
                relations,
                types: HashMap::new(),
                functions,
                sequences: HashMap::new(),
                publications: HashMap::new(),
                subscriptions: HashMap::new(),
                roles: HashMap::new(),
                triggers: HashMap::new(),
                graph,
                search_path: vec!["public".to_string()],
                current_role: "postgres".to_string(),
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

    pub fn resolve_function_schema(
        &self,
        name: &crate::ast::identifiers::QualifiedName,
        sig_str: &str,
    ) -> String {
        if let Some(schema) = &name.schema {
            return schema.resolve();
        }
        for schema in &self.local.search_path {
            let candidate = ObjectId::new(schema.clone(), sig_str.to_string());
            if self.local.functions.contains_key(&candidate) {
                return schema.clone();
            }
        }
        self.local
            .search_path
            .first()
            .cloned()
            .unwrap_or_else(|| "public".to_string())
    }

    pub fn resolve_relation_id(&self, name: &crate::ast::identifiers::QualifiedName) -> ObjectId {
        if let Some(schema) = &name.schema {
            return ObjectId::new(schema.resolve(), name.name.resolve());
        }
        let resolved_name = name.name.resolve();
        for schema in &self.local.search_path {
            let mut candidate = ObjectId::new(schema.clone(), resolved_name.clone());
            if self.local.relations.contains_key(&candidate) {
                candidate.inferred_schema = true;
                return candidate;
            }
        }
        let schema = self
            .local
            .search_path
            .first()
            .cloned()
            .unwrap_or_else(|| "public".to_string());
        let mut id = ObjectId::new(schema, resolved_name);
        id.inferred_schema = true;
        id
    }

    pub fn relation_is_present(&self, id: &ObjectId) -> bool {
        matches!(
            self.local.relations.get(id),
            Some(RelationOverlay::Present(_))
        )
    }

    pub fn column_was_added_in_transaction(&self, table_id: &ObjectId, column: &str) -> bool {
        if self.local.transactions.is_empty() {
            return false;
        }

        // Search from the oldest transaction frame to the newest
        for frame in &self.local.transactions {
            for change in &frame.undo_log {
                if let StateChange::RelationSnapshot { id, previous } = change
                    && id == table_id
                {
                    match previous.as_ref() {
                        None | Some(RelationOverlay::Dropped) => {
                            return true;
                        }
                        Some(RelationOverlay::Present(r)) => {
                            let col_existed = r.columns.iter().any(|c| c.name == column);
                            return !col_existed;
                        }
                    }
                }
            }
        }
        false
    }

    pub fn capture_pre_state(&self) -> PreState {
        let mut relations = HashMap::new();
        for (id, overlay) in &self.local.relations {
            if let RelationOverlay::Present(s) = overlay {
                relations.insert(id.clone(), s.clone());
            }
        }

        let mut functions = HashMap::new();
        for (id, overlay) in &self.local.functions {
            if let crate::model::function::FunctionOverlay::Present(s) = overlay {
                functions.insert(id.clone(), s.clone());
            }
        }

        let mut roles = HashMap::new();
        for (name, overlay) in &self.local.roles {
            if let crate::model::role::RoleOverlay::Present(s) = overlay {
                roles.insert(name.clone(), s.clone());
            }
        }

        let mut publications = HashMap::new();
        for (name, overlay) in &self.local.publications {
            if let crate::model::replication::PublicationOverlay::Present(s) = overlay {
                publications.insert(name.clone(), s.clone());
            }
        }

        let mut subscriptions = HashMap::new();
        for (name, overlay) in &self.local.subscriptions {
            if let crate::model::replication::SubscriptionOverlay::Present(s) = overlay {
                subscriptions.insert(name.clone(), s.clone());
            }
        }

        let mut sequences = HashMap::new();
        for (id, overlay) in &self.local.sequences {
            if let SequenceOverlay::Present(s) = overlay {
                sequences.insert(id.clone(), s.clone());
            }
        }

        let mut types = HashMap::new();
        for (id, overlay) in &self.local.types {
            if let TypeOverlay::Present(s) = overlay {
                types.insert(id.clone(), s.clone());
            }
        }

        let indexes = self.local.graph.indexes.clone();

        PreState {
            relations,
            functions,
            roles,
            publications,
            subscriptions,
            sequences,
            types,
            indexes,
        }
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

    fn resolve_grant_privileges(
        spec: &crate::analysis::facts::PrivilegeSpec,
    ) -> HashSet<Privilege> {
        match spec {
            crate::analysis::facts::PrivilegeSpec::All => vec![
                Privilege::Select,
                Privilege::Insert,
                Privilege::Update,
                Privilege::Delete,
                Privilege::Truncate,
                Privilege::References,
                Privilege::Trigger,
            ]
            .into_iter()
            .collect(),
            crate::analysis::facts::PrivilegeSpec::List(list) => list
                .iter()
                .filter_map(|p| match p {
                    crate::analysis::facts::PrivilegeFact::Select => Some(Privilege::Select),
                    crate::analysis::facts::PrivilegeFact::Insert => Some(Privilege::Insert),
                    crate::analysis::facts::PrivilegeFact::Update => Some(Privilege::Update),
                    crate::analysis::facts::PrivilegeFact::Delete => Some(Privilege::Delete),
                    crate::analysis::facts::PrivilegeFact::Truncate => Some(Privilege::Truncate),
                    crate::analysis::facts::PrivilegeFact::References => {
                        Some(Privilege::References)
                    }
                    crate::analysis::facts::PrivilegeFact::Trigger => Some(Privilege::Trigger),
                    _ => None,
                })
                .collect(),
        }
    }

    fn resolve_role_name(
        role: &crate::analysis::facts::RoleFact,
        current_role: &str,
    ) -> Option<ObjectId> {
        let name = match role {
            crate::analysis::facts::RoleFact::Named { name, .. } => Some(name.clone()),
            crate::analysis::facts::RoleFact::CurrentUser
            | crate::analysis::facts::RoleFact::CurrentRole => Some(current_role.to_string()),
            crate::analysis::facts::RoleFact::SessionUser => Some("postgres".to_string()),
            crate::analysis::facts::RoleFact::Unknown => None,
        }?;
        Some(ObjectId::new("", name))
    }

    fn apply_grant_to_relation(
        &mut self,
        id: &ObjectId,
        privileges: &HashSet<Privilege>,
        grantees: &[crate::analysis::facts::RoleFact],
    ) {
        self.snapshot_relation(id);
        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(id) {
            for grantee in grantees {
                if let Some(role_id) = Self::resolve_role_name(grantee, &self.local.current_role) {
                    rel.privileges.grant(role_id, privileges.clone());
                }
            }
        }
    }

    fn apply_revoke_to_relation(
        &mut self,
        id: &ObjectId,
        privileges: &HashSet<Privilege>,
        revokees: &[crate::analysis::facts::RoleFact],
    ) {
        self.snapshot_relation(id);
        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(id) {
            for revokee in revokees {
                if let Some(role_id) = Self::resolve_role_name(revokee, &self.local.current_role) {
                    rel.privileges.revoke(&role_id, privileges);
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
                    self.snapshot_trigger_graph_full();
                    self.snapshot_publication_graph_full();

                    let g = &mut self.local.graph;
                    g.foreign_keys.retain(|fk| {
                        !drop_schema.names.contains(&fk.from_table.schema)
                            && !drop_schema.names.contains(&fk.to_table.schema)
                    });
                    g.views
                        .retain(|v| !drop_schema.names.contains(&v.view_id.schema));
                    g.indexes
                        .retain(|idx| !drop_schema.names.contains(&idx.index_id.schema));
                    g.partitions.retain(|p| {
                        !drop_schema.names.contains(&p.parent.schema)
                            && !drop_schema.names.contains(&p.child.schema)
                    });
                    g.sequences
                        .retain(|s| !drop_schema.names.contains(&s.sequence_id.schema));
                    g.renames.retain(|r| {
                        !drop_schema.names.contains(&r.from.schema)
                            && !drop_schema.names.contains(&r.to.schema)
                    });
                    g.trigger_dependencies.retain(|t| {
                        !drop_schema.names.contains(&t.trigger_id.schema)
                            && !drop_schema.names.contains(&t.table_id.schema)
                            && !drop_schema.names.contains(&t.function_id.schema)
                    });
                    g.publication_dependencies
                        .retain(|p| !drop_schema.names.contains(&p.table_id.schema));
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

                // Cleanup trigger dependencies
                self.snapshot_trigger_graph_full();
                self.local
                    .graph
                    .trigger_dependencies
                    .retain(|t| t.table_id != drop_table.id);
                // Also remove the trigger states themselves if cascading (or simply leave them orphaned)
                // For now, assume trigger state drops with the table in a cascade
                if drop_table.cascade {
                    let triggers_to_drop: Vec<ObjectId> = self
                        .local
                        .triggers
                        .iter()
                        .filter_map(|(id, overlay)| {
                            if let TriggerOverlay::Present(t) = overlay {
                                if t.table_id == drop_table.id {
                                    Some(id.clone())
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .collect();
                    for tid in triggers_to_drop {
                        self.snapshot_trigger(&tid);
                        self.local.triggers.insert(tid, TriggerOverlay::Dropped);
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

                    self.snapshot_sequence_graph_full();
                    self.local.graph.sequences.retain(|s| {
                        let resolved_table = resolve(&s.table_id);
                        !closure.dropped_relations.contains(&resolved_table)
                    });
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

                    self.snapshot_sequence_graph_full();
                    self.local
                        .graph
                        .sequences
                        .retain(|s| resolve(&s.table_id) != resolved_drop);
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

                let resolved_persistence = match create.persistence {
                    PersistenceMutation::Permanent => {
                        crate::model::relation::Persistence::Permanent
                    }
                    PersistenceMutation::Temporary => {
                        crate::model::relation::Persistence::Temporary
                    }
                    PersistenceMutation::Unlogged => crate::model::relation::Persistence::Unlogged,
                };

                let mut rel_state = RelationState::new(
                    create.id.clone(),
                    ObjectId::new("public", &self.local.current_role),
                    generation,
                    if create.as_select { None } else { Some(0) },
                    RelationKind::Table,
                    resolved_persistence,
                    self.local.transactions.len(),
                );

                // Store partition strategy information
                rel_state.partition_type = create
                    .partition_by
                    .as_ref()
                    .and_then(|pb| pb.split_whitespace().nth(2).map(|s| s.to_uppercase()))
                    .or_else(|| {
                        create.partition_of.as_ref().and_then(|parent_id| {
                            self.local.relations.get(parent_id).and_then(|r| {
                                if let RelationOverlay::Present(rel) = r {
                                    rel.partition_type.clone()
                                } else {
                                    None
                                }
                            })
                        })
                    });
                rel_state.partition_by = create.partition_by.clone();

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
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.relations.insert(
                    create_view.id.clone(),
                    RelationOverlay::Present(RelationState::new(
                        create_view.id.clone(),
                        ObjectId::new("public", &self.local.current_role),
                        generation,
                        None,
                        RelationKind::View,
                        Persistence::Permanent,
                        self.local.transactions.len(),
                    )),
                );

                self.snapshot_view_graph();
                self.local.graph.views.push(ViewEdge {
                    view_id: create_view.id.clone(),
                    depends_on: create_view.depends_on.clone(),
                    view_generation: generation,
                });
                MutationResult::Applied
            }
            Mutation::CreateMaterializedView(create_mv) => {
                self.snapshot_relation(&create_mv.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.relations.insert(
                    create_mv.id.clone(),
                    RelationOverlay::Present(RelationState::new(
                        create_mv.id.clone(),
                        ObjectId::new("public", &self.local.current_role),
                        generation,
                        None,
                        RelationKind::MaterializedView,
                        Persistence::Permanent,
                        self.local.transactions.len(),
                    )),
                );

                self.snapshot_view_graph();
                self.local.graph.views.push(ViewEdge {
                    view_id: create_mv.id.clone(),
                    depends_on: create_mv.depends_on.clone(),
                    view_generation: generation,
                });
                MutationResult::Applied
            }
            Mutation::RefreshMaterializedView(_) => MutationResult::Applied,
            Mutation::CreateIndex(create_idx) => {
                if create_idx.if_not_exists
                    && self
                        .local
                        .graph
                        .indexes
                        .iter()
                        .any(|ix| ix.index_id == create_idx.id)
                {
                    return MutationResult::Skipped;
                }
                self.snapshot_index_graph();
                self.local.graph.indexes.push(IndexEdge {
                    index_id: create_idx.id.clone(),
                    relation_id: create_idx.table.clone(),
                    using_method: create_idx.using_method.clone(),
                    has_predicate: create_idx.has_predicate,
                    is_concurrent: create_idx.concurrently,
                    is_unique: create_idx.unique,
                });
                MutationResult::Applied
            }
            Mutation::CreatePolicy(create_policy) => {
                self.snapshot_relation(&create_policy.table);
                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&create_policy.table)
                {
                    rel.policies.insert(create_policy.name.clone());
                }
                MutationResult::Applied
            }
            Mutation::DropPolicy(drop_policy) => {
                self.snapshot_relation(&drop_policy.table);
                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&drop_policy.table)
                {
                    rel.policies.remove(&drop_policy.name);
                }
                MutationResult::Applied
            }
            Mutation::CreateTrigger(create_trigger) => {
                let trigger_id = ObjectId::new(
                    create_trigger.table.schema.clone(),
                    create_trigger.name.clone(),
                );
                self.snapshot_trigger(&trigger_id);
                self.local.triggers.insert(
                    trigger_id.clone(),
                    TriggerOverlay::Present(crate::model::trigger::TriggerState {
                        id: trigger_id.clone(),
                        table_id: create_trigger.table.clone(),
                        generation: self.local.generation_counter,
                    }),
                );

                self.snapshot_relation(&create_trigger.table);
                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&create_trigger.table)
                {
                    rel.triggers.insert(create_trigger.name.clone());
                }

                self.snapshot_trigger_graph_full();
                self.local
                    .graph
                    .trigger_dependencies
                    .push(crate::analysis::graph::TriggerEdge {
                        trigger_id,
                        table_id: create_trigger.table.clone(),
                        function_id: create_trigger.function_id.clone(),
                    });

                MutationResult::Applied
            }
            Mutation::DropTrigger(drop_trigger) => {
                let trigger_id =
                    ObjectId::new(drop_trigger.table.schema.clone(), drop_trigger.name.clone());
                self.snapshot_trigger(&trigger_id);
                self.local
                    .triggers
                    .insert(trigger_id.clone(), TriggerOverlay::Dropped);

                self.snapshot_relation(&drop_trigger.table);
                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&drop_trigger.table)
                {
                    rel.triggers.remove(&drop_trigger.name);
                }

                self.snapshot_trigger_graph_full();
                self.local
                    .graph
                    .trigger_dependencies
                    .retain(|t| t.trigger_id != trigger_id);

                MutationResult::Applied
            }
            Mutation::AlterTable(alter) => {
                self.snapshot_relation(&alter.id);
                let rel_overlay = self.local.relations.get_mut(&alter.id);
                if let Some(RelationOverlay::Present(rel)) = rel_overlay {
                    let generation = rel.generation;
                    match &alter.action {
                        AlterTableActionMutation::AddColumn {
                            name,
                            ty,
                            if_not_exists,
                            not_null,
                            default,
                            depends_on,
                        } => {
                            if !(*if_not_exists && rel.has_column(name)) {
                                if let Some(existing_col) =
                                    rel.columns.iter().find(|c| c.name == *name)
                                    && existing_col.data_type.as_deref() != ty.as_deref()
                                {
                                    return MutationResult::Conflict {
                                        reason: format!(
                                            "column '{}' already added with type {} (likely an earlier file in this chain), this file adds it again with type {}",
                                            name,
                                            existing_col.data_type.as_deref().unwrap_or("unknown"),
                                            ty.as_deref().unwrap_or("unknown")
                                        ),
                                    };
                                }
                                rel.apply_column_action(&ColumnAction::Add {
                                    name: name.clone(),
                                    data_type: ty.clone(),
                                    not_null: *not_null,
                                    default: default.clone(),
                                });

                                if let Some((source_table, source_col)) = depends_on {
                                    self.snapshot_column_graph();
                                    self.local.graph.column_dependencies.push(
                                        crate::analysis::graph::ColumnDependencyEdge {
                                            table_id: alter.id.clone(),
                                            column: name.clone(),
                                            depends_on_table: source_table.clone(),
                                            depends_on_column: source_col.clone(),
                                        },
                                    );
                                }
                            }
                        }
                        AlterTableActionMutation::DropColumn { name, if_exists } => {
                            if !rel.has_column(name) {
                                if *if_exists {
                                    // Column doesn't exist and IF EXISTS was specified: no-op
                                    return MutationResult::Skipped;
                                }
                                // Column doesn't exist and IF EXISTS not specified: PG runtime error
                                self.local.confidence = Confidence::Tainted;
                                return MutationResult::Skipped;
                            }
                            rel.apply_column_action(&ColumnAction::Drop { name: name.clone() });
                        }
                        AlterTableActionMutation::RenameColumn { from, to } => {
                            rel.apply_column_action(&ColumnAction::Rename {
                                from: from.clone(),
                                to: to.clone(),
                            });
                        }
                        AlterTableActionMutation::SetNotNull { column } => {
                            rel.apply_column_action(&ColumnAction::SetNotNull {
                                name: column.clone(),
                            });
                        }
                        AlterTableActionMutation::DropNotNull { column } => {
                            rel.apply_column_action(&ColumnAction::DropNotNull {
                                name: column.clone(),
                            });
                        }
                        AlterTableActionMutation::SetType { column, ty, .. } => {
                            if !rel.has_column(column) {
                                self.local.confidence = Confidence::Tainted;
                            }
                            rel.apply_column_action(&ColumnAction::SetType {
                                name: column.clone(),
                                data_type: ty.clone(),
                            });
                        }
                        AlterTableActionMutation::SetDefault { column, default } => {
                            if !rel.has_column(column) {
                                self.local.confidence = Confidence::Tainted;
                            }
                            rel.apply_column_action(&ColumnAction::SetDefault {
                                name: column.clone(),
                                default: default.clone(),
                            });
                        }
                        AlterTableActionMutation::AddForeignKey {
                            constraint_name,
                            to_table,
                            from_columns,
                            to_columns,
                            ..
                        } => {
                            self.snapshot_fk_graph();
                            self.local.graph.foreign_keys.push(FkEdge {
                                constraint_name: constraint_name.clone(),
                                from_table: alter.id.clone(),
                                from_columns: from_columns.clone(),
                                to_table: to_table.clone(),
                                to_columns: to_columns.clone(),
                                from_generation: generation,
                            });
                        }
                        AlterTableActionMutation::DropConstraint { name } => {
                            self.snapshot_fk_graph();
                            self.local.graph.foreign_keys.retain(|fk| {
                                !(fk.from_table == alter.id
                                    && fk.constraint_name.as_ref() == Some(name))
                            });
                        }
                        AlterTableActionMutation::AttachPartition { child } => {
                            self.snapshot_partition_graph();
                            self.local.graph.partitions.push(PartitionEdge {
                                parent: alter.id.clone(),
                                child: child.clone(),
                            });
                        }
                        AlterTableActionMutation::DetachPartition { child } => {
                            self.snapshot_partition_graph();
                            self.local
                                .graph
                                .partitions
                                .retain(|p| !(p.parent == alter.id && p.child == *child));
                        }
                        _ => {}
                    }
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
            Mutation::AlterType(alter_type) => {
                self.snapshot_type(&alter_type.id);
                if let Some(TypeOverlay::Present(t)) = self.local.types.get_mut(&alter_type.id) {
                    match &alter_type.action {
                        AlterTypeActionMutation::AddValue { new_value } => {
                            if let TypeKind::Enum { variants } = &mut t.kind {
                                variants.push(new_value.clone());
                            }
                        }
                    }
                }
                MutationResult::Applied
            }
            Mutation::CreateDomain(create_domain) => {
                self.snapshot_type(&create_domain.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.types.insert(
                    create_domain.id.clone(),
                    TypeOverlay::Present(TypeState {
                        id: create_domain.id.clone(),
                        generation,
                        kind: TypeKind::Domain {
                            base_type: create_domain.base_type.clone(),
                        },
                    }),
                );
                MutationResult::Applied
            }
            Mutation::AlterDomain(_) => MutationResult::Applied,
            Mutation::DropDomain(drop_domain) => {
                for id in &drop_domain.ids {
                    self.snapshot_type(id);
                    self.local.types.insert(id.clone(), TypeOverlay::Dropped);
                }
                MutationResult::Applied
            }
            Mutation::CreateSequence(create_seq) => {
                if create_seq.if_not_exists && self.local.sequences.contains_key(&create_seq.id) {
                    return MutationResult::Skipped;
                }
                self.snapshot_sequence(&create_seq.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.sequences.insert(
                    create_seq.id.clone(),
                    SequenceOverlay::Present(SequenceState {
                        id: create_seq.id.clone(),
                        generation,
                    }),
                );

                if let Some((table_id, col)) = &create_seq.owned_by {
                    self.snapshot_sequence_graph();
                    self.local.graph.sequences.push(SequenceEdge {
                        sequence_id: create_seq.id.clone(),
                        table_id: table_id.clone(),
                        column: col.clone(),
                    });
                }
                MutationResult::Applied
            }
            Mutation::AlterSequence(alter_seq) => {
                self.snapshot_sequence(&alter_seq.id);
                self.snapshot_sequence_graph();
                self.local
                    .graph
                    .sequences
                    .retain(|s| s.sequence_id != alter_seq.id);
                if let Some((table_id, col)) = &alter_seq.owned_by {
                    self.local.graph.sequences.push(SequenceEdge {
                        sequence_id: alter_seq.id.clone(),
                        table_id: table_id.clone(),
                        column: col.clone(),
                    });
                }
                MutationResult::Applied
            }
            Mutation::DropSequence(drop_seq) => {
                for id in &drop_seq.ids {
                    self.snapshot_sequence(id);
                    self.local
                        .sequences
                        .insert(id.clone(), SequenceOverlay::Dropped);
                }
                self.snapshot_sequence_graph_full();
                self.local
                    .graph
                    .sequences
                    .retain(|s| !drop_seq.ids.contains(&s.sequence_id));
                MutationResult::Applied
            }
            Mutation::Rename(rename) => {
                self.snapshot_relation(&rename.old_id);
                self.snapshot_relation(&rename.new_id);
                if let Some(RelationOverlay::Present(mut state)) =
                    self.local.relations.remove(&rename.old_id)
                {
                    state.id = rename.new_id.clone();
                    self.local
                        .relations
                        .insert(rename.new_id.clone(), RelationOverlay::Present(state));
                }
                self.snapshot_rename_graph();
                self.local.graph.renames.push(RenameEdge {
                    from: rename.old_id.clone(),
                    to: rename.new_id.clone(),
                });

                // Snapshot all 8 affected graph edge lists before calling propagate_rename
                self.snapshot_fk_graph_full();
                self.snapshot_view_graph_full();
                self.snapshot_index_graph_full();
                self.snapshot_partition_graph_full();
                self.snapshot_sequence_graph_full();
                self.snapshot_column_graph_full();
                self.snapshot_trigger_graph_full();
                self.snapshot_publication_graph_full();

                self.local
                    .graph
                    .propagate_rename(&rename.old_id, &rename.new_id);

                MutationResult::Applied
            }
            Mutation::DropView(drop_view) => {
                for id in &drop_view.ids {
                    self.snapshot_relation(id);
                    self.local
                        .relations
                        .insert(id.clone(), RelationOverlay::Dropped);
                }
                self.snapshot_view_graph_full();
                self.local
                    .graph
                    .views
                    .retain(|v| !drop_view.ids.contains(&v.view_id));
                MutationResult::Applied
            }
            Mutation::DropMaterializedView(drop_mv) => {
                for id in &drop_mv.ids {
                    self.snapshot_relation(id);
                    self.local
                        .relations
                        .insert(id.clone(), RelationOverlay::Dropped);
                }
                self.snapshot_view_graph_full();
                self.local
                    .graph
                    .views
                    .retain(|v| !drop_mv.ids.contains(&v.view_id));
                MutationResult::Applied
            }
            Mutation::DropIndex(drop_idx) => {
                self.snapshot_index_graph();
                self.local
                    .graph
                    .indexes
                    .retain(|idx| idx.index_id != drop_idx.id);
                MutationResult::Applied
            }
            Mutation::SearchPath(sp) => {
                self.snapshot_search_path();
                match &sp.target {
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
                    .push(TransactionFrame::new("transaction"));
                MutationResult::Applied
            }
            Mutation::CommitTransaction => {
                while self.local.transactions.pop().is_some() {}
                MutationResult::Applied
            }
            Mutation::RollbackTransaction => {
                while let Some(frame) = self.local.transactions.pop() {
                    self.rollback_frame(frame);
                }
                MutationResult::Applied
            }
            Mutation::RollbackToSavepoint(rts) => {
                let mut rolled_back = Vec::new();
                while let Some(frame) = self.local.transactions.last() {
                    if frame.name == rts.name {
                        break;
                    }
                    rolled_back.push(self.local.transactions.pop().unwrap());
                }
                if let Some(frame) = self.local.transactions.last_mut() {
                    let mut temp_frame = TransactionFrame::new(&frame.name);
                    while let Some(change) = frame.undo_log.pop() {
                        temp_frame.undo_log.push(change);
                    }
                    self.rollback_frame(temp_frame);
                }
                for frame in rolled_back.into_iter().rev() {
                    self.rollback_frame(frame);
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
                let mut rolled_back = Vec::new();
                while let Some(frame) = self.local.transactions.last() {
                    if frame.name == rsp.name {
                        break;
                    }
                    rolled_back.push(self.local.transactions.pop().unwrap());
                }
                if let Some(frame) = self.local.transactions.pop()
                    && let Some(outer) = self.local.transactions.last_mut()
                {
                    outer.undo_log.extend(frame.undo_log);
                }
                for frame in rolled_back.into_iter().rev() {
                    self.local.transactions.push(frame);
                }
                MutationResult::Applied
            }
            Mutation::Opaque(_) => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                MutationResult::Applied
            }
            Mutation::CreateFunction(f) => {
                self.snapshot_function(&f.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let _generation = self.local.generation_counter;

                let volatility = f
                    .options
                    .iter()
                    .find_map(|opt| {
                        if let crate::analysis::facts::FuncOptionFact::Volatility(v) = opt {
                            Some(match v {
                                crate::analysis::facts::VolatilityKind::Volatile => {
                                    crate::model::function::Volatility::Volatile
                                }
                                crate::analysis::facts::VolatilityKind::Stable => {
                                    crate::model::function::Volatility::Stable
                                }
                                crate::analysis::facts::VolatilityKind::Immutable => {
                                    crate::model::function::Volatility::Immutable
                                }
                            })
                        } else {
                            None
                        }
                    })
                    .unwrap_or(crate::model::function::Volatility::Volatile);

                let security = f
                    .options
                    .iter()
                    .find_map(|opt| {
                        if let crate::analysis::facts::FuncOptionFact::Security(s) = opt {
                            Some(match s {
                                crate::analysis::facts::SecurityKind::Invoker => {
                                    crate::model::function::SecurityMode::Invoker
                                }
                                crate::analysis::facts::SecurityKind::Definer => {
                                    crate::model::function::SecurityMode::Definer
                                }
                            })
                        } else {
                            None
                        }
                    })
                    .unwrap_or(crate::model::function::SecurityMode::Invoker);

                let language = f
                    .options
                    .iter()
                    .find_map(|opt| {
                        if let crate::analysis::facts::FuncOptionFact::Language(l) = opt {
                            Some(l.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "sql".to_string());

                self.local.functions.insert(
                    f.id.clone(),
                    crate::model::function::FunctionOverlay::Present(
                        crate::model::function::FunctionState {
                            id: f.id.clone(),
                            arg_types: f.params.iter().map(|p| p.ty.clone()).collect(),
                            return_type: f
                                .return_type
                                .as_ref()
                                .map(|rt| format!("{:?}", rt))
                                .unwrap_or_default(),
                            volatility,
                            language,
                            security,
                        },
                    ),
                );
                MutationResult::Applied
            }
            Mutation::AlterFunction(f) => {
                self.snapshot_function(&f.id);
                // Function generation tracking removed to match model definition
                MutationResult::Applied
            }
            Mutation::DropFunction(f) => {
                let mut any_applied = false;
                for sig in &f.signatures {
                    let sig_str = format!("{}({})", sig.name.name.resolve(), sig.params.join(","));
                    let schema = self.resolve_function_schema(&sig.name, &sig_str);
                    let id = ObjectId::new(schema, sig_str);
                    if !matches!(
                        self.local.functions.get(&id),
                        Some(crate::model::function::FunctionOverlay::Present(_))
                    ) {
                        if !f.if_exists {
                            self.local.confidence = Confidence::Tainted;
                            return MutationResult::Skipped;
                        }
                    } else {
                        any_applied = true;
                        self.snapshot_function(&id);
                        self.local
                            .functions
                            .insert(id, crate::model::function::FunctionOverlay::Dropped);
                    }
                }
                if any_applied {
                    MutationResult::Applied
                } else {
                    MutationResult::Skipped
                }
            }
            Mutation::CreateProcedure(p) => {
                self.snapshot_function(&p.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let _generation = self.local.generation_counter;

                self.local.functions.insert(
                    p.id.clone(),
                    crate::model::function::FunctionOverlay::Present(
                        crate::model::function::FunctionState {
                            id: p.id.clone(),
                            arg_types: p.params.iter().map(|p| p.ty.clone()).collect(),
                            return_type: "void".to_string(),
                            volatility: crate::model::function::Volatility::Volatile,
                            language: "sql".to_string(),
                            security: crate::model::function::SecurityMode::Invoker,
                        },
                    ),
                );
                MutationResult::Applied
            }
            Mutation::AlterProcedure(p) => {
                self.snapshot_function(&p.id);
                // No generation tracking in FunctionState
                MutationResult::Applied
            }
            Mutation::DropProcedure(p) => {
                let mut any_applied = false;
                for sig in &p.signatures {
                    let sig_str = format!("{}({})", sig.name.name.resolve(), sig.params.join(","));
                    let schema = self.resolve_function_schema(&sig.name, &sig_str);
                    let id = ObjectId::new(schema, sig_str);
                    if !matches!(
                        self.local.functions.get(&id),
                        Some(crate::model::function::FunctionOverlay::Present(_))
                    ) {
                        if !p.if_exists {
                            self.local.confidence = Confidence::Tainted;
                            return MutationResult::Skipped;
                        }
                    } else {
                        any_applied = true;
                        self.snapshot_function(&id);
                        self.local
                            .functions
                            .insert(id, crate::model::function::FunctionOverlay::Dropped);
                    }
                }
                if any_applied {
                    MutationResult::Applied
                } else {
                    MutationResult::Skipped
                }
            }
            Mutation::CreatePublication(p) => {
                self.snapshot_publication(&p.name);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.publications.insert(
                    p.name.clone(),
                    crate::model::replication::PublicationOverlay::Present(
                        crate::model::replication::PublicationState {
                            name: p.name.clone(),
                            scope: p.scope.clone(),
                            params: p.params.clone(),
                            generation,
                        },
                    ),
                );

                if let crate::analysis::facts::PublicationScope::Explicit(objects) = &p.scope {
                    self.snapshot_publication_graph_full();
                    for obj in objects {
                        if let crate::analysis::facts::PublicationObjectFact::Table {
                            name, ..
                        } = obj
                        {
                            let table_id = self.resolve_relation_id(name);
                            self.local
                                .graph
                                .publication_dependencies
                                .push(PublicationEdge {
                                    publication_name: p.name.clone(),
                                    table_id,
                                });
                        }
                    }
                }
                MutationResult::Applied
            }
            Mutation::AlterPublication(p) => {
                self.snapshot_publication(&p.name);
                if !self.local.publications.contains_key(&p.name) {
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let new_gen = self.local.generation_counter;

                if let Some(crate::model::replication::PublicationOverlay::Present(publ)) =
                    self.local.publications.get_mut(&p.name)
                {
                    publ.generation = new_gen;
                }
                MutationResult::Applied
            }
            Mutation::DropPublication(p) => {
                for name in &p.names {
                    self.snapshot_publication(name);
                    if !p.if_exists && !self.local.publications.contains_key(name) {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                    self.local.publications.insert(
                        name.clone(),
                        crate::model::replication::PublicationOverlay::Dropped,
                    );
                }
                self.snapshot_publication_graph_full();
                self.local
                    .graph
                    .publication_dependencies
                    .retain(|edge| !p.names.contains(&edge.publication_name));
                MutationResult::Applied
            }
            Mutation::CreateSubscription(s) => {
                let name = s.name.clone().unwrap_or_else(|| "unnamed_sub".into());
                self.snapshot_subscription(&name);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.subscriptions.insert(
                    name.clone(),
                    crate::model::replication::SubscriptionOverlay::Present(
                        crate::model::replication::SubscriptionState {
                            name,
                            connection: s.connection.clone(),
                            publications: s.publications.clone(),
                            params: s.params.clone(),
                            generation,
                        },
                    ),
                );
                MutationResult::Applied
            }
            Mutation::AlterSubscription(s) => {
                self.snapshot_subscription(&s.name);
                if !self.local.subscriptions.contains_key(&s.name) {
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let new_gen = self.local.generation_counter;

                if let Some(crate::model::replication::SubscriptionOverlay::Present(sub)) =
                    self.local.subscriptions.get_mut(&s.name)
                {
                    sub.generation = new_gen;
                }
                MutationResult::Applied
            }
            Mutation::DropSubscription(s) => {
                self.snapshot_subscription(&s.name);
                if !s.if_exists && !self.local.subscriptions.contains_key(&s.name) {
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }
                self.local.subscriptions.insert(
                    s.name.clone(),
                    crate::model::replication::SubscriptionOverlay::Dropped,
                );
                MutationResult::Applied
            }
            Mutation::CreateRole(r) => {
                let role_id = ObjectId::new("", &r.name);
                self.snapshot_role(&role_id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let _generation = self.local.generation_counter;

                self.local.roles.insert(
                    role_id.clone(),
                    crate::model::role::RoleOverlay::Present(crate::model::role::RoleState {
                        id: role_id,
                        can_login: true,
                        is_superuser: false,
                        member_of: Vec::new(),
                        granted_privileges: Vec::new(),
                    }),
                );
                MutationResult::Applied
            }
            Mutation::AlterRole(r) => {
                if let Some(role_id) = Self::resolve_role_name(&r.name, &self.local.current_role) {
                    self.snapshot_role(&role_id);
                    if !self.local.roles.contains_key(&role_id) {
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                    self.snapshot_generation_counter();
                    self.local.generation_counter += 1;
                    let _new_gen = self.local.generation_counter;

                    if let Some(crate::model::role::RoleOverlay::Present(_role)) =
                        self.local.roles.get_mut(&role_id)
                    {
                        // No further action as fields have been simplified
                    }
                    MutationResult::Applied
                } else {
                    MutationResult::Skipped
                }
            }
            Mutation::DropRole(r) => {
                for name in &r.names {
                    if let Some(role_id) = Self::resolve_role_name(
                        &crate::analysis::facts::RoleFact::Named {
                            name: name.clone(),
                            via_legacy_group_syntax: false,
                        },
                        &self.local.current_role,
                    ) {
                        self.snapshot_role(&role_id);
                        if !r.if_exists && !self.local.roles.contains_key(&role_id) {
                            self.local.confidence = Confidence::Tainted;

                            return MutationResult::Skipped;
                        }
                        self.local
                            .roles
                            .insert(role_id, crate::model::role::RoleOverlay::Dropped);
                    }
                }
                MutationResult::Applied
            }
            Mutation::Grant(grant) => {
                let privileges = Self::resolve_grant_privileges(&grant.privileges);
                let grantees = &grant.grantees;
                match &grant.target {
                    crate::analysis::mutations::ResolvedGrantTarget::Tables(ids) => {
                        for id in ids {
                            self.apply_grant_to_relation(id, &privileges, grantees);
                        }
                    }
                    crate::analysis::mutations::ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                        let target_ids: Vec<ObjectId> = self
                            .local
                            .relations
                            .keys()
                            .filter(|id| schemas.contains(&id.schema))
                            .cloned()
                            .collect();
                        for id in &target_ids {
                            self.apply_grant_to_relation(id, &privileges, grantees);
                        }
                    }
                }
                MutationResult::Applied
            }
            Mutation::Revoke(revoke) => {
                let privileges = Self::resolve_grant_privileges(&revoke.privileges);
                let revokees = &revoke.revokees;
                match &revoke.target {
                    crate::analysis::mutations::ResolvedGrantTarget::Tables(ids) => {
                        for id in ids {
                            self.apply_revoke_to_relation(id, &privileges, revokees);
                        }
                    }
                    crate::analysis::mutations::ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                        let target_ids: Vec<ObjectId> = self
                            .local
                            .relations
                            .keys()
                            .filter(|id| schemas.contains(&id.schema))
                            .cloned()
                            .collect();
                        for id in &target_ids {
                            self.apply_revoke_to_relation(id, &privileges, revokees);
                        }
                    }
                }
                MutationResult::Applied
            }
            Mutation::CreateDatabase(_) => MutationResult::Applied,
            Mutation::AlterDatabase(_) => MutationResult::Applied,
            Mutation::DropDatabase(_) => MutationResult::Applied,
            Mutation::Vacuum { .. } => MutationResult::Applied,
        }
    }

    fn snapshot_relation(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.relations.get(id).cloned();
            frame.undo_log.push(StateChange::RelationSnapshot {
                id: id.clone(),
                previous: Box::new(previous),
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

    fn snapshot_function(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.functions.get(id).cloned();
            frame.undo_log.push(StateChange::FunctionSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    fn snapshot_publication(&mut self, name: &str) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.publications.get(name).cloned();
            frame.undo_log.push(StateChange::PublicationSnapshot {
                id: ObjectId::new("", name),
                previous,
            });
        }
    }

    fn snapshot_subscription(&mut self, name: &str) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.subscriptions.get(name).cloned();
            frame.undo_log.push(StateChange::SubscriptionSnapshot {
                id: ObjectId::new("", name),
                previous,
            });
        }
    }

    fn snapshot_role(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.roles.get(id).cloned();
            frame.undo_log.push(StateChange::RoleSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    fn snapshot_trigger(&mut self, id: &ObjectId) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let previous = self.local.triggers.get(id).cloned();
            frame.undo_log.push(StateChange::TriggerSnapshot {
                id: id.clone(),
                previous,
            });
        }
    }

    fn snapshot_trigger_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::TriggerGraphSnapshot {
                previous: self.local.graph.trigger_dependencies.clone(),
            });
        }
    }

    fn snapshot_publication_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::PublicationGraphSnapshot {
                previous: self.local.graph.publication_dependencies.clone(),
            });
        }
    }

    #[allow(dead_code)]
    fn snapshot_current_role(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::CurrentRoleSnapshot {
                previous: self.local.current_role.clone(),
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

    #[allow(dead_code)]
    fn snapshot_pending_validation(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::PendingValidationSnapshot {
                previous: self.local.pending_validation.clone(),
            });
        }
    }

    fn snapshot_confidence(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::ConfidenceSnapshot {
                previous: self.local.confidence.clone(),
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

    fn snapshot_partition_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::PartitionGraphMarker {
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

    fn snapshot_column_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::ColumnGraphLengthMarker {
                len: self.local.graph.column_dependencies.len(),
            });
        }
    }

    fn snapshot_column_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::ColumnGraphSnapshot {
                previous: self.local.graph.column_dependencies.clone(),
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

    fn rollback_frame(&mut self, mut frame: TransactionFrame) {
        while let Some(change) = frame.undo_log.pop() {
            match change {
                StateChange::RelationSnapshot { id, previous } => {
                    if let Some(prev) = *previous {
                        self.local.relations.insert(id, prev);
                    } else {
                        self.local.relations.remove(&id);
                    }
                }
                StateChange::TypeSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.types.insert(id, prev);
                    } else {
                        self.local.types.remove(&id);
                    }
                }
                StateChange::SequenceSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.sequences.insert(id, prev);
                    } else {
                        self.local.sequences.remove(&id);
                    }
                }
                StateChange::FunctionSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.functions.insert(id, prev);
                    } else {
                        self.local.functions.remove(&id);
                    }
                }
                StateChange::PublicationSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.publications.insert(id.name, prev);
                    } else {
                        self.local.publications.remove(&id.name);
                    }
                }
                StateChange::SubscriptionSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.subscriptions.insert(id.name, prev);
                    } else {
                        self.local.subscriptions.remove(&id.name);
                    }
                }
                StateChange::RoleSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.roles.insert(id, prev);
                    } else {
                        self.local.roles.remove(&id);
                    }
                }
                StateChange::TriggerSnapshot { id, previous } => {
                    if let Some(prev) = previous {
                        self.local.triggers.insert(id, prev);
                    } else {
                        self.local.triggers.remove(&id);
                    }
                }
                StateChange::TriggerGraphSnapshot { previous } => {
                    self.local.graph.trigger_dependencies = previous;
                }
                StateChange::PublicationGraphSnapshot { previous } => {
                    self.local.graph.publication_dependencies = previous;
                }
                StateChange::CurrentRoleSnapshot { previous } => {
                    self.local.current_role = previous;
                }
                StateChange::SearchPathSnapshot { previous } => {
                    self.local.search_path = previous;
                }
                StateChange::GenerationCounterSnapshot { previous } => {
                    self.local.generation_counter = previous;
                }
                StateChange::PendingValidationSnapshot { previous } => {
                    self.local.pending_validation = previous;
                }
                StateChange::ConfidenceSnapshot { previous } => {
                    self.local.confidence = previous;
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
                StateChange::PartitionGraphMarker { len } => {
                    self.local.graph.partitions.truncate(len);
                }
                StateChange::PartitionGraphSnapshot { previous } => {
                    self.local.graph.partitions = previous;
                }
                StateChange::SequenceGraphLengthMarker { len } => {
                    self.local.graph.sequences.truncate(len);
                }
                StateChange::SequenceGraphSnapshot { previous } => {
                    self.local.graph.sequences = previous;
                }
                StateChange::RenameGraphLengthMarker { len } => {
                    self.local.graph.renames.truncate(len);
                }
                StateChange::RenameGraphSnapshot { previous } => {
                    self.local.graph.renames = previous;
                }
                StateChange::ColumnGraphLengthMarker { len } => {
                    self.local.graph.column_dependencies.truncate(len);
                }
                StateChange::ColumnGraphSnapshot { previous } => {
                    self.local.graph.column_dependencies = previous;
                }
            }
        }
    }
}
