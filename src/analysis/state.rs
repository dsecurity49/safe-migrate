use crate::analysis::graph::{DependencyEdge, DependencyGraph, DependencyKind};
use crate::analysis::mutations::Mutation;
use crate::analysis::settings::ScopedSetting;
use crate::analysis::transaction::{NamespaceSnapshot, StateChange, TransactionFrame};
use crate::ast::identifiers::ObjectId;
use crate::db::cache::DbCache;
use crate::model::constraint::ConstraintState;
use crate::model::function::FunctionOverlay;
pub use crate::model::relation::RelationOverlay;
use crate::model::relation::{Persistence, Privilege, RelationKind};
use crate::model::schema::SchemaOverlay;
use crate::model::sequence::SequenceOverlay;
use crate::model::trigger::TriggerOverlay;
use crate::model::types::{TypeKind, TypeOverlay, TypeState};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

mod apply_misc;
mod apply_policy_trigger;
mod apply_relation;
mod apply_replication;
mod apply_role;
mod apply_routine;
mod apply_schema;
mod apply_sequence;
mod apply_settings;
mod apply_transaction;
mod apply_type;
mod apply_view_index;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    Exact,
    Tainted,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MutationResult {
    Applied,
    Skipped,
    /// PostgreSQL did not execute this statement because an earlier statement
    /// aborted the active transaction.
    NotExecuted,
    Conflict {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectLookup {
    Present,
    WrongKind,
    Tombstone,
    AuthoritativelyAbsent,
    Unknown,
}

fn sync_present_map<K, V, O, F>(target: &mut HashMap<K, V>, source: &HashMap<K, O>, present: F)
where
    K: Clone + Eq + Hash,
    V: Clone + PartialEq,
    F: for<'a> Fn(&'a O) -> Option<&'a V> + Copy,
{
    target.retain(|key, value| {
        let Some(current) = source.get(key).and_then(present) else {
            return false;
        };
        if value != current {
            value.clone_from(current);
        }
        true
    });
    target.reserve(source.len().saturating_sub(target.len()));
    for (key, overlay) in source {
        if !target.contains_key(key)
            && let Some(value) = present(overlay)
        {
            target.insert(key.clone(), value.clone());
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct CascadeResult {
    pub dropped_relations: HashSet<ObjectId>,
    pub dropped_indexes: HashSet<ObjectId>,
    pub dropped_constraints: HashSet<(ObjectId, String)>,
}

#[derive(Clone)]
pub struct LocalState {
    pub schemas: HashMap<String, SchemaOverlay>,
    pub relations: HashMap<ObjectId, RelationOverlay>,
    pub types: HashMap<ObjectId, TypeOverlay>,
    pub functions: HashMap<ObjectId, crate::model::function::FunctionOverlay>,
    pub sequences: HashMap<ObjectId, SequenceOverlay>,
    pub publications: HashMap<String, crate::model::replication::PublicationOverlay>,
    pub subscriptions: HashMap<String, crate::model::replication::SubscriptionOverlay>,
    pub roles: HashMap<ObjectId, crate::model::role::RoleOverlay>,
    pub triggers: HashMap<ObjectId, TriggerOverlay>,
    pub constraints: HashMap<(ObjectId, String), ConstraintState>,
    pub graph: DependencyGraph,
    pub search_path: Vec<String>,
    pub default_search_path: Vec<String>,
    pub search_path_template: Vec<String>,
    pub session_search_path_template: Vec<String>,
    pub default_search_path_template: Vec<String>,
    pub lock_timeout: ScopedSetting<Option<u64>>,
    pub statement_timeout: ScopedSetting<Option<u64>>,
    /// Role currently active for this session context (updated by SET ROLE /
    /// SET SESSION AUTHORIZATION). Begins equal to `session_role`.
    pub current_role: String,
    /// Whether `current_role` is statically known. False when no synchronized cache was
    /// loaded and no SET ROLE statement has been processed yet.
    pub current_role_known: bool,
    /// Effective role setting that survives transaction commit. A LOCAL role
    /// change updates `current_role` without changing this value.
    pub persistent_current_role: String,
    pub persistent_current_role_known: bool,
    /// The session-level role as captured from the cache's `source_role`. This
    /// is the value `SET ROLE NONE` / `SET SESSION AUTHORIZATION DEFAULT`
    /// reverts to.
    pub session_role: String,
    /// Whether `session_role` is statically known (mirrors `current_role_known`
    /// at baseline; a SET SESSION AUTHORIZATION updates this too).
    pub session_role_known: bool,
    /// Session authorization that survives transaction commit.
    pub persistent_session_role: String,
    pub persistent_session_role_known: bool,
    /// Login identity restored by `SET SESSION AUTHORIZATION DEFAULT`.
    pub authenticated_role: String,
    pub authenticated_role_known: bool,
    /// Whether the cache contains a complete PostgreSQL role catalog.
    pub roles_known: bool,
    pub confidence: Confidence,
    pub transactions: Vec<TransactionFrame>,
    pub transaction_aborted: bool,
    pub pending_validation: HashSet<(ObjectId, String)>,
    pub generation_counter: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PreState {
    pub relations: HashMap<ObjectId, crate::model::relation::RelationState>,
    pub functions: HashMap<ObjectId, crate::model::function::FunctionState>,
    pub roles: HashMap<ObjectId, crate::model::role::RoleState>,
    pub publications: HashMap<String, crate::model::replication::PublicationState>,
    pub subscriptions: HashMap<String, crate::model::replication::SubscriptionState>,
    pub sequences: HashMap<ObjectId, crate::model::sequence::SequenceState>,
    pub types: HashMap<ObjectId, crate::model::types::TypeState>,
    pub indexes: Vec<crate::analysis::graph::DependencyEdge>,
    pub baseline_foreign_keys: HashSet<(ObjectId, String)>,
}

#[cfg(test)]
mod pre_state_tests {
    use super::*;

    #[test]
    fn incremental_capture_matches_a_fresh_public_pre_state() {
        let mut state = AnalysisState::new(DbCache::new());
        let table_id = ObjectId::new("public", "capture_table");
        state.local.relations.insert(
            table_id.clone(),
            RelationOverlay::Present(crate::model::relation::RelationState::new(
                table_id.clone(),
                ObjectId::new("", "postgres"),
                1,
                Some(1),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            )),
        );

        let mut reused = PreState::default();
        state.capture_pre_state_into(&mut reused);
        assert_eq!(reused, state.capture_pre_state());

        let Some(RelationOverlay::Present(relation)) = state.local.relations.get_mut(&table_id)
        else {
            panic!("test relation must remain present");
        };
        relation.estimated_rows = Some(2);
        let index_id = ObjectId::new("public", "capture_table_idx");
        state.local.graph.add_edge(DependencyEdge::new(
            index_id,
            table_id.clone(),
            DependencyKind::IndexOnRelation {
                using_method: Some("btree".into()),
                has_predicate: false,
                is_concurrent: false,
                is_unique: false,
                eligibility_known: true,
            },
        ));
        state.capture_pre_state_into(&mut reused);
        assert_eq!(reused, state.capture_pre_state());
        assert_eq!(reused.relations[&table_id].estimated_rows, Some(2));
        assert_eq!(reused.indexes.len(), 1);

        state
            .local
            .relations
            .insert(table_id.clone(), RelationOverlay::Dropped);
        state.local.graph.replace_edges(Vec::new());
        state.capture_pre_state_into(&mut reused);
        assert_eq!(reused, state.capture_pre_state());
        assert!(!reused.relations.contains_key(&table_id));
        assert!(reused.indexes.is_empty());
    }
}

#[derive(Clone)]
pub struct AnalysisState {
    pub pg_version_num: Option<u32>,
    /// Whether the initial cache was loaded from a real cache file. An empty
    /// cache can be a valid baseline for an empty database, so availability
    /// must not be inferred from the number of modeled objects.
    pub baseline_available: bool,
    /// `None` means the cache covered all non-system schemas. A populated set
    /// records an explicitly scoped sync, for which objects outside the set
    /// are unknown rather than known absent.
    pub baseline_schemas: Option<HashSet<String>>,
    pub baseline_relations: HashSet<ObjectId>,
    pub baseline_indexes: HashSet<ObjectId>,
    pub baseline_foreign_keys: HashSet<(ObjectId, String)>,
    pub baseline_fk_dependencies: HashSet<ObjectId>,
    pub baseline_sequences: HashSet<ObjectId>,
    pub local: LocalState,
}

impl AnalysisState {
    fn trigger_key(table_id: &ObjectId, name: &str) -> ObjectId {
        // PostgreSQL identifiers cannot contain NUL, so this is an unambiguous
        // internal composite key while keeping the public cache representation
        // as the trigger's actual name.
        ObjectId::new(&table_id.schema, format!("{}\0{name}", table_id.name))
    }

    fn publication_object_key(
        &self,
        object: &crate::analysis::facts::PublicationObjectFact,
    ) -> String {
        match object {
            crate::analysis::facts::PublicationObjectFact::Table { name, .. } => {
                format!("table\0{}", self.resolve_relation_id(name))
            }
            crate::analysis::facts::PublicationObjectFact::SchemaTables { schema, .. } => {
                format!("schema\0{schema}")
            }
            crate::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand => {
                format!(
                    "schema\0{}",
                    self.local
                        .search_path
                        .first()
                        .map(String::as_str)
                        .unwrap_or("public")
                )
            }
            crate::analysis::facts::PublicationObjectFact::Unknown => "unknown".to_string(),
        }
    }

    fn replace_publication_edges(
        &mut self,
        publication_name: &str,
        scope: &crate::analysis::facts::PublicationScope,
    ) {
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !matches!(
                &edge.kind,
                DependencyKind::PublicationIncludes { publication_name: name }
                    if name == publication_name
            )
        });
        if let crate::analysis::facts::PublicationScope::Explicit(objects) = scope {
            for object in objects {
                if let crate::analysis::facts::PublicationObjectFact::Table { name, .. } = object {
                    self.local.graph.add_edge(DependencyEdge::new(
                        self.resolve_relation_id(name),
                        ObjectId::new("public", publication_name),
                        DependencyKind::PublicationIncludes {
                            publication_name: publication_name.to_string(),
                        },
                    ));
                }
            }
        }
    }

    fn validate_publication_scope(
        &mut self,
        scope: &crate::analysis::facts::PublicationScope,
    ) -> Result<(), String> {
        let crate::analysis::facts::PublicationScope::Explicit(objects) = scope else {
            return Ok(());
        };
        let mut object_keys = HashSet::new();
        for object in objects {
            if !object_keys.insert(self.publication_object_key(object)) {
                return Err("publication contains the same object more than once".to_string());
            }
            match object {
                crate::analysis::facts::PublicationObjectFact::Table { name, columns, .. } => {
                    let id = self.resolve_relation_id(name);
                    match self.local.relations.get(&id) {
                        Some(RelationOverlay::Present(relation))
                            if relation.kind == RelationKind::Table
                                && relation.persistence == Persistence::Permanent =>
                        {
                            if let Some(columns) = columns {
                                let mut seen = HashSet::new();
                                for column in columns {
                                    if !seen.insert(column) {
                                        return Err(format!(
                                            "publication lists column '{}' more than once for '{}'",
                                            column, id
                                        ));
                                    }
                                    if !relation.has_column(column) {
                                        return Err(format!(
                                            "publication column '{}.{}' does not exist",
                                            id, column
                                        ));
                                    }
                                }
                            }
                        }
                        Some(RelationOverlay::Present(_)) => {
                            return Err(format!(
                                "publication target '{}' is not a permanent table",
                                id
                            ));
                        }
                        Some(RelationOverlay::Dropped) => {
                            return Err(format!("publication table '{}' does not exist", id));
                        }
                        None if self.baseline_available && self.baseline_covers_object(&id) => {
                            return Err(format!("publication table '{}' does not exist", id));
                        }
                        None => {
                            self.snapshot_confidence();
                            self.local.confidence = Confidence::Tainted;
                        }
                    }
                }
                crate::analysis::facts::PublicationObjectFact::SchemaTables { schema, .. } => {
                    if !self.schema_is_present(schema) {
                        if self.schema_absence_is_authoritative(schema) {
                            return Err(format!("publication schema '{}' does not exist", schema));
                        }
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                    }
                }
                crate::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand
                | crate::analysis::facts::PublicationObjectFact::Unknown => {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                }
            }
        }
        Ok(())
    }

    fn publication_scope_needs_inheritance_knowledge(
        &self,
        scope: &crate::analysis::facts::PublicationScope,
    ) -> bool {
        match scope {
            // FOR ALL TABLES necessarily depends on the complete catalog and
            // future table/inheritance state, neither of which Cache V6 stores.
            crate::analysis::facts::PublicationScope::AllTables { .. } => true,
            crate::analysis::facts::PublicationScope::Explicit(objects) => {
                objects.iter().any(|object| match object {
                    crate::analysis::facts::PublicationObjectFact::Table {
                        name,
                        only,
                        include_partitions,
                        ..
                    } if !only || *include_partitions => {
                        let id = self.resolve_relation_id(name);
                        !matches!(
                            self.local.relations.get(&id),
                            Some(RelationOverlay::Present(relation)) if relation.generation > 0
                        ) || self.local.graph.edges().iter().any(|edge| {
                            matches!(edge.kind, DependencyKind::PartitionOf)
                                && self.local.graph.resolve_rename(&edge.referenced)
                                    == self.local.graph.resolve_rename(&id)
                        })
                    }
                    // Schema-wide and current-schema shorthand scopes also
                    // include inherited/partitioned descendants.
                    crate::analysis::facts::PublicationObjectFact::SchemaTables { .. }
                    | crate::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand => true,
                    crate::analysis::facts::PublicationObjectFact::Unknown => false,
                    _ => false,
                })
            }
        }
    }

    fn taint_inheritance_sensitive_publication_scope(
        &mut self,
        scope: &crate::analysis::facts::PublicationScope,
    ) {
        if self.publication_scope_needs_inheritance_knowledge(scope) {
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
        }
    }

    fn subscription_option<'a>(
        params: Option<&'a [crate::analysis::facts::AttributeFact]>,
        name: &str,
    ) -> Option<&'a str> {
        params?
            .iter()
            .rev()
            .find(|param| param.name.eq_ignore_ascii_case(name))
            .map(|param| param.value.as_str())
    }

    fn postgres_boolean(value: &str) -> Option<bool> {
        let value = value.trim().to_ascii_lowercase();
        match value.as_str() {
            "1" => return Some(true),
            "0" => return Some(false),
            "" => return None,
            _ => {}
        }

        let mut matched = None;
        for (spelling, parsed) in [
            ("true", true),
            ("yes", true),
            ("on", true),
            ("false", false),
            ("no", false),
            ("off", false),
        ] {
            if spelling.starts_with(&value) {
                if matched.is_some() {
                    return None;
                }
                matched = Some(parsed);
            }
        }
        matched
    }

    fn subscription_boolean_option(
        params: Option<&[crate::analysis::facts::AttributeFact]>,
        name: &str,
    ) -> Option<bool> {
        Self::subscription_option(params, name).and_then(Self::postgres_boolean)
    }

    fn validate_subscription_boolean_options(
        params: Option<&[crate::analysis::facts::AttributeFact]>,
        names: &[&str],
    ) -> Result<(), String> {
        let Some(params) = params else {
            return Ok(());
        };
        for option in params {
            if names
                .iter()
                .any(|name| option.name.eq_ignore_ascii_case(name))
                && Self::postgres_boolean(&option.value).is_none()
            {
                return Err(format!(
                    "subscription option '{}' requires a PostgreSQL boolean value",
                    option.name
                ));
            }
        }
        Ok(())
    }

    fn set_subscription_option(
        subscription: &mut crate::model::replication::SubscriptionState,
        option: &crate::analysis::facts::AttributeFact,
    ) {
        let params = subscription.params.get_or_insert_with(Vec::new);
        params.retain(|existing| !existing.name.eq_ignore_ascii_case(&option.name));
        params.push(option.clone());
    }

    pub fn new(cache: DbCache) -> Self {
        Self::with_baseline(cache, true)
    }

    pub fn with_baseline(cache: DbCache, baseline_available: bool) -> Self {
        let source_lock_timeout =
            baseline_available.then_some(cache.metadata.source_lock_timeout_ms);
        let source_statement_timeout =
            baseline_available.then_some(cache.metadata.source_statement_timeout_ms);
        let default_search_path = cache.search_path.clone();
        let default_search_path_template = if cache.metadata.schemas.is_none() {
            cache
                .metadata
                .source_search_path
                .clone()
                .unwrap_or_else(|| default_search_path.clone())
        } else {
            default_search_path.clone()
        };
        let current_role_known = cache.metadata.source_role.is_some();
        let current_role = cache
            .metadata
            .source_role
            .clone()
            .unwrap_or_else(|| "postgres".to_string());
        let session_role_known = cache.metadata.source_session_role.is_some();
        let session_role = cache
            .metadata
            .source_session_role
            .clone()
            .unwrap_or_else(|| current_role.clone());
        let authenticated_role = session_role.clone();
        let authenticated_role_known = session_role_known;
        let persistent_current_role = current_role.clone();
        let persistent_current_role_known = current_role_known;
        let persistent_session_role = session_role.clone();
        let persistent_session_role_known = session_role_known;
        let roles_known = cache.metadata.source_session_role.is_some();
        let baseline_schemas: Option<HashSet<String>> = cache
            .metadata
            .schemas
            .as_ref()
            .map(|schemas| schemas.iter().cloned().collect());
        let mut relations: HashMap<ObjectId, RelationOverlay> = HashMap::new();
        let mut baseline_relations = HashSet::new();
        let mut baseline_indexes = HashSet::new();
        let mut baseline_foreign_keys = HashSet::new();
        let mut baseline_fk_dependencies = HashSet::new();
        let mut triggers = HashMap::new();
        let mut constraints = HashMap::new();
        let mut types = HashMap::new();
        let mut graph = DependencyGraph::new();

        let mut schemas: HashMap<String, SchemaOverlay> = cache
            .schemas
            .iter()
            .map(|(name, schema)| (name.clone(), SchemaOverlay::Present(schema.clone())))
            .collect();
        // Effective cached search-path entries and modeled objects are direct
        // evidence that their namespaces existed at synchronization time.
        // This also keeps programmatically assembled caches internally
        // consistent without treating unrelated out-of-scope schemas as
        // authoritative catalogs.
        let inferred_schema_owner = ObjectId::new(
            "",
            cache.metadata.source_role.as_deref().unwrap_or("postgres"),
        );
        for name in cache
            .relations
            .keys()
            .map(|id| &id.schema)
            .chain(cache.types.keys().map(|id| &id.schema))
            .chain(cache.functions.keys().map(|id| &id.schema))
            .chain(cache.sequences.keys().map(|id| &id.schema))
        {
            schemas.entry(name.clone()).or_insert_with(|| {
                SchemaOverlay::Present(crate::model::schema::SchemaState {
                    name: name.clone(),
                    owner: inferred_schema_owner.clone(),
                    generation: 0,
                })
            });
        }
        if cache.schemas.is_empty() && cache.metadata.schemas.is_none() {
            for name in &cache.search_path {
                schemas.entry(name.clone()).or_insert_with(|| {
                    SchemaOverlay::Present(crate::model::schema::SchemaState {
                        name: name.clone(),
                        owner: inferred_schema_owner.clone(),
                        generation: 0,
                    })
                });
            }
        }

        let sequences = cache
            .sequences
            .iter()
            .map(|(id, sequence)| (id.clone(), SequenceOverlay::Present(sequence.clone())))
            .collect();
        let baseline_sequences = cache.sequences.keys().cloned().collect();
        for sequence in cache.sequences.values() {
            if let Some((table, column)) = &sequence.owned_by {
                graph.add_edge(DependencyEdge::new(
                    sequence.id.clone(),
                    table.clone(),
                    DependencyKind::SequenceOwnedBy {
                        column: column.clone(),
                    },
                ));
            }
        }

        for (id, rel_state) in cache.baseline_relations() {
            if rel_state.is_fk_dependency {
                baseline_fk_dependencies.insert(id.clone());
            }
            relations.insert(id.clone(), RelationOverlay::Present(rel_state.clone()));
            baseline_relations.insert(id.clone());
        }

        for (id, type_state) in &cache.types {
            types.insert(id.clone(), TypeOverlay::Present(type_state.clone()));
        }
        let type_catalog = types.clone();
        for overlay in relations.values_mut() {
            if let RelationOverlay::Present(relation) = overlay {
                for column in &mut relation.columns {
                    column.type_id = column.data_type.as_deref().and_then(|raw| {
                        Self::resolve_type_reference_from_catalog(
                            raw,
                            &type_catalog,
                            &default_search_path,
                        )
                    });
                }
            }
        }
        for overlay in types.values_mut() {
            if let TypeOverlay::Present(TypeState {
                kind:
                    TypeKind::Domain {
                        base_type,
                        base_type_id,
                    },
                ..
            }) = overlay
            {
                *base_type_id = Self::resolve_type_reference_from_catalog(
                    base_type,
                    &type_catalog,
                    &default_search_path,
                );
            }
        }
        for fk in cache.foreign_keys {
            baseline_foreign_keys.insert((fk.from_table.clone(), fk.constraint_name.clone()));
            graph.add_edge(DependencyEdge::new(
                fk.from_table,
                fk.to_table,
                DependencyKind::ForeignKey {
                    constraint_name: Some(fk.constraint_name),
                    from_columns: Vec::new(),
                    to_columns: Vec::new(),
                    from_generation: 0,
                },
            ));
        }

        for idx in cache.indexes {
            // Index identities are tracked separately from relation identities.
            baseline_indexes.insert(idx.index_id.clone());
            graph.add_edge(DependencyEdge::new(
                idx.index_id,
                idx.table_id,
                DependencyKind::IndexOnRelation {
                    using_method: None,
                    has_predicate: false,
                    is_concurrent: false,
                    is_unique: false,
                    eligibility_known: false,
                },
            ));
        }

        for dependency in cache.dependencies {
            if dependency.deptype != "view" {
                continue;
            }
            let (Some(obj_schema), Some(obj_name), Some(ref_schema), Some(ref_name)) = (
                dependency.obj_schema,
                dependency.obj_name,
                dependency.ref_schema,
                dependency.ref_name,
            ) else {
                continue;
            };
            let dependent = ObjectId::new(obj_schema, obj_name);
            let referenced = ObjectId::new(ref_schema, ref_name);
            // Older caches created on PostgreSQL 14/15 can contain an
            // internal pg_rewrite self-edge for a view. Ignore it while
            // loading so upgrading safe-migrate does not require a re-sync to
            // restore a meaningful dependency graph.
            if dependent == referenced {
                continue;
            }
            let is_view = relations.get(&dependent).is_some_and(|relation| {
                matches!(
                    relation,
                    RelationOverlay::Present(state)
                        if matches!(
                            state.kind,
                            crate::model::relation::RelationKind::View
                                | crate::model::relation::RelationKind::MaterializedView
                    )
                )
            });
            let dependent_schema_is_omitted = baseline_schemas
                .as_ref()
                .is_some_and(|schemas| !schemas.contains(&dependent.schema));
            if is_view || dependent_schema_is_omitted {
                // Scoped caches may intentionally omit the referenced schema.
                // The dependency query can also return a view outside the
                // selected scope when it depends on an in-scope relation.
                // Preserve either direction so a later migration cannot
                // mistake an omitted dependent or referenced object for a
                // safe drop target.
                graph.add_edge(DependencyEdge::new(
                    dependent,
                    referenced,
                    DependencyKind::ViewDependency { view_generation: 0 },
                ));
            }
        }

        for constraint in cache.constraints {
            constraints.insert(
                (constraint.table_id.clone(), constraint.name.clone()),
                constraint,
            );
        }

        for t in cache.triggers {
            let trigger_key = Self::trigger_key(&t.table_id, &t.trigger_id.name);
            triggers.insert(
                trigger_key.clone(),
                TriggerOverlay::Present(crate::model::trigger::TriggerState {
                    name: t.trigger_id.name.clone(),
                    id: trigger_key.clone(),
                    table_id: t.table_id.clone(),
                    enabled_mode: t.enabled_mode,
                    generation: 0,
                }),
            );
            graph.add_edge(DependencyEdge::new(
                trigger_key.clone(),
                t.table_id,
                DependencyKind::TriggerOnTable {
                    trigger_id: trigger_key,
                    function_id: t.function_id,
                },
            ));
        }

        let mut functions: HashMap<ObjectId, crate::model::function::FunctionOverlay> =
            HashMap::new();
        for (id, func_state) in &cache.functions {
            functions.insert(
                id.clone(),
                crate::model::function::FunctionOverlay::Present(func_state.clone()),
            );
        }
        for overlay in functions.values_mut() {
            if let crate::model::function::FunctionOverlay::Present(function) = overlay {
                function.arg_type_ids = function
                    .arg_types
                    .iter()
                    .map(|raw| {
                        Self::resolve_type_reference_from_catalog(
                            raw,
                            &type_catalog,
                            &default_search_path,
                        )
                    })
                    .collect();
                function.return_type_id = Self::resolve_type_reference_from_catalog(
                    &function.return_type,
                    &type_catalog,
                    &default_search_path,
                );
            }
        }

        let publications = cache
            .publications
            .into_iter()
            .map(|(name, publication)| {
                if let crate::analysis::facts::PublicationScope::Explicit(objects) =
                    &publication.scope
                {
                    for object in objects {
                        if let crate::analysis::facts::PublicationObjectFact::Table {
                            name: relation,
                            ..
                        } = object
                        {
                            let table_id = ObjectId::new(
                                relation
                                    .schema
                                    .as_ref()
                                    .map(|schema| schema.resolve())
                                    .unwrap_or_else(|| "public".to_string()),
                                relation.name.resolve(),
                            );
                            graph.add_edge(DependencyEdge::new(
                                table_id,
                                ObjectId::new("public", &name),
                                DependencyKind::PublicationIncludes {
                                    publication_name: name.clone(),
                                },
                            ));
                        }
                    }
                }
                (
                    name,
                    crate::model::replication::PublicationOverlay::Present(publication),
                )
            })
            .collect();
        let subscriptions = cache
            .subscriptions
            .into_iter()
            .map(|(name, subscription)| {
                (
                    name,
                    crate::model::replication::SubscriptionOverlay::Present(subscription),
                )
            })
            .collect();

        let mut state = Self {
            pg_version_num: cache.pg_version_num,
            baseline_available,
            baseline_schemas,
            baseline_relations,
            baseline_indexes,
            baseline_foreign_keys,
            baseline_fk_dependencies,
            baseline_sequences,
            local: LocalState {
                schemas,
                relations,
                types,
                functions,
                sequences,
                publications,
                subscriptions,
                roles: cache
                    .roles
                    .into_iter()
                    .map(|(id, role)| (id, crate::model::role::RoleOverlay::Present(role)))
                    .collect(),
                triggers,
                constraints,
                graph,
                search_path: default_search_path.clone(),
                default_search_path,
                search_path_template: default_search_path_template.clone(),
                session_search_path_template: default_search_path_template.clone(),
                default_search_path_template,
                lock_timeout: ScopedSetting::new(source_lock_timeout),
                statement_timeout: ScopedSetting::new(source_statement_timeout),
                current_role,
                current_role_known,
                persistent_current_role,
                persistent_current_role_known,
                session_role,
                session_role_known,
                persistent_session_role,
                persistent_session_role_known,
                authenticated_role,
                authenticated_role_known,
                roles_known,
                confidence: Confidence::Exact,
                transactions: Vec::new(),
                transaction_aborted: false,
                pending_validation: HashSet::new(),
                generation_counter: 0,
            },
        };
        state.refresh_role_sensitive_search_path();
        state.local.default_search_path = state.local.search_path.clone();
        state
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
            if self.routine_is_present(&candidate) {
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
            if self.relation_namespace_object_is_present(&candidate) {
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

    /// Returns whether a cache-backed absence is authoritative for an object.
    /// A scoped cache only establishes absence in the schemas it actually
    /// synchronized.
    pub fn baseline_covers_object(&self, id: &ObjectId) -> bool {
        self.baseline_schemas
            .as_ref()
            .is_none_or(|schemas| schemas.contains(&id.schema))
    }

    fn relation_lookup(
        &self,
        id: &ObjectId,
        expected: impl FnOnce(&RelationKind) -> bool,
    ) -> ObjectLookup {
        match self.local.relations.get(id) {
            Some(RelationOverlay::Present(relation)) if expected(&relation.kind) => {
                ObjectLookup::Present
            }
            Some(RelationOverlay::Present(_)) => ObjectLookup::WrongKind,
            Some(RelationOverlay::Dropped) => ObjectLookup::Tombstone,
            None if self.sequence_is_present(id) || self.index_is_present(id) => {
                ObjectLookup::WrongKind
            }
            None if self.baseline_available && self.baseline_covers_object(id) => {
                ObjectLookup::AuthoritativelyAbsent
            }
            None => ObjectLookup::Unknown,
        }
    }

    /// Validate a relation reference before a mutation creates a dependent
    /// object.  A scoped baseline cannot prove anything about an omitted
    /// schema, so leave the state conservative instead of inventing an edge.
    pub(super) fn ensure_relation_target<F>(
        &mut self,
        id: &ObjectId,
        expected: F,
        missing_reason: String,
        wrong_kind_reason: String,
    ) -> Result<(), MutationResult>
    where
        F: FnOnce(&RelationKind) -> bool,
    {
        match self.relation_lookup(id, expected) {
            ObjectLookup::Present => Ok(()),
            ObjectLookup::WrongKind => Err(MutationResult::Conflict {
                reason: wrong_kind_reason,
            }),
            ObjectLookup::AuthoritativelyAbsent | ObjectLookup::Tombstone => {
                Err(MutationResult::Conflict {
                    reason: missing_reason,
                })
            }
            ObjectLookup::Unknown => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                Err(MutationResult::Skipped)
            }
        }
    }

    fn type_lookup(&self, id: &ObjectId, expected: impl FnOnce(&TypeKind) -> bool) -> ObjectLookup {
        match self.local.types.get(id) {
            Some(TypeOverlay::Present(state)) if expected(&state.kind) => ObjectLookup::Present,
            Some(TypeOverlay::Present(_)) => ObjectLookup::WrongKind,
            Some(TypeOverlay::Dropped) => ObjectLookup::Tombstone,
            None if self.baseline_available && self.baseline_covers_object(id) => {
                ObjectLookup::AuthoritativelyAbsent
            }
            None => ObjectLookup::Unknown,
        }
    }

    pub(super) fn ensure_routine_target(
        &mut self,
        id: &ObjectId,
        expected: crate::model::function::RoutineKind,
        missing_reason: String,
        wrong_kind_reason: String,
    ) -> Result<(), MutationResult> {
        match self.local.functions.get(id) {
            Some(FunctionOverlay::Present(function)) if function.routine_kind == expected => Ok(()),
            Some(FunctionOverlay::Present(_)) => Err(MutationResult::Conflict {
                reason: wrong_kind_reason,
            }),
            Some(FunctionOverlay::Dropped) => Err(MutationResult::Conflict {
                reason: missing_reason,
            }),
            None if self.baseline_available && self.baseline_covers_object(id) => {
                Err(MutationResult::Conflict {
                    reason: missing_reason,
                })
            }
            None => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                Err(MutationResult::Skipped)
            }
        }
    }

    /// Validate the namespace in which a newly-created object will live.
    ///
    /// A full baseline (or an explicit schema creation earlier in the chain)
    /// can prove that a schema exists.  An omitted scoped schema is unknown;
    /// do not manufacture an object there while claiming an exact result.
    pub(super) fn ensure_schema_target(&mut self, schema: &str) -> Result<(), MutationResult> {
        match self.schema_lookup(schema) {
            ObjectLookup::Present => Ok(()),
            ObjectLookup::Tombstone | ObjectLookup::AuthoritativelyAbsent => {
                Err(MutationResult::Conflict {
                    reason: format!("schema '{}' does not exist", schema),
                })
            }
            ObjectLookup::Unknown => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                Err(MutationResult::Skipped)
            }
            ObjectLookup::WrongKind => {
                unreachable!("schemas do not share an overlay with other object kinds")
            }
        }
    }

    fn snapshot_baseline_foreign_keys(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame
                .undo_log
                .push(StateChange::BaselineForeignKeysSnapshot {
                    previous: self.baseline_foreign_keys.clone(),
                });
        }
    }

    /// Remove constraint metadata and baseline FK identities for objects that
    /// PostgreSQL drops as part of a relation dependency operation.
    pub(super) fn remove_dropped_constraints(
        &mut self,
        dropped_relations: &HashSet<ObjectId>,
        dropped_constraints: &HashSet<(ObjectId, String)>,
    ) {
        let resolution_graph = self.local.graph.clone();
        let should_remove = |table_id: &ObjectId, name: &str| {
            let resolved_table = resolution_graph.resolve_rename(table_id);
            dropped_relations.contains(resolved_table)
                || dropped_constraints.contains(&(resolved_table.clone(), name.to_string()))
        };

        let constraint_keys: Vec<(ObjectId, String)> = self
            .local
            .constraints
            .keys()
            .filter(|(table_id, name)| should_remove(table_id, name))
            .cloned()
            .collect();
        for (table_id, name) in constraint_keys {
            self.snapshot_constraint(&table_id, &name);
            self.local.constraints.remove(&(table_id, name));
        }

        let pending_changed = self
            .local
            .pending_validation
            .iter()
            .any(|(table_id, name)| should_remove(table_id, name));
        if pending_changed {
            self.snapshot_pending_validation();
            self.local
                .pending_validation
                .retain(|(table_id, name)| !should_remove(table_id, name));
        }

        if self
            .baseline_foreign_keys
            .iter()
            .any(|(table_id, name)| should_remove(table_id, name))
        {
            self.snapshot_baseline_foreign_keys();
            self.baseline_foreign_keys
                .retain(|(table_id, name)| !should_remove(table_id, name));
        }
    }

    pub fn baseline_scope_omits_displayed_object<'a>(
        &self,
        object_name: &'a str,
    ) -> Option<&'a str> {
        let schemas = self.baseline_schemas.as_ref()?;
        let (schema, _) = object_name.split_once('.')?;
        (!schemas.contains(schema)).then_some(schema)
    }

    pub(crate) fn sequence_is_present(&self, id: &ObjectId) -> bool {
        matches!(
            self.local.sequences.get(id),
            Some(SequenceOverlay::Present(_))
        )
    }

    pub(crate) fn type_is_present(&self, id: &ObjectId) -> bool {
        matches!(self.local.types.get(id), Some(TypeOverlay::Present(_)))
    }

    pub(crate) fn routine_is_present(&self, id: &ObjectId) -> bool {
        matches!(
            self.local.functions.get(id),
            Some(FunctionOverlay::Present(_))
        )
    }

    fn resolve_type_reference_from_catalog(
        raw: &str,
        types: &HashMap<ObjectId, TypeOverlay>,
        search_path: &[String],
    ) -> Option<ObjectId> {
        let (schema, name) = Self::parse_type_reference(raw)?;
        if let Some(schema) = schema {
            let candidate = ObjectId::new(schema, name);
            return matches!(types.get(&candidate), Some(TypeOverlay::Present(_)))
                .then_some(candidate);
        }
        search_path.iter().find_map(|schema| {
            let candidate = ObjectId::new(schema, &name);
            matches!(types.get(&candidate), Some(TypeOverlay::Present(_))).then_some(candidate)
        })
    }

    /// Parse a SQL type name exactly enough to resolve modeled named types.
    /// Quoted identifiers retain their case, unquoted identifiers fold to
    /// lowercase, and any number of array suffixes are ignored for lookup.
    fn parse_type_reference(raw: &str) -> Option<(Option<String>, String)> {
        let mut token = raw.trim();
        while let Some(without_array) = token.strip_suffix("[]") {
            token = without_array.trim_end();
        }

        let mut parts = Vec::new();
        let mut current = String::new();
        let mut quoted = false;
        let mut part_is_quoted = false;
        let mut chars = token.chars().peekable();
        while let Some(character) = chars.next() {
            match character {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    current.push('"');
                    chars.next();
                }
                '"' => {
                    quoted = !quoted;
                    part_is_quoted = true;
                }
                '.' if !quoted => {
                    parts.push(Self::resolve_type_identifier(&current, part_is_quoted)?);
                    current.clear();
                    part_is_quoted = false;
                }
                character if !quoted && character.is_whitespace() => {}
                character => current.push(character),
            }
        }
        if quoted {
            return None;
        }
        parts.push(Self::resolve_type_identifier(&current, part_is_quoted)?);
        match parts.as_slice() {
            [name] => Some((None, name.clone())),
            [schema, name] => Some((Some(schema.clone()), name.clone())),
            _ => None,
        }
    }

    fn resolve_type_identifier(identifier: &str, quoted: bool) -> Option<String> {
        (!identifier.is_empty()).then(|| {
            if quoted {
                identifier.to_string()
            } else {
                identifier.to_lowercase()
            }
        })
    }

    fn resolve_type_reference(&self, raw: &str) -> Option<ObjectId> {
        Self::resolve_type_reference_from_catalog(raw, &self.local.types, &self.local.search_path)
    }

    fn type_reference_name(id: &ObjectId, qualified: bool) -> String {
        let quote = |identifier: &str| {
            let unquoted = identifier
                .chars()
                .enumerate()
                .all(|(index, character)| match index {
                    0 => character.is_ascii_lowercase() || character == '_',
                    _ => {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '_'
                            || character == '$'
                    }
                });
            if unquoted {
                identifier.to_string()
            } else {
                format!("\"{}\"", identifier.replace('"', "\"\""))
            }
        };

        if qualified {
            format!("{}.{}", quote(&id.schema), quote(&id.name))
        } else {
            quote(&id.name)
        }
    }

    fn remapped_type_display(raw: &str, new_id: &ObjectId, schema_changed: bool) -> String {
        let suffix = raw.find('[').map(|index| &raw[index..]).unwrap_or("");
        format!(
            "{}{}",
            Self::type_reference_name(new_id, schema_changed),
            suffix
        )
    }

    pub(crate) fn index_is_present(&self, id: &ObjectId) -> bool {
        self.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexOnRelation { .. }) && edge.dependent == *id
        })
    }

    pub(crate) fn relation_namespace_object_is_present(&self, id: &ObjectId) -> bool {
        self.relation_is_present(id) || self.sequence_is_present(id) || self.index_is_present(id)
    }

    /// Pick a generated name while also avoiding names reserved by other
    /// constraints in the same CREATE TABLE statement. The ordinary helper
    /// only sees already-applied state, which is not enough for a batch of
    /// inline constraints that becomes visible at the end of the statement.
    pub(super) fn next_generated_constraint_name_avoiding(
        &self,
        table: &ObjectId,
        name1: &str,
        name2: Option<&str>,
        label: &str,
        reserved: &HashSet<String>,
    ) -> String {
        (0..)
            .map(|suffix| {
                let label = if suffix == 0 {
                    label.to_string()
                } else {
                    format!("{label}{suffix}")
                };
                Self::postgres_object_name(name1, name2, &label)
            })
            .find(|candidate| {
                !reserved.contains(candidate)
                    && !self
                        .local
                        .constraints
                        .contains_key(&(table.clone(), candidate.clone()))
            })
            .expect("constraint suffix space is unbounded")
    }

    fn postgres_object_name(name1: &str, name2: Option<&str>, label: &str) -> String {
        const MAX_IDENTIFIER_BYTES: usize = 63;

        fn truncate(value: &str, max_bytes: usize) -> &str {
            let mut end = max_bytes.min(value.len());
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            &value[..end]
        }

        let separators = usize::from(name2.is_some()) + 1;
        let available = MAX_IDENTIFIER_BYTES.saturating_sub(label.len() + separators);
        let mut name1_bytes = name1.len();
        let mut name2_bytes = name2.map_or(0, str::len);
        while name1_bytes + name2_bytes > available {
            if name1_bytes > name2_bytes {
                name1_bytes -= 1;
            } else {
                name2_bytes -= 1;
            }
        }

        let name1 = truncate(name1, name1_bytes);
        match name2 {
            Some(name2) => format!("{name1}_{}_{}", truncate(name2, name2_bytes), label),
            None => format!("{name1}_{label}"),
        }
    }

    fn relation_namespace_is_taken(&self, id: &ObjectId) -> bool {
        self.relation_namespace_object_is_present(id) || self.type_is_present(id)
    }

    fn next_implicit_sequence_id(
        &self,
        table: &ObjectId,
        column: &str,
        reserved: &HashSet<ObjectId>,
    ) -> ObjectId {
        (0..)
            .map(|suffix| {
                let label = if suffix == 0 {
                    "seq".to_string()
                } else {
                    format!("seq{suffix}")
                };
                ObjectId::new(
                    &table.schema,
                    Self::postgres_object_name(&table.name, Some(column), &label),
                )
            })
            .find(|candidate| {
                !reserved.contains(candidate) && !self.relation_namespace_is_taken(candidate)
            })
            .expect("implicit sequence suffix space is unbounded")
    }

    fn sequence_nextval_default(id: &ObjectId) -> crate::analysis::expr_ir::ExprIr {
        crate::analysis::expr_ir::ExprIr::FunctionCall {
            name: "nextval".to_string(),
            args: vec![crate::analysis::expr_ir::ExprIr::Literal(format!(
                "{}.{}",
                id.schema, id.name
            ))],
        }
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
        let mut pre_state = PreState::default();
        self.capture_pre_state_into(&mut pre_state);
        pre_state
    }

    pub(crate) fn capture_pre_state_into(&self, pre_state: &mut PreState) {
        let PreState {
            relations,
            functions,
            roles,
            publications,
            subscriptions,
            sequences,
            types,
            indexes,
            baseline_foreign_keys,
        } = pre_state;

        sync_present_map(relations, &self.local.relations, |overlay| match overlay {
            RelationOverlay::Present(state) => Some(state),
            RelationOverlay::Dropped => None,
        });
        sync_present_map(functions, &self.local.functions, |overlay| match overlay {
            crate::model::function::FunctionOverlay::Present(state) => Some(state),
            crate::model::function::FunctionOverlay::Dropped => None,
        });
        sync_present_map(roles, &self.local.roles, |overlay| match overlay {
            crate::model::role::RoleOverlay::Present(state) => Some(state),
            crate::model::role::RoleOverlay::Dropped => None,
        });
        sync_present_map(
            publications,
            &self.local.publications,
            |overlay| match overlay {
                crate::model::replication::PublicationOverlay::Present(state) => Some(state),
                crate::model::replication::PublicationOverlay::Dropped => None,
            },
        );
        sync_present_map(
            subscriptions,
            &self.local.subscriptions,
            |overlay| match overlay {
                crate::model::replication::SubscriptionOverlay::Present(state) => Some(state),
                crate::model::replication::SubscriptionOverlay::Dropped => None,
            },
        );
        sync_present_map(sequences, &self.local.sequences, |overlay| match overlay {
            SequenceOverlay::Present(state) => Some(state),
            SequenceOverlay::Dropped => None,
        });
        sync_present_map(types, &self.local.types, |overlay| match overlay {
            TypeOverlay::Present(state) => Some(state),
            TypeOverlay::Dropped => None,
        });

        let mut index = 0;
        for edge in self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| matches!(edge.kind, DependencyKind::IndexOnRelation { .. }))
        {
            if let Some(existing) = indexes.get_mut(index) {
                if existing != edge {
                    existing.clone_from(edge);
                }
            } else {
                indexes.push(edge.clone());
            }
            index += 1;
        }
        indexes.truncate(index);
        baseline_foreign_keys.clone_from(&self.baseline_foreign_keys);
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

        if self.local.graph.cascade_index_is_worthwhile() {
            for edge in self.local.graph.cascade_edges(&resolved_current) {
                self.walk_cascade_edge(edge, &resolved_current, visited, result);
            }
        } else {
            for edge in self.local.graph.edges() {
                self.walk_cascade_edge(edge, &resolved_current, visited, result);
            }
        }
    }

    fn walk_cascade_edge(
        &self,
        edge: &DependencyEdge,
        resolved_current: &ObjectId,
        visited: &mut HashSet<ObjectId>,
        result: &mut CascadeResult,
    ) {
        match &edge.kind {
            DependencyKind::ViewDependency { .. } => {
                if self.local.graph.resolve_rename(&edge.referenced) == resolved_current {
                    let resolved_view_id = self.local.graph.resolve_rename(&edge.dependent).clone();
                    if !visited.contains(&resolved_view_id) {
                        self.walk_cascade(&resolved_view_id, visited, result);
                    }
                }
            }
            DependencyKind::IndexOnRelation { .. } => {
                if self.local.graph.resolve_rename(&edge.referenced) == resolved_current {
                    result
                        .dropped_indexes
                        .insert(self.local.graph.resolve_rename(&edge.dependent).clone());
                }
            }
            DependencyKind::ForeignKey {
                constraint_name, ..
            } => {
                if self.local.graph.resolve_rename(&edge.referenced) == resolved_current
                    && let Some(cname) = constraint_name
                {
                    result.dropped_constraints.insert((
                        self.local.graph.resolve_rename(&edge.dependent).clone(),
                        cname.clone(),
                    ));
                }
            }
            DependencyKind::PartitionOf
                if self.local.graph.resolve_rename(&edge.referenced) == resolved_current =>
            {
                let resolved_child = self.local.graph.resolve_rename(&edge.dependent).clone();
                if !visited.contains(&resolved_child) {
                    self.walk_cascade(&resolved_child, visited, result);
                }
            }
            _ => {}
        }
    }

    fn resolve_grant_privileges(
        &self,
        spec: &crate::analysis::facts::PrivilegeSpec,
    ) -> HashSet<Privilege> {
        let supports_maintain = self
            .pg_version_num
            .is_some_and(|version| version >= 180_000);
        match spec {
            crate::analysis::facts::PrivilegeSpec::All => {
                let mut privileges = [
                    Privilege::Select,
                    Privilege::Insert,
                    Privilege::Update,
                    Privilege::Delete,
                    Privilege::Truncate,
                    Privilege::References,
                    Privilege::Trigger,
                ]
                .into_iter()
                .collect::<HashSet<_>>();
                if supports_maintain {
                    privileges.insert(Privilege::Maintain);
                }
                privileges
            }
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
                    crate::analysis::facts::PrivilegeFact::Maintain if supports_maintain => {
                        Some(Privilege::Maintain)
                    }
                    _ => None,
                })
                .collect(),
        }
    }

    fn resolve_role_name(
        role: &crate::analysis::facts::RoleFact,
        current_role: &str,
        session_role: &str,
    ) -> Option<ObjectId> {
        let name = match role {
            crate::analysis::facts::RoleFact::Named { name, .. } => Some(name.clone()),
            crate::analysis::facts::RoleFact::CurrentUser
            | crate::analysis::facts::RoleFact::CurrentRole => Some(current_role.to_string()),
            crate::analysis::facts::RoleFact::SessionUser => Some(session_role.to_string()),
            crate::analysis::facts::RoleFact::Unknown => None,
        }?;
        Some(ObjectId::new("", name))
    }

    fn role_fact_identity(
        &self,
        role: &crate::analysis::facts::RoleFact,
    ) -> Option<(String, bool)> {
        match role {
            crate::analysis::facts::RoleFact::Named { name, .. } => Some((name.clone(), true)),
            crate::analysis::facts::RoleFact::CurrentUser
            | crate::analysis::facts::RoleFact::CurrentRole => Some((
                self.local.current_role.clone(),
                self.local.current_role_known,
            )),
            crate::analysis::facts::RoleFact::SessionUser => Some((
                self.local.session_role.clone(),
                self.local.session_role_known,
            )),
            crate::analysis::facts::RoleFact::Unknown => None,
        }
    }

    fn present_role(&self, name: &str) -> Option<&crate::model::role::RoleState> {
        match self.local.roles.get(&ObjectId::new("", name)) {
            Some(crate::model::role::RoleOverlay::Present(role)) => Some(role),
            _ => None,
        }
    }

    fn can_set_role_to(&self, target: &str) -> Option<bool> {
        if !self.local.roles_known || !self.local.session_role_known {
            return None;
        }
        if self.present_role(target).is_none() {
            return Some(false);
        }
        if self.local.session_role == target {
            return Some(true);
        }
        let session = self.present_role(&self.local.session_role)?;
        if session.is_superuser {
            return Some(true);
        }

        let mut pending = session.can_set_role_to.clone();
        let mut visited = HashSet::new();
        while let Some(role_id) = pending.pop() {
            if !visited.insert(role_id.clone()) {
                continue;
            }
            if role_id.name == target {
                return Some(true);
            }
            if let Some(role) = self.present_role(&role_id.name) {
                pending.extend(role.can_set_role_to.iter().cloned());
            }
        }
        Some(false)
    }

    fn can_set_session_authorization_to(&self, target: &str) -> Option<bool> {
        if !self.local.roles_known || !self.local.authenticated_role_known {
            return None;
        }
        if self.present_role(target).is_none() {
            return Some(false);
        }
        if self.local.authenticated_role == target {
            return Some(true);
        }
        Some(
            self.present_role(&self.local.authenticated_role)
                .is_some_and(|role| role.is_superuser),
        )
    }

    fn schema_is_present(&self, name: &str) -> bool {
        matches!(
            self.local.schemas.get(name),
            Some(SchemaOverlay::Present(_))
        )
    }

    fn schema_lookup(&self, name: &str) -> ObjectLookup {
        match self.local.schemas.get(name) {
            Some(SchemaOverlay::Present(_)) => ObjectLookup::Present,
            Some(SchemaOverlay::Dropped) => ObjectLookup::Tombstone,
            None if self.schema_absence_is_authoritative(name) => {
                ObjectLookup::AuthoritativelyAbsent
            }
            None => ObjectLookup::Unknown,
        }
    }

    fn schema_absence_is_authoritative(&self, name: &str) -> bool {
        if matches!(self.local.schemas.get(name), Some(SchemaOverlay::Dropped)) {
            return true;
        }
        self.baseline_available
            && self
                .baseline_schemas
                .as_ref()
                .is_none_or(|schemas| schemas.contains(name))
    }

    fn refresh_role_sensitive_search_path(&mut self) {
        let template = self.local.search_path_template.clone();
        let mut effective = Vec::new();
        for entry in template {
            let schema = if entry == "$user" {
                if self.local.current_role_known {
                    self.local.current_role.clone()
                } else {
                    self.local.confidence = Confidence::Tainted;
                    continue;
                }
            } else {
                entry
            };
            if self.schema_is_present(&schema) {
                if !effective.contains(&schema) {
                    effective.push(schema);
                }
            } else if !self.schema_absence_is_authoritative(&schema) {
                self.local.confidence = Confidence::Tainted;
                if !effective.contains(&schema) {
                    effective.push(schema);
                }
            }
        }
        self.local.search_path = effective;
    }

    fn remap_schema_id(id: &mut ObjectId, old_name: &str, new_name: &str) {
        if id.schema == old_name {
            id.schema = new_name.to_string();
        }
    }

    fn rename_schema_namespace(&mut self, old_name: &str, new_name: &str) {
        self.snapshot_namespace();

        let mut aliases = Vec::new();
        let mut relations = HashMap::new();
        for (mut id, mut overlay) in std::mem::take(&mut self.local.relations) {
            let old_id = id.clone();
            Self::remap_schema_id(&mut id, old_name, new_name);
            if let RelationOverlay::Present(state) = &mut overlay {
                Self::remap_schema_id(&mut state.id, old_name, new_name);
            }
            if id != old_id {
                aliases.push((old_id, id.clone()));
            }
            relations.insert(id, overlay);
        }
        self.local.relations = relations;

        let mut types = HashMap::new();
        for (mut id, mut overlay) in std::mem::take(&mut self.local.types) {
            let old_id = id.clone();
            Self::remap_schema_id(&mut id, old_name, new_name);
            if let TypeOverlay::Present(state) = &mut overlay {
                Self::remap_schema_id(&mut state.id, old_name, new_name);
            }
            if id != old_id {
                aliases.push((old_id, id.clone()));
            }
            types.insert(id, overlay);
        }
        self.local.types = types;

        let mut functions = HashMap::new();
        for (mut id, mut overlay) in std::mem::take(&mut self.local.functions) {
            let old_id = id.clone();
            Self::remap_schema_id(&mut id, old_name, new_name);
            if let crate::model::function::FunctionOverlay::Present(state) = &mut overlay {
                Self::remap_schema_id(&mut state.id, old_name, new_name);
            }
            if id != old_id {
                aliases.push((old_id, id.clone()));
            }
            functions.insert(id, overlay);
        }
        self.local.functions = functions;

        let mut sequences = HashMap::new();
        for (mut id, mut overlay) in std::mem::take(&mut self.local.sequences) {
            let old_id = id.clone();
            Self::remap_schema_id(&mut id, old_name, new_name);
            if let SequenceOverlay::Present(state) = &mut overlay {
                Self::remap_schema_id(&mut state.id, old_name, new_name);
                if let Some((table, _)) = &mut state.owned_by {
                    Self::remap_schema_id(table, old_name, new_name);
                }
            }
            if id != old_id {
                aliases.push((old_id, id.clone()));
            }
            sequences.insert(id, overlay);
        }
        self.local.sequences = sequences;

        let mut triggers = HashMap::new();
        for (mut id, mut overlay) in std::mem::take(&mut self.local.triggers) {
            let old_id = id.clone();
            Self::remap_schema_id(&mut id, old_name, new_name);
            if let TriggerOverlay::Present(state) = &mut overlay {
                Self::remap_schema_id(&mut state.id, old_name, new_name);
                Self::remap_schema_id(&mut state.table_id, old_name, new_name);
            }
            if id != old_id {
                aliases.push((old_id, id.clone()));
            }
            triggers.insert(id, overlay);
        }
        self.local.triggers = triggers;

        for overlay in self.local.publications.values_mut() {
            let crate::model::replication::PublicationOverlay::Present(publication) = overlay
            else {
                continue;
            };
            let crate::analysis::facts::PublicationScope::Explicit(objects) =
                &mut publication.scope
            else {
                continue;
            };
            for object in objects {
                match object {
                    crate::analysis::facts::PublicationObjectFact::Table { name, .. } => {
                        if name
                            .schema
                            .as_ref()
                            .is_some_and(|schema| schema.resolve() == old_name)
                        {
                            name.schema = Some(crate::ast::identifiers::Ident::new(new_name, true));
                        }
                    }
                    crate::analysis::facts::PublicationObjectFact::SchemaTables {
                        schema, ..
                    } if schema == old_name => *schema = new_name.to_string(),
                    _ => {}
                }
            }
        }

        self.local.constraints = std::mem::take(&mut self.local.constraints)
            .into_iter()
            .map(|((mut table, name), mut constraint)| {
                Self::remap_schema_id(&mut table, old_name, new_name);
                Self::remap_schema_id(&mut constraint.table_id, old_name, new_name);
                ((table, name), constraint)
            })
            .collect();
        self.local.pending_validation = std::mem::take(&mut self.local.pending_validation)
            .into_iter()
            .map(|(mut table, name)| {
                Self::remap_schema_id(&mut table, old_name, new_name);
                (table, name)
            })
            .collect();

        self.local.graph.mutate_edges(|edges| {
            for edge in edges {
                match &mut edge.kind {
                    // Publication nodes are synthetic `public/<name>` IDs;
                    // only the included relation is schema-qualified.
                    DependencyKind::PublicationIncludes { .. } => {
                        Self::remap_schema_id(&mut edge.dependent, old_name, new_name);
                    }
                    DependencyKind::TriggerOnTable {
                        trigger_id,
                        function_id,
                    } => {
                        Self::remap_schema_id(&mut edge.dependent, old_name, new_name);
                        Self::remap_schema_id(&mut edge.referenced, old_name, new_name);
                        Self::remap_schema_id(trigger_id, old_name, new_name);
                        Self::remap_schema_id(function_id, old_name, new_name);
                    }
                    _ => {
                        Self::remap_schema_id(&mut edge.dependent, old_name, new_name);
                        Self::remap_schema_id(&mut edge.referenced, old_name, new_name);
                    }
                }
            }
        });
        for (old_id, new_id) in aliases {
            self.local.graph.add_edge(DependencyEdge::new(
                old_id,
                new_id,
                DependencyKind::RenameTo,
            ));
        }

        let remap_set = |set: &mut HashSet<ObjectId>| {
            *set = std::mem::take(set)
                .into_iter()
                .map(|mut id| {
                    Self::remap_schema_id(&mut id, old_name, new_name);
                    id
                })
                .collect();
        };
        remap_set(&mut self.baseline_relations);
        remap_set(&mut self.baseline_indexes);
        remap_set(&mut self.baseline_fk_dependencies);
        remap_set(&mut self.baseline_sequences);
        self.baseline_foreign_keys = std::mem::take(&mut self.baseline_foreign_keys)
            .into_iter()
            .map(|(mut table, name)| {
                Self::remap_schema_id(&mut table, old_name, new_name);
                (table, name)
            })
            .collect();
        if let Some(schemas) = &mut self.baseline_schemas
            && schemas.remove(old_name)
        {
            schemas.insert(new_name.to_string());
        }

        if let Some(SchemaOverlay::Present(mut schema)) = self.local.schemas.remove(old_name) {
            schema.name = new_name.to_string();
            self.local
                .schemas
                .insert(new_name.to_string(), SchemaOverlay::Present(schema));
        }
        self.refresh_role_sensitive_search_path();
    }

    fn restore_persistent_role_context(&mut self) {
        self.local.current_role = self.local.persistent_current_role.clone();
        self.local.current_role_known = self.local.persistent_current_role_known;
        self.local.session_role = self.local.persistent_session_role.clone();
        self.local.session_role_known = self.local.persistent_session_role_known;
        self.local.search_path_template = self.local.session_search_path_template.clone();
        self.local.lock_timeout.reset_effective_to_session();
        self.local.statement_timeout.reset_effective_to_session();
        self.refresh_role_sensitive_search_path();
    }

    fn apply_grant_to_relation(
        &mut self,
        id: &ObjectId,
        privileges: &HashSet<Privilege>,
        grantees: &[ObjectId],
    ) {
        self.snapshot_relation(id);
        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(id) {
            for grantee in grantees {
                rel.privileges.grant(grantee.clone(), privileges.clone());
            }
        }
    }

    fn apply_revoke_to_relation(
        &mut self,
        id: &ObjectId,
        privileges: &HashSet<Privilege>,
        revokees: &[ObjectId],
    ) {
        self.snapshot_relation(id);
        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(id) {
            for revokee in revokees {
                rel.privileges.revoke(revokee, privileges);
            }
        }
    }

    pub fn apply(
        &mut self,
        mutation: &Mutation,
        precomputed_cascade: Option<&CascadeResult>,
    ) -> MutationResult {
        if self.local.transaction_aborted
            && !matches!(
                mutation,
                Mutation::CommitTransaction
                    | Mutation::CommitAndChain
                    | Mutation::RollbackTransaction
                    | Mutation::RollbackAndChain
                    | Mutation::RollbackToSavepoint(_)
            )
        {
            return MutationResult::NotExecuted;
        }

        let result = self.apply_inner(mutation, precomputed_cascade);
        if matches!(result, MutationResult::Conflict { .. }) && !self.local.transactions.is_empty()
        {
            self.local.transaction_aborted = true;
        }
        result
    }

    fn apply_inner(
        &mut self,
        mutation: &Mutation,
        precomputed_cascade: Option<&CascadeResult>,
    ) -> MutationResult {
        match mutation {
            Mutation::CreateSchema(create_schema) => self.apply_create_schema(create_schema),
            Mutation::AlterSchema(alter_schema) => self.apply_alter_schema(alter_schema),
            Mutation::DropSchema(drop_schema) => self.apply_drop_schema(drop_schema),
            Mutation::DropTable(drop) => self.apply_drop_table(drop, precomputed_cascade),
            Mutation::CreateTable(create) => self.apply_create_table(create),
            Mutation::CreateView(create) => self.apply_create_view(create),
            Mutation::CreateMaterializedView(create) => self.apply_create_materialized_view(create),
            Mutation::RefreshMaterializedView(refresh) => {
                self.apply_refresh_materialized_view(refresh)
            }
            Mutation::CreateIndex(create) => self.apply_create_index(create),
            Mutation::CreatePolicy(create_policy) => self.apply_create_policy(create_policy),
            Mutation::DropPolicy(drop_policy) => self.apply_drop_policy(drop_policy),
            Mutation::CreateTrigger(create_trigger) => self.apply_create_trigger(create_trigger),
            Mutation::DropTrigger(drop_trigger) => self.apply_drop_trigger(drop_trigger),
            Mutation::RenameTrigger(rename_trigger) => self.apply_rename_trigger(rename_trigger),
            Mutation::AlterTable(alter) => self.apply_alter_table(alter),
            Mutation::CreateType(create) => self.apply_create_type(create),
            Mutation::RenameType(rename) => self.apply_rename_type(rename),
            Mutation::AlterType(alter) => self.apply_alter_type(alter),
            Mutation::CreateDomain(create) => self.apply_create_domain(create),
            Mutation::AlterDomain(alter) => self.apply_alter_domain(alter),
            Mutation::DropDomain(drop) => self.apply_drop_domain(drop),
            Mutation::DropType(drop) => self.apply_drop_type(drop),
            Mutation::CreateSequence(create) => self.apply_create_sequence(create),
            Mutation::AlterSequence(alter) => self.apply_alter_sequence(alter),
            Mutation::DropSequence(drop) => self.apply_drop_sequence(drop),
            Mutation::Rename(rename) => self.apply_rename_relation(rename),
            Mutation::DropView(drop) => self.apply_drop_view(drop),
            Mutation::DropMaterializedView(drop) => self.apply_drop_materialized_view(drop),
            Mutation::DropIndex(drop) => self.apply_drop_index(drop),
            Mutation::ChangeRelationOwner { id, new_owner } => {
                self.apply_change_relation_owner(id, new_owner)
            }
            Mutation::SearchPath(search_path) => self.apply_search_path(search_path),
            Mutation::TimeoutSetting(timeout) => self.apply_timeout_setting(timeout),
            Mutation::ResetSettings(target) => self.apply_reset_settings(target),
            Mutation::CheckTimeouts => self.apply_check_timeouts(),
            Mutation::SwitchRole {
                role,
                local,
                is_session_auth,
            } => self.apply_switch_role(role, *local, *is_session_auth),
            Mutation::BeginTransaction => self.apply_begin_transaction(),
            Mutation::CommitTransaction => self.apply_commit_transaction(false),
            Mutation::CommitAndChain => self.apply_commit_transaction(true),
            Mutation::RollbackTransaction => self.apply_rollback_transaction(false),
            Mutation::RollbackAndChain => self.apply_rollback_transaction(true),
            Mutation::RollbackToSavepoint(rollback) => self.apply_rollback_to_savepoint(rollback),
            Mutation::Savepoint(savepoint) => self.apply_savepoint(savepoint),
            Mutation::ReleaseSavepoint(release) => self.apply_release_savepoint(release),
            Mutation::Opaque(opaque) => self.apply_opaque(opaque),
            Mutation::CreateFunction(function) => self.apply_create_function(function),
            Mutation::AlterFunction(function) => self.apply_alter_function(function),
            Mutation::DropFunction(function) => self.apply_drop_function(function),
            Mutation::CreateProcedure(procedure) => self.apply_create_procedure(procedure),
            Mutation::AlterProcedure(procedure) => self.apply_alter_procedure(procedure),
            Mutation::DropProcedure(procedure) => self.apply_drop_procedure(procedure),
            Mutation::CreateAggregate(aggregate) => self.apply_create_aggregate(aggregate),
            Mutation::AlterAggregate(aggregate) => self.apply_alter_aggregate(aggregate),
            Mutation::DropAggregate(aggregate) => self.apply_drop_aggregate(aggregate),
            Mutation::CreatePublication(publication) => self.apply_create_publication(publication),
            Mutation::AlterPublication(publication) => self.apply_alter_publication(publication),
            Mutation::DropPublication(publication) => self.apply_drop_publication(publication),
            Mutation::CreateSubscription(subscription) => {
                self.apply_create_subscription(subscription)
            }
            Mutation::AlterSubscription(subscription) => {
                self.apply_alter_subscription(subscription)
            }
            Mutation::DropSubscription(subscription) => self.apply_drop_subscription(subscription),
            Mutation::CreateRole(role) => self.apply_create_role(role),
            Mutation::AlterRole(role) => self.apply_alter_role(role),
            Mutation::DropRole(role) => self.apply_drop_role(role),
            Mutation::Grant(grant) => self.apply_grant(grant),
            Mutation::Revoke(revoke) => self.apply_revoke(revoke),
            Mutation::CreateDatabase(create_database) => {
                self.apply_create_database(create_database)
            }
            Mutation::AlterDatabase(alter_database) => self.apply_alter_database(alter_database),
            Mutation::DropDatabase(drop_database) => self.apply_drop_database(drop_database),
            Mutation::Vacuum { table_id, is_full } => self.apply_vacuum(table_id, *is_full),
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

    fn snapshot_schema(&mut self, name: &str) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::SchemaSnapshot {
                name: name.to_string(),
                previous: self.local.schemas.get(name).cloned(),
            });
        }
    }

    fn snapshot_namespace(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::NamespaceSnapshot(Box::new(
                NamespaceSnapshot {
                    schemas: self.local.schemas.clone(),
                    relations: self.local.relations.clone(),
                    types: self.local.types.clone(),
                    functions: self.local.functions.clone(),
                    sequences: self.local.sequences.clone(),
                    publications: self.local.publications.clone(),
                    triggers: self.local.triggers.clone(),
                    constraints: self.local.constraints.clone(),
                    graph: self.local.graph.edges().to_vec(),
                    pending_validation: self.local.pending_validation.clone(),
                    baseline_relations: self.baseline_relations.clone(),
                    baseline_indexes: self.baseline_indexes.clone(),
                    baseline_foreign_keys: self.baseline_foreign_keys.clone(),
                    baseline_fk_dependencies: self.baseline_fk_dependencies.clone(),
                    baseline_sequences: self.baseline_sequences.clone(),
                },
            )));
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

    fn move_function(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        self.snapshot_function(old_id);
        self.snapshot_function(new_id);
        if let Some(crate::model::function::FunctionOverlay::Present(mut function)) =
            self.local.functions.remove(old_id)
        {
            function.id = new_id.clone();
            self.local.functions.insert(
                new_id.clone(),
                crate::model::function::FunctionOverlay::Present(function),
            );
        }

        self.snapshot_graph_full();
        self.local.graph.propagate_function_rename(old_id, new_id);
        self.local.graph.add_edge(DependencyEdge::new(
            old_id.clone(),
            new_id.clone(),
            DependencyKind::RenameTo,
        ));
    }

    pub(super) fn validate_function_move(
        &mut self,
        old_id: &ObjectId,
        new_id: &ObjectId,
    ) -> Result<(), MutationResult> {
        if old_id == new_id {
            return Ok(());
        }
        self.ensure_schema_target(&new_id.schema)?;
        match self.local.functions.get(new_id) {
            Some(crate::model::function::FunctionOverlay::Present(_)) => {
                Err(MutationResult::Conflict {
                    reason: format!("routine '{}' already exists", new_id),
                })
            }
            // A prior DROP in this migration leaves a tombstone but the
            // namespace is available again, just as it is in PostgreSQL.
            Some(crate::model::function::FunctionOverlay::Dropped) => Ok(()),
            None => Ok(()),
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

    fn snapshot_constraint(&mut self, table_id: &ObjectId, name: &str) {
        if let Some(frame) = self.local.transactions.last_mut() {
            let key = (table_id.clone(), name.to_string());
            let previous = self.local.constraints.get(&key).cloned();
            frame.undo_log.push(StateChange::ConstraintSnapshot {
                table_id: table_id.clone(),
                name: name.to_string(),
                previous,
            });
        }
    }

    fn snapshot_role_context(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::RoleContextSnapshot {
                current_role: self.local.current_role.clone(),
                current_role_known: self.local.current_role_known,
                persistent_current_role: self.local.persistent_current_role.clone(),
                persistent_current_role_known: self.local.persistent_current_role_known,
                session_role: self.local.session_role.clone(),
                session_role_known: self.local.session_role_known,
                persistent_session_role: self.local.persistent_session_role.clone(),
                persistent_session_role_known: self.local.persistent_session_role_known,
            });
        }
    }

    fn snapshot_search_path(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::SearchPathSnapshot {
                previous: self.local.search_path.clone(),
                previous_template: self.local.search_path_template.clone(),
                previous_session_template: self.local.session_search_path_template.clone(),
            });
        }
    }

    fn snapshot_timeout_settings(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::TimeoutSettingsSnapshot {
                lock_timeout: self.local.lock_timeout.clone(),
                statement_timeout: self.local.statement_timeout.clone(),
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

    fn snapshot_graph(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::GraphLengthMarker {
                len: self.local.graph.edge_count(),
            });
        }
    }

    fn snapshot_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::GraphSnapshot {
                previous: self.local.graph.edges().to_vec(),
            });
        }
    }

    fn rollback_frame(&mut self, mut frame: TransactionFrame) {
        self.rollback_undo_log(std::mem::take(&mut frame.undo_log));
    }

    fn rollback_undo_log(&mut self, mut undo_log: Vec<StateChange>) {
        while let Some(change) = undo_log.pop() {
            match change {
                StateChange::SchemaSnapshot { name, previous } => match previous {
                    Some(overlay) => {
                        self.local.schemas.insert(name, overlay);
                    }
                    None => {
                        self.local.schemas.remove(&name);
                    }
                },
                StateChange::NamespaceSnapshot(snapshot) => {
                    self.local.schemas = snapshot.schemas;
                    self.local.relations = snapshot.relations;
                    self.local.types = snapshot.types;
                    self.local.functions = snapshot.functions;
                    self.local.sequences = snapshot.sequences;
                    self.local.publications = snapshot.publications;
                    self.local.triggers = snapshot.triggers;
                    self.local.constraints = snapshot.constraints;
                    self.local.graph.replace_edges(snapshot.graph);
                    self.local.pending_validation = snapshot.pending_validation;
                    self.baseline_relations = snapshot.baseline_relations;
                    self.baseline_indexes = snapshot.baseline_indexes;
                    self.baseline_foreign_keys = snapshot.baseline_foreign_keys;
                    self.baseline_fk_dependencies = snapshot.baseline_fk_dependencies;
                    self.baseline_sequences = snapshot.baseline_sequences;
                }
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
                StateChange::ConstraintSnapshot {
                    table_id,
                    name,
                    previous,
                } => {
                    let key = (table_id, name);
                    if let Some(previous) = previous {
                        self.local.constraints.insert(key, previous);
                    } else {
                        self.local.constraints.remove(&key);
                    }
                }
                StateChange::BaselineForeignKeysSnapshot { previous } => {
                    self.baseline_foreign_keys = previous;
                }
                StateChange::GraphLengthMarker { len } => {
                    self.local.graph.truncate(len);
                }
                StateChange::GraphSnapshot { previous } => {
                    self.local.graph.replace_edges(previous);
                }
                StateChange::RoleContextSnapshot {
                    current_role,
                    current_role_known,
                    persistent_current_role,
                    persistent_current_role_known,
                    session_role,
                    session_role_known,
                    persistent_session_role,
                    persistent_session_role_known,
                } => {
                    self.local.current_role = current_role;
                    self.local.current_role_known = current_role_known;
                    self.local.persistent_current_role = persistent_current_role;
                    self.local.persistent_current_role_known = persistent_current_role_known;
                    self.local.session_role = session_role;
                    self.local.session_role_known = session_role_known;
                    self.local.persistent_session_role = persistent_session_role;
                    self.local.persistent_session_role_known = persistent_session_role_known;
                }
                StateChange::SearchPathSnapshot {
                    previous,
                    previous_template,
                    previous_session_template,
                } => {
                    self.local.search_path = previous;
                    self.local.search_path_template = previous_template;
                    self.local.session_search_path_template = previous_session_template;
                }
                StateChange::TimeoutSettingsSnapshot {
                    lock_timeout,
                    statement_timeout,
                } => {
                    self.local.lock_timeout = lock_timeout;
                    self.local.statement_timeout = statement_timeout;
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
            }
        }
    }

    pub(crate) fn transaction_undo_checkpoint(&self) -> Option<(usize, usize)> {
        self.local
            .transactions
            .last()
            .map(|frame| (self.local.transactions.len(), frame.undo_log.len()))
    }

    pub(crate) fn rollback_to_transaction_undo_checkpoint(
        &mut self,
        transaction_depth: usize,
        undo_len: usize,
    ) -> Result<(), &'static str> {
        if self.local.transactions.len() != transaction_depth {
            return Err("statement changed transaction depth while using an undo checkpoint");
        }
        let Some(frame) = self.local.transactions.last_mut() else {
            return Err("statement undo checkpoint lost its transaction frame");
        };
        if frame.undo_log.len() < undo_len {
            return Err("statement shortened the transaction undo log unexpectedly");
        }
        let statement_undo = frame.undo_log.split_off(undo_len);
        self.rollback_undo_log(statement_undo);
        Ok(())
    }
}
