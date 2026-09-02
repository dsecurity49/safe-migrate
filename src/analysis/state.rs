use crate::analysis::evidence::{
    EvidenceCode, EvidenceLocation, EvidenceLog, EvidenceRecord, EvidenceScope,
};
use crate::analysis::graph::{DependencyEdge, DependencyGraph, DependencyKind};
use crate::analysis::mutations::Mutation;
use crate::analysis::settings::ScopedSetting;
use crate::analysis::transaction::{NamespaceSnapshot, StateChange, TransactionFrame};
use crate::ast::identifiers::ObjectId;
use crate::db::cache::CatalogCoverage;
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
    pub evidence: EvidenceLog,
    pub current_evidence_location: Option<EvidenceLocation>,
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

struct HydratedRelationTypes {
    relations: HashMap<ObjectId, RelationOverlay>,
    baseline_relations: HashSet<ObjectId>,
    baseline_fk_dependencies: HashSet<ObjectId>,
    types: HashMap<ObjectId, TypeOverlay>,
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
                key_columns: vec!["id".into()],
                included_columns: Vec::new(),
                dependency_columns: vec!["id".into()],
                dependency_columns_known: true,
                has_expression_keys: false,
                has_predicate: false,
                is_concurrent: false,
                is_unique: false,
                is_valid: true,
                is_ready: true,
                is_live: true,
                has_default_sort_order: true,
                has_default_opclasses: true,
                has_default_collations: true,
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
    /// Whether scoped cross-catalog boundary queries were run by the
    /// synchronizer. Programmatic caches lack this provenance and remain
    /// conservative for destructive scoped transitions.
    pub baseline_boundary_queries_complete: bool,
    /// V7 catalog completeness used for authoritative absence decisions.
    /// Family-specific legacy fields remain only while their consumers migrate.
    pub baseline_coverage: CatalogCoverage,
    /// `None` means the cache covered all non-system schemas. A populated set
    /// records an explicitly scoped sync, for which objects outside the set
    /// are unknown rather than known absent.
    pub baseline_schemas: Option<HashSet<String>>,
    pub baseline_relations: HashSet<ObjectId>,
    pub baseline_indexes: HashSet<ObjectId>,
    pub baseline_foreign_keys: HashSet<(ObjectId, String)>,
    pub baseline_fk_dependencies: HashSet<ObjectId>,
    pub baseline_sequences: HashSet<ObjectId>,
    pub scoped_external_relation_dependencies: HashSet<ObjectId>,
    pub scoped_external_type_dependencies: HashSet<ObjectId>,
    pub scoped_external_routine_dependencies: HashSet<ObjectId>,
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
                        None if self.baseline_covers_family_object(
                            &id,
                            crate::db::cache::CatalogFamily::Relations,
                        ) =>
                        {
                            return Err(format!("publication table '{}' does not exist", id));
                        }
                        None => {
                            self.taint(
                                EvidenceCode::CatalogCoverageIncomplete,
                                EvidenceScope::Chain,
                            );
                        }
                    }
                }
                crate::analysis::facts::PublicationObjectFact::SchemaTables { schema, .. } => {
                    if !self.schema_is_present(schema) {
                        if self.schema_absence_is_authoritative(schema) {
                            return Err(format!("publication schema '{}' does not exist", schema));
                        }
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    }
                }
                crate::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand => {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
                crate::analysis::facts::PublicationObjectFact::Unknown => {
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
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
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
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

    /// Construct an authoritative state only from a semantically valid cache.
    pub fn try_new(cache: DbCache) -> Result<Self, String> {
        Ok(Self::new(cache.validated()?))
    }

    /// Hydrate namespace presence independently from the state families that
    /// occupy those namespaces. Relationship records may legitimately retain
    /// an out-of-scope endpoint, so every typed identity contributes schema
    /// evidence before any transition resolver runs.
    fn hydrate_schema_overlays(cache: &DbCache) -> HashMap<String, SchemaOverlay> {
        let mut schemas: HashMap<String, SchemaOverlay> = cache
            .schemas
            .iter()
            .map(|(name, schema)| (name.clone(), SchemaOverlay::Present(schema.clone())))
            .collect();
        let inferred_schema_owner = ObjectId::new(
            "",
            cache.metadata.source_role.as_deref().unwrap_or("postgres"),
        );
        let mut add_schema = |name: &str| {
            schemas.entry(name.to_owned()).or_insert_with(|| {
                SchemaOverlay::Present(crate::model::schema::SchemaState {
                    name: name.to_owned(),
                    owner: inferred_schema_owner.clone(),
                    generation: 0,
                })
            });
        };

        // Effective cached search-path entries and modeled objects are direct
        // evidence that their namespaces existed at synchronization time.
        for name in cache
            .relations
            .keys()
            .map(|id| id.schema.as_str())
            .chain(cache.types.keys().map(|id| id.schema.as_str()))
            .chain(cache.functions.keys().map(|id| id.schema.as_str()))
            .chain(cache.sequences.keys().map(|id| id.schema.as_str()))
            .chain(
                cache
                    .foreign_keys
                    .iter()
                    .flat_map(|fk| [&fk.from_table, &fk.to_table])
                    .map(|id| id.schema.as_str()),
            )
            .chain(
                cache
                    .indexes
                    .iter()
                    .flat_map(|index| [&index.index_id, &index.table_id])
                    .map(|id| id.schema.as_str()),
            )
            .chain(
                cache
                    .dependencies
                    .iter()
                    .flat_map(|dependency| [&dependency.dependent, &dependency.referenced])
                    .map(|id| id.schema.as_str()),
            )
            .chain(
                cache
                    .inheritances
                    .iter()
                    .flat_map(|inheritance| [&inheritance.child, &inheritance.parent])
                    .map(|id| id.schema.as_str()),
            )
            .chain(
                cache
                    .triggers
                    .iter()
                    .map(|trigger| trigger.table_id.schema.as_str()),
            )
            .chain(
                cache
                    .constraints
                    .iter()
                    .map(|constraint| constraint.table_id.schema.as_str()),
            )
            .chain(
                cache
                    .constraint_keys
                    .iter()
                    .map(|key| key.table_id.schema.as_str()),
            )
            .chain(
                cache
                    .constraint_dependencies
                    .iter()
                    .map(|dependency| dependency.table_id.schema.as_str()),
            )
            .chain(
                cache
                    .generated_column_dependencies
                    .iter()
                    .map(|dependency| dependency.table_id.schema.as_str()),
            )
            .chain(
                cache
                    .default_sequence_dependencies
                    .iter()
                    .flat_map(|dependency| [&dependency.table_id, &dependency.sequence_id])
                    .map(|id| id.schema.as_str()),
            )
        {
            add_schema(name);
        }

        // Publication membership can retain an explicitly named table or
        // schema even when the corresponding relation rows are out of scope.
        for publication in cache.publications.values() {
            if let crate::analysis::facts::PublicationScope::Explicit(objects) = &publication.scope
            {
                for object in objects {
                    let schema = match object {
                        crate::analysis::facts::PublicationObjectFact::Table { name, .. } => {
                            name.schema.as_ref().map(|schema| schema.resolve())
                        }
                        crate::analysis::facts::PublicationObjectFact::SchemaTables {
                            schema,
                            ..
                        } => Some(schema.clone()),
                        _ => None,
                    };
                    if let Some(schema) = schema {
                        add_schema(&schema);
                    }
                }
            }
        }
        if cache.schemas.is_empty() && cache.metadata.schemas.is_none() {
            for name in &cache.search_path {
                add_schema(name);
            }
        }
        schemas
    }

    fn hydrate_relation_type_overlays(
        cache: &DbCache,
        search_path: &[String],
    ) -> HydratedRelationTypes {
        let mut relations = HashMap::new();
        let mut baseline_relations = HashSet::new();
        let mut baseline_fk_dependencies = HashSet::new();
        for (id, rel_state) in cache.baseline_relations() {
            if rel_state.is_fk_dependency {
                baseline_fk_dependencies.insert(id.clone());
            }
            relations.insert(id.clone(), RelationOverlay::Present(rel_state.clone()));
            baseline_relations.insert(id.clone());
        }

        let mut types = cache
            .types
            .iter()
            .map(|(id, type_state)| (id.clone(), TypeOverlay::Present(type_state.clone())))
            .collect::<HashMap<_, _>>();
        let type_catalog = types.clone();
        for overlay in relations.values_mut() {
            if let RelationOverlay::Present(relation) = overlay {
                for column in &mut relation.columns {
                    column.type_id = column.data_type.as_deref().and_then(|raw| {
                        Self::resolve_type_reference_from_catalog(raw, &type_catalog, search_path)
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
                    search_path,
                );
            }
        }
        HydratedRelationTypes {
            relations,
            baseline_relations,
            baseline_fk_dependencies,
            types,
        }
    }

    pub fn with_baseline(cache: DbCache, baseline_available: bool) -> Self {
        let baseline_coverage = cache.coverage.clone();
        let baseline_boundary_queries_complete =
            baseline_available && cache.metadata.boundary_queries_complete;
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
        // Role catalog completeness is independent from session provenance.
        // A validated programmatic cache may intentionally omit the source
        // session role while still carrying an authoritative cluster-wide
        // role catalog. Conversely, an unavailable baseline must never make
        // its cached rows authoritative merely because provenance is present.
        let roles_known = baseline_available
            && baseline_coverage.has(crate::db::cache::CatalogFamily::Roles)
            // A hand-built `DbCache::new()` retains the historical broad
            // coverage defaults but has no role rows or provenance. Treat
            // that synthetic empty catalog as unknown; a synchronized
            // PostgreSQL catalog always has at least its authenticated role.
            && (!cache.roles.is_empty() || cache.metadata.source_session_role.is_some());
        let baseline_schemas: Option<HashSet<String>> = cache
            .metadata
            .schemas
            .as_ref()
            .map(|schemas| schemas.iter().cloned().collect());
        let HydratedRelationTypes {
            relations,
            baseline_relations,
            baseline_fk_dependencies,
            types,
        } = Self::hydrate_relation_type_overlays(&cache, &default_search_path);
        let mut baseline_indexes = HashSet::new();
        let mut baseline_foreign_keys = HashSet::new();
        let mut incomplete_fk_operator_evidence = false;
        let mut triggers = HashMap::new();
        let mut constraints = HashMap::new();
        let mut graph = DependencyGraph::new();

        let schemas = Self::hydrate_schema_overlays(&cache);

        let sequences = cache
            .sequences
            .iter()
            .map(|(id, sequence)| (id.clone(), SequenceOverlay::Present(sequence.clone())))
            .collect();
        let baseline_sequences = cache.sequences.keys().cloned().collect();
        let scoped_external_relation_dependencies = cache
            .scoped_external_relation_dependencies
            .iter()
            .cloned()
            .collect();
        let scoped_external_type_dependencies = cache
            .scoped_external_type_dependencies
            .iter()
            .cloned()
            .collect();
        let scoped_external_routine_dependencies = cache
            .scoped_external_routine_dependencies
            .iter()
            .cloned()
            .collect();
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

        let type_catalog = types.clone();
        for fk in cache.foreign_keys {
            baseline_foreign_keys.insert((fk.from_table.clone(), fk.constraint_name.clone()));
            let operator_evidence = if fk.has_complete_operator_evidence() {
                Some(crate::analysis::graph::ForeignKeyOperatorEvidence {
                    pk_fk: fk.pk_fk_equality_operators,
                    pk_pk: fk.pk_pk_equality_operators,
                    fk_fk: fk.fk_fk_equality_operators,
                })
            } else {
                incomplete_fk_operator_evidence = true;
                None
            };
            graph.add_edge(DependencyEdge::new(
                fk.from_table,
                fk.to_table,
                DependencyKind::ForeignKey {
                    constraint_name: Some(fk.constraint_name),
                    from_columns: fk.from_columns,
                    to_columns: fk.to_columns,
                    operator_evidence,
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
                    using_method: Some(idx.using_method),
                    key_columns: idx.key_columns,
                    included_columns: idx.included_columns,
                    dependency_columns: idx.dependency_columns,
                    dependency_columns_known: idx.dependency_columns_known,
                    has_expression_keys: idx.has_expression_keys,
                    has_predicate: idx.has_predicate,
                    is_concurrent: false,
                    is_unique: idx.is_unique,
                    is_valid: idx.is_valid,
                    is_ready: idx.is_ready,
                    is_live: idx.is_live,
                    has_default_sort_order: idx.has_default_sort_order,
                    has_default_opclasses: idx.has_default_opclasses,
                    has_default_collations: idx.has_default_collations,
                    // Eligibility facts are distinct from dependency-column
                    // proof. A catalog row can deterministically prove an
                    // index is ineligible (for example, partial or
                    // expression-based) while dependency columns remain a
                    // separate completeness concern.
                    eligibility_known: true,
                },
            ));
        }

        for dependency in cache.dependencies {
            let dependent = dependency.dependent;
            let referenced = dependency.referenced;
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
                    DependencyKind::ViewDependency {
                        view_generation: 0,
                        referenced_column: dependency.referenced_column,
                    },
                ));
            }
        }

        for inheritance in cache.inheritances {
            // Cache validation rejects a detach-in-progress row, so every
            // hydrated edge represents a stable direct relationship. Keep
            // cross-scope endpoints too: they are evidence that an in-scope
            // destructive change may have an omitted dependent.
            graph.add_edge(DependencyEdge::new(
                inheritance.child,
                inheritance.parent,
                if inheritance.is_partition {
                    DependencyKind::PartitionOf
                } else {
                    DependencyKind::InheritanceOf
                },
            ));
        }

        for constraint in cache.constraints {
            constraints.insert(
                (constraint.table_id.clone(), constraint.name.clone()),
                constraint,
            );
        }
        for key in cache.constraint_keys {
            graph.add_edge(DependencyEdge::new(
                key.table_id.clone(),
                key.table_id,
                DependencyKind::ConstraintOnRelation {
                    constraint_name: key.constraint_name,
                    columns: key.columns,
                    is_primary: key.is_primary,
                },
            ));
        }
        for dependency in cache.constraint_dependencies {
            graph.add_edge(DependencyEdge::new(
                dependency.table_id.clone(),
                dependency.table_id,
                DependencyKind::ConstraintDependency {
                    constraint_name: dependency.constraint_name,
                    columns: dependency.columns,
                },
            ));
        }

        for dependency in cache.generated_column_dependencies {
            graph.add_edge(DependencyEdge::new(
                dependency.table_id.clone(),
                dependency.table_id,
                DependencyKind::ColumnGeneratedFrom {
                    column: dependency.column_name,
                    depends_on_column: dependency.depends_on_column,
                },
            ));
        }

        for dependency in cache.default_sequence_dependencies {
            graph.add_edge(DependencyEdge::new(
                dependency.table_id,
                dependency.sequence_id,
                DependencyKind::ColumnDefaultOnSequence {
                    column: dependency.column_name,
                },
            ));
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
                    trigger_generation: 0,
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
            baseline_boundary_queries_complete,
            baseline_coverage,
            baseline_schemas,
            baseline_relations,
            baseline_indexes,
            baseline_foreign_keys,
            baseline_fk_dependencies,
            baseline_sequences,
            scoped_external_relation_dependencies,
            scoped_external_type_dependencies,
            scoped_external_routine_dependencies,
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
                evidence: EvidenceLog::default(),
                current_evidence_location: None,
                transactions: Vec::new(),
                transaction_aborted: false,
                pending_validation: HashSet::new(),
                generation_counter: 0,
            },
        };
        state.refresh_role_sensitive_search_path();
        state.local.default_search_path = state.local.search_path.clone();
        if baseline_available && incomplete_fk_operator_evidence {
            state.taint(
                crate::analysis::evidence::EvidenceCode::CatalogCoverageIncomplete,
                crate::analysis::evidence::EvidenceScope::Chain,
            );
        }
        state
    }

    /// Construct state from a cache after validating its cross-record
    /// invariants, preserving the requested baseline-availability flag.
    pub fn try_with_baseline(cache: DbCache, baseline_available: bool) -> Result<Self, String> {
        Ok(Self::with_baseline(cache.validated()?, baseline_available))
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

    /// Returns the effective PostgreSQL version used for semantic decisions.
    /// A synchronized cache supplies the authoritative version; callers pass
    /// their configured fallback for cache-free analysis.
    pub(crate) fn effective_pg_version_num(&self, fallback: u32) -> u32 {
        self.pg_version_num.unwrap_or(fallback)
    }

    /// Read-only search-path view for name resolution. Keeping resolution on
    /// this accessor prevents callers from coupling themselves to `LocalState`.
    pub(crate) fn search_path(&self) -> &[String] {
        &self.local.search_path
    }

    /// Returns whether a cache-backed absence is authoritative for an object.
    /// A scoped cache only establishes absence in the schemas it actually
    /// synchronized.
    pub fn baseline_covers_object(&self, id: &ObjectId) -> bool {
        // V7 validation requires these scopes to agree. Keep the legacy
        // metadata intersection while direct in-process cache construction is
        // supported, so a caller cannot accidentally turn an explicitly
        // scoped baseline into global absence knowledge by omitting coverage.
        self.baseline_available
            && self.baseline_coverage.schema_scope.covers(&id.schema)
            && self
                .baseline_schemas
                .as_ref()
                .is_none_or(|schemas| schemas.contains(&id.schema))
    }

    /// Returns whether the requested catalog family can authoritatively
    /// answer about an object. Schema scope alone is insufficient: a V7 cache
    /// may intentionally omit one family while retaining rows from another.
    pub(crate) fn baseline_covers_family_object(
        &self,
        id: &ObjectId,
        family: crate::db::cache::CatalogFamily,
    ) -> bool {
        self.baseline_covers_object(id) && self.baseline_coverage.has(family)
    }

    /// Read-only semantic views used by rules instead of exposing the
    /// family-specific baseline storage representation.
    pub(crate) fn baseline_relation_is_known(&self, id: &ObjectId) -> bool {
        self.baseline_relations.contains(id)
    }

    pub(crate) fn baseline_fk_dependency_is_known(&self, id: &ObjectId) -> bool {
        self.baseline_fk_dependencies.contains(id)
    }

    pub(crate) fn baseline_is_available(&self) -> bool {
        self.baseline_available
    }

    pub(crate) fn baseline_has_coverage(&self, family: crate::db::cache::CatalogFamily) -> bool {
        self.baseline_coverage.has(family)
    }

    /// A schema-scoped baseline cannot prove that cross-schema dependents were
    /// absent unless the relevant catalog loader explicitly includes them.
    /// Destructive transitions for families whose dependency queries are not
    /// yet scope-complete must therefore remain conservative.  This helper
    /// also requires family authority, so local objects and unavailable
    /// baselines are not accidentally treated as scoped catalog rows.
    pub(crate) fn baseline_scoped_family_object(
        &self,
        id: &ObjectId,
        family: crate::db::cache::CatalogFamily,
    ) -> bool {
        if self.baseline_schemas.is_none() || !self.baseline_covers_family_object(id, family) {
            return false;
        }
        // A scoped cache created programmatically has no proof that the
        // cross-scope boundary queries ran. Keep it conservative even when
        // the external-dependency list is empty; an empty list is meaningful
        // only for a synchronized cache with provenance metadata.
        if !self.baseline_boundary_queries_complete {
            return true;
        }
        if matches!(family, crate::db::cache::CatalogFamily::Relations) {
            return self.scoped_external_relation_dependencies.contains(id);
        }
        if matches!(family, crate::db::cache::CatalogFamily::Types) {
            return self.scoped_external_type_dependencies.contains(id);
        }
        if matches!(family, crate::db::cache::CatalogFamily::Routines) {
            return self.scoped_external_routine_dependencies.contains(id);
        }
        true
    }

    pub(crate) fn transaction_depth(&self) -> usize {
        self.local.transactions.len()
    }

    pub(crate) fn in_transaction(&self) -> bool {
        self.transaction_depth() > 0
    }

    pub(crate) fn effective_lock_timeout(&self) -> Option<u64> {
        self.local.lock_timeout.effective
    }

    pub(crate) fn effective_statement_timeout(&self) -> Option<u64> {
        self.local.statement_timeout.effective
    }

    pub(crate) fn has_usable_unique_index(&self, relation_id: &ObjectId) -> bool {
        self.local.graph.edges().iter().any(|edge| {
            if let crate::analysis::graph::DependencyKind::IndexOnRelation {
                is_unique,
                has_expression_keys,
                has_predicate,
                is_valid,
                is_ready,
                is_live,
                eligibility_known,
                ..
            } = &edge.kind
            {
                edge.referenced == *relation_id
                    && *eligibility_known
                    && *is_unique
                    && !*has_expression_keys
                    && !*has_predicate
                    && *is_valid
                    && *is_ready
                    && *is_live
            } else {
                false
            }
        })
    }

    pub(crate) fn relation_is_owned_by(&self, relation_id: &ObjectId, owner: &str) -> bool {
        matches!(
            self.local.relations.get(relation_id),
            Some(RelationOverlay::Present(relation)) if relation.owner.name == owner
        )
    }

    pub(crate) fn transaction_is_aborted(&self) -> bool {
        self.local.transaction_aborted
    }

    pub(crate) fn mark_transaction_aborted(&mut self) {
        self.local.transaction_aborted = true;
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
            None if self
                .baseline_covers_family_object(id, crate::db::cache::CatalogFamily::Relations) =>
            {
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
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                Err(MutationResult::Skipped)
            }
        }
    }

    fn type_lookup(&self, id: &ObjectId, expected: impl FnOnce(&TypeKind) -> bool) -> ObjectLookup {
        match self.local.types.get(id) {
            Some(TypeOverlay::Present(state)) if expected(&state.kind) => ObjectLookup::Present,
            Some(TypeOverlay::Present(_)) => ObjectLookup::WrongKind,
            Some(TypeOverlay::Dropped) => ObjectLookup::Tombstone,
            None if self
                .baseline_covers_family_object(id, crate::db::cache::CatalogFamily::Types) =>
            {
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
            None if self
                .baseline_covers_family_object(id, crate::db::cache::CatalogFamily::Routines) =>
            {
                Err(MutationResult::Conflict {
                    reason: missing_reason,
                })
            }
            None => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
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
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
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

    /// Dependency edges that carry an object generation are only valid while
    /// their dependent relation is the same incarnation that created the edge.
    /// A drop/recreate sequence must not inherit view/FK metadata from the
    /// previous incarnation. Baseline rows use generation zero and are
    /// validated the same way. An absent overlay is deliberately treated as
    /// unknown rather than stale so scoped-cache omissions remain conservative
    /// and can still produce the existing catalog-coverage evidence.
    fn dependency_edge_is_current(&self, edge: &DependencyEdge) -> bool {
        let (generation, dependent) = match &edge.kind {
            DependencyKind::ForeignKey {
                from_generation, ..
            } => (*from_generation, &edge.dependent),
            DependencyKind::ViewDependency {
                view_generation, ..
            } => (*view_generation, &edge.dependent),
            DependencyKind::TriggerOnTable {
                trigger_generation,
                trigger_id,
                ..
            } => (*trigger_generation, trigger_id),
            _ => return true,
        };
        let resolved_dependent = self.local.graph.resolve_rename(dependent);
        match &edge.kind {
            DependencyKind::TriggerOnTable { .. } => {
                match self.local.triggers.get(resolved_dependent) {
                    Some(TriggerOverlay::Present(trigger)) => trigger.generation == generation,
                    Some(TriggerOverlay::Dropped) => false,
                    None => true,
                }
            }
            _ => match self.local.relations.get(resolved_dependent) {
                Some(RelationOverlay::Present(relation)) => relation.generation == generation,
                Some(RelationOverlay::Dropped) => false,
                None => true,
            },
        }
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
        if !self.dependency_edge_is_current(edge) {
            return;
        }
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
            DependencyKind::InheritanceOf | DependencyKind::PartitionOf
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
            .is_some_and(|version| version >= 170_000);
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

    /// Resolve a direct or inherited relation privilege for a role.  ACL
    /// rows are direct grants; PostgreSQL only exposes them through a role's
    /// membership edges when the role has INHERIT and that edge carries the
    /// INHERIT option.  Unknown role catalogs deliberately return `None` so
    /// callers cannot turn an incomplete cache into an exact authorization
    /// decision.
    fn effective_relation_privilege(
        &self,
        relation: &crate::model::relation::RelationState,
        role: &ObjectId,
        privilege: Privilege,
        grant_option: bool,
    ) -> Option<bool> {
        if !self.local.roles_known {
            return None;
        }
        let mut pending = vec![role.clone()];
        let mut visited = HashSet::new();
        while let Some(candidate) = pending.pop() {
            if !visited.insert(candidate.clone()) {
                continue;
            }
            if if grant_option {
                relation
                    .privileges
                    .has_direct_grant_option(&candidate, privilege)
            } else {
                relation
                    .privileges
                    .has_direct_privilege(&candidate, privilege)
            } {
                return Some(true);
            }
            let role_state = self.present_role(&candidate.name)?;
            if !role_state.inherits && candidate == *role {
                continue;
            }
            if role_state.inherits {
                pending.extend(role_state.can_inherit_from.iter().cloned());
            }
        }
        Some(false)
    }

    fn grantor_identity(
        &self,
        granted_by: Option<&crate::analysis::facts::RoleFact>,
    ) -> Option<ObjectId> {
        granted_by
            .and_then(|fact| {
                self.role_fact_identity(fact)
                    .map(|(name, _)| ObjectId::new("", name))
            })
            .or_else(|| {
                self.local
                    .current_role_known
                    .then(|| ObjectId::new("", self.local.current_role.clone()))
            })
    }

    fn authorize_relation_grant(
        &self,
        relation: &crate::model::relation::RelationState,
        privileges: &HashSet<Privilege>,
        grantor: Option<&ObjectId>,
    ) -> Option<bool> {
        let grantor = grantor?;
        let role = self.present_role(&grantor.name)?;
        if role.is_superuser || relation.owner == *grantor {
            return Some(true);
        }
        for privilege in privileges {
            if self.effective_relation_privilege(relation, grantor, *privilege, true) != Some(true)
            {
                return Some(false);
            }
        }
        Some(true)
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
                .baseline_coverage
                .has(crate::db::cache::CatalogFamily::Schemas)
            && self
                .baseline_schemas
                .as_ref()
                .is_none_or(|schemas| schemas.contains(name))
    }

    fn refresh_role_sensitive_search_path(&mut self) {
        let template = self.local.search_path_template.clone();
        let mut effective = Vec::new();
        let mut role_identity_unknown = false;
        let mut schema_state_unknown = false;
        for entry in template {
            let schema = if entry == "$user" {
                if self.local.current_role_known {
                    self.local.current_role.clone()
                } else {
                    role_identity_unknown = true;
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
                schema_state_unknown = true;
                if !effective.contains(&schema) {
                    effective.push(schema);
                }
            }
        }
        self.local.search_path = effective;
        if role_identity_unknown {
            self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
        }
        if schema_state_unknown {
            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
        }
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

        self.local.graph.remap_schema_namespace(old_name, new_name);
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
        remap_set(&mut self.scoped_external_relation_dependencies);
        remap_set(&mut self.scoped_external_type_dependencies);
        remap_set(&mut self.scoped_external_routine_dependencies);
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
            // A rename proves the old namespace is absent for the rest of the
            // chain. Retain that fact explicitly: removing the entry makes an
            // old name outside a scoped baseline look unknown, which can keep
            // it in search_path and prevent an exact recreate.
            self.local
                .schemas
                .insert(old_name.to_string(), SchemaOverlay::Dropped);
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
        with_grant_option: bool,
        grantor: Option<ObjectId>,
    ) {
        self.snapshot_relation(id);
        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(id) {
            for grantee in grantees {
                if with_grant_option {
                    rel.privileges.grant_from(
                        grantee.clone(),
                        privileges.clone(),
                        grantor.clone(),
                        true,
                    );
                } else {
                    rel.privileges.grant_from(
                        grantee.clone(),
                        privileges.clone(),
                        grantor.clone(),
                        false,
                    );
                }
            }
        }
    }

    fn apply_revoke_to_relation(
        &mut self,
        id: &ObjectId,
        privileges: &HashSet<Privilege>,
        revokees: &[ObjectId],
        grant_option_only: bool,
        grantor: Option<&ObjectId>,
        cascade: bool,
    ) {
        self.snapshot_relation(id);
        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(id) {
            for revokee in revokees {
                if grant_option_only {
                    rel.privileges
                        .revoke_grant_option_from(revokee, privileges, grantor);
                } else {
                    rel.privileges
                        .revoke_from_cascade(revokee, privileges, grantor, cascade);
                }
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
        // Keep the derived dependency indexes inside their invariant boundary
        // while the state-delta migration is in progress. This is debug-only
        // and therefore does not add release overhead, but catches a missed
        // invalidation immediately after the transition that caused it.
        debug_assert!(self.local.graph.indexes_are_valid());
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
                    scoped_external_relation_dependencies: self
                        .scoped_external_relation_dependencies
                        .clone(),
                    scoped_external_type_dependencies: self
                        .scoped_external_type_dependencies
                        .clone(),
                    scoped_external_routine_dependencies: self
                        .scoped_external_routine_dependencies
                        .clone(),
                    baseline_schemas: self.baseline_schemas.clone(),
                    search_path: self.local.search_path.clone(),
                    search_path_template: self.local.search_path_template.clone(),
                    session_search_path_template: self.local.session_search_path_template.clone(),
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

    fn snapshot_evidence(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::EvidenceSnapshot {
                previous: self.local.evidence.clone(),
            });
        }
    }

    /// Adds conservative-analysis evidence and marks later chain state tainted.
    pub fn record_evidence(&mut self, mut record: EvidenceRecord) {
        if record.location.is_none() {
            record.location = self.local.current_evidence_location.clone();
        }
        if self.local.evidence.contains(&record) {
            return;
        }
        self.snapshot_evidence();
        if self.local.confidence != Confidence::Tainted {
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
        }
        self.local.evidence.insert(record);
    }

    pub(crate) fn taint(&mut self, code: EvidenceCode, scope: EvidenceScope) {
        self.record_evidence(EvidenceRecord::new(code, scope));
    }

    pub(crate) fn set_evidence_location(&mut self, location: Option<EvidenceLocation>) {
        self.local.current_evidence_location = location;
    }

    pub fn evidence(&self) -> &[EvidenceRecord] {
        self.local.evidence.records()
    }

    pub fn confidence(&self) -> &Confidence {
        &self.local.confidence
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
                    self.scoped_external_relation_dependencies =
                        snapshot.scoped_external_relation_dependencies;
                    self.scoped_external_type_dependencies =
                        snapshot.scoped_external_type_dependencies;
                    self.scoped_external_routine_dependencies =
                        snapshot.scoped_external_routine_dependencies;
                    self.baseline_schemas = snapshot.baseline_schemas;
                    self.local.search_path = snapshot.search_path;
                    self.local.search_path_template = snapshot.search_path_template;
                    self.local.session_search_path_template = snapshot.session_search_path_template;
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
                StateChange::EvidenceSnapshot { previous } => {
                    self.local.evidence = previous;
                }
            }
        }
        debug_assert!(self.local.graph.indexes_are_valid());
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
        debug_assert!(self.local.graph.indexes_are_valid());
        Ok(())
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;
    use crate::analysis::evidence::{EvidenceCode, EvidenceRecord, EvidenceScope};

    fn table_with_columns(id: ObjectId, columns: &[&str]) -> crate::model::relation::RelationState {
        let mut relation = crate::model::relation::RelationState::new(
            id,
            ObjectId::new("", "postgres"),
            0,
            None,
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        relation.columns = columns
            .iter()
            .map(|name| crate::model::column::Column {
                name: (*name).to_string(),
                data_type: Some("integer".to_string()),
                type_id: None,
                is_nullable: false,
                default: None,
                avg_width: Some(4),
                default_expr_text: None,
                type_modifier: None,
            })
            .collect();
        relation
    }

    #[test]
    fn evidence_added_in_a_transaction_rolls_back_with_confidence() {
        let mut state = AnalysisState::new(DbCache::new());
        state.apply(&Mutation::BeginTransaction, None);
        state.record_evidence(EvidenceRecord::new(
            EvidenceCode::CatalogCoverageIncomplete,
            EvidenceScope::Chain,
        ));

        assert_eq!(state.local.confidence, Confidence::Tainted);
        assert_eq!(state.evidence().len(), 1);

        state.apply(&Mutation::RollbackTransaction, None);
        assert_eq!(state.local.confidence, Confidence::Exact);
        assert!(state.evidence().is_empty());
    }

    #[test]
    fn invalid_transaction_control_records_typed_evidence() {
        let mut state = AnalysisState::new(DbCache::new());
        let result = state.apply(
            &Mutation::Savepoint(crate::analysis::mutations::SavepointMutation {
                name: "before_change".to_string(),
            }),
            None,
        );

        assert!(matches!(result, MutationResult::Conflict { .. }));
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| record.code == EvidenceCode::TransactionStateUnknown)
        );
    }

    #[test]
    fn scoped_schema_lookup_records_unknown_object_evidence() {
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["public".to_string()]);
        cache.coverage = CatalogCoverage::from_sync_scope(cache.metadata.schemas.as_deref());
        let mut state = AnalysisState::new(cache);
        let result = state.apply(
            &Mutation::CreateSchema(crate::analysis::mutations::CreateSchemaMutation {
                name: "outside_scope".to_string(),
                if_not_exists: false,
                authorization: None,
            }),
            None,
        );

        assert_eq!(result, MutationResult::Skipped);
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| record.code == EvidenceCode::UnknownObjectState)
        );
    }

    #[test]
    fn schema_absence_requires_schema_catalog_coverage() {
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["public".to_string()]);
        cache.coverage = CatalogCoverage::from_sync_scope(cache.metadata.schemas.as_deref());
        cache
            .coverage
            .families
            .remove(&crate::db::cache::CatalogFamily::Schemas);
        let mut state = AnalysisState::new(cache);

        let result = state.apply(
            &Mutation::CreateSchema(crate::analysis::mutations::CreateSchemaMutation {
                name: "public".to_string(),
                if_not_exists: false,
                authorization: None,
            }),
            None,
        );

        assert_eq!(result, MutationResult::Skipped);
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| { record.code == EvidenceCode::UnknownObjectState })
        );
    }

    #[test]
    fn role_inherit_option_is_preserved_across_mutations() {
        let mut state = AnalysisState::new(DbCache::new());
        let role_id = ObjectId::new("", "no_inherit");
        let create = Mutation::CreateRole(crate::analysis::mutations::CreateRoleMutation {
            name: role_id.name.clone(),
            inherits: false,
            can_login: false,
        });
        assert_eq!(state.apply(&create, None), MutationResult::Applied);
        let Some(crate::model::role::RoleOverlay::Present(role)) = state.local.roles.get(&role_id)
        else {
            panic!("expected role to be present");
        };
        assert!(!role.inherits);

        let alter = Mutation::AlterRole(crate::analysis::mutations::AlterRoleMutation {
            name: crate::analysis::facts::RoleFact::Named {
                name: role_id.name.clone(),
                via_legacy_group_syntax: false,
            },
            inherits: Some(true),
        });
        assert_eq!(state.apply(&alter, None), MutationResult::Applied);
        let Some(crate::model::role::RoleOverlay::Present(role)) = state.local.roles.get(&role_id)
        else {
            panic!("expected role to remain present");
        };
        assert!(role.inherits);
    }

    #[test]
    fn relation_absence_requires_relation_catalog_coverage() {
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["public".to_string()]);
        cache.coverage = CatalogCoverage::from_sync_scope(cache.metadata.schemas.as_deref());
        cache
            .coverage
            .families
            .remove(&crate::db::cache::CatalogFamily::Relations);
        let mut state = AnalysisState::new(cache);
        let result = state.apply(
            &Mutation::DropTable(crate::analysis::mutations::DropTable {
                ids: vec![ObjectId::new("public", "missing")],
                if_exists: false,
                cascade: false,
            }),
            None,
        );

        assert_eq!(result, MutationResult::Skipped);
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| { record.code == EvidenceCode::UnknownObjectState })
        );
    }

    #[test]
    fn baseline_drop_requires_dependency_catalog_coverage() {
        let table_id = ObjectId::new("public", "known_table");
        let mut cache = DbCache::new();
        cache.insert_baseline(
            table_id.clone(),
            table_with_columns(table_id.clone(), &["id"]),
        );
        cache
            .coverage
            .families
            .remove(&crate::db::cache::CatalogFamily::Dependencies);
        let mut state = AnalysisState::new(cache);

        let result = state.apply(
            &Mutation::DropTable(crate::analysis::mutations::DropTable {
                ids: vec![table_id],
                if_exists: false,
                cascade: false,
            }),
            None,
        );

        assert_eq!(result, MutationResult::Skipped);
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| { record.code == EvidenceCode::CatalogCoverageIncomplete })
        );
    }

    #[test]
    fn scoped_boundary_authority_requires_explicit_completion_marker() {
        let table_id = ObjectId::new("app", "known_table");
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["app".to_string()]);
        cache.metadata.created_at_unix_secs = Some(1);
        cache.insert_baseline(
            table_id.clone(),
            table_with_columns(table_id.clone(), &["id"]),
        );

        let state = AnalysisState::with_baseline(cache.clone(), true);
        assert!(
            state.baseline_scoped_family_object(
                &table_id,
                crate::db::cache::CatalogFamily::Relations
            )
        );

        cache.metadata.boundary_queries_complete = true;
        let state = AnalysisState::with_baseline(cache, true);
        assert!(
            !state.baseline_scoped_family_object(
                &table_id,
                crate::db::cache::CatalogFamily::Relations
            )
        );
    }

    #[test]
    fn local_drop_cascade_requires_dependency_coverage_for_baseline_dependents() {
        let parent = ObjectId::new("public", "new_parent");
        let child = ObjectId::new("public", "baseline_child");
        let mut cache = DbCache::new();
        cache.insert_baseline(
            child.clone(),
            table_with_columns(child.clone(), &["parent_id"]),
        );
        cache
            .coverage
            .families
            .remove(&crate::db::cache::CatalogFamily::Dependencies);
        let mut state = AnalysisState::new(cache);
        state
            .baseline_foreign_keys
            .insert((child.clone(), "baseline_child_parent_fkey".to_string()));
        state.local.relations.insert(
            parent.clone(),
            RelationOverlay::Present(table_with_columns(parent.clone(), &["id"])),
        );
        state.local.graph.add_edge(DependencyEdge::new(
            child.clone(),
            parent.clone(),
            DependencyKind::ForeignKey {
                constraint_name: Some("baseline_child_parent_fkey".to_string()),
                from_columns: vec!["parent_id".to_string()],
                to_columns: vec!["id".to_string()],
                operator_evidence: None,
                from_generation: 0,
            },
        ));

        let result = state.apply(
            &Mutation::DropTable(crate::analysis::mutations::DropTable {
                ids: vec![parent],
                if_exists: false,
                cascade: true,
            }),
            None,
        );
        assert_eq!(result, MutationResult::Skipped);
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| { record.code == EvidenceCode::CatalogCoverageIncomplete })
        );
        assert!(state.relation_is_present(&child));
    }

    #[test]
    fn baseline_sequence_drop_requires_dependency_coverage() {
        let sequence_id = ObjectId::new("public", "known_sequence");
        let mut cache = DbCache::new();
        cache.sequences.insert(
            sequence_id.clone(),
            crate::model::sequence::SequenceState {
                id: sequence_id.clone(),
                owner: ObjectId::new("", "postgres"),
                owned_by: None,
                kind: crate::model::sequence::SequenceKind::Standalone,
                generation: 0,
            },
        );
        cache
            .coverage
            .families
            .remove(&crate::db::cache::CatalogFamily::Dependencies);
        let mut state = AnalysisState::new(cache);

        let result = state.apply(
            &Mutation::DropSequence(crate::analysis::mutations::DropSequenceMutation {
                ids: vec![sequence_id.clone()],
                if_exists: false,
                cascade: false,
            }),
            None,
        );
        assert_eq!(result, MutationResult::Skipped);
        assert!(matches!(
            state.local.sequences.get(&sequence_id),
            Some(SequenceOverlay::Present(_))
        ));
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| { record.code == EvidenceCode::CatalogCoverageIncomplete })
        );
    }

    #[test]
    fn scoped_baseline_sequence_drop_requires_cross_schema_dependency_proof() {
        let sequence_id = ObjectId::new("public", "scoped_sequence");
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["public".to_string()]);
        cache.coverage = CatalogCoverage::from_sync_scope(cache.metadata.schemas.as_deref());
        cache.sequences.insert(
            sequence_id.clone(),
            crate::model::sequence::SequenceState {
                id: sequence_id.clone(),
                owner: ObjectId::new("", "postgres"),
                owned_by: None,
                kind: crate::model::sequence::SequenceKind::Standalone,
                generation: 0,
            },
        );
        let mut state = AnalysisState::new(cache);
        let result = state.apply(
            &Mutation::DropSequence(crate::analysis::mutations::DropSequenceMutation {
                ids: vec![sequence_id.clone()],
                if_exists: false,
                cascade: false,
            }),
            None,
        );
        assert_eq!(result, MutationResult::Skipped);
        assert!(matches!(
            state.local.sequences.get(&sequence_id),
            Some(SequenceOverlay::Present(_))
        ));
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| record.code == EvidenceCode::CatalogCoverageIncomplete)
        );
    }

    #[test]
    fn baseline_drop_column_requires_dependency_coverage() {
        let table_id = ObjectId::new("public", "known_table");
        let mut cache = DbCache::new();
        cache.insert_baseline(
            table_id.clone(),
            table_with_columns(table_id.clone(), &["id"]),
        );
        cache
            .coverage
            .families
            .remove(&crate::db::cache::CatalogFamily::Dependencies);
        let mut state = AnalysisState::new(cache);

        let result = state.apply(
            &Mutation::AlterTable(crate::analysis::mutations::AlterTable {
                id: table_id.clone(),
                action: crate::analysis::mutations::AlterTableActionMutation::DropColumn {
                    name: "id".to_string(),
                    if_exists: false,
                    cascade: false,
                },
            }),
            None,
        );
        assert_eq!(result, MutationResult::Skipped);
        assert!(state.local.relations.get(&table_id).is_some_and(|overlay| {
            matches!(overlay, RelationOverlay::Present(relation) if relation.has_column("id"))
        }));
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| { record.code == EvidenceCode::CatalogCoverageIncomplete })
        );
    }

    #[test]
    fn scoped_baseline_type_drop_requires_cross_schema_dependency_proof() {
        let type_id = ObjectId::new("public", "known_type");
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["public".to_string()]);
        cache.coverage = CatalogCoverage::from_sync_scope(cache.metadata.schemas.as_deref());
        cache.types.insert(
            type_id.clone(),
            crate::model::types::TypeState {
                id: type_id.clone(),
                generation: 0,
                kind: crate::model::types::TypeKind::Base,
            },
        );
        let mut state = AnalysisState::new(cache);
        let result = state.apply(
            &Mutation::DropType(crate::analysis::mutations::DropTypeMutation {
                ids: vec![type_id.clone()],
                if_exists: false,
                cascade: false,
            }),
            None,
        );
        assert_eq!(result, MutationResult::Skipped);
        assert!(matches!(
            state.local.types.get(&type_id),
            Some(crate::model::types::TypeOverlay::Present(_))
        ));
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| record.code == EvidenceCode::CatalogCoverageIncomplete)
        );
    }

    #[test]
    fn scoped_baseline_function_drop_requires_cross_schema_dependency_proof() {
        let function_id = ObjectId::new("public", "work(integer)");
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["public".to_string()]);
        cache.coverage = CatalogCoverage::from_sync_scope(cache.metadata.schemas.as_deref());
        cache.functions.insert(
            function_id.clone(),
            crate::model::function::FunctionState {
                id: function_id.clone(),
                routine_kind: crate::model::function::RoutineKind::Function,
                arg_types: vec!["integer".to_string()],
                arg_type_ids: Vec::new(),
                return_type: "integer".to_string(),
                return_type_id: None,
                volatility: crate::model::function::Volatility::Volatile,
                language: "sql".to_string(),
                security: crate::model::function::SecurityMode::Invoker,
            },
        );
        let mut state = AnalysisState::new(cache);
        let result = state.apply(
            &Mutation::DropFunction(crate::analysis::mutations::DropFunctionMutation {
                signatures: vec![crate::analysis::facts::FunctionSigFact {
                    name: crate::ast::identifiers::QualifiedName::new(
                        Some(crate::ast::identifiers::Ident::new("public", false)),
                        crate::ast::identifiers::Ident::new("work", false),
                    ),
                    params: vec!["integer".to_string()],
                }],
                if_exists: false,
                cascade: false,
            }),
            None,
        );
        assert_eq!(result, MutationResult::Skipped);
        assert!(matches!(
            state.local.functions.get(&function_id),
            Some(crate::model::function::FunctionOverlay::Present(_))
        ));
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| record.code == EvidenceCode::CatalogCoverageIncomplete)
        );
    }

    #[test]
    fn routine_cascade_without_dependency_edges_is_not_applied_partially() {
        let id = ObjectId::new("public", "work(integer)");
        let routine = |kind| crate::model::function::FunctionState {
            id: id.clone(),
            routine_kind: kind,
            arg_types: vec!["integer".to_string()],
            arg_type_ids: Vec::new(),
            return_type: "integer".to_string(),
            return_type_id: None,
            volatility: crate::model::function::Volatility::Volatile,
            language: "sql".to_string(),
            security: crate::model::function::SecurityMode::Invoker,
        };
        let signature = || crate::analysis::facts::FunctionSigFact {
            name: crate::ast::identifiers::QualifiedName::new(
                Some(crate::ast::identifiers::Ident::new("public", false)),
                crate::ast::identifiers::Ident::new("work", false),
            ),
            params: vec!["integer".to_string()],
        };

        let mut procedure_cache = DbCache::new();
        procedure_cache.functions.insert(
            id.clone(),
            routine(crate::model::function::RoutineKind::Procedure),
        );
        let mut procedure_state = AnalysisState::new(procedure_cache);
        assert_eq!(
            procedure_state.apply(
                &Mutation::DropProcedure(crate::analysis::mutations::DropProcedureMutation {
                    signatures: vec![signature()],
                    if_exists: false,
                    cascade: true,
                }),
                None,
            ),
            MutationResult::Skipped
        );
        assert!(
            procedure_state
                .evidence()
                .iter()
                .any(|record| record.code == EvidenceCode::UnmodeledState)
        );
        assert!(procedure_state.local.functions.contains_key(&id));

        let mut aggregate_cache = DbCache::new();
        aggregate_cache.functions.insert(
            id.clone(),
            routine(crate::model::function::RoutineKind::Aggregate),
        );
        let mut aggregate_state = AnalysisState::new(aggregate_cache);
        assert_eq!(
            aggregate_state.apply(
                &Mutation::DropAggregate(crate::analysis::mutations::DropAggregateMutation {
                    signatures: vec![signature()],
                    if_exists: false,
                    cascade: true,
                }),
                None,
            ),
            MutationResult::Skipped
        );
        assert!(
            aggregate_state
                .evidence()
                .iter()
                .any(|record| record.code == EvidenceCode::UnmodeledState)
        );
        assert!(aggregate_state.local.functions.contains_key(&id));
    }

    #[test]
    fn concurrent_index_drop_rejects_transaction_and_cascade_forms() {
        let mut state = AnalysisState::new(DbCache::new());
        assert_eq!(
            state.apply(&Mutation::BeginTransaction, None),
            MutationResult::Applied
        );
        let concurrent = Mutation::DropIndex(crate::analysis::mutations::DropIndex {
            ids: Vec::new(),
            if_exists: true,
            concurrently: true,
            cascade: false,
        });
        assert!(matches!(
            state.apply(&concurrent, None),
            MutationResult::Conflict { .. }
        ));

        let mut state = AnalysisState::new(DbCache::new());
        let concurrent_cascade = Mutation::DropIndex(crate::analysis::mutations::DropIndex {
            ids: Vec::new(),
            if_exists: true,
            concurrently: true,
            cascade: true,
        });
        assert!(matches!(
            state.apply(&concurrent_cascade, None),
            MutationResult::Conflict { .. }
        ));

        let mut state = AnalysisState::new(DbCache::new());
        assert_eq!(
            state.apply(&Mutation::BeginTransaction, None),
            MutationResult::Applied
        );
        let concurrent_create = Mutation::CreateIndex(crate::analysis::mutations::CreateIndex {
            id: ObjectId::new("public", "idx"),
            table: ObjectId::new("public", "table"),
            if_not_exists: false,
            concurrently: true,
            using_method: None,
            has_predicate: false,
            unique: false,
            key_columns: vec!["id".to_string()],
            included_columns: Vec::new(),
            has_expression_keys: false,
            has_default_sort_order: true,
            has_default_opclasses: true,
            has_default_collations: true,
        });
        assert!(matches!(
            state.apply(&concurrent_create, None),
            MutationResult::Conflict { .. }
        ));

        let mut refresh_state = AnalysisState::new(DbCache::new());
        assert_eq!(
            refresh_state.apply(&Mutation::BeginTransaction, None),
            MutationResult::Applied
        );
        let concurrent_refresh = Mutation::RefreshMaterializedView(
            crate::analysis::mutations::RefreshMaterializedViewMutation {
                id: ObjectId::new("public", "mv"),
                concurrently: true,
            },
        );
        assert!(matches!(
            refresh_state.apply(&concurrent_refresh, None),
            MutationResult::Conflict { .. }
        ));

        let partitioned_table = ObjectId::new("public", "events");
        let mut partition_state = AnalysisState::new(DbCache::new());
        let mut relation = table_with_columns(partitioned_table.clone(), &["id"]);
        relation.partition_type = Some("RANGE".to_string());
        partition_state.local.relations.insert(
            partitioned_table.clone(),
            RelationOverlay::Present(relation),
        );
        let concurrent_partition_index =
            Mutation::CreateIndex(crate::analysis::mutations::CreateIndex {
                id: ObjectId::new("public", "events_id_idx"),
                table: partitioned_table,
                if_not_exists: false,
                concurrently: true,
                using_method: None,
                has_predicate: false,
                unique: false,
                key_columns: vec!["id".to_string()],
                included_columns: Vec::new(),
                has_expression_keys: false,
                has_default_sort_order: true,
                has_default_opclasses: true,
                has_default_collations: true,
            });
        assert!(matches!(
            partition_state.apply(&concurrent_partition_index, None),
            MutationResult::Conflict { .. }
        ));

        let partition_drop_table = ObjectId::new("public", "drop_events");
        let mut partition_drop_state = AnalysisState::new(DbCache::new());
        let mut drop_relation = table_with_columns(partition_drop_table.clone(), &["id"]);
        drop_relation.partition_type = Some("RANGE".to_string());
        partition_drop_state.local.relations.insert(
            partition_drop_table.clone(),
            RelationOverlay::Present(drop_relation),
        );
        let drop_index_id = ObjectId::new("public", "drop_events_id_idx");
        assert_eq!(
            partition_drop_state.apply(
                &Mutation::CreateIndex(crate::analysis::mutations::CreateIndex {
                    id: drop_index_id.clone(),
                    table: partition_drop_table,
                    if_not_exists: false,
                    concurrently: false,
                    using_method: None,
                    has_predicate: false,
                    unique: false,
                    key_columns: vec!["id".to_string()],
                    included_columns: Vec::new(),
                    has_expression_keys: false,
                    has_default_sort_order: true,
                    has_default_opclasses: true,
                    has_default_collations: true,
                }),
                None,
            ),
            MutationResult::Applied
        );
        assert!(matches!(
            partition_drop_state.apply(
                &Mutation::DropIndex(crate::analysis::mutations::DropIndex {
                    ids: vec![drop_index_id],
                    if_exists: false,
                    concurrently: true,
                    cascade: false,
                }),
                None,
            ),
            MutationResult::Conflict { .. }
        ));
    }

    #[test]
    fn concurrent_refresh_rejects_unpopulated_materialized_view() {
        let view_id = ObjectId::new("public", "empty_mv");
        let mut cache = DbCache::new();
        let mut view = crate::model::relation::RelationState::new(
            view_id.clone(),
            ObjectId::new("", "postgres"),
            0,
            None,
            RelationKind::MaterializedView,
            Persistence::Permanent,
            0,
        );
        view.is_populated = Some(false);
        cache.insert_baseline(view_id.clone(), view);
        let mut state = AnalysisState::new(cache);
        let result = state.apply(
            &Mutation::RefreshMaterializedView(
                crate::analysis::mutations::RefreshMaterializedViewMutation {
                    id: view_id,
                    concurrently: true,
                },
            ),
            None,
        );
        assert!(matches!(result, MutationResult::Conflict { .. }));
    }

    #[test]
    fn stale_generation_edges_do_not_block_or_cascade_after_recreation() {
        let parent = ObjectId::new("public", "parent");
        let child = ObjectId::new("public", "child");
        let view = ObjectId::new("public", "parent_view");
        let mut cache = DbCache::new();
        cache.insert_baseline(parent.clone(), table_with_columns(parent.clone(), &["id"]));
        cache.insert_baseline(
            child.clone(),
            table_with_columns(child.clone(), &["parent_id"]),
        );
        let mut view_state = table_with_columns(view.clone(), &["id"]);
        view_state.kind = RelationKind::View;
        cache.insert_baseline(view.clone(), view_state);
        let mut state = AnalysisState::new(cache);
        state.local.graph.add_edge(DependencyEdge::new(
            child.clone(),
            parent.clone(),
            DependencyKind::ForeignKey {
                constraint_name: Some("child_parent_fkey".to_string()),
                from_columns: vec!["parent_id".to_string()],
                to_columns: vec!["id".to_string()],
                operator_evidence: None,
                from_generation: 41,
            },
        ));
        state.local.graph.add_edge(DependencyEdge::new(
            view.clone(),
            parent.clone(),
            DependencyKind::ViewDependency {
                view_generation: 42,
                referenced_column: None,
            },
        ));

        let closure = state.get_cascade_closure(&parent);
        assert_eq!(closure.dropped_relations, HashSet::from([parent.clone()]));
        assert!(closure.dropped_constraints.is_empty());

        let result = state.apply(
            &Mutation::DropTable(crate::analysis::mutations::DropTable {
                ids: vec![parent],
                if_exists: false,
                cascade: false,
            }),
            None,
        );
        assert_eq!(result, MutationResult::Applied);
    }

    #[test]
    fn unhydrated_generation_edge_remains_conservative() {
        let parent = ObjectId::new("public", "parent");
        let omitted_view = ObjectId::new("tenant", "parent_view");
        let mut cache = DbCache::new();
        cache.insert_baseline(parent.clone(), table_with_columns(parent.clone(), &["id"]));
        let mut state = AnalysisState::new(cache);
        state.local.graph.add_edge(DependencyEdge::new(
            omitted_view.clone(),
            parent.clone(),
            DependencyKind::ViewDependency {
                view_generation: 7,
                referenced_column: None,
            },
        ));

        let closure = state.get_cascade_closure(&parent);
        assert!(closure.dropped_relations.contains(&omitted_view));
        let result = state.apply(
            &Mutation::DropTable(crate::analysis::mutations::DropTable {
                ids: vec![parent],
                if_exists: false,
                cascade: true,
            }),
            None,
        );
        assert_eq!(result, MutationResult::Applied);
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| { record.code == EvidenceCode::UnknownObjectState })
        );
    }

    #[test]
    fn stale_trigger_generation_does_not_block_schema_restrict() {
        let mut cache = DbCache::new();
        cache.schemas.insert(
            "old_schema".to_string(),
            crate::model::schema::SchemaState {
                name: "old_schema".to_string(),
                owner: ObjectId::new("", "postgres"),
                generation: 0,
            },
        );
        let mut state = AnalysisState::new(cache);
        let trigger_id = ObjectId::new("other_schema", "table\0stale_trigger");
        state.local.triggers.insert(
            trigger_id.clone(),
            TriggerOverlay::Present(crate::model::trigger::TriggerState {
                name: "stale_trigger".to_string(),
                id: trigger_id.clone(),
                table_id: ObjectId::new("old_schema", "table"),
                enabled_mode: crate::model::trigger::TriggerEnableMode::Origin,
                generation: 0,
            }),
        );
        state.local.graph.add_edge(DependencyEdge::new(
            trigger_id.clone(),
            ObjectId::new("old_schema", "table"),
            DependencyKind::TriggerOnTable {
                trigger_id,
                function_id: ObjectId::new("other_schema", "fn()"),
                trigger_generation: 9,
            },
        ));

        let result = state.apply(
            &Mutation::DropSchema(crate::analysis::mutations::DropSchemaMutation {
                names: vec!["old_schema".to_string()],
                if_exists: false,
                cascade: false,
            }),
            None,
        );
        assert_eq!(result, MutationResult::Skipped);
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| record.code == EvidenceCode::UnmodeledState)
        );
    }

    #[test]
    fn baseline_constraint_keys_hydrate_into_the_dependency_graph() {
        let parent = ObjectId::new("public", "parent");
        let mut cache = DbCache::new();
        cache.insert_baseline(parent.clone(), table_with_columns(parent.clone(), &["id"]));
        cache.constraints.push(ConstraintState {
            table_id: parent.clone(),
            name: "parent_pkey".to_string(),
            kind: crate::model::constraint::ConstraintKind::PrimaryKey,
            validated: true,
            backing_index: None,
        });
        cache
            .constraint_keys
            .push(crate::db::cache::ConstraintKeyCache {
                table_id: parent.clone(),
                constraint_name: "parent_pkey".to_string(),
                columns: vec!["id".to_string()],
                is_primary: true,
            });

        let state = AnalysisState::new(cache);
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.dependent == parent
                && edge.referenced == parent
                && matches!(
                    &edge.kind,
                    DependencyKind::ConstraintOnRelation {
                        constraint_name,
                        columns,
                        is_primary: true,
                    } if constraint_name == "parent_pkey" && columns == &["id"]
                )
        }));
    }

    #[test]
    fn malformed_baseline_fk_operator_evidence_is_tainted_not_claimed_exact() {
        let child = ObjectId::new("public", "child");
        let parent = ObjectId::new("public", "parent");
        let mut cache = DbCache::new();
        cache.insert_baseline(
            child.clone(),
            table_with_columns(child.clone(), &["parent_id"]),
        );
        cache.insert_baseline(parent.clone(), table_with_columns(parent.clone(), &["id"]));
        cache.foreign_keys.push(crate::db::cache::ForeignKeyCache {
            constraint_name: "child_parent_fkey".into(),
            from_table: child.clone(),
            to_table: parent.clone(),
            from_columns: vec!["parent_id".into()],
            to_columns: vec!["id".into()],
            pk_fk_equality_operators: Vec::new(),
            pk_pk_equality_operators: vec!["=".into()],
            fk_fk_equality_operators: vec!["=".into()],
        });

        let state = AnalysisState::with_baseline(cache, true);
        assert_eq!(*state.confidence(), Confidence::Tainted);
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| record.code == EvidenceCode::CatalogCoverageIncomplete)
        );
        assert!(state.local.graph.edges().iter().any(|edge| {
            matches!(
                &edge.kind,
                DependencyKind::ForeignKey {
                    operator_evidence: None,
                    ..
                }
            )
        }));
    }

    #[test]
    fn complete_baseline_fk_operator_evidence_reaches_graph_edge() {
        let child = ObjectId::new("public", "child");
        let parent = ObjectId::new("public", "parent");
        let mut cache = DbCache::new();
        cache.insert_baseline(
            child.clone(),
            table_with_columns(child.clone(), &["parent_id"]),
        );
        cache.insert_baseline(parent.clone(), table_with_columns(parent.clone(), &["id"]));
        cache.foreign_keys.push(crate::db::cache::ForeignKeyCache {
            constraint_name: "child_parent_fkey".into(),
            from_table: child.clone(),
            to_table: parent.clone(),
            from_columns: vec!["parent_id".into()],
            to_columns: vec!["id".into()],
            pk_fk_equality_operators: vec!["pg_catalog.=(integer,integer)".into()],
            pk_pk_equality_operators: vec!["pg_catalog.=(integer,integer)".into()],
            fk_fk_equality_operators: vec!["pg_catalog.=(integer,integer)".into()],
        });

        let state = AnalysisState::with_baseline(cache, true);
        assert_eq!(*state.confidence(), Confidence::Exact);
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.dependent == child
                && edge.referenced == parent
                && matches!(
                    &edge.kind,
                    DependencyKind::ForeignKey {
                        operator_evidence: Some(evidence),
                        ..
                    } if evidence.pk_fk == ["pg_catalog.=(integer,integer)".to_string()]
                )
        }));
    }

    #[test]
    fn try_new_rejects_semantically_invalid_cache_before_hydration() {
        let mut cache = DbCache::new();
        cache.schemas.insert(
            "public".into(),
            crate::model::schema::SchemaState {
                name: "other".into(),
                owner: ObjectId::new("", "postgres"),
                generation: 0,
            },
        );

        let error = match AnalysisState::try_new(cache) {
            Ok(_) => panic!("invalid cache unexpectedly hydrated"),
            Err(error) => error,
        };
        assert!(error.contains("schema cache key 'public'"));
    }

    #[test]
    fn role_catalog_coverage_is_authoritative_without_session_provenance() {
        let mut cache = DbCache::new();
        let role = ObjectId::new("", "app_role");
        cache.roles.insert(
            role.clone(),
            crate::model::role::RoleState {
                id: role,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        cache.metadata.source_role = None;
        cache.metadata.source_session_role = None;

        let state = AnalysisState::with_baseline(cache, true);
        assert!(state.local.roles_known);
    }
}
