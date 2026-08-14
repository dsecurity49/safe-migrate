// FILE: src/analysis/state.rs
use crate::analysis::facts::{SearchPathTarget, TableConstraintFact};
use crate::analysis::graph::{DependencyEdge, DependencyGraph, DependencyKind};
use crate::analysis::mutations::{
    AlterTableActionMutation, AlterTypeActionMutation, Mutation, PersistenceMutation,
};
use crate::analysis::transaction::{NamespaceSnapshot, StateChange, TransactionFrame};
use crate::ast::identifiers::ObjectId;
use crate::db::cache::DbCache;
use crate::model::constraint::{ConstraintKind, ConstraintState};
pub use crate::model::relation::RelationOverlay;
use crate::model::relation::{ColumnAction, Persistence, Privilege, RelationKind, RelationState};
use crate::model::schema::SchemaOverlay;
use crate::model::sequence::{SequenceKind, SequenceOverlay, SequenceState};
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
    /// PostgreSQL did not execute this statement because an earlier statement
    /// aborted the active transaction.
    NotExecuted,
    Conflict {
        reason: String,
    },
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
    pub default_search_path_template: Vec<String>,
    /// Role currently active for this session context (updated by SET ROLE /
    /// SET SESSION AUTHORIZATION). Begins equal to `session_role`.
    pub current_role: String,
    /// Whether `current_role` is statically known. False when no V5 cache was
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

#[derive(Clone, Debug)]
pub struct PreState {
    pub relations: HashMap<ObjectId, crate::model::relation::RelationState>,
    pub functions: HashMap<ObjectId, crate::model::function::FunctionState>,
    pub roles: HashMap<ObjectId, crate::model::role::RoleState>,
    pub publications: HashMap<String, crate::model::replication::PublicationState>,
    pub subscriptions: HashMap<String, crate::model::replication::SubscriptionState>,
    pub sequences: HashMap<ObjectId, crate::model::sequence::SequenceState>,
    pub types: HashMap<ObjectId, crate::model::types::TypeState>,
    pub indexes: Vec<crate::analysis::graph::DependencyEdge>,
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

    pub fn new(cache: DbCache) -> Self {
        Self::with_baseline(cache, true)
    }

    pub fn with_baseline(cache: DbCache, baseline_available: bool) -> Self {
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
        let baseline_schemas = cache
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
        // This also keeps programmatically assembled V5 caches internally
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
                graph.edges.push(DependencyEdge::new(
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
            graph.edges.push(DependencyEdge::new(
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
            // BUG-008: index ObjectIds go into baseline_indexes, not baseline_relations
            baseline_indexes.insert(idx.index_id.clone());
            graph.edges.push(DependencyEdge::new(
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
            if is_view && relations.contains_key(&referenced) {
                graph.edges.push(DependencyEdge::new(
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
            graph.edges.push(DependencyEdge::new(
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
                publications: HashMap::new(),
                subscriptions: HashMap::new(),
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
                default_search_path_template,
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

    /// Returns whether a cache-backed absence is authoritative for an object.
    /// A scoped cache only establishes absence in the schemas it actually
    /// synchronized.
    pub fn baseline_covers_object(&self, id: &ObjectId) -> bool {
        self.baseline_schemas
            .as_ref()
            .is_none_or(|schemas| schemas.contains(&id.schema))
    }

    pub fn baseline_scope_omits_displayed_object<'a>(
        &self,
        object_name: &'a str,
    ) -> Option<&'a str> {
        let schemas = self.baseline_schemas.as_ref()?;
        let (schema, _) = object_name.split_once('.')?;
        (!schemas.contains(schema)).then_some(schema)
    }

    fn sequence_is_present(&self, id: &ObjectId) -> bool {
        matches!(
            self.local.sequences.get(id),
            Some(SequenceOverlay::Present(_))
        )
    }

    fn type_is_present(&self, id: &ObjectId) -> bool {
        matches!(self.local.types.get(id), Some(TypeOverlay::Present(_)))
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

    fn index_is_present(&self, id: &ObjectId) -> bool {
        self.local.graph.edges.iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexOnRelation { .. }) && edge.dependent == *id
        })
    }

    fn next_generated_constraint_name(
        &self,
        table: &ObjectId,
        name1: &str,
        name2: Option<&str>,
        label: &str,
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
                !self
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
        self.relation_is_present(id)
            || self.sequence_is_present(id)
            || self.index_is_present(id)
            || self.type_is_present(id)
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

        let indexes = self
            .local
            .graph
            .edges
            .iter()
            .filter(|e| matches!(e.kind, DependencyKind::IndexOnRelation { .. }))
            .cloned()
            .collect();

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

        for edge in &self.local.graph.edges {
            match &edge.kind {
                DependencyKind::ViewDependency { .. } => {
                    if self.local.graph.resolve_rename(&edge.referenced) == &resolved_current {
                        let resolved_view_id =
                            self.local.graph.resolve_rename(&edge.dependent).clone();
                        if !visited.contains(&resolved_view_id) {
                            self.walk_cascade(&resolved_view_id, visited, result);
                        }
                    }
                }
                DependencyKind::IndexOnRelation { .. } => {
                    if self.local.graph.resolve_rename(&edge.referenced) == &resolved_current {
                        result
                            .dropped_indexes
                            .insert(self.local.graph.resolve_rename(&edge.dependent).clone());
                    }
                }
                DependencyKind::ForeignKey {
                    constraint_name, ..
                } => {
                    if self.local.graph.resolve_rename(&edge.referenced) == &resolved_current
                        && let Some(cname) = constraint_name
                    {
                        result.dropped_constraints.insert((
                            self.local.graph.resolve_rename(&edge.dependent).clone(),
                            cname.clone(),
                        ));
                    }
                }
                DependencyKind::PartitionOf
                    if self.local.graph.resolve_rename(&edge.referenced) == &resolved_current =>
                {
                    let resolved_child = self.local.graph.resolve_rename(&edge.dependent).clone();
                    if !visited.contains(&resolved_child) {
                        self.walk_cascade(&resolved_child, visited, result);
                    }
                }
                _ => {}
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

        for edge in &mut self.local.graph.edges {
            Self::remap_schema_id(&mut edge.dependent, old_name, new_name);
            Self::remap_schema_id(&mut edge.referenced, old_name, new_name);
            if let DependencyKind::TriggerOnTable {
                trigger_id,
                function_id,
            } = &mut edge.kind
            {
                Self::remap_schema_id(trigger_id, old_name, new_name);
                Self::remap_schema_id(function_id, old_name, new_name);
            }
        }
        for (old_id, new_id) in aliases {
            self.local.graph.edges.push(DependencyEdge::new(
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
        self.refresh_role_sensitive_search_path();
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
                if let Some(role_id) = Self::resolve_role_name(
                    grantee,
                    &self.local.current_role,
                    &self.local.session_role,
                ) {
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
                if let Some(role_id) = Self::resolve_role_name(
                    revokee,
                    &self.local.current_role,
                    &self.local.session_role,
                ) {
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
            Mutation::CreateSchema(create_schema) => {
                if self.schema_is_present(&create_schema.name) {
                    return if create_schema.if_not_exists {
                        MutationResult::Skipped
                    } else {
                        MutationResult::Conflict {
                            reason: format!("schema '{}' already exists", create_schema.name),
                        }
                    };
                }
                let (owner_name, owner_known) = match &create_schema.authorization {
                    Some(role) => match self.role_fact_identity(role) {
                        Some(identity) => identity,
                        None => {
                            self.snapshot_confidence();
                            self.local.confidence = Confidence::Tainted;
                            (self.local.current_role.clone(), false)
                        }
                    },
                    None => (
                        self.local.current_role.clone(),
                        self.local.current_role_known,
                    ),
                };
                if owner_known && self.local.roles_known && self.present_role(&owner_name).is_none()
                {
                    return MutationResult::Conflict {
                        reason: format!("role '{}' does not exist", owner_name),
                    };
                }
                if !owner_known || !self.local.roles_known {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                }
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;
                self.snapshot_schema(&create_schema.name);
                self.local.schemas.insert(
                    create_schema.name.clone(),
                    SchemaOverlay::Present(crate::model::schema::SchemaState {
                        name: create_schema.name.clone(),
                        owner: ObjectId::new("", owner_name),
                        generation,
                    }),
                );
                self.snapshot_search_path();
                self.refresh_role_sensitive_search_path();
                MutationResult::Applied
            }
            Mutation::AlterSchema(alter_schema) => match alter_schema {
                crate::analysis::mutations::AlterSchemaMutation::OwnerTo { name, new_owner } => {
                    if !self.schema_is_present(name) {
                        if self.schema_absence_is_authoritative(name) {
                            return MutationResult::Conflict {
                                reason: format!("schema '{}' does not exist", name),
                            };
                        }
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                    let Some((owner_name, owner_known)) = self.role_fact_identity(new_owner) else {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    };
                    if owner_known
                        && self.local.roles_known
                        && self.present_role(&owner_name).is_none()
                    {
                        return MutationResult::Conflict {
                            reason: format!("role '{}' does not exist", owner_name),
                        };
                    }
                    if !owner_known || !self.local.roles_known {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                    }
                    self.snapshot_schema(name);
                    if let Some(SchemaOverlay::Present(schema)) = self.local.schemas.get_mut(name) {
                        schema.owner = ObjectId::new("", owner_name);
                    }
                    MutationResult::Applied
                }
                crate::analysis::mutations::AlterSchemaMutation::Rename { old_name, new_name } => {
                    if !self.schema_is_present(old_name) {
                        if !self.schema_absence_is_authoritative(old_name) {
                            self.snapshot_confidence();
                            self.local.confidence = Confidence::Tainted;
                            return MutationResult::Skipped;
                        }
                        return MutationResult::Conflict {
                            reason: format!("schema '{}' does not exist", old_name),
                        };
                    }
                    if self.schema_is_present(new_name) {
                        return MutationResult::Conflict {
                            reason: format!("schema '{}' already exists", new_name),
                        };
                    }
                    if !self.schema_absence_is_authoritative(new_name) {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                    }
                    self.snapshot_search_path();
                    self.rename_schema_namespace(old_name, new_name);
                    MutationResult::Applied
                }
            },
            Mutation::DropSchema(drop_schema) => {
                for name in &drop_schema.names {
                    if !self.schema_is_present(name) && self.schema_absence_is_authoritative(name) {
                        if !drop_schema.if_exists {
                            return MutationResult::Conflict {
                                reason: format!("schema '{}' does not exist", name),
                            };
                        }
                    } else if !self.schema_is_present(name) {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                    }
                }
                let present_names: Vec<String> = drop_schema
                    .names
                    .iter()
                    .filter(|name| self.schema_is_present(name))
                    .cloned()
                    .collect();
                if present_names.is_empty() {
                    return MutationResult::Skipped;
                }
                if drop_schema.cascade {
                    self.snapshot_namespace();
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

                    let constraints_to_drop: Vec<(ObjectId, String)> = self
                        .local
                        .constraints
                        .keys()
                        .filter(|(table_id, _)| drop_schema.names.contains(&table_id.schema))
                        .cloned()
                        .collect();
                    for (table_id, name) in constraints_to_drop {
                        self.snapshot_constraint(&table_id, &name);
                        self.local.constraints.remove(&(table_id, name));
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

                    let functions_to_drop: Vec<ObjectId> = self
                        .local
                        .functions
                        .keys()
                        .filter(|id| drop_schema.names.contains(&id.schema))
                        .cloned()
                        .collect();
                    for id in functions_to_drop {
                        self.snapshot_function(&id);
                        self.local
                            .functions
                            .insert(id, crate::model::function::FunctionOverlay::Dropped);
                    }

                    let triggers_to_drop: Vec<ObjectId> = self
                        .local
                        .triggers
                        .keys()
                        .filter(|id| drop_schema.names.contains(&id.schema))
                        .cloned()
                        .collect();
                    for id in triggers_to_drop {
                        self.snapshot_trigger(&id);
                        self.local.triggers.insert(id, TriggerOverlay::Dropped);
                    }

                    self.local
                        .pending_validation
                        .retain(|(table, _)| !drop_schema.names.contains(&table.schema));
                    for overlay in self.local.publications.values_mut() {
                        let crate::model::replication::PublicationOverlay::Present(publication) =
                            overlay
                        else {
                            continue;
                        };
                        let crate::analysis::facts::PublicationScope::Explicit(objects) =
                            &mut publication.scope
                        else {
                            continue;
                        };
                        objects.retain(|object| match object {
                            crate::analysis::facts::PublicationObjectFact::Table {
                                name, ..
                            } => name.schema.as_ref().is_none_or(|schema| {
                                !drop_schema.names.contains(&schema.resolve())
                            }),
                            crate::analysis::facts::PublicationObjectFact::SchemaTables {
                                schema,
                                ..
                            } => !drop_schema.names.contains(schema),
                            _ => true,
                        });
                    }

                    self.snapshot_graph_full();

                    let g = &mut self.local.graph;
                    g.edges.retain(|e| {
                        !drop_schema.names.contains(&e.dependent.schema)
                            && !drop_schema.names.contains(&e.referenced.schema)
                            && match &e.kind {
                                DependencyKind::TriggerOnTable { function_id, .. } => {
                                    !drop_schema.names.contains(&function_id.schema)
                                }
                                _ => true,
                            }
                    });
                } else {
                    // Non-cascade: fail if any objects in the schema still exist
                    let has_relation = self.local.relations.iter().any(|(id, ov)| {
                        drop_schema.names.contains(&id.schema)
                            && !matches!(ov, RelationOverlay::Dropped)
                    });
                    let has_type = self.local.types.iter().any(|(id, ov)| {
                        drop_schema.names.contains(&id.schema)
                            && !matches!(ov, TypeOverlay::Dropped)
                    });
                    let has_sequence = self.local.sequences.iter().any(|(id, ov)| {
                        drop_schema.names.contains(&id.schema)
                            && !matches!(ov, SequenceOverlay::Dropped)
                    });
                    let has_function = self.local.functions.iter().any(|(id, ov)| {
                        drop_schema.names.contains(&id.schema)
                            && !matches!(ov, crate::model::function::FunctionOverlay::Dropped)
                    });
                    let has_trigger = self.local.triggers.iter().any(|(id, ov)| {
                        drop_schema.names.contains(&id.schema)
                            && !matches!(ov, TriggerOverlay::Dropped)
                    });
                    if has_relation || has_type || has_sequence || has_function || has_trigger {
                        return MutationResult::Conflict {
                            reason: format!(
                                "schema(s) {:?} still contain objects; use CASCADE to drop them",
                                drop_schema.names
                            ),
                        };
                    }
                }
                for name in present_names {
                    self.snapshot_schema(&name);
                    self.local.schemas.insert(name, SchemaOverlay::Dropped);
                }
                self.snapshot_search_path();
                self.refresh_role_sensitive_search_path();
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

                let renames: Vec<DependencyEdge> = self
                    .local
                    .graph
                    .edges
                    .iter()
                    .filter(|e| matches!(e.kind, DependencyKind::RenameTo))
                    .cloned()
                    .collect();
                let resolve = |id: &ObjectId| -> ObjectId {
                    let mut current = id;
                    let mut visited = HashSet::new();
                    loop {
                        if !visited.insert(current.clone()) {
                            return id.clone();
                        }
                        match renames.iter().find(|r| &r.dependent == current) {
                            Some(edge) => current = &edge.referenced,
                            None => return current.clone(),
                        }
                    }
                };

                let resolved_drop = resolve(&drop_table.id);
                let mut dropped_relations = HashSet::from([resolved_drop.clone()]);

                if drop_table.cascade {
                    let local_closure;
                    let closure = match precomputed_cascade {
                        Some(c) => c,
                        None => {
                            local_closure = self.get_cascade_closure(&drop_table.id);
                            &local_closure
                        }
                    };
                    dropped_relations = closure.dropped_relations.clone();

                    for dropped_rel_id in &closure.dropped_relations {
                        self.snapshot_relation(dropped_rel_id);
                        self.local
                            .relations
                            .insert(dropped_rel_id.clone(), RelationOverlay::Dropped);
                    }

                    self.snapshot_graph_full();
                    self.local.graph.edges.retain(|e| match &e.kind {
                        DependencyKind::IndexOnRelation { .. } => {
                            !closure.dropped_indexes.contains(&resolve(&e.dependent))
                        }
                        DependencyKind::ForeignKey {
                            constraint_name, ..
                        } => {
                            let from_dropped =
                                closure.dropped_relations.contains(&resolve(&e.dependent));
                            let to_dropped =
                                closure.dropped_relations.contains(&resolve(&e.referenced));
                            let constraint_explicitly_dropped = if let Some(cname) = constraint_name
                            {
                                closure
                                    .dropped_constraints
                                    .contains(&(resolve(&e.dependent), cname.clone()))
                            } else {
                                false
                            };
                            !(from_dropped || to_dropped || constraint_explicitly_dropped)
                        }
                        DependencyKind::ViewDependency { .. } => {
                            !closure.dropped_relations.contains(&resolve(&e.dependent))
                        }
                        DependencyKind::SequenceOwnedBy { .. } => {
                            !closure.dropped_relations.contains(&resolve(&e.referenced))
                        }
                        _ => true,
                    });
                } else {
                    let has_view_deps = self.local.graph.edges.iter().any(|e| {
                        matches!(e.kind, DependencyKind::ViewDependency { .. })
                            && resolve(&e.referenced) == resolved_drop
                    });
                    let has_fk_deps = self.local.graph.edges.iter().any(|e| {
                        matches!(e.kind, DependencyKind::ForeignKey { .. })
                            && resolve(&e.referenced) == resolved_drop
                            && resolve(&e.dependent) != resolved_drop
                    });
                    let has_partition_deps = self.local.graph.edges.iter().any(|e| {
                        matches!(e.kind, DependencyKind::PartitionOf)
                            && resolve(&e.referenced) == resolved_drop
                    });

                    if has_view_deps || has_fk_deps || has_partition_deps {
                        return MutationResult::Conflict {
                            reason: format!(
                                "relation '{}' still has dependent objects; use CASCADE",
                                drop_table.id
                            ),
                        };
                    }

                    self.snapshot_relation(&drop_table.id);
                    self.local
                        .relations
                        .insert(drop_table.id.clone(), RelationOverlay::Dropped);

                    self.snapshot_graph_full();
                    self.local.graph.edges.retain(|e| {
                        !(matches!(e.kind, DependencyKind::SequenceOwnedBy { .. })
                            && resolve(&e.referenced) == resolved_drop)
                    });
                }

                let owned_sequences_to_drop: Vec<ObjectId> = self
                    .local
                    .sequences
                    .iter()
                    .filter_map(|(id, overlay)| match overlay {
                        SequenceOverlay::Present(sequence)
                            if sequence.owned_by.as_ref().is_some_and(|(table, _)| {
                                dropped_relations.contains(&resolve(table))
                            }) =>
                        {
                            Some(id.clone())
                        }
                        _ => None,
                    })
                    .collect();
                for sequence_id in owned_sequences_to_drop {
                    self.snapshot_sequence(&sequence_id);
                    self.local
                        .sequences
                        .insert(sequence_id, SequenceOverlay::Dropped);
                }

                let constraints_to_drop: Vec<(ObjectId, String)> = self
                    .local
                    .constraints
                    .keys()
                    .filter(|(table_id, _)| dropped_relations.contains(&resolve(table_id)))
                    .cloned()
                    .collect();
                for (table_id, name) in constraints_to_drop {
                    self.snapshot_constraint(&table_id, &name);
                    self.local.constraints.remove(&(table_id, name));
                }

                let triggers_to_drop: Vec<ObjectId> = self
                    .local
                    .triggers
                    .iter()
                    .filter_map(|(id, overlay)| {
                        let TriggerOverlay::Present(trigger) = overlay else {
                            return None;
                        };
                        let graph_matches = self.local.graph.edges.iter().any(|edge| {
                            matches!(edge.kind, DependencyKind::TriggerOnTable { .. })
                                && edge.dependent == *id
                                && dropped_relations.contains(&resolve(&edge.referenced))
                        });
                        (dropped_relations.contains(&resolve(&trigger.table_id)) || graph_matches)
                            .then(|| id.clone())
                    })
                    .collect();
                for trigger_id in triggers_to_drop {
                    self.snapshot_trigger(&trigger_id);
                    self.local
                        .triggers
                        .insert(trigger_id, TriggerOverlay::Dropped);
                }

                // PostgreSQL drops triggers only after the table drop succeeds.
                self.snapshot_graph_full();
                self.local.graph.edges.retain(|e| {
                    !(matches!(e.kind, DependencyKind::TriggerOnTable { .. })
                        && dropped_relations.contains(&resolve(&e.referenced)))
                });

                self.snapshot_graph_full();
                self.local.graph.edges.retain(|e| {
                    if let DependencyKind::PartitionOf = e.kind {
                        resolve(&e.referenced) != resolved_drop
                            && resolve(&e.dependent) != resolved_drop
                    } else {
                        true
                    }
                });

                MutationResult::Applied
            }
            Mutation::CreateTable(create) => {
                if create.if_not_exists && self.relation_namespace_is_taken(&create.id) {
                    return MutationResult::Skipped;
                }
                if self.relation_namespace_is_taken(&create.id) {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' already exists", create.id),
                    };
                }

                // PostgreSQL chooses all implicit sequence names before the
                // table becomes visible. Reserve them up front so a collision
                // or malformed statement cannot leave partial local state.
                let mut reserved_sequences = HashSet::new();
                let mut implicit_sequences = Vec::new();
                for column in &create.columns {
                    let kind = match column.generation {
                        crate::analysis::facts::ColumnGeneration::Serial => {
                            Some(SequenceKind::SerialLike)
                        }
                        crate::analysis::facts::ColumnGeneration::Identity => {
                            Some(SequenceKind::Identity)
                        }
                        crate::analysis::facts::ColumnGeneration::Ordinary => None,
                    };
                    if let Some(kind) = kind {
                        let sequence_id = self.next_implicit_sequence_id(
                            &create.id,
                            &column.name,
                            &reserved_sequences,
                        );
                        reserved_sequences.insert(sequence_id.clone());
                        implicit_sequences.push((sequence_id, column.name.clone(), kind));
                    }
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
                    ObjectId::new("", &self.local.current_role),
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
                        if let TableConstraintFact::PrimaryKey { columns, .. } = tc {
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
                    if let Some(column) = rel_state
                        .columns
                        .iter_mut()
                        .find(|column| column.name == col.name)
                    {
                        column.type_id = column
                            .data_type
                            .as_deref()
                            .and_then(|raw| self.resolve_type_reference(raw));
                    }
                }

                for (sequence_id, column_name, _) in &implicit_sequences {
                    if let Some(column) = rel_state
                        .columns
                        .iter_mut()
                        .find(|column| column.name == *column_name)
                    {
                        column.default = Some(Self::sequence_nextval_default(sequence_id));
                        column.default_expr_text = Some(format!(
                            "nextval('{}.{}'::regclass)",
                            sequence_id.schema, sequence_id.name
                        ));
                        column.is_nullable = false;
                    }
                }

                self.local
                    .relations
                    .insert(create.id.clone(), RelationOverlay::Present(rel_state));

                for (sequence_id, column_name, kind) in implicit_sequences {
                    self.snapshot_sequence(&sequence_id);
                    self.snapshot_generation_counter();
                    self.local.generation_counter += 1;
                    self.local.sequences.insert(
                        sequence_id.clone(),
                        SequenceOverlay::Present(SequenceState {
                            id: sequence_id.clone(),
                            owner: ObjectId::new("", &self.local.current_role),
                            owned_by: Some((create.id.clone(), column_name.clone())),
                            kind,
                            generation: self.local.generation_counter,
                        }),
                    );
                    self.snapshot_graph();
                    self.local.graph.edges.push(DependencyEdge::new(
                        sequence_id,
                        create.id.clone(),
                        DependencyKind::SequenceOwnedBy {
                            column: column_name,
                        },
                    ));
                }

                let primary_key_name = create
                    .columns
                    .iter()
                    .find(|column| column.is_primary_key)
                    .map(|column| column.primary_key_constraint_name.clone())
                    .or_else(|| {
                        create.table_constraints.iter().find_map(|constraint| {
                            if let TableConstraintFact::PrimaryKey {
                                constraint_name, ..
                            } = constraint
                            {
                                Some(constraint_name.clone())
                            } else {
                                None
                            }
                        })
                    });
                if let Some(explicit_name) = primary_key_name {
                    let name = explicit_name.unwrap_or_else(|| {
                        self.next_generated_constraint_name(
                            &create.id,
                            &create.id.name,
                            None,
                            "pkey",
                        )
                    });
                    self.snapshot_constraint(&create.id, &name);
                    self.local.constraints.insert(
                        (create.id.clone(), name.clone()),
                        ConstraintState {
                            table_id: create.id.clone(),
                            name,
                            kind: ConstraintKind::PrimaryKey,
                            validated: true,
                        },
                    );
                }

                let unique_constraints = create
                    .columns
                    .iter()
                    .filter(|column| column.is_unique)
                    .map(|column| {
                        (
                            column.unique_constraint_name.as_ref(),
                            vec![column.name.as_str()],
                        )
                    })
                    .chain(create.table_constraints.iter().filter_map(|constraint| {
                        if let TableConstraintFact::Unique {
                            constraint_name,
                            columns,
                        } = constraint
                        {
                            Some((
                                constraint_name.as_ref(),
                                columns.iter().map(String::as_str).collect(),
                            ))
                        } else {
                            None
                        }
                    }))
                    .collect::<Vec<_>>();
                for (explicit_name, columns) in unique_constraints {
                    let name = explicit_name.cloned().unwrap_or_else(|| {
                        self.next_generated_constraint_name(
                            &create.id,
                            &create.id.name,
                            Some(&columns.join("_")),
                            "key",
                        )
                    });
                    self.snapshot_constraint(&create.id, &name);
                    self.local.constraints.insert(
                        (create.id.clone(), name.clone()),
                        ConstraintState {
                            table_id: create.id.clone(),
                            name,
                            kind: ConstraintKind::Unique,
                            validated: true,
                        },
                    );
                }

                if let Some(parent_id) = &create.partition_of {
                    self.snapshot_graph();
                    self.local.graph.edges.push(DependencyEdge::new(
                        create.id.clone(),
                        parent_id.clone(),
                        DependencyKind::PartitionOf,
                    ));
                }

                if !create.foreign_keys.is_empty() {
                    self.snapshot_graph();
                }

                for fk in &create.foreign_keys {
                    self.local.graph.edges.push(DependencyEdge::new(
                        create.id.clone(),
                        fk.to_table.clone(),
                        DependencyKind::ForeignKey {
                            constraint_name: fk.constraint_name.clone(),
                            from_columns: fk.from_columns.clone(),
                            to_columns: fk.to_columns.clone(),
                            from_generation: generation,
                        },
                    ));
                }
                MutationResult::Applied
            }
            Mutation::CreateView(create_view) => {
                if self.relation_namespace_is_taken(&create_view.id) {
                    let is_replaceable_view = matches!(
                        self.local.relations.get(&create_view.id),
                        Some(RelationOverlay::Present(relation))
                            if relation.kind == RelationKind::View
                    );
                    if !create_view.or_replace || !is_replaceable_view {
                        return MutationResult::Conflict {
                            reason: format!("relation '{}' already exists", create_view.id),
                        };
                    }
                }
                self.snapshot_relation(&create_view.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.relations.insert(
                    create_view.id.clone(),
                    RelationOverlay::Present(RelationState::new(
                        create_view.id.clone(),
                        ObjectId::new("", &self.local.current_role),
                        generation,
                        None,
                        RelationKind::View,
                        Persistence::Permanent,
                        self.local.transactions.len(),
                    )),
                );

                self.snapshot_graph();
                for dep in &create_view.depends_on {
                    self.local.graph.edges.push(DependencyEdge::new(
                        create_view.id.clone(),
                        dep.clone(),
                        DependencyKind::ViewDependency {
                            view_generation: generation,
                        },
                    ));
                }
                MutationResult::Applied
            }
            Mutation::CreateMaterializedView(create_mv) => {
                if self.relation_namespace_is_taken(&create_mv.id) {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' already exists", create_mv.id),
                    };
                }
                self.snapshot_relation(&create_mv.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.relations.insert(
                    create_mv.id.clone(),
                    RelationOverlay::Present(RelationState::new(
                        create_mv.id.clone(),
                        ObjectId::new("", &self.local.current_role),
                        generation,
                        None,
                        RelationKind::MaterializedView,
                        Persistence::Permanent,
                        self.local.transactions.len(),
                    )),
                );

                self.snapshot_graph();
                for dep in &create_mv.depends_on {
                    self.local.graph.edges.push(DependencyEdge::new(
                        create_mv.id.clone(),
                        dep.clone(),
                        DependencyKind::ViewDependency {
                            view_generation: generation,
                        },
                    ));
                }
                MutationResult::Applied
            }
            Mutation::RefreshMaterializedView(_) => MutationResult::Applied,
            Mutation::CreateIndex(create_idx) => {
                let exists = self.index_is_present(&create_idx.id);
                if create_idx.if_not_exists && exists {
                    return MutationResult::Skipped;
                }
                if self.relation_namespace_is_taken(&create_idx.id) {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' already exists", create_idx.id),
                    };
                }
                self.snapshot_graph();
                self.local.graph.edges.push(DependencyEdge::new(
                    create_idx.id.clone(),
                    create_idx.table.clone(),
                    DependencyKind::IndexOnRelation {
                        using_method: create_idx.using_method.clone(),
                        has_predicate: create_idx.has_predicate,
                        is_concurrent: create_idx.concurrently,
                        is_unique: create_idx.unique,
                        eligibility_known: true,
                    },
                ));
                MutationResult::Applied
            }
            Mutation::CreatePolicy(create_policy) => {
                self.snapshot_relation(&create_policy.table);
                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&create_policy.table)
                {
                    if rel.policies.contains(&create_policy.name) {
                        return MutationResult::Conflict {
                            reason: format!(
                                "policy '{}' already exists on relation '{}'",
                                create_policy.name, create_policy.table
                            ),
                        };
                    }
                    rel.policies.insert(create_policy.name.clone());
                } else {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' does not exist", create_policy.table),
                    };
                }
                MutationResult::Applied
            }
            Mutation::DropPolicy(drop_policy) => {
                self.snapshot_relation(&drop_policy.table);
                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&drop_policy.table)
                {
                    if !rel.policies.contains(&drop_policy.name) {
                        return if drop_policy.if_exists {
                            MutationResult::Skipped
                        } else {
                            MutationResult::Conflict {
                                reason: format!(
                                    "policy '{}' does not exist on relation '{}'",
                                    drop_policy.name, drop_policy.table
                                ),
                            }
                        };
                    }
                    rel.policies.remove(&drop_policy.name);
                } else {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' does not exist", drop_policy.table),
                    };
                }
                MutationResult::Applied
            }
            Mutation::CreateTrigger(create_trigger) => {
                let trigger_id = Self::trigger_key(&create_trigger.table, &create_trigger.name);
                if matches!(
                    self.local.triggers.get(&trigger_id),
                    Some(TriggerOverlay::Present(_))
                ) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "trigger '{}' already exists on relation '{}'",
                            create_trigger.name, create_trigger.table
                        ),
                    };
                }
                self.snapshot_trigger(&trigger_id);
                self.local.triggers.insert(
                    trigger_id.clone(),
                    TriggerOverlay::Present(crate::model::trigger::TriggerState {
                        name: create_trigger.name.clone(),
                        id: trigger_id.clone(),
                        table_id: create_trigger.table.clone(),
                        enabled_mode: crate::model::trigger::TriggerEnableMode::Origin,
                        generation: self.local.generation_counter,
                    }),
                );

                self.snapshot_relation(&create_trigger.table);
                if let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&create_trigger.table)
                {
                    rel.triggers.insert(create_trigger.name.clone());
                }

                self.snapshot_graph_full();
                self.local.graph.edges.push(DependencyEdge::new(
                    trigger_id.clone(),
                    create_trigger.table.clone(),
                    DependencyKind::TriggerOnTable {
                        trigger_id: trigger_id.clone(),
                        function_id: create_trigger.function_id.clone(),
                    },
                ));

                MutationResult::Applied
            }
            Mutation::DropTrigger(drop_trigger) => {
                let trigger_id = Self::trigger_key(&drop_trigger.table, &drop_trigger.name);
                if !matches!(
                    self.local.triggers.get(&trigger_id),
                    Some(TriggerOverlay::Present(_))
                ) {
                    return if drop_trigger.if_exists {
                        MutationResult::Skipped
                    } else {
                        MutationResult::Conflict {
                            reason: format!(
                                "trigger '{}' does not exist on relation '{}'",
                                drop_trigger.name, drop_trigger.table
                            ),
                        }
                    };
                }
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

                self.snapshot_graph_full();
                self.local.graph.edges.retain(|e| {
                    !(matches!(e.kind, DependencyKind::TriggerOnTable { .. })
                        && e.dependent == trigger_id)
                });

                MutationResult::Applied
            }
            Mutation::RenameTrigger(rename_trigger) => {
                let old_id = Self::trigger_key(&rename_trigger.table, &rename_trigger.name);
                let new_id = Self::trigger_key(&rename_trigger.table, &rename_trigger.new_name);
                let Some(TriggerOverlay::Present(mut trigger)) =
                    self.local.triggers.get(&old_id).cloned()
                else {
                    return MutationResult::Conflict {
                        reason: format!(
                            "trigger '{}' does not exist on relation '{}'",
                            rename_trigger.name, rename_trigger.table
                        ),
                    };
                };
                if old_id != new_id
                    && matches!(
                        self.local.triggers.get(&new_id),
                        Some(TriggerOverlay::Present(_))
                    )
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "trigger '{}' already exists on relation '{}'",
                            rename_trigger.new_name, rename_trigger.table
                        ),
                    };
                }
                self.snapshot_trigger(&old_id);
                self.snapshot_trigger(&new_id);
                self.snapshot_relation(&rename_trigger.table);
                self.snapshot_graph_full();
                self.local.triggers.remove(&old_id);
                trigger.id = new_id.clone();
                trigger.name = rename_trigger.new_name.clone();
                self.local
                    .triggers
                    .insert(new_id.clone(), TriggerOverlay::Present(trigger));
                if let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(&rename_trigger.table)
                {
                    relation.triggers.remove(&rename_trigger.name);
                    relation.triggers.insert(rename_trigger.new_name.clone());
                }
                self.local.graph.propagate_rename(&old_id, &new_id);
                self.local.graph.edges.push(DependencyEdge::new(
                    old_id,
                    new_id,
                    DependencyKind::RenameTo,
                ));
                MutationResult::Applied
            }
            Mutation::AlterTable(alter) => {
                if let AlterTableActionMutation::OwnerTo { new_owner } = &alter.action {
                    let Some((owner, known)) = self.role_fact_identity(new_owner) else {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    };
                    if !known {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                    }
                    self.snapshot_relation(&alter.id);
                    return match self.local.relations.get_mut(&alter.id) {
                        Some(RelationOverlay::Present(relation)) => {
                            relation.owner = ObjectId::new("", owner);
                            MutationResult::Applied
                        }
                        _ => MutationResult::Conflict {
                            reason: format!("relation '{}' does not exist", alter.id),
                        },
                    };
                }

                let trigger_mode = match &alter.action {
                    AlterTableActionMutation::DisableTrigger { trigger_name } => Some((
                        trigger_name.as_deref(),
                        crate::model::trigger::TriggerEnableMode::Disabled,
                    )),
                    AlterTableActionMutation::EnableTrigger { trigger_name } => Some((
                        trigger_name.as_deref(),
                        crate::model::trigger::TriggerEnableMode::Origin,
                    )),
                    _ => None,
                };
                if let Some((trigger_name, enabled_mode)) = trigger_mode {
                    let all = trigger_name.is_none_or(|name| name.eq_ignore_ascii_case("all"));
                    let trigger_ids: Vec<ObjectId> = self
                        .local
                        .triggers
                        .iter()
                        .filter_map(|(id, overlay)| {
                            let TriggerOverlay::Present(trigger) = overlay else {
                                return None;
                            };
                            (trigger.table_id == alter.id
                                && (all || trigger_name == Some(trigger.name.as_str())))
                            .then(|| id.clone())
                        })
                        .collect();
                    for trigger_id in trigger_ids {
                        self.snapshot_trigger(&trigger_id);
                        if let Some(TriggerOverlay::Present(trigger)) =
                            self.local.triggers.get_mut(&trigger_id)
                        {
                            trigger.enabled_mode = enabled_mode;
                        }
                    }
                    return MutationResult::Applied;
                }

                if let AlterTableActionMutation::AddForeignKey {
                    to_table,
                    from_columns,
                    to_columns,
                    ..
                } = &alter.action
                {
                    if let Some(RelationOverlay::Present(child)) =
                        self.local.relations.get(&alter.id)
                        && let Some(column) =
                            from_columns.iter().find(|column| !child.has_column(column))
                    {
                        return MutationResult::Conflict {
                            reason: format!(
                                "foreign key column '{}' does not exist on relation '{}'",
                                column, alter.id
                            ),
                        };
                    }

                    let Some(RelationOverlay::Present(parent)) = self.local.relations.get(to_table)
                    else {
                        return MutationResult::Conflict {
                            reason: format!(
                                "foreign key references relation '{}' which does not exist",
                                to_table
                            ),
                        };
                    };
                    if let Some(column) =
                        to_columns.iter().find(|column| !parent.has_column(column))
                    {
                        return MutationResult::Conflict {
                            reason: format!(
                                "foreign key references column '{}.{}' which does not exist",
                                to_table, column
                            ),
                        };
                    }
                }

                let implicit_add = match &alter.action {
                    AlterTableActionMutation::AddColumn {
                        name, generation, ..
                    } => match generation {
                        crate::analysis::facts::ColumnGeneration::Serial => Some((
                            self.next_implicit_sequence_id(&alter.id, name, &HashSet::new()),
                            name.clone(),
                            SequenceKind::SerialLike,
                        )),
                        crate::analysis::facts::ColumnGeneration::Identity => Some((
                            self.next_implicit_sequence_id(&alter.id, name, &HashSet::new()),
                            name.clone(),
                            SequenceKind::Identity,
                        )),
                        crate::analysis::facts::ColumnGeneration::Ordinary => None,
                    },
                    _ => None,
                };
                let owned_sequences_for_column: Vec<ObjectId> = match &alter.action {
                    AlterTableActionMutation::DropColumn { name, .. }
                    | AlterTableActionMutation::RenameColumn { from: name, .. } => self
                        .local
                        .sequences
                        .iter()
                        .filter_map(|(id, overlay)| match overlay {
                            SequenceOverlay::Present(sequence)
                                if sequence.owned_by.as_ref()
                                    == Some(&(alter.id.clone(), name.clone())) =>
                            {
                                Some(id.clone())
                            }
                            _ => None,
                        })
                        .collect(),
                    _ => Vec::new(),
                };

                let using_index = match &alter.action {
                    AlterTableActionMutation::AddUniqueConstraint { using_index, .. }
                    | AlterTableActionMutation::AddPrimaryKeyConstraint { using_index, .. } => {
                        using_index.as_ref()
                    }
                    _ => None,
                };
                if let Some(index) = using_index {
                    let Some(edge) = self.local.graph.edges.iter().find(|edge| {
                        matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                            && edge.dependent == *index
                    }) else {
                        return MutationResult::Conflict {
                            reason: format!(
                                "constraint references index '{}' which does not exist",
                                index
                            ),
                        };
                    };
                    if edge.referenced != alter.id {
                        return MutationResult::Conflict {
                            reason: format!(
                                "constraint index '{}' belongs to relation '{}', not '{}'",
                                index, edge.referenced, alter.id
                            ),
                        };
                    }
                    if let DependencyKind::IndexOnRelation {
                        has_predicate,
                        is_unique,
                        eligibility_known,
                        ..
                    } = &edge.kind
                        && *eligibility_known
                        && (!is_unique || *has_predicate)
                    {
                        return MutationResult::Conflict {
                            reason: format!(
                                "constraint index '{}' must be unique and non-partial",
                                index
                            ),
                        };
                    }
                }

                self.snapshot_relation(&alter.id);
                let action_type_id = match &alter.action {
                    AlterTableActionMutation::AddColumn { ty, .. } => ty
                        .as_deref()
                        .and_then(|raw| self.resolve_type_reference(raw)),
                    AlterTableActionMutation::SetType { ty, .. } => self.resolve_type_reference(ty),
                    _ => None,
                };
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
                            generation: _,
                        } => {
                            if let Some(existing_col) = rel.columns.iter().find(|c| c.name == *name)
                            {
                                if *if_not_exists {
                                    return MutationResult::Skipped;
                                }
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "column '{}' already exists with type {}; this statement adds it again with type {}",
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
                            if let Some(column) =
                                rel.columns.iter_mut().find(|column| column.name == *name)
                            {
                                column.type_id = action_type_id.clone();
                            }

                            if let Some((sequence_id, column_name, _)) = &implicit_add
                                && column_name == name
                                && let Some(column) =
                                    rel.columns.iter_mut().find(|column| column.name == *name)
                            {
                                column.default = Some(Self::sequence_nextval_default(sequence_id));
                                column.default_expr_text = Some(format!(
                                    "nextval('{}.{}'::regclass)",
                                    sequence_id.schema, sequence_id.name
                                ));
                                column.is_nullable = false;
                            }

                            if let Some((source_table, source_col)) = depends_on {
                                self.snapshot_graph();
                                self.local.graph.edges.push(DependencyEdge::new(
                                    alter.id.clone(),
                                    source_table.clone(),
                                    DependencyKind::ColumnGeneratedFrom {
                                        column: name.clone(),
                                        depends_on_column: source_col.clone(),
                                    },
                                ));
                            }
                        }
                        AlterTableActionMutation::DropColumn { name, if_exists } => {
                            if !rel.has_column(name) {
                                if *if_exists {
                                    // Column doesn't exist and IF EXISTS was specified: no-op
                                    return MutationResult::Skipped;
                                }
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "column '{}' does not exist on relation '{}'",
                                        name, alter.id
                                    ),
                                };
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
                            if let Some(column) =
                                rel.columns.iter_mut().find(|entry| entry.name == *column)
                            {
                                column.type_id = action_type_id.clone();
                            }
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
                            not_valid,
                        } => {
                            let constraint_name = constraint_name.clone().unwrap_or_else(|| {
                                format!("{}_{}_fkey", alter.id.name, from_columns.join("_"))
                            });
                            self.snapshot_constraint(&alter.id, &constraint_name);
                            self.local.constraints.insert(
                                (alter.id.clone(), constraint_name.clone()),
                                ConstraintState {
                                    table_id: alter.id.clone(),
                                    name: constraint_name.clone(),
                                    kind: ConstraintKind::ForeignKey,
                                    validated: !not_valid,
                                },
                            );
                            self.snapshot_graph();
                            self.local.graph.edges.push(DependencyEdge::new(
                                alter.id.clone(),
                                to_table.clone(),
                                DependencyKind::ForeignKey {
                                    constraint_name: Some(constraint_name),
                                    from_columns: from_columns.clone(),
                                    to_columns: to_columns.clone(),
                                    from_generation: generation,
                                },
                            ));
                        }
                        AlterTableActionMutation::DropConstraint { name } => {
                            self.snapshot_constraint(&alter.id, name);
                            self.local
                                .constraints
                                .remove(&(alter.id.clone(), name.clone()));
                            self.snapshot_graph();
                            self.local.graph.edges.retain(|e| {
                                if let DependencyKind::ForeignKey {
                                    constraint_name, ..
                                } = &e.kind
                                {
                                    !(e.dependent == alter.id
                                        && constraint_name.as_ref() == Some(name))
                                } else {
                                    true
                                }
                            });
                        }
                        AlterTableActionMutation::RenameConstraint { old_name, new_name } => {
                            self.snapshot_constraint(&alter.id, old_name);
                            self.snapshot_constraint(&alter.id, new_name);
                            if let Some(mut constraint) = self
                                .local
                                .constraints
                                .remove(&(alter.id.clone(), old_name.clone()))
                            {
                                constraint.name = new_name.clone();
                                self.local
                                    .constraints
                                    .insert((alter.id.clone(), new_name.clone()), constraint);
                            }
                            self.snapshot_graph_full();
                            for edge in &mut self.local.graph.edges {
                                if edge.dependent == alter.id
                                    && let DependencyKind::ForeignKey {
                                        constraint_name, ..
                                    } = &mut edge.kind
                                    && constraint_name.as_deref() == Some(old_name)
                                {
                                    *constraint_name = Some(new_name.clone());
                                }
                            }
                        }
                        AlterTableActionMutation::AddCheckConstraint {
                            constraint_name,
                            not_valid,
                        } => {
                            let constraint_name = constraint_name
                                .clone()
                                .unwrap_or_else(|| format!("{}_check", alter.id.name));
                            self.snapshot_constraint(&alter.id, &constraint_name);
                            self.local.constraints.insert(
                                (alter.id.clone(), constraint_name.clone()),
                                ConstraintState {
                                    table_id: alter.id.clone(),
                                    name: constraint_name,
                                    kind: ConstraintKind::Check,
                                    validated: !not_valid,
                                },
                            );
                        }
                        AlterTableActionMutation::AddUniqueConstraint {
                            constraint_name,
                            using_index,
                        } => {
                            let constraint_name = constraint_name
                                .clone()
                                .or_else(|| using_index.as_ref().map(|index| index.name.clone()))
                                .unwrap_or_else(|| format!("{}_key", alter.id.name));
                            self.snapshot_constraint(&alter.id, &constraint_name);
                            self.local.constraints.insert(
                                (alter.id.clone(), constraint_name.clone()),
                                ConstraintState {
                                    table_id: alter.id.clone(),
                                    name: constraint_name,
                                    kind: ConstraintKind::Unique,
                                    validated: true,
                                },
                            );
                        }
                        AlterTableActionMutation::AddPrimaryKeyConstraint {
                            constraint_name,
                            using_index,
                        } => {
                            let constraint_name = constraint_name
                                .clone()
                                .or_else(|| using_index.as_ref().map(|index| index.name.clone()))
                                .unwrap_or_else(|| format!("{}_pkey", alter.id.name));
                            self.snapshot_constraint(&alter.id, &constraint_name);
                            self.local.constraints.insert(
                                (alter.id.clone(), constraint_name.clone()),
                                ConstraintState {
                                    table_id: alter.id.clone(),
                                    name: constraint_name,
                                    kind: ConstraintKind::PrimaryKey,
                                    validated: true,
                                },
                            );
                        }
                        AlterTableActionMutation::AddExcludeConstraint { constraint_name } => {
                            let constraint_name = constraint_name
                                .clone()
                                .unwrap_or_else(|| format!("{}_excl", alter.id.name));
                            self.snapshot_constraint(&alter.id, &constraint_name);
                            self.local.constraints.insert(
                                (alter.id.clone(), constraint_name.clone()),
                                ConstraintState {
                                    table_id: alter.id.clone(),
                                    name: constraint_name,
                                    kind: ConstraintKind::Exclusion,
                                    validated: true,
                                },
                            );
                        }
                        AlterTableActionMutation::ValidateConstraint { constraint_name } => {
                            self.snapshot_constraint(&alter.id, constraint_name);
                            if let Some(constraint) = self
                                .local
                                .constraints
                                .get_mut(&(alter.id.clone(), constraint_name.clone()))
                            {
                                constraint.validated = true;
                            }
                        }
                        AlterTableActionMutation::AttachPartition { child, .. } => {
                            // BUG-012: Reject cycle topologies before inserting the edge.
                            if self.local.graph.check_partition_cycle(&alter.id, child) {
                                self.snapshot_confidence();
                                self.local.confidence = Confidence::Tainted;
                            } else {
                                self.snapshot_graph();
                                self.local.graph.edges.push(DependencyEdge::new(
                                    child.clone(),
                                    alter.id.clone(),
                                    DependencyKind::PartitionOf,
                                ));
                            }
                        }
                        AlterTableActionMutation::DetachPartition { child } => {
                            self.snapshot_graph();
                            self.local.graph.edges.retain(|e| {
                                !(matches!(e.kind, DependencyKind::PartitionOf)
                                    && e.dependent == *child
                                    && e.referenced == alter.id)
                            });
                        }
                        _ => {}
                    }
                }
                if let Some((sequence_id, column_name, kind)) = implicit_add {
                    self.snapshot_sequence(&sequence_id);
                    self.snapshot_generation_counter();
                    self.local.generation_counter += 1;
                    self.local.sequences.insert(
                        sequence_id.clone(),
                        SequenceOverlay::Present(SequenceState {
                            id: sequence_id.clone(),
                            owner: self
                                .local
                                .relations
                                .get(&alter.id)
                                .and_then(|overlay| match overlay {
                                    RelationOverlay::Present(table) => Some(table.owner.clone()),
                                    RelationOverlay::Dropped => None,
                                })
                                .unwrap_or_else(|| ObjectId::new("", &self.local.current_role)),
                            owned_by: Some((alter.id.clone(), column_name.clone())),
                            kind,
                            generation: self.local.generation_counter,
                        }),
                    );
                    self.snapshot_graph();
                    self.local.graph.edges.push(DependencyEdge::new(
                        sequence_id,
                        alter.id.clone(),
                        DependencyKind::SequenceOwnedBy {
                            column: column_name,
                        },
                    ));
                }
                match &alter.action {
                    AlterTableActionMutation::DropColumn { .. } => {
                        for sequence_id in owned_sequences_for_column {
                            self.snapshot_sequence(&sequence_id);
                            self.local
                                .sequences
                                .insert(sequence_id.clone(), SequenceOverlay::Dropped);
                            self.snapshot_graph_full();
                            self.local.graph.edges.retain(|edge| {
                                !(matches!(edge.kind, DependencyKind::SequenceOwnedBy { .. })
                                    && edge.dependent == sequence_id)
                            });
                        }
                    }
                    AlterTableActionMutation::RenameColumn { to, .. } => {
                        for sequence_id in owned_sequences_for_column {
                            self.snapshot_sequence(&sequence_id);
                            if let Some(SequenceOverlay::Present(sequence)) =
                                self.local.sequences.get_mut(&sequence_id)
                                && let Some((_, column)) = &mut sequence.owned_by
                            {
                                *column = to.clone();
                            }
                            self.snapshot_graph_full();
                            for edge in &mut self.local.graph.edges {
                                if edge.dependent == sequence_id
                                    && let DependencyKind::SequenceOwnedBy { column } =
                                        &mut edge.kind
                                {
                                    *column = to.clone();
                                }
                            }
                        }
                    }
                    _ => {}
                }
                MutationResult::Applied
            }
            Mutation::CreateType(create_type) => {
                if self.relation_namespace_is_taken(&create_type.id) {
                    return MutationResult::Conflict {
                        reason: format!("type '{}' already exists", create_type.id),
                    };
                }
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
            Mutation::RenameType(rename) => {
                if !self.type_is_present(&rename.old_id) {
                    if self.baseline_covers_object(&rename.old_id) {
                        return MutationResult::Conflict {
                            reason: format!("type '{}' does not exist", rename.old_id),
                        };
                    }
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }
                if rename.old_id != rename.new_id
                    && self.relation_namespace_is_taken(&rename.new_id)
                {
                    return MutationResult::Conflict {
                        reason: format!("type '{}' already exists", rename.new_id),
                    };
                }
                if rename.old_id.schema != rename.new_id.schema
                    && !self.schema_is_present(&rename.new_id.schema)
                {
                    if self.schema_absence_is_authoritative(&rename.new_id.schema) {
                        return MutationResult::Conflict {
                            reason: format!("schema '{}' does not exist", rename.new_id.schema),
                        };
                    }
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }

                let mut remapped_functions = Vec::new();
                for (function_id, overlay) in &self.local.functions {
                    let crate::model::function::FunctionOverlay::Present(function) = overlay else {
                        continue;
                    };
                    let new_arg_types = function
                        .arg_types
                        .iter()
                        .enumerate()
                        .map(|(index, raw)| {
                            if function.arg_type_ids.get(index)
                                == Some(&Some(rename.old_id.clone()))
                            {
                                Self::remapped_type_display(
                                    raw,
                                    &rename.new_id,
                                    rename.old_id.schema != rename.new_id.schema,
                                )
                            } else {
                                raw.clone()
                            }
                        })
                        .collect::<Vec<_>>();
                    let new_return_type = if function.return_type_id == Some(rename.old_id.clone())
                    {
                        Self::remapped_type_display(
                            &function.return_type,
                            &rename.new_id,
                            rename.old_id.schema != rename.new_id.schema,
                        )
                    } else {
                        function.return_type.clone()
                    };
                    let base_name = function_id
                        .name
                        .split_once('(')
                        .map(|(name, _)| name)
                        .unwrap_or(&function_id.name);
                    let mut new_function_id = ObjectId::new(
                        &function_id.schema,
                        format!("{}({})", base_name, new_arg_types.join(",")),
                    );
                    new_function_id.inferred_schema = function_id.inferred_schema;
                    if new_function_id != *function_id
                        || new_arg_types != function.arg_types
                        || new_return_type != function.return_type
                    {
                        remapped_functions.push((
                            function_id.clone(),
                            new_function_id,
                            new_arg_types,
                            new_return_type,
                        ));
                    }
                }
                let moved_function_ids = remapped_functions
                    .iter()
                    .map(|(old_id, _, _, _)| old_id)
                    .collect::<HashSet<_>>();
                let mut destinations = HashSet::new();
                for (_, new_id, _, _) in &remapped_functions {
                    if !destinations.insert(new_id)
                        || (self.local.functions.contains_key(new_id)
                            && !moved_function_ids.contains(new_id))
                    {
                        return MutationResult::Conflict {
                            reason: format!(
                                "routine '{}' already exists after renaming type '{}'",
                                new_id, rename.old_id
                            ),
                        };
                    }
                }

                self.snapshot_namespace();
                if let Some(TypeOverlay::Present(mut state)) =
                    self.local.types.remove(&rename.old_id)
                {
                    state.id = rename.new_id.clone();
                    self.local
                        .types
                        .insert(rename.new_id.clone(), TypeOverlay::Present(state));
                }
                for overlay in self.local.relations.values_mut() {
                    if let RelationOverlay::Present(relation) = overlay {
                        for column in &mut relation.columns {
                            if column.type_id == Some(rename.old_id.clone()) {
                                column.data_type = Some(Self::remapped_type_display(
                                    column.data_type.as_deref().unwrap_or_default(),
                                    &rename.new_id,
                                    rename.old_id.schema != rename.new_id.schema,
                                ));
                                column.type_id = Some(rename.new_id.clone());
                            }
                        }
                    }
                }
                for overlay in self.local.types.values_mut() {
                    if let TypeOverlay::Present(TypeState {
                        kind:
                            TypeKind::Domain {
                                base_type,
                                base_type_id,
                            },
                        ..
                    }) = overlay
                        && *base_type_id == Some(rename.old_id.clone())
                    {
                        *base_type = Self::remapped_type_display(
                            base_type,
                            &rename.new_id,
                            rename.old_id.schema != rename.new_id.schema,
                        );
                        *base_type_id = Some(rename.new_id.clone());
                    }
                }
                for (old_id, new_id, arg_types, return_type) in remapped_functions {
                    if let Some(crate::model::function::FunctionOverlay::Present(mut function)) =
                        self.local.functions.remove(&old_id)
                    {
                        function.id = new_id.clone();
                        function.arg_types = arg_types;
                        for type_id in &mut function.arg_type_ids {
                            if *type_id == Some(rename.old_id.clone()) {
                                *type_id = Some(rename.new_id.clone());
                            }
                        }
                        function.return_type = return_type;
                        if function.return_type_id == Some(rename.old_id.clone()) {
                            function.return_type_id = Some(rename.new_id.clone());
                        }
                        self.local.functions.insert(
                            new_id.clone(),
                            crate::model::function::FunctionOverlay::Present(function),
                        );
                        if old_id != new_id {
                            self.local.graph.propagate_rename(&old_id, &new_id);
                            self.local.graph.edges.push(DependencyEdge::new(
                                old_id,
                                new_id,
                                DependencyKind::RenameTo,
                            ));
                        }
                    }
                }
                MutationResult::Applied
            }
            Mutation::AlterType(alter_type) => {
                self.snapshot_type(&alter_type.id);
                if let Some(TypeOverlay::Present(t)) = self.local.types.get_mut(&alter_type.id) {
                    match &alter_type.action {
                        AlterTypeActionMutation::AddValue {
                            new_value,
                            neighbor,
                            before,
                        } => {
                            if let TypeKind::Enum { variants } = &mut t.kind {
                                if variants.contains(new_value) {
                                    return MutationResult::Skipped;
                                }
                                let insertion_index = neighbor
                                    .as_ref()
                                    .and_then(|neighbor| {
                                        variants.iter().position(|value| value == neighbor)
                                    })
                                    .map(|index| if *before { index } else { index + 1 })
                                    .unwrap_or(variants.len());
                                variants.insert(insertion_index, new_value.clone());
                            }
                        }
                        AlterTypeActionMutation::RenameValue {
                            old_value,
                            new_value,
                        } => {
                            let TypeKind::Enum { variants } = &mut t.kind else {
                                return MutationResult::Conflict {
                                    reason: format!("type '{}' is not an enum", alter_type.id),
                                };
                            };
                            let Some(old_index) =
                                variants.iter().position(|value| value == old_value)
                            else {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "'{}' is not an existing label of enum '{}'",
                                        old_value, alter_type.id
                                    ),
                                };
                            };
                            if variants.iter().any(|value| value == new_value) {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "enum label '{}' already exists on type '{}'",
                                        new_value, alter_type.id
                                    ),
                                };
                            }
                            variants[old_index] = new_value.clone();
                        }
                    }
                } else if matches!(
                    alter_type.action,
                    AlterTypeActionMutation::RenameValue { .. }
                ) {
                    return MutationResult::Conflict {
                        reason: format!("type '{}' does not exist", alter_type.id),
                    };
                }
                MutationResult::Applied
            }
            Mutation::CreateDomain(create_domain) => {
                if self.relation_namespace_is_taken(&create_domain.id) {
                    return MutationResult::Conflict {
                        reason: format!("type '{}' already exists", create_domain.id),
                    };
                }
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
                            base_type_id: self.resolve_type_reference(&create_domain.base_type),
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
            Mutation::DropType(drop_type) => {
                for id in &drop_type.ids {
                    self.snapshot_type(id);
                    self.local.types.insert(id.clone(), TypeOverlay::Dropped);
                }
                MutationResult::Applied
            }
            Mutation::CreateSequence(create_seq) => {
                if create_seq.if_not_exists && self.relation_namespace_is_taken(&create_seq.id) {
                    return MutationResult::Skipped;
                }
                if self.relation_namespace_is_taken(&create_seq.id) {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' already exists", create_seq.id),
                    };
                }
                if let Some((table_id, column)) = &create_seq.owned_by {
                    if table_id.schema != create_seq.id.schema {
                        return MutationResult::Conflict {
                            reason: "sequence must be in the same schema as its owning table"
                                .to_string(),
                        };
                    }
                    match self.local.relations.get(table_id) {
                        Some(RelationOverlay::Present(table)) => {
                            if !table.has_column(column) {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "column '{}.{}' does not exist",
                                        table_id, column
                                    ),
                                };
                            }
                            if self.local.current_role_known
                                && table.owner.name != self.local.current_role
                            {
                                return MutationResult::Conflict {
                                    reason: "sequence and table must have the same owner"
                                        .to_string(),
                                };
                            }
                        }
                        _ if self.baseline_covers_object(table_id) && self.baseline_available => {
                            return MutationResult::Conflict {
                                reason: format!("relation '{}' does not exist", table_id),
                            };
                        }
                        _ => {
                            self.snapshot_confidence();
                            self.local.confidence = Confidence::Tainted;
                        }
                    }
                }
                self.snapshot_sequence(&create_seq.id);
                self.snapshot_generation_counter();
                self.local.generation_counter += 1;
                let generation = self.local.generation_counter;

                self.local.sequences.insert(
                    create_seq.id.clone(),
                    SequenceOverlay::Present(SequenceState {
                        id: create_seq.id.clone(),
                        owner: ObjectId::new("", self.local.current_role.clone()),
                        owned_by: create_seq.owned_by.clone(),
                        kind: if create_seq.owned_by.is_some() {
                            SequenceKind::Owned
                        } else {
                            SequenceKind::Standalone
                        },
                        generation,
                    }),
                );

                if let Some((table_id, col)) = &create_seq.owned_by {
                    self.snapshot_graph();
                    self.local.graph.edges.push(DependencyEdge::new(
                        create_seq.id.clone(),
                        table_id.clone(),
                        DependencyKind::SequenceOwnedBy {
                            column: col.clone(),
                        },
                    ));
                }
                MutationResult::Applied
            }
            Mutation::AlterSequence(alter_seq) => {
                if !self.sequence_is_present(&alter_seq.id) {
                    if alter_seq.if_exists {
                        return MutationResult::Skipped;
                    }
                    if self.baseline_covers_object(&alter_seq.id) && self.baseline_available {
                        return MutationResult::Conflict {
                            reason: format!("sequence '{}' does not exist", alter_seq.id),
                        };
                    }
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }
                let current = match self.local.sequences.get(&alter_seq.id) {
                    Some(SequenceOverlay::Present(sequence)) => sequence.clone(),
                    _ => unreachable!("presence checked above"),
                };
                match &alter_seq.action {
                    crate::analysis::mutations::AlterSequenceActionMutation::OwnedBy(owned_by) => {
                        if current.kind == SequenceKind::Identity {
                            return MutationResult::Conflict {
                                reason: "cannot change ownership of an identity sequence"
                                    .to_string(),
                            };
                        }
                        if let Some((table_id, column)) = owned_by {
                            if table_id.schema != alter_seq.id.schema {
                                return MutationResult::Conflict {
                                    reason:
                                        "sequence must be in the same schema as its owning table"
                                            .to_string(),
                                };
                            }
                            let Some(RelationOverlay::Present(table)) =
                                self.local.relations.get(table_id)
                            else {
                                return MutationResult::Conflict {
                                    reason: format!("relation '{}' does not exist", table_id),
                                };
                            };
                            if !table.has_column(column) {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "column '{}.{}' does not exist",
                                        table_id, column
                                    ),
                                };
                            }
                            if table.owner != current.owner {
                                return MutationResult::Conflict {
                                    reason: "sequence and table must have the same owner"
                                        .to_string(),
                                };
                            }
                        }
                        self.snapshot_sequence(&alter_seq.id);
                        self.snapshot_graph();
                        self.local.graph.edges.retain(|edge| {
                            !(matches!(edge.kind, DependencyKind::SequenceOwnedBy { .. })
                                && edge.dependent == alter_seq.id)
                        });
                        if let Some(SequenceOverlay::Present(sequence)) =
                            self.local.sequences.get_mut(&alter_seq.id)
                        {
                            sequence.owned_by = owned_by.clone();
                            sequence.kind = if owned_by.is_some() {
                                SequenceKind::Owned
                            } else {
                                SequenceKind::Standalone
                            };
                        }
                        if let Some((table_id, column)) = owned_by {
                            self.local.graph.edges.push(DependencyEdge::new(
                                alter_seq.id.clone(),
                                table_id.clone(),
                                DependencyKind::SequenceOwnedBy {
                                    column: column.clone(),
                                },
                            ));
                        }
                        MutationResult::Applied
                    }
                    crate::analysis::mutations::AlterSequenceActionMutation::OwnerTo(owner) => {
                        if current.kind == SequenceKind::Identity {
                            return MutationResult::Conflict {
                                reason: "cannot alter an identity sequence independently"
                                    .to_string(),
                            };
                        }
                        let Some((owner_name, known)) = self.role_fact_identity(owner) else {
                            self.snapshot_confidence();
                            self.local.confidence = Confidence::Tainted;
                            return MutationResult::Skipped;
                        };
                        if known
                            && self.local.roles_known
                            && self.present_role(&owner_name).is_none()
                        {
                            return MutationResult::Conflict {
                                reason: format!("role '{}' does not exist", owner_name),
                            };
                        }
                        if let Some((table_id, _)) = &current.owned_by
                            && let Some(RelationOverlay::Present(table)) =
                                self.local.relations.get(table_id)
                            && table.owner.name != owner_name
                        {
                            return MutationResult::Conflict {
                                reason: "sequence and table must have the same owner".to_string(),
                            };
                        }
                        self.snapshot_sequence(&alter_seq.id);
                        if let Some(SequenceOverlay::Present(sequence)) =
                            self.local.sequences.get_mut(&alter_seq.id)
                        {
                            sequence.owner = ObjectId::new("", owner_name);
                        }
                        MutationResult::Applied
                    }
                    crate::analysis::mutations::AlterSequenceActionMutation::RenameTo(new_id)
                    | crate::analysis::mutations::AlterSequenceActionMutation::SetSchema(new_id) => {
                        if current.kind == SequenceKind::Identity {
                            return MutationResult::Conflict {
                                reason: "cannot alter an identity sequence independently"
                                    .to_string(),
                            };
                        }
                        if self.relation_namespace_is_taken(new_id) {
                            return MutationResult::Conflict {
                                reason: format!("relation '{}' already exists", new_id),
                            };
                        }
                        if let Some((table_id, _)) = &current.owned_by
                            && table_id.schema != new_id.schema
                        {
                            return MutationResult::Conflict {
                                reason: "sequence must be in the same schema as its owning table"
                                    .to_string(),
                            };
                        }
                        self.snapshot_namespace();
                        let mut moved = current;
                        moved.id = new_id.clone();
                        self.local.sequences.remove(&alter_seq.id);
                        self.local
                            .sequences
                            .insert(new_id.clone(), SequenceOverlay::Present(moved));
                        self.local.graph.propagate_rename(&alter_seq.id, new_id);
                        self.local.graph.edges.push(DependencyEdge::new(
                            alter_seq.id.clone(),
                            new_id.clone(),
                            DependencyKind::RenameTo,
                        ));
                        if self.baseline_sequences.remove(&alter_seq.id) {
                            self.baseline_sequences.insert(new_id.clone());
                        }
                        MutationResult::Applied
                    }
                    crate::analysis::mutations::AlterSequenceActionMutation::Other => {
                        MutationResult::Applied
                    }
                }
            }
            Mutation::DropSequence(drop_seq) => {
                if !drop_seq.if_exists {
                    let missing: Vec<ObjectId> = drop_seq
                        .ids
                        .iter()
                        .filter(|id| !self.sequence_is_present(id))
                        .cloned()
                        .collect();
                    for id in &missing {
                        if self.baseline_covers_object(id) && self.baseline_available {
                            return MutationResult::Conflict {
                                reason: format!("sequence '{}' does not exist", id),
                            };
                        }
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                    }
                }
                let present: Vec<ObjectId> = drop_seq
                    .ids
                    .iter()
                    .filter(|id| self.sequence_is_present(id))
                    .cloned()
                    .collect();
                if present.is_empty() {
                    return MutationResult::Skipped;
                }
                for id in &present {
                    let Some(SequenceOverlay::Present(sequence)) = self.local.sequences.get(id)
                    else {
                        continue;
                    };
                    if sequence.kind == SequenceKind::Identity {
                        return MutationResult::Conflict {
                            reason: format!("cannot drop identity sequence '{}' independently", id),
                        };
                    }
                    if sequence.kind == SequenceKind::SerialLike && !drop_seq.cascade {
                        return MutationResult::Conflict {
                            reason: format!("sequence '{}' still has dependent defaults", id),
                        };
                    }
                }
                if drop_seq.cascade {
                    let serial_owners: Vec<(ObjectId, String)> = present
                        .iter()
                        .filter_map(|id| match self.local.sequences.get(id) {
                            Some(SequenceOverlay::Present(sequence))
                                if sequence.kind == SequenceKind::SerialLike =>
                            {
                                sequence.owned_by.clone()
                            }
                            _ => None,
                        })
                        .collect();
                    for (table_id, column) in serial_owners {
                        self.snapshot_relation(&table_id);
                        if let Some(RelationOverlay::Present(table)) =
                            self.local.relations.get_mut(&table_id)
                            && let Some(column) =
                                table.columns.iter_mut().find(|item| item.name == column)
                        {
                            column.default = None;
                            column.default_expr_text = None;
                        }
                    }
                }
                for id in &present {
                    self.snapshot_sequence(id);
                    self.local
                        .sequences
                        .insert(id.clone(), SequenceOverlay::Dropped);
                }
                self.snapshot_graph_full();
                self.local.graph.edges.retain(|e| {
                    !(matches!(e.kind, DependencyKind::SequenceOwnedBy { .. })
                        && present.contains(&e.dependent))
                });
                MutationResult::Applied
            }
            Mutation::Rename(rename) => {
                let renames_relation = self.relation_is_present(&rename.old_id);
                let renames_index = self.index_is_present(&rename.old_id);
                if !renames_relation && !renames_index {
                    if self.baseline_covers_object(&rename.old_id) {
                        return MutationResult::Conflict {
                            reason: format!("relation '{}' does not exist", rename.old_id),
                        };
                    }
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }
                if rename.old_id != rename.new_id
                    && self.relation_namespace_is_taken(&rename.new_id)
                {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' already exists", rename.new_id),
                    };
                }
                if rename.old_id.schema != rename.new_id.schema
                    && !self.schema_is_present(&rename.new_id.schema)
                {
                    if self.schema_absence_is_authoritative(&rename.new_id.schema) {
                        return MutationResult::Conflict {
                            reason: format!("schema '{}' does not exist", rename.new_id.schema),
                        };
                    }
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }

                self.snapshot_namespace();
                if let Some(RelationOverlay::Present(mut state)) =
                    self.local.relations.remove(&rename.old_id)
                {
                    state.id = rename.new_id.clone();
                    self.local
                        .relations
                        .insert(rename.new_id.clone(), RelationOverlay::Present(state));
                }
                let owned_sequence_ids: Vec<ObjectId> = self
                    .local
                    .sequences
                    .iter()
                    .filter_map(|(id, overlay)| match overlay {
                        SequenceOverlay::Present(sequence)
                            if sequence
                                .owned_by
                                .as_ref()
                                .is_some_and(|(table, _)| table == &rename.old_id) =>
                        {
                            Some(id.clone())
                        }
                        _ => None,
                    })
                    .collect();
                for sequence_id in owned_sequence_ids {
                    self.snapshot_sequence(&sequence_id);
                    if let Some(SequenceOverlay::Present(sequence)) =
                        self.local.sequences.get_mut(&sequence_id)
                        && let Some((table, _)) = &mut sequence.owned_by
                    {
                        *table = rename.new_id.clone();
                    }
                }
                let triggers_to_move: Vec<(ObjectId, crate::model::trigger::TriggerState)> = self
                    .local
                    .triggers
                    .iter()
                    .filter_map(|(id, overlay)| match overlay {
                        TriggerOverlay::Present(trigger) if trigger.table_id == rename.old_id => {
                            Some((id.clone(), trigger.clone()))
                        }
                        _ => None,
                    })
                    .collect();
                for (old_trigger_id, mut trigger) in triggers_to_move {
                    let new_trigger_id = Self::trigger_key(&rename.new_id, &trigger.name);
                    self.local.triggers.remove(&old_trigger_id);
                    trigger.id = new_trigger_id.clone();
                    trigger.table_id = rename.new_id.clone();
                    self.local
                        .triggers
                        .insert(new_trigger_id.clone(), TriggerOverlay::Present(trigger));
                    self.local
                        .graph
                        .propagate_rename(&old_trigger_id, &new_trigger_id);
                    self.local.graph.edges.push(DependencyEdge::new(
                        old_trigger_id,
                        new_trigger_id,
                        DependencyKind::RenameTo,
                    ));
                }
                let constraints_to_move: Vec<(String, ConstraintState)> = self
                    .local
                    .constraints
                    .iter()
                    .filter(|((table_id, _), _)| table_id == &rename.old_id)
                    .map(|((_, name), constraint)| (name.clone(), constraint.clone()))
                    .collect();
                for (name, mut constraint) in constraints_to_move {
                    self.snapshot_constraint(&rename.old_id, &name);
                    self.snapshot_constraint(&rename.new_id, &name);
                    self.local
                        .constraints
                        .remove(&(rename.old_id.clone(), name.clone()));
                    constraint.table_id = rename.new_id.clone();
                    self.local
                        .constraints
                        .insert((rename.new_id.clone(), name), constraint);
                }
                self.local.pending_validation = std::mem::take(&mut self.local.pending_validation)
                    .into_iter()
                    .map(|(table, name)| {
                        if table == rename.old_id {
                            (rename.new_id.clone(), name)
                        } else {
                            (table, name)
                        }
                    })
                    .collect();
                self.local.graph.edges.push(DependencyEdge::new(
                    rename.old_id.clone(),
                    rename.new_id.clone(),
                    DependencyKind::RenameTo,
                ));
                self.local
                    .graph
                    .propagate_rename(&rename.old_id, &rename.new_id);

                if renames_relation {
                    if self.baseline_relations.remove(&rename.old_id) {
                        self.baseline_relations.insert(rename.new_id.clone());
                    }
                    if self.baseline_fk_dependencies.remove(&rename.old_id) {
                        self.baseline_fk_dependencies.insert(rename.new_id.clone());
                    }
                    self.baseline_foreign_keys = std::mem::take(&mut self.baseline_foreign_keys)
                        .into_iter()
                        .map(|(table, name)| {
                            if table == rename.old_id {
                                (rename.new_id.clone(), name)
                            } else {
                                (table, name)
                            }
                        })
                        .collect();
                }
                if renames_index && self.baseline_indexes.remove(&rename.old_id) {
                    self.baseline_indexes.insert(rename.new_id.clone());
                }

                MutationResult::Applied
            }
            Mutation::DropView(drop_view) => {
                for id in &drop_view.ids {
                    self.snapshot_relation(id);
                    self.local
                        .relations
                        .insert(id.clone(), RelationOverlay::Dropped);
                }
                self.snapshot_graph_full();
                self.local.graph.edges.retain(|e| {
                    !(matches!(e.kind, DependencyKind::ViewDependency { .. })
                        && drop_view.ids.contains(&e.dependent))
                });
                MutationResult::Applied
            }
            Mutation::DropMaterializedView(drop_mv) => {
                for id in &drop_mv.ids {
                    self.snapshot_relation(id);
                    self.local
                        .relations
                        .insert(id.clone(), RelationOverlay::Dropped);
                }
                self.snapshot_graph_full();
                self.local.graph.edges.retain(|e| {
                    !((matches!(e.kind, DependencyKind::ViewDependency { .. })
                        && drop_mv.ids.contains(&e.dependent))
                        || (matches!(e.kind, DependencyKind::IndexOnRelation { .. })
                            && drop_mv.ids.contains(&e.referenced)))
                });
                MutationResult::Applied
            }
            Mutation::DropIndex(drop_idx) => {
                self.snapshot_graph();
                self.local.graph.edges.retain(|e| {
                    !(matches!(e.kind, DependencyKind::IndexOnRelation { .. })
                        && e.dependent == drop_idx.id)
                });
                MutationResult::Applied
            }
            Mutation::ChangeRelationOwner { id, new_owner } => {
                let Some((owner, known)) = self.role_fact_identity(new_owner) else {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                };
                if !known {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                }
                self.snapshot_relation(id);
                if let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(id) {
                    relation.owner = ObjectId::new("", owner);
                    MutationResult::Applied
                } else {
                    MutationResult::Conflict {
                        reason: format!("relation '{}' does not exist", id),
                    }
                }
            }
            Mutation::SearchPath(sp) => {
                self.snapshot_search_path();
                self.snapshot_confidence();
                match &sp.target {
                    SearchPathTarget::Default => {
                        self.local.search_path_template =
                            self.local.default_search_path_template.clone();
                        self.refresh_role_sensitive_search_path();
                    }
                    SearchPathTarget::Schemas(schemas) => {
                        self.local.search_path_template = schemas.clone();
                        self.refresh_role_sensitive_search_path();
                    }
                }
                MutationResult::Applied
            }
            Mutation::SwitchRole {
                role,
                local,
                is_session_auth,
            } => {
                if *local && self.local.transactions.is_empty() {
                    // PostgreSQL warns and leaves the setting unchanged.
                    return MutationResult::Skipped;
                }

                let target = if let Some(role) = role {
                    let Some(identity) = self.role_fact_identity(role) else {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    };
                    Some(identity)
                } else if *is_session_auth {
                    Some((
                        self.local.authenticated_role.clone(),
                        self.local.authenticated_role_known,
                    ))
                } else {
                    Some((
                        self.local.session_role.clone(),
                        self.local.session_role_known,
                    ))
                };
                let (target_name, target_known) = target.expect("role reset always has a target");
                let persistent_role_reset_target = if role.is_none() && !*is_session_auth {
                    Some((
                        self.local.persistent_session_role.clone(),
                        self.local.persistent_session_role_known,
                    ))
                } else {
                    None
                };

                let authorized = if role.is_none() {
                    Some(true)
                } else if *is_session_auth {
                    self.can_set_session_authorization_to(&target_name)
                } else {
                    self.can_set_role_to(&target_name)
                };
                match authorized {
                    Some(false) => {
                        return MutationResult::Conflict {
                            reason: if self.present_role(&target_name).is_none() {
                                format!("role '{}' does not exist", target_name)
                            } else {
                                format!("permission denied to set role '{}'", target_name)
                            },
                        };
                    }
                    None => {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                    }
                    Some(true) => {}
                }

                self.snapshot_role_context();
                self.snapshot_search_path();
                self.snapshot_confidence();
                if *is_session_auth {
                    self.local.session_role = target_name.clone();
                    self.local.session_role_known = target_known;
                    self.local.current_role = target_name.clone();
                    self.local.current_role_known = target_known;
                    if !local {
                        self.local.persistent_session_role = target_name.clone();
                        self.local.persistent_session_role_known = target_known;
                        self.local.persistent_current_role = target_name;
                        self.local.persistent_current_role_known = target_known;
                    }
                } else {
                    self.local.current_role = target_name.clone();
                    self.local.current_role_known = target_known;
                    if !local {
                        let (persistent_name, persistent_known) =
                            persistent_role_reset_target.unwrap_or((target_name, target_known));
                        self.local.persistent_current_role = persistent_name;
                        self.local.persistent_current_role_known = persistent_known;
                    }
                }
                self.refresh_role_sensitive_search_path();
                MutationResult::Applied
            }
            Mutation::BeginTransaction => {
                if self.local.transactions.is_empty() {
                    self.local.transactions.push(TransactionFrame::root());
                    MutationResult::Applied
                } else {
                    // PostgreSQL emits a warning and leaves the current
                    // transaction active for a nested BEGIN.
                    MutationResult::Skipped
                }
            }
            Mutation::CommitTransaction => {
                if self.local.transaction_aborted {
                    while let Some(frame) = self.local.transactions.pop() {
                        self.rollback_frame(frame);
                    }
                } else {
                    while self.local.transactions.pop().is_some() {}
                    self.restore_persistent_role_context();
                }
                self.local.transaction_aborted = false;
                MutationResult::Applied
            }
            Mutation::CommitAndChain => {
                if self.local.transactions.is_empty() {
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Conflict {
                        reason: "COMMIT AND CHAIN can only be used in transaction blocks"
                            .to_string(),
                    };
                }
                if self.local.transaction_aborted {
                    while let Some(frame) = self.local.transactions.pop() {
                        self.rollback_frame(frame);
                    }
                } else {
                    while self.local.transactions.pop().is_some() {}
                    self.restore_persistent_role_context();
                }
                self.local.transaction_aborted = false;
                self.local.transactions.push(TransactionFrame::root());
                MutationResult::Applied
            }
            Mutation::RollbackTransaction => {
                while let Some(frame) = self.local.transactions.pop() {
                    self.rollback_frame(frame);
                }
                self.local.transaction_aborted = false;
                MutationResult::Applied
            }
            Mutation::RollbackAndChain => {
                if self.local.transactions.is_empty() {
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Conflict {
                        reason: "ROLLBACK AND CHAIN can only be used in transaction blocks"
                            .to_string(),
                    };
                }
                while let Some(frame) = self.local.transactions.pop() {
                    self.rollback_frame(frame);
                }
                self.local.transaction_aborted = false;
                self.local.transactions.push(TransactionFrame::root());
                MutationResult::Applied
            }
            Mutation::RollbackToSavepoint(rts) => {
                let Some(position) = self
                    .local
                    .transactions
                    .iter()
                    .rposition(|frame| frame.is_named_savepoint(&rts.name))
                else {
                    self.local.confidence = Confidence::Tainted;
                    if !self.local.transactions.is_empty() {
                        self.local.transaction_aborted = true;
                    }
                    return MutationResult::Conflict {
                        reason: format!("savepoint '{}' does not exist", rts.name),
                    };
                };
                let rolled_back = self.local.transactions.split_off(position + 1);
                // Frames are popped newest-first. Restore them in that same
                // order before restoring changes made after the target
                // savepoint itself; undo logs are chronological.
                for frame in rolled_back.into_iter().rev() {
                    self.rollback_frame(frame);
                }
                let undo_log = std::mem::take(&mut self.local.transactions[position].undo_log);
                self.rollback_undo_log(undo_log);
                self.local.transaction_aborted = false;
                MutationResult::Applied
            }
            Mutation::Savepoint(sp) => {
                if self.local.transactions.is_empty() {
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Conflict {
                        reason: "SAVEPOINT can only be used in transaction blocks".to_string(),
                    };
                }
                self.local
                    .transactions
                    .push(TransactionFrame::savepoint(sp.name.clone()));
                MutationResult::Applied
            }
            Mutation::ReleaseSavepoint(rsp) => {
                let Some(position) = self
                    .local
                    .transactions
                    .iter()
                    .rposition(|frame| frame.is_named_savepoint(&rsp.name))
                else {
                    self.local.confidence = Confidence::Tainted;
                    if !self.local.transactions.is_empty() {
                        self.local.transaction_aborted = true;
                    }
                    return MutationResult::Conflict {
                        reason: format!("savepoint '{}' does not exist", rsp.name),
                    };
                };
                if position == 0 {
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Conflict {
                        reason: format!("savepoint '{}' is not inside a transaction", rsp.name),
                    };
                }

                let released = self.local.transactions.split_off(position);
                let outer = self
                    .local
                    .transactions
                    .last_mut()
                    .expect("a released savepoint always has an outer transaction frame");
                for frame in released {
                    outer.undo_log.extend(frame.undo_log);
                }
                MutationResult::Applied
            }
            Mutation::Opaque(_) => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                MutationResult::Applied
            }
            Mutation::CreateFunction(f) => {
                if matches!(
                    self.local.functions.get(&f.id),
                    Some(crate::model::function::FunctionOverlay::Present(_))
                ) && !f.or_replace
                {
                    return MutationResult::Conflict {
                        reason: format!("routine '{}' already exists", f.id),
                    };
                }
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
                            arg_type_ids: f
                                .params
                                .iter()
                                .map(|parameter| self.resolve_type_reference(&parameter.ty))
                                .collect(),
                            return_type: f
                                .return_type
                                .as_ref()
                                .map(|rt| match rt {
                                    crate::analysis::facts::RetTypeFact::Scalar(ty) => ty.clone(),
                                    crate::analysis::facts::RetTypeFact::Table(columns) => columns
                                        .iter()
                                        .map(|column| {
                                            format!(
                                                "{} {}",
                                                column.name,
                                                column.ty.as_deref().unwrap_or("unknown")
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                })
                                .unwrap_or_default(),
                            return_type_id: f.return_type.as_ref().and_then(|return_type| {
                                match return_type {
                                    crate::analysis::facts::RetTypeFact::Scalar(ty) => {
                                        self.resolve_type_reference(ty)
                                    }
                                    crate::analysis::facts::RetTypeFact::Table(_) => None,
                                }
                            }),
                            volatility,
                            language,
                            security,
                        },
                    ),
                );
                MutationResult::Applied
            }
            Mutation::AlterFunction(f) => {
                use crate::analysis::facts::{AlterFunctionAction, FuncOptionFact};
                use crate::model::function::{FunctionOverlay, SecurityMode, Volatility};

                match &f.action {
                    AlterFunctionAction::OptionsChange(options) => {
                        self.snapshot_function(&f.id);
                        if let Some(FunctionOverlay::Present(function)) =
                            self.local.functions.get_mut(&f.id)
                        {
                            for option in options {
                                match option {
                                    FuncOptionFact::Volatility(volatility) => {
                                        function.volatility = match volatility {
                                            crate::analysis::facts::VolatilityKind::Volatile => {
                                                Volatility::Volatile
                                            }
                                            crate::analysis::facts::VolatilityKind::Stable => {
                                                Volatility::Stable
                                            }
                                            crate::analysis::facts::VolatilityKind::Immutable => {
                                                Volatility::Immutable
                                            }
                                        };
                                    }
                                    FuncOptionFact::Security(security) => {
                                        function.security = match security {
                                            crate::analysis::facts::SecurityKind::Invoker => {
                                                SecurityMode::Invoker
                                            }
                                            crate::analysis::facts::SecurityKind::Definer => {
                                                SecurityMode::Definer
                                            }
                                        };
                                    }
                                    FuncOptionFact::Language(language) => {
                                        function.language = language.clone();
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    AlterFunctionAction::Rename { to, .. } => {
                        let signature =
                            f.id.name
                                .find('(')
                                .map(|index| &f.id.name[index..])
                                .unwrap_or("");
                        let new_id = ObjectId::new(f.id.schema.clone(), format!("{to}{signature}"));
                        self.move_function(&f.id, &new_id);
                    }
                    AlterFunctionAction::SchemaChange { new_schema } => {
                        let new_id = ObjectId::new(new_schema.clone(), f.id.name.clone());
                        self.move_function(&f.id, &new_id);
                    }
                    AlterFunctionAction::OwnerChange(_)
                    | AlterFunctionAction::DependsOnExtension { .. }
                    | AlterFunctionAction::NoDependsOnExtension { .. } => {
                        self.snapshot_function(&f.id);
                    }
                }
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
                            return MutationResult::Conflict {
                                reason: format!("function '{}' does not exist", id),
                            };
                        }
                    } else {
                        let dependent_triggers: Vec<(ObjectId, ObjectId)> = self
                            .local
                            .graph
                            .edges
                            .iter()
                            .filter_map(|edge| {
                                let DependencyKind::TriggerOnTable { function_id, .. } = &edge.kind
                                else {
                                    return None;
                                };
                                (function_id == &id)
                                    .then(|| (edge.dependent.clone(), edge.referenced.clone()))
                            })
                            .collect();
                        if !dependent_triggers.is_empty() && !f.cascade {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "function '{}' still has dependent triggers; use CASCADE",
                                    id
                                ),
                            };
                        }

                        any_applied = true;
                        self.snapshot_function(&id);
                        self.local
                            .functions
                            .insert(id.clone(), crate::model::function::FunctionOverlay::Dropped);

                        if f.cascade {
                            for (trigger_id, table_id) in &dependent_triggers {
                                let trigger_name =
                                    self.local.triggers.get(trigger_id).and_then(|overlay| {
                                        match overlay {
                                            TriggerOverlay::Present(trigger) => {
                                                Some(trigger.name.clone())
                                            }
                                            TriggerOverlay::Dropped => None,
                                        }
                                    });
                                self.snapshot_trigger(trigger_id);
                                self.local
                                    .triggers
                                    .insert(trigger_id.clone(), TriggerOverlay::Dropped);
                                self.snapshot_relation(table_id);
                                if let Some(RelationOverlay::Present(relation)) =
                                    self.local.relations.get_mut(table_id)
                                    && let Some(trigger_name) = trigger_name
                                {
                                    relation.triggers.remove(&trigger_name);
                                }
                            }
                            if !dependent_triggers.is_empty() {
                                self.snapshot_graph_full();
                                self.local.graph.edges.retain(|edge| {
                                    !dependent_triggers
                                        .iter()
                                        .any(|(trigger_id, _)| edge.dependent == *trigger_id)
                                });
                            }
                        }
                    }
                }
                if any_applied {
                    MutationResult::Applied
                } else {
                    MutationResult::Skipped
                }
            }
            Mutation::CreateProcedure(p) => {
                if matches!(
                    self.local.functions.get(&p.id),
                    Some(crate::model::function::FunctionOverlay::Present(_))
                ) && !p.or_replace
                {
                    return MutationResult::Conflict {
                        reason: format!("routine '{}' already exists", p.id),
                    };
                }
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
                            arg_type_ids: p
                                .params
                                .iter()
                                .map(|parameter| self.resolve_type_reference(&parameter.ty))
                                .collect(),
                            return_type: "void".to_string(),
                            return_type_id: None,
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
                            return MutationResult::Conflict {
                                reason: format!("procedure '{}' does not exist", id),
                            };
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
                    self.snapshot_graph_full();
                    for obj in objects {
                        if let crate::analysis::facts::PublicationObjectFact::Table {
                            name, ..
                        } = obj
                        {
                            let table_id = self.resolve_relation_id(name);
                            self.local.graph.edges.push(DependencyEdge::new(
                                table_id,
                                ObjectId::new("public", &p.name),
                                DependencyKind::PublicationIncludes {
                                    publication_name: p.name.clone(),
                                },
                            ));
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
                self.snapshot_graph_full();
                self.local.graph.edges.retain(|e| {
                    !(matches!(e.kind, DependencyKind::PublicationIncludes { .. })
                        && p.names.contains(&e.referenced.name))
                });
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
                if matches!(
                    self.local.roles.get(&role_id),
                    Some(crate::model::role::RoleOverlay::Present(_))
                ) {
                    return MutationResult::Conflict {
                        reason: format!("role '{}' already exists", r.name),
                    };
                }
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
                        can_set_role_to: Vec::new(),
                        granted_privileges: Vec::new(),
                    }),
                );
                MutationResult::Applied
            }
            Mutation::AlterRole(r) => {
                if let Some(role_id) = Self::resolve_role_name(
                    &r.name,
                    &self.local.current_role,
                    &self.local.session_role,
                ) {
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
                        &self.local.session_role,
                    ) {
                        self.snapshot_role(&role_id);
                        if !r.if_exists
                            && !matches!(
                                self.local.roles.get(&role_id),
                                Some(crate::model::role::RoleOverlay::Present(_))
                            )
                        {
                            return MutationResult::Conflict {
                                reason: format!("role '{}' does not exist", name),
                            };
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
                    graph: self.local.graph.edges.clone(),
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
        self.local.graph.propagate_rename(old_id, new_id);
        self.local.graph.edges.push(DependencyEdge::new(
            old_id.clone(),
            new_id.clone(),
            DependencyKind::RenameTo,
        ));
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
                len: self.local.graph.edges.len(),
            });
        }
    }

    fn snapshot_graph_full(&mut self) {
        if let Some(frame) = self.local.transactions.last_mut() {
            frame.undo_log.push(StateChange::GraphSnapshot {
                previous: self.local.graph.edges.clone(),
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
                    self.local.graph.edges = snapshot.graph;
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
                StateChange::GraphLengthMarker { len } => {
                    self.local.graph.edges.truncate(len);
                }
                StateChange::GraphSnapshot { previous } => {
                    self.local.graph.edges = previous;
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
                } => {
                    self.local.search_path = previous;
                    self.local.search_path_template = previous_template;
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
}
