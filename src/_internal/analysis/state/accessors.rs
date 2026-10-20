use super::*;

impl AnalysisState {
    #[cfg(test)]
    pub(crate) fn get_relation(&self, id: &ObjectId) -> Option<&RelationOverlay> {
        self.local.relations.get(id)
    }

    pub(crate) fn resolve_function_schema(
        &self,
        name: &crate::_internal::ast::identifiers::QualifiedName,
        sig_str: &str,
    ) -> String {
        if let Some(schema) = &name.schema {
            return schema.resolve();
        }
        for entry in &self.local.search_path {
            let Some(schema) = entry.searched_schema() else {
                continue;
            };
            let candidate = ObjectId::new(schema, sig_str.to_string());
            if self.routine_is_present(&candidate) {
                return schema.to_string();
            }
        }
        self.local
            .search_path
            .first()
            .and_then(SearchPathEntry::name)
            .unwrap_or_default()
            .to_string()
    }

    pub(crate) fn resolve_relation_id(
        &self,
        name: &crate::_internal::ast::identifiers::QualifiedName,
    ) -> ObjectId {
        if let Some(schema) = &name.schema {
            return ObjectId::new(schema.resolve(), name.name.resolve());
        }
        let resolved_name = name.name.resolve();
        for entry in &self.local.search_path {
            let Some(schema) = entry.searched_schema() else {
                continue;
            };
            let mut candidate = ObjectId::new(schema, resolved_name.clone());
            if self.relation_namespace_object_is_present(&candidate) {
                candidate.inferred_schema = true;
                return candidate;
            }
        }
        // An empty path searches nothing, so no schema may be inferred.
        let schema = self
            .local
            .search_path
            .first()
            .and_then(SearchPathEntry::name)
            .unwrap_or_default();
        let mut id = ObjectId::new(schema, resolved_name);
        id.inferred_schema = true;
        id
    }

    /// The schema an unqualified creation targets: the first path entry whose
    /// schema the model knows exists. The system catalog is not a valid target,
    /// and an unresolved entry never is, because PostgreSQL may not create
    /// there or may not have searched it at all.
    pub(crate) fn creation_schema(&self) -> Option<&str> {
        self.local.search_path.iter().find_map(|entry| {
            entry
                .searched_schema()
                .filter(|schema| *schema != SYSTEM_CATALOG_SCHEMA)
        })
    }

    pub(crate) fn relation_is_present(&self, id: &ObjectId) -> bool {
        matches!(
            self.local.relations.get(id),
            Some(RelationOverlay::Present(_))
        )
    }

    /// Record a configured version, used only when the cache carries none.
    pub(crate) fn record_not_evaluated(
        &mut self,
        record: crate::_internal::report::violations::NotEvaluated,
    ) {
        if !self
            .not_evaluated
            .iter()
            .any(|entry| entry.rule_id == record.rule_id && entry.cause == record.cause)
        {
            self.not_evaluated.push(record);
        }
    }

    pub(crate) fn not_evaluated(&self) -> &[crate::_internal::report::violations::NotEvaluated] {
        &self.not_evaluated
    }

    /// Record a configured version, used only when the cache carries none.
    pub(crate) fn with_asserted_pg_version(mut self, version: Option<u32>) -> Self {
        self.asserted_pg_version_num = version;
        self
    }

    /// The database the migrations are applied to, when the caller states it.
    pub(crate) fn set_target_database(&mut self, database: Option<String>) {
        self.target_database = database;
    }

    /// The database the migration runs against, and whether it is known.
    ///
    /// PostgreSQL compares a `REINDEX DATABASE`/`REINDEX SYSTEM` name with the
    /// database its session is attached to. A baseline records where it was
    /// synchronized *from*, which is a different fact, so it is never used
    /// here.
    pub(crate) fn target_database(&self) -> Option<&str> {
        self.target_database.as_deref()
    }

    /// The version in effect and where it came from. An observed cache version
    /// always wins over a configured one.
    pub(crate) fn pg_version(&self) -> PgVersion {
        match (self.pg_version_num, self.asserted_pg_version_num) {
            (Some(version), _) => PgVersion::Observed(version),
            (None, Some(version)) => PgVersion::Assumed(version),
            (None, None) => PgVersion::Unresolved,
        }
    }

    /// Read-only search-path view for name resolution. Keeping resolution on
    /// this accessor prevents callers from coupling themselves to `LocalState`.
    pub(crate) fn search_path(&self) -> &[SearchPathEntry] {
        &self.local.search_path
    }

    /// The named schemas of the effective path, in order. Used where an
    /// unresolved entry can neither match nor change the answer.
    #[cfg(test)]
    pub(crate) fn search_path_names(&self) -> Vec<String> {
        self.local
            .search_path
            .iter()
            .filter_map(|entry| entry.searched_schema())
            .map(str::to_string)
            .collect()
    }

    /// Whether an unqualified lookup that resolved to `schema` could have
    /// resolved elsewhere: an unresolved entry lies before it in the path, so
    /// PostgreSQL may have searched a schema the model cannot see first.
    pub(crate) fn path_shadows(&self, schema: &str) -> bool {
        let mut shadow = false;
        for entry in &self.local.search_path {
            match entry {
                SearchPathEntry::Schema(name) if name == schema => return shadow,
                SearchPathEntry::Schema(_) => {}
                SearchPathEntry::Unresolved(_) => shadow = true,
            }
        }
        shadow
    }

    /// Built-in types of the synchronized cluster, used to resolve written type
    /// names to catalog identities.
    pub(crate) fn builtin_types(&self) -> &BuiltinTypeCatalogue {
        &self.local.builtin_types
    }

    pub(crate) fn casts(&self) -> &CastCatalogue {
        &self.local.casts
    }

    pub(crate) fn aggregates(&self) -> &crate::_internal::model::aggregate::AggregateCatalogue {
        &self.local.aggregates
    }

    /// Whether this session has a temporary schema, which is searched before
    /// every explicit path entry for relations and types.
    pub(crate) fn temp_namespace_exists(&self) -> bool {
        self.local.saw_temp_object
            && (self
                .local
                .relations
                .keys()
                .any(|id| is_session_temp_schema(&id.schema))
                || self
                    .local
                    .types
                    .keys()
                    .any(|id| is_session_temp_schema(&id.schema)))
    }

    /// Entries to search for an unqualified relation or type, implicit first.
    ///
    /// PostgreSQL searches the temporary namespace before every path entry
    /// only when the path does not name it; a written `pg_temp` is searched at
    /// its position like any other entry.
    pub(crate) fn relation_search_path(&self) -> Vec<SearchPathEntry> {
        if !self.temp_namespace_exists()
            || self
                .local
                .search_path
                .iter()
                .any(|entry| entry.searched_schema() == Some(SESSION_TEMP_SCHEMA))
        {
            return self.local.search_path.clone();
        }
        let mut path = Vec::with_capacity(self.local.search_path.len() + 1);
        path.push(SearchPathEntry::Schema(SESSION_TEMP_SCHEMA.to_string()));
        path.extend(self.local.search_path.iter().cloned());
        path
    }

    /// Entries to search for an unqualified routine.
    ///
    /// PostgreSQL never searches the temporary schema for function or operator
    /// names, even when a path entry names it explicitly, so the entry is
    /// dropped rather than searched in place.
    pub(crate) fn routine_search_path(&self) -> Vec<SearchPathEntry> {
        self.local
            .search_path
            .iter()
            .filter(|entry| entry.name() != Some(SESSION_TEMP_SCHEMA))
            .cloned()
            .collect()
    }

    pub(crate) fn note_temp_object_created(&mut self) {
        self.local.saw_temp_object = true;
        // A path that names the temporary alias could not search it before the
        // namespace existed; now it can, at its written position.
        self.refresh_role_sensitive_search_path();
    }

    /// Column names and types of a present relation, for view projection.
    pub(crate) fn relation_column_types(
        &self,
        id: &ObjectId,
    ) -> Option<Vec<(String, Option<String>)>> {
        match self.local.relations.get(id) {
            Some(RelationOverlay::Present(relation)) => Some(
                relation
                    .columns
                    .iter()
                    .map(|column| (column.name.clone(), column.data_type.clone()))
                    .collect(),
            ),
            _ => None,
        }
    }

    /// Whether the index backs an exclusion constraint, which PostgreSQL
    /// refuses to rebuild concurrently.
    /// Whether `index` or the relation it backs is temporary.
    ///
    /// The index's own identity carries its schema, so a temporary index is
    /// recognizable from that; a temporary table is not, because `REINDEX TABLE`
    /// names the table. `REINDEX SYSTEM` and `REINDEX DATABASE` are already exempt.
    pub(crate) fn reindex_target_is_temporary(
        &self,
        target: &crate::_internal::analysis::mutations::ReindexTargetMutation,
    ) -> bool {
        use crate::_internal::analysis::mutations::ReindexTargetMutation;
        const TEMP_SCHEMA: &str = "pg_temp";
        match target {
            ReindexTargetMutation::Table(id) => match self.local.relations.get(id) {
                Some(RelationOverlay::Present(relation)) => {
                    relation.persistence
                        == crate::_internal::model::relation::Persistence::Temporary
                        || id.schema == TEMP_SCHEMA
                }
                _ => false,
            },
            ReindexTargetMutation::Index(id) => id.schema == TEMP_SCHEMA,
            ReindexTargetMutation::Database(_)
            | ReindexTargetMutation::Schema(_)
            | ReindexTargetMutation::System(_) => false,
        }
    }

    pub(crate) fn index_backs_exclusion_constraint(&self, index: &ObjectId) -> bool {
        self.local.constraints.values().any(|constraint| {
            matches!(constraint.kind, ConstraintKind::Exclusion)
                && constraint.backing_index.as_ref() == Some(index)
        })
    }

    /// Returns whether a cache-backed absence is authoritative for an object.
    /// A scoped cache only establishes absence in the schemas it actually
    /// synchronized.
    pub(crate) fn baseline_covers_object(&self, id: &ObjectId) -> bool {
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
        family: crate::_internal::db::cache::CatalogFamily,
    ) -> bool {
        self.baseline_covers_object(id) && self.baseline_coverage.has(family)
    }

    /// The type a routine was created as an internal part of, if any. Only
    /// PostgreSQL creates these; a user cannot define one directly.
    pub(crate) fn routine_internal_type_owner(&self, id: &ObjectId) -> Option<&ObjectId> {
        match self.local.functions.get(id)? {
            FunctionOverlay::Present(function) => function.internal_type_owner.as_ref(),
            FunctionOverlay::Dropped => None,
        }
    }

    /// The single callable routine whose bare name is `name`, when the modeled
    /// universe holds exactly one.
    ///
    /// PostgreSQL resolves a routine reference while creating the view, so the
    /// candidate set at that moment is the one it sees. A lone candidate
    /// therefore settles the reference without needing argument types, and any
    /// later drop of it is provably refused. Two or more candidates leave the
    /// overload open, and the caller keeps the bare name.
    pub(crate) fn unique_routine_named(&self, name: &ObjectId) -> Option<ObjectId> {
        let wanted = bare_routine_name(&name.name);
        let mut found: Option<ObjectId> = None;
        for (id, overlay) in &self.local.functions {
            let FunctionOverlay::Present(function) = overlay else {
                continue;
            };
            if !matches!(
                function.routine_kind,
                crate::_internal::model::function::RoutineKind::Function
                    | crate::_internal::model::function::RoutineKind::Window
            ) || bare_routine_name(&id.name) != wanted
            {
                continue;
            }
            if found.is_some() {
                return None;
            }
            found = Some(id.clone());
        }
        found
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

    pub(crate) fn baseline_has_coverage(
        &self,
        family: crate::_internal::db::cache::CatalogFamily,
    ) -> bool {
        self.baseline_coverage.has(family)
    }

    /// Schemas outside the synchronized scope that a loaded object depends on.
    /// Adding one of these to `schemas` is what makes the boundary answerable.
    pub(crate) fn external_referenced_schemas(&self) -> Vec<String> {
        let mut names: BTreeSet<String> = BTreeSet::new();
        for edge in &self.scoped_external_dependencies {
            if let Some(external) = &edge.external {
                names.insert(external.schema.clone());
            }
        }
        // A reference through a catalog class the model does not hold — an
        // operator, today — has no family and therefore no edge, but widening
        // the scope would still change the answer.
        names.extend(self.external_referencing_schemas.iter().cloned());
        names.into_iter().collect()
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
        family: crate::_internal::db::cache::CatalogFamily,
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
        if matches!(
            family,
            crate::_internal::db::cache::CatalogFamily::Relations
                | crate::_internal::db::cache::CatalogFamily::Types
                | crate::_internal::db::cache::CatalogFamily::Routines
                | crate::_internal::db::cache::CatalogFamily::Indexes
        ) {
            return self
                .scoped_external_dependencies
                .iter()
                .any(|edge| edge.exposes(family, id));
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
            if let crate::_internal::analysis::graph::DependencyKind::IndexOnRelation {
                definition,
                is_immediate,
                eligibility_known,
                ..
            } = &edge.kind
            {
                // Mirrors `is_usable_unique_index` (matview.c): unique, valid,
                // immediate, non-partial, and over plain columns.
                edge.referenced == *relation_id
                    && *eligibility_known
                    && *is_immediate
                    && definition.is_usable()
                    && definition.unique
                    && !definition.has_expression_keys()
                    && !definition.has_predicate()
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
}
