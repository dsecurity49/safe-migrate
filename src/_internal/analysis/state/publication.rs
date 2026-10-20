use super::*;

impl AnalysisState {
    pub(super) fn trigger_key(table_id: &ObjectId, name: &str) -> ObjectId {
        // PostgreSQL identifiers cannot contain NUL, so this is an unambiguous
        // internal composite key while keeping the public cache representation
        // as the trigger's actual name.
        ObjectId::new(&table_id.schema, format!("{}\0{name}", table_id.name))
    }

    pub(super) fn publication_object_key(
        &self,
        object: &crate::_internal::analysis::facts::PublicationObjectFact,
    ) -> String {
        match object {
            crate::_internal::analysis::facts::PublicationObjectFact::Table { name, .. } => {
                format!("table\0{}", self.resolve_relation_id(name))
            }
            crate::_internal::analysis::facts::PublicationObjectFact::SchemaTables {
                schema,
                ..
            } => {
                format!("schema\0{schema}")
            }
            crate::_internal::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand => {
                format!(
                    "schema\0{}",
                    self.local
                        .search_path
                        .first()
                        .and_then(SearchPathEntry::name)
                        .unwrap_or("public")
                )
            }
            crate::_internal::analysis::facts::PublicationObjectFact::Unknown => {
                "unknown".to_string()
            }
        }
    }

    /// Recover squawk's misparse of `CREATE PUBLICATION ... FOR TABLES IN
    /// SCHEMA s1, s2, ...`: the parser wraps every schema after the first as a
    /// bare (unqualified) `Table`.  When a schema-scoped object is already
    /// present and a following bare table names an actual schema, PostgreSQL
    /// intends a schema-scoped object, so coerce it back.
    pub(super) fn normalize_publication_scope(
        &self,
        scope: &crate::_internal::analysis::facts::PublicationScope,
    ) -> crate::_internal::analysis::facts::PublicationScope {
        use crate::_internal::analysis::facts::{PublicationObjectFact, PublicationScope};
        let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) = scope else {
            return scope.clone();
        };
        let mut normalized: Vec<PublicationObjectFact> = Vec::new();
        for object in objects {
            if let PublicationObjectFact::Table { name, .. } = object
                && normalized
                    .iter()
                    .any(|prior| matches!(prior, PublicationObjectFact::SchemaTables { .. }))
                && self.schema_is_present(&name.name.text)
            {
                normalized.push(PublicationObjectFact::SchemaTables {
                    schema: name.name.text.clone(),
                    row_filter: None,
                });
                continue;
            }
            normalized.push(object.clone());
        }
        PublicationScope::Explicit(normalized)
    }

    pub(super) fn replace_publication_edges(
        &mut self,
        publication_name: &str,
        scope: &crate::_internal::analysis::facts::PublicationScope,
    ) {
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !matches!(
                &edge.kind,
                DependencyKind::PublicationIncludes { publication_name: name }
                    if name == publication_name
            )
        });
        if let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) = scope {
            for object in objects {
                if let crate::_internal::analysis::facts::PublicationObjectFact::Table {
                    name,
                    ..
                } = object
                {
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

    pub(super) fn validate_publication_scope(
        &mut self,
        scope: &crate::_internal::analysis::facts::PublicationScope,
    ) -> Result<(), String> {
        let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) = scope else {
            return Ok(());
        };
        let mut object_keys = HashSet::new();
        for object in objects {
            if !object_keys.insert(self.publication_object_key(object)) {
                return Err("publication contains the same object more than once".to_string());
            }
            match object {
                crate::_internal::analysis::facts::PublicationObjectFact::Table { name, columns, .. } => {
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
                            crate::_internal::db::cache::CatalogFamily::Relations,
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
                crate::_internal::analysis::facts::PublicationObjectFact::SchemaTables { schema, .. } => {
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
                crate::_internal::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand => {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
                crate::_internal::analysis::facts::PublicationObjectFact::Unknown => {
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                }
            }
        }
        Ok(())
    }

    pub(super) fn publication_scope_needs_inheritance_knowledge(
        &self,
        scope: &crate::_internal::analysis::facts::PublicationScope,
    ) -> bool {
        let schema_has_complete_inheritance = |schema: &str| {
            let scope_id = ObjectId::new(schema, "");
            self.baseline_covers_family_object(
                &scope_id,
                crate::_internal::db::cache::CatalogFamily::Relations,
            ) && self.baseline_covers_family_object(
                &scope_id,
                crate::_internal::db::cache::CatalogFamily::Inheritance,
            )
        };
        match scope {
            crate::_internal::analysis::facts::PublicationScope::AllTables { .. } => {
                !self.baseline_available
                    || !matches!(
                        self.baseline_coverage.schema_scope,
                        crate::_internal::db::cache::SchemaCoverage::AllNonSystem
                    )
                    || !self
                        .baseline_coverage
                        .has(crate::_internal::db::cache::CatalogFamily::Relations)
                    || !self
                        .baseline_coverage
                        .has(crate::_internal::db::cache::CatalogFamily::Inheritance)
            }
            crate::_internal::analysis::facts::PublicationScope::Explicit(objects) => {
                objects.iter().any(|object| match object {
                    crate::_internal::analysis::facts::PublicationObjectFact::Table {
                        name,
                        only,
                        include_partitions,
                        ..
                    } if !only || *include_partitions => {
                        let id = self.resolve_relation_id(name);
                        let is_local = matches!(
                            self.local.relations.get(&id),
                            Some(RelationOverlay::Present(relation)) if relation.generation > 0
                        );
                        !is_local && !schema_has_complete_inheritance(&id.schema)
                    }
                    crate::_internal::analysis::facts::PublicationObjectFact::SchemaTables {
                        schema,
                        ..
                    } => !schema_has_complete_inheritance(schema),
                    crate::_internal::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand => self
                        .local
                        .search_path
                        .first()
                        .and_then(SearchPathEntry::name)
                        .is_none_or(|schema| !schema_has_complete_inheritance(schema)),
                    crate::_internal::analysis::facts::PublicationObjectFact::Unknown => false,
                    _ => false,
                })
            }
        }
    }

    pub(super) fn taint_inheritance_sensitive_publication_scope(
        &mut self,
        scope: &crate::_internal::analysis::facts::PublicationScope,
    ) {
        if self.publication_scope_needs_inheritance_knowledge(scope) {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
    }

    pub(super) fn subscription_option<'a>(
        params: Option<&'a [crate::_internal::analysis::facts::AttributeFact]>,
        name: &str,
    ) -> Option<&'a str> {
        params?
            .iter()
            .rev()
            .find(|param| param.name.eq_ignore_ascii_case(name))
            .and_then(|param| param.value.as_deref())
    }

    /// Whether `value` is a value `parse_bool` accepts.
    ///
    /// PostgreSQL compares against `true` and `false` with
    /// `pg_strncasecmp`, which a caller reaches only after trimming, so this
    /// trims too. A prefix matches only when it is unambiguous, except that
    /// `on` and `off` both need at least two characters because a bare `o`
    /// matches neither uniquely. `1` and `0` are accepted whole and never as a
    /// prefix.
    pub(crate) fn postgres_boolean(value: &str) -> Option<bool> {
        let candidate = value.trim().to_ascii_lowercase();
        if candidate.is_empty() {
            return None;
        }
        if candidate == "1" {
            return Some(true);
        }
        if candidate == "0" {
            return Some(false);
        }
        if candidate == "o" {
            return None;
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
            if spelling.starts_with(&candidate) {
                if matched.is_some() {
                    return None;
                }
                matched = Some(parsed);
            }
        }
        matched
    }

    /// Whether `value` is a value `parse_bool` accepts, for the reloption model.
    pub(crate) fn reloption_parses_bool(value: &str) -> bool {
        Self::postgres_boolean(value).is_some()
    }

    pub(super) fn subscription_boolean_option(
        params: Option<&[crate::_internal::analysis::facts::AttributeFact]>,
        name: &str,
    ) -> Option<bool> {
        Self::subscription_option(params, name).and_then(Self::postgres_boolean)
    }

    /// Checks every subscription parameter against the server that will run it:
    /// the name must be one PostgreSQL knows, the version must have introduced
    /// it, and a boolean option must carry a boolean value.
    pub(super) fn validate_subscription_options(
        &mut self,
        params: Option<&[crate::_internal::analysis::facts::AttributeFact]>,
    ) -> Result<(), MutationResult> {
        let Some(params) = params else {
            return Ok(());
        };
        let version = self.pg_version();
        for option in params {
            let Some(param) = SUBSCRIPTION_PARAMS
                .iter()
                .find(|param| option.name.eq_ignore_ascii_case(param.name))
            else {
                return Err(MutationResult::conflict(format!(
                    "unrecognized parameter \"{}\"",
                    option.name
                )));
            };
            if param.boolean
                && Self::postgres_boolean(option.value.as_deref().unwrap_or("true")).is_none()
            {
                return Err(MutationResult::conflict(format!(
                    "subscription option '{}' requires a PostgreSQL boolean value",
                    option.name
                )));
            }
            let (Some(since), Some(version_num)) = (param.since, version.num()) else {
                // Either every supported release has it, or the server is unknown.
                if version.num().is_none() && param.since.is_some() {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Statement);
                }
                continue;
            };
            if version_num < since {
                return Err(MutationResult::conflict(format!(
                    "subscription option '{}' requires PostgreSQL {}",
                    option.name,
                    pg_version_label(since)
                )));
            }
        }
        Ok(())
    }

    pub(super) fn set_subscription_option(
        subscription: &mut crate::_internal::model::replication::SubscriptionState,
        option: &crate::_internal::analysis::facts::AttributeFact,
    ) {
        let params = subscription.params.get_or_insert_with(Vec::new);
        params.retain(|existing| !existing.name.eq_ignore_ascii_case(&option.name));
        params.push(option.clone());
    }

    #[cfg(test)]
    pub(crate) fn new(cache: DbCache) -> Self {
        Self::with_baseline(cache, true)
    }

    /// Construct an authoritative state only from a semantically valid cache.
    #[cfg(test)]
    pub(crate) fn try_new(cache: DbCache) -> Result<Self, String> {
        Ok(Self::new(cache.validated()?))
    }
}
