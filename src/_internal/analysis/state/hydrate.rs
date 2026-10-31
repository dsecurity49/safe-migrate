use super::*;

impl AnalysisState {
    /// Hydrate namespace presence independently from the state families that
    /// occupy those namespaces. Relationship records may legitimately retain
    /// an out-of-scope endpoint, so every typed identity contributes schema
    /// evidence before any transition resolver runs.
    pub(super) fn hydrate_schema_overlays(cache: &DbCache) -> HashMap<String, SchemaOverlay> {
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
                SchemaOverlay::Present(crate::_internal::model::schema::SchemaState {
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
            if let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                &publication.scope
            {
                for object in objects {
                    let schema = match object {
                        crate::_internal::analysis::facts::PublicationObjectFact::Table { name, .. } => {
                            name.schema.as_ref().map(|schema| schema.resolve())
                        }
                        crate::_internal::analysis::facts::PublicationObjectFact::SchemaTables {
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

    pub(super) fn hydrate_relation_type_overlays(
        cache: &DbCache,
        search_path: &[SearchPathEntry],
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
        let row_types: HashSet<_> = relations.keys().cloned().collect();
        for overlay in relations.values_mut() {
            if let RelationOverlay::Present(relation) = overlay {
                for column in &mut relation.columns {
                    column.type_id = column.data_type.as_deref().and_then(|raw| {
                        Self::resolve_type_reference_from_catalog(
                            raw,
                            &type_catalog,
                            search_path,
                            |id| row_types.contains(id),
                        )
                    });
                }
            }
        }
        for overlay in types.values_mut() {
            if let TypeOverlay::Present(TypeState { kind, .. }) = overlay {
                match kind {
                    TypeKind::Domain {
                        base_type,
                        base_type_id,
                        ..
                    } => {
                        *base_type_id = Self::resolve_type_reference_from_catalog(
                            base_type,
                            &type_catalog,
                            search_path,
                            |id| row_types.contains(id),
                        );
                    }
                    TypeKind::Composite { fields } => {
                        for field in fields {
                            field.data_type_id = Self::resolve_type_reference_from_catalog(
                                &field.data_type,
                                &type_catalog,
                                search_path,
                                |id| row_types.contains(id),
                            );
                        }
                    }
                    TypeKind::Range {
                        subtype,
                        subtype_id,
                        ..
                    } => {
                        if let Some(subtype) = subtype {
                            *subtype_id = Self::resolve_type_reference_from_catalog(
                                subtype,
                                &type_catalog,
                                search_path,
                                |id| row_types.contains(id),
                            );
                        }
                    }
                    TypeKind::Enum { .. } | TypeKind::Base { .. } | TypeKind::Multirange { .. } => {
                    }
                }
            }
        }
        HydratedRelationTypes {
            relations,
            baseline_relations,
            baseline_fk_dependencies,
            types,
        }
    }

    pub(crate) fn with_baseline(cache: DbCache, baseline_available: bool) -> Self {
        let baseline_coverage = cache.coverage.clone();
        let baseline_boundary_queries_complete =
            baseline_available && cache.metadata.boundary_queries_complete;
        let source_lock_timeout =
            baseline_available.then_some(cache.metadata.source_lock_timeout_ms);
        let source_statement_timeout =
            baseline_available.then_some(cache.metadata.source_statement_timeout_ms);
        let default_search_path = cache.search_path.clone();
        let catalog_search_path = SearchPathEntry::from_catalog_names(&default_search_path);
        // The template must be the path PostgreSQL actually searched. Under a
        // `--schemas` scope the cache's resolved path has already had every
        // out-of-scope entry dropped, so resolving against it would retarget an
        // unqualified name to a schema PostgreSQL never reached first. The raw
        // setting keeps those entries visible, where they become unknown rather
        // than absent. The scope is deliberately not appended here: the template
        // is what `SET search_path TO DEFAULT` restores, and that must be the
        // session's own setting.
        let default_search_path_template = cache
            .metadata
            .source_search_path
            .clone()
            .unwrap_or_else(|| default_search_path.clone());
        let source_existing_schemas = baseline_available
            .then(|| cache.metadata.source_existing_schemas.clone())
            .flatten()
            .map(|schemas| schemas.into_iter().collect::<HashSet<_>>());
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
            && baseline_coverage.has(crate::_internal::db::cache::CatalogFamily::Roles)
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
            mut relations,
            baseline_relations,
            baseline_fk_dependencies,
            types,
        } = Self::hydrate_relation_type_overlays(&cache, &catalog_search_path);
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
        let extensions = cache
            .extensions
            .iter()
            .map(|(name, extension)| {
                (
                    name.clone(),
                    crate::_internal::model::extension::ExtensionOverlay::Present(
                        extension.clone(),
                    ),
                )
            })
            .collect();
        let baseline_sequences = cache.sequences.keys().cloned().collect();
        let scoped_external_dependencies =
            cache.scoped_external_dependencies.iter().cloned().collect();
        let external_referencing_schemas =
            cache.external_referencing_schemas.iter().cloned().collect();
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
                Some(
                    crate::_internal::analysis::graph::ForeignKeyOperatorEvidence {
                        pk_fk: fk.pk_fk_equality_operators,
                        pk_pk: fk.pk_pk_equality_operators,
                        fk_fk: fk.fk_fk_equality_operators,
                    },
                )
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
                    definition: idx.definition,
                    dependency_columns: idx.dependency_columns,
                    dependency_columns_known: idx.dependency_columns_known,
                    is_concurrent: false,
                    is_immediate: idx.is_immediate,
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
                            crate::_internal::model::relation::RelationKind::View
                                | crate::_internal::model::relation::RelationKind::MaterializedView
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

        for dependency in cache.view_object_dependencies {
            let dependent = dependency.dependent;
            let dependent_schema_is_omitted = baseline_schemas
                .as_ref()
                .is_some_and(|schemas| !schemas.contains(&dependent.schema));
            let is_view = relations.get(&dependent).is_some_and(|relation| {
                matches!(
                    relation,
                    RelationOverlay::Present(state)
                        if matches!(
                            state.kind,
                            crate::_internal::model::relation::RelationKind::View
                                | crate::_internal::model::relation::RelationKind::MaterializedView
                    )
                )
            });
            if !(is_view || dependent_schema_is_omitted) {
                continue;
            }
            match dependency.target {
                crate::_internal::db::cache::ViewDependencyTarget::Routine { routine } => {
                    graph.add_edge(DependencyEdge::new(
                        dependent,
                        routine.clone(),
                        DependencyKind::ViewUsesRoutine {
                            unresolved_name: None,
                        },
                    ));
                }
                crate::_internal::db::cache::ViewDependencyTarget::Type { ty } => {
                    graph.add_edge(DependencyEdge::new(
                        dependent,
                        ty.clone(),
                        DependencyKind::ViewUsesType,
                    ));
                }
            }
        }

        for inheritance in cache.inheritances {
            // A committed first phase of DETACH CONCURRENTLY remains visible
            // as an inheritance row with inhdetachpending until FINALIZE.
            // Keep cross-scope endpoints too: they are evidence that an
            // in-scope destructive change may have an omitted dependent.
            graph.add_edge(DependencyEdge::new(
                inheritance.child,
                inheritance.parent,
                if inheritance.detach_pending {
                    DependencyKind::PartitionDetachPending
                } else if inheritance.is_partition {
                    DependencyKind::PartitionOf
                } else {
                    DependencyKind::InheritanceOf
                },
            ));
        }

        for attachment in cache.index_attachments {
            graph.add_edge(DependencyEdge::new(
                attachment.child.clone(),
                attachment.parent.clone(),
                DependencyKind::IndexPartitionOf,
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
            if let Some(RelationOverlay::Present(relation)) = relations.get_mut(&t.table_id) {
                relation.triggers.insert(t.trigger_id.name.clone());
            }
            triggers.insert(
                trigger_key.clone(),
                TriggerOverlay::Present(crate::_internal::model::trigger::TriggerState {
                    name: t.trigger_id.name.clone(),
                    id: trigger_key.clone(),
                    table_id: t.table_id.clone(),
                    function_id: t.function_id.clone(),
                    row_level: t.row_level,
                    parent_trigger_id: t.parent_trigger_id.clone(),
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

        let mut functions: HashMap<ObjectId, crate::_internal::model::function::FunctionOverlay> =
            HashMap::new();
        for (id, func_state) in &cache.functions {
            functions.insert(
                id.clone(),
                crate::_internal::model::function::FunctionOverlay::Present(func_state.clone()),
            );
        }
        for overlay in functions.values_mut() {
            if let crate::_internal::model::function::FunctionOverlay::Present(function) = overlay {
                function.arg_type_ids = function
                    .arg_types
                    .iter()
                    .map(|raw| {
                        Self::resolve_type_reference_from_catalog(
                            raw,
                            &type_catalog,
                            &catalog_search_path,
                            |id| matches!(relations.get(id), Some(RelationOverlay::Present(_))),
                        )
                    })
                    .collect();
                function.return_type_id = Self::resolve_type_reference_from_catalog(
                    &function.return_type,
                    &type_catalog,
                    &catalog_search_path,
                    |id| matches!(relations.get(id), Some(RelationOverlay::Present(_))),
                );
            }
        }

        let publications = cache
            .publications
            .into_iter()
            .map(|(name, publication)| {
                if let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                    &publication.scope
                {
                    for object in objects {
                        if let crate::_internal::analysis::facts::PublicationObjectFact::Table {
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
                    crate::_internal::model::replication::PublicationOverlay::Present(publication),
                )
            })
            .collect();
        let subscriptions = cache
            .subscriptions
            .into_iter()
            .map(|(name, subscription)| {
                (
                    name,
                    crate::_internal::model::replication::SubscriptionOverlay::Present(
                        subscription,
                    ),
                )
            })
            .collect();

        let mut state = Self {
            pg_version_num: cache.pg_version_num,
            not_evaluated: Vec::new(),
            asserted_pg_version_num: None,
            target_database: None,
            baseline_available,
            baseline_boundary_queries_complete,
            baseline_coverage,
            baseline_schemas,
            baseline_relations,
            baseline_indexes,
            baseline_foreign_keys,
            baseline_fk_dependencies,
            baseline_sequences,
            scoped_external_dependencies,
            external_referencing_schemas,
            co_dropped_objects: HashSet::new(),
            local: LocalState {
                schemas,
                relations,
                types,
                functions,
                sequences,
                extensions,
                publications,
                subscriptions,
                roles: cache
                    .roles
                    .into_iter()
                    .map(|(id, role)| {
                        (
                            id,
                            crate::_internal::model::role::RoleOverlay::Present(role),
                        )
                    })
                    .collect(),
                role_membership_grantors: cache.role_membership_grantors,
                role_membership_grantors_complete: cache.role_membership_grantors_complete,
                bootstrap_superuser: cache.bootstrap_superuser,
                triggers,
                constraints,
                graph,
                search_path: Vec::new(),
                builtin_types: cache
                    .builtin_types
                    .clone()
                    .unwrap_or_else(BuiltinTypeCatalogue::fallback),
                opclasses: cache.opclasses.clone().unwrap_or_default(),
                collations: cache.collations.clone().unwrap_or_default(),
                casts: cache.casts.clone().unwrap_or_else(CastCatalogue::fallback),
                aggregates: cache
                    .aggregates
                    .clone()
                    .unwrap_or_else(AggregateCatalogue::fallback),
                saw_temp_object: false,
                search_path_template: default_search_path_template.clone(),
                session_search_path_template: default_search_path_template.clone(),
                default_search_path_template,
                source_existing_schemas,
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
        if baseline_available && incomplete_fk_operator_evidence {
            state.taint(
                crate::_internal::analysis::evidence::EvidenceCode::CatalogCoverageIncomplete,
                crate::_internal::analysis::evidence::EvidenceScope::Chain,
            );
        }
        state
    }

    /// Construct state from a cache after validating its cross-record
    /// invariants, preserving the requested baseline-availability flag.
    ///
    /// An unavailable baseline is a synthetic empty cache with no coverage, so
    /// validating it would reject the very state `--no-cache` asks for.
    pub(crate) fn try_with_baseline(
        cache: DbCache,
        baseline_available: bool,
    ) -> Result<Self, String> {
        let cache = if baseline_available {
            cache.validated()?
        } else {
            cache
        };
        Ok(Self::with_baseline(cache, baseline_available))
    }
}
