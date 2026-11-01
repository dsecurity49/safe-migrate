use super::*;

#[test]
fn dropping_a_child_table_removes_its_outgoing_dependency_edges() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE TABLE parent (id int primary key); CREATE TABLE child (id int, parent_id int REFERENCES parent(id)); CREATE INDEX child_idx ON child(id); DROP TABLE child;",
                &mut state,
            )
            .unwrap();

    assert!(!state.relation_is_present(&object_id("public", "child")));
    assert!(!state.local.graph.edges().iter().any(|edge| {
        edge.dependent == object_id("public", "child")
            || (matches!(
                edge.kind,
                safe_migrate::_internal::analysis::graph::DependencyKind::IndexOnRelation { .. }
            ) && edge.referenced == object_id("public", "child"))
    }));
}

#[test]
fn unavailable_baseline_never_claims_schema_coverage() {
    let engine = setup_engine();
    // `Baseline::unavailable()` hands analysis a default-constructed cache,
    // whose coverage is empty because nothing was ever read.
    let mut state = crate::_internal::analysis::state::AnalysisState::with_baseline(
        crate::common::unavailable_cache(),
        false,
    );
    let missing = object_id("public", "not_loaded");

    assert!(!state.baseline_covers_object(&missing));
    let findings = engine
        .analyze("ALTER TABLE not_loaded RENAME TO moved;", &mut state)
        .unwrap();

    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "unknown baseline must not become a deterministic conflict: {findings:?}"
    );
    assert_eq!(state.confidence(), &Confidence::Tainted);
    assert!(!state.relation_is_present(&object_id("public", "moved")));
}

#[test]
fn scoped_drop_with_incomplete_dependency_coverage_applies_and_taints() {
    let in_scope_table = object_id("app", "base");
    let omitted_view = object_id("tenant", "v");
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["app".to_string()]);
    cache.insert_baseline(
        in_scope_table.clone(),
        RelationState::new(
            in_scope_table.clone(),
            object_id("public", "owner"),
            0,
            None,
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    cache.dependencies.push(ViewDependencyCache {
        dependent: omitted_view,
        referenced: in_scope_table.clone(),
        referenced_column: None,
    });

    let engine = setup_engine();
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
    let violations = engine
        .analyze("DROP TABLE app.base CASCADE;", &mut state)
        .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "coverage uncertainty should skip without inventing a conflict: {violations:?}"
    );
    // PostgreSQL drops the table even when the baseline could not enumerate
    // every dependent; only the chain's exactness is lost.
    assert_eq!(state.local.confidence, Confidence::Tainted);
    assert!(!state.relation_is_present(&in_scope_table));
}

#[test]
fn recursive_column_rename_collision_preserves_every_relation_and_dependency() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE parent (id integer CHECK (id > 0));
             CREATE TABLE child (renamed integer) INHERITS (parent);
             CREATE INDEX child_id_idx ON child (id);",
            &mut state,
        )
        .unwrap();
    let relations = state.local.relations.clone();
    let constraints = state.local.constraints.clone();
    let edges = state.local.graph.edges().to_vec();
    let findings = engine
        .analyze(
            "ALTER TABLE parent RENAME COLUMN id TO renamed;",
            &mut state,
        )
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "{findings:?}"
    );
    assert_eq!(state.local.relations, relations);
    assert_eq!(state.local.constraints, constraints);
    assert_eq!(state.local.graph.edges(), edges);
}

#[test]
fn temporary_table_on_commit_drop_is_removed_with_dependents() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "BEGIN;
                 CREATE TEMPORARY TABLE work (id integer) ON COMMIT DROP;
                 CREATE INDEX work_id_idx ON work (id);
                 COMMIT;",
            &mut state,
        )
        .unwrap();

    assert!(!state.relation_is_present(&object_id("public", "work")));
    assert!(!state.index_is_present(&object_id("public", "work_id_idx")));
}

#[test]
fn temporary_table_on_commit_delete_rows_preserves_its_schema() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "BEGIN;
                 CREATE TEMPORARY TABLE work (id integer) ON COMMIT DELETE ROWS;
                 COMMIT;",
            &mut state,
        )
        .unwrap();

    assert!(matches!(
        state.get_relation(&object_id("pg_temp", "work")),
        Some(RelationOverlay::Present(relation))
            if relation.has_column("id") && relation.estimated_rows == Some(0)
    ));
}

#[test]
fn temporary_relation_shadows_a_permanent_one_of_the_same_name() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE users (id int);
                 CREATE TEMP TABLE users (id int, temp_only int);
                 ALTER TABLE users ADD COLUMN seen int;",
            &mut state,
        )
        .unwrap();

    // The unqualified ALTER targets the temporary relation, because the
    // session schema is searched first.
    let temp = state
        .get_relation(&object_id("pg_temp", "users"))
        .expect("temporary table must exist in the session schema");
    assert!(
        matches!(temp, RelationOverlay::Present(relation) if relation.has_column("temp_only")
                && relation.has_column("seen")),
        "the ALTER must land on the temporary relation: {temp:?}"
    );

    let permanent = state
        .get_relation(&object_id("public", "users"))
        .expect("permanent table must be untouched");
    assert!(
        matches!(permanent, RelationOverlay::Present(relation) if !relation.has_column("seen")),
        "the permanent relation must not be modified: {permanent:?}"
    );
}

#[test]
fn a_named_schema_is_rejected_for_a_temporary_relation() {
    let engine = setup_engine();
    let mut state = setup_state();
    let v = engine
        .analyze("CREATE TEMP TABLE public.work (id int);", &mut state)
        .unwrap();
    assert!(
        v.iter().any(|v| v
            .reason
            .contains("cannot create temporary relation in non-temporary schema")),
        "expected PostgreSQL's rejection: {v:?}"
    );
}

#[test]
fn create_table_as_select_taints_unknown_columns_and_skips_later_column_edits() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze("CREATE TABLE copied AS SELECT 1 AS id;", &mut state)
        .unwrap();
    assert_eq!(state.local.confidence, Confidence::Tainted);

    let violations = engine
        .analyze("ALTER TABLE copied DROP COLUMN id;", &mut state)
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    assert!(state.relation_is_present(&object_id("public", "copied")));
}

#[test]
fn an_unknown_user_schema_taints_only_the_lookup_that_resolves_past_it() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    let id = object_id("public", "mood");
    cache.types.insert(
        id.clone(),
        TypeState {
            id: id.clone(),
            generation: 0,
            owner: object_id("", "postgres"),
            kind: TypeKind::Enum {
                variants: vec!["old".into()],
            },
        },
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze("SET search_path TO \"$user\", public;", &mut state)
        .unwrap();

    assert!(!state.local.current_role_known);
    assert_eq!(
        state.local.search_path,
        [
            SearchPathEntry::Unresolved(None),
            SearchPathEntry::Schema("public".to_string())
        ]
    );
    assert_eq!(
        state.local.confidence,
        Confidence::Exact,
        "an unresolved entry is only uncertain once a lookup resolves past it"
    );

    engine
        .analyze("ALTER TYPE mood RENAME VALUE 'old' TO 'new';", &mut state)
        .unwrap();

    assert_eq!(state.local.confidence, Confidence::Tainted);
    let Some(TypeOverlay::Present(type_state)) = state.local.types.get(&id) else {
        panic!("public.mood missing");
    };
    assert_eq!(
        type_state.kind,
        TypeKind::Enum {
            variants: vec!["old".into()]
        },
        "a target behind the unresolved $user schema is reported, not mutated"
    );
}

#[test]
fn a_scoped_baseline_does_not_make_its_scope_searchable() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.coverage = CatalogCoverage::for_families(
        SchemaCoverage::from_sync_scope(Some(&["app".to_string()])),
        CatalogFamily::ALL,
    );
    cache.metadata.schemas = Some(vec!["app".to_string()]);
    cache.schemas.insert(
        "app".to_string(),
        SchemaState {
            name: "app".to_string(),
            owner: object_id("", "postgres"),
            generation: 0,
        },
    );
    // The sync session searched a schema the scope omits, so its contents
    // are unknown; the scope itself must not become reachable instead.
    cache.metadata.source_search_path = Some(vec!["public".to_string()]);
    cache.search_path = Vec::new();
    let id = object_id("app", "mood");
    cache.types.insert(
        id.clone(),
        TypeState {
            id,
            generation: 0,
            owner: object_id("", "postgres"),
            kind: TypeKind::Enum {
                variants: vec!["old".into()],
            },
        },
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze("ALTER TYPE mood RENAME VALUE 'old' TO 'new';", &mut state)
        .unwrap();

    assert_eq!(state.search_path_names(), Vec::<String>::new());
    assert_eq!(state.local.confidence, Confidence::Tainted);
    let Some(TypeOverlay::Present(type_state)) = state.local.types.get(&object_id("app", "mood"))
    else {
        panic!("app.mood missing");
    };
    assert_eq!(
        type_state.kind,
        TypeKind::Enum {
            variants: vec!["old".into()]
        },
        "the out-of-scope search path entry must not be replaced by the sync scope"
    );
}

#[test]
fn a_creation_behind_an_unresolved_path_entry_is_reported_not_placed() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.coverage = CatalogCoverage::for_families(
        SchemaCoverage::from_sync_scope(Some(&["public".to_string()])),
        CatalogFamily::ALL,
    );
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.schemas.insert(
        "public".to_string(),
        SchemaState {
            name: "public".to_string(),
            owner: object_id("", "postgres"),
            generation: 0,
        },
    );
    cache.metadata.source_search_path = Some(vec!["app".to_string(), "public".to_string()]);
    cache.search_path = vec!["public".to_string()];
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze("CREATE TABLE t(id int);", &mut state)
        .unwrap();

    assert_eq!(
        state.local.search_path,
        [
            SearchPathEntry::Unresolved(Some("app".to_string())),
            SearchPathEntry::Schema("public".to_string())
        ]
    );
    assert_eq!(state.local.confidence, Confidence::Tainted);
    assert!(
        !state.relation_is_present(&object_id("public", "t")),
        "PostgreSQL might have created the table in the unresolved schema"
    );
}

#[test]
fn a_scoped_baseline_drops_template_entries_absent_at_sync() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.coverage = CatalogCoverage::for_families(
        SchemaCoverage::from_sync_scope(Some(&["public".to_string()])),
        CatalogFamily::ALL,
    );
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.metadata.source_role = Some("app_role".into());
    cache.metadata.source_session_role = Some("app_role".into());
    cache.metadata.source_search_path = Some(vec!["gone".into(), "$user".into(), "public".into()]);
    // The synchronizing session recorded no `gone` and no role schema, so
    // neither entry resolved then and PostgreSQL would skip both.
    cache.metadata.source_existing_schemas = Some(vec!["public".to_string()]);
    cache.search_path = vec!["public".to_string()];
    cache.schemas.insert(
        "public".to_string(),
        SchemaState {
            name: "public".to_string(),
            owner: object_id("", "postgres"),
            generation: 0,
        },
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze("CREATE TABLE t(id int);", &mut state)
        .unwrap();

    assert_eq!(
        state.local.search_path,
        [SearchPathEntry::Schema("public".to_string())]
    );
    assert_eq!(state.local.confidence, Confidence::Exact);
    assert!(state.relation_is_present(&object_id("public", "t")));
}

#[test]
fn a_scoped_baseline_keeps_template_entries_that_existed_at_sync() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.coverage = CatalogCoverage::for_families(
        SchemaCoverage::from_sync_scope(Some(&["public".to_string()])),
        CatalogFamily::ALL,
    );
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.metadata.source_role = Some("app_role".into());
    cache.metadata.source_session_role = Some("app_role".into());
    cache.metadata.source_search_path = Some(vec!["gone".into(), "$user".into(), "public".into()]);
    // Both out-of-scope schemas existed at sync, so either can still shadow
    // `public` even though the cache carries none of their objects.
    cache.metadata.source_existing_schemas =
        Some(vec!["gone".into(), "app_role".into(), "public".into()]);
    cache.search_path = vec!["public".to_string()];
    cache.schemas.insert(
        "public".to_string(),
        SchemaState {
            name: "public".to_string(),
            owner: object_id("", "postgres"),
            generation: 0,
        },
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze("CREATE TABLE t(id int);", &mut state)
        .unwrap();

    assert_eq!(
        state.local.search_path,
        [
            SearchPathEntry::Unresolved(Some("gone".to_string())),
            SearchPathEntry::Unresolved(Some("app_role".to_string())),
            SearchPathEntry::Schema("public".to_string())
        ]
    );
    assert_eq!(state.local.confidence, Confidence::Tainted);
    assert!(
        !state.relation_is_present(&object_id("public", "t")),
        "PostgreSQL might have created the table in an earlier schema"
    );
}

#[test]
fn test_topology_replication_graph() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE TABLE t(id int); CREATE PUBLICATION p FOR TABLE t; CREATE SUBSCRIPTION s CONNECTION '...' PUBLICATION p;",
                &mut state,
            )
            .unwrap();

    assert!(state.local.publications.contains_key("p"));
    assert!(state.local.subscriptions.contains_key("s"));

    engine
        .analyze("DROP PUBLICATION p; DROP SUBSCRIPTION s;", &mut state)
        .unwrap();

    assert!(matches!(
        state.local.publications.get("p"),
        Some(safe_migrate::_internal::model::replication::PublicationOverlay::Dropped)
    ));
    assert!(matches!(
        state.local.subscriptions.get("s"),
        Some(safe_migrate::_internal::model::replication::SubscriptionOverlay::Dropped)
    ));
}

#[test]
fn test_topology_publication() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE TABLE t1 (id integer);
                 CREATE TABLE t2 (id integer);
                 CREATE PUBLICATION pub FOR TABLE t1, t2;",
            &mut state,
        )
        .unwrap();
    assert!(state.local.publications.contains_key("pub"));

    let deps = &state.local.graph.edges();
    assert!(
            deps.iter()
                .any(|d| matches!(&d.kind, DependencyKind::PublicationIncludes { publication_name } if publication_name == "pub") && d.dependent == object_id("public", "t1"))
        );
    assert!(
            deps.iter()
                .any(|d| matches!(&d.kind, DependencyKind::PublicationIncludes { publication_name } if publication_name == "pub") && d.dependent == object_id("public", "t2"))
        );
}

#[test]
fn test_topology_subscription() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE SUBSCRIPTION sub CONNECTION 'host=localhost' PUBLICATION pub;",
            &mut state,
        )
        .unwrap();
    assert!(state.local.subscriptions.contains_key("sub"));
}

#[test]
fn test_topology_search_path() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "SET search_path TO myschema, public; CREATE TABLE t(id int);",
            &mut state,
        )
        .unwrap();

    assert!(state.relation_is_present(&object_id("public", "t")));
    assert_eq!(state.search_path_names(), ["public"]);
}

#[test]
fn set_time_zone_does_not_reset_search_path() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "SET search_path TO tenant, public; SET TIME ZONE DEFAULT; CREATE TABLE t(id int);",
            &mut state,
        )
        .unwrap();

    assert!(state.relation_is_present(&object_id("public", "t")));
    assert_eq!(state.search_path_names(), ["public"]);
}

#[test]
fn test_synced_search_path_is_initial_and_default_path() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.search_path = vec!["tenant_app".to_string(), "shared".to_string()];
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze("CREATE TABLE first(id int);", &mut state)
        .unwrap();
    engine
            .analyze(
                "SET search_path TO temporary_path; SET search_path TO DEFAULT; CREATE TABLE second(id int);",
                &mut state,
            )
            .unwrap();

    assert!(state.relation_is_present(&object_id("tenant_app", "first")));
    assert!(state.relation_is_present(&object_id("tenant_app", "second")));
    assert_eq!(state.search_path_names(), ["tenant_app", "shared"]);
}

#[test]
fn test_state_confidence_is_accessible() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze("CREATE TABLE t(id int);", &mut state)
        .unwrap();
    let _ = &state.local.confidence;
}

#[test]
fn publication_and_subscription_duplicates_conflict() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
        .analyze(
            "CREATE PUBLICATION p FOR ALL TABLES;
                 CREATE PUBLICATION p FOR ALL TABLES;
                 CREATE SUBSCRIPTION s CONNECTION 'host=localhost' PUBLICATION p;
                 CREATE SUBSCRIPTION s CONNECTION 'host=localhost' PUBLICATION p;",
            &mut state,
        )
        .unwrap();

    assert_eq!(
        violations
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .count(),
        2
    );
}

#[test]
fn complete_v7_baseline_rejects_an_alter_of_a_missing_publication_exactly() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE PUBLICATION existing_pub FOR ALL TABLES;",
            &mut state,
        )
        .unwrap();
    assert!(state.local.publications.contains_key("existing_pub"));

    let violations = engine
        .analyze("ALTER PUBLICATION missing_pub SET TABLE t;", &mut state)
        .unwrap();
    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation.reason.contains("missing_pub")
            && violation.reason.contains("does not exist")
    }));
    assert_eq!(state.local.confidence, Confidence::Exact);
}

#[test]
fn publication_targets_use_cache_scope_for_conflicts_and_unknowns() {
    let engine = setup_engine();
    let mut exact_state = setup_state();
    let violations = engine
        .analyze(
            "CREATE PUBLICATION invalid_pub FOR TABLE missing_table;",
            &mut exact_state,
        )
        .unwrap();
    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation.reason.contains("missing_table")
            && violation.reason.contains("does not exist")
    }));
    assert_eq!(exact_state.local.confidence, Confidence::Exact);

    let mut scoped_cache = synced_cache();
    scoped_cache.metadata.schemas = Some(vec!["public".into()]);
    let mut scoped_state = crate::_internal::analysis::state::AnalysisState::new(scoped_cache);
    let violations = engine
        .analyze(
            "CREATE PUBLICATION external_pub FOR TABLE tenant.entries;",
            &mut scoped_state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    assert_eq!(scoped_state.local.confidence, Confidence::Tainted);
    assert!(matches!(
        scoped_state.local.publications.get("external_pub"),
        Some(safe_migrate::_internal::model::replication::PublicationOverlay::Present(_))
    ));
}

#[test]
fn cached_publication_and_subscription_actions_update_exact_state() {
    let engine = setup_engine();
    let mut cache = cache_with_table("public", "first", None);
    cache.pg_version_num = Some(180_006);
    let second = object_id("public", "second");
    cache.insert_baseline(
        second.clone(),
        RelationState::new(
            second,
            object_id("", "postgres"),
            0,
            None,
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    cache.publications.insert(
        "changes".into(),
        safe_migrate::_internal::model::replication::PublicationState {
            name: "changes".into(),
            owner: Some("postgres".into()),
            scope: safe_migrate::_internal::analysis::facts::PublicationScope::Explicit(vec![
                safe_migrate::_internal::analysis::facts::PublicationObjectFact::Table {
                    name: safe_migrate::_internal::ast::identifiers::QualifiedName::new(
                        Some(safe_migrate::_internal::ast::identifiers::Ident::new(
                            "public", true,
                        )),
                        safe_migrate::_internal::ast::identifiers::Ident::new("first", true),
                    ),
                    only: true,
                    include_partitions: false,
                    columns: None,
                    row_filter: None,
                },
            ]),
            params: Vec::new(),
            generation: 0,
        },
    );
    cache.subscriptions.insert(
        "subscriber".into(),
        safe_migrate::_internal::model::replication::SubscriptionState {
            name: "subscriber".into(),
            owner: Some("postgres".into()),
            connection: safe_migrate::_internal::analysis::facts::ConnectionTarget::Redacted,
            publications: vec!["changes".into()],
            params: Some(Vec::new()),
            enabled: false,
            slot_name: None,
            generation: 0,
        },
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let violations = engine
            .analyze(
                "ALTER PUBLICATION changes ADD TABLE ONLY second;
                 ALTER PUBLICATION changes RENAME TO renamed_changes;
                 ALTER SUBSCRIPTION subscriber SET PUBLICATION renamed_changes WITH (refresh = false);
                 ALTER SUBSCRIPTION subscriber SET (streaming = parallel);
                 ALTER SUBSCRIPTION subscriber RENAME TO renamed_subscriber;",
                &mut state,
            )
            .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    assert_eq!(state.local.confidence, Confidence::Exact);
    let Some(safe_migrate::_internal::model::replication::PublicationOverlay::Present(publication)) =
        state.local.publications.get("renamed_changes")
    else {
        panic!("renamed publication missing");
    };
    let safe_migrate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
        &publication.scope
    else {
        panic!("expected explicit publication scope");
    };
    assert_eq!(objects.len(), 2);
    assert!(state.local.graph.edges().iter().any(|edge| {
        matches!(
            &edge.kind,
            DependencyKind::PublicationIncludes { publication_name }
                if publication_name == "renamed_changes"
        ) && edge.dependent == object_id("public", "second")
    }));

    let Some(safe_migrate::_internal::model::replication::SubscriptionOverlay::Present(
        subscription,
    )) = state.local.subscriptions.get("renamed_subscriber")
    else {
        panic!("renamed subscription missing");
    };
    assert_eq!(subscription.publications, ["renamed_changes"]);
    assert!(subscription.params.as_ref().is_some_and(|params| {
        params
            .iter()
            .any(|param| param.name == "streaming" && param.value.as_deref() == Some("parallel"))
    }));

    engine.analyze("DROP TABLE second;", &mut state).unwrap();
    let Some(safe_migrate::_internal::model::replication::PublicationOverlay::Present(publication)) =
        state.local.publications.get("renamed_changes")
    else {
        panic!("publication missing after table drop");
    };
    let safe_migrate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
        &publication.scope
    else {
        panic!("expected explicit publication scope");
    };
    assert_eq!(objects.len(), 1);
}

#[test]
fn subscription_publication_conflicts_do_not_partially_mutate_direct_state() {
    let mut cache = synced_cache();
    cache.subscriptions.insert(
        "subscriber".into(),
        safe_migrate::_internal::model::replication::SubscriptionState {
            name: "subscriber".into(),
            owner: Some("postgres".into()),
            connection: safe_migrate::_internal::analysis::facts::ConnectionTarget::Redacted,
            publications: vec!["existing".into()],
            params: Some(Vec::new()),
            enabled: false,
            slot_name: None,
            generation: 0,
        },
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
    let initial_generation = state.local.generation_counter;

    for (mode, publications) in [
        (
            safe_migrate::_internal::analysis::facts::SubscriptionPublicationMode::Add,
            vec!["new".to_string(), "existing".to_string()],
        ),
        (
            safe_migrate::_internal::analysis::facts::SubscriptionPublicationMode::Drop,
            vec!["existing".to_string(), "missing".to_string()],
        ),
    ] {
        let mutation = safe_migrate::_internal::analysis::mutations::Mutation::AlterSubscription(
                safe_migrate::_internal::analysis::mutations::AlterSubscriptionMutation {
                    name: "subscriber".into(),
                    action:
                        safe_migrate::_internal::analysis::facts::AlterSubscriptionActionFact::Publications {
                            mode,
                            publications,
                            params: Vec::new(),
                        },
                },
            );
        assert!(matches!(
            state.apply(&mutation, None),
            safe_migrate::_internal::analysis::state::MutationResult::Conflict { .. }
        ));
        let Some(safe_migrate::_internal::model::replication::SubscriptionOverlay::Present(
            subscription,
        )) = state.local.subscriptions.get("subscriber")
        else {
            panic!("subscription missing");
        };
        assert_eq!(subscription.publications, ["existing"]);
        assert_eq!(subscription.generation, 0);
        assert_eq!(state.local.generation_counter, initial_generation);
    }
}

#[test]
fn cached_publication_parent_edits_are_tainted_without_inheritance_catalogs() {
    let engine = setup_engine();
    let mut cache = cache_with_table("public", "parent", None);
    cache.coverage.families.remove(&CatalogFamily::Inheritance);
    cache.publications.insert(
        "changes".into(),
        safe_migrate::_internal::model::replication::PublicationState {
            name: "changes".into(),
            owner: Some("postgres".into()),
            scope: safe_migrate::_internal::analysis::facts::PublicationScope::Explicit(vec![
                safe_migrate::_internal::analysis::facts::PublicationObjectFact::Table {
                    name: safe_migrate::_internal::ast::identifiers::QualifiedName::new(
                        Some(safe_migrate::_internal::ast::identifiers::Ident::new(
                            "public", true,
                        )),
                        safe_migrate::_internal::ast::identifiers::Ident::new("parent", true),
                    ),
                    only: true,
                    include_partitions: false,
                    columns: None,
                    row_filter: None,
                },
            ]),
            params: Vec::new(),
            generation: 0,
        },
    );

    let mut inherited_state = crate::_internal::analysis::state::AnalysisState::new(cache.clone());
    engine
        .analyze(
            "ALTER PUBLICATION changes DROP TABLE parent *;",
            &mut inherited_state,
        )
        .unwrap();
    assert_eq!(inherited_state.local.confidence, Confidence::Tainted);

    let mut only_state = crate::_internal::analysis::state::AnalysisState::new(cache);
    engine
        .analyze(
            "ALTER PUBLICATION changes DROP TABLE ONLY parent;",
            &mut only_state,
        )
        .unwrap();
    assert_eq!(only_state.local.confidence, Confidence::Exact);
}

#[test]
fn complete_inheritance_catalog_keeps_publication_parent_edits_exact() {
    let engine = setup_engine();
    let mut cache = cache_with_table("public", "parent", None);
    let child = object_id("public", "child");
    cache.insert_baseline(
        child.clone(),
        RelationState::new(
            child.clone(),
            object_id("public", "postgres"),
            0,
            None,
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    cache
        .inheritances
        .push(safe_migrate::_internal::db::cache::InheritanceCache {
            child,
            parent: object_id("public", "parent"),
            sequence: 1,
            is_partition: false,
            detach_pending: false,
        });
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze("CREATE PUBLICATION changes FOR TABLE parent *;", &mut state)
        .unwrap();

    assert_eq!(state.local.confidence, Confidence::Exact);
}

#[test]
fn subscription_publisher_operations_taint_and_slot_drops_obey_transaction_rules() {
    let engine = setup_engine();
    let mut state = setup_state();

    let create_violations = engine
            .analyze(
                "CREATE SUBSCRIPTION deferred CONNECTION 'host=publisher.invalid' PUBLICATION changes WITH (connect = false);",
                &mut state,
            )
            .unwrap();
    let Some(safe_migrate::_internal::model::replication::SubscriptionOverlay::Present(
        subscription,
    )) = state.local.subscriptions.get("deferred")
    else {
        panic!(
            "deferred subscription missing: keys={:?} violations={create_violations:?}",
            state.local.subscriptions.keys().collect::<Vec<_>>()
        );
    };
    assert!(!subscription.enabled);
    assert_eq!(subscription.slot_name.as_deref(), Some("deferred"));
    assert_eq!(state.local.confidence, Confidence::Exact);

    let violations = engine
        .analyze("BEGIN; DROP SUBSCRIPTION deferred; ROLLBACK;", &mut state)
        .unwrap();
    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation
                .reason
                .contains("cannot be dropped inside a transaction")
    }));
    assert!(matches!(
        state.local.subscriptions.get("deferred"),
        Some(safe_migrate::_internal::model::replication::SubscriptionOverlay::Present(_))
    ));

    engine
        .analyze(
            "ALTER SUBSCRIPTION deferred SET (slot_name = NONE);
                 DROP SUBSCRIPTION deferred;",
            &mut state,
        )
        .unwrap();
    assert_eq!(state.local.confidence, Confidence::Tainted);
    assert!(matches!(
        state.local.subscriptions.get("deferred"),
        Some(safe_migrate::_internal::model::replication::SubscriptionOverlay::Dropped)
    ));
}

#[test]
fn subscription_options_are_gated_on_the_server_version() {
    let engine = setup_engine();
    // Parameter introductions, plus the PostgreSQL 16 value gate for streaming.
    for (since, parameter) in [
        (140_000, "binary = true"),
        (140_000, "streaming = true"),
        (160_000, "streaming = parallel"),
        (150_000, "two_phase = true"),
        (150_000, "disable_on_error = true"),
        (160_000, "password_required = true"),
        (160_000, "run_as_owner = true"),
        (160_000, "origin = 'any'"),
        (170_000, "failover = true"),
    ] {
        let sql = format!(
            "CREATE SUBSCRIPTION s CONNECTION 'host=publisher.invalid' \
                 PUBLICATION p WITH ({parameter});"
        );

        let mut state = setup_state();
        state.pg_version_num = Some(since - 10_000);
        let violations = engine.analyze(&sql, &mut state).unwrap();
        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict"),
            "{parameter} must be rejected below {since}"
        );

        let mut state = setup_state();
        state.pg_version_num = Some(since);
        let violations = engine.analyze(&sql, &mut state).unwrap();
        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict"),
            "{parameter} must be accepted from {since}"
        );
    }
}

#[test]
fn subscription_boolean_options_require_def_get_boolean_values() {
    let engine = setup_engine();
    for (version, parameter) in [
        (180_006, "connect = yes"),
        (180_006, "enabled = t"),
        (180_006, "binary = yes"),
        (180_006, "streaming = yes"),
        (150_000, "streaming = yes"),
        (180_006, "binary = ' true '"),
        (180_006, "connect = false, enabled"),
    ] {
        let mut state = setup_state();
        state.pg_version_num = Some(version);
        let sql = format!(
            "CREATE SUBSCRIPTION s CONNECTION 'host=publisher.invalid' \
                 PUBLICATION p WITH ({parameter});"
        );
        let violations = engine.analyze(&sql, &mut state).unwrap();
        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict"),
            "{parameter} at {version} must be rejected"
        );
        assert!(
            !matches!(
                state.local.subscriptions.get("s"),
                Some(safe_migrate::_internal::model::replication::SubscriptionOverlay::Present(_))
            ),
            "{parameter} at {version} must not create a subscription"
        );
    }
}

#[test]
fn an_unknown_server_version_taints_rather_than_conflicting() {
    let engine = setup_engine();
    let mut state = setup_state();
    state.pg_version_num = None;
    let violations = engine
        .analyze(
            "CREATE SUBSCRIPTION s CONNECTION 'host=publisher.invalid' \
                 PUBLICATION p WITH (failover = true);",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "an unanswerable version question cannot prove a conflict"
    );
    assert_eq!(state.local.confidence, Confidence::Tainted);
}

#[test]
fn subscription_options_enforce_postgresql_slot_and_publication_invariants() {
    let engine = setup_engine();

    for sql in [
        "CREATE SUBSCRIPTION invalid CONNECTION 'host=publisher.invalid' PUBLICATION p WITH (connect=false, enabled=true);",
        "CREATE SUBSCRIPTION invalid CONNECTION 'host=publisher.invalid' PUBLICATION p WITH (slot_name=NONE);",
        "CREATE SUBSCRIPTION invalid CONNECTION 'host=publisher.invalid' PUBLICATION p, p WITH (connect=false);",
        "CREATE SUBSCRIPTION invalid CONNECTION 'host=publisher.invalid' PUBLICATION p WITH (connect=maybe);",
        "CREATE SUBSCRIPTION invalid CONNECTION 'host=publisher.invalid' PUBLICATION p WITH (connect=o);",
    ] {
        let mut state = setup_state();
        let violations = engine.analyze(sql, &mut state).unwrap();
        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict"),
            "{sql}"
        );
        assert_eq!(state.local.confidence, Confidence::Exact, "{sql}");
        assert!(!matches!(
            state.local.subscriptions.get("invalid"),
            Some(safe_migrate::_internal::model::replication::SubscriptionOverlay::Present(_))
        ));
    }

    let mut boolean_state = setup_state();
    // `binary` is PostgreSQL 14, so this baseline must know its server.
    boolean_state.pg_version_num = Some(180_006);
    let violations = engine
            .analyze(
                "CREATE SUBSCRIPTION boolean_options
                   CONNECTION 'host=publisher.invalid'
                   PUBLICATION p
                   WITH (connect=OFF, enabled=FALSE, create_slot=off, copy_data=0, binary=1, slot_name=NONE);
                 BEGIN;
                 ALTER SUBSCRIPTION boolean_options SET PUBLICATION p2 WITH (refresh=OFF);
                 ROLLBACK;",
                &mut boolean_state,
            )
            .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    assert_eq!(boolean_state.local.confidence, Confidence::Exact);
    assert!(matches!(
        boolean_state.local.subscriptions.get("boolean_options"),
        Some(safe_migrate::_internal::model::replication::SubscriptionOverlay::Present(
            subscription
        )) if !subscription.enabled && subscription.slot_name.is_none()
    ));

    let mut state = setup_state();
    engine
            .analyze(
                "CREATE SUBSCRIPTION slotless CONNECTION 'host=publisher.invalid' PUBLICATION p WITH (connect=false, slot_name=NONE);",
                &mut state,
            )
            .unwrap();
    let violations = engine
        .analyze("ALTER SUBSCRIPTION slotless ENABLE;", &mut state)
        .unwrap();
    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict" && violation.reason.contains("without a slot_name")
    }));
    assert_eq!(state.local.confidence, Confidence::Exact);

    let mut state = setup_state();
    engine
            .analyze(
                "CREATE SUBSCRIPTION enabled_sub CONNECTION 'host=publisher.invalid' PUBLICATION p WITH (create_slot=false);",
                &mut state,
            )
            .unwrap();
    let violations = engine
        .analyze(
            "ALTER SUBSCRIPTION enabled_sub SET (slot_name=NONE);",
            &mut state,
        )
        .unwrap();
    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation
                .reason
                .contains("disabled before changing slot_name")
    }));
}

#[test]
fn cached_generated_column_drop_handles_transitive_cascade_closure() {
    let engine = setup_engine();
    let table = object_id("public", "metrics");
    let mut cache = cache_with_table("public", "metrics", None);
    cache
        .relations
        .get_mut(&table)
        .expect("baseline table")
        .columns
        .extend([
            Column {
                name: "source".to_string(),
                data_type: Some("integer".to_string()),
                type_id: None,
                is_nullable: true,
                default: None,
                avg_width: None,
                default_expr_text: None,
                type_modifier: Some(-1),
                storage: None,
                compression: None,
                statistics_target: None,
                options: Default::default(),
                generated: Some(false),
            },
            Column {
                name: "derived".to_string(),
                data_type: Some("integer".to_string()),
                type_id: None,
                is_nullable: true,
                default: None,
                avg_width: None,
                default_expr_text: None,
                type_modifier: Some(-1),
                storage: None,
                compression: None,
                statistics_target: None,
                options: Default::default(),
                generated: Some(true),
            },
            Column {
                name: "derived_twice".to_string(),
                data_type: Some("integer".to_string()),
                type_id: None,
                is_nullable: true,
                default: None,
                avg_width: None,
                default_expr_text: None,
                type_modifier: Some(-1),
                storage: None,
                compression: None,
                statistics_target: None,
                options: Default::default(),
                generated: Some(true),
            },
        ]);
    cache
        .generated_column_dependencies
        .push(GeneratedColumnDependencyCache {
            table_id: table.clone(),
            column_name: "derived".to_string(),
            depends_on_column: "source".to_string(),
        });
    cache
        .generated_column_dependencies
        .push(GeneratedColumnDependencyCache {
            table_id: table.clone(),
            column_name: "derived_twice".to_string(),
            depends_on_column: "derived".to_string(),
        });
    cache.constraints.push(
        safe_migrate::_internal::model::constraint::ConstraintState {
            table_id: table.clone(),
            name: "derived_twice_check".to_string(),
            kind: ConstraintKind::Check,
            validated: true,
            definition: Some("derived_twice > 0".to_string()),
            backing_index: None,
        },
    );
    cache
        .constraint_dependencies
        .push(ConstraintDependencyCache {
            table_id: table.clone(),
            constraint_name: "derived_twice_check".to_string(),
            columns: vec!["derived_twice".to_string()],
        });
    let derived_index = object_id("public", "metrics_derived_idx");
    cache
        .indexes
        .push(safe_migrate::_internal::db::cache::IndexCache {
            index_id: derived_index.clone(),
            table_id: table.clone(),
            definition: IndexDefinition {
                method: Some("btree".into()),
                keys: index_keys(vec!["derived".to_string()]),
                included: index_keys(Vec::new()),
                expression_keys: 0,
                unique: false,
                nulls_not_distinct: Some(false),
                predicate: IndexPredicate::None,
                unestablished: false,
                valid: true,
                ready: true,
                live: true,
            },
            dependency_columns: vec!["derived".to_string()],
            dependency_columns_known: true,
            is_immediate: true,
        });
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache.clone());

    let findings = engine
        .analyze("ALTER TABLE metrics DROP COLUMN derived;", &mut state)
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
    assert!(
        state
            .local
            .graph
            .edges()
            .iter()
            .any(|edge| { matches!(edge.kind, DependencyKind::ColumnGeneratedFrom { .. }) })
    );
    assert!(matches!(
        state.get_relation(&table),
        Some(RelationOverlay::Present(relation)) if relation.has_column("derived")
    ));

    let mut derived_cascade_state =
        crate::_internal::analysis::state::AnalysisState::new(cache.clone());
    let findings = engine
        .analyze(
            "ALTER TABLE metrics DROP COLUMN derived CASCADE;",
            &mut derived_cascade_state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
    assert!(matches!(
        derived_cascade_state.get_relation(&table),
        Some(RelationOverlay::Present(relation))
            if !relation.has_column("derived") && !relation.has_column("derived_twice")
    ));
    assert!(
        !derived_cascade_state
            .local
            .constraints
            .contains_key(&(table.clone(), "derived_twice_check".to_string()))
    );

    let mut source_state = crate::_internal::analysis::state::AnalysisState::new(cache.clone());
    let findings = engine
        .analyze("ALTER TABLE metrics DROP COLUMN source;", &mut source_state)
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
    let mut cascade_state = crate::_internal::analysis::state::AnalysisState::new(cache);
    let findings = engine
        .analyze(
            "ALTER TABLE metrics DROP COLUMN source CASCADE;",
            &mut cascade_state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
    assert!(matches!(
        cascade_state.get_relation(&table),
        Some(RelationOverlay::Present(relation))
            if !relation.has_column("source")
                && !relation.has_column("derived")
                && !relation.has_column("derived_twice")
    ));
    assert!(!cascade_state.local.graph.edges().iter().any(|edge| {
        matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
            && edge.dependent == derived_index
    }));
}

#[test]
fn dropping_a_column_from_a_baseline_relation_removes_it() {
    let mut cache = crate::common::cache_with_table("public", "t", None);
    let tid = object_id("public", "t");
    if let Some(rel) = cache.relations.get_mut(&tid) {
        rel.columns = vec![
            Column {
                name: "id".to_string(),
                data_type: Some("integer".to_string()),
                type_id: None,
                is_nullable: false,
                default: None,
                avg_width: None,
                default_expr_text: None,
                type_modifier: None,
                storage: None,
                compression: None,
                statistics_target: None,
                options: Default::default(),
                generated: None,
            },
            Column {
                name: "doomed".to_string(),
                data_type: Some("text".to_string()),
                type_id: None,
                is_nullable: true,
                default: None,
                avg_width: None,
                default_expr_text: None,
                type_modifier: None,
                storage: None,
                compression: None,
                statistics_target: None,
                options: Default::default(),
                generated: None,
            },
        ];
    }
    let mut state = AnalysisState::with_baseline(cache, true);
    setup_engine()
        .analyze("ALTER TABLE t DROP COLUMN doomed;", &mut state)
        .unwrap();
    let columns = state
        .local
        .relations
        .get(&tid)
        .and_then(|overlay| match overlay {
            RelationOverlay::Present(rel) => Some(
                rel.columns
                    .iter()
                    .map(|c| c.name.clone())
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .unwrap_or_default();
    assert_eq!(columns, ["id"], "baseline column must be gone");
}
