use super::*;

#[test]
fn replacing_a_view_replaces_its_dependency_edges() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE TABLE first (id int); CREATE TABLE second (id int); CREATE VIEW v AS SELECT * FROM first; CREATE OR REPLACE VIEW v AS SELECT * FROM second;",
                &mut state,
            )
            .unwrap();

    let dependencies: Vec<_> = state
        .local
        .graph
        .edges()
        .iter()
        .filter(|edge| {
            matches!(
                edge.kind,
                safe_migrate::_internal::analysis::graph::DependencyKind::ViewDependency { .. }
            ) && edge.dependent == object_id("public", "v")
        })
        .map(|edge| edge.referenced.clone())
        .collect();
    assert_eq!(dependencies, vec![object_id("public", "second")]);
}

#[test]
fn replacing_a_view_preserves_relation_metadata() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE TABLE base (id int); CREATE VIEW v AS SELECT * FROM base; CREATE FUNCTION notify_view() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$; CREATE TRIGGER v_insert INSTEAD OF INSERT ON v FOR EACH ROW EXECUTE FUNCTION notify_view(); GRANT SELECT ON v TO app_user; CREATE OR REPLACE VIEW v AS SELECT id FROM base;",
                &mut state,
            )
            .unwrap();

    let Some(RelationOverlay::Present(view)) = state.local.relations.get(&object_id("public", "v"))
    else {
        panic!("view should remain present");
    };
    assert!(view.triggers.contains("v_insert"));
    assert!(
        view.privileges
            .grants
            .contains_key(&ObjectId::new("", "app_user"))
    );
}

#[test]
fn dropping_a_view_honors_restrict_and_cascade_dependencies() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE TABLE source (id int); CREATE VIEW base_view AS SELECT * FROM source; CREATE VIEW dependent_view AS SELECT * FROM base_view;",
                &mut state,
            )
            .unwrap();
    let restricted = engine.analyze("DROP VIEW base_view;", &mut state).unwrap();
    assert!(
        restricted
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    assert!(state.relation_is_present(&object_id("public", "base_view")));
    assert!(state.relation_is_present(&object_id("public", "dependent_view")));

    engine
        .analyze("DROP VIEW base_view CASCADE;", &mut state)
        .unwrap();
    assert!(!state.relation_is_present(&object_id("public", "base_view")));
    assert!(!state.relation_is_present(&object_id("public", "dependent_view")));
}

#[test]
fn views_using_sequence_functions_do_not_treat_function_names_as_relations() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
            .analyze(
                "CREATE SEQUENCE source_seq; CREATE VIEW sequence_view AS SELECT nextval('source_seq'::regclass);",
                &mut state,
            )
            .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "sequence-backed view should be accepted: {violations:?}"
    );
}

#[test]
fn cached_view_rewrite_self_edge_is_ignored_but_real_dependency_is_kept() {
    let view_id = object_id("public", "v");
    let table_id = object_id("public", "t");
    let mut cache = synced_cache();

    for (id, kind) in [
        (view_id.clone(), RelationKind::View),
        (table_id.clone(), RelationKind::Table),
    ] {
        cache.insert_baseline(
            id.clone(),
            RelationState::new(
                id,
                object_id("public", "owner"),
                0,
                None,
                kind,
                Persistence::Permanent,
                0,
            ),
        );
    }

    let dependency = |referenced: &ObjectId| ViewDependencyCache {
        dependent: view_id.clone(),
        referenced: referenced.clone(),
        referenced_column: None,
    };
    cache.dependencies.push(dependency(&view_id));
    cache.dependencies.push(dependency(&table_id));

    let state = crate::_internal::analysis::state::AnalysisState::new(cache);
    assert!(!state.local.graph.edges().iter().any(|edge| {
        matches!(edge.kind, DependencyKind::ViewDependency { .. })
            && edge.dependent == view_id
            && edge.referenced == view_id
    }));
    assert!(state.local.graph.edges().iter().any(|edge| {
        matches!(edge.kind, DependencyKind::ViewDependency { .. })
            && edge.dependent == view_id
            && edge.referenced == table_id
    }));
}

#[test]
fn cached_view_column_dependencies_allow_dropping_an_unreferenced_column() {
    let table_id = object_id("public", "t");
    let view_id = object_id("public", "v");
    let mut cache = synced_cache();
    let mut table = RelationState::new(
        table_id.clone(),
        object_id("public", "owner"),
        0,
        None,
        RelationKind::Table,
        Persistence::Permanent,
        0,
    );
    for name in ["id", "unused"] {
        table.apply_column_action(&ColumnAction::Add {
            name: name.to_string(),
            data_type: Some("integer".to_string()),
            not_null: false,
            default: None,
        });
    }
    cache.insert_baseline(table_id.clone(), table);
    cache.insert_baseline(
        view_id.clone(),
        RelationState::new(
            view_id.clone(),
            object_id("public", "owner"),
            0,
            None,
            RelationKind::View,
            Persistence::Permanent,
            0,
        ),
    );
    cache.dependencies.push(ViewDependencyCache {
        dependent: view_id.clone(),
        referenced: table_id.clone(),
        referenced_column: Some("id".to_string()),
    });

    let engine = setup_engine();
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache.clone());
    let findings = engine
        .analyze("ALTER TABLE t DROP COLUMN unused;", &mut state)
        .unwrap();

    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "unrelated column drop must not conflict: {findings:?}"
    );
    assert_eq!(
        state.local.confidence,
        Confidence::Exact,
        "unexpected evidence: {:?}",
        state.evidence()
    );
    assert!(
        state
            .get_relation(&table_id)
            .is_some_and(|relation| match relation {
                RelationOverlay::Present(table) => !table.has_column("unused"),
                RelationOverlay::Dropped => false,
            })
    );
    let mut blocked_state = crate::_internal::analysis::state::AnalysisState::new(cache.clone());
    let findings = engine
        .analyze("ALTER TABLE t DROP COLUMN id;", &mut blocked_state)
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );

    let mut cascade_state = crate::_internal::analysis::state::AnalysisState::new(cache);
    let findings = engine
        .analyze("ALTER TABLE t DROP COLUMN id CASCADE;", &mut cascade_state)
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
    assert!(matches!(
        cascade_state.get_relation(&view_id),
        Some(RelationOverlay::Dropped)
    ));
}

#[test]
fn scoped_view_dependencies_keep_edges_to_omitted_schemas() {
    let view_id = object_id("app", "v");
    let external_table = object_id("tenant", "base");
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["app".to_string()]);
    cache.insert_baseline(
        view_id.clone(),
        RelationState::new(
            view_id.clone(),
            object_id("public", "owner"),
            0,
            None,
            RelationKind::View,
            Persistence::Permanent,
            0,
        ),
    );
    cache.dependencies.push(ViewDependencyCache {
        dependent: view_id.clone(),
        referenced: external_table.clone(),
        referenced_column: None,
    });

    let state = crate::_internal::analysis::state::AnalysisState::new(cache);
    assert!(state.local.graph.edges().iter().any(|edge| {
        matches!(edge.kind, DependencyKind::ViewDependency { .. })
            && edge.dependent == view_id
            && edge.referenced == external_table
    }));
}

#[test]
fn scoped_view_dependencies_keep_omitted_dependents() {
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
        dependent: omitted_view.clone(),
        referenced: in_scope_table.clone(),
        referenced_column: None,
    });

    let state = crate::_internal::analysis::state::AnalysisState::new(cache);
    assert!(state.local.graph.edges().iter().any(|edge| {
        matches!(edge.kind, DependencyKind::ViewDependency { .. })
            && edge.dependent == omitted_view
            && edge.referenced == in_scope_table
    }));
}

#[test]
fn empty_typed_view_dependency_cache_does_not_create_graph_edges() {
    let view_id = object_id("public", "v");
    let table_id = object_id("public", "t");
    let mut cache = synced_cache();
    for (id, kind) in [
        (view_id.clone(), RelationKind::View),
        (table_id.clone(), RelationKind::Table),
    ] {
        cache.insert_baseline(
            id.clone(),
            RelationState::new(
                id,
                object_id("public", "owner"),
                0,
                None,
                kind,
                Persistence::Permanent,
                0,
            ),
        );
    }
    let state = crate::_internal::analysis::state::AnalysisState::new(cache);
    assert!(
        !state
            .local
            .graph
            .edges()
            .iter()
            .any(|edge| { edge.dependent == view_id && edge.referenced == table_id })
    );
}

#[test]
fn schema_cascade_cleans_cross_schema_view_and_foreign_key_state() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE SCHEMA base;
                 CREATE SCHEMA app;
                 CREATE TABLE base.parent (id integer PRIMARY KEY);
                 CREATE TABLE app.child (parent_id integer);
                 ALTER TABLE app.child ADD CONSTRAINT child_parent_fk
                    FOREIGN KEY (parent_id) REFERENCES base.parent(id);
                 CREATE VIEW app.parent_view AS SELECT * FROM base.parent;
                 DROP SCHEMA base CASCADE;",
            &mut state,
        )
        .unwrap();

    let child = object_id("app", "child");
    let view = object_id("app", "parent_view");
    assert!(state.relation_is_present(&child));
    assert!(!state.relation_is_present(&view));
    assert!(
        !state
            .local
            .constraints
            .contains_key(&(child, "child_parent_fk".to_string()))
    );
}

#[test]
fn view_projection_is_derived_from_the_source_relation() {
    // Column names and types verified against PostgreSQL 18.2.
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE vsrc (id int, label text, extra numeric);
                 CREATE VIEW vplain AS SELECT id, label FROM vsrc;
                 CREATE VIEW vstar AS SELECT * FROM vsrc;
                 CREATE VIEW valias AS SELECT id AS user_id, label FROM vsrc;",
            &mut state,
        )
        .unwrap();

    let columns = |name: &str| {
        state
            .get_relation(&object_id("public", name))
            .and_then(|overlay| match overlay {
                RelationOverlay::Present(relation) => Some(
                    relation
                        .columns
                        .iter()
                        .map(|c| (c.name.clone(), c.data_type.clone()))
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .unwrap_or_default()
    };

    assert_eq!(
        columns("vplain"),
        vec![
            ("id".to_string(), Some("integer".to_string())),
            ("label".to_string(), Some("text".to_string())),
        ]
    );
    assert_eq!(
        columns("vstar"),
        vec![
            ("id".to_string(), Some("integer".to_string())),
            ("label".to_string(), Some("text".to_string())),
            ("extra".to_string(), Some("numeric".to_string())),
        ]
    );
    assert_eq!(
        columns("valias"),
        vec![
            ("user_id".to_string(), Some("integer".to_string())),
            ("label".to_string(), Some("text".to_string())),
        ]
    );
}

#[test]
fn view_with_an_expression_projection_reports_unknown_columns() {
    // PostgreSQL types the output by analysing the query, so an expression
    // cannot be typed offline; the view still exists but taints.
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE vsrc (id int, label text);
                 CREATE VIEW vexpr AS SELECT id + 1 AS bumped FROM vsrc;",
            &mut state,
        )
        .unwrap();
    assert!(
        state.relation_is_present(&object_id("public", "vexpr")),
        "the view must still be created"
    );
    assert_eq!(
        state.local.confidence,
        safe_migrate::_internal::analysis::state::Confidence::Tainted
    );
}

#[test]
fn test_topology_view_graph() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE TABLE t(id int); CREATE VIEW v AS SELECT * FROM t;",
            &mut state,
        )
        .unwrap();

    assert!(
        state
            .local
            .graph
            .edges()
            .iter()
            .filter(|e| matches!(
                e.kind,
                safe_migrate::_internal::analysis::graph::DependencyKind::ViewDependency { .. }
            ))
            .any(|v| v.dependent == object_id("public", "v")
                && v.referenced == object_id("public", "t"))
    );

    engine.analyze("DROP VIEW v;", &mut state).unwrap();
    assert!(
        state
            .local
            .graph
            .edges()
            .iter()
            .filter(|e| matches!(
                e.kind,
                safe_migrate::_internal::analysis::graph::DependencyKind::ViewDependency { .. }
            ))
            .count()
            == 0
    );
}

#[test]
fn test_topology_materialized_view_graph() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE TABLE t(id int); CREATE MATERIALIZED VIEW mv AS SELECT * FROM t;",
            &mut state,
        )
        .unwrap();

    assert!(
        state
            .local
            .graph
            .edges()
            .iter()
            .filter(|e| matches!(
                e.kind,
                safe_migrate::_internal::analysis::graph::DependencyKind::ViewDependency { .. }
            ))
            .any(|v| v.dependent == object_id("public", "mv")
                && v.referenced == object_id("public", "t"))
    );
}

#[test]
fn a_name_only_view_reference_blocks_a_drop_only_when_one_overload_can_fill_it() {
    for (extra_overload, expect_conflict) in [(false, true), (true, false)] {
        let engine = setup_engine();
        let mut cache = synced_cache();
        let view = object_id("public", "v");
        cache.insert_baseline(
            view.clone(),
            RelationState::new(
                view.clone(),
                object_id("", "postgres"),
                0,
                Some(0),
                RelationKind::View,
                Persistence::Permanent,
                0,
            ),
        );
        let target = object_id("public", "f(integer)");
        cache.functions.insert(
            target.clone(),
            FunctionState {
                return_type: "integer".into(),
                ..FunctionState::with_inputs(
                    target.clone(),
                    RoutineKind::Function,
                    vec!["integer".into()],
                )
            },
        );
        if extra_overload {
            let other = object_id("public", "f(text)");
            cache.functions.insert(
                other.clone(),
                FunctionState {
                    return_type: "text".into(),
                    ..FunctionState::with_inputs(
                        other.clone(),
                        RoutineKind::Function,
                        vec!["text".into()],
                    )
                },
            );
        }
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
        // A call the body could not pin to a signature names the routine
        // only, which is what `views_for_function` matches by name.
        let written = object_id("public", "f");
        state.local.graph.add_edge(DependencyEdge::new(
            view.clone(),
            written.clone(),
            DependencyKind::ViewUsesRoutine {
                unresolved_name: Some(written.clone()),
            },
        ));

        let violations = engine
            .analyze("DROP FUNCTION public.f(integer);", &mut state)
            .expect("the drop should analyze");
        let blocked = violations
            .iter()
            .any(|violation| violation.reason.contains("is required by view"));
        if expect_conflict {
            assert!(blocked, "one overload makes the view reference definite");
        } else {
            assert!(!blocked, "a second overload leaves the reference open");
            assert_eq!(state.local.confidence, Confidence::Tainted);
        }
    }
}

#[test]
fn create_materialized_view_if_not_exists_skips_an_existing_relation() {
    let conflicts = |sql: &str| {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .unwrap()
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .count()
    };
    assert_eq!(
        conflicts(
            "CREATE MATERIALIZED VIEW mv AS SELECT 1 AS a;
                 CREATE MATERIALIZED VIEW IF NOT EXISTS mv AS SELECT 2 AS a;"
        ),
        0,
        "IF NOT EXISTS must skip the existing relation"
    );
    assert_eq!(
        conflicts(
            "CREATE MATERIALIZED VIEW mv AS SELECT 1 AS a;
                 CREATE MATERIALIZED VIEW mv AS SELECT 2 AS a;"
        ),
        1,
        "an unguarded duplicate materialized view must conflict"
    );
}

#[test]
fn refresh_without_data_leaves_the_view_unpopulated() {
    let conflicts = |sql: &str| {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .unwrap()
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason.clone())
            .collect::<Vec<_>>()
    };

    // `WITH NO DATA` is a modeled state change, not an opaque statement.
    let unpopulated = conflicts(
        "CREATE MATERIALIZED VIEW mv AS SELECT 1 AS a WITH NO DATA;
             REFRESH MATERIALIZED VIEW CONCURRENTLY mv;",
    );
    assert!(
        unpopulated
            .iter()
            .any(|message| message.contains("is not populated")),
        "a concurrent refresh of an unpopulated view must conflict: {unpopulated:?}"
    );

    // PostgreSQL rejects the option pair before looking for a unique index.
    let pair = conflicts(
        "CREATE MATERIALIZED VIEW mv AS SELECT 1 AS a;
             REFRESH MATERIALIZED VIEW CONCURRENTLY mv WITH NO DATA;",
    );
    assert!(
        pair.iter()
            .any(|message| message.contains("cannot be used together")),
        "CONCURRENTLY with WITH NO DATA must conflict: {pair:?}"
    );

    // A plain refresh repopulates, so the populated-state conflict goes away.
    let repopulated = conflicts(
        "CREATE MATERIALIZED VIEW mv AS SELECT 1 AS a WITH NO DATA;
             REFRESH MATERIALIZED VIEW mv;
             REFRESH MATERIALIZED VIEW CONCURRENTLY mv;",
    );
    assert!(
        !repopulated
            .iter()
            .any(|message| message.contains("is not populated")),
        "a populated view must not report the populated-state conflict: {repopulated:?}"
    );
}

#[test]
fn a_view_depends_on_the_types_its_body_casts_to() {
    let conflicts = |sql: &str| {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .unwrap()
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .count()
    };
    assert_eq!(
        conflicts(
            "CREATE TYPE ct AS (z int);
                 CREATE VIEW v AS SELECT 1::ct AS r;
                 DROP TYPE ct;"
        ),
        1,
        "a cast to a user type must block dropping it"
    );
    assert_eq!(
        conflicts(
            "CREATE TYPE ct AS (z int);
                 CREATE VIEW v AS SELECT 1::ct AS r;
                 DROP TYPE ct CASCADE;"
        ),
        0,
        "CASCADE applies the drop; the view fallout is reported as unmodeled"
    );
    assert_eq!(
        conflicts(
            "CREATE TYPE ct AS (z int);
                 CREATE VIEW v AS SELECT 1 AS r;
                 DROP TYPE ct;"
        ),
        0,
        "a view that never names the type must not block it"
    );
}

#[test]
fn a_view_depends_on_every_routine_its_query_calls() {
    let conflicts = |sql: &str| {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .unwrap()
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason.clone())
            .collect::<Vec<_>>()
    };
    let blocked = |sql: &str| {
        conflicts(sql)
            .iter()
            .any(|reason| reason.contains("is required by view"))
    };

    // The call is in the target list.
    assert!(
        blocked(
            "CREATE TABLE t (a int);
                 CREATE FUNCTION f(int) RETURNS int AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
                 CREATE VIEW v AS SELECT f(a) AS fa FROM t;
                 DROP FUNCTION f(integer);"
        ),
        "a view's target list is a routine dependency"
    );
    // The call is in the WHERE clause, which the old scan never reached.
    assert!(
        blocked(
            "CREATE TABLE t (a int);
                 CREATE FUNCTION f(int) RETURNS int AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
                 CREATE VIEW v AS SELECT a FROM t WHERE f(a) > 0;
                 DROP FUNCTION f(integer);"
        ),
        "a view's WHERE clause is a routine dependency"
    );
    // CASCADE clears the dependent view.
    assert!(
        !blocked(
            "CREATE TABLE t (a int);
                 CREATE FUNCTION f(int) RETURNS int AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
                 CREATE VIEW v AS SELECT a FROM t WHERE f(a) > 0;
                 DROP FUNCTION f(integer) CASCADE;
                 DROP VIEW v;"
        ),
        "CASCADE must drop the dependent view"
    );
    // An exact reference must not block a different overload.
    assert!(
        !blocked(
            "CREATE TABLE t (a int);
                 CREATE FUNCTION f(int) RETURNS int AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
                 CREATE FUNCTION f(text) RETURNS text AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
                 CREATE VIEW v AS SELECT f(a) AS fa FROM t;
                 DROP FUNCTION f(text);"
        ),
        "an exact signature must not block another overload"
    );
    // A call whose arguments do not resolve names no overload, so the
    // drop is reported unresolved rather than as a conflict.
    let undecided = conflicts(
        "CREATE TABLE t (a int);
             CREATE FUNCTION f(int) RETURNS int AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
             CREATE FUNCTION f(text) RETURNS text AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
             CREATE VIEW v AS SELECT f(a + 1) AS fa FROM t;
             DROP FUNCTION f(text);",
    );
    assert!(
        !undecided
            .iter()
            .any(|reason| reason.contains("is required by view")),
        "an unresolved reference must not report a conflict: {undecided:?}"
    );
}

#[test]
fn a_view_reference_follows_a_rename_of_its_target() {
    let conflicts = |sql: &str| {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .unwrap()
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason.clone())
            .collect::<Vec<_>>()
    };
    let blocked = |sql: &str| {
        conflicts(sql)
            .iter()
            .any(|reason| reason.contains("is required by view"))
    };

    assert!(
        blocked(
            "CREATE TABLE t (a int);
                 CREATE FUNCTION f(int) RETURNS int AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
                 CREATE VIEW v AS SELECT f(a) AS fa FROM t;
                 ALTER FUNCTION f(integer) RENAME TO g;
                 DROP FUNCTION g(integer);"
        ),
        "a resolved call must follow the renamed routine"
    );
    assert!(
        blocked(
            "CREATE SCHEMA other;
                 CREATE TABLE t (a int);
                 CREATE FUNCTION f(int) RETURNS int AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
                 CREATE VIEW v AS SELECT f(a) AS fa FROM t;
                 ALTER FUNCTION f(integer) SET SCHEMA other;
                 DROP FUNCTION other.f(integer);"
        ),
        "a resolved call must follow the moved routine"
    );
    assert!(
        blocked(
            "CREATE TABLE t (a int);
                 CREATE FUNCTION f(int) RETURNS int AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
                 CREATE VIEW v AS SELECT f(a + 1) AS fa FROM t;
                 ALTER FUNCTION f(integer) RENAME TO g;
                 DROP FUNCTION g(integer);"
        ),
        "a name-only reference must follow a fully moved name"
    );
    assert!(
        conflicts(
            "CREATE TYPE ct AS (z int);
                 CREATE TABLE t (a int);
                 CREATE VIEW v AS SELECT a FROM t WHERE a::ct IS NOT NULL;
                 ALTER TYPE ct RENAME TO renamed_ct;
                 DROP TYPE renamed_ct;"
        )
        .iter()
        .any(|reason| reason.contains("dependent objects")),
        "a view cast must follow the renamed type"
    );
}

#[test]
fn cascading_a_type_drop_removes_a_dependent_view_and_frees_the_name() {
    let engine = setup_engine();
    let mut state = setup_state();
    let ct = object_id("public", "ct");
    let view = object_id("public", "v");
    engine
        .analyze(
            "CREATE TYPE ct AS (z int);
                 CREATE VIEW v AS SELECT 1::ct AS r;
                 DROP TYPE ct CASCADE;",
            &mut state,
        )
        .unwrap();
    assert!(
        matches!(state.local.types.get(&ct), Some(TypeOverlay::Dropped)),
        "the cascade must not refuse to mark the type dropped"
    );
    assert!(
        !state.relation_is_present(&view),
        "the view casting to the type goes with it"
    );
    let violations = engine
        .analyze(
            "CREATE TYPE ct AS (z int);
                 CREATE VIEW v AS SELECT 1 AS r;",
            &mut state,
        )
        .unwrap();
    assert_eq!(
        violations
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .count(),
        0,
        "both names must be free again: {violations:?}"
    );
}

#[test]
fn a_routine_cascade_drops_triggers_of_cascaded_views() {
    use safe_migrate::_internal::model::trigger::TriggerOverlay;
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE t (a int);
                 CREATE FUNCTION f() RETURNS trigger AS 'BEGIN RETURN NULL; END' LANGUAGE plpgsql;
                 CREATE FUNCTION g(int) RETURNS int AS 'SELECT $1' LANGUAGE sql;
                 CREATE VIEW v AS SELECT g(a) AS ga FROM t;
                 CREATE TRIGGER trg INSTEAD OF INSERT ON v FOR EACH ROW EXECUTE FUNCTION f();
                 DROP FUNCTION g(integer) CASCADE;",
            &mut state,
        )
        .unwrap();
    assert!(
        !state.relation_is_present(&object_id("public", "v")),
        "the view calling the routine goes with it"
    );
    assert!(
        !state.local.triggers.values().any(|overlay| matches!(
            overlay,
            TriggerOverlay::Present(trigger) if trigger.name == "trg"
        )),
        "the trigger on the cascaded view goes with it"
    );
}

#[test]
fn dropping_an_aggregate_a_view_calls_requires_cascade() {
    let engine = setup_engine();
    let setup = "CREATE TABLE t (a int);
                     CREATE FUNCTION af(int, int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT $1 + $2';
                     CREATE AGGREGATE ag(int) (SFUNC = af, STYPE = int);
                     CREATE VIEW v AS SELECT ag(a) AS x FROM t;";

    let mut state = setup_state();
    let violations = engine
        .analyze(&format!("{setup} DROP AGGREGATE ag(int);"), &mut state)
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"
                && violation.reason.contains("required by view")),
        "a view call must block dropping the aggregate: {violations:?}"
    );

    let mut state = setup_state();
    engine
        .analyze(
            &format!("{setup} DROP AGGREGATE ag(int) CASCADE;"),
            &mut state,
        )
        .unwrap();
    assert!(!state.relation_is_present(&object_id("public", "v")));
    assert!(matches!(
        state
            .local
            .functions
            .get(&object_id("public", "ag(integer)")),
        Some(FunctionOverlay::Dropped)
    ));
}

#[test]
fn cascading_a_function_drop_removes_transitive_view_dependents() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE FUNCTION f() RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT 1';
                 CREATE VIEW v AS SELECT f() AS x;
                 CREATE VIEW w AS SELECT * FROM v;
                 CREATE MATERIALIZED VIEW m AS SELECT * FROM v;
                 DROP FUNCTION f() CASCADE;",
            &mut state,
        )
        .unwrap();
    assert!(!state.relation_is_present(&object_id("public", "v")));
    assert!(!state.relation_is_present(&object_id("public", "w")));
    assert!(!state.relation_is_present(&object_id("public", "m")));
}

#[test]
fn view_column_lists_rename_the_projection_prefix() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE t (a int, b int);
                 CREATE VIEW v (x) AS SELECT a, b FROM t;
                 CREATE MATERIALIZED VIEW m (y) AS SELECT a, b FROM t;",
            &mut state,
        )
        .unwrap();
    assert_eq!(
        state
            .relation_column_types(&object_id("public", "v"))
            .unwrap(),
        vec![
            ("x".to_string(), Some("integer".to_string())),
            ("b".to_string(), Some("integer".to_string())),
        ]
    );
    assert_eq!(
        state
            .relation_column_types(&object_id("public", "m"))
            .unwrap(),
        vec![
            ("y".to_string(), Some("integer".to_string())),
            ("b".to_string(), Some("integer".to_string())),
        ]
    );
}

#[test]
fn concurrent_refresh_requires_a_usable_unique_index() {
    let conflicts = |sql: &str| {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .unwrap()
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason.clone())
            .collect::<Vec<_>>()
    };

    let missing = conflicts(
        "CREATE TABLE t (id int);
             CREATE MATERIALIZED VIEW m AS SELECT id FROM t;
             REFRESH MATERIALIZED VIEW CONCURRENTLY m;",
    );
    assert!(
        missing
            .iter()
            .any(|reason| reason.contains("cannot refresh materialized view 'public.m")),
        "a concurrent refresh without a unique index must conflict: {missing:?}"
    );

    let usable = conflicts(
        "CREATE TABLE t (id int);
             CREATE MATERIALIZED VIEW m AS SELECT id FROM t;
             CREATE UNIQUE INDEX m_id_idx ON m (id);
             REFRESH MATERIALIZED VIEW CONCURRENTLY m;",
    );
    assert!(
        usable.is_empty(),
        "a usable unique index must allow the concurrent refresh: {usable:?}"
    );

    for keys in ["(id) WHERE id > 0", "((id + 1))"] {
        let partial = conflicts(&format!(
            "CREATE TABLE t (id int);
                 CREATE MATERIALIZED VIEW m AS SELECT id FROM t;
                 CREATE UNIQUE INDEX m_id_idx ON m {keys};
                 REFRESH MATERIALIZED VIEW CONCURRENTLY m;"
        ));
        assert!(
            partial
                .iter()
                .any(|reason| reason.contains("cannot refresh materialized view 'public.m")),
            "a partial or expression index is not usable: {partial:?}"
        );
    }
}

#[test]
fn materialized_view_creation_validates_its_options() {
    let conflicts = |sql: &str| {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .unwrap()
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason.clone())
            .collect::<Vec<_>>()
    };

    let bad_value =
        conflicts("CREATE MATERIALIZED VIEW m WITH (fillfactor = 5) AS SELECT 1 AS id;");
    assert!(
        bad_value
            .iter()
            .any(|reason| reason.contains("invalid value for parameter \"fillfactor\"")),
        "a value outside the option's domain must conflict: {bad_value:?}"
    );

    let view_only =
        conflicts("CREATE MATERIALIZED VIEW m WITH (check_option = 'cascaded') AS SELECT 1 AS id;");
    assert!(
        view_only
            .iter()
            .any(|reason| reason.contains("unrecognized parameter \"check_option\"")),
        "a view-only option must not reach a materialized view: {view_only:?}"
    );

    let accepted =
        conflicts("CREATE MATERIALIZED VIEW m WITH (fillfactor = 70) AS SELECT 1 AS id;");
    assert!(
        accepted.is_empty(),
        "a valid option must not conflict: {accepted:?}"
    );
}

#[test]
fn rollback_restores_a_materialized_views_populated_state() {
    let conflicts = |sql: &str| {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .unwrap()
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason.clone())
            .collect::<Vec<_>>()
    };

    // The rollback must undo the refresh, or the concurrent refresh below
    // would reach the unique-index check instead of the populated one.
    let after_rollback = conflicts(
        "CREATE MATERIALIZED VIEW m AS SELECT 1 AS id WITH NO DATA;
             BEGIN;
             REFRESH MATERIALIZED VIEW m;
             ROLLBACK;
             REFRESH MATERIALIZED VIEW CONCURRENTLY m;",
    );
    assert!(
        after_rollback
            .iter()
            .any(|reason| reason.contains("is not populated")),
        "a rolled-back refresh must restore the unpopulated state: {after_rollback:?}"
    );
}

#[test]
fn create_or_replace_view_only_appends_columns() {
    let conflicts = |sql: &str| {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .unwrap()
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason.clone())
            .collect::<Vec<_>>()
    };

    assert!(
        conflicts(
            "CREATE TABLE t (a int, b int);
                 CREATE VIEW v AS SELECT a FROM t;
                 CREATE OR REPLACE VIEW v AS SELECT b AS renamed FROM t;"
        )
        .iter()
        .any(|reason| reason.contains("cannot change name of view column \"a\" to \"renamed\"")),
        "a leading column may not be renamed"
    );
    assert!(
        conflicts(
            "CREATE TABLE t (a int, b int);
                 CREATE VIEW v AS SELECT a, b FROM t;
                 CREATE OR REPLACE VIEW v AS SELECT a FROM t;"
        )
        .iter()
        .any(|reason| reason.contains("cannot drop columns from view")),
        "columns may not be dropped"
    );
    assert!(
        conflicts(
            "CREATE TABLE t (a int, c text);
                 CREATE VIEW v AS SELECT a FROM t;
                 CREATE OR REPLACE VIEW v AS SELECT c AS a FROM t;"
        )
        .iter()
        .any(|reason| reason
            .contains("cannot change data type of view column \"a\" from integer to text")),
        "a leading column may not change type"
    );
    assert!(
        conflicts(
            "CREATE TABLE t (a varchar(10), c varchar(20));
                 CREATE VIEW v AS SELECT a FROM t;
                 CREATE OR REPLACE VIEW v AS SELECT c AS a FROM t;"
        )
        .iter()
        .any(|reason| reason.contains("from character varying(10) to character varying(20)")),
        "a typmod change is a type change"
    );
    assert!(
        conflicts(
            "CREATE TABLE t (a int, b int);
                 CREATE VIEW v AS SELECT a FROM t;
                 CREATE OR REPLACE VIEW v AS SELECT a, b FROM t;
                 CREATE OR REPLACE VIEW v AS SELECT a, b, 1 AS c FROM t;"
        )
        .is_empty(),
        "appending columns is allowed"
    );
}

#[test]
fn a_materialized_view_carries_its_columns_and_storage() {
    let engine = setup_engine();
    let mut state = setup_state();

    // A view expanding `*` over a materialized view must see its columns,
    // and an explicit column list renames them.
    let violations = engine
        .analyze(
            "CREATE TABLE t (id int, nm text);
                 CREATE MATERIALIZED VIEW mv (xx, yy) USING heap AS SELECT id, nm FROM t;
                 CREATE VIEW v AS SELECT * FROM mv;
                 ALTER VIEW v ALTER COLUMN yy SET DEFAULT 1;",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "a materialized view must expose the renamed columns: {violations:?}"
    );
    assert_eq!(
        state.local.confidence,
        safe_migrate::_internal::analysis::state::Confidence::Exact,
        "modeled storage and column state must not taint"
    );
}

#[test]
fn a_view_call_resolves_in_the_routine_namespace_not_the_relation_one() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    for schema in ["public", "other"] {
        cache.schemas.insert(
            schema.to_string(),
            SchemaState {
                name: schema.to_string(),
                owner: object_id("", "postgres"),
                generation: 0,
            },
        );
    }
    let table = object_id("public", "f");
    cache.insert_baseline(
        table.clone(),
        RelationState::new(
            table.clone(),
            object_id("", "postgres"),
            0,
            Some(0),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    let function = object_id("other", "f()");
    cache.functions.insert(
        function.clone(),
        FunctionState {
            return_type: "integer".into(),
            ..FunctionState::with_inputs(function.clone(), RoutineKind::Function, Vec::new())
        },
    );
    cache.metadata.source_search_path = Some(vec!["public".to_string(), "other".to_string()]);
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze("CREATE VIEW public.v AS SELECT f();", &mut state)
        .unwrap();

    assert!(
        state.local.graph.edges().iter().any(|edge| {
            edge.dependent == object_id("public", "v")
                && edge.referenced == function
                && matches!(edge.kind, DependencyKind::ViewUsesRoutine { .. })
        }),
        "the call must follow the routine namespace, not resolve to public.f the table"
    );
}

#[test]
fn instead_of_trigger_on_view_is_tracked() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
            .analyze(
                "CREATE TABLE base(id int); CREATE VIEW v AS SELECT * FROM base; CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$; CREATE TRIGGER tr INSTEAD OF INSERT ON v FOR EACH ROW EXECUTE FUNCTION f();",
                &mut state,
            )
            .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "view trigger target should be valid: {violations:?}"
    );
    let Some(RelationOverlay::Present(view)) = state.local.relations.get(&object_id("public", "v"))
    else {
        panic!("view should remain present");
    };
    assert!(view.triggers.contains("tr"));
}

#[test]
fn test_state_drop_view_cascade() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE TABLE t(id int); CREATE VIEW v AS SELECT * FROM t;",
            &mut state,
        )
        .unwrap();

    assert!(state.relation_is_present(&object_id("public", "v")));

    engine.analyze("DROP VIEW v;", &mut state).unwrap();
    assert!(!state.relation_is_present(&object_id("public", "v")));
    assert!(state.relation_is_present(&object_id("public", "t")));
}

#[test]
fn test_state_drop_materialized_view_cleanup() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE TABLE t(id int); CREATE MATERIALIZED VIEW mv AS SELECT * FROM t; CREATE INDEX i ON mv(id);",
                &mut state,
            )
            .unwrap();

    assert!(state.relation_is_present(&object_id("public", "mv")));
    assert!(
        state
            .local
            .graph
            .edges()
            .iter()
            .filter(|e| matches!(
                e.kind,
                safe_migrate::_internal::analysis::graph::DependencyKind::IndexOnRelation { .. }
            ))
            .any(|i| i.referenced == object_id("public", "mv"))
    );

    engine
        .analyze("DROP MATERIALIZED VIEW mv;", &mut state)
        .unwrap();
    assert!(!state.relation_is_present(&object_id("public", "mv")));
    assert!(state.relation_is_present(&object_id("public", "t")));
}

#[test]
fn test_drop_materialized_view_removes_its_indexes() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE MATERIALIZED VIEW mv AS SELECT 1 AS id; CREATE UNIQUE INDEX mv_id_idx ON mv(id); DROP MATERIALIZED VIEW mv;",
                &mut state,
            )
            .unwrap();

    assert!(!state.local.graph.edges().iter().any(|edge| {
        matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
            && edge.referenced == object_id("public", "mv")
    }));
}

#[test]
fn alter_view_owner_updates_relation_metadata() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    let view = object_id("public", "owned_view");
    cache.insert_baseline(
        view.clone(),
        RelationState::new(
            view.clone(),
            object_id("", "old_owner"),
            0,
            None,
            RelationKind::View,
            Persistence::Permanent,
            0,
        ),
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze(
            "ALTER VIEW public.owned_view OWNER TO new_owner;",
            &mut state,
        )
        .unwrap();

    let RelationOverlay::Present(relation) = state.get_relation(&view).unwrap() else {
        panic!("view missing");
    };
    assert_eq!(relation.owner, object_id("", "new_owner"));
}
