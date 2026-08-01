mod common;

mod state_mutation_tests {
    use crate::common::*;
    use safe_migrate::analysis::graph::{DependencyEdge, DependencyGraph, DependencyKind};
    use safe_migrate::analysis::state::Confidence;
    use safe_migrate::ast::identifiers::ObjectId;
    use safe_migrate::db::cache::{DbCache, DependencyCache};
    use safe_migrate::model::constraint::ConstraintKind;
    use safe_migrate::model::relation::{
        Persistence, RelationKind, RelationOverlay, RelationState,
    };
    use safe_migrate::model::sequence::SequenceOverlay;
    use safe_migrate::model::types::{TypeKind, TypeOverlay, TypeState};

    #[test]
    fn test_topology_table_basic() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id int); ALTER TABLE t ADD COLUMN name text; ALTER TABLE t RENAME COLUMN name TO full_name;",
                &mut state,
            )
            .unwrap();

        let rel = state.get_relation(&object_id("public", "t")).unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert!(r.has_column("id"));
            assert!(r.has_column("full_name"));
            assert!(!r.has_column("name"));
        } else {
            panic!("relation should be present");
        }
    }

    #[test]
    fn cached_view_rewrite_self_edge_is_ignored_but_real_dependency_is_kept() {
        let view_id = object_id("public", "v");
        let table_id = object_id("public", "t");
        let mut cache = DbCache::new();

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

        let dependency = |referenced: &ObjectId| DependencyCache {
            classid: 0,
            objid: 0,
            objsubid: 0,
            refclassid: 0,
            refobjid: 0,
            refobjsubid: 0,
            deptype: "view".to_string(),
            obj_schema: Some(view_id.schema.clone()),
            obj_name: Some(view_id.name.clone()),
            ref_schema: Some(referenced.schema.clone()),
            ref_name: Some(referenced.name.clone()),
        };
        cache.dependencies.push(dependency(&view_id));
        cache.dependencies.push(dependency(&table_id));

        let state = safe_migrate::AnalysisState::new(cache);
        assert!(!state.local.graph.edges.iter().any(|edge| {
            matches!(edge.kind, DependencyKind::ViewDependency { .. })
                && edge.dependent == view_id
                && edge.referenced == view_id
        }));
        assert!(state.local.graph.edges.iter().any(|edge| {
            matches!(edge.kind, DependencyKind::ViewDependency { .. })
                && edge.dependent == view_id
                && edge.referenced == table_id
        }));
    }

    #[test]
    fn test_topology_drop_table() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id int); DROP TABLE t;", &mut state)
            .unwrap();
        assert!(!state.relation_is_present(&object_id("public", "t")));
    }

    #[test]
    fn create_if_not_exists_skips_when_another_relation_kind_uses_the_name() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE SEQUENCE occupied; CREATE TABLE IF NOT EXISTS occupied (id int); CREATE TABLE after_skip (id int);",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        assert!(state.relation_is_present(&object_id("public", "after_skip")));
    }

    #[test]
    fn create_sequence_if_not_exists_skips_when_a_table_uses_the_name() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE occupied (id int); CREATE SEQUENCE IF NOT EXISTS occupied; CREATE TABLE after_skip (id int);",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        assert!(state.relation_is_present(&object_id("public", "after_skip")));
    }

    #[test]
    fn drop_trigger_if_exists_is_a_no_op_when_missing() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE t (id int); DROP TRIGGER IF EXISTS missing ON t; ALTER TABLE t ADD COLUMN later int;",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        let Some(RelationOverlay::Present(table)) = state.get_relation(&object_id("public", "t"))
        else {
            panic!("table should remain present");
        };
        assert!(table.has_column("later"));
    }

    #[test]
    fn drop_sequence_if_exists_drops_present_names_after_missing_ones() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE SEQUENCE present; DROP SEQUENCE IF EXISTS missing, present;",
                &mut state,
            )
            .unwrap();

        assert!(!matches!(
            state.local.sequences.get(&object_id("public", "present")),
            Some(SequenceOverlay::Present(_))
        ));
    }

    #[test]
    fn cascade_drop_marks_triggers_on_partition_children_as_dropped() {
        use safe_migrate::model::trigger::TriggerOverlay;

        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE parent (id int) PARTITION BY LIST (id); CREATE TABLE child PARTITION OF parent FOR VALUES IN (1); CREATE FUNCTION audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$; CREATE TRIGGER audit_trigger BEFORE INSERT ON child FOR EACH ROW EXECUTE FUNCTION audit(); DROP TABLE parent CASCADE;",
                &mut state,
            )
            .unwrap();

        assert!(
            state
                .local
                .triggers
                .values()
                .all(|trigger| { matches!(trigger, TriggerOverlay::Dropped) })
        );
    }

    #[test]
    fn cascade_drop_removes_constraints_on_cascade_dropped_relations() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE parent (id int) PARTITION BY LIST (id); CREATE TABLE child PARTITION OF parent FOR VALUES IN (1); ALTER TABLE child ADD CONSTRAINT child_check CHECK (id > 0); DROP TABLE parent CASCADE;",
                &mut state,
            )
            .unwrap();

        assert!(
            !state
                .local
                .constraints
                .contains_key(&(object_id("public", "child"), "child_check".to_string())),
            "constraints for cascade-dropped relations must not remain in state"
        );
    }

    #[test]
    fn failed_drop_table_keeps_owned_triggers_for_later_dependency_checks() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE t(id int); CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$; CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW EXECUTE FUNCTION f(); CREATE VIEW v AS SELECT * FROM t; DROP TABLE t; DROP FUNCTION f();",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.reason.contains("relation 'public.t")
                && violation.reason.contains("still has dependent objects")
        }));
        assert!(violations.iter().any(|violation| {
            violation
                .reason
                .contains("function 'public.f()' still has dependent triggers")
        }));
        assert!(state.relation_is_present(&object_id("public", "t")));
    }

    #[test]
    fn test_topology_rename_table() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE a(id int); ALTER TABLE a RENAME TO b;",
                &mut state,
            )
            .unwrap();

        assert!(!state.relation_is_present(&object_id("public", "a")));
        assert!(state.relation_is_present(&object_id("public", "b")));
        assert!(
            state
                .local
                .graph
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::RenameTo
                ))
                .any(|e| e.dependent == object_id("public", "a")
                    && e.referenced == object_id("public", "b"))
        );
    }

    #[test]
    fn rename_back_to_original_name_does_not_loop_during_drop() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE a(id int); ALTER TABLE a RENAME TO b; ALTER TABLE b RENAME TO a; DROP TABLE a;",
                &mut state,
            )
            .unwrap();

        assert!(!state.relation_is_present(&object_id("public", "a")));
    }

    #[test]
    fn malformed_partition_ancestry_is_rejected_without_looping() {
        let a = object_id("public", "a");
        let b = object_id("public", "b");
        let child = object_id("public", "new_child");
        let mut graph = DependencyGraph::new();
        graph.edges.push(DependencyEdge::new(
            a.clone(),
            b.clone(),
            DependencyKind::PartitionOf,
        ));
        graph.edges.push(DependencyEdge::new(
            b,
            a.clone(),
            DependencyKind::PartitionOf,
        ));

        assert!(graph.check_partition_cycle(&a, &child));
    }

    #[test]
    fn test_topology_rename_index() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id int); CREATE INDEX i ON t(id); ALTER INDEX i RENAME TO i2;",
                &mut state,
            )
            .unwrap();

        assert!(
            state
                .local
                .graph
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::IndexOnRelation { .. }
                ))
                .any(|i| i.dependent == object_id("public", "i2"))
        );
        assert!(
            !state
                .local
                .graph
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::IndexOnRelation { .. }
                ))
                .any(|i| i.dependent == object_id("public", "i"))
        );
    }

    #[test]
    fn test_topology_foreign_key_graph() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE p(id int); CREATE TABLE c(p_id int); ALTER TABLE c ADD CONSTRAINT fk FOREIGN KEY (p_id) REFERENCES p(id);",
                &mut state,
            )
            .unwrap();

        assert!(
            state
                .local
                .graph
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::ForeignKey { .. }
                ))
                .any(|fk| fk.dependent == object_id("public", "c")
                    && fk.referenced == object_id("public", "p"))
        );

        engine
            .analyze("ALTER TABLE c DROP CONSTRAINT fk;", &mut state)
            .unwrap();
        assert!(
            state
                .local
                .graph
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::ForeignKey { .. }
                ))
                .count()
                == 0
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
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::ViewDependency { .. }
                ))
                .any(|v| v.dependent == object_id("public", "v")
                    && v.referenced == object_id("public", "t"))
        );

        engine.analyze("DROP VIEW v;", &mut state).unwrap();
        assert!(
            state
                .local
                .graph
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::ViewDependency { .. }
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
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::ViewDependency { .. }
                ))
                .any(|v| v.dependent == object_id("public", "mv")
                    && v.referenced == object_id("public", "t"))
        );
    }

    #[test]
    fn test_topology_sequence_graph() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id int); CREATE SEQUENCE s OWNED BY t.id;",
                &mut state,
            )
            .unwrap();

        assert!(
            state
                .local
                .graph
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::SequenceOwnedBy { .. }
                ))
                .any(|s| s.dependent == object_id("public", "s")
                    && s.referenced == object_id("public", "t"))
        );

        engine.analyze("DROP SEQUENCE s;", &mut state).unwrap();
        assert!(matches!(
            state.local.sequences.get(&object_id("public", "s")),
            Some(SequenceOverlay::Dropped)
        ));
        assert!(
            state
                .local
                .graph
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::SequenceOwnedBy { .. }
                ))
                .count()
                == 0
        );
    }

    #[test]
    fn test_topology_type_and_domain() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TYPE e AS ENUM('a'); ALTER TYPE e ADD VALUE 'b'; CREATE DOMAIN d AS INT; ALTER DOMAIN d SET DEFAULT 1;",
                &mut state,
            )
            .unwrap();

        if let Some(TypeOverlay::Present(t)) = state.local.types.get(&object_id("public", "e")) {
            if let TypeKind::Enum { variants } = &t.kind {
                assert!(variants.contains(&"b".to_string()));
            } else {
                panic!("type e should be enum");
            }
        } else {
            panic!("type e missing");
        }

        engine.analyze("DROP DOMAIN d;", &mut state).unwrap();
        assert!(matches!(
            state.local.types.get(&object_id("public", "d")),
            Some(TypeOverlay::Dropped)
        ));
    }

    #[test]
    fn test_enum_add_value_preserves_postgres_ordering() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();
        let id = object_id("public", "e");
        cache.types.insert(
            id.clone(),
            TypeState {
                id: id.clone(),
                generation: 0,
                kind: TypeKind::Enum {
                    variants: vec!["first".into(), "last".into()],
                },
            },
        );
        let mut state = safe_migrate::AnalysisState::new(cache);

        engine
            .analyze(
                "ALTER TYPE e ADD VALUE 'middle' BEFORE 'last'; ALTER TYPE e ADD VALUE 'tail' AFTER 'last';",
                &mut state,
            )
            .unwrap();

        let Some(TypeOverlay::Present(type_state)) = state.local.types.get(&id) else {
            panic!("enum e missing");
        };
        assert_eq!(
            type_state.kind,
            TypeKind::Enum {
                variants: vec![
                    "first".into(),
                    "middle".into(),
                    "last".into(),
                    "tail".into()
                ]
            }
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
            Some(safe_migrate::model::replication::PublicationOverlay::Dropped)
        ));
        assert!(matches!(
            state.local.subscriptions.get("s"),
            Some(safe_migrate::model::replication::SubscriptionOverlay::Dropped)
        ));
    }

    #[test]
    fn test_topology_trigger_and_policy() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id int); CREATE POLICY p ON t FOR SELECT USING(true); CREATE TRIGGER tr BEFORE INSERT ON t EXECUTE FUNCTION f();",
                &mut state,
            )
            .unwrap();

        if let Some(RelationOverlay::Present(r)) = state.get_relation(&object_id("public", "t")) {
            assert!(r.policies.contains("p"));
            assert!(r.triggers.contains("tr"));
        }

        engine
            .analyze("DROP POLICY p ON t; DROP TRIGGER tr ON t;", &mut state)
            .unwrap();

        if let Some(RelationOverlay::Present(r)) = state.get_relation(&object_id("public", "t")) {
            assert!(!r.policies.contains("p"));
            assert!(!r.triggers.contains("tr"));
        }
    }

    #[test]
    fn test_topology_publication() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE PUBLICATION pub FOR TABLE t1, t2;", &mut state)
            .unwrap();
        assert!(state.local.publications.contains_key("pub"));

        let deps = &state.local.graph.edges;
        assert_eq!(deps.len(), 2);
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
    fn test_topology_role_lifecycle() {
        let engine = setup_engine();
        let mut state = setup_state();

        // Create
        let role_id = ObjectId::new("", "app_user");
        engine.analyze("CREATE ROLE app_user;", &mut state).unwrap();
        assert!(state.local.roles.contains_key(&role_id));

        // Alter
        engine
            .analyze("ALTER ROLE app_user WITH INHERIT;", &mut state)
            .unwrap();
        if let Some(safe_migrate::model::role::RoleOverlay::Present(role)) =
            state.local.roles.get(&role_id)
        {
            assert!(role.can_login);
        } else {
            panic!("role app_user should be present");
        }

        // Drop
        engine.analyze("DROP ROLE app_user;", &mut state).unwrap();
        assert!(matches!(
            state.local.roles.get(&role_id),
            Some(safe_migrate::model::role::RoleOverlay::Dropped)
        ));
    }

    #[test]
    fn test_topology_function() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE FUNCTION fn(a int) RETURNS int LANGUAGE sql AS 'SELECT 1';",
                &mut state,
            )
            .unwrap();

        let id = ObjectId::new("public", "fn(integer)");
        assert!(state.local.functions.contains_key(&id));
    }

    #[test]
    fn test_topology_procedure() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE PROCEDURE p(int) AS '...' LANGUAGE plpgsql;",
                &mut state,
            )
            .unwrap();

        let id = ObjectId::new("public", "p(integer)");
        assert!(state.local.functions.contains_key(&id));
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

        assert!(state.relation_is_present(&object_id("myschema", "t")));
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

        assert!(state.relation_is_present(&object_id("tenant", "t")));
        assert_eq!(state.local.search_path, ["tenant", "public"]);
    }

    #[test]
    fn test_synced_search_path_is_initial_and_default_path() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();
        cache.search_path = vec!["tenant_app".to_string(), "shared".to_string()];
        let mut state = safe_migrate::AnalysisState::new(cache);

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
        assert_eq!(state.local.search_path, ["tenant_app", "shared"]);
    }

    #[test]
    fn test_unqualified_index_uses_table_schema() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE public.indexed_table(id int); SET search_path TO other_schema, public; CREATE INDEX indexed_table_id_idx ON public.indexed_table(id);",
                &mut state,
            )
            .unwrap();

        assert!(state.local.graph.edges.iter().any(|edge| {
            edge.dependent == object_id("public", "indexed_table_id_idx")
                && edge.referenced == object_id("public", "indexed_table")
                && matches!(
                    edge.kind,
                    safe_migrate::analysis::graph::DependencyKind::IndexOnRelation { .. }
                )
        }));
    }

    #[test]
    fn test_serial_and_default_null_follow_postgres_column_state() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE serial_test (id SERIAL, optional INT DEFAULT NULL);",
                &mut state,
            )
            .unwrap();

        let Some(RelationOverlay::Present(relation)) =
            state.get_relation(&object_id("public", "serial_test"))
        else {
            panic!("serial_test should be present");
        };
        let id = relation.get_column("id").unwrap();
        assert_eq!(id.data_type.as_deref(), Some("integer"));
        assert!(!id.is_nullable);
        assert!(id.default.is_some());

        let optional = relation.get_column("optional").unwrap();
        assert!(optional.is_nullable);
        assert!(optional.default.is_none());
    }

    #[test]
    fn test_state_alter_column_types() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id INT NOT NULL); ALTER TABLE t ALTER COLUMN id SET DATA TYPE text; ALTER TABLE t ALTER COLUMN id DROP NOT NULL; ALTER TABLE t ALTER COLUMN id SET DEFAULT 'x';",
                &mut state,
            )
            .unwrap();

        if let Some(RelationOverlay::Present(r)) = state.get_relation(&object_id("public", "t")) {
            let col = r.get_column("id").unwrap();
            assert_eq!(col.data_type.as_deref(), Some("text"));
            assert!(col.is_nullable);
            assert!(col.default.is_some());
        } else {
            panic!("relation should be present");
        }
    }

    #[test]
    fn test_state_storage_and_access_method() {
        let engine = setup_engine();
        let mut state = setup_state();

        assert!(engine
            .analyze(
                "CREATE TABLE t(id int); ALTER TABLE t ALTER COLUMN id SET STORAGE MAIN; ALTER TABLE t SET ACCESS METHOD heap;",
                &mut state,
            )
            .is_ok());
    }

    #[test]
    fn test_bug011_set_storage_multiple_spaces() {
        let engine = setup_engine();
        let mut state = setup_state();

        assert!(
            engine
                .analyze(
                    "CREATE TABLE t(id int); ALTER TABLE t ALTER COLUMN id SET    STORAGE MAIN;",
                    &mut state,
                )
                .is_ok()
        );
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
                .edges
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::IndexOnRelation { .. }
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

        assert!(!state.local.graph.edges.iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                && edge.referenced == object_id("public", "mv")
        }));
    }

    #[test]
    fn test_state_drop_function_if_exists() {
        let engine = setup_engine();
        let mut state = setup_state();

        // Should not taint when dropping nonexistent function with IF EXISTS
        assert_eq!(state.local.confidence, Confidence::Exact);
        engine
            .analyze("DROP FUNCTION IF EXISTS missing_func();", &mut state)
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Exact);
    }

    #[test]
    fn test_state_drop_procedure_if_exists() {
        let engine = setup_engine();
        let mut state = setup_state();

        assert_eq!(state.local.confidence, Confidence::Exact);
        engine
            .analyze("DROP PROCEDURE IF EXISTS missing_proc();", &mut state)
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Exact);
    }

    #[test]
    fn test_state_alter_publication_non_existent() {
        let engine = setup_engine();
        let mut state = setup_state();

        // Create the publication first (it needs to exist before we alter it)
        // Then alter with a non-existent one will taint
        engine
            .analyze(
                "CREATE PUBLICATION existing_pub FOR ALL TABLES;",
                &mut state,
            )
            .unwrap();
        assert!(state.local.publications.contains_key("existing_pub"));

        // Alter a non-existent publication should taint
        // We catch this via the engine's resolve path which returns Opaque
        // This is already tested in the resolver - here we verify confidence
        engine
            .analyze("ALTER PUBLICATION missing_pub SET TABLE t;", &mut state)
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Tainted);
    }

    #[test]
    fn test_state_grant_revoke_topology() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id int); GRANT SELECT ON t TO public;",
                &mut state,
            )
            .unwrap();

        assert!(state.relation_is_present(&object_id("public", "t")));
        assert_eq!(state.local.confidence, Confidence::Exact);

        engine
            .analyze("REVOKE SELECT ON t FROM public;", &mut state)
            .unwrap();
        assert!(state.relation_is_present(&object_id("public", "t")));
    }

    #[test]
    fn test_state_hydrates_and_disables_trigger() {
        use safe_migrate::db::cache::TriggerCache;
        use safe_migrate::model::trigger::{TriggerEnableMode, TriggerOverlay};

        let engine = setup_engine();
        let mut cache = cache_with_table("public", "test_table", None);
        cache.triggers.push(TriggerCache {
            trigger_id: object_id("public", "check_trigger"),
            table_id: object_id("public", "test_table"),
            function_id: object_id("public", "check_row()"),
            enabled_mode: TriggerEnableMode::Origin,
        });
        let mut state = safe_migrate::AnalysisState::new(cache);

        engine
            .analyze(
                "ALTER TABLE test_table DISABLE TRIGGER check_trigger;",
                &mut state,
            )
            .unwrap();

        let Some(TriggerOverlay::Present(trigger)) = state
            .local
            .triggers
            .values()
            .find(|overlay| matches!(overlay, TriggerOverlay::Present(trigger) if trigger.name == "check_trigger"))
        else {
            panic!("baseline trigger should be hydrated");
        };
        assert_eq!(trigger.enabled_mode, TriggerEnableMode::Disabled);
    }

    #[test]
    fn test_state_alter_function_updates_volatility_and_identity() {
        use safe_migrate::model::function::{FunctionOverlay, Volatility};

        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1';",
                &mut state,
            )
            .unwrap();
        engine
            .analyze("ALTER FUNCTION f() IMMUTABLE;", &mut state)
            .unwrap();

        let Some(FunctionOverlay::Present(function)) =
            state.local.functions.get(&object_id("public", "f()"))
        else {
            panic!("function should remain present after volatility change");
        };
        assert_eq!(function.volatility, Volatility::Immutable);

        engine
            .analyze("ALTER FUNCTION f() RENAME TO g;", &mut state)
            .unwrap();
        assert!(
            !state
                .local
                .functions
                .contains_key(&object_id("public", "f()"))
        );
        assert!(matches!(
            state.local.functions.get(&object_id("public", "g()")),
            Some(FunctionOverlay::Present(_))
        ));
    }

    #[test]
    fn test_state_adds_named_check_constraint() {
        use safe_migrate::model::constraint::ConstraintKind;

        let engine = setup_engine();
        let mut state =
            safe_migrate::AnalysisState::new(cache_with_table("public", "t_large", None));
        engine
            .analyze(
                "ALTER TABLE t_large ADD CONSTRAINT positive_id CHECK (id > 0);",
                &mut state,
            )
            .unwrap();

        let constraint = state
            .local
            .constraints
            .get(&(object_id("public", "t_large"), "positive_id".to_string()))
            .expect("check constraint should be represented");
        assert_eq!(constraint.kind, ConstraintKind::Check);
        assert!(constraint.validated);
    }

    #[test]
    fn test_state_adds_named_unique_constraint() {
        use safe_migrate::model::constraint::ConstraintKind;

        let engine = setup_engine();
        let mut state =
            safe_migrate::AnalysisState::new(cache_with_table("public", "t_large", None));
        engine
            .analyze(
                "ALTER TABLE t_large ADD CONSTRAINT unique_id UNIQUE (id);",
                &mut state,
            )
            .unwrap();

        let constraint = state
            .local
            .constraints
            .get(&(object_id("public", "t_large"), "unique_id".to_string()))
            .expect("unique constraint should be represented");
        assert_eq!(constraint.kind, ConstraintKind::Unique);
        assert!(constraint.validated);
    }

    #[test]
    fn test_drop_function_cascade_removes_dependent_trigger() {
        use safe_migrate::model::function::FunctionOverlay;
        use safe_migrate::model::trigger::TriggerOverlay;

        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "
                CREATE TABLE target (id integer);
                CREATE FUNCTION compute_trigger() RETURNS trigger
                    LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
                CREATE TRIGGER compute_row AFTER INSERT ON target
                    EXECUTE FUNCTION compute_trigger();
                DROP FUNCTION compute_trigger() CASCADE;
                ",
                &mut state,
            )
            .unwrap();

        assert!(matches!(
            state
                .local
                .functions
                .get(&object_id("public", "compute_trigger()")),
            Some(FunctionOverlay::Dropped)
        ));
        assert!(matches!(
            state.local.triggers.values().next(),
            Some(TriggerOverlay::Dropped)
        ));
    }

    #[test]
    fn same_named_triggers_on_different_tables_remain_independent() {
        use safe_migrate::model::trigger::{TriggerEnableMode, TriggerOverlay};

        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "
                CREATE TABLE first_table (id integer);
                CREATE TABLE second_table (id integer);
                CREATE FUNCTION audit_trigger() RETURNS trigger
                    LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
                CREATE TRIGGER audit AFTER INSERT ON first_table
                    EXECUTE FUNCTION audit_trigger();
                CREATE TRIGGER audit AFTER INSERT ON second_table
                    EXECUTE FUNCTION audit_trigger();
                ALTER TABLE first_table DISABLE TRIGGER audit;
                ",
                &mut state,
            )
            .unwrap();

        let modes: Vec<_> = state
            .local
            .triggers
            .values()
            .filter_map(|overlay| match overlay {
                TriggerOverlay::Present(trigger) if trigger.name == "audit" => {
                    Some((trigger.table_id.name.as_str(), trigger.enabled_mode))
                }
                _ => None,
            })
            .collect();
        assert_eq!(modes.len(), 2);
        assert!(modes.contains(&("first_table", TriggerEnableMode::Disabled)));
        assert!(modes.contains(&("second_table", TriggerEnableMode::Origin)));
    }

    #[test]
    fn test_variadic_function_drop_normalizes_array_alias() {
        use safe_migrate::db::cache::DbCache;
        use safe_migrate::model::function::{
            FunctionOverlay, FunctionState, SecurityMode, Volatility,
        };

        let engine = setup_engine();
        let function_id = object_id("public", "f_safe(integer[])");
        let mut cache = DbCache::new();
        cache.functions.insert(
            function_id.clone(),
            FunctionState {
                id: function_id.clone(),
                arg_types: vec!["integer[]".to_string()],
                return_type: "integer".to_string(),
                volatility: Volatility::Volatile,
                language: "sql".to_string(),
                security: SecurityMode::Invoker,
            },
        );
        let mut state = safe_migrate::AnalysisState::new(cache);
        engine
            .analyze("DROP FUNCTION f_safe(VARIADIC INT[]);", &mut state)
            .unwrap();

        assert!(matches!(
            state.local.functions.get(&function_id),
            Some(FunctionOverlay::Dropped)
        ));
    }

    #[test]
    fn foreign_key_not_valid_then_validate_updates_constraint_state() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE parent (id integer PRIMARY KEY);
                 CREATE TABLE child (parent_id integer);
                 ALTER TABLE child ADD CONSTRAINT child_parent_fk
                    FOREIGN KEY (parent_id) REFERENCES parent(id) NOT VALID;",
                &mut state,
            )
            .unwrap();

        let key = (object_id("public", "child"), "child_parent_fk".to_string());
        let constraint = state
            .local
            .constraints
            .get(&key)
            .expect("foreign key should be recorded");
        assert_eq!(constraint.kind, ConstraintKind::ForeignKey);
        assert!(!constraint.validated);

        engine
            .analyze(
                "ALTER TABLE child VALIDATE CONSTRAINT child_parent_fk;",
                &mut state,
            )
            .unwrap();
        assert!(state.local.constraints[&key].validated);
    }

    #[test]
    fn missing_foreign_key_source_column_is_a_conflict() {
        let engine = setup_engine();
        let mut state = setup_state();
        let violations = engine
            .analyze(
                "CREATE TABLE parent (id integer PRIMARY KEY);
                 CREATE TABLE child (parent_id integer);
                 ALTER TABLE child ADD CONSTRAINT child_parent_fk
                    FOREIGN KEY (missing_parent_id) REFERENCES parent(id) NOT VALID;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("missing_parent_id")
        }));
        assert!(
            !state
                .local
                .constraints
                .contains_key(&(object_id("public", "child"), "child_parent_fk".to_string()))
        );
    }

    #[test]
    fn create_table_records_inline_primary_key_and_table_unique_constraints() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE accounts (
                    id integer PRIMARY KEY,
                    tenant_id integer,
                    email text,
                    UNIQUE (tenant_id, email)
                );",
                &mut state,
            )
            .unwrap();

        let table_id = object_id("public", "accounts");
        let primary_key = state
            .local
            .constraints
            .get(&(table_id.clone(), "accounts_pkey".to_string()))
            .expect("inline primary key should be recorded");
        assert_eq!(primary_key.kind, ConstraintKind::PrimaryKey);
        assert!(primary_key.validated);

        let unique = state
            .local
            .constraints
            .get(&(table_id, "accounts_tenant_id_email_key".to_string()))
            .expect("table unique constraint should be recorded");
        assert_eq!(unique.kind, ConstraintKind::Unique);
        assert!(unique.validated);
    }

    #[test]
    fn unique_using_index_attaches_constraint_without_blocking_index_finding() {
        let engine = setup_engine();
        let mut state = setup_state();
        let violations = engine
            .analyze(
                "CREATE TABLE users (email text);
                 CREATE UNIQUE INDEX users_email_key ON users(email);
                 ALTER TABLE users ADD CONSTRAINT users_email_key
                    UNIQUE USING INDEX users_email_key;",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "blocking-index-constraint")
        );
        let constraint = state
            .local
            .constraints
            .get(&(object_id("public", "users"), "users_email_key".to_string()))
            .expect("unique constraint should be recorded");
        assert_eq!(constraint.kind, ConstraintKind::Unique);
        assert!(constraint.validated);
    }

    #[test]
    fn exclusion_constraint_is_recorded_and_reported() {
        let engine = setup_engine();
        let table_id = object_id("public", "reservations");
        let mut relation = RelationState::new(
            table_id.clone(),
            object_id("public", "postgres"),
            0,
            Some(500_000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        relation.columns.push(safe_migrate::model::column::Column {
            name: "period".to_string(),
            data_type: Some("int4range".to_string()),
            is_nullable: true,
            default: None,
            avg_width: None,
            default_expr_text: None,
            type_modifier: None,
        });
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id, relation);
        let mut state = safe_migrate::AnalysisState::new(cache);
        let violations = engine
            .analyze(
                "ALTER TABLE reservations ADD CONSTRAINT no_overlap
                    EXCLUDE USING gist (period WITH &&);",
                &mut state,
            )
            .unwrap();

        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "blocking-index-constraint")
        );
        assert_eq!(
            state.local.constraints[&(
                object_id("public", "reservations"),
                "no_overlap".to_string()
            )]
                .kind,
            ConstraintKind::Exclusion
        );
    }
}

// ─────────────────────────────────────────────
// 4. Transaction Lifecycle Rollback Exhaustion
// ─────────────────────────────────────────────
