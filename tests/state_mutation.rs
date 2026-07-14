mod common;

mod state_mutation_tests {
    use crate::common::*;
    use safe_migrate::analysis::state::Confidence;
    use safe_migrate::ast::identifiers::ObjectId;
    use safe_migrate::model::relation::RelationOverlay;
    use safe_migrate::model::sequence::SequenceOverlay;
    use safe_migrate::model::types::{TypeKind, TypeOverlay};

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
    fn test_topology_drop_table() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id int); DROP TABLE t;", &mut state)
            .unwrap();
        assert!(!state.relation_is_present(&object_id("public", "t")));
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
                .renames
                .iter()
                .any(|e| e.from == object_id("public", "a") && e.to == object_id("public", "b"))
        );
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
                .indexes
                .iter()
                .any(|i| i.index_id == object_id("public", "i2"))
        );
        assert!(
            !state
                .local
                .graph
                .indexes
                .iter()
                .any(|i| i.index_id == object_id("public", "i"))
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
                .foreign_keys
                .iter()
                .any(|fk| fk.from_table == object_id("public", "c")
                    && fk.to_table == object_id("public", "p"))
        );

        engine
            .analyze("ALTER TABLE c DROP CONSTRAINT fk;", &mut state)
            .unwrap();
        assert!(state.local.graph.foreign_keys.is_empty());
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
                .views
                .iter()
                .any(|v| v.view_id == object_id("public", "v")
                    && v.depends_on.contains(&object_id("public", "t")))
        );

        engine.analyze("DROP VIEW v;", &mut state).unwrap();
        assert!(state.local.graph.views.is_empty());
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
                .views
                .iter()
                .any(|v| v.view_id == object_id("public", "mv")
                    && v.depends_on.contains(&object_id("public", "t")))
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
                .sequences
                .iter()
                .any(|s| s.sequence_id == object_id("public", "s")
                    && s.table_id == object_id("public", "t"))
        );

        engine.analyze("DROP SEQUENCE s;", &mut state).unwrap();
        assert!(matches!(
            state.local.sequences.get(&object_id("public", "s")),
            Some(SequenceOverlay::Dropped)
        ));
        assert!(state.local.graph.sequences.is_empty());
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

        let deps = &state.local.graph.publication_dependencies;
        assert_eq!(deps.len(), 2);
        assert!(
            deps.iter()
                .any(|d| d.publication_name == "pub" && d.table_id == object_id("public", "t1"))
        );
        assert!(
            deps.iter()
                .any(|d| d.publication_name == "pub" && d.table_id == object_id("public", "t2"))
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
                "CREATE FUNCTION f(int) RETURNS int AS '...' LANGUAGE plpgsql;",
                &mut state,
            )
            .unwrap();
        let id = object_id("public", "f(int)");
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
        let id = object_id("public", "p(int)");
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
                .indexes
                .iter()
                .any(|i| i.relation_id == object_id("public", "mv"))
        );

        engine
            .analyze("DROP MATERIALIZED VIEW mv;", &mut state)
            .unwrap();
        assert!(!state.relation_is_present(&object_id("public", "mv")));
        assert!(state.relation_is_present(&object_id("public", "t")));
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
}

// ─────────────────────────────────────────────
// 4. Transaction Lifecycle Rollback Exhaustion
// ─────────────────────────────────────────────
