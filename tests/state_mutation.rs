mod common;

mod state_mutation_tests {
    use crate::common::*;
    use safe_migrate::analysis::graph::{DependencyEdge, DependencyGraph, DependencyKind};
    use safe_migrate::analysis::state::Confidence;
    use safe_migrate::ast::identifiers::ObjectId;
    use safe_migrate::db::cache::{DbCache, DependencyCache};
    use safe_migrate::model::constraint::ConstraintKind;
    use safe_migrate::model::function::{
        FunctionOverlay, FunctionState, RoutineKind, SecurityMode, Volatility,
    };
    use safe_migrate::model::relation::{
        Persistence, RelationKind, RelationOverlay, RelationState,
    };
    use safe_migrate::model::role::RoleState;
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
    fn create_then_rename_enum_value_preserves_order_and_escaped_labels() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TYPE mood AS ENUM ('sad', 'it''s fine', 'happy');
                 ALTER TYPE mood RENAME VALUE 'it''s fine' TO 'it''s great';",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        let Some(TypeOverlay::Present(type_state)) =
            state.local.types.get(&object_id("public", "mood"))
        else {
            panic!("enum mood missing");
        };
        assert_eq!(
            type_state.kind,
            TypeKind::Enum {
                variants: vec!["sad".into(), "it's great".into(), "happy".into()]
            }
        );
    }

    #[test]
    fn rename_type_updates_identity_and_rolls_back() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "BEGIN; CREATE TYPE mood AS ENUM ('sad'); ALTER TYPE mood RENAME TO emotion;",
                &mut state,
            )
            .unwrap();

        assert!(!state.local.types.contains_key(&object_id("public", "mood")));
        let Some(TypeOverlay::Present(type_state)) =
            state.local.types.get(&object_id("public", "emotion"))
        else {
            panic!("renamed type missing");
        };
        assert_eq!(type_state.id, object_id("public", "emotion"));

        engine.analyze("ROLLBACK;", &mut state).unwrap();
        assert!(
            !state
                .local
                .types
                .contains_key(&object_id("public", "emotion"))
        );
        assert!(!state.local.types.contains_key(&object_id("public", "mood")));
    }

    #[test]
    fn rename_type_rejects_an_existing_target() {
        let engine = setup_engine();
        let mut state = setup_state();
        let violations = engine
            .analyze(
                "CREATE TYPE old_name AS ENUM ('old'); CREATE TYPE new_name AS ENUM ('new'); ALTER TYPE old_name RENAME TO new_name;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("new_name")
        }));
        assert!(matches!(
            state.local.types.get(&object_id("public", "old_name")),
            Some(TypeOverlay::Present(_))
        ));
    }

    #[test]
    fn rename_type_remaps_modeled_dependent_references() {
        let engine = setup_engine();
        let mut state = setup_state();
        let violations = engine
            .analyze(
                "CREATE TYPE mood AS ENUM ('sad');
                 CREATE TABLE entries (status mood, statuses mood[]);
                 CREATE DOMAIN mood_alias AS mood;
                 CREATE FUNCTION accepts_mood(value mood) RETURNS mood LANGUAGE sql AS $$ SELECT value $$;
                 ALTER TYPE mood RENAME TO emotion;",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        let RelationOverlay::Present(relation) =
            state.get_relation(&object_id("public", "entries")).unwrap()
        else {
            panic!("entries table missing");
        };
        assert_eq!(
            relation.get_column("status").unwrap().data_type.as_deref(),
            Some("emotion")
        );
        assert_eq!(
            relation
                .get_column("statuses")
                .unwrap()
                .data_type
                .as_deref(),
            Some("emotion[]")
        );
        let Some(TypeOverlay::Present(TypeState {
            kind: TypeKind::Domain { base_type, .. },
            ..
        })) = state.local.types.get(&object_id("public", "mood_alias"))
        else {
            panic!("domain missing");
        };
        assert_eq!(base_type, "emotion");
        let function_id = object_id("public", "accepts_mood(emotion)");
        let Some(safe_migrate::model::function::FunctionOverlay::Present(function)) =
            state.local.functions.get(&function_id)
        else {
            panic!("remapped function missing");
        };
        assert_eq!(function.arg_types, vec!["emotion"]);
        assert_eq!(function.return_type, "emotion");
    }

    #[test]
    fn rename_type_remaps_only_the_resolved_schema_and_preserves_quoted_identity() {
        let engine = setup_engine();
        let mut state = setup_state();
        let violations = engine
            .analyze(
                "CREATE SCHEMA other;
                 CREATE TYPE public.mood AS ENUM ('sad');
                 CREATE TYPE other.mood AS ENUM ('happy');
                 SET search_path TO other, public;
                 CREATE TABLE other_entries (status mood);
                 CREATE TYPE public.\"Mood\" AS ENUM ('calm');
                 CREATE TABLE public.quoted_entries (status public.\"Mood\");
                 CREATE FUNCTION quoted_mood(value public.\"Mood\") RETURNS public.\"Mood\" LANGUAGE sql AS $$ SELECT value $$;
                 ALTER TYPE public.mood RENAME TO emotion;
                 ALTER TYPE public.\"Mood\" RENAME TO \"Emotion\";",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        let RelationOverlay::Present(other_entries) = state
            .get_relation(&object_id("other", "other_entries"))
            .unwrap()
        else {
            panic!("other_entries table missing");
        };
        assert_eq!(
            other_entries
                .get_column("status")
                .unwrap()
                .data_type
                .as_deref(),
            Some("mood")
        );
        assert_eq!(
            other_entries.get_column("status").unwrap().type_id,
            Some(object_id("other", "mood"))
        );
        let RelationOverlay::Present(quoted_entries) = state
            .get_relation(&object_id("public", "quoted_entries"))
            .unwrap()
        else {
            panic!("quoted_entries table missing");
        };
        assert_eq!(
            quoted_entries
                .get_column("status")
                .unwrap()
                .data_type
                .as_deref(),
            Some("\"Emotion\"")
        );
        assert_eq!(
            quoted_entries.get_column("status").unwrap().type_id,
            Some(object_id("public", "Emotion"))
        );
        assert!(
            state
                .local
                .types
                .contains_key(&object_id("public", "emotion"))
        );
        assert!(state.local.types.contains_key(&object_id("other", "mood")));
        assert!(
            state
                .local
                .types
                .contains_key(&object_id("public", "Emotion"))
        );
        let Some(FunctionOverlay::Present(function)) = state
            .local
            .functions
            .get(&object_id("other", "quoted_mood(\"Emotion\")"))
        else {
            panic!("quoted remapped function missing");
        };
        assert_eq!(function.return_type, "\"Emotion\"");
    }

    #[test]
    fn rename_type_updates_columns_added_or_retyped_later_in_the_chain() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TYPE mood AS ENUM ('sad');
                 CREATE TABLE entries (status text);
                 ALTER TABLE entries ALTER COLUMN status TYPE mood;
                 ALTER TABLE entries ADD COLUMN secondary mood[];
                 ALTER TYPE mood RENAME TO emotion;",
                &mut state,
            )
            .unwrap();

        let RelationOverlay::Present(relation) =
            state.get_relation(&object_id("public", "entries")).unwrap()
        else {
            panic!("entries table missing");
        };
        assert_eq!(
            relation.get_column("status").unwrap().data_type.as_deref(),
            Some("emotion")
        );
        assert_eq!(
            relation
                .get_column("secondary")
                .unwrap()
                .data_type
                .as_deref(),
            Some("emotion[]")
        );
    }

    #[test]
    fn quoted_embedded_quote_type_resolves_in_function_signature() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                r#"CREATE TYPE public."a""b" AS ENUM ('value');
                   CREATE FUNCTION accepts_embedded(value public."a""b")
                   RETURNS public."a""b" LANGUAGE sql AS $$ SELECT value $$;"#,
                &mut state,
            )
            .unwrap();

        let Some(FunctionOverlay::Present(function)) = state
            .local
            .functions
            .values()
            .find(|function| {
                matches!(function, FunctionOverlay::Present(function) if function.id.name.starts_with("accepts_embedded("))
            })
        else {
            panic!("embedded-quote function missing");
        };
        assert_eq!(
            function.arg_type_ids,
            vec![Some(object_id("public", "a\"b"))]
        );
        assert_eq!(function.return_type_id, Some(object_id("public", "a\"b")));
    }

    #[test]
    fn rename_type_updates_cached_routine_signatures_and_undo_restores_them() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        let type_id = object_id("public", "mood");
        cache.types.insert(
            type_id.clone(),
            TypeState {
                id: type_id,
                generation: 0,
                kind: TypeKind::Enum {
                    variants: vec!["sad".into()],
                },
            },
        );
        let function_id = object_id("public", "accepts_mood(mood)");
        cache.functions.insert(
            function_id.clone(),
            FunctionState {
                id: function_id.clone(),
                routine_kind: safe_migrate::model::function::RoutineKind::Function,
                arg_types: vec!["mood".into()],
                arg_type_ids: Vec::new(),
                return_type: "mood".into(),
                return_type_id: None,
                volatility: Volatility::Volatile,
                language: "sql".into(),
                security: SecurityMode::Invoker,
            },
        );
        let mut state = safe_migrate::AnalysisState::new(cache);

        engine
            .analyze(
                "BEGIN; ALTER TYPE mood RENAME TO emotion; ROLLBACK;",
                &mut state,
            )
            .unwrap();

        assert!(matches!(
            state.local.functions.get(&function_id),
            Some(FunctionOverlay::Present(function))
                if function.arg_type_ids == vec![Some(object_id("public", "mood"))]
                    && function.return_type_id == Some(object_id("public", "mood"))
        ));
        assert!(
            !state
                .local
                .functions
                .contains_key(&object_id("public", "accepts_mood(emotion)"))
        );
    }

    #[test]
    fn alter_type_set_schema_updates_identity_and_rolls_back() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE SCHEMA app;
                 CREATE TYPE mood AS ENUM ('sad');
                 BEGIN;
                 ALTER TYPE mood SET SCHEMA app;",
                &mut state,
            )
            .unwrap();

        assert!(!state.local.types.contains_key(&object_id("public", "mood")));
        assert!(matches!(
            state.local.types.get(&object_id("app", "mood")),
            Some(TypeOverlay::Present(_))
        ));

        engine.analyze("ROLLBACK;", &mut state).unwrap();
        assert!(matches!(
            state.local.types.get(&object_id("public", "mood")),
            Some(TypeOverlay::Present(_))
        ));
        assert!(!state.local.types.contains_key(&object_id("app", "mood")));
    }

    #[test]
    fn alter_type_set_schema_rejects_missing_schema_and_existing_target() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TYPE missing_target AS ENUM ('value');
                 ALTER TYPE missing_target SET SCHEMA missing_schema;
                 CREATE SCHEMA app;
                 CREATE TYPE source AS ENUM ('value');
                 CREATE TYPE app.source AS ENUM ('value');
                 ALTER TYPE source SET SCHEMA app;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict"
                && violation.reason.contains("schema 'missing_schema'")
        }));
        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("app.source")
        }));
    }

    #[test]
    fn alter_type_set_schema_remaps_modeled_dependent_references() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE SCHEMA app;
                 CREATE TYPE mood AS ENUM ('sad');
                 CREATE TABLE entries (status mood);
                 CREATE DOMAIN mood_alias AS mood;
                 CREATE FUNCTION accepts_mood(value mood) RETURNS mood LANGUAGE sql AS $$ SELECT value $$;
                 ALTER TYPE mood SET SCHEMA app;",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        assert!(!state.local.types.contains_key(&object_id("public", "mood")));
        assert!(matches!(
            state.local.types.get(&object_id("app", "mood")),
            Some(TypeOverlay::Present(_))
        ));
        let RelationOverlay::Present(relation) =
            state.get_relation(&object_id("public", "entries")).unwrap()
        else {
            panic!("entries table missing");
        };
        assert_eq!(
            relation.get_column("status").unwrap().data_type.as_deref(),
            Some("app.mood")
        );
        let Some(TypeOverlay::Present(TypeState {
            kind: TypeKind::Domain { base_type, .. },
            ..
        })) = state.local.types.get(&object_id("public", "mood_alias"))
        else {
            panic!("domain missing");
        };
        assert_eq!(base_type, "app.mood");
        let Some(FunctionOverlay::Present(function)) = state
            .local
            .functions
            .get(&object_id("public", "accepts_mood(app.mood)"))
        else {
            panic!("remapped function missing");
        };
        assert_eq!(function.return_type, "app.mood");
    }

    #[test]
    fn enum_value_rename_obeys_cached_explicit_and_default_search_path_order() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();
        cache.search_path = vec!["sm_core".into(), "public".into()];
        for schema in ["sm_core", "public"] {
            let id = object_id(schema, "mood");
            cache.types.insert(
                id.clone(),
                TypeState {
                    id,
                    generation: 0,
                    kind: TypeKind::Enum {
                        variants: vec!["old".into(), format!("{schema}_only")],
                    },
                },
            );
        }
        let mut state = safe_migrate::AnalysisState::new(cache);

        engine
            .analyze(
                "ALTER TYPE mood RENAME VALUE 'old' TO 'core_new';
                 SET search_path TO public, sm_core;
                 ALTER TYPE mood RENAME VALUE 'old' TO 'public_new';
                 SET search_path TO DEFAULT;
                 ALTER TYPE mood RENAME VALUE 'core_new' TO 'core_final';",
                &mut state,
            )
            .unwrap();

        let variants = |schema: &str| {
            let Some(TypeOverlay::Present(type_state)) =
                state.local.types.get(&object_id(schema, "mood"))
            else {
                panic!("{schema}.mood missing");
            };
            let TypeKind::Enum { variants } = &type_state.kind else {
                panic!("{schema}.mood is not an enum");
            };
            variants.clone()
        };
        assert_eq!(variants("sm_core"), ["core_final", "sm_core_only"]);
        assert_eq!(variants("public"), ["public_new", "public_only"]);
        assert_eq!(state.local.search_path, ["sm_core", "public"]);
    }

    #[test]
    fn enum_value_rename_expands_user_search_path_from_v4_role_provenance() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some("app_user".into());
        for schema in ["app_user", "public"] {
            let id = object_id(schema, "mood");
            cache.types.insert(
                id.clone(),
                TypeState {
                    id,
                    generation: 0,
                    kind: TypeKind::Enum {
                        variants: vec!["old".into()],
                    },
                },
            );
        }
        let mut state = safe_migrate::AnalysisState::new(cache);

        engine
            .analyze(
                "SET search_path TO \"$user\", public;
                 ALTER TYPE mood RENAME VALUE 'old' TO 'new';",
                &mut state,
            )
            .unwrap();

        assert_eq!(state.local.current_role, "app_user");
        assert!(state.local.current_role_known);
        assert_eq!(state.local.search_path, ["app_user", "public"]);
        assert_eq!(state.local.confidence, Confidence::Exact);
        let Some(TypeOverlay::Present(type_state)) =
            state.local.types.get(&object_id("app_user", "mood"))
        else {
            panic!("app_user.mood missing");
        };
        assert_eq!(
            type_state.kind,
            TypeKind::Enum {
                variants: vec!["new".into()]
            }
        );
    }

    #[test]
    fn cache_without_role_provenance_taints_explicit_user_search_path() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        let id = object_id("public", "mood");
        cache.types.insert(
            id.clone(),
            TypeState {
                id: id.clone(),
                generation: 0,
                kind: TypeKind::Enum {
                    variants: vec!["old".into()],
                },
            },
        );
        let mut state = safe_migrate::AnalysisState::new(cache);

        engine
            .analyze(
                "SET search_path TO \"$user\", public;
                 ALTER TYPE mood RENAME VALUE 'old' TO 'new';",
                &mut state,
            )
            .unwrap();

        assert!(!state.local.current_role_known);
        assert_eq!(state.local.search_path, ["public"]);
        assert_eq!(state.local.confidence, Confidence::Tainted);
    }

    #[test]
    fn enum_value_rename_skips_dropped_type_tombstones_in_the_search_path() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();
        cache.search_path = vec!["first".into(), "second".into()];
        for schema in ["first", "second"] {
            let id = object_id(schema, "mood");
            cache.types.insert(
                id.clone(),
                TypeState {
                    id,
                    generation: 0,
                    kind: TypeKind::Enum {
                        variants: vec!["old".into(), format!("{schema}_only")],
                    },
                },
            );
        }
        let mut state = safe_migrate::AnalysisState::new(cache);

        let violations = engine
            .analyze(
                "DROP TYPE first.mood;
                 ALTER TYPE mood RENAME VALUE 'old' TO 'second_new';",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        assert!(matches!(
            state.local.types.get(&object_id("first", "mood")),
            Some(TypeOverlay::Dropped)
        ));
        let Some(TypeOverlay::Present(type_state)) =
            state.local.types.get(&object_id("second", "mood"))
        else {
            panic!("second.mood missing");
        };
        assert_eq!(
            type_state.kind,
            TypeKind::Enum {
                variants: vec!["second_new".into(), "second_only".into()]
            }
        );
    }

    #[test]
    fn enum_value_rename_reports_postgres_conflicts_without_mutating_state() {
        for (sql, expected_reason) in [
            (
                "ALTER TYPE mood RENAME VALUE 'missing' TO 'new';",
                "not an existing label",
            ),
            (
                "ALTER TYPE mood RENAME VALUE 'old' TO 'existing';",
                "already exists",
            ),
            (
                "ALTER TYPE mood RENAME VALUE 'old' TO 'old';",
                "already exists",
            ),
        ] {
            let engine = setup_engine();
            let mut cache = safe_migrate::db::cache::DbCache::new();
            let id = object_id("public", "mood");
            cache.types.insert(
                id.clone(),
                TypeState {
                    id: id.clone(),
                    generation: 0,
                    kind: TypeKind::Enum {
                        variants: vec!["old".into(), "existing".into()],
                    },
                },
            );
            let mut state = safe_migrate::AnalysisState::new(cache);
            let violations = engine.analyze(sql, &mut state).unwrap();

            assert!(violations.iter().any(|violation| {
                violation.rule_id == "chain-conflict" && violation.reason.contains(expected_reason)
            }));
            assert_eq!(
                state.local.types.get(&id),
                Some(&TypeOverlay::Present(TypeState {
                    id: id.clone(),
                    generation: 0,
                    kind: TypeKind::Enum {
                        variants: vec!["old".into(), "existing".into()]
                    }
                }))
            );
        }
    }

    #[test]
    fn enum_value_rename_rejects_missing_and_non_enum_types() {
        let engine = setup_engine();
        for (setup, rename, expected_reason) in [
            (
                "",
                "ALTER TYPE missing_type RENAME VALUE 'old' TO 'new';",
                "does not exist",
            ),
            (
                "CREATE DOMAIN not_enum AS text;",
                "ALTER TYPE not_enum RENAME VALUE 'old' TO 'new';",
                "is not an enum",
            ),
        ] {
            let mut state = setup_state();
            let sql = format!("{setup} {rename}");
            let violations = engine.analyze(&sql, &mut state).unwrap();
            assert!(violations.iter().any(|violation| {
                violation.rule_id == "chain-conflict" && violation.reason.contains(expected_reason)
            }));
        }
    }

    #[test]
    fn enum_value_rename_rolls_back_with_the_transaction() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TYPE mood AS ENUM ('old', 'stable');
                 BEGIN;
                 ALTER TYPE mood RENAME VALUE 'old' TO 'temporary';
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();

        let Some(TypeOverlay::Present(type_state)) =
            state.local.types.get(&object_id("public", "mood"))
        else {
            panic!("enum mood missing");
        };
        assert_eq!(
            type_state.kind,
            TypeKind::Enum {
                variants: vec!["old".into(), "stable".into()]
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
    fn rename_trigger_updates_identity_and_rolls_back() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id int);
                 CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$;
                 CREATE TRIGGER old_trigger BEFORE INSERT ON t FOR EACH ROW EXECUTE FUNCTION f();
                 BEGIN;
                 ALTER TRIGGER old_trigger ON t RENAME TO new_trigger;",
                &mut state,
            )
            .unwrap();

        let RelationOverlay::Present(relation) =
            state.get_relation(&object_id("public", "t")).unwrap()
        else {
            panic!("table missing");
        };
        assert!(!relation.triggers.contains("old_trigger"));
        assert!(relation.triggers.contains("new_trigger"));
        assert!(state.local.triggers.values().any(|overlay| matches!(overlay,
            safe_migrate::model::trigger::TriggerOverlay::Present(trigger) if trigger.name == "new_trigger"
        )));

        engine.analyze("ROLLBACK;", &mut state).unwrap();
        let RelationOverlay::Present(relation) =
            state.get_relation(&object_id("public", "t")).unwrap()
        else {
            panic!("table missing");
        };
        assert!(relation.triggers.contains("old_trigger"));
        assert!(!relation.triggers.contains("new_trigger"));
    }

    #[test]
    fn rename_trigger_rejects_an_existing_target() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE t(id int);
                 CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$;
                 CREATE TRIGGER first_trigger BEFORE INSERT ON t FOR EACH ROW EXECUTE FUNCTION f();
                 CREATE TRIGGER second_trigger BEFORE UPDATE ON t FOR EACH ROW EXECUTE FUNCTION f();
                 ALTER TRIGGER first_trigger ON t RENAME TO second_trigger;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("second_trigger")
        }));
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

        let deps = &state.local.graph.edges;
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
            assert!(!role.can_login);
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
    fn create_user_and_role_login_options_are_distinct() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE USER web_user; CREATE ROLE worker LOGIN NOINHERIT; CREATE ROLE batch;",
                &mut state,
            )
            .unwrap();

        let Some(safe_migrate::model::role::RoleOverlay::Present(user)) =
            state.local.roles.get(&ObjectId::new("", "web_user"))
        else {
            panic!("user missing");
        };
        assert!(user.can_login);

        let Some(safe_migrate::model::role::RoleOverlay::Present(role)) =
            state.local.roles.get(&ObjectId::new("", "worker"))
        else {
            panic!("role missing");
        };
        assert!(role.can_login);

        let Some(safe_migrate::model::role::RoleOverlay::Present(batch)) =
            state.local.roles.get(&ObjectId::new("", "batch"))
        else {
            panic!("plain role missing");
        };
        assert!(!batch.can_login);
    }

    #[test]
    fn unquoted_role_and_replication_names_are_case_folded() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE ROLE AppUser;
                 CREATE ROLE appuser;
                 CREATE PUBLICATION MixedPub FOR ALL TABLES;
                 CREATE PUBLICATION mixedpub FOR ALL TABLES;",
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

        assert!(state.relation_is_present(&object_id("public", "t")));
        assert_eq!(state.local.search_path, ["public"]);
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
        assert_eq!(state.local.search_path, ["public"]);
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

        assert_eq!(state.local.confidence, Confidence::Exact);
        engine
            .analyze("DROP FUNCTION IF EXISTS missing_func();", &mut state)
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Exact);
    }

    #[test]
    fn creating_a_new_function_is_exact_when_v6_proves_the_routine_name_is_free() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE FUNCTION work() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;",
                &mut state,
            )
            .unwrap();

        assert_eq!(state.local.confidence, Confidence::Exact);
        assert!(matches!(
            state.local.functions.get(&object_id("public", "work()")),
            Some(FunctionOverlay::Present(function))
                if function.routine_kind
                    == RoutineKind::Function
        ));
    }

    #[test]
    fn cached_aggregate_and_window_routines_reserve_the_shared_namespace() {
        let engine = setup_engine();

        for routine_kind in [RoutineKind::Aggregate, RoutineKind::Window] {
            let mut cache = DbCache::new();
            let id = object_id("public", "work(integer)");
            cache.functions.insert(
                id.clone(),
                FunctionState {
                    id,
                    routine_kind,
                    arg_types: vec!["integer".into()],
                    arg_type_ids: Vec::new(),
                    return_type: "integer".into(),
                    return_type_id: None,
                    volatility: Volatility::Immutable,
                    language: "internal".into(),
                    security: SecurityMode::Invoker,
                },
            );
            let mut state = safe_migrate::AnalysisState::new(cache);

            for sql in [
                "CREATE FUNCTION work(integer) RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;",
                "CREATE PROCEDURE work(integer) LANGUAGE sql AS $$ SELECT 1 $$;",
            ] {
                let violations = engine.analyze(sql, &mut state).unwrap();
                assert!(violations.iter().any(|violation| {
                    violation.rule_id == "chain-conflict"
                        && violation.reason.contains("already exists")
                }));
                assert_eq!(state.local.confidence, Confidence::Exact);
            }
        }
    }

    #[test]
    fn aggregate_and_window_lifecycles_use_the_shared_routine_state() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE AGGREGATE total(integer) (
                    SFUNC = int4pl,
                    STYPE = integer,
                    INITCOND = '0'
                );
                ALTER AGGREGATE total(integer) RENAME TO combined;
                DROP AGGREGATE combined(integer);",
                &mut state,
            )
            .unwrap();
        assert!(matches!(
            state
                .local
                .functions
                .get(&object_id("public", "combined(integer)")),
            Some(FunctionOverlay::Dropped)
        ));
        assert_eq!(state.local.confidence, Confidence::Exact);

        engine
            .analyze(
                "CREATE FUNCTION ranked() RETURNS bigint
                   AS 'window_row_number' LANGUAGE internal WINDOW;
                 ALTER FUNCTION ranked() IMMUTABLE;",
                &mut state,
            )
            .unwrap();
        assert!(matches!(
            state.local.functions.get(&object_id("public", "ranked()")),
            Some(FunctionOverlay::Present(function))
                if function.routine_kind == RoutineKind::Window
                    && function.volatility == Volatility::Immutable
        ));
        engine
            .analyze("DROP FUNCTION ranked();", &mut state)
            .unwrap();
        assert!(matches!(
            state.local.functions.get(&object_id("public", "ranked()")),
            Some(FunctionOverlay::Dropped)
        ));
    }

    #[test]
    fn replacing_a_routine_cannot_change_function_window_or_aggregate_kind() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE FUNCTION work(integer) RETURNS integer
                   LANGUAGE sql AS $$ SELECT $1 $$;",
                &mut state,
            )
            .unwrap();

        let window_conflict = engine
            .analyze(
                "CREATE OR REPLACE FUNCTION work(integer) RETURNS integer
                   LANGUAGE sql WINDOW AS $$ SELECT $1 $$;",
                &mut state,
            )
            .unwrap();
        assert!(window_conflict.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("already exists")
        }));

        let aggregate_conflict = engine
            .analyze(
                "CREATE OR REPLACE AGGREGATE work(integer) (
                    SFUNC = int4pl,
                    STYPE = integer
                );",
                &mut state,
            )
            .unwrap();
        assert!(aggregate_conflict.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("already exists")
        }));
    }

    #[test]
    fn cached_aggregate_and_window_routines_accept_their_postgresql_commands() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        for (name, routine_kind) in [
            ("total(integer)", RoutineKind::Aggregate),
            ("ranked()", RoutineKind::Window),
        ] {
            let id = object_id("public", name);
            cache.functions.insert(
                id.clone(),
                FunctionState {
                    id,
                    routine_kind,
                    arg_types: if routine_kind == RoutineKind::Aggregate {
                        vec!["integer".into()]
                    } else {
                        Vec::new()
                    },
                    arg_type_ids: Vec::new(),
                    return_type: "integer".into(),
                    return_type_id: None,
                    volatility: Volatility::Volatile,
                    language: "internal".into(),
                    security: SecurityMode::Invoker,
                },
            );
        }
        let mut state = safe_migrate::AnalysisState::new(cache);

        engine
            .analyze(
                "ALTER AGGREGATE total(integer) RENAME TO combined;
                 ALTER FUNCTION ranked() IMMUTABLE;
                 DROP AGGREGATE combined(integer);
                 DROP FUNCTION ranked();",
                &mut state,
            )
            .unwrap();

        assert_eq!(state.local.confidence, Confidence::Exact);
        assert!(matches!(
            state
                .local
                .functions
                .get(&object_id("public", "combined(integer)")),
            Some(FunctionOverlay::Dropped)
        ));
        assert!(matches!(
            state.local.functions.get(&object_id("public", "ranked()")),
            Some(FunctionOverlay::Dropped)
        ));
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
    fn guarded_routine_drop_still_rejects_the_wrong_routine_kind() {
        let engine = setup_engine();
        let routine_id = object_id("public", "work(integer)");

        for (routine_kind, sql) in [
            (
                safe_migrate::model::function::RoutineKind::Function,
                "DROP PROCEDURE IF EXISTS work(int);",
            ),
            (
                safe_migrate::model::function::RoutineKind::Procedure,
                "DROP FUNCTION IF EXISTS work(int);",
            ),
        ] {
            let mut cache = safe_migrate::db::cache::DbCache::new();
            cache.functions.insert(
                routine_id.clone(),
                FunctionState {
                    id: routine_id.clone(),
                    routine_kind,
                    arg_types: vec!["integer".into()],
                    arg_type_ids: Vec::new(),
                    return_type: "void".into(),
                    return_type_id: None,
                    volatility: Volatility::Volatile,
                    language: "sql".into(),
                    security: SecurityMode::Invoker,
                },
            );
            let mut state = safe_migrate::AnalysisState::new(cache);
            let violations = engine.analyze(sql, &mut state).unwrap();

            assert!(
                violations
                    .iter()
                    .any(|violation| violation.rule_id == "chain-conflict"),
                "{sql} should reject the wrong routine kind"
            );
        }
    }

    #[test]
    fn procedure_kind_and_lifecycle_are_enforced_within_the_chain() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE PROCEDURE work() LANGUAGE sql AS $$ SELECT 1 $$;",
                &mut state,
            )
            .unwrap();
        let id = object_id("public", "work()");
        let Some(FunctionOverlay::Present(routine)) = state.local.functions.get(&id) else {
            panic!("procedure missing");
        };
        assert_eq!(
            routine.routine_kind,
            safe_migrate::model::function::RoutineKind::Procedure
        );

        let wrong_kind = engine
            .analyze("ALTER FUNCTION work() IMMUTABLE;", &mut state)
            .unwrap();
        assert!(
            wrong_kind
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );

        engine
            .analyze("DROP PROCEDURE work();", &mut state)
            .unwrap();
        let after_drop = engine
            .analyze("ALTER PROCEDURE work() RENAME TO renamed_work;", &mut state)
            .unwrap();
        assert!(
            after_drop
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
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
    fn exact_v6_baseline_rejects_an_alter_of_a_missing_publication() {
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

        let mut scoped_cache = DbCache::new();
        scoped_cache.metadata.schemas = Some(vec!["public".into()]);
        let mut scoped_state = safe_migrate::AnalysisState::new(scoped_cache);
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
            Some(safe_migrate::model::replication::PublicationOverlay::Present(_))
        ));
    }

    #[test]
    fn cached_publication_and_subscription_actions_update_exact_state() {
        let engine = setup_engine();
        let mut cache = cache_with_table("public", "first", None);
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
            safe_migrate::model::replication::PublicationState {
                name: "changes".into(),
                owner: Some("postgres".into()),
                scope: safe_migrate::analysis::facts::PublicationScope::Explicit(vec![
                    safe_migrate::analysis::facts::PublicationObjectFact::Table {
                        name: safe_migrate::ast::identifiers::QualifiedName::new(
                            Some(safe_migrate::ast::identifiers::Ident::new("public", true)),
                            safe_migrate::ast::identifiers::Ident::new("first", true),
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
            safe_migrate::model::replication::SubscriptionState {
                name: "subscriber".into(),
                owner: Some("postgres".into()),
                connection: safe_migrate::analysis::facts::ConnectionTarget::Redacted,
                publications: vec!["changes".into()],
                params: Some(Vec::new()),
                enabled: false,
                slot_name: None,
                generation: 0,
            },
        );
        let mut state = safe_migrate::AnalysisState::new(cache);

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
        let Some(safe_migrate::model::replication::PublicationOverlay::Present(publication)) =
            state.local.publications.get("renamed_changes")
        else {
            panic!("renamed publication missing");
        };
        let safe_migrate::analysis::facts::PublicationScope::Explicit(objects) = &publication.scope
        else {
            panic!("expected explicit publication scope");
        };
        assert_eq!(objects.len(), 2);
        assert!(state.local.graph.edges.iter().any(|edge| {
            matches!(
                &edge.kind,
                DependencyKind::PublicationIncludes { publication_name }
                    if publication_name == "renamed_changes"
            ) && edge.dependent == object_id("public", "second")
        }));

        let Some(safe_migrate::model::replication::SubscriptionOverlay::Present(subscription)) =
            state.local.subscriptions.get("renamed_subscriber")
        else {
            panic!("renamed subscription missing");
        };
        assert_eq!(subscription.publications, ["renamed_changes"]);
        assert!(subscription.params.as_ref().is_some_and(|params| {
            params
                .iter()
                .any(|param| param.name == "streaming" && param.value == "parallel")
        }));

        engine.analyze("DROP TABLE second;", &mut state).unwrap();
        let Some(safe_migrate::model::replication::PublicationOverlay::Present(publication)) =
            state.local.publications.get("renamed_changes")
        else {
            panic!("publication missing after table drop");
        };
        let safe_migrate::analysis::facts::PublicationScope::Explicit(objects) = &publication.scope
        else {
            panic!("expected explicit publication scope");
        };
        assert_eq!(objects.len(), 1);
    }

    #[test]
    fn subscription_publication_conflicts_do_not_partially_mutate_direct_state() {
        let mut cache = DbCache::new();
        cache.subscriptions.insert(
            "subscriber".into(),
            safe_migrate::model::replication::SubscriptionState {
                name: "subscriber".into(),
                owner: Some("postgres".into()),
                connection: safe_migrate::analysis::facts::ConnectionTarget::Redacted,
                publications: vec!["existing".into()],
                params: Some(Vec::new()),
                enabled: false,
                slot_name: None,
                generation: 0,
            },
        );
        let mut state = safe_migrate::AnalysisState::new(cache);
        let initial_generation = state.local.generation_counter;

        for (mode, publications) in [
            (
                safe_migrate::analysis::facts::SubscriptionPublicationMode::Add,
                vec!["new".to_string(), "existing".to_string()],
            ),
            (
                safe_migrate::analysis::facts::SubscriptionPublicationMode::Drop,
                vec!["existing".to_string(), "missing".to_string()],
            ),
        ] {
            let mutation = safe_migrate::analysis::mutations::Mutation::AlterSubscription(
                safe_migrate::analysis::mutations::AlterSubscriptionMutation {
                    name: "subscriber".into(),
                    action:
                        safe_migrate::analysis::facts::AlterSubscriptionActionFact::Publications {
                            mode,
                            publications,
                            params: Vec::new(),
                        },
                },
            );
            assert!(matches!(
                state.apply(&mutation, None),
                safe_migrate::analysis::state::MutationResult::Conflict { .. }
            ));
            let Some(safe_migrate::model::replication::SubscriptionOverlay::Present(subscription)) =
                state.local.subscriptions.get("subscriber")
            else {
                panic!("subscription missing");
            };
            assert_eq!(subscription.publications, ["existing"]);
            assert_eq!(subscription.generation, 0);
            assert_eq!(state.local.generation_counter, initial_generation);
        }
    }

    #[test]
    fn table_drop_resolves_unqualified_publication_membership_through_search_path() {
        let engine = setup_engine();
        let mut cache = cache_with_table("tenant", "entries", None);
        cache.search_path = vec!["tenant".into()];
        cache.publications.insert(
            "changes".into(),
            safe_migrate::model::replication::PublicationState {
                name: "changes".into(),
                owner: Some("postgres".into()),
                scope: safe_migrate::analysis::facts::PublicationScope::Explicit(vec![
                    safe_migrate::analysis::facts::PublicationObjectFact::Table {
                        name: safe_migrate::ast::identifiers::QualifiedName::new(
                            None,
                            safe_migrate::ast::identifiers::Ident::new("entries", true),
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
        let mut state = safe_migrate::AnalysisState::new(cache);

        engine.analyze("DROP TABLE entries;", &mut state).unwrap();

        let Some(safe_migrate::model::replication::PublicationOverlay::Present(publication)) =
            state.local.publications.get("changes")
        else {
            panic!("publication missing");
        };
        assert!(matches!(
            &publication.scope,
            safe_migrate::analysis::facts::PublicationScope::Explicit(objects)
                if objects.is_empty()
        ));
    }

    #[test]
    fn cached_publication_parent_edits_are_tainted_without_inheritance_catalogs() {
        let engine = setup_engine();
        let mut cache = cache_with_table("public", "parent", None);
        cache.publications.insert(
            "changes".into(),
            safe_migrate::model::replication::PublicationState {
                name: "changes".into(),
                owner: Some("postgres".into()),
                scope: safe_migrate::analysis::facts::PublicationScope::Explicit(vec![
                    safe_migrate::analysis::facts::PublicationObjectFact::Table {
                        name: safe_migrate::ast::identifiers::QualifiedName::new(
                            Some(safe_migrate::ast::identifiers::Ident::new("public", true)),
                            safe_migrate::ast::identifiers::Ident::new("parent", true),
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

        let mut inherited_state = safe_migrate::AnalysisState::new(cache.clone());
        engine
            .analyze(
                "ALTER PUBLICATION changes DROP TABLE parent;",
                &mut inherited_state,
            )
            .unwrap();
        assert_eq!(inherited_state.local.confidence, Confidence::Tainted);

        let mut only_state = safe_migrate::AnalysisState::new(cache);
        engine
            .analyze(
                "ALTER PUBLICATION changes DROP TABLE ONLY parent;",
                &mut only_state,
            )
            .unwrap();
        assert_eq!(only_state.local.confidence, Confidence::Exact);
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
        let Some(safe_migrate::model::replication::SubscriptionOverlay::Present(subscription)) =
            state.local.subscriptions.get("deferred")
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
            Some(safe_migrate::model::replication::SubscriptionOverlay::Present(_))
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
            Some(safe_migrate::model::replication::SubscriptionOverlay::Dropped)
        ));
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
                Some(safe_migrate::model::replication::SubscriptionOverlay::Present(_))
            ));
        }

        let mut boolean_state = setup_state();
        let violations = engine
            .analyze(
                "CREATE SUBSCRIPTION boolean_options
                   CONNECTION 'host=publisher.invalid'
                   PUBLICATION p
                   WITH (connect=of, enabled=fals, create_slot=fa, copy_data=f, binary=tru, slot_name=NONE);
                 BEGIN;
                 ALTER SUBSCRIPTION boolean_options SET PUBLICATION p2 WITH (refresh=of);
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
            Some(safe_migrate::model::replication::SubscriptionOverlay::Present(
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
            violation.rule_id == "chain-conflict"
                && violation.reason.contains("without a slot_name")
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
                routine_kind: safe_migrate::model::function::RoutineKind::Function,
                arg_types: vec!["integer[]".to_string()],
                arg_type_ids: vec![None],
                return_type: "integer".to_string(),
                return_type_id: None,
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
    fn create_table_preserves_explicit_constraint_names_and_avoids_generated_collisions() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE accounts (
                    id integer CONSTRAINT accounts_primary PRIMARY KEY,
                    email text CONSTRAINT accounts_email_unique UNIQUE,
                    a_b integer,
                    c integer,
                    a integer,
                    b_c integer,
                    UNIQUE (a_b, c),
                    UNIQUE (a, b_c)
                );",
                &mut state,
            )
            .unwrap();

        let table = object_id("public", "accounts");
        for (name, kind) in [
            ("accounts_primary", ConstraintKind::PrimaryKey),
            ("accounts_email_unique", ConstraintKind::Unique),
            ("accounts_a_b_c_key", ConstraintKind::Unique),
            ("accounts_a_b_c_key1", ConstraintKind::Unique),
        ] {
            assert_eq!(
                state
                    .local
                    .constraints
                    .get(&(table.clone(), name.to_string()))
                    .map(|constraint| constraint.kind),
                Some(kind),
                "missing constraint {name}"
            );
        }
    }

    #[test]
    fn generated_constraint_names_follow_postgres_identifier_length_limit() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx (
                    abcdefghijklmnopqrstuvwxyzabcd integer UNIQUE
                );",
                &mut state,
            )
            .unwrap();

        let table = object_id(
            "public",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx",
        );
        let expected =
            "abcdefghijklmnopqrstuvwxyzabc_abcdefghijklmnopqrstuvwxyzabc_key".to_string();
        assert_eq!(expected.len(), 63);
        assert!(state.local.constraints.contains_key(&(table, expected)));
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
    fn using_index_resolves_in_the_altered_tables_schema_and_preserves_quoting() {
        let engine = setup_engine();
        let mut state = setup_state();
        let violations = engine
            .analyze(
                "CREATE SCHEMA tenant;
                 SET search_path TO public;
                 CREATE TABLE tenant.users (email text);
                 CREATE UNIQUE INDEX \"UserEmailKey\" ON tenant.users(email);
                 ALTER TABLE tenant.users ADD CONSTRAINT users_email_key
                    UNIQUE USING INDEX \"UserEmailKey\";",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        assert!(
            state
                .local
                .constraints
                .contains_key(&(object_id("tenant", "users"), "users_email_key".to_string()))
        );
    }

    #[test]
    fn using_index_rejects_wrong_table_non_unique_and_partial_indexes() {
        for (index_sql, expected_reason) in [
            (
                "CREATE UNIQUE INDEX candidate ON other(id);",
                "belongs to relation",
            ),
            (
                "CREATE INDEX candidate ON target(id);",
                "unique and non-partial",
            ),
            (
                "CREATE UNIQUE INDEX candidate ON target(id) WHERE id > 0;",
                "unique and non-partial",
            ),
        ] {
            let engine = setup_engine();
            let mut state = setup_state();
            let sql = format!(
                "CREATE TABLE target(id integer); CREATE TABLE other(id integer); {index_sql}
                 ALTER TABLE target ADD CONSTRAINT target_id_key UNIQUE USING INDEX candidate;"
            );
            let violations = engine.analyze(&sql, &mut state).unwrap();

            assert!(violations.iter().any(|violation| {
                violation.rule_id == "chain-conflict" && violation.reason.contains(expected_reason)
            }));
            assert!(
                !state
                    .local
                    .constraints
                    .contains_key(&(object_id("public", "target"), "target_id_key".to_string()))
            );
        }
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
            type_id: None,
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

    #[test]
    fn set_role_updates_current_role_and_owner_assignments() {
        let engine = setup_engine();
        let mut state = setup_state();
        assert_eq!(state.local.current_role, "postgres");
        assert!(!state.local.current_role_known); // default mock state

        engine
            .analyze(
                "SET ROLE app_admin;
                 CREATE TABLE admin_log(id int);",
                &mut state,
            )
            .unwrap();

        assert_eq!(state.local.current_role, "app_admin");
        assert!(state.local.current_role_known);
        // session_role should not have changed
        assert_eq!(state.local.session_role, "postgres");
        assert!(!state.local.session_role_known);

        // The table should be owned by app_admin
        let rel = state
            .get_relation(&object_id("public", "admin_log"))
            .unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert_eq!(r.owner, object_id("", "app_admin"));
        } else {
            panic!("Expected admin_log to be present");
        }
    }

    #[test]
    fn set_session_authorization_updates_session_role_and_allows_reset() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some("app_user".to_string());
        cache.metadata.source_session_role = Some("app_user".to_string());
        for (name, superuser) in [
            ("app_user", true),
            ("new_owner", false),
            ("temp_role", false),
        ] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: true,
                    is_superuser: superuser,
                    member_of: Vec::new(),
                    can_set_role_to: Vec::new(),
                    granted_privileges: Vec::new(),
                },
            );
        }
        let mut state = safe_migrate::AnalysisState::new(cache);

        assert_eq!(state.local.current_role, "app_user");
        assert_eq!(state.local.session_role, "app_user");

        engine
            .analyze(
                "SET SESSION AUTHORIZATION new_owner;
                 SET ROLE NONE;
                 SET SESSION AUTHORIZATION DEFAULT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(state.local.current_role, "app_user");
        assert_eq!(state.local.session_role, "app_user");
        assert_eq!(state.local.authenticated_role, "app_user");
    }

    #[test]
    fn set_role_is_rolled_back_on_abort() {
        let engine = setup_engine();
        let mut state = setup_state();

        state.local.current_role = "start_role".to_string();
        state.local.current_role_known = true;

        engine
            .analyze(
                "BEGIN;
                 SET ROLE temp_admin;
                 CREATE TABLE inside_txn(id int);
                 ROLLBACK;
                 CREATE TABLE outside_txn(id int);",
                &mut state,
            )
            .unwrap();

        // Outside the transaction, the role should be restored
        assert_eq!(state.local.current_role, "start_role");

        // Table inside txn was rolled back, so it shouldn't exist
        assert!(
            state
                .get_relation(&object_id("public", "inside_txn"))
                .is_none()
        );

        // Table outside txn was created by start_role
        if let RelationOverlay::Present(r) = state
            .get_relation(&object_id("public", "outside_txn"))
            .unwrap()
        {
            assert_eq!(r.owner, object_id("", "start_role"));
        } else {
            panic!("missing outside_txn");
        }
    }

    #[test]
    fn local_role_expires_on_commit_while_session_role_setting_persists() {
        let engine = setup_engine();
        let mut state = setup_state();
        state.local.current_role = "login_role".into();
        state.local.current_role_known = true;
        state.local.persistent_current_role = "login_role".into();
        state.local.persistent_current_role_known = true;
        state.local.session_role = "login_role".into();
        state.local.session_role_known = true;

        engine
            .analyze(
                "BEGIN;
                 SET LOCAL ROLE local_role;
                 CREATE TABLE local_owned(id int);
                 COMMIT;
                 CREATE TABLE login_owned(id int);
                 BEGIN;
                 SET ROLE persistent_role;
                 COMMIT;
                 CREATE TABLE persistent_owned(id int);",
                &mut state,
            )
            .unwrap();

        let owner = |table: &str| match state
            .get_relation(&object_id("public", table))
            .expect("table")
        {
            RelationOverlay::Present(relation) => relation.owner.name.clone(),
            RelationOverlay::Dropped => panic!("table dropped"),
        };
        assert_eq!(owner("local_owned"), "local_role");
        assert_eq!(owner("login_owned"), "login_role");
        assert_eq!(owner("persistent_owned"), "persistent_role");
    }

    #[test]
    fn local_role_outside_transaction_has_no_effect() {
        let engine = setup_engine();
        let mut state = setup_state();
        state.local.current_role = "login_role".into();
        state.local.current_role_known = true;
        state.local.persistent_current_role = "login_role".into();
        state.local.persistent_current_role_known = true;

        engine
            .analyze(
                "SET LOCAL ROLE ignored_role;
                 CREATE TABLE still_login_owned(id int);",
                &mut state,
            )
            .unwrap();

        let RelationOverlay::Present(relation) = state
            .get_relation(&object_id("public", "still_login_owned"))
            .unwrap()
        else {
            panic!("table missing");
        };
        assert_eq!(relation.owner, object_id("", "login_role"));
    }

    #[test]
    fn session_authorization_local_and_rollback_restore_all_identity_fields() {
        let engine = setup_engine();
        let mut state = setup_state();
        for field in [
            &mut state.local.current_role,
            &mut state.local.persistent_current_role,
            &mut state.local.session_role,
            &mut state.local.persistent_session_role,
            &mut state.local.authenticated_role,
        ] {
            *field = "login_role".into();
        }
        state.local.current_role_known = true;
        state.local.persistent_current_role_known = true;
        state.local.session_role_known = true;
        state.local.persistent_session_role_known = true;
        state.local.authenticated_role_known = true;

        engine
            .analyze(
                "BEGIN;
                 SET LOCAL SESSION AUTHORIZATION local_auth;
                 CREATE TABLE local_auth_owned(id int);
                 COMMIT;
                 CREATE TABLE login_auth_owned(id int);
                 BEGIN;
                 SET SESSION AUTHORIZATION rolled_back_auth;
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();

        assert_eq!(state.local.current_role, "login_role");
        assert_eq!(state.local.session_role, "login_role");
        assert_eq!(state.local.persistent_current_role, "login_role");
        assert_eq!(state.local.persistent_session_role, "login_role");
        assert!(state.local.current_role_known);
        assert!(state.local.session_role_known);
    }

    #[test]
    fn role_none_during_local_session_authorization_restores_persistent_session_on_commit() {
        let engine = setup_engine();
        let mut state = setup_state();
        for field in [
            &mut state.local.current_role,
            &mut state.local.persistent_current_role,
            &mut state.local.session_role,
            &mut state.local.persistent_session_role,
            &mut state.local.authenticated_role,
        ] {
            *field = "login_role".into();
        }
        state.local.current_role_known = true;
        state.local.persistent_current_role_known = true;
        state.local.session_role_known = true;
        state.local.persistent_session_role_known = true;
        state.local.authenticated_role_known = true;

        engine
            .analyze(
                "BEGIN;
                 SET LOCAL SESSION AUTHORIZATION local_auth;
                 SET ROLE NONE;
                 COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(state.local.current_role, "login_role");
        assert_eq!(state.local.session_role, "login_role");
    }

    #[test]
    fn role_switch_recomputes_user_search_path_and_owner_keywords() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some("login_role".into());
        cache.metadata.source_session_role = Some("login_role".into());
        cache.metadata.source_search_path = Some(vec!["$user".into(), "public".into()]);
        cache.search_path = vec!["login_role".into(), "public".into()];
        for (name, superuser) in [("login_role", true), ("app_role", false)] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: true,
                    is_superuser: superuser,
                    member_of: Vec::new(),
                    can_set_role_to: Vec::new(),
                    granted_privileges: Vec::new(),
                },
            );
        }
        let table = object_id("public", "owned_table");
        cache.insert_baseline(
            table.clone(),
            RelationState::new(
                table.clone(),
                object_id("", "login_role"),
                0,
                Some(0),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        let mut state = safe_migrate::AnalysisState::new(cache);

        engine
            .analyze(
                "SET ROLE app_role;
                 ALTER TABLE public.owned_table OWNER TO SESSION_USER;",
                &mut state,
            )
            .unwrap();

        assert_eq!(state.local.search_path, ["public"]);
        let RelationOverlay::Present(relation) = state.get_relation(&table).unwrap() else {
            panic!("table missing");
        };
        assert_eq!(relation.owner, object_id("", "login_role"));
    }

    #[test]
    fn alter_view_owner_updates_relation_metadata() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
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
        let mut state = safe_migrate::AnalysisState::new(cache);

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

    #[test]
    fn complete_role_catalog_rejects_missing_role_switch() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some("login_role".into());
        cache.metadata.source_session_role = Some("login_role".into());
        let login = object_id("", "login_role");
        cache.roles.insert(
            login.clone(),
            RoleState {
                id: login,
                can_login: true,
                is_superuser: false,
                member_of: Vec::new(),
                can_set_role_to: Vec::new(),
                granted_privileges: Vec::new(),
            },
        );
        let mut state = safe_migrate::AnalysisState::new(cache);

        let violations = engine
            .analyze("SET ROLE role_that_does_not_exist;", &mut state)
            .unwrap();
        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        assert_eq!(state.local.current_role, "login_role");
    }

    #[test]
    fn set_role_follows_transitive_set_option_edges() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some("member".into());
        cache.metadata.source_session_role = Some("member".into());
        for (name, can_set_role_to) in [
            ("member", vec![object_id("", "bridge")]),
            ("bridge", vec![object_id("", "target")]),
            ("target", Vec::new()),
        ] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: name == "member",
                    is_superuser: false,
                    member_of: can_set_role_to.clone(),
                    can_set_role_to,
                    granted_privileges: Vec::new(),
                },
            );
        }
        let mut state = safe_migrate::AnalysisState::new(cache);

        let violations = engine
            .analyze(
                "SET ROLE target; CREATE TABLE transitively_owned(id integer);",
                &mut state,
            )
            .unwrap();

        assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
        let RelationOverlay::Present(relation) = state
            .get_relation(&object_id("public", "transitively_owned"))
            .unwrap()
        else {
            panic!("table missing");
        };
        assert_eq!(relation.owner, object_id("", "target"));
    }

    #[test]
    fn membership_without_set_option_does_not_authorize_set_role() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some("member".into());
        cache.metadata.source_session_role = Some("member".into());
        for (name, member_of) in [
            ("member", vec![object_id("", "target")]),
            ("target", Vec::new()),
        ] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: name == "member",
                    is_superuser: false,
                    member_of,
                    can_set_role_to: Vec::new(),
                    granted_privileges: Vec::new(),
                },
            );
        }
        let mut state = safe_migrate::AnalysisState::new(cache);

        let violations = engine.analyze("SET ROLE target;", &mut state).unwrap();

        assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
        assert_eq!(state.local.current_role, "member");
    }
}
