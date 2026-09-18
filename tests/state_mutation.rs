mod state_mutation_tests {
    use crate::common::*;
    use safe_migrate::_internal::analysis::evidence::EvidenceCode;
    use safe_migrate::_internal::analysis::facts::FunctionSigFact;
    use safe_migrate::_internal::analysis::graph::{
        DependencyEdge, DependencyGraph, DependencyKind,
    };
    use safe_migrate::_internal::analysis::mutations::{
        DropAggregateMutation, DropFunctionMutation, DropProcedureMutation, Mutation,
    };
    use safe_migrate::_internal::analysis::state::{Confidence, MutationResult};
    use safe_migrate::_internal::ast::identifiers::{Ident, ObjectId, QualifiedName};
    use safe_migrate::_internal::db::cache::{
        CatalogFamily, ConstraintDependencyCache, DbCache, GeneratedColumnDependencyCache,
        ViewDependencyCache,
    };
    use safe_migrate::_internal::model::column::Column;
    use safe_migrate::_internal::model::constraint::ConstraintKind;
    use safe_migrate::_internal::model::function::{
        FunctionOverlay, FunctionState, RoutineKind, SecurityMode, Volatility,
    };
    use safe_migrate::_internal::model::relation::{
        ColumnAction, Persistence, Privilege, RelationKind, RelationOverlay, RelationState,
    };
    use safe_migrate::_internal::model::role::{RoleOverlay, RoleState};
    use safe_migrate::_internal::model::schema::SchemaState;
    use safe_migrate::_internal::model::sequence::{SequenceKind, SequenceOverlay, SequenceState};
    use safe_migrate::_internal::model::types::{TypeKind, TypeOverlay, TypeState};

    #[test]
    fn key_index_renames_preserve_constraint_and_table_metadata() {
        let engine = setup_engine();
        for rename in [
            "ALTER TABLE rename_keys RENAME CONSTRAINT original_key TO renamed_key;",
            "ALTER INDEX original_key RENAME TO renamed_key;",
        ] {
            let mut state = setup_state();
            engine.analyze("CREATE TABLE rename_keys(id integer NOT NULL); ALTER TABLE rename_keys ADD CONSTRAINT original_key UNIQUE(id); ALTER TABLE rename_keys CLUSTER ON original_key; ALTER TABLE rename_keys REPLICA IDENTITY USING INDEX original_key;", &mut state).unwrap();
            let before_constraints = state.local.constraints.clone();
            let before_relations = state.local.relations.clone();
            let before_edges = state.local.graph.edges().to_vec();
            let findings = engine
                .analyze(&format!("BEGIN; {rename}"), &mut state)
                .unwrap();
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict"),
                "{findings:?}"
            );
            let table = object_id("public", "rename_keys");
            assert!(
                !state
                    .local
                    .constraints
                    .contains_key(&(table.clone(), "original_key".into()))
            );
            assert_eq!(
                state.local.constraints[&(table.clone(), "renamed_key".into())].backing_index,
                Some(object_id("public", "renamed_key"))
            );
            let RelationOverlay::Present(relation) = &state.local.relations[&table] else {
                panic!("missing table")
            };
            assert_eq!(relation.cluster_index.as_deref(), Some("renamed_key"));
            assert_eq!(
                relation.replica_identity.as_deref(),
                Some("USING INDEX renamed_key")
            );
            engine.analyze("ROLLBACK;", &mut state).unwrap();
            assert_eq!(state.local.constraints, before_constraints);
            assert_eq!(state.local.relations, before_relations);
            assert_eq!(state.local.graph.edges(), before_edges.as_slice());
            engine.analyze(rename, &mut state).unwrap();
            let findings = engine
                .analyze(
                    "ALTER TABLE rename_keys DROP CONSTRAINT renamed_key;",
                    &mut state,
                )
                .unwrap();
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict"),
                "{findings:?}"
            );
            assert!(
                !state
                    .local
                    .graph
                    .edges()
                    .iter()
                    .any(|edge| edge.referenced == table
                        && matches!(edge.kind, DependencyKind::IndexOnRelation { .. }))
            );
            let RelationOverlay::Present(relation) = &state.local.relations[&table] else {
                panic!("missing table")
            };
            assert_eq!(relation.cluster_index, None);
            assert_eq!(relation.replica_identity.as_deref(), Some("USING INDEX"));
        }
    }

    #[test]
    fn key_index_rename_rejects_constraint_name_collision_without_changes() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE rename_keys(id integer NOT NULL, CONSTRAINT occupied CHECK(id > 0)); ALTER TABLE rename_keys ADD CONSTRAINT original_key UNIQUE(id);", &mut state).unwrap();
        let before_constraints = state.local.constraints.clone();
        let before_edges = state.local.graph.edges().to_vec();
        let findings = engine
            .analyze("ALTER INDEX original_key RENAME TO occupied;", &mut state)
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "{findings:?}"
        );
        assert_eq!(state.local.constraints, before_constraints);
        assert_eq!(state.local.graph.edges(), before_edges.as_slice());
    }

    #[test]
    fn dropping_foreign_key_keeps_its_referenced_index() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE referenced_key(id integer); ALTER TABLE referenced_key ADD CONSTRAINT referenced_unique UNIQUE(id); CREATE TABLE referencing_key(id integer); ALTER TABLE referencing_key ADD CONSTRAINT referencing_fk FOREIGN KEY(id) REFERENCES referenced_key(id);", &mut state).unwrap();
        let parent = object_id("public", "referenced_key");
        let index = state
            .local
            .constraints
            .values()
            .find(|constraint| {
                constraint.table_id == parent && constraint.kind == ConstraintKind::Unique
            })
            .unwrap()
            .backing_index
            .clone()
            .unwrap();
        state
            .local
            .constraints
            .get_mut(&(
                object_id("public", "referencing_key"),
                "referencing_fk".into(),
            ))
            .unwrap()
            .backing_index = Some(index.clone());
        engine
            .analyze(
                "ALTER TABLE referencing_key DROP CONSTRAINT referencing_fk;",
                &mut state,
            )
            .unwrap();
        assert!(
            state
                .local
                .graph
                .edges()
                .iter()
                .any(|edge| edge.dependent == index
                    && matches!(edge.kind, DependencyKind::IndexOnRelation { .. }))
        );
    }

    #[test]
    fn dropping_identity_index_settings_is_transactional() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE index_settings(id integer NOT NULL); CREATE UNIQUE INDEX identity_idx ON index_settings(id); ALTER TABLE index_settings CLUSTER ON identity_idx; ALTER TABLE index_settings REPLICA IDENTITY USING INDEX identity_idx;", &mut state).unwrap();
        let before = state.local.relations.clone();
        engine
            .analyze("BEGIN; DROP INDEX identity_idx;", &mut state)
            .unwrap();
        let RelationOverlay::Present(table) =
            &state.local.relations[&object_id("public", "index_settings")]
        else {
            panic!("missing table")
        };
        assert_eq!(table.cluster_index, None);
        assert_eq!(table.replica_identity.as_deref(), Some("USING INDEX"));
        engine.analyze("ROLLBACK;", &mut state).unwrap();
        assert_eq!(state.local.relations, before);
    }

    #[test]
    fn dropping_qualified_quoted_index_clears_index_settings() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE quoted_index_settings(id integer NOT NULL); CREATE UNIQUE INDEX \"IdentityIndex\" ON quoted_index_settings(id); ALTER TABLE quoted_index_settings CLUSTER ON \"IdentityIndex\"; ALTER TABLE quoted_index_settings REPLICA IDENTITY USING INDEX \"IdentityIndex\"; DROP INDEX public.\"IdentityIndex\";", &mut state).unwrap();
        let table = object_id("public", "quoted_index_settings");
        assert!(!state.index_is_present(&object_id("public", "IdentityIndex")));
        let RelationOverlay::Present(relation) = &state.local.relations[&table] else {
            panic!("missing table")
        };
        assert_eq!(relation.cluster_index, None);
        assert_eq!(relation.replica_identity.as_deref(), Some("USING INDEX"));
    }

    #[test]
    fn renamed_check_dependencies_follow_rollback_and_drop() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE check_rename(id integer, CONSTRAINT old_check CHECK (id > 0));",
                &mut state,
            )
            .unwrap();
        let table = object_id("public", "check_rename");
        let edges_before = state.local.graph.edges().to_vec();
        engine.analyze("BEGIN; ALTER TABLE check_rename RENAME CONSTRAINT old_check TO new_check; ROLLBACK;", &mut state).unwrap();
        assert_eq!(state.local.graph.edges(), edges_before.as_slice());
        assert!(
            state
                .local
                .constraints
                .contains_key(&(table.clone(), "old_check".into()))
        );
        engine
            .analyze(
                "ALTER TABLE check_rename RENAME CONSTRAINT old_check TO new_check;",
                &mut state,
            )
            .unwrap();
        assert!(state.local.graph.edges().iter().any(|edge| edge.dependent == table && matches!(&edge.kind, DependencyKind::ConstraintDependency { constraint_name, .. } if constraint_name == "new_check")));
        let findings = engine.analyze("ALTER TABLE check_rename DROP CONSTRAINT new_check; ALTER TABLE check_rename DROP COLUMN id;", &mut state).unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "{findings:?}"
        );
        assert!(
            !state
                .local
                .graph
                .edges()
                .iter()
                .any(|edge| edge.dependent == table
                    && matches!(
                        edge.kind,
                        DependencyKind::ConstraintDependency { .. }
                            | DependencyKind::ConstraintOnRelation { .. }
                    ))
        );
    }

    #[test]
    fn altered_key_constraints_own_indexes_and_rollback_restores_them() {
        let engine = setup_engine();
        for kind in ["UNIQUE", "PRIMARY KEY"] {
            let mut state = setup_state();
            engine.analyze(&format!("CREATE TABLE key_owner(id int); ALTER TABLE key_owner ADD CONSTRAINT key_owner_key {kind} (id);"), &mut state).unwrap();
            let table = object_id("public", "key_owner");
            let index = object_id("public", "key_owner_key");
            assert_eq!(
                state.local.constraints[&(table.clone(), "key_owner_key".into())].backing_index,
                Some(index.clone())
            );
            assert!(
                state
                    .local
                    .graph
                    .edges()
                    .iter()
                    .any(|edge| edge.dependent == index
                        && matches!(
                            edge.kind,
                            DependencyKind::IndexOnRelation {
                                is_unique: true,
                                ..
                            }
                        ))
            );
            engine
                .analyze(
                    "BEGIN; ALTER TABLE key_owner DROP CONSTRAINT key_owner_key; ROLLBACK;",
                    &mut state,
                )
                .unwrap();
            assert!(
                state
                    .local
                    .graph
                    .edges()
                    .iter()
                    .any(|edge| edge.dependent == index)
            );
            engine
                .analyze(
                    "ALTER TABLE key_owner DROP CONSTRAINT key_owner_key;",
                    &mut state,
                )
                .unwrap();
            assert!(
                !state
                    .local
                    .graph
                    .edges()
                    .iter()
                    .any(|edge| edge.dependent == index)
            );
        }
    }

    #[test]
    fn alter_column_type_resets_storage_and_compression_transactionally() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE type_reset(value text); ALTER TABLE type_reset ALTER COLUMN value SET STORAGE MAIN; ALTER TABLE type_reset ALTER COLUMN value SET COMPRESSION pglz; BEGIN; ALTER TABLE type_reset ALTER COLUMN value TYPE varchar(80);", &mut state).unwrap();
        let Some(RelationOverlay::Present(relation)) =
            state.get_relation(&object_id("public", "type_reset"))
        else {
            panic!("missing relation")
        };
        let column = relation.get_column("value").unwrap();
        assert_eq!(column.storage, None);
        assert_eq!(column.compression, None);
        engine.analyze("ROLLBACK;", &mut state).unwrap();
        let Some(RelationOverlay::Present(relation)) =
            state.get_relation(&object_id("public", "type_reset"))
        else {
            panic!("missing relation")
        };
        let column = relation.get_column("value").unwrap();
        assert_eq!(column.storage.as_deref(), Some("MAIN"));
        assert_eq!(column.compression.as_deref(), Some("pglz"));
    }

    #[test]
    fn unavailable_compression_method_stays_conservative_without_mutating_state() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE compression_probe(value text);", &mut state)
            .unwrap();
        let findings = engine
            .analyze(
                "ALTER TABLE compression_probe ALTER COLUMN value SET COMPRESSION lz4;",
                &mut state,
            )
            .unwrap();

        assert!(findings.is_empty());
        let RelationOverlay::Present(relation) = state
            .get_relation(&object_id("public", "compression_probe"))
            .unwrap()
        else {
            panic!("missing relation")
        };
        assert_eq!(relation.get_column("value").unwrap().compression, None);
        assert_eq!(state.confidence(), &Confidence::Tainted);
        assert!(
            state
                .evidence()
                .iter()
                .any(|evidence| evidence.code == EvidenceCode::UnsupportedSemantics)
        );
    }

    #[test]
    fn column_type_lookup_prefers_earlier_table_row_type_over_later_domain() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE SCHEMA early; CREATE SCHEMA late; CREATE TABLE early.shared(id int); CREATE DOMAIN late.shared AS integer; SET search_path TO early, late, public; CREATE TABLE public.probe(value shared);", &mut state).unwrap();
        let Some(RelationOverlay::Present(relation)) =
            state.get_relation(&object_id("public", "probe"))
        else {
            panic!("missing relation")
        };
        assert_eq!(
            relation.get_column("value").unwrap().type_id,
            Some(object_id("early", "shared"))
        );
    }

    #[test]
    fn generated_expression_text_tracks_create_add_change_and_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE generated_text(base integer, doubled integer GENERATED ALWAYS AS (base * 2) STORED); ALTER TABLE generated_text ADD COLUMN tripled integer GENERATED ALWAYS AS (base * 3) STORED;", &mut state).unwrap();
        let id = object_id("public", "generated_text");
        let Some(RelationOverlay::Present(relation)) = state.get_relation(&id) else {
            panic!("missing relation")
        };
        assert_eq!(
            relation.generated_columns["doubled"].expression.as_deref(),
            Some("base * 2")
        );
        assert_eq!(
            relation.generated_columns["tripled"].expression.as_deref(),
            Some("base * 3")
        );
        engine.analyze("BEGIN; ALTER TABLE generated_text ALTER COLUMN doubled SET EXPRESSION AS (base * 4);", &mut state).unwrap();
        let Some(RelationOverlay::Present(relation)) = state.get_relation(&id) else {
            panic!("missing relation")
        };
        assert_eq!(
            relation.generated_columns["doubled"].expression.as_deref(),
            Some("base * 4")
        );
        engine.analyze("ROLLBACK;", &mut state).unwrap();
        let Some(RelationOverlay::Present(relation)) = state.get_relation(&id) else {
            panic!("missing relation")
        };
        assert_eq!(
            relation.generated_columns["doubled"].expression.as_deref(),
            Some("base * 2")
        );
    }

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
    fn index_column_identities_follow_rename_and_drop_cleanup() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id int, name text); \
                 CREATE INDEX t_name_idx ON t(name) INCLUDE (id); \
                 ALTER TABLE t RENAME COLUMN name TO full_name; \
                 ALTER TABLE t DROP COLUMN full_name;",
                &mut state,
            )
            .unwrap();

        assert!(
            !state
                .local
                .graph
                .edges()
                .iter()
                .any(|edge| edge.dependent == object_id("public", "t_name_idx")),
            "dropping an indexed column must remove PostgreSQL's implicit index dependency"
        );
    }

    #[test]
    fn simple_unique_btree_index_can_be_adopted_as_a_constraint() {
        let engine = setup_engine();
        let mut state = setup_state();

        let findings = engine
            .analyze(
                "CREATE TABLE t(id int); \
                 CREATE UNIQUE INDEX t_id_idx ON t(id); \
                 ALTER TABLE t ADD CONSTRAINT t_id_key UNIQUE USING INDEX t_id_idx;",
                &mut state,
            )
            .unwrap();

        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "a catalog-equivalent unique btree index should be adoptable: {findings:?}"
        );
        assert!(state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                && edge.dependent == object_id("public", "t_id_key")
        }));
        assert!(!state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                && edge.dependent == object_id("public", "t_id_idx")
        }));
    }

    #[test]
    fn local_expression_index_separates_eligibility_from_dependency_proof() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(name text); CREATE INDEX t_lower_name_idx ON t ((lower(name)));",
                &mut state,
            )
            .unwrap();

        let edge = state
            .local
            .graph
            .edges()
            .iter()
            .find(|edge| {
                edge.dependent == object_id("public", "t_lower_name_idx")
                    && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
            })
            .expect("expression index edge should be retained");
        assert!(matches!(
            edge.kind,
            DependencyKind::IndexOnRelation {
                has_expression_keys: true,
                dependency_columns_known: false,
                eligibility_known: true,
                ..
            }
        ));
    }

    #[test]
    fn missing_alter_table_does_not_leave_an_implicit_sequence() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze("ALTER TABLE missing ADD COLUMN id serial;", &mut state)
            .unwrap();

        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        assert!(state.local.sequences.is_empty());
        assert!(!state.relation_is_present(&object_id("public", "missing")));
    }

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
    fn dropping_a_table_removes_publication_and_partition_edges() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE parent (id int) PARTITION BY LIST (id); CREATE TABLE child PARTITION OF parent FOR VALUES IN (1); CREATE PUBLICATION pub FOR TABLE child; DROP TABLE parent CASCADE;",
                &mut state,
            )
            .unwrap();

        assert!(state.local.graph.edges().iter().all(|edge| {
            edge.dependent != object_id("public", "parent")
                && edge.dependent != object_id("public", "child")
                && edge.referenced != object_id("public", "parent")
                && edge.referenced != object_id("public", "child")
        }));
    }

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

        let Some(RelationOverlay::Present(view)) =
            state.local.relations.get(&object_id("public", "v"))
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
    fn dependent_object_creates_and_type_alterations_require_existing_targets() {
        let engine = setup_engine();
        let mut state = setup_state();

        for sql in [
            "CREATE INDEX missing_idx ON missing(id);",
            "CREATE TRIGGER missing_trigger BEFORE INSERT ON missing FOR EACH ROW EXECUTE FUNCTION missing_function();",
            "REFRESH MATERIALIZED VIEW missing_view;",
            "ALTER TYPE missing_type ADD VALUE 'new';",
        ] {
            let violations = engine.analyze(sql, &mut state).unwrap();
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.rule_id == "chain-conflict"),
                "expected target validation for {sql}"
            );
        }
        assert!(state.local.graph.edges().is_empty());
        assert!(state.local.types.is_empty());
    }

    #[test]
    fn unavailable_baseline_never_claims_schema_coverage() {
        let engine = setup_engine();
        let mut state = crate::_internal::analysis::state::AnalysisState::with_baseline(
            safe_migrate::_internal::db::cache::DbCache::new(),
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
    fn sequence_ownership_requires_a_table_target() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE VIEW occupied (id) AS SELECT 1;", &mut state)
            .unwrap();
        let violations = engine
            .analyze("CREATE SEQUENCE owned OWNED BY occupied.id;", &mut state)
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("not a table")
        }));
        assert!(
            !state
                .local
                .sequences
                .contains_key(&object_id("public", "owned"))
        );
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
    fn policies_require_existing_table_targets() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE VIEW protected_view AS SELECT 1 AS id;", &mut state)
            .unwrap();
        let violations = engine
            .analyze(
                "CREATE POLICY protected_policy ON protected_view USING (true);",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("is not a table")
        }));
        let Some(RelationOverlay::Present(view)) = state
            .local
            .relations
            .get(&object_id("public", "protected_view"))
        else {
            panic!("view should remain present");
        };
        assert!(view.policies.is_empty());
    }

    #[test]
    fn dropping_a_type_with_modeled_dependents_requires_cascade() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TYPE status AS ENUM ('new'); CREATE TABLE jobs (state status);",
                &mut state,
            )
            .unwrap();
        let violations = engine.analyze("DROP TYPE status;", &mut state).unwrap();
        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        assert!(matches!(
            state.local.types.get(&object_id("public", "status")),
            Some(TypeOverlay::Present(_))
        ));
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
        let mut cache = DbCache::new();
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
        let mut blocked_state =
            crate::_internal::analysis::state::AnalysisState::new(cache.clone());
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
    fn cached_expression_index_dependencies_follow_the_referenced_columns() {
        let table_id = object_id("public", "t");
        let index_id = object_id("public", "t_lower_note_idx");
        let mut cache = DbCache::new();
        let mut table = RelationState::new(
            table_id.clone(),
            object_id("public", "owner"),
            0,
            None,
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        for name in ["id", "note", "unused"] {
            table.apply_column_action(&ColumnAction::Add {
                name: name.to_string(),
                data_type: Some("text".to_string()),
                not_null: false,
                default: None,
            });
        }
        cache.insert_baseline(table_id.clone(), table);
        cache
            .indexes
            .push(safe_migrate::_internal::db::cache::IndexCache {
                index_id: index_id.clone(),
                table_id: table_id.clone(),
                using_method: "btree".to_string(),
                key_columns: Vec::new(),
                included_columns: Vec::new(),
                dependency_columns: vec!["note".to_string()],
                dependency_columns_known: true,
                has_expression_keys: true,
                has_predicate: false,
                is_unique: false,
                is_immediate: true,
                is_valid: true,
                is_ready: true,
                is_live: true,
                has_default_sort_order: true,
                has_default_opclasses: true,
                has_default_collations: true,
            });

        let engine = setup_engine();
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
        let unrelated = engine
            .analyze("ALTER TABLE t DROP COLUMN unused;", &mut state)
            .unwrap();
        assert!(
            !unrelated
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "unrelated expression-index column drop must not conflict: {unrelated:?}"
        );
        assert_eq!(state.local.confidence, Confidence::Exact);
        assert!(state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                && edge.dependent == index_id
        }));

        let referenced = engine
            .analyze("ALTER TABLE t DROP COLUMN note;", &mut state)
            .unwrap();
        assert!(
            !referenced
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "dependent expression-index column drop must match PostgreSQL cleanup: {referenced:?}"
        );
        assert_eq!(state.local.confidence, Confidence::Exact);
        assert!(!state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                && edge.dependent == index_id
        }));
    }

    #[test]
    fn scoped_view_dependencies_keep_edges_to_omitted_schemas() {
        let view_id = object_id("app", "v");
        let external_table = object_id("tenant", "base");
        let mut cache = DbCache::new();
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
        let mut cache = DbCache::new();
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
    fn scoped_drop_with_incomplete_dependency_coverage_stays_unchanged() {
        let in_scope_table = object_id("app", "base");
        let omitted_view = object_id("tenant", "v");
        let mut cache = DbCache::new();
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
        assert_eq!(state.local.confidence, Confidence::Tainted);
        assert!(state.relation_is_present(&in_scope_table));
    }

    #[test]
    fn empty_typed_view_dependency_cache_does_not_create_graph_edges() {
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
        use safe_migrate::_internal::model::trigger::TriggerOverlay;

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
    fn cascade_drop_removes_foreign_key_metadata_from_surviving_tables() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE parent (id integer PRIMARY KEY);
                 CREATE TABLE child (parent_id integer);
                 ALTER TABLE child ADD CONSTRAINT child_parent_fk
                    FOREIGN KEY (parent_id) REFERENCES parent(id);
                 DROP TABLE parent CASCADE;",
                &mut state,
            )
            .unwrap();

        let child = object_id("public", "child");
        assert!(state.relation_is_present(&child));
        assert!(
            !state
                .local
                .constraints
                .contains_key(&(child.clone(), "child_parent_fk".to_string())),
            "the surviving table must not retain a dropped foreign key"
        );
        assert!(!state.local.graph.edges().iter().any(|edge| {
            matches!(
                edge.kind,
                DependencyKind::ForeignKey {
                    constraint_name: Some(ref name),
                    ..
                } if name == "child_parent_fk"
            )
        }));
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
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::RenameTo
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
        graph.add_edge(DependencyEdge::new(
            a.clone(),
            b.clone(),
            DependencyKind::PartitionOf,
        ));
        graph.add_edge(DependencyEdge::new(
            b,
            a.clone(),
            DependencyKind::PartitionOf,
        ));

        assert!(graph.check_partition_cycle(&a, &child));
    }

    #[test]
    fn partition_operations_reject_unpartitioned_or_unattached_targets() {
        let engine = setup_engine();
        let mut state = setup_state();
        let violations = engine
            .analyze(
                "CREATE TABLE plain (id integer);
                 CREATE TABLE child (id integer);
                 CREATE TABLE invalid PARTITION OF plain FOR VALUES IN (1);
                 ALTER TABLE plain ATTACH PARTITION child FOR VALUES IN (1);
                 ALTER TABLE plain DETACH PARTITION child;",
                &mut state,
            )
            .unwrap();

        assert!(!state.relation_is_present(&object_id("public", "invalid")));
        assert!(!state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::PartitionOf)
                && edge.dependent == object_id("public", "child")
        }));
        assert_eq!(
            violations
                .iter()
                .filter(|violation| violation.rule_id == "chain-conflict")
                .count(),
            3,
            "every invalid partition operation should be rejected: {violations:?}"
        );
    }

    #[test]
    fn partition_bounds_follow_attach_detach_and_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE bound_parent(id integer) PARTITION BY RANGE(id); CREATE TABLE bound_child PARTITION OF bound_parent DEFAULT;", &mut state).unwrap();
        let child = object_id("public", "bound_child");
        let bound = |state: &safe_migrate::_internal::analysis::state::AnalysisState| {
            let RelationOverlay::Present(relation) = &state.local.relations[&child] else {
                panic!("missing child")
            };
            relation.partition_bound.clone()
        };
        assert_eq!(bound(&state).as_deref(), Some("DEFAULT"));
        engine
            .analyze(
                "BEGIN; ALTER TABLE bound_parent DETACH PARTITION bound_child;",
                &mut state,
            )
            .unwrap();
        assert_eq!(bound(&state), None);
        engine.analyze("ROLLBACK;", &mut state).unwrap();
        assert_eq!(bound(&state).as_deref(), Some("DEFAULT"));
        engine.analyze("ALTER TABLE bound_parent DETACH PARTITION bound_child; ALTER TABLE bound_parent ATTACH PARTITION bound_child FOR VALUES FROM (0) TO (10);", &mut state).unwrap();
        assert_eq!(
            bound(&state).as_deref(),
            Some("FOR VALUES FROM (0) TO (10)")
        );
    }

    #[test]
    fn partition_strategy_is_typed_and_invalid_values_leave_no_table() {
        let engine = setup_engine();
        for strategy in ["range", "\"RANGE\"", "list", "hash"] {
            let mut state = setup_state();
            let findings = engine.analyze(&format!("CREATE TABLE typed_parent(id integer) PARTITION /* comment */ BY {strategy} (id);"), &mut state).unwrap();
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict"),
                "{findings:?}"
            );
            let RelationOverlay::Present(parent) =
                &state.local.relations[&object_id("public", "typed_parent")]
            else {
                panic!("missing parent")
            };
            assert_eq!(
                parent.partition_type.as_deref(),
                Some(strategy.trim_matches('"').to_uppercase().as_str())
            );
        }
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE invalid_strategy(id integer) PARTITION BY imaginary(id);",
                &mut state,
            )
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"
                    && finding
                        .reason
                        .contains("unrecognized partitioning strategy")),
            "{findings:?}"
        );
        assert!(!state.relation_is_present(&object_id("public", "invalid_strategy")));
    }

    #[test]
    fn concurrent_detach_rejects_default_and_pending_siblings() {
        let engine = setup_engine();
        for pending in [false, true] {
            let mut state = setup_state();
            engine.analyze("CREATE TABLE bound_parent(id integer) PARTITION BY RANGE(id); CREATE TABLE bound_child PARTITION OF bound_parent FOR VALUES FROM (0) TO (10); CREATE TABLE bound_default PARTITION OF bound_parent DEFAULT;", &mut state).unwrap();
            if pending {
                state
                    .local
                    .graph
                    .retain_edges(|edge| edge.dependent != object_id("public", "bound_default"));
                state.local.graph.add_edge(DependencyEdge::new(
                    object_id("public", "bound_default"),
                    object_id("public", "bound_parent"),
                    DependencyKind::PartitionDetachPending,
                ));
            }
            let findings = engine
                .analyze(
                    "ALTER TABLE bound_parent DETACH PARTITION bound_child CONCURRENTLY;",
                    &mut state,
                )
                .unwrap();
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict"
                        && finding.reason.contains(if pending {
                            "pending detach"
                        } else {
                            "default partition"
                        })),
                "{findings:?}"
            );
            assert!(
                state
                    .local
                    .graph
                    .edges()
                    .iter()
                    .any(|edge| edge.dependent == object_id("public", "bound_child")
                        && matches!(edge.kind, DependencyKind::PartitionOf))
            );
        }
    }

    #[test]
    fn concurrent_detach_in_transaction_preserves_partition_state() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine.analyze("CREATE TABLE detach_parent(id integer) PARTITION BY RANGE(id); CREATE TABLE detach_child PARTITION OF detach_parent FOR VALUES FROM (0) TO (10); BEGIN; ALTER TABLE detach_parent DETACH PARTITION detach_child CONCURRENTLY; ROLLBACK;", &mut state).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"
                    && finding.reason.contains("inside a transaction"))
        );
        assert!(
            state
                .local
                .graph
                .edges()
                .iter()
                .any(|edge| edge.dependent == object_id("public", "detach_child")
                    && edge.referenced == object_id("public", "detach_parent")
                    && matches!(edge.kind, DependencyKind::PartitionOf))
        );
        assert!(
            !state
                .local
                .graph
                .edges()
                .iter()
                .any(|edge| matches!(edge.kind, DependencyKind::PartitionDetachPending))
        );
    }

    #[test]
    fn concurrent_hash_partition_detach_completes_without_pending_or_check() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine.analyze("CREATE TABLE hash_parent(id integer PRIMARY KEY) PARTITION BY HASH(id); CREATE TABLE hash_child PARTITION OF hash_parent FOR VALUES WITH (MODULUS 2, REMAINDER 0); ALTER TABLE hash_parent DETACH PARTITION hash_child CONCURRENTLY;", &mut state).unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "{findings:?}"
        );
        let child = object_id("public", "hash_child");
        assert!(
            !state
                .local
                .graph
                .edges()
                .iter()
                .any(|edge| edge.dependent == child
                    && matches!(
                        edge.kind,
                        DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
                    ))
        );
        let RelationOverlay::Present(relation) = &state.local.relations[&child] else {
            panic!("missing detached child")
        };
        assert_eq!(relation.partition_bound, None);
        assert!(
            !state
                .local
                .constraints
                .values()
                .any(|constraint| constraint.table_id == child
                    && constraint.kind == ConstraintKind::Check)
        );
        let findings = engine
            .analyze(
                "ALTER TABLE hash_parent DETACH PARTITION hash_child FINALIZE;",
                &mut state,
            )
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"
                    && finding.reason.contains("no pending")),
            "{findings:?}"
        );
    }

    #[test]
    fn inherit_provenance_preserves_other_parents_and_local_status() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE p1(id integer); CREATE TABLE p2(id integer); CREATE TABLE child() INHERITS(p1,p2);", &mut state).unwrap();
        for (sql, count, local) in [
            ("ALTER TABLE child NO INHERIT p1;", 1, false),
            ("ALTER TABLE child NO INHERIT p2;", 0, true),
            ("ALTER TABLE child INHERIT p1;", 1, true),
        ] {
            let findings = engine.analyze(sql, &mut state).unwrap();
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict"),
                "{findings:?}"
            );
            let RelationOverlay::Present(relation) =
                &state.local.relations[&object_id("public", "child")]
            else {
                panic!("missing child")
            };
            let provenance = &relation.column_inheritance["id"];
            assert_eq!(
                (provenance.parent_count, provenance.is_local),
                (count, local),
                "{sql}"
            );
        }
    }

    #[test]
    fn partition_attachment_provenance_follows_detach_and_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE parent(id integer) PARTITION BY RANGE(id); CREATE TABLE child(id integer);", &mut state).unwrap();
        let child = object_id("public", "child");
        let provenance = |state: &safe_migrate::_internal::analysis::state::AnalysisState| {
            let RelationOverlay::Present(relation) = &state.local.relations[&child] else {
                panic!("missing child")
            };
            let value = &relation.column_inheritance["id"];
            (value.parent_count, value.is_local)
        };
        assert_eq!(provenance(&state), (0, true));
        engine
            .analyze(
                "ALTER TABLE parent ATTACH PARTITION child FOR VALUES FROM (0) TO (10);",
                &mut state,
            )
            .unwrap();
        assert_eq!(provenance(&state), (1, false));
        engine
            .analyze(
                "BEGIN; ALTER TABLE parent DETACH PARTITION child;",
                &mut state,
            )
            .unwrap();
        assert_eq!(provenance(&state), (0, true));
        engine.analyze("ROLLBACK;", &mut state).unwrap();
        assert_eq!(provenance(&state), (1, false));
    }

    #[test]
    fn create_table_records_column_inheritance_provenance() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE p1 (id integer); CREATE TABLE p2 (id integer);
             CREATE TABLE inherited () INHERITS (p1, p2);
             CREATE TABLE local_child (id integer) INHERITS (p1);
             CREATE TABLE partitioned (id integer) PARTITION BY RANGE (id);
             CREATE TABLE part PARTITION OF partitioned FOR VALUES FROM (0) TO (10);",
                &mut state,
            )
            .unwrap();
        for (name, parent_count, is_local) in [
            ("p1", 0, true),
            ("inherited", 2, false),
            ("local_child", 1, true),
            ("part", 1, false),
        ] {
            let RelationOverlay::Present(relation) =
                &state.local.relations[&object_id("public", name)]
            else {
                panic!("missing relation")
            };
            let provenance = &relation.column_inheritance["id"];
            assert_eq!(
                (provenance.parent_count, provenance.is_local),
                (parent_count, is_local),
                "{name}"
            );
        }
    }

    #[test]
    fn ancestor_detach_invalidates_descendant_predicate_and_rollback_restores_it() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze(
            "CREATE TABLE root (id integer) PARTITION BY RANGE (id);
             CREATE TABLE middle PARTITION OF root FOR VALUES FROM (0) TO (100) PARTITION BY RANGE (id);
             CREATE TABLE leaf PARTITION OF middle FOR VALUES FROM (0) TO (10);",
            &mut state,
        ).unwrap();
        let leaf = object_id("public", "leaf");
        let predicate = "(id IS NOT NULL) AND (id >= 0) AND (id < 10)";
        let Some(RelationOverlay::Present(relation)) = state.local.relations.get_mut(&leaf) else {
            panic!("missing leaf");
        };
        relation.partition_constraint = Some(predicate.into());
        let findings = engine
            .analyze(
                "BEGIN; ALTER TABLE root DETACH PARTITION middle;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "{findings:?}"
        );
        let RelationOverlay::Present(relation) = &state.local.relations[&leaf] else {
            panic!("missing leaf");
        };
        assert_eq!(relation.partition_constraint, None);
        engine.analyze("ROLLBACK;", &mut state).unwrap();
        let RelationOverlay::Present(relation) = &state.local.relations[&leaf] else {
            panic!("missing leaf");
        };
        assert_eq!(relation.partition_constraint.as_deref(), Some(predicate));
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
    fn recursive_column_rename_updates_descendant_metadata_and_rolls_back() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE parent (id integer CHECK (id > 0));
             CREATE TABLE child () INHERITS (parent);
             CREATE INDEX child_id_idx ON child (id);
             BEGIN; ALTER TABLE parent RENAME COLUMN id TO renamed;",
                &mut state,
            )
            .unwrap();
        for name in ["parent", "child"] {
            let RelationOverlay::Present(relation) =
                &state.local.relations[&object_id("public", name)]
            else {
                panic!("missing {name}")
            };
            assert!(relation.has_column("renamed"));
            assert!(!relation.has_column("id"));
        }
        assert!(
            state
                .local
                .constraints
                .values()
                .filter(
                    |constraint| constraint.table_id == object_id("public", "parent")
                        && constraint.kind == ConstraintKind::Check
                )
                .all(|constraint| constraint
                    .definition
                    .as_deref()
                    .is_some_and(|definition| definition.contains("renamed")))
        );
        assert!(state.local.graph.edges().iter().any(|edge| edge.dependent == object_id("public", "child_id_idx")
            && matches!(&edge.kind, DependencyKind::IndexOnRelation { key_columns, .. } if key_columns == &["renamed".to_string()])));
        engine.analyze("ROLLBACK;", &mut state).unwrap();
        for name in ["parent", "child"] {
            let RelationOverlay::Present(relation) =
                &state.local.relations[&object_id("public", name)]
            else {
                panic!("missing {name}")
            };
            assert!(relation.has_column("id"));
            assert!(!relation.has_column("renamed"));
        }
    }

    #[test]
    fn only_column_rename_rejects_descendants_without_mutation() {
        let engine = setup_engine();
        for child_sql in [
            "CREATE TABLE child () INHERITS (parent);",
            "CREATE TABLE child PARTITION OF parent FOR VALUES FROM (0) TO (10);",
        ] {
            let mut state = setup_state();
            let parent_sql = if child_sql.contains("PARTITION") {
                "CREATE TABLE parent (id integer) PARTITION BY RANGE (id);"
            } else {
                "CREATE TABLE parent (id integer);"
            };
            engine
                .analyze(&format!("{parent_sql} {child_sql}"), &mut state)
                .unwrap();
            let findings = engine
                .analyze(
                    "ALTER TABLE ONLY parent RENAME COLUMN id TO renamed;",
                    &mut state,
                )
                .unwrap();
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict"),
                "{findings:?}"
            );
            for name in ["parent", "child"] {
                let RelationOverlay::Present(relation) =
                    &state.local.relations[&object_id("public", name)]
                else {
                    panic!("missing relation")
                };
                assert!(relation.has_column("id"));
                assert!(!relation.has_column("renamed"));
            }
        }
    }

    #[test]
    fn partition_key_column_rename_preserves_expressions_and_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze(
            "CREATE TABLE key_parent (id integer, other integer) PARTITION BY RANGE (id, (id + other));",
            &mut state,
        ).unwrap();
        let id = object_id("public", "key_parent");
        let RelationOverlay::Present(before) = &state.local.relations[&id] else {
            panic!("missing parent")
        };
        let original = before.partition_by.clone();
        let findings = engine
            .analyze(
                "BEGIN; ALTER TABLE key_parent RENAME COLUMN id TO \"NewKey\";",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "{findings:?}"
        );
        let RelationOverlay::Present(relation) = &state.local.relations[&id] else {
            panic!("missing parent")
        };
        assert_eq!(
            relation.partition_by.as_deref(),
            Some("PARTITION BY RANGE (\"NewKey\", (\"NewKey\" + other))")
        );
        engine.analyze("ROLLBACK;", &mut state).unwrap();
        let RelationOverlay::Present(relation) = &state.local.relations[&id] else {
            panic!("missing parent")
        };
        assert_eq!(relation.partition_by, original);
    }

    #[test]
    fn partition_predicate_column_rename_restores_on_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE predicate_child (id integer);", &mut state)
            .unwrap();
        let id = object_id("public", "predicate_child");
        let predicate = "id IS NOT NULL AND id >= 0 AND id < 10";
        let RelationOverlay::Present(relation) = state.local.relations.get_mut(&id).unwrap() else {
            panic!("missing relation")
        };
        relation.partition_constraint = Some(predicate.into());
        engine
            .analyze(
                "BEGIN; ALTER TABLE predicate_child RENAME COLUMN id TO renamed;",
                &mut state,
            )
            .unwrap();
        let RelationOverlay::Present(relation) = &state.local.relations[&id] else {
            panic!("missing relation")
        };
        assert_eq!(
            relation.partition_constraint.as_deref(),
            Some("renamed IS NOT NULL AND renamed >= 0 AND renamed < 10")
        );
        engine.analyze("ROLLBACK;", &mut state).unwrap();
        let RelationOverlay::Present(relation) = &state.local.relations[&id] else {
            panic!("missing relation")
        };
        assert_eq!(relation.partition_constraint.as_deref(), Some(predicate));
    }

    #[test]
    fn finalize_interrupted_detach_retains_existing_check_and_undo_state() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze(
            "CREATE TABLE parent (id integer) PARTITION BY RANGE (id);
             CREATE TABLE child PARTITION OF parent FOR VALUES FROM (0) TO (10);
             ALTER TABLE child ADD CONSTRAINT retained_bound CHECK (id IS NOT NULL AND id >= 0 AND id < 10);",
            &mut state,
        ).unwrap();
        let child = object_id("public", "child");
        let parent = object_id("public", "parent");
        // Model the catalog after the first internal transaction was committed.
        state.local.graph.retain_edges(|edge| {
            !(edge.dependent == child
                && edge.referenced == parent
                && matches!(edge.kind, DependencyKind::PartitionOf))
        });
        state.local.graph.add_edge(DependencyEdge::new(
            child.clone(),
            parent.clone(),
            DependencyKind::PartitionDetachPending,
        ));
        let check = state.local.constraints[&(child.clone(), "retained_bound".into())].clone();
        let findings = engine
            .analyze(
                "BEGIN; ALTER TABLE parent DETACH PARTITION child FINALIZE; ROLLBACK;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "{findings:?}"
        );
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.dependent == child
                && edge.referenced == parent
                && matches!(edge.kind, DependencyKind::PartitionDetachPending)
        }));
        let findings = engine
            .analyze(
                "ALTER TABLE parent DETACH PARTITION child FINALIZE;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "{findings:?}"
        );
        assert!(!state.local.graph.edges().iter().any(|edge| {
            edge.dependent == child
                && edge.referenced == parent
                && matches!(
                    edge.kind,
                    DependencyKind::PartitionDetachPending | DependencyKind::PartitionOf
                )
        }));
        assert_eq!(
            state.local.constraints[&(child.clone(), "retained_bound".into())],
            check
        );
        assert_eq!(
            state
                .local
                .constraints
                .values()
                .filter(|constraint| {
                    constraint.table_id == child && constraint.kind == ConstraintKind::Check
                })
                .count(),
            1
        );
    }

    #[test]
    fn successful_concurrent_partition_detach_completes_without_finalize() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE parent (id integer) PARTITION BY RANGE (id);
                 CREATE TABLE child (id integer);
                 ALTER TABLE parent ATTACH PARTITION child FOR VALUES FROM (0) TO (10);
                 ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;",
                &mut state,
            )
            .unwrap();

        assert!(!state.local.graph.edges().iter().any(|edge| {
            matches!(
                edge.kind,
                DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
            ) && edge.dependent == object_id("public", "child")
                && edge.referenced == object_id("public", "parent")
        }));

        let RelationOverlay::Present(child) = &state.local.relations[&object_id("public", "child")]
        else {
            panic!("detached child must remain present")
        };
        assert_eq!(child.partition_bound, None);
        assert_eq!(child.partition_constraint, None);
        // Concurrent detach retained a CHECK reproducing the partition
        // predicate; the chain is now provable.
        assert_eq!(state.local.confidence, Confidence::Exact);
        let retained =
            &state.local.constraints[&(object_id("public", "child"), "child_id_check".into())];
        assert_eq!(retained.kind, ConstraintKind::Check);
        assert!(retained.validated);
        assert_eq!(
            retained.definition.as_deref(),
            Some("((id IS NOT NULL) AND (id >= 0) AND (id < 10))")
        );

        let findings = engine
            .analyze(
                "ALTER TABLE parent DETACH PARTITION child FINALIZE;",
                &mut state,
            )
            .unwrap();
        assert!(findings.iter().any(|finding| {
            finding.rule_id == "chain-conflict" && finding.reason.contains("no pending")
        }));
    }

    #[test]
    fn retained_partition_check_preserves_quoted_key_identity() {
        let engine = setup_engine();
        for name in ["MyKey", "key with space", "key\"quote"] {
            let mut state = setup_state();
            let quoted = format!("\"{}\"", name.replace('"', "\"\""));
            let sql = format!(
                "CREATE TABLE parent({quoted} integer) PARTITION BY RANGE ({quoted});
                CREATE TABLE child PARTITION OF parent FOR VALUES FROM (0) TO (10);
                ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;"
            );
            engine.analyze(&sql, &mut state).unwrap();
            let child = object_id("public", "child");
            let check = state
                .local
                .constraints
                .values()
                .find(|check| check.table_id == child && check.kind == ConstraintKind::Check)
                .expect("retained check");
            assert_eq!(
                check.definition.as_deref(),
                Some(
                    format!("(({quoted} IS NOT NULL) AND ({quoted} >= 0) AND ({quoted} < 10))")
                        .as_str()
                )
            );
            assert!(state.local.graph.edges().iter().any(|edge|
                edge.dependent == child && matches!(&edge.kind, DependencyKind::ConstraintDependency { columns, .. } if columns == &[name.to_string()])));
        }
    }

    #[test]
    fn concurrent_detach_of_list_null_partition_retains_or_predicate() {
        let engine = setup_engine();
        for (bound, expected) in [
            (
                "IN (1, 2, NULL)",
                "(((a IS NULL) OR (a = ANY ('{1,2}'::integer[]))))",
            ),
            ("IN (NULL)", "((a IS NULL))"),
            ("IN (5, NULL)", "(((a IS NULL) OR (a = 5)))"),
        ] {
            let mut state = setup_state();
            let sql = format!(
                "CREATE TABLE parent(a integer) PARTITION BY LIST (a);
                CREATE TABLE child PARTITION OF parent FOR VALUES {bound};
                ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;"
            );
            engine.analyze(&sql, &mut state).unwrap();
            let child = object_id("public", "child");
            let check = state
                .local
                .constraints
                .values()
                .find(|check| check.table_id == child && check.kind == ConstraintKind::Check)
                .expect("retained check");
            assert_eq!(check.definition.as_deref(), Some(expected));
        }
    }

    #[test]
    fn retained_partition_check_tracks_all_cached_predicate_columns() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE parent(id integer, ancestor_key integer) PARTITION BY RANGE(id); CREATE TABLE child PARTITION OF parent FOR VALUES FROM (0) TO (10);", &mut state).unwrap();
        let child = object_id("public", "child");
        let RelationOverlay::Present(relation) = state.local.relations.get_mut(&child).unwrap()
        else {
            panic!("child")
        };
        relation.partition_constraint =
            Some("id IS NOT NULL AND id >= 0 AND id < 10 AND ancestor_key > 5".into());
        engine
            .analyze(
                "ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;",
                &mut state,
            )
            .unwrap();
        assert!(
            state
                .local
                .constraints
                .contains_key(&(child.clone(), "child_check".into()))
        );
        assert!(
            state
                .local
                .graph
                .edges()
                .iter()
                .any(|edge| edge.dependent == child
                    && matches!(&edge.kind, DependencyKind::ConstraintDependency { columns, .. }
                if columns == &["ancestor_key".to_string(), "id".to_string()]))
        );
    }

    #[test]
    fn concurrent_detach_uses_parent_strategy_for_subpartitioned_child() {
        let engine = setup_engine();
        for (parent_strategy, child_strategy, bound, check_expected) in [
            ("RANGE", "HASH", "FROM (0) TO (10)", true),
            ("HASH", "RANGE", "WITH (MODULUS 2, REMAINDER 0)", false),
        ] {
            let mut state = setup_state();
            let sql = format!("CREATE TABLE parent(id integer) PARTITION BY {parent_strategy}(id);
                CREATE TABLE child PARTITION OF parent FOR VALUES {bound} PARTITION BY {child_strategy}(id);
                ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;");
            let findings = engine.analyze(&sql, &mut state).unwrap();
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict"),
                "{findings:?}"
            );
            assert_eq!(
                state
                    .local
                    .constraints
                    .values()
                    .any(
                        |constraint| constraint.table_id == object_id("public", "child")
                            && constraint.kind == ConstraintKind::Check
                    ),
                check_expected
            );
        }
    }

    #[test]
    fn concurrent_detach_retains_check_from_created_partition_bound() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE parent (id integer) PARTITION BY RANGE (id);
                 CREATE TABLE child PARTITION OF parent FOR VALUES FROM (0) TO (10);
                 ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;",
                &mut state,
            )
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Exact);
        let retained =
            &state.local.constraints[&(object_id("public", "child"), "child_id_check".into())];
        assert_eq!(
            retained.definition.as_deref(),
            Some("((id IS NOT NULL) AND (id >= 0) AND (id < 10))")
        );
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.dependent == object_id("public", "child")
                && edge.referenced == object_id("public", "child")
                && matches!(
                    edge.kind,
                    DependencyKind::ConstraintDependency { ref columns, .. }
                        if columns == &vec!["id".to_string()]
                )
        }));
    }

    #[test]
    fn concurrent_detach_synthesizes_check_for_composite_range_key() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE parent (a integer, b integer) PARTITION BY RANGE (a, b);
                 CREATE TABLE child PARTITION OF parent FOR VALUES FROM (0, 0) TO (10, 10);
                 ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;",
                &mut state,
            )
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Exact);
        assert!(state.local.constraints.values().any(|constraint| {
            constraint.table_id == object_id("public", "child")
                && constraint.kind == ConstraintKind::Check
                && constraint.definition.as_deref() == Some("((a IS NOT NULL) AND (b IS NOT NULL) AND ((a > 0) OR ((a = 0) AND (b >= 0))) AND ((a < 10) OR ((a = 10) AND (b < 10))))")
        }));
    }

    #[test]
    fn composite_range_detach_synthesis_matches_postgres_wildcard_bounds() {
        let engine = setup_engine();
        for (columns, keys, bound, expected) in [
            (
                "a integer, b integer, c integer",
                "(a, b, c)",
                "FROM (1, 2, 3) TO (10, 20, 30)",
                "((a IS NOT NULL) AND (b IS NOT NULL) AND (c IS NOT NULL) AND ((a > 1) OR ((a = 1) AND (b > 2)) OR ((a = 1) AND (b = 2) AND (c >= 3))) AND ((a < 10) OR ((a = 10) AND (b < 20)) OR ((a = 10) AND (b = 20) AND (c < 30))))",
            ),
            (
                "a integer, b integer, c integer",
                "(a, b, c)",
                "FROM (1, 2, MINVALUE) TO (10, 20, MAXVALUE)",
                "((a IS NOT NULL) AND (b IS NOT NULL) AND (c IS NOT NULL) AND ((a > 1) OR ((a = 1) AND (b >= 2))) AND ((a < 10) OR ((a = 10) AND (b <= 20))))",
            ),
            (
                "a integer, b integer, c integer",
                "(a, b, c)",
                "FROM (1, MINVALUE, MINVALUE) TO (10, MAXVALUE, MAXVALUE)",
                "((a IS NOT NULL) AND (b IS NOT NULL) AND (c IS NOT NULL) AND (a >= 1) AND (a <= 10))",
            ),
            (
                "a integer, b integer",
                "(a, b)",
                "FROM (MINVALUE, MINVALUE) TO (MAXVALUE, MAXVALUE)",
                "((a IS NOT NULL) AND (b IS NOT NULL))",
            ),
            (
                "a integer, b integer",
                "(a, b)",
                "FROM (MINVALUE, MINVALUE) TO (10, 20)",
                "((a IS NOT NULL) AND (b IS NOT NULL) AND ((a < 10) OR ((a = 10) AND (b < 20))))",
            ),
        ] {
            let mut state = setup_state();
            let sql = format!(
                "CREATE TABLE parent ({columns}) PARTITION BY RANGE {keys};
                CREATE TABLE child PARTITION OF parent FOR VALUES {bound};
                ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;"
            );
            engine.analyze(&sql, &mut state).unwrap();
            assert_eq!(state.local.confidence, Confidence::Exact, "{bound}");
            assert!(
                state.local.constraints.values().any(|constraint| {
                    constraint.table_id == object_id("public", "child")
                        && constraint.kind == ConstraintKind::Check
                        && constraint.definition.as_deref() == Some(expected)
                }),
                "{bound}"
            );
        }
    }

    #[test]
    fn composite_range_detach_synthesis_matches_postgres_for_varchar_keys() {
        let engine = setup_engine();
        for (columns, keys, bound, expected) in [
            (
                "a character varying(32), b character varying(32)",
                "(a, b)",
                "FROM ('a', 'b') TO ('m', 'n')",
                "((a IS NOT NULL) AND (b IS NOT NULL) AND (((a)::text > 'a'::character varying(32)) OR (((a)::text = 'a'::character varying(32)) AND ((b)::text >= 'b'::character varying(32)))) AND (((a)::text < 'm'::character varying(32)) OR (((a)::text = 'm'::character varying(32)) AND ((b)::text < 'n'::character varying(32)))))",
            ),
            (
                "a character varying(32), b integer",
                "(a, b)",
                "FROM ('a', 0) TO ('m', 10)",
                "((a IS NOT NULL) AND (b IS NOT NULL) AND (((a)::text > 'a'::character varying(32)) OR (((a)::text = 'a'::character varying(32)) AND (b >= 0))) AND (((a)::text < 'm'::character varying(32)) OR (((a)::text = 'm'::character varying(32)) AND (b < 10))))",
            ),
            (
                "a character varying(16), b character varying(16), c character varying(16)",
                "(a, b, c)",
                "FROM ('a', 'b', 'c') TO ('x', 'y', 'z')",
                "((a IS NOT NULL) AND (b IS NOT NULL) AND (c IS NOT NULL) AND (((a)::text > 'a'::character varying(16)) OR (((a)::text = 'a'::character varying(16)) AND ((b)::text > 'b'::character varying(16))) OR (((a)::text = 'a'::character varying(16)) AND ((b)::text = 'b'::character varying(16)) AND ((c)::text >= 'c'::character varying(16)))) AND (((a)::text < 'x'::character varying(16)) OR (((a)::text = 'x'::character varying(16)) AND ((b)::text < 'y'::character varying(16))) OR (((a)::text = 'x'::character varying(16)) AND ((b)::text = 'y'::character varying(16)) AND ((c)::text < 'z'::character varying(16)))))",
            ),
        ] {
            let mut state = setup_state();
            let sql = format!(
                "CREATE TABLE parent ({columns}) PARTITION BY RANGE {keys};
                CREATE TABLE child PARTITION OF parent FOR VALUES {bound};
                ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;"
            );
            engine.analyze(&sql, &mut state).unwrap();
            assert_eq!(state.local.confidence, Confidence::Exact, "{bound}");
            assert!(
                state.local.constraints.values().any(|constraint| {
                    constraint.table_id == object_id("public", "child")
                        && constraint.kind == ConstraintKind::Check
                        && constraint.definition.as_deref() == Some(expected)
                }),
                "{bound}"
            );
        }
    }

    #[test]
    fn parenthesized_plain_column_keys_deparse_as_bare_columns() {
        let engine = setup_engine();
        for (columns, keys, bound, expected) in [
            (
                "a integer",
                "((a))",
                "FROM (10) TO (20)",
                "((a IS NOT NULL) AND (a >= 10) AND (a < 20))",
            ),
            (
                "a integer, b integer",
                "((a), (b))",
                "FROM (0, 0) TO (10, 10)",
                "((a IS NOT NULL) AND (b IS NOT NULL) AND ((a > 0) OR ((a = 0) AND (b >= 0))) AND ((a < 10) OR ((a = 10) AND (b < 10))))",
            ),
            (
                "a integer, b integer",
                "(((a)), b)",
                "FROM (0, 0) TO (10, 10)",
                "((a IS NOT NULL) AND (b IS NOT NULL) AND ((a > 0) OR ((a = 0) AND (b >= 0))) AND ((a < 10) OR ((a = 10) AND (b < 10))))",
            ),
            (
                "a character varying(32), b integer",
                "((a), (b))",
                "FROM ('a', 0) TO ('m', 10)",
                "((a IS NOT NULL) AND (b IS NOT NULL) AND (((a)::text > 'a'::character varying(32)) OR (((a)::text = 'a'::character varying(32)) AND (b >= 0))) AND (((a)::text < 'm'::character varying(32)) OR (((a)::text = 'm'::character varying(32)) AND (b < 10))))",
            ),
        ] {
            let mut state = setup_state();
            let sql = format!(
                "CREATE TABLE parent ({columns}) PARTITION BY RANGE {keys};
                CREATE TABLE child PARTITION OF parent FOR VALUES {bound};
                ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;"
            );
            engine.analyze(&sql, &mut state).unwrap();
            assert_eq!(state.local.confidence, Confidence::Exact, "{keys}");
            assert!(
                state.local.constraints.values().any(|constraint| {
                    constraint.table_id == object_id("public", "child")
                        && constraint.kind == ConstraintKind::Check
                        && constraint.definition.as_deref() == Some(expected)
                }),
                "{keys}"
            );
        }
    }

    #[test]
    fn expression_partition_keys_retain_conservative_taint() {
        let engine = setup_engine();
        for keys in ["((a * 2))", "((upper(a)))", "(((a)::date))", "((a + b))"] {
            let mut state = setup_state();
            let columns = if keys.contains("a + b") {
                "a integer, b integer"
            } else if keys.contains("upper(a)") {
                "a text"
            } else if keys.contains("::date") {
                "a date"
            } else {
                "a integer"
            };
            let sql = format!(
                "CREATE TABLE parent ({columns}) PARTITION BY RANGE {keys};
                CREATE TABLE child PARTITION OF parent FOR VALUES FROM ({lower}) TO ({upper});
                ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;",
                lower = if keys.contains("upper(a)") {
                    "'A'"
                } else {
                    "0"
                },
                upper = if keys.contains("upper(a)") {
                    "'Z'"
                } else {
                    "10"
                }
            );
            engine.analyze(&sql, &mut state).unwrap();
            assert_ne!(state.local.confidence, Confidence::Exact, "{keys}");
            assert!(
                !state.local.constraints.values().any(|constraint| {
                    constraint.table_id == object_id("public", "child")
                        && constraint.kind == ConstraintKind::Check
                }),
                "{keys}"
            );
        }
    }

    #[test]
    fn concurrent_detach_of_hash_partition_adds_no_check() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE parent (id integer) PARTITION BY HASH (id);
                 CREATE TABLE child PARTITION OF parent FOR VALUES WITH (MODULUS 2, REMAINDER 0);
                 ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;",
                &mut state,
            )
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Exact);
        assert!(!state.local.constraints.values().any(|constraint| {
            constraint.table_id == object_id("public", "child")
                && constraint.kind == ConstraintKind::Check
        }));
    }

    #[test]
    fn concurrent_detach_folds_baseline_cached_list_predicate() {
        use safe_migrate::_internal::db::cache::InheritanceCache;

        let engine = setup_engine();
        let mut cache = DbCache::new();
        let parent_id = object_id("public", "parent");
        let child_id = object_id("public", "child");
        let owner = object_id("public", "postgres");
        let mut parent = RelationState::new(
            parent_id.clone(),
            owner.clone(),
            0,
            Some(1000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        parent.partition_type = Some("LIST".into());
        parent.partition_by = Some("PARTITION BY LIST (b)".into());
        parent.last_analyze = Some("2024-01-01 00:00:00+00".into());
        let mut child = RelationState::new(
            child_id.clone(),
            owner.clone(),
            0,
            Some(1000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        child.partition_type = Some("LIST".into());
        child.partition_bound = Some("FOR VALUES IN (true, false)".into());
        child.partition_constraint =
            Some("((b IS NOT NULL) AND (b = ANY (ARRAY[true, false])))".into());
        child.columns.push(Column {
            name: "b".into(),
            data_type: Some("boolean".into()),
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
        });
        cache.insert_baseline(parent_id.clone(), parent);
        cache.insert_baseline(child_id.clone(), child);
        cache.inheritances.push(InheritanceCache {
            child: child_id.clone(),
            parent: parent_id.clone(),
            sequence: 0,
            is_partition: true,
            detach_pending: false,
        });
        let mut state = safe_migrate::_internal::analysis::state::AnalysisState::new(cache);
        engine
            .analyze(
                "ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;",
                &mut state,
            )
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Exact);
        let retained = &state.local.constraints[&(child_id, "child_b_check".into())];
        assert_eq!(retained.kind, ConstraintKind::Check);
        assert!(retained.validated);
        assert_eq!(
            retained.definition.as_deref(),
            Some("((b IS NOT NULL) AND (b = ANY ('{t,f}'::boolean[])))")
        );
    }

    #[test]
    fn concurrent_detach_folds_baseline_cached_boolean_single_predicate() {
        use safe_migrate::_internal::db::cache::InheritanceCache;

        let engine = setup_engine();
        let mut cache = DbCache::new();
        let parent_id = object_id("public", "parent");
        let child_id = object_id("public", "child");
        let owner = object_id("public", "postgres");
        let mut parent = RelationState::new(
            parent_id.clone(),
            owner.clone(),
            0,
            Some(1000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        parent.partition_type = Some("LIST".into());
        parent.partition_by = Some("PARTITION BY LIST (b)".into());
        parent.last_analyze = Some("2024-01-01 00:00:00+00".into());
        let mut child = RelationState::new(
            child_id.clone(),
            owner.clone(),
            0,
            Some(1000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        child.partition_type = Some("LIST".into());
        child.partition_bound = Some("FOR VALUES IN (true)".into());
        child.last_analyze = Some("2024-01-01 00:00:00+00".into());
        child.partition_constraint = Some("((b IS NOT NULL) AND (b = true))".into());
        child.columns.push(Column {
            name: "b".into(),
            data_type: Some("boolean".into()),
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
        });
        cache.insert_baseline(parent_id.clone(), parent);
        cache.insert_baseline(child_id.clone(), child);
        cache.inheritances.push(InheritanceCache {
            child: child_id.clone(),
            parent: parent_id.clone(),
            sequence: 0,
            is_partition: true,
            detach_pending: false,
        });
        let mut state = safe_migrate::_internal::analysis::state::AnalysisState::new(cache);
        engine
            .analyze(
                "ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;",
                &mut state,
            )
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Exact);
        let retained = &state.local.constraints[&(child_id, "child_b_check".into())];
        assert_eq!(
            retained.definition.as_deref(),
            Some("((b IS NOT NULL) AND b)")
        );
    }

    #[test]
    fn concurrent_detach_synthesizes_list_integer_array_from_bound() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE parent (a integer) PARTITION BY LIST (a);
                 CREATE TABLE child PARTITION OF parent FOR VALUES IN (1, 2, 3);
                 ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;",
                &mut state,
            )
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Exact);
        let retained =
            &state.local.constraints[&(object_id("public", "child"), "child_a_check".into())];
        assert_eq!(
            retained.definition.as_deref(),
            Some("((a IS NOT NULL) AND (a = ANY ('{1,2,3}'::integer[])))")
        );
    }

    #[test]
    fn partition_attachment_validates_catalog_and_tracks_generated_objects() {
        use safe_migrate::_internal::model::constraint::ConstraintKind;
        use safe_migrate::_internal::model::trigger::TriggerOverlay;

        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE parent (
                     id integer PRIMARY KEY,
                     value text,
                     CONSTRAINT positive CHECK (id > 0)
                 ) PARTITION BY RANGE (id);
                 CREATE INDEX parent_value_idx ON parent (value);
                 CREATE FUNCTION audit_row() RETURNS trigger LANGUAGE plpgsql
                     AS $$ BEGIN RETURN NEW; END; $$;
                 CREATE TRIGGER audit_row AFTER INSERT ON parent
                     FOR EACH ROW EXECUTE FUNCTION audit_row();
                 CREATE TRIGGER audit_statement AFTER INSERT ON parent
                     FOR EACH STATEMENT EXECUTE FUNCTION audit_row();
                 CREATE TABLE child (
                     id integer NOT NULL,
                     value text,
                     CONSTRAINT positive CHECK (id > 0)
                 );
                 ALTER TABLE parent ATTACH PARTITION child
                     FOR VALUES FROM (1) TO (100);",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "valid partition attachment conflicted: {findings:?}"
        );

        let parent = object_id("public", "parent");
        let child = object_id("public", "child");
        assert_eq!(
            state
                .local
                .graph
                .edges()
                .iter()
                .filter(|edge| {
                    edge.referenced == child
                        && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                })
                .count(),
            2,
            "both parent indexes should have child counterparts"
        );
        assert!(state.local.constraints.values().any(|constraint| {
            constraint.table_id == child && constraint.kind == ConstraintKind::PrimaryKey
        }));
        let clone = state
            .local
            .triggers
            .values()
            .find_map(|overlay| match overlay {
                TriggerOverlay::Present(trigger)
                    if trigger.table_id == child && trigger.name == "audit_row" =>
                {
                    Some(trigger)
                }
                _ => None,
            });
        assert!(clone.is_some_and(|trigger| {
            trigger.row_level
                && trigger.parent_trigger_id.as_ref()
                    == Some(&object_id("public", "parent\0audit_row"))
        }));
        assert!(!state.local.triggers.values().any(|overlay| {
            matches!(overlay, TriggerOverlay::Present(trigger)
                if trigger.table_id == child && trigger.name == "audit_statement")
        }));

        engine
            .analyze(
                "ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;",
                &mut state,
            )
            .unwrap();
        assert!(!state.local.triggers.values().any(|overlay| {
            matches!(overlay, TriggerOverlay::Present(trigger)
                if trigger.table_id == child && trigger.parent_trigger_id.is_some())
        }));
        assert!(state.local.constraints.values().any(|constraint| {
            constraint.table_id == child && constraint.kind == ConstraintKind::PrimaryKey
        }));
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.referenced == parent && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
        }));

        engine
            .analyze(
                "CREATE TABLE rollback_child (
                     id integer NOT NULL,
                     value text,
                     CONSTRAINT positive CHECK (id > 0)
                 );
                 BEGIN;
                 ALTER TABLE parent ATTACH PARTITION rollback_child
                     FOR VALUES FROM (100) TO (200);
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();
        let rollback_child = object_id("public", "rollback_child");
        assert!(!state.local.graph.edges().iter().any(|edge| {
            edge.referenced == rollback_child
                && matches!(
                    edge.kind,
                    DependencyKind::IndexOnRelation { .. } | DependencyKind::PartitionOf
                )
        }));
        assert!(!state.local.constraints.values().any(|constraint| {
            constraint.table_id == rollback_child && constraint.kind == ConstraintKind::PrimaryKey
        }));
        assert!(!state.local.triggers.values().any(|overlay| {
            matches!(overlay, TriggerOverlay::Present(trigger)
                if trigger.table_id == rollback_child && trigger.parent_trigger_id.is_some())
        }));
    }

    #[test]
    fn partition_attachment_rejects_incompatible_columns_checks_and_triggers() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE parent (id integer NOT NULL, CONSTRAINT positive CHECK (id > 0))
                     PARTITION BY RANGE (id);
                 CREATE FUNCTION audit_row() RETURNS trigger LANGUAGE plpgsql
                     AS $$ BEGIN RETURN NEW; END; $$;
                 CREATE TRIGGER audit AFTER INSERT ON parent
                     FOR EACH ROW EXECUTE FUNCTION audit_row();
                 CREATE TABLE wrong_type (id bigint NOT NULL, CONSTRAINT positive CHECK (id > 0));
                 CREATE TABLE wrong_check (id integer NOT NULL, CONSTRAINT positive CHECK (id >= 0));
                 CREATE TABLE trigger_collision (id integer NOT NULL, CONSTRAINT positive CHECK (id > 0));
                 CREATE TRIGGER audit AFTER INSERT ON trigger_collision
                     FOR EACH ROW EXECUTE FUNCTION audit_row();
                 ALTER TABLE parent ATTACH PARTITION wrong_type FOR VALUES FROM (1) TO (10);
                 ALTER TABLE parent ATTACH PARTITION wrong_check FOR VALUES FROM (10) TO (20);
                 ALTER TABLE parent ATTACH PARTITION trigger_collision FOR VALUES FROM (20) TO (30);",
                &mut state,
            )
            .unwrap();
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == "chain-conflict")
                .count(),
            3,
            "every incompatible attachment should conflict: {findings:?}"
        );
        assert!(!state.local.graph.edges().iter().any(|edge| {
            edge.referenced == object_id("public", "parent")
                && matches!(edge.kind, DependencyKind::PartitionOf)
        }));
    }

    #[test]
    fn create_table_inherits_copies_parent_columns_and_records_each_edge() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE parent_a (id integer);
                 CREATE TABLE parent_b (created_at timestamp);
                 CREATE TABLE child (local_value text) INHERITS (parent_a, parent_b);",
                &mut state,
            )
            .unwrap();

        let child = object_id("public", "child");
        assert!(matches!(
            state.get_relation(&child),
            Some(RelationOverlay::Present(relation))
                if relation.has_column("id")
                    && relation.has_column("created_at")
                    && relation.has_column("local_value")
        ));
        for parent in ["parent_a", "parent_b"] {
            assert!(state.local.graph.edges().iter().any(|edge| {
                matches!(edge.kind, DependencyKind::InheritanceOf)
                    && edge.dependent == child
                    && edge.referenced == object_id("public", parent)
            }));
        }
    }

    #[test]
    fn create_table_inherits_merges_compatible_columns_and_rejects_conflicts() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE parent_a (id integer NOT NULL, value integer DEFAULT 7);
                 CREATE TABLE parent_b (id integer, value integer DEFAULT 7);
                 CREATE TABLE child (id integer, value integer DEFAULT 9)
                   INHERITS (parent_a, parent_b);",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "compatible inherited columns should merge: {findings:?}"
        );
        let Some(RelationOverlay::Present(child)) =
            state.get_relation(&object_id("public", "child"))
        else {
            panic!("merged child relation missing")
        };
        assert!(!child.get_column("id").expect("id").is_nullable);
        assert_eq!(
            child.get_column("value").expect("value").default,
            Some(safe_migrate::_internal::analysis::expr_ir::ExprIr::Literal(
                "9".to_string()
            ))
        );

        let mut conflicting = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE left_parent (id integer);
                 CREATE TABLE right_parent (id text);
                 CREATE TABLE broken () INHERITS (left_parent, right_parent);",
                &mut conflicting,
            )
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        assert!(!conflicting.relation_is_present(&object_id("public", "broken")));
    }

    #[test]
    fn inheritance_requires_and_merges_matching_check_definitions() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE parent_a (value integer, CONSTRAINT positive CHECK (value > 0));
                 CREATE TABLE parent_b (value integer, CONSTRAINT positive CHECK (value > 0));
                 CREATE TABLE child () INHERITS (parent_a, parent_b);
                 CREATE TABLE attached (value integer, CONSTRAINT positive CHECK (value > 0));
                 ALTER TABLE attached INHERIT parent_a;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "matching inherited CHECK definitions should merge: {findings:?}"
        );
        assert_eq!(
            state
                .local
                .constraints
                .values()
                .filter(|constraint| {
                    constraint.table_id == object_id("public", "child")
                        && constraint.name == "positive"
                })
                .count(),
            1
        );

        let mut conflict = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE parent_a (value integer, CONSTRAINT positive CHECK (value > 0));
                 CREATE TABLE parent_b (value integer, CONSTRAINT positive CHECK (value >= 0));
                 CREATE TABLE broken () INHERITS (parent_a, parent_b);",
                &mut conflict,
            )
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        assert!(!conflict.relation_is_present(&object_id("public", "broken")));

        let mut literal_case = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE parent_a (value text, CONSTRAINT same_name CHECK (value = 'A'));
                 CREATE TABLE parent_b (value text, CONSTRAINT same_name CHECK (value = 'a'));
                 CREATE TABLE broken () INHERITS (parent_a, parent_b);",
                &mut literal_case,
            )
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        assert!(!literal_case.relation_is_present(&object_id("public", "broken")));
    }

    #[test]
    fn create_table_like_copies_only_default_like_column_properties() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE source (id integer NOT NULL DEFAULT 42, note text);
                 CREATE TABLE copy (LIKE source);",
                &mut state,
            )
            .unwrap();

        let relation = state
            .get_relation(&object_id("public", "copy"))
            .expect("LIKE target relation");
        let RelationOverlay::Present(relation) = relation else {
            panic!("LIKE target should be present");
        };
        let id = relation.get_column("id").expect("copied id column");
        assert!(!id.is_nullable);
        assert_eq!(id.data_type.as_deref(), Some("integer"));
        assert!(id.default.is_none());
        assert!(id.default_expr_text.is_none());
    }

    #[test]
    fn create_table_like_copies_each_supported_selected_property() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE source (id integer NOT NULL DEFAULT 42, computed integer GENERATED ALWAYS AS (id + 1) STORED);
                 ALTER TABLE source ALTER COLUMN id SET STORAGE PLAIN;
                 ALTER TABLE source ALTER COLUMN id SET STATISTICS 100;
                 ALTER TABLE source ALTER COLUMN id SET (n_distinct = -0.25);
                 CREATE TABLE copy (LIKE source INCLUDING DEFAULTS INCLUDING GENERATED INCLUDING STORAGE INCLUDING STATISTICS);",
                &mut state,
            )
            .unwrap();

        let RelationOverlay::Present(relation) = state
            .get_relation(&object_id("public", "copy"))
            .expect("LIKE target relation")
        else {
            panic!("LIKE target should be present");
        };
        let id = relation.get_column("id").expect("copied id column");
        assert!(id.default.is_some());
        assert_eq!(id.storage.as_deref(), Some("PLAIN"));
        assert_eq!(id.statistics_target, None);
        assert!(id.options.is_empty());
        assert_eq!(
            relation
                .get_column("computed")
                .and_then(|column| column.generated),
            Some(true),
            "INCLUDING GENERATED must preserve generated-column state"
        );
        assert_eq!(
            relation
                .generated_columns
                .get("computed")
                .map(|state| state.kind),
            Some(safe_migrate::_internal::model::relation::GeneratedColumnKind::Stored)
        );
        assert!(state.local.graph.edges().iter().any(|edge| {
            matches!(
                &edge.kind,
                DependencyKind::ColumnGeneratedFrom { column, depends_on_column }
                    if edge.dependent == object_id("public", "copy")
                        && column == "computed"
                        && depends_on_column == "id"
            )
        }));
    }

    #[test]
    fn create_table_like_clones_constraints_indexes_and_identity_objects() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE source (
                     id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                     code text UNIQUE,
                     amount integer CHECK (amount > 0)
                 );
                 CREATE INDEX source_amount_idx ON source (amount);
                 CREATE TABLE copy (
                     LIKE source INCLUDING CONSTRAINTS INCLUDING INDEXES INCLUDING IDENTITY
                 );",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "LIKE catalog-object cloning unexpectedly conflicted: {findings:?}"
        );

        let copy = object_id("public", "copy");
        let Some(RelationOverlay::Present(relation)) = state.local.relations.get(&copy) else {
            panic!("LIKE target relation missing")
        };
        assert_eq!(
            relation.identity_columns.get("id"),
            Some(&safe_migrate::_internal::model::relation::IdentityGeneration::Always)
        );
        assert!(state.local.sequences.values().any(|overlay| matches!(
            overlay,
            SequenceOverlay::Present(sequence)
                if sequence.kind == SequenceKind::Identity
                    && sequence.owned_by.as_ref() == Some(&(copy.clone(), "id".to_string()))
        )));
        let cloned_constraints: Vec<_> = state
            .local
            .constraints
            .values()
            .filter(|constraint| constraint.table_id == copy)
            .collect();
        assert!(
            cloned_constraints
                .iter()
                .any(|constraint| constraint.kind == ConstraintKind::Check)
        );
        assert!(
            cloned_constraints
                .iter()
                .any(|constraint| constraint.kind == ConstraintKind::PrimaryKey)
        );
        assert!(
            cloned_constraints
                .iter()
                .any(|constraint| constraint.kind == ConstraintKind::Unique)
        );
        assert_eq!(
            state
                .local
                .graph
                .edges()
                .iter()
                .filter(|edge| {
                    edge.referenced == copy
                        && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                })
                .count(),
            3
        );
    }

    #[test]
    fn identity_sequence_options_round_trip_into_state_and_like_clone() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE source (
                    id integer GENERATED BY DEFAULT AS IDENTITY
                      (SEQUENCE NAME source_custom_seq INCREMENT BY 5 START WITH 10
                       MINVALUE 5 MAXVALUE 100 CACHE 4 CYCLE)
                 );
                 CREATE TABLE copy (LIKE source INCLUDING IDENTITY);",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "identity sequence options should be valid: {findings:?}"
        );
        for table in ["source", "copy"] {
            let table_id = object_id("public", table);
            let sequence = state
                .local
                .sequences
                .values()
                .find_map(|overlay| match overlay {
                    SequenceOverlay::Present(sequence)
                        if sequence.kind == SequenceKind::Identity
                            && sequence.owned_by.as_ref()
                                == Some(&(table_id.clone(), "id".to_string())) =>
                    {
                        Some(sequence)
                    }
                    _ => None,
                })
                .expect("owned identity sequence");
            assert_eq!(sequence.parameters.increment, 5);
            assert_eq!(sequence.parameters.start_value, 10);
            assert_eq!(sequence.parameters.min_value, 5);
            assert_eq!(sequence.parameters.max_value, 100);
            assert_eq!(sequence.parameters.cache_size, 4);
            assert!(sequence.parameters.cycle);
        }
        assert!(
            state
                .local
                .sequences
                .contains_key(&object_id("public", "source_custom_seq"))
        );
    }

    #[test]
    fn alter_add_identity_validates_negative_ranges_names_and_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE events (name text);
                 ALTER TABLE events ADD COLUMN id integer GENERATED ALWAYS AS IDENTITY
                   (INCREMENT BY -2 NO MINVALUE NO MAXVALUE START WITH -1 CACHE 3 NO CYCLE);
                 BEGIN;
                 ALTER TABLE events ADD COLUMN rolled_back bigint GENERATED BY DEFAULT AS IDENTITY;
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "valid ALTER ADD IDENTITY conflicted: {findings:?}"
        );
        let events = object_id("public", "events");
        let Some(RelationOverlay::Present(relation)) = state.get_relation(&events) else {
            panic!("events relation missing")
        };
        assert!(relation.identity_columns.contains_key("id"));
        assert!(!relation.has_column("rolled_back"));
        let sequence = state
            .local
            .sequences
            .values()
            .find_map(|overlay| match overlay {
                SequenceOverlay::Present(sequence)
                    if sequence.owned_by.as_ref() == Some(&(events.clone(), "id".to_string())) =>
                {
                    Some(sequence)
                }
                _ => None,
            })
            .expect("identity sequence missing");
        assert_eq!(sequence.parameters.increment, -2);
        assert_eq!(sequence.parameters.start_value, -1);
        assert_eq!(sequence.parameters.min_value, i32::MIN as i64);
        assert_eq!(sequence.parameters.max_value, -1);
        assert_eq!(sequence.parameters.cache_size, 3);
        assert!(!sequence.parameters.cycle);
        assert!(!state.local.sequences.values().any(|overlay| {
            matches!(overlay, SequenceOverlay::Present(sequence)
                if sequence.owned_by.as_ref()
                    == Some(&(events.clone(), "rolled_back".to_string())))
        }));

        let invalid = engine
            .analyze(
                "CREATE SEQUENCE occupied;
                 CREATE TABLE collision (
                   id integer GENERATED ALWAYS AS IDENTITY (SEQUENCE NAME occupied)
                 );
                 CREATE TABLE invalid_range (
                   id integer GENERATED ALWAYS AS IDENTITY (START WITH 20 MAXVALUE 10)
                 );",
                &mut state,
            )
            .unwrap();
        assert_eq!(
            invalid
                .iter()
                .filter(|finding| finding.rule_id == "chain-conflict")
                .count(),
            2,
            "invalid identity definitions must conflict: {invalid:?}"
        );
        assert!(!state.relation_is_present(&object_id("public", "collision")));
        assert!(!state.relation_is_present(&object_id("public", "invalid_range")));
    }

    #[test]
    fn like_extended_statistics_follow_column_lifecycle_and_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE source (a integer, b integer);", &mut state)
            .unwrap();
        let source = object_id("public", "source");
        let statistics_id = object_id("public", "source_a_b_stat");
        let Some(RelationOverlay::Present(source_relation)) =
            state.local.relations.get_mut(&source)
        else {
            panic!("source relation missing")
        };
        source_relation.extended_statistics.insert(
            statistics_id.clone(),
            safe_migrate::_internal::model::relation::ExtendedStatisticsState {
                id: statistics_id,
                kinds: vec!["d".to_string(), "f".to_string()],
                columns: vec!["a".to_string(), "b".to_string()],
                expressions: Some("(a + b), (a * b)".to_string()),
                target: Some(250),
            },
        );

        let findings = engine
            .analyze(
                "CREATE TABLE copy (LIKE source INCLUDING STATISTICS);
                 ALTER TABLE copy RENAME COLUMN a TO renamed;
                 BEGIN;
                 ALTER TABLE copy DROP COLUMN renamed CASCADE;
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "extended-statistics lifecycle unexpectedly conflicted: {findings:?}"
        );
        let copy = object_id("public", "copy");
        let Some(RelationOverlay::Present(copy_relation)) = state.local.relations.get(&copy) else {
            panic!("copy relation missing")
        };
        let cloned = copy_relation
            .extended_statistics
            .values()
            .next()
            .expect("cloned extended statistics");
        assert_eq!(cloned.columns, vec!["renamed", "b"]);
        assert_eq!(
            cloned.expressions.as_deref(),
            Some("(renamed + b), (renamed * b)")
        );
        assert_eq!(cloned.target, None);

        let findings = engine
            .analyze("ALTER TABLE copy DROP COLUMN renamed RESTRICT;", &mut state)
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        assert!(state
            .get_relation(&copy)
            .is_some_and(|overlay| matches!(overlay, RelationOverlay::Present(relation) if relation.has_column("renamed") && !relation.extended_statistics.is_empty())));
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
    fn autocommit_runs_on_commit_drop_before_the_next_statement() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TEMPORARY TABLE work (id integer) ON COMMIT DROP;
                 CREATE INDEX work_id_idx ON work (id);",
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
            state.get_relation(&object_id("public", "work")),
            Some(RelationOverlay::Present(relation))
                if relation.has_column("id") && relation.estimated_rows == Some(0)
        ));
    }

    #[test]
    fn alter_table_options_update_and_reset_relation_state() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE entries (id integer);
                 ALTER TABLE entries SET (fillfactor = 70);
                 ALTER TABLE entries RESET (fillfactor);",
                &mut state,
            )
            .unwrap();
        let Some(RelationOverlay::Present(relation)) =
            state.get_relation(&object_id("public", "entries"))
        else {
            panic!("relation should be present");
        };
        assert!(!relation.table_options.contains_key("fillfactor"));
    }

    #[test]
    fn column_metadata_defaults_clear_prior_overrides() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE entries (payload text);
                 ALTER TABLE entries ALTER COLUMN payload SET STORAGE MAIN;
                 ALTER TABLE entries ALTER COLUMN payload SET STORAGE DEFAULT;
                 ALTER TABLE entries ALTER COLUMN payload SET STATISTICS 450;
                 ALTER TABLE entries ALTER COLUMN payload SET STATISTICS DEFAULT;",
                &mut state,
            )
            .unwrap();
        let Some(RelationOverlay::Present(relation)) =
            state.get_relation(&object_id("public", "entries"))
        else {
            panic!("relation should be present");
        };
        let column = relation.get_column("payload").expect("payload column");
        assert_eq!(column.storage, None);
        assert_eq!(column.statistics_target, None);
    }

    #[test]
    fn cluster_on_requires_an_index_owned_by_the_relation() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE entries (id integer);
                 CREATE TABLE other (id integer);
                 CREATE INDEX entries_id_idx ON entries (id);
                 CREATE INDEX other_id_idx ON other (id);
                 ALTER TABLE entries CLUSTER ON entries_id_idx;",
                &mut state,
            )
            .unwrap();
        assert!(matches!(
            state.get_relation(&object_id("public", "entries")),
            Some(RelationOverlay::Present(relation))
                if relation.cluster_index.as_deref() == Some("entries_id_idx")
        ));
        engine
            .analyze("ALTER TABLE entries CLUSTER ON other_id_idx;", &mut state)
            .unwrap();
        assert!(matches!(
            state.get_relation(&object_id("public", "entries")),
            Some(RelationOverlay::Present(relation))
                if relation.cluster_index.as_deref() == Some("entries_id_idx")
        ));
    }

    #[test]
    fn replica_identity_using_index_requires_a_usable_owned_index() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE entries (id integer NOT NULL);
                 CREATE TABLE other (id integer NOT NULL);
                 CREATE UNIQUE INDEX entries_identity_idx ON entries (id);
                 CREATE UNIQUE INDEX other_identity_idx ON other (id);
                 ALTER TABLE entries REPLICA IDENTITY USING INDEX entries_identity_idx;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "eligible replica identity index should be accepted: {findings:?}"
        );
        assert!(matches!(
            state.get_relation(&object_id("public", "entries")),
            Some(RelationOverlay::Present(relation))
                if relation.replica_identity.as_deref() == Some("USING INDEX entries_identity_idx")
        ));

        let findings = engine
            .analyze(
                "ALTER TABLE entries REPLICA IDENTITY USING INDEX other_identity_idx;",
                &mut state,
            )
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        assert!(matches!(
            state.get_relation(&object_id("public", "entries")),
            Some(RelationOverlay::Present(relation))
                if relation.replica_identity.as_deref() == Some("USING INDEX entries_identity_idx")
        ));
    }

    #[test]
    fn typed_table_uses_the_composite_type_column_layout() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TYPE component AS (code text);
                 CREATE TYPE address AS (street text, zip integer, component component);
                 CREATE TABLE addresses OF address;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "opaque-dynamic-sql"),
            "typed table should not be opaque: {findings:?}"
        );
        assert!(matches!(
            state.get_relation(&object_id("public", "addresses")),
            Some(RelationOverlay::Present(relation))
                if relation.of_type == Some(object_id("public", "address"))
                    && relation.columns.iter().map(|column| column.name.as_str()).collect::<Vec<_>>()
                        == vec!["street", "zip", "component"]
        ));
    }

    #[test]
    fn alter_table_of_and_not_of_validate_the_composite_layout() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TYPE address AS (street text, zip integer);
                 CREATE TABLE addresses (street text, zip integer);
                 ALTER TABLE addresses OF address;
                 ALTER TABLE addresses NOT OF;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "opaque-dynamic-sql"),
            "typed-table alterations should not be opaque: {findings:?}"
        );
        assert!(matches!(
            state.get_relation(&object_id("public", "addresses")),
            Some(RelationOverlay::Present(relation)) if relation.of_type.is_none()
        ));
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
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::IndexOnRelation { .. }
                ))
                .any(|i| i.dependent == object_id("public", "i2"))
        );
        assert!(
            !state
                .local
                .graph
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::IndexOnRelation { .. }
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
                "CREATE TABLE p(id int PRIMARY KEY); CREATE TABLE c(p_id int); ALTER TABLE c ADD CONSTRAINT fk FOREIGN KEY (p_id) REFERENCES p(id);",
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
                    safe_migrate::_internal::analysis::graph::DependencyKind::ForeignKey { .. }
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
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::ForeignKey { .. }
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
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::SequenceOwnedBy { .. }
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
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::SequenceOwnedBy { .. }
                ))
                .count()
                == 0
        );
    }

    #[test]
    fn dropping_owned_sequence_cascade_removes_dependent_nextval_default() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id int, other_id int); CREATE SEQUENCE s OWNED BY t.id; CREATE SEQUENCE other OWNED BY t.other_id; ALTER TABLE t ALTER COLUMN id SET DEFAULT nextval('s'); ALTER TABLE t ALTER COLUMN other_id SET DEFAULT nextval('other');",
                &mut state,
            )
            .unwrap();

        let findings = engine.analyze("DROP SEQUENCE s;", &mut state).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "migration-local nextval default must block a non-CASCADE sequence drop: {findings:?}"
        );

        engine
            .analyze("DROP SEQUENCE s CASCADE;", &mut state)
            .unwrap();

        let Some(RelationOverlay::Present(table)) = state.get_relation(&object_id("public", "t"))
        else {
            panic!("table should remain present");
        };
        assert_eq!(
            table
                .get_column("id")
                .and_then(|column| column.default.as_ref()),
            None
        );
        assert!(
            table
                .get_column("other_id")
                .and_then(|column| column.default.as_ref())
                .is_some()
        );
        assert_eq!(
            table
                .get_column("id")
                .and_then(|column| column.default_expr_text.as_deref()),
            None
        );
    }

    #[test]
    fn migration_local_default_blocks_standalone_sequence_drop() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE local_defaults(id int); CREATE SEQUENCE local_defaults_id_seq; ALTER TABLE local_defaults ALTER COLUMN id SET DEFAULT nextval('local_defaults_id_seq');",
                &mut state,
            )
            .unwrap();

        let findings = engine
            .analyze("DROP SEQUENCE local_defaults_id_seq;", &mut state)
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "migration-local default must block a standalone sequence drop: {findings:?}"
        );

        engine
            .analyze("DROP SEQUENCE local_defaults_id_seq CASCADE;", &mut state)
            .unwrap();
        let table = object_id("public", "local_defaults");
        assert!(matches!(
            state.get_relation(&table),
            Some(RelationOverlay::Present(relation))
                if relation.get_column("id").is_some_and(|column| column.default.is_none())
        ));
    }

    #[test]
    fn dropping_migration_local_default_removes_sequence_dependency() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE local_default_reset(id int); CREATE SEQUENCE local_default_reset_seq; ALTER TABLE local_default_reset ALTER COLUMN id SET DEFAULT nextval('local_default_reset_seq'); ALTER TABLE local_default_reset ALTER COLUMN id DROP DEFAULT;",
                &mut state,
            )
            .unwrap();

        let findings = engine
            .analyze("DROP SEQUENCE local_default_reset_seq;", &mut state)
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "DROP DEFAULT must remove the local sequence dependency: {findings:?}"
        );
    }

    #[test]
    fn sequence_rename_preserves_default_dependency() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE local_default_reset(id int); CREATE SEQUENCE local_default_reset_seq; ALTER TABLE local_default_reset ALTER COLUMN id SET DEFAULT nextval('local_default_reset_seq'); ALTER SEQUENCE local_default_reset_seq RENAME TO local_default_reset_seq_renamed;",
                &mut state,
            )
            .unwrap();
        let findings = engine
            .analyze("DROP SEQUENCE local_default_reset_seq_renamed;", &mut state)
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "renaming must preserve the default dependency: {findings:?}"
        );

        engine
            .analyze(
                "ALTER TABLE local_default_reset ALTER COLUMN id DROP DEFAULT;",
                &mut state,
            )
            .unwrap();
        let findings = engine
            .analyze("DROP SEQUENCE local_default_reset_seq_renamed;", &mut state)
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "DROP DEFAULT must remove the renamed sequence dependency: {findings:?}"
        );
    }

    #[test]
    fn dropping_schema_cascade_removes_cross_schema_sequence_defaults() {
        let engine = setup_engine();
        let mut cache = {
            let mut cache = DbCache::new();
            cache.metadata.source_lock_timeout_ms = 1_000;
            cache.metadata.source_statement_timeout_ms = 10_000;
            cache
        };
        let name = "public";
        cache.schemas.insert(
            name.to_string(),
            SchemaState {
                name: name.to_string(),
                owner: object_id("", "postgres"),
                generation: 0,
            },
        );
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        engine
            .analyze(
                "CREATE SCHEMA seq_schema; CREATE TABLE t(id int); CREATE SEQUENCE seq_schema.s; ALTER TABLE t ALTER COLUMN id SET DEFAULT nextval('seq_schema.s');",
                &mut state,
            )
            .unwrap();

        engine
            .analyze("DROP SCHEMA seq_schema CASCADE;", &mut state)
            .unwrap();

        assert!(matches!(
            state.local.schemas.get("seq_schema"),
            Some(safe_migrate::_internal::model::schema::SchemaOverlay::Dropped)
        ));

        assert!(matches!(
            state.local.sequences.get(&object_id("seq_schema", "s")),
            Some(SequenceOverlay::Dropped)
        ));

        let Some(RelationOverlay::Present(table)) = state.get_relation(&object_id("public", "t"))
        else {
            panic!("table should remain present");
        };
        assert_eq!(
            table
                .get_column("id")
                .and_then(|column| column.default.as_ref()),
            None
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
    fn select_into_projects_simple_source_columns_exactly() {
        let engine = setup_engine();
        let mut state = setup_state();

        let findings = engine
            .analyze(
                "CREATE TABLE source (id integer NOT NULL, name varchar(40));
                 SELECT id AS copied_id, name INTO snapshot FROM source;
                 ALTER TABLE snapshot DROP COLUMN name;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "simple SELECT INTO should remain exact: {findings:?}"
        );
        assert_eq!(
            state.local.confidence,
            Confidence::Exact,
            "unexpected evidence: {:?}",
            state.evidence()
        );
        let Some(RelationOverlay::Present(snapshot)) =
            state.get_relation(&object_id("public", "snapshot"))
        else {
            panic!("SELECT INTO relation missing")
        };
        let copied_id = snapshot
            .get_column("copied_id")
            .expect("projected alias missing");
        assert_eq!(copied_id.data_type.as_deref(), Some("integer"));
        assert!(copied_id.is_nullable, "SELECT INTO does not copy NOT NULL");
        assert!(!snapshot.has_column("name"));
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
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
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
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
        let Some(safe_migrate::_internal::model::function::FunctionOverlay::Present(function)) =
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
                routine_kind: safe_migrate::_internal::model::function::RoutineKind::Function,
                arg_types: vec!["mood".into()],
                arg_type_ids: Vec::new(),
                return_type: "mood".into(),
                return_type_id: None,
                volatility: Volatility::Volatile,
                language: "sql".into(),
                security: SecurityMode::Invoker,
            },
        );
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
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
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
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
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
            let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
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
            let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
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
            Some(safe_migrate::_internal::model::replication::PublicationOverlay::Dropped)
        ));
        assert!(matches!(
            state.local.subscriptions.get("s"),
            Some(safe_migrate::_internal::model::replication::SubscriptionOverlay::Dropped)
        ));
    }

    #[test]
    fn test_topology_trigger_and_policy() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id int); CREATE POLICY p ON t FOR SELECT USING(true); CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$; CREATE TRIGGER tr BEFORE INSERT ON t EXECUTE FUNCTION f();",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            state.local.confidence,
            Confidence::Tainted,
            "policy expressions are retained for rule evaluation but are not modeled in relation state"
        );

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
        let Some(RelationOverlay::Present(view)) =
            state.local.relations.get(&object_id("public", "v"))
        else {
            panic!("view should remain present");
        };
        assert!(view.triggers.contains("tr"));
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
            safe_migrate::_internal::model::trigger::TriggerOverlay::Present(trigger) if trigger.name == "new_trigger"
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
        if let Some(safe_migrate::_internal::model::role::RoleOverlay::Present(role)) =
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
            Some(safe_migrate::_internal::model::role::RoleOverlay::Dropped)
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

        let Some(safe_migrate::_internal::model::role::RoleOverlay::Present(user)) =
            state.local.roles.get(&ObjectId::new("", "web_user"))
        else {
            panic!("user missing");
        };
        assert!(user.can_login);

        let Some(safe_migrate::_internal::model::role::RoleOverlay::Present(role)) =
            state.local.roles.get(&ObjectId::new("", "worker"))
        else {
            panic!("role missing");
        };
        assert!(role.can_login);

        let Some(safe_migrate::_internal::model::role::RoleOverlay::Present(batch)) =
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
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
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

        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.dependent == object_id("public", "indexed_table_id_idx")
                && edge.referenced == object_id("public", "indexed_table")
                && matches!(
                    edge.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::IndexOnRelation { .. }
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
    fn creating_a_new_function_taints_unmodeled_body_state() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE FUNCTION work() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;",
                &mut state,
            )
            .unwrap();

        // FunctionState tracks identity and selected options, but not the
        // SQL body/dependency graph represented by `AS`; retaining Exact here
        // would overstate what later dependency checks can prove.
        assert_eq!(state.local.confidence, Confidence::Tainted);
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
            let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
        assert_eq!(
            state.local.confidence,
            Confidence::Tainted,
            "aggregate implementation details are intentionally not modeled"
        );

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
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
                safe_migrate::_internal::model::function::RoutineKind::Function,
                "DROP PROCEDURE IF EXISTS work(int);",
            ),
            (
                safe_migrate::_internal::model::function::RoutineKind::Procedure,
                "DROP FUNCTION IF EXISTS work(int);",
            ),
        ] {
            let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
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
            let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
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
    fn routine_drop_lookup_outcomes_preserve_guarded_and_unknown_semantics() {
        fn signature(schema: &str) -> FunctionSigFact {
            FunctionSigFact {
                name: QualifiedName::new(
                    Some(Ident::new(schema, false)),
                    Ident::new("work", false),
                ),
                params: vec!["integer".into()],
            }
        }

        fn routine(kind: RoutineKind) -> FunctionState {
            let id = object_id("public", "work(integer)");
            FunctionState {
                id,
                routine_kind: kind,
                arg_types: vec!["integer".into()],
                arg_type_ids: Vec::new(),
                return_type: "void".into(),
                return_type_id: None,
                volatility: Volatility::Volatile,
                language: "sql".into(),
                security: SecurityMode::Invoker,
            }
        }

        let function_drop = |schema: &str, if_exists| {
            Mutation::DropFunction(DropFunctionMutation {
                signatures: vec![signature(schema)],
                if_exists,
                cascade: false,
            })
        };
        let procedure_drop = |schema: &str, if_exists| {
            Mutation::DropProcedure(DropProcedureMutation {
                signatures: vec![signature(schema)],
                if_exists,
                cascade: false,
            })
        };
        let aggregate_drop = |schema: &str, if_exists| {
            Mutation::DropAggregate(DropAggregateMutation {
                signatures: vec![signature(schema)],
                if_exists,
                cascade: false,
            })
        };

        for (kind, drop) in [
            (RoutineKind::Procedure, function_drop("public", true)),
            (RoutineKind::Function, procedure_drop("public", true)),
        ] {
            let mut cache = DbCache::new();
            cache
                .functions
                .insert(object_id("public", "work(integer)"), routine(kind));
            let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
            assert!(matches!(
                state.apply(&drop, None),
                MutationResult::Conflict { .. }
            ));
            assert_eq!(state.local.confidence, Confidence::Exact);
        }

        let mut wrong_kind_cache = DbCache::new();
        wrong_kind_cache.functions.insert(
            object_id("public", "work(integer)"),
            routine(RoutineKind::Function),
        );
        let mut wrong_kind_state =
            crate::_internal::analysis::state::AnalysisState::new(wrong_kind_cache);
        assert!(matches!(
            wrong_kind_state.apply(&aggregate_drop("public", true), None),
            MutationResult::Conflict { .. }
        ));
        assert_eq!(wrong_kind_state.local.confidence, Confidence::Exact);

        for drop in [
            function_drop("public", true),
            procedure_drop("public", true),
            aggregate_drop("public", true),
        ] {
            let mut state = setup_state();
            assert_eq!(state.apply(&drop, None), MutationResult::Skipped);
            assert_eq!(state.local.confidence, Confidence::Exact);
        }

        for drop in [
            function_drop("tenant", false),
            procedure_drop("tenant", false),
            aggregate_drop("tenant", false),
        ] {
            let mut cache = DbCache::new();
            cache.metadata.schemas = Some(vec!["public".into()]);
            let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
            assert_eq!(state.apply(&drop, None), MutationResult::Skipped);
            assert_eq!(state.local.confidence, Confidence::Tainted);
        }

        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["public".into()]);
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
        assert_eq!(
            state.apply(&function_drop("tenant", true), None),
            MutationResult::Skipped
        );
        assert_eq!(state.local.confidence, Confidence::Tainted);
        assert_eq!(
            state.apply(&aggregate_drop("tenant", true), None),
            MutationResult::Skipped
        );
        assert_eq!(state.local.confidence, Confidence::Tainted);
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
            safe_migrate::_internal::model::function::RoutineKind::Procedure
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

        let mut scoped_cache = DbCache::new();
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
        let Some(safe_migrate::_internal::model::replication::PublicationOverlay::Present(
            publication,
        )) = state.local.publications.get("renamed_changes")
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
                .any(|param| param.name == "streaming" && param.value == "parallel")
        }));

        engine.analyze("DROP TABLE second;", &mut state).unwrap();
        let Some(safe_migrate::_internal::model::replication::PublicationOverlay::Present(
            publication,
        )) = state.local.publications.get("renamed_changes")
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
        let mut cache = DbCache::new();
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
    fn table_drop_resolves_unqualified_publication_membership_through_search_path() {
        let engine = setup_engine();
        let mut cache = cache_with_table("tenant", "entries", None);
        cache.search_path = vec!["tenant".into()];
        cache.publications.insert(
            "changes".into(),
            safe_migrate::_internal::model::replication::PublicationState {
                name: "changes".into(),
                owner: Some("postgres".into()),
                scope: safe_migrate::_internal::analysis::facts::PublicationScope::Explicit(vec![
                    safe_migrate::_internal::analysis::facts::PublicationObjectFact::Table {
                        name: safe_migrate::_internal::ast::identifiers::QualifiedName::new(
                            None,
                            safe_migrate::_internal::ast::identifiers::Ident::new("entries", true),
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
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        engine.analyze("DROP TABLE entries;", &mut state).unwrap();

        let Some(safe_migrate::_internal::model::replication::PublicationOverlay::Present(
            publication,
        )) = state.local.publications.get("changes")
        else {
            panic!("publication missing");
        };
        assert!(matches!(
            &publication.scope,
            safe_migrate::_internal::analysis::facts::PublicationScope::Explicit(objects)
                if objects.is_empty()
        ));
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

        let mut inherited_state =
            crate::_internal::analysis::state::AnalysisState::new(cache.clone());
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
    fn grant_option_changes_preserve_effective_privilege_state() {
        let engine = setup_engine();
        let mut state = setup_state();
        let role = object_id("", "app_user");
        let table = object_id("public", "grant_option_table");

        engine
            .analyze(
                "CREATE TABLE grant_option_table(id int); GRANT SELECT ON grant_option_table TO app_user WITH GRANT OPTION;",
                &mut state,
            )
            .unwrap();
        let RelationOverlay::Present(relation) = state.local.relations.get(&table).unwrap() else {
            panic!("table missing");
        };
        assert!(relation.privileges.has_privilege(&role, Privilege::Select));
        assert!(
            relation
                .privileges
                .has_grant_option(&role, Privilege::Select)
        );

        engine
            .analyze(
                "REVOKE GRANT OPTION FOR SELECT ON grant_option_table FROM app_user;",
                &mut state,
            )
            .unwrap();
        let RelationOverlay::Present(relation) = state.local.relations.get(&table).unwrap() else {
            panic!("table missing");
        };
        assert!(relation.privileges.has_privilege(&role, Privilege::Select));
        assert!(
            !relation
                .privileges
                .has_grant_option(&role, Privilege::Select)
        );
    }

    #[test]
    fn targeted_revoke_without_acl_provenance_is_tainted() {
        let engine = setup_engine();
        let table_id = object_id("public", "provenance_table");
        let reader = object_id("", "reader");
        let owner = object_id("", "owner");
        let mut cache = cache_with_table("public", "provenance_table", None);
        cache.metadata.source_role = Some(owner.name.clone());
        cache.metadata.source_session_role = Some(owner.name.clone());
        cache.roles.insert(
            owner.clone(),
            RoleState {
                id: owner.clone(),
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        cache.roles.insert(
            reader.clone(),
            RoleState {
                id: reader.clone(),
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        if let Some(relation) = cache.relations.get_mut(&table_id) {
            // The helper's default owner is schema-qualified; use the
            // cluster role that executes the targeted revoke.
            relation.owner = owner.clone();
            let privileges = &mut relation.privileges;
            let select: std::collections::HashSet<_> = [Privilege::Select].into_iter().collect();
            // Deliberately model a legacy/hand-built ACL: the privilege and
            // grant option exist, but their grantor provenance is absent.
            privileges.grant(reader.clone(), select.clone());
            privileges.grant_options.insert(reader.clone(), select);
        }
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let _findings = engine
            .analyze(
                "REVOKE SELECT ON provenance_table FROM reader GRANTED BY owner;",
                &mut state,
            )
            .unwrap();

        assert_eq!(state.local.confidence, Confidence::Tainted);
    }

    #[test]
    fn object_granted_by_must_match_the_current_role() {
        let engine = setup_engine();
        let table_id = object_id("public", "explicit_grantor_table");
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some("current_user".into());
        cache.metadata.source_session_role = Some("current_user".into());
        for name in ["current_user", "other_grantor", "reader"] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: true,
                    is_superuser: false,
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let mut relation = RelationState::new(
            table_id.clone(),
            object_id("", "owner"),
            0,
            Some(1),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        relation.privileges.grant_with_option(
            object_id("", "other_grantor"),
            [Privilege::Select].into_iter().collect(),
        );
        cache.insert_baseline(table_id, relation);
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let findings = engine
            .analyze(
                "GRANT SELECT ON explicit_grantor_table TO reader GRANTED BY other_grantor;",
                &mut state,
            )
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        let RelationOverlay::Present(relation) = state
            .get_relation(&object_id("public", "explicit_grantor_table"))
            .unwrap()
        else {
            panic!("relation missing");
        };
        assert!(
            !relation
                .privileges
                .has_privilege(&object_id("", "reader"), Privilege::Select)
        );

        let findings = engine
            .analyze(
                "GRANT SELECT ON ALL TABLES IN SCHEMA public TO reader GRANTED BY other_grantor;",
                &mut state,
            )
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
    }

    #[test]
    fn inherited_grant_option_authorizes_a_delegated_grant() {
        let engine = setup_engine();
        let table_id = object_id("public", "inherited_grant_table");
        let parent = object_id("", "grant_parent");
        let member = object_id("", "grant_member");
        let mut cache = DbCache::new();
        cache.pg_version_num = Some(160_000);
        cache.metadata.source_role = Some("grant_member".into());
        cache.metadata.source_session_role = Some("grant_member".into());
        cache.roles.insert(
            parent.clone(),
            RoleState {
                id: parent.clone(),
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        cache.roles.insert(
            member.clone(),
            RoleState {
                id: member.clone(),
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: vec![parent.clone()],
                can_administer_membership: Vec::new(),
                can_inherit_from: vec![parent.clone()],
                can_set_role_to: Vec::new(),
            },
        );
        let delegated = object_id("", "delegated_user");
        cache.roles.insert(
            delegated.clone(),
            RoleState {
                id: delegated,
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        let mut relation = RelationState::new(
            table_id.clone(),
            object_id("", "owner"),
            0,
            Some(1),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        relation
            .privileges
            .grant_with_option(parent, [Privilege::Select].into_iter().collect());
        cache.insert_baseline(table_id, relation);
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let violations = engine
            .analyze(
                "GRANT SELECT ON inherited_grant_table TO delegated_user;",
                &mut state,
            )
            .unwrap();
        assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
        let RelationOverlay::Present(relation) = state
            .get_relation(&object_id("public", "inherited_grant_table"))
            .unwrap()
        else {
            panic!("relation missing");
        };
        assert!(
            relation
                .privileges
                .has_privilege(&object_id("", "delegated_user"), Privilege::Select)
        );
    }

    #[test]
    fn membership_without_inherit_option_cannot_delegate_grants() {
        let engine = setup_engine();
        let table_id = object_id("public", "non_inherited_grant_table");
        let parent = object_id("", "grant_parent");
        let member = object_id("", "grant_member");
        let mut cache = DbCache::new();
        cache.pg_version_num = Some(160_000);
        cache.metadata.source_role = Some("grant_member".into());
        cache.metadata.source_session_role = Some("grant_member".into());
        for (id, can_inherit_from) in [(parent.clone(), Vec::new()), (member.clone(), Vec::new())] {
            let is_member = id == member;
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: true,
                    is_superuser: false,
                    inherits: true,
                    member_of: if is_member {
                        vec![parent.clone()]
                    } else {
                        Vec::new()
                    },
                    can_administer_membership: Vec::new(),
                    can_inherit_from,
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let delegated = object_id("", "delegated_user");
        cache.roles.insert(
            delegated.clone(),
            RoleState {
                id: delegated,
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        let mut relation = RelationState::new(
            table_id.clone(),
            object_id("", "owner"),
            0,
            Some(1),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        relation
            .privileges
            .grant_with_option(parent, [Privilege::Select].into_iter().collect());
        cache.insert_baseline(table_id, relation);
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let violations = engine
            .analyze(
                "GRANT SELECT ON non_inherited_grant_table TO delegated_user;",
                &mut state,
            )
            .unwrap();
        assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
        let RelationOverlay::Present(relation) = state
            .get_relation(&object_id("public", "non_inherited_grant_table"))
            .unwrap()
        else {
            panic!("relation missing");
        };
        assert!(
            !relation
                .privileges
                .has_privilege(&object_id("", "delegated_user"), Privilege::Select)
        );
    }

    #[test]
    fn pg16_membership_inherit_option_overrides_member_noinherit() {
        let engine = setup_engine();
        let table_id = object_id("public", "membership_option_table");
        let parent = object_id("", "grant_parent");
        let member = object_id("", "grant_member");
        let delegated = object_id("", "delegated_user");
        let mut cache = DbCache::new();
        cache.pg_version_num = Some(160_000);
        cache.metadata.source_role = Some(member.name.clone());
        cache.metadata.source_session_role = Some(member.name.clone());
        for (id, inherits, can_inherit_from) in [
            (parent.clone(), true, Vec::new()),
            (member.clone(), false, vec![parent.clone()]),
            (delegated.clone(), true, Vec::new()),
        ] {
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id: id.clone(),
                    can_login: true,
                    is_superuser: false,
                    inherits,
                    member_of: (id == member)
                        .then_some(parent.clone())
                        .into_iter()
                        .collect(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from,
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let mut relation = RelationState::new(
            table_id.clone(),
            object_id("", "owner"),
            0,
            Some(1),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        relation
            .privileges
            .grant_with_option(parent, [Privilege::Select].into_iter().collect());
        cache.insert_baseline(table_id, relation);
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let findings = engine
            .analyze(
                "GRANT SELECT ON membership_option_table TO delegated_user;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
    }

    #[test]
    fn pg15_alter_role_inherit_activates_existing_membership() {
        let engine = setup_engine();
        let table_id = object_id("public", "legacy_inherit_table");
        let parent = object_id("", "grant_parent");
        let member = object_id("", "grant_member");
        let delegated = object_id("", "delegated_user");
        let mut cache = DbCache::new();
        cache.pg_version_num = Some(150_000);
        cache.metadata.source_role = Some(member.name.clone());
        cache.metadata.source_session_role = Some(member.name.clone());
        for (id, inherits) in [
            (parent.clone(), true),
            (member.clone(), false),
            (delegated.clone(), true),
        ] {
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: true,
                    is_superuser: false,
                    inherits,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let member_state = cache.roles.get_mut(&member).expect("member role exists");
        member_state.member_of.push(parent.clone());
        member_state.can_inherit_from.push(parent.clone());

        let mut relation = RelationState::new(
            table_id.clone(),
            object_id("", "owner"),
            0,
            Some(1),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        relation
            .privileges
            .grant_with_option(parent, [Privilege::Select].into_iter().collect());
        cache.insert_baseline(table_id, relation);
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let findings = engine
            .analyze(
                "ALTER ROLE grant_member INHERIT; \
                 GRANT SELECT ON legacy_inherit_table TO delegated_user;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
    }

    #[test]
    fn inherited_admin_option_authorizes_role_membership_grants() {
        let engine = setup_engine();
        let actor = object_id("", "membership_actor");
        let delegator = object_id("", "membership_delegator");
        let target = object_id("", "membership_target");
        let recipient = object_id("", "membership_recipient");
        let mut cache = DbCache::new();
        cache.pg_version_num = Some(160_000);
        cache.metadata.source_role = Some(actor.name.clone());
        cache.metadata.source_session_role = Some(actor.name.clone());
        for (id, member_of, can_inherit_from, can_administer_membership) in [
            (
                actor.clone(),
                vec![delegator.clone()],
                vec![delegator.clone()],
                Vec::new(),
            ),
            (
                delegator.clone(),
                Vec::new(),
                Vec::new(),
                vec![target.clone()],
            ),
            (target.clone(), Vec::new(), Vec::new(), Vec::new()),
            (recipient.clone(), Vec::new(), Vec::new(), Vec::new()),
        ] {
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: true,
                    is_superuser: false,
                    inherits: false,
                    member_of,
                    can_administer_membership,
                    can_inherit_from,
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let findings = engine
            .analyze(
                "GRANT membership_target TO membership_recipient;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        let RoleOverlay::Present(recipient) = state
            .local
            .roles
            .get(&object_id("", "membership_recipient"))
            .unwrap()
        else {
            panic!("recipient role unexpectedly dropped");
        };
        assert_eq!(recipient.member_of, vec![target]);
    }

    #[test]
    fn revoke_cascade_removes_grants_delegated_by_the_revoked_role() {
        let engine = setup_engine();
        let table_id = object_id("public", "cascade_grant_table");
        let owner = object_id("", "grant_owner");
        let delegate = object_id("", "grant_delegate");
        let reader = object_id("", "grant_reader");
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some("grant_owner".into());
        cache.metadata.source_session_role = Some("grant_owner".into());
        for (id, can_set_role_to) in [
            (owner.clone(), vec![delegate.clone()]),
            (delegate.clone(), vec![owner.clone()]),
            (reader.clone(), Vec::new()),
        ] {
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: true,
                    is_superuser: false,
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to,
                },
            );
        }
        cache.insert_baseline(
            table_id.clone(),
            RelationState::new(
                table_id,
                owner.clone(),
                0,
                Some(1),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
        engine
            .analyze(
                "GRANT SELECT ON cascade_grant_table TO grant_delegate WITH GRANT OPTION; SET ROLE grant_delegate; GRANT SELECT ON cascade_grant_table TO grant_reader WITH GRANT OPTION; SET ROLE grant_owner;",
                &mut state,
            )
            .unwrap();
        let violations = engine
            .analyze(
                "REVOKE SELECT ON cascade_grant_table FROM grant_delegate CASCADE;",
                &mut state,
            )
            .unwrap();
        assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
        let RelationOverlay::Present(relation) = state
            .get_relation(&object_id("public", "cascade_grant_table"))
            .unwrap()
        else {
            panic!("relation missing");
        };
        assert!(
            !relation
                .privileges
                .has_privilege(&delegate, Privilege::Select)
        );
        assert!(
            !relation
                .privileges
                .has_privilege(&reader, Privilege::Select)
        );
    }

    #[test]
    fn test_revoke_all_cascade_removes_privileges_and_downstream_grants() {
        use safe_migrate::_internal::model::role::RoleState;

        let engine = setup_engine();
        let mut cache = crate::_internal::db::cache::DbCache::new();
        let table_id = object_id("public", "revoke_all_table");
        let owner = object_id("", "owner");
        let intermediate = object_id("", "intermediate");
        let leaf = object_id("", "leaf");

        cache.metadata.source_session_role = Some("owner".into());
        for (id, can_set_role_to) in [
            (owner.clone(), vec![intermediate.clone()]),
            (intermediate.clone(), vec![owner.clone()]),
            (leaf.clone(), Vec::new()),
        ] {
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: true,
                    is_superuser: false,
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to,
                },
            );
        }
        cache.insert_baseline(
            table_id.clone(),
            RelationState::new(
                table_id.clone(),
                owner.clone(),
                0,
                Some(1),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
        engine
            .analyze(
                "GRANT SELECT, UPDATE ON revoke_all_table TO intermediate WITH GRANT OPTION; SET ROLE intermediate; GRANT SELECT ON revoke_all_table TO leaf; SET ROLE owner;",
                &mut state,
            )
            .unwrap();

        let relation = match state.get_relation(&table_id).unwrap() {
            RelationOverlay::Present(r) => r,
            _ => panic!("relation missing"),
        };
        assert!(
            relation
                .privileges
                .has_privilege(&intermediate, Privilege::Select)
        );
        assert!(
            relation
                .privileges
                .has_privilege(&intermediate, Privilege::Update)
        );
        assert!(relation.privileges.has_privilege(&leaf, Privilege::Select));

        let violations = engine
            .analyze(
                "REVOKE ALL ON revoke_all_table FROM intermediate CASCADE;",
                &mut state,
            )
            .unwrap();
        assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));

        let relation = match state.get_relation(&table_id).unwrap() {
            RelationOverlay::Present(r) => r,
            _ => panic!("relation missing"),
        };

        assert!(
            !relation
                .privileges
                .has_privilege(&intermediate, Privilege::Select)
        );
        assert!(
            !relation
                .privileges
                .has_privilege(&intermediate, Privilege::Update)
        );
        assert!(!relation.privileges.has_privilege(&leaf, Privilege::Select));
    }

    #[test]
    fn test_state_hydrates_and_disables_trigger() {
        use safe_migrate::_internal::db::cache::TriggerCache;
        use safe_migrate::_internal::model::trigger::{TriggerEnableMode, TriggerOverlay};

        let engine = setup_engine();
        let mut cache = cache_with_table("public", "test_table", None);
        cache.triggers.push(TriggerCache {
            trigger_id: object_id("public", "check_trigger"),
            table_id: object_id("public", "test_table"),
            function_id: object_id("public", "check_row()"),
            row_level: true,
            parent_trigger_id: None,
            enabled_mode: TriggerEnableMode::Origin,
        });
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
        use safe_migrate::_internal::model::function::{FunctionOverlay, Volatility};

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
        use safe_migrate::_internal::model::constraint::ConstraintKind;

        let engine = setup_engine();
        let mut cache = cache_with_table("public", "t_large", None);
        cache
            .relations
            .get_mut(&object_id("public", "t_large"))
            .expect("baseline table")
            .columns
            .push(Column {
                name: "id".to_string(),
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
                generated: None,
            });
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
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
        assert!(state.local.graph.edges().iter().any(|edge| {
            matches!(
                &edge.kind,
                safe_migrate::_internal::analysis::graph::DependencyKind::ConstraintDependency {
                    constraint_name,
                    columns,
                } if constraint_name == "positive_id" && columns == &["id".to_string()]
            )
        }));
    }

    #[test]
    fn cached_check_dependency_blocks_drop_without_cascade_and_cleans_up_with_cascade() {
        let engine = setup_engine();
        let table = object_id("public", "accounts");
        let mut cache = cache_with_table("public", "accounts", None);
        cache
            .relations
            .get_mut(&table)
            .expect("baseline table")
            .columns
            .extend([
                Column {
                    name: "id".to_string(),
                    data_type: Some("integer".to_string()),
                    type_id: None,
                    is_nullable: false,
                    default: None,
                    avg_width: None,
                    default_expr_text: None,
                    type_modifier: Some(-1),
                    storage: None,
                    compression: None,
                    statistics_target: None,
                    options: Default::default(),
                    generated: None,
                },
                Column {
                    name: "note".to_string(),
                    data_type: Some("text".to_string()),
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
                    generated: None,
                },
            ]);
        cache.constraints.push(
            safe_migrate::_internal::model::constraint::ConstraintState {
                table_id: table.clone(),
                name: "accounts_note_check".to_string(),
                kind: ConstraintKind::Check,
                validated: true,
                definition: Some("note IS NOT NULL".to_string()),
                backing_index: None,
            },
        );
        cache
            .constraint_dependencies
            .push(ConstraintDependencyCache {
                table_id: table.clone(),
                constraint_name: "accounts_note_check".to_string(),
                columns: vec!["note".to_string()],
            });

        let mut drop_constraint_state =
            crate::_internal::analysis::state::AnalysisState::new(cache.clone());
        engine
            .analyze(
                "ALTER TABLE accounts DROP CONSTRAINT accounts_note_check;",
                &mut drop_constraint_state,
            )
            .unwrap();
        assert!(
            !drop_constraint_state
                .local
                .graph
                .edges()
                .iter()
                .any(|edge| {
                    matches!(
                        edge.kind,
                        DependencyKind::ConstraintDependency { ref constraint_name, .. }
                            if constraint_name == "accounts_note_check"
                    )
                })
        );

        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache.clone());
        let findings = engine
            .analyze("ALTER TABLE accounts DROP COLUMN note;", &mut state)
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        assert!(matches!(
            state.get_relation(&table),
            Some(RelationOverlay::Present(relation)) if relation.has_column("note")
        ));

        let mut cascade_state = crate::_internal::analysis::state::AnalysisState::new(cache);
        let findings = engine
            .analyze(
                "ALTER TABLE accounts DROP COLUMN note CASCADE;",
                &mut cascade_state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        assert!(!matches!(
            cascade_state.get_relation(&table),
            Some(RelationOverlay::Present(relation)) if relation.has_column("note")
        ));
        assert!(
            !cascade_state
                .local
                .constraints
                .contains_key(&(table, "accounts_note_check".to_string()))
        );
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
                using_method: "btree".to_string(),
                key_columns: vec!["derived".to_string()],
                included_columns: Vec::new(),
                dependency_columns: vec!["derived".to_string()],
                dependency_columns_known: true,
                has_expression_keys: false,
                has_predicate: false,
                is_unique: false,
                is_immediate: true,
                is_valid: true,
                is_ready: true,
                is_live: true,
                has_default_sort_order: true,
                has_default_opclasses: true,
                has_default_collations: true,
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
    fn standalone_default_sequence_is_a_drop_dependency() {
        let engine = setup_engine();
        let table = object_id("public", "events");
        let sequence = object_id("public", "event_seq");
        let mut cache = cache_with_table("public", "events", None);
        cache
            .relations
            .get_mut(&table)
            .expect("baseline table")
            .columns
            .push(Column {
                name: "event_id".to_string(),
                data_type: Some("integer".to_string()),
                type_id: None,
                is_nullable: true,
                default: None,
                avg_width: None,
                default_expr_text: Some("nextval('public.event_seq'::regclass)".to_string()),
                type_modifier: Some(-1),
                storage: None,
                compression: None,
                statistics_target: None,
                options: Default::default(),
                generated: None,
            });
        cache.sequences.insert(
            sequence.clone(),
            SequenceState {
                id: sequence.clone(),
                owner: object_id("public", "postgres"),
                owned_by: None,
                kind: SequenceKind::Standalone,
                parameters: Default::default(),
                generation: 0,
            },
        );
        cache.default_sequence_dependencies.push(
            safe_migrate::_internal::db::cache::DefaultSequenceDependencyCache {
                table_id: table.clone(),
                column_name: "event_id".to_string(),
                sequence_id: sequence.clone(),
            },
        );

        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache.clone());
        let findings = engine
            .analyze("DROP SEQUENCE event_seq;", &mut state)
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );

        let mut cascade_state =
            crate::_internal::analysis::state::AnalysisState::new(cache.clone());
        let findings = engine
            .analyze("DROP SEQUENCE event_seq CASCADE;", &mut cascade_state)
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        assert!(
            !cascade_state.local.graph.edges().iter().any(|edge| {
                matches!(edge.kind, DependencyKind::ColumnDefaultOnSequence { .. })
            })
        );
        assert!(matches!(
            cascade_state.get_relation(&table),
            Some(RelationOverlay::Present(relation))
                if relation
                    .get_column("event_id")
                    .is_some_and(|column| column.default_expr_text.is_none())
        ));

        let mut table_drop_state =
            crate::_internal::analysis::state::AnalysisState::new(cache.clone());
        let findings = engine
            .analyze("DROP TABLE events;", &mut table_drop_state)
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        assert!(matches!(
            table_drop_state.local.sequences.get(&sequence),
            Some(SequenceOverlay::Present(_))
        ));
        assert!(
            !table_drop_state.local.graph.edges().iter().any(|edge| {
                matches!(edge.kind, DependencyKind::ColumnDefaultOnSequence { .. })
            })
        );
        // An unqualified regclass rendering is interpreted through PostgreSQL's
        // search path. The typed catalog edge, rather than this text, must
        // decide which same-named sequence owns the default.
        let alternate_sequence = object_id("tenant", "event_seq");
        let mut same_name_cache = cache.clone();
        same_name_cache.sequences.insert(
            alternate_sequence.clone(),
            SequenceState {
                id: alternate_sequence.clone(),
                owner: object_id("public", "postgres"),
                owned_by: None,
                kind: SequenceKind::Standalone,
                parameters: Default::default(),
                generation: 0,
            },
        );
        same_name_cache.default_sequence_dependencies.clear();
        same_name_cache.default_sequence_dependencies.push(
            safe_migrate::_internal::db::cache::DefaultSequenceDependencyCache {
                table_id: table.clone(),
                column_name: "event_id".to_string(),
                sequence_id: alternate_sequence,
            },
        );
        let column = same_name_cache
            .relations
            .get_mut(&table)
            .expect("baseline table")
            .columns
            .iter_mut()
            .find(|column| column.name == "event_id")
            .expect("baseline column");
        column.default_expr_text = Some("nextval('event_seq'::regclass)".to_string());
        let mut same_name_state =
            crate::_internal::analysis::state::AnalysisState::new(same_name_cache);
        engine
            .analyze(
                "DROP SEQUENCE public.event_seq CASCADE;",
                &mut same_name_state,
            )
            .unwrap();
        assert!(matches!(
            same_name_state.get_relation(&table),
            Some(RelationOverlay::Present(relation))
                if relation.get_column("event_id").is_some_and(|column| column.default_expr_text.is_some())
        ));

        let mut rollback_state = crate::_internal::analysis::state::AnalysisState::new(cache);
        engine
            .analyze("BEGIN; DROP TABLE events; ROLLBACK;", &mut rollback_state)
            .unwrap();
        assert!(rollback_state.relation_is_present(&table));
        assert!(rollback_state.local.graph.edges().iter().any(|edge| {
            matches!(
                edge.kind,
                DependencyKind::ColumnDefaultOnSequence { ref column } if column == "event_id"
            ) && edge.dependent == table
                && edge.referenced == sequence
        }));
    }
    #[test]
    fn rename_table_updates_column_default_sequence_dependency() {
        let engine = setup_engine();
        let mut state = setup_state();
        let seq_id = object_id("public", "test_seq");
        engine
            .analyze("CREATE SEQUENCE public.test_seq;", &mut state)
            .unwrap();
        let table_id = object_id("public", "test_table");
        engine
            .analyze("CREATE TABLE public.test_table (id INT);", &mut state)
            .unwrap();

        state.local.graph.add_edge(DependencyEdge {
            dependent: table_id.clone(),
            referenced: seq_id.clone(),
            kind: DependencyKind::ColumnDefaultOnSequence {
                column: "id".to_string(),
            },
        });

        assert!(state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::ColumnDefaultOnSequence { .. })
                && edge.dependent == table_id
                && edge.referenced == seq_id
        }));

        let new_table_id = object_id("public", "new_table");
        engine
            .analyze(
                "ALTER TABLE public.test_table RENAME TO new_table;",
                &mut state,
            )
            .unwrap();

        assert!(state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::ColumnDefaultOnSequence { .. })
                && edge.dependent == new_table_id
                && edge.referenced == seq_id
        }));

        // Assert the old table is no longer present as dependent
        assert!(!state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::ColumnDefaultOnSequence { .. })
                && edge.dependent == table_id
                && edge.referenced == seq_id
        }));
    }

    #[test]
    fn create_sequence_applies_all_catalog_parameters() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE UNLOGGED SEQUENCE public.parameterized_seq AS integer \
                 INCREMENT BY -3 MINVALUE -99 MAXVALUE -3 START WITH -3 CACHE 7 CYCLE;",
                &mut state,
            )
            .unwrap();

        let id = object_id("public", "parameterized_seq");
        let Some(SequenceOverlay::Present(sequence)) = state.local.sequences.get(&id) else {
            panic!("sequence was not created");
        };
        assert_eq!(sequence.parameters.data_type, "integer");
        assert_eq!(sequence.parameters.increment, -3);
        assert_eq!(sequence.parameters.min_value, -99);
        assert_eq!(sequence.parameters.max_value, -3);
        assert_eq!(sequence.parameters.start_value, -3);
        assert_eq!(sequence.parameters.cache_size, 7);
        assert!(sequence.parameters.cycle);
        assert_eq!(
            sequence.parameters.persistence,
            safe_migrate::_internal::model::sequence::SequencePersistence::Unlogged
        );
    }

    #[test]
    fn test_state_adds_named_unique_constraint() {
        use safe_migrate::_internal::model::constraint::ConstraintKind;

        let engine = setup_engine();
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache_with_table(
            "public", "t_large", None,
        ));
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
        use safe_migrate::_internal::model::function::FunctionOverlay;
        use safe_migrate::_internal::model::trigger::TriggerOverlay;

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
        use safe_migrate::_internal::model::trigger::{TriggerEnableMode, TriggerOverlay};

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
        use safe_migrate::_internal::db::cache::DbCache;
        use safe_migrate::_internal::model::function::{
            FunctionOverlay, FunctionState, SecurityMode, Volatility,
        };

        let engine = setup_engine();
        let function_id = object_id("public", "f_safe(integer[])");
        let mut cache = DbCache::new();
        cache.functions.insert(
            function_id.clone(),
            FunctionState {
                id: function_id.clone(),
                routine_kind: safe_migrate::_internal::model::function::RoutineKind::Function,
                arg_types: vec!["integer[]".to_string()],
                arg_type_ids: vec![None],
                return_type: "integer".to_string(),
                return_type_id: None,
                volatility: Volatility::Volatile,
                language: "sql".to_string(),
                security: SecurityMode::Invoker,
            },
        );
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
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
        assert!(state.local.pending_validation.contains(&key));

        engine
            .analyze(
                "ALTER TABLE child VALIDATE CONSTRAINT child_parent_fk;",
                &mut state,
            )
            .unwrap();
        assert!(state.local.constraints[&key].validated);
        assert!(!state.local.pending_validation.contains(&key));
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
    fn create_table_records_inline_foreign_key_check_and_exclusion_constraints() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE parent (id integer PRIMARY KEY);
                 CREATE TABLE reservations (
                    id integer,
                    parent_id integer,
                    period int4range,
                    CONSTRAINT reservations_parent_fk
                        FOREIGN KEY (parent_id) REFERENCES parent(id),
                    CONSTRAINT reservations_id_check CHECK (id > 0),
                    CONSTRAINT reservations_period_excl
                        EXCLUDE USING gist (period WITH &&)
                 );",
                &mut state,
            )
            .unwrap();

        let table = object_id("public", "reservations");
        for (name, kind) in [
            ("reservations_parent_fk", ConstraintKind::ForeignKey),
            ("reservations_id_check", ConstraintKind::Check),
            ("reservations_period_excl", ConstraintKind::Exclusion),
        ] {
            assert_eq!(
                state
                    .local
                    .constraints
                    .get(&(table.clone(), name.to_string()))
                    .map(|constraint| constraint.kind),
                Some(kind),
                "missing inline constraint {name}"
            );
        }
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.dependent == table
                && matches!(
                    edge.kind,
                    DependencyKind::ForeignKey {
                        constraint_name: Some(ref name),
                        ..
                    } if name == "reservations_parent_fk"
                )
        }));
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
    fn generated_check_names_avoid_other_tables_in_same_schema() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE SCHEMA other;
             CREATE TABLE other.holder (id integer
                 CONSTRAINT target_id_check CHECK (id > 0)
                 CONSTRAINT target_id_check1 CHECK (id < 100));
             CREATE TABLE public.holder (id integer CONSTRAINT target_id_check CHECK (id > 0));
             CREATE TABLE public.target (id integer CHECK (id > 0));
             CREATE TABLE other.target (id integer CHECK (id > 0));",
                &mut state,
            )
            .unwrap();
        for (schema, name) in [
            ("public", "target_id_check1"),
            ("other", "target_id_check2"),
        ] {
            assert!(
                state
                    .local
                    .constraints
                    .contains_key(&(object_id(schema, "target"), name.into()))
            );
        }
    }

    #[test]
    fn check_names_use_one_distinct_column_for_create_and_alter() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE check_names (id integer, other integer,
                CHECK (id > 0 AND id < 100), CHECK (id < other));
             ALTER TABLE check_names ADD CHECK (id > 1 AND id < 99);",
                &mut state,
            )
            .unwrap();
        let table = object_id("public", "check_names");
        for name in [
            "check_names_id_check",
            "check_names_check",
            "check_names_id_check1",
        ] {
            assert!(
                state
                    .local
                    .constraints
                    .contains_key(&(table.clone(), name.into())),
                "missing {name}"
            );
        }
        let findings = engine
            .analyze(
                "ALTER TABLE check_names DROP CONSTRAINT check_names_id_check1;
             ALTER TABLE check_names RENAME CONSTRAINT check_names_id_check TO bounded_id;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "{findings:?}"
        );
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
        relation
            .columns
            .push(safe_migrate::_internal::model::column::Column {
                name: "period".to_string(),
                data_type: Some("int4range".to_string()),
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
            });
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id, relation);
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
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
    fn role_inherit_option_is_preserved_across_create_and_alter() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE ROLE no_inherit NOINHERIT;
                 ALTER ROLE no_inherit INHERIT;",
                &mut state,
            )
            .unwrap();

        let role_id = object_id("", "no_inherit");
        let RoleOverlay::Present(role) = state.local.roles.get(&role_id).unwrap() else {
            panic!("expected role to be present");
        };
        assert!(role.inherits);
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
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
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
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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

    #[test]
    fn alter_table_owner_moves_owned_sequence_owner() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        let table = object_id("public", "owned_table");
        let sequence = object_id("public", "owned_table_id_seq");
        cache.insert_baseline(
            table.clone(),
            RelationState::new(
                table.clone(),
                object_id("", "old_owner"),
                0,
                None,
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        cache.sequences.insert(
            sequence.clone(),
            SequenceState {
                id: sequence.clone(),
                owner: object_id("", "old_owner"),
                owned_by: Some((table.clone(), "id".into())),
                kind: SequenceKind::Owned,
                parameters: Default::default(),
                generation: 0,
            },
        );
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        engine
            .analyze(
                "ALTER TABLE public.owned_table OWNER TO new_owner;",
                &mut state,
            )
            .unwrap();

        let SequenceOverlay::Present(sequence_state) =
            state.local.sequences.get(&sequence).unwrap()
        else {
            panic!("owned sequence missing");
        };
        assert_eq!(sequence_state.owner, object_id("", "new_owner"));
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
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
                    inherits: true,
                    member_of: can_set_role_to.clone(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to,
                },
            );
        }
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

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
                    inherits: true,
                    member_of,
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let violations = engine.analyze("SET ROLE target;", &mut state).unwrap();

        assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
        assert_eq!(state.local.current_role, "member");
    }

    #[test]
    fn grant_set_option_authorizes_set_role_and_revoke_removes_it() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some("member".into());
        cache.metadata.source_session_role = Some("member".into());
        for name in ["member", "parent"] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: name == "member",
                    is_superuser: false,
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: vec![object_id("", "parent")],
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let violations = engine
            .analyze("GRANT parent TO member; SET ROLE parent;", &mut state)
            .unwrap();
        assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
        assert_eq!(state.local.current_role, "parent");

        let violations = engine
            .analyze(
                "GRANT parent TO member WITH SET TRUE; SET ROLE parent;",
                &mut state,
            )
            .unwrap();
        assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
        assert_eq!(state.local.current_role, "parent");

        let violations = engine
            .analyze(
                "SET ROLE member; REVOKE SET OPTION FOR parent FROM member;",
                &mut state,
            )
            .unwrap();
        assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
        assert_eq!(state.local.current_role, "member");

        let violations = engine.analyze("SET ROLE parent;", &mut state).unwrap();
        assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
        assert_eq!(state.local.current_role, "member");

        let violations = engine
            .analyze(
                "BEGIN; GRANT parent TO member WITH SET TRUE; ROLLBACK; SET ROLE parent;",
                &mut state,
            )
            .unwrap();
        assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
        assert_eq!(state.local.current_role, "member");
    }

    #[test]
    fn role_membership_admin_and_inherit_options_round_trip() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        for name in ["member", "parent"] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: false,
                    is_superuser: false,
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let violations = engine
            .analyze(
                "GRANT parent TO member WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;",
                &mut state,
            )
            .unwrap();
        assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
        let RoleOverlay::Present(role) = state.local.roles.get(&object_id("", "member")).unwrap()
        else {
            panic!("member role unexpectedly dropped");
        };
        assert_eq!(role.member_of, vec![object_id("", "parent")]);
        assert_eq!(
            role.can_administer_membership,
            vec![object_id("", "parent")]
        );
        assert!(role.can_inherit_from.is_empty());
        assert!(role.can_set_role_to.is_empty());

        engine
            .analyze("REVOKE ADMIN OPTION FOR parent FROM member;", &mut state)
            .unwrap();
        let RoleOverlay::Present(role) = state.local.roles.get(&object_id("", "member")).unwrap()
        else {
            panic!("member role unexpectedly dropped");
        };
        assert!(role.can_administer_membership.is_empty());
        assert_eq!(role.member_of, vec![object_id("", "parent")]);
    }

    #[test]
    fn role_membership_revoke_cascade_removes_dependent_grants() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some("admin".into());
        cache.metadata.source_session_role = Some("admin".into());
        for name in ["admin", "parent", "member", "child"] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: true,
                    is_superuser: false,
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let parent = object_id("", "parent");
        let member = object_id("", "member");
        cache
            .roles
            .get_mut(&object_id("", "admin"))
            .unwrap()
            .member_of = vec![parent.clone()];
        cache
            .roles
            .get_mut(&object_id("", "admin"))
            .unwrap()
            .can_administer_membership = vec![parent.clone()];
        cache.roles.get_mut(&member).unwrap().member_of = vec![parent.clone()];
        cache
            .roles
            .get_mut(&member)
            .unwrap()
            .can_administer_membership = vec![parent.clone()];
        cache.role_membership_grantors.push(
            safe_migrate::_internal::model::role::RoleMembershipGrantor {
                member: member.clone(),
                role: parent.clone(),
                grantor: object_id("", "admin"),
                admin: false,
                inherit: true,
                set: true,
            },
        );
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        engine
            .analyze(
                "GRANT parent TO child GRANTED BY member; \
                 GRANT parent TO child GRANTED BY admin; \
                 REVOKE parent FROM member CASCADE;",
                &mut state,
            )
            .unwrap();
        let RoleOverlay::Present(child) = state.local.roles.get(&object_id("", "child")).unwrap()
        else {
            panic!("child role unexpectedly dropped");
        };
        assert!(!child.member_of.contains(&parent));
    }

    #[test]
    fn role_grant_to_public_is_rejected_before_partial_mutation() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        for name in ["member", "parent"] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: false,
                    is_superuser: false,
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
        let result = engine.analyze("GRANT parent TO member, PUBLIC WITH SET TRUE;", &mut state);
        assert!(result.is_ok());
        let role = state
            .local
            .roles
            .get(&object_id("", "member"))
            .expect("member role");
        let RoleOverlay::Present(role) = role else {
            panic!("member role unexpectedly dropped");
        };
        assert!(role.member_of.is_empty());
        assert!(role.can_set_role_to.is_empty());
    }

    #[test]
    fn role_grant_rejects_cycles_before_mutating_the_batch() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        for name in ["role_a", "role_b"] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: false,
                    is_superuser: false,
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
        let _ = engine
            .analyze("GRANT role_a, role_b TO role_b, role_a;", &mut state)
            .unwrap();
        for name in ["role_a", "role_b"] {
            let role = state.local.roles.get(&object_id("", name)).unwrap();
            let RoleOverlay::Present(role) = role else {
                panic!("role unexpectedly dropped");
            };
            assert!(role.member_of.is_empty());
        }
    }

    #[test]
    fn rollback_restores_every_destructively_rewritten_graph_edge() {
        let engine = setup_engine();
        let mut state = setup_state();
        state.pg_version_num = Some(180_000);

        let findings = engine
            .analyze(
                "CREATE TABLE items (id integer NOT NULL);
                 CREATE INDEX items_idx ON items (id);
                 ALTER TABLE items ADD CONSTRAINT items_check CHECK (id > 0) NOT VALID;
                 CREATE TABLE parent (id integer) PARTITION BY RANGE (id);
                 CREATE TABLE child PARTITION OF parent FOR VALUES FROM (0) TO (10);
                 BEGIN;
                 DROP INDEX items_idx;
                 ALTER TABLE items DROP CONSTRAINT items_check;
                 ALTER TABLE items ALTER COLUMN id DROP NOT NULL;
                 ALTER TABLE parent DETACH PARTITION child;
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "rollback setup unexpectedly conflicted: {findings:?}"
        );

        let items = object_id("public", "items");
        let index = object_id("public", "items_idx");
        let parent = object_id("public", "parent");
        let child = object_id("public", "child");
        assert!(matches!(
            state.get_relation(&child),
            Some(RelationOverlay::Present(relation)) if relation.has_column("id")
        ));
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.dependent == index
                && edge.referenced == items
                && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
        }));
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.dependent == items
                && matches!(
                    &edge.kind,
                    DependencyKind::ConstraintDependency {
                        constraint_name,
                        ..
                    } if constraint_name == "items_check"
                )
        }));
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.dependent == items
                && matches!(
                    &edge.kind,
                    DependencyKind::ConstraintOnRelation {
                        columns,
                        is_primary: false,
                        ..
                    } if columns == &["id"]
                )
        }));
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.dependent == child
                && edge.referenced == parent
                && matches!(edge.kind, DependencyKind::PartitionOf)
        }));
    }

    #[test]
    fn alter_rule_modes_validate_catalog_identity_and_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        let table_id = object_id("public", "events");
        engine
            .analyze("CREATE TABLE events (id integer);", &mut state)
            .unwrap();
        let Some(RelationOverlay::Present(relation)) = state.local.relations.get_mut(&table_id)
        else {
            panic!("created relation missing from state")
        };
        relation.rules.insert(
            "rewrite_rule".to_string(),
            safe_migrate::_internal::model::relation::RuleEnableMode::Origin,
        );

        let findings = engine
            .analyze(
                "ALTER TABLE events ENABLE REPLICA RULE rewrite_rule;
                 ALTER TABLE events ENABLE ALWAYS RULE rewrite_rule;
                 BEGIN;
                 ALTER TABLE events DISABLE RULE rewrite_rule;
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "valid rule mode changes unexpectedly conflicted: {findings:?}"
        );
        let Some(RelationOverlay::Present(relation)) = state.local.relations.get(&table_id) else {
            panic!("relation missing after rule mode rollback")
        };
        assert_eq!(
            relation.rules.get("rewrite_rule"),
            Some(&safe_migrate::_internal::model::relation::RuleEnableMode::Always)
        );

        let findings = engine
            .analyze("ALTER TABLE events ENABLE RULE missing_rule;", &mut state)
            .unwrap();
        assert!(findings.iter().any(|finding| {
            finding.rule_id == "chain-conflict"
                && finding
                    .reason
                    .contains("rule 'missing_rule' does not exist")
        }));
    }
}
