use super::*;

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
                            definition: IndexDefinition { unique: true, .. },
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
            definition: IndexDefinition {
                expression_keys: 1,
                ..
            },
            dependency_columns_known: false,
            eligibility_known: true,
            ..
        }
    ));
}

#[test]
fn cached_expression_index_dependencies_follow_the_referenced_columns() {
    let table_id = object_id("public", "t");
    let index_id = object_id("public", "t_lower_note_idx");
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
            definition: IndexDefinition {
                method: Some("btree".into()),
                keys: index_keys(Vec::new()),
                included: index_keys(Vec::new()),
                expression_keys: 1,
                unique: false,
                nulls_not_distinct: Some(false),
                predicate: IndexPredicate::None,
                unestablished: false,
                valid: true,
                ready: true,
                live: true,
            },
            dependency_columns: vec!["note".to_string()],
            dependency_columns_known: true,
            is_immediate: true,
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
        matches!(edge.kind, DependencyKind::IndexOnRelation { .. }) && edge.dependent == index_id
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
        matches!(edge.kind, DependencyKind::IndexOnRelation { .. }) && edge.dependent == index_id
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
fn create_index_validates_key_and_include_columns() {
    let engine = setup_engine();
    let reason = |sql: &str| {
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .expect("the statement should analyze")
            .into_iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason)
            .next()
            .unwrap_or_default()
    };

    // PostgreSQL looks every key and INCLUDE column up by name.
    assert!(
        reason("CREATE TABLE t (a int); CREATE INDEX i ON t (nosuch);")
            .contains("column \"nosuch\" does not exist"),
        "an unknown key column must be rejected"
    );
    assert!(
        reason("CREATE TABLE t (a int); CREATE INDEX i ON t (a) INCLUDE (nosuch);")
            .contains("column \"nosuch\" does not exist"),
        "an unknown INCLUDE column must be rejected"
    );
    // An expression key is typed rather than looked up, so it is not a
    // column-existence question.
    assert_eq!(
        reason("CREATE TABLE t (a int); CREATE INDEX i ON t ((a + 1));"),
        ""
    );
    assert_eq!(
        reason("CREATE TABLE t (a int, b int); CREATE INDEX i ON t (a) INCLUDE (b);"),
        ""
    );
}

#[test]
fn create_index_skips_column_checks_when_the_relation_columns_are_unknown() {
    let engine = setup_engine();
    let reason = |sql: &str| {
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .expect("the statement should analyze")
            .into_iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason)
            .next()
            .unwrap_or_default()
    };

    // PostgreSQL accepted this index; an unresolved projection leaves the
    // columns unknown.
    assert_eq!(
        reason(
            "CREATE MATERIALIZED VIEW mv AS SELECT * FROM generate_series(1,10) AS g(id);
                 CREATE INDEX i ON mv (id);"
        ),
        ""
    );
    // A `CREATE TABLE AS` keeps only the columns it could resolve.
    assert_eq!(
        reason(
            "CREATE TABLE t AS SELECT 1 AS id, 'x'::text AS label; CREATE INDEX i ON t (label);"
        ),
        ""
    );
    assert_eq!(
        reason(
            "CREATE TABLE t AS SELECT * FROM generate_series(1,5) AS g(id);
                 CREATE INDEX i ON t (id);"
        ),
        ""
    );
    // Incompleteness propagates through inheritance.
    assert_eq!(
        reason(
            "CREATE TABLE t AS SELECT 1 AS id;
                 CREATE TABLE c () INHERITS (t);
                 CREATE INDEX i ON c (id);"
        ),
        ""
    );
    // A known-complete column list still rejects an impossible column.
    assert!(
        reason("CREATE TABLE t (); CREATE INDEX i ON t (nosuch);")
            .contains("column \"nosuch\" does not exist"),
        "a complete column list cannot excuse an unknown column"
    );
}

#[test]
fn create_index_if_not_exists_skips_a_name_held_by_another_relation() {
    let engine = setup_engine();
    let reason = |sql: &str| {
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .expect("the statement should analyze")
            .into_iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason)
            .next()
            .unwrap_or_default()
    };

    // The guard covers the whole name, not only an index of that name.
    assert_eq!(
        reason(
            "CREATE TABLE t (a int);
                 CREATE TABLE dup (a int);
                 CREATE INDEX IF NOT EXISTS dup ON t (a);"
        ),
        ""
    );
    assert!(
        reason(
            "CREATE TABLE t (a int);
                 CREATE TABLE dup (a int);
                 CREATE INDEX dup ON t (a);"
        )
        .contains("relation 'public.dup' already exists"),
        "without the guard a same-name relation is a conflict"
    );
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
fn alter_index_set_statistics_matches_postgres_acceptance() {
    let cases = [
        (
            "ALTER INDEX idx_plain ALTER COLUMN 1 SET STATISTICS 100;",
            true,
            "non-expression column",
        ),
        (
            "ALTER INDEX idx_expr ALTER COLUMN 1 SET STATISTICS 100;",
            false,
            "",
        ),
        (
            "ALTER INDEX idx_plain ALTER COLUMN 1 SET STATISTICS 10001;",
            false,
            "",
        ),
        (
            "ALTER INDEX idx_plain ALTER COLUMN 1 SET STATISTICS -2;",
            true,
            "is too low",
        ),
        (
            "ALTER INDEX idx_expr ALTER COLUMN 1 SET STATISTICS -1;",
            false,
            "",
        ),
    ];

    for (statement, expect_conflict, reason) in cases {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE st (a int, b text);
                     CREATE INDEX idx_plain ON st (a);
                     CREATE INDEX idx_expr ON st (lower(b));",
                &mut state,
            )
            .unwrap();
        let findings = engine.analyze(statement, &mut state).unwrap();

        let conflict = findings
            .iter()
            .find(|finding| finding.rule_id == "chain-conflict" && finding.reason.contains(reason));
        assert_eq!(
            conflict.is_some(),
            expect_conflict,
            "unexpected result for {statement}: {findings:?}"
        );
    }
}

#[test]
fn alter_index_set_statistics_column_number_is_parsed() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE st (a int, b text);
                 CREATE INDEX idx_expr ON st (lower(b));
                 ALTER INDEX idx_expr ALTER COLUMN 1 SET STATISTICS 250;",
            &mut state,
        )
        .unwrap();

    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "a column number must be recognized, not parsed as no column: {findings:?}"
    );
}

#[test]
fn dropping_a_partitioned_index_drops_its_attached_child() {
    // PostgreSQL removes an attached partition index with its parent, so
    // dropping the child afterwards must fail.
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE parent_tbl (a int) PARTITION BY RANGE (a);
                 CREATE TABLE child_tbl (a int);
                 CREATE INDEX child_idx ON child_tbl (a);
                 CREATE INDEX parent_idx ON parent_tbl (a);
                 ALTER TABLE parent_tbl ATTACH PARTITION child_tbl FOR VALUES FROM (0) TO (10);
                 ALTER INDEX parent_idx ATTACH PARTITION child_idx;
                 DROP INDEX parent_idx;
                 DROP INDEX child_idx;",
            &mut state,
        )
        .unwrap();

    assert!(
        findings.iter().any(|finding| {
            finding.rule_id == "chain-conflict"
                && finding.reason.contains("does not exist")
                && finding.reason.contains("child_idx")
        }),
        "the child index is gone with its parent: {findings:?}"
    );
}

#[test]
fn dropping_an_unattached_index_leaves_others_alone() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE t (a int);
                 CREATE INDEX keep_idx ON t (a);
                 CREATE INDEX drop_idx ON t (a);
                 DROP INDEX drop_idx;
                 DROP INDEX keep_idx;",
            &mut state,
        )
        .unwrap();

    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "an unrelated index must survive its neighbour's drop: {findings:?}"
    );
}

#[test]
fn attaching_a_mismatched_index_partition_is_refused() {
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text, d text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text, d text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_b ON c (b);
             CREATE INDEX p_d ON ONLY p (d);
             ALTER INDEX p_d ATTACH PARTITION c_b;",
    );
    // PostgreSQL: "cannot attach index ... the index definitions do not match"
    assert!(
        !state
            .local
            .graph
            .edges()
            .iter()
            .any(|edge| matches!(edge.kind, DependencyKind::IndexPartitionOf))
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation.reason.contains("index definitions do not match")),
        "expected a definition mismatch, got {violations:?}"
    );
}

#[test]
fn attaching_an_index_from_a_non_partition_is_refused() {
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer);
             CREATE TABLE elsewhere (a integer);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX elsewhere_a ON elsewhere (a);
             CREATE INDEX p_a ON ONLY p (a);
             ALTER INDEX p_a ATTACH PARTITION elsewhere_a;",
    );
    assert!(
        !state
            .local
            .graph
            .edges()
            .iter()
            .any(|edge| matches!(edge.kind, DependencyKind::IndexPartitionOf))
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation.reason.contains("not an index on any partition")),
        "expected a non-partition refusal, got {violations:?}"
    );
}

#[test]
fn attaching_a_matching_index_partition_is_accepted() {
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_b ON c (b);
             CREATE INDEX p_b ON p (b);
             ALTER INDEX p_b ATTACH PARTITION c_b;",
    );
    assert!(
        state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_b")
            && edge.referenced == object_id("public", "p_b")),
        "expected the attachment to be recorded, got {violations:?}"
    );
}

#[test]
fn attaching_an_index_with_a_different_opclass_is_refused() {
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_ops ON c (b varchar_pattern_ops);
             CREATE INDEX p_ops ON p (b varchar_pattern_ops);
             ALTER INDEX p_ops ATTACH PARTITION c_ops;
             CREATE INDEX c_plain ON c (b);
             CREATE INDEX p_plain ON p (b);",
    );
    // Sanity: the matching pair attaches.
    assert!(
        state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_ops")
            && edge.referenced == object_id("public", "p_ops")),
        "matching opclasses must attach, got {violations:?}"
    );
    // A default opclass against an explicit one must not.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_ops ON c (b varchar_pattern_ops);
             CREATE INDEX p_plain ON ONLY p (b);
             ALTER INDEX p_plain ATTACH PARTITION c_ops;",
    );
    assert!(
        !state
            .local
            .graph
            .edges()
            .iter()
            .any(|edge| matches!(edge.kind, DependencyKind::IndexPartitionOf)),
        "a differing opclass must not attach, got {violations:?}"
    );
}

#[test]
fn attaching_indexes_that_differ_only_in_sort_order_is_accepted() {
    // Verified live: `CompareIndexInfo` never reads `indoption`, so a
    // child whose key is written with the opposite direction attaches.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_desc ON c (b DESC);
             CREATE INDEX p_plain ON p (b);
             ALTER INDEX p_plain ATTACH PARTITION c_desc;",
    );
    assert!(
        state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_desc")
            && edge.referenced == object_id("public", "p_plain")),
        "a differing sort order must attach, got {violations:?}"
    );
}

#[test]
fn attaching_indexes_with_different_nulls_not_distinct_is_refused() {
    // Verified live: `CompareIndexInfo` compares `indnullsnotdistinct`;
    // equal settings attach and a mismatch is refused.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_nnd ON c (b) NULLS NOT DISTINCT;
             CREATE INDEX p_nnd ON p (b) NULLS NOT DISTINCT;
             ALTER INDEX p_nnd ATTACH PARTITION c_nnd;
             CREATE INDEX c_mix ON c (b) NULLS NOT DISTINCT;
             CREATE INDEX p_lenient ON ONLY p (b);
             ALTER INDEX p_lenient ATTACH PARTITION c_mix;",
    );
    assert!(
        state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_nnd")
            && edge.referenced == object_id("public", "p_nnd")),
        "matching NULLS NOT DISTINCT must attach, got {violations:?}"
    );
    assert!(
        !state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_mix")),
        "a differing NULLS NOT DISTINCT must not attach"
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation.reason.contains("index definitions do not match")),
        "expected a definition mismatch, got {violations:?}"
    );
}

#[test]
fn attaching_an_index_with_a_non_default_collation_is_undecidable() {
    // Live PostgreSQL refuses this pair — the child's key carries
    // collation OID 950 and the parent's the database default 100. The
    // simulator does not record a column's declared collation, so it
    // cannot prove the pair differs (a column declared `COLLATE "C"`
    // would make it one collation) and stays undecidable.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_c ON c (b COLLATE \"C\");
             CREATE INDEX p_plain ON ONLY p (b);
             ALTER INDEX p_plain ATTACH PARTITION c_c;",
    );
    assert!(
        !state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_c")),
        "a child with an unresolvable-relative collation must not attach"
    );
    assert_eq!(
        state.local.confidence,
        Confidence::Tainted,
        "got {violations:?}"
    );
}

#[test]
fn attaching_expression_indexes_matches_expression_identity() {
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_lower ON c (lower(b));
             CREATE INDEX p_lower ON ONLY p (lower(b));
             ALTER INDEX p_lower ATTACH PARTITION c_lower;
             CREATE INDEX c_upper ON c (upper(b));
             CREATE INDEX p_upper ON ONLY p (lower(b));
             ALTER INDEX p_upper ATTACH PARTITION c_upper;",
    );
    assert!(
        state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_lower")
            && edge.referenced == object_id("public", "p_lower")),
        "equal expressions must attach, got {violations:?}"
    );
    assert!(
        !state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_upper")),
        "different expressions must not attach"
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation.reason.contains("index definitions do not match")),
        "expected a definition mismatch, got {violations:?}"
    );
}

#[test]
fn an_exclusion_backed_child_index_leaves_attachment_undecidable() {
    // Live PostgreSQL refuses this pair because the child's backing index
    // carries exclusion operators the parent's does not. The constraint
    // marker records the key columns but not the operators, so the
    // simulator stays undecidable instead of claiming a mismatch it has
    // not established.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_b ON c (b);
             CREATE INDEX p_b ON ONLY p (b);
             ALTER TABLE c ADD CONSTRAINT c_excl EXCLUDE USING btree (b WITH =);
             ALTER INDEX p_b ATTACH PARTITION c_excl;",
    );
    assert!(
        !state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_excl")),
        "an exclusion-backed child must not attach to a plain parent"
    );
    assert_eq!(
        state.local.confidence,
        Confidence::Tainted,
        "got {violations:?}"
    );
}

#[test]
fn an_exclusion_backed_parent_index_leaves_attachment_undecidable() {
    // Live PostgreSQL refuses this pair because the parent's backing
    // constraint has no counterpart on the child. The simulator cannot
    // model the constraint rule on a shape it has not established, so the
    // outcome stays undecidable on both sides of the comparison.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_a ON c (a);
             ALTER TABLE p ADD CONSTRAINT p_excl EXCLUDE USING btree (a WITH =);
             ALTER INDEX p_excl ATTACH PARTITION c_a;",
    );
    assert!(
        !state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_a")),
        "a plain child must not attach to an exclusion-backed parent"
    );
    assert_eq!(
        state.local.confidence,
        Confidence::Tainted,
        "got {violations:?}"
    );
}

#[test]
fn a_synced_index_attaches_to_a_statement_created_parent() {
    // The catalog records the resolved opfamily (`text_ops`), and the
    // statement normalizes the omitted default to the same family, so a
    // synced child attaches to a statement-created parent.
    use safe_migrate::_internal::db::cache::{IndexCache, InheritanceCache};
    use safe_migrate::_internal::model::index::{
        IndexKey, IndexKeyKind, IndexOrder, KeyCollation, KeyOpclass, ResolvedName,
    };

    let engine = setup_engine();
    let mut cache = synced_cache();
    let parent_id = object_id("public", "p");
    let child_id = object_id("public", "c");
    let owner = object_id("public", "postgres");
    let synced_table = |id: &ObjectId| {
        let mut table = RelationState::new(
            id.clone(),
            owner.clone(),
            0,
            None,
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        table.columns.push(Column {
            name: "b".to_string(),
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
        });
        table
    };
    let mut parent = synced_table(&parent_id);
    parent.partition_type = Some("RANGE".to_string());
    parent.partition_by = Some("PARTITION BY RANGE (b)".to_string());
    cache.insert_baseline(parent_id.clone(), parent);
    cache.insert_baseline(child_id.clone(), synced_table(&child_id));
    cache.inheritances.push(InheritanceCache {
        child: child_id.clone(),
        parent: parent_id.clone(),
        sequence: 0,
        is_partition: true,
        detach_pending: false,
    });
    cache.indexes.push(IndexCache {
        index_id: object_id("public", "c_b"),
        table_id: child_id,
        definition: IndexDefinition {
            method: Some("btree".to_string()),
            keys: vec![IndexKey {
                kind: IndexKeyKind::Column("b".to_string()),
                opclass: KeyOpclass::Default(Some(ResolvedName {
                    schema: "pg_catalog".to_string(),
                    name: "text_ops".to_string(),
                })),
                collation: KeyCollation::Derived,
                order: IndexOrder::Default,
            }],
            included: Vec::new(),
            expression_keys: 0,
            unique: false,
            nulls_not_distinct: Some(false),
            predicate: IndexPredicate::None,
            unestablished: false,
            valid: true,
            ready: true,
            live: true,
        },
        dependency_columns: vec!["b".to_string()],
        dependency_columns_known: true,
        is_immediate: true,
    });
    let mut state = AnalysisState::new(cache);
    let violations = engine
        .analyze(
            "CREATE INDEX p_b ON p (b);
                 ALTER INDEX p_b ATTACH PARTITION c_b;",
            &mut state,
        )
        .unwrap();
    assert!(
        state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_b")
            && edge.referenced == object_id("public", "p_b")),
        "a synced default opclass must attach to a statement parent, got {violations:?}"
    );
}

#[test]
fn an_attached_child_index_cannot_be_dropped_on_its_own() {
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_a ON c (a);
             CREATE INDEX p_a ON p (a);
             ALTER INDEX p_a ATTACH PARTITION c_a;
             DROP INDEX c_a;",
    );
    // PostgreSQL refuses this as 2BP01 even with CASCADE.
    assert!(
        violations
            .iter()
            .any(|violation| violation.reason.contains("requires it")),
        "expected a dependent-index refusal, got {violations:?}"
    );
    assert!(state.local.graph.edges().iter().any(|edge| matches!(
        edge.kind,
        DependencyKind::IndexOnRelation { .. }
    ) && edge.dependent
        == object_id("public", "c_a")));
}

#[test]
fn creating_a_partition_attaches_its_indexes_to_the_parent() {
    // PostgreSQL creates and attaches the partition's index as part of
    // CREATE TABLE ... PARTITION OF, so the child cannot be dropped alone.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE INDEX p_b ON p (b);
             CREATE TABLE c PARTITION OF p FOR VALUES FROM (0) TO (10);",
    );
    assert!(
        state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.referenced
            == object_id("public", "p_b")),
        "the partition's index must be attached to the parent's, got {violations:?}"
    );
}

#[test]
fn dropping_a_partitioned_index_removes_attached_grandchildren() {
    // PostgreSQL drops the whole attached index tree with its parent, so a
    // grandchild index on a sub-partition must not survive.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer) PARTITION BY RANGE (a);
             CREATE INDEX p_a ON p (a);
             CREATE TABLE c PARTITION OF p FOR VALUES FROM (0) TO (10) PARTITION BY RANGE (a);
             CREATE TABLE d PARTITION OF c FOR VALUES FROM (0) TO (5);
             DROP INDEX p_a;",
    );
    for name in ["p_a", "c_a_idx", "d_a_idx"] {
        assert!(
            !state.local.graph.edges().iter().any(|edge| matches!(
                edge.kind,
                DependencyKind::IndexOnRelation { .. }
            ) && edge.dependent
                == object_id("public", name)),
            "the attached index tree must go with its parent, {name} survived: {violations:?}"
        );
    }
}

#[test]
fn attaching_a_partition_attaches_reused_child_indexes_to_the_parent() {
    // The pre-existing child index is reused rather than recreated, and is
    // still attached, so DROP INDEX on it must be refused. PostgreSQL
    // creates no parent index when the parent has none, so the parent index
    // has to exist here for an attachment to happen at all.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             CREATE INDEX c_b ON c (b);
             CREATE INDEX p_b ON p (b);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);",
    );
    assert!(
        state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_b")
            && edge.referenced == object_id("public", "p_b")),
        "a reused partition index must be attached to the parent's, got {violations:?}"
    );
}

#[test]
fn attaching_a_partition_creates_the_missing_child_index_and_attaches_it() {
    // Verified live: PostgreSQL creates the partition's index when it is
    // missing and attaches it to the parent's, so it cannot be dropped
    // alone afterwards.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE INDEX p_b ON p (b);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);",
    );
    let attachment = state
        .local
        .graph
        .edges()
        .iter()
        .find(|edge| matches!(edge.kind, DependencyKind::IndexPartitionOf));
    let child = attachment.map(|edge| edge.dependent.clone());
    assert!(
        attachment.is_some() && child.as_ref() == Some(&object_id("public", "c_b_idx")),
        "expected a generated child index attached to p_b, got {child:?} in {violations:?}"
    );
    assert!(state.local.graph.edges().iter().any(|edge| matches!(
        edge.kind,
        DependencyKind::IndexOnRelation { .. }
    ) && edge.dependent
        == object_id("public", "c_b_idx")
        && edge.referenced == object_id("public", "c")));
}

#[test]
fn attaching_a_partition_without_a_parent_index_creates_no_attachment() {
    // Verified live: PostgreSQL does not invent a parent index here, so the
    // child index stays independent and remains droppable.
    let (state, _violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             CREATE INDEX c_b ON c (b);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);",
    );
    assert!(
        !state
            .local
            .graph
            .edges()
            .iter()
            .any(|edge| matches!(edge.kind, DependencyKind::IndexPartitionOf)),
        "no parent index means no attachment"
    );
}

#[test]
fn a_concurrent_detach_also_releases_index_attachments() {
    // PostgreSQL detaches the indexes on the first phase, before FINALIZE,
    // so a later DROP INDEX must already be allowed.
    let (state, _violations) = attach_fixture(
        "CREATE TABLE p (a integer) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_a ON c (a);
             CREATE INDEX p_a ON p (a);
             ALTER TABLE p DETACH PARTITION c CONCURRENTLY;",
    );
    assert!(
        !state
            .local
            .graph
            .edges()
            .iter()
            .any(|edge| matches!(edge.kind, DependencyKind::IndexPartitionOf)),
        "DETACH PARTITION CONCURRENTLY must release index attachments"
    );
}

#[test]
fn detaching_a_partition_releases_its_index_attachments() {
    let (state, _violations) = attach_fixture(
        "CREATE TABLE p (a integer) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_a ON c (a);
             CREATE INDEX p_a ON p (a);
             ALTER INDEX p_a ATTACH PARTITION c_a;
             ALTER TABLE p DETACH PARTITION c;",
    );
    // PostgreSQL detaches the indexes with the partition, so leaving the
    // edge behind would make a later DROP INDEX fail spuriously.
    assert!(
        !state
            .local
            .graph
            .edges()
            .iter()
            .any(|edge| matches!(edge.kind, DependencyKind::IndexPartitionOf)),
        "detach must not leave a stale index attachment"
    );
}

#[test]
fn attaching_to_an_incomplete_partitioned_index_is_allowed() {
    let engine = setup_engine();
    for extra in ["", "ALTER INDEX pt_idx ATTACH PARTITION p1_idx;"] {
        let mut state = setup_state();
        let violations = engine
            .analyze(
                &format!(
                    "CREATE TABLE pt (a int) PARTITION BY RANGE (a);
                         CREATE TABLE p1 PARTITION OF pt FOR VALUES FROM (0) TO (10);
                         CREATE TABLE p2 PARTITION OF pt FOR VALUES FROM (10) TO (20);
                         CREATE INDEX pt_idx ON ONLY pt (a);
                         CREATE INDEX p1_idx ON ONLY p1 (a);
                         CREATE INDEX p2_idx ON ONLY p2 (a);
                         ALTER INDEX pt_idx ATTACH PARTITION p1_idx;
                         {extra}"
                ),
                &mut state,
            )
            .unwrap();
        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict"),
            "attaching an incomplete parent must succeed"
        );
    }
}

#[test]
fn creating_an_index_on_only_leaves_covered_partitioned_parents_invalid() {
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine
        .analyze(
            "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
                 CREATE TABLE c (a integer, b text);
                 ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
                 CREATE INDEX p_only ON ONLY p (b);
                 CREATE TABLE q (a integer, b text) PARTITION BY RANGE (a);
                 CREATE INDEX q_only ON ONLY q (b);
                 CREATE TABLE r (a integer, b text);
                 CREATE INDEX r_only ON ONLY r (b);",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "ON ONLY is legal everywhere the server accepts it: {violations:?}"
    );
    let valid = |name: &str| {
        state
            .local
            .graph
            .edges()
            .iter()
            .find_map(|edge| match &edge.kind {
                DependencyKind::IndexOnRelation { definition, .. }
                    if edge.dependent == object_id("public", name) =>
                {
                    Some(definition.valid)
                }
                _ => None,
            })
    };
    assert_eq!(valid("p_only"), Some(false));
    assert_eq!(valid("q_only"), Some(true));
    assert_eq!(valid("r_only"), Some(true));
    assert!(
        !state
            .local
            .graph
            .edges()
            .iter()
            .any(|edge| matches!(edge.kind, DependencyKind::IndexPartitionOf)),
        "ON ONLY must not create or attach partition indexes"
    );
}

#[test]
fn creating_an_index_on_a_partitioned_table_clones_children_recursively() {
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine
        .analyze(
            "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
                 CREATE TABLE c (a integer, b text) PARTITION BY RANGE (a);
                 ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
                 CREATE TABLE d (a integer, b text);
                 ALTER TABLE c ATTACH PARTITION d FOR VALUES FROM (0) TO (5);
                 CREATE INDEX p_idx ON p (b);",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "creating a partitioned index must be clean: {violations:?}"
    );
    let attached = |child: &str, parent: &str| {
        state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexPartitionOf)
                && edge.dependent == object_id("public", child)
                && edge.referenced == object_id("public", parent)
        })
    };
    assert!(attached("c_b_idx", "p_idx"));
    assert!(attached("d_b_idx", "c_b_idx"));
    for name in ["p_idx", "c_b_idx", "d_b_idx"] {
        assert!(
            state.local.graph.edges().iter().any(|edge| {
                edge.dependent == object_id("public", name)
                    && matches!(
                        &edge.kind,
                        DependencyKind::IndexOnRelation { definition, .. }
                            if definition.valid
                    )
            }),
            "{name} must be valid: {violations:?}"
        );
    }
}

#[test]
fn creating_an_index_on_a_partitioned_table_reuses_an_equivalent_child() {
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine
        .analyze(
            "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
                 CREATE TABLE c (a integer, b text);
                 ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
                 CREATE INDEX c_existing ON c (b);
                 CREATE INDEX p_idx ON p (b);",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "reusing an equivalent child must be clean: {violations:?}"
    );
    assert!(
        state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexPartitionOf)
                && edge.dependent == object_id("public", "c_existing")
                && edge.referenced == object_id("public", "p_idx")
        }),
        "the existing index must be attached"
    );
    assert!(
        !state.index_is_present(&object_id("public", "c_b_idx")),
        "no second index may be created on the partition"
    );
}

#[test]
fn attaching_a_table_does_not_revalidate_the_parent_index() {
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine
        .analyze(
            "CREATE TABLE p (a integer) PARTITION BY RANGE (a);
                 CREATE TABLE c1 (a integer);
                 ALTER TABLE p ATTACH PARTITION c1 FOR VALUES FROM (0) TO (10);
                 CREATE INDEX p_idx ON ONLY p (a);
                 CREATE TABLE c2 (a integer);
                 CREATE INDEX c2_idx ON c2 (a);
                 ALTER TABLE p ATTACH PARTITION c2 FOR VALUES FROM (10) TO (20);",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "the server accepts the whole sequence: {violations:?}"
    );
    fn parent_valid(state: &AnalysisState) -> Option<bool> {
        state
            .local
            .graph
            .edges()
            .iter()
            .find_map(|edge| match &edge.kind {
                DependencyKind::IndexOnRelation { definition, .. }
                    if edge.dependent == object_id("public", "p_idx") =>
                {
                    Some(definition.valid)
                }
                _ => None,
            })
    }
    assert!(
        state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexPartitionOf)
                && edge.dependent == object_id("public", "c2_idx")
                && edge.referenced == object_id("public", "p_idx")
        }),
        "attaching the table adopts the partition's existing index"
    );
    assert_eq!(
        parent_valid(&state),
        Some(false),
        "attaching a table must not revalidate the parent"
    );
    let violations = engine
        .analyze(
            "CREATE INDEX c1_idx ON c1 (a);
                 ALTER INDEX p_idx ATTACH PARTITION c1_idx;",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "the last attachment is accepted: {violations:?}"
    );
    assert_eq!(
        parent_valid(&state),
        Some(true),
        "the last attachment must validate the parent"
    );
}

#[test]
fn attaching_a_second_index_for_the_same_partition_is_refused() {
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text, d text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text, d text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_b ON c (b);
             CREATE INDEX p_d ON p (d);
             ALTER INDEX p_d ATTACH PARTITION c_b;",
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation.reason.contains("already attached")),
        "expected the duplicate-attachment refusal, got {violations:?}"
    );
    assert!(
        !state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexPartitionOf)
                && edge.dependent == object_id("public", "c_b")
        }),
        "the manually named index must not be attached"
    );
}

#[test]
fn attaching_a_partition_index_over_a_nullable_key_is_refused() {
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer NOT NULL);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             ALTER TABLE c ALTER COLUMN a DROP NOT NULL;
             ALTER TABLE p ADD PRIMARY KEY (a);
             ALTER TABLE c ADD CONSTRAINT c_u UNIQUE (a);
             ALTER INDEX p_pkey ATTACH PARTITION c_u;",
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation.reason.contains("is not marked NOT NULL")),
        "expected the primary-key nullability refusal, got {violations:?}"
    );
    assert!(
        !state.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexPartitionOf)
                && edge.dependent == object_id("public", "c_u")
        }),
        "a nullable key must not attach to a primary key"
    );
}

#[test]
fn reindex_makes_a_broken_index_usable() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    let broken = object_id("public", "broken_idx");
    let table = object_id("public", "t");
    let definition = safe_migrate::_internal::model::index::IndexDefinition {
        method: Some("btree".to_string()),
        keys: index_keys(vec!["a".to_string()]),
        included: Vec::new(),
        expression_keys: 0,
        unique: true,
        nulls_not_distinct: Some(false),
        predicate: IndexPredicate::None,
        unestablished: false,
        valid: false,
        ready: false,
        live: true,
    };
    cache.insert_baseline(
        table.clone(),
        RelationState::new(
            table.clone(),
            object_id("public", "owner"),
            0,
            Some(1000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    cache
        .indexes
        .push(safe_migrate::_internal::db::cache::IndexCache {
            index_id: broken.clone(),
            table_id: table.clone(),
            definition,
            dependency_columns: vec!["a".to_string()],
            dependency_columns_known: true,
            is_immediate: true,
        });
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
    let violations = engine
        .analyze(
            "REINDEX INDEX broken_idx;
                 ALTER TABLE t ADD CONSTRAINT t_u UNIQUE USING INDEX broken_idx;",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "a rebuilt index is usable"
    );
}
