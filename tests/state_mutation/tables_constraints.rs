use super::*;

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
    engine
        .analyze(
            "BEGIN; ALTER TABLE check_rename RENAME CONSTRAINT old_check TO new_check; ROLLBACK;",
            &mut state,
        )
        .unwrap();
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
fn test_topology_drop_table() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze("CREATE TABLE t(id int); DROP TABLE t;", &mut state)
        .unwrap();
    assert!(!state.relation_is_present(&object_id("public", "t")));
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
        let RelationOverlay::Present(relation) = &state.local.relations[&object_id("public", name)]
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
        let RelationOverlay::Present(relation) = &state.local.relations[&object_id("public", name)]
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
            && matches!(&edge.kind, DependencyKind::IndexOnRelation { definition, .. } if definition.key_column_names() == ["renamed"])));
    engine.analyze("ROLLBACK;", &mut state).unwrap();
    for name in ["parent", "child"] {
        let RelationOverlay::Present(relation) = &state.local.relations[&object_id("public", name)]
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
fn multi_parent_outside_cone_column_rename_is_rejected_without_mutation() {
    // child INHERITS (parent_a, parent_b).
    // Renaming parent_a.id while parent_b also owns child.id is blocked:
    // child.id has parent_count=2, but only 1 parent is in the rename cone.
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE parent_a (id integer);
                 CREATE TABLE parent_b (id integer);
                 CREATE TABLE child () INHERITS (parent_a, parent_b);",
            &mut state,
        )
        .unwrap();
    let relations_before = state.local.relations.clone();
    let findings = engine
        .analyze(
            "ALTER TABLE parent_a RENAME COLUMN id TO renamed;",
            &mut state,
        )
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "expected chain-conflict finding; got: {findings:?}"
    );
    // Nothing mutated on any of the three relations.
    assert_eq!(state.local.relations, relations_before);
}

#[test]
fn multi_parent_both_in_cone_column_rename_succeeds() {
    // When both parents are renamed together (via two statements in the same
    // migration the simulator processes sequentially), the child rename goes
    // through cleanly because every parent is in the already-renamed set by
    // the time we process parent_b.  Model this via a single shared ancestor:
    // grandparent → (parent_a, parent_b) → child.
    // Renaming grandparent.id propagates to both parents and the child, all
    // of which are descendants of grandparent — all in the cone.
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE grandparent (id integer);
                 CREATE TABLE parent_a () INHERITS (grandparent);
                 CREATE TABLE parent_b () INHERITS (grandparent);
                 CREATE TABLE child () INHERITS (parent_a, parent_b);",
            &mut state,
        )
        .unwrap();
    engine
        .analyze(
            "ALTER TABLE grandparent RENAME COLUMN id TO renamed;",
            &mut state,
        )
        .unwrap();
    for name in ["grandparent", "parent_a", "parent_b", "child"] {
        let RelationOverlay::Present(relation) = &state.local.relations[&object_id("public", name)]
        else {
            panic!("missing {name}");
        };
        assert!(
            relation.has_column("renamed"),
            "{name} missing column 'renamed'"
        );
        assert!(
            !relation.has_column("id"),
            "{name} still has old column 'id'"
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
            "(((a IS NOT NULL) AND (a >= 10) AND (a < 20)))",
        ),
        (
            "a integer, b integer",
            "((a), (b))",
            "FROM (0, 0) TO (10, 10)",
            "(((a IS NOT NULL) AND (b IS NOT NULL) AND ((a > 0) OR ((a = 0) AND (b >= 0))) AND ((a < 10) OR ((a = 10) AND (b < 10)))))",
        ),
        (
            "a integer, b integer",
            "(((a)), b)",
            "FROM (0, 0) TO (10, 10)",
            "(((a IS NOT NULL) AND (b IS NOT NULL) AND ((a > 0) OR ((a = 0) AND (b >= 0))) AND ((a < 10) OR ((a = 10) AND (b < 10)))))",
        ),
        (
            "a character varying(32), b integer",
            "((a), (b))",
            "FROM ('a', 0) TO ('m', 10)",
            "(((a IS NOT NULL) AND (b IS NOT NULL) AND (((a)::text > 'a'::character varying(32)) OR (((a)::text = 'a'::character varying(32)) AND (b >= 0))) AND (((a)::text < 'm'::character varying(32)) OR (((a)::text = 'm'::character varying(32)) AND (b < 10)))))",
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
        let child_id = object_id("public", "child");
        let constraint = state
            .local
            .constraints
            .values()
            .find(|c| c.table_id == child_id && c.kind == ConstraintKind::Check)
            .unwrap();
        assert_eq!(constraint.definition.as_deref(), Some(expected), "{bound}");
    }
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
    let Some(RelationOverlay::Present(child)) = state.get_relation(&object_id("public", "child"))
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
                constraint.table_id == object_id("public", "child") && constraint.name == "positive"
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
fn a_column_list_longer_than_the_projection_is_a_conflict() {
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
                 CREATE VIEW v (x, y, z) AS SELECT a, b FROM t;"
        )
        .iter()
        .any(|reason| reason.contains("CREATE VIEW specifies more column names than columns")),
        "a view column list may not exceed the projection"
    );
    assert!(
        conflicts(
            "CREATE TABLE t (a int, b int);
                 CREATE MATERIALIZED VIEW m (x, y, z) AS SELECT a, b FROM t;"
        )
        .iter()
        .any(|reason| reason.contains("too many column names were specified")),
        "a materialized view column list may not exceed the projection"
    );
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
fn create_table_foreign_keys_accept_inherited_source_columns() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE target (id integer PRIMARY KEY);
             CREATE TABLE base (parent_id integer);
             CREATE TABLE child (FOREIGN KEY (parent_id) REFERENCES target(id))
                INHERITS (base);
             CREATE TABLE base_like (parent_id integer);
             CREATE TABLE child_like (
                LIKE base_like INCLUDING ALL,
                FOREIGN KEY (parent_id) REFERENCES target(id)
             );
             CREATE TYPE address AS (parent_id integer);
             CREATE TABLE child_of OF address (
                FOREIGN KEY (parent_id) REFERENCES target(id)
             );
             CREATE TABLE parent_part (parent_id integer, id integer)
                PARTITION BY RANGE (id);
             CREATE TABLE child_part PARTITION OF parent_part (
                FOREIGN KEY (parent_id) REFERENCES target(id)
             ) FOR VALUES FROM (0) TO (10);",
            &mut state,
        )
        .unwrap();

    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "{findings:?}"
    );
    for table in ["child", "child_like", "child_of", "child_part"] {
        assert!(
            state.local.constraints.contains_key(&(
                object_id("public", table),
                format!("{table}_parent_id_fkey")
            )),
            "missing foreign key on {table}"
        );
    }
}

#[test]
fn self_referencing_foreign_key_accepts_inherited_columns() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE base (id integer);
             CREATE TABLE child (
                PRIMARY KEY (id),
                FOREIGN KEY (id) REFERENCES child(id)
             ) INHERITS (base);",
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
        state
            .local
            .constraints
            .contains_key(&(object_id("public", "child"), "child_id_fkey".to_string()))
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
fn alter_table_generated_key_and_exclusion_names_use_columns() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE generated_names (email text, period int4range);
             ALTER TABLE generated_names ADD UNIQUE (email);
             ALTER TABLE generated_names
                ADD EXCLUDE USING gist (period WITH &&);",
            &mut state,
        )
        .unwrap();

    let table = object_id("public", "generated_names");
    for (name, kind) in [
        ("generated_names_email_key", ConstraintKind::Unique),
        ("generated_names_period_excl", ConstraintKind::Exclusion),
    ] {
        let constraint = state
            .local
            .constraints
            .get(&(table.clone(), name.to_string()))
            .unwrap_or_else(|| panic!("missing generated constraint {name}"));
        assert_eq!(constraint.kind, kind);
        assert_eq!(
            constraint.backing_index.as_ref(),
            Some(&object_id("public", name))
        );
    }
}

#[test]
fn create_table_generated_exclusion_name_uses_columns() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE generated_exclusion (
                period int4range,
                EXCLUDE USING gist (period WITH &&)
             );",
            &mut state,
        )
        .unwrap();

    let table = object_id("public", "generated_exclusion");
    let constraint = state
        .local
        .constraints
        .get(&(table, "generated_exclusion_period_excl".to_string()))
        .expect("generated exclusion constraint should use its key columns");
    assert_eq!(constraint.kind, ConstraintKind::Exclusion);
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
    let expected = "abcdefghijklmnopqrstuvwxyzabc_abcdefghijklmnopqrstuvwxyzabc_key".to_string();
    assert_eq!(expected.len(), 63);
    assert!(state.local.constraints.contains_key(&(table, expected)));
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
    let mut cache = synced_cache();
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
fn a_written_default_opclass_matches_an_omitted_one() {
    // Verified live: PostgreSQL records opclass OID 3126 for both
    // `CREATE INDEX ... (note)` and `CREATE INDEX ... (note text_ops)`,
    // and attaches one to the other. The simulator must agree, or it
    // rejects an attachment PostgreSQL accepts.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, note text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, note text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_note ON c (note text_ops);
             CREATE INDEX p_note ON p (note);
             ALTER INDEX p_note ATTACH PARTITION c_note;",
    );
    assert!(
        state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_note")
            && edge.referenced == object_id("public", "p_note")),
        "an explicit default opclass must attach like an omitted one, got {violations:?}"
    );
}

#[test]
fn dropping_a_column_removes_it() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE t (id integer, doomed text, keep text);",
            &mut state,
        )
        .unwrap();
    assert!(state.relation_is_present(&object_id("public", "t")));
    engine
        .analyze("ALTER TABLE t DROP COLUMN doomed;", &mut state)
        .unwrap();
    let columns = state
        .local
        .relations
        .get(&object_id("public", "t"))
        .and_then(|o| match o {
            RelationOverlay::Present(r) => {
                Some(r.columns.iter().map(|c| c.name.clone()).collect::<Vec<_>>())
            }
            _ => None,
        })
        .unwrap_or_default();
    assert_eq!(columns, ["id", "keep"], "dropped column must be gone");
}

#[test]
fn dropping_a_column_works_alongside_a_pg18_not_null_constraint() {
    let tid = object_id("public", "t");
    let mut state = setup_state();
    state.pg_version_num = Some(180_006);
    setup_engine()
        .analyze(
            "CREATE TABLE t (id integer NOT NULL, doomed text);
                 ALTER TABLE t DROP COLUMN doomed;",
            &mut state,
        )
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
    assert_eq!(columns, ["id"], "dropped column must be gone");
}

#[test]
fn foreign_table_accepts_the_statements_postgres_accepts() {
    let id = object_id("public", "remote_t");
    let mut cache = synced_cache();
    cache.insert_baseline(
        id.clone(),
        RelationState::new(
            id.clone(),
            object_id("public", "owner"),
            0,
            None,
            RelationKind::ForeignTable,
            Persistence::Permanent,
            0,
        ),
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let alter = Mutation::AlterTable(AlterTable {
        id: id.clone(),
        only: false,
        action: AlterTableActionMutation::AddColumn {
            name: "extra".to_string(),
            ty: Some("integer".to_string()),
            if_not_exists: false,
            not_null: false,
            default: None,
            depends_on: None,
            generation: crate::_internal::analysis::facts::ColumnGeneration::Ordinary,
            identity_sequence: None,
            generated_expr: None,
            generated_expr_sql: None,
        },
    });
    assert!(
        matches!(state.apply(&alter, None), MutationResult::Applied),
        "ALTER TABLE is accepted on a foreign table"
    );
}

#[test]
fn drop_table_still_rejects_a_foreign_table() {
    let id = object_id("public", "remote_t");
    let mut cache = synced_cache();
    cache.insert_baseline(
        id.clone(),
        RelationState::new(
            id.clone(),
            object_id("public", "owner"),
            0,
            None,
            RelationKind::ForeignTable,
            Persistence::Permanent,
            0,
        ),
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let drop = Mutation::DropTable(DropTable {
        ids: vec![id],
        if_exists: false,
        cascade: false,
    });
    assert!(
        matches!(state.apply(&drop, None), MutationResult::Conflict { .. }),
        "the server answers DROP TABLE with 'is not a table'"
    );
}
