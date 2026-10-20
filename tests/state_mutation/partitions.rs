use super::*;

#[test]
fn partition_key_rename_updates_keys_for_synthesis() {
    let mut state = setup_state();
    let engine = setup_engine();
    engine
        .analyze(
            "CREATE TABLE parent (a integer) PARTITION BY LIST (a);
                 ALTER TABLE parent RENAME COLUMN a TO b;
                 CREATE TABLE child PARTITION OF parent FOR VALUES IN (1);",
            &mut state,
        )
        .unwrap();

    let child = object_id("public", "child");
    let relation = match state.local.relations.get(&child).unwrap() {
        RelationOverlay::Present(rel) => rel,
        _ => panic!("missing child"),
    };
    // The check must reference 'b' not 'a'
    let constraint = relation.partition_constraint.as_deref().unwrap();
    assert!(constraint.contains("(b = 1)"), "found: {}", constraint);
    assert!(!constraint.contains("a"), "found: {}", constraint);
}

#[test]
fn exponent_form_numeric_list_bounds_are_not_scale_padded() {
    let mut state = setup_state();
    let engine = setup_engine();
    engine
        .analyze(
            "CREATE TABLE parent (a numeric(10,2)) PARTITION BY LIST (a);
                 CREATE TABLE child_multi PARTITION OF parent FOR VALUES IN (5e2, 6e2);
                 CREATE TABLE child_single PARTITION OF parent FOR VALUES IN (7e2);",
            &mut state,
        )
        .unwrap();

    for (child, needle) in [
        ("child_multi", "'{5e2,6e2}'::numeric(10,2)[]"),
        ("child_single", "7e2::numeric(10,2)"),
    ] {
        let relation = match state
            .local
            .relations
            .get(&object_id("public", child))
            .unwrap()
        {
            RelationOverlay::Present(rel) => rel,
            _ => panic!("missing {child}"),
        };
        let constraint = relation.partition_constraint.as_deref().unwrap();
        assert!(constraint.contains(needle), "{child} found: {}", constraint);
        assert!(
            !constraint.contains("5e2.00") && !constraint.contains("7e2.00"),
            "{child} found: {}",
            constraint
        );
    }
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
        Some("(((id IS NOT NULL) AND (id >= 0) AND (id < 10)))")
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
                format!("((({quoted} IS NOT NULL) AND ({quoted} >= 0) AND ({quoted} < 10)))")
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
    let RelationOverlay::Present(relation) = state.local.relations.get_mut(&child).unwrap() else {
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
        Some("(((id IS NOT NULL) AND (id >= 0) AND (id < 10)))")
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
                && constraint.definition.as_deref() == Some("(((a IS NOT NULL) AND (b IS NOT NULL) AND ((a > 0) OR ((a = 0) AND (b >= 0))) AND ((a < 10) OR ((a = 10) AND (b < 10)))))")
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
            "(((a IS NOT NULL) AND (b IS NOT NULL) AND (c IS NOT NULL) AND ((a > 1) OR ((a = 1) AND (b > 2)) OR ((a = 1) AND (b = 2) AND (c >= 3))) AND ((a < 10) OR ((a = 10) AND (b < 20)) OR ((a = 10) AND (b = 20) AND (c < 30)))))",
        ),
        (
            "a integer, b integer, c integer",
            "(a, b, c)",
            "FROM (1, 2, MINVALUE) TO (10, 20, MAXVALUE)",
            "(((a IS NOT NULL) AND (b IS NOT NULL) AND (c IS NOT NULL) AND ((a > 1) OR ((a = 1) AND (b >= 2))) AND ((a < 10) OR ((a = 10) AND (b <= 20)))))",
        ),
        (
            "a integer, b integer, c integer",
            "(a, b, c)",
            "FROM (1, MINVALUE, MINVALUE) TO (10, MAXVALUE, MAXVALUE)",
            "(((a IS NOT NULL) AND (b IS NOT NULL) AND (c IS NOT NULL) AND (a >= 1) AND (a <= 10)))",
        ),
        (
            "a integer, b integer",
            "(a, b)",
            "FROM (MINVALUE, MINVALUE) TO (MAXVALUE, MAXVALUE)",
            "(((a IS NOT NULL) AND (b IS NOT NULL)))",
        ),
        (
            "a integer, b integer",
            "(a, b)",
            "FROM (MINVALUE, MINVALUE) TO (10, 20)",
            "(((a IS NOT NULL) AND (b IS NOT NULL) AND ((a < 10) OR ((a = 10) AND (b < 20)))))",
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
fn composite_range_detach_synthesis_matches_postgres_for_varchar_keys() {
    let engine = setup_engine();
    for (columns, keys, bound, expected) in [
        (
            "a character varying(32), b character varying(32)",
            "(a, b)",
            "FROM ('a', 'b') TO ('m', 'n')",
            "(((a IS NOT NULL) AND (b IS NOT NULL) AND (((a)::text > 'a'::character varying(32)) OR (((a)::text = 'a'::character varying(32)) AND ((b)::text >= 'b'::character varying(32)))) AND (((a)::text < 'm'::character varying(32)) OR (((a)::text = 'm'::character varying(32)) AND ((b)::text < 'n'::character varying(32))))))",
        ),
        (
            "a character varying(32), b integer",
            "(a, b)",
            "FROM ('a', 0) TO ('m', 10)",
            "(((a IS NOT NULL) AND (b IS NOT NULL) AND (((a)::text > 'a'::character varying(32)) OR (((a)::text = 'a'::character varying(32)) AND (b >= 0))) AND (((a)::text < 'm'::character varying(32)) OR (((a)::text = 'm'::character varying(32)) AND (b < 10)))))",
        ),
        (
            "a character varying(16), b character varying(16), c character varying(16)",
            "(a, b, c)",
            "FROM ('a', 'b', 'c') TO ('x', 'y', 'z')",
            "(((a IS NOT NULL) AND (b IS NOT NULL) AND (c IS NOT NULL) AND (((a)::text > 'a'::character varying(16)) OR (((a)::text = 'a'::character varying(16)) AND ((b)::text > 'b'::character varying(16))) OR (((a)::text = 'a'::character varying(16)) AND ((b)::text = 'b'::character varying(16)) AND ((c)::text >= 'c'::character varying(16)))) AND (((a)::text < 'x'::character varying(16)) OR (((a)::text = 'x'::character varying(16)) AND ((b)::text < 'y'::character varying(16))) OR (((a)::text = 'x'::character varying(16)) AND ((b)::text = 'y'::character varying(16)) AND ((c)::text < 'z'::character varying(16))))))",
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
    let mut cache = synced_cache();
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
    let mut cache = synced_cache();
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
        Some("(((a IS NOT NULL) AND (a = ANY ('{1,2,3}'::integer[]))))")
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
            && trigger.parent_trigger_id.as_ref() == Some(&object_id("public", "parent\0audit_row"))
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
fn partition_columns_match_by_name_not_position() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE parent (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE child (b text, a integer);
             ALTER TABLE parent ATTACH PARTITION child
                FOR VALUES FROM (0) TO (10);",
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
        edge.referenced == object_id("public", "parent")
            && edge.dependent == object_id("public", "child")
            && matches!(edge.kind, DependencyKind::PartitionOf)
    }));
}

#[test]
fn partition_attachment_accepts_builtin_type_aliases() {
    let engine = setup_engine();
    let mut state = setup_state();
    for (index, (parent_type, child_type, from, to)) in [
        ("integer", "int", "0", "10"),
        ("varchar", "character varying", "'a'", "'z'"),
        (
            "timestamptz",
            "timestamp with time zone",
            "'2020-01-01'",
            "'2021-01-01'",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let findings = engine
            .analyze(
                &format!(
                    "CREATE TABLE parent_{index} (a {parent_type}) PARTITION BY RANGE (a);
                     CREATE TABLE child_{index} (a {child_type});
                     ALTER TABLE parent_{index} ATTACH PARTITION child_{index}
                        FOR VALUES FROM ({from}) TO ({to});"
                ),
                &mut state,
            )
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "{parent_type}/{child_type}: {findings:?}"
        );
        assert!(state.local.graph.edges().iter().any(|edge| {
            edge.referenced == object_id("public", &format!("parent_{index}"))
                && edge.dependent == object_id("public", &format!("child_{index}"))
                && matches!(edge.kind, DependencyKind::PartitionOf)
        }));
    }
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
fn writing_the_default_collation_leaves_attachment_undecidable() {
    // Live PostgreSQL attaches: both spellings land on collation OID 100
    // when the column carries no collation of its own. The simulator does
    // not record column collations, so it cannot prove the written
    // `default` is the same choice and refuses to equate them silently.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_def ON c (b COLLATE \"default\");
             CREATE INDEX p_plain ON ONLY p (b);
             ALTER INDEX p_plain ATTACH PARTITION c_def;",
    );
    assert!(
        !state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_def")),
        "a written default collation must not be silently equated"
    );
    assert_eq!(
        state.local.confidence,
        Confidence::Tainted,
        "got {violations:?}"
    );
}

#[test]
fn an_explicit_opclass_on_an_expression_leaves_attachment_undecidable() {
    // Live PostgreSQL attaches: `lower(b)` on a text column is `text_ops`
    // (OID 3126) whether written or not. The simulator does not infer an
    // expression's result type, so it cannot prove the written class is
    // the expression's default and refuses to guess.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_ops ON c (lower(b) text_ops);
             CREATE INDEX p_lower ON ONLY p (lower(b));
             ALTER INDEX p_lower ATTACH PARTITION c_ops;",
    );
    assert!(
        !state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_ops")),
        "a written class on an expression must not be silently equated"
    );
    assert_eq!(
        state.local.confidence,
        Confidence::Tainted,
        "got {violations:?}"
    );
}

#[test]
fn opclasses_in_the_same_family_attach_despite_different_names() {
    // Verified live: `varchar_pattern_ops` and `text_pattern_ops` both
    // belong to family `text_pattern_ops`, and `CompareIndexInfo`
    // compares family OIDs, so the attachment succeeds.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer, b text) PARTITION BY RANGE (a);
             CREATE TABLE c (a integer, b text);
             ALTER TABLE p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);
             CREATE INDEX c_ops ON c (b text_pattern_ops);
             CREATE INDEX p_ops ON p (b varchar_pattern_ops);
             ALTER INDEX p_ops ATTACH PARTITION c_ops;",
    );
    assert!(
        state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexPartitionOf
        ) && edge.dependent
            == object_id("public", "c_ops")
            && edge.referenced == object_id("public", "p_ops")),
        "same-family classes must attach, got {violations:?}"
    );
}

#[test]
fn dropping_an_attached_child_with_its_parent_in_one_statement_is_allowed() {
    // PostgreSQL applies a statement's DROP INDEX targets as a batch, so
    // the parent and its attached child may be named together.
    let (state, violations) = attach_fixture(
        "CREATE TABLE p (a integer) PARTITION BY RANGE (a);
             CREATE INDEX p_a ON p (a);
             CREATE TABLE c PARTITION OF p FOR VALUES FROM (0) TO (10);
             DROP INDEX p_a, c_a_idx;",
    );
    assert!(
        !violations
            .iter()
            .any(|violation| violation.reason.contains("requires it")),
        "a parent dropped in the same statement does not require its child, got {violations:?}"
    );
    assert!(
        !state.local.graph.edges().iter().any(|edge| matches!(
            edge.kind,
            DependencyKind::IndexOnRelation { .. }
        ) && (edge.dependent
            == object_id("public", "p_a")
            || edge.dependent == object_id("public", "c_a_idx"))),
        "both indexes must be gone, got {violations:?}"
    );
}

#[test]
fn a_foreign_table_can_hold_a_partition() {
    let parent = object_id("public", "parent");
    let child = object_id("public", "child");
    let mut cache = synced_cache();
    for (id, kind) in [
        (parent.clone(), RelationKind::Table),
        (child.clone(), RelationKind::ForeignTable),
    ] {
        cache.insert_baseline(
            id.clone(),
            RelationState::new(
                id.clone(),
                object_id("public", "owner"),
                0,
                None,
                kind,
                Persistence::Permanent,
                0,
            ),
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
    if let Some(RelationOverlay::Present(parent_state)) = state.local.relations.get_mut(&parent) {
        parent_state.partition_type = Some("RANGE".to_string());
        parent_state.partition_by = Some("id".to_string());
    }
    let attach = Mutation::AlterTable(AlterTable {
        id: parent,
        only: false,
        action: AlterTableActionMutation::AttachPartition {
            child,
            strategy: None,
            bound: None,
        },
    });
    assert!(
        !matches!(state.apply(&attach, None), MutationResult::Conflict { .. }),
        "ATTACH PARTITION accepts a foreign table"
    );
}
