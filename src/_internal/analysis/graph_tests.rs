use super::*;
use crate::_internal::model::index::{IndexPredicate, index_keys};

fn id(name: &str) -> ObjectId {
    ObjectId::new("public", name)
}

fn view_edge(dependent: &str, referenced: &str) -> DependencyEdge {
    DependencyEdge::new(
        id(dependent),
        id(referenced),
        DependencyKind::ViewDependency {
            view_generation: 1,
            referenced_column: None,
        },
    )
}

#[test]
fn a_definition_update_keeps_the_edge_set_in_step() {
    let mut graph = DependencyGraph::new();
    graph.add_edge(relation_edge(
        "index",
        "table",
        DependencyKind::IndexOnRelation {
            definition: IndexDefinition {
                method: Some("btree".into()),
                keys: index_keys(vec!["id".into()]),
                included: index_keys(Vec::new()),
                expression_keys: 0,
                unique: false,
                nulls_not_distinct: Some(false),
                predicate: IndexPredicate::None,
                unestablished: false,
                valid: false,
                ready: false,
                live: true,
            },
            dependency_columns: Vec::new(),
            dependency_columns_known: true,
            is_concurrent: false,
            is_immediate: true,
            eligibility_known: true,
        },
    ));
    graph.build_indexes_for_tests();
    graph.update_index_definition(&id("index"), |definition| {
        definition.valid = true;
        definition.ready = true;
    });

    // The updated edge is the one now in the graph, so re-adding it must be
    // rejected as a duplicate rather than inserted beside itself.
    let updated = graph.edges()[0].clone();
    if let DependencyKind::IndexOnRelation { definition, .. } = &updated.kind {
        assert!(definition.valid && definition.ready);
    } else {
        panic!("expected IndexOnRelation edge");
    }
    graph.add_edge(updated);
    assert_eq!(graph.edge_count(), 1);
    // A definition payload is not part of the derived lookup structure, so
    // the warm index survives the update.
    assert!(graph.dependent_index.get().is_some());
    assert!(graph.indexes_are_valid());
}

#[test]
fn a_definition_update_collapsing_duplicates_keeps_the_earliest_edge() {
    let mut graph = DependencyGraph::new();
    let before = view_edge("before", "table");
    let first = index_edge("index", "table", false);
    let second = index_edge("index", "table", true);
    let after = view_edge("after", "table");
    graph.add_edge(before.clone());
    graph.add_edge(first);
    graph.add_edge(second.clone());
    graph.add_edge(after.clone());
    graph.build_indexes_for_tests();

    graph.update_index_definition(&id("index"), |definition| {
        definition.valid = true;
        definition.ready = true;
    });

    assert_eq!(graph.edge_count(), 3);
    assert_eq!(graph.edges(), [before, second, after]);
    assert!(graph.edge_set_is_valid());
    assert!(graph.indexes_are_valid());
}

#[test]
fn a_schema_rename_remaps_a_name_only_view_routine_reference() {
    let mut graph = DependencyGraph::new();
    let written = ObjectId::new("s", "f");
    graph.add_edge(DependencyEdge::new(
        ObjectId::new("s", "v"),
        written.clone(),
        DependencyKind::ViewUsesRoutine {
            unresolved_name: Some(written.clone()),
        },
    ));

    graph.remap_schema_namespace("s", "t");

    // A later `DROP FUNCTION t.f(...)` must find the view the rename moved.
    let renamed = ObjectId::new("t", "f");
    assert_eq!(graph.views_for_function(&renamed).len(), 1);
    assert!(graph.has_view_reference_to_name(&renamed));
    assert!(!graph.has_view_reference_to_name(&written));
}

#[test]
fn identical_dependency_edges_are_deduplicated() {
    let mut graph = DependencyGraph::new();
    let edge = view_edge("view", "table");
    graph.add_edge(edge.clone());
    graph.add_edge(edge);

    assert_eq!(graph.edge_count(), 1);
    assert_eq!(graph.cascade_edges(&id("table")).len(), 1);
}

#[test]
fn no_op_edge_mutations_preserve_derived_indexes() {
    let mut graph = DependencyGraph::new();
    graph.add_edge(view_edge("view", "table"));
    let _ = graph.cascade_edges(&id("table"));

    graph.retain_edges(|_| true);
    graph.truncate(graph.edge_count() + 1);

    assert!(graph.indexes_are_valid());
    assert_eq!(graph.cascade_edges(&id("table")).len(), 1);
}

#[test]
fn identity_remaps_collapse_duplicate_edges() {
    let mut graph = DependencyGraph::new();
    graph.add_edge(view_edge("view_a", "table"));
    graph.add_edge(view_edge("view_b", "table"));

    graph.propagate_relation_rename(&id("view_b"), &id("view_a"));

    assert_eq!(graph.edge_count(), 1);
    assert!(graph.indexes_are_valid());
}

#[test]
fn rename_delta_restores_rewritten_and_deduplicated_edges() {
    let mut graph = DependencyGraph::new();
    graph.add_edge(view_edge("view_a", "table"));
    graph.add_edge(view_edge("view_b", "table"));
    let before = graph.edges().to_vec();

    let mut plan = GraphRenamePlan::default();
    plan.relations.insert(id("view_b"), id("view_a"));
    let delta = graph
        .apply_rename_plan_recorded(&plan)
        .expect("rename should change edges");
    assert_eq!(graph.edge_count(), 1);
    assert!(graph.indexes_are_valid());

    graph.restore_edge_delta(delta);
    assert_eq!(graph.edges(), before.as_slice());
    assert!(graph.indexes_are_valid());
}

#[test]
fn rename_delta_drops_edges_appended_after_it_was_recorded() {
    let mut graph = DependencyGraph::new();
    graph.add_edge(view_edge("view_a", "table"));
    graph.add_edge(view_edge("view_b", "table"));
    let before = graph.edges().to_vec();

    let mut plan = GraphRenamePlan::default();
    plan.relations.insert(id("view_b"), id("view_a"));
    let delta = graph
        .apply_rename_plan_recorded(&plan)
        .expect("rename should change edges");
    graph.add_edge(view_edge("view_c", "table"));

    graph.restore_edge_delta(delta);
    assert_eq!(graph.edges(), before.as_slice());
    assert!(graph.indexes_are_valid());
}

#[test]
fn rename_delta_keeps_edges_added_before_it_was_recorded_until_the_length_marker_runs() {
    let mut graph = DependencyGraph::new();
    graph.add_edge(view_edge("view_a", "table"));
    graph.add_edge(view_edge("view_b", "table"));
    let before = graph.edges().to_vec();
    let before_len = graph.edge_count();
    graph.add_edge(view_edge("renamed", "table"));

    let mut plan = GraphRenamePlan::default();
    plan.relations.insert(id("view_b"), id("view_a"));
    let delta = graph
        .apply_rename_plan_recorded(&plan)
        .expect("rename should change edges");
    graph.restore_edge_delta(delta);
    assert_eq!(graph.edge_count(), before_len + 1);

    graph.truncate(before_len);
    assert_eq!(graph.edges(), before.as_slice());
    assert!(graph.indexes_are_valid());
}

#[test]
fn rename_plan_remaps_index_partition_of_endpoints() {
    let mut graph = DependencyGraph::new();
    let parent_idx = id("parent_idx");
    let child_idx = id("child_idx");
    let table = id("table");
    let child_table = id("child_table");

    let index_kind = || DependencyKind::IndexOnRelation {
        definition: IndexDefinition {
            method: Some("btree".into()),
            keys: index_keys(vec!["id".into()]),
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
        dependency_columns: Vec::new(),
        dependency_columns_known: true,
        is_concurrent: false,
        is_immediate: true,
        eligibility_known: true,
    };

    graph.add_edge(DependencyEdge::new(parent_idx.clone(), table, index_kind()));
    graph.add_edge(DependencyEdge::new(
        child_idx.clone(),
        child_table,
        index_kind(),
    ));
    graph.add_edge(DependencyEdge::new(
        child_idx.clone(),
        parent_idx.clone(),
        DependencyKind::IndexPartitionOf,
    ));

    let renamed_parent = id("renamed_parent_idx");
    let renamed_child = id("renamed_child_idx");
    let mut plan = GraphRenamePlan::default();
    plan.indexes
        .insert(parent_idx.clone(), renamed_parent.clone());
    plan.indexes
        .insert(child_idx.clone(), renamed_child.clone());

    let delta = graph
        .apply_rename_plan_recorded(&plan)
        .expect("rename plan must record edge changes");

    assert_eq!(graph.index_parent_of(&renamed_child), Some(&renamed_parent));
    assert_eq!(graph.index_parent_of(&child_idx), None);

    let partition_edge = graph
        .edges()
        .iter()
        .find(|edge| matches!(edge.kind, DependencyKind::IndexPartitionOf))
        .expect("partition edge must remain");
    assert_eq!(partition_edge.dependent, renamed_child);
    assert_eq!(partition_edge.referenced, renamed_parent);

    graph.restore_edge_delta(delta);
    assert_eq!(graph.index_parent_of(&child_idx), Some(&parent_idx));
    assert_eq!(graph.index_parent_of(&renamed_child), None);
}

#[test]
fn interleaved_constraint_deltas_and_additions_restore_the_original_edges() {
    let mut graph = DependencyGraph::new();
    graph.add_edge(relation_edge(
        "table",
        "table",
        DependencyKind::ConstraintDependency {
            constraint_name: "first".into(),
            columns: vec!["id".into()],
        },
    ));
    graph.add_edge(relation_edge(
        "table",
        "table",
        DependencyKind::ConstraintDependency {
            constraint_name: "second".into(),
            columns: vec!["id".into()],
        },
    ));
    let before = graph.edges().to_vec();
    let first = graph
        .rename_constraint_recorded(&id("table"), "first", "first_renamed")
        .expect("first constraint rename should change an edge");
    graph.add_edge(view_edge("view_a", "table"));
    let second = graph
        .rename_constraint_recorded(&id("table"), "second", "second_renamed")
        .expect("second constraint rename should change an edge");
    graph.add_edge(view_edge("view_b", "table"));

    graph.restore_edge_delta(second);
    graph.restore_edge_delta(first);
    graph.truncate(before.len());
    assert_eq!(graph.edges(), before.as_slice());
    assert!(graph.indexes_are_valid());
}

#[test]
fn column_rename_updates_both_sides_of_self_referencing_fk() {
    let table = id("self_ref");
    let mut graph = DependencyGraph::new();
    graph.add_edge(DependencyEdge::new(
        table.clone(),
        table.clone(),
        DependencyKind::ForeignKey {
            constraint_name: Some("self_fk".into()),
            from_columns: vec!["old_id".into()],
            to_columns: vec!["old_id".into()],
            operator_evidence: None,
            from_generation: 0,
        },
    ));
    graph.add_edge(DependencyEdge::new(
        table.clone(),
        table.clone(),
        DependencyKind::ConstraintDependency {
            constraint_name: "check_self".into(),
            columns: vec!["old_id".into()],
        },
    ));

    graph.rename_column_dependencies(&table, "old_id", "new_id");

    let DependencyKind::ForeignKey {
        from_columns,
        to_columns,
        ..
    } = &graph.edges()[0].kind
    else {
        panic!("expected foreign-key edge");
    };
    assert_eq!(from_columns, &["new_id"]);
    assert_eq!(to_columns, &["new_id"]);
    let DependencyKind::ConstraintDependency { columns, .. } = &graph.edges()[1].kind else {
        panic!("expected constraint dependency edge");
    };
    assert_eq!(columns, &["new_id"]);
}

#[test]
fn column_rename_updates_cached_view_columns_for_all_affected_relations() {
    let mut graph = DependencyGraph::new();
    for (view, table, column) in [
        ("parent_view", "parent", Some("old_id")),
        ("child_view", "child", Some("old_id")),
        ("relation_level_view", "child", None),
    ] {
        graph.add_edge(DependencyEdge::new(
            id(view),
            id(table),
            DependencyKind::ViewDependency {
                view_generation: 1,
                referenced_column: column.map(str::to_string),
            },
        ));
    }
    let before = graph.edges().to_vec();
    let affected: HashSet<ObjectId> = [id("parent"), id("child")].into_iter().collect();

    let delta = graph
        .rename_columns_for_relations_recorded(&affected, "old_id", "new_id")
        .expect("a precise view-column dependency should follow the rename");

    let columns: Vec<_> = graph
        .edges()
        .iter()
        .map(|edge| match &edge.kind {
            DependencyKind::ViewDependency {
                referenced_column, ..
            } => referenced_column.clone(),
            _ => unreachable!("only view dependencies were inserted"),
        })
        .collect();
    assert_eq!(
        columns,
        vec![Some("new_id".to_string()), Some("new_id".to_string()), None,]
    );

    graph.restore_edge_delta(delta);
    assert_eq!(graph.edges(), before.as_slice());
    assert!(graph.indexes_are_valid());
}

fn relation_edge(dependent: &str, referenced: &str, kind: DependencyKind) -> DependencyEdge {
    DependencyEdge::new(id(dependent), id(referenced), kind)
}

fn index_edge(dependent: &str, referenced: &str, valid: bool) -> DependencyEdge {
    relation_edge(
        dependent,
        referenced,
        DependencyKind::IndexOnRelation {
            definition: IndexDefinition {
                method: Some("btree".into()),
                keys: index_keys(vec!["id".into()]),
                included: index_keys(Vec::new()),
                expression_keys: 0,
                unique: false,
                nulls_not_distinct: Some(false),
                predicate: IndexPredicate::None,
                unestablished: false,
                valid,
                ready: valid,
                live: true,
            },
            dependency_columns: Vec::new(),
            dependency_columns_known: true,
            is_concurrent: false,
            is_immediate: true,
            eligibility_known: true,
        },
    )
}

fn canonical_views<'a>(graph: &'a DependencyGraph, target: &ObjectId) -> Vec<&'a ObjectId> {
    let resolved_target = graph.resolve_rename(target);
    graph
        .edges()
        .iter()
        .filter(|edge| {
            matches!(edge.kind, DependencyKind::ViewDependency { .. })
                && (graph.resolve_rename(&edge.referenced) == resolved_target
                    || &edge.referenced == target)
        })
        .map(|edge| graph.resolve_rename(&edge.dependent))
        .collect()
}

fn assert_indexed_views_match_scan(graph: &DependencyGraph, targets: &[ObjectId]) {
    assert!(graph.indexes_are_valid());
    for target in targets {
        let indexed = graph
            .cascade_edges(target)
            .into_iter()
            .filter(|edge| matches!(edge.kind, DependencyKind::ViewDependency { .. }))
            .map(|edge| graph.resolve_rename(&edge.dependent))
            .collect::<Vec<_>>();
        assert_eq!(indexed, canonical_views(graph, target));
    }
}

#[test]
fn indexes_track_every_graph_mutation_and_alias_cycle() {
    let a = id("a");
    let b = id("b");
    let c = id("c");
    let d = id("d");
    let targets = [a.clone(), b.clone(), c.clone(), d.clone()];
    let mut graph = DependencyGraph::new();

    graph.add_edge(view_edge("view_a", "a"));
    graph.add_edge(view_edge("view_b", "b"));
    for index in 0..DependencyGraph::CASCADE_INDEX_MIN_EDGES {
        graph.add_edge(view_edge(
            &format!("unrelated_view_{index}"),
            &format!("unrelated_table_{index}"),
        ));
    }
    assert_indexed_views_match_scan(&graph, &targets);

    graph.add_edge(DependencyEdge::new(
        a.clone(),
        b.clone(),
        DependencyKind::RenameTo,
    ));
    assert_indexed_views_match_scan(&graph, &targets);

    graph.propagate_relation_rename(&b, &c);
    graph.add_edge(DependencyEdge::new(
        b.clone(),
        c.clone(),
        DependencyKind::RenameTo,
    ));
    assert_indexed_views_match_scan(&graph, &targets);

    graph.mutate_edges(|edges| {
        for edge in edges {
            if edge.dependent == id("view_b") {
                edge.dependent = id("view_c");
            }
        }
    });
    assert_indexed_views_match_scan(&graph, &targets);

    let snapshot = graph.edges().to_vec();
    graph.retain_edges(|edge| edge.dependent != id("view_a"));
    assert_indexed_views_match_scan(&graph, &targets);
    graph.replace_edges(snapshot);
    assert_indexed_views_match_scan(&graph, &targets);

    let checkpoint = graph.edge_count();
    graph.add_edge(view_edge("temporary", "c"));
    graph.truncate(checkpoint);
    assert_indexed_views_match_scan(&graph, &targets);

    graph.add_edge(DependencyEdge::new(
        c.clone(),
        a.clone(),
        DependencyKind::RenameTo,
    ));
    assert_eq!(graph.resolve_rename(&a), &a);
    assert_eq!(graph.resolve_rename(&b), &b);
    assert_eq!(graph.resolve_rename(&c), &c);
    assert_indexed_views_match_scan(&graph, &targets);
}

#[test]
fn trigger_dependencies_preserve_overloaded_function_identity() {
    let mut graph = DependencyGraph::new();
    let trigger_function = id("notify()");
    let overload = id("notify(integer)");
    graph.add_edge(DependencyEdge::new(
        id("events_notify_trigger"),
        id("events"),
        DependencyKind::TriggerOnTable {
            trigger_id: id("events_notify_trigger"),
            function_id: trigger_function.clone(),
            trigger_generation: 0,
        },
    ));

    assert_eq!(graph.triggers_for_function(&trigger_function).len(), 1);
    assert!(graph.triggers_for_function(&overload).is_empty());
}

#[test]
fn index_table_lookup_matches_cold_and_warm_indexes() {
    let mut graph = DependencyGraph::new();
    graph.add_edge(relation_edge(
        "index",
        "table",
        DependencyKind::IndexOnRelation {
            definition: IndexDefinition {
                method: Some("btree".into()),
                keys: index_keys(vec!["id".into()]),
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
            dependency_columns: Vec::new(),
            dependency_columns_known: true,
            is_concurrent: false,
            is_immediate: true,
            eligibility_known: true,
        },
    ));

    assert_eq!(graph.index_table_of(&id("index")), Some(&id("table")));
    graph.build_indexes_for_tests();
    assert_eq!(graph.index_table_of(&id("index")), Some(&id("table")));
    assert_eq!(graph.index_table_of(&id("missing")), None);
}

#[test]
fn memoized_index_resolution_matches_endpoint_walks() {
    let a = id("a");
    let b = id("b");
    let c = id("c");
    let d = id("d");
    let x = id("x");
    let y = id("y");
    let z = id("z");
    let mut graph = DependencyGraph::new();
    graph.add_edge(view_edge("v1", "a"));
    graph.add_edge(view_edge("v2", "a"));
    graph.add_edge(view_edge("v3", "b"));
    graph.add_edge(view_edge("v4", "d"));
    graph.add_edge(DependencyEdge::new(a, b.clone(), DependencyKind::RenameTo));
    graph.add_edge(DependencyEdge::new(b, c.clone(), DependencyKind::RenameTo));
    graph.add_edge(DependencyEdge::new(c, d.clone(), DependencyKind::RenameTo));
    graph.add_edge(DependencyEdge::new(
        x.clone(),
        y.clone(),
        DependencyKind::RenameTo,
    ));
    graph.add_edge(DependencyEdge::new(y, x.clone(), DependencyKind::RenameTo));
    graph.add_edge(view_edge("vx", "x"));
    graph.add_edge(DependencyEdge::new(
        z.clone(),
        x.clone(),
        DependencyKind::RenameTo,
    ));
    graph.add_edge(view_edge("vz", "z"));

    let edges = graph.edges();
    let rename = DependencyGraph::build_rename_index(edges);
    let built = DependencyGraph::build_resolved_indexes(edges, &rename);
    let mut expected: HashMap<ObjectId, Vec<usize>> = HashMap::new();
    for (index, edge) in edges.iter().enumerate() {
        if !DependencyGraph::cascade_kind(&edge.kind) {
            continue;
        }
        let referenced =
            DependencyGraph::resolve_rename_with(edges, &rename, &edge.referenced).clone();
        expected.entry(referenced).or_default().push(index);
    }

    assert_eq!(built.by_resolved_referenced, expected);
    assert_eq!(
        built.by_resolved_referenced.get(&id("d")),
        Some(&vec![0, 1, 2, 3])
    );
    assert_eq!(built.by_resolved_referenced.get(&x), Some(&vec![9]));
    // An acyclic start that enters a cycle returns the original start
    // rather than a node from the cycle.
    assert_eq!(graph.resolve_rename(&z), &z);
    assert_eq!(graph.resolve_rename(&x), &x);
}

#[test]
fn indexed_reverse_dependency_lookups_match_alias_resolution() {
    let target = id("target");
    let renamed = id("renamed_target");
    let mut graph = DependencyGraph::new();
    for index in 0..DependencyGraph::CASCADE_INDEX_MIN_EDGES {
        graph.add_edge(view_edge(
            &format!("unrelated_view_{index}"),
            &format!("unrelated_table_{index}"),
        ));
    }
    graph.add_edge(relation_edge(
        "view",
        "target",
        DependencyKind::ViewDependency {
            view_generation: 1,
            referenced_column: None,
        },
    ));
    graph.add_edge(relation_edge(
        "index",
        "target",
        DependencyKind::IndexOnRelation {
            definition: IndexDefinition {
                method: Some("btree".into()),
                keys: index_keys(vec!["id".into()]),
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
            dependency_columns: Vec::new(),
            dependency_columns_known: true,
            is_concurrent: false,
            is_immediate: true,
            eligibility_known: true,
        },
    ));
    graph.add_edge(relation_edge(
        "child",
        "target",
        DependencyKind::ForeignKey {
            constraint_name: Some("child_target_fkey".into()),
            from_columns: vec!["target_id".into()],
            to_columns: vec!["id".into()],
            operator_evidence: None,
            from_generation: 7,
        },
    ));
    graph.add_edge(relation_edge(
        "partition",
        "target",
        DependencyKind::PartitionOf,
    ));
    graph.add_edge(DependencyEdge::new(
        target.clone(),
        renamed.clone(),
        DependencyKind::RenameTo,
    ));

    assert_eq!(
        graph
            .is_referenced_by_view(&renamed)
            .into_iter()
            .map(|id| id.name.clone())
            .collect::<Vec<_>>(),
        vec!["view"]
    );
    assert_eq!(
        graph
            .is_referenced_by_index(&renamed)
            .into_iter()
            .map(|id| id.name.clone())
            .collect::<Vec<_>>(),
        vec!["index"]
    );
    assert_eq!(
        graph
            .is_referenced_by_fk(&renamed)
            .into_iter()
            .map(|(id, generation)| (id.name.clone(), generation))
            .collect::<Vec<_>>(),
        vec![("child".into(), 7)]
    );
    assert_eq!(
        graph
            .partitions_of(&renamed)
            .into_iter()
            .map(|id| id.name.clone())
            .collect::<Vec<_>>(),
        vec!["partition"]
    );
    assert!(graph.indexes_are_valid());
}

#[test]
fn inheritance_cycle_checks_every_parent_and_accepts_diamonds() {
    let mut graph = DependencyGraph::new();
    for (child, parent) in [
        ("leaf", "left"),
        ("leaf", "right"),
        ("left", "root"),
        ("right", "root"),
    ] {
        graph.add_edge(DependencyEdge::new(
            id(child),
            id(parent),
            DependencyKind::InheritanceOf,
        ));
    }
    assert!(graph.check_inheritance_cycle(&id("leaf"), &id("right")));
    assert!(graph.check_inheritance_cycle(&id("leaf"), &id("root")));
    assert!(!graph.check_inheritance_cycle(&id("leaf"), &id("new_child")));
}

#[test]
fn traditional_inheritance_cascades_without_becoming_a_partition() {
    let parent = id("parent");
    let child = id("child");
    let mut graph = DependencyGraph::new();
    graph.add_edge(DependencyEdge::new(
        child.clone(),
        parent.clone(),
        DependencyKind::InheritanceOf,
    ));

    assert!(graph.partitions_of(&parent).is_empty());
    assert!(graph.cascade_edges(&parent).iter().any(|edge| {
        edge.dependent == child && matches!(edge.kind, DependencyKind::InheritanceOf)
    }));
}

#[test]
fn large_graph_cycle_checks_use_indexes_and_match_unindexed() {
    let mut graph = DependencyGraph::new();
    for index in 0..DependencyGraph::CASCADE_INDEX_MIN_EDGES {
        let child = id(&format!("part_child_{index}"));
        let parent = id(&format!("part_parent_{index}"));
        graph.add_edge(DependencyEdge::new(
            child,
            parent,
            DependencyKind::PartitionOf,
        ));
    }
    assert!(graph.cascade_index_is_worthwhile());
    // part_parent_0 has child part_child_0; attaching part_parent_0 to part_child_0 creates a cycle
    assert!(graph.check_partition_cycle(&id("part_child_0"), &id("part_parent_0")));
    assert!(!graph.check_partition_cycle(&id("part_parent_0"), &id("unrelated")));

    // Multi-parent inheritance cycle check with indexed vs unindexed comparison
    let multi_child = id("multi_child");
    let first_parent = id("first_parent");
    let second_parent = id("second_parent");
    let ancestor = id("ancestor_via_second");
    graph.add_edge(DependencyEdge::new(
        second_parent.clone(),
        ancestor.clone(),
        DependencyKind::InheritanceOf,
    ));
    graph.add_edge(DependencyEdge::new(
        multi_child.clone(),
        first_parent,
        DependencyKind::InheritanceOf,
    ));
    graph.add_edge(DependencyEdge::new(
        multi_child.clone(),
        second_parent,
        DependencyKind::InheritanceOf,
    ));
    assert!(graph.check_inheritance_cycle(&multi_child, &ancestor));
    assert!(!graph.check_inheritance_cycle(&ancestor, &multi_child));
}
