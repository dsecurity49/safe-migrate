use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;

static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !pointer.is_null() {
            ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(new_size, Ordering::Relaxed);
        }
        pointer
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

mod performance_scenarios {
    use super::{ALLOCATED_BYTES, ALLOCATION_COUNT};
    use crate::common::{object_id, setup_engine, setup_state};
    use safe_migrate::_internal::db::cache::{DbCache, DbCacheVersioned};
    use safe_migrate::_internal::db::cache_file::{
        CACHE_KEY_ENV, protect_cache_bytes, unprotect_cache_bytes,
    };
    use safe_migrate::_internal::model::relation::{Persistence, RelationKind, RelationState};
    use safe_migrate::_internal::test_support::EnvironmentValueGuard;
    use std::io::Cursor;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    const LARGE_BASELINE_RELATIONS: usize = 1_000;
    const LONG_CHAIN_STATEMENTS: usize = 1_000;
    const ROLLBACK_STATEMENTS: usize = 500;
    const SAVEPOINT_ITERATIONS: usize = 250;
    const GRAPH_OBJECTS: usize = 100;
    const REPORT_FINDINGS: usize = 250;

    fn report_elapsed(scenario: &str, statements: usize, elapsed: std::time::Duration) {
        eprintln!(
            "scenario={scenario} statements={statements} elapsed_ms={}",
            elapsed.as_millis()
        );
    }

    fn baseline_with_relations(relations: usize) -> DbCache {
        let mut cache = crate::common::synced_cache();
        cache.search_path = vec!["public".to_string()];
        for index in 0..relations {
            let id = object_id("public", &format!("perf_baseline_{index}"));
            cache.insert_baseline(
                id.clone(),
                RelationState::new(
                    id,
                    object_id("public", "postgres"),
                    0,
                    Some(1_000),
                    RelationKind::Table,
                    Persistence::Permanent,
                    0,
                ),
            );
        }
        cache
    }

    fn large_baseline() -> DbCache {
        baseline_with_relations(LARGE_BASELINE_RELATIONS)
    }

    fn allocation_snapshot() -> (usize, usize) {
        (
            ALLOCATION_COUNT.load(Ordering::Relaxed),
            ALLOCATED_BYTES.load(Ordering::Relaxed),
        )
    }

    fn allocation_delta(before: (usize, usize)) -> (usize, usize) {
        let after = allocation_snapshot();
        (after.0 - before.0, after.1 - before.1)
    }

    #[test]
    #[ignore = "manual allocation scenario; run alone with --ignored --nocapture"]
    fn large_state_checkpoint_and_prestate_capture() {
        let state =
            crate::_internal::analysis::state::AnalysisState::with_baseline(large_baseline(), true);

        let started = Instant::now();
        let before = allocation_snapshot();
        let checkpoint = std::hint::black_box(state.clone());
        let checkpoint_allocations = allocation_delta(before);
        let checkpoint_elapsed = started.elapsed();
        assert_eq!(checkpoint.local.relations.len(), LARGE_BASELINE_RELATIONS);

        let started = Instant::now();
        let before = allocation_snapshot();
        let pre_state = std::hint::black_box(state.capture_pre_state());
        let pre_state_allocations = allocation_delta(before);
        let pre_state_elapsed = started.elapsed();
        assert_eq!(pre_state.relations.len(), LARGE_BASELINE_RELATIONS);

        eprintln!(
            "scenario=large_state_checkpoint relations={LARGE_BASELINE_RELATIONS} allocations={} allocated_bytes={} elapsed_us={}",
            checkpoint_allocations.0,
            checkpoint_allocations.1,
            checkpoint_elapsed.as_micros()
        );
        eprintln!(
            "scenario=large_prestate_capture relations={LARGE_BASELINE_RELATIONS} allocations={} allocated_bytes={} elapsed_us={}",
            pre_state_allocations.0,
            pre_state_allocations.1,
            pre_state_elapsed.as_micros()
        );
    }

    #[test]
    #[ignore = "manual allocation scenario; run alone with --ignored --nocapture"]
    fn large_baseline_short_chain_allocations() {
        let engine = setup_engine();
        let mut state =
            crate::_internal::analysis::state::AnalysisState::with_baseline(large_baseline(), true);
        let files = (0..50)
            .map(|index| {
                (
                    format!("V{index:04}__alter.sql"),
                    format!("ALTER TABLE perf_baseline_{index} ADD COLUMN measured_value integer;"),
                )
            })
            .collect::<Vec<_>>();

        let started = Instant::now();
        let before = allocation_snapshot();
        let findings = engine
            .analyze_chain(&files, &mut state)
            .expect("large-baseline allocation chain should analyze");
        let allocations = allocation_delta(before);
        let elapsed = started.elapsed();

        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id != "chain-conflict"),
            "unexpected state conflict: {findings:?}"
        );
        let relation = state
            .get_relation(&object_id("public", "perf_baseline_49"))
            .expect("last baseline relation should remain present");
        let safe_migrate::_internal::model::relation::RelationOverlay::Present(relation) = relation
        else {
            panic!("last baseline relation was dropped");
        };
        assert!(relation.has_column("measured_value"));
        eprintln!(
            "scenario=large_baseline_short_chain statements=50 relations={LARGE_BASELINE_RELATIONS} allocations={} allocated_bytes={} elapsed_ms={}",
            allocations.0,
            allocations.1,
            elapsed.as_millis()
        );
    }

    #[test]
    #[ignore = "manual allocation scenario; run alone with --ignored --nocapture"]
    fn large_baseline_rename_chain_allocations() {
        let engine = setup_engine();
        let mut state =
            crate::_internal::analysis::state::AnalysisState::with_baseline(large_baseline(), true);
        let files = (0..50)
            .map(|index| {
                (
                    format!("V{index:04}__rename.sql"),
                    format!("ALTER TABLE perf_baseline_{index} RENAME TO perf_renamed_{index};"),
                )
            })
            .collect::<Vec<_>>();

        let started = Instant::now();
        let before = allocation_snapshot();
        let findings = engine
            .analyze_chain(&files, &mut state)
            .expect("large-baseline rename chain should analyze");
        let allocations = allocation_delta(before);
        let elapsed = started.elapsed();

        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id != "chain-conflict"),
            "unexpected state conflict: {findings:?}"
        );
        assert!(state.relation_is_present(&object_id("public", "perf_renamed_49")));
        eprintln!(
            "scenario=large_baseline_rename_chain statements=50 relations={LARGE_BASELINE_RELATIONS} allocations={} allocated_bytes={} elapsed_ms={}",
            allocations.0,
            allocations.1,
            elapsed.as_millis()
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn pre_state_capture_against_large_baselines() {
        use crate::_internal::analysis::mutations::{
            AlterTable, AlterTableActionMutation, Mutation,
        };
        use crate::_internal::analysis::state::{PreState, PreStateReadSet};
        use crate::_internal::ast::identifiers::ObjectId;
        use crate::_internal::engine::pre_state_footprint;

        const CAPTURES: usize = 1_000;

        for relations in [100, 1_000, 10_000] {
            let state = crate::_internal::analysis::state::AnalysisState::with_baseline(
                baseline_with_relations(relations),
                true,
            );
            let mutation = Mutation::AlterTable(AlterTable {
                id: ObjectId::new("public", "perf_baseline_0"),
                only: false,
                action: AlterTableActionMutation::DropColumn {
                    name: "unused".to_string(),
                    if_exists: true,
                    cascade: false,
                },
            });
            let full = PreStateReadSet::full();
            let selective = pre_state_footprint::for_mutation(&state, &mutation, None);
            let mut pre_state = PreState::default();

            state.capture_pre_state_into(&mut pre_state, &full);
            let started = Instant::now();
            for _ in 0..CAPTURES {
                state.capture_pre_state_into(&mut pre_state, &full);
            }
            let full_ms = started.elapsed().as_millis();

            let started = Instant::now();
            for _ in 0..CAPTURES {
                state.capture_pre_state_into(&mut pre_state, &selective);
            }
            let selective_ms = started.elapsed().as_millis();

            eprintln!(
                "scenario=pre_state_capture relations={relations} captures={CAPTURES} full_ms={full_ms} selective_ms={selective_ms}"
            );
        }
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn thousand_alter_mutations_against_large_baselines() {
        use crate::_internal::analysis::mutations::{
            AlterTable, AlterTableActionMutation, Mutation,
        };
        use crate::_internal::analysis::state::{PreState, PreStateReadSet};
        use crate::_internal::ast::identifiers::ObjectId;
        use crate::_internal::engine::pre_state_footprint;

        const MUTATIONS: usize = 1_000;

        for relations in [100, 1_000, 10_000] {
            let state = crate::_internal::analysis::state::AnalysisState::with_baseline(
                baseline_with_relations(relations),
                true,
            );
            let mutations = (0..MUTATIONS)
                .map(|index| {
                    Mutation::AlterTable(AlterTable {
                        id: ObjectId::new("public", format!("perf_baseline_{}", index % relations)),
                        only: false,
                        action: AlterTableActionMutation::DropColumn {
                            name: "unused".to_string(),
                            if_exists: true,
                            cascade: false,
                        },
                    })
                })
                .collect::<Vec<_>>();
            let full = PreStateReadSet::full();
            let mut pre_state = PreState::default();

            let started = Instant::now();
            for _ in &mutations {
                state.capture_pre_state_into(&mut pre_state, &full);
            }
            let full_ms = started.elapsed().as_millis();

            let started = Instant::now();
            for mutation in &mutations {
                let reads = pre_state_footprint::for_mutation(&state, mutation, None);
                state.capture_pre_state_into(&mut pre_state, &reads);
            }
            let selective_ms = started.elapsed().as_millis();

            eprintln!(
                "scenario=pre_state_mutation_footprint relations={relations} mutations={MUTATIONS} full_ms={full_ms} selective_ms={selective_ms}"
            );
        }
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn ordered_thousand_statement_chain() {
        let engine = setup_engine();
        let mut state = setup_state();
        let files = (0..LONG_CHAIN_STATEMENTS)
            .map(|index| {
                (
                    format!("V{index:04}__create.sql"),
                    format!("CREATE TABLE IF NOT EXISTS perf_chain_{index} (id bigint NOT NULL);"),
                )
            })
            .collect::<Vec<_>>();

        let started = Instant::now();
        let findings = engine
            .analyze_chain(&files, &mut state)
            .expect("long ordered chain should analyze");
        let elapsed = started.elapsed();

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
        assert!(state.relation_is_present(&object_id("public", "perf_chain_999")));
        report_elapsed(
            "ordered_thousand_statement_chain",
            LONG_CHAIN_STATEMENTS,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual allocation scenario; run alone with --ignored --nocapture"]
    fn large_baseline_schema_rename_allocations() {
        let engine = setup_engine();
        let mut state =
            crate::_internal::analysis::state::AnalysisState::with_baseline(large_baseline(), true);
        for statement in [
            "CREATE SCHEMA perf_schema;",
            "CREATE TABLE perf_schema.only_table (id integer);",
            "BEGIN;",
        ] {
            let findings = engine
                .analyze(statement, &mut state)
                .unwrap_or_else(|errors| panic!("setup failed on {statement}: {errors:?}"));
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.rule_id != "chain-conflict"),
                "unexpected state conflict on {statement}: {findings:?}"
            );
        }

        let before = allocation_snapshot();
        let started = Instant::now();
        let findings = engine
            .analyze(
                "ALTER SCHEMA perf_schema RENAME TO perf_schema_moved;",
                &mut state,
            )
            .expect("schema rename should analyze");
        let rollback = engine
            .analyze("ROLLBACK;", &mut state)
            .expect("schema rename rollback should analyze");
        let allocations = allocation_delta(before);
        let elapsed = started.elapsed();

        assert!(
            findings
                .iter()
                .chain(&rollback)
                .all(|finding| finding.rule_id != "chain-conflict"),
            "unexpected state conflict: {findings:?} {rollback:?}"
        );
        assert!(state.relation_is_present(&object_id("perf_schema", "only_table")));
        assert!(!state.relation_is_present(&object_id("perf_schema_moved", "only_table")));
        eprintln!(
            "scenario=large_baseline_schema_rename statements=2 relations={LARGE_BASELINE_RELATIONS} allocations={} allocated_bytes={} elapsed_ms={}",
            allocations.0,
            allocations.1,
            elapsed.as_millis()
        );
    }

    #[test]
    #[ignore = "manual allocation scenario; run alone with --ignored --nocapture"]
    fn large_graph_index_and_definition_update_allocations() {
        use safe_migrate::_internal::analysis::graph::{
            DependencyEdge, DependencyGraph, DependencyKind,
        };
        use safe_migrate::_internal::model::index::{IndexDefinition, IndexPredicate, index_keys};

        const INDEXES: usize = 10_000;
        const UPDATES: usize = 1_000;
        const RENAME_CHAIN: usize = 100;
        const FOREIGN_KEYS: usize = 1_000;
        const TRIGGERS: usize = 1_000;
        const INHERITANCE_EDGES: usize = 1_000;

        let build_graph = || {
            let mut graph = DependencyGraph::new();
            for rename in 0..RENAME_CHAIN {
                graph.add_edge(DependencyEdge::new(
                    object_id("public", &format!("perf_shared_table_{rename}")),
                    object_id("public", &format!("perf_shared_table_{}", rename + 1)),
                    DependencyKind::RenameTo,
                ));
            }
            for foreign_key in 0..FOREIGN_KEYS {
                graph.add_edge(DependencyEdge::new(
                    object_id("public", &format!("perf_fk_table_{foreign_key}")),
                    object_id(
                        "public",
                        &format!("perf_fk_table_{}", (foreign_key + 1) % FOREIGN_KEYS),
                    ),
                    DependencyKind::ForeignKey {
                        constraint_name: Some(format!("perf_fk_{foreign_key}")),
                        from_columns: vec!["id".into()],
                        to_columns: vec!["id".into()],
                        operator_evidence: None,
                        from_generation: 0,
                    },
                ));
            }
            for trigger in 0..TRIGGERS {
                let trigger_id = object_id("public", &format!("perf_trigger_{trigger}"));
                graph.add_edge(DependencyEdge::new(
                    trigger_id.clone(),
                    object_id("public", &format!("perf_trigger_table_{trigger}")),
                    DependencyKind::TriggerOnTable {
                        trigger_id,
                        function_id: object_id("public", &format!("perf_trigger_fn_{trigger}")),
                        trigger_generation: 0,
                    },
                ));
            }
            for inheritance in 0..INHERITANCE_EDGES {
                graph.add_edge(DependencyEdge::new(
                    object_id("public", &format!("perf_child_table_{inheritance}")),
                    object_id("public", &format!("perf_parent_table_{inheritance}")),
                    DependencyKind::InheritanceOf,
                ));
            }
            let written_table = object_id("public", "perf_shared_table_0");
            for index in 0..INDEXES {
                graph.add_edge(DependencyEdge::new(
                    object_id("public", &format!("perf_index_{index}")),
                    written_table.clone(),
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
            }
            graph
        };

        let renamed_table = object_id("public", &format!("perf_shared_table_{RENAME_CHAIN}"));

        let mut graph = build_graph();
        let before = allocation_snapshot();
        let started = Instant::now();
        graph.build_indexes_for_tests();
        let index_allocations = allocation_delta(before);
        let index_elapsed = started.elapsed();

        let before = allocation_snapshot();
        let started = Instant::now();
        assert_eq!(graph.cascade_edges(&renamed_table).len(), INDEXES);
        let warm_lookup_allocations = allocation_delta(before);
        let warm_lookup_elapsed = started.elapsed();

        let update_ids = (0..UPDATES)
            .map(|index| object_id("public", &format!("perf_index_{index}")))
            .collect::<Vec<_>>();
        let before = allocation_snapshot();
        let started = Instant::now();
        for index in &update_ids {
            graph.update_index_definition(index, |definition| definition.valid = false);
        }
        let update_allocations = allocation_delta(before);
        let update_elapsed = started.elapsed();
        assert!(graph.indexes_are_valid());
        assert!(graph.edge_set_is_valid());

        let cold_graph = build_graph();
        let before = allocation_snapshot();
        let started = Instant::now();
        assert_eq!(cold_graph.cascade_edges(&renamed_table).len(), INDEXES);
        let cold_lookup_allocations = allocation_delta(before);
        let cold_lookup_elapsed = started.elapsed();

        eprintln!(
            "scenario=large_graph_index_construction edges={} renames={RENAME_CHAIN} allocations={} allocated_bytes={} elapsed_ms={}",
            INDEXES + RENAME_CHAIN + FOREIGN_KEYS + TRIGGERS + INHERITANCE_EDGES,
            index_allocations.0,
            index_allocations.1,
            index_elapsed.as_millis()
        );
        eprintln!(
            "scenario=large_graph_warm_cascade_lookup lookups=1 edges={} renames={RENAME_CHAIN} allocations={} allocated_bytes={} elapsed_ms={}",
            INDEXES + RENAME_CHAIN + FOREIGN_KEYS + TRIGGERS + INHERITANCE_EDGES,
            warm_lookup_allocations.0,
            warm_lookup_allocations.1,
            warm_lookup_elapsed.as_millis()
        );
        eprintln!(
            "scenario=large_graph_definition_updates updates={UPDATES} edges={} allocations={} allocated_bytes={} elapsed_ms={}",
            INDEXES + RENAME_CHAIN + FOREIGN_KEYS + TRIGGERS + INHERITANCE_EDGES,
            update_allocations.0,
            update_allocations.1,
            update_elapsed.as_millis()
        );
        eprintln!(
            "scenario=large_graph_cold_cascade_lookup lookups=1 edges={} renames={RENAME_CHAIN} allocations={} allocated_bytes={} elapsed_ms={}",
            INDEXES + RENAME_CHAIN + FOREIGN_KEYS + TRIGGERS + INHERITANCE_EDGES,
            cold_lookup_allocations.0,
            cold_lookup_allocations.1,
            cold_lookup_elapsed.as_millis()
        );
    }

    #[test]
    #[ignore = "manual allocation scenario; run alone with --ignored --nocapture"]
    fn large_baseline_type_resolution_after_temp_rollback() {
        const RESOLUTIONS: usize = 10_000;

        let engine = setup_engine();
        let mut state =
            crate::_internal::analysis::state::AnalysisState::with_baseline(large_baseline(), true);
        let findings = engine
            .analyze(
                "BEGIN;\nCREATE TEMP TABLE pg_temp.perf_temp (id bigint NOT NULL);\nROLLBACK;",
                &mut state,
            )
            .expect("temp rollback scenario should analyze");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id != "chain-conflict"),
            "unexpected state conflict: {findings:?}"
        );
        assert!(
            !state.temp_namespace_exists(),
            "rollback must remove the temp namespace created by the transaction"
        );

        fn measure(label: &str, state: &mut crate::_internal::analysis::state::AnalysisState) {
            for _ in 0..100 {
                std::hint::black_box(state.resolve_type_reference("integer"));
            }
            let started = Instant::now();
            for _ in 0..RESOLUTIONS {
                std::hint::black_box(state.resolve_type_reference("integer"));
            }
            eprintln!(
                "scenario=large_baseline_type_resolution_temp_state={label} resolutions={RESOLUTIONS} relations={LARGE_BASELINE_RELATIONS} elapsed_ms={}",
                started.elapsed().as_millis()
            );
        }

        measure("after_rollback", &mut state);

        let findings = engine
            .analyze(
                "CREATE TEMP TABLE pg_temp.perf_temp (id bigint NOT NULL);",
                &mut state,
            )
            .expect("temp creation should analyze");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id != "chain-conflict"),
            "unexpected state conflict: {findings:?}"
        );
        assert!(
            state.temp_namespace_exists(),
            "creating a temp table must establish the session temp namespace"
        );
        measure("namespace_present", &mut state);
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn large_synchronized_baseline_hydration() {
        let started = Instant::now();
        let state =
            crate::_internal::analysis::state::AnalysisState::with_baseline(large_baseline(), true);
        let elapsed = started.elapsed();

        assert!(state.baseline_available);
        assert_eq!(state.baseline_relations.len(), LARGE_BASELINE_RELATIONS);
        assert!(state.relation_is_present(&object_id("public", "perf_baseline_999")));
        report_elapsed(
            "large_synchronized_baseline_hydration",
            LARGE_BASELINE_RELATIONS,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn cache_encode_compress_encrypt_round_trip() {
        let cache = large_baseline();
        let started = Instant::now();
        let config = bincode::config::standard().with_variable_int_encoding();
        let payload = bincode::serde::encode_to_vec(DbCacheVersioned::current(cache), config)
            .expect("cache should encode");
        let compressed = zstd::stream::encode_all(Cursor::new(payload), 3)
            .expect("cache payload should compress");
        let _cache_key = EnvironmentValueGuard::set(
            CACHE_KEY_ENV,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        let encrypted = protect_cache_bytes(compressed, true).expect("cache should encrypt");
        let compressed =
            unprotect_cache_bytes(encrypted.clone(), true).expect("cache should decrypt");
        let payload = zstd::stream::decode_all(Cursor::new(compressed))
            .expect("cache payload should decompress");
        let decoded: DbCacheVersioned = bincode::serde::decode_from_slice(&payload, config)
            .expect("cache payload should decode")
            .0;
        let cache = decoded
            .into_cache()
            .expect("cache version should be current");
        let elapsed = started.elapsed();

        assert_eq!(cache.relations.len(), LARGE_BASELINE_RELATIONS);
        eprintln!(
            "scenario=cache_encode_compress_encrypt_round_trip relations={LARGE_BASELINE_RELATIONS} encrypted_bytes={} elapsed_ms={}",
            encrypted.len(),
            elapsed.as_millis()
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn rename_and_cascade_dependency_graph() {
        let engine = setup_engine();
        let mut state = setup_state();
        let mut sql = String::from(
            "CREATE TABLE IF NOT EXISTS perf_graph_parent (id bigint PRIMARY KEY);\nCREATE VIEW perf_graph_parent_view AS SELECT id FROM perf_graph_parent;\n",
        );
        for index in 0..GRAPH_OBJECTS {
            sql.push_str(&format!(
                "CREATE TABLE IF NOT EXISTS perf_graph_child_{index} (id bigint PRIMARY KEY, parent_id bigint REFERENCES perf_graph_parent(id));\nCREATE INDEX IF NOT EXISTS perf_graph_child_{index}_parent_idx ON perf_graph_child_{index}(parent_id);\nCREATE VIEW perf_graph_view_{index} AS SELECT parent_id FROM perf_graph_child_{index};\n"
            ));
        }
        sql.push_str(
            "ALTER TABLE perf_graph_parent RENAME TO perf_graph_renamed;\nDROP TABLE perf_graph_renamed CASCADE;",
        );

        let started = Instant::now();
        let findings = engine
            .analyze(&sql, &mut state)
            .expect("graph scenario should analyze");
        let elapsed = started.elapsed();

        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id != "chain-conflict"),
            "graph workload must complete without a state conflict: {findings:?}"
        );
        assert!(!state.relation_is_present(&object_id("public", "perf_graph_renamed")));
        assert!(!state.relation_is_present(&object_id("public", "perf_graph_parent_view")));
        assert!(state.relation_is_present(&object_id("public", "perf_graph_child_0")));
        assert!(state.relation_is_present(&object_id("public", "perf_graph_view_99")));
        report_elapsed(
            "rename_and_cascade_dependency_graph",
            GRAPH_OBJECTS * 3 + 4,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual graph-index scenario; run alone with --ignored --nocapture"]
    fn large_dependency_graph_lookup_index() {
        use safe_migrate::_internal::analysis::graph::{
            DependencyEdge, DependencyGraph, DependencyKind,
        };

        const EDGES: usize = 10_000;
        const TARGETS: usize = 100;
        const ROUNDS: usize = 10;

        let mut graph = DependencyGraph::new();
        for index in 0..EDGES {
            graph.add_edge(DependencyEdge::new(
                object_id("public", &format!("perf_view_{index}")),
                object_id("public", &format!("perf_target_{}", index % TARGETS)),
                DependencyKind::ViewDependency {
                    view_generation: 1,
                    referenced_column: None,
                },
            ));
        }
        let targets = (0..TARGETS)
            .map(|index| object_id("public", &format!("perf_target_{index}")))
            .collect::<Vec<_>>();

        let indexed_started = Instant::now();
        let mut indexed_count = 0;
        for _ in 0..ROUNDS {
            for target in &targets {
                indexed_count += graph.cascade_edges(target).len();
            }
        }
        let indexed_elapsed = indexed_started.elapsed();

        let scan_started = Instant::now();
        let mut scan_count = 0;
        for _ in 0..ROUNDS {
            for target in &targets {
                scan_count += graph
                    .edges()
                    .iter()
                    .filter(|edge| {
                        matches!(edge.kind, DependencyKind::ViewDependency { .. })
                            && edge.referenced == *target
                    })
                    .count();
            }
        }
        let scan_elapsed = scan_started.elapsed();

        assert_eq!(indexed_count, EDGES * ROUNDS);
        assert_eq!(scan_count, indexed_count);
        assert!(graph.indexes_are_valid());
        eprintln!(
            "scenario=large_dependency_graph_lookup_index edges={EDGES} lookups={} indexed_us={} canonical_scan_us={}",
            TARGETS * ROUNDS,
            indexed_elapsed.as_micros(),
            scan_elapsed.as_micros()
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn location_rich_reports_with_many_findings() {
        let engine = setup_engine();
        let mut state = setup_state();
        let sql = (0..REPORT_FINDINGS)
            .map(|index| format!("CREATE TABLE perf_report_{index} (id bigint NOT NULL);"))
            .collect::<Vec<_>>()
            .join("\n");

        let started = Instant::now();
        let findings = engine
            .analyze_with_locations("performance.sql".to_string(), sql, &mut state)
            .expect("report scenario should analyze");
        let json = crate::_internal::report::reporter::Reporter::json_report_with_locations(
            &findings,
            &state.local.confidence,
            state.not_evaluated(),
        );
        let markdown = crate::_internal::report::reporter::Reporter::markdown_report(
            &findings,
            &state.local.confidence,
            &[],
        );
        let elapsed = started.elapsed();

        assert_eq!(findings.len(), REPORT_FINDINGS);
        assert_eq!(json["summary"]["total"], REPORT_FINDINGS);
        assert!(markdown.contains("perf_report_249"));
        report_elapsed(
            "location_rich_reports_with_many_findings",
            REPORT_FINDINGS,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn long_transaction_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        let mut sql = String::from("BEGIN;\n");
        for index in 0..ROLLBACK_STATEMENTS {
            sql.push_str(&format!(
                "CREATE TABLE perf_undo_{index} (id bigint NOT NULL);\n"
            ));
        }
        sql.push_str("ALTER TABLE perf_undo_0 DROP COLUMN missing_column;\nCOMMIT;");

        let started = Instant::now();
        let findings = engine
            .analyze(&sql, &mut state)
            .expect("rollback scenario should analyze");
        let elapsed = started.elapsed();

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "missing rollback conflict: {findings:?}"
        );
        for index in 0..ROLLBACK_STATEMENTS {
            assert!(
                !state.relation_is_present(&object_id("public", &format!("perf_undo_{index}"))),
                "rollback left perf_undo_{index} present"
            );
        }
        report_elapsed(
            "long_transaction_rollback",
            ROLLBACK_STATEMENTS + 3,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn multi_action_failure_restores_the_statement_state() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE perf_multi_action (id bigint NOT NULL);",
                &mut state,
            )
            .expect("baseline table should analyze");

        let started = Instant::now();
        let findings = engine
            .analyze(
                "BEGIN;
                 ALTER TABLE perf_multi_action
                    ADD COLUMN first_value integer,
                    ADD COLUMN second_value integer,
                    DROP COLUMN missing_column;
                 COMMIT;",
                &mut state,
            )
            .expect("multi-action rollback scenario should analyze");
        let elapsed = started.elapsed();

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        let relation = state
            .local
            .relations
            .get(&object_id("public", "perf_multi_action"))
            .expect("baseline relation should remain modeled");
        let safe_migrate::_internal::model::relation::RelationOverlay::Present(relation) = relation
        else {
            panic!("failed transaction must not drop the baseline relation");
        };
        assert!(
            relation
                .columns
                .iter()
                .all(|column| { column.name != "first_value" && column.name != "second_value" })
        );
        report_elapsed(
            "multi_action_failure_restores_the_statement_state",
            3,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn repeated_savepoint_rollbacks_leave_no_transient_relations() {
        let engine = setup_engine();
        let mut state = setup_state();
        let mut sql = String::from("BEGIN;\n");
        for index in 0..SAVEPOINT_ITERATIONS {
            sql.push_str(&format!(
                "SAVEPOINT checkpoint_{index};\nCREATE TABLE IF NOT EXISTS perf_savepoint_{index} (id bigint NOT NULL);\nROLLBACK TO SAVEPOINT checkpoint_{index};\n"
            ));
        }
        sql.push_str("COMMIT;");

        let started = Instant::now();
        let findings = engine
            .analyze(&sql, &mut state)
            .expect("savepoint scenario should analyze");
        let elapsed = started.elapsed();

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
        assert!(!state.relation_is_present(&object_id("public", "perf_savepoint_0")));
        assert!(!state.relation_is_present(&object_id("public", "perf_savepoint_249")));
        report_elapsed(
            "repeated_savepoint_rollbacks_leave_no_transient_relations",
            SAVEPOINT_ITERATIONS * 3 + 2,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual allocation scenario; run alone with --ignored --nocapture"]
    fn large_graph_rename_plan_allocations_and_fast_path() {
        use safe_migrate::_internal::analysis::graph::{
            DependencyEdge, DependencyGraph, DependencyKind, GraphRenamePlan,
        };
        use safe_migrate::_internal::ast::identifiers::ObjectId;
        use safe_migrate::_internal::model::index::{IndexDefinition, IndexPredicate, index_keys};

        const EDGES: usize = 10_000;
        let mut graph = DependencyGraph::new();

        for i in 0..EDGES {
            let index_id = ObjectId::new("public", format!("idx_{i}"));
            let table_id = ObjectId::new("public", format!("tbl_{i}"));
            graph.add_edge(DependencyEdge::new(
                index_id,
                table_id,
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
        }

        let mut plan = GraphRenamePlan::default();
        plan.relations.insert(
            ObjectId::new("public", "tbl_0"),
            ObjectId::new("public", "tbl_0_renamed"),
        );

        let initial_edges = graph.edges().to_vec();
        let target_index = ObjectId::new("public", "idx_0");

        let before = allocation_snapshot();
        let started = Instant::now();
        let delta = graph
            .apply_rename_plan_recorded(&plan)
            .expect("rename plan must apply");
        let allocations = allocation_delta(before);
        let elapsed = started.elapsed();

        assert_eq!(graph.edge_count(), EDGES);
        assert_eq!(
            graph.index_table_of(&target_index),
            Some(&ObjectId::new("public", "tbl_0_renamed"))
        );
        assert!(graph.indexes_are_valid());

        let before = allocation_snapshot();
        let started = Instant::now();
        graph.restore_edge_delta(delta);
        let rollback_allocs = allocation_delta(before);
        let rollback_elapsed = started.elapsed();

        assert_eq!(graph.edge_count(), EDGES);
        assert_eq!(
            graph.index_table_of(&target_index),
            Some(&ObjectId::new("public", "tbl_0"))
        );
        assert_eq!(graph.edges(), initial_edges.as_slice());
        assert!(graph.indexes_are_valid());

        eprintln!(
            "scenario=large_graph_rename_plan_single_change edges={EDGES} allocations={} allocated_bytes={} elapsed_ms={}",
            allocations.0,
            allocations.1,
            elapsed.as_millis()
        );
        eprintln!(
            "scenario=large_graph_rename_plan_rollback edges={EDGES} allocations={} allocated_bytes={} elapsed_ms={}",
            rollback_allocs.0,
            rollback_allocs.1,
            rollback_elapsed.as_millis()
        );
    }

    #[test]
    #[ignore = "manual allocation scenario; run alone with --ignored --nocapture"]
    fn large_graph_batched_column_rename_sparse_vs_unrelated() {
        use safe_migrate::_internal::analysis::expr_ir::ExprIr;
        use safe_migrate::_internal::analysis::graph::{
            DependencyEdge, DependencyGraph, DependencyKind,
        };
        use safe_migrate::_internal::ast::identifiers::ObjectId;
        use safe_migrate::_internal::model::index::{
            IndexDefinition, IndexKey, IndexKeyKind, IndexPredicate, index_keys,
        };
        use std::collections::HashSet;

        const EDGES: usize = 10_000;
        let mut graph = DependencyGraph::new();

        let target_table = ObjectId::new("public", "target_tbl");
        let other_table = ObjectId::new("public", "other_tbl");

        // 1 target edge that actually matches
        graph.add_edge(DependencyEdge::new(
            ObjectId::new("public", "target_idx"),
            target_table.clone(),
            DependencyKind::IndexOnRelation {
                definition: IndexDefinition {
                    method: Some("btree".into()),
                    keys: index_keys(vec!["target_col".into()]),
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

        // 9,999 unrelated expression and column indexes
        for i in 1..EDGES {
            let index_id = ObjectId::new("public", format!("idx_{i}"));
            graph.add_edge(DependencyEdge::new(
                index_id,
                other_table.clone(),
                DependencyKind::IndexOnRelation {
                    definition: IndexDefinition {
                        method: Some("btree".into()),
                        keys: vec![IndexKey {
                            kind: IndexKeyKind::CatalogExpression(ExprIr::ColumnRef(
                                "unrelated_col".into(),
                            )),
                            opclass: safe_migrate::_internal::model::index::KeyOpclass::Default(
                                None,
                            ),
                            collation: safe_migrate::_internal::model::index::KeyCollation::Derived,
                            order: safe_migrate::_internal::model::index::IndexOrder::Default,
                        }],
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
                    dependency_columns: vec!["unrelated_col".into()],
                    dependency_columns_known: true,
                    is_concurrent: false,
                    is_immediate: true,
                    eligibility_known: true,
                },
            ));
        }

        let mut affected = HashSet::new();
        affected.insert(target_table);

        let before = allocation_snapshot();
        let started = Instant::now();
        let delta = graph
            .rename_columns_for_relations_recorded(&affected, "target_col", "renamed_col")
            .expect("must mutate the target edge");
        let allocations = allocation_delta(before);
        let elapsed = started.elapsed();

        assert_eq!(graph.edge_count(), EDGES);
        assert!(graph.indexes_are_valid());

        let before = allocation_snapshot();
        let started = Instant::now();
        graph.restore_edge_delta(delta);
        let rollback_allocs = allocation_delta(before);
        let rollback_elapsed = started.elapsed();

        assert_eq!(graph.edge_count(), EDGES);
        assert!(graph.indexes_are_valid());

        eprintln!(
            "scenario=large_graph_batched_column_rename edges={EDGES} allocations={} allocated_bytes={} elapsed_ms={}",
            allocations.0,
            allocations.1,
            elapsed.as_millis()
        );
        eprintln!(
            "scenario=large_graph_batched_column_rename_rollback edges={EDGES} allocations={} allocated_bytes={} elapsed_ms={}",
            rollback_allocs.0,
            rollback_allocs.1,
            rollback_elapsed.as_millis()
        );
    }
}
