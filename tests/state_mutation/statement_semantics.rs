use super::*;

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
    engine
        .analyze(
            "BEGIN; ALTER TABLE generated_text ALTER COLUMN doubled SET EXPRESSION AS (base * 4);",
            &mut state,
        )
        .unwrap();
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
fn aborted_compound_statement_does_not_leak_not_evaluated_records() {
    let engine = setup_engine();
    let mut state = AnalysisState::new(cache_with_table("public", "t", None));

    engine.analyze("BEGIN;", &mut state).unwrap();
    let findings = engine
        .analyze(
            "ALTER TABLE t DROP COLUMN missing, ADD COLUMN a integer, ADD COLUMN a integer;",
            &mut state,
        )
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "the duplicate column should abort the statement: {findings:?}"
    );
    assert!(
        state.not_evaluated().is_empty(),
        "the aborted statement leaked not-evaluated records: {:?}",
        state.not_evaluated()
    );
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
fn like_extended_statistics_follow_column_lifecycle_and_rollback() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze("CREATE TABLE source (a integer, b integer);", &mut state)
        .unwrap();
    let source = object_id("public", "source");
    let statistics_id = object_id("public", "source_a_b_stat");
    let Some(RelationOverlay::Present(source_relation)) = state.local.relations.get_mut(&source)
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
            owner: None,
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
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "PostgreSQL records DEPENDENCY_AUTO on extended statistics columns and drops the statistics automatically on DROP COLUMN RESTRICT: {findings:?}"
    );
    assert!(state
            .get_relation(&copy)
            .is_some_and(|overlay| matches!(overlay, RelationOverlay::Present(relation) if !relation.has_column("renamed") && relation.extended_statistics.is_empty())));
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
fn a_statement_the_build_claims_keeps_every_action() {
    use safe_migrate::_internal::model::relation::RelationOverlay;
    use safe_migrate::_internal::model::sequence::SequenceOverlay;

    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE t (a int, b int);
                 CREATE SEQUENCE s INCREMENT BY 1;
                 ALTER TABLE t ADD COLUMN c int, ALTER COLUMN a SET DEFAULT 1;
                 ALTER SEQUENCE s INCREMENT BY 2 CACHE 5;",
            &mut state,
        )
        .expect("the statements should analyze");

    assert!(
        state
            .local
            .relations
            .get(&object_id("public", "t"))
            .is_some_and(|overlay| matches!(
                overlay,
                RelationOverlay::Present(relation)
                    if relation.has_column("c") && relation.has_column("a")
            )),
        "ALTER TABLE must apply every action it carries"
    );
    assert!(
        state
            .local
            .sequences
            .get(&object_id("public", "s"))
            .is_some_and(|overlay| matches!(
                overlay,
                SequenceOverlay::Present(sequence)
                    if sequence.parameters.increment == 2
                        && sequence.parameters.cache_size == 5
            )),
        "ALTER SEQUENCE must apply every option it carries"
    );
}

#[test]
fn if_exists_guards_only_the_relation_lookup() {
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

    // PostgreSQL notices and skips; neither statement is an error.
    assert!(
        conflicts("ALTER VIEW IF EXISTS missing RENAME TO other;").is_empty(),
        "ALTER VIEW IF EXISTS must skip a missing view"
    );
    assert!(
        conflicts("ALTER MATERIALIZED VIEW IF EXISTS missing RENAME TO other;").is_empty(),
        "ALTER MATERIALIZED VIEW IF EXISTS must skip a missing view"
    );

    // The guard does not cover a relation of the wrong kind.
    assert!(
        conflicts("CREATE TABLE t (a int); ALTER VIEW IF EXISTS t RENAME TO other;")
            .iter()
            .any(|message| message.contains("is not a view")),
        "IF EXISTS must not suppress the wrong-kind error"
    );

    // Without the guard the same statement conflicts.
    assert!(
        conflicts("ALTER VIEW missing RENAME TO other;")
            .iter()
            .any(|message| message.contains("does not exist")),
        "an unguarded ALTER of a missing view must conflict"
    );
}

#[test]
fn a_rejected_declaration_does_not_block_the_valid_ones() {
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine
        .analyze(
            "CREATE TABLE ok_a (c text, d text[], e serial, f bigserial);
                 CREATE DOMAIN ok_dom AS text;
                 CREATE TYPE ok_enum AS ENUM ('a', 'b');
                 CREATE TYPE ok_comp AS (a int, b text);
                 CREATE TYPE ok_range AS RANGE (subtype = int4);
                 CREATE TYPE ok_range2 AS RANGE (subtype = text);",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "valid declarations must still apply"
    );
}

#[test]
fn a_canonical_alias_is_not_a_rewrite() {
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine
        .analyze(
            "CREATE TABLE alias_probe (a int, b integer, c int4);
                 ALTER TABLE alias_probe ALTER COLUMN a TYPE integer;
                 ALTER TABLE alias_probe ALTER COLUMN b TYPE int4;",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "type-change-rewrite"),
        "two spellings of one type are one type"
    );
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
fn analyze_on_view_sequence_index_and_composite_type_is_a_noop_like_postgres() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE t (id integer, name text);
             CREATE VIEW v AS SELECT id FROM t;
             CREATE SEQUENCE seq;
             CREATE INDEX idx ON t (id);
             CREATE TYPE comp AS (a integer, b text);
             ANALYZE v (nonexistent_col);
             ANALYZE seq (nonexistent_col);
             ANALYZE idx (nonexistent_col);
             ANALYZE comp;
             ANALYZE t (id);",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings.iter().any(|f| f.rule_id == "chain-conflict"),
        "ANALYZE on view/sequence/index/composite must not conflict: {findings:?}"
    );
    assert_eq!(*state.confidence(), Confidence::Exact);

    let bad = engine
        .analyze("ANALYZE t (missing_col);", &mut state)
        .unwrap();
    assert!(
        bad.iter()
            .any(|f| f.rule_id == "chain-conflict" && f.reason.contains("missing_col")),
        "ANALYZE on table with missing column must conflict: {bad:?}"
    );
}

#[test]
fn create_statistics_enforces_max_dimensions_btree_opclass_and_expression_columns() {
    let engine = setup_engine();
    let mut state = setup_state();
    let setup = engine
        .analyze(
            "CREATE TABLE stats_probe (
                 c1 int, c2 int, c3 int, c4 int, c5 int, c6 int, c7 int, c8 int, c9 int,
                 pt point,
                 pt_arr point[],
                 js json,
                 xm xml,
                 virt int GENERATED ALWAYS AS (c1 + 1) VIRTUAL
             );",
            &mut state,
        )
        .unwrap();
    assert!(!setup.iter().any(|f| f.rule_id == "chain-conflict"));

    for (sql, expected_substr) in [
        (
            "CREATE STATISTICS s_too_many ON c1, c2, c3, c4, c5, c6, c7, c8, c9 FROM stats_probe;",
            "cannot have more than 8 columns in statistics",
        ),
        (
            "CREATE STATISTICS s_too_many_expr ON c1, c2, c3, c4, c5, c6, c7, c8, ((c9 + 1)) FROM stats_probe;",
            "cannot have more than 8 columns in statistics",
        ),
        (
            "CREATE STATISTICS s_point ON pt, c1 FROM stats_probe;",
            "has no default btree operator class",
        ),
        (
            "CREATE STATISTICS s_point_paren ON (pt), c1 FROM stats_probe;",
            "has no default btree operator class",
        ),
        (
            "CREATE STATISTICS s_point_arr ON pt_arr, c1 FROM stats_probe;",
            "has no default btree operator class",
        ),
        (
            "CREATE STATISTICS s_json ON js, c1 FROM stats_probe;",
            "has no default btree operator class",
        ),
        (
            "CREATE STATISTICS s_xml ON xm, c1 FROM stats_probe;",
            "has no default btree operator class",
        ),
        (
            "CREATE STATISTICS s_missing_expr ON ((missing_col + 1)), c1 FROM stats_probe;",
            "column \"missing_col\" does not exist",
        ),
        (
            "CREATE STATISTICS s_dup_paren ON c1, (c1) FROM stats_probe;",
            "duplicate column name in statistics definition",
        ),
        (
            "CREATE STATISTICS s_dup_expr ON ((c1 + 1)), ((c1 + 1)) FROM stats_probe;",
            "duplicate expression in statistics definition",
        ),
        (
            "CREATE STATISTICS s_single_expr_kinds (ndistinct) ON ((c1 + 1)) FROM stats_probe;",
            "when building statistics on a single expression, statistics kinds may not be specified",
        ),
        (
            "CREATE STATISTICS s_syscol ON ctid, c1 FROM stats_probe;",
            "statistics creation on system columns is not supported",
        ),
        (
            "CREATE STATISTICS s_syscol_expr ON ((xmin::text)), c1 FROM stats_probe;",
            "statistics creation on system columns is not supported",
        ),
        (
            "CREATE STATISTICS s_virt ON virt, c1 FROM stats_probe;",
            "statistics creation on virtual generated columns is not supported",
        ),
        (
            "CREATE STATISTICS s_virt_expr ON ((virt + 1)), c1 FROM stats_probe;",
            "statistics creation on virtual generated columns is not supported",
        ),
    ] {
        let mut probe_state = state.clone();
        let findings = engine.analyze(sql, &mut probe_state).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "chain-conflict" && f.reason.contains(expected_substr)),
            "expected '{expected_substr}' for `{sql}`, got: {findings:?}"
        );
    }

    let created = engine
        .analyze(
            "CREATE STATISTICS s_valid_single_expr ON ((c1 + 1)) FROM stats_probe;
             CREATE STATISTICS s_valid_expr_and_col ON ((c1 + c2)), c3 FROM stats_probe;",
            &mut state,
        )
        .unwrap();
    assert!(
        !created.iter().any(|f| f.rule_id == "chain-conflict"),
        "creating expression statistics must succeed: {created:?}"
    );
    assert!(
        state
            .get_relation(&object_id("public", "stats_probe"))
            .is_some_and(|r| match r {
                RelationOverlay::Present(rel) => rel
                    .extended_statistics
                    .contains_key(&object_id("public", "s_valid_expr_and_col")),
                RelationOverlay::Dropped => false,
            }),
        "s_valid_expr_and_col must exist before dropping c2"
    );
    let ok = engine
        .analyze("ALTER TABLE stats_probe DROP COLUMN c2;", &mut state)
        .unwrap();
    assert!(
        !ok.iter().any(|f| f.rule_id == "chain-conflict"),
        "valid expression statistics and DROP COLUMN auto-drop must succeed: {ok:?}"
    );
    let Some(RelationOverlay::Present(rel)) =
        state.get_relation(&object_id("public", "stats_probe"))
    else {
        panic!("stats_probe missing");
    };
    assert!(
        rel.extended_statistics
            .contains_key(&object_id("public", "s_valid_single_expr"))
    );
    assert!(
        !rel.extended_statistics
            .contains_key(&object_id("public", "s_valid_expr_and_col")),
        "dropping c2 must auto-drop s_valid_expr_and_col which references c2 in an expression"
    );
}

#[test]
fn create_and_drop_cast_full_vertical_slice_and_function_dependencies() {
    let engine = setup_engine();
    let mut state = setup_state();
    let setup = engine
        .analyze(
            "CREATE TYPE c_src AS (v int);
             CREATE TYPE c_dst AS (v int);
             CREATE TYPE c_other AS (v int);
             CREATE DOMAIN d_int AS integer;
             CREATE FUNCTION fn_cast_ok(c_src) RETURNS c_dst LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::c_dst';
             CREATE FUNCTION fn_cast_2arg(c_src, integer) RETURNS c_dst LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::c_dst';
             CREATE FUNCTION fn_cast_3arg(c_src, integer, boolean) RETURNS c_dst LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::c_dst';
             CREATE FUNCTION fn_cast_4arg(c_src, integer, boolean, text) RETURNS c_dst LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::c_dst';
             CREATE FUNCTION fn_cast_bad_arg1(c_other) RETURNS c_dst LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::c_dst';
             CREATE FUNCTION fn_cast_bad_arg2(c_src, text) RETURNS c_dst LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::c_dst';
             CREATE FUNCTION fn_cast_bad_arg3(c_src, integer, integer) RETURNS c_dst LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::c_dst';
             CREATE FUNCTION fn_cast_bad_ret(c_src) RETURNS c_other LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::c_other';
             CREATE FUNCTION fn_cast_setof(c_src) RETURNS SETOF c_dst LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::c_dst';",
            &mut state,
        )
        .unwrap();
    assert!(!setup.iter().any(|f| f.rule_id == "chain-conflict"));
    assert_eq!(*state.confidence(), Confidence::Exact);

    for (sql, expected_substr) in [
        (
            "CREATE CAST (internal AS c_dst) WITH INOUT;",
            "source data type internal is a pseudo-type",
        ),
        (
            "CREATE CAST (c_src AS void) WITH INOUT;",
            "target data type void is a pseudo-type",
        ),
        (
            "CREATE CAST (c_src AS c_dst) WITHOUT FUNCTION;",
            "composite data types are not binary-compatible",
        ),
        (
            "CREATE CAST (integer[] AS text[]) WITHOUT FUNCTION;",
            "array data types are not binary-compatible",
        ),
        (
            "CREATE CAST (d_int AS text) WITHOUT FUNCTION;",
            "domain data types must not be marked binary-compatible",
        ),
        (
            "CREATE CAST (int4range AS text) WITHOUT FUNCTION;",
            "range data types are not binary-compatible",
        ),
        (
            "CREATE CAST (integer AS bigint) WITHOUT FUNCTION;",
            "source and target data types are not physically compatible",
        ),
        (
            "CREATE CAST (c_src AS c_dst) WITH FUNCTION fn_cast_4arg(c_src, integer, boolean, text);",
            "cast function must take one to three arguments",
        ),
        (
            "CREATE CAST (c_src AS c_dst) WITH FUNCTION fn_cast_bad_arg1(c_other);",
            "argument of cast function must match or be binary-coercible from source data type",
        ),
        (
            "CREATE CAST (c_src AS c_dst) WITH FUNCTION fn_cast_bad_arg2(c_src, text);",
            "second argument of cast function must be type integer",
        ),
        (
            "CREATE CAST (c_src AS c_dst) WITH FUNCTION fn_cast_bad_arg3(c_src, integer, integer);",
            "third argument of cast function must be type boolean",
        ),
        (
            "CREATE CAST (c_src AS c_dst) WITH FUNCTION fn_cast_bad_ret(c_src);",
            "return data type of cast function must match or be binary-coercible to target data type",
        ),
        (
            "CREATE CAST (c_src AS c_dst) WITH FUNCTION fn_cast_setof(c_src);",
            "cast function must not return a set",
        ),
        (
            "DROP CAST (c_src AS c_dst);",
            "cast from type public.c_src to type public.c_dst does not exist",
        ),
    ] {
        let mut probe = state.clone();
        let findings = engine.analyze(sql, &mut probe).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "chain-conflict" && f.reason.contains(expected_substr)),
            "expected '{expected_substr}' for `{sql}`, got: {findings:?}"
        );
    }

    // Explicit and assignment casts are tracked without tainting the chain!
    let findings = engine
        .analyze(
            "CREATE CAST (c_src AS c_dst) WITH FUNCTION fn_cast_ok(c_src) AS ASSIGNMENT;",
            &mut state,
        )
        .unwrap();
    assert!(!findings.iter().any(|f| f.rule_id == "chain-conflict"));
    assert_eq!(*state.confidence(), Confidence::Exact);

    // Duplicate cast (even with a different context) is rejected:
    let dup = engine
        .analyze(
            "CREATE CAST (c_src AS c_dst) WITH INOUT;",
            &mut state.clone(),
        )
        .unwrap();
    assert!(
        dup.iter()
            .any(|f| f.rule_id == "chain-conflict" && f.reason.contains("already exists")),
        "duplicate cast must conflict: {dup:?}"
    );

    // Dropping the cast function without CASCADE fails:
    let drop_fn = engine
        .analyze("DROP FUNCTION fn_cast_ok(c_src);", &mut state.clone())
        .unwrap();
    assert!(
        drop_fn
            .iter()
            .any(|f| f.rule_id == "chain-conflict" && f.reason.contains("cast from")),
        "dropping cast function without CASCADE must conflict: {drop_fn:?}"
    );

    // Dropping the source type without CASCADE fails:
    let drop_ty = engine
        .analyze("DROP TYPE c_src;", &mut state.clone())
        .unwrap();
    assert!(
        drop_ty
            .iter()
            .any(|f| f.rule_id == "chain-conflict" && f.reason.contains("has dependent objects")),
        "dropping cast source type without CASCADE must conflict: {drop_ty:?}"
    );

    // Dropping the cast function WITH CASCADE removes the cast so it can be recreated:
    let cascade_ok = engine
        .analyze(
            "DROP FUNCTION fn_cast_ok(c_src) CASCADE;
             CREATE CAST (c_src AS c_dst) WITH FUNCTION fn_cast_2arg(c_src, integer);",
            &mut state,
        )
        .unwrap();
    assert!(
        !cascade_ok.iter().any(|f| f.rule_id == "chain-conflict"),
        "DROP FUNCTION CASCADE must drop dependent cast: {cascade_ok:?}"
    );
    assert_eq!(*state.confidence(), Confidence::Exact);
}

#[test]
fn drop_function_on_baseline_cast_function_conflicts_without_cascade_and_drops_cast_with_cascade() {
    use safe_migrate::_internal::analysis::facts::CastContextFact;
    use safe_migrate::_internal::model::cast::{CastEntry, CastEntryMethod};

    let mut cache = synced_cache();
    let src_id = object_id("public", "base_cast_src");
    let dst_id = object_id("public", "base_cast_dst");
    cache.types.insert(
        src_id.clone(),
        TypeState {
            id: src_id.clone(),
            owner: object_id("", "postgres"),
            kind: TypeKind::Composite { fields: Vec::new() },
            generation: 1,
        },
    );
    cache.types.insert(
        dst_id.clone(),
        TypeState {
            id: dst_id.clone(),
            owner: object_id("", "postgres"),
            kind: TypeKind::Composite { fields: Vec::new() },
            generation: 1,
        },
    );
    let func_id = object_id("public", "fn_base_cast(public.base_cast_src)");
    let mut fn_state = FunctionState::with_inputs(
        func_id.clone(),
        RoutineKind::Function,
        vec!["public.base_cast_src".to_string()],
    );
    fn_state.return_type = "public.base_cast_dst".to_string();
    cache.functions.insert(func_id.clone(), fn_state);

    let mut casts = safe_migrate::_internal::model::cast::CastCatalogue::fallback();
    casts.insert_cast(CastEntry {
        source: "public.base_cast_src".to_string(),
        target: "public.base_cast_dst".to_string(),
        context: CastContextFact::Explicit,
        method: CastEntryMethod::WithFunction(Some(func_id.clone())),
    });
    cache.casts = Some(casts);

    let engine = setup_engine();
    let state = AnalysisState::new(cache);

    let findings = engine
        .analyze(
            "DROP FUNCTION fn_base_cast(base_cast_src);",
            &mut state.clone(),
        )
        .unwrap();
    assert!(
        findings.iter().any(|f| f.rule_id == "chain-conflict"
            && f.reason
                .contains("cast from public.base_cast_src to public.base_cast_dst requires it")),
        "dropping a baseline cast's function without CASCADE must conflict: {findings:?}"
    );

    let mut cascade_state = state;
    let ok = engine
        .analyze(
            "DROP FUNCTION fn_base_cast(base_cast_src) CASCADE;",
            &mut cascade_state,
        )
        .unwrap();
    assert!(
        !ok.iter().any(|f| f.rule_id == "chain-conflict"),
        "dropping a baseline cast's function with CASCADE must succeed: {ok:?}"
    );
    assert!(
        !cascade_state
            .casts()
            .has_cast("public.base_cast_src", "public.base_cast_dst"),
        "DROP FUNCTION CASCADE must remove the baseline cast from CastCatalogue"
    );
}

#[test]
fn v12_0_cache_with_partial_cast_coverage_stays_honest_on_drop_cast() {
    let mut cache = synced_cache();
    let src_id = object_id("public", "v12_0_src");
    let dst_id = object_id("public", "v12_0_dst");
    cache.casts = Some(safe_migrate::_internal::model::cast::CastCatalogue::fallback());
    for id in [&src_id, &dst_id] {
        cache.types.insert(
            id.clone(),
            TypeState {
                id: id.clone(),
                owner: object_id("", "postgres"),
                kind: TypeKind::Composite { fields: Vec::new() },
                generation: 1,
            },
        );
    }
    // Simulate a V12.0 cache decoded via bincode (where `entries` was not yet populated).
    let config = bincode::config::standard().with_variable_int_encoding();
    let v12_0 = safe_migrate::_internal::db::cache::DbCacheVersioned::V12(Box::new(cache));
    let bytes = bincode::serde::encode_to_vec(&v12_0, config).unwrap();
    let decoded: safe_migrate::_internal::db::cache::DbCacheVersioned =
        bincode::serde::decode_from_slice(&bytes, config).unwrap().0;
    let hydrated_cache = decoded.into_cache().unwrap();

    let engine = setup_engine();
    let mut state = AnalysisState::new(hydrated_cache);
    let findings = engine
        .analyze("DROP CAST (v12_0_src AS v12_0_dst);", &mut state)
        .unwrap();
    assert!(
        !findings.iter().any(|f| f.rule_id == "chain-conflict"),
        "a V12.0 cache only recorded implicit casts, so DROP CAST on an unrecorded cast must taint rather than falsely claim conflict: {findings:?}"
    );
    assert_eq!(*state.confidence(), Confidence::Tainted);
}

#[test]
fn audit_v0_14_0_c2_to_c6_h1_to_h9_v1_to_v7_m1_to_m3() {
    use safe_migrate::_internal::analysis::facts::CastContextFact;
    use safe_migrate::_internal::db::cache::{RoutineDependencyCache, RoutineDependencyTarget};
    use safe_migrate::_internal::engine::engine::SafeMigrateEngine;
    use safe_migrate::_internal::model::cast::{CastCatalogue, CastEntry, CastEntryMethod};
    use safe_migrate::_internal::model::extension::{
        ExtensionMember, ExtensionMemberKind, ExtensionState,
    };
    use safe_migrate::_internal::model::relation::{ColumnAction, ExtendedStatisticsState};
    use safe_migrate::_internal::model::types::{BaseTypeOptions, TypeKind, TypeState};
    use safe_migrate::api::Config;

    let mut base_cache = synced_cache();
    base_cache.pg_version_num = Some(180_000);

    // C2: DROP EXTENSION owning both a type and a cast on that type
    let mut ext_cache = base_cache.clone();
    let hstore_id = object_id("public", "hstore");
    ext_cache.types.insert(
        hstore_id.clone(),
        TypeState {
            id: hstore_id.clone(),
            kind: TypeKind::Base {
                shell: false,
                options: BaseTypeOptions::default(),
            },
            owner: object_id("", "postgres"),
            generation: 0,
        },
    );
    let mut casts = CastCatalogue::fallback();
    casts.insert_cast(CastEntry {
        source: "public.hstore".into(),
        target: "json".into(),
        context: CastContextFact::Assignment,
        method: CastEntryMethod::WithFunction(Some(object_id(
            "public",
            "hstore_to_json(public.hstore)",
        ))),
    });
    ext_cache.casts = Some(casts);
    ext_cache.extensions.insert(
        "hstore".into(),
        ExtensionState {
            name: "hstore".into(),
            schema: Some("public".into()),
            version: Some("1.8".into()),
            relocatable: Some(true),
            owner: object_id("", "postgres"),
            members_complete: true,
            config_tables: Vec::new(),
            members: [
                ExtensionMember {
                    kind: ExtensionMemberKind::Type,
                    id: hstore_id.clone(),
                },
                ExtensionMember {
                    kind: ExtensionMemberKind::Cast,
                    id: object_id("pg_catalog", "public.hstore->json"),
                },
            ]
            .into_iter()
            .collect(),
            generation: 0,
        },
    );
    let engine = setup_engine();
    let mut s_ext = AnalysisState::new(ext_cache);
    let f_ext = engine
        .analyze("DROP EXTENSION hstore;", &mut s_ext)
        .unwrap();
    assert!(
        !f_ext.iter().any(|v| v.rule_id == "chain-conflict"),
        "C2: DROP EXTENSION owning type + cast must not self-conflict: {f_ext:?}"
    );
    assert_eq!(s_ext.local.confidence, Confidence::Exact);
    assert!(!s_ext.local.casts.has_casts_for_type("public.hstore"));

    // C3: EXISTS (SELECT 1, 2 ...) subquery inside scalar SQL function + MultiColumn composite return
    let mut s_c3 = AnalysisState::new(base_cache.clone());
    let f_c3 = engine
        .analyze(
            "CREATE TABLE public.t (a int, b text);
             CREATE FUNCTION public.scalar_with_exists() RETURNS boolean
                 LANGUAGE sql AS $$ SELECT EXISTS (SELECT 1, 2 FROM public.t WHERE t.a > 0) $$;
             CREATE TYPE public.pair_t AS (x int, y text);
             CREATE FUNCTION public.make_pair() RETURNS public.pair_t
                 LANGUAGE sql BEGIN ATOMIC SELECT a, b FROM public.t; END;",
            &mut s_c3,
        )
        .unwrap();
    assert!(
        !f_c3.iter().any(|v| v.rule_id == "chain-conflict"),
        "C3: EXISTS multi-col subquery and composite return must be accepted: {f_c3:?}"
    );

    // C4: Transitive cascade through BEGIN ATOMIC routine to dependent view
    let mut s_c4 = AnalysisState::new(base_cache.clone());
    let f_c4 = engine
        .analyze(
            "CREATE TABLE public.base_t (id int);
             CREATE FUNCTION public.read_base() RETURNS int
                 LANGUAGE sql BEGIN ATOMIC SELECT id FROM public.base_t; END;
             CREATE VIEW public.v_on_fn AS SELECT public.read_base() AS v;
             DROP TABLE public.base_t CASCADE;",
            &mut s_c4,
        )
        .unwrap();
    assert!(
        !f_c4.iter().any(|v| v.rule_id == "chain-conflict"),
        "C4: DROP TABLE CASCADE must transitively drop view depending on cascaded routine: {f_c4:?}"
    );
    assert!(
        matches!(
            s_c4.get_relation(&object_id("public", "v_on_fn")),
            Some(RelationOverlay::Dropped) | None
        ),
        "C4: dependent view v_on_fn must be dropped"
    );

    // C5: DROP CAST on built-in system cast must conflict
    let mut s_c5 = AnalysisState::new(base_cache.clone());
    let f_c5 = engine
        .analyze("DROP CAST IF EXISTS (integer AS bigint);", &mut s_c5)
        .unwrap();
    assert!(
        f_c5.iter().any(|v| v.rule_id == "chain-conflict"),
        "C5: DROP CAST IF EXISTS on built-in system cast must be rejected: {f_c5:?}"
    );

    // C6: Synced extended statistics expression dependencies on quoted identifier + unparenthesized cast
    let mut stats_cache = cache_with_table("public", "items", None);
    let items_id = object_id("public", "items");
    if let Some(rel) = stats_cache.relations.get_mut(&items_id) {
        rel.apply_column_action(&ColumnAction::Add {
            name: "MixedCol".into(),
            data_type: Some("integer".into()),
            not_null: false,
            default: None,
        });
        rel.extended_statistics.insert(
            object_id("public", "items_expr_stat"),
            ExtendedStatisticsState {
                id: object_id("public", "items_expr_stat"),
                kinds: vec!["d".into()],
                columns: Vec::new(),
                expressions: Some(
                    "public.\"MixedFn\"(\"MixedCol\"), \"MixedCol\"::public.custom_dom".into(),
                ),
                target: None,
                owner: Some(object_id("", "postgres")),
            },
        );
    }
    stats_cache.functions.insert(
        object_id("public", "MixedFn(integer)"),
        FunctionState::with_inputs(
            object_id("public", "MixedFn(integer)"),
            RoutineKind::Function,
            vec!["integer".into()],
        ),
    );
    stats_cache.types.insert(
        object_id("public", "custom_dom"),
        TypeState {
            id: object_id("public", "custom_dom"),
            kind: TypeKind::Domain {
                base_type: "integer".into(),
                base_type_id: None,
                collation: None,
                collation_id: None,
                default: None,
                default_text: None,
                not_null: false,
                not_null_constraint: None,
                constraints: Default::default(),
            },
            owner: object_id("", "postgres"),
            generation: 0,
        },
    );
    let s_c6 = AnalysisState::new(stats_cache);
    let mut s_c6_fn = s_c6.clone();
    let f_c6_fn = engine
        .analyze("DROP FUNCTION public.\"MixedFn\"(integer);", &mut s_c6_fn)
        .unwrap();
    assert!(
        f_c6_fn.iter().any(|v| v.rule_id == "chain-conflict"),
        "C6: DROP FUNCTION on quoted routine referenced by synced statistics expression must conflict: {f_c6_fn:?}"
    );
    let mut s_c6_ty = s_c6;
    let f_c6_ty = engine
        .analyze("DROP DOMAIN public.custom_dom;", &mut s_c6_ty)
        .unwrap();
    assert!(
        f_c6_ty.iter().any(|v| v.rule_id == "chain-conflict"),
        "C6: DROP DOMAIN on type referenced by unparenthesized cast in synced statistics expression must conflict: {f_c6_ty:?}"
    );

    // H1: Multi-target DROP FUNCTION excluding co-dropped sibling
    let mut s_h1 = AnalysisState::new(base_cache.clone());
    let f_h1 = engine
        .analyze(
            "CREATE FUNCTION public.helper() RETURNS int LANGUAGE sql BEGIN ATOMIC RETURN 1; END;
             CREATE FUNCTION public.caller() RETURNS int LANGUAGE sql BEGIN ATOMIC RETURN public.helper(); END;
             DROP FUNCTION public.helper(), public.caller();",
            &mut s_h1,
        )
        .unwrap();
    assert!(
        !f_h1.iter().any(|v| v.rule_id == "chain-conflict"),
        "H1: multi-target DROP FUNCTION of helper and caller together must succeed: {f_h1:?}"
    );

    // H2: Schema-qualified missing routine call must not match different schema in search_path
    let mut s_h2 = AnalysisState::new(base_cache.clone());
    let f_h2 = engine
        .analyze(
            "CREATE SCHEMA other_s;
             CREATE FUNCTION public.only_in_public(int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT $1';
             CREATE FUNCTION public.bad_caller() RETURNS int LANGUAGE sql
                 BEGIN ATOMIC SELECT other_s.only_in_public(1); END;",
            &mut s_h2,
        )
        .unwrap();
    assert!(
        f_h2.iter().any(|v| v.rule_id == "chain-conflict"),
        "H2: schema-qualified call to other_s.only_in_public(1) must conflict when function is in public: {f_h2:?}"
    );

    // H5: ALTER FUNCTION ... SUPPORT replaces previous support edge
    let mut s_h5 = AnalysisState::new(base_cache.clone());
    let f_h5 = engine
        .analyze(
            "CREATE FUNCTION public.sup1(internal) RETURNS internal LANGUAGE internal AS ' int4recv ';
             CREATE FUNCTION public.sup2(internal) RETURNS internal LANGUAGE internal AS ' int4send ';
             CREATE FUNCTION public.fn_with_sup() RETURNS int LANGUAGE sql AS 'SELECT 1';
             ALTER FUNCTION public.fn_with_sup() SUPPORT public.sup1;
             ALTER FUNCTION public.fn_with_sup() SUPPORT public.sup2;
             DROP FUNCTION public.sup1(internal);",
            &mut s_h5,
        )
        .unwrap();
    assert!(
        !f_h5.iter().any(|v| v.rule_id == "chain-conflict"),
        "H5: dropping replaced support function sup1 must not conflict: {f_h5:?}"
    );

    // H6: CREATE CAST ... WITH FUNCTION using single OUT parameter
    let mut s_h6 = AnalysisState::new(base_cache.clone());
    let f_h6 = engine
        .analyze(
            "CREATE TYPE public.out_src AS (v int);
             CREATE TYPE public.out_dst AS (v int);
             CREATE FUNCTION public.cast_via_out(src public.out_src, OUT res public.out_dst)
                 LANGUAGE sql IMMUTABLE AS 'SELECT ROW((src).v)::public.out_dst';
             CREATE CAST (public.out_src AS public.out_dst) WITH FUNCTION public.cast_via_out(public.out_src);",
            &mut s_h6,
        )
        .unwrap();
    assert!(
        !f_h6.iter().any(|v| v.rule_id == "chain-conflict"),
        "H6: CREATE CAST WITH FUNCTION having single OUT parameter must succeed: {f_h6:?}"
    );

    // H7: Subscriptable base type with ELEMENT and raw_array_subscript_handler in CREATE CAST WITHOUT FUNCTION
    let mut s_h7 = AnalysisState::new(base_cache.clone());
    let f_h7 = engine
        .analyze(
            "CREATE TYPE public.myvec;
             CREATE FUNCTION public.myvec_in(cstring) RETURNS public.myvec LANGUAGE internal IMMUTABLE STRICT AS 'int4in';
             CREATE FUNCTION public.myvec_out(public.myvec) RETURNS cstring LANGUAGE internal IMMUTABLE STRICT AS 'int4out';
             CREATE TYPE public.myvec (
                 INPUT = public.myvec_in,
                 OUTPUT = public.myvec_out,
                 INTERNALLENGTH = 16,
                 ELEMENT = float4,
                 SUBSCRIPT = raw_array_subscript_handler
             );
             CREATE TYPE public.myvec2;
             CREATE FUNCTION public.myvec2_in(cstring) RETURNS public.myvec2 LANGUAGE internal IMMUTABLE STRICT AS 'int4in';
             CREATE FUNCTION public.myvec2_out(public.myvec2) RETURNS cstring LANGUAGE internal IMMUTABLE STRICT AS 'int4out';
             CREATE TYPE public.myvec2 (
                 INPUT = public.myvec2_in,
                 OUTPUT = public.myvec2_out,
                 INTERNALLENGTH = 16,
                 ELEMENT = float4,
                 SUBSCRIPT = raw_array_subscript_handler
             );
             CREATE CAST (public.myvec AS public.myvec2) WITHOUT FUNCTION;",
            &mut s_h7,
        )
        .unwrap();
    assert!(
        !f_h7.iter().any(|v| v.rule_id == "chain-conflict"),
        "H7: CREATE CAST WITHOUT FUNCTION on base type with ELEMENT + raw_array_subscript_handler must succeed: {f_h7:?}"
    );

    // H8: CREATE STATISTICS expression cast to type lacking default B-tree opclass (json)
    let mut s_h8 = AnalysisState::new(base_cache.clone());
    let f_h8 = engine
        .analyze(
            "CREATE TABLE public.j_tbl (j text, id int);
             CREATE STATISTICS public.j_stats ON ((j::json)), id FROM public.j_tbl;",
            &mut s_h8,
        )
        .unwrap();
    assert!(
        f_h8.iter().any(|v| v.rule_id == "chain-conflict"),
        "H8: CREATE STATISTICS on expression returning json must conflict: {f_h8:?}"
    );

    // H9: ANALYZE pg_catalog.pg_class (relname) taints with CatalogCoverageIncomplete, and ALTER FUNCTION SET unknown_guc taints
    let mut s_h9_a = AnalysisState::new(base_cache.clone());
    engine
        .analyze("ANALYZE pg_catalog.pg_class (relname);", &mut s_h9_a)
        .unwrap();
    assert_eq!(
        s_h9_a.local.confidence,
        Confidence::Tainted,
        "H9: ANALYZE pg_catalog.pg_class with explicit columns must taint"
    );
    let mut s_h9_b = AnalysisState::new(base_cache.clone());
    engine
        .analyze(
            "CREATE FUNCTION public.guc_fn() RETURNS int LANGUAGE sql AS 'SELECT 1';
             ALTER FUNCTION public.guc_fn() SET custom.ext_param = 'val';",
            &mut s_h9_b,
        )
        .unwrap();
    assert_eq!(
        s_h9_b.local.confidence,
        Confidence::Tainted,
        "H9: ALTER FUNCTION SET unknown GUC must taint"
    );

    // V1-V7: Version gates (PG 15 vs PG 16 vs PG 17 vs PG 18) and ALTER STATISTICS IF EXISTS
    let mut cache_pg15 = base_cache.clone();
    cache_pg15.pg_version_num = Some(150_000);
    let engine_pg15 = SafeMigrateEngine::new(Config {
        assume_pg_version: Some(150_000),
        ..Config::default()
    });
    let mut s_v1_15 = AnalysisState::new(cache_pg15.clone());
    let f_v1_15 = engine_pg15
        .analyze(
            "CREATE TABLE public.t15 (id int);
             ANALYZE (BUFFER_USAGE_LIMIT '256kB') public.t15;",
            &mut s_v1_15,
        )
        .unwrap();
    assert!(
        f_v1_15.iter().any(|v| v.rule_id == "chain-conflict"),
        "V1: ANALYZE BUFFER_USAGE_LIMIT must conflict on PG 15: {f_v1_15:?}"
    );

    let mut cache_pg16 = base_cache.clone();
    cache_pg16.pg_version_num = Some(160_000);
    let engine_pg16 = SafeMigrateEngine::new(Config {
        assume_pg_version: Some(160_000),
        ..Config::default()
    });
    let mut s_v2_16 = AnalysisState::new(cache_pg16.clone());
    let f_v2_16 = engine_pg16
        .analyze(
            "CREATE TABLE public.t16 (a int, b int);
             CREATE STATISTICS public.s16 ON a, b FROM public.t16;
             ALTER STATISTICS public.s16 SET STATISTICS DEFAULT;",
            &mut s_v2_16,
        )
        .unwrap();
    assert!(
        f_v2_16.iter().any(|v| v.rule_id == "chain-conflict"),
        "V2: ALTER STATISTICS SET STATISTICS DEFAULT must conflict on PG 16: {f_v2_16:?}"
    );

    let mut s_v3_16 = AnalysisState::new(cache_pg16.clone());
    let f_v3_16 = engine_pg16
        .analyze(
            "CREATE FUNCTION public.f16() RETURNS int LANGUAGE sql AS 'SELECT 1';
             ALTER FUNCTION public.f16() SET transaction_timeout = 1000;",
            &mut s_v3_16,
        )
        .unwrap();
    assert!(
        f_v3_16.iter().any(|v| v.rule_id == "chain-conflict"),
        "V3: SET transaction_timeout must conflict on PG 16: {f_v3_16:?}"
    );

    // V6: Partitioned table SET UNLOGGED is accepted on PG 17, rejected on PG 18
    let mut cache_pg17 = base_cache.clone();
    cache_pg17.pg_version_num = Some(170_000);
    let engine_pg17 = SafeMigrateEngine::new(Config {
        assume_pg_version: Some(170_000),
        ..Config::default()
    });
    let mut s_v6_17 = AnalysisState::new(cache_pg17);
    let f_v6_17 = engine_pg17
        .analyze(
            "CREATE TABLE public.p17 (id int) PARTITION BY RANGE (id);
             ALTER TABLE public.p17 SET UNLOGGED;",
            &mut s_v6_17,
        )
        .unwrap();
    assert!(
        !f_v6_17.iter().any(|v| v.rule_id == "chain-conflict"),
        "V6: ALTER TABLE <partitioned> SET UNLOGGED must be accepted on PG 17: {f_v6_17:?}"
    );

    let mut s_v6_18 = AnalysisState::new(base_cache.clone());
    let f_v6_18 = engine
        .analyze(
            "CREATE TABLE public.p18 (id int) PARTITION BY RANGE (id);
             ALTER TABLE public.p18 SET UNLOGGED;",
            &mut s_v6_18,
        )
        .unwrap();
    assert!(
        f_v6_18.iter().any(|v| v.rule_id == "chain-conflict"),
        "V6: ALTER TABLE <partitioned> SET UNLOGGED must conflict on PG 18: {f_v6_18:?}"
    );

    // V7: ALTER STATISTICS IF EXISTS on missing statistics object (SET STATISTICS is valid; OWNER TO with IF EXISTS conflicts)
    let mut s_v7 = AnalysisState::new(base_cache.clone());
    let f_v7 = engine
        .analyze(
            "ALTER STATISTICS IF EXISTS public.missing_stats SET STATISTICS 100;",
            &mut s_v7,
        )
        .unwrap();
    assert!(
        !f_v7.iter().any(|v| v.rule_id == "chain-conflict"),
        "V7: ALTER STATISTICS IF EXISTS ... SET STATISTICS on missing statistics object must not conflict: {f_v7:?}"
    );
    assert_eq!(s_v7.local.confidence, Confidence::Exact);
    let mut s_v7_bad = AnalysisState::new(base_cache.clone());
    let f_v7_bad = engine
        .analyze(
            "ALTER STATISTICS IF EXISTS public.missing_stats OWNER TO postgres;",
            &mut s_v7_bad,
        )
        .unwrap();
    assert!(
        f_v7_bad.iter().any(|v| v.rule_id == "chain-conflict"),
        "V7: ALTER STATISTICS IF EXISTS ... OWNER TO must conflict as in PostgreSQL grammar: {f_v7_bad:?}"
    );

    // M1: Cache semantic validation rejects dangling routine_dependencies
    let mut bad_cache = base_cache.clone();
    bad_cache.routine_dependencies.push(RoutineDependencyCache {
        dependent: object_id("public", "nonexistent_fn()"),
        target: RoutineDependencyTarget::Relation {
            relation: object_id("public", "nonexistent_tbl"),
            column: None,
        },
    });
    assert!(
        bad_cache.validate_semantics().is_err(),
        "M1: validate_semantics must reject routine_dependencies with missing routine"
    );
}
