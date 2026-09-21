use crate::common::*;
use safe_migrate::_internal::model::constraint::ConstraintKind;
use std::collections::BTreeMap;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct OracleCache {
    entries: BTreeMap<String, String>,
}

/// Type×bound differential parity oracle.
///
/// # Three case categories
///
/// **`verified`** — Bounds whose DDL PostgreSQL accepts and for which `DETACH
/// PARTITION … CONCURRENTLY` leaves a deterministic `CHECK` constraint.  The
/// simulator must produce the byte-identical string that `pg_get_constraintdef`
/// returns.  Ground-truth bytes are stored in
/// `tests/golden/partition_bounds_oracle.json`.  In offline mode every entry
/// must be present in the cache (missing → regenerate hint + panic) and must
/// match byte-for-byte (mismatches collected, all reported at once).
///
/// **`taint_only`** — `timestamptz` bounds: PostgreSQL accepts the DDL and
/// produces a real constraint, but the rendered timestamp literal depends on
/// the server's `TimeZone` GUC.  A cache entry would be machine-specific and
/// would silently diverge on any other timezone.  The correct policy is that
/// the simulator conservatively taints (returns no synthesized constraint)
/// rather than fabricate a timezone-dependent string.  Offline assertion:
/// `engine.analyze` succeeds and no child `Check` constraint is synthesized.
/// This pins the design decision: if a future implementation emits a
/// timezone-dependent literal this test fails, forcing an explicit review.
///
/// **`rejected_default`** — PostgreSQL rejects `DETACH PARTITION … CONCURRENTLY`
/// when a default partition exists (SQLSTATE 55000).  There is therefore no
/// byte-comparable ground truth.  In live mode the oracle asserts PostgreSQL
/// still rejects (guards against future PG behaviour change).  Offline: the
/// simulator must not crash and must not synthesize a concrete bound predicate
/// for the `DEFAULT` child.
#[test]
fn partition_bounds_parity_oracle() {
    // ── verified cases ──────────────────────────────────────────────────────
    // (columns_ddl, keys, strategy, bound)
    // Every entry here must have a golden-cache counterpart after live regen.
    let verified: &[(&str, &str, &str, &str)] = &[
        // integer - LIST
        ("a integer", "(a)", "LIST", "FOR VALUES IN (1)"),
        ("a integer", "(a)", "LIST", "FOR VALUES IN (1, 2, 3)"),
        ("a integer", "(a)", "LIST", "FOR VALUES IN (NULL)"),
        ("a integer", "(a)", "LIST", "FOR VALUES IN (1, NULL)"),
        ("a integer", "(a)", "LIST", "FOR VALUES IN (-1, -2)"),
        // integer - RANGE
        ("a integer", "(a)", "RANGE", "FOR VALUES FROM (1) TO (10)"),
        ("a integer", "(a)", "RANGE", "FOR VALUES FROM (-5) TO (5)"),
        (
            "a integer",
            "(a)",
            "RANGE",
            "FOR VALUES FROM (MINVALUE) TO (10)",
        ),
        (
            "a integer",
            "(a)",
            "RANGE",
            "FOR VALUES FROM (1) TO (MAXVALUE)",
        ),
        (
            "a integer",
            "(a)",
            "RANGE",
            "FOR VALUES FROM (MINVALUE) TO (MAXVALUE)",
        ),
        // smallint / bigint
        ("a smallint", "(a)", "LIST", "FOR VALUES IN (32767)"),
        ("a smallint", "(a)", "LIST", "FOR VALUES IN (1, 2)"),
        (
            "a bigint",
            "(a)",
            "LIST",
            "FOR VALUES IN (9223372036854775807)",
        ),
        ("a bigint", "(a)", "LIST", "FOR VALUES IN (100, 200)"),
        (
            "a bigint",
            "(a)",
            "RANGE",
            "FOR VALUES FROM (0) TO (9223372036854775807)",
        ),
        // boolean
        ("a boolean", "(a)", "LIST", "FOR VALUES IN (true)"),
        ("a boolean", "(a)", "LIST", "FOR VALUES IN (false)"),
        ("a boolean", "(a)", "LIST", "FOR VALUES IN (true, NULL)"),
        ("a boolean", "(a)", "LIST", "FOR VALUES IN (true, false)"),
        (
            "a boolean",
            "(a)",
            "LIST",
            "FOR VALUES IN (true, false, NULL)",
        ),
        // numeric - bare (no typmod) - float-like bare; non-float-like quoted
        ("a numeric", "(a)", "LIST", "FOR VALUES IN (123.45)"),
        ("a numeric", "(a)", "LIST", "FOR VALUES IN (1.5, 2.5)"),
        ("a numeric", "(a)", "LIST", "FOR VALUES IN (5)"),
        (
            "a numeric",
            "(a)",
            "RANGE",
            "FOR VALUES FROM (0.5) TO (1.5)",
        ),
        // numeric with typmod - always cast with ::numeric(p,s)
        ("a numeric(10,2)", "(a)", "LIST", "FOR VALUES IN (123.45)"),
        ("a numeric(10,2)", "(a)", "LIST", "FOR VALUES IN (5)"),
        (
            "a numeric(10,2)",
            "(a)",
            "LIST",
            "FOR VALUES IN (123.45, 67.89)",
        ),
        (
            "a numeric(10,2)",
            "(a)",
            "RANGE",
            "FOR VALUES FROM (0.50) TO (1.50)",
        ),
        // real / double precision
        ("a real", "(a)", "LIST", "FOR VALUES IN (1.5)"),
        ("a double precision", "(a)", "LIST", "FOR VALUES IN (1.5)"),
        // uuid
        (
            "a uuid",
            "(a)",
            "LIST",
            "FOR VALUES IN ('11111111-2222-3333-4444-555555555555')",
        ),
        // text
        ("a text", "(a)", "LIST", "FOR VALUES IN ('hello')"),
        ("a text", "(a)", "LIST", "FOR VALUES IN ('hello', 'world')"),
        (
            "a text",
            "(a)",
            "LIST",
            "FOR VALUES IN ('hello', 'world', NULL)",
        ),
        ("a text", "(a)", "LIST", "FOR VALUES IN (NULL)"),
        ("a text", "(a)", "LIST", "FOR VALUES IN ('a b', 'c,d')"),
        ("a text", "(a)", "RANGE", "FOR VALUES FROM ('a') TO ('z')"),
        // name
        ("a name", "(a)", "LIST", "FOR VALUES IN ('hello')"),
        // varchar - bare (no typmod)
        ("a varchar", "(a)", "LIST", "FOR VALUES IN ('hello')"),
        // varchar(N) - canonical spelling used in array casts and literal casts
        (
            "a varchar(32)",
            "(a)",
            "LIST",
            "FOR VALUES IN ('hello world')",
        ),
        (
            "a varchar(32)",
            "(a)",
            "LIST",
            "FOR VALUES IN ('hello', 'world')",
        ),
        (
            "a varchar(32)",
            "(a)",
            "RANGE",
            "FOR VALUES FROM ('abc') TO ('xyz')",
        ),
        // character varying(N) - alternate DDL spelling, same PG type
        (
            "a character varying(32)",
            "(a)",
            "LIST",
            "FOR VALUES IN ('hello world')",
        ),
        (
            "a character varying(32)",
            "(a)",
            "RANGE",
            "FOR VALUES FROM ('abc') TO ('xyz')",
        ),
        // char / character - bare = character(1)
        ("a char", "(a)", "LIST", "FOR VALUES IN ('x')"),
        // char(N)
        ("a char(5)", "(a)", "LIST", "FOR VALUES IN ('hello')"),
        (
            "a char(5)",
            "(a)",
            "LIST",
            "FOR VALUES IN ('abcde', 'fghij')",
        ),
        (
            "a char(5)",
            "(a)",
            "RANGE",
            "FOR VALUES FROM ('aaaaa') TO ('zzzzz')",
        ),
        // bpchar - bare stays as bpchar; bpchar(N) renders as character(N)
        ("a bpchar", "(a)", "LIST", "FOR VALUES IN ('x')"),
        ("a bpchar(5)", "(a)", "LIST", "FOR VALUES IN ('hello')"),
        // date / timestamp
        ("a date", "(a)", "LIST", "FOR VALUES IN ('2020-01-01')"),
        (
            "a date",
            "(a)",
            "RANGE",
            "FOR VALUES FROM ('2020-01-01') TO ('2021-01-01')",
        ),
        (
            "a timestamp",
            "(a)",
            "LIST",
            "FOR VALUES IN ('2020-01-01 12:00:00')",
        ),
        (
            "a timestamp",
            "(a)",
            "RANGE",
            "FOR VALUES FROM ('2020-01-01 00:00:00') TO ('2021-01-01 00:00:00')",
        ),
        // composite RANGE - integer
        (
            "a integer, b integer, c integer",
            "(a, b, c)",
            "RANGE",
            "FOR VALUES FROM (1, 2, 3) TO (10, 20, 30)",
        ),
        (
            "a integer, b integer, c integer",
            "(a, b, c)",
            "RANGE",
            "FOR VALUES FROM (1, 2, MINVALUE) TO (10, 20, MAXVALUE)",
        ),
        (
            "a integer, b integer, c integer",
            "(a, b, c)",
            "RANGE",
            "FOR VALUES FROM (1, MINVALUE, MINVALUE) TO (10, MAXVALUE, MAXVALUE)",
        ),
        (
            "a integer, b integer",
            "(a, b)",
            "RANGE",
            "FOR VALUES FROM (MINVALUE, MINVALUE) TO (MAXVALUE, MAXVALUE)",
        ),
        (
            "a integer, b integer",
            "(a, b)",
            "RANGE",
            "FOR VALUES FROM (MINVALUE, MINVALUE) TO (10, 20)",
        ),
        // composite RANGE - text
        (
            "a text, b text",
            "(a, b)",
            "RANGE",
            "FOR VALUES FROM ('a', 'a') TO ('z', 'z')",
        ),
        // composite RANGE - mixed varchar + integer (exercises ::text cast on left)
        (
            "a varchar, b integer",
            "(a, b)",
            "RANGE",
            "FOR VALUES FROM ('abc', 1) TO ('xyz', 10)",
        ),
        (
            "a varchar(32), b integer",
            "(a, b)",
            "RANGE",
            "FOR VALUES FROM ('abc', 0) TO ('xyz', 10)",
        ),
        (
            "a character varying(32), b integer",
            "(a, b)",
            "RANGE",
            "FOR VALUES FROM ('abc', 0) TO ('xyz', 10)",
        ),
        // composite RANGE - 3-column varchar
        (
            "a character varying(16), b character varying(16), c character varying(16)",
            "(a, b, c)",
            "RANGE",
            "FOR VALUES FROM ('a', 'b', 'c') TO ('x', 'y', 'z')",
        ),
    ];

    // ── taint_only cases ────────────────────────────────────────────────────
    // timestamptz: PG accepts the DDL but renders the literal in session
    // TimeZone — not byte-stable across environments.  The simulator must
    // conservatively taint (produce no synthesized CHECK constraint) rather
    // than fabricate a timezone-dependent string.
    let taint_only: &[(&str, &str, &str, &str)] = &[
        (
            "a timestamptz",
            "(a)",
            "LIST",
            "FOR VALUES IN ('2020-01-01 12:00:00Z')",
        ),
        (
            "a timestamptz",
            "(a)",
            "RANGE",
            "FOR VALUES FROM ('2020-01-01 00:00:00Z') TO ('2021-01-01 00:00:00Z')",
        ),
    ];

    // ── rejected_default cases ──────────────────────────────────────────────
    // PostgreSQL rejects DETACH PARTITION … CONCURRENTLY when a DEFAULT
    // partition exists (SQLSTATE 55000).  No byte-comparable ground truth
    // exists.  In live mode we assert PG still rejects.  Offline we assert
    // the simulator does not crash and synthesizes no concrete bound predicate.
    let rejected_default: &[(&str, &str, &str, &str)] = &[
        ("a integer", "(a)", "LIST", "DEFAULT"),
        ("a integer", "(a)", "RANGE", "DEFAULT"),
    ];

    let cache_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/partition_bounds_oracle.json");

    // ── live mode: connect to PG, rebuild cache from scratch ────────────────
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let mut client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        let mut fresh_entries: BTreeMap<String, String> = BTreeMap::new();

        for (columns, keys, strategy, bound) in verified {
            client
                .batch_execute(
                    "DROP TABLE IF EXISTS oracle_parent CASCADE; \
                     DROP TABLE IF EXISTS oracle_child CASCADE;",
                )
                .unwrap();
            let _ = client.simple_query(&format!(
                "CREATE TABLE oracle_parent ({columns}) PARTITION BY {strategy} {keys};"
            ));
            let _ = client.simple_query(&format!(
                "CREATE TABLE oracle_child PARTITION OF oracle_parent {bound};"
            ));
            let res = client.simple_query(
                "ALTER TABLE oracle_parent DETACH PARTITION oracle_child CONCURRENTLY;",
            );
            if let Err(e) = res {
                panic!("PG rejected verified bound {bound} for ({columns}): {e}");
            }
            let row = client
                .query_one(
                    "SELECT pg_get_constraintdef(oid) \
                     FROM pg_constraint \
                     WHERE conrelid = 'oracle_child'::regclass AND contype = 'c'",
                    &[],
                )
                .expect("expected a retained CHECK after DETACH CONCURRENTLY");
            let def: String = row.get(0);
            let check_expr = def
                .strip_prefix("CHECK ")
                .expect("pg_get_constraintdef must start with CHECK")
                .to_string();
            let key = cache_key(columns, keys, strategy, bound);
            fresh_entries.insert(key, check_expr);
        }

        // taint_only: assert PG accepts the DDL (valid type+bound) even though
        // we do not store the timezone-dependent text.
        for (columns, keys, strategy, bound) in taint_only {
            client
                .batch_execute(
                    "DROP TABLE IF EXISTS oracle_parent CASCADE; \
                     DROP TABLE IF EXISTS oracle_child CASCADE;",
                )
                .unwrap();
            let _ = client.simple_query(&format!(
                "CREATE TABLE oracle_parent ({columns}) PARTITION BY {strategy} {keys};"
            ));
            let _ = client.simple_query(&format!(
                "CREATE TABLE oracle_child PARTITION OF oracle_parent {bound};"
            ));
            let res = client.simple_query(
                "ALTER TABLE oracle_parent DETACH PARTITION oracle_child CONCURRENTLY;",
            );
            if let Err(e) = res {
                panic!(
                    "PG rejected taint_only bound {bound} for ({columns}) — \
                     if this is a PG behaviour change, review the taint_only category: {e}"
                );
            }
            // Do not cache: the text is timezone-dependent.
        }

        // rejected_default: assert PG still rejects DETACH CONCURRENTLY with DEFAULT.
        for (columns, keys, strategy, _bound) in rejected_default {
            client
                .batch_execute(
                    "DROP TABLE IF EXISTS oracle_parent CASCADE; \
                     DROP TABLE IF EXISTS oracle_child CASCADE; \
                     DROP TABLE IF EXISTS oracle_default CASCADE;",
                )
                .unwrap();
            let _ = client.simple_query(&format!(
                "CREATE TABLE oracle_parent ({columns}) PARTITION BY {strategy} {keys};"
            ));
            let _ = client
                .simple_query("CREATE TABLE oracle_default PARTITION OF oracle_parent DEFAULT;");
            let res = client.simple_query(
                "ALTER TABLE oracle_parent DETACH PARTITION oracle_default CONCURRENTLY;",
            );
            match res {
                Err(e) => {
                    let db_err = e.as_db_error().expect("expected a DB error");
                    assert_eq!(
                        db_err.code(),
                        &postgres::error::SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE,
                        "expected SQLSTATE 55000 for DEFAULT detach, got {:?}",
                        db_err.code()
                    );
                }
                Ok(_) => panic!(
                    "PG should reject DETACH CONCURRENTLY of a DEFAULT partition \
                     (SQLSTATE 55000) but succeeded — PG behaviour has changed; review policy"
                ),
            }
        }

        // Write the fresh cache atomically (rebuild from scratch every live run
        // so stale entries from removed matrix rows never linger).
        let cache = OracleCache {
            entries: fresh_entries,
        };
        let json = serde_json::to_string_pretty(&cache).unwrap();
        std::fs::write(&cache_path, json).unwrap();
        eprintln!("WROTE CACHE ({} entries)", cache.entries.len());
        if std::env::var("CI").is_ok() {
            panic!(
                "Parity oracle cache was rebuilt in CI. \
                 Run locally with DATABASE_URL to update tests/golden/partition_bounds_oracle.json \
                 then commit the result."
            );
        }
        return;
    }

    // ── offline mode: assert byte-identical parity against committed cache ──
    let cache: OracleCache = {
        let text = std::fs::read_to_string(&cache_path).unwrap_or_else(|_| {
            panic!(
                "Golden cache not found at {}. \
                 Run once with DATABASE_URL set to populate it.",
                cache_path.display()
            )
        });
        serde_json::from_str(&text).expect("golden cache must be valid JSON")
    };

    let engine = setup_engine();
    let mut failures: Vec<String> = Vec::new();

    // verified: must exist in cache and match byte-for-byte.
    for (columns, keys, strategy, bound) in verified {
        let key = cache_key(columns, keys, strategy, bound);
        let expected = match cache.entries.get(&key) {
            Some(e) => e.as_str(),
            None => {
                failures.push(format!(
                    "MISSING CACHE ENTRY: {key}\n  \
                     → run with DATABASE_URL to regenerate tests/golden/partition_bounds_oracle.json"
                ));
                continue;
            }
        };

        let mut state = setup_state();
        let sql = format!(
            "CREATE TABLE oracle_parent ({columns}) PARTITION BY {strategy} {keys};\n\
             CREATE TABLE oracle_child PARTITION OF oracle_parent {bound};\n\
             ALTER TABLE oracle_parent DETACH PARTITION oracle_child CONCURRENTLY;"
        );
        if let Err(e) = engine.analyze(&sql, &mut state) {
            failures.push(format!("ANALYZE ERROR for {key}: {e:?}"));
            continue;
        }

        let child_id = object_id("public", "oracle_child");
        let actual = state
            .local
            .constraints
            .values()
            .find(|c| c.table_id == child_id && c.kind == ConstraintKind::Check)
            .and_then(|c| c.definition.as_deref());

        if actual != Some(expected) {
            failures.push(format!(
                "MISMATCH: {key}\n  actual:   {actual:?}\n  expected: {expected:?}"
            ));
        }
    }

    // taint_only: simulator must NOT synthesize a concrete Check constraint.
    for (columns, keys, strategy, bound) in taint_only {
        let key = cache_key(columns, keys, strategy, bound);
        let mut state = setup_state();
        let sql = format!(
            "CREATE TABLE oracle_parent ({columns}) PARTITION BY {strategy} {keys};\n\
             CREATE TABLE oracle_child PARTITION OF oracle_parent {bound};\n\
             ALTER TABLE oracle_parent DETACH PARTITION oracle_child CONCURRENTLY;"
        );
        if let Err(e) = engine.analyze(&sql, &mut state) {
            failures.push(format!("ANALYZE ERROR (taint_only) for {key}: {e:?}"));
            continue;
        }
        let child_id = object_id("public", "oracle_child");
        let has_check = state
            .local
            .constraints
            .values()
            .any(|c| c.table_id == child_id && c.kind == ConstraintKind::Check);
        if has_check {
            failures.push(format!(
                "TAINT VIOLATION: {key}\n  \
                 Simulator synthesized a concrete Check constraint for a timestamptz bound.\n  \
                 timestamptz rendering is TimeZone-GUC-dependent; the simulator must conservatively \
                 taint (produce no constraint) rather than fabricate an environment-specific string.\n  \
                 If timestamptz synthesis is intentionally implemented, update the oracle policy."
            ));
        }
    }

    // rejected_default: simulator must not crash and must not synthesize a bound predicate.
    for (columns, keys, strategy, bound) in rejected_default {
        let key = cache_key(columns, keys, strategy, bound);
        let mut state = setup_state();
        // DEFAULT partition: DETACH CONCURRENTLY is rejected by PG (55000).
        // The simulator sees only SQL text; it must handle gracefully without fabricating
        // a concrete bound predicate for the DEFAULT child.
        let sql = format!(
            "CREATE TABLE oracle_parent ({columns}) PARTITION BY {strategy} {keys};\n\
             CREATE TABLE oracle_child PARTITION OF oracle_parent {bound};\n\
             ALTER TABLE oracle_parent DETACH PARTITION oracle_child CONCURRENTLY;"
        );
        if let Err(e) = engine.analyze(&sql, &mut state) {
            failures.push(format!("ANALYZE ERROR (rejected_default) for {key}: {e:?}"));
            continue;
        }
        let child_id = object_id("public", "oracle_child");
        if let Some(c) = state
            .local
            .constraints
            .values()
            .find(|c| c.table_id == child_id && c.kind == ConstraintKind::Check)
            .filter(|c| {
                c.definition
                    .as_deref()
                    .map(|d| !d.contains("IS NOT NULL"))
                    .unwrap_or(false)
            })
        {
            failures.push(format!(
                "DEFAULT FABRICATION: {key}\n  \
                 Simulator emitted a concrete bound predicate {:?} for a DEFAULT partition.\n  \
                 DEFAULT partitions have no bound; no predicate should be synthesized.",
                c.definition
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "\n\n{} parity failure(s):\n\n{}\n",
        failures.len(),
        failures.join("\n\n")
    );
}

fn cache_key(columns: &str, keys: &str, strategy: &str, bound: &str) -> String {
    format!("{columns}|{keys}|{strategy}|{bound}")
}
