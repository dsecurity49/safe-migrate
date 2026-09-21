use crate::common::*;
use safe_migrate::_internal::model::constraint::ConstraintKind;
use std::collections::BTreeMap;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct OracleCache {
    entries: BTreeMap<String, String>,
}

#[test]
fn partition_bounds_parity_oracle() {
    let matrix = vec![
        ("a integer", "(a)", "LIST", "FOR VALUES IN (1)"),
        ("a integer", "(a)", "LIST", "FOR VALUES IN (1, 2, 3)"),
        ("a integer", "(a)", "LIST", "FOR VALUES IN (NULL)"),
        ("a integer", "(a)", "LIST", "FOR VALUES IN (1, NULL)"),
        ("a bigint", "(a)", "LIST", "FOR VALUES IN (9223372036854775807)"),
        ("a smallint", "(a)", "LIST", "FOR VALUES IN (32767)"),
        ("a boolean", "(a)", "LIST", "FOR VALUES IN (true)"),
        ("a boolean", "(a)", "LIST", "FOR VALUES IN (false)"),
        ("a boolean", "(a)", "LIST", "FOR VALUES IN (true, NULL)"),
        ("a text", "(a)", "LIST", "FOR VALUES IN ('hello')"),
        ("a text", "(a)", "LIST", "FOR VALUES IN ('hello', 'world', NULL)"),
        ("a varchar", "(a)", "LIST", "FOR VALUES IN ('hello')"),
        ("a char(5)", "(a)", "LIST", "FOR VALUES IN ('hello')"),
        ("a name", "(a)", "LIST", "FOR VALUES IN ('hello')"),
        ("a date", "(a)", "LIST", "FOR VALUES IN ('2020-01-01')"),
        ("a timestamp", "(a)", "LIST", "FOR VALUES IN ('2020-01-01 12:00:00')"),
        ("a timestamptz", "(a)", "LIST", "FOR VALUES IN ('2020-01-01 12:00:00Z')"),
        ("a integer", "(a)", "RANGE", "FOR VALUES FROM (1) TO (10)"),
        ("a integer", "(a)", "RANGE", "FOR VALUES FROM (MINVALUE) TO (MAXVALUE)"),
        ("a integer", "(a)", "RANGE", "FOR VALUES FROM (1) TO (MAXVALUE)"),
        ("a integer", "(a)", "RANGE", "FOR VALUES FROM (MINVALUE) TO (10)"),
        ("a integer, b integer, c integer", "(a, b, c)", "RANGE", "FOR VALUES FROM (1, 2, 3) TO (10, 20, 30)"),
        ("a integer, b integer, c integer", "(a, b, c)", "RANGE", "FOR VALUES FROM (1, 2, MINVALUE) TO (10, 20, MAXVALUE)"),
        ("a integer, b integer, c integer", "(a, b, c)", "RANGE", "FOR VALUES FROM (1, MINVALUE, MINVALUE) TO (10, MAXVALUE, MAXVALUE)"),
        ("a integer, b integer", "(a, b)", "RANGE", "FOR VALUES FROM (MINVALUE, MINVALUE) TO (MAXVALUE, MAXVALUE)"),
        ("a integer, b integer", "(a, b)", "RANGE", "FOR VALUES FROM (MINVALUE, MINVALUE) TO (10, 20)"),
        ("a text", "(a)", "RANGE", "FOR VALUES FROM ('a') TO ('z')"),
        ("a text, b text", "(a, b)", "RANGE", "FOR VALUES FROM ('a', 'a') TO ('z', 'z')"),
        ("a varchar, b integer", "(a, b)", "RANGE", "FOR VALUES FROM ('abc', 1) TO ('xyz', 10)"),
        ("a date", "(a)", "RANGE", "FOR VALUES FROM ('2020-01-01') TO ('2021-01-01')"),
        ("a timestamp", "(a)", "RANGE", "FOR VALUES FROM ('2020-01-01 00:00:00') TO ('2021-01-01 00:00:00')"),
        ("a integer", "(a)", "LIST", "DEFAULT"),
        ("a integer", "(a)", "RANGE", "DEFAULT"),
    ];

    let cache_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/partition_bounds_oracle.json");
    let mut cache = if cache_path.exists() {
        let text = std::fs::read_to_string(&cache_path).unwrap();
        serde_json::from_str::<OracleCache>(&text).unwrap_or(OracleCache { entries: BTreeMap::new() })
    } else {
        OracleCache { entries: BTreeMap::new() }
    };
    
    let mut cache_updated = false;
    
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let mut client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        for (columns, keys, strategy, bound) in &matrix {
            client.batch_execute("DROP TABLE IF EXISTS oracle_parent CASCADE; DROP TABLE IF EXISTS oracle_child CASCADE;").unwrap();
            let _ = client.simple_query(&format!("CREATE TABLE oracle_parent ({columns}) PARTITION BY {strategy} {keys};"));
            let _ = client.simple_query(&format!("CREATE TABLE oracle_child PARTITION OF oracle_parent {bound};"));
            let res = client.simple_query("ALTER TABLE oracle_parent DETACH PARTITION oracle_child CONCURRENTLY;");
            if let Err(e) = res {
                eprintln!("Postgres rejected bound {bound}: {:?}", e);
                continue;
            }
            
            let row = client.query_one(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'oracle_child'::regclass AND contype = 'c';",
                &[]
            );
            match row {
                Ok(r) => {
                    let def: Option<String> = r.get(0);
                    if let Some(def) = def {
                        if let Some(check_expr) = def.strip_prefix("CHECK ") {
                            let check_expr = check_expr.to_string();
                            let key = format!("{}|{}|{}|{}", columns, keys, strategy, bound);
                            if cache.entries.get(&key) != Some(&check_expr) {
                                cache.entries.insert(key, check_expr);
                                cache_updated = true;
                            }
                        }
                    } else {
                        eprintln!("NULL constraint def for {bound}");
                    }
                },
                Err(e) => eprintln!("Query error for {bound}: {:?}", e),
            }
        }
    }
    
    if cache_updated {
        let json = serde_json::to_string_pretty(&cache).unwrap();
        std::fs::write(&cache_path, json).unwrap();
        eprintln!("WROTE CACHE");
        if std::env::var("CI").is_ok() {
            panic!("Parity oracle cache was updated in CI. Run locally with DATABASE_URL to update.");
        }
    }
    
    let engine = setup_engine();
    for (columns, keys, strategy, bound) in &matrix {
        let key = format!("{}|{}|{}|{}", columns, keys, strategy, bound);
        let expected = match cache.entries.get(&key) {
            Some(e) => e,
            None => {
                eprintln!("Missing cache entry for {}; skipping", key);
                continue;
            }
        };
        
        let mut state = setup_state();
        let sql = format!(
            "CREATE TABLE oracle_parent ({columns}) PARTITION BY {strategy} {keys};
             CREATE TABLE oracle_child PARTITION OF oracle_parent {bound};
             ALTER TABLE oracle_parent DETACH PARTITION oracle_child CONCURRENTLY;"
        );
        let _ = engine.analyze(&sql, &mut state);
        
        let child_id = object_id("public", "oracle_child");
        let constraint = state.local.constraints.values()
            .find(|c| c.table_id == child_id && c.kind == ConstraintKind::Check);
            
        let actual = constraint.and_then(|c| c.definition.as_deref());
        assert_eq!(actual, Some(expected.as_str()), "Mismatch for key: {}", key);
    }
}
