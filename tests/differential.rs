use postgres::{Client, NoTls};
use safe_migrate::AnalysisState;
use safe_migrate::analysis::state::Confidence;
use safe_migrate::db::cache::DbCache;
use safe_migrate::engine::config::Config;
use safe_migrate::engine::engine::SafeMigrateEngine;
use safe_migrate::sync::populate_cache;
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

static PG_MUTEX: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, PartialEq, Serialize)]
enum ComparisonResult {
    AllClear,
    CorrectlyCaught,
    FalsePositiveSafety,
    GenuineCoverageGap,
    SimOverAlert,
}

#[derive(Debug, Clone, Serialize)]
struct DifferentialEntry {
    rule_dir: String,
    fixture: String,
    pg_accepts: bool,
    is_safe: bool,
    sim_violations: usize,
    sim_confidence: String,
    comparison: ComparisonResult,
    sim_rule_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DifferentialReport {
    entries: Vec<DifferentialEntry>,
    divergences: Vec<DifferentialEntry>,
    total: usize,
    passed: usize,
    diverged: usize,
}

fn ident_map_for(rule_dir: &str) -> Vec<(&'static str, &'static str)> {
    let mut m = Vec::new();
    match rule_dir {
        "rule_01_irreversible-migration" => {
            m.push(("test_table", "billing.invoices"));
            m.push(("name", "invoice_number"));
            m.push(("id", "id"));
        }
        "rule_02_drop-database" => {
            m.push(("mydb", "safe_migrate_test_db"));
            m.push(("test_table", "billing.invoices"));
        }
        "rule_03_drop-schema-cascade" => {
            m.push(("test_schema", "billing"));
            m.push(("test_table", "crm.accounts"));
        }
        "rule_04_destructive-general-cascade" => {
            m.push(("test_table", "crm.accounts"));
            m.push(("name", "name"));
            m.push(("id", "id"));
        }
        "rule_05_destructive-cascade" => {
            m.push(("test_table", "crm.contacts"));
            m.push(("name", "email"));
            m.push(("id", "id"));
        }
        "rule_06_create-table-as-select" => {
            m.push(("test_table", "billing.invoices"));
        }
        "rule_07_size-aware-add-column" => {
            m.push(("test_table", "billing.invoices"));
            m.push(("id", "id"));
            m.push(("name", "invoice_number"));
        }
        "rule_08_type-change-rewrite" => {
            m.push(("test_table", "billing.invoices"));
            m.push(("name", "invoice_number"));
            m.push(("id", "id"));
        }
        "rule_09_blocking-constraint" => {
            m.push(("test_table", "billing.invoices"));
        }
        "rule_10_require-concurrent-index" => {
            m.push(("test_table", "billing.invoices"));
            m.push(("name", "invoice_number"));
        }
        "rule_11_blocking-mat-view-refresh" => {
            m.push(("test_table", "analytics.materialized_query_results"));
        }
        "rule_12_blocking-partition-mutation" => {
            m.push(("test_table", "audit.audit_log"));
            m.push(("test_col", "event_type"));
        }
        "rule_13_partition-strategy-mismatch" => {
            m.push(("test_table", "analytics.event_queue"));
            m.push(("test_col", "category"));
            m.push(("parent", "org._r_p"));
            m.push(("list_parent", "org._l_p"));
            m.push(("range_parent", "org._r_p"));
            m.push(("hash_parent", "org._h_p"));
            m.push(("list_child", "org._l_c"));
            m.push(("range_child", "org._r_c"));
            m.push(("hash_child", "org._h_c"));
            m.push(("new_name", "x"));
        }
        "rule_14_restrictive-policy" => {
            m.push(("test_table", "content.articles"));
        }
        "rule_15_disable-trigger" => {
            m.push(("test_table", "iam.tenants"));
            m.push(("test_trigger", "trg_tenants_updated_at"));
        }
        "rule_16_broken-compute" => {
            m.push(("test_table", "iam.tenants"));
            m.push(("public.f()", "audit.log_event()"));
            m.push(("f()", "audit.log_event()"));
        }
        "rule_17_function-volatility-change" => {
            m.push(("test_table", "billing.invoices"));
            m.push(("name", "invoice_number"));
            m.push(("public.f()", "audit.log_event()"));
            m.push(("f(integer)", "org._f17_vol(integer)"));
            m.push(("f(text)", "crm.normalize_phone(text)"));
            m.push(("f()", "audit.log_event()"));
        }
        "rule_18_missing-idempotency" => {
            m.push(("test_table", "billing.invoices"));
        }
        "rule_19_concurrent-in-transaction" => {
            m.push(("test_table", "billing.invoices"));
            m.push(("name", "invoice_number"));
        }
        "rule_20_alter-type-add-value-txn" => {
            m.push(("test_type", "billing.invoice_status"));
            m.push(("test_table", "billing.invoices"));
        }
        "rule_21_vacuum-full" => {
            m.push(("test_table", "billing.invoices"));
        }
        "rule_22_opaque-dynamic-sql" => {
            m.push(("test_table", "billing.invoices"));
        }
        "rule_23_volatile-default" => {
            m.push(("test_table", "billing.invoices"));
            m.push(("name", "invoice_number"));
        }
        "rule_24_overbroad-grant" => {
            m.push(("test_table", "billing.invoices"));
            m.push(("test_role", "public"));
            m.push(("test_schema", "billing"));
        }
        "rule_25_schema-drift" => {
            m.push(("test_table", "billing.invoices"));
            m.push(("name", "invoice_number"));
        }
        "rule_26_chain-conflict" => {
            m.push(("test_table", "billing.invoices"));
        }
        _ => {}
    }
    m
}

fn replace_ident(src: &str, from: &str, to: &str) -> String {
    let mut result = String::new();
    let mut pos = 0;
    while pos < src.len() {
        if src[pos..].starts_with(from) {
            let prev_ok = pos == 0 || !src.as_bytes()[pos - 1].is_ascii_alphanumeric();
            let next_ok = pos + from.len() >= src.len()
                || !src.as_bytes()[pos + from.len()].is_ascii_alphanumeric();
            if prev_ok && next_ok {
                result.push_str(to);
                pos += from.len();
                continue;
            }
        }
        result.push(src.as_bytes()[pos] as char);
        pos += 1;
    }
    result
}

fn rewrite_sql(sql: &str, rule_dir: &str) -> String {
    let mut map = ident_map_for(rule_dir);
    map.sort_by_key(|a| std::cmp::Reverse(a.0.len()));
    let mut result = sql.to_string();
    for (from, to) in &map {
        result = result.replace(&format!("\"{}\"", from), to);
        result = replace_ident(&result, &format!("public.{from}"), to);
        result = replace_ident(&result, from, to);
        let upper = from.to_uppercase();
        if upper != *from {
            result = replace_ident(&result, &upper, to);
        }
    }
    result
}

fn reset_schema(client: &mut Client) {
    let schema_sql = "\
DROP SCHEMA IF EXISTS iam CASCADE;
DROP SCHEMA IF EXISTS org CASCADE;
DROP SCHEMA IF EXISTS billing CASCADE;
DROP SCHEMA IF EXISTS crm CASCADE;
DROP SCHEMA IF EXISTS content CASCADE;
DROP SCHEMA IF EXISTS audit CASCADE;
DROP SCHEMA IF EXISTS analytics CASCADE;
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS org;
CREATE SCHEMA IF NOT EXISTS billing;
CREATE SCHEMA IF NOT EXISTS crm;
CREATE SCHEMA IF NOT EXISTS content;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS analytics;
";
    client
        .simple_query(schema_sql)
        .expect("Failed to reset schemas");

    let baseline = include_str!("fixtures/baseline.sql");
    client
        .simple_query(baseline)
        .expect("Failed to apply baseline schema");
}

fn pg_dry_run(client: &mut Client, sql: &str, _rule_dir: &str) -> bool {
    let sql_upper = sql.to_uppercase();
    if sql_upper.contains("DROP DATABASE")
        || sql_upper.contains("CREATE DATABASE")
        || sql_upper.contains("ALTER DATABASE")
    {
        return false;
    }

    let _ = client.simple_query("BEGIN");

    let ok = client.simple_query(sql).is_ok();

    let _ = client.simple_query("ROLLBACK");

    ok
}

fn compare(
    pg_accepts: bool,
    _sim_violations: usize,
    sim_confidence: &Confidence,
    is_safe: bool,
    sim_rule_ids: &[String],
    expected_rule_id: &str,
) -> ComparisonResult {
    let has_expected = sim_rule_ids.iter().any(|id| id == expected_rule_id);
    if is_safe {
        if !has_expected {
            ComparisonResult::AllClear
        } else {
            ComparisonResult::SimOverAlert
        }
    } else if has_expected {
        ComparisonResult::CorrectlyCaught
    } else if !pg_accepts && *sim_confidence == Confidence::Exact {
        ComparisonResult::FalsePositiveSafety
    } else {
        ComparisonResult::GenuineCoverageGap
    }
}

fn should_skip(rule_dir: &str) -> bool {
    rule_dir == "rule_26_chain-conflict"
}

fn run_differential(rule_dir: &str, _rule_id: &str) -> DifferentialReport {
    let _guard = PG_MUTEX.lock().unwrap();

    let db_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for differential tests");

    let mut pg = Client::connect(&db_url, NoTls).expect("Failed to connect to PostgreSQL");

    reset_schema(&mut pg);

    let cache: DbCache = populate_cache(&mut pg, None).expect("Failed to sync cache");

    let engine = SafeMigrateEngine::new(Config::default());

    let fixtures_dir = format!("live_tests/{rule_dir}");
    let path = Path::new(&fixtures_dir);

    let mut entries = Vec::new();

    if !path.exists() {
        return DifferentialReport {
            entries: vec![],
            divergences: vec![],
            total: 0,
            passed: 0,
            diverged: 0,
        };
    }

    let mut dir_entries: Vec<_> = std::fs::read_dir(path)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("sql"))
        .collect();
    dir_entries.sort_by_key(|e| e.file_name());

    for entry in &dir_entries {
        let fixture_name = entry.file_name().to_str().unwrap().to_string();
        let raw_sql = std::fs::read_to_string(entry.path()).unwrap();
        let sql = rewrite_sql(&raw_sql, rule_dir);

        let is_safe = fixture_name.starts_with("safe_");

        let pg_accepts = pg_dry_run(&mut pg, &sql, rule_dir);

        let mut state = AnalysisState::new(cache.clone());
        let violations = engine.analyze(&sql, &mut state).unwrap_or_default();

        let sim_confidence = match &state.local.confidence {
            Confidence::Exact => "exact",
            Confidence::Tainted => "tainted",
        };

        let sim_rule_ids: Vec<String> = violations.iter().map(|v| v.rule_id.to_string()).collect();

        let comparison = compare(
            pg_accepts,
            violations.len(),
            &state.local.confidence,
            is_safe,
            &sim_rule_ids,
            _rule_id,
        );

        let entry = DifferentialEntry {
            rule_dir: rule_dir.to_string(),
            fixture: fixture_name,
            pg_accepts,
            is_safe,
            sim_violations: violations.len(),
            sim_confidence: sim_confidence.to_string(),
            comparison: comparison.clone(),
            sim_rule_ids,
        };
        entries.push(entry);
    }

    let divergences: Vec<DifferentialEntry> = entries
        .iter()
        .filter(|e| {
            if e.is_safe {
                e.comparison != ComparisonResult::AllClear
            } else {
                e.comparison != ComparisonResult::CorrectlyCaught
            }
        })
        .cloned()
        .collect();

    let total = entries.len();
    let diverged = divergences.len();
    let passed = total - diverged;

    DifferentialReport {
        entries,
        divergences,
        total,
        passed,
        diverged,
    }
}

fn write_report(report: &DifferentialReport, suffix: &str) {
    let report_dir = Path::new("target");
    let report_path = report_dir.join(format!("differential_report_{suffix}.json"));
    let json = serde_json::to_string_pretty(report).unwrap();
    std::fs::write(&report_path, json).unwrap();
    eprintln!("Differential report written to {}", report_path.display());
}

fn get_pg_connection() -> Option<Client> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Client::connect(&url, NoTls).ok()
}

macro_rules! differential_test {
    ($name:ident, $rule_dir:expr, $rule_id:expr) => {
        #[test]
        fn $name() {
            if get_pg_connection().is_none() {
                eprintln!("Skipping: DATABASE_URL not set");
                return;
            }

            if should_skip($rule_dir) {
                eprintln!("Skipping {}: chain-conflict not yet supported", $rule_dir);
                return;
            }

            let report = run_differential($rule_dir, $rule_id);
            write_report(&report, $rule_dir);

            if report.diverged > 0 {
                eprintln!(
                    "{} divergences in {}: {:#?}",
                    report.diverged, $rule_dir, report.divergences
                );
            }

            assert!(
                report.diverged == 0,
                "{} — {} divergence(s) found",
                $rule_dir,
                report.diverged
            );
        }
    };
}

differential_test!(
    test_rule_01_irreversible_migration,
    "rule_01_irreversible-migration",
    "irreversible-migration"
);
differential_test!(
    test_rule_02_drop_database,
    "rule_02_drop-database",
    "drop-database"
);
differential_test!(
    test_rule_03_drop_schema_cascade,
    "rule_03_drop-schema-cascade",
    "drop-schema-cascade"
);
differential_test!(
    test_rule_04_destructive_general_cascade,
    "rule_04_destructive-general-cascade",
    "destructive-general-cascade"
);
differential_test!(
    test_rule_05_destructive_cascade,
    "rule_05_destructive-cascade",
    "destructive-cascade"
);
differential_test!(
    test_rule_06_create_table_as_select,
    "rule_06_create-table-as-select",
    "create-table-as-select"
);
differential_test!(
    test_rule_07_size_aware_add_column,
    "rule_07_size-aware-add-column",
    "size-aware-add-column"
);
differential_test!(
    test_rule_08_type_change_rewrite,
    "rule_08_type-change-rewrite",
    "type-change-rewrite"
);
differential_test!(
    test_rule_09_blocking_constraint,
    "rule_09_blocking-constraint",
    "blocking-constraint"
);
differential_test!(
    test_rule_10_require_concurrent_index,
    "rule_10_require-concurrent-index",
    "require-concurrent-index"
);
differential_test!(
    test_rule_11_blocking_mat_view_refresh,
    "rule_11_blocking-mat-view-refresh",
    "blocking-mat-view-refresh"
);
differential_test!(
    test_rule_12_blocking_partition_mutation,
    "rule_12_blocking-partition-mutation",
    "blocking-partition-mutation"
);
differential_test!(
    test_rule_13_partition_strategy_mismatch,
    "rule_13_partition-strategy-mismatch",
    "partition-strategy-mismatch"
);
differential_test!(
    test_rule_14_restrictive_policy,
    "rule_14_restrictive-policy",
    "restrictive-policy"
);
differential_test!(
    test_rule_15_disable_trigger,
    "rule_15_disable-trigger",
    "disable-trigger"
);
differential_test!(
    test_rule_16_broken_compute,
    "rule_16_broken-compute",
    "broken-compute"
);
differential_test!(
    test_rule_17_function_volatility_change,
    "rule_17_function-volatility-change",
    "function-volatility-change"
);
differential_test!(
    test_rule_18_missing_idempotency,
    "rule_18_missing-idempotency",
    "missing-idempotency"
);
differential_test!(
    test_rule_19_concurrent_in_transaction,
    "rule_19_concurrent-in-transaction",
    "concurrent-in-transaction"
);
differential_test!(
    test_rule_20_alter_type_add_value_txn,
    "rule_20_alter-type-add-value-txn",
    "alter-type-add-value-txn"
);
differential_test!(
    test_rule_21_vacuum_full,
    "rule_21_vacuum-full",
    "vacuum-full"
);
differential_test!(
    test_rule_22_opaque_dynamic_sql,
    "rule_22_opaque-dynamic-sql",
    "opaque-dynamic-sql"
);
differential_test!(
    test_rule_23_volatile_default,
    "rule_23_volatile-default",
    "volatile-default"
);
differential_test!(
    test_rule_24_overbroad_grant,
    "rule_24_overbroad-grant",
    "overbroad-grant"
);
differential_test!(
    test_rule_25_schema_drift,
    "rule_25_schema-drift",
    "schema-drift"
);
differential_test!(
    test_rule_26_chain_conflict,
    "rule_26_chain-conflict",
    "chain-conflict"
);
