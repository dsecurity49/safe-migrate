use std::fs;
use std::io::Read;
use std::path::Path;

use safe_migrate::db::cache::{CACHE_V5_MAGIC, DbCacheVersioned};

fn run_auto_sync_case(
    database_url: &str,
    expected_role: &str,
    expected_session_role: &str,
    mode: &str,
) {
    let temp_dir = tempfile::tempdir().expect("create live auto-sync temp directory");
    let config_path = temp_dir.path().join("safe-migrate.toml");
    let cache_path = temp_dir.path().join("baseline.cache");
    fs::write(&config_path, "auto_sync = true\nschemas = [\"public\"]\n")
        .expect("write live auto-sync config");

    let mut command = assert_cmd::Command::cargo_bin("safe-migrate").expect("safe-migrate binary");
    command
        .arg(mode)
        .arg("--config")
        .arg(&config_path)
        .arg("--cache")
        .arg(&cache_path)
        .arg("--json")
        .env("DATABASE_URL", database_url);

    match mode {
        "lint" => {
            let migration_path = temp_dir.path().join("migration.sql");
            fs::write(&migration_path, "SET search_path TO public;\n")
                .expect("write lint migration");
            command.arg("--file").arg(migration_path);
        }
        "lint-chain" => {
            let migrations_dir = temp_dir.path().join("migrations");
            fs::create_dir(&migrations_dir).expect("create lint-chain directory");
            fs::write(
                migrations_dir.join("001_first.sql"),
                "SET search_path TO public;\n",
            )
            .expect("write first chain migration");
            fs::write(
                migrations_dir.join("002_second.sql"),
                "SET search_path TO public;\n",
            )
            .expect("write second chain migration");
            command.arg("--dir").arg(migrations_dir);
        }
        other => panic!("unsupported live auto-sync mode: {other}"),
    }

    let output = command.output().expect("run safe-migrate");
    assert!(
        output.status.success(),
        "{mode} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse auto-sync JSON report");
    assert_eq!(report["baseline"]["auto_sync"], "refreshed");
    assert_eq!(report["baseline"]["status"], "available");
    assert_eq!(report["confidence"], "Exact");
    assert!(
        Path::new(&cache_path).is_file(),
        "auto-sync cache was not written"
    );
    let encoded = fs::read(&cache_path).expect("read auto-sync cache");
    let mut decoder = zstd::stream::Decoder::new(encoded.as_slice()).expect("decode cache zstd");
    let mut payload = Vec::new();
    decoder
        .read_to_end(&mut payload)
        .expect("read decoded cache payload");
    let v5_payload = payload
        .strip_prefix(CACHE_V5_MAGIC)
        .expect("auto-sync must write a V5 cache");
    let config = bincode::config::standard().with_variable_int_encoding();
    let (versioned, bytes_read): (DbCacheVersioned, usize) =
        bincode::serde::decode_from_slice(v5_payload, config).expect("decode V5 cache");
    assert_eq!(bytes_read, v5_payload.len());
    let DbCacheVersioned::V5(cache) = versioned else {
        panic!("auto-sync must encode the V5 cache variant");
    };
    assert_eq!(cache.metadata.source_role.as_deref(), Some(expected_role));
    assert_eq!(
        cache.metadata.source_session_role.as_deref(),
        Some(expected_session_role)
    );
    assert!(cache.metadata.source_search_path.is_some());
    assert!(!cache.roles.is_empty());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Automatic cache sync enabled"));
    assert!(!stderr.contains("Automatic cache sync failed"));
}

#[test]
#[ignore = "requires a live local PostgreSQL database via DATABASE_URL"]
fn live_auto_sync_refreshes_lint_and_lint_chain() {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL is required for live auto-sync proof");
    let mut client = postgres::Client::connect(&database_url, postgres::NoTls)
        .expect("connect for current_user oracle");
    let role_oracle = client
        .query_one("SELECT current_user, session_user", &[])
        .expect("query role oracle");
    let expected_role: String = role_oracle.get(0);
    let expected_session_role: String = role_oracle.get(1);
    run_auto_sync_case(
        &database_url,
        &expected_role,
        &expected_session_role,
        "lint",
    );
    run_auto_sync_case(
        &database_url,
        &expected_role,
        &expected_session_role,
        "lint-chain",
    );
}
