use std::fs;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use safe_migrate::ast::identifiers::ObjectId;
use safe_migrate::db::cache::{CACHE_V6_MAGIC, DbCache, DbCacheVersioned};
use safe_migrate::model::relation::{Persistence, RelationKind, RelationState};
use safe_migrate::model::schema::SchemaState;

fn parse_json_stdout(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout must contain exactly one JSON document")
}

fn write_fresh_cache(path: &std::path::Path) {
    write_cache_with_timestamp(
        path,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
}

fn write_cache_with_timestamp(path: &std::path::Path, created_at_unix_secs: u64) {
    let mut cache = DbCache::new();
    cache.metadata.created_at_unix_secs = Some(created_at_unix_secs);
    let relation_id = ObjectId::new("public", "test_table");
    cache.insert_baseline(
        relation_id.clone(),
        RelationState::new(
            relation_id,
            ObjectId::new("", "postgres"),
            0,
            Some(0),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    let mut compressed = Vec::new();
    let mut encoder = zstd::stream::Encoder::new(&mut compressed, 3).unwrap();
    let config = bincode::config::standard().with_variable_int_encoding();
    encoder.write_all(CACHE_V6_MAGIC).unwrap();
    bincode::serde::encode_into_std_write(
        DbCacheVersioned::V6(Box::new(cache)),
        &mut encoder,
        config,
    )
    .unwrap();
    encoder.finish().unwrap();
    fs::write(path, compressed).unwrap();
}

#[test]
fn test_cli_help() {
    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("--help");
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Sync PostgreSQL metadata, then lint migrations offline"));
    assert!(!stdout.contains("prevent blocking locks"));
    assert!(stdout.contains("Sync PostgreSQL schema metadata and statistics into a local cache"));
    assert!(!stdout.contains("Sync database table statistics"));
}

#[test]
fn rules_command_lists_registry_descriptors_in_json() {
    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let output = cmd.arg("rules").arg("--json").output().unwrap();
    assert!(output.status.success());
    let report = parse_json_stdout(&output);
    assert_eq!(report["schema_version"], 2);
    let rules = report["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), 28);
    assert_eq!(rules[0]["id"], "irreversible-migration");
    assert_eq!(rules[0]["title"], "Irreversible migration");
    assert!(
        rules[0]["supported_configuration_fields"]
            .as_array()
            .expect("configuration fields")
            .iter()
            .any(|field| field == "disabled")
    );
    assert_eq!(rules[0]["effective"]["enabled"], true);
    for rule_id in ["require-lock-timeout", "require-statement-timeout"] {
        let rule = rules
            .iter()
            .find(|rule| rule["id"] == rule_id)
            .expect("timeout rule descriptor");
        assert_eq!(rule["default_tier"], "Tier2");
        assert_eq!(
            rule["supported_configuration_fields"],
            serde_json::json!(["disabled"])
        );
        assert_eq!(rule["effective"], serde_json::json!({ "enabled": true }));
    }
}

#[test]
fn rules_command_separates_human_descriptors() {
    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let output = cmd.arg("rules").arg("--no-color").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.starts_with("Irreversible migration (irreversible-migration)\n"));
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.len() >= 40 && line.bytes().all(|byte| byte == b'-'))
            .count(),
        27
    );
}

#[test]
fn rules_command_filters_one_rule_and_rejects_unknown_ids() {
    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let output = cmd
        .arg("rules")
        .arg("--rule")
        .arg("require-concurrent-index")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success());
    let report = parse_json_stdout(&output);
    assert_eq!(report["rules"].as_array().unwrap().len(), 1);
    assert_eq!(report["rules"][0]["id"], "require-concurrent-index");

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "[rules.require-concurrent-index]\ndisabled = true\ntier1_threshold_rows = 123\ntier2_threshold_rows = 45"
    )
    .unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let output = cmd
        .arg("rules")
        .arg("--rule")
        .arg("require-concurrent-index")
        .arg("--json")
        .arg("--config")
        .arg(config.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let configured = parse_json_stdout(&output);
    assert_eq!(configured["rules"][0]["effective"]["enabled"], false);
    assert_eq!(
        configured["rules"][0]["effective"]["tier1_threshold_rows"],
        123
    );
    assert_eq!(
        configured["rules"][0]["effective"]["tier2_threshold_rows"],
        45
    );

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("rules")
        .arg("--rule")
        .arg("unknown-rule")
        .assert()
        .code(1);
    assert!(
        String::from_utf8_lossy(&assert.get_output().stderr)
            .contains("Unknown primary rule ID 'unknown-rule'")
    );
}

#[test]
fn test_cli_rejects_unknown_configured_rule_id() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "SELECT 1;").unwrap();
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "[rules.concurent-index]\ndisabled = true").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--config")
        .arg(config_file.path())
        .arg("--no-cache")
        .assert()
        .code(1);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("Unknown primary rule ID(s): concurent-index"));
    assert!(stderr.contains("require-concurrent-index"));
}

#[test]
fn test_cli_rejects_thresholds_unsupported_by_a_rule() {
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        "[rules.require-lock-timeout]\ntier1_threshold_rows = 1"
    )
    .unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("rules")
        .arg("--json")
        .arg("--config")
        .arg(config_file.path())
        .assert()
        .code(1);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("Rule 'require-lock-timeout' does not support 'tier1_threshold_rows'"));
}

#[test]
fn test_cli_rejects_unknown_configuration_setting() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "SELECT 1;").unwrap();
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "auto_syn = true").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--config")
        .arg(config_file.path())
        .arg("--no-cache")
        .assert()
        .code(1);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("unknown field `auto_syn`"));
    assert!(stderr.contains("auto_sync"));
}

#[test]
fn test_cli_lint_nonexistent_file() {
    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("lint").arg("--file").arg("nonexistent_file.sql");
    cmd.assert().failure();
}

#[test]
fn test_cli_lint_invalid_cache() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "CREATE TABLE t (id int);").unwrap();

    let mut corrupted_cache = tempfile::NamedTempFile::new().unwrap();
    writeln!(corrupted_cache, "invalid json data").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--cache")
        .arg(corrupted_cache.path());
    cmd.assert().failure();
}

#[test]
fn test_cli_rejects_semantically_contradictory_v6_cache() {
    let mut invalid = DbCache::new();
    invalid.schemas.insert(
        "app".to_string(),
        SchemaState {
            name: "other".to_string(),
            owner: ObjectId::new("", "postgres"),
            generation: 0,
        },
    );
    let config = bincode::config::standard().with_variable_int_encoding();
    let encoded =
        bincode::serde::encode_to_vec(DbCacheVersioned::V6(Box::new(invalid)), config).unwrap();
    let mut compressed = Vec::new();
    let mut encoder = zstd::stream::Encoder::new(&mut compressed, 3).unwrap();
    encoder.write_all(CACHE_V6_MAGIC).unwrap();
    encoder.write_all(&encoded).unwrap();
    encoder.finish().unwrap();
    let cache = tempfile::NamedTempFile::new().unwrap();
    fs::write(cache.path(), compressed).unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("cache")
        .arg("inspect")
        .arg("--cache")
        .arg(cache.path())
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("schema cache key 'app' disagrees with embedded identity 'other'"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn test_cli_rejects_authenticated_semantically_contradictory_v6_cache() {
    let mut invalid = DbCache::new();
    invalid.schemas.insert(
        "app".to_string(),
        SchemaState {
            name: "other".to_string(),
            owner: ObjectId::new("", "postgres"),
            generation: 0,
        },
    );
    let config = bincode::config::standard().with_variable_int_encoding();
    let encoded =
        bincode::serde::encode_to_vec(DbCacheVersioned::V6(Box::new(invalid)), config).unwrap();
    let mut compressed = Vec::new();
    let mut encoder = zstd::stream::Encoder::new(&mut compressed, 3).unwrap();
    encoder.write_all(CACHE_V6_MAGIC).unwrap();
    encoder.write_all(&encoded).unwrap();
    encoder.finish().unwrap();

    let key = [0x2au8; 32];
    let nonce_bytes = [0x17u8; 24];
    let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = XNonce::try_from(nonce_bytes.as_slice()).unwrap();
    let ciphertext = cipher.encrypt(&nonce, compressed.as_ref()).unwrap();
    let mut envelope = b"SMENC001".to_vec();
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    let cache = tempfile::NamedTempFile::new().unwrap();
    fs::write(cache.path(), envelope).unwrap();
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "cache_encryption = true").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .env("SAFE_MIGRATE_CACHE_KEY", "2a".repeat(32))
        .arg("cache")
        .arg("inspect")
        .arg("--cache")
        .arg(cache.path())
        .arg("--config")
        .arg(config_file.path())
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("schema cache key 'app' disagrees with embedded identity 'other'"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains(&"2a".repeat(32)));
}

#[test]
fn test_cli_rejects_cache_with_oversized_decoded_container() {
    let config = bincode::config::standard().with_variable_int_encoding();
    let encoded =
        bincode::serde::encode_to_vec(DbCacheVersioned::V6(Box::default()), config).unwrap();
    assert_eq!(&encoded[..4], &[5, 0, 0, 0]);

    let mut malicious = encoded[..3].to_vec();
    malicious.push(1);
    malicious.push(252);
    malicious.extend_from_slice(&300_000_000u32.to_le_bytes());

    let mut compressed = Vec::new();
    let mut encoder = zstd::stream::Encoder::new(&mut compressed, 3).unwrap();
    encoder.write_all(CACHE_V6_MAGIC).unwrap();
    encoder.write_all(&malicious).unwrap();
    encoder.finish().unwrap();

    let mut cache = tempfile::NamedTempFile::new().unwrap();
    cache.write_all(&compressed).unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("cache")
        .arg("inspect")
        .arg("--cache")
        .arg(cache.path());
    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exceeds the 256 MiB decoded-size limit"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn test_cli_rejects_trailing_data_after_streamed_cache_decode() {
    let config = bincode::config::standard().with_variable_int_encoding();
    let encoded =
        bincode::serde::encode_to_vec(DbCacheVersioned::V6(Box::default()), config).unwrap();

    let mut compressed = Vec::new();
    let mut encoder = zstd::stream::Encoder::new(&mut compressed, 3).unwrap();
    encoder.write_all(CACHE_V6_MAGIC).unwrap();
    encoder.write_all(&encoded).unwrap();
    encoder.write_all(b"trailing-data").unwrap();
    encoder.finish().unwrap();

    let mut cache = tempfile::NamedTempFile::new().unwrap();
    cache.write_all(&compressed).unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("cache")
        .arg("inspect")
        .arg("--cache")
        .arg(cache.path())
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("trailing payload data"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn test_cache_inspect_rejects_unsupported_legacy_cache_without_exposing_its_version() {
    let mut compressed = Vec::new();
    let mut encoder = zstd::stream::Encoder::new(&mut compressed, 3).unwrap();
    encoder.write_all(b"legacy unheadered cache").unwrap();
    encoder.finish().unwrap();

    let cache = tempfile::NamedTempFile::new().unwrap();
    fs::write(cache.path(), compressed).unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("cache")
        .arg("inspect")
        .arg("--cache")
        .arg(cache.path())
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("unsupported cache format"));
    assert!(stderr.contains("safe-migrate sync"));
    assert!(!stderr.contains("V1"));
    assert!(!stderr.contains("V2"));
}

#[test]
fn test_cache_inspect_rejects_headered_legacy_caches() {
    for (header, internal_label) in [
        (b"SMCACHE03".as_slice(), "V3"),
        (b"SMCACHE05".as_slice(), "V5"),
    ] {
        let mut compressed = Vec::new();
        let mut encoder = zstd::stream::Encoder::new(&mut compressed, 3).unwrap();
        encoder.write_all(header).unwrap();
        encoder.write_all(b"legacy payload").unwrap();
        encoder.finish().unwrap();
        let cache = tempfile::NamedTempFile::new().unwrap();
        fs::write(cache.path(), compressed).unwrap();

        let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
        let assert = cmd
            .arg("cache")
            .arg("inspect")
            .arg("--cache")
            .arg(cache.path())
            .arg("--json")
            .assert()
            .failure();
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
        assert!(stderr.contains("unsupported cache format"));
        assert!(stderr.contains("safe-migrate sync"));
        assert!(!stderr.contains(internal_label));
    }
}

#[test]
fn test_cache_inspect_rejects_unknown_unheadered_cache_generically() {
    let mut compressed = Vec::new();
    let mut encoder = zstd::stream::Encoder::new(&mut compressed, 3).unwrap();
    encoder.write_all(&[4, 0, 0, 0]).unwrap();
    encoder.finish().unwrap();

    let cache = tempfile::NamedTempFile::new().unwrap();
    fs::write(cache.path(), compressed).unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("cache")
        .arg("inspect")
        .arg("--cache")
        .arg(cache.path())
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("unsupported cache format"));
    assert!(stderr.contains("safe-migrate sync"));
    assert!(!stderr.contains("V6"));
}

#[test]
fn test_cli_sync_no_db_url() {
    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("sync");
    // Ensure DATABASE_URL is not set
    cmd.env_remove("DATABASE_URL");
    cmd.assert().failure();
}

#[test]
fn test_cache_inspect_outputs_a_redacted_json_summary() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cache_path = temp_dir.path().join("baseline.cache");
    write_fresh_cache(&cache_path);

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("cache")
        .arg("inspect")
        .arg("--cache")
        .arg(&cache_path)
        .arg("--json")
        .assert()
        .success();
    let report = parse_json_stdout(assert.get_output());

    assert_eq!(report["path"], cache_path.display().to_string());
    assert_eq!(report["format_version"], 6);
    assert_eq!(report["encrypted"], false);
    assert_eq!(report["observed_settings"]["lock_timeout_ms"], 0);
    assert_eq!(report["observed_settings"]["statement_timeout_ms"], 0);
    assert!(report["contents"]["relations"].is_number());
    assert!(report["contents"]["columns"].is_number());
    assert!(report["contents"]["roles"].is_number());
    assert!(report["contents"]["schemas"].is_number());
    assert!(report["contents"]["sequences"].is_number());
    assert!(report["contents"]["functions"].is_number());
    assert!(report["contents"]["procedures"].is_number());
    assert!(report["contents"]["aggregates"].is_number());
    assert!(report["contents"]["window_functions"].is_number());
    assert!(report["contents"]["publications"].is_number());
    assert!(report["contents"]["subscriptions"].is_number());
    assert!(report.get("relation_names").is_none());
    assert!(report.get("database_url").is_none());
}

#[test]
fn test_cache_inspect_human_summary_discloses_redaction() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cache_path = temp_dir.path().join("baseline.cache");
    write_fresh_cache(&cache_path);

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("cache")
        .arg("inspect")
        .arg("--cache")
        .arg(&cache_path)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);

    assert!(stdout.contains("Observed lock_timeout: 0 ms"));
    assert!(stdout.contains("Observed statement_timeout: 0 ms"));
    assert!(stdout.contains("Contents (counts only):\n  Database objects\n"));
    assert!(stdout.contains("\n  Routines\n"));
    assert!(stdout.contains("\n  Replication\n"));
    assert!(stdout.contains("\n  Security and graph\n"));
    assert!(stdout.contains("    Window functions:"));
    assert!(stdout.contains(
        "    Relations:             1\n      Tables:              1\n      Views:               0\n      Materialized views:  0"
    ));
    assert!(!stdout.contains("relations ("));
    assert!(stdout.contains("Redaction: this summary intentionally omits"));
}

#[test]
fn test_cli_json_is_machine_clean_and_marks_missing_baseline_tainted() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "CREATE TABLE widgets (id bigint PRIMARY KEY);").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--no-cache")
        .arg("--json")
        .assert()
        .success();
    let output = assert.get_output();
    let report = parse_json_stdout(output);

    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["confidence"], "Tainted");
    assert_eq!(report["baseline"]["status"], "unavailable");
    assert!(report["baseline"]["observed_settings"]["lock_timeout_ms"].is_null());
    assert!(report["baseline"]["observed_settings"]["statement_timeout_ms"].is_null());
    assert!(report["violations"].is_array());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("[ INFO ]"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--no-cache passed"));
}

#[test]
fn test_cli_no_cache_does_not_invent_schema_drift() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "ALTER TABLE widgets ADD COLUMN status text;").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--no-cache")
        .arg("--json")
        .assert()
        .success();
    let report = parse_json_stdout(assert.get_output());

    assert_eq!(report["confidence"], "Tainted");
    assert!(
        report["violations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|violation| violation["rule_id"] != "schema-drift")
    );
}

#[test]
fn test_cli_no_cache_bypasses_configured_auto_sync() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "CREATE TABLE widgets (id bigint PRIMARY KEY);").unwrap();
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "auto_sync = true").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--config")
        .arg(config_file.path())
        .arg("--no-cache")
        .arg("--json")
        .env("DATABASE_URL", "postgres://127.0.0.1:1/not-used")
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("bypasses configured automatic cache sync"));
    assert!(!stderr.contains("Automatic cache sync enabled"));
}

#[test]
fn test_cli_no_auto_sync_uses_cache_without_database_access() {
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path = cache_dir.path().join("baseline.cache");
    write_fresh_cache(&cache_path);
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "auto_sync = true").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg("live_tests/rule_01_irreversible-migration/safe_002_add_col.sql")
        .arg("--config")
        .arg(config_file.path())
        .arg("--cache")
        .arg(&cache_path)
        .arg("--no-auto-sync")
        .arg("--json")
        .env("DATABASE_URL", "postgres://127.0.0.1:1/not-used")
        .assert()
        .success();

    let output = assert.get_output();
    let report = parse_json_stdout(output);
    assert_eq!(report["baseline"]["auto_sync"], "bypassed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--no-auto-sync bypasses configured automatic cache sync"));
    assert!(!stderr.contains("Automatic cache sync enabled"));
}

#[test]
fn explicit_missing_config_is_an_error_for_lint_and_rules() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "SELECT 1;").unwrap();
    let missing = sql_file.path().with_extension("missing.toml");

    for command in ["lint", "rules"] {
        let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
        cmd.arg(command);
        if command == "lint" {
            cmd.arg("--file").arg(sql_file.path()).arg("--no-cache");
        }
        cmd.arg("--config").arg(&missing);
        let output = cmd.output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Failed to load configuration"));
    }
}

#[test]
fn lint_chain_rejects_a_directory_without_sql_files() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("README.txt"), "not a migration").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let output = cmd
        .arg("lint-chain")
        .arg("--dir")
        .arg(directory.path())
        .arg("--no-cache")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("No .sql migration files found"));
}

#[test]
fn empty_configured_schema_scope_fails_before_auto_sync() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "SELECT 1;").unwrap();
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "auto_sync = true\nschemas = []").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let output = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--config")
        .arg(config_file.path())
        .arg("--no-cache")
        .env("DATABASE_URL", "postgres://127.0.0.1:1/not-used")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no schema name may be blank"));
}

#[test]
fn test_cli_auto_sync_failure_continues_without_a_cache() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "CREATE TABLE widgets (id bigint PRIMARY KEY);").unwrap();
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "auto_sync = true").unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path = cache_dir.path().join("missing.cache");

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--config")
        .arg(config_file.path())
        .arg("--cache")
        .arg(&cache_path)
        .arg("--json")
        .env("DATABASE_URL", "postgres://127.0.0.1:1/safe_migrate")
        .assert()
        .success();

    let output = assert.get_output();
    let report = parse_json_stdout(output);
    assert_eq!(report["confidence"], "Tainted");
    assert_eq!(report["baseline"]["status"], "unavailable");
    assert_eq!(report["baseline"]["auto_sync"], "failed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Automatic cache sync failed"));
    assert!(stderr.contains("No usable cache is available"));
}

#[test]
fn test_cli_auto_sync_failure_uses_the_previous_cache() {
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path = cache_dir.path().join("baseline.cache");
    write_cache_with_timestamp(&cache_path, 0);

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "auto_sync = true").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg("live_tests/rule_01_irreversible-migration/safe_002_add_col.sql")
        .arg("--config")
        .arg(config_file.path())
        .arg("--cache")
        .arg(&cache_path)
        .arg("--json")
        .env("DATABASE_URL", "postgres://127.0.0.1:1/safe_migrate")
        .assert()
        .success();

    let output = assert.get_output();
    let report = parse_json_stdout(output);
    assert_eq!(report["confidence"], "Tainted");
    assert_eq!(report["baseline"]["status"], "stale");
    assert_eq!(report["baseline"]["auto_sync"], "failed");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Continuing with the previous cache"));
}

#[test]
fn test_cli_auto_sync_failure_keeps_fresh_cache_confidence_exact() {
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path = cache_dir.path().join("fresh-baseline.cache");
    write_fresh_cache(&cache_path);

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "auto_sync = true").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg("live_tests/rule_01_irreversible-migration/safe_002_add_col.sql")
        .arg("--config")
        .arg(config_file.path())
        .arg("--cache")
        .arg(&cache_path)
        .arg("--json")
        .env("DATABASE_URL", "postgres://127.0.0.1:1/safe_migrate")
        .assert()
        .success();

    let output = assert.get_output();
    let report = parse_json_stdout(output);
    assert_eq!(report["confidence"], "Exact");
    assert_eq!(report["baseline"]["status"], "available");
    assert_eq!(report["baseline"]["auto_sync"], "failed");
    assert_eq!(
        report["baseline"]["observed_settings"]["lock_timeout_ms"],
        0
    );
    assert_eq!(
        report["baseline"]["observed_settings"]["statement_timeout_ms"],
        0
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Continuing with the previous cache"));
}

#[test]
fn test_cli_json_halt_is_json_and_uses_blocking_exit_status() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "DROP DATABASE production;").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--no-cache")
        .arg("--json")
        .assert()
        .code(2);
    let report = parse_json_stdout(assert.get_output());

    assert_eq!(report["verdict"], "HALT");
    assert_eq!(report["confidence"], "Tainted");
    let finding = report["violations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|violation| violation["rule_id"] == "drop-database" && violation["tier"] == "Tier1")
        .expect("drop-database finding");
    assert_eq!(
        finding["location"]["file"],
        sql_file.path().display().to_string()
    );
    assert_eq!(finding["location"]["line"], 1);
    assert_eq!(finding["location"]["column"], 1);
    assert_eq!(finding["statement_index"], 1);
    assert_eq!(finding["rule_title"], "Drop database");
    assert_eq!(finding["impact"], "data loss");
    let rule_ids = report["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|violation| violation["rule_id"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert!(rule_ids.contains("require-lock-timeout"));
    assert!(rule_ids.contains("require-statement-timeout"));
    assert_eq!(report["summary"]["total"], 3);
    assert_eq!(report["summary"]["tier1"], 1);
    assert_eq!(report["summary"]["tier2"], 2);
}

#[test]
fn test_cli_json_statement_index_counts_preceding_schema_neutral_statements() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "COMMENT ON TABLE widgets IS 'migration note';").unwrap();
    writeln!(sql_file, "DROP DATABASE production;").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--no-cache")
        .arg("--json")
        .assert()
        .code(2);
    let report = parse_json_stdout(assert.get_output());
    let finding = report["violations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|violation| violation["rule_id"] == "drop-database")
        .expect("drop-database finding");

    assert_eq!(finding["statement_index"], 2);
}

#[test]
fn test_cli_markdown_report_is_machine_clean_and_includes_location() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "DROP DATABASE production;").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--no-cache")
        .arg("--markdown")
        .assert()
        .code(2);
    let output = assert.get_output();
    let markdown = String::from_utf8_lossy(&output.stdout);

    assert!(markdown.starts_with("# safe-migrate report\n"));
    assert!(markdown.contains("### HALT — Drop database (`drop-database`)"));
    assert!(markdown.contains("**Impact:** data loss"));
    assert!(markdown.contains("**Statement:** 1"));
    assert!(markdown.contains(&format!("`{}:1:1`", sql_file.path().display())));
    assert!(markdown.contains("## Baseline"));
    assert!(!markdown.contains("Analyzing migration"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Analyzing migration"));
}

#[test]
fn test_cli_chain_json_reports_the_source_file_for_findings() {
    let dir = tempfile::tempdir().unwrap();
    let migration = dir.path().join("002_drop_database.sql");
    fs::write(&migration, "DROP DATABASE production;").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint-chain")
        .arg("--dir")
        .arg(dir.path())
        .arg("--no-cache")
        .arg("--json")
        .assert()
        .code(2);
    let report = parse_json_stdout(assert.get_output());
    let finding = report["violations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|violation| violation["rule_id"] == "drop-database")
        .expect("drop-database finding");
    assert_eq!(finding["location"]["file"], migration.display().to_string());
    assert_eq!(finding["location"]["line"], 1);
}

#[test]
fn test_cli_json_locations_preserve_offsets_through_execute_normalization() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "-- generated migration").unwrap();
    writeln!(sql_file, "EXECUTE 'DROP DATABASE production';").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--no-cache")
        .arg("--json")
        .assert()
        .success();
    let report = parse_json_stdout(assert.get_output());
    let finding = report["violations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|violation| violation["rule_id"] == "opaque-dynamic-sql")
        .expect("opaque dynamic SQL finding");

    assert_eq!(finding["location"]["line"], 2);
    assert_eq!(finding["location"]["column"], 1);
}

#[test]
fn test_cli_rejects_json_and_markdown_together() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "CREATE TABLE widgets (id bigint PRIMARY KEY);").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--json")
        .arg("--markdown")
        .assert()
        .failure();
}

#[test]
fn test_cli_human_halt_uses_blocking_exit_status() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "DROP DATABASE production;").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--no-cache")
        .assert()
        .code(2);
}

#[test]
fn test_cli_chain_json_is_machine_clean() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("001_create_widgets.sql"),
        "CREATE TABLE widgets (id bigint PRIMARY KEY);",
    )
    .unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint-chain")
        .arg("--dir")
        .arg(dir.path())
        .arg("--no-cache")
        .arg("--json")
        .assert()
        .success();
    let output = assert.get_output();
    let report = parse_json_stdout(output);

    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["confidence"], "Tainted");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Analyzing migration"));
}

#[test]
fn test_cli_rejects_json_and_interactive_together() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "CREATE TABLE widgets (id bigint PRIMARY KEY);").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    let assert = cmd
        .arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--json")
        .arg("--interactive")
        .assert()
        .failure();

    assert!(String::from_utf8_lossy(&assert.get_output().stderr).contains("cannot be used with"));
}
