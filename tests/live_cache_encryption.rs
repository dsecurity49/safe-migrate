use std::fs;
use std::process::Output;

const TEST_KEY: &str = "4242424242424242424242424242424242424242424242424242424242424242";
const WRONG_KEY: &str = "2424242424242424242424242424242424242424242424242424242424242424";

fn parse_json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout must contain one JSON document")
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires a live local PostgreSQL database via DATABASE_URL"]
fn live_encrypted_cache_round_trip_and_rejection_contract() {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL is required for encryption proof");
    let temp_dir = tempfile::tempdir().expect("create live encryption temp directory");
    let config_path = temp_dir.path().join("encrypted.toml");
    let plain_config_path = temp_dir.path().join("plain.toml");
    let cache_path = temp_dir.path().join("encrypted.cache");
    fs::write(&config_path, "cache_encryption = true\n").expect("write encryption config");
    fs::write(&plain_config_path, "").expect("write plain config");

    let mut sync = assert_cmd::Command::cargo_bin("safe-migrate").expect("safe-migrate binary");
    let sync_output = sync
        .arg("sync")
        .arg("--out")
        .arg(&cache_path)
        .arg("--config")
        .arg(&config_path)
        .arg("--schemas")
        .arg("public")
        .env("DATABASE_URL", &database_url)
        .env("SAFE_MIGRATE_CACHE_KEY", TEST_KEY)
        .output()
        .expect("run encrypted sync");
    assert_success(&sync_output, "encrypted sync");
    assert!(
        String::from_utf8_lossy(&sync_output.stdout)
            .contains("Syncing PostgreSQL schema metadata and statistics")
    );
    assert!(!String::from_utf8_lossy(&sync_output.stdout).contains(TEST_KEY));
    assert!(!String::from_utf8_lossy(&sync_output.stderr).contains(TEST_KEY));

    let cache_bytes = fs::read(&cache_path).expect("read encrypted cache");
    assert!(cache_bytes.starts_with(b"SMENC001"));
    assert!(
        !cache_bytes
            .windows(TEST_KEY.len())
            .any(|bytes| bytes == TEST_KEY.as_bytes())
    );

    let mut inspect = assert_cmd::Command::cargo_bin("safe-migrate").expect("safe-migrate binary");
    let inspect_output = inspect
        .arg("cache")
        .arg("inspect")
        .arg("--cache")
        .arg(&cache_path)
        .arg("--config")
        .arg(&config_path)
        .arg("--json")
        .env("SAFE_MIGRATE_CACHE_KEY", TEST_KEY)
        .output()
        .expect("inspect encrypted cache");
    assert_success(&inspect_output, "encrypted cache inspect");
    let inspection = parse_json(&inspect_output);
    assert_eq!(inspection["encrypted"], true);
    assert_eq!(inspection["format_version"], 6);

    let migration_path = temp_dir.path().join("migration.sql");
    fs::write(&migration_path, "SELECT 1;\n").expect("write lint migration");
    let mut lint = assert_cmd::Command::cargo_bin("safe-migrate").expect("safe-migrate binary");
    let lint_output = lint
        .arg("lint")
        .arg("--file")
        .arg(&migration_path)
        .arg("--cache")
        .arg(&cache_path)
        .arg("--config")
        .arg(&config_path)
        .arg("--json")
        .env("SAFE_MIGRATE_CACHE_KEY", TEST_KEY)
        .output()
        .expect("lint with encrypted cache");
    assert_success(&lint_output, "lint with encrypted cache");
    let lint_report = parse_json(&lint_output);
    assert_eq!(lint_report["baseline"]["status"], "available");
    assert_eq!(lint_report["confidence"], "Exact");

    let auto_config_path = temp_dir.path().join("encrypted-auto-sync.toml");
    let auto_cache_path = temp_dir.path().join("encrypted-auto-sync.cache");
    fs::write(
        &auto_config_path,
        "auto_sync = true\ncache_encryption = true\nschemas = [\"public\"]\n",
    )
    .expect("write encrypted auto-sync config");
    let mut encrypted_auto_sync =
        assert_cmd::Command::cargo_bin("safe-migrate").expect("safe-migrate binary");
    let auto_sync_output = encrypted_auto_sync
        .arg("lint")
        .arg("--file")
        .arg(&migration_path)
        .arg("--cache")
        .arg(&auto_cache_path)
        .arg("--config")
        .arg(&auto_config_path)
        .arg("--json")
        .env("DATABASE_URL", &database_url)
        .env("SAFE_MIGRATE_CACHE_KEY", TEST_KEY)
        .output()
        .expect("run encrypted automatic sync");
    assert_success(&auto_sync_output, "encrypted automatic sync");
    let auto_sync_report = parse_json(&auto_sync_output);
    assert_eq!(auto_sync_report["baseline"]["auto_sync"], "refreshed");
    assert_eq!(auto_sync_report["baseline"]["status"], "available");
    assert!(
        fs::read(&auto_cache_path)
            .expect("read encrypted auto-sync cache")
            .starts_with(b"SMENC001")
    );

    let migrations_dir = temp_dir.path().join("migrations");
    fs::create_dir(&migrations_dir).expect("create lint-chain directory");
    fs::write(migrations_dir.join("001_first.sql"), "SELECT 1;\n")
        .expect("write first chain migration");
    fs::write(migrations_dir.join("002_second.sql"), "SELECT 2;\n")
        .expect("write second chain migration");
    let mut lint_chain =
        assert_cmd::Command::cargo_bin("safe-migrate").expect("safe-migrate binary");
    let chain_output = lint_chain
        .arg("lint-chain")
        .arg("--dir")
        .arg(&migrations_dir)
        .arg("--cache")
        .arg(&cache_path)
        .arg("--config")
        .arg(&config_path)
        .arg("--json")
        .env("SAFE_MIGRATE_CACHE_KEY", TEST_KEY)
        .output()
        .expect("lint-chain with encrypted cache");
    assert_success(&chain_output, "lint-chain with encrypted cache");
    let chain_report = parse_json(&chain_output);
    assert_eq!(chain_report["baseline"]["status"], "available");
    assert_eq!(chain_report["confidence"], "Exact");

    for (label, config, key, expected) in [
        (
            "disabled encryption",
            &plain_config_path,
            Some(TEST_KEY),
            "Cache file is encrypted",
        ),
        (
            "missing key",
            &config_path,
            None,
            "SAFE_MIGRATE_CACHE_KEY must contain",
        ),
        (
            "wrong key",
            &config_path,
            Some(WRONG_KEY),
            "key is incorrect or the file was modified",
        ),
    ] {
        let mut rejected =
            assert_cmd::Command::cargo_bin("safe-migrate").expect("safe-migrate binary");
        rejected
            .arg("cache")
            .arg("inspect")
            .arg("--cache")
            .arg(&cache_path)
            .arg("--config")
            .arg(config);
        if let Some(key) = key {
            rejected.env("SAFE_MIGRATE_CACHE_KEY", key);
        } else {
            rejected.env_remove("SAFE_MIGRATE_CACHE_KEY");
        }
        let output = rejected.output().expect("run encrypted-cache rejection");
        assert!(!output.status.success(), "{label} unexpectedly succeeded");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected),
            "{label} produced unexpected stderr: {stderr}"
        );
    }
}
