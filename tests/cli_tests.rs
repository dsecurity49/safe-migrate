use std::io::Write;

#[test]
fn test_cli_help() {
    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("--help");
    cmd.assert().success();
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
fn test_cli_lint_cache_format_version_mismatch() {
    let mut sql_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(sql_file, "CREATE TABLE t (id int);").unwrap();

    let cache_file = tempfile::NamedTempFile::new().unwrap();

    // Write a valid zstd+bincode cache with wrong format version
    let mut cache = safe_migrate::DbCache::new();
    cache.cache_format_version = 999;
    let encoded = bincode::serde::encode_to_vec(&cache, bincode::config::standard()).unwrap();
    let compressed = zstd::encode_all(encoded.as_slice(), 3).unwrap();
    std::fs::write(cache_file.path(), &compressed).unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("lint")
        .arg("--file")
        .arg(sql_file.path())
        .arg("--cache")
        .arg(cache_file.path());
    cmd.assert().failure();
}

#[test]
fn test_cli_sync_no_db_url() {
    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("sync");
    // Ensure DATABASE_URL is not set
    cmd.env_remove("DATABASE_URL");
    cmd.assert().failure();
}
