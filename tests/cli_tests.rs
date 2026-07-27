use std::fs;
use std::io::Write;

fn parse_json_stdout(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout must contain exactly one JSON document")
}

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
fn test_cli_sync_no_db_url() {
    let mut cmd = assert_cmd::Command::cargo_bin("safe-migrate").unwrap();
    cmd.arg("sync");
    // Ensure DATABASE_URL is not set
    cmd.env_remove("DATABASE_URL");
    cmd.assert().failure();
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
    assert!(report["violations"].is_array());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("[ INFO ]"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--no-cache passed"));
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
    assert!(
        report["violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |violation| violation["rule_id"] == "drop-database" && violation["tier"] == "Tier1"
            )
    );
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
