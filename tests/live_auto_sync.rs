use std::fs;
use std::path::Path;

fn run_auto_sync_case(database_url: &str, mode: &str) {
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

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Automatic cache sync enabled"));
    assert!(!stderr.contains("Automatic cache sync failed"));
}

#[test]
#[ignore = "requires a live local PostgreSQL database via DATABASE_URL"]
fn live_auto_sync_refreshes_lint_and_lint_chain() {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL is required for live auto-sync proof");
    run_auto_sync_case(&database_url, "lint");
    run_auto_sync_case(&database_url, "lint-chain");
}
