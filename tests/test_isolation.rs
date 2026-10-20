//! Test-isolation invariants.
//!
//! `DATABASE_URL` and the live test database are process-wide resources shared
//! by every test in the binary. A test that reads the URL without the shared
//! lock races with the tests that replace or remove it, and silently changes
//! behaviour depending on scheduling; that showed up as a suite that failed a
//! different handful of tests on each run. These tests make the rule mechanical
//! instead of a convention.

mod test_isolation_tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn rust_sources_under(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()));
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                rust_sources_under(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    fn all_rust_sources() -> Vec<PathBuf> {
        let mut out = Vec::new();
        for dir in ["tests", "src"] {
            rust_sources_under(&repo_root().join(dir), &mut out);
        }
        assert!(!out.is_empty(), "no Rust sources discovered");
        out
    }

    fn relative(path: &Path) -> String {
        path.strip_prefix(repo_root())
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    }

    /// Reading `DATABASE_URL` from the environment is only safe while holding
    /// the shared lock, so test code must go through `LiveDatabaseGuard`.
    /// Production may read it; the guard is the single place that may.
    #[test]
    fn only_production_and_the_live_guard_read_database_url_from_the_environment() {
        const ALLOWED: [&str; 2] = ["src/_internal/sync/mod.rs", "src/_internal/test_support.rs"];

        let offenders: Vec<String> = all_rust_sources()
            .into_iter()
            .filter(|path| {
                let rel = relative(path);
                !ALLOWED.contains(&rel.as_str())
            })
            .filter(|path| {
                std::fs::read_to_string(path)
                    .map(|source| {
                        source.contains("var(\"DATABASE_URL\")")
                            || source.contains("var_os(\"DATABASE_URL\")")
                    })
                    .unwrap_or(false)
            })
            .map(|path| relative(&path))
            .collect();

        assert!(
            offenders.is_empty(),
            "these files read DATABASE_URL from the environment without the live-database \
             guard, so they race with tests that replace or remove it. Use \
             `crate::internal_tests::live_database_test_lock()` and read the URL through \
             `LiveDatabaseGuard::url()`: {offenders:?}"
        );
    }

    /// A live test that does not take the guard can collide with another live
    /// test over the shared disposable fixtures.
    #[test]
    fn every_live_test_file_takes_the_live_database_guard() {
        // A live suite is a unit: `tests/live_x.rs` or the `tests/live_x/`
        // directory that replaces it when the suite grows submodules. The
        // guard may live in any file of the unit.
        let mut units: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
        for path in all_rust_sources() {
            let rel = relative(&path);
            if !rel.starts_with("tests/live_") || !rel.ends_with(".rs") {
                continue;
            }
            let unit = match rel
                .strip_prefix("tests/")
                .and_then(|rest| rest.split_once('/'))
            {
                Some((directory, _)) => format!("tests/{directory}"),
                None => rel.clone(),
            };
            units.entry(unit).or_default().push(path);
        }

        assert!(!units.is_empty(), "no live test files discovered");

        let offenders: Vec<String> = units
            .into_iter()
            .filter(|(_, files)| {
                !files.iter().any(|path| {
                    // A file may read the URL only through the guard, so requiring
                    // the guard to appear is the whole check.
                    std::fs::read_to_string(path)
                        .expect("read live test file")
                        .contains("live_database_test_lock")
                })
            })
            .map(|(unit, _)| unit)
            .collect();

        assert!(
            offenders.is_empty(),
            "live test files must hold `live_database_test_lock()`: {offenders:?}"
        );
    }

    /// Guards must be bound to a name, not created and dropped immediately: a
    /// bare `live_database_test_lock();` releases the lock before the test body
    /// and serializes nothing.
    #[test]
    fn live_database_guard_is_bound_to_a_let_binding() {
        let offenders: Vec<String> = all_rust_sources()
            .into_iter()
            .filter(|path| relative(path).starts_with("tests/live_"))
            .filter(|path| {
                let source = std::fs::read_to_string(path).expect("read live test file");
                source.lines().any(|line| {
                    let trimmed = line.trim();
                    trimmed.starts_with("crate::internal_tests::live_database_test_lock()")
                        || trimmed.starts_with("live_database_test_lock()")
                })
            })
            .map(|path| relative(&path))
            .collect();

        assert!(
            offenders.is_empty(),
            "bind the guard (`let _guard = ...`) so it lives for the test body: {offenders:?}"
        );
    }
}
