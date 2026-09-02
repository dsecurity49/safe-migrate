use safe_migrate::api;

#[test]
fn public_api_analyzes_with_only_supported_reexports() {
    let outcome = api::analyze(
        api::Config::default(),
        "migration.sql",
        "",
        api::DbCache::new(),
    )
    .expect("the supported API should accept a valid empty migration");

    assert!(outcome.findings.is_empty());
    assert!(outcome.evidence.is_empty());
}
