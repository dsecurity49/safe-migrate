use safe_migrate::api;
use std::error::Error as _;

#[test]
fn public_api_analyzes_a_typed_migration_chain_with_an_opaque_baseline() {
    let config = api::Config::default()
        .with_cache_encryption(false)
        .with_tier_thresholds(100_000, 10_000);
    let outcome = api::analyze_chain(
        &config,
        [api::Migration::new("migration.sql", "")],
        &api::Baseline::unavailable(),
    )
    .expect("the supported API should accept a valid empty migration");

    assert!(outcome.findings().is_empty());
    assert_eq!(outcome.confidence(), api::Confidence::Tainted);
    assert_eq!(outcome.evidence().len(), 1);
    assert_eq!(
        outcome.evidence()[0].code,
        api::EvidenceCode::BaselineUnavailable
    );
    assert!(api::rule(&api::Config::default(), "missing-idempotency").is_ok());
}

#[test]
fn public_config_builders_cover_every_runtime_setting() {
    let rule = api::RuleConfig::new()
        .disabled(true)
        .tier_thresholds(Some(25), Some(10));
    let config = api::Config::default()
        .with_cache_encryption(true)
        .with_auto_sync(true)
        .with_stale_stats_days(3)
        .with_tier_thresholds(500, 50)
        .with_default_rows(250)
        .with_toast_width_threshold_bytes(1024)
        .with_assumed_postgres_version(170000)
        .with_schema_scope(["public"])
        .with_rule("missing-idempotency", rule.clone())
        .enable_rule("missing-idempotency")
        .disable_rule("require-lock-timeout");

    assert!(config.cache_encryption());
    assert!(config.auto_sync());
    assert_eq!(config.stale_stats_days(), 3);
    assert_eq!(config.tier1_threshold_rows(), 500);
    assert_eq!(config.tier2_threshold_rows(), 50);
    assert_eq!(config.default_rows(), 250);
    assert_eq!(config.toast_width_threshold_bytes(), 1024);
    assert_eq!(config.assumed_postgres_version(), 170000);
    assert_eq!(
        config.schema_scope(),
        Some([String::from("public")].as_slice())
    );
    assert!(!config.is_rule_disabled("missing-idempotency"));
    assert!(config.is_rule_disabled("require-lock-timeout"));
    assert_eq!(
        config
            .rule_config("missing-idempotency")
            .unwrap()
            .disabled_override(),
        Some(false)
    );
    assert_eq!(rule.disabled_override(), Some(true));
    assert_eq!(rule.tier1_threshold_rows(), Some(25));
    assert_eq!(rule.tier2_threshold_rows(), Some(10));
}

#[test]
fn unavailable_baseline_is_honest_in_every_report_surface() {
    let config = api::Config::default();
    let baseline = api::Baseline::unavailable();
    let inspection = baseline.inspect();
    assert!(!inspection.available);
    assert_eq!(inspection.format_version, None);
    assert_eq!(inspection.observed_settings.lock_timeout_ms, None);

    let outcome = api::analyze(
        &config,
        "001_create_users.sql",
        "CREATE TABLE users (id bigint);",
        &baseline,
    )
    .expect("analyze with conservative defaults");
    assert_eq!(outcome.baseline().status, api::BaselineStatus::Unavailable);
    assert_eq!(outcome.confidence(), api::Confidence::Tainted);
    assert_eq!(
        serde_json::to_value(outcome.confidence()).unwrap(),
        "Tainted"
    );

    let json = outcome.json();
    assert_eq!(json["baseline"]["status"], "unavailable");
    assert_eq!(json["baseline"]["auto_sync"], "not_requested");
    assert_eq!(
        json["baseline"],
        serde_json::to_value(outcome.baseline()).unwrap()
    );
    assert_eq!(
        json["evidence"],
        serde_json::to_value(outcome.evidence()).unwrap()
    );
    assert!(outcome.markdown().contains("## Baseline"));
}

#[test]
fn public_finding_serialization_matches_the_report_contract() {
    let config = api::Config::default();
    let baseline = api::Baseline::unavailable();
    let outcome = api::analyze(
        &config,
        "001_create_users.sql",
        "CREATE TABLE users (id bigint);",
        &baseline,
    )
    .unwrap();
    let finding = outcome
        .findings()
        .iter()
        .find(|finding| finding.rule_id == "missing-idempotency")
        .expect("CREATE TABLE without a guard should be reported");
    assert_eq!(finding.operation_kind, api::OperationKind::CreateTable);
    assert_eq!(finding.object_kind, api::ObjectKind::Table);
    let value = serde_json::to_value(finding).unwrap();

    assert_eq!(value["fk_dependency_related"], false);
    assert!(value.get("foreign_key_dependency_related").is_none());
    assert_eq!(value["rule_title"], "Missing idempotency");
    assert!(value.get("rule_summary").is_some());
    assert!(value.get("impact").is_some());
    assert!(value.get("dedup_key").is_some());
    let report_finding = outcome.json()["violations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["rule_id"] == finding.rule_id)
        .unwrap()
        .clone();
    assert_eq!(value, report_finding);
}

#[test]
fn outcome_exposes_the_same_verdict_and_summary_as_its_reports() {
    let outcome = api::analyze(
        &api::Config::default(),
        "001_create_users.sql",
        "CREATE TABLE users (id bigint);",
        &api::Baseline::unavailable(),
    )
    .unwrap();

    assert_eq!(outcome.verdict(), api::Verdict::Safe);
    assert_eq!(outcome.verdict().as_str(), "SAFE");
    assert_eq!(
        outcome.recommendation(),
        "no blocking finding, but baseline evidence is uncertain — review before deploying"
    );
    let summary = outcome.summary();
    assert_eq!(summary.total, outcome.findings().len());
    assert_eq!(summary.total, summary.tier1 + summary.tier2 + summary.tier3);
    assert_eq!(outcome.json()["verdict"], "SAFE");
    assert_eq!(outcome.json()["schema_version"], api::REPORT_SCHEMA_VERSION);
    assert_eq!(
        outcome.json()["summary"],
        serde_json::to_value(summary).unwrap()
    );
}

#[test]
fn optional_baseline_only_downgrades_a_missing_file() {
    let directory = tempfile::tempdir().unwrap();
    let config = api::Config::default();
    let missing = directory.path().join("missing.cache");
    let baseline = api::Baseline::load_optional(&missing, &config).unwrap();

    assert!(!baseline.is_available());
}

#[test]
fn configuration_errors_have_a_stable_kind_and_source() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid.toml");
    std::fs::write(&path, "auto_syn = true").unwrap();
    let error = api::Config::load_required_from_file(&path).unwrap_err();

    assert_eq!(error.kind(), api::ErrorKind::Configuration);
    assert!(error.source().is_some());

    let unknown = api::rule(&api::Config::default(), "not-a-rule").unwrap_err();
    assert_eq!(unknown.kind(), api::ErrorKind::UnknownRule);
}

#[test]
fn config_and_baseline_can_be_reused_across_analyses() {
    let config = api::Config::default();
    let baseline = api::Baseline::unavailable();

    for filename in ["001.sql", "002.sql"] {
        api::analyze(&config, filename, "", &baseline).unwrap();
    }
}

#[test]
fn public_api_values_remain_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<api::Config>();
    assert_send_sync::<api::Baseline>();
    assert_send_sync::<api::AnalysisOutcome>();
    assert_send_sync::<api::Error>();
}

#[test]
fn unsafe_conservative_defaults_are_rejected_at_the_api_boundary() {
    let zero_rows = api::Config::default().with_default_rows(0);
    assert_eq!(
        zero_rows.validate().unwrap_err().kind(),
        api::ErrorKind::Configuration
    );

    let invalid_width = api::Config::default().with_toast_width_threshold_bytes(0);
    assert_eq!(
        invalid_width.validate().unwrap_err().kind(),
        api::ErrorKind::Configuration
    );
}
