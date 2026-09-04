mod common;

use safe_migrate::_internal::analysis::evidence::EvidenceCode;

#[test]
fn opaque_statement_outcome_has_typed_location_aware_evidence() {
    let engine = common::setup_engine();
    let mut state = common::setup_state();
    let outcome = engine
        .analyze_outcome_with_locations(
            "migrations/001.sql".to_string(),
            "DO $$ BEGIN NULL; END $$;".to_string(),
            &mut state,
        )
        .expect("DO block should parse");

    let evidence = outcome
        .evidence
        .iter()
        .find(|record| record.code == EvidenceCode::UnsupportedSemantics)
        .expect("opaque statement should retain unsupported-semantics evidence");
    assert_eq!(
        evidence
            .location
            .as_ref()
            .map(|location| location.file.as_str()),
        Some("migrations/001.sql")
    );
    assert_eq!(
        evidence
            .location
            .as_ref()
            .map(|location| location.statement_index),
        Some(1)
    );
}

#[test]
fn foreign_key_type_compatibility_gap_has_catalog_evidence_not_legacy_taint() {
    let engine = common::setup_engine();
    let mut state = common::setup_state();
    let outcome = engine
        .analyze_outcome_with_locations(
            "migrations/002.sql".to_string(),
            "CREATE TABLE parent(id integer PRIMARY KEY); \
             CREATE TABLE child(parent_id bigint); \
             ALTER TABLE child ADD CONSTRAINT child_parent_fk \
             FOREIGN KEY (parent_id) REFERENCES parent(id);"
                .to_string(),
            &mut state,
        )
        .expect("foreign-key migration should analyze conservatively");

    assert!(
        outcome
            .evidence
            .iter()
            .any(|record| record.code == EvidenceCode::CatalogCoverageIncomplete),
        "expected typed catalog evidence, got {:?}; findings: {:?}",
        outcome.evidence,
        outcome.findings
    );
}

#[test]
fn unknown_sequence_target_has_typed_object_state_evidence() {
    let engine = common::setup_engine();
    let mut state = safe_migrate::api::AnalysisState::with_baseline(
        safe_migrate::_internal::db::cache::DbCache::new(),
        false,
    );
    let outcome = engine
        .analyze_outcome_with_locations(
            "migrations/003.sql".to_string(),
            "DROP SEQUENCE IF EXISTS not_in_the_baseline;".to_string(),
            &mut state,
        )
        .expect("unknown sequence drop should analyze conservatively");

    assert!(
        outcome
            .evidence
            .iter()
            .any(|record| record.code == EvidenceCode::UnknownObjectState)
    );
}

#[test]
fn unavailable_rule_capability_is_recorded_before_rule_evaluation() {
    let engine = common::setup_engine();
    let mut state = safe_migrate::api::AnalysisState::with_baseline(
        safe_migrate::_internal::db::cache::DbCache::new(),
        false,
    );
    let outcome = engine
        .analyze_outcome_with_locations(
            "migrations/004.sql".to_string(),
            "CREATE TABLE accounts (id integer); CREATE INDEX idx ON accounts (id);".to_string(),
            &mut state,
        )
        .expect("index migration should analyze without a baseline");

    assert!(
        outcome
            .evidence
            .iter()
            .any(|record| record.code == EvidenceCode::BaselineUnavailable),
        "stateful rule capability gap must be explicit: {:?}",
        outcome.evidence
    );
}
