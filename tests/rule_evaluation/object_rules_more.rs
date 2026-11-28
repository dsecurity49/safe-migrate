use super::*;

#[test]
fn a_cross_category_implicit_cast_shadows_the_built_in_aggregate() {
    let engine = setup_engine();
    let mut state = setup_state();

    // `text -> regclass` is implicit even though the categories differ, so
    // `public.sum(regclass)` can take `sum(c)` and the call is not a
    // definite aggregate.
    let v = engine
            .analyze(
                "CREATE TABLE base_cross (a int, c text);
                 CREATE FUNCTION public.sum(regclass) RETURNS regclass LANGUAGE sql IMMUTABLE AS 'SELECT $1';
                 SET search_path = public, pg_catalog;
                 CREATE VIEW crossed AS SELECT a, sum(c) AS s FROM base_cross WITH CHECK OPTION;",
                &mut state,
            )
            .unwrap();

    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "a cross-category implicit cast must not be refused: {v:?}"
    );
    assert_eq!(state.local.confidence, Confidence::Tainted);
}

#[test]
fn only_a_matching_overload_shadows_a_built_in_aggregate() {
    let engine = setup_engine();
    let mut state = setup_state();

    // `public.sum(text)` is searched before `pg_catalog`, but `b` is `int`,
    // so the overload does not match and `sum(b)` is still the built-in
    // aggregate. An identical-signature overload does match, so there the
    // call is scalar and PostgreSQL accepts the view.
    let v = engine
            .analyze(
                "CREATE TABLE base_overload (a int, b int);
                 CREATE FUNCTION public.sum(text) RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT $1';
                 SET search_path = public, pg_catalog;
                 CREATE VIEW mismatched AS SELECT a, sum(b) AS s FROM base_overload WITH CHECK OPTION;
                 CREATE FUNCTION public.sum(int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT 1';
                 CREATE VIEW matched AS SELECT a, sum(b) AS s FROM base_overload WITH CHECK OPTION;",
                &mut state,
            )
            .unwrap();

    let reasons: Vec<&str> = v
        .iter()
        .filter(|v| v.rule_id == "chain-conflict")
        .map(|v| v.reason.as_str())
        .collect();
    assert_eq!(
        reasons.len(),
        1,
        "only the mismatched overload leaves the aggregate in place: {reasons:?}"
    );
    assert!(
        reasons[0].contains("aggregate functions"),
        "the conflict is the aggregate refusal: {reasons:?}"
    );

    let matched = state
        .get_relation(&object_id("public", "matched"))
        .expect("view must exist");
    assert!(
        matches!(matched, RelationOverlay::Present(r)
                if r.view_updatability == ViewUpdatability::Updatable),
        "the matching overload is scalar, so the view is updatable: {matched:?}"
    );
    let mismatched_view = object_id("public", "mismatched");
    assert!(
        state.get_relation(&mismatched_view).is_none(),
        "the rejected CREATE VIEW leaves no relation behind"
    );
}

#[test]
fn altering_a_view_check_option_requires_an_auto_updatable_query() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine
        .analyze(
            "CREATE TABLE base_ac (id int);
                 CREATE VIEW bad AS SELECT DISTINCT id FROM base_ac;
                 ALTER VIEW bad SET (security_barrier = true);
                 ALTER VIEW bad SET (check_option = cascaded);
                 CREATE VIEW good AS SELECT id FROM base_ac;
                 ALTER TABLE good SET (check_option = local);",
            &mut state,
        )
        .unwrap();

    let reasons: Vec<&str> = v
        .iter()
        .filter(|v| v.rule_id == "chain-conflict")
        .map(|v| v.reason.as_str())
        .collect();
    assert_eq!(
        reasons.len(),
        1,
        "only the check_option SET conflicts: {reasons:?}"
    );
    assert!(
        reasons[0].contains("automatically updatable views"),
        "the refusal names the check option: {reasons:?}"
    );
}

#[test]
fn an_unplaced_view_call_taints_rather_than_conflicting() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine
        .analyze(
            "CREATE TABLE base_call (x int);
                 CREATE VIEW maybe AS SELECT upper('x') FROM base_call WITH CHECK OPTION;",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "an unclassified call must not be claimed as a conflict: {v:?}"
    );
    assert_eq!(state.local.confidence, Confidence::Tainted);
}

#[test]
fn security_definer_is_not_a_view_reloption_on_any_version() {
    use crate::_internal::analysis::mutations::ReloptionTarget;
    use crate::_internal::analysis::state::PgVersion;
    use crate::_internal::model::reloption::{ReloptionNamespace, ReloptionOutcome, evaluate};

    // It is a routine attribute. PostgreSQL 15 added security_invoker
    // beside security_barrier rather than replacing anything.
    for version in [140_000, 150_000, 160_000, 170_000, 180_000] {
        assert_eq!(
            evaluate(
                "security_definer",
                ReloptionNamespace::Main,
                Some("true"),
                ReloptionTarget::View,
                PgVersion::Observed(version)
            ),
            ReloptionOutcome::Unrecognized {
                name: "security_definer".to_string()
            },
            "PG {version} must not accept security_definer"
        );
    }
}

#[test]
fn reloption_values_are_checked_against_their_domain() {
    use crate::_internal::analysis::mutations::ReloptionTarget;
    use crate::_internal::analysis::state::PgVersion;
    use crate::_internal::model::reloption::{
        ReloptionNamespace, ReloptionOutcome, evaluate, parses_as_bool,
    };

    let version = PgVersion::Observed(180_000);
    let view = ReloptionTarget::View;
    let bad = |name: &'static str, value: &str| {
        matches!(
            evaluate(name, ReloptionNamespace::Main, Some(value), view, version),
            ReloptionOutcome::BadValue { .. }
        )
    };
    // parse_bool takes a unique prefix, so these all hold.
    for value in ["true", "t", "tr", "yes", "y", "on", "1", "TRUE", "of"] {
        assert!(parses_as_bool(value), "{value} should parse as a bool");
    }
    // A bare `o` is ambiguous between on and off, which PostgreSQL
    // rejects, and a numeric spelling must be exactly `1` or `0`.
    for value in ["o", "maybe", "2", "01", "truex", ""] {
        assert!(!parses_as_bool(value), "{value} should not parse");
    }
    assert!(bad("security_barrier", "banana"));
    assert!(bad("security_barrier", "o"));
    // An enum is compared whole, never by prefix.
    assert!(bad("check_option", "casc"));
    assert!(bad("check_option", "banana"));
    assert!(!bad("check_option", "cascaded"));
    assert_eq!(
        evaluate(
            "check_option",
            ReloptionNamespace::Main,
            Some("LOCAL"),
            view,
            version
        ),
        ReloptionOutcome::Accepted
    );

    let heap = ReloptionTarget::MaterializedView;
    assert_eq!(
        evaluate(
            "fillfactor",
            ReloptionNamespace::Main,
            Some("100"),
            heap,
            version
        ),
        ReloptionOutcome::Accepted
    );
    assert!(matches!(
        evaluate(
            "fillfactor",
            ReloptionNamespace::Main,
            Some("5"),
            heap,
            version
        ),
        ReloptionOutcome::BadValue { .. }
    ));
    assert!(matches!(
        evaluate(
            "fillfactor",
            ReloptionNamespace::Main,
            Some("banana"),
            heap,
            version
        ),
        ReloptionOutcome::BadValue { .. }
    ));
}

#[test]
fn materialized_view_uses_the_heap_options_and_views_do_not() {
    use crate::_internal::analysis::mutations::ReloptionTarget;
    use crate::_internal::analysis::state::PgVersion;
    use crate::_internal::model::reloption::{ReloptionNamespace, ReloptionOutcome, evaluate};

    let version = PgVersion::Observed(180_000);
    assert_eq!(
        evaluate(
            "fillfactor",
            ReloptionNamespace::Main,
            Some("70"),
            ReloptionTarget::MaterializedView,
            version
        ),
        ReloptionOutcome::Accepted
    );
    assert_eq!(
        evaluate(
            "fillfactor",
            ReloptionNamespace::Main,
            Some("70"),
            ReloptionTarget::View,
            version
        ),
        ReloptionOutcome::Unrecognized {
            name: "fillfactor".to_string()
        },
        "a view has no storage, so it cannot set fillfactor"
    );
    for view_only in ["security_barrier", "check_option"] {
        assert_eq!(
            evaluate(
                view_only,
                ReloptionNamespace::Main,
                Some("true"),
                ReloptionTarget::MaterializedView,
                version
            ),
            ReloptionOutcome::Unrecognized {
                name: view_only.to_string()
            },
            "{view_only} is a view option and must not reach a materialized view"
        );
    }
}

#[test]
fn an_empty_option_value_is_not_an_absent_one() {
    let analyze = |sql: &str| {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
        cache.pg_version_num = Some(180_000);
        let mut state = AnalysisState::new(cache);
        state.baseline_available = true;
        engine.analyze(sql, &mut state).unwrap()
    };

    // A bare option reads as `true` and is accepted; an explicitly empty
    // value is a value the boolean domain refuses, shown without its quotes.
    let bare = analyze(
        "CREATE TABLE base (id int);
             ALTER TABLE base SET (autovacuum_enabled);",
    );
    assert!(
        !bare.iter().any(|v| v.rule_id == "chain-conflict"),
        "a bare option reads as true: {bare:?}"
    );

    let empty = analyze(
        "CREATE TABLE base (id int);
             ALTER TABLE base SET (autovacuum_enabled = '');",
    );
    let reasons: Vec<&str> = empty
        .iter()
        .filter(|v| v.rule_id == "chain-conflict")
        .map(|v| v.reason.as_str())
        .collect();
    assert_eq!(reasons.len(), 1, "the empty value is refused: {reasons:?}");
    assert!(
        reasons[0].contains("invalid value for parameter \"autovacuum_enabled\":")
            && !reasons[0].contains("''"),
        "the empty value is shown as empty, not as its quotes: {reasons:?}"
    );

    let reset = analyze(
        "CREATE TABLE base (id int);
             ALTER TABLE base RESET (fillfactor = '');",
    );
    assert!(
        reset
            .iter()
            .any(|v| v.reason.contains("RESET must not include values")),
        "a RESET carrying the empty value is refused: {reset:?}"
    );
}

#[test]
fn create_materialized_view_validates_the_toast_namespace() {
    let analyze = |sql: &str| {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
        cache.pg_version_num = Some(180_000);
        let mut state = AnalysisState::new(cache);
        state.baseline_available = true;
        engine.analyze(sql, &mut state).unwrap()
    };

    // The matview itself takes `fillfactor`, but its TOAST table does not.
    let rejected = analyze(
        "CREATE TABLE base (id int);
             CREATE MATERIALIZED VIEW mv WITH (toast.fillfactor = 70) AS SELECT id FROM base;",
    );
    assert!(
        rejected
            .iter()
            .any(|v| v.reason.contains("unrecognized parameter")),
        "a TOAST name the toast table does not take must be rejected: {rejected:?}"
    );

    let accepted = analyze(
            "CREATE TABLE base (id int);
             CREATE MATERIALIZED VIEW mv WITH (toast.autovacuum_enabled = false) AS SELECT id FROM base;",
        );
    assert!(
        !accepted
            .iter()
            .any(|v| v.reason.contains("unrecognized parameter")),
        "a real TOAST option must be accepted: {accepted:?}"
    );
}

#[test]
fn a_toast_option_on_a_view_is_ignored_like_postgresql() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    // A view has no storage, so PostgreSQL drops `toast.` options instead
    // of validating them.
    let v = engine
        .analyze(
            "CREATE TABLE base (id int);
                 CREATE VIEW v AS SELECT id FROM base;
                 ALTER VIEW v SET (toast.fillfactor = 70);",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "a view silently ignores toast options: {v:?}"
    );
    assert_eq!(state.local.confidence, Confidence::Exact);
}

#[test]
fn alter_materialized_view_toast_option_depends_on_the_toast_table() {
    let analyze = |has_toast: bool| {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
        cache.pg_version_num = Some(180_000);
        let mut mv = RelationState::new(
            object_id("public", "mv"),
            ObjectId::new("public", "postgres"),
            0,
            None,
            RelationKind::MaterializedView,
            Persistence::Permanent,
            0,
        );
        mv.has_toast_table = Some(has_toast);
        cache.insert_baseline(object_id("public", "mv"), mv);
        let mut state = AnalysisState::new(cache);
        state.baseline_available = true;
        engine
            .analyze(
                "ALTER MATERIALIZED VIEW mv SET (toast.fillfactor = 70);",
                &mut state,
            )
            .unwrap()
    };

    let with_toast = analyze(true);
    assert!(
        with_toast
            .iter()
            .any(|v| v.reason.contains("unrecognized parameter")),
        "a toast table rejects a name it does not take: {with_toast:?}"
    );
    let without_toast = analyze(false);
    assert!(
        !without_toast
            .iter()
            .any(|v| v.reason.contains("unrecognized parameter")),
        "no toast table means the option is dropped, not checked: {without_toast:?}"
    );
}

#[test]
fn a_set_option_without_a_value_means_true() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    // A boolean option takes the implied `true`; an integer option then
    // rejects it the way the server does.
    engine
        .analyze(
            "CREATE TABLE base_set (id int);
                 ALTER TABLE base_set SET (autovacuum_enabled);",
            &mut state,
        )
        .unwrap();
    let relation = state
        .get_relation(&object_id("public", "base_set"))
        .expect("table must exist");
    assert!(
        matches!(relation, RelationOverlay::Present(r)
                if r.table_options.get("autovacuum_enabled") == Some(&"true".to_string())),
        "a name alone means true: {relation:?}"
    );

    let v = engine
        .analyze("ALTER TABLE base_set SET (fillfactor);", &mut state)
        .unwrap();
    assert!(
        v.iter().any(|v| v
            .reason
            .contains("invalid value for parameter \"fillfactor\"")),
        "an implied true is not an integer: {v:?}"
    );
}

#[test]
fn a_reset_option_must_not_carry_a_value() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;
    engine
        .analyze(
            "CREATE TABLE base_reset (id int);
                 CREATE VIEW view_reset AS SELECT id FROM base_reset;",
            &mut state,
        )
        .unwrap();

    for sql in [
        "ALTER TABLE base_reset RESET (fillfactor = 70);",
        "ALTER TABLE base_reset ALTER COLUMN id RESET (n_distinct = 1);",
        "ALTER VIEW view_reset RESET (security_barrier = true);",
    ] {
        let v = engine.analyze(sql, &mut state).unwrap();
        assert!(
            v.iter()
                .any(|v| v.reason.contains("RESET must not include values")),
            "{sql} must be rejected: {v:?}"
        );
    }

    // A name alone, even one PostgreSQL does not know, is accepted.
    let v = engine
        .analyze("ALTER VIEW view_reset RESET (not_an_option);", &mut state)
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "RESET checks no name: {v:?}"
    );
}

#[test]
fn a_temporary_relation_is_exempt_from_requiring_concurrency() {
    let engine = setup_engine();
    let mut state = setup_state();
    let v = engine
        .analyze(
            "CREATE TEMP TABLE bookings (id int);
                 CREATE INDEX bookings_idx ON bookings(id);
                 REINDEX INDEX bookings_idx;
                 REINDEX TABLE bookings;",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter()
            .any(|violation| violation.rule_id == "require-concurrent-reindex"),
        "a temporary relation cannot be reindexed concurrently: {v:?}"
    );
}

#[test]
fn schema_drift_and_idempotency_cover_extensions_and_domains() {
    let engine = setup_engine();
    let mut state = setup_state();
    state.baseline_available = true;

    // Drop extension without IF EXISTS when missing -> drift and idempotency
    let findings = engine
        .analyze("DROP EXTENSION uninstalled;", &mut state)
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "schema-drift" && f.object_name == "uninstalled")
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "missing-idempotency" && f.object_name == "uninstalled")
    );

    // Create extension without IF NOT EXISTS -> idempotency
    let findings = engine
        .analyze("CREATE EXTENSION hstore;", &mut state)
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "missing-idempotency" && f.object_name == "hstore")
    );

    // Alter missing extension -> schema drift
    let findings = engine
        .analyze(
            "ALTER EXTENSION missing_ext SET SCHEMA new_schema;",
            &mut state,
        )
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "schema-drift" && f.object_name == "missing_ext")
    );

    // Alter missing domain -> schema drift
    let findings = engine
        .analyze(
            "ALTER DOMAIN public.missing_domain DROP NOT NULL;",
            &mut state,
        )
        .unwrap();
    assert!(findings.iter().any(|f| f.rule_id == "schema-drift"));

    // Drop extension CASCADE -> destructive-general-cascade
    let findings = engine
        .analyze("DROP EXTENSION IF EXISTS hstore CASCADE;", &mut state)
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "destructive-general-cascade")
    );
}
