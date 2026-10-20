use super::*;

#[test]
fn test_rule_size_aware_toast_escalation() {
    let engine = setup_engine();

    let mut cache = crate::common::synced_cache();

    let tid = object_id("public", "t_toast");

    let mut rel = RelationState::new(
        tid.clone(),
        ObjectId::new("public", "postgres"),
        0,
        Some(50_000),
        RelationKind::Table,
        Persistence::Permanent,
        0,
    );

    rel.columns.push(Column {
        name: "data".into(),
        data_type: Some("text".into()),
        type_id: None,
        is_nullable: true,
        default: None,
        avg_width: Some(3000),
        default_expr_text: None,
        type_modifier: None,
        storage: None,
        compression: None,
        statistics_target: None,
        options: Default::default(),
        generated: None,
    });

    cache.insert_baseline(tid, rel);

    let mut state = AnalysisState::new(cache);

    let violations = engine
        .analyze(
            "
                ALTER TABLE t_toast
                ADD COLUMN c INT DEFAULT random();
                ",
            &mut state,
        )
        .unwrap();

    assert!(violations.iter().any(|v| v.rule_id.contains("size")
        || v.rule_id.contains("rewrite")
        || v.rule_id.contains("toast")));
}

#[test]
fn test_rule_blocking_constraint_check_and_not_valid_fast_path() {
    let engine = setup_engine();

    let mut cache = crate::common::synced_cache();

    cache.insert_baseline(
        object_id("public", "t"),
        RelationState::new(
            object_id("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            Some(500_000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );

    let mut state = AnalysisState::new(cache);

    let v1 = engine
        .analyze(
            "
                ALTER TABLE t
                ADD CONSTRAINT c CHECK (id > 0);
                ",
            &mut state,
        )
        .unwrap();

    assert!(v1.iter().any(|v| v.rule_id.contains("constraint")));

    let v2 = engine
        .analyze(
            "
                ALTER TABLE t
                ADD CONSTRAINT c2 CHECK (id > 0) NOT VALID;
                ",
            &mut state,
        )
        .unwrap();

    assert!(!v2.iter().any(|v| v.rule_id == "blocking-constraint"));
}

#[test]
fn test_rule_blocking_constraint_pk_and_unique() {
    let engine = setup_engine();

    let mut cache = crate::common::synced_cache();

    cache.insert_baseline(
        object_id("public", "t"),
        RelationState::new(
            object_id("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            Some(500_000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );

    let mut state = AnalysisState::new(cache);

    let v1 = engine
        .analyze("ALTER TABLE t ADD PRIMARY KEY (id);", &mut state)
        .unwrap();

    assert!(
        v1.iter()
            .any(|v| v.rule_id.contains("constraint") || v.rule_id.contains("index"))
    );

    let v2 = engine
        .analyze("ALTER TABLE t ADD UNIQUE (id);", &mut state)
        .unwrap();

    assert!(
        v2.iter()
            .any(|v| v.rule_id.contains("constraint") || v.rule_id.contains("index"))
    );
}

#[test]
fn test_rule_partition_attach_detach() {
    let engine = setup_engine();

    let mut cache = crate::common::synced_cache();

    cache.insert_baseline(
        object_id("public", "p"),
        RelationState::new(
            object_id("public", "p"),
            ObjectId::new("public", "postgres"),
            0,
            Some(500_000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );

    let mut state = AnalysisState::new(cache);

    engine
        .analyze("CREATE TABLE c(id int);", &mut state)
        .unwrap();

    let v1 = engine
        .analyze(
            "
                ALTER TABLE p
                ATTACH PARTITION c
                FOR VALUES IN (1);
                ",
            &mut state,
        )
        .unwrap();

    assert!(v1.iter().any(|v| v.rule_id.contains("partition")));

    let v2 = engine
        .analyze(
            "
                ALTER TABLE p
                DETACH PARTITION c;
                ",
            &mut state,
        )
        .unwrap();

    assert!(v2.iter().any(|v| v.rule_id.contains("partition")));
}

#[test]
fn test_rule_volatile_default_create() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine
        .analyze(
            "
                CREATE TABLE t(
                    id int DEFAULT random()
                );
                ",
            &mut state,
        )
        .unwrap();

    assert!(
        v.iter()
            .any(|v| v.rule_id.contains("volatile") || v.rule_id.contains("default"))
    );
}

#[test]
fn test_rule_volatile_default_alter() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    let tid = object_id("public", "t");
    let rel = RelationState::new(
        tid.clone(),
        object_id("public", "postgres"),
        0,
        Some(10),
        safe_migrate::_internal::model::relation::RelationKind::Table,
        safe_migrate::_internal::model::relation::Persistence::Permanent,
        0,
    );
    cache.insert_baseline(tid, rel);
    let mut state = AnalysisState::new(cache);

    // test ADD COLUMN
    let v = engine
        .analyze(
            "ALTER TABLE t ADD COLUMN new_col int DEFAULT random();",
            &mut state,
        )
        .unwrap();
    assert!(v.iter().any(|v| v.rule_id == "volatile-default"));

    // test SET DEFAULT
    let v2 = engine
        .analyze(
            "ALTER TABLE t ALTER COLUMN new_col SET DEFAULT random();",
            &mut state,
        )
        .unwrap();
    assert!(v2.iter().any(|v| v.rule_id == "volatile-default"));

    let v3 = engine
            .analyze(
                "ALTER TABLE t ADD COLUMN nested_default double precision DEFAULT coalesce(random(), 0);",
                &mut state,
            )
            .unwrap();
    assert!(v3.iter().any(|v| v.rule_id == "volatile-default"));
}

#[test]
fn test_rule_concurrent_index() {
    let engine = setup_engine();
    let mut state = setup_state();

    // 1. Setup table
    engine
        .analyze("CREATE TABLE t(id int);", &mut state)
        .unwrap();

    // 2. Force the table to be "massive" and originate from an old transaction
    // to bypass the same-transaction exemption logic we introduced.
    if let Some(safe_migrate::_internal::model::relation::RelationOverlay::Present(rel)) =
        state.local.relations.get_mut(&object_id("public", "t"))
    {
        rel.estimated_rows = Some(500_000);
        rel.created_at_tx_depth = 999;
    }

    // 3. Evaluate synchronous lock escalation
    let v1 = engine
        .analyze("CREATE INDEX i ON t(id);", &mut state)
        .unwrap();

    assert!(
        v1.iter()
            .any(|v| v.rule_id.contains("concurrent") || v.rule_id.contains("index"))
    );

    // 4. Evaluate safe concurrent creation
    let v2 = engine
        .analyze("CREATE INDEX CONCURRENTLY i2 ON t(id);", &mut state)
        .unwrap();

    assert!(!v2.iter().any(|v| v.rule_id == "require-concurrent-index"));
}

#[test]
fn test_rule_concurrent_index_outside_transaction() {
    let engine = setup_engine();
    let mut state = setup_state();

    state.baseline_relations.insert(object_id("public", "t"));
    state.local.relations.insert(
        object_id("public", "t"),
        safe_migrate::_internal::model::relation::RelationOverlay::Present(
            safe_migrate::_internal::model::relation::RelationState::new(
                object_id("public", "t"),
                object_id("public", "postgres"),
                0,
                Some(500_000),
                safe_migrate::_internal::model::relation::RelationKind::Table,
                safe_migrate::_internal::model::relation::Persistence::Permanent,
                0,
            ),
        ),
    );

    let v1 = engine
        .analyze("CREATE INDEX i ON t(id);", &mut state)
        .unwrap();

    assert!(v1.iter().any(|v| v.rule_id == "require-concurrent-index"));
}

#[test]
fn test_rule_concurrent_drop_index() {
    let mut config = Config::default();
    config.rules.insert(
        "require-concurrent-index".to_string(),
        RuleConfig {
            tier1_threshold_rows: Some(1_000_000),
            tier2_threshold_rows: Some(800_000),
            ..RuleConfig::default()
        },
    );
    let engine = SafeMigrateEngine::new(config);

    let mut cache = crate::common::synced_cache();
    cache.insert_baseline(
        object_id("public", "t"),
        safe_migrate::_internal::model::relation::RelationState::new(
            object_id("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            Some(500_000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );

    let mut state = AnalysisState::new(cache);

    engine
        .analyze("CREATE INDEX i ON t(id);", &mut state)
        .unwrap();

    let v = engine.analyze("DROP INDEX i;", &mut state).unwrap();

    let finding = v
        .iter()
        .find(|v| v.rule_id == "require-concurrent-drop-index")
        .expect("non-concurrent DROP INDEX should be flagged");
    assert_eq!(finding.tier, ViolationTier::Tier3);
}

#[test]
fn test_rule_concurrent_drop_index_small() {
    let engine = setup_engine();

    let mut cache = crate::common::synced_cache();
    cache.insert_baseline(
        object_id("public", "t"),
        safe_migrate::_internal::model::relation::RelationState::new(
            object_id("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            Some(100),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );

    let mut state = AnalysisState::new(cache);

    engine
        .analyze("CREATE INDEX i ON t(id);", &mut state)
        .unwrap();

    let v = engine.analyze("DROP INDEX i;", &mut state).unwrap();

    assert!(
        v.iter()
            .any(|v| v.rule_id == "require-concurrent-drop-index"),
        "Small table DROP INDEX should still be flagged at Tier3 or not at all"
    );
}

#[test]
fn an_unresolvable_create_index_records_the_concurrent_index_rule_as_unevaluated() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.metadata.schemas = Some(vec!["app".to_string()]);
    let mut state = AnalysisState::new(cache);

    let violations = engine
        .analyze("CREATE INDEX i ON public.secret_table (id);", &mut state)
        .unwrap();

    assert!(
        !violations
            .iter()
            .any(|v| v.rule_id == "require-concurrent-index"),
        "the lock a synchronous index takes cannot be sized without the relation"
    );
    assert!(
        state
            .not_evaluated()
            .iter()
            .any(|entry| entry.rule_id == "require-concurrent-index"),
        "a declined Tier1 check must be recorded so the verdict cannot stay SAFE"
    );
}

#[test]
fn reindex_of_an_exclusion_backing_index_is_not_flagged() {
    // PostgreSQL raises an error if an exclusion-constraint index is named
    // directly in a concurrent REINDEX, so the synchronous form is required.
    let engine = setup_engine();
    let mut state = setup_state();
    let sql = "
            CREATE TABLE bookings (
                room int, during tsrange,
                CONSTRAINT bookings_no_overlap EXCLUDE USING gist (room WITH =, during WITH &&));
            REINDEX INDEX bookings_no_overlap;
        ";
    let v = engine.analyze(sql, &mut state).unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "require-concurrent-reindex"
            && v.object_name.contains("bookings_no_overlap")),
        "an exclusion backing index must not demand CONCURRENTLY: {v:?}"
    );
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "the backing index must exist in the simulated state: {v:?}"
    );
}

#[test]
fn exclude_constraint_recipe_does_not_recommend_using_index() {
    let engine = setup_engine();
    let cache = cache_with_table("public", "bookings", Some(500_000));
    let mut state = AnalysisState::new(cache);
    let v = engine
        .analyze(
            "ALTER TABLE bookings ADD EXCLUDE USING gist (room WITH =, during WITH &&);",
            &mut state,
        )
        .unwrap();
    let finding = v
        .iter()
        .find(|v| v.rule_id == "blocking-index-constraint")
        .expect("adding an exclusion constraint should be reported");
    // PostgreSQL rejects EXCLUDE ... USING INDEX outright.
    assert!(
        !finding.recipe.contains("add the constraint USING INDEX"),
        "must not recommend a form PostgreSQL rejects: {}",
        finding.recipe
    );
}

#[test]
fn unique_constraint_recipe_still_recommends_using_index() {
    let engine = setup_engine();
    let cache = cache_with_table("public", "bookings", Some(500_000));
    let mut state = AnalysisState::new(cache);
    let v = engine
        .analyze("ALTER TABLE bookings ADD UNIQUE (room);", &mut state)
        .unwrap();
    let finding = v
        .iter()
        .find(|v| v.rule_id == "blocking-index-constraint")
        .expect("adding a unique constraint should be reported");
    assert!(
        finding.recipe.contains("USING INDEX"),
        "USING INDEX is valid for UNIQUE: {}",
        finding.recipe
    );
}

#[test]
fn version_dependent_reloption_without_a_baseline_does_not_conflict() {
    let engine = setup_engine();
    let mut state = setup_state();
    let v = engine
        .analyze(
            "CREATE TABLE base_v (id int);
                 CREATE VIEW v AS SELECT id FROM base_v;
                 ALTER VIEW v SET (security_invoker = true);",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter()
            .any(|v| v.reason.contains("unrecognized parameter")),
        "an unknown version cannot justify rejecting a name: {v:?}"
    );
}

#[test]
fn a_reloption_added_in_a_later_release_is_rejected_before_it() {
    use crate::_internal::analysis::mutations::ReloptionTarget;
    use crate::_internal::analysis::state::PgVersion;
    use crate::_internal::model::reloption::{ReloptionNamespace, ReloptionOutcome, evaluate};

    let target = ReloptionTarget::View;
    assert_eq!(
        evaluate(
            "security_invoker",
            ReloptionNamespace::Main,
            Some("true"),
            target,
            PgVersion::Observed(140_000)
        ),
        ReloptionOutcome::Unrecognized {
            name: "security_invoker".to_string()
        }
    );
    assert_eq!(
        evaluate(
            "security_invoker",
            ReloptionNamespace::Main,
            Some("true"),
            target,
            PgVersion::Observed(150_000)
        ),
        ReloptionOutcome::Accepted
    );
}

#[test]
fn vacuum_index_cleanup_accepts_the_boolean_spellings() {
    use crate::_internal::analysis::mutations::ReloptionTarget;
    use crate::_internal::analysis::state::PgVersion;
    use crate::_internal::model::reloption::{ReloptionNamespace, ReloptionOutcome, evaluate};

    // Verified live on PostgreSQL 18.6: `vacuum_index_cleanup` is an enum
    // option, and an enum option also accepts `parse_bool` spellings.
    let heap = ReloptionTarget::MaterializedView;
    let version = PgVersion::Observed(180_000);
    for value in [
        "auto", "on", "off", "true", "false", "yes", "no", "1", "0", "AUTO",
    ] {
        assert_eq!(
            evaluate(
                "vacuum_index_cleanup",
                ReloptionNamespace::Main,
                Some(value),
                heap,
                version
            ),
            ReloptionOutcome::Accepted,
            "{value}"
        );
    }
    // PostgreSQL lists only on/off/auto, and rejects anything else.
    for value in ["bogus", "2", "always"] {
        assert!(
            matches!(
                evaluate(
                    "vacuum_index_cleanup",
                    ReloptionNamespace::Main,
                    Some(value),
                    heap,
                    version
                ),
                ReloptionOutcome::BadValue { .. }
            ),
            "{value} must be rejected"
        );
    }
}

#[test]
fn toast_reloptions_depend_on_the_namespace_and_the_toast_table() {
    use crate::_internal::analysis::mutations::ReloptionTarget;
    use crate::_internal::analysis::state::PgVersion;
    use crate::_internal::model::reloption::{
        ReloptionNamespace, ReloptionOutcome, ToastOptions, evaluate,
    };

    let version = PgVersion::Observed(180_000);
    let matview = ReloptionTarget::MaterializedView;
    let toast = ReloptionNamespace::Toast;
    // `autovacuum_enabled` is one of the options the TOAST table takes;
    // `fillfactor` and `autovacuum_analyze_threshold` are heap options it
    // does not, which is why a matview accepts them but its toast table
    // cannot.
    assert_eq!(
        evaluate(
            "autovacuum_enabled",
            toast(ToastOptions::Validated),
            Some("false"),
            matview,
            version
        ),
        ReloptionOutcome::Accepted
    );
    for name in ["fillfactor", "autovacuum_analyze_threshold"] {
        assert_eq!(
            evaluate(
                name,
                toast(ToastOptions::Validated),
                Some("70"),
                matview,
                version
            ),
            ReloptionOutcome::Unrecognized {
                name: name.to_string()
            },
            "{name} is not a TOAST option"
        );
    }
    // Without a TOAST table PostgreSQL drops the option without parsing it,
    // so even an out-of-set or ill-formed value is accepted.
    for name in ["autovacuum_enabled", "fillfactor", "not_a_thing"] {
        assert_eq!(
            evaluate(
                name,
                toast(ToastOptions::Ignored),
                Some("banana"),
                matview,
                version
            ),
            ReloptionOutcome::Accepted
        );
    }
    // When presence is unknown only a cleanly valid option is certain.
    assert_eq!(
        evaluate(
            "autovacuum_enabled",
            toast(ToastOptions::Unknown),
            Some("false"),
            matview,
            version
        ),
        ReloptionOutcome::Accepted
    );
    assert_eq!(
        evaluate(
            "fillfactor",
            toast(ToastOptions::Unknown),
            Some("70"),
            matview,
            version
        ),
        ReloptionOutcome::Unplaced
    );
}

#[test]
fn a_toast_option_is_not_stored_on_the_relation() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    // A `toast.` option configures the TOAST relation, so PostgreSQL keeps
    // it out of the relation's own `reloptions` for every relation kind.
    engine
            .analyze(
                "CREATE TABLE base (id int);
                 CREATE VIEW v WITH (toast.autovacuum_enabled = false) AS SELECT id FROM base;
                 ALTER VIEW v SET (toast.fillfactor = 70, security_barrier = true);
                 CREATE MATERIALIZED VIEW mv WITH (fillfactor = 70, toast.autovacuum_enabled = false) AS SELECT id FROM base;
                 ALTER TABLE base SET (fillfactor = 70, toast.autovacuum_enabled = false);",
                &mut state,
            )
            .unwrap();

    for (name, main, value) in [
        ("v", "security_barrier", "true"),
        ("mv", "fillfactor", "70"),
        ("base", "fillfactor", "70"),
    ] {
        let relation = state
            .get_relation(&object_id("public", name))
            .unwrap_or_else(|| panic!("{name} must exist"));
        assert!(
            matches!(relation, RelationOverlay::Present(r)
                    if r.table_options.get(main) == Some(&value.to_string())
                        && !r.table_options.keys().any(|key| key.starts_with("toast."))),
            "{name} must keep {main} and drop every toast. option: {relation:?}"
        );
    }
}

#[test]
fn an_unknown_reloption_namespace_is_a_conflict() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    let v = engine
        .analyze(
            "CREATE TABLE base (id int);
                 CREATE VIEW v AS SELECT id FROM base;
                 ALTER VIEW v SET (foo.bar = 1);",
            &mut state,
        )
        .unwrap();
    assert!(
        v.iter()
            .any(|v| v.reason.contains("unrecognized parameter namespace")),
        "only the toast namespace exists: {v:?}"
    );
}

#[test]
fn repeated_toast_options_are_rejected_within_their_namespace() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    let duplicate = engine
            .analyze(
                "CREATE TABLE base (id int);
                 CREATE MATERIALIZED VIEW mv WITH (toast.autovacuum_enabled = true, toast.autovacuum_enabled = false) AS SELECT id FROM base;",
                &mut state,
            )
            .unwrap();
    assert!(
        duplicate
            .iter()
            .any(|v| v.reason.contains("specified more than once")),
        "a repeated option within one namespace is a conflict: {duplicate:?}"
    );

    // The same bare name in two namespaces is not a repetition.
    let distinct = engine
            .analyze(
                "CREATE TABLE base2 (id int);
                 CREATE MATERIALIZED VIEW mv2 WITH (autovacuum_enabled = true, toast.autovacuum_enabled = false) AS SELECT id FROM base2;",
                &mut state,
            )
            .unwrap();
    assert!(
        !distinct
            .iter()
            .any(|v| v.reason.contains("specified more than once")),
        "different namespaces are different parameters: {distinct:?}"
    );
}

#[test]
fn resetting_a_toast_option_leaves_the_main_option() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE TABLE base (id int);
                 CREATE MATERIALIZED VIEW mv WITH (fillfactor = 70, toast.autovacuum_enabled = false) AS SELECT id FROM base;
                 ALTER MATERIALIZED VIEW mv RESET (toast.autovacuum_enabled);",
                &mut state,
            )
            .unwrap();

    let relation = state
        .get_relation(&object_id("public", "mv"))
        .expect("matview must exist");
    assert!(
        matches!(relation, RelationOverlay::Present(r)
                if r.table_options.get("fillfactor") == Some(&"70".to_string())
                    && !r.table_options.contains_key("toast.autovacuum_enabled")),
        "RESET must only clear the namespaced option: {relation:?}"
    );
}

#[test]
fn alter_table_set_options_validate_against_the_table_option_set() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    // The view-only option is not a heap option, so the table rejects it;
    // the heap option is stored and the statement is exact.
    let v = engine
        .analyze(
            "CREATE TABLE base (id int);
                 ALTER TABLE base SET (security_barrier = true);",
            &mut state,
        )
        .unwrap();
    assert!(
        v.iter().any(|v| v
            .reason
            .contains("unrecognized parameter \"security_barrier\"")),
        "a table must reject a view-only option: {v:?}"
    );

    engine
        .analyze(
            "CREATE TABLE base2 (id int);
                 ALTER TABLE base2 SET (fillfactor = 70);",
            &mut state,
        )
        .unwrap();
    let relation = state
        .get_relation(&object_id("public", "base2"))
        .expect("table must exist");
    assert!(
        matches!(relation, RelationOverlay::Present(r)
                if r.table_options.get("fillfactor") == Some(&"70".to_string())),
        "a heap option must be stored: {relation:?}"
    );
}

#[test]
fn alter_table_set_options_reject_storage_parameters_on_a_partitioned_table() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    let v = engine
        .analyze(
            "CREATE TABLE part (id int) PARTITION BY RANGE (id);
                 ALTER TABLE part SET (fillfactor = 70);",
            &mut state,
        )
        .unwrap();
    assert!(
        v.iter()
            .any(|v| v.reason.contains("cannot specify storage parameters")),
        "a partitioned table takes no storage parameter: {v:?}"
    );

    // A toast option is dropped, and an unknown namespace is still rejected
    // before the storage-parameter rule.
    let accepted = engine
        .analyze(
            "CREATE TABLE part2 (id int) PARTITION BY RANGE (id);
                 ALTER TABLE part2 SET (toast.autovacuum_enabled = false);",
            &mut state,
        )
        .unwrap();
    assert!(
        !accepted
            .iter()
            .any(|v| v.reason.contains("storage parameters")),
        "a partitioned table silently drops toast options: {accepted:?}"
    );
    let namespace = engine
        .analyze("ALTER TABLE part2 SET (foo.bar = 1);", &mut state)
        .unwrap();
    assert!(
        namespace
            .iter()
            .any(|v| v.reason.contains("unrecognized parameter namespace")),
        "the namespace is checked before the kind: {namespace:?}"
    );
}

#[test]
fn alter_table_toast_option_depends_on_the_toast_table() {
    let analyze = |has_toast: bool| {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
        cache.pg_version_num = Some(180_000);
        let mut table = RelationState::new(
            object_id("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            None,
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        table.has_toast_table = Some(has_toast);
        cache.insert_baseline(object_id("public", "t"), table);
        let mut state = AnalysisState::new(cache);
        state.baseline_available = true;
        engine
            .analyze("ALTER TABLE t SET (toast.fillfactor = 70);", &mut state)
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
fn repeated_toast_options_are_not_checked_without_a_toast_table() {
    let analyze = |has_toast: bool| {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
        cache.pg_version_num = Some(180_000);
        let mut table = RelationState::new(
            object_id("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            None,
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        table.has_toast_table = Some(has_toast);
        cache.insert_baseline(object_id("public", "t"), table);
        let mut state = AnalysisState::new(cache);
        state.baseline_available = true;
        engine
                .analyze(
                    "ALTER TABLE t SET (toast.autovacuum_enabled = true, toast.autovacuum_enabled = false);",
                    &mut state,
                )
                .unwrap()
    };

    // A repeated name is only parsed into an option array when the toast
    // table exists; otherwise PostgreSQL drops the whole set.
    assert!(
        analyze(true)
            .iter()
            .any(|v| v.reason.contains("specified more than once")),
        "a toast table parses the set and repeats are rejected"
    );
    assert!(
        !analyze(false)
            .iter()
            .any(|v| v.reason.contains("specified more than once")),
        "no toast table means the repeated set is never parsed"
    );
}

#[test]
fn alter_table_reloptions_are_refused_on_a_foreign_table() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let foreign = RelationState::new(
        object_id("public", "ft"),
        ObjectId::new("public", "postgres"),
        0,
        None,
        RelationKind::ForeignTable,
        Persistence::Permanent,
        0,
    );
    cache.insert_baseline(object_id("public", "ft"), foreign);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    let set = engine
        .analyze("ALTER TABLE ft SET (fillfactor = 70);", &mut state)
        .unwrap();
    assert!(
        set.iter()
            .any(|v| v.reason.contains("ALTER action cannot be performed")),
        "a foreign table cannot take SET options: {set:?}"
    );
    let reset = engine
        .analyze("ALTER TABLE ft RESET (fillfactor);", &mut state)
        .unwrap();
    assert!(
        reset
            .iter()
            .any(|v| v.reason.contains("ALTER action cannot be performed")),
        "a foreign table cannot take RESET options: {reset:?}"
    );
}

#[test]
fn alter_table_reloptions_follow_the_target_relation_kind() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    // `ALTER TABLE` is overloaded for a view, and its options come from the
    // view set rather than the heap set.
    let v = engine
        .analyze(
            "CREATE TABLE base_target (id int);
                 CREATE VIEW target_view AS SELECT id FROM base_target;
                 ALTER TABLE target_view SET (security_barrier = true);",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "a view accepts the actions its relkind admits: {v:?}"
    );
    let view = state
        .get_relation(&object_id("public", "target_view"))
        .expect("view must exist");
    assert!(
        matches!(view, RelationOverlay::Present(r)
                if r.table_options.get("security_barrier") == Some(&"true".to_string())),
        "the view option must be stored: {view:?}"
    );

    let v = engine
        .analyze("ALTER TABLE target_view ADD COLUMN extra int;", &mut state)
        .unwrap();
    assert!(
        v.iter()
            .any(|v| v.reason.contains("ALTER action cannot be performed")),
        "a view cannot gain a column: {v:?}"
    );

    let v = engine
        .analyze(
            "ALTER TABLE target_view RENAME COLUMN id TO renamed;",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "a view column can be renamed: {v:?}"
    );

    let v = engine
        .analyze(
            "ALTER TABLE target_view ALTER COLUMN renamed SET STATISTICS 100;",
            &mut state,
        )
        .unwrap();
    assert!(
        v.iter()
            .any(|v| v.reason.contains("ALTER action cannot be performed")),
        "a view column cannot take statistics: {v:?}"
    );

    // A materialized view takes the heap set.
    engine
        .analyze(
            "CREATE MATERIALIZED VIEW target_mat AS SELECT id FROM base_target;
                 ALTER TABLE target_mat SET (fillfactor = 70);",
            &mut state,
        )
        .unwrap();
    let mat = state
        .get_relation(&object_id("public", "target_mat"))
        .expect("materialized view must exist");
    assert!(
        matches!(mat, RelationOverlay::Present(r)
                if r.table_options.get("fillfactor") == Some(&"70".to_string())),
        "a materialized view stores a heap option: {mat:?}"
    );
}

#[test]
fn alter_table_reloptions_read_the_value_as_the_server_does() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    // An option name folds like any identifier and a string literal is the
    // value it spells, so these are the statements PostgreSQL accepts.
    let v = engine
        .analyze(
            "CREATE TABLE opt_target (id int);
                 ALTER TABLE opt_target SET (FILLFACTOR = 70, autovacuum_enabled = 'on');",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "a folded name and a quoted value are valid: {v:?}"
    );
    let relation = state
        .get_relation(&object_id("public", "opt_target"))
        .expect("table must exist");
    assert!(
        matches!(relation, RelationOverlay::Present(r)
                if r.table_options.get("fillfactor") == Some(&"70".to_string())
                    && r.table_options.get("autovacuum_enabled") == Some(&"on".to_string())),
        "the options must be stored under their folded names: {relation:?}"
    );

    // `RESET` refuses an option that carries a value, empty or not.
    let v = engine
        .analyze(
            "ALTER TABLE opt_target RESET (fillfactor = '');",
            &mut state,
        )
        .unwrap();
    assert!(
        v.iter()
            .any(|v| v.rule_id == "chain-conflict" && v.reason.contains("must not include values")),
        "a RESET carrying a value is refused: {v:?}"
    );
}

#[test]
fn alter_table_permissions_distinguish_partitioned_tables() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    let v = engine
            .analyze(
                "CREATE TABLE plain_attach (id int);
                 CREATE TABLE partitioned_child (id int) PARTITION BY RANGE (id);
                 ALTER TABLE plain_attach ATTACH PARTITION partitioned_child FOR VALUES FROM (1) TO (2);",
                &mut state,
            )
            .unwrap();
    assert!(
        v.iter()
            .any(|v| v.reason.contains("ALTER action cannot be performed")),
        "only a partitioned table can attach a partition: {v:?}"
    );

    let v = engine
        .analyze(
            "CREATE TABLE partitioned_persist (id int) PARTITION BY RANGE (id);
                 ALTER TABLE partitioned_persist SET UNLOGGED;",
            &mut state,
        )
        .unwrap();
    assert!(
        v.iter()
            .any(|v| v.reason.contains("ALTER action cannot be performed")),
        "a partitioned table cannot change persistence: {v:?}"
    );
}

#[test]
fn column_options_use_the_attribute_option_set() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;
    engine
        .analyze("CREATE TABLE base_col (id int);", &mut state)
        .unwrap();

    let accepted = engine
            .analyze(
                "ALTER TABLE base_col ALTER COLUMN id SET (n_distinct = 100, n_distinct_inherited = -1);",
                &mut state,
            )
            .unwrap();
    assert!(
        !accepted.iter().any(|v| v.rule_id == "chain-conflict"),
        "valid attribute options: {accepted:?}"
    );

    for (sql, message) in [
        (
            "ALTER TABLE base_col ALTER COLUMN id SET (n_distinct = -2);",
            "invalid value for parameter \"n_distinct\"",
        ),
        (
            "ALTER TABLE base_col ALTER COLUMN id SET (fillfactor = 70);",
            "unrecognized parameter \"fillfactor\"",
        ),
        (
            "ALTER TABLE base_col ALTER COLUMN id SET (toast.n_distinct = 1);",
            "unrecognized parameter namespace \"toast\"",
        ),
        (
            "ALTER TABLE base_col ALTER COLUMN id SET (n_distinct = 1, n_distinct = 2);",
            "specified more than once",
        ),
    ] {
        let v = engine.analyze(sql, &mut state).unwrap();
        assert!(
            v.iter().any(|v| v.reason.contains(message)),
            "{sql} must be rejected: {v:?}"
        );
    }
}

#[test]
fn index_options_follow_the_access_method() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;
    engine
        .analyze(
            "CREATE TABLE base_idx (id int, arr int[], r int4range);
                 CREATE INDEX idx_btree ON base_idx (id);
                 CREATE INDEX idx_hash ON base_idx USING hash (id);
                 CREATE INDEX idx_gin ON base_idx USING gin (arr);
                 CREATE INDEX idx_gist ON base_idx USING gist (r);
                 CREATE INDEX idx_brin ON base_idx USING brin (id);",
            &mut state,
        )
        .unwrap();

    let accepted = engine
        .analyze(
            "ALTER INDEX idx_btree SET (fillfactor = 70);
                 ALTER INDEX idx_hash SET (fillfactor = 70);
                 ALTER INDEX idx_gin SET (fastupdate = off);
                 ALTER INDEX idx_gist SET (buffering = on);
                 ALTER INDEX idx_brin SET (pages_per_range = 32);",
            &mut state,
        )
        .unwrap();
    assert!(
        !accepted.iter().any(|v| v.rule_id == "chain-conflict"),
        "each method takes its own options: {accepted:?}"
    );

    for (sql, message) in [
        (
            "ALTER INDEX idx_btree SET (fastupdate = on);",
            "unrecognized parameter \"fastupdate\"",
        ),
        (
            "ALTER INDEX idx_gin SET (fillfactor = 70);",
            "unrecognized parameter \"fillfactor\"",
        ),
        (
            "ALTER INDEX idx_brin SET (autosummarize = on, autosummarize = off);",
            "specified more than once",
        ),
        (
            "ALTER INDEX idx_btree RESET (fillfactor = 70);",
            "RESET must not include values",
        ),
    ] {
        let v = engine.analyze(sql, &mut state).unwrap();
        assert!(
            v.iter().any(|v| v.reason.contains(message)),
            "{sql} must be rejected: {v:?}"
        );
    }
}

#[test]
fn a_repeated_reloption_is_rejected() {
    let engine = setup_engine();
    let mut state = setup_state();
    let v = engine
        .analyze(
            "CREATE TABLE base_v (id int);
                 CREATE VIEW v AS SELECT id FROM base_v;
                 ALTER VIEW v SET (security_barrier = true, security_barrier = false);",
            &mut state,
        )
        .unwrap();
    assert!(
        v.iter()
            .any(|violation| violation.reason.contains("specified more than once")),
        "a repeated option must be rejected: {v:?}"
    );
}

#[test]
fn reindex_follows_postgresql_legality() {
    let engine = setup_engine();
    let reason = |sql: &str| {
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .expect("the statement should analyze")
            .into_iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason)
            .next()
            .unwrap_or_default()
    };

    // System catalogs have no concurrent reindex form at any scope.
    assert_eq!(
        reason("REINDEX SYSTEM CONCURRENTLY;"),
        "Migration chain conflict: cannot reindex system catalogs concurrently"
    );
    // Each of these takes its own commit point per relation.
    for (sql, form) in [
        ("BEGIN; REINDEX SYSTEM; COMMIT;", "REINDEX SYSTEM"),
        ("BEGIN; REINDEX SCHEMA public; COMMIT;", "REINDEX SCHEMA"),
        ("BEGIN; REINDEX DATABASE; COMMIT;", "REINDEX DATABASE"),
    ] {
        assert_eq!(
            reason(sql),
            format!("Migration chain conflict: {form} cannot run inside a transaction block"),
            "{form} inside a transaction block"
        );
    }
    assert_eq!(
        reason("REINDEX TABLE CONCURRENTLY pg_catalog.pg_class;"),
        "Migration chain conflict: cannot reindex system catalogs concurrently"
    );
    // Verified live on PostgreSQL 18.6: only a `pg_catalog` relation has no
    // concurrent form. A user table whose name merely begins with
    // `pg_toast_` reindexes concurrently, in any schema.
    assert_eq!(
        reason(
            "CREATE TABLE public.pg_toast_archive (a int);
                 REINDEX TABLE CONCURRENTLY public.pg_toast_archive;"
        ),
        "",
        "a user table is not a TOAST table"
    );
    assert!(
        reason("CREATE TABLE t (a int); CREATE VIEW v AS SELECT a FROM t; REINDEX TABLE v;")
            .contains("is not a table or materialized view"),
        "REINDEX TABLE must reject a view"
    );
    assert_eq!(
        reason(
            "CREATE TABLE p (a int) PARTITION BY RANGE (a);
                 BEGIN; REINDEX TABLE p; COMMIT;"
        ),
        "Migration chain conflict: REINDEX TABLE cannot run inside a transaction block"
    );
}

#[test]
fn a_named_reindex_target_must_be_the_migration_target() {
    let engine_for =
        |database: &str| SafeMigrateEngine::new(Config::default().with_target_database(database));
    let reason = |engine: &SafeMigrateEngine, sql: &str| {
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .expect("the statement should analyze")
            .into_iter()
            .find(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason)
            .unwrap_or_default()
    };
    let app = engine_for("app");

    // `ReindexMultipleTables` resolves both forms against `MyDatabaseId`,
    // so a name that is not the current database is refused for either.
    for form in ["DATABASE", "SYSTEM"] {
        assert!(
            reason(&app, &format!("REINDEX {form} other;"))
                .contains("can only reindex the currently open database"),
            "REINDEX {form} must reject a database that is not the target"
        );
        assert_eq!(
            reason(&app, &format!("REINDEX {form} app;")),
            "",
            "REINDEX {form} naming the target is legal"
        );
    }
    // An omitted name is the current database by the grammar.
    assert_eq!(reason(&app, "REINDEX DATABASE;"), "");
    assert_eq!(reason(&app, "REINDEX SYSTEM;"), "");
}

#[test]
fn an_unchecked_reindex_target_name_is_reported_as_unknown() {
    // Without a configured target the name cannot be checked, and saying
    // nothing would claim an exactness the analysis does not have.
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = setup_state();
    engine
        .analyze("REINDEX DATABASE other;", &mut state)
        .expect("the statement should analyze");
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| record.code == EvidenceCode::UnknownObjectState),
        "an unresolvable target name must not pass silently"
    );
}

#[test]
fn legal_reindex_statements_stay_clean() {
    let engine = setup_engine();
    let mut state = setup_state();
    let v = engine
        .analyze(
            "CREATE TABLE t (a int);
                 CREATE INDEX t_idx ON t (a);
                 REINDEX SYSTEM;
                 REINDEX (CONCURRENTLY) TABLE t;
                 REINDEX INDEX CONCURRENTLY t_idx;
                 REINDEX TABLE CONCURRENTLY t;",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "a legal REINDEX form must not conflict: {v:?}"
    );
}

#[test]
fn a_permanent_index_is_still_reported_as_needing_concurrency() {
    let engine = setup_engine();
    let mut state = setup_state();
    let v = engine
        .analyze(
            "CREATE TABLE bookings (id int);
                 CREATE INDEX bookings_idx ON bookings(id);
                 REINDEX INDEX bookings_idx;",
            &mut state,
        )
        .unwrap();
    assert!(
        v.iter()
            .any(|violation| violation.rule_id == "require-concurrent-reindex"),
        "the temporary exemption must not leak to permanent relations: {v:?}"
    );
}

#[test]
fn test_rule_require_concurrent_reindex() {
    let sql = "
            CREATE TABLE t1 (id int);
            CREATE INDEX idx1 ON t1(id);
            REINDEX TABLE t1; -- blocks, flagged
            REINDEX INDEX idx1; -- blocks, flagged
            REINDEX SCHEMA public; -- blocks, flagged
            REINDEX DATABASE mydb; -- blocks, flagged
            REINDEX (CONCURRENTLY) TABLE t1; -- safe
            REINDEX TABLE CONCURRENTLY t1; -- safe
            REINDEX SYSTEM mydb; -- system doesn't support concurrently, not flagged
        ";
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine.analyze(sql, &mut state).unwrap();

    let reindex_table = violations
        .iter()
        .find(|v| v.rule_id == "require-concurrent-reindex" && v.object_name == "public.t1")
        .expect("should flag synchronous table reindex");
    assert_eq!(reindex_table.tier, ViolationTier::Tier1);

    let reindex_index = violations
        .iter()
        .find(|v| v.rule_id == "require-concurrent-reindex" && v.object_name == "public.idx1")
        .expect("should flag synchronous index reindex");
    assert_eq!(reindex_index.tier, ViolationTier::Tier1);

    let reindex_schema = violations
        .iter()
        .find(|v| v.rule_id == "require-concurrent-reindex" && v.object_name == "public")
        .expect("should flag synchronous schema reindex");
    assert_eq!(reindex_schema.tier, ViolationTier::Tier1);

    let reindex_database = violations
        .iter()
        .find(|v| v.rule_id == "require-concurrent-reindex" && v.object_name == "mydb")
        .expect("should flag synchronous database reindex");
    assert_eq!(reindex_database.tier, ViolationTier::Tier1);

    assert_eq!(
        violations
            .iter()
            .filter(|v| v.rule_id == "require-concurrent-reindex")
            .count(),
        4,
        "should not flag CONCURRENTLY or SYSTEM"
    );
}

#[test]
fn reindex_of_temporary_table_is_not_flagged() {
    // PostgreSQL rejects REINDEX ... CONCURRENTLY on a temporary relation, so
    // the synchronous form is the only legal statement. Demanding CONCURRENTLY
    // here would be a false positive with no correct alternative.
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine
        .analyze(
            "CREATE TEMP TABLE scratch (id int); REINDEX TABLE scratch;",
            &mut state,
        )
        .unwrap();

    assert!(
            !violations
                .iter()
                .any(|v| v.rule_id == "require-concurrent-reindex"
                    && v.object_name == "public.scratch"),
            "temporary table reindex must not be flagged: {violations:?}"
        );
}

#[test]
fn alter_index_variants_are_modeled_not_opaque() {
    let engine = setup_engine();
    let mut state = setup_state();
    let sql = "
            CREATE TABLE t_alter (id int);
            CREATE INDEX idx_tablespace ON t_alter(id);
            CREATE INDEX idx_options ON t_alter(id);
            CREATE INDEX idx_depends ON t_alter(id);
            CREATE TABLE part_parent (id int) PARTITION BY RANGE (id);
            CREATE TABLE part_child (id int);
            CREATE INDEX part_parent_idx ON part_parent(id);
            CREATE INDEX part_child_idx ON part_child(id);
            ALTER INDEX idx_tablespace SET TABLESPACE pg_default;
            ALTER INDEX idx_options SET (fillfactor = 70);
            ALTER INDEX idx_options RESET (fillfactor);
            ALTER INDEX idx_depends DEPENDS ON EXTENSION my_ext;
            ALTER INDEX idx_depends NO DEPENDS ON EXTENSION my_ext;
            ALTER INDEX part_parent_idx ATTACH PARTITION part_child_idx;
        ";
    let violations = engine.analyze(sql, &mut state).unwrap();

    assert!(
        !violations.iter().any(|v| v.rule_id == "opaque-dynamic-sql"),
        "ALTER INDEX actions must be modeled, not opaque: {violations:?}"
    );
    assert!(
        !violations.iter().any(|v| v.rule_id == "schema-drift"),
        "no schema-drift conflicts expected: {violations:?}"
    );
}

#[test]
fn alter_index_rename_updates_state() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE t_rename_index (id int);
                 CREATE INDEX idx_old ON t_rename_index(id);
                 ALTER INDEX idx_old RENAME TO idx_new;",
            &mut state,
        )
        .unwrap();
    assert!(state.index_is_present(&object_id("public", "idx_new")));
    assert!(!state.index_is_present(&object_id("public", "idx_old")));
}

#[test]
fn alter_index_if_exists_missing_is_safe() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE t_missing (id int);
                 ALTER INDEX IF EXISTS idx_missing RENAME TO idx_also_missing;",
            &mut state,
        )
        .unwrap();
    assert!(!state.index_is_present(&object_id("public", "idx_also_missing")));
}
