use super::*;

#[test]
fn drop_trigger_if_exists_is_a_no_op_when_missing() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
            .analyze(
                "CREATE TABLE t (id int); DROP TRIGGER IF EXISTS missing ON t; ALTER TABLE t ADD COLUMN later int;",
                &mut state,
            )
            .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    let Some(RelationOverlay::Present(table)) = state.get_relation(&object_id("public", "t"))
    else {
        panic!("table should remain present");
    };
    assert!(table.has_column("later"));
}

#[test]
fn test_topology_trigger_and_policy() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE TABLE t(id int); CREATE POLICY p ON t FOR SELECT USING(true); CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$; CREATE TRIGGER tr BEFORE INSERT ON t EXECUTE FUNCTION f();",
                &mut state,
            )
            .unwrap();

    assert_eq!(
        state.local.confidence,
        Confidence::Tainted,
        "policy expressions are retained for rule evaluation but are not modeled in relation state"
    );

    if let Some(RelationOverlay::Present(r)) = state.get_relation(&object_id("public", "t")) {
        assert!(r.policies.contains("p"));
        assert!(r.triggers.contains("tr"));
    }

    engine
        .analyze("DROP POLICY p ON t; DROP TRIGGER tr ON t;", &mut state)
        .unwrap();

    if let Some(RelationOverlay::Present(r)) = state.get_relation(&object_id("public", "t")) {
        assert!(!r.policies.contains("p"));
        assert!(!r.triggers.contains("tr"));
    }
}

#[test]
fn rename_trigger_updates_identity_and_rolls_back() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE TABLE t(id int);
                 CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$;
                 CREATE TRIGGER old_trigger BEFORE INSERT ON t FOR EACH ROW EXECUTE FUNCTION f();
                 BEGIN;
                 ALTER TRIGGER old_trigger ON t RENAME TO new_trigger;",
                &mut state,
            )
            .unwrap();

    let RelationOverlay::Present(relation) = state.get_relation(&object_id("public", "t")).unwrap()
    else {
        panic!("table missing");
    };
    assert!(!relation.triggers.contains("old_trigger"));
    assert!(relation.triggers.contains("new_trigger"));
    assert!(state.local.triggers.values().any(|overlay| matches!(overlay,
            safe_migrate::_internal::model::trigger::TriggerOverlay::Present(trigger) if trigger.name == "new_trigger"
        )));

    engine.analyze("ROLLBACK;", &mut state).unwrap();
    let RelationOverlay::Present(relation) = state.get_relation(&object_id("public", "t")).unwrap()
    else {
        panic!("table missing");
    };
    assert!(relation.triggers.contains("old_trigger"));
    assert!(!relation.triggers.contains("new_trigger"));
}

#[test]
fn rename_trigger_rejects_an_existing_target() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
            .analyze(
                "CREATE TABLE t(id int);
                 CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$;
                 CREATE TRIGGER first_trigger BEFORE INSERT ON t FOR EACH ROW EXECUTE FUNCTION f();
                 CREATE TRIGGER second_trigger BEFORE UPDATE ON t FOR EACH ROW EXECUTE FUNCTION f();
                 ALTER TRIGGER first_trigger ON t RENAME TO second_trigger;",
                &mut state,
            )
            .unwrap();

    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict" && violation.reason.contains("second_trigger")
    }));
}

#[test]
fn test_state_hydrates_and_disables_trigger() {
    use safe_migrate::_internal::db::cache::TriggerCache;
    use safe_migrate::_internal::model::trigger::{TriggerEnableMode, TriggerOverlay};

    let engine = setup_engine();
    let mut cache = cache_with_table("public", "test_table", None);
    cache.triggers.push(TriggerCache {
        trigger_id: object_id("public", "check_trigger"),
        table_id: object_id("public", "test_table"),
        function_id: object_id("public", "check_row()"),
        row_level: true,
        parent_trigger_id: None,
        enabled_mode: TriggerEnableMode::Origin,
    });
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze(
            "ALTER TABLE test_table DISABLE TRIGGER check_trigger;",
            &mut state,
        )
        .unwrap();

    let Some(TriggerOverlay::Present(trigger)) = state
            .local
            .triggers
            .values()
            .find(|overlay| matches!(overlay, TriggerOverlay::Present(trigger) if trigger.name == "check_trigger"))
        else {
            panic!("baseline trigger should be hydrated");
        };
    assert_eq!(trigger.enabled_mode, TriggerEnableMode::Disabled);
}

#[test]
fn same_named_triggers_on_different_tables_remain_independent() {
    use safe_migrate::_internal::model::trigger::{TriggerEnableMode, TriggerOverlay};

    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "
                CREATE TABLE first_table (id integer);
                CREATE TABLE second_table (id integer);
                CREATE FUNCTION audit_trigger() RETURNS trigger
                    LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
                CREATE TRIGGER audit AFTER INSERT ON first_table
                    EXECUTE FUNCTION audit_trigger();
                CREATE TRIGGER audit AFTER INSERT ON second_table
                    EXECUTE FUNCTION audit_trigger();
                ALTER TABLE first_table DISABLE TRIGGER audit;
                ",
            &mut state,
        )
        .unwrap();

    let modes: Vec<_> = state
        .local
        .triggers
        .values()
        .filter_map(|overlay| match overlay {
            TriggerOverlay::Present(trigger) if trigger.name == "audit" => {
                Some((trigger.table_id.name.as_str(), trigger.enabled_mode))
            }
            _ => None,
        })
        .collect();
    assert_eq!(modes.len(), 2);
    assert!(modes.contains(&("first_table", TriggerEnableMode::Disabled)));
    assert!(modes.contains(&("second_table", TriggerEnableMode::Origin)));
}

#[test]
fn alter_rule_modes_validate_catalog_identity_and_rollback() {
    let engine = setup_engine();
    let mut state = setup_state();
    let table_id = object_id("public", "events");
    engine
        .analyze("CREATE TABLE events (id integer);", &mut state)
        .unwrap();
    let Some(RelationOverlay::Present(relation)) = state.local.relations.get_mut(&table_id) else {
        panic!("created relation missing from state")
    };
    relation.rules.insert(
        "rewrite_rule".to_string(),
        safe_migrate::_internal::model::relation::RuleEnableMode::Origin,
    );

    let findings = engine
        .analyze(
            "ALTER TABLE events ENABLE REPLICA RULE rewrite_rule;
                 ALTER TABLE events ENABLE ALWAYS RULE rewrite_rule;
                 BEGIN;
                 ALTER TABLE events DISABLE RULE rewrite_rule;
                 ROLLBACK;",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "valid rule mode changes unexpectedly conflicted: {findings:?}"
    );
    let Some(RelationOverlay::Present(relation)) = state.local.relations.get(&table_id) else {
        panic!("relation missing after rule mode rollback")
    };
    assert_eq!(
        relation.rules.get("rewrite_rule"),
        Some(&safe_migrate::_internal::model::relation::RuleEnableMode::Always)
    );

    let findings = engine
        .analyze("ALTER TABLE events ENABLE RULE missing_rule;", &mut state)
        .unwrap();
    assert!(findings.iter().any(|finding| {
        finding.rule_id == "chain-conflict"
            && finding
                .reason
                .contains("rule 'missing_rule' does not exist")
    }));
}
