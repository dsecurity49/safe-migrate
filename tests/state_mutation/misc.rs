use super::*;

#[test]
fn generated_expression_text_tracks_create_add_change_and_rollback() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine.analyze("CREATE TABLE generated_text(base integer, doubled integer GENERATED ALWAYS AS (base * 2) STORED); ALTER TABLE generated_text ADD COLUMN tripled integer GENERATED ALWAYS AS (base * 3) STORED;", &mut state).unwrap();
    let id = object_id("public", "generated_text");
    let Some(RelationOverlay::Present(relation)) = state.get_relation(&id) else {
        panic!("missing relation")
    };
    assert_eq!(
        relation.generated_columns["doubled"].expression.as_deref(),
        Some("base * 2")
    );
    assert_eq!(
        relation.generated_columns["tripled"].expression.as_deref(),
        Some("base * 3")
    );
    engine
        .analyze(
            "BEGIN; ALTER TABLE generated_text ALTER COLUMN doubled SET EXPRESSION AS (base * 4);",
            &mut state,
        )
        .unwrap();
    let Some(RelationOverlay::Present(relation)) = state.get_relation(&id) else {
        panic!("missing relation")
    };
    assert_eq!(
        relation.generated_columns["doubled"].expression.as_deref(),
        Some("base * 4")
    );
    engine.analyze("ROLLBACK;", &mut state).unwrap();
    let Some(RelationOverlay::Present(relation)) = state.get_relation(&id) else {
        panic!("missing relation")
    };
    assert_eq!(
        relation.generated_columns["doubled"].expression.as_deref(),
        Some("base * 2")
    );
}

#[test]
fn create_if_not_exists_skips_when_another_relation_kind_uses_the_name() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
            .analyze(
                "CREATE SEQUENCE occupied; CREATE TABLE IF NOT EXISTS occupied (id int); CREATE TABLE after_skip (id int);",
                &mut state,
            )
            .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    assert!(state.relation_is_present(&object_id("public", "after_skip")));
}

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
fn like_extended_statistics_follow_column_lifecycle_and_rollback() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze("CREATE TABLE source (a integer, b integer);", &mut state)
        .unwrap();
    let source = object_id("public", "source");
    let statistics_id = object_id("public", "source_a_b_stat");
    let Some(RelationOverlay::Present(source_relation)) = state.local.relations.get_mut(&source)
    else {
        panic!("source relation missing")
    };
    source_relation.extended_statistics.insert(
        statistics_id.clone(),
        safe_migrate::_internal::model::relation::ExtendedStatisticsState {
            id: statistics_id,
            kinds: vec!["d".to_string(), "f".to_string()],
            columns: vec!["a".to_string(), "b".to_string()],
            expressions: Some("(a + b), (a * b)".to_string()),
            target: Some(250),
        },
    );

    let findings = engine
        .analyze(
            "CREATE TABLE copy (LIKE source INCLUDING STATISTICS);
                 ALTER TABLE copy RENAME COLUMN a TO renamed;
                 BEGIN;
                 ALTER TABLE copy DROP COLUMN renamed CASCADE;
                 ROLLBACK;",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "extended-statistics lifecycle unexpectedly conflicted: {findings:?}"
    );
    let copy = object_id("public", "copy");
    let Some(RelationOverlay::Present(copy_relation)) = state.local.relations.get(&copy) else {
        panic!("copy relation missing")
    };
    let cloned = copy_relation
        .extended_statistics
        .values()
        .next()
        .expect("cloned extended statistics");
    assert_eq!(cloned.columns, vec!["renamed", "b"]);
    assert_eq!(
        cloned.expressions.as_deref(),
        Some("(renamed + b), (renamed * b)")
    );
    assert_eq!(cloned.target, None);

    let findings = engine
        .analyze("ALTER TABLE copy DROP COLUMN renamed RESTRICT;", &mut state)
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
    assert!(state
            .get_relation(&copy)
            .is_some_and(|overlay| matches!(overlay, RelationOverlay::Present(relation) if relation.has_column("renamed") && !relation.extended_statistics.is_empty())));
}

#[test]
fn autocommit_runs_on_commit_drop_before_the_next_statement() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TEMPORARY TABLE work (id integer) ON COMMIT DROP;
                 CREATE INDEX work_id_idx ON work (id);",
            &mut state,
        )
        .unwrap();

    assert!(!state.relation_is_present(&object_id("public", "work")));
    assert!(!state.index_is_present(&object_id("public", "work_id_idx")));
}

#[test]
fn a_statement_the_build_claims_keeps_every_action() {
    use safe_migrate::_internal::model::relation::RelationOverlay;
    use safe_migrate::_internal::model::sequence::SequenceOverlay;

    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE t (a int, b int);
                 CREATE SEQUENCE s INCREMENT BY 1;
                 ALTER TABLE t ADD COLUMN c int, ALTER COLUMN a SET DEFAULT 1;
                 ALTER SEQUENCE s INCREMENT BY 2 CACHE 5;",
            &mut state,
        )
        .expect("the statements should analyze");

    assert!(
        state
            .local
            .relations
            .get(&object_id("public", "t"))
            .is_some_and(|overlay| matches!(
                overlay,
                RelationOverlay::Present(relation)
                    if relation.has_column("c") && relation.has_column("a")
            )),
        "ALTER TABLE must apply every action it carries"
    );
    assert!(
        state
            .local
            .sequences
            .get(&object_id("public", "s"))
            .is_some_and(|overlay| matches!(
                overlay,
                SequenceOverlay::Present(sequence)
                    if sequence.parameters.increment == 2
                        && sequence.parameters.cache_size == 5
            )),
        "ALTER SEQUENCE must apply every option it carries"
    );
}

#[test]
fn if_exists_guards_only_the_relation_lookup() {
    let conflicts = |sql: &str| {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(sql, &mut state)
            .unwrap()
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .map(|violation| violation.reason.clone())
            .collect::<Vec<_>>()
    };

    // PostgreSQL notices and skips; neither statement is an error.
    assert!(
        conflicts("ALTER VIEW IF EXISTS missing RENAME TO other;").is_empty(),
        "ALTER VIEW IF EXISTS must skip a missing view"
    );
    assert!(
        conflicts("ALTER MATERIALIZED VIEW IF EXISTS missing RENAME TO other;").is_empty(),
        "ALTER MATERIALIZED VIEW IF EXISTS must skip a missing view"
    );

    // The guard does not cover a relation of the wrong kind.
    assert!(
        conflicts("CREATE TABLE t (a int); ALTER VIEW IF EXISTS t RENAME TO other;")
            .iter()
            .any(|message| message.contains("is not a view")),
        "IF EXISTS must not suppress the wrong-kind error"
    );

    // Without the guard the same statement conflicts.
    assert!(
        conflicts("ALTER VIEW missing RENAME TO other;")
            .iter()
            .any(|message| message.contains("does not exist")),
        "an unguarded ALTER of a missing view must conflict"
    );
}

#[test]
fn a_rejected_declaration_does_not_block_the_valid_ones() {
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine
        .analyze(
            "CREATE TABLE ok_a (c text, d text[], e serial, f bigserial);
                 CREATE DOMAIN ok_dom AS text;
                 CREATE TYPE ok_enum AS ENUM ('a', 'b');
                 CREATE TYPE ok_comp AS (a int, b text);
                 CREATE TYPE ok_range AS RANGE (subtype = int4);
                 CREATE TYPE ok_range2 AS RANGE (subtype = text);",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "valid declarations must still apply"
    );
}

#[test]
fn a_canonical_alias_is_not_a_rewrite() {
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine
        .analyze(
            "CREATE TABLE alias_probe (a int, b integer, c int4);
                 ALTER TABLE alias_probe ALTER COLUMN a TYPE integer;
                 ALTER TABLE alias_probe ALTER COLUMN b TYPE int4;",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "type-change-rewrite"),
        "two spellings of one type are one type"
    );
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
fn rollback_restores_every_destructively_rewritten_graph_edge() {
    let engine = setup_engine();
    let mut state = setup_state();
    state.pg_version_num = Some(180_000);

    let findings = engine
        .analyze(
            "CREATE TABLE items (id integer NOT NULL);
                 CREATE INDEX items_idx ON items (id);
                 ALTER TABLE items ADD CONSTRAINT items_check CHECK (id > 0) NOT VALID;
                 CREATE TABLE parent (id integer) PARTITION BY RANGE (id);
                 CREATE TABLE child PARTITION OF parent FOR VALUES FROM (0) TO (10);
                 BEGIN;
                 DROP INDEX items_idx;
                 ALTER TABLE items DROP CONSTRAINT items_check;
                 ALTER TABLE items ALTER COLUMN id DROP NOT NULL;
                 ALTER TABLE parent DETACH PARTITION child;
                 ROLLBACK;",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "rollback setup unexpectedly conflicted: {findings:?}"
    );

    let items = object_id("public", "items");
    let index = object_id("public", "items_idx");
    let parent = object_id("public", "parent");
    let child = object_id("public", "child");
    assert!(matches!(
        state.get_relation(&child),
        Some(RelationOverlay::Present(relation)) if relation.has_column("id")
    ));
    assert!(state.local.graph.edges().iter().any(|edge| {
        edge.dependent == index
            && edge.referenced == items
            && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
    }));
    assert!(state.local.graph.edges().iter().any(|edge| {
        edge.dependent == items
            && matches!(
                &edge.kind,
                DependencyKind::ConstraintDependency {
                    constraint_name,
                    ..
                } if constraint_name == "items_check"
            )
    }));
    assert!(state.local.graph.edges().iter().any(|edge| {
        edge.dependent == items
            && matches!(
                &edge.kind,
                DependencyKind::ConstraintOnRelation {
                    columns,
                    is_primary: false,
                    ..
                } if columns == &["id"]
            )
    }));
    assert!(state.local.graph.edges().iter().any(|edge| {
        edge.dependent == child
            && edge.referenced == parent
            && matches!(edge.kind, DependencyKind::PartitionOf)
    }));
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
