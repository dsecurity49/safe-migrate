use super::*;

fn identity_sequence(state: &AnalysisState, table: &ObjectId, column: &str) -> ObjectId {
    state
        .local
        .sequences
        .iter()
        .find_map(|(id, overlay)| match overlay {
            SequenceOverlay::Present(sequence)
                if sequence.kind == SequenceKind::Identity
                    && sequence.owned_by.as_ref() == Some(&(table.clone(), column.to_string())) =>
            {
                Some(id.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("identity sequence for {table}.{column} missing"))
}

#[test]
fn add_identity_creates_owned_sequence_and_marks_column() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE idt (id integer NOT NULL);
             ALTER TABLE idt ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY
               (START WITH 5 INCREMENT BY 2);",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "valid ADD GENERATED conflicted: {findings:?}"
    );

    let table = object_id("public", "idt");
    let Some(RelationOverlay::Present(relation)) = state.get_relation(&table) else {
        panic!("idt relation missing")
    };
    assert_eq!(
        relation.identity_columns.get("id"),
        Some(&safe_migrate::_internal::model::relation::IdentityGeneration::Always)
    );
    let column = relation.get_column("id").expect("id column missing");
    assert!(!column.is_nullable);
    assert!(column.default.is_some());
    assert_eq!(
        column.default_expr_text.as_deref(),
        Some("nextval('public.idt_id_seq'::regclass)")
    );

    let sequence_id = identity_sequence(&state, &table, "id");
    assert_eq!(sequence_id, object_id("public", "idt_id_seq"));
    let Some(SequenceOverlay::Present(sequence)) = state.local.sequences.get(&sequence_id) else {
        panic!("identity sequence missing")
    };
    assert_eq!(sequence.parameters.start_value, 5);
    assert_eq!(sequence.parameters.increment, 2);
    assert!(state.local.graph.edges().iter().any(|edge| {
        edge.dependent == sequence_id
            && edge.referenced == table
            && matches!(&edge.kind, DependencyKind::SequenceOwnedBy { column } if column == "id")
    }));
}

#[test]
fn add_identity_requires_not_null_and_rejects_defaults_identities_and_types() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE idt (
                nullable integer,
                with_default integer NOT NULL DEFAULT 1,
                textual text NOT NULL,
                generated integer NOT NULL GENERATED ALWAYS AS (1) STORED,
                already bigint NOT NULL
             );
             ALTER TABLE idt ALTER COLUMN already ADD GENERATED ALWAYS AS IDENTITY;",
            &mut state,
        )
        .unwrap();

    for sql in [
        "ALTER TABLE idt ALTER COLUMN nullable ADD GENERATED ALWAYS AS IDENTITY;",
        "ALTER TABLE idt ALTER COLUMN with_default ADD GENERATED ALWAYS AS IDENTITY;",
        "ALTER TABLE idt ALTER COLUMN textual ADD GENERATED ALWAYS AS IDENTITY;",
        "ALTER TABLE idt ALTER COLUMN generated ADD GENERATED ALWAYS AS IDENTITY;",
        "ALTER TABLE idt ALTER COLUMN already ADD GENERATED ALWAYS AS IDENTITY;",
    ] {
        let findings = engine.analyze(sql, &mut state).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "expected conflict for {sql}"
        );
    }

    let table = object_id("public", "idt");
    let Some(RelationOverlay::Present(relation)) = state.get_relation(&table) else {
        panic!("idt relation missing")
    };
    assert_eq!(relation.identity_columns.len(), 1);
    assert!(relation.identity_columns.contains_key("already"));
}

#[test]
fn add_identity_suffixes_an_implicit_sequence_name_collision() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE idt (id integer NOT NULL);
             CREATE SEQUENCE idt_id_seq;
             ALTER TABLE idt ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY;",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "implicit sequence suffixing conflicted: {findings:?}"
    );

    let table = object_id("public", "idt");
    assert_eq!(
        identity_sequence(&state, &table, "id"),
        object_id("public", "idt_id_seq1")
    );
}

#[test]
fn add_identity_explicit_sequence_name_conflicts_when_taken() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE idt (id integer NOT NULL);
             CREATE SEQUENCE custom_seq;
             ALTER TABLE idt ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY
               (SEQUENCE NAME custom_seq);",
            &mut state,
        )
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "explicit sequence name collision was accepted: {findings:?}"
    );

    let table = object_id("public", "idt");
    let Some(RelationOverlay::Present(relation)) = state.get_relation(&table) else {
        panic!("idt relation missing")
    };
    assert!(!relation.identity_columns.contains_key("id"));
    assert!(!state.local.sequences.values().any(|overlay| matches!(
        overlay,
        SequenceOverlay::Present(sequence)
            if sequence.owned_by.as_ref() == Some(&(table.clone(), "id".to_string()))
    )));
}

#[test]
fn add_identity_on_partitioned_table_reaches_existing_partitions() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE idp (id integer NOT NULL) PARTITION BY RANGE (id);
             CREATE TABLE idp1 PARTITION OF idp FOR VALUES FROM (0) TO (10);
             ALTER TABLE idp ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY;",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "valid partitioned ADD GENERATED conflicted: {findings:?}"
    );

    let parent = object_id("public", "idp");
    let child = object_id("public", "idp1");
    let Some(RelationOverlay::Present(parent_relation)) = state.get_relation(&parent) else {
        panic!("idp relation missing")
    };
    assert_eq!(
        parent_relation.identity_columns.get("id"),
        Some(&safe_migrate::_internal::model::relation::IdentityGeneration::ByDefault)
    );
    let Some(RelationOverlay::Present(child_relation)) = state.get_relation(&child) else {
        panic!("idp1 relation missing")
    };
    assert_eq!(
        child_relation.identity_columns.get("id"),
        Some(&safe_migrate::_internal::model::relation::IdentityGeneration::ByDefault)
    );
    let sequence_id = identity_sequence(&state, &parent, "id");
    assert_eq!(sequence_id, object_id("public", "idp_id_seq"));
    assert!(state.local.sequences.values().all(|overlay| !matches!(
        overlay,
        SequenceOverlay::Present(sequence)
            if sequence.owned_by.as_ref() == Some(&(child.clone(), "id".to_string()))
    )));
}

#[test]
fn add_identity_on_a_partition_is_rejected() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE idp (id integer NOT NULL) PARTITION BY RANGE (id);
             CREATE TABLE idp1 PARTITION OF idp FOR VALUES FROM (0) TO (10);",
            &mut state,
        )
        .unwrap();
    let findings = engine
        .analyze(
            "ALTER TABLE idp1 ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY;",
            &mut state,
        )
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "identity was added to a partition: {findings:?}"
    );
    let child = object_id("public", "idp1");
    let Some(RelationOverlay::Present(child_relation)) = state.get_relation(&child) else {
        panic!("idp1 relation missing")
    };
    assert!(!child_relation.identity_columns.contains_key("id"));
}

#[test]
fn add_identity_on_parent_fails_when_a_partition_has_a_local_default() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE idp (id integer NOT NULL) PARTITION BY RANGE (id);
             CREATE TABLE idp1 (id integer NOT NULL DEFAULT 5);
             ALTER TABLE idp ATTACH PARTITION idp1 FOR VALUES FROM (0) TO (10);",
            &mut state,
        )
        .unwrap();
    let findings = engine
        .analyze(
            "ALTER TABLE idp ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY;",
            &mut state,
        )
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "partition local default did not abort ADD GENERATED: {findings:?}"
    );
    let parent = object_id("public", "idp");
    let Some(RelationOverlay::Present(parent_relation)) = state.get_relation(&parent) else {
        panic!("idp relation missing")
    };
    assert!(!parent_relation.identity_columns.contains_key("id"));
    assert!(
        !state
            .local
            .sequences
            .contains_key(&object_id("public", "idp_id_seq"))
    );
}

#[test]
fn attach_rejects_a_child_with_its_own_identity_column() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE idp (id integer NOT NULL) PARTITION BY RANGE (id);
             CREATE TABLE idp1 (id integer NOT NULL GENERATED ALWAYS AS IDENTITY);",
            &mut state,
        )
        .unwrap();
    let findings = engine
        .analyze(
            "ALTER TABLE idp ATTACH PARTITION idp1 FOR VALUES FROM (0) TO (10);",
            &mut state,
        )
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "child identity column was accepted on attach: {findings:?}"
    );
}

#[test]
fn attaching_a_partition_inherits_the_parent_identity() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE idp (id integer NOT NULL) PARTITION BY RANGE (id);
             ALTER TABLE idp ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY;
             CREATE TABLE idp1 (id integer NOT NULL);
             ALTER TABLE idp ATTACH PARTITION idp1 FOR VALUES FROM (0) TO (10);",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "valid identity attach conflicted: {findings:?}"
    );
    let child = object_id("public", "idp1");
    let Some(RelationOverlay::Present(child_relation)) = state.get_relation(&child) else {
        panic!("idp1 relation missing")
    };
    assert_eq!(
        child_relation.identity_columns.get("id"),
        Some(&safe_migrate::_internal::model::relation::IdentityGeneration::Always)
    );
    assert_eq!(
        child_relation
            .get_column("id")
            .and_then(|column| column.default_expr_text.as_deref()),
        Some("nextval('public.idp_id_seq'::regclass)")
    );
}

#[test]
fn creating_a_partition_of_an_identity_parent_inherits_the_identity() {
    let engine = setup_engine();
    let mut state = setup_state();
    let findings = engine
        .analyze(
            "CREATE TABLE idp (id integer NOT NULL) PARTITION BY RANGE (id);
             ALTER TABLE idp ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY;
             CREATE TABLE idp1 PARTITION OF idp FOR VALUES FROM (0) TO (10);",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "partition creation after ADD GENERATED conflicted: {findings:?}"
    );
    let child = object_id("public", "idp1");
    let Some(RelationOverlay::Present(child_relation)) = state.get_relation(&child) else {
        panic!("idp1 relation missing")
    };
    assert_eq!(
        child_relation.identity_columns.get("id"),
        Some(&safe_migrate::_internal::model::relation::IdentityGeneration::ByDefault)
    );
}

#[test]
fn detaching_a_partition_drops_the_inherited_identity_from_the_subtree() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE idp (id integer NOT NULL) PARTITION BY RANGE (id);
             CREATE TABLE idp1 PARTITION OF idp FOR VALUES FROM (0) TO (100) PARTITION BY RANGE (id);
             CREATE TABLE idp2 PARTITION OF idp1 FOR VALUES FROM (0) TO (10);
             ALTER TABLE idp ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY;
             ALTER TABLE idp DETACH PARTITION idp1;",
            &mut state,
        )
        .unwrap();

    let parent = object_id("public", "idp");
    for table in [object_id("public", "idp1"), object_id("public", "idp2")] {
        let Some(RelationOverlay::Present(relation)) = state.get_relation(&table) else {
            panic!("{table} relation missing")
        };
        assert!(
            !relation.identity_columns.contains_key("id"),
            "{table} retained inherited identity after detach"
        );
        assert!(
            relation
                .get_column("id")
                .is_some_and(|column| column.default_expr_text.is_none()),
            "{table} retained the inherited sequence default after detach"
        );
    }
    let Some(RelationOverlay::Present(parent_relation)) = state.get_relation(&parent) else {
        panic!("idp relation missing")
    };
    assert!(parent_relation.identity_columns.contains_key("id"));
}

#[test]
fn dropping_an_identity_column_drops_its_sequence() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE idt (id integer NOT NULL);
             ALTER TABLE idt ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY;",
            &mut state,
        )
        .unwrap();
    engine
        .analyze("ALTER TABLE idt DROP COLUMN id;", &mut state)
        .unwrap();
    let table = object_id("public", "idt");
    let Some(RelationOverlay::Present(relation)) = state.get_relation(&table) else {
        panic!("idt relation missing")
    };
    assert!(!relation.has_column("id"));
    assert!(!state.local.sequences.values().any(|overlay| matches!(
        overlay,
        SequenceOverlay::Present(sequence)
            if sequence.owned_by.as_ref() == Some(&(table.clone(), "id".to_string()))
    )));
}
