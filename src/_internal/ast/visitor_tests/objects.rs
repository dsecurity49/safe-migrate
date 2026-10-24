use super::*;

#[test]
fn expression_column_rename_preserves_functions_literals_and_unicode() {
    use crate::_internal::analysis::expr_visitor::ExprVisitor;
    assert_eq!(
        ExprVisitor::rename_column_source("abs(abs) + length('abs')", "items", "abs", "Renamed"),
        Some("abs(\"Renamed\") + length('abs')".into())
    );
    assert_eq!(
        ExprVisitor::rename_column_source("\"café\" + 1", "items", "café", "new\"name"),
        Some("\"new\"\"name\" + 1".into())
    );
    assert_eq!(
        ExprVisitor::rename_column_source(
            "items.value + payload.value",
            "items",
            "value",
            "new_value"
        ),
        Some("items.new_value + payload.value".into())
    );
    assert!(ExprVisitor::rename_column_source("base +", "items", "base", "renamed").is_none());
    assert_eq!(
        ExprVisitor::rename_column_source(
            "pg_catalog.abs(pg_catalog) + pg_catalog.abs(items.pg_catalog)",
            "items",
            "pg_catalog",
            "renamed"
        ),
        Some("pg_catalog.abs(renamed) + pg_catalog.abs(items.renamed)".into())
    );
    assert_eq!(
        ExprVisitor::rename_column_source("(a + b), (a * b)", "items", "a", "renamed"),
        Some("(renamed + b), (renamed * b)".into())
    );
}

#[test]
fn qualified_trigger_function_preserves_schema() {
    let fact = parse_and_extract_statement(
        "CREATE TRIGGER trg AFTER INSERT ON s.t1 FOR EACH ROW EXECUTE FUNCTION s.notify_func();",
    )
    .expect("trigger fact");

    let StatementFact::CreateTrigger {
        function: Some(function),
        row_level,
        ..
    } = fact
    else {
        panic!("expected qualified trigger function");
    };
    assert_eq!(
        function.schema.as_ref().map(Ident::resolve),
        Some("s".into())
    );
    assert_eq!(function.name.resolve(), "notify_func");
    assert!(row_level);

    let statement_fact = parse_and_extract_statement(
        "CREATE TRIGGER trg AFTER INSERT ON s.t1 EXECUTE FUNCTION s.notify_func();",
    )
    .expect("statement trigger fact");
    assert!(matches!(
        statement_fact,
        StatementFact::CreateTrigger {
            row_level: false,
            ..
        }
    ));
}

#[test]
fn create_enum_extracts_ordered_and_escaped_labels() {
    let fact = parse_and_extract_statement(
        r#"CREATE TYPE "Mood" AS ENUM ('sad', 'it''s fine', E'line\nbreak');"#,
    )
    .expect("create type fact");

    let StatementFact::CreateType(create_type) = fact else {
        panic!("expected create type fact");
    };
    assert_eq!(create_type.name.name.resolve(), "Mood");
    assert!(create_type.name.name.quoted);
    assert_eq!(
        create_type.kind,
        TypeCreationKind::Enum {
            variants: vec!["sad".into(), "it's fine".into(), "line\nbreak".into()]
        }
    );
}

#[test]
fn create_composite_type_preserves_ordered_fields() {
    let fact = parse_and_extract_statement(r#"CREATE TYPE address AS (street text, zip integer);"#)
        .expect("composite type fact");
    let StatementFact::CreateType(create_type) = fact else {
        panic!("expected create type fact");
    };
    assert!(matches!(
        create_type.kind,
        crate::_internal::analysis::facts::TypeCreationKind::Composite { fields }
            if fields.iter().map(|field| (field.name.as_str(), field.data_type.as_str())).collect::<Vec<_>>()
                == vec![("street", "text"), ("zip", "integer")]
    ));
}

#[test]
fn alter_type_rename_value_extracts_qualified_identity_and_labels() {
    let fact = parse_and_extract_statement(
        r#"ALTER TYPE sm_core."Mood" RENAME VALUE 'it''s fine' TO 'it''s great';"#,
    )
    .expect("alter type fact");

    let StatementFact::AlterType(alter_type) = fact else {
        panic!("expected alter type fact");
    };
    assert_eq!(
        alter_type
            .name
            .schema
            .as_ref()
            .map(|schema| schema.resolve()),
        Some("sm_core".to_string())
    );
    assert_eq!(alter_type.name.name.resolve(), "Mood");
    assert!(alter_type.name.name.quoted);
    assert_eq!(
        alter_type.actions,
        vec![AlterTypeActionFact::RenameValue {
            old_value: "it's fine".into(),
            new_value: "it's great".into(),
        }]
    );
}

#[test]
fn alter_type_rename_to_extracts_quoted_name() {
    let fact = parse_and_extract_statement(r#"ALTER TYPE sm_core.old_name RENAME TO "NewName";"#)
        .expect("alter type fact");

    let StatementFact::AlterType(alter_type) = fact else {
        panic!("expected alter type fact");
    };
    assert_eq!(
        alter_type.name.schema.as_ref().map(Ident::resolve),
        Some("sm_core".into())
    );
    assert_eq!(
        alter_type.actions,
        vec![AlterTypeActionFact::RenameTo {
            new_name: Ident::new("NewName", true),
        }]
    );
}

#[test]
fn alter_type_set_schema_extracts_quoted_schema_name() {
    let fact = parse_and_extract_statement(r#"ALTER TYPE sm_core.mood SET SCHEMA "App";"#)
        .expect("alter type fact");

    let StatementFact::AlterType(alter_type) = fact else {
        panic!("expected alter type fact");
    };
    assert_eq!(
        alter_type.actions,
        vec![AlterTypeActionFact::SetSchema {
            new_schema: "App".into(),
        }]
    );
}

#[test]
fn alter_trigger_rename_to_extracts_quoted_name_and_table() {
    let fact = parse_and_extract_statement(
        r#"ALTER TRIGGER old_trigger ON sm_core.events RENAME TO "NewTrigger";"#,
    )
    .expect("alter trigger fact");

    let StatementFact::AlterTrigger {
        name,
        table,
        new_name,
    } = fact
    else {
        panic!("expected alter trigger fact");
    };
    assert_eq!(name, "old_trigger");
    assert_eq!(
        table.schema.as_ref().map(Ident::resolve),
        Some("sm_core".into())
    );
    assert_eq!(table.name.resolve(), "events");
    assert_eq!(new_name, "NewTrigger");
}

#[test]
fn alter_type_add_value_uses_ast_position_when_label_contains_before() {
    let fact =
        parse_and_extract_statement("ALTER TYPE mood ADD VALUE 'not before now' AFTER 'ready';")
            .expect("alter type fact");

    let StatementFact::AlterType(alter_type) = fact else {
        panic!("expected alter type fact");
    };
    assert_eq!(
        alter_type.actions,
        vec![AlterTypeActionFact::AddValue {
            new_value: "not before now".into(),
            neighbor: Some("ready".into()),
            before: false,
        }]
    );
}

#[test]
fn alter_table_drop_default_is_a_typed_default_reset() {
    let fact = parse_and_extract_statement("ALTER TABLE users ALTER COLUMN email DROP DEFAULT;")
        .expect("alter table fact");

    let StatementFact::AlterTable { actions, .. } = fact else {
        panic!("expected alter table fact");
    };
    assert!(matches!(
        actions.as_slice(),
        [AlterTableActionFact::SetDefault { column, default: None }]
            if column == "email"
    ));
}

#[test]
fn temporary_table_on_commit_uses_the_typed_action() {
    let fact = parse_and_extract_statement(
        "CREATE TEMPORARY TABLE work (id integer) ON COMMIT DELETE ROWS;",
    )
    .expect("temporary ON COMMIT fact");
    assert!(matches!(
        fact,
        StatementFact::CreateTable {
            persistence: crate::_internal::analysis::facts::PersistenceFact::Temporary,
            on_commit: Some(crate::_internal::analysis::facts::OnCommitFact::DeleteRows),
            ..
        }
    ));
}

#[test]
fn alter_table_options_preserve_typed_keys_and_values() {
    let fact = parse_and_extract_statement(
        "ALTER TABLE entries SET (fillfactor = 70, autovacuum_enabled = false);",
    )
    .expect("table options fact");
    assert!(matches!(
        fact,
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [crate::_internal::analysis::facts::AlterTableActionFact::SetTableOptions { attributes }]
                if attributes.iter().any(|attribute| attribute.name == "fillfactor" && attribute.value.as_deref() == Some("70"))
                    && attributes.iter().any(|attribute| attribute.name == "autovacuum_enabled" && attribute.value.as_deref() == Some("false")))
    ));
}

#[test]
fn prepare_transaction_uses_the_typed_literal_and_decodes_quotes() {
    let fact = parse_and_extract_statement("PREPARE TRANSACTION 'a''b';")
        .expect("prepare transaction fact");
    assert!(matches!(
        fact,
        StatementFact::PrepareTransaction { name } if name == "a'b"
    ));
}

#[test]
fn routine_identity_excludes_out_parameters_in_alter_and_drop_signatures() {
    let facts = parse_and_extract(
        "ALTER FUNCTION calculate(IN value integer, OUT label text) RENAME TO calculated;
             DROP FUNCTION calculate(IN value integer, OUT label text);
             ALTER PROCEDURE process(IN value integer, OUT label text) RENAME TO processed;
             DROP PROCEDURE process(IN value integer, OUT label text);",
    );
    assert_eq!(facts.len(), 4);

    let params = facts
        .iter()
        .map(|fact| match fact {
            StatementFact::AlterFunction(fact) => fact.params.as_slice(),
            StatementFact::DropFunction(fact) => fact.signatures[0].params.as_slice(),
            StatementFact::AlterProcedure(fact) => fact.params.as_slice(),
            StatementFact::DropProcedure(fact) => fact.signatures[0].params.as_slice(),
            other => panic!("unexpected routine fact: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert!(params.iter().all(|params| *params == ["integer"]));
}

#[test]
fn publication_and_subscription_alter_actions_are_typed() {
    let facts = parse_and_extract(
        r#"
            ALTER PUBLICATION MixedPub ADD TABLE app.entries ("Camel") WHERE ("Camel" > 0);
            ALTER PUBLICATION MixedPub SET (publish = 'insert, update');
            ALTER PUBLICATION MixedPub RENAME TO RenamedPub;
            ALTER SUBSCRIPTION MixedSub SET PUBLICATION MixedPub, "AuditPub" WITH (refresh = false);
            ALTER SUBSCRIPTION MixedSub SET (streaming = parallel, slot_name = NONE);
            ALTER SUBSCRIPTION MixedSub SKIP (lsn = '0/16B6C50');
            ALTER SUBSCRIPTION MixedSub RENAME TO RenamedSub;
            "#,
    );
    assert_eq!(facts.len(), 7);

    assert!(matches!(
        &facts[0],
        StatementFact::AlterPublication(fact)
            if fact.name == "mixedpub"
                && matches!(
                    &fact.action,
                    AlterPublicationActionFact::AddObjects(objects)
                        if matches!(
                            &objects[0],
                            PublicationObjectFact::Table {
                                columns: Some(columns),
                                row_filter: Some(_),
                                ..
                            } if columns == &["Camel"]
                        )
                )
    ));
    assert!(matches!(
        &facts[1],
        StatementFact::AlterPublication(fact)
            if matches!(
                &fact.action,
                AlterPublicationActionFact::SetOptions(options)
                    if options == &[crate::_internal::analysis::facts::AttributeFact {
                        name: "publish".into(),
                        value: Some("insert, update".into()),
                        namespace: None,
                    }]
            )
    ));
    assert!(matches!(
        &facts[2],
        StatementFact::AlterPublication(fact)
            if matches!(&fact.action, AlterPublicationActionFact::Rename { to } if to == "renamedpub")
    ));
    assert!(
        matches!(
            &facts[3],
            StatementFact::AlterSubscription(fact)
                if fact.name == "mixedsub"
                    && matches!(
                        &fact.action,
                        AlterSubscriptionActionFact::Publications {
                            mode: SubscriptionPublicationMode::Set,
                            publications,
                            params,
                        } if publications == &["mixedpub", "AuditPub"]
                            && params.iter().any(|param| param.name == "refresh" && param.value.as_deref() == Some("false"))
                    )
        ),
        "extracted subscription publication action: {:?}",
        facts[3]
    );
    assert!(matches!(
        &facts[4],
        StatementFact::AlterSubscription(fact)
            if matches!(
                &fact.action,
                AlterSubscriptionActionFact::SetOptions(options)
                    if options.iter().any(|option| option.name == "streaming" && option.value.as_deref() == Some("parallel"))
                        && options.iter().any(|option| option.name == "slot_name" && option.value.as_deref().is_some_and(|value| value.eq_ignore_ascii_case("none")))
            )
    ));
    assert!(matches!(
        &facts[5],
        StatementFact::AlterSubscription(fact)
            if matches!(
                &fact.action,
                AlterSubscriptionActionFact::Skip(options)
                    if options.iter().any(|option| option.name == "lsn" && option.value.as_deref() == Some("0/16B6C50"))
            )
    ));
    assert!(matches!(
        &facts[6],
        StatementFact::AlterSubscription(fact)
            if matches!(&fact.action, AlterSubscriptionActionFact::Rename { to } if to == "renamedsub")
    ));
}

#[test]
fn subscription_connection_literals_use_postgresql_string_decoding() {
    let facts = parse_and_extract(
            "CREATE SUBSCRIPTION app_sub CONNECTION 'password=it''s-local' PUBLICATION app_pub WITH (connect = false);
             ALTER SUBSCRIPTION app_sub CONNECTION E'password=line\\nfeed';",
        );
    assert!(matches!(
        &facts[0],
        StatementFact::CreateSubscription(fact)
            if fact.connection
                == crate::_internal::analysis::facts::ConnectionTarget::Literal(
                    Some("password=it's-local".into())
                )
    ));
    assert!(matches!(
        &facts[1],
        StatementFact::AlterSubscription(fact)
            if fact.action
                == AlterSubscriptionActionFact::SetConnection(
                    crate::_internal::analysis::facts::ConnectionTarget::Literal(
                        Some("password=line\nfeed".into())
                    )
                )
    ));
}

#[test]
fn aggregate_commands_extract_shared_routine_identities() {
    let create = parse_and_extract_statement(
        "CREATE OR REPLACE AGGREGATE \"Analytics\".Total(integer) (
                SFUNC = int4pl,
                STYPE = integer
            );",
    )
    .expect("create aggregate fact");
    let StatementFact::CreateAggregate(create) = create else {
        panic!("expected create aggregate fact");
    };
    assert!(create.or_replace);
    assert_eq!(create.name.schema.unwrap().resolve(), "Analytics");
    assert_eq!(create.name.name.resolve(), "total");
    assert_eq!(create.params.len(), 1);
    assert_eq!(create.params[0].ty, "integer");
    assert_eq!(
        create.kind,
        crate::_internal::model::aggregate::AggregateKind::Normal
    );
    assert_eq!(create.direct_count, 1);

    let alter = parse_and_extract_statement(
        "ALTER AGGREGATE \"Analytics\".Total(integer) RENAME TO \"Combined\";",
    )
    .expect("alter aggregate fact");
    let StatementFact::AlterAggregate(alter) = alter else {
        panic!("expected alter aggregate fact");
    };
    assert_eq!(alter.name.schema.unwrap().resolve(), "Analytics");
    assert_eq!(alter.name.name.resolve(), "total");
    assert_eq!(alter.params, ["integer"]);
    assert!(matches!(
        alter.action,
        crate::_internal::analysis::facts::AlterFunctionAction::Rename { ref to, .. }
            if to == "Combined"
    ));

    let drop = parse_and_extract_statement(
        "DROP AGGREGATE IF EXISTS \"Analytics\".\"Combined\"(integer) CASCADE;",
    )
    .expect("drop aggregate fact");
    let StatementFact::DropAggregate(drop) = drop else {
        panic!("expected drop aggregate fact");
    };
    assert!(drop.if_exists);
    assert!(drop.cascade);
    assert_eq!(drop.signatures.len(), 1);
    assert_eq!(drop.signatures[0].name.name.resolve(), "Combined");
    assert_eq!(drop.signatures[0].params, ["integer"]);

    let ordered = parse_and_extract_statement(
        "DROP AGGREGATE percentile(double precision ORDER BY numeric, text);",
    )
    .expect("ordered-set aggregate fact");
    let StatementFact::DropAggregate(ordered) = ordered else {
        panic!("expected ordered-set aggregate fact");
    };
    assert_eq!(
        ordered.signatures[0].params,
        ["double precision", "numeric", "text"]
    );

    let legacy = parse_and_extract_statement(
        "CREATE AGGREGATE legacy_total (
                BASETYPE = integer,
                SFUNC = int4pl,
                STYPE = integer
            );",
    )
    .expect("legacy aggregate fact");
    let StatementFact::CreateAggregate(legacy) = legacy else {
        panic!("expected legacy create aggregate fact");
    };
    assert_eq!(legacy.params.len(), 1);
    assert_eq!(legacy.params[0].ty, "integer");
    assert_eq!(
        legacy.kind,
        crate::_internal::model::aggregate::AggregateKind::Normal
    );
    assert_eq!(legacy.direct_count, 1);
}

#[test]
fn create_aggregate_records_ordered_and_hypothetical_kinds() {
    let ordered = parse_and_extract_statement(
        "CREATE AGGREGATE my_percentile(double precision ORDER BY double precision) (
                SFUNC = ordered_set_transition,
                STYPE = internal,
                FINALFUNC = percentile_final
            );",
    )
    .expect("ordered-set create aggregate fact");
    let StatementFact::CreateAggregate(ordered) = ordered else {
        panic!("expected create aggregate fact");
    };
    assert_eq!(
        ordered.kind,
        crate::_internal::model::aggregate::AggregateKind::OrderedSet
    );
    assert_eq!(ordered.direct_count, 1);
    assert_eq!(ordered.params.len(), 2);
    assert_eq!(ordered.params[0].ty, "double precision");
    assert_eq!(ordered.params[1].ty, "double precision");

    let hypothetical = parse_and_extract_statement(
        "CREATE AGGREGATE my_rank(VARIADIC \"any\" ORDER BY VARIADIC \"any\") (
                SFUNC = ordered_set_transition,
                STYPE = internal,
                FINALFUNC = rank_final,
                HYPOTHETICAL
            );",
    )
    .expect("hypothetical create aggregate fact");
    let StatementFact::CreateAggregate(hypothetical) = hypothetical else {
        panic!("expected create aggregate fact");
    };
    assert_eq!(
        hypothetical.kind,
        crate::_internal::model::aggregate::AggregateKind::Hypothetical
    );
    assert_eq!(hypothetical.direct_count, 1);
    assert_eq!(hypothetical.params.len(), 2);
}

#[test]
fn squawk_264_function_types_preserve_percent_and_table_signatures() {
    let fact = parse_and_extract_statement(
        "CREATE FUNCTION typed(value app.items.amount%TYPE)
             RETURNS TABLE (label character varying(40), amount numeric, source app.items%TYPE)
             LANGUAGE sql AS 'SELECT NULL, NULL, NULL';",
    )
    .expect("typed function fact");
    let StatementFact::CreateFunction(function) = fact else {
        panic!("expected create function fact");
    };
    assert_eq!(function.params.len(), 1);
    assert_eq!(function.params[0].ty, "app.items.amount%TYPE");
    let Some(RetTypeFact::Table(columns)) = function.return_type else {
        panic!("expected table return type");
    };
    assert_eq!(
        columns
            .iter()
            .map(|column| (column.name.as_str(), column.ty.as_deref()))
            .collect::<Vec<_>>(),
        [
            ("label", Some("character varying(40)")),
            ("amount", Some("numeric")),
            ("source", Some("app.items%TYPE")),
        ]
    );
}

#[test]
fn create_function_window_option_is_typed() {
    let fact = parse_and_extract_statement(
        "CREATE FUNCTION ranked() RETURNS bigint AS 'window_row_number' LANGUAGE internal WINDOW;",
    )
    .expect("window function fact");
    let StatementFact::CreateFunction(function) = fact else {
        panic!("expected create function fact");
    };
    assert!(function.options.iter().any(|option| matches!(
        option,
        crate::_internal::analysis::facts::FuncOptionFact::Window
    )));
}

#[test]
fn test_create_view() {
    let sql = "CREATE VIEW user_view AS SELECT id, name FROM users;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateView { name, .. } => {
            assert_eq!(name.name.resolve(), "user_view");
        }
        _ => panic!("Expected CreateView fact"),
    }
}

#[test]
fn test_drop_view() {
    let sql = "DROP VIEW user_view CASCADE;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::DropView { names, cascade, .. } => {
            assert_eq!(names.len(), 1);
            assert_eq!(names[0].name.resolve(), "user_view");
            assert!(cascade);
        }
        _ => panic!("Expected DropView fact"),
    }
}

#[test]
fn test_create_materialized_view() {
    let sql = "CREATE MATERIALIZED VIEW mv_users AS SELECT * FROM users;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateMaterializedView { name, .. } => {
            assert_eq!(name.name.resolve(), "mv_users");
        }
        _ => panic!("Expected CreateMaterializedView fact"),
    }
}

#[test]
fn test_drop_materialized_view() {
    let sql = "DROP MATERIALIZED VIEW mv_users;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::DropMaterializedView { names, .. } => {
            assert!(!names.is_empty());
        }
        _ => panic!("Expected DropMaterializedView fact"),
    }
}

#[test]
fn test_refresh_materialized_view() {
    let sql = "REFRESH MATERIALIZED VIEW mv_users;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::RefreshMaterializedView { name, .. } => {
            assert_eq!(name.name.resolve(), "mv_users");
        }
        _ => panic!("Expected RefreshMaterializedView fact"),
    }
}

#[test]
fn nested_function_arguments_preserve_volatility() {
    let volatile = ExprIr::FunctionCall {
        name: "coalesce".into(),
        args: vec![ExprIr::FunctionCall {
            name: "random".into(),
            args: vec![],
        }],
    };
    let stable = ExprIr::FunctionCall {
        name: "coalesce".into(),
        args: vec![ExprIr::FunctionCall {
            name: "now".into(),
            args: vec![],
        }],
    };

    assert!(volatile.is_volatile());
    assert!(!stable.is_volatile());
}

#[test]
fn squawk_264_typed_alter_table_children_preserve_facts() {
    let facts = parse_and_extract(
        "ALTER TABLE events ADD COLUMN generated_id bigint GENERATED ALWAYS AS IDENTITY;
             ALTER TABLE events ADD CONSTRAINT events_parent_fk
                 FOREIGN KEY (parent_id) REFERENCES parents(id) NOT VALID;
             ALTER TABLE events ADD CONSTRAINT events_id_positive
                 CHECK (generated_id > 0) NOT VALID;
             ALTER TABLE events DISABLE TRIGGER ALL;
             ALTER TABLE events ENABLE TRIGGER audit_log;
             ALTER TABLE events REPLICA IDENTITY USING INDEX events_identity_idx;",
    );
    assert_eq!(facts.len(), 6);

    assert!(matches!(
        &facts[0],
        StatementFact::AlterTable { actions, .. }
            if matches!(
                actions.as_slice(),
                [AlterTableActionFact::AddColumn {
                    name,
                    generation: crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways,
                    not_null: true,
                    ..
                }] if name == "generated_id"
            )
    ));
    assert!(matches!(
        &facts[1],
        StatementFact::AlterTable { actions, .. }
            if matches!(
                actions.as_slice(),
                [AlterTableActionFact::AddForeignKey {
                    constraint_name: Some(name),
                    from_columns,
                    to_columns,
                    not_valid: true,
                    ..
                }] if name == "events_parent_fk"
                    && from_columns == &["parent_id".to_string()]
                    && to_columns == &["id".to_string()]
            )
    ));
    assert!(matches!(
        &facts[2],
        StatementFact::AlterTable { actions, .. }
            if matches!(
                actions.as_slice(),
                [AlterTableActionFact::AddCheckConstraint {
                    constraint_name: Some(name),
                    columns,
                    not_valid: true,
                    columns_complete: true,
                    definition: _,
                }] if name == "events_id_positive"
                    && columns == &["generated_id".to_string()]
            )
    ));
    assert!(matches!(
        &facts[3],
        StatementFact::AlterTable { actions, .. }
            if matches!(
                actions.as_slice(),
                [AlterTableActionFact::DisableTrigger { trigger_name: Some(name) }]
                    if name == "ALL"
            )
    ));
    assert!(matches!(
        &facts[4],
        StatementFact::AlterTable { actions, .. }
            if matches!(
                actions.as_slice(),
                [AlterTableActionFact::EnableTrigger { trigger_name: Some(name) }]
                    if name == "audit_log"
            )
    ));
    assert!(matches!(
        &facts[5],
        StatementFact::AlterTable { actions, .. }
            if matches!(
                actions.as_slice(),
                [AlterTableActionFact::ReplicaIdentity {
                    option: crate::_internal::analysis::facts::ReplicaIdentityFact::UsingIndex(index)
                }]
                    if index.name.resolve() == "events_identity_idx"
            )
    ));
}

#[test]
fn alter_table_rule_modes_use_typed_names_and_modes() {
    let facts = parse_and_extract(
        "ALTER TABLE events ENABLE RULE rewrite_rule;
             ALTER TABLE events DISABLE RULE rewrite_rule;
             ALTER TABLE events ENABLE REPLICA RULE rewrite_rule;
             ALTER TABLE events ENABLE ALWAYS RULE rewrite_rule;",
    );
    let expected = [
        crate::_internal::analysis::facts::RuleEnableModeFact::Origin,
        crate::_internal::analysis::facts::RuleEnableModeFact::Disabled,
        crate::_internal::analysis::facts::RuleEnableModeFact::Replica,
        crate::_internal::analysis::facts::RuleEnableModeFact::Always,
    ];
    assert_eq!(facts.len(), expected.len());
    for (fact, expected_mode) in facts.iter().zip(expected) {
        assert!(matches!(
            fact,
            StatementFact::AlterTable { actions, .. }
                if matches!(actions.as_slice(), [AlterTableActionFact::SetRuleMode { rule_name: Some(name), mode }]
                    if name == "rewrite_rule" && *mode == expected_mode)
        ));
    }
}

#[test]
fn typed_column_storage_and_generated_expression_options_preserve_values() {
    let facts = parse_and_extract(
        "ALTER TABLE events ALTER COLUMN payload SET STORAGE EXTERNAL;
             ALTER TABLE events ALTER COLUMN payload SET COMPRESSION lz4;
             ALTER TABLE events ALTER COLUMN payload SET COMPRESSION DEFAULT;
             ALTER TABLE events ALTER COLUMN payload SET STATISTICS 100;
             ALTER TABLE events ALTER COLUMN payload SET (n_distinct = -0.5);
             ALTER TABLE events ALTER COLUMN payload RESET (n_distinct);
             ALTER TABLE events ALTER COLUMN payload SET EXPRESSION AS (source_id + 1);
             ALTER TABLE events ALTER COLUMN payload DROP EXPRESSION IF EXISTS;",
    );
    assert!(matches!(
        &facts[0],
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::SetStorage { column, mode }]
                if column == "payload" && mode == "EXTERNAL")
    ));
    assert!(matches!(
        &facts[1],
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::SetCompression { column, method }]
                if column == "payload" && method.as_deref() == Some("lz4"))
    ));
    assert!(matches!(
        &facts[2],
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::SetCompression { method: None, .. }])
    ));
    assert!(matches!(
        &facts[3],
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::SetStatistics { column, target }]
                if column == "payload" && target == &Some(100))
    ));
    assert!(matches!(
        &facts[4],
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::SetOptions { column, attributes }]
                if column == "payload"
                    && attributes.len() == 1
                    && attributes[0].name == "n_distinct"
                    && attributes[0].value.as_deref() == Some("-0.5"))
    ));
    assert!(matches!(
        &facts[5],
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::ResetOptions { column, attributes }]
                if column == "payload"
                    && attributes.len() == 1
                    && attributes[0].name == "n_distinct"
                    && attributes[0].value.is_none())
    ));
    assert!(matches!(
        &facts[6],
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::SetExpression { column, .. }]
                if column == "payload")
    ));
    assert!(matches!(
        &facts[7],
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::DropExpression { column, if_exists }]
                if column == "payload" && *if_exists)
    ));
}

#[test]
fn typed_column_default_metadata_options_preserve_reset_semantics() {
    let facts = parse_and_extract(
        "ALTER TABLE events ALTER COLUMN payload SET STORAGE DEFAULT;
             ALTER TABLE events ALTER COLUMN payload SET STATISTICS DEFAULT;",
    );
    assert!(matches!(
        &facts[0],
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::SetStorage { mode, .. }]
                if mode == "DEFAULT")
    ));
    assert!(matches!(
        &facts[1],
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::SetStatistics { target: None, .. }])
    ));
}

#[test]
fn create_view_with_check_option_carries_the_option_and_updatability() {
    let facts = parse_and_extract_statement(
        "CREATE VIEW writable AS SELECT id FROM source WITH CHECK OPTION;",
    )
    .expect("a check-option view is modeled");
    let StatementFact::CreateView {
        options,
        updatability,
        ..
    } = facts
    else {
        panic!("expected CreateView");
    };
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].name, "check_option");
    assert_eq!(options[0].value.as_deref(), Some("cascaded"));
    assert_eq!(updatability, ViewUpdatabilityFact::Updatable);

    let StatementFact::CreateView {
        options,
        updatability,
        ..
    } = parse_and_extract_statement(
        "CREATE VIEW writable AS SELECT id FROM source WITH LOCAL CHECK OPTION;",
    )
    .expect("view fact")
    else {
        panic!("expected CreateView");
    };
    assert_eq!(options[0].value.as_deref(), Some("local"));
    assert_eq!(updatability, ViewUpdatabilityFact::Updatable);
}

#[test]
fn create_view_records_unqualified_aggregate_candidates() {
    let StatementFact::CreateView {
        updatability,
        updatability_without_aggregates,
        aggregate_candidates,
        ..
    } = parse_and_extract_statement(
        "CREATE VIEW v AS SELECT a, sum(b) AS s FROM t WITH CHECK OPTION;",
    )
    .expect("view fact")
    else {
        panic!("expected CreateView");
    };
    assert_eq!(
        aggregate_candidates,
        vec![AggregateCandidateFact {
            name: "sum".to_string(),
            explicit: false,
            star: false,
            aggregate_only_clause: None,
            arguments: vec![AggregateArgumentFact::Column("b".to_string())],
            within_group: Vec::new(),
            nested: false,
            references: vec![AggregateReferenceFact {
                qualifier: None,
                name: "b".to_string(),
            }],
            scopes: Vec::new(),
            contains_subquery: false,
        }]
    );
    assert_eq!(
        updatability,
        ViewUpdatabilityFact::NotUpdatable(ViewUpdatabilityReason::Aggregate)
    );
    assert_eq!(
        updatability_without_aggregates,
        ViewUpdatabilityFact::Updatable
    );

    // An explicit `pg_catalog` aggregate is settled, not a candidate.
    let StatementFact::CreateView {
        updatability,
        aggregate_candidates,
        ..
    } = parse_and_extract_statement(
        "CREATE VIEW v AS SELECT pg_catalog.sum(b) AS s FROM t WITH CHECK OPTION;",
    )
    .expect("view fact")
    else {
        panic!("expected CreateView");
    };
    assert!(aggregate_candidates.is_empty());
    assert_eq!(
        updatability,
        ViewUpdatabilityFact::NotUpdatable(ViewUpdatabilityReason::Aggregate)
    );
}

#[test]
fn create_view_marks_explicit_variadic_aggregate_arguments() {
    let StatementFact::CreateView {
        aggregate_candidates,
        ..
    } = parse_and_extract_statement(
        "CREATE VIEW v AS SELECT a, sum(VARIADIC NULL::int[]) AS s FROM t WITH CHECK OPTION;",
    )
    .expect("view fact")
    else {
        panic!("expected CreateView");
    };
    assert_eq!(
        aggregate_candidates,
        vec![AggregateCandidateFact {
            name: "sum".to_string(),
            explicit: false,
            star: false,
            aggregate_only_clause: None,
            arguments: vec![AggregateArgumentFact::Variadic(Box::new(
                AggregateArgumentFact::Typed("int[]".to_string())
            ))],
            within_group: Vec::new(),
            nested: false,
            references: Vec::new(),
            scopes: Vec::new(),
            contains_subquery: false,
        }]
    );
}

#[test]
fn create_view_ignores_calls_inside_nested_queries() {
    // A nested query's calls belong to that query, not the view, so an
    // aggregate, a window function or an unplaceable call inside one never
    // disqualifies the outer view. Verified accepted on PostgreSQL 18.6.
    let facts = |sql: &str| match parse_and_extract_statement(sql).expect("view fact") {
        StatementFact::CreateView {
            updatability,
            aggregate_candidates,
            ..
        } => (updatability, aggregate_candidates),
        other => panic!("expected CreateView, got {other:?}"),
    };
    for sql in [
        "CREATE VIEW v AS SELECT a, (SELECT sum(o.amount) FROM o WHERE o.id = t.id) AS total FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, (SELECT row_number() OVER () FROM o) AS r FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, (SELECT upper(o.x) FROM o) AS u FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, (SELECT sum(t.b) FROM o AS t) AS s FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, (SELECT sum(t.b) FROM t) AS s FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, EXISTS (SELECT sum(o.amount) FROM o) AS e FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, a = ANY (SELECT sum(o.amount) FROM o) AS m FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, ARRAY(SELECT sum(o.amount) FROM o) AS y FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, a IN (SELECT sum(o.amount) FROM o) AS i FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, (SELECT sum(t.b) FROM (SELECT 1 AS b) AS t) AS s FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, (SELECT sum(t.b) FROM o JOIN (SELECT 1 AS b) AS t ON true) AS s FROM t WITH CHECK OPTION;",
        "CREATE VIEW v AS SELECT a, (SELECT (SELECT sum(t.b)) FROM (SELECT 1 AS b) AS t) AS s FROM t WITH CHECK OPTION;",
    ] {
        let (updatability, candidates) = facts(sql);
        assert_eq!(updatability, ViewUpdatabilityFact::Updatable, "{sql}");
        assert!(candidates.is_empty(), "{sql}");
    }
}

#[test]
fn create_view_promotes_a_correlated_aggregate_to_the_outer_query() {
    let StatementFact::CreateView {
        updatability,
        updatability_without_aggregates,
        aggregate_candidates,
        ..
    } = parse_and_extract_statement(
        "CREATE VIEW v AS SELECT a, (SELECT sum(t.b)) AS s FROM t AS t WITH CHECK OPTION;",
    )
    .expect("view fact")
    else {
        panic!("expected CreateView");
    };
    assert_eq!(
        aggregate_candidates,
        vec![AggregateCandidateFact {
            name: "sum".to_string(),
            explicit: false,
            star: false,
            aggregate_only_clause: None,
            arguments: vec![AggregateArgumentFact::Field {
                base: Box::new(AggregateArgumentFact::Column("t".to_string())),
                field: "b".to_string(),
            }],
            within_group: Vec::new(),
            nested: true,
            references: vec![AggregateReferenceFact {
                qualifier: Some("t".to_string()),
                name: "b".to_string(),
            }],
            scopes: vec![AggregateScopeFact {
                bindings: Vec::new(),
                unknown: false,
            }],
            contains_subquery: false,
        }]
    );
    assert_eq!(
        updatability,
        ViewUpdatabilityFact::NotUpdatable(ViewUpdatabilityReason::Aggregate)
    );
    assert_eq!(
        updatability_without_aggregates,
        ViewUpdatabilityFact::Updatable
    );
}

#[test]
fn create_view_promotes_a_correlated_aggregate_through_nested_query_levels() {
    let StatementFact::CreateView {
        updatability,
        aggregate_candidates,
        ..
    } = parse_and_extract_statement(
        "CREATE VIEW v AS SELECT a, (SELECT (SELECT sum(t.b)) FROM o) AS s FROM t WITH CHECK OPTION;",
    )
    .expect("view fact")
    else {
        panic!("expected CreateView");
    };
    assert_eq!(aggregate_candidates.len(), 1);
    assert_eq!(
        updatability,
        ViewUpdatabilityFact::NotUpdatable(ViewUpdatabilityReason::Aggregate)
    );
}

#[test]
fn create_view_records_aggregate_only_call_forms() {
    let candidate = |sql: &str| match parse_and_extract_statement(sql).expect("view fact") {
        StatementFact::CreateView {
            aggregate_candidates,
            ..
        } => aggregate_candidates.into_iter().next().expect("candidate"),
        other => panic!("expected CreateView, got {other:?}"),
    };
    let star = candidate("CREATE VIEW v AS SELECT count(*) AS n FROM t WITH CHECK OPTION;");
    assert!(star.star);
    assert_eq!(star.aggregate_only_clause, None);
    assert!(star.arguments.is_empty());

    for (sql, clause) in [
        (
            "CREATE VIEW v AS SELECT sum(DISTINCT b) AS s FROM t WITH CHECK OPTION;",
            AggregateOnlyClauseFact::Distinct,
        ),
        (
            "CREATE VIEW v AS SELECT sum(b) FILTER (WHERE b > 0) AS s FROM t WITH CHECK OPTION;",
            AggregateOnlyClauseFact::Filter,
        ),
        (
            "CREATE VIEW v AS SELECT sum(b ORDER BY b) AS s FROM t WITH CHECK OPTION;",
            AggregateOnlyClauseFact::OrderBy,
        ),
        (
            "CREATE VIEW v AS SELECT sum(b) WITHIN GROUP (ORDER BY b) AS s FROM t WITH CHECK OPTION;",
            AggregateOnlyClauseFact::WithinGroup,
        ),
    ] {
        assert_eq!(candidate(sql).aggregate_only_clause, Some(clause));
    }

    let ordered = candidate(
        "CREATE VIEW v AS SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY b) AS p FROM t WITH CHECK OPTION;",
    );
    assert_eq!(
        ordered.within_group,
        vec![AggregateArgumentFact::Column("b".to_string())]
    );
    assert_eq!(
        ordered.references,
        vec![AggregateReferenceFact {
            qualifier: None,
            name: "b".to_string(),
        }]
    );
}

#[test]
fn create_view_keeps_composite_field_bases() {
    let candidate = |sql: &str| match parse_and_extract_statement(sql).expect("view fact") {
        StatementFact::CreateView {
            aggregate_candidates,
            ..
        } => aggregate_candidates.into_iter().next().expect("candidate"),
        other => panic!("expected CreateView, got {other:?}"),
    };
    assert_eq!(
        candidate("CREATE VIEW v AS SELECT sum((p).y) AS s FROM t WITH CHECK OPTION;").arguments,
        vec![AggregateArgumentFact::Field {
            base: Box::new(AggregateArgumentFact::Column("p".to_string())),
            field: "y".to_string(),
        }]
    );
    assert_eq!(
        candidate("CREATE VIEW v AS SELECT sum(t.a) AS s FROM t WITH CHECK OPTION;").arguments,
        vec![AggregateArgumentFact::Field {
            base: Box::new(AggregateArgumentFact::Column("t".to_string())),
            field: "a".to_string(),
        }]
    );
    assert_eq!(
        candidate("CREATE VIEW v AS SELECT sum(make_pair().y) AS s FROM t WITH CHECK OPTION;")
            .arguments,
        vec![AggregateArgumentFact::Field {
            base: Box::new(AggregateArgumentFact::Unknown),
            field: "y".to_string(),
        }]
    );
}

#[test]
fn create_view_updatability_matches_postgres_refusals() {
    let updatability = |sql: &str| match parse_and_extract_statement(sql).expect("view fact") {
        StatementFact::CreateView { updatability, .. } => updatability,
        other => panic!("expected CreateView, got {other:?}"),
    };
    let refused = |reason| ViewUpdatabilityFact::NotUpdatable(reason);
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT DISTINCT a FROM t WITH CHECK OPTION;"),
        refused(ViewUpdatabilityReason::Distinct)
    );
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT count(*) FROM t WITH CHECK OPTION;"),
        refused(ViewUpdatabilityReason::Aggregate)
    );
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT a FROM t GROUP BY a WITH CHECK OPTION;"),
        refused(ViewUpdatabilityReason::GroupBy)
    );
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT a FROM t HAVING count(*) > 0 WITH CHECK OPTION;"),
        refused(ViewUpdatabilityReason::Having)
    );
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT a FROM t LIMIT 1 WITH CHECK OPTION;"),
        refused(ViewUpdatabilityReason::Limit)
    );
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT a FROM t UNION SELECT a FROM t WITH CHECK OPTION;"),
        refused(ViewUpdatabilityReason::SetOperation)
    );
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT a FROM t, u WITH CHECK OPTION;"),
        refused(ViewUpdatabilityReason::SingleRelation)
    );
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT t FROM t WITH CHECK OPTION;"),
        refused(ViewUpdatabilityReason::NoUpdatableColumns)
    );
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT ctid FROM t WITH CHECK OPTION;"),
        refused(ViewUpdatabilityReason::NoUpdatableColumns)
    );
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT a FROM t WHERE b > 0 WITH CHECK OPTION;"),
        ViewUpdatabilityFact::Updatable
    );
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT * FROM t WITH CHECK OPTION;"),
        ViewUpdatabilityFact::Updatable
    );
    // A call the analyzer cannot place might be set-returning, so it stays
    // unknown rather than guessing a refusal.
    assert_eq!(
        updatability("CREATE VIEW v AS SELECT upper('x') FROM t WITH CHECK OPTION;"),
        ViewUpdatabilityFact::Unknown
    );
}

#[test]
fn create_view_carries_its_explicit_column_list() {
    let names = |sql: &str| {
        let parsed = SourceFile::parse(sql);
        let statement = parsed.tree().stmts().next().expect("statement");
        match AstVisitor::extract(&statement).expect("view fact") {
            StatementFact::CreateView { column_list, .. } => column_list,
            other => panic!("expected CreateView, got {other:?}"),
        }
    };
    assert_eq!(
        names("CREATE VIEW renamed (x, y) AS SELECT a, b FROM source;"),
        vec!["x".to_string(), "y".to_string()]
    );
    assert!(names("CREATE VIEW plain AS SELECT a FROM source;").is_empty());
}

#[test]
fn create_materialized_view_carries_its_explicit_column_list() {
    let names = |sql: &str| {
        let parsed = SourceFile::parse(sql);
        let statement = parsed.tree().stmts().next().expect("statement");
        match AstVisitor::extract(&statement).expect("materialized view fact") {
            StatementFact::CreateMaterializedView { column_list, .. } => column_list,
            other => panic!("expected CreateMaterializedView, got {other:?}"),
        }
    };
    assert_eq!(
        names("CREATE MATERIALIZED VIEW renamed (x) AS SELECT a FROM source;"),
        vec!["x".to_string()]
    );
    assert!(names("CREATE MATERIALIZED VIEW plain AS SELECT a FROM source;").is_empty());
}

#[test]
fn create_materialized_view_carries_its_population_and_guard() {
    let population = |sql: &str| {
        let parsed = SourceFile::parse(sql);
        let statement = parsed.tree().stmts().next().expect("statement");
        match AstVisitor::extract(&statement).expect("materialized view fact") {
            StatementFact::CreateMaterializedView {
                with_no_data,
                if_not_exists,
                ..
            } => (with_no_data, if_not_exists),
            other => panic!("expected CreateMaterializedView, got {other:?}"),
        }
    };
    assert_eq!(
        population("CREATE MATERIALIZED VIEW snapshot AS SELECT id FROM source;"),
        (false, false)
    );
    assert_eq!(
        population("CREATE MATERIALIZED VIEW snapshot AS SELECT id FROM source WITH NO DATA;"),
        (true, false)
    );
    assert_eq!(
        population("CREATE MATERIALIZED VIEW IF NOT EXISTS snapshot AS SELECT id FROM source;"),
        (false, true)
    );
}

#[test]
fn unsupported_create_domain_constraints_are_not_silent() {
    for sql in [
        "CREATE DOMAIN bounded AS integer CHECK (VALUE > 0);",
        "CREATE DOMAIN collated AS text COLLATE \"C\";",
    ] {
        let parsed = SourceFile::parse(sql);
        let statement = parsed.tree().stmts().next().expect("statement");
        assert!(
            AstVisitor::extract(&statement).is_none(),
            "unmodeled CREATE DOMAIN semantics must use the opaque engine path: {sql}"
        );
    }
}

#[test]
fn range_and_base_types_match_the_synced_catalog_kinds() {
    // The cache reports these kinds from `pg_type.typtype`, so a type
    // created by the migration must be modeled the same way.
    for (sql, expected) in [
        (
            "CREATE TYPE floatrange AS RANGE (subtype = float8);",
            TypeCreationKind::Range {
                subtype: Some("float8".to_string()),
            },
        ),
        (
            "CREATE TYPE my_input (INPUT = int4in, OUTPUT = int4out);",
            TypeCreationKind::Base { element: None },
        ),
        (
            // PostgreSQL spells the base-type element `ELEMENT`; `typelem`
            // is only the catalog column name.
            "CREATE TYPE my_input (INPUT = int4in, OUTPUT = int4out, ELEMENT = int4);",
            TypeCreationKind::Base {
                element: Some("int4".to_string()),
            },
        ),
    ] {
        let parsed = SourceFile::parse(sql);
        let statement = parsed.tree().stmts().next().expect("statement");
        let Some(StatementFact::CreateType(crate::_internal::analysis::facts::CreateTypeFact {
            kind,
            ..
        })) = AstVisitor::extract(&statement)
        else {
            panic!("expected a typed CREATE TYPE fact: {sql}");
        };
        assert_eq!(kind, expected, "unexpected creation kind for: {sql}");
    }
}

#[test]
fn unsupported_create_policy_semantics_are_not_silent() {
    for sql in [
        "CREATE POLICY scoped ON source TO app_user;",
        "CREATE POLICY filtered ON source USING (id > 0);",
        "CREATE POLICY checked ON source WITH CHECK (id > 0);",
    ] {
        let parsed = SourceFile::parse(sql);
        let statement = parsed.tree().stmts().next().expect("statement");
        let Some(StatementFact::CreatePolicy {
            semantics_complete, ..
        }) = AstVisitor::extract(&statement)
        else {
            panic!("expected policy fact retaining rule-visible semantics: {sql}");
        };
        assert!(
            !semantics_complete,
            "policy semantics must be marked incomplete: {sql}"
        );
    }
}

#[test]
fn unsupported_alter_type_actions_are_not_silent_noops() {
    for sql in [
        "ALTER TYPE mood OWNER TO app_user;",
        "ALTER TYPE mood ADD ATTRIBUTE label text;",
    ] {
        let parsed = SourceFile::parse(sql);
        let statement = parsed.tree().stmts().next().expect("statement");
        assert!(
            AstVisitor::extract(&statement).is_none(),
            "unsupported ALTER TYPE action must use the opaque engine path: {sql}"
        );
    }
}

#[test]
fn alter_materialized_view_actions_produce_typed_facts_not_opaque_paths() {
    use crate::_internal::analysis::facts::AlterMaterializedViewActionFact;

    let extract_matview_action = |sql: &str| {
        let parsed = SourceFile::parse(sql);
        let stmt = parsed.tree().stmts().next().expect("statement");
        match AstVisitor::extract(&stmt).unwrap_or_else(|| panic!("no fact for: {sql}")) {
            StatementFact::AlterMaterializedView { actions, .. } => {
                actions.into_iter().next().expect("at least one action")
            }
            other => panic!("expected AlterMaterializedView fact, got {other:?} for: {sql}"),
        }
    };

    assert!(matches!(
        extract_matview_action("ALTER MATERIALIZED VIEW mv SET SCHEMA archive;"),
        AlterMaterializedViewActionFact::SetSchema { new_schema } if new_schema == "archive"
    ));
    assert!(matches!(
        extract_matview_action("ALTER MATERIALIZED VIEW mv SET (fillfactor = 90);"),
        AlterMaterializedViewActionFact::SetOptions { .. }
    ));
    assert!(matches!(
        extract_matview_action("ALTER MATERIALIZED VIEW mv CLUSTER ON my_idx;"),
        AlterMaterializedViewActionFact::ClusterOn { index_name } if index_name.resolve() == "my_idx"
    ));
}

#[test]
fn alter_view_column_and_options_produce_typed_facts_not_opaque_paths() {
    // SET DEFAULT, DROP DEFAULT, SET/RESET OPTIONS are parsed-valid view
    // mutations that produce typed facts, which the resolver turns into
    // SetColumnDefault/SetReloptions/ResetReloptions mutations.
    use crate::_internal::analysis::facts::AlterViewAction;

    let extract_view_action = |sql: &str| {
        let parsed = SourceFile::parse(sql);
        let stmt = parsed.tree().stmts().next().expect("statement");
        match AstVisitor::extract(&stmt).unwrap_or_else(|| panic!("no fact for: {sql}")) {
            StatementFact::AlterView { action, .. } => action,
            other => panic!("expected AlterView fact, got {other:?} for: {sql}"),
        }
    };

    assert!(matches!(
        extract_view_action("ALTER VIEW report ALTER COLUMN total SET DEFAULT 0;"),
        AlterViewAction::SetDefault { column, .. } if column == "total"
    ));
    assert!(matches!(
        extract_view_action("ALTER VIEW report ALTER COLUMN total DROP DEFAULT;"),
        AlterViewAction::DropDefault { column } if column == "total"
    ));
    assert!(matches!(
        extract_view_action("ALTER VIEW report SET (security_barrier = true);"),
        AlterViewAction::SetOptions { .. }
    ));
    assert!(matches!(
        extract_view_action("ALTER VIEW report RESET (security_invoker);"),
        AlterViewAction::ResetOptions { .. }
    ));
}

#[test]
fn squawk_264_typed_view_sequence_policy_and_function_children_preserve_facts() {
    let facts = parse_and_extract(
        "CREATE SEQUENCE event_ids OWNED BY public.events.id;
             ALTER SEQUENCE event_ids OWNED BY NONE;
             CREATE POLICY readers ON events FOR SELECT TO PUBLIC USING (true);
             CREATE FUNCTION stable_owner() RETURNS integer
                 LANGUAGE sql IMMUTABLE SECURITY DEFINER AS 'SELECT 1';",
    );
    assert_eq!(facts.len(), 4);
    assert!(matches!(
        &facts[0],
        StatementFact::CreateSequence {
            owned_by: Some((table, column)),
            ..
        } if table.schema.as_ref().map(Ident::resolve).as_deref() == Some("public")
            && table.name.resolve() == "events"
            && column == "id"
    ));
    assert!(matches!(
        &facts[1],
        StatementFact::AlterSequence {
            options,
            ..
        } if matches!(
            options.as_slice(),
            [crate::_internal::analysis::facts::SequenceOptionFact::OwnedBy(None)]
        )
    ));
    assert!(matches!(
        &facts[2],
        StatementFact::CreatePolicy {
            command: crate::_internal::analysis::facts::PolicyCommand::Select,
            ..
        }
    ));
    let StatementFact::CreateFunction(function) = &facts[3] else {
        panic!("expected create function fact");
    };
    assert!(function.options.iter().any(|option| matches!(
        option,
        crate::_internal::analysis::facts::FuncOptionFact::Volatility(
            crate::_internal::analysis::facts::VolatilityKind::Immutable
        )
    )));
    assert!(function.options.iter().any(|option| matches!(
        option,
        crate::_internal::analysis::facts::FuncOptionFact::Security(
            crate::_internal::analysis::facts::SecurityKind::Definer
        )
    )));
}

#[test]
fn create_sequence_preserves_typed_parameters_and_persistence() {
    let facts = parse_and_extract(
        "CREATE UNLOGGED SEQUENCE public.event_ids AS integer INCREMENT BY -3 \
             MINVALUE -99 MAXVALUE -3 START WITH -3 CACHE 7 CYCLE;",
    );
    let StatementFact::CreateSequence {
        persistence,
        options,
        ..
    } = &facts[0]
    else {
        panic!("expected create sequence fact");
    };
    assert_eq!(
        *persistence,
        crate::_internal::analysis::facts::PersistenceFact::Unlogged
    );
    assert_eq!(options.data_type.as_deref(), Some("integer"));
    assert_eq!(options.increment, Some(-3));
    assert_eq!(options.min_value, Some(Some(-99)));
    assert_eq!(options.max_value, Some(Some(-3)));
    assert_eq!(options.start_value, Some(-3));
    assert_eq!(options.cache_size, Some(7));
    assert_eq!(options.cycle, Some(true));
}

#[test]
fn function_options_use_typed_targets_and_decode_literals() {
    let fact = parse_and_extract_statement(
            "CREATE FUNCTION native_fn() RETURNS integer LANGUAGE c PARALLEL SAFE NOT LEAKPROOF AS 'lib''x', 'entry''x';",
        )
        .expect("create function fact");
    let StatementFact::CreateFunction(function) = fact else {
        panic!("expected create function fact");
    };
    assert!(function.options.iter().any(|option| matches!(
        option,
        crate::_internal::analysis::facts::FuncOptionFact::Parallel(value) if value == "safe"
    )));
    assert!(function.options.iter().any(|option| matches!(
        option,
        crate::_internal::analysis::facts::FuncOptionFact::Leakproof(false)
    )));
    assert!(function.options.iter().any(|option| matches!(
        option,
        crate::_internal::analysis::facts::FuncOptionFact::As {
            obj_file: Some(obj_file),
            link_symbol: Some(link_symbol),
            definition: None,
        } if obj_file == "lib'x" && link_symbol == "entry'x"
    )));
}

#[test]
fn squawk_264_typed_replication_and_privilege_children_preserve_facts() {
    let facts = parse_and_extract(
        "CREATE PUBLICATION all_events FOR ALL TABLES EXCEPT TABLE audit_events;
             CREATE PUBLICATION selected_events FOR TABLE public.events;
             CREATE SUBSCRIPTION event_sub SERVER event_server
                 PUBLICATION selected_events WITH (connect = false);
             ALTER SUBSCRIPTION event_sub SERVER replacement_server;
             GRANT ALL PRIVILEGES ON TABLE public.events TO app_user GRANTED BY admin;
             REVOKE GRANT OPTION FOR SELECT ON TABLE public.events
                 FROM app_user GRANTED BY admin CASCADE;",
    );
    assert_eq!(facts.len(), 6);

    assert!(matches!(
        &facts[0],
        StatementFact::CreatePublication(publication)
            if publication.name == "all_events"
                && publication.scope
                    == PublicationScope::AllTables { except: vec!["audit_events".into()] }
    ));
    assert!(matches!(
        &facts[1],
        StatementFact::CreatePublication(publication)
            if matches!(&publication.scope, PublicationScope::Explicit(objects) if objects.len() == 1)
    ));
    assert!(matches!(
        &facts[2],
        StatementFact::CreateSubscription(subscription)
            if subscription.connection
                == crate::_internal::analysis::facts::ConnectionTarget::Server(
                    Some("event_server".into())
                )
    ));
    assert!(matches!(
        &facts[3],
        StatementFact::AlterSubscription(subscription)
            if subscription.action
                == AlterSubscriptionActionFact::SetServer(Some("replacement_server".into()))
    ));
    assert!(matches!(
        &facts[4],
        StatementFact::Grant(grant)
            if grant.privileges == crate::_internal::analysis::facts::PrivilegeSpec::All
                && grant.granted_by
                    == Some(crate::_internal::analysis::facts::RoleFact::Named {
                        name: "admin".into(),
                        via_legacy_group_syntax: false,
                    })
    ));
    assert!(matches!(
        &facts[5],
        StatementFact::Revoke(revoke)
            if revoke.grant_option_only
                && revoke.cascade
                && revoke.privileges
                    == crate::_internal::analysis::facts::PrivilegeSpec::List(vec![
                        crate::_internal::analysis::facts::PrivilegeFact::Select,
                    ])
                && revoke.granted_by
                    == Some(crate::_internal::analysis::facts::RoleFact::Named {
                        name: "admin".into(),
                        via_legacy_group_syntax: false,
                    })
    ));
}
