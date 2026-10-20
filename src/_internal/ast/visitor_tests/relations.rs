use super::*;

#[test]
fn key_constraint_columns_preserve_keyword_and_quoted_names() {
    let facts =
        parse_and_extract("ALTER TABLE items ADD CONSTRAINT items_key UNIQUE (value, \"Mixed\");");
    assert!(
        matches!(&facts[0], StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [AlterTableActionFact::AddUniqueConstraint { columns, .. }]
                if columns == &["value", "Mixed"]))
    );
}

#[test]
fn generated_prefix_operators_preserve_semantics_and_dependencies() {
    for (source, expected) in [("-base", "-"), ("+base", "+"), ("NOT base", "NOT")] {
        let facts = parse_and_extract(&format!(
            "CREATE TABLE expressions (base integer, computed integer GENERATED ALWAYS AS ({source}) STORED);"
        ));
        let StatementFact::CreateTable { columns, .. } = &facts[0] else {
            panic!("expected table")
        };
        let expression = columns[1].generated_expr.as_ref().unwrap();
        assert!(
            matches!(expression, ExprIr::UnaryOp { op, expr } if op == expected && matches!(expr.as_ref(), ExprIr::ColumnRef(name) if name == "base"))
        );
        assert_eq!(
            expression.referenced_columns().unwrap(),
            ["base".into()].into_iter().collect()
        );
        assert!(!expression.contains_opaque());
    }
    let expression = ExprIr::UnaryOp {
        op: "-".into(),
        expr: Box::new(ExprIr::FunctionCall {
            name: "random".into(),
            args: vec![],
        }),
    };
    assert!(expression.is_volatile());
}

#[test]
fn test_create_table_with_columns() {
    let sql = "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(255) NOT NULL);";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateTable { name, columns, .. } => {
            assert_eq!(name.name.resolve(), "users");
            assert_eq!(columns.len(), 2);
        }
        _ => panic!("Expected CreateTable fact"),
    }
}

#[test]
fn create_table_identity_column_is_non_null() {
    let fact = parse_and_extract_statement(
        "CREATE TABLE events (id bigint GENERATED ALWAYS AS IDENTITY);",
    )
    .expect("create table fact");

    let StatementFact::CreateTable { columns, .. } = fact else {
        panic!("expected create table fact");
    };
    assert_eq!(columns.len(), 1);
    assert_eq!(
        columns[0].generation,
        crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
    );
    assert!(columns[0].not_null);
}

#[test]
fn test_create_table_preserves_inline_constraint_names() {
    let fact = parse_and_extract_statement(
        "CREATE TABLE users (
                id integer CONSTRAINT users_pk PRIMARY KEY,
                email text CONSTRAINT users_email_unique UNIQUE,
                tenant_id integer,
                CONSTRAINT users_tenant_unique UNIQUE (tenant_id)
            );",
    )
    .expect("create table fact");

    let StatementFact::CreateTable {
        columns,
        table_constraints,
        ..
    } = fact
    else {
        panic!("expected create table fact");
    };
    assert_eq!(
        columns[0].primary_key_constraint_name.as_deref(),
        Some("users_pk")
    );
    assert_eq!(
        columns[1].unique_constraint_name.as_deref(),
        Some("users_email_unique")
    );
    assert!(matches!(
        &table_constraints[0],
        TableConstraintFact::Unique {
            constraint_name: Some(name),
            columns,
        } if name == "users_tenant_unique" && columns == &["tenant_id"]
    ));
}

#[test]
fn alter_table_preserves_only_scope() {
    for (sql, expected) in [
        ("ALTER TABLE ONLY t RENAME COLUMN a TO b;", true),
        ("ALTER TABLE t RENAME COLUMN a TO b;", false),
    ] {
        assert!(matches!(parse_and_extract_statement(sql),
                Some(StatementFact::AlterTable { only, .. }) if only == expected));
    }
}

#[test]
fn create_table_preserves_table_check_and_exclusion_constraint_names() {
    let fact = parse_and_extract_statement(
        "CREATE TABLE reservations (
                id integer,
                period int4range,
                CONSTRAINT reservations_id_check CHECK (id > 0),
                CONSTRAINT reservations_period_excl EXCLUDE USING gist (period WITH &&)
            );",
    )
    .expect("create table fact");

    let StatementFact::CreateTable {
        table_constraints, ..
    } = fact
    else {
        panic!("expected create table fact");
    };
    assert!(matches!(
        table_constraints.as_slice(),
        [
            TableConstraintFact::Check {
                constraint_name: Some(check),
                name_hint: Some(hint),
                definition: _,
                columns: check_columns,
                columns_complete: check_complete,
            },
            TableConstraintFact::Exclude {
                constraint_name: Some(exclude),
                columns: exclude_columns,
                columns_complete: exclude_complete,
            },
        ] if check == "reservations_id_check"
            && hint == "id"
            && check_columns == &["id".to_string()]
            && exclude == "reservations_period_excl"
            && exclude_columns == &["period".to_string()]
            && *check_complete
            && *exclude_complete
    ));
}

#[test]
fn test_create_table_with_quoted_identifiers() {
    let sql = r#"CREATE TABLE "MyTable" ("MyColumn" INT);"#;
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateTable { name, columns, .. } => {
            assert_eq!(name.name.resolve(), "MyTable");
            assert!(name.name.quoted);
            assert_eq!(columns[0].name, "MyColumn");
        }
        _ => panic!("Expected CreateTable fact"),
    }
}

#[test]
fn test_create_table_with_default_expr() {
    let sql = "CREATE TABLE events (id INT, created_at TIMESTAMP DEFAULT NOW());";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateTable { columns, .. } => {
            assert_eq!(columns.len(), 2);
            // Check default expression
            if let Some(default) = &columns[1].default {
                assert!(!default.is_volatile()); // NOW() is STABLE
            }
        }
        _ => panic!("Expected CreateTable fact"),
    }
}

#[test]
fn test_create_table_unlogged() {
    let sql = "CREATE UNLOGGED TABLE unlogged_table (id INT);";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateTable {
            name, persistence, ..
        } => {
            assert_eq!(name.name.resolve(), "unlogged_table");
            assert!(matches!(
                persistence,
                crate::_internal::analysis::facts::PersistenceFact::Unlogged
            ));
        }
        _ => panic!("Expected CreateTable fact"),
    }
}

#[test]
fn test_create_table_if_not_exists() {
    let sql = "CREATE TABLE IF NOT EXISTS existing_table (id INT);";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateTable {
            name,
            if_not_exists,
            ..
        } => {
            assert_eq!(name.name.resolve(), "existing_table");
            assert!(if_not_exists);
        }
        _ => panic!("Expected CreateTable fact"),
    }
}

#[test]
fn test_alter_table_add_column() {
    let sql = "ALTER TABLE users ADD COLUMN email VARCHAR(255);";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::AlterTable { name, actions, .. } => {
            assert_eq!(name.name.resolve(), "users");
            assert!(!actions.is_empty());
        }
        _ => panic!("Expected AlterTable fact"),
    }
}

#[test]
fn test_alter_table_drop_column() {
    let sql = "ALTER TABLE users DROP COLUMN email;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::AlterTable { name, actions, .. } => {
            assert_eq!(name.name.resolve(), "users");
            assert!(!actions.is_empty());
        }
        _ => panic!("Expected AlterTable fact"),
    }
}

#[test]
fn test_alter_table_rename_column() {
    let sql = "ALTER TABLE users RENAME COLUMN email TO email_address;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::AlterTable { name, actions, .. } => {
            assert_eq!(name.name.resolve(), "users");
            assert!(!actions.is_empty());
        }
        _ => panic!("Expected AlterTable fact"),
    }
}

#[test]
fn test_alter_table_rename_table() {
    let sql = "ALTER TABLE users RENAME TO accounts;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::AlterTable { name, actions, .. } => {
            assert_eq!(name.name.resolve(), "users");
            assert!(!actions.is_empty());
        }
        _ => panic!("Expected AlterTable fact"),
    }
}

#[test]
fn test_alter_table_set_not_null() {
    let sql = "ALTER TABLE users ALTER COLUMN email SET NOT NULL;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::AlterTable { name, actions, .. } => {
            assert_eq!(name.name.resolve(), "users");
            assert!(!actions.is_empty());
        }
        _ => panic!("Expected AlterTable fact"),
    }
}

#[test]
fn alter_column_preserves_quoted_identifier_case() {
    let fact =
        parse_and_extract_statement(r#"ALTER TABLE entries ALTER COLUMN "Camel" TYPE bigint;"#)
            .expect("alter table fact");

    let StatementFact::AlterTable { actions, .. } = fact else {
        panic!("expected alter table fact");
    };
    let AlterTableActionFact::SetType { column, .. } = &actions[0] else {
        panic!("expected set type fact");
    };
    assert_eq!(column, "Camel");
}

#[test]
fn test_alter_table_drop_not_null() {
    let sql = "ALTER TABLE users ALTER COLUMN email DROP NOT NULL;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::AlterTable { name, actions, .. } => {
            assert_eq!(name.name.resolve(), "users");
            assert!(!actions.is_empty());
        }
        _ => panic!("Expected AlterTable fact"),
    }
}

#[test]
fn test_alter_table_unique_using_index() {
    let fact = parse_and_extract_statement(
        "ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE USING INDEX users_email_key;",
    )
    .expect("alter table fact");

    let StatementFact::AlterTable { actions, .. } = fact else {
        panic!("expected alter table fact");
    };
    let AlterTableActionFact::AddUniqueConstraint {
        constraint_name,
        using_index,
        ..
    } = &actions[0]
    else {
        panic!("expected unique constraint fact");
    };
    assert_eq!(constraint_name.as_deref(), Some("users_email_key"));
    assert_eq!(
        using_index.as_ref().map(|name| name.name.resolve()),
        Some("users_email_key".to_string())
    );
}

#[test]
fn test_alter_table_primary_key_using_index() {
    let fact = parse_and_extract_statement(
        "ALTER TABLE users ADD CONSTRAINT users_pkey PRIMARY KEY USING INDEX users_id_key;",
    )
    .expect("alter table fact");

    let StatementFact::AlterTable { actions, .. } = fact else {
        panic!("expected alter table fact");
    };
    let AlterTableActionFact::AddPrimaryKeyConstraint {
        constraint_name,
        using_index,
        ..
    } = &actions[0]
    else {
        panic!("expected primary-key constraint fact");
    };
    assert_eq!(constraint_name.as_deref(), Some("users_pkey"));
    assert_eq!(
        using_index.as_ref().map(|name| name.name.resolve()),
        Some("users_id_key".to_string())
    );
}

#[test]
fn test_alter_table_exclusion_constraint() {
    let fact = parse_and_extract_statement(
        "ALTER TABLE reservations ADD CONSTRAINT no_overlap EXCLUDE USING gist (period WITH &&);",
    )
    .expect("alter table fact");

    let StatementFact::AlterTable { actions, .. } = fact else {
        panic!("expected alter table fact");
    };
    assert!(matches!(
        actions.as_slice(),
        [AlterTableActionFact::AddExcludeConstraint {
            constraint_name,
            columns,
            columns_complete,
        }]
            if constraint_name.as_deref() == Some("no_overlap")
                && columns == &["period".to_string()]
                && *columns_complete
    ));
}

#[test]
fn test_drop_table() {
    let sql = "DROP TABLE users;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::DropTable { names, .. } => {
            assert_eq!(names.len(), 1);
            assert_eq!(names[0].name.resolve(), "users");
        }
        _ => panic!("Expected DropTable fact"),
    }
}

#[test]
fn test_drop_table_if_exists() {
    let sql = "DROP TABLE IF EXISTS users;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::DropTable {
            names, if_exists, ..
        } => {
            assert_eq!(names.len(), 1);
            assert_eq!(names[0].name.resolve(), "users");
            assert!(if_exists);
        }
        _ => panic!("Expected DropTable fact"),
    }
}

#[test]
fn test_drop_table_cascade() {
    let sql = "DROP TABLE users CASCADE;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::DropTable { names, cascade, .. } => {
            assert_eq!(names.len(), 1);
            assert_eq!(names[0].name.resolve(), "users");
            assert!(cascade);
        }
        _ => panic!("Expected DropTable fact"),
    }
}

#[test]
fn test_create_index() {
    let sql = "CREATE INDEX idx_users_email ON users(email);";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateIndex {
            name: _, relation, ..
        } => {
            assert_eq!(relation.name.resolve(), "users");
        }
        _ => panic!("Expected CreateIndex fact"),
    }
}

#[test]
fn test_create_index_unique() {
    let sql = "CREATE UNIQUE INDEX idx_users_email ON users(email);";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateIndex { unique, .. } => {
            assert!(unique);
        }
        _ => panic!("Expected CreateIndex fact"),
    }
}

#[test]
fn test_create_index_concurrently() {
    let sql = "CREATE INDEX CONCURRENTLY idx_users_email ON users(email);";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateIndex { concurrently, .. } => {
            assert!(concurrently);
        }
        _ => panic!("Expected CreateIndex fact"),
    }
}

#[test]
fn test_create_index_with_predicate() {
    let sql = "CREATE INDEX idx_users_active ON users(id) WHERE active = true;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateIndex { predicate, .. } => {
            assert!(predicate.has_predicate());
            assert!(matches!(predicate, IndexPredicate::Parsed(_)));
        }
        _ => panic!("Expected CreateIndex fact"),
    }
}

#[test]
fn create_index_records_nulls_not_distinct() {
    for (sql, expected) in [
        (
            "CREATE UNIQUE INDEX idx ON users(email) NULLS NOT DISTINCT;",
            true,
        ),
        ("CREATE UNIQUE INDEX idx ON users(email);", false),
    ] {
        let facts = parse_and_extract_statement(sql);
        let Some(StatementFact::CreateIndex {
            nulls_not_distinct, ..
        }) = facts
        else {
            panic!("Expected CreateIndex fact for: {sql}");
        };
        assert_eq!(nulls_not_distinct, expected, "for: {sql}");
    }
}

#[test]
fn create_index_records_only_recursion() {
    for (sql, expected) in [
        ("CREATE INDEX idx ON ONLY users(email);", true),
        ("CREATE INDEX idx ON users(email);", false),
    ] {
        let facts = parse_and_extract_statement(sql);
        let Some(StatementFact::CreateIndex { only, .. }) = facts else {
            panic!("Expected CreateIndex fact for: {sql}");
        };
        assert_eq!(only, expected, "for: {sql}");
    }
}

#[test]
fn test_create_index_using_method() {
    let sql = "CREATE INDEX idx_users_gin ON users USING GIN(data);";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateIndex { using_method, .. } => {
            assert!(using_method.is_some());
            assert_eq!(using_method.unwrap(), "GIN");
        }
        _ => panic!("Expected CreateIndex fact"),
    }
}

#[test]
fn test_drop_index() {
    let sql = "DROP INDEX idx_users_email;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::DropIndex { names, .. } => {
            assert_eq!(names.len(), 1);
        }
        _ => panic!("Expected DropIndex fact"),
    }
}

#[test]
fn drop_index_preserves_qualified_quoted_identity() {
    let StatementFact::DropIndex { names, .. } =
        parse_and_extract_statement("DROP INDEX sm_core.\"IdentityIndex\";")
            .expect("drop index fact")
    else {
        panic!("expected drop index fact")
    };
    assert_eq!(names.len(), 1);
    assert_eq!(
        names[0].schema.as_ref().map(Ident::resolve).as_deref(),
        Some("sm_core")
    );
    assert_eq!(names[0].name.resolve(), "IdentityIndex");
    assert!(names[0].name.quoted);
}

#[test]
fn test_vacuum_with_table() {
    let sql = "VACUUM FULL accounts;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::Vacuum { relation, is_full } => {
            assert!(is_full);
            assert!(relation.is_some());
            let rel = relation.unwrap();
            assert_eq!(rel.name.resolve(), "accounts");
            assert!(rel.schema.is_none());
        }
        _ => panic!("Expected Vacuum fact"),
    }
}

#[test]
fn detach_partition_preserves_its_lifecycle_mode() {
    let facts = parse_and_extract(
        "ALTER TABLE measurements DETACH PARTITION measurements_2025;
             ALTER TABLE measurements DETACH PARTITION measurements_2026 CONCURRENTLY;
             ALTER TABLE measurements DETACH PARTITION measurements_2027 FINALIZE;",
    );
    for (fact, expected_child, expected_mode) in [
        (
            &facts[0],
            "measurements_2025",
            crate::_internal::analysis::facts::DetachPartitionMode::Immediate,
        ),
        (
            &facts[1],
            "measurements_2026",
            crate::_internal::analysis::facts::DetachPartitionMode::Concurrently,
        ),
        (
            &facts[2],
            "measurements_2027",
            crate::_internal::analysis::facts::DetachPartitionMode::Finalize,
        ),
    ] {
        assert!(matches!(
            fact,
            StatementFact::AlterTable { actions, .. }
                if matches!(actions.as_slice(), [AlterTableActionFact::DetachPartition { child, mode }]
                    if child.name.resolve() == expected_child && *mode == expected_mode)
        ));
    }
}

#[test]
fn select_into_preserves_relation_name_and_persistence() {
    let facts = parse_and_extract(
        "SELECT id INTO TEMPORARY TABLE recent_events FROM events;
             SELECT id INTO UNLOGGED TABLE snapshot FROM events;
             SELECT id AS copied_id, name INTO projected FROM events;",
    );
    assert!(matches!(
        &facts[0],
        StatementFact::CreateTable {
            name,
            as_select: true,
            persistence,
            select_source: Some(source),
            select_outputs,
            select_projection_complete: true,
            ..
        }
            if name.name.resolve() == "recent_events"
                && source.name.resolve() == "events"
                && matches!(select_outputs.as_slice(), [
                    crate::_internal::analysis::facts::SelectOutputFact::Column {
                        source_name,
                        output_name,
                    }
                ] if source_name == "id" && output_name == "id")
                && *persistence
                    == crate::_internal::analysis::facts::PersistenceFact::Temporary
    ));
    assert!(matches!(
        &facts[1],
        StatementFact::CreateTable { name, as_select: true, persistence, .. }
            if name.name.resolve() == "snapshot"
                && *persistence
                    == crate::_internal::analysis::facts::PersistenceFact::Unlogged
    ));
    assert!(
        matches!(
            &facts[2],
            StatementFact::CreateTable {
                select_outputs,
                select_projection_complete: true,
                ..
            } if matches!(select_outputs.as_slice(), [
                crate::_internal::analysis::facts::SelectOutputFact::Column {
                    source_name,
                    output_name,
                },
                crate::_internal::analysis::facts::SelectOutputFact::Column {
                    source_name: second_source,
                    output_name: second_output,
                }
            ] if source_name == "id" && output_name == "copied_id"
                && second_source == "name" && second_output == "name")
        ),
        "unexpected projected SELECT INTO fact: {:?}",
        facts[2]
    );
}

#[test]
fn create_table_inherits_preserves_all_parent_references() {
    let fact = parse_and_extract_statement(
        "CREATE TABLE child (local_value integer) INHERITS (public.parent_a, parent_b);",
    )
    .expect("CREATE TABLE INHERITS fact");
    assert!(matches!(
        fact,
        StatementFact::CreateTable { inherits, .. }
            if inherits.len() == 2
                && inherits[0].schema.as_ref().is_some_and(|schema| schema.resolve() == "public")
                && inherits[0].name.resolve() == "parent_a"
                && inherits[1].name.resolve() == "parent_b"
    ));
}

#[test]
fn create_table_like_preserves_supported_property_selection() {
    let fact = parse_and_extract_statement("CREATE TABLE copy (LIKE public.source);")
        .expect("unadorned LIKE fact");
    assert!(matches!(
        fact,
        StatementFact::CreateTable { like_sources, .. }
            if like_sources.len() == 1
                && like_sources[0].relation.schema.as_ref().is_some_and(|schema| schema.resolve() == "public")
                && like_sources[0].relation.name.resolve() == "source"
    ));
    let with_properties = parse_and_extract_statement(
            "CREATE TABLE copy_options (LIKE source INCLUDING DEFAULTS INCLUDING GENERATED INCLUDING STORAGE INCLUDING COMPRESSION INCLUDING STATISTICS);",
        )
        .expect("supported LIKE properties");
    assert!(matches!(
        with_properties,
        StatementFact::CreateTable { like_sources, .. }
            if matches!(like_sources.as_slice(), [source]
                if source.properties.defaults
                    && source.properties.generated
                    && source.properties.storage
                    && source.properties.compression
                    && source.properties.statistics)
    ));
    assert!(matches!(
        parse_and_extract_statement(
            "CREATE TABLE indexed_like (LIKE source INCLUDING INDEXES);"
        ),
        Some(StatementFact::CreateTable { like_sources, .. })
            if like_sources[0].properties.indexes
    ));
    assert!(parse_and_extract_statement(
            "CREATE TABLE all_but_objects (LIKE source INCLUDING ALL EXCLUDING INDEXES EXCLUDING CONSTRAINTS EXCLUDING IDENTITY);"
        )
        .is_some());
}

#[test]
fn alter_table_options_fold_names_and_read_literal_values() {
    let fact = parse_and_extract_statement(
        "ALTER TABLE entries SET (FILLFACTOR = 70, autovacuum_enabled = 'on');",
    )
    .expect("table options fact");
    assert!(matches!(
        fact,
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [crate::_internal::analysis::facts::AlterTableActionFact::SetTableOptions { attributes }]
                if attributes.iter().any(|attribute| attribute.name == "fillfactor" && attribute.value.as_deref() == Some("70"))
                    && attributes.iter().any(|attribute| attribute.name == "autovacuum_enabled" && attribute.value.as_deref() == Some("on")))
    ));

    // A `RESET` that carries a value keeps it, even the empty string, so the
    // server's refusal is reproduced; the empty string is stored as itself,
    // not as its quotes.
    let fact = parse_and_extract_statement("ALTER TABLE entries RESET (fillfactor = '');")
        .expect("reset options fact");
    assert!(matches!(
        fact,
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [crate::_internal::analysis::facts::AlterTableActionFact::ResetTableOptions { attributes }]
                if attributes.iter().any(|attribute| attribute.name == "fillfactor" && attribute.value.as_deref() == Some("")))
    ));

    // A `RESET` with no value carries none, which is what makes it valid.
    let fact = parse_and_extract_statement("ALTER TABLE entries RESET (fillfactor);")
        .expect("reset options fact");
    assert!(matches!(
        fact,
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [crate::_internal::analysis::facts::AlterTableActionFact::ResetTableOptions { attributes }]
                if attributes.iter().any(|attribute| attribute.name == "fillfactor" && attribute.value.is_none()))
    ));

    // A bare `SET` option reads as `true`, as the server reads it, while an
    // explicitly empty value stays empty.
    let fact = parse_and_extract_statement(
        "ALTER TABLE entries SET (autovacuum_enabled, autovacuum_analyze_threshold = '');",
    )
    .expect("table options fact");
    assert!(matches!(
        fact,
        StatementFact::AlterTable { actions, .. }
            if matches!(actions.as_slice(), [crate::_internal::analysis::facts::AlterTableActionFact::SetTableOptions { attributes }]
                if attributes.iter().any(|attribute| attribute.name == "autovacuum_enabled" && attribute.value.as_deref() == Some("true"))
                    && attributes.iter().any(|attribute| attribute.name == "autovacuum_analyze_threshold" && attribute.value.as_deref() == Some("")))
    ));
}

#[test]
fn timeout_settings_extract_scope_units_defaults_and_invalid_values() {
    for (sql, expected) in [
        (
            "SET lock_timeout = '1500us';",
            StatementFact::SetTimeout {
                setting: TimeoutSetting::Lock,
                value: TimeoutSettingValue::Milliseconds(2),
                local: false,
            },
        ),
        (
            "SET LOCAL statement_timeout TO '2min';",
            StatementFact::SetTimeout {
                setting: TimeoutSetting::Statement,
                value: TimeoutSettingValue::Milliseconds(120_000),
                local: true,
            },
        ),
        (
            "SET lock_timeout = '-0.5ms';",
            StatementFact::SetTimeout {
                setting: TimeoutSetting::Lock,
                value: TimeoutSettingValue::Milliseconds(0),
                local: false,
            },
        ),
        (
            "SET SESSION lock_timeout TO DEFAULT;",
            StatementFact::SetTimeout {
                setting: TimeoutSetting::Lock,
                value: TimeoutSettingValue::Default,
                local: false,
            },
        ),
        (
            "SET lock_timeout FROM CURRENT;",
            StatementFact::SetTimeout {
                setting: TimeoutSetting::Lock,
                value: TimeoutSettingValue::Current,
                local: false,
            },
        ),
    ] {
        assert_eq!(parse_and_extract_statement(sql), Some(expected), "{sql}");
    }

    assert!(matches!(
        parse_and_extract_statement("SET lock_timeout = 'forever';"),
        Some(StatementFact::SetTimeout {
            setting: TimeoutSetting::Lock,
            value: TimeoutSettingValue::Invalid(_),
            local: false,
        })
    ));
    assert!(matches!(
        parse_and_extract_statement("SET lock_timeout = -1;"),
        Some(StatementFact::SetTimeout {
            setting: TimeoutSetting::Lock,
            value: TimeoutSettingValue::Invalid(_),
            local: false,
        })
    ));
}

#[test]
fn test_alter_table_attach_partition() {
    let sql = "ALTER TABLE parent ATTACH PARTITION child FOR VALUES FROM (1) TO (100);";
    let fact = parse_and_extract_statement(sql).expect("attach partition fact");
    let StatementFact::AlterTable { actions, .. } = fact else {
        panic!("expected alter table fact");
    };
    assert!(matches!(
        actions.as_slice(),
        [AlterTableActionFact::AttachPartition {
            strategy: Some(strategy),
            bound: Some(bound),
            ..
        }] if strategy == "RANGE" && bound == "FOR VALUES FROM (1) TO (100)"
    ));
}

#[test]
fn partition_strategy_ignores_comments_and_preserves_bound_identity() {
    for (sql_strategy, expected) in [("RANGE", "range"), ("list", "list"), ("\"HASH\"", "HASH")] {
        let sql = format!(
            "CREATE TABLE child PARTITION OF parent DEFAULT PARTITION /* key */ BY {sql_strategy} /* bound is separate */ (id);"
        );
        let StatementFact::CreateTable {
            partition_strategy,
            partition_bound,
            ..
        } = parse_and_extract_statement(&sql).expect("partition fact")
        else {
            panic!("expected create table")
        };
        assert_eq!(partition_strategy.as_deref(), Some(expected));
        assert_eq!(partition_bound.as_deref(), Some("DEFAULT"));
    }
}

#[test]
fn attach_partition_strategy_comes_from_typed_partition_node() {
    // The range bound deliberately contains the words "FOR VALUES IN".
    // Classifying from statement text would misidentify this as a LIST
    // partition; Squawk's typed PartitionType is authoritative.
    let fact = parse_and_extract_statement(
        "ALTER TABLE parent ATTACH PARTITION child FOR VALUES FROM ('FOR VALUES IN') TO ('z');",
    )
    .expect("attach partition fact");
    let StatementFact::AlterTable { actions, .. } = fact else {
        panic!("expected alter table fact");
    };
    assert!(matches!(
        actions.as_slice(),
        [AlterTableActionFact::AttachPartition {
            strategy: Some(strategy),
            ..
        }] if strategy == "RANGE"
    ));
}

#[test]
fn partition_keys_resolved_at_visitor_time_for_simple_columns() {
    // Single-column RANGE, LIST, and HASH keys must be resolved directly
    // from the typed PartitionBy node — no synthetic re-parse.
    for (strategy, sql) in [
        (
            "RANGE",
            "CREATE TABLE parent (id integer) PARTITION BY RANGE (id);",
        ),
        (
            "LIST",
            "CREATE TABLE parent (id integer) PARTITION BY LIST (id);",
        ),
        (
            "HASH",
            "CREATE TABLE parent (id integer) PARTITION BY HASH (id);",
        ),
    ] {
        let StatementFact::CreateTable {
            partition_keys,
            partition_strategy,
            ..
        } = parse_and_extract_statement(sql).expect("create table fact")
        else {
            panic!("expected create table for {strategy}");
        };
        assert_eq!(
            partition_strategy.as_deref(),
            Some(&strategy.to_lowercase()[..]),
            "{strategy}: strategy"
        );
        assert_eq!(
            partition_keys,
            vec![("id".to_string(), "id".to_string())],
            "{strategy}: keys"
        );
    }
}

#[test]
fn partition_keys_resolved_for_multi_column_and_quoted_names() {
    // Multi-column key and a quoted identifier.
    let multi = "CREATE TABLE parent (a integer, b integer) PARTITION BY RANGE (a, b);";
    let StatementFact::CreateTable { partition_keys, .. } =
        parse_and_extract_statement(multi).expect("multi-column fact")
    else {
        panic!("expected create table");
    };
    assert_eq!(
        partition_keys,
        vec![
            ("a".to_string(), "a".to_string()),
            ("b".to_string(), "b".to_string()),
        ]
    );

    // Quoted identifier: resolved name is case-preserved, raw spelling
    // includes the quotes.
    let quoted = "CREATE TABLE parent (\"MyId\" integer) PARTITION BY LIST (\"MyId\");";
    let StatementFact::CreateTable { partition_keys, .. } =
        parse_and_extract_statement(quoted).expect("quoted fact")
    else {
        panic!("expected create table");
    };
    assert_eq!(partition_keys.len(), 1);
    assert_eq!(partition_keys[0].0, "MyId");
    assert!(
        partition_keys[0].1.contains("MyId"),
        "raw spelling must contain the identifier"
    );
}

#[test]
fn partition_keys_empty_when_key_has_unsupported_modifiers() {
    // A key with COLLATE or an op-class cannot be represented as a simple
    // name — partition_keys must be empty so callers use the partition_by
    // text fallback.
    let with_collate = "CREATE TABLE parent (t text) PARTITION BY LIST (t COLLATE \"POSIX\");";
    let StatementFact::CreateTable { partition_keys, .. } =
        parse_and_extract_statement(with_collate).expect("collate fact")
    else {
        panic!("expected create table");
    };
    assert!(
        partition_keys.is_empty(),
        "partition_keys must be empty for COLLATE keys, got {partition_keys:?}"
    );
}

#[test]
fn test_alter_table_detach_partition() {
    let sql = "ALTER TABLE parent DETACH PARTITION child;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
}

#[test]
fn test_expr_ir_is_volatile_column_ref() {
    let expr = ExprIr::ColumnRef("column_name".into());
    assert!(!expr.is_volatile());
}

#[test]
fn test_now_is_stable_not_volatile() {
    let expr = ExprIr::FunctionCall {
        name: "now".to_string(),
        args: vec![],
    };
    assert!(!expr.is_volatile(), "now() should be STABLE, not VOLATILE");
}

#[test]
fn test_current_timestamp_is_stable() {
    let expr = ExprIr::FunctionCall {
        name: "current_timestamp".to_string(),
        args: vec![],
    };
    assert!(!expr.is_volatile(), "current_timestamp should be STABLE");
}

#[test]
fn squawk_264_alter_constraint_and_using_wrappers_preserve_facts() {
    let facts = parse_and_extract(
        "ALTER TABLE events ALTER CONSTRAINT events_parent_fk
                 DEFERRABLE INITIALLY DEFERRED;
             ALTER TABLE events ALTER CONSTRAINT events_parent_fk
                 NOT DEFERRABLE INITIALLY IMMEDIATE;
             ALTER TABLE events ALTER COLUMN payload TYPE jsonb USING payload::jsonb;",
    );
    assert_eq!(facts.len(), 3);
    assert!(matches!(
        &facts[0],
        StatementFact::AlterTable { actions, .. }
            if matches!(
                actions.as_slice(),
                [AlterTableActionFact::AlterConstraint {
                    name: Some(name),
                    deferrable: true,
                }] if name == "events_parent_fk"
            )
    ));
    assert!(matches!(
        &facts[1],
        StatementFact::AlterTable { actions, .. }
            if matches!(
                actions.as_slice(),
                [AlterTableActionFact::AlterConstraint {
                    name: Some(name),
                    deferrable: false,
                }] if name == "events_parent_fk"
            )
    ));
    assert!(matches!(
        &facts[2],
        StatementFact::AlterTable { actions, .. }
            if matches!(
                actions.as_slice(),
                [AlterTableActionFact::SetType {
                    column,
                    ty,
                    has_using: true,
                }] if column == "payload" && ty == "jsonb"
            )
    ));
}

#[test]
fn trigger_user_target_is_preserved_without_including_constraint_triggers() {
    let facts = parse_and_extract(
        "ALTER TABLE events DISABLE TRIGGER USER;
             ALTER TABLE events ENABLE TRIGGER USER;",
    );
    for fact in facts {
        assert!(matches!(
            fact,
            StatementFact::AlterTable { actions, .. }
                if matches!(actions.as_slice(),
                    [AlterTableActionFact::DisableTrigger { trigger_name: Some(name) }]
                        | [AlterTableActionFact::EnableTrigger { trigger_name: Some(name) }]
                    if name == "USER")
        ));
    }
}

#[test]
fn create_table_preserves_stored_generated_column_expression() {
    let fact = parse_and_extract_statement(
            "CREATE TABLE metrics (value integer, doubled integer GENERATED ALWAYS AS (value * 2) STORED);",
        )
        .expect("generated-column CREATE TABLE fact");
    assert!(matches!(
        fact,
        StatementFact::CreateTable { columns, .. }
            if matches!(columns.as_slice(), [_, column]
                if column.generation == crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                    && column.generated_expr.as_ref().and_then(ExprIr::referenced_columns)
                        .is_some_and(|references| references.len() == 1 && references.contains("value")))
    ));
}

#[test]
fn create_table_preserves_virtual_generated_column_kind() {
    let fact = parse_and_extract_statement(
            "CREATE TABLE metrics (value integer, doubled integer GENERATED ALWAYS AS (value * 2) VIRTUAL);",
        )
        .expect("virtual generated-column CREATE TABLE fact");
    assert!(matches!(
        fact,
        StatementFact::CreateTable { columns, .. }
            if matches!(columns.as_slice(), [_, column]
                if column.generation == crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual
                    && column.generated_expr.as_ref().and_then(ExprIr::referenced_columns)
                        .is_some_and(|references| references.contains("value")))
    ));
}

#[test]
fn expression_indexes_keep_their_parsed_identity() {
    let parsed =
        SourceFile::parse("CREATE UNIQUE INDEX normalized_name ON source ((lower(name)));");
    let statement = parsed.tree().stmts().next().expect("statement");
    let Some(StatementFact::CreateIndex {
        unique,
        concurrently,
        predicate,
        key_columns,
        key_expressions,
        ..
    }) = AstVisitor::extract(&statement)
    else {
        panic!("expected create index fact");
    };
    assert!(unique);
    assert!(!concurrently);
    assert!(!predicate.has_predicate());
    // An expression key names no column, so the columns list is empty while
    // the key itself is still present and carries its parsed identity.
    assert!(key_columns.is_empty());
    assert_eq!(key_expressions.len(), 1);
    assert!(key_expressions[0].is_some());
}

#[test]
fn a_collated_column_key_stays_a_column() {
    // PostgreSQL strips top-level COLLATE and parentheses before deciding
    // a key is a column, so a collated bare column is a column key that
    // carries the written collation, not an expression.
    for sql in [
        "CREATE INDEX ON source (name COLLATE \"C\");",
        "CREATE INDEX ON source ((name) COLLATE \"C\");",
    ] {
        let Some(StatementFact::CreateIndex {
            key_columns,
            key_expressions,
            key_collations,
            ..
        }) = parse_and_extract_statement(sql)
        else {
            panic!("expected create index fact for: {sql}");
        };
        assert_eq!(key_columns, ["name"], "for: {sql}");
        assert_eq!(key_expressions, [None], "for: {sql}");
        assert_eq!(
            key_collations,
            [Some(WrittenName {
                schema: None,
                name: "C".to_string(),
            })],
            "for: {sql}"
        );
    }
    let Some(StatementFact::CreateIndex {
        key_columns,
        key_expressions,
        key_collations,
        ..
    }) = parse_and_extract_statement("CREATE INDEX ON source ((name));")
    else {
        panic!("expected create index fact");
    };
    assert_eq!(key_columns, ["name"]);
    assert_eq!(key_expressions, [None]);
    assert_eq!(key_collations, [None]);
    let Some(StatementFact::CreateIndex {
        key_columns,
        key_expressions,
        key_collations,
        ..
    }) = parse_and_extract_statement("CREATE INDEX ON source (lower(name) COLLATE \"C\");")
    else {
        panic!("expected create index fact");
    };
    assert!(key_columns.is_empty());
    assert_eq!(key_expressions.len(), 1);
    assert!(key_expressions[0].is_some());
    assert_eq!(
        key_collations,
        [Some(WrittenName {
            schema: None,
            name: "C".to_string(),
        })]
    );
}

#[test]
fn expression_indexes_preserve_index_rule_metadata() {
    let parsed =
        SourceFile::parse("CREATE UNIQUE INDEX normalized_name ON source ((lower(name)));");
    let statement = parsed.tree().stmts().next().expect("statement");
    assert!(matches!(
        AstVisitor::extract(&statement),
        Some(StatementFact::CreateIndex {
            unique: true,
            concurrently: false,
            predicate: IndexPredicate::None,
            ..
        })
    ));
}

#[test]
fn create_index_retains_eligibility_proof_facts() {
    let parsed =
        SourceFile::parse("CREATE UNIQUE INDEX source_name_idx ON source (name) INCLUDE (id);");
    let statement = parsed.tree().stmts().next().expect("statement");
    let Some(StatementFact::CreateIndex {
        key_columns,
        key_expressions,
        included_columns,
        key_orders,
        key_opclasses,
        key_collations,
        nulls_not_distinct,
        ..
    }) = AstVisitor::extract(&statement)
    else {
        panic!("expected create index fact");
    };
    assert_eq!(key_columns, ["name"]);
    // Key positions stay aligned: one plain column, no expressions.
    assert_eq!(key_expressions, [None]);
    assert_eq!(included_columns, ["id"]);
    assert_eq!(key_orders, [IndexOrder::Default]);
    assert_eq!(key_opclasses, [None]);
    assert_eq!(key_collations, [None]);
    assert!(!nulls_not_distinct);
}
