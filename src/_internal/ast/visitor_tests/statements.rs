use super::*;

#[test]
fn test_create_table_temporary() {
    let sql = "CREATE TEMP TABLE temp_table (id INT);";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateTable {
            name, persistence, ..
        } => {
            assert_eq!(name.name.resolve(), "temp_table");
            assert!(matches!(
                persistence,
                crate::_internal::analysis::facts::PersistenceFact::Temporary
            ));
        }
        _ => panic!("Expected CreateTable fact"),
    }
}

#[test]
fn test_vacuum_full() {
    let sql = "VACUUM FULL;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::Vacuum { relation, is_full } => {
            assert!(is_full);
            assert!(relation.is_none());
        }
        _ => panic!("Expected Vacuum fact"),
    }
}

#[test]
fn test_vacuum() {
    let sql = "VACUUM;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::Vacuum { relation, is_full } => {
            assert!(!is_full);
            assert!(relation.is_none());
        }
        _ => panic!("Expected Vacuum fact"),
    }
}

#[test]
fn lock_and_truncate_preserve_targets_and_options() {
    let lock = parse_and_extract_statement(
        "LOCK TABLE ONLY public.events IN ACCESS EXCLUSIVE MODE NOWAIT;",
    )
    .expect("LOCK TABLE fact");
    match lock {
        StatementFact::Lock {
            targets,
            mode,
            nowait,
        } => {
            assert_eq!(targets.len(), 1);
            assert!(targets[0].only);
            assert_eq!(targets[0].name.schema.as_ref().unwrap().resolve(), "public");
            assert_eq!(targets[0].name.name.resolve(), "events");
            assert_eq!(
                mode,
                crate::_internal::analysis::facts::LockModeFact::AccessExclusive
            );
            assert!(nowait);
        }
        other => panic!("expected LOCK TABLE fact, got {other:?}"),
    }

    let truncate = parse_and_extract_statement(
        "TRUNCATE TABLE ONLY public.events, audit RESTART IDENTITY CASCADE;",
    )
    .expect("TRUNCATE fact");
    match truncate {
        StatementFact::Truncate {
            targets,
            cascade,
            restart_identity,
        } => {
            assert_eq!(targets.len(), 2);
            assert!(targets[0].only);
            assert_eq!(targets[0].name.name.resolve(), "events");
            assert!(!targets[1].only);
            assert_eq!(targets[1].name.name.resolve(), "audit");
            assert!(cascade);
            assert!(restart_identity);
        }
        other => panic!("expected TRUNCATE fact, got {other:?}"),
    }
}

#[test]
fn incomplete_replication_alters_do_not_target_an_empty_name() {
    for sql in [
        "ALTER PUBLICATION SET (publish = 'insert');",
        "ALTER SUBSCRIPTION SET (enabled = false);",
    ] {
        assert!(parse_and_extract_statement(sql).is_none(), "{sql}");
    }
}

#[test]
fn test_create_schema() {
    let sql = "CREATE SCHEMA my_schema;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CreateSchema { name, .. } => {
            assert_eq!(name.name.resolve(), "my_schema");
        }
        _ => panic!("Expected CreateSchema fact"),
    }
}

#[test]
fn test_drop_schema() {
    let sql = "DROP SCHEMA my_schema CASCADE;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::DropSchema { names, cascade, .. } => {
            assert!(!names.is_empty());
            assert!(cascade);
        }
        _ => panic!("Expected DropSchema fact"),
    }
}

#[test]
fn test_alter_schema() {
    let sql = "ALTER SCHEMA my_schema RENAME TO new_schema;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::AlterSchema { name, action } => {
            assert_eq!(name.name.resolve(), "my_schema");
            assert!(
                matches!(action, crate::_internal::analysis::facts::AlterSchemaActionFact::RenameTo { new_name } if new_name.resolve() == "new_schema")
            );
        }
        _ => panic!("Expected AlterSchema fact"),
    }
}

#[test]
fn test_multiple_statements() {
    let sql = "
            CREATE TABLE users (id INT);
            CREATE TABLE orders (id INT);
            DROP TABLE users;
        ";
    let facts = parse_and_extract(sql);
    assert_eq!(facts.len(), 3);
}

#[test]
fn parser_accepts_lf_crlf_and_cr_line_endings() {
    for (name, line_ending) in [("LF", "\n"), ("CRLF", "\r\n"), ("CR", "\r")] {
        let sql = format!(
            "CREATE TABLE users (id integer);{line_ending}ALTER TABLE users ADD COLUMN name text;"
        );
        let parsed = SourceFile::parse(&sql);
        assert!(parsed.errors().is_empty(), "{name} input must parse");
        assert_eq!(parse_and_extract(&sql).len(), 2, "{name} input facts");
    }
}

#[test]
fn parser_accepts_postgres_19_property_graph_syntax_as_opaque() {
    for sql in [
        "CREATE PROPERTY GRAPH social
                VERTEX TABLES (people)
                EDGE TABLES (knows SOURCE people DESTINATION people);",
        "ALTER PROPERTY GRAPH social SET SCHEMA graph_schema;",
        "DROP PROPERTY GRAPH IF EXISTS social CASCADE;",
    ] {
        let parsed = SourceFile::parse(sql);
        assert!(
            parsed.errors().is_empty(),
            "property graph must parse: {sql}"
        );
        let statement = parsed
            .tree()
            .stmts()
            .next()
            .expect("property graph statement");
        assert!(
            AstVisitor::extract(&statement).is_none(),
            "unmodeled property graph syntax must stay opaque: {sql}"
        );
    }
}

#[test]
fn test_do_block() {
    let sql = "DO $$ BEGIN RAISE NOTICE 'hello'; END $$;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::OpaqueBlock => {}
        _ => panic!("Expected OpaqueBlock fact"),
    }
}

#[test]
fn test_execute_stmt() {
    let sql = "EXECUTE my_plan;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::Execute => {}
        _ => panic!("Expected Execute fact"),
    }
}

#[test]
fn comment_on_extracts_as_schema_neutral_noop() {
    let fact = parse_and_extract_statement("COMMENT ON TABLE public.events IS 'audit log';")
        .expect("comment statement fact");
    assert!(matches!(fact, StatementFact::SchemaNeutralNoop));
}

#[test]
fn alter_table_owner_to_session_user_is_captured() {
    let fact = parse_and_extract_statement("ALTER TABLE foo OWNER TO SESSION_USER;")
        .expect("should extract a fact");
    let StatementFact::AlterTable { actions, .. } = fact else {
        panic!("expected AlterTable");
    };
    let owner = actions.iter().find_map(|a| {
        if let AlterTableActionFact::OwnerTo { new_owner } = a {
            Some(new_owner.clone())
        } else {
            None
        }
    });
    assert_eq!(
        owner,
        Some(crate::_internal::analysis::facts::RoleFact::SessionUser)
    );
}

#[test]
fn create_table_like_preserves_catalog_object_selections() {
    let fact = parse_and_extract_statement(
        "CREATE TABLE copied (LIKE source INCLUDING ALL EXCLUDING DEFAULTS);",
    )
    .expect("typed LIKE fact");
    assert!(matches!(
        fact,
        StatementFact::CreateTable { like_sources, .. }
            if matches!(like_sources.as_slice(), [source]
                if source.properties.constraints
                    && source.properties.indexes
                    && source.properties.identity
                    && source.properties.generated
                    && source.properties.storage
                    && source.properties.compression
                    && source.properties.statistics
                    && !source.properties.defaults)
    ));
}

#[test]
fn unsupported_create_table_as_transaction_lifecycle_is_not_silent() {
    let parsed =
        SourceFile::parse("CREATE TEMP TABLE snapshot ON COMMIT DROP AS SELECT id FROM source;");
    let statement = parsed.tree().stmts().next().expect("statement");
    assert!(matches!(
        AstVisitor::extract(&statement),
        Some(StatementFact::CreateTable {
            as_select: true,
            ..
        })
    ));

    let parsed = SourceFile::parse("CREATE TABLE snapshot AS SELECT id FROM source WITH NO DATA;");
    let statement = parsed.tree().stmts().next().expect("statement");
    assert!(matches!(
        AstVisitor::extract(&statement),
        Some(StatementFact::CreateTable {
            as_select: true,
            ..
        })
    ));
}

#[test]
fn a_malformed_owned_by_target_is_not_read_as_owned_by_none() {
    // PostgreSQL refuses `OWNED BY column` with "invalid OWNED BY option",
    // so the statement must stay unmodeled rather than become OWNED BY NONE.
    assert!(parse_and_extract_statement("ALTER SEQUENCE public.s OWNED BY id").is_none());
    let fact = parse_and_extract_statement("ALTER SEQUENCE public.s OWNED BY public.t.id")
        .expect("a qualified target still extracts");
    assert!(matches!(
        fact,
        StatementFact::AlterSequence { options, .. }
            if matches!(
                options.as_slice(),
                [crate::_internal::analysis::facts::SequenceOptionFact::OwnedBy(Some(_))]
            )
    ));
}

#[test]
fn squawk_264_validation_matrix_rejects_invalid_expression_shapes() {
    for sql in [
        "SELECT * FROM t WHERE a NOT IN ();",
        "SELECT * FROM t WHERE a NOT IN ARRAY[1, 2];",
        "SELECT 1 OVERLAPS 2;",
        "CREATE TABLE t (a int, FOREIGN KEY (a WITHOUT OVERLAPS) REFERENCES u (c));",
    ] {
        let parsed = SourceFile::parse(sql);
        assert!(
            !parsed.errors().is_empty(),
            "expected validation error: {sql}"
        );
    }

    for sql in [
        "SELECT * FROM t WHERE a NOT IN (1, 2);",
        "SELECT (1, 2) OVERLAPS (3, 4);",
        "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3 ORDER BY 1 LIMIT 1;",
    ] {
        let parsed = SourceFile::parse(sql);
        assert!(parsed.errors().is_empty(), "expected valid SQL: {sql}");
    }
}
