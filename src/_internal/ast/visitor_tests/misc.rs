use super::*;

#[test]
fn test_grant_extracts_individual_table_privileges() {
    let fact = parse_and_extract_statement(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON test_table TO app_user;",
    )
    .expect("grant fact");

    let StatementFact::Grant(grant) = fact else {
        panic!("expected grant fact");
    };
    assert_eq!(
        grant.privileges,
        crate::_internal::analysis::facts::PrivilegeSpec::List(vec![
            crate::_internal::analysis::facts::PrivilegeFact::Select,
            crate::_internal::analysis::facts::PrivilegeFact::Insert,
            crate::_internal::analysis::facts::PrivilegeFact::Update,
            crate::_internal::analysis::facts::PrivilegeFact::Delete,
        ])
    );
}

#[test]
fn grant_extracts_keyword_token_privileges_from_nested_role_name_ref() {
    let fact = parse_and_extract_statement(
        "GRANT TRUNCATE, TRIGGER, EXECUTE, TEMP ON TABLE test_table TO app_user;",
    )
    .expect("grant fact");

    let StatementFact::Grant(grant) = fact else {
        panic!("expected grant fact");
    };
    assert_eq!(
        grant.privileges,
        crate::_internal::analysis::facts::PrivilegeSpec::List(vec![
            crate::_internal::analysis::facts::PrivilegeFact::Truncate,
            crate::_internal::analysis::facts::PrivilegeFact::Trigger,
            crate::_internal::analysis::facts::PrivilegeFact::Execute,
            crate::_internal::analysis::facts::PrivilegeFact::Temporary,
        ])
    );
}

#[test]
fn grant_role_membership_is_not_confused_with_keyword_privileges() {
    let fact = parse_and_extract_statement("GRANT writer TO app_user;").expect("grant fact");

    let StatementFact::Grant(grant) = fact else {
        panic!("expected grant fact");
    };
    assert_eq!(
        grant.privileges,
        crate::_internal::analysis::facts::PrivilegeSpec::List(vec![
            crate::_internal::analysis::facts::PrivilegeFact::RoleMembership("writer".into()),
        ])
    );
}

#[test]
fn revoke_extracts_keyword_token_privileges_from_nested_role_name_ref() {
    for sql in [
        "REVOKE TRUNCATE, TRIGGER, EXECUTE, TEMP ON TABLE test_table FROM app_user;",
        "REVOKE INSERT, UPDATE, DELETE ON TABLE test_table FROM app_user;",
    ] {
        let fact = parse_and_extract_statement(sql).expect("revoke fact");
        let StatementFact::Revoke(revoke) = fact else {
            panic!("expected revoke fact");
        };
        if matches!(
            revoke.privileges,
            crate::_internal::analysis::facts::PrivilegeSpec::List(_)
        ) {
            assert!(
                !matches!(
                    revoke.privileges,
                    crate::_internal::analysis::facts::PrivilegeSpec::List(ref l) if l.contains(&crate::_internal::analysis::facts::PrivilegeFact::Unknown)
                ),
                "no privilege may be Unknown: {sql}"
            );
        }

        let expected = if sql.contains("TEMP") {
            vec![
                crate::_internal::analysis::facts::PrivilegeFact::Truncate,
                crate::_internal::analysis::facts::PrivilegeFact::Trigger,
                crate::_internal::analysis::facts::PrivilegeFact::Execute,
                crate::_internal::analysis::facts::PrivilegeFact::Temporary,
            ]
        } else {
            vec![
                crate::_internal::analysis::facts::PrivilegeFact::Insert,
                crate::_internal::analysis::facts::PrivilegeFact::Update,
                crate::_internal::analysis::facts::PrivilegeFact::Delete,
            ]
        };
        assert_eq!(
            revoke.privileges,
            crate::_internal::analysis::facts::PrivilegeSpec::List(expected),
            "for {sql}"
        );
    }
}

#[test]
fn postgres17_maintain_privilege_is_extracted_from_grant_and_revoke() {
    for sql in [
        "GRANT MAINTAIN ON TABLE test_table TO app_user;",
        "REVOKE MAINTAIN ON TABLE test_table FROM app_user;",
    ] {
        let fact = parse_and_extract_statement(sql).expect("privilege fact");
        let privileges = match fact {
            StatementFact::Grant(grant) => grant.privileges,
            StatementFact::Revoke(revoke) => revoke.privileges,
            other => panic!("expected grant or revoke fact, got {other:?}"),
        };
        assert_eq!(
            privileges,
            crate::_internal::analysis::facts::PrivilegeSpec::List(vec![
                crate::_internal::analysis::facts::PrivilegeFact::Maintain,
            ]),
            "MAINTAIN must remain a typed relation privilege: {sql}"
        );
    }
}

#[test]
fn role_membership_set_option_is_extracted() {
    let fact = { parse_and_extract_statement("GRANT parent_role TO member_role WITH SET TRUE;") }
        .expect("role grant fact");
    let StatementFact::Grant(grant) = fact else {
        panic!("expected grant fact");
    };
    assert_eq!(
        grant.target,
        crate::_internal::analysis::facts::GrantTarget::Roles(vec!["parent_role".into()])
    );
    assert_eq!(
        grant.role_options,
        vec![crate::_internal::analysis::facts::RoleMembershipOptionFact::Set(true)]
    );

    let fact = parse_and_extract_statement("REVOKE SET OPTION FOR parent_role FROM member_role;")
        .expect("role revoke fact");
    let StatementFact::Revoke(revoke) = fact else {
        panic!("expected revoke fact");
    };
    assert_eq!(
        revoke.target,
        crate::_internal::analysis::facts::GrantTarget::Roles(vec!["parent_role".into()])
    );
    assert_eq!(
        revoke.role_option,
        Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Set(false))
    );

    for (sql, expected) in [
        (
            "GRANT parent_role TO member_role WITH ADMIN TRUE;",
            crate::_internal::analysis::facts::RoleMembershipOptionFact::Admin(true),
        ),
        (
            "GRANT parent_role TO member_role WITH INHERIT FALSE;",
            crate::_internal::analysis::facts::RoleMembershipOptionFact::Inherit(false),
        ),
    ] {
        let StatementFact::Grant(grant) =
            parse_and_extract_statement(sql).expect("role option grant fact")
        else {
            panic!("expected grant fact");
        };
        assert_eq!(grant.role_options, vec![expected]);
    }
}

#[test]
fn test_quoted_identifiers_unescape_doubled_quotes() {
    let facts = parse_and_extract(
        r#"
            CREATE SCHEMA "schema""name";
            CREATE TABLE "table""name" ("column""name" int);
            CREATE POLICY "policy""name" ON "table""name";
            CREATE TRIGGER "trigger""name" BEFORE INSERT ON "table""name"
                FOR EACH ROW EXECUTE FUNCTION "function""name"();
        "#,
    );

    match &facts[0] {
        StatementFact::CreateSchema { name, .. } => {
            assert_eq!(name.name.resolve(), "schema\"name");
        }
        _ => panic!("expected create schema fact"),
    }
    match &facts[1] {
        StatementFact::CreateTable { name, columns, .. } => {
            assert_eq!(name.name.resolve(), "table\"name");
            assert_eq!(columns[0].name, "column\"name");
        }
        _ => panic!("expected create table fact"),
    }
    match &facts[2] {
        StatementFact::CreatePolicy { name, .. } => assert_eq!(name, "policy\"name"),
        _ => panic!("expected create policy fact"),
    }
    match &facts[3] {
        StatementFact::CreateTrigger { name, function, .. } => {
            assert_eq!(name, "trigger\"name");
            assert_eq!(function.as_ref().unwrap().name.resolve(), "function\"name");
        }
        _ => panic!("expected create trigger fact"),
    }
}

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
fn test_begin_transaction() {
    let sql = "BEGIN;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::BeginTransaction => {}
        _ => panic!("Expected BeginTransaction fact"),
    }
}

#[test]
fn test_commit_transaction() {
    let sql = "COMMIT;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::CommitTransaction => {}
        _ => panic!("Expected CommitTransaction fact"),
    }
}

#[test]
fn test_rollback() {
    let sql = "ROLLBACK;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::RollbackTransaction => {}
        _ => panic!("Expected RollbackTransaction fact"),
    }
}

#[test]
fn test_rollback_to_savepoint() {
    let sql = "ROLLBACK TO SAVEPOINT sp1;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::RollbackToSavepoint { name } => {
            assert_eq!(name, "sp1");
        }
        _ => panic!("Expected RollbackToSavepoint fact"),
    }
}

#[test]
fn test_commit_and_chain() {
    let facts = parse_and_extract_statement("COMMIT AND CHAIN;");
    assert!(matches!(facts, Some(StatementFact::CommitAndChain)));

    let facts = parse_and_extract_statement("COMMIT AND NO CHAIN;");
    assert!(matches!(facts, Some(StatementFact::CommitTransaction)));
}

#[test]
fn prepared_transaction_completion_does_not_end_the_current_transaction() {
    for sql in [
        "COMMIT PREPARED 'migration';",
        "ROLLBACK PREPARED 'migration';",
    ] {
        assert_eq!(
            parse_and_extract_statement(sql),
            Some(StatementFact::OpaqueBlock),
            "{sql}"
        );
    }
}

#[test]
fn test_rollback_and_chain() {
    let facts = parse_and_extract_statement("ROLLBACK AND CHAIN;");
    assert!(matches!(facts, Some(StatementFact::RollbackAndChain)));

    let facts = parse_and_extract_statement("ROLLBACK AND NO CHAIN;");
    assert!(matches!(facts, Some(StatementFact::RollbackTransaction)));
}

#[test]
fn test_savepoint() {
    let sql = "SAVEPOINT sp1;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::Savepoint { name } => {
            assert_eq!(name, "sp1");
        }
        _ => panic!("Expected Savepoint fact"),
    }
}

#[test]
fn test_savepoint_identifier_casing_matches_postgres() {
    let unquoted = parse_and_extract_statement("SAVEPOINT MixedCase;").unwrap();
    assert!(matches!(
        unquoted,
        StatementFact::Savepoint { name } if name == "mixedcase"
    ));

    let quoted = parse_and_extract_statement("SAVEPOINT \"MixedCase\";").unwrap();
    assert!(matches!(
        quoted,
        StatementFact::Savepoint { name } if name == "MixedCase"
    ));

    let escaped = parse_and_extract_statement("SAVEPOINT \"a\"\"b\";").unwrap();
    assert!(matches!(
        escaped,
        StatementFact::Savepoint { name } if name == "a\"b"
    ));

    for (sql, expected) in [
        ("ROLLBACK TO MixedCase;", "mixedcase"),
        ("ROLLBACK TO \"MixedCase\";", "MixedCase"),
        ("RELEASE SAVEPOINT MixedCase;", "mixedcase"),
        ("RELEASE SAVEPOINT \"MixedCase\";", "MixedCase"),
    ] {
        let fact = parse_and_extract_statement(sql).unwrap();
        match fact {
            StatementFact::RollbackToSavepoint { name }
            | StatementFact::ReleaseSavepoint { name } => assert_eq!(name, expected),
            _ => panic!("expected savepoint reference"),
        }
    }
}

#[test]
fn test_release_savepoint() {
    let sql = "RELEASE SAVEPOINT sp1;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::ReleaseSavepoint { name } => {
            assert_eq!(name, "sp1");
        }
        _ => panic!("Expected ReleaseSavepoint fact"),
    }
}

#[test]
fn test_set_search_path_default() {
    let sql = "SET search_path TO DEFAULT;";
    let facts = parse_and_extract_statement(sql);
    assert!(facts.is_some());
    match facts.unwrap() {
        StatementFact::SetSearchPath {
            target: crate::_internal::analysis::facts::SearchPathTarget::Default,
            local: false,
        } => {}
        _ => panic!("Expected SetSearchPath fact"),
    }
}

#[test]
fn test_set_search_path_preserves_user_placeholder() {
    let facts = parse_and_extract_statement("SET search_path TO \"$user\", public;")
        .expect("search_path fact");
    assert_eq!(
        facts,
        StatementFact::SetSearchPath {
            target: crate::_internal::analysis::facts::SearchPathTarget::Schemas(vec![
                "$user".into(),
                "public".into(),
            ]),
            local: false,
        }
    );
}

#[test]
fn set_local_search_path_and_quoted_default_are_distinct() {
    assert_eq!(
        parse_and_extract_statement("SET LOCAL search_path TO private, public;"),
        Some(StatementFact::SetSearchPath {
            target: SearchPathTarget::Schemas(vec!["private".into(), "public".into()]),
            local: true,
        })
    );
    assert_eq!(
        parse_and_extract_statement("SET search_path TO \"default\";"),
        Some(StatementFact::SetSearchPath {
            target: SearchPathTarget::Schemas(vec!["default".into()]),
            local: false,
        })
    );
}

#[test]
fn create_role_and_user_apply_postgresql_defaults() {
    for (sql, expected_name, expected_inherits, expected_login) in [
        ("CREATE ROLE AppUser;", "appuser", true, false),
        (r#"CREATE ROLE "AppUser";"#, "AppUser", true, false),
        ("CREATE USER WebUser;", "webuser", true, true),
        (
            "CREATE ROLE service NOINHERIT LOGIN;",
            "service",
            false,
            true,
        ),
    ] {
        let Some(StatementFact::CreateRole(role)) = parse_and_extract_statement(sql) else {
            panic!("expected create role fact for {sql}");
        };
        assert_eq!(role.name, expected_name, "{sql}");
        assert_eq!(role.inherits, expected_inherits, "{sql}");
        assert_eq!(role.can_login, expected_login, "{sql}");
    }
}

#[test]
fn unsupported_create_role_options_are_not_silent_noops() {
    for sql in [
        "CREATE ROLE privileged SUPERUSER;",
        "CREATE USER app CREATEDB;",
        "CREATE ROLE member IN ROLE admins;",
    ] {
        let parsed = SourceFile::parse(sql);
        let statement = parsed.tree().stmts().next().expect("statement");
        assert!(
            AstVisitor::extract(&statement).is_none(),
            "unmodeled role option must use the opaque engine path: {sql}"
        );
    }
}

#[test]
fn alter_role_extracts_both_inherit_options() {
    for (sql, expected) in [
        ("ALTER ROLE app_user WITH INHERIT;", Some(true)),
        ("ALTER ROLE app_user WITH NOINHERIT;", Some(false)),
        ("ALTER ROLE app_user WITH LOGIN;", None),
    ] {
        let Some(StatementFact::AlterRole(role)) = parse_and_extract_statement(sql) else {
            panic!("expected alter role fact for {sql}");
        };
        assert_eq!(role.inherits, expected, "{sql}");
    }
}

#[test]
fn global_object_identifiers_follow_postgresql_case_rules() {
    let Some(StatementFact::CreatePublication(publication)) =
        parse_and_extract_statement(r#"CREATE PUBLICATION MixedPub FOR TABLE entries ("Camel");"#)
    else {
        panic!("expected publication fact");
    };
    assert_eq!(publication.name, "mixedpub");
    let PublicationScope::Explicit(objects) = publication.scope else {
        panic!("expected explicit publication objects");
    };
    let PublicationObjectFact::Table { columns, .. } = &objects[0] else {
        panic!("expected publication table");
    };
    assert_eq!(columns.as_deref(), Some(["Camel".to_string()].as_slice()));

    let Some(StatementFact::CreateSubscription(subscription)) = parse_and_extract_statement(
        "CREATE SUBSCRIPTION MixedSub CONNECTION 'host=localhost' PUBLICATION MixedPub;",
    ) else {
        panic!("expected subscription fact");
    };
    assert_eq!(subscription.name.as_deref(), Some("mixedsub"));
    assert_eq!(subscription.publications, vec!["mixedpub".to_string()]);

    let Some(StatementFact::AlterDatabase(database)) =
        parse_and_extract_statement(r#"ALTER DATABASE "MixedDb" RENAME TO "NewDb";"#)
    else {
        panic!("expected alter database fact");
    };
    assert_eq!(database.name.name.resolve(), "MixedDb");
    assert!(matches!(
        database.action,
        AlterDatabaseAction::Rename { to } if to == "NewDb"
    ));

    let Some(StatementFact::AlterDatabase(database)) =
        parse_and_extract_statement("ALTER DATABASE app OWNER TO AppOwner;")
    else {
        panic!("expected alter database owner fact");
    };
    assert!(matches!(
        database.action,
        AlterDatabaseAction::OwnerChange(crate::_internal::analysis::facts::RoleFact::Named { name, .. })
            if name == "appowner"
    ));
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
fn reset_extracts_only_modeled_settings() {
    for (sql, target) in [
        ("RESET ALL;", ResetSettingTarget::All),
        ("RESET search_path;", ResetSettingTarget::SearchPath),
        ("RESET lock_timeout;", ResetSettingTarget::LockTimeout),
        (
            "RESET statement_timeout;",
            ResetSettingTarget::StatementTimeout,
        ),
    ] {
        assert_eq!(
            parse_and_extract_statement(sql),
            Some(StatementFact::ResetSettings { target }),
            "{sql}"
        );
    }
    assert_eq!(
        parse_and_extract_statement("RESET application_name;"),
        Some(StatementFact::SchemaNeutralNoop)
    );
    assert!(parse_and_extract_statement("RESET synchronous_commit;").is_none());
    assert_eq!(
        parse_and_extract_statement("SET application_name = 'migration-check';"),
        Some(StatementFact::SchemaNeutralNoop)
    );
}

#[test]
fn test_set_time_zone_does_not_produce_a_search_path_fact() {
    assert!(parse_and_extract_statement("SET TIME ZONE DEFAULT;").is_none());
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
fn test_ident_resolve_quoted() {
    let ident = Ident::new("MyIdent".to_string(), true);
    assert_eq!(ident.resolve(), "MyIdent");
}

#[test]
fn test_ident_resolve_unquoted() {
    let ident = Ident::new("MyIdent".to_string(), false);
    assert_eq!(ident.resolve(), "myident");
}

#[test]
fn unquoted_identifiers_use_postgres_ascii_folding() {
    let ident = Ident::new("ÄTable".to_string(), false);
    assert_eq!(ident.resolve(), "Ätable");
}

#[test]
fn test_qualified_name_new() {
    let schema = Some(Ident::new("my_schema".to_string(), false));
    let name = Ident::new("my_table".to_string(), false);
    let qname = QualifiedName::new(schema.clone(), name.clone());
    assert!(qname.schema.is_some());
    assert_eq!(qname.name.resolve(), "my_table");
}

#[test]
fn test_expr_ir_is_volatile_literal() {
    let expr = ExprIr::Literal("static_value".into());
    assert!(!expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_omitted() {
    let expr = ExprIr::Omitted;
    assert!(!expr.is_volatile());
    assert!(expr.contains_opaque());
}

#[test]
fn test_expr_ir_opaque_sentinel_is_not_dependency_proof() {
    assert!(ExprIr::Sentinel("<complex>".into()).contains_opaque());
    assert!(!ExprIr::Literal("<case>".into()).contains_opaque());
    assert!(!ExprIr::Literal("'<'".into()).contains_opaque());
}

#[test]
fn test_expr_ir_nested_opaque_sentinel_is_detected() {
    let expr = ExprIr::BinaryOp {
        left: Box::new(ExprIr::ColumnRef("id".into())),
        op: "=".into(),
        right: Box::new(ExprIr::Sentinel("<complex>".into())),
    };
    assert!(expr.contains_opaque());
}

#[test]
fn test_expr_ir_structural_sentinels_are_detected() {
    assert!(
        ExprIr::FunctionCall {
            name: "<fn>".into(),
            args: vec![]
        }
        .contains_opaque()
    );
    assert!(
        ExprIr::BinaryOp {
            left: Box::new(ExprIr::ColumnRef("id".into())),
            op: "<op>".into(),
            right: Box::new(ExprIr::Literal("1".into())),
        }
        .contains_opaque()
    );
    assert!(
        ExprIr::Cast {
            expr: Box::new(ExprIr::ColumnRef("id".into())),
            target_type: "<type>".into(),
        }
        .contains_opaque()
    );
}

#[test]
fn test_expr_ir_is_volatile_now() {
    let expr = ExprIr::FunctionCall {
        name: "now".into(),
        args: vec![],
    };
    assert!(!expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_random() {
    let expr = ExprIr::FunctionCall {
        name: "random".into(),
        args: vec![],
    };
    assert!(expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_gen_random_uuid() {
    let expr = ExprIr::FunctionCall {
        name: "gen_random_uuid".into(),
        args: vec![],
    };
    assert!(expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_case_expr() {
    let expr = ExprIr::FunctionCall {
        name: "<case>".into(),
        args: vec![ExprIr::FunctionCall {
            name: "random".into(),
            args: vec![],
        }],
    };
    assert!(expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_binary_op() {
    let expr = ExprIr::BinaryOp {
        left: Box::new(ExprIr::FunctionCall {
            name: "random".into(),
            args: vec![],
        }),
        op: "||".into(),
        right: Box::new(ExprIr::Literal("test".into())),
    };
    assert!(expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_cast() {
    let expr = ExprIr::Cast {
        expr: Box::new(ExprIr::FunctionCall {
            name: "random".into(),
            args: vec![],
        }),
        target_type: "text".into(),
    };
    assert!(expr.is_volatile());
}

#[test]
fn test_clock_timestamp_is_volatile() {
    let expr = ExprIr::FunctionCall {
        name: "clock_timestamp".to_string(),
        args: vec![],
    };
    assert!(expr.is_volatile(), "clock_timestamp() should be VOLATILE");
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
fn set_role_named_produces_set_role_fact() {
    let fact = parse_and_extract_statement("SET ROLE app_user;").expect("should extract a fact");
    let StatementFact::SetRole {
        role,
        local,
        is_session_auth,
    } = fact
    else {
        panic!("expected SetRole, got {fact:?}");
    };
    assert_eq!(
        role,
        Some(crate::_internal::analysis::facts::RoleFact::Named {
            name: "app_user".to_string(),
            via_legacy_group_syntax: false,
        })
    );
    assert!(!local);
    assert!(!is_session_auth);
}

#[test]
fn set_local_role_sets_local_flag() {
    let fact =
        parse_and_extract_statement("SET LOCAL ROLE analyst;").expect("should extract a fact");
    let StatementFact::SetRole { local, .. } = fact else {
        panic!("expected SetRole");
    };
    assert!(local);
}

#[test]
fn set_role_none_produces_none_role() {
    let fact = parse_and_extract_statement("SET ROLE NONE;").expect("should extract a fact");
    let StatementFact::SetRole {
        role,
        local,
        is_session_auth,
    } = fact
    else {
        panic!("expected SetRole");
    };
    assert_eq!(role, None);
    assert!(!local);
    assert!(!is_session_auth);
}

#[test]
fn set_role_current_user_is_not_treated_as_valid_postgres_sql() {
    assert!(parse_and_extract_statement("SET ROLE CURRENT_USER;").is_none());
}

#[test]
fn set_role_current_role_is_not_treated_as_valid_postgres_sql() {
    assert!(parse_and_extract_statement("SET ROLE CURRENT_ROLE;").is_none());
}

#[test]
fn set_session_authorization_named_is_session_auth() {
    let fact = parse_and_extract_statement("SET SESSION AUTHORIZATION app_user;")
        .expect("should extract a fact");
    let StatementFact::SetRole {
        role,
        local,
        is_session_auth,
    } = fact
    else {
        panic!("expected SetRole");
    };
    assert_eq!(
        role,
        Some(crate::_internal::analysis::facts::RoleFact::Named {
            name: "app_user".to_string(),
            via_legacy_group_syntax: false,
        })
    );
    assert!(!local);
    assert!(is_session_auth);
}

#[test]
fn set_session_authorization_default_produces_none_role() {
    let fact = parse_and_extract_statement("SET SESSION AUTHORIZATION DEFAULT;")
        .expect("should extract a fact");
    let StatementFact::SetRole {
        role,
        is_session_auth,
        ..
    } = fact
    else {
        panic!("expected SetRole");
    };
    assert_eq!(role, None);
    assert!(is_session_auth);
}

#[test]
fn set_session_authorization_literal_unescapes_sql_quotes() {
    let fact = parse_and_extract_statement("SET SESSION AUTHORIZATION 'owner''s_role';")
        .expect("should extract a fact");
    let StatementFact::SetRole { role, .. } = fact else {
        panic!("expected SetRole");
    };
    assert_eq!(
        role,
        Some(crate::_internal::analysis::facts::RoleFact::Named {
            name: "owner's_role".to_string(),
            via_legacy_group_syntax: false,
        })
    );
}

#[test]
fn set_session_authorization_decodes_escape_string_literal() {
    let fact = parse_and_extract_statement(r"SET SESSION AUTHORIZATION E'app\x5fuser';")
        .expect("should extract a fact");
    let StatementFact::SetRole { role, .. } = fact else {
        panic!("expected SetRole");
    };
    assert_eq!(
        role,
        Some(crate::_internal::analysis::facts::RoleFact::Named {
            name: "app_user".to_string(),
            via_legacy_group_syntax: false,
        })
    );
}

#[test]
fn set_local_session_authorization_sets_local_flag() {
    let fact = parse_and_extract_statement("SET LOCAL SESSION AUTHORIZATION analyst;")
        .expect("should extract a fact");
    let StatementFact::SetRole {
        local,
        is_session_auth,
        ..
    } = fact
    else {
        panic!("expected SetRole");
    };
    assert!(local);
    assert!(is_session_auth);
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
