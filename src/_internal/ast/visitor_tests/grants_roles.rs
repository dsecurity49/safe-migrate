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
