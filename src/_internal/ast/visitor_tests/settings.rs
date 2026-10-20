use super::*;

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
