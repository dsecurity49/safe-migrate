use super::*;

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
