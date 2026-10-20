use super::*;

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
