use super::*;
use crate::_internal::model::index::{IndexPredicate, index_keys};

/// Coverage for a hand-built cache that retrieved the whole catalog.
fn fully_covering(schemas: Option<&[String]>) -> CatalogCoverage {
    CatalogCoverage::for_families(SchemaCoverage::from_sync_scope(schemas), CatalogFamily::ALL)
}

/// A hand-built cache that retrieved the whole catalog, ready for
/// `validate_semantics`.
fn synced_cache() -> DbCache {
    let mut cache = DbCache::new();
    cache.coverage = fully_covering(None);
    cache
}

fn table(id: ObjectId, columns: &[&str]) -> RelationState {
    let mut relation = RelationState::new(
        id,
        ObjectId::new("", "postgres"),
        0,
        None,
        RelationKind::Table,
        crate::_internal::model::relation::Persistence::Permanent,
        0,
    );
    relation.columns = columns
        .iter()
        .map(|name| crate::_internal::model::column::Column {
            name: (*name).to_string(),
            data_type: Some("integer".to_string()),
            type_id: None,
            is_nullable: false,
            default: None,
            avg_width: Some(4),
            default_expr_text: None,
            type_modifier: None,
            storage: None,
            compression: None,
            statistics_target: None,
            options: Default::default(),
            generated: None,
        })
        .collect();
    relation
}

#[test]
fn every_legacy_cache_variant_is_rejected_generically() {
    for (versioned, expected_version) in [
        (DbCacheVersioned::V1, 1),
        (DbCacheVersioned::V2, 2),
        (DbCacheVersioned::V3, 3),
        (DbCacheVersioned::V4, 4),
    ] {
        assert_eq!(versioned.format_version(), expected_version);
        assert_eq!(
            versioned.into_cache().unwrap_err(),
            "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
        );
    }
    let v5 = DbCacheVersioned::V5(Box::default());
    assert_eq!(v5.format_version(), 5);
    assert_eq!(
        v5.into_cache().unwrap_err(),
        "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
    );
    let v6 = DbCacheVersioned::V6(Box::default());
    assert_eq!(v6.format_version(), 6);
    assert_eq!(
        v6.into_cache().unwrap_err(),
        "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
    );
}

#[test]
fn current_cache_format_is_v11() {
    assert_eq!(CACHE_FORMAT_VERSION, 11);
    assert_eq!(DbCacheVersioned::V11(Box::default()).format_version(), 11);
    assert_eq!(CACHE_MAGIC, b"SMCACHE11");
}

#[test]
fn legacy_cache_versions_are_rejected_before_validation() {
    assert!(DbCacheVersioned::V9(Box::default()).into_cache().is_err());
    assert!(DbCacheVersioned::V1.into_cache().is_err());
}

#[test]
fn a_default_cache_claims_no_coverage_and_is_therefore_invalid() {
    // Nothing was read, so nothing can be proven absent.
    let cache = DbCache::new();
    assert!(cache.coverage.families.is_empty());
    assert!(cache.validate_semantics().is_err());
}

#[test]
fn coverage_records_exactly_the_families_whose_loaders_ran() {
    let mut builder = CatalogCoverageBuilder::from_sync_scope(None);
    builder.record(CatalogFamily::Schemas);
    builder.record(CatalogFamily::Types);

    let coverage = builder.finish();
    assert!(coverage.has(CatalogFamily::Schemas));
    assert!(coverage.has(CatalogFamily::Types));
    assert!(!coverage.has(CatalogFamily::Relations));
}

#[test]
fn a_synchronized_baseline_records_every_family() {
    // Reaching the end of `populate_cache_from_client` records all of them.
    let mut builder = CatalogCoverageBuilder::from_sync_scope(None);
    for family in CatalogFamily::ALL {
        builder.record(*family);
    }
    let coverage = builder.finish();
    assert_eq!(coverage.families.len(), CatalogFamily::ALL.len());
    assert!(synced_cache().validate_semantics().is_ok());
}

#[test]
fn current_cache_rejects_an_unsupported_postgresql_version() {
    let mut cache = synced_cache();
    cache.pg_version_num = Some(130_000);

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("PostgreSQL 14 or newer"));
}

#[test]
fn current_cache_rejects_malformed_relation_and_column_options() {
    let id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    let mut relation = table(id.clone(), &["id"]);
    relation
        .table_options
        .insert("".to_string(), "1".to_string());
    cache.insert_baseline(id.clone(), relation);
    assert!(
        cache
            .validate_semantics()
            .unwrap_err()
            .contains("malformed table option")
    );

    let mut cache = synced_cache();
    let mut relation = table(id.clone(), &["id"]);
    relation.columns[0]
        .options
        .insert("n_distinct".to_string(), "".to_string());
    cache.insert_baseline(id, relation);
    assert!(
        cache
            .validate_semantics()
            .unwrap_err()
            .contains("malformed column option")
    );
}

#[test]
fn current_cache_rejects_external_boundary_identity_outside_scope() {
    let mut cache = synced_cache();
    let schemas = vec!["public".to_string()];
    cache.coverage = fully_covering(Some(&schemas));
    cache.metadata.schemas = Some(schemas.clone());
    // The scoped endpoint is the one that must lie inside the scope.
    cache
        .scoped_external_dependencies
        .push(ScopedDependencyEdge::new(
            CatalogFamily::Relations,
            ObjectId::new("omitted", "scoped"),
            ObjectId::new("public", "table"),
        ));

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("outside the cache schema scope"), "{error}");

    // An external endpoint inside the scope is the contradictory case.
    let mut cache = synced_cache();
    cache.coverage = fully_covering(Some(&schemas));
    cache.metadata.schemas = Some(schemas);
    cache
        .scoped_external_dependencies
        .push(ScopedDependencyEdge::new(
            CatalogFamily::Relations,
            ObjectId::new("public", "scoped"),
            ObjectId::new("public", "table"),
        ));
    let error = cache.validate_semantics().unwrap_err();
    assert!(
        error.contains("must not be in the cache schema scope"),
        "{error}"
    );
}

#[test]
fn current_cache_accepts_unresolvable_external_endpoint() {
    let mut cache = synced_cache();
    let schemas = vec!["public".to_string()];
    cache.coverage = fully_covering(Some(&schemas));
    cache.metadata.schemas = Some(schemas);
    cache
        .scoped_external_dependencies
        .push(ScopedDependencyEdge::unresolved_external(
            CatalogFamily::Relations,
            ObjectId::new("public", "scoped"),
        ));

    // An unresolvable dependent is exposure we can neither model nor name,
    // so it is recorded rather than rejected.
    assert!(cache.validate_semantics().is_ok());
}

#[test]
fn scoped_external_edges_keep_family_distinct() {
    let mut cache = synced_cache();
    let schemas = vec!["public".to_string()];
    cache.coverage = fully_covering(Some(&schemas));
    cache.metadata.schemas = Some(schemas);
    let scoped = ObjectId::new("public", "widget");
    let external = ObjectId::new("other", "widget");
    cache
        .scoped_external_dependencies
        .push(ScopedDependencyEdge::new(
            CatalogFamily::Indexes,
            scoped.clone(),
            external.clone(),
        ));
    cache
        .scoped_external_dependencies
        .push(ScopedDependencyEdge::new(
            CatalogFamily::Relations,
            scoped,
            external,
        ));

    // A table and an index may share an identity, so the family stays part
    // of the key and the duplicate check does not fire.
    assert!(cache.validate_semantics().is_ok());
}

#[test]
fn current_cache_rejects_mismatched_embedded_identity() {
    let mut cache = synced_cache();
    cache.schemas.insert(
        "app".to_string(),
        SchemaState {
            name: "other".to_string(),
            owner: ObjectId::new("", "postgres"),
            generation: 0,
        },
    );

    let error = DbCacheVersioned::V11(Box::new(cache))
        .into_cache()
        .unwrap_err();
    assert!(error.contains("schema cache key 'app'"));
}

#[test]
fn current_cache_rejects_mismatched_schema_coverage() {
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["app".to_string()]);

    let error = DbCacheVersioned::V11(Box::new(cache))
        .into_cache()
        .unwrap_err();
    assert!(error.contains("schema coverage disagrees"));
}

#[test]
fn current_cache_rejects_typed_table_with_missing_or_mismatched_type() {
    let table_id = ObjectId::new("public", "addresses");
    let type_id = ObjectId::new("public", "address");
    let mut cache = synced_cache();
    let mut relation = table(table_id.clone(), &["zip"]);
    relation.of_type = Some(type_id.clone());
    cache.insert_baseline(table_id.clone(), relation.clone());
    assert!(
        cache
            .validate_semantics()
            .unwrap_err()
            .contains("references missing composite type")
    );

    cache.types.insert(
        type_id,
        TypeState {
            id: ObjectId::new("public", "address"),
            generation: 0,
            owner: ObjectId::new("", "postgres"),
            kind: TypeKind::Composite {
                fields: vec![crate::_internal::model::types::CompositeFieldState {
                    name: "street".to_string(),
                    data_type: "text".to_string(),
                    data_type_id: None,
                    collation: None,
                    collation_id: None,
                }],
            },
        },
    );
    assert!(
        cache
            .validate_semantics()
            .unwrap_err()
            .contains("does not match composite type")
    );
}

#[test]
fn current_cache_rejects_invalid_foreign_key_column_identity() {
    let child = ObjectId::new("public", "child");
    let parent = ObjectId::new("public", "parent");
    let mut cache = synced_cache();
    cache.insert_baseline(child.clone(), table(child.clone(), &["parent_id"]));
    cache.insert_baseline(parent.clone(), table(parent.clone(), &["id"]));
    cache.constraints.push(ConstraintState {
        table_id: child.clone(),
        name: "child_parent_id_fkey".to_string(),
        kind: crate::_internal::model::constraint::ConstraintKind::ForeignKey,
        validated: true,
        definition: None,
        backing_index: None,
    });
    cache.foreign_keys.push(ForeignKeyCache {
        constraint_name: "child_parent_id_fkey".to_string(),
        from_table: child,
        to_table: parent,
        from_columns: vec!["missing".to_string()],
        to_columns: vec!["id".to_string()],
        pk_fk_equality_operators: vec!["=".to_string()],
        pk_pk_equality_operators: vec!["=".to_string()],
        fk_fk_equality_operators: vec!["=".to_string()],
    });

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("missing source column 'public.child.missing'"));
}

#[test]
fn current_cache_rejects_repeated_foreign_key_columns() {
    let child = ObjectId::new("public", "child");
    let parent = ObjectId::new("public", "parent");
    let mut cache = synced_cache();
    cache.insert_baseline(child.clone(), table(child.clone(), &["a", "b"]));
    cache.insert_baseline(parent.clone(), table(parent.clone(), &["id", "other"]));
    cache.constraints.push(ConstraintState {
        table_id: child.clone(),
        name: "child_parent_fkey".to_string(),
        kind: ConstraintKind::ForeignKey,
        validated: true,
        definition: None,
        backing_index: None,
    });
    cache.foreign_keys.push(ForeignKeyCache {
        constraint_name: "child_parent_fkey".to_string(),
        from_table: child,
        to_table: parent,
        from_columns: vec!["a".to_string(), "a".to_string()],
        to_columns: vec!["id".to_string(), "other".to_string()],
        pk_fk_equality_operators: vec!["=".to_string(), "=".to_string()],
        pk_pk_equality_operators: vec!["=".to_string(), "=".to_string()],
        fk_fk_equality_operators: vec!["=".to_string(), "=".to_string()],
    });

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("repeats source column 'a'"));
}

#[test]
fn current_cache_rejects_incomplete_foreign_key_operator_evidence() {
    let child = ObjectId::new("public", "child");
    let parent = ObjectId::new("public", "parent");
    let mut cache = synced_cache();
    cache.insert_baseline(child.clone(), table(child.clone(), &["parent_id"]));
    cache.insert_baseline(parent.clone(), table(parent.clone(), &["id"]));
    cache.constraints.push(ConstraintState {
        table_id: child.clone(),
        name: "child_parent_fkey".into(),
        kind: ConstraintKind::ForeignKey,
        validated: true,
        definition: None,
        backing_index: None,
    });
    cache.foreign_keys.push(ForeignKeyCache {
        constraint_name: "child_parent_fkey".into(),
        from_table: child,
        to_table: parent,
        from_columns: vec!["parent_id".into()],
        to_columns: vec!["id".into()],
        pk_fk_equality_operators: vec!["".into()],
        pk_pk_equality_operators: vec!["=".into()],
        fk_fk_equality_operators: vec!["=".into()],
    });

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("incomplete PK/FK equality-operator evidence"));
}

#[test]
fn current_cache_accepts_a_valid_primary_key_record() {
    let parent = ObjectId::new("public", "parent");
    let mut cache = synced_cache();
    cache.insert_baseline(parent.clone(), table(parent.clone(), &["id"]));
    cache.constraints.push(ConstraintState {
        table_id: parent.clone(),
        name: "parent_pkey".to_string(),
        kind: ConstraintKind::PrimaryKey,
        validated: true,
        definition: None,
        backing_index: None,
    });
    cache.constraint_keys.push(ConstraintKeyCache {
        table_id: parent,
        constraint_name: "parent_pkey".to_string(),
        columns: vec!["id".to_string()],
        is_primary: true,
    });

    assert!(cache.validate_semantics().is_ok());
}

#[test]
fn current_cache_accepts_non_unique_exclusion_backing_index() {
    let table_id = ObjectId::new("public", "ranges");
    let index_id = ObjectId::new("public", "ranges_excl");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
    cache.indexes.push(IndexCache {
        index_id: index_id.clone(),
        table_id: table_id.clone(),
        definition: IndexDefinition {
            method: Some("gist".into()),
            keys: index_keys(vec!["id".to_string()]),
            included: index_keys(Vec::new()),
            expression_keys: 0,
            unique: false,
            nulls_not_distinct: Some(false),
            predicate: IndexPredicate::None,
            unestablished: false,
            valid: true,
            ready: true,
            live: true,
        },
        dependency_columns: vec!["id".to_string()],
        dependency_columns_known: true,
        is_immediate: true,
    });
    cache.constraints.push(ConstraintState {
        table_id,
        name: "ranges_excl_constraint".to_string(),
        kind: ConstraintKind::Exclusion,
        validated: true,
        definition: None,
        backing_index: Some(index_id),
    });

    assert!(cache.validate_semantics().is_ok());
}

#[test]
fn current_cache_rejects_population_state_on_non_materialized_relation() {
    let table_id = ObjectId::new("public", "events");
    let mut relation = table(table_id.clone(), &[]);
    relation.is_populated = Some(true);
    let mut cache = synced_cache();
    cache.insert_baseline(table_id, relation);

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("materialized-view population state"));
}

#[test]
fn current_cache_rejects_inconsistent_role_membership_edges() {
    let member = ObjectId::new("", "member");
    let parent = ObjectId::new("", "parent");
    let mut cache = synced_cache();
    cache.roles.insert(
        member.clone(),
        RoleState {
            id: member.clone(),
            can_login: true,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: vec![parent.clone()],
        },
    );
    cache.roles.insert(
        parent.clone(),
        RoleState {
            id: parent,
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("SET ROLE access") && error.contains("without membership"));
}

#[test]
fn current_cache_rejects_membership_options_without_membership() {
    let member = ObjectId::new("", "member");
    let parent = ObjectId::new("", "parent");
    let mut cache = synced_cache();
    cache.roles.insert(
        member.clone(),
        RoleState {
            id: member,
            can_login: true,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: vec![parent.clone()],
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    cache.roles.insert(
        parent.clone(),
        RoleState {
            id: parent,
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("ADMIN option") && error.contains("without membership"));
}

#[test]
fn current_cache_rejects_circular_role_membership() {
    let first = ObjectId::new("", "first");
    let second = ObjectId::new("", "second");
    let mut cache = synced_cache();
    cache.roles.insert(
        first.clone(),
        RoleState {
            id: first.clone(),
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: vec![second.clone()],
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: vec![second.clone()],
        },
    );
    cache.roles.insert(
        second.clone(),
        RoleState {
            id: second,
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: vec![first.clone()],
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: vec![first],
        },
    );

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("circular path"));
}

#[test]
fn current_cache_rejects_schema_qualified_role_identity() {
    let role = ObjectId::new("public", "app_role");
    let mut cache = synced_cache();
    cache.roles.insert(
        role.clone(),
        RoleState {
            id: role,
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("cluster role namespace"));
}

#[test]
fn current_cache_rejects_schema_qualified_role_membership_target() {
    let member = ObjectId::new("", "member");
    let parent = ObjectId::new("public", "parent");
    let mut cache = synced_cache();
    cache.roles.insert(
        member.clone(),
        RoleState {
            id: member,
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: vec![parent.clone()],
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: vec![parent.clone()],
        },
    );
    cache.roles.insert(
        parent.clone(),
        RoleState {
            id: parent,
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("cluster role namespace"));
}

#[test]
fn current_cache_rejects_invalid_column_inheritance_provenance() {
    for (column, parent_count, is_local) in [
        ("missing", 1, false),
        ("id", 0, false),
        ("id", u32::MAX, true),
    ] {
        let id = ObjectId::new("public", "entries");
        let mut relation = table(id.clone(), &["id"]);
        relation.column_inheritance.insert(
            column.into(),
            crate::_internal::model::relation::ColumnInheritance {
                parent_count,
                is_local,
            },
        );
        let mut cache = synced_cache();
        cache.insert_baseline(id, relation);
        assert!(
            cache
                .validate_semantics()
                .unwrap_err()
                .contains("inheritance provenance")
        );
    }
}

#[test]
fn current_cache_rejects_ambiguous_relation_columns() {
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id, &["id", "id"]));

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("duplicate column 'id'"));
}

#[test]
fn current_cache_rejects_empty_relation_column_identity() {
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id, &[""]));

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("empty identity"));
}

#[test]
fn current_cache_rejects_noncanonical_object_identities() {
    let mut quoted_whitespace = synced_cache();
    let id = ObjectId::new("public", " ");
    quoted_whitespace
        .relations
        .insert(id.clone(), table(id, &[" "]));
    assert!(quoted_whitespace.validate_semantics().is_ok());

    let mut empty_name = synced_cache();
    let id = ObjectId::new("public", "");
    empty_name.relations.insert(id.clone(), table(id, &[]));
    let error = empty_name.validate_semantics().unwrap_err();
    assert!(error.contains("empty object name"));

    let mut inferred = synced_cache();
    let mut id = ObjectId::new("public", "items");
    id.inferred_schema = true;
    inferred.relations.insert(id.clone(), table(id, &[]));
    let error = inferred.validate_semantics().unwrap_err();
    assert!(error.contains("inferred schema identity"));
}

#[test]
fn current_cache_rejects_ambiguous_schema_scope_and_search_path() {
    let mut duplicate_scope = DbCache::new();
    duplicate_scope.metadata.schemas = Some(vec!["app".into(), "app".into()]);
    let error = duplicate_scope.validate_semantics().unwrap_err();
    assert!(error.contains("duplicate schema 'app'"));

    let mut duplicate_path = DbCache::new();
    duplicate_path.search_path = vec!["public".into(), "public".into()];
    let error = duplicate_path.validate_semantics().unwrap_err();
    assert!(error.contains("search path contains duplicate schema 'public'"));
}

#[test]
fn current_cache_accepts_explicit_scope_in_caller_order() {
    let scope = vec!["public".to_string(), "app".to_string()];
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(scope.clone());
    cache.coverage = fully_covering(Some(&scope));
    assert!(cache.validate_semantics().is_ok());
}

#[test]
fn current_cache_rejects_owner_absent_from_role_catalog() {
    let table_id = ObjectId::new("public", "items");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id, &[]));
    let role_id = ObjectId::new("", "known_owner");
    cache.roles.insert(
        role_id.clone(),
        RoleState {
            id: role_id,
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("relation owner identity 'postgres'"));
}

#[test]
fn current_cache_rejects_empty_provenance_identities() {
    let mut cache = synced_cache();
    cache.metadata.source_role = Some(String::new());
    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("empty source role identity"));

    let mut cache = synced_cache();
    cache.metadata.source_search_path = Some(vec![String::new()]);
    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("source search path contains an empty"));

    let mut cache = synced_cache();
    cache.metadata.source_existing_schemas = Some(vec![String::new()]);
    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("source existing schemas contain an empty"));
}

#[test]
fn current_cache_rejects_malformed_publication_scope_metadata() {
    let table = crate::_internal::analysis::facts::PublicationObjectFact::Table {
        name: crate::_internal::ast::identifiers::QualifiedName::new(
            Some(crate::_internal::ast::identifiers::Ident::new(
                "public", false,
            )),
            crate::_internal::ast::identifiers::Ident::new("items", false),
        ),
        only: false,
        include_partitions: false,
        columns: Some(vec!["id".into(), "id".into()]),
        row_filter: None,
    };
    let mut cache = synced_cache();
    cache.publications.insert(
        "pub_items".into(),
        PublicationState {
            name: "pub_items".into(),
            owner: None,
            scope: crate::_internal::analysis::facts::PublicationScope::Explicit(vec![
                table.clone(),
                table,
            ]),
            params: Vec::new(),
            generation: 0,
        },
    );

    let error = DbCacheVersioned::V11(Box::new(cache))
        .into_cache()
        .unwrap_err();
    assert!(error.contains("empty or duplicate table column"));
}

#[test]
fn current_cache_rejects_subscription_owner_outside_role_catalog() {
    let mut cache = synced_cache();
    cache.roles.insert(
        ObjectId::new("", "present_owner"),
        RoleState {
            id: ObjectId::new("", "present_owner"),
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    cache.subscriptions.insert(
        "sub".into(),
        SubscriptionState {
            name: "sub".into(),
            owner: Some("missing_owner".into()),
            connection: crate::_internal::analysis::facts::ConnectionTarget::Redacted,
            publications: vec!["pub".into()],
            params: None,
            enabled: true,
            slot_name: None,
            generation: 0,
        },
    );

    let error = DbCacheVersioned::V11(Box::new(cache))
        .into_cache()
        .unwrap_err();
    assert!(error.contains("owner 'missing_owner' is absent"));
}

#[test]
fn current_cache_rejects_duplicate_view_dependencies() {
    let view = ObjectId::new("public", "active_entries");
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    let mut view_state = table(view.clone(), &["id"]);
    view_state.kind = RelationKind::View;
    cache.insert_baseline(view.clone(), view_state);
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
    let dependency = ViewDependencyCache {
        dependent: view,
        referenced: table_id,
        referenced_column: Some("id".into()),
    };
    cache.dependencies = vec![dependency.clone(), dependency];

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("appears more than once"));
}

#[test]
fn a_synced_cache_carries_view_dependencies_on_routines_and_types() {
    let view = ObjectId::new("public", "vsync");
    let mut cache = synced_cache();
    let mut view_state = table(view.clone(), &["a"]);
    view_state.kind = RelationKind::View;
    cache.insert_baseline(view.clone(), view_state);
    let routine = ObjectId::new("public", "fsync(integer)");
    let ty = ObjectId::new("public", "tsync_t");
    cache.view_object_dependencies = vec![
        ViewObjectDependencyCache {
            dependent: view.clone(),
            target: ViewDependencyTarget::Routine {
                routine: routine.clone(),
            },
        },
        ViewObjectDependencyCache {
            dependent: view.clone(),
            target: ViewDependencyTarget::Type { ty: ty.clone() },
        },
    ];
    cache
        .validate_semantics()
        .expect("valid view object dependencies");

    let state = crate::_internal::analysis::state::AnalysisState::new(cache);
    let edges = state.local.graph.views_for_function(&routine);
    assert_eq!(edges.len(), 1, "a synced view must block its routine");
    let edges = state.local.graph.views_for_type(&ty);
    assert_eq!(edges.len(), 1, "a synced view must block its type");
}

#[test]
fn current_cache_rejects_empty_view_dependency_column() {
    let view = ObjectId::new("public", "active_entries");
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    let mut view_state = table(view.clone(), &["id"]);
    view_state.kind = RelationKind::View;
    cache.insert_baseline(view.clone(), view_state);
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
    cache.dependencies.push(ViewDependencyCache {
        dependent: view,
        referenced: table_id,
        referenced_column: Some(String::new()),
    });

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("empty referenced column identity"));
}

#[test]
fn current_cache_rejects_privilege_for_missing_role() {
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    let mut relation = table(table_id.clone(), &["id"]);
    relation.privileges.grants.insert(
        ObjectId::new("", "missing_role"),
        [crate::_internal::model::relation::Privilege::Select]
            .into_iter()
            .collect(),
    );
    cache.insert_baseline(table_id, relation);

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("missing grantee role"));
}

#[test]
fn current_cache_allows_public_privilege_grantee() {
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    let mut relation = table(table_id.clone(), &["id"]);
    relation.privileges.grants.insert(
        ObjectId::new("", "public"),
        [crate::_internal::model::relation::Privilege::Select]
            .into_iter()
            .collect(),
    );
    cache.insert_baseline(table_id, relation);

    assert!(cache.validate_semantics().is_ok());
}

#[test]
fn current_cache_rejects_repeated_constraint_key_columns() {
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    cache.insert_baseline(
        table_id.clone(),
        table(table_id.clone(), &["id", "tenant_id"]),
    );
    cache.constraints.push(ConstraintState {
        table_id: table_id.clone(),
        name: "entries_key".to_string(),
        kind: ConstraintKind::Unique,
        validated: true,
        definition: None,
        backing_index: None,
    });
    cache.constraint_keys.push(ConstraintKeyCache {
        table_id,
        constraint_name: "entries_key".to_string(),
        columns: vec!["id".to_string(), "id".to_string()],
        is_primary: false,
    });

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("constraint key 'public.entries.entries_key' repeats column 'id'"));
}

#[test]
fn scoped_cache_accepts_a_dependency_to_an_omitted_schema() {
    let view_id = ObjectId::new("app", "v");
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["app".to_string()]);
    cache.coverage = fully_covering(cache.metadata.schemas.as_deref());
    cache.insert_baseline(
        view_id.clone(),
        RelationState::new(
            view_id.clone(),
            ObjectId::new("", "postgres"),
            0,
            None,
            crate::_internal::model::relation::RelationKind::View,
            crate::_internal::model::relation::Persistence::Permanent,
            0,
        ),
    );
    cache.dependencies.push(ViewDependencyCache {
        dependent: view_id,
        referenced: ObjectId::new("tenant", "base"),
        referenced_column: None,
    });

    assert!(cache.validate_semantics().is_ok());
}

#[test]
fn current_cache_rejects_view_dependency_on_a_missing_column() {
    let table_id = ObjectId::new("public", "entries");
    let view_id = ObjectId::new("public", "entry_view");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
    cache.insert_baseline(
        view_id.clone(),
        RelationState::new(
            view_id.clone(),
            ObjectId::new("", "postgres"),
            0,
            None,
            RelationKind::View,
            crate::_internal::model::relation::Persistence::Permanent,
            0,
        ),
    );
    cache.dependencies.push(ViewDependencyCache {
        dependent: view_id,
        referenced: table_id,
        referenced_column: Some("missing".to_string()),
    });

    assert!(
        cache
            .validate_semantics()
            .unwrap_err()
            .contains("references missing column")
    );
}

#[test]
fn current_cache_rejects_view_dependency_with_a_non_view_dependent() {
    let table_id = ObjectId::new("public", "entries");
    let referenced_id = ObjectId::new("public", "source");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
    cache.insert_baseline(referenced_id.clone(), table(referenced_id.clone(), &["id"]));
    cache.dependencies.push(ViewDependencyCache {
        dependent: table_id,
        referenced: referenced_id,
        referenced_column: Some("id".to_string()),
    });

    assert!(
        cache
            .validate_semantics()
            .unwrap_err()
            .contains("has a non-view dependent")
    );
}

#[test]
fn current_cache_rejects_constraint_dependency_on_a_missing_column() {
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
    cache
        .constraints
        .push(crate::_internal::model::constraint::ConstraintState {
            table_id: table_id.clone(),
            name: "entries_check".to_string(),
            kind: crate::_internal::model::constraint::ConstraintKind::Check,
            validated: true,
            definition: Some("id > 0".to_string()),
            backing_index: None,
        });
    cache
        .constraint_dependencies
        .push(ConstraintDependencyCache {
            table_id,
            constraint_name: "entries_check".to_string(),
            columns: vec!["missing".to_string()],
        });

    assert!(
        cache
            .validate_semantics()
            .unwrap_err()
            .contains("constraint dependency")
    );
}

#[test]
fn current_cache_rejects_generated_dependency_on_a_missing_source_column() {
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id", "total"]));
    cache
        .generated_column_dependencies
        .push(GeneratedColumnDependencyCache {
            table_id,
            column_name: "total".to_string(),
            depends_on_column: "missing".to_string(),
        });

    assert!(
        cache
            .validate_semantics()
            .unwrap_err()
            .contains("generated column dependency")
    );
}

#[test]
fn current_cache_rejects_self_referencing_generated_dependency() {
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["total"]));
    cache
        .generated_column_dependencies
        .push(GeneratedColumnDependencyCache {
            table_id,
            column_name: "total".to_string(),
            depends_on_column: "total".to_string(),
        });

    let error = cache.validate_semantics().unwrap_err();
    assert!(error.contains("cannot depend on itself"));
}

#[test]
fn current_cache_rejects_duplicate_generated_dependency_rows() {
    let table_id = ObjectId::new("public", "entries");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id", "total"]));
    let dependency = GeneratedColumnDependencyCache {
        table_id,
        column_name: "total".to_string(),
        depends_on_column: "id".to_string(),
    };
    cache.generated_column_dependencies.push(dependency.clone());
    cache.generated_column_dependencies.push(dependency);

    assert!(cache.validate_semantics().unwrap_err().contains(
        "generated column dependency 'public.entries.total -> id' appears more than once"
    ));
}
#[test]
fn current_cache_rejects_dangling_index_relationship() {
    let mut cache = synced_cache();
    cache.indexes.push(IndexCache {
        index_id: ObjectId::new("public", "items_idx"),
        table_id: ObjectId::new("public", "items"),
        definition: IndexDefinition {
            method: Some("btree".into()),
            keys: index_keys(vec!["id".into()]),
            included: index_keys(Vec::new()),
            expression_keys: 0,
            unique: false,
            nulls_not_distinct: Some(false),
            predicate: IndexPredicate::None,
            unestablished: false,
            valid: true,
            ready: true,
            live: true,
        },
        dependency_columns: vec!["id".into()],
        dependency_columns_known: true,
        is_immediate: true,
    });

    let error = DbCacheVersioned::V11(Box::new(cache))
        .into_cache()
        .unwrap_err();
    assert!(error.contains("references missing relation 'public.items'"));
}

#[test]
fn current_cache_rejects_index_in_a_different_schema_than_relation() {
    let table_id = ObjectId::new("public", "items");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
    cache.indexes.push(IndexCache {
        index_id: ObjectId::new("other", "items_idx"),
        table_id,
        definition: IndexDefinition {
            method: Some("btree".into()),
            keys: index_keys(vec!["id".into()]),
            included: index_keys(Vec::new()),
            expression_keys: 0,
            unique: false,
            nulls_not_distinct: Some(false),
            predicate: IndexPredicate::None,
            unestablished: false,
            valid: true,
            ready: true,
            live: true,
        },
        dependency_columns: vec!["id".into()],
        dependency_columns_known: true,
        is_immediate: true,
    });

    let error = DbCacheVersioned::V11(Box::new(cache))
        .into_cache()
        .unwrap_err();
    assert!(error.contains("must be in the same schema as indexed relation"));
}

#[test]
fn current_cache_rejects_index_colliding_with_relation_namespace_object() {
    let table_id = ObjectId::new("public", "items");
    let index_id = ObjectId::new("public", "shared_name");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id, &["id"]));
    cache.insert_baseline(index_id.clone(), table(index_id.clone(), &["id"]));
    cache.indexes.push(IndexCache {
        index_id,
        table_id: ObjectId::new("public", "items"),
        definition: IndexDefinition {
            method: Some("btree".into()),
            keys: index_keys(vec!["id".into()]),
            included: index_keys(Vec::new()),
            expression_keys: 0,
            unique: false,
            nulls_not_distinct: Some(false),
            predicate: IndexPredicate::None,
            unestablished: false,
            valid: true,
            ready: true,
            live: true,
        },
        dependency_columns: vec!["id".into()],
        dependency_columns_known: true,
        is_immediate: true,
    });

    let error = DbCacheVersioned::V11(Box::new(cache))
        .into_cache()
        .unwrap_err();
    assert!(error.contains("collides with another relation-namespace object"));
}

#[test]
fn current_cache_rejects_sequence_colliding_with_relation_namespace_object() {
    let table_id = ObjectId::new("public", "items");
    let shared_id = ObjectId::new("public", "shared_name");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id, &["id"]));
    cache.insert_baseline(shared_id.clone(), table(shared_id.clone(), &["id"]));
    cache.sequences.insert(
        shared_id.clone(),
        SequenceState {
            id: shared_id,
            owner: ObjectId::new("", "postgres"),
            owned_by: None,
            kind: crate::_internal::model::sequence::SequenceKind::Owned,
            parameters: Default::default(),
            runtime: crate::_internal::model::sequence::SequenceRuntime::unknown(),
            runtime_exact: false,
            generation: 0,
        },
    );

    let error = DbCacheVersioned::V11(Box::new(cache))
        .into_cache()
        .unwrap_err();
    assert!(error.contains("collides with another relation-namespace object"));
}

#[test]
fn current_cache_rejects_trigger_in_a_different_schema_than_table() {
    let table_id = ObjectId::new("public", "items");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
    cache.triggers.push(TriggerCache {
        trigger_id: ObjectId::new("other", "items_trigger"),
        table_id,
        function_id: ObjectId::new("public", "items_trigger_fn()"),
        row_level: true,
        parent_trigger_id: None,
        enabled_mode: TriggerEnableMode::Origin,
    });

    let error = DbCacheVersioned::V11(Box::new(cache))
        .into_cache()
        .unwrap_err();
    assert!(error.contains("must be in the same schema as trigger table"));
}

#[test]
fn current_cache_rejects_index_without_complete_dependency_evidence() {
    let table_id = ObjectId::new("public", "items");
    let mut cache = synced_cache();
    cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
    cache.indexes.push(IndexCache {
        index_id: ObjectId::new("public", "items_idx"),
        table_id,
        definition: IndexDefinition {
            method: Some("btree".into()),
            keys: index_keys(vec!["id".into()]),
            included: index_keys(Vec::new()),
            expression_keys: 0,
            unique: false,
            nulls_not_distinct: Some(false),
            predicate: IndexPredicate::None,
            unestablished: false,
            valid: true,
            ready: true,
            live: true,
        },
        dependency_columns: vec!["id".into()],
        dependency_columns_known: false,
        is_immediate: true,
    });

    assert!(
        DbCacheVersioned::current(cache)
            .into_cache()
            .unwrap_err()
            .contains("missing complete dependency-column evidence")
    );
}

#[test]
fn current_cache_validates_stable_direct_inheritance() {
    let parent = ObjectId::new("public", "parent");
    let child = ObjectId::new("public", "child");
    let mut cache = synced_cache();
    cache.search_path.clear();
    cache.insert_baseline(parent.clone(), table(parent.clone(), &["id"]));
    cache.insert_baseline(child.clone(), table(child.clone(), &["id"]));
    cache.inheritances.push(InheritanceCache {
        child: child.clone(),
        parent: parent.clone(),
        sequence: 1,
        is_partition: false,
        detach_pending: false,
    });
    assert!(
        DbCacheVersioned::current(cache.clone())
            .into_cache()
            .is_ok()
    );

    cache.inheritances[0].detach_pending = true;
    let error = DbCacheVersioned::V11(Box::new(cache))
        .into_cache()
        .unwrap_err();
    assert!(error.contains("pending detach requires"));
}

#[test]
fn current_cache_accepts_pending_partition_detach() {
    let parent = ObjectId::new("public", "parent");
    let child = ObjectId::new("public", "child");
    let mut cache = synced_cache();
    cache.search_path.clear();
    let mut parent_relation = table(parent.clone(), &["id"]);
    parent_relation.partition_type = Some("RANGE".into());
    let mut child_relation = table(child.clone(), &["id"]);
    child_relation.partition_bound = Some("FOR VALUES FROM (0) TO (10)".into());
    cache.insert_baseline(parent.clone(), parent_relation);
    cache.insert_baseline(child.clone(), child_relation);
    cache.inheritances.push(InheritanceCache {
        child,
        parent,
        sequence: 1,
        is_partition: true,
        detach_pending: true,
    });
    assert!(DbCacheVersioned::current(cache).into_cache().is_ok());
}

#[test]
fn current_cache_rejects_cross_catalog_contradictions() {
    let mut missing_search_schema = synced_cache();
    missing_search_schema.schemas.insert(
        "app".to_string(),
        SchemaState {
            name: "app".to_string(),
            owner: ObjectId::new("", "postgres"),
            generation: 0,
        },
    );
    assert!(
        missing_search_schema
            .validate_semantics()
            .unwrap_err()
            .contains("search path references missing schema 'public'")
    );

    let mut missing_sequence_owner = synced_cache();
    let sequence_id = ObjectId::new("public", "items_id_seq");
    missing_sequence_owner.sequences.insert(
        sequence_id.clone(),
        SequenceState {
            id: sequence_id,
            owner: ObjectId::new("", "postgres"),
            owned_by: Some((ObjectId::new("public", "items"), "id".to_string())),
            kind: crate::_internal::model::sequence::SequenceKind::Owned,
            parameters: Default::default(),
            runtime: crate::_internal::model::sequence::SequenceRuntime::unknown(),
            runtime_exact: false,
            generation: 0,
        },
    );
    assert!(
        missing_sequence_owner
            .validate_semantics()
            .unwrap_err()
            .contains("ownership references missing relation 'public.items'")
    );

    let mut cross_schema_sequence_owner = synced_cache();
    let table_id = ObjectId::new("public", "items");
    cross_schema_sequence_owner.insert_baseline(table_id.clone(), table(table_id, &["id"]));
    cross_schema_sequence_owner.sequences.insert(
        ObjectId::new("archive", "items_id_seq"),
        SequenceState {
            id: ObjectId::new("archive", "items_id_seq"),
            owner: ObjectId::new("", "postgres"),
            owned_by: Some((ObjectId::new("public", "items"), "id".to_string())),
            kind: crate::_internal::model::sequence::SequenceKind::Owned,
            parameters: Default::default(),
            runtime: crate::_internal::model::sequence::SequenceRuntime::unknown(),
            runtime_exact: false,
            generation: 0,
        },
    );
    assert!(
        cross_schema_sequence_owner
            .validate_semantics()
            .unwrap_err()
            .contains("must be in the same schema as owning table")
    );

    let mut missing_membership_role = synced_cache();
    let role_id = ObjectId::new("", "member");
    missing_membership_role.roles.insert(
        role_id.clone(),
        RoleState {
            id: role_id,
            can_login: true,
            is_superuser: false,
            inherits: true,
            member_of: vec![ObjectId::new("", "missing")],
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    assert!(
        missing_membership_role
            .validate_semantics()
            .unwrap_err()
            .contains("membership references missing role")
    );

    let mut invalid_view_dependency = synced_cache();
    invalid_view_dependency
        .dependencies
        .push(ViewDependencyCache {
            dependent: ObjectId::new("public", "view"),
            referenced: ObjectId::new("public", "missing"),
            referenced_column: None,
        });
    assert!(
        invalid_view_dependency
            .validate_semantics()
            .unwrap_err()
            .contains("references a missing relation")
    );
}

#[test]
fn current_cache_validates_extension_membership_and_configuration_tables() {
    let mut cache = synced_cache();
    cache.extensions.insert(
        "hstore".to_string(),
        ExtensionState {
            name: "hstore".to_string(),
            schema: Some("public".to_string()),
            version: Some("1.8".to_string()),
            relocatable: Some(true),
            owner: ObjectId::new("", "postgres"),
            members: [
                crate::_internal::model::extension::ExtensionMember {
                    kind: crate::_internal::model::extension::ExtensionMemberKind::Type,
                    id: ObjectId::new("public", "hstore"),
                },
                crate::_internal::model::extension::ExtensionMember {
                    kind: crate::_internal::model::extension::ExtensionMemberKind::Routine,
                    id: ObjectId::new("public", "hstore(record)"),
                },
            ]
            .into_iter()
            .collect(),
            members_complete: true,
            config_tables: vec![crate::_internal::model::extension::ExtensionConfigTable {
                table: ObjectId::new("public", "hstore_config"),
                condition: Some("id > 0".to_string()),
            }],
            generation: 0,
        },
    );
    cache.validate_semantics().unwrap();
}

#[test]
fn current_cache_rejects_extension_member_with_empty_identity() {
    let mut cache = synced_cache();
    cache.extensions.insert(
        "hstore".to_string(),
        ExtensionState {
            name: "hstore".to_string(),
            schema: None,
            version: None,
            relocatable: None,
            owner: ObjectId::new("", "postgres"),
            members: [crate::_internal::model::extension::ExtensionMember {
                kind: crate::_internal::model::extension::ExtensionMemberKind::Type,
                id: ObjectId::new("", ""),
            }]
            .into_iter()
            .collect(),
            members_complete: true,
            config_tables: Vec::new(),
            generation: 0,
        },
    );
    assert!(
        cache
            .validate_semantics()
            .unwrap_err()
            .contains("empty object name")
    );
}
