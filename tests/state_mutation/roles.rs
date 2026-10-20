use super::*;

#[test]
fn test_topology_role_lifecycle() {
    let engine = setup_engine();
    let mut state = setup_state();

    // Create
    let role_id = ObjectId::new("", "app_user");
    engine.analyze("CREATE ROLE app_user;", &mut state).unwrap();
    assert!(state.local.roles.contains_key(&role_id));

    // Alter
    engine
        .analyze("ALTER ROLE app_user WITH INHERIT;", &mut state)
        .unwrap();
    if let Some(safe_migrate::_internal::model::role::RoleOverlay::Present(role)) =
        state.local.roles.get(&role_id)
    {
        assert!(!role.can_login);
    } else {
        panic!("role app_user should be present");
    }

    // Drop
    engine.analyze("DROP ROLE app_user;", &mut state).unwrap();
    assert!(matches!(
        state.local.roles.get(&role_id),
        Some(safe_migrate::_internal::model::role::RoleOverlay::Dropped)
    ));
}

#[test]
fn create_user_and_role_login_options_are_distinct() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE USER web_user; CREATE ROLE worker LOGIN NOINHERIT; CREATE ROLE batch;",
            &mut state,
        )
        .unwrap();

    let Some(safe_migrate::_internal::model::role::RoleOverlay::Present(user)) =
        state.local.roles.get(&ObjectId::new("", "web_user"))
    else {
        panic!("user missing");
    };
    assert!(user.can_login);

    let Some(safe_migrate::_internal::model::role::RoleOverlay::Present(role)) =
        state.local.roles.get(&ObjectId::new("", "worker"))
    else {
        panic!("role missing");
    };
    assert!(role.can_login);

    let Some(safe_migrate::_internal::model::role::RoleOverlay::Present(batch)) =
        state.local.roles.get(&ObjectId::new("", "batch"))
    else {
        panic!("plain role missing");
    };
    assert!(!batch.can_login);
}

#[test]
fn unquoted_role_and_replication_names_are_case_folded() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
        .analyze(
            "CREATE ROLE AppUser;
                 CREATE ROLE appuser;
                 CREATE PUBLICATION MixedPub FOR ALL TABLES;
                 CREATE PUBLICATION mixedpub FOR ALL TABLES;",
            &mut state,
        )
        .unwrap();

    assert_eq!(
        violations
            .iter()
            .filter(|violation| violation.rule_id == "chain-conflict")
            .count(),
        2
    );
}

#[test]
fn table_drop_resolves_unqualified_publication_membership_through_search_path() {
    let engine = setup_engine();
    let mut cache = cache_with_table("tenant", "entries", None);
    cache.search_path = vec!["tenant".into()];
    cache.publications.insert(
        "changes".into(),
        safe_migrate::_internal::model::replication::PublicationState {
            name: "changes".into(),
            owner: Some("postgres".into()),
            scope: safe_migrate::_internal::analysis::facts::PublicationScope::Explicit(vec![
                safe_migrate::_internal::analysis::facts::PublicationObjectFact::Table {
                    name: safe_migrate::_internal::ast::identifiers::QualifiedName::new(
                        None,
                        safe_migrate::_internal::ast::identifiers::Ident::new("entries", true),
                    ),
                    only: true,
                    include_partitions: false,
                    columns: None,
                    row_filter: None,
                },
            ]),
            params: Vec::new(),
            generation: 0,
        },
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine.analyze("DROP TABLE entries;", &mut state).unwrap();

    let Some(safe_migrate::_internal::model::replication::PublicationOverlay::Present(publication)) =
        state.local.publications.get("changes")
    else {
        panic!("publication missing");
    };
    assert!(matches!(
        &publication.scope,
        safe_migrate::_internal::analysis::facts::PublicationScope::Explicit(objects)
            if objects.is_empty()
    ));
}

#[test]
fn test_state_grant_revoke_topology() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE TABLE t(id int); GRANT SELECT ON t TO public;",
            &mut state,
        )
        .unwrap();

    assert!(state.relation_is_present(&object_id("public", "t")));
    assert_eq!(state.local.confidence, Confidence::Exact);

    engine
        .analyze("REVOKE SELECT ON t FROM public;", &mut state)
        .unwrap();
    assert!(state.relation_is_present(&object_id("public", "t")));
}

#[test]
fn grant_option_changes_preserve_effective_privilege_state() {
    let engine = setup_engine();
    let mut state = setup_state();
    let role = object_id("", "app_user");
    let table = object_id("public", "grant_option_table");

    engine
            .analyze(
                "CREATE TABLE grant_option_table(id int); GRANT SELECT ON grant_option_table TO app_user WITH GRANT OPTION;",
                &mut state,
            )
            .unwrap();
    let RelationOverlay::Present(relation) = state.local.relations.get(&table).unwrap() else {
        panic!("table missing");
    };
    assert!(relation.privileges.has_privilege(&role, Privilege::Select));
    assert!(
        relation
            .privileges
            .has_grant_option(&role, Privilege::Select)
    );

    engine
        .analyze(
            "REVOKE GRANT OPTION FOR SELECT ON grant_option_table FROM app_user;",
            &mut state,
        )
        .unwrap();
    let RelationOverlay::Present(relation) = state.local.relations.get(&table).unwrap() else {
        panic!("table missing");
    };
    assert!(relation.privileges.has_privilege(&role, Privilege::Select));
    assert!(
        !relation
            .privileges
            .has_grant_option(&role, Privilege::Select)
    );
}

#[test]
fn targeted_revoke_without_acl_provenance_is_tainted() {
    let engine = setup_engine();
    let table_id = object_id("public", "provenance_table");
    let reader = object_id("", "reader");
    let owner = object_id("", "owner");
    let mut cache = cache_with_table("public", "provenance_table", None);
    cache.metadata.source_role = Some(owner.name.clone());
    cache.metadata.source_session_role = Some(owner.name.clone());
    cache.roles.insert(
        owner.clone(),
        RoleState {
            id: owner.clone(),
            can_login: true,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    cache.roles.insert(
        reader.clone(),
        RoleState {
            id: reader.clone(),
            can_login: true,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    if let Some(relation) = cache.relations.get_mut(&table_id) {
        // The helper's default owner is schema-qualified; use the
        // cluster role that executes the targeted revoke.
        relation.owner = owner.clone();
        let privileges = &mut relation.privileges;
        let select: std::collections::HashSet<_> = [Privilege::Select].into_iter().collect();
        // Deliberately model a legacy/hand-built ACL: the privilege and
        // grant option exist, but their grantor provenance is absent.
        privileges.grant(reader.clone(), select.clone());
        privileges.grant_options.insert(reader.clone(), select);
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let _findings = engine
        .analyze(
            "REVOKE SELECT ON provenance_table FROM reader GRANTED BY owner;",
            &mut state,
        )
        .unwrap();

    assert_eq!(state.local.confidence, Confidence::Tainted);
}

#[test]
fn object_granted_by_must_match_the_current_role() {
    let engine = setup_engine();
    let table_id = object_id("public", "explicit_grantor_table");
    let mut cache = synced_cache();
    cache.metadata.source_role = Some("current_user".into());
    cache.metadata.source_session_role = Some("current_user".into());
    for name in ["current_user", "other_grantor", "reader"] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let mut relation = RelationState::new(
        table_id.clone(),
        object_id("", "owner"),
        0,
        Some(1),
        RelationKind::Table,
        Persistence::Permanent,
        0,
    );
    relation.privileges.grant_with_option(
        object_id("", "other_grantor"),
        [Privilege::Select].into_iter().collect(),
    );
    cache.insert_baseline(table_id, relation);
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let findings = engine
        .analyze(
            "GRANT SELECT ON explicit_grantor_table TO reader GRANTED BY other_grantor;",
            &mut state,
        )
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
    let RelationOverlay::Present(relation) = state
        .get_relation(&object_id("public", "explicit_grantor_table"))
        .unwrap()
    else {
        panic!("relation missing");
    };
    assert!(
        !relation
            .privileges
            .has_privilege(&object_id("", "reader"), Privilege::Select)
    );

    let findings = engine
        .analyze(
            "GRANT SELECT ON ALL TABLES IN SCHEMA public TO reader GRANTED BY other_grantor;",
            &mut state,
        )
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
}

#[test]
fn inherited_grant_option_authorizes_a_delegated_grant() {
    let engine = setup_engine();
    let table_id = object_id("public", "inherited_grant_table");
    let parent = object_id("", "grant_parent");
    let member = object_id("", "grant_member");
    let mut cache = synced_cache();
    cache.pg_version_num = Some(160_000);
    cache.metadata.source_role = Some("grant_member".into());
    cache.metadata.source_session_role = Some("grant_member".into());
    cache.roles.insert(
        parent.clone(),
        RoleState {
            id: parent.clone(),
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    cache.roles.insert(
        member.clone(),
        RoleState {
            id: member.clone(),
            can_login: true,
            is_superuser: false,
            inherits: true,
            member_of: vec![parent.clone()],
            can_administer_membership: Vec::new(),
            can_inherit_from: vec![parent.clone()],
            can_set_role_to: Vec::new(),
        },
    );
    let delegated = object_id("", "delegated_user");
    cache.roles.insert(
        delegated.clone(),
        RoleState {
            id: delegated,
            can_login: true,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    let mut relation = RelationState::new(
        table_id.clone(),
        object_id("", "owner"),
        0,
        Some(1),
        RelationKind::Table,
        Persistence::Permanent,
        0,
    );
    relation
        .privileges
        .grant_with_option(parent, [Privilege::Select].into_iter().collect());
    cache.insert_baseline(table_id, relation);
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let violations = engine
        .analyze(
            "GRANT SELECT ON inherited_grant_table TO delegated_user;",
            &mut state,
        )
        .unwrap();
    assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
    let RelationOverlay::Present(relation) = state
        .get_relation(&object_id("public", "inherited_grant_table"))
        .unwrap()
    else {
        panic!("relation missing");
    };
    assert!(
        relation
            .privileges
            .has_privilege(&object_id("", "delegated_user"), Privilege::Select)
    );
}

#[test]
fn membership_without_inherit_option_cannot_delegate_grants() {
    let engine = setup_engine();
    let table_id = object_id("public", "non_inherited_grant_table");
    let parent = object_id("", "grant_parent");
    let member = object_id("", "grant_member");
    let mut cache = synced_cache();
    cache.pg_version_num = Some(160_000);
    cache.metadata.source_role = Some("grant_member".into());
    cache.metadata.source_session_role = Some("grant_member".into());
    for (id, can_inherit_from) in [(parent.clone(), Vec::new()), (member.clone(), Vec::new())] {
        let is_member = id == member;
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: if is_member {
                    vec![parent.clone()]
                } else {
                    Vec::new()
                },
                can_administer_membership: Vec::new(),
                can_inherit_from,
                can_set_role_to: Vec::new(),
            },
        );
    }
    let delegated = object_id("", "delegated_user");
    cache.roles.insert(
        delegated.clone(),
        RoleState {
            id: delegated,
            can_login: true,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    let mut relation = RelationState::new(
        table_id.clone(),
        object_id("", "owner"),
        0,
        Some(1),
        RelationKind::Table,
        Persistence::Permanent,
        0,
    );
    relation
        .privileges
        .grant_with_option(parent, [Privilege::Select].into_iter().collect());
    cache.insert_baseline(table_id, relation);
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let violations = engine
        .analyze(
            "GRANT SELECT ON non_inherited_grant_table TO delegated_user;",
            &mut state,
        )
        .unwrap();
    assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
    let RelationOverlay::Present(relation) = state
        .get_relation(&object_id("public", "non_inherited_grant_table"))
        .unwrap()
    else {
        panic!("relation missing");
    };
    assert!(
        !relation
            .privileges
            .has_privilege(&object_id("", "delegated_user"), Privilege::Select)
    );
}

#[test]
fn pg16_membership_inherit_option_overrides_member_noinherit() {
    let engine = setup_engine();
    let table_id = object_id("public", "membership_option_table");
    let parent = object_id("", "grant_parent");
    let member = object_id("", "grant_member");
    let delegated = object_id("", "delegated_user");
    let mut cache = synced_cache();
    cache.pg_version_num = Some(160_000);
    cache.metadata.source_role = Some(member.name.clone());
    cache.metadata.source_session_role = Some(member.name.clone());
    for (id, inherits, can_inherit_from) in [
        (parent.clone(), true, Vec::new()),
        (member.clone(), false, vec![parent.clone()]),
        (delegated.clone(), true, Vec::new()),
    ] {
        cache.roles.insert(
            id.clone(),
            RoleState {
                id: id.clone(),
                can_login: true,
                is_superuser: false,
                inherits,
                member_of: (id == member)
                    .then_some(parent.clone())
                    .into_iter()
                    .collect(),
                can_administer_membership: Vec::new(),
                can_inherit_from,
                can_set_role_to: Vec::new(),
            },
        );
    }
    let mut relation = RelationState::new(
        table_id.clone(),
        object_id("", "owner"),
        0,
        Some(1),
        RelationKind::Table,
        Persistence::Permanent,
        0,
    );
    relation
        .privileges
        .grant_with_option(parent, [Privilege::Select].into_iter().collect());
    cache.insert_baseline(table_id, relation);
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let findings = engine
        .analyze(
            "GRANT SELECT ON membership_option_table TO delegated_user;",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
}

#[test]
fn pg15_alter_role_inherit_activates_existing_membership() {
    let engine = setup_engine();
    let table_id = object_id("public", "legacy_inherit_table");
    let parent = object_id("", "grant_parent");
    let member = object_id("", "grant_member");
    let delegated = object_id("", "delegated_user");
    let mut cache = synced_cache();
    cache.pg_version_num = Some(150_000);
    cache.metadata.source_role = Some(member.name.clone());
    cache.metadata.source_session_role = Some(member.name.clone());
    for (id, inherits) in [
        (parent.clone(), true),
        (member.clone(), false),
        (delegated.clone(), true),
    ] {
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: true,
                is_superuser: false,
                inherits,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let member_state = cache.roles.get_mut(&member).expect("member role exists");
    member_state.member_of.push(parent.clone());
    member_state.can_inherit_from.push(parent.clone());

    let mut relation = RelationState::new(
        table_id.clone(),
        object_id("", "owner"),
        0,
        Some(1),
        RelationKind::Table,
        Persistence::Permanent,
        0,
    );
    relation
        .privileges
        .grant_with_option(parent, [Privilege::Select].into_iter().collect());
    cache.insert_baseline(table_id, relation);
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let findings = engine
        .analyze(
            "ALTER ROLE grant_member INHERIT; \
                 GRANT SELECT ON legacy_inherit_table TO delegated_user;",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
}

#[test]
fn inherited_admin_option_authorizes_role_membership_grants() {
    let engine = setup_engine();
    let actor = object_id("", "membership_actor");
    let delegator = object_id("", "membership_delegator");
    let target = object_id("", "membership_target");
    let recipient = object_id("", "membership_recipient");
    let mut cache = synced_cache();
    cache.pg_version_num = Some(160_000);
    cache.metadata.source_role = Some(actor.name.clone());
    cache.metadata.source_session_role = Some(actor.name.clone());
    for (id, member_of, can_inherit_from, can_administer_membership) in [
        (
            actor.clone(),
            vec![delegator.clone()],
            vec![delegator.clone()],
            Vec::new(),
        ),
        (
            delegator.clone(),
            Vec::new(),
            Vec::new(),
            vec![target.clone()],
        ),
        (target.clone(), Vec::new(), Vec::new(), Vec::new()),
        (recipient.clone(), Vec::new(), Vec::new(), Vec::new()),
    ] {
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: true,
                is_superuser: false,
                inherits: false,
                member_of,
                can_administer_membership,
                can_inherit_from,
                can_set_role_to: Vec::new(),
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let findings = engine
        .analyze(
            "GRANT membership_target TO membership_recipient;",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict")
    );
    let RoleOverlay::Present(recipient) = state
        .local
        .roles
        .get(&object_id("", "membership_recipient"))
        .unwrap()
    else {
        panic!("recipient role unexpectedly dropped");
    };
    assert_eq!(recipient.member_of, vec![target]);
}

#[test]
fn revoke_cascade_removes_grants_delegated_by_the_revoked_role() {
    let engine = setup_engine();
    let table_id = object_id("public", "cascade_grant_table");
    let owner = object_id("", "grant_owner");
    let delegate = object_id("", "grant_delegate");
    let reader = object_id("", "grant_reader");
    let mut cache = synced_cache();
    cache.metadata.source_role = Some("grant_owner".into());
    cache.metadata.source_session_role = Some("grant_owner".into());
    for (id, can_set_role_to) in [
        (owner.clone(), vec![delegate.clone()]),
        (delegate.clone(), vec![owner.clone()]),
        (reader.clone(), Vec::new()),
    ] {
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to,
            },
        );
    }
    cache.insert_baseline(
        table_id.clone(),
        RelationState::new(
            table_id,
            owner.clone(),
            0,
            Some(1),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
    engine
            .analyze(
                "GRANT SELECT ON cascade_grant_table TO grant_delegate WITH GRANT OPTION; SET ROLE grant_delegate; GRANT SELECT ON cascade_grant_table TO grant_reader WITH GRANT OPTION; SET ROLE grant_owner;",
                &mut state,
            )
            .unwrap();
    let violations = engine
        .analyze(
            "REVOKE SELECT ON cascade_grant_table FROM grant_delegate CASCADE;",
            &mut state,
        )
        .unwrap();
    assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
    let RelationOverlay::Present(relation) = state
        .get_relation(&object_id("public", "cascade_grant_table"))
        .unwrap()
    else {
        panic!("relation missing");
    };
    assert!(
        !relation
            .privileges
            .has_privilege(&delegate, Privilege::Select)
    );
    assert!(
        !relation
            .privileges
            .has_privilege(&reader, Privilege::Select)
    );
}

#[test]
fn test_revoke_all_cascade_removes_privileges_and_downstream_grants() {
    use safe_migrate::_internal::model::role::RoleState;

    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    let table_id = object_id("public", "revoke_all_table");
    let owner = object_id("", "owner");
    let intermediate = object_id("", "intermediate");
    let leaf = object_id("", "leaf");

    cache.metadata.source_session_role = Some("owner".into());
    for (id, can_set_role_to) in [
        (owner.clone(), vec![intermediate.clone()]),
        (intermediate.clone(), vec![owner.clone()]),
        (leaf.clone(), Vec::new()),
    ] {
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to,
            },
        );
    }
    cache.insert_baseline(
        table_id.clone(),
        RelationState::new(
            table_id.clone(),
            owner.clone(),
            0,
            Some(1),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
    engine
            .analyze(
                "GRANT SELECT, UPDATE ON revoke_all_table TO intermediate WITH GRANT OPTION; SET ROLE intermediate; GRANT SELECT ON revoke_all_table TO leaf; SET ROLE owner;",
                &mut state,
            )
            .unwrap();

    let relation = match state.get_relation(&table_id).unwrap() {
        RelationOverlay::Present(r) => r,
        _ => panic!("relation missing"),
    };
    assert!(
        relation
            .privileges
            .has_privilege(&intermediate, Privilege::Select)
    );
    assert!(
        relation
            .privileges
            .has_privilege(&intermediate, Privilege::Update)
    );
    assert!(relation.privileges.has_privilege(&leaf, Privilege::Select));

    let violations = engine
        .analyze(
            "REVOKE ALL ON revoke_all_table FROM intermediate CASCADE;",
            &mut state,
        )
        .unwrap();
    assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));

    let relation = match state.get_relation(&table_id).unwrap() {
        RelationOverlay::Present(r) => r,
        _ => panic!("relation missing"),
    };

    assert!(
        !relation
            .privileges
            .has_privilege(&intermediate, Privilege::Select)
    );
    assert!(
        !relation
            .privileges
            .has_privilege(&intermediate, Privilege::Update)
    );
    assert!(!relation.privileges.has_privilege(&leaf, Privilege::Select));
}

#[test]
fn set_role_updates_current_role_and_owner_assignments() {
    let engine = setup_engine();
    let mut state = setup_state();
    assert_eq!(state.local.current_role, "postgres");
    assert!(!state.local.current_role_known); // default mock state

    engine
        .analyze(
            "SET ROLE app_admin;
                 CREATE TABLE admin_log(id int);",
            &mut state,
        )
        .unwrap();

    assert_eq!(state.local.current_role, "app_admin");
    assert!(state.local.current_role_known);
    // session_role should not have changed
    assert_eq!(state.local.session_role, "postgres");
    assert!(!state.local.session_role_known);

    // The table should be owned by app_admin
    let rel = state
        .get_relation(&object_id("public", "admin_log"))
        .unwrap();
    if let RelationOverlay::Present(r) = rel {
        assert_eq!(r.owner, object_id("", "app_admin"));
    } else {
        panic!("Expected admin_log to be present");
    }
}

#[test]
fn role_inherit_option_is_preserved_across_create_and_alter() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE ROLE no_inherit NOINHERIT;
                 ALTER ROLE no_inherit INHERIT;",
            &mut state,
        )
        .unwrap();

    let role_id = object_id("", "no_inherit");
    let RoleOverlay::Present(role) = state.local.roles.get(&role_id).unwrap() else {
        panic!("expected role to be present");
    };
    assert!(role.inherits);
}

#[test]
fn set_session_authorization_updates_session_role_and_allows_reset() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.metadata.source_role = Some("app_user".to_string());
    cache.metadata.source_session_role = Some("app_user".to_string());
    for (name, superuser) in [
        ("app_user", true),
        ("new_owner", false),
        ("temp_role", false),
    ] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: true,
                is_superuser: superuser,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    assert_eq!(state.local.current_role, "app_user");
    assert_eq!(state.local.session_role, "app_user");

    engine
        .analyze(
            "SET SESSION AUTHORIZATION new_owner;
                 SET ROLE NONE;
                 SET SESSION AUTHORIZATION DEFAULT;",
            &mut state,
        )
        .unwrap();

    assert_eq!(state.local.current_role, "app_user");
    assert_eq!(state.local.session_role, "app_user");
    assert_eq!(state.local.authenticated_role, "app_user");
}

#[test]
fn set_role_is_rolled_back_on_abort() {
    let engine = setup_engine();
    let mut state = setup_state();

    state.local.current_role = "start_role".to_string();
    state.local.current_role_known = true;

    engine
        .analyze(
            "BEGIN;
                 SET ROLE temp_admin;
                 CREATE TABLE inside_txn(id int);
                 ROLLBACK;
                 CREATE TABLE outside_txn(id int);",
            &mut state,
        )
        .unwrap();

    // Outside the transaction, the role should be restored
    assert_eq!(state.local.current_role, "start_role");

    // Table inside txn was rolled back, so it shouldn't exist
    assert!(
        state
            .get_relation(&object_id("public", "inside_txn"))
            .is_none()
    );

    // Table outside txn was created by start_role
    if let RelationOverlay::Present(r) = state
        .get_relation(&object_id("public", "outside_txn"))
        .unwrap()
    {
        assert_eq!(r.owner, object_id("", "start_role"));
    } else {
        panic!("missing outside_txn");
    }
}

#[test]
fn local_role_expires_on_commit_while_session_role_setting_persists() {
    let engine = setup_engine();
    let mut state = setup_state();
    state.local.current_role = "login_role".into();
    state.local.current_role_known = true;
    state.local.persistent_current_role = "login_role".into();
    state.local.persistent_current_role_known = true;
    state.local.session_role = "login_role".into();
    state.local.session_role_known = true;

    engine
        .analyze(
            "BEGIN;
                 SET LOCAL ROLE local_role;
                 CREATE TABLE local_owned(id int);
                 COMMIT;
                 CREATE TABLE login_owned(id int);
                 BEGIN;
                 SET ROLE persistent_role;
                 COMMIT;
                 CREATE TABLE persistent_owned(id int);",
            &mut state,
        )
        .unwrap();

    let owner = |table: &str| match state
        .get_relation(&object_id("public", table))
        .expect("table")
    {
        RelationOverlay::Present(relation) => relation.owner.name.clone(),
        RelationOverlay::Dropped => panic!("table dropped"),
    };
    assert_eq!(owner("local_owned"), "local_role");
    assert_eq!(owner("login_owned"), "login_role");
    assert_eq!(owner("persistent_owned"), "persistent_role");
}

#[test]
fn local_role_outside_transaction_has_no_effect() {
    let engine = setup_engine();
    let mut state = setup_state();
    state.local.current_role = "login_role".into();
    state.local.current_role_known = true;
    state.local.persistent_current_role = "login_role".into();
    state.local.persistent_current_role_known = true;

    engine
        .analyze(
            "SET LOCAL ROLE ignored_role;
                 CREATE TABLE still_login_owned(id int);",
            &mut state,
        )
        .unwrap();

    let RelationOverlay::Present(relation) = state
        .get_relation(&object_id("public", "still_login_owned"))
        .unwrap()
    else {
        panic!("table missing");
    };
    assert_eq!(relation.owner, object_id("", "login_role"));
}

#[test]
fn session_authorization_local_and_rollback_restore_all_identity_fields() {
    let engine = setup_engine();
    let mut state = setup_state();
    for field in [
        &mut state.local.current_role,
        &mut state.local.persistent_current_role,
        &mut state.local.session_role,
        &mut state.local.persistent_session_role,
        &mut state.local.authenticated_role,
    ] {
        *field = "login_role".into();
    }
    state.local.current_role_known = true;
    state.local.persistent_current_role_known = true;
    state.local.session_role_known = true;
    state.local.persistent_session_role_known = true;
    state.local.authenticated_role_known = true;

    engine
        .analyze(
            "BEGIN;
                 SET LOCAL SESSION AUTHORIZATION local_auth;
                 CREATE TABLE local_auth_owned(id int);
                 COMMIT;
                 CREATE TABLE login_auth_owned(id int);
                 BEGIN;
                 SET SESSION AUTHORIZATION rolled_back_auth;
                 ROLLBACK;",
            &mut state,
        )
        .unwrap();

    assert_eq!(state.local.current_role, "login_role");
    assert_eq!(state.local.session_role, "login_role");
    assert_eq!(state.local.persistent_current_role, "login_role");
    assert_eq!(state.local.persistent_session_role, "login_role");
    assert!(state.local.current_role_known);
    assert!(state.local.session_role_known);
}

#[test]
fn role_none_during_local_session_authorization_restores_persistent_session_on_commit() {
    let engine = setup_engine();
    let mut state = setup_state();
    for field in [
        &mut state.local.current_role,
        &mut state.local.persistent_current_role,
        &mut state.local.session_role,
        &mut state.local.persistent_session_role,
        &mut state.local.authenticated_role,
    ] {
        *field = "login_role".into();
    }
    state.local.current_role_known = true;
    state.local.persistent_current_role_known = true;
    state.local.session_role_known = true;
    state.local.persistent_session_role_known = true;
    state.local.authenticated_role_known = true;

    engine
        .analyze(
            "BEGIN;
                 SET LOCAL SESSION AUTHORIZATION local_auth;
                 SET ROLE NONE;
                 COMMIT;",
            &mut state,
        )
        .unwrap();

    assert_eq!(state.local.current_role, "login_role");
    assert_eq!(state.local.session_role, "login_role");
}

#[test]
fn role_switch_recomputes_user_search_path_and_owner_keywords() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.metadata.source_role = Some("login_role".into());
    cache.metadata.source_session_role = Some("login_role".into());
    cache.metadata.source_search_path = Some(vec!["$user".into(), "public".into()]);
    cache.search_path = vec!["login_role".into(), "public".into()];
    for (name, superuser) in [("login_role", true), ("app_role", false)] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: true,
                is_superuser: superuser,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let table = object_id("public", "owned_table");
    cache.insert_baseline(
        table.clone(),
        RelationState::new(
            table.clone(),
            object_id("", "login_role"),
            0,
            Some(0),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze(
            "SET ROLE app_role;
                 ALTER TABLE public.owned_table OWNER TO SESSION_USER;",
            &mut state,
        )
        .unwrap();

    assert_eq!(state.search_path_names(), ["public"]);
    let RelationOverlay::Present(relation) = state.get_relation(&table).unwrap() else {
        panic!("table missing");
    };
    assert_eq!(relation.owner, object_id("", "login_role"));
}

#[test]
fn complete_role_catalog_rejects_missing_role_switch() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.metadata.source_role = Some("login_role".into());
    cache.metadata.source_session_role = Some("login_role".into());
    let login = object_id("", "login_role");
    cache.roles.insert(
        login.clone(),
        RoleState {
            id: login,
            can_login: true,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let violations = engine
        .analyze("SET ROLE role_that_does_not_exist;", &mut state)
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    assert_eq!(state.local.current_role, "login_role");
}

#[test]
fn set_role_follows_transitive_set_option_edges() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.metadata.source_role = Some("member".into());
    cache.metadata.source_session_role = Some("member".into());
    for (name, can_set_role_to) in [
        ("member", vec![object_id("", "bridge")]),
        ("bridge", vec![object_id("", "target")]),
        ("target", Vec::new()),
    ] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: name == "member",
                is_superuser: false,
                inherits: true,
                member_of: can_set_role_to.clone(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to,
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let violations = engine
        .analyze(
            "SET ROLE target; CREATE TABLE transitively_owned(id integer);",
            &mut state,
        )
        .unwrap();

    assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
    let RelationOverlay::Present(relation) = state
        .get_relation(&object_id("public", "transitively_owned"))
        .unwrap()
    else {
        panic!("table missing");
    };
    assert_eq!(relation.owner, object_id("", "target"));
}

#[test]
fn membership_without_set_option_does_not_authorize_set_role() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.metadata.source_role = Some("member".into());
    cache.metadata.source_session_role = Some("member".into());
    for (name, member_of) in [
        ("member", vec![object_id("", "target")]),
        ("target", Vec::new()),
    ] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: name == "member",
                is_superuser: false,
                inherits: true,
                member_of,
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let violations = engine.analyze("SET ROLE target;", &mut state).unwrap();

    assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
    assert_eq!(state.local.current_role, "member");
}

#[test]
fn grant_set_option_authorizes_set_role_and_revoke_removes_it() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    // Per-membership SET/INHERIT options exist from PostgreSQL 16 onward.
    cache.pg_version_num = Some(180_002);
    cache.metadata.source_role = Some("member".into());
    cache.metadata.source_session_role = Some("member".into());
    for name in ["member", "parent"] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: name == "member",
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: vec![object_id("", "parent")],
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let violations = engine
        .analyze("GRANT parent TO member; SET ROLE parent;", &mut state)
        .unwrap();
    assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
    assert_eq!(state.local.current_role, "parent");

    let violations = engine
        .analyze(
            "GRANT parent TO member WITH SET TRUE; SET ROLE parent;",
            &mut state,
        )
        .unwrap();
    assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
    assert_eq!(state.local.current_role, "parent");

    let violations = engine
        .analyze(
            "SET ROLE member; REVOKE SET OPTION FOR parent FROM member;",
            &mut state,
        )
        .unwrap();
    assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
    assert_eq!(state.local.current_role, "member");

    let violations = engine.analyze("SET ROLE parent;", &mut state).unwrap();
    assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
    assert_eq!(state.local.current_role, "member");

    let violations = engine
        .analyze(
            "BEGIN; GRANT parent TO member WITH SET TRUE; ROLLBACK; SET ROLE parent;",
            &mut state,
        )
        .unwrap();
    assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
    assert_eq!(state.local.current_role, "member");
}

#[test]
fn role_membership_admin_and_inherit_options_round_trip() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    // Per-membership SET/INHERIT options exist from PostgreSQL 16 onward.
    cache.pg_version_num = Some(180_002);
    for name in ["member", "parent"] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let violations = engine
        .analyze(
            "GRANT parent TO member WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;",
            &mut state,
        )
        .unwrap();
    assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
    let RoleOverlay::Present(role) = state.local.roles.get(&object_id("", "member")).unwrap()
    else {
        panic!("member role unexpectedly dropped");
    };
    assert_eq!(role.member_of, vec![object_id("", "parent")]);
    assert_eq!(
        role.can_administer_membership,
        vec![object_id("", "parent")]
    );
    assert!(role.can_inherit_from.is_empty());
    assert!(role.can_set_role_to.is_empty());

    engine
        .analyze("REVOKE ADMIN OPTION FOR parent FROM member;", &mut state)
        .unwrap();
    let RoleOverlay::Present(role) = state.local.roles.get(&object_id("", "member")).unwrap()
    else {
        panic!("member role unexpectedly dropped");
    };
    assert!(role.can_administer_membership.is_empty());
    assert_eq!(role.member_of, vec![object_id("", "parent")]);
}

#[test]
fn per_membership_options_need_a_known_pre_16_version_to_conflict() {
    let engine = setup_engine();
    for sql in [
        "GRANT parent TO member WITH INHERIT FALSE;",
        "REVOKE INHERIT OPTION FOR parent FROM member;",
    ] {
        let mut state = membership_state(None);
        assert_eq!(conflict_reason(&engine, &mut state, sql), "", "{sql}");
        assert!(
            state
                .evidence()
                .iter()
                .any(|record| record.code == EvidenceCode::UnsupportedSemantics),
            "an unknown server version cannot place {sql}"
        );
    }
}

#[test]
fn per_membership_options_conflict_on_a_known_pre_16_version() {
    let engine = setup_engine();
    for sql in [
        "GRANT parent TO member WITH INHERIT FALSE;",
        "REVOKE INHERIT OPTION FOR parent FROM member;",
    ] {
        let mut state = membership_state(Some(150_000));
        assert!(
            conflict_reason(&engine, &mut state, sql).contains("require PostgreSQL 16+"),
            "{sql}"
        );
    }
}

#[test]
fn role_membership_revoke_cascade_removes_dependent_grants() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.metadata.source_role = Some("admin".into());
    cache.metadata.source_session_role = Some("admin".into());
    for name in ["admin", "parent", "member", "child"] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let parent = object_id("", "parent");
    let member = object_id("", "member");
    cache
        .roles
        .get_mut(&object_id("", "admin"))
        .unwrap()
        .member_of = vec![parent.clone()];
    cache
        .roles
        .get_mut(&object_id("", "admin"))
        .unwrap()
        .can_administer_membership = vec![parent.clone()];
    cache.roles.get_mut(&member).unwrap().member_of = vec![parent.clone()];
    cache
        .roles
        .get_mut(&member)
        .unwrap()
        .can_administer_membership = vec![parent.clone()];
    cache.role_membership_grantors.push(
        safe_migrate::_internal::model::role::RoleMembershipGrantor {
            member: member.clone(),
            role: parent.clone(),
            grantor: object_id("", "admin"),
            admin: false,
            inherit: true,
            set: true,
        },
    );
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze(
            "GRANT parent TO child GRANTED BY member; \
                 GRANT parent TO child GRANTED BY admin; \
                 REVOKE parent FROM member CASCADE;",
            &mut state,
        )
        .unwrap();
    let RoleOverlay::Present(child) = state.local.roles.get(&object_id("", "child")).unwrap()
    else {
        panic!("child role unexpectedly dropped");
    };
    assert!(!child.member_of.contains(&parent));
}

#[test]
fn role_grant_to_public_is_rejected_before_partial_mutation() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    for name in ["member", "parent"] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
    let result = engine.analyze("GRANT parent TO member, PUBLIC WITH SET TRUE;", &mut state);
    assert!(result.is_ok());
    let role = state
        .local
        .roles
        .get(&object_id("", "member"))
        .expect("member role");
    let RoleOverlay::Present(role) = role else {
        panic!("member role unexpectedly dropped");
    };
    assert!(role.member_of.is_empty());
    assert!(role.can_set_role_to.is_empty());
}

#[test]
fn role_grant_rejects_cycles_before_mutating_the_batch() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    for name in ["role_a", "role_b"] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
    let _ = engine
        .analyze("GRANT role_a, role_b TO role_b, role_a;", &mut state)
        .unwrap();
    for name in ["role_a", "role_b"] {
        let role = state.local.roles.get(&object_id("", name)).unwrap();
        let RoleOverlay::Present(role) = role else {
            panic!("role unexpectedly dropped");
        };
        assert!(role.member_of.is_empty());
    }
}

#[test]
fn maintain_grants_and_revokes_require_postgres_17() {
    let engine = setup_engine();
    let table = object_id("public", "maintain_table");
    let grantee = object_id("", "app_user");

    for (version, supported) in [(160_000, false), (170_000, true)] {
        let mut cache = cache_with_table("public", "maintain_table", None);
        cache.pg_version_num = Some(version);
        let mut state = AnalysisState::new(cache);

        let violations = engine
            .analyze(
                "GRANT MAINTAIN ON TABLE maintain_table TO app_user;",
                &mut state,
            )
            .unwrap();
        assert_eq!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict"),
            !supported,
            "GRANT MAINTAIN on PostgreSQL {version}"
        );

        let RelationOverlay::Present(relation) = state.local.relations.get(&table).unwrap() else {
            panic!("maintain_table missing");
        };
        assert_eq!(
            relation
                .privileges
                .has_privilege(&grantee, Privilege::Maintain),
            supported
        );

        let violations = engine
            .analyze(
                "REVOKE MAINTAIN ON TABLE maintain_table FROM app_user;",
                &mut state,
            )
            .unwrap();
        assert_eq!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict"),
            !supported,
            "REVOKE MAINTAIN on PostgreSQL {version}"
        );
        let RelationOverlay::Present(relation) = state.local.relations.get(&table).unwrap() else {
            panic!("maintain_table missing");
        };
        assert!(
            !relation
                .privileges
                .has_privilege(&grantee, Privilege::Maintain)
        );
    }
}

#[test]
fn maintain_with_an_unknown_server_version_is_unresolved() {
    let engine = setup_engine();
    let mut cache = cache_with_table("public", "maintain_table", None);
    cache.pg_version_num = None;
    let mut state = AnalysisState::new(cache);

    let violations = engine
        .analyze(
            "GRANT MAINTAIN ON TABLE maintain_table TO app_user;",
            &mut state,
        )
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    assert_eq!(state.local.confidence, Confidence::Tainted);
}

#[test]
fn role_membership_grantor_uses_bootstrap_from_postgres_16() {
    let engine = setup_engine();
    let member = object_id("", "member");
    let parent = object_id("", "parent");

    for (version, expected) in [(150_000, "admin"), (160_000, "bootstrap")] {
        let mut cache = synced_cache();
        cache.pg_version_num = Some(version);
        cache.bootstrap_superuser = Some("bootstrap".into());
        cache.metadata.source_role = Some("admin".into());
        cache.metadata.source_session_role = Some("admin".into());
        for name in ["admin", "bootstrap", "parent", "member"] {
            let id = object_id("", name);
            cache.roles.insert(
                id.clone(),
                RoleState {
                    id,
                    can_login: true,
                    is_superuser: name == "admin" || name == "bootstrap",
                    inherits: true,
                    member_of: Vec::new(),
                    can_administer_membership: Vec::new(),
                    can_inherit_from: Vec::new(),
                    can_set_role_to: Vec::new(),
                },
            );
        }
        let mut state = AnalysisState::new(cache);

        let violations = engine
            .analyze("GRANT parent TO member;", &mut state)
            .unwrap();
        assert!(violations.is_empty(), "{violations:?}");

        let record = state
            .local
            .role_membership_grantors
            .iter()
            .find(|record| record.member == member && record.role == parent)
            .unwrap();
        assert_eq!(
            record.grantor.name, expected,
            "implicit role grantor on PostgreSQL {version}"
        );
    }
}

#[test]
fn role_membership_grantor_is_unresolved_without_a_server_version() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.pg_version_num = None;
    cache.bootstrap_superuser = Some("bootstrap".into());
    cache.metadata.source_role = Some("admin".into());
    cache.metadata.source_session_role = Some("admin".into());
    for name in ["admin", "bootstrap", "parent", "member"] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: true,
                is_superuser: name == "admin",
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let mut state = AnalysisState::new(cache);

    engine
        .analyze("GRANT parent TO member;", &mut state)
        .unwrap();

    assert_eq!(state.local.confidence, Confidence::Tainted);
    assert!(state.local.role_membership_grantors.is_empty());
}
