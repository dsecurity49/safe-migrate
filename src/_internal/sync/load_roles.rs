use super::*;

pub(super) fn load_roles(
    client: &mut impl GenericClient,
    pg_version_num: u32,
) -> Result<std::collections::HashMap<ObjectId, crate::_internal::model::role::RoleState>> {
    let mut roles = std::collections::HashMap::new();
    let rows = client
        .query(
            "SELECT rolname, rolcanlogin, rolsuper, rolinherit FROM pg_roles ORDER BY rolname;",
            &[],
        )
        .context("Failed to load role identities from pg_roles")?;
    for row in rows {
        let name: String = row.try_get(0).context("role name")?;
        let id = ObjectId::new("", &name);
        roles.insert(
            id.clone(),
            crate::_internal::model::role::RoleState {
                id,
                can_login: row.try_get(1).context("role login capability")?,
                is_superuser: row.try_get(2).context("role superuser capability")?,
                inherits: row.try_get(3).context("role inherit capability")?,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }

    let membership_query = if pg_version_num >= 160_000 {
        "SELECT member.rolname, parent.rolname, membership.admin_option,
                membership.inherit_option, membership.set_option
         FROM pg_auth_members membership
         JOIN pg_roles member ON member.oid = membership.member
         JOIN pg_roles parent ON parent.oid = membership.roleid;"
    } else {
        "SELECT member.rolname, parent.rolname, membership.admin_option,
                true AS inherit_option, true AS set_option
         FROM pg_auth_members membership
         JOIN pg_roles member ON member.oid = membership.member
         JOIN pg_roles parent ON parent.oid = membership.roleid;"
    };
    let memberships = client
        .query(membership_query, &[])
        .context("Failed to load role memberships from pg_auth_members")?;
    // PostgreSQL 16+ may store several rows for the same (member, role) pair,
    // one per grantor.  The effective projection is the union of their
    // options, so aggregate rows instead of duplicating the edge.
    let mut seen_edges = std::collections::HashSet::new();
    for row in memberships {
        let member = ObjectId::new("", row.try_get::<_, String>(0).context("member role")?);
        let parent = ObjectId::new("", row.try_get::<_, String>(1).context("parent role")?);
        let admin_option: bool = row.try_get(2).context("role membership ADMIN option")?;
        let inherit_option: bool = row.try_get(3).context("role membership INHERIT option")?;
        let set_option: bool = row.try_get(4).context("role membership SET option")?;
        if let Some(role) = roles.get_mut(&member) {
            if seen_edges.insert((member, parent.clone())) {
                role.member_of.push(parent.clone());
                if admin_option {
                    role.can_administer_membership.push(parent.clone());
                }
                if inherit_option {
                    role.can_inherit_from.push(parent.clone());
                }
                if set_option {
                    role.can_set_role_to.push(parent.clone());
                }
            } else {
                if admin_option && !role.can_administer_membership.contains(&parent) {
                    role.can_administer_membership.push(parent.clone());
                }
                if inherit_option && !role.can_inherit_from.contains(&parent) {
                    role.can_inherit_from.push(parent.clone());
                }
                if set_option && !role.can_set_role_to.contains(&parent) {
                    role.can_set_role_to.push(parent);
                }
            }
        }
    }
    Ok(roles)
}

pub(super) fn load_role_membership_grantors(
    client: &mut impl GenericClient,
    pg_version_num: u32,
) -> Result<Vec<crate::_internal::model::role::RoleMembershipGrantor>> {
    let query = if pg_version_num >= 160_000 {
        "SELECT member.rolname, parent.rolname, grantor.rolname,
                membership.admin_option, membership.inherit_option,
                membership.set_option
         FROM pg_auth_members membership
         JOIN pg_roles member ON member.oid = membership.member
         JOIN pg_roles parent ON parent.oid = membership.roleid
         JOIN pg_roles grantor ON grantor.oid = membership.grantor
         ORDER BY member.rolname, parent.rolname, grantor.rolname;"
    } else {
        "SELECT member.rolname, parent.rolname, grantor.rolname,
                membership.admin_option, true AS inherit_option,
                true AS set_option
         FROM pg_auth_members membership
         JOIN pg_roles member ON member.oid = membership.member
         JOIN pg_roles parent ON parent.oid = membership.roleid
         JOIN pg_roles grantor ON grantor.oid = membership.grantor
         ORDER BY member.rolname, parent.rolname, grantor.rolname;"
    };
    let rows = client
        .query(query, &[])
        .context("Failed to load role membership grantors")?;
    rows.into_iter()
        .map(|row| {
            Ok(crate::_internal::model::role::RoleMembershipGrantor {
                member: ObjectId::new("", row.try_get::<_, String>(0)?),
                role: ObjectId::new("", row.try_get::<_, String>(1)?),
                grantor: ObjectId::new("", row.try_get::<_, String>(2)?),
                admin: row.try_get(3)?,
                inherit: row.try_get(4)?,
                set: row.try_get(5)?,
            })
        })
        .collect()
}

pub(super) struct ProvenanceCatalog {
    pub(super) pg_version_num: u32,
    pub(super) metadata: crate::_internal::db::cache::CacheMetadata,
    pub(super) search_path: Vec<String>,
}

pub(super) fn load_provenance(
    client: &mut impl GenericClient,
    schemas: Option<&[String]>,
) -> Result<ProvenanceCatalog> {
    let version_row = client
        .query_one("SHOW server_version_num;", &[])
        .context("Failed to load PostgreSQL server version")?;
    let version_str: String = version_row
        .try_get(0)
        .context("PostgreSQL server version field")?;
    let pg_version_num = version_str
        .parse::<u32>()
        .context("PostgreSQL returned an invalid server_version_num")?;
    ensure_supported_postgres_version(pg_version_num)?;

    let search_path_row = client
        .query_one("SHOW search_path;", &[])
        .context("Failed to load search_path setting")?;
    let search_path_setting: String = search_path_row.try_get(0).context("search_path field")?;

    // Must be read before the path is pinned below, or the recorded resolution
    // order would describe pg_catalog rather than the real search path.
    let effective_search_path: Vec<String> = client
        .query_one("SELECT current_schemas(false);", &[])
        .context("Failed to load the effective PostgreSQL search path")?
        .try_get(0)
        .context("effective PostgreSQL search path field")?;

    // Protect all subsequent catalog queries from shadowing by explicitly
    // selecting the system schema. This prevents an attacker from creating
    // a public.pg_class view to inject forged baseline data.
    client
        .execute("SET LOCAL search_path = pg_catalog;", &[])
        .context("Failed to secure search_path")?;

    // Recorded before the scope filter: absence proves the schema did not
    // exist, not merely that the scope omitted it.
    let existing_schemas: Vec<String> = client
        .query("SELECT nspname FROM pg_catalog.pg_namespace", &[])
        .context("Failed to load PostgreSQL schemas")?
        .into_iter()
        .map(|row| row.try_get(0).context("schema identity field"))
        .collect::<Result<Vec<String>>>()?;

    let row = client
        .query_one(
            "SELECT current_database(), current_user, session_user,
                    (SELECT setting::bigint FROM pg_settings WHERE name = 'lock_timeout'),
                    (SELECT setting::bigint FROM pg_settings WHERE name = 'statement_timeout');",
            &[],
        )
        .context("Failed to load synchronization provenance and timeout settings")?;
    let lock_timeout_ms = row
        .try_get::<_, Option<i64>>(3)
        .context("synchronization provenance lock_timeout field")?
        .context("PostgreSQL did not report lock_timeout")?;
    let statement_timeout_ms = row
        .try_get::<_, Option<i64>>(4)
        .context("synchronization provenance statement_timeout field")?
        .context("PostgreSQL did not report statement_timeout")?;

    Ok(ProvenanceCatalog {
        pg_version_num,
        metadata: crate::_internal::db::cache::CacheMetadata {
            created_at_unix_secs: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            boundary_queries_complete: false,
            source_database: Some(
                row.try_get(0)
                    .context("synchronization provenance database field")?,
            ),
            source_role: Some(
                row.try_get(1)
                    .context("synchronization provenance current-role field")?,
            ),
            source_session_role: Some(
                row.try_get(2)
                    .context("synchronization provenance session-role field")?,
            ),
            source_search_path: Some(parse_search_path_setting(&search_path_setting)),
            source_existing_schemas: Some(existing_schemas),
            source_lock_timeout_ms: lock_timeout_ms
                .try_into()
                .context("PostgreSQL returned a negative lock_timeout")?,
            source_statement_timeout_ms: statement_timeout_ms
                .try_into()
                .context("PostgreSQL returned a negative statement_timeout")?,
            schemas: schemas.map(<[String]>::to_vec),
        },
        search_path: cache_search_path(effective_search_path, schemas),
    })
}
