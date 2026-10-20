use super::*;

pub(crate) fn populate_cache(client: &mut Client, schemas: Option<&[String]>) -> Result<DbCache> {
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .context("Failed to start read-only cache synchronization transaction")?;
    let cache = populate_cache_from_client(&mut transaction, schemas)?;
    transaction
        .commit()
        .context("Failed to commit cache synchronization transaction")?;
    Ok(cache)
}

#[doc(hidden)]
#[cfg(test)]
pub(crate) fn populate_cache_in_current_transaction(
    client: &mut Client,
    schemas: Option<&[String]>,
) -> Result<DbCache> {
    populate_cache_from_client(client, schemas)
}

/// A view's dependencies on the routines and types its body uses.
///
/// `pg_depend` records these from the view's rewrite rules, so a view loaded
/// from the catalog carries the same obligations as one built from statements.
/// The routine signature is formed exactly as `load_routines` forms it, so a
/// drop matches whichever path produced the view.
pub(super) fn populate_cache_from_client(
    client: &mut impl GenericClient,
    schemas: Option<&[String]>,
) -> Result<DbCache> {
    let normalized_schemas = normalize_schema_scope(schemas)?;
    let schemas = normalized_schemas.as_deref();
    let mut cache = DbCache::new();
    let schema_values = normalized_schemas.clone();
    let provenance = load_provenance(client, schemas)?;
    cache.pg_version_num = Some(provenance.pg_version_num);
    cache.metadata = provenance.metadata;
    let mut coverage = CatalogCoverageBuilder::from_sync_scope(schemas);
    cache.search_path = provenance.search_path;

    let schema_filter = "AND ($1::text[] IS NULL OR n.nspname = ANY($1))";
    let schema_filter_with_fk = r#"
        AND (
            $1::text[] IS NULL
            OR n.nspname = ANY($1)
            OR c.oid IN (
                SELECT conrelid FROM pg_constraint cst
                JOIN pg_class c2 ON c2.oid = cst.confrelid
                JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                WHERE n2.nspname = ANY($1)
            )
            OR c.oid IN (
                SELECT confrelid FROM pg_constraint cst
                JOIN pg_class c2 ON c2.oid = cst.conrelid
                JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                WHERE n2.nspname = ANY($1)
            )
        )
    "#;
    let schema_filter_n1_or_n2 =
        "AND ($1::text[] IS NULL OR n1.nspname = ANY($1) OR n2.nspname = ANY($1))";
    let schema_filter_nt = r#"
        AND (
            $1::text[] IS NULL
            OR n_t.nspname = ANY($1)
            OR t.oid IN (
                SELECT conrelid FROM pg_constraint cst
                JOIN pg_class c2 ON c2.oid = cst.confrelid
                JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                WHERE n2.nspname = ANY($1)
            )
            OR t.oid IN (
                SELECT confrelid FROM pg_constraint cst
                JOIN pg_class c2 ON c2.oid = cst.conrelid
                JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                WHERE n2.nspname = ANY($1)
            )
        )
    "#;

    // Schemas are an authoritative catalog only for the requested sync scope.
    // FK-only external schemas pulled in below deliberately do not enter it.
    cache.schemas = load_schemas(client, &schema_values, schema_filter)?;

    // Built-ins are cluster-wide, so they are read once and never scoped, and
    // they are read first because every loader that renders a type name needs
    // them to agree with what a migration would resolve.
    cache.builtin_types = Some(load_builtin_types(client)?);
    cache.opclasses = Some(load_opclasses(client)?);
    cache.collations = Some(load_collations(client)?);
    cache.casts = Some(load_casts(client)?);
    cache.aggregates = Some(load_aggregates(client)?);
    let builtin_types = cache.builtin_types.as_ref().expect("just loaded");
    coverage.record(CatalogFamily::Schemas);
    // A scoped request can name schemas that do not exist yet. PostgreSQL's
    // effective search path skips those entries, so do not let them become
    // inferred-present namespaces when the cache is hydrated.
    cache
        .search_path
        .retain(|schema| cache.schemas.contains_key(schema));

    cache.sequences = load_sequences(client, &schema_values)?;
    coverage.record(CatalogFamily::Sequences);

    cache.relations =
        load_relations_and_columns(client, schemas, &schema_values, schema_filter_with_fk)?;
    coverage.record(CatalogFamily::Relations);

    let (relation_decorations, relation_grants) =
        load_relation_decorations(client, &schema_values, schema_filter_with_fk)?;
    for decoration in relation_decorations {
        let relation = cache
            .relations
            .get_mut(&decoration.relation_id)
            .with_context(|| {
                format!(
                    "relation decoration references omitted relation '{}'",
                    decoration.relation_id
                )
            })?;
        relation.triggers.extend(decoration.triggers);
        relation.policies.extend(decoration.policies);
        relation.rules.extend(decoration.rules);
    }
    for grant in relation_grants {
        let relation = cache
            .relations
            .get_mut(&grant.relation_id)
            .with_context(|| {
                format!(
                    "relation privilege references omitted relation '{}'",
                    grant.relation_id
                )
            })?;
        let privileges = [grant.privilege].into_iter().collect();
        if grant.is_grantable {
            relation
                .privileges
                .grant_from(grant.grantee, privileges, Some(grant.grantor), true);
        } else {
            relation
                .privileges
                .grant_from(grant.grantee, privileges, Some(grant.grantor), false);
        }
    }

    cache.triggers = load_triggers(client, &schema_values, schema_filter_with_fk)?;
    coverage.record(CatalogFamily::Triggers);

    cache.constraints = load_constraints(client, &schema_values, schema_filter_with_fk)?;
    cache.constraint_keys = load_constraint_keys(client, &schema_values, schema_filter_with_fk)?;
    cache.constraint_dependencies =
        load_constraint_dependencies(client, &schema_values, schema_filter_with_fk)?;
    cache.generated_column_dependencies =
        load_generated_column_dependencies(client, &schema_values, schema_filter_with_fk)?;
    coverage.record(CatalogFamily::Constraints);
    cache.default_sequence_dependencies =
        load_default_sequence_dependencies(client, &schema_values, schema_filter_with_fk)?;

    cache.foreign_keys =
        load_foreign_keys(client, schemas, &schema_values, schema_filter_n1_or_n2)?;

    cache.inheritances = load_inheritances(client, &schema_values)?;
    cache.index_attachments = load_index_attachments(client, &schema_values)?;
    coverage.record(CatalogFamily::Inheritance);

    cache.indexes = load_indexes(
        client,
        &schema_values,
        schema_filter_nt,
        cache.pg_version_num.unwrap_or_default(),
    )?;
    coverage.record(CatalogFamily::Indexes);

    cache.functions = load_routines(client, &schema_values, schema_filter, builtin_types)?;
    coverage.record(CatalogFamily::Routines);

    cache.publications = load_publications(client, cache.pg_version_num.unwrap_or_default())?;
    cache.subscriptions = load_subscriptions(client, cache.pg_version_num.unwrap_or_default())?;
    coverage.record(CatalogFamily::Publications);
    coverage.record(CatalogFamily::Subscriptions);

    cache.types = load_types(client, &schema_values, schema_filter)?;
    coverage.record(CatalogFamily::Types);

    // Only view dependencies are consumed by cache hydration. Generic
    // pg_depend rows use PostgreSQL dependency codes (n/a/i) and were ignored
    // after synchronization, so avoid loading them into Cache V8.
    cache.dependencies = load_view_dependencies(client, &schema_values)?;
    cache.view_object_dependencies = load_view_object_dependencies(
        client,
        &schema_values,
        &cache
            .builtin_types
            .clone()
            .unwrap_or_else(BuiltinTypeCatalogue::fallback),
    )?;
    coverage.record(CatalogFamily::Dependencies);
    let scoped_external = load_scoped_external_dependencies(client, &schema_values)?;
    cache.scoped_external_dependencies = scoped_external.edges;
    cache.external_referencing_schemas = scoped_external.external_schemas;
    // All scope-boundary queries above completed inside the same repeatable
    // read transaction. Mark this only after every query succeeds; a cache
    // that was assembled programmatically or by a partial loader remains
    // conservative even if it has a timestamp.
    cache.metadata.boundary_queries_complete = true;

    // Role identity and membership are required to distinguish a valid
    // `SET ROLE` from a migration that PostgreSQL would reject. pg_roles does
    // not expose password hashes or other credentials.
    cache.roles = load_roles(client, cache.pg_version_num.unwrap_or_default())?;
    cache.role_membership_grantors =
        load_role_membership_grantors(client, cache.pg_version_num.unwrap_or_default())?;
    cache.role_membership_grantors_complete = true;
    coverage.record(CatalogFamily::Roles);

    // Every loader above is fallible, so reaching this point means each one
    // completed and recorded its own family.
    cache.coverage = coverage.finish();

    // The bootstrap superuser (pg_authid OID 10, `BOOTSTRAP_SUPERUSERID`)
    // receives implicit superuser-issued role grantor attribution on modern
    // PostgreSQL.  Recording its name lets state resolution distinguish it
    // from a session role when replaying unchecked GRANT statements.
    cache.bootstrap_superuser = client
        .query("SELECT rolname FROM pg_roles WHERE oid = 10;", &[])
        .context("Failed to load the bootstrap superuser role")?
        .first()
        .map(|row| row.try_get::<_, String>(0))
        .transpose()
        .context("bootstrap superuser name")?;

    cache
        .validate_semantics()
        .map_err(anyhow::Error::msg)
        .context("PostgreSQL catalogs produced a semantically invalid cache baseline")?;
    Ok(cache)
}

/// Normalize a user-provided schema scope once at the synchronization
/// boundary. PostgreSQL treats an array membership filter as a set, while the
/// cache metadata is ordered and validated for uniqueness; preserving the
/// first occurrence gives callers deterministic search-path behavior without
/// allowing duplicate or empty identities into the durable snapshot.
pub(super) fn normalize_schema_scope(schemas: Option<&[String]>) -> Result<Option<Vec<String>>> {
    let Some(schemas) = schemas else {
        return Ok(None);
    };
    let mut seen = HashSet::new();
    let mut normalized = Vec::with_capacity(schemas.len());
    for schema in schemas {
        if schema.is_empty() {
            anyhow::bail!("schema scope must not contain an empty schema identity");
        }
        if seen.insert(schema) {
            normalized.push(schema.clone());
        }
    }
    Ok(Some(normalized))
}
