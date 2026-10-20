use super::*;

pub(super) fn load_publications(
    client: &mut impl GenericClient,
    pg_version_num: u32,
) -> Result<std::collections::HashMap<String, crate::_internal::model::replication::PublicationState>>
{
    let publication_query = if pg_version_num >= 180_000 {
        r#"
            SELECT p.oid, p.pubname::text AS publication_name,
                   pg_catalog.pg_get_userbyid(p.pubowner) AS owner_name,
                   p.puballtables, p.pubinsert, p.pubupdate, p.pubdelete,
                   p.pubtruncate, p.pubviaroot, p.pubgencols::text AS generated_columns
            FROM pg_publication p
            ORDER BY p.oid
        "#
    } else {
        r#"
            SELECT p.oid, p.pubname::text AS publication_name,
                   pg_catalog.pg_get_userbyid(p.pubowner) AS owner_name,
                   p.puballtables, p.pubinsert, p.pubupdate, p.pubdelete,
                   p.pubtruncate, p.pubviaroot, NULL::text AS generated_columns
            FROM pg_publication p
            ORDER BY p.oid
        "#
    };
    let rows = client
        .query(publication_query, &[])
        .context("Failed to load publications from pg_publication")?;
    let mut names_by_oid = std::collections::HashMap::<u32, String>::new();
    let mut publications = std::collections::HashMap::new();
    for row in rows {
        let oid: u32 = row.try_get("oid").context("publication OID")?;
        let name: String = row
            .try_get("publication_name")
            .context("publication name")?;
        let mut operations = Vec::new();
        for (field, operation) in [
            ("pubinsert", "insert"),
            ("pubupdate", "update"),
            ("pubdelete", "delete"),
            ("pubtruncate", "truncate"),
        ] {
            if row
                .try_get::<_, bool>(field)
                .with_context(|| format!("publication '{name}' {field}"))?
            {
                operations.push(operation);
            }
        }
        let mut params = vec![
            crate::_internal::analysis::facts::AttributeFact {
                name: "publish".to_string(),
                value: Some(operations.join(", ")),
                namespace: None,
            },
            crate::_internal::analysis::facts::AttributeFact {
                name: "publish_via_partition_root".to_string(),
                value: Some(
                    row.try_get::<_, bool>("pubviaroot")
                        .context("publication partition-root mode")?
                        .to_string(),
                ),
                namespace: None,
            },
        ];
        if let Some(generated_columns) = row
            .try_get::<_, Option<String>>("generated_columns")
            .context("publication generated-column mode")?
        {
            let value = match generated_columns.as_str() {
                "n" => "none",
                "s" => "stored",
                other => anyhow::bail!(
                    "publication '{name}' has unknown generated-column mode '{other}'"
                ),
            };
            params.push(crate::_internal::analysis::facts::AttributeFact {
                name: "publish_generated_columns".to_string(),
                value: Some(value.to_string()),
                namespace: None,
            });
        }
        let scope = if row
            .try_get::<_, bool>("puballtables")
            .context("publication all-tables mode")?
        {
            crate::_internal::analysis::facts::PublicationScope::AllTables { except: Vec::new() }
        } else {
            crate::_internal::analysis::facts::PublicationScope::Explicit(Vec::new())
        };
        names_by_oid.insert(oid, name.clone());
        publications.insert(
            name.clone(),
            crate::_internal::model::replication::PublicationState {
                name,
                owner: Some(row.try_get("owner_name").context("publication owner")?),
                scope,
                params,
                generation: 0,
            },
        );
    }

    let relation_query = if pg_version_num >= 150_000 {
        r#"
            SELECT pr.prpubid, n.nspname::text AS schema_name,
                   c.relname::text AS relation_name,
                   pg_catalog.pg_get_expr(pr.prqual, pr.prrelid) AS row_filter,
                   CASE WHEN pr.prattrs IS NULL THEN NULL ELSE ARRAY(
                       SELECT a.attname::text
                       FROM pg_attribute a
                       WHERE a.attrelid = pr.prrelid
                         AND a.attnum = ANY(pr.prattrs::smallint[])
                       ORDER BY array_position(pr.prattrs::smallint[], a.attnum)
                   ) END AS columns
            FROM pg_publication_rel pr
            JOIN pg_class c ON c.oid = pr.prrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            ORDER BY pr.prpubid, pr.oid
        "#
    } else {
        r#"
            SELECT pr.prpubid, n.nspname::text AS schema_name,
                   c.relname::text AS relation_name,
                   NULL::text AS row_filter, NULL::text[] AS columns
            FROM pg_publication_rel pr
            JOIN pg_class c ON c.oid = pr.prrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            ORDER BY pr.prpubid, pr.oid
        "#
    };
    for row in client
        .query(relation_query, &[])
        .context("Failed to load publication relation membership")?
    {
        let oid: u32 = row.try_get("prpubid").context("publication relation OID")?;
        let name = names_by_oid.get(&oid).with_context(|| {
            format!("publication relation membership references unknown publication OID {oid}")
        })?;
        let publication = publications
            .get_mut(name)
            .with_context(|| format!("publication '{name}' disappeared during assembly"))?;
        let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
            &mut publication.scope
        else {
            continue;
        };
        objects.push(
            crate::_internal::analysis::facts::PublicationObjectFact::Table {
                name: crate::_internal::ast::identifiers::QualifiedName::new(
                    Some(crate::_internal::ast::identifiers::Ident::new(
                        row.try_get::<_, String>("schema_name")
                            .context("publication relation schema")?,
                        true,
                    )),
                    crate::_internal::ast::identifiers::Ident::new(
                        row.try_get::<_, String>("relation_name")
                            .context("publication relation name")?,
                        true,
                    ),
                ),
                only: true,
                include_partitions: false,
                columns: row
                    .try_get("columns")
                    .context("publication relation column list")?,
                row_filter: row
                    .try_get::<_, Option<String>>("row_filter")
                    .context("publication relation row filter")?
                    .map(crate::_internal::analysis::facts::PublicationRowFilter::CatalogSql),
            },
        );
    }

    if pg_version_num >= 150_000 {
        for row in client
            .query(
                r#"
                    SELECT pn.pnpubid, n.nspname::text AS schema_name
                    FROM pg_publication_namespace pn
                    JOIN pg_namespace n ON n.oid = pn.pnnspid
                    ORDER BY pn.pnpubid, pn.oid
                "#,
                &[],
            )
            .context("Failed to load publication schema membership")?
        {
            let oid: u32 = row.try_get("pnpubid").context("publication schema OID")?;
            let name = names_by_oid.get(&oid).with_context(|| {
                format!("publication schema membership references unknown publication OID {oid}")
            })?;
            let publication = publications
                .get_mut(name)
                .with_context(|| format!("publication '{name}' disappeared during assembly"))?;
            let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                &mut publication.scope
            else {
                continue;
            };
            objects.push(
                crate::_internal::analysis::facts::PublicationObjectFact::SchemaTables {
                    schema: row
                        .try_get("schema_name")
                        .context("publication member schema name")?,
                    row_filter: None,
                },
            );
        }
    }
    Ok(publications)
}

pub(super) fn load_subscriptions(
    client: &mut impl GenericClient,
    pg_version_num: u32,
) -> Result<
    std::collections::HashMap<String, crate::_internal::model::replication::SubscriptionState>,
> {
    // Every version-specific query deliberately omits pg_subscription.subconninfo.
    let query = match pg_version_num {
        170_000.. => {
            r#"
            SELECT s.subname::text AS subscription_name,
                   pg_catalog.pg_get_userbyid(s.subowner) AS owner_name,
                   s.subenabled, s.subbinary, s.subslotname::text,
                   s.subsynccommit, s.subpublications,
                   s.substream::text AS streaming,
                   s.subtwophasestate::text AS two_phase_state,
                   s.subdisableonerr AS disable_on_error,
                   s.subpasswordrequired AS password_required,
                   s.subrunasowner AS run_as_owner,
                   s.subfailover AS failover,
                   s.suborigin AS origin,
                   s.subskiplsn::text AS skip_lsn
            FROM pg_subscription s
            WHERE s.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
            ORDER BY s.oid
        "#
        }
        160_000.. => {
            r#"
            SELECT s.subname::text AS subscription_name,
                   pg_catalog.pg_get_userbyid(s.subowner) AS owner_name,
                   s.subenabled, s.subbinary, s.subslotname::text,
                   s.subsynccommit, s.subpublications,
                   s.substream::text AS streaming,
                   s.subtwophasestate::text AS two_phase_state,
                   s.subdisableonerr AS disable_on_error,
                   s.subpasswordrequired AS password_required,
                   s.subrunasowner AS run_as_owner,
                   NULL::bool AS failover,
                   s.suborigin AS origin,
                   s.subskiplsn::text AS skip_lsn
            FROM pg_subscription s
            WHERE s.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
            ORDER BY s.oid
        "#
        }
        150_000.. => {
            r#"
            SELECT s.subname::text AS subscription_name,
                   pg_catalog.pg_get_userbyid(s.subowner) AS owner_name,
                   s.subenabled, s.subbinary, s.subslotname::text,
                   s.subsynccommit, s.subpublications,
                   s.substream::text AS streaming,
                   s.subtwophasestate::text AS two_phase_state,
                   s.subdisableonerr AS disable_on_error,
                   NULL::bool AS password_required,
                   NULL::bool AS run_as_owner,
                   NULL::bool AS failover,
                   NULL::text AS origin,
                   s.subskiplsn::text AS skip_lsn
            FROM pg_subscription s
            WHERE s.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
            ORDER BY s.oid
        "#
        }
        _ => {
            r#"
            SELECT s.subname::text AS subscription_name,
                   pg_catalog.pg_get_userbyid(s.subowner) AS owner_name,
                   s.subenabled, s.subbinary, s.subslotname::text,
                   s.subsynccommit, s.subpublications,
                   s.substream::text AS streaming,
                   NULL::text AS two_phase_state,
                   NULL::bool AS disable_on_error,
                   NULL::bool AS password_required,
                   NULL::bool AS run_as_owner,
                   NULL::bool AS failover,
                   NULL::text AS origin,
                   NULL::text AS skip_lsn
            FROM pg_subscription s
            WHERE s.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
            ORDER BY s.oid
        "#
        }
    };
    client
        .query(query, &[])
        .context("Failed to load non-secret subscription metadata")?
        .into_iter()
        .map(|row| {
            let name: String = row
                .try_get("subscription_name")
                .context("subscription name")?;
            let streaming_code: String = row
                .try_get("streaming")
                .with_context(|| format!("subscription '{name}' streaming mode"))?;
            let streaming = subscription_streaming_from_pg(&streaming_code)
                .with_context(|| format!("subscription '{name}' streaming mode"))?;
            let mut params = vec![
                crate::_internal::analysis::facts::AttributeFact {
                    name: "binary".to_string(),
                    value: Some(
                        row.try_get::<_, bool>("subbinary")
                            .with_context(|| format!("subscription '{name}' binary mode"))?
                            .to_string(),
                    ),
                    namespace: None,
                },
                crate::_internal::analysis::facts::AttributeFact {
                    name: "streaming".to_string(),
                    value: Some(streaming.to_string()),
                    namespace: None,
                },
                crate::_internal::analysis::facts::AttributeFact {
                    name: "synchronous_commit".to_string(),
                    value: Some(
                        row.try_get("subsynccommit")
                            .with_context(|| format!("subscription '{name}' synchronous_commit"))?,
                    ),
                    namespace: None,
                },
            ];
            let two_phase = row
                .try_get::<_, Option<String>>("two_phase_state")
                .with_context(|| format!("subscription '{name}' two-phase state"))?
                .map(|state| subscription_two_phase_from_pg(&state).map(str::to_string))
                .transpose()?;
            let mut push_param = |param_name: &str, value: Option<String>| {
                if let Some(value) = value {
                    params.push(crate::_internal::analysis::facts::AttributeFact {
                        name: param_name.to_string(),
                        value: Some(value),
                        namespace: None,
                    });
                }
            };
            push_param("two_phase", two_phase);
            for (field, param_name) in [
                ("disable_on_error", "disable_on_error"),
                ("password_required", "password_required"),
                ("run_as_owner", "run_as_owner"),
                ("failover", "failover"),
            ] {
                push_param(
                    param_name,
                    row.try_get::<_, Option<bool>>(field)
                        .with_context(|| format!("subscription '{name}' {field}"))?
                        .map(|value| value.to_string()),
                );
            }
            push_param(
                "origin",
                row.try_get("origin")
                    .with_context(|| format!("subscription '{name}' origin"))?,
            );
            push_param(
                "skip_lsn",
                row.try_get::<_, Option<String>>("skip_lsn")
                    .with_context(|| format!("subscription '{name}' skip LSN"))?
                    .filter(|lsn| lsn != "0/0"),
            );
            Ok((
                name.clone(),
                crate::_internal::model::replication::SubscriptionState {
                    name,
                    owner: Some(row.try_get("owner_name").context("subscription owner")?),
                    connection: crate::_internal::analysis::facts::ConnectionTarget::Redacted,
                    publications: row
                        .try_get("subpublications")
                        .context("subscription publication names")?,
                    params: Some(params),
                    enabled: row
                        .try_get("subenabled")
                        .context("subscription enabled state")?,
                    slot_name: row
                        .try_get("subslotname")
                        .context("subscription slot name")?,
                    generation: 0,
                },
            ))
        })
        .collect()
}
