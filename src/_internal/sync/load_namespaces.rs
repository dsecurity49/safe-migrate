use super::*;

pub(super) fn load_schemas(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter: &str,
) -> Result<std::collections::HashMap<String, crate::_internal::model::schema::SchemaState>> {
    let query = format!(
        "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner)
         FROM pg_namespace n
         WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND n.nspname <> 'information_schema'
           {schema_filter}
         ORDER BY n.nspname;"
    );
    let rows = client
        .query(&query, &[schema_values])
        .context("Failed to load schemas from pg_namespace")?;
    rows.into_iter()
        .map(|row| {
            let name: String = row.try_get(0).context("schema name")?;
            let owner: String = row.try_get(1).context("schema owner")?;
            Ok((
                name.clone(),
                crate::_internal::model::schema::SchemaState {
                    name,
                    owner: relation_owner_id(owner),
                    generation: 0,
                },
            ))
        })
        .collect()
}

pub(super) fn load_sequences(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    pg_version_num: u32,
) -> Result<std::collections::HashMap<ObjectId, crate::_internal::model::sequence::SequenceState>> {
    // Keep a sequence when either side of OWNED BY is in the requested
    // scope. A sequence can live in a different schema from its owning
    // table, and dropping it without that edge would make a later migration
    // look exact while missing PostgreSQL's ownership dependency.
    let schema_filter = r#"
        AND (
            $1::text[] IS NULL
            OR n.nspname = ANY($1)
            OR tn.nspname = ANY($1)
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
    let query = format!(
        "SELECT
             n.nspname AS sequence_schema,
             s.relname AS sequence_name,
             pg_catalog.pg_get_userbyid(s.relowner) AS owner_name,
             tn.nspname AS table_schema,
             t.relname AS table_name,
             a.attname AS column_name,
             d.deptype::text AS dependency_type,
             CASE WHEN ad.adbin IS NULL THEN false
                  -- Heuristic: We detect serial/identity sequences by checking if the
                  -- column's default expression invokes nextval. Anchoring the match
                  -- to the expression start (pg_get_expr canonicalizes a real serial
                  -- default to `nextval('schema.seq'::regclass)`) rules out string
                  -- literals such as a default of 'nextval(', which deparse as
                  -- `'nextval('::text` and would otherwise false-positive.
                  ELSE pg_catalog.pg_get_expr(ad.adbin, ad.adrelid) LIKE 'nextval(%'
             END AS has_nextval_default,
             pg_catalog.format_type(q.seqtypid, NULL) AS sequence_data_type,
             q.seqstart AS sequence_start,
             q.seqincrement AS sequence_increment,
             q.seqmin AS sequence_min,
             q.seqmax AS sequence_max,
             q.seqcache AS sequence_cache,
             q.seqcycle AS sequence_cycle,
             s.relpersistence::text AS sequence_persistence,
             pg_catalog.has_sequence_privilege(s.oid, 'SELECT') AS can_read_runtime
         FROM pg_class s
         JOIN pg_namespace n ON n.oid = s.relnamespace
         JOIN pg_sequence q ON q.seqrelid = s.oid
         LEFT JOIN pg_depend d
           ON d.classid = 'pg_class'::regclass
          AND d.objid = s.oid
          AND d.objsubid = 0
          AND d.refclassid = 'pg_class'::regclass
          AND d.deptype IN ('a', 'i')
         LEFT JOIN pg_class t ON t.oid = d.refobjid
         LEFT JOIN pg_namespace tn ON tn.oid = t.relnamespace
         LEFT JOIN pg_attribute a
           ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
         LEFT JOIN pg_attrdef ad
           ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
         WHERE s.relkind = 'S'
           AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND n.nspname <> 'information_schema'
           {schema_filter}
         ORDER BY n.nspname, s.relname;"
    );
    let rows = client
        .query(&query, &[schema_values])
        .context("Failed to load sequences and ownership from pg_class/pg_depend")?;
    let mut sequences = std::collections::HashMap::new();
    for row in rows {
        let id = ObjectId::new(
            row.try_get::<_, String>("sequence_schema")
                .context("sequence schema")?,
            row.try_get::<_, String>("sequence_name")
                .context("sequence name")?,
        );
        let owner = relation_owner_id(
            row.try_get::<_, String>("owner_name")
                .context("sequence owner")?,
        );
        let table_schema: Option<String> = row
            .try_get("table_schema")
            .context("sequence owner table schema")?;
        let table_name: Option<String> = row
            .try_get("table_name")
            .context("sequence owner table name")?;
        let column_name: Option<String> = row
            .try_get("column_name")
            .context("sequence owner column name")?;
        let dependency_type: Option<String> = row
            .try_get("dependency_type")
            .context("sequence dependency type")?;
        let has_nextval_default: bool = row
            .try_get("has_nextval_default")
            .context("sequence-backed default marker")?;
        let owned_by = table_schema
            .zip(table_name)
            .zip(column_name)
            .map(|((schema, table), column)| (ObjectId::new(schema, table), column));
        let kind = sequence_kind_from_pg(dependency_type.as_deref(), has_nextval_default)
            .with_context(|| format!("sequence '{}' dependency kind", id))?;
        let persistence: String = row
            .try_get("sequence_persistence")
            .context("sequence persistence")?;
        let persistence = match persistence.as_str() {
            "p" => crate::_internal::model::sequence::SequencePersistence::Permanent,
            "t" => crate::_internal::model::sequence::SequencePersistence::Temporary,
            "u" => crate::_internal::model::sequence::SequencePersistence::Unlogged,
            other => anyhow::bail!("unsupported sequence persistence code '{other}'"),
        };
        let can_read_runtime: bool = row
            .try_get("can_read_runtime")
            .context("sequence runtime read privilege")?;
        let runtime = if can_read_runtime {
            load_sequence_runtime(client, &id, pg_version_num)?
        } else {
            crate::_internal::model::sequence::SequenceRuntime::unknown()
        };
        sequences.insert(
            id.clone(),
            crate::_internal::model::sequence::SequenceState {
                id,
                owner,
                owned_by,
                kind,
                parameters: crate::_internal::model::sequence::SequenceParameters {
                    data_type: row
                        .try_get("sequence_data_type")
                        .context("sequence data type")?,
                    start_value: row.try_get("sequence_start").context("sequence start")?,
                    increment: row
                        .try_get("sequence_increment")
                        .context("sequence increment")?,
                    min_value: row.try_get("sequence_min").context("sequence minimum")?,
                    max_value: row.try_get("sequence_max").context("sequence maximum")?,
                    cache_size: row.try_get("sequence_cache").context("sequence cache")?,
                    cycle: row.try_get("sequence_cycle").context("sequence cycle")?,
                    persistence,
                },
                runtime,
                runtime_exact: false,
                generation: 0,
            },
        );
    }
    Ok(sequences)
}

fn load_sequence_runtime(
    client: &mut impl GenericClient,
    id: &ObjectId,
    pg_version_num: u32,
) -> Result<crate::_internal::model::sequence::SequenceRuntime> {
    let relation = format!("{}.{}", quote_ident(&id.schema), quote_ident(&id.name));
    let row = if pg_version_num >= 180_000 {
        client
            .query_one(
                "SELECT last_value, is_called FROM pg_catalog.pg_get_sequence_data($1::text::regclass)",
                &[&relation],
            )
            .context("Failed to read sequence runtime data")?
    } else {
        client
            .query_one(
                &format!("SELECT last_value, is_called FROM {relation}"),
                &[],
            )
            .context("Failed to read sequence runtime data")?
    };
    Ok(crate::_internal::model::sequence::SequenceRuntime {
        last_value: Some(row.try_get("last_value").context("sequence last value")?),
        is_called: Some(row.try_get("is_called").context("sequence is_called")?),
    })
}

fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
