use super::*;

pub(super) fn load_relations_and_columns(
    client: &mut impl GenericClient,
    schemas: Option<&[String]>,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<std::collections::HashMap<ObjectId, RelationState>> {
    let relation_query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            c.relkind AS relation_kind,
            c.relpersistence AS persistence,
            c.relrowsecurity AS row_security,
            c.relforcerowsecurity AS force_row_security,
            (c.reltoastrelid <> 0) AS has_toast_table,
            CASE c.relreplident
                WHEN 'd' THEN 'DEFAULT'
                WHEN 'n' THEN 'NOTHING'
                WHEN 'f' THEN 'FULL'
                WHEN 'i' THEN CASE
                    WHEN replica_index.relname IS NULL THEN 'USING INDEX'
                    ELSE 'USING INDEX ' || replica_index.relname
                END
                ELSE NULL
            END AS replica_identity,
            type_namespace.nspname AS typed_table_type_schema,
            table_type.typname AS typed_table_type_name,
            c.reloptions AS relation_options,
            ts.spcname AS tablespace,
            am.amname AS access_method,
            cluster_index.relname AS cluster_index,
            pg_catalog.pg_get_userbyid(c.relowner) AS owner_name,
            CASE WHEN c.reltuples < 0 THEN -1 ELSE c.reltuples::bigint END AS estimated_rows,
            c.relpages::bigint AS relpages,
            to_char(s.last_analyze, 'YYYY-MM-DD HH24:MI:SS') AS last_analyze,
            to_char(s.last_autoanalyze, 'YYYY-MM-DD HH24:MI:SS') AS last_autoanalyze,
            p.partstrat::text AS partition_strategy,
            pg_catalog.pg_get_partkeydef(c.oid) AS partition_key,
            pg_catalog.pg_get_expr(c.relpartbound, c.oid) AS partition_bound,
            pg_catalog.pg_get_partition_constraintdef(c.oid) AS partition_constraint,
            CASE WHEN c.relkind = 'm' THEN c.relispopulated ELSE NULL END AS is_populated
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_tablespace ts ON ts.oid = c.reltablespace
        LEFT JOIN pg_am am ON am.oid = c.relam
        LEFT JOIN pg_type table_type ON table_type.oid = c.reloftype
        LEFT JOIN pg_namespace type_namespace ON type_namespace.oid = table_type.typnamespace
        LEFT JOIN pg_index cluster_i ON cluster_i.indrelid = c.oid AND cluster_i.indisclustered
        LEFT JOIN pg_class cluster_index ON cluster_index.oid = cluster_i.indexrelid
        LEFT JOIN pg_index replica_i ON replica_i.indrelid = c.oid AND replica_i.indisreplident
        LEFT JOIN pg_class replica_index ON replica_index.oid = replica_i.indexrelid
        LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
        LEFT JOIN pg_partitioned_table p ON p.partrelid = c.oid
        WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
    "
    );
    let rows = client
        .query(&relation_query, &[schema_values])
        .context("Failed to load relations and statistics from pg_class")?;
    let mut relations = std::collections::HashMap::new();
    for row in rows {
        let schema_name: String = row.try_get("schema_name").context("relation schema")?;
        let relation_name: String = row.try_get("relation_name").context("relation name")?;
        let relkind: i8 = row.try_get("relation_kind").context("relation kind")?;
        let persistence_char: i8 = row.try_get("persistence").context("relation persistence")?;
        let row_security: bool = row
            .try_get("row_security")
            .context("relation row security")?;
        let force_row_security: bool = row
            .try_get("force_row_security")
            .context("relation forced row security")?;
        let replica_identity: Option<String> = row
            .try_get("replica_identity")
            .context("relation replica identity")?;
        let typed_table_type_schema: Option<String> = row
            .try_get("typed_table_type_schema")
            .context("typed-table type schema")?;
        let typed_table_type_name: Option<String> = row
            .try_get("typed_table_type_name")
            .context("typed-table type name")?;
        let relation_options: Option<Vec<String>> = row
            .try_get("relation_options")
            .context("relation options")?;
        let tablespace: Option<String> =
            row.try_get("tablespace").context("relation tablespace")?;
        let access_method: Option<String> = row
            .try_get("access_method")
            .context("relation access method")?;
        let cluster_index: Option<String> = row
            .try_get("cluster_index")
            .context("relation cluster index")?;
        let owner_name: String = row.try_get("owner_name").context("relation owner")?;
        let raw_rows: i64 = row
            .try_get("estimated_rows")
            .context("relation estimated row count")?;
        let relpages: i64 = row.try_get("relpages").context("relation page count")?;
        let last_analyze: Option<String> = row
            .try_get("last_analyze")
            .context("relation last-analyze timestamp")?;
        let last_autoanalyze: Option<String> = row
            .try_get("last_autoanalyze")
            .context("relation last-autoanalyze timestamp")?;
        let is_populated: Option<bool> = row
            .try_get("is_populated")
            .context("materialized-view population state")?;

        let object_id = ObjectId::new(&schema_name, &relation_name);
        let kind = relation_kind_from_pg(relkind as u8)
            .with_context(|| format!("relation '{}' kind", object_id))?;
        let persistence = persistence_from_pg(persistence_char as u8)
            .with_context(|| format!("relation '{}' persistence", object_id))?;
        let estimated_rows = if raw_rows < 0 {
            None
        } else {
            Some(raw_rows as u64)
        };
        let mut state = RelationState::new(
            object_id.clone(),
            relation_owner_id(owner_name),
            0,
            estimated_rows,
            kind,
            persistence,
            0,
        );
        state.relpages = if relpages < 0 {
            None
        } else {
            Some(relpages as u64)
        };
        state.last_analyze = last_analyze;
        state.last_autoanalyze = last_autoanalyze;
        let partition_strategy: Option<String> = row
            .try_get("partition_strategy")
            .context("relation partition strategy")?;
        state.partition_type = partition_strategy_from_pg(partition_strategy.as_deref())
            .with_context(|| format!("relation '{}' partition strategy", object_id))?;
        state.is_populated = is_populated;
        state.has_toast_table = Some(
            row.try_get::<_, bool>("has_toast_table")
                .context("relation TOAST table presence")?,
        );
        state.partition_by = row
            .try_get::<_, Option<String>>("partition_key")?
            .map(|key| format!("PARTITION BY {key}"));
        state.partition_bound = row.try_get("partition_bound")?;
        state.partition_constraint = row.try_get("partition_constraint")?;
        state.row_security = Some(row_security);
        state.force_row_security = Some(force_row_security);
        state.replica_identity = replica_identity;
        state.of_type = match (typed_table_type_schema, typed_table_type_name) {
            (Some(schema), Some(name)) => Some(ObjectId::new(schema, name)),
            (None, None) => None,
            _ => anyhow::bail!("PostgreSQL returned incomplete typed-table type identity"),
        };
        state.table_options = catalog_options(relation_options, "relation")
            .with_context(|| format!("relation '{}' options", object_id))?;
        state.tablespace = tablespace;
        state.access_method = access_method;
        state.cluster_index = cluster_index;
        if let Some(scoped_schemas) = schemas
            && !scoped_schemas.contains(&schema_name)
        {
            state.mark_fk_dependency();
        }
        relations.insert(object_id, state);
    }

    let column_query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            a.attname AS column_name,
            CASE WHEN type_ns.nspname <> 'pg_catalog'
                       AND pg_catalog.pg_type_is_visible(a.atttypid)
                 THEN quote_ident(type_ns.nspname) || '.' || pg_catalog.format_type(a.atttypid, a.atttypmod)
                 ELSE pg_catalog.format_type(a.atttypid, a.atttypmod)
            END AS type_name,
            a.attnotnull AS not_null,
            s.avg_width AS avg_width,
            pg_get_expr(ad.adbin, ad.adrelid) AS default_expr_text,
            a.atttypmod AS type_modifier,
            a.attstorage::text AS storage,
            NULLIF(a.attcompression::text, '') AS compression,
            a.attstattarget::integer AS statistics_target,
            a.attoptions AS column_options,
            a.attinhcount::integer AS inheritance_count,
            a.attislocal AS is_local,
            NULLIF(a.attgenerated::text, '') AS generated_kind,
            NULLIF(a.attidentity::text, '') AS identity_generation
        FROM pg_attribute a
        JOIN pg_type column_type ON column_type.oid = a.atttypid
        JOIN pg_namespace type_ns ON type_ns.oid = column_type.typnamespace
        JOIN pg_class c ON a.attrelid = c.oid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_stats s ON s.schemaname = n.nspname AND s.tablename = c.relname AND s.attname = a.attname
        LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE a.attnum > 0 AND NOT a.attisdropped
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk}
        -- Composite-type fields are ordered by pg_attribute.attnum.  Keep the
        -- relation projection in that same order so typed-table layout
        -- validation does not depend on PostgreSQL's join plan.
        ORDER BY n.nspname, c.relname, a.attnum;
    "
    );
    let rows = client
        .query(&column_query, &[schema_values])
        .context("Failed to load relation columns from pg_attribute")?;
    for row in rows {
        let relation_id = ObjectId::new(
            row.try_get::<_, String>("schema_name")
                .context("column relation schema")?,
            row.try_get::<_, String>("relation_name")
                .context("column relation name")?,
        );
        let relation = relations.get_mut(&relation_id).with_context(|| {
            format!(
                "column catalog row references relation '{}' omitted by the relation loader",
                relation_id
            )
        })?;
        let column_name: String = row.try_get("column_name").context("column name")?;
        let identity_generation: Option<String> = row
            .try_get("identity_generation")
            .context("column identity generation")?;
        if let Some(code) = identity_generation {
            let mut chars = code.chars();
            let generation = chars
                .next()
                .filter(|_| chars.next().is_none())
                .and_then(crate::_internal::model::relation::IdentityGeneration::from_pg_code)
                .with_context(|| {
                    format!(
                        "column '{}.{}' identity generation",
                        relation_id, column_name
                    )
                })?;
            relation
                .identity_columns
                .insert(column_name.clone(), generation);
        }
        let generated_kind: Option<String> = row
            .try_get("generated_kind")
            .context("column generated kind")?;
        let expression_text: Option<String> = row
            .try_get("default_expr_text")
            .context("column expression")?;
        if let Some(code) = generated_kind.as_deref() {
            let mut chars = code.chars();
            let kind = chars
                .next()
                .filter(|_| chars.next().is_none())
                .and_then(crate::_internal::model::relation::GeneratedColumnKind::from_pg_code)
                .with_context(|| {
                    format!("column '{}.{}' generated kind", relation_id, column_name)
                })?;
            relation.generated_columns.insert(
                column_name.clone(),
                crate::_internal::model::relation::GeneratedColumnState {
                    kind,
                    expression: expression_text.clone(),
                },
            );
        }
        relation.column_inheritance.insert(
            column_name.clone(),
            crate::_internal::model::relation::ColumnInheritance {
                parent_count: u32::try_from(row.try_get::<_, i32>("inheritance_count")?)
                    .context("negative column inheritance count")?,
                is_local: row.try_get("is_local")?,
            },
        );
        relation
            .columns
            .push(crate::_internal::model::column::Column {
                name: column_name,
                data_type: Some(row.try_get("type_name").context("column type")?),
                type_id: None,
                is_nullable: !row
                    .try_get::<_, bool>("not_null")
                    .context("column nullability")?,
                default: None,
                avg_width: row.try_get("avg_width").context("column average width")?,
                default_expr_text: generated_kind
                    .is_none()
                    .then_some(expression_text)
                    .flatten(),
                type_modifier: row
                    .try_get("type_modifier")
                    .context("column type modifier")?,
                storage: column_storage_from_pg(
                    &row.try_get::<_, String>("storage")
                        .context("column storage")?,
                )
                .context("column storage")
                .map(Some)?,
                compression: column_compression_from_pg(
                    row.try_get::<_, Option<String>>("compression")
                        .context("column compression")?
                        .as_deref(),
                )
                .context("column compression")?,
                statistics_target: row
                    .try_get("statistics_target")
                    .context("column statistics target")?,
                options: catalog_options(
                    row.try_get("column_options").context("column options")?,
                    "column",
                )
                .with_context(|| format!("column options on relation '{}'", relation_id))?,
                generated: Some(generated_kind.is_some()),
            });
    }

    let statistics_query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            stats_ns.nspname AS statistics_schema,
            stats.stxname AS statistics_name,
            ARRAY(SELECT kind::text FROM unnest(stats.stxkind) AS kind) AS kinds,
            ARRAY(
                SELECT attribute.attname
                FROM (
                    SELECT key.attnum
                    FROM unnest(stats.stxkeys::smallint[]) AS key(attnum)
                    UNION
                    SELECT dependency.refobjsubid::smallint
                    FROM pg_depend dependency
                    WHERE dependency.classid = 'pg_statistic_ext'::regclass
                      AND dependency.objid = stats.oid
                      AND dependency.refclassid = 'pg_class'::regclass
                      AND dependency.refobjid = stats.stxrelid
                      AND dependency.refobjsubid > 0
                ) AS key
                JOIN pg_attribute attribute
                  ON attribute.attrelid = stats.stxrelid
                 AND attribute.attnum = key.attnum
                ORDER BY attribute.attname
            ) AS columns,
            pg_get_expr(stats.stxexprs, stats.stxrelid, false) AS expressions,
            stats.stxstattarget::integer AS statistics_target
        FROM pg_statistic_ext stats
        JOIN pg_class c ON c.oid = stats.stxrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_namespace stats_ns ON stats_ns.oid = stats.stxnamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk}
        ORDER BY stats_ns.nspname, stats.stxname;
        "
    );
    for row in client
        .query(&statistics_query, &[schema_values])
        .context("Failed to load extended statistics from pg_statistic_ext")?
    {
        let relation_id = ObjectId::new(
            row.try_get::<_, String>("table_schema")
                .context("extended statistics table schema")?,
            row.try_get::<_, String>("table_name")
                .context("extended statistics table name")?,
        );
        let statistics_id = ObjectId::new(
            row.try_get::<_, String>("statistics_schema")
                .context("extended statistics schema")?,
            row.try_get::<_, String>("statistics_name")
                .context("extended statistics name")?,
        );
        let relation = relations.get_mut(&relation_id).with_context(|| {
            format!(
                "extended statistics '{}' reference omitted relation '{}'",
                statistics_id, relation_id
            )
        })?;
        relation.extended_statistics.insert(
            statistics_id.clone(),
            crate::_internal::model::relation::ExtendedStatisticsState {
                id: statistics_id,
                kinds: row.try_get("kinds").context("extended statistics kinds")?,
                columns: row
                    .try_get("columns")
                    .context("extended statistics columns")?,
                expressions: row
                    .try_get("expressions")
                    .context("extended statistics expressions")?,
                target: row
                    .try_get("statistics_target")
                    .context("extended statistics target")?,
            },
        );
    }
    Ok(relations)
}

pub(super) struct RelationDecoration {
    pub(super) relation_id: ObjectId,
    pub(super) triggers: Vec<String>,
    pub(super) policies: Vec<String>,
    pub(super) rules:
        std::collections::HashMap<String, crate::_internal::model::relation::RuleEnableMode>,
}

pub(super) struct RelationGrant {
    pub(super) relation_id: ObjectId,
    pub(super) grantor: ObjectId,
    pub(super) grantee: ObjectId,
    pub(super) privilege: crate::_internal::model::relation::Privilege,
    pub(super) is_grantable: bool,
}

pub(super) fn load_relation_decorations(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<(Vec<RelationDecoration>, Vec<RelationGrant>)> {
    let topology_query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            COALESCE(array_agg(DISTINCT t.tgname) FILTER (WHERE t.tgname IS NOT NULL AND t.tgisinternal = false), '{{}}') as triggers,
            COALESCE(array_agg(DISTINCT p.polname) FILTER (WHERE p.polname IS NOT NULL), '{{}}') as policies,
            ARRAY(
                SELECT r.rulename
                FROM pg_rewrite r
                WHERE r.ev_class = c.oid AND r.rulename <> '_RETURN'
                ORDER BY r.oid
            ) AS rule_names,
            ARRAY(
                SELECT r.ev_enabled::text
                FROM pg_rewrite r
                WHERE r.ev_class = c.oid AND r.rulename <> '_RETURN'
                ORDER BY r.oid
            ) AS rule_modes
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_trigger t ON t.tgrelid = c.oid
        LEFT JOIN pg_policy p ON p.polrelid = c.oid
        WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        {schema_filter_with_fk}
        GROUP BY n.nspname, c.relname, c.oid;
    "
    );
    let decorations = client
        .query(&topology_query, &[schema_values])
        .context("Failed to load relation triggers and policies")?
        .into_iter()
        .map(|row| {
            let rule_names: Vec<String> = row.try_get("rule_names").context("relation rules")?;
            let rule_modes: Vec<String> =
                row.try_get("rule_modes").context("relation rule modes")?;
            if rule_names.len() != rule_modes.len() {
                anyhow::bail!("PostgreSQL returned mismatched relation rule metadata");
            }
            let rules = rule_names
                .into_iter()
                .zip(rule_modes)
                .map(|(name, code)| {
                    let mut chars = code.chars();
                    let mode = chars
                        .next()
                        .filter(|_| chars.next().is_none())
                        .and_then(crate::_internal::model::relation::RuleEnableMode::from_pg_code)
                        .with_context(|| format!("rule '{name}' enable mode"))?;
                    Ok((name, mode))
                })
                .collect::<Result<std::collections::HashMap<_, _>>>()?;
            Ok(RelationDecoration {
                relation_id: ObjectId::new(
                    row.try_get::<_, String>("schema_name")
                        .context("decorated relation schema")?,
                    row.try_get::<_, String>("relation_name")
                        .context("decorated relation name")?,
                ),
                triggers: row.try_get("triggers").context("relation trigger names")?,
                policies: row.try_get("policies").context("relation policy names")?,
                rules,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let acl_query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            CASE
                WHEN acl.grantee = 0 THEN 'public'
                ELSE pg_catalog.pg_get_userbyid(acl.grantee)
            END AS grantee,
            pg_catalog.pg_get_userbyid(acl.grantor) AS grantor,
            acl.privilege_type,
            acl.is_grantable
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl
        WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND acl.grantee <> c.relowner
          {schema_filter_with_fk};
        "
    );
    let grants = client
        .query(&acl_query, &[schema_values])
        .context("Failed to load explicit relation privileges")?
        .into_iter()
        .map(|row| {
            let privilege_type: String = row
                .try_get("privilege_type")
                .context("relation privilege type")?;
            let privilege = match privilege_type.as_str() {
                "SELECT" => crate::_internal::model::relation::Privilege::Select,
                "INSERT" => crate::_internal::model::relation::Privilege::Insert,
                "UPDATE" => crate::_internal::model::relation::Privilege::Update,
                "DELETE" => crate::_internal::model::relation::Privilege::Delete,
                "TRUNCATE" => crate::_internal::model::relation::Privilege::Truncate,
                "REFERENCES" => crate::_internal::model::relation::Privilege::References,
                "TRIGGER" => crate::_internal::model::relation::Privilege::Trigger,
                "MAINTAIN" => crate::_internal::model::relation::Privilege::Maintain,
                other => anyhow::bail!("unsupported relation privilege type '{other}'"),
            };
            Ok(RelationGrant {
                relation_id: ObjectId::new(
                    row.try_get::<_, String>("schema_name")
                        .context("privileged relation schema")?,
                    row.try_get::<_, String>("relation_name")
                        .context("privileged relation name")?,
                ),
                grantor: ObjectId::new(
                    "",
                    row.try_get::<_, String>("grantor")
                        .context("relation privilege grantor")?,
                ),
                grantee: ObjectId::new(
                    "",
                    row.try_get::<_, String>("grantee")
                        .context("relation privilege grantee")?,
                ),
                privilege,
                is_grantable: row
                    .try_get("is_grantable")
                    .context("relation privilege grant option")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((decorations, grants))
}

pub(super) fn load_triggers(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<crate::_internal::db::cache::TriggerCache>> {
    let query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            t.tgname AS trigger_name,
            t.tgenabled::text AS enabled_mode,
            (t.tgtype & 1) <> 0 AS row_level,
            COALESCE(pn.nspname, inferred_pn.nspname) AS parent_table_schema,
            COALESCE(pc.relname, inferred_pc.relname) AS parent_table_name,
            COALESCE(pt.tgname, inferred_pt.tgname) AS parent_trigger_name,
            fn.nspname AS function_schema,
            f.proname || '()' AS function_name
        FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_proc f ON f.oid = t.tgfoid
        JOIN pg_namespace fn ON fn.oid = f.pronamespace
        LEFT JOIN pg_trigger pt ON pt.oid = t.tgparentid
        LEFT JOIN pg_class pc ON pc.oid = pt.tgrelid
        LEFT JOIN pg_namespace pn ON pn.oid = pc.relnamespace
        LEFT JOIN LATERAL (
            SELECT parent_t.oid AS trigger_oid,
                   parent_c.oid AS table_oid,
                   parent_c.relname,
                   parent_n.nspname,
                   parent_t.tgname
            FROM pg_inherits inheritance
            JOIN pg_trigger parent_t
              ON parent_t.tgrelid = inheritance.inhparent
             AND parent_t.tgname = t.tgname
             AND parent_t.tgisinternal = false
            JOIN pg_class parent_c ON parent_c.oid = parent_t.tgrelid
            JOIN pg_namespace parent_n ON parent_n.oid = parent_c.relnamespace
            WHERE inheritance.inhrelid = t.tgrelid
            -- A cloned trigger normally keeps the same function OID.  Older
            -- PostgreSQL releases have catalog cases where that linkage is
            -- not stable, so prefer an exact function match but retain the
            -- unique parent/name relationship as a compatibility fallback.
            ORDER BY (parent_t.tgfoid = t.tgfoid) DESC, parent_t.oid
            LIMIT 1
        ) inferred_pt ON true
        LEFT JOIN pg_class inferred_pc ON inferred_pc.oid = inferred_pt.table_oid
        LEFT JOIN pg_namespace inferred_pn ON inferred_pn.oid = inferred_pc.relnamespace
        WHERE (t.tgisinternal = false OR (t.tgparentid <> 0 AND pt.tgisinternal = false))
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
    "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load triggers and trigger functions")?
        .into_iter()
        .map(|row| {
            let table_schema: String = row.try_get("table_schema").context("trigger schema")?;
            let enabled_mode: String = row
                .try_get("enabled_mode")
                .context("trigger enabled mode")?;
            Ok(crate::_internal::db::cache::TriggerCache {
                trigger_id: ObjectId::new(
                    &table_schema,
                    row.try_get::<_, String>("trigger_name")
                        .context("trigger name")?,
                ),
                table_id: ObjectId::new(
                    &table_schema,
                    row.try_get::<_, String>("table_name")
                        .context("trigger table name")?,
                ),
                function_id: ObjectId::new(
                    row.try_get::<_, String>("function_schema")
                        .context("trigger function schema")?,
                    row.try_get::<_, String>("function_name")
                        .context("trigger function name")?,
                ),
                row_level: row.try_get("row_level").context("trigger level")?,
                parent_trigger_id: match (
                    row.try_get::<_, Option<String>>("parent_table_schema")
                        .context("parent trigger table schema")?,
                    row.try_get::<_, Option<String>>("parent_table_name")
                        .context("parent trigger table name")?,
                    row.try_get::<_, Option<String>>("parent_trigger_name")
                        .context("parent trigger name")?,
                ) {
                    (Some(schema), Some(table), Some(name)) => {
                        Some(ObjectId::new(schema, format!("{table}\0{name}")))
                    }
                    (None, None, None) => None,
                    _ => anyhow::bail!("PostgreSQL returned incomplete parent trigger identity"),
                },
                enabled_mode: crate::_internal::model::trigger::TriggerEnableMode::from_pg_code(
                    &enabled_mode,
                )
                .ok_or_else(|| {
                    anyhow::anyhow!("unknown pg_trigger.tgenabled value {enabled_mode}")
                })?,
            })
        })
        .collect()
}

pub(super) fn load_inheritances(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
) -> Result<Vec<InheritanceCache>> {
    let query = r#"
        SELECT
            child_ns.nspname AS child_schema,
            child.relname AS child_name,
            parent_ns.nspname AS parent_schema,
            parent.relname AS parent_name,
            inh.inhseqno,
            child.relispartition AS child_is_partition,
            inh.inhdetachpending
        FROM pg_inherits inh
        JOIN pg_class child ON child.oid = inh.inhrelid
        JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
        JOIN pg_class parent ON parent.oid = inh.inhparent
        JOIN pg_namespace parent_ns ON parent_ns.oid = parent.relnamespace
        WHERE child.relkind IN ('r', 'p', 'f')
          AND parent.relkind IN ('r', 'p', 'f')
          AND child_ns.nspname NOT IN ('pg_catalog', 'information_schema')
          AND parent_ns.nspname NOT IN ('pg_catalog', 'information_schema')
          AND (
              $1::text[] IS NULL
              OR child_ns.nspname = ANY($1)
              OR parent_ns.nspname = ANY($1)
          )
        ORDER BY child_ns.nspname, child.relname, inh.inhseqno
    "#;
    client
        .query(query, &[schema_values])
        .context("Failed to load table inheritance from pg_inherits")?
        .into_iter()
        .map(|row| {
            Ok(InheritanceCache {
                child: ObjectId::new(
                    row.try_get::<_, String>("child_schema")
                        .context("inheritance child schema")?,
                    row.try_get::<_, String>("child_name")
                        .context("inheritance child name")?,
                ),
                parent: ObjectId::new(
                    row.try_get::<_, String>("parent_schema")
                        .context("inheritance parent schema")?,
                    row.try_get::<_, String>("parent_name")
                        .context("inheritance parent name")?,
                ),
                sequence: row.try_get("inhseqno").context("inheritance sequence")?,
                is_partition: row
                    .try_get("child_is_partition")
                    .context("inheritance partition flag")?,
                detach_pending: row
                    .try_get("inhdetachpending")
                    .context("inheritance detach-pending flag")?,
            })
        })
        .collect()
}
