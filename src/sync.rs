// FILE: src/sync.rs

use crate::ast::identifiers::ObjectId;
use crate::db::cache::{CACHE_V6_MAGIC, DbCache, DbCacheVersioned, ForeignKeyCache, IndexCache};
use crate::db::cache_file::protect_cache_bytes;
use crate::model::relation::{Persistence, RelationKind, RelationState};
use anyhow::{Context, Result};
use postgres::config::Host;
use postgres::{Client, Config as PostgresConfig, NoTls};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

#[cfg(windows)]
use std::fs;

pub fn sync_cache(
    out_path: &Path,
    schemas: Option<&[String]>,
    cache_encryption: bool,
) -> Result<()> {
    // Strict env-only credential enforcement
    let db_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL environment variable is required to sync PostgreSQL schema metadata and statistics. Do not pass credentials via CLI flags or config files.")?;

    let mut client = connect_database(&db_url)?;

    let cache = populate_cache(&mut client, schemas)?;

    write_cache(out_path, cache, cache_encryption)
}

fn connect_database(db_url: &str) -> Result<Client> {
    let config: PostgresConfig = db_url
        .parse()
        .context("DATABASE_URL is not a valid PostgreSQL connection string")?;

    if config
        .get_hosts()
        .iter()
        .any(|host| matches!(host, Host::Tcp(name) if !is_local_host(name)))
    {
        anyhow::bail!(
            "Remote DATABASE_URL connections are not supported by this build. Use an SSH tunnel and connect through localhost or a Unix socket."
        );
    }

    config
        .connect(NoTls)
        .context("Failed to connect to PostgreSQL")
}

pub(crate) fn is_local_host(host: &str) -> bool {
    if host.starts_with('/') || host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

pub(crate) fn cache_search_path(
    database_search_path: Vec<String>,
    schemas: Option<&[String]>,
) -> Vec<String> {
    let Some(schemas) = schemas else {
        return database_search_path;
    };

    let mut scoped_search_path = Vec::new();
    for schema in database_search_path
        .into_iter()
        .filter(|schema| schemas.contains(schema))
        .chain(schemas.iter().cloned())
    {
        if !scoped_search_path.contains(&schema) {
            scoped_search_path.push(schema);
        }
    }
    scoped_search_path
}

/// Parse PostgreSQL's canonical `SHOW search_path` representation while
/// preserving the special `$user` placeholder and quoted identifier casing.
pub(crate) fn parse_search_path_setting(setting: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut current = String::new();
    let mut chars = setting.chars().peekable();
    let mut quoted = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                let entry = current.trim();
                if !entry.is_empty() {
                    entries.push(entry.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    let entry = current.trim();
    if !entry.is_empty() {
        entries.push(entry.to_string());
    }
    entries
}

pub(crate) fn relation_owner_id(owner_name: impl Into<String>) -> ObjectId {
    ObjectId::new("", owner_name)
}

pub(crate) fn is_system_schema(schema: &str) -> bool {
    schema == "information_schema" || schema.starts_with("pg_")
}

fn write_cache(out_path: &Path, cache: DbCache, cache_encryption: bool) -> Result<()> {
    write_cache_with_protection(out_path, cache, |compressed| {
        protect_cache_bytes(compressed, cache_encryption)
    })
}

fn write_cache_with_protection(
    out_path: &Path,
    cache: DbCache,
    protect: impl FnOnce(Vec<u8>) -> Result<Vec<u8>>,
) -> Result<()> {
    let parent = out_path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "Failed to create temporary cache file beside {}",
            out_path.display()
        )
    })?;
    let mut compressed = Vec::new();
    let mut encoder = zstd::stream::Encoder::new(&mut compressed, 3)
        .context("Failed to init zstd compression")?;

    encoder
        .write_all(CACHE_V6_MAGIC)
        .context("Failed to write cache V6 payload header")?;

    let versioned = DbCacheVersioned::V6(Box::new(cache));
    let bincode_config = bincode::config::standard().with_variable_int_encoding();

    bincode::serde::encode_into_std_write(&versioned, &mut encoder, bincode_config)
        .context("Failed bincode schema compilation and write")?;

    encoder
        .finish()
        .context("Failed to flush final zstd stream to disk")?;

    let cache_bytes = protect(compressed)?;
    temp_file
        .write_all(&cache_bytes)
        .context("Failed to write cache payload")?;
    temp_file.flush().context("Failed to flush cache payload")?;

    replace_cache(temp_file, out_path)?;

    Ok(())
}

#[cfg(not(windows))]
fn replace_cache(temp_file: NamedTempFile, out_path: &Path) -> Result<()> {
    temp_file
        .persist(out_path)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "Failed to atomically replace cache file: {}",
                out_path.display()
            )
        })?;
    Ok(())
}

#[cfg(windows)]
fn replace_cache(temp_file: NamedTempFile, out_path: &Path) -> Result<()> {
    if !out_path.exists() {
        temp_file
            .persist(out_path)
            .map_err(|error| error.error)
            .with_context(|| format!("Failed to install cache file: {}", out_path.display()))?;
        return Ok(());
    }

    let backup = out_path.with_extension("safe-migrate.backup");
    fs::rename(out_path, &backup).with_context(|| {
        format!(
            "Failed to stage existing cache for replacement: {}",
            out_path.display()
        )
    })?;

    match temp_file.persist(out_path) {
        Ok(_) => {
            fs::remove_file(&backup).with_context(|| {
                format!(
                    "Installed new cache but failed to remove backup: {}",
                    backup.display()
                )
            })?;
            Ok(())
        }
        Err(error) => {
            let restore_result = fs::rename(&backup, out_path);
            let message = if let Err(restore_error) = restore_result {
                format!(
                    "Failed to install new cache: {}. The old cache could not be restored: {}",
                    error.error, restore_error
                )
            } else {
                format!(
                    "Failed to install new cache; restored the previous cache: {}",
                    error.error
                )
            };
            Err(anyhow::anyhow!(message))
        }
    }
}

pub fn populate_cache(client: &mut Client, schemas: Option<&[String]>) -> Result<DbCache> {
    let mut cache = DbCache::new();
    let schema_values = schemas.map(|items| items.to_vec());
    cache.metadata.created_at_unix_secs = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    cache.metadata.schemas = schema_values.clone();

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

    // Query 1: Server Version
    let version_row = client.query_one("SHOW server_version_num;", &[])?;
    let version_str: String = version_row.get(0);
    cache.pg_version_num = version_str.parse::<u32>().ok();

    let provenance_row = client.query_one(
        "SELECT current_database(), current_user, session_user, current_setting('search_path'),
                (SELECT setting::bigint FROM pg_settings WHERE name = 'lock_timeout'),
                (SELECT setting::bigint FROM pg_settings WHERE name = 'statement_timeout');",
        &[],
    )?;
    cache.metadata.source_database = Some(provenance_row.get(0));
    cache.metadata.source_role = Some(provenance_row.get(1));
    cache.metadata.source_session_role = Some(provenance_row.get(2));
    let search_path_setting: String = provenance_row.get(3);
    cache.metadata.source_search_path = Some(parse_search_path_setting(&search_path_setting));
    let lock_timeout_ms: i64 = provenance_row.get(4);
    let statement_timeout_ms: i64 = provenance_row.get(5);
    cache.metadata.source_lock_timeout_ms = lock_timeout_ms
        .try_into()
        .context("PostgreSQL returned a negative lock_timeout")?;
    cache.metadata.source_statement_timeout_ms = statement_timeout_ms
        .try_into()
        .context("PostgreSQL returned a negative statement_timeout")?;

    // Resolve role/database defaults and special entries such as "$user" exactly
    // as PostgreSQL does, while excluding the implicit pg_catalog lookup. An
    // explicit schema scope remains the resolution boundary, but selected
    // schemas retain their live PostgreSQL priority.
    let search_path_row = client.query_one("SELECT current_schemas(false);", &[])?;
    cache.search_path = cache_search_path(search_path_row.get(0), schemas);

    // Schemas are an authoritative catalog only for the requested sync scope.
    // FK-only external schemas pulled in below deliberately do not enter it.
    let schema_query = format!(
        "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner)
         FROM pg_namespace n
         WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND n.nspname <> 'information_schema'
           {schema_filter}
         ORDER BY n.nspname;"
    );
    for row in client.query(&schema_query, &[&schema_values])? {
        let name: String = row.get(0);
        let owner: String = row.get(1);
        cache.schemas.insert(
            name.clone(),
            crate::model::schema::SchemaState {
                name,
                owner: relation_owner_id(owner),
                generation: 0,
            },
        );
    }
    // A scoped request can name schemas that do not exist yet. PostgreSQL's
    // effective search path skips those entries, so do not let them become
    // inferred-present namespaces when the cache is hydrated.
    cache
        .search_path
        .retain(|schema| cache.schemas.contains_key(schema));

    // A sequence can have at most one pg_depend ownership relationship. The
    // dependency flavor distinguishes identity's internal dependency from an
    // ordinary OWNED BY relationship. An auto dependency is serial-like only
    // when the owning column also has the sequence-backed nextval default.
    let sequence_query = format!(
        "SELECT
             n.nspname AS sequence_schema,
             s.relname AS sequence_name,
             pg_catalog.pg_get_userbyid(s.relowner) AS owner_name,
             tn.nspname AS table_schema,
             t.relname AS table_name,
             a.attname AS column_name,
             d.deptype::text AS dependency_type,
             CASE WHEN ad.adbin IS NULL THEN false
                  ELSE pg_catalog.pg_get_expr(ad.adbin, ad.adrelid) LIKE '%nextval(%'
             END AS has_nextval_default
         FROM pg_class s
         JOIN pg_namespace n ON n.oid = s.relnamespace
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
    for row in client.query(&sequence_query, &[&schema_values])? {
        let id = ObjectId::new(row.get::<_, String>(0), row.get::<_, String>(1));
        let owner = relation_owner_id(row.get::<_, String>(2));
        let table_schema: Option<String> = row.get(3);
        let table_name: Option<String> = row.get(4);
        let column_name: Option<String> = row.get(5);
        let dependency_type: Option<String> = row.get(6);
        let has_nextval_default: bool = row.get(7);
        let owned_by = table_schema
            .zip(table_name)
            .zip(column_name)
            .map(|((schema, table), column)| (ObjectId::new(schema, table), column));
        let kind = match dependency_type.as_deref() {
            Some("i") => crate::model::sequence::SequenceKind::Identity,
            Some("a") if has_nextval_default => crate::model::sequence::SequenceKind::SerialLike,
            Some("a") => crate::model::sequence::SequenceKind::Owned,
            _ => crate::model::sequence::SequenceKind::Standalone,
        };
        cache.sequences.insert(
            id.clone(),
            crate::model::sequence::SequenceState {
                id,
                owner,
                owned_by,
                kind,
                generation: 0,
            },
        );
    }

    // Query 2: Relations + Staleness
    let table_query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            c.relkind AS relation_kind,
            c.relpersistence AS persistence,
            pg_catalog.pg_get_userbyid(c.relowner) AS owner_name,
            CASE WHEN c.reltuples < 0 THEN -1 ELSE c.reltuples::bigint END AS estimated_rows,
            c.relpages::bigint AS relpages,
            to_char(s.last_analyze, 'YYYY-MM-DD HH24:MI:SS') AS last_analyze,
            to_char(s.last_autoanalyze, 'YYYY-MM-DD HH24:MI:SS') AS last_autoanalyze,
            p.partstrat::text AS partition_strategy
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
        LEFT JOIN pg_partitioned_table p ON p.partrelid = c.oid
        WHERE c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
    "
    );

    for row in client.query(&table_query, &[&schema_values])? {
        let schema_name: String = row.get("schema_name");
        let relation_name: String = row.get("relation_name");
        let relkind: i8 = row.get("relation_kind");
        let persistence_char: i8 = row.get("persistence");
        let owner_name: String = row.get("owner_name");
        let raw_rows: i64 = row.get("estimated_rows");
        let relpages: i64 = row.get("relpages");

        let last_analyze: Option<String> = row.get("last_analyze");
        let last_autoanalyze: Option<String> = row.get("last_autoanalyze");

        let object_id = ObjectId::new(&schema_name, &relation_name);

        let kind = match relkind as u8 {
            b'v' => RelationKind::View,
            b'm' => RelationKind::MaterializedView,
            _ => RelationKind::Table,
        };

        let persistence = match persistence_char as u8 {
            b't' => Persistence::Temporary,
            b'u' => Persistence::Unlogged,
            _ => Persistence::Permanent,
        };

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
        state.relpages = Some(relpages as u64);
        state.last_analyze = last_analyze;
        state.last_autoanalyze = last_autoanalyze;

        let partition_strategy: Option<String> = row.get("partition_strategy");
        if let Some(ref strat) = partition_strategy {
            state.partition_type = Some(match strat.as_str() {
                "r" => "RANGE".to_string(),
                "l" => "LIST".to_string(),
                "h" => "HASH".to_string(),
                _ => strat.to_uppercase(),
            });
        }

        if let Some(s) = schemas
            && !s.contains(&schema_name)
        {
            state.mark_fk_dependency();
        }

        cache.insert_baseline(object_id, state);
    }

    // Query 3: Columns + Width
    let col_query = format!("
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            a.attname AS column_name,
            pg_catalog.format_type(a.atttypid, a.atttypmod) AS type_name,
            a.attnotnull AS not_null,
            s.avg_width AS avg_width,
            pg_get_expr(ad.adbin, ad.adrelid) AS default_expr_text,
            a.atttypmod AS type_modifier
        FROM pg_attribute a
        JOIN pg_class c ON a.attrelid = c.oid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_stats s ON s.schemaname = n.nspname AND s.tablename = c.relname AND s.attname = a.attname
        LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE a.attnum > 0 AND NOT a.attisdropped
          AND c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk}
        ORDER BY n.nspname, c.relname;
    ");

    for row in client.query(&col_query, &[&schema_values])? {
        let schema_name: String = row.get("schema_name");
        let relation_name: String = row.get("relation_name");
        let column_name: String = row.get("column_name");
        let type_name: String = row.get("type_name");
        let not_null: bool = row.get("not_null");
        let avg_width: Option<i32> = row.get("avg_width");
        let default_expr_text: Option<String> = row.get("default_expr_text");
        let type_modifier: Option<i32> = row.get("type_modifier");

        let relation_id = ObjectId::new(&schema_name, &relation_name);
        if let Some(rel) = cache.relations.get_mut(&relation_id) {
            rel.columns.push(crate::model::column::Column {
                name: column_name,
                data_type: Some(type_name),
                type_id: None,
                is_nullable: !not_null,
                default: None,
                avg_width,
                default_expr_text,
                type_modifier,
            });
        }
    }

    // Query 4: Triggers & Policies
    let tp_query = format!("
        SELECT 
            n.nspname AS schema_name,
            c.relname AS relation_name,
            COALESCE(array_agg(DISTINCT t.tgname) FILTER (WHERE t.tgname IS NOT NULL AND t.tgisinternal = false), '{{}}') as triggers,
            COALESCE(array_agg(DISTINCT p.polname) FILTER (WHERE p.polname IS NOT NULL), '{{}}') as policies
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_trigger t ON t.tgrelid = c.oid
        LEFT JOIN pg_policy p ON p.polrelid = c.oid
        WHERE c.relkind IN ('r', 'p', 'v', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        {schema_filter_with_fk}
        GROUP BY n.nspname, c.relname;
    ");

    for row in client.query(&tp_query, &[&schema_values])? {
        let schema_name: String = row.get("schema_name");
        let relation_name: String = row.get("relation_name");
        let triggers: Vec<String> = row.get("triggers");
        let policies: Vec<String> = row.get("policies");

        let object_id = ObjectId::new(&schema_name, &relation_name);

        if let Some(rel) = cache.relations.get_mut(&object_id) {
            rel.triggers.extend(triggers);
            rel.policies.extend(policies);
        }
    }

    // Query 4.25: Explicit non-owner relation privileges.
    let acl_query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            CASE
                WHEN acl.grantee = 0 THEN 'public'
                ELSE pg_catalog.pg_get_userbyid(acl.grantee)
            END AS grantee,
            acl.privilege_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl
        WHERE c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND acl.grantee <> c.relowner
          {schema_filter_with_fk};
        "
    );

    for row in client.query(&acl_query, &[&schema_values])? {
        let schema_name: String = row.get("schema_name");
        let relation_name: String = row.get("relation_name");
        let grantee: String = row.get("grantee");
        let privilege_type: String = row.get("privilege_type");
        let privilege = match privilege_type.as_str() {
            "SELECT" => crate::model::relation::Privilege::Select,
            "INSERT" => crate::model::relation::Privilege::Insert,
            "UPDATE" => crate::model::relation::Privilege::Update,
            "DELETE" => crate::model::relation::Privilege::Delete,
            "TRUNCATE" => crate::model::relation::Privilege::Truncate,
            "REFERENCES" => crate::model::relation::Privilege::References,
            "TRIGGER" => crate::model::relation::Privilege::Trigger,
            _ => continue,
        };
        if let Some(relation) = cache
            .relations
            .get_mut(&ObjectId::new(&schema_name, &relation_name))
        {
            relation.privileges.grant(
                ObjectId::new("", grantee),
                [privilege].into_iter().collect(),
            );
        }
    }

    // Query 4.5: Trigger Functions
    let trig_query = format!(
        "
        SELECT 
            n.nspname AS table_schema,
            c.relname AS table_name,
            t.tgname AS trigger_name,
            t.tgenabled::text AS enabled_mode,
            fn.nspname AS function_schema,
            f.proname || '()' AS function_name
        FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_proc f ON f.oid = t.tgfoid
        JOIN pg_namespace fn ON fn.oid = f.pronamespace
        WHERE t.tgisinternal = false
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
    "
    );

    for row in client.query(&trig_query, &[&schema_values])? {
        let table_schema: String = row.get("table_schema");
        let table_name: String = row.get("table_name");
        let trigger_name: String = row.get("trigger_name");
        let enabled_mode: String = row.get("enabled_mode");
        let function_schema: String = row.get("function_schema");
        let function_name: String = row.get("function_name");

        cache.triggers.push(crate::db::cache::TriggerCache {
            trigger_id: ObjectId::new(&table_schema, &trigger_name),
            table_id: ObjectId::new(&table_schema, &table_name),
            function_id: ObjectId::new(&function_schema, &function_name),
            enabled_mode: crate::model::trigger::TriggerEnableMode::from_pg_code(&enabled_mode)
                .ok_or_else(|| {
                    anyhow::anyhow!("unknown pg_trigger.tgenabled value {enabled_mode}")
                })?,
        });
    }

    // Query 4.75: Table constraints
    let constraint_query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            con.conname AS constraint_name,
            con.contype::text AS constraint_type,
            con.convalidated AS validated
        FROM pg_constraint con
        JOIN pg_class c ON c.oid = con.conrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE con.contype IN ('c', 'f', 'p', 'u', 'x')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter};
        "
    );

    for row in client.query(&constraint_query, &[&schema_values])? {
        let table_schema: String = row.get("table_schema");
        let table_name: String = row.get("table_name");
        let constraint_name: String = row.get("constraint_name");
        let constraint_type: String = row.get("constraint_type");
        let validated: bool = row.get("validated");
        let kind = match constraint_type.as_str() {
            "c" => crate::model::constraint::ConstraintKind::Check,
            "f" => crate::model::constraint::ConstraintKind::ForeignKey,
            "p" => crate::model::constraint::ConstraintKind::PrimaryKey,
            "u" => crate::model::constraint::ConstraintKind::Unique,
            "x" => crate::model::constraint::ConstraintKind::Exclusion,
            _ => continue,
        };
        cache
            .constraints
            .push(crate::model::constraint::ConstraintState {
                table_id: ObjectId::new(&table_schema, &table_name),
                name: constraint_name,
                kind,
                validated,
            });
    }

    // Query 5: Foreign Keys
    let fk_query = format!(
        "
        SELECT 
            c.conname AS constraint_name,
            n1.nspname AS from_schema, t1.relname AS from_table,
            n2.nspname AS to_schema, t2.relname AS to_table
        FROM pg_constraint c
        JOIN pg_class t1 ON t1.oid = c.conrelid
        JOIN pg_namespace n1 ON n1.oid = t1.relnamespace
        JOIN pg_class t2 ON t2.oid = c.confrelid
        JOIN pg_namespace n2 ON n2.oid = t2.relnamespace
        WHERE c.contype = 'f'
        {schema_filter_n1_or_n2};
    "
    );

    for row in client.query(&fk_query, &[&schema_values])? {
        let constraint_name: String = row.get("constraint_name");
        let from_schema: String = row.get("from_schema");
        let from_table: String = row.get("from_table");
        let to_schema: String = row.get("to_schema");
        let to_table: String = row.get("to_table");

        if let Some(s) = schemas
            && (!s.contains(&from_schema) || !s.contains(&to_schema))
        {
            // Determine which one is out of scope to print a helpful warning
            let out_of_scope_schema = if !s.contains(&from_schema) {
                &from_schema
            } else {
                &to_schema
            };
            let out_of_scope_table = if !s.contains(&from_schema) {
                &from_table
            } else {
                &to_table
            };
            eprintln!(
                "[WARN] Foreign key '{}' crosses schema boundary. Table '{}.{}' was pulled into cache as a dependency to evaluate cross-team locks.",
                constraint_name, out_of_scope_schema, out_of_scope_table
            );
        }

        cache.foreign_keys.push(ForeignKeyCache {
            constraint_name,
            from_table: ObjectId::new(&from_schema, &from_table),
            to_table: ObjectId::new(&to_schema, &to_table),
        });
    }

    // Query 6: Indexes
    let idx_query = format!(
        "
        SELECT 
            n_i.nspname AS index_schema, i.relname AS index_name,
            n_t.nspname AS table_schema, t.relname AS table_name
        FROM pg_index x
        JOIN pg_class i ON i.oid = x.indexrelid
        JOIN pg_namespace n_i ON n_i.oid = i.relnamespace
        JOIN pg_class t ON t.oid = x.indrelid
        JOIN pg_namespace n_t ON n_t.oid = t.relnamespace
        WHERE x.indisvalid = true
          AND n_i.nspname !~ '^pg_'
          AND n_i.nspname <> 'information_schema'
          AND n_t.nspname !~ '^pg_'
          AND n_t.nspname <> 'information_schema'
        {schema_filter_nt};
    "
    );

    for row in client.query(&idx_query, &[&schema_values])? {
        let index_schema: String = row.get("index_schema");
        let index_name: String = row.get("index_name");
        let table_schema: String = row.get("table_schema");
        let table_name: String = row.get("table_name");

        if is_system_schema(&index_schema) || is_system_schema(&table_schema) {
            continue;
        }

        cache.indexes.push(IndexCache {
            index_id: ObjectId::new(&index_schema, &index_name),
            table_id: ObjectId::new(&table_schema, &table_name),
        });
    }

    // Query 7: Functions
    let func_query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            p.proname AS func_name,
            COALESCE(
                (SELECT string_agg(pg_catalog.format_type(t, NULL), ',' ORDER BY n)
                 FROM unnest(p.proargtypes::int[]) WITH ORDINALITY AS u(t, n)),
                ''
            ) AS arg_types,
            pg_catalog.pg_get_function_result(p.oid) AS return_type,
            p.provolatile::text AS volatility,
            l.lanname AS language,
            p.prosecdef AS security_definer
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_language l ON l.oid = p.prolang
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND p.prokind = 'f'
          {schema_filter};
    "
    );

    for row in client.query(&func_query, &[&schema_values])? {
        let schema_name: String = row.get("schema_name");
        let func_name: String = row.get("func_name");
        let arg_types_str: String = row.get("arg_types");
        let return_type: Option<String> = row.get("return_type");
        let volatility_char: String = row.get("volatility");
        let language: String = row.get("language");
        let security_definer: bool = row.get("security_definer");

        let volatility = match volatility_char.as_str() {
            "v" => crate::model::function::Volatility::Volatile,
            "s" => crate::model::function::Volatility::Stable,
            "i" => crate::model::function::Volatility::Immutable,
            _ => crate::model::function::Volatility::Volatile,
        };

        let security = if security_definer {
            crate::model::function::SecurityMode::Definer
        } else {
            crate::model::function::SecurityMode::Invoker
        };

        // Normalize argument types in sync just like in resolver
        let arg_types_str = arg_types_str
            .split(',')
            .map(crate::analysis::resolver::Resolver::normalize_function_arg_type)
            .collect::<Vec<_>>()
            .join(",");

        let id = ObjectId::new(&schema_name, format!("{}({})", func_name, arg_types_str));

        let arg_types = if arg_types_str.is_empty() {
            Vec::new()
        } else {
            arg_types_str.split(',').map(|s| s.to_string()).collect()
        };

        cache.functions.insert(
            id.clone(),
            crate::model::function::FunctionState {
                id,
                arg_types,
                arg_type_ids: Vec::new(),
                return_type: return_type.unwrap_or_default(),
                return_type_id: None,
                volatility,
                language,
                security,
            },
        );
    }

    // Query 8: User-defined types, including ordered enum labels and domains.
    let type_query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            t.typname AS type_name,
            t.typtype::text AS type_kind,
            CASE WHEN t.typtype = 'd'
                THEN pg_catalog.format_type(t.typbasetype, t.typtypmod)
                ELSE NULL
            END AS domain_base_type,
            COALESCE(
                array_agg(e.enumlabel ORDER BY e.enumsortorder)
                    FILTER (WHERE e.enumlabel IS NOT NULL),
                ARRAY[]::text[]
            ) AS enum_labels
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        LEFT JOIN pg_enum e ON e.enumtypid = t.oid
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND t.typtype IN ('e', 'd')
          {schema_filter}
        GROUP BY n.nspname, t.typname, t.typtype, t.typbasetype, t.typtypmod;
        "
    );

    for row in client.query(&type_query, &[&schema_values])? {
        let schema_name: String = row.get("schema_name");
        let type_name: String = row.get("type_name");
        let type_kind: String = row.get("type_kind");
        let domain_base_type: Option<String> = row.get("domain_base_type");
        let enum_labels: Vec<String> = row.get("enum_labels");
        let kind = match type_kind.as_str() {
            "e" => crate::model::types::TypeKind::Enum {
                variants: enum_labels,
            },
            "d" => crate::model::types::TypeKind::Domain {
                base_type: domain_base_type.unwrap_or_default(),
                base_type_id: None,
            },
            _ => continue,
        };
        let id = ObjectId::new(&schema_name, &type_name);
        cache.types.insert(
            id.clone(),
            crate::model::types::TypeState {
                id,
                generation: 0,
                kind,
            },
        );
    }

    // Query 9: Dependencies (pg_depend)
    let depend_query = r#"
        SELECT
            d.classid, d.objid, d.objsubid,
            d.refclassid, d.refobjid, d.refobjsubid,
            d.deptype::text,
            COALESCE(n1.nspname, n1p.nspname, n1t.nspname) AS obj_schema,
            COALESCE(c1.relname, p1.proname, t1.typname) AS obj_name,
            COALESCE(n2.nspname, n2p.nspname, n2t.nspname) AS ref_schema,
            COALESCE(c2.relname, p2.proname, t2.typname) AS ref_name
        FROM pg_depend d
        LEFT JOIN pg_class c1 ON c1.oid = d.objid AND d.classid = 'pg_class'::regclass
        LEFT JOIN pg_namespace n1 ON n1.oid = c1.relnamespace
        LEFT JOIN pg_proc p1 ON p1.oid = d.objid AND d.classid = 'pg_proc'::regclass
        LEFT JOIN pg_namespace n1p ON n1p.oid = p1.pronamespace
        LEFT JOIN pg_type t1 ON t1.oid = d.objid AND d.classid = 'pg_type'::regclass
        LEFT JOIN pg_namespace n1t ON n1t.oid = t1.typnamespace
        LEFT JOIN pg_class c2 ON c2.oid = d.refobjid AND d.refclassid = 'pg_class'::regclass
        LEFT JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
        LEFT JOIN pg_proc p2 ON p2.oid = d.refobjid AND d.refclassid = 'pg_proc'::regclass
        LEFT JOIN pg_namespace n2p ON n2p.oid = p2.pronamespace
        LEFT JOIN pg_type t2 ON t2.oid = d.refobjid AND d.refclassid = 'pg_type'::regclass
        LEFT JOIN pg_namespace n2t ON n2t.oid = t2.typnamespace
        WHERE d.deptype IN ('n', 'a', 'i')
          AND COALESCE(n1.nspname, n1p.nspname, n1t.nspname) IS NOT NULL
          AND COALESCE(n1.nspname, n1p.nspname, n1t.nspname)
              NOT IN ('pg_catalog', 'information_schema')
          AND (
              $1::text[] IS NULL
              OR COALESCE(n1.nspname, n1p.nspname, n1t.nspname) = ANY($1)
          )
    "#;

    for row in client.query(depend_query, &[&schema_values])? {
        let classid: u32 = row.get(0);
        let objid: u32 = row.get(1);
        let objsubid: i32 = row.get(2);
        let refclassid: u32 = row.get(3);
        let refobjid: u32 = row.get(4);
        let refobjsubid: i32 = row.get(5);
        let deptype: String = row.get(6);
        let obj_schema: Option<String> = row.get(7);
        let obj_name: Option<String> = row.get(8);
        let ref_schema: Option<String> = row.get(9);
        let ref_name: Option<String> = row.get(10);

        cache.dependencies.push(crate::db::cache::DependencyCache {
            classid,
            objid,
            objsubid,
            refclassid,
            refobjid,
            refobjsubid,
            deptype,
            obj_schema,
            obj_name,
            ref_schema,
            ref_name,
        });
    }

    // View dependencies are owned by pg_rewrite entries, so the generic pg_depend
    // query above cannot recover the dependent view's schema-qualified identity.
    let view_depend_query = r#"
        SELECT DISTINCT
            'pg_class'::regclass::oid AS classid,
            vc.oid AS objid,
            0 AS objsubid,
            'pg_class'::regclass::oid AS refclassid,
            tc.oid AS refobjid,
            0 AS refobjsubid,
            vn.nspname AS obj_schema,
            vc.relname AS obj_name,
            tn.nspname AS ref_schema,
            tc.relname AS ref_name
        FROM pg_rewrite rw
        JOIN pg_class vc ON vc.oid = rw.ev_class
        JOIN pg_namespace vn ON vn.oid = vc.relnamespace
        JOIN pg_depend d ON d.objid = rw.oid
        JOIN pg_class tc ON tc.oid = d.refobjid
        JOIN pg_namespace tn ON tn.oid = tc.relnamespace
        WHERE vc.relkind IN ('v', 'm')
          AND d.deptype = 'n'
          -- PostgreSQL 14/15 expose an internal rewrite-rule self-edge. It is
          -- not a dependency of the view definition and must not enter the
          -- modeled dependency graph.
          AND tc.oid <> vc.oid
          AND (
              $1::text[] IS NULL
              OR (vn.nspname = ANY($1) AND tn.nspname = ANY($1))
          )
    "#;

    for row in client.query(view_depend_query, &[&schema_values])? {
        cache.dependencies.push(crate::db::cache::DependencyCache {
            classid: row.get(0),
            objid: row.get(1),
            objsubid: row.get(2),
            refclassid: row.get(3),
            refobjid: row.get(4),
            refobjsubid: row.get(5),
            deptype: "view".to_string(),
            obj_schema: Some(row.get(6)),
            obj_name: Some(row.get(7)),
            ref_schema: Some(row.get(8)),
            ref_name: Some(row.get(9)),
        });
    }

    // Role identity and membership are required to distinguish a valid
    // `SET ROLE` from a migration that PostgreSQL would reject. pg_roles does
    // not expose password hashes or other credentials.
    for row in client.query(
        "SELECT rolname, rolcanlogin, rolsuper FROM pg_roles ORDER BY rolname;",
        &[],
    )? {
        let name: String = row.get(0);
        let id = ObjectId::new("", &name);
        cache.roles.insert(
            id.clone(),
            crate::model::role::RoleState {
                id,
                can_login: row.get(1),
                is_superuser: row.get(2),
                member_of: Vec::new(),
                can_set_role_to: Vec::new(),
                granted_privileges: Vec::new(),
            },
        );
    }

    let membership_query = if cache.pg_version_num.unwrap_or_default() >= 160_000 {
        "SELECT member.rolname, parent.rolname, membership.set_option
         FROM pg_auth_members membership
         JOIN pg_roles member ON member.oid = membership.member
         JOIN pg_roles parent ON parent.oid = membership.roleid;"
    } else {
        "SELECT member.rolname, parent.rolname, true AS set_option
         FROM pg_auth_members membership
         JOIN pg_roles member ON member.oid = membership.member
         JOIN pg_roles parent ON parent.oid = membership.roleid;"
    };
    for row in client.query(membership_query, &[])? {
        let member = ObjectId::new("", row.get::<_, String>(0));
        let parent = ObjectId::new("", row.get::<_, String>(1));
        let set_option: bool = row.get(2);
        if let Some(role) = cache.roles.get_mut(&member) {
            role.member_of.push(parent.clone());
            if set_option {
                role.can_set_role_to.push(parent);
            }
        }
    }

    Ok(cache)
}

#[cfg(test)]
mod atomic_write_tests {
    use super::*;
    use crate::db::cache::DbCacheVersioned;
    use std::fs;
    use std::io::Read;

    #[test]
    fn production_cache_writer_atomically_replaces_and_decodes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("baseline.cache");
        fs::write(&cache_path, b"old-cache").unwrap();

        let mut cache = DbCache::new();
        cache.pg_version_num = Some(180002);
        write_cache(&cache_path, cache, false).unwrap();

        let encoded = fs::read(&cache_path).unwrap();
        assert_ne!(encoded, b"old-cache");
        let reader = std::io::Cursor::new(encoded);
        let mut decoder = zstd::stream::Decoder::new(reader).unwrap();
        let mut payload = Vec::new();
        decoder.read_to_end(&mut payload).unwrap();
        let payload = payload
            .strip_prefix(CACHE_V6_MAGIC)
            .expect("writer must prefix V6 cache payloads");
        let config = bincode::config::standard().with_variable_int_encoding();
        let versioned: DbCacheVersioned = bincode::serde::decode_from_slice(payload, config)
            .unwrap()
            .0;
        assert_eq!(versioned.into_cache().unwrap().pg_version_num, Some(180002));
        assert_eq!(fs::read_dir(temp_dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn production_cache_writer_preserves_old_bytes_after_pre_install_failure() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("baseline.cache");
        fs::write(&cache_path, b"known-good-cache").unwrap();

        let error = write_cache_with_protection(&cache_path, DbCache::new(), |_| {
            Err(anyhow::anyhow!("injected payload-protection failure"))
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("injected payload-protection failure")
        );
        assert_eq!(fs::read(&cache_path).unwrap(), b"known-good-cache");
        assert_eq!(fs::read_dir(temp_dir.path()).unwrap().count(), 1);
    }
}
