use crate::ast::identifiers::ObjectId;
use crate::db::cache::{
    CACHE_V7_MAGIC, CatalogCoverage, ConstraintDependencyCache, ConstraintKeyCache, DbCache,
    DbCacheVersioned, DefaultSequenceDependencyCache, ForeignKeyCache,
    GeneratedColumnDependencyCache, IndexCache, InheritanceCache, ViewDependencyCache,
};
use crate::db::cache_file::{
    MAX_CACHE_DECODE_BYTES, MAX_CACHE_FILE_BYTES, protect_cache_bytes,
    validate_cache_encryption_configuration,
};
use crate::model::relation::{Persistence, RelationKind, RelationState};
use anyhow::{Context, Result};
use postgres::config::Host;
use postgres::{Client, Config as PostgresConfig, GenericClient, IsolationLevel, NoTls};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

#[cfg(windows)]
use std::fs;

const MIN_POSTGRES_VERSION_NUM: u32 = 140_000;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub fn sync_cache(
    out_path: &Path,
    schemas: Option<&[String]>,
    cache_encryption: bool,
) -> Result<()> {
    validate_cache_encryption_configuration(cache_encryption)
        .context("Invalid cache encryption configuration")?;
    // Strict env-only credential enforcement
    let db_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL environment variable is required to sync PostgreSQL schema metadata and statistics. Do not pass credentials via CLI flags or config files.")?;
    if db_url.trim().is_empty() {
        anyhow::bail!("DATABASE_URL must not be empty or whitespace");
    }

    let mut client = connect_database(&db_url)?;

    let cache = populate_cache(&mut client, schemas)?;

    write_cache(out_path, cache, cache_encryption)
}

fn connect_database(db_url: &str) -> Result<Client> {
    let mut config: PostgresConfig = db_url
        .parse()
        .context("DATABASE_URL is not a valid PostgreSQL connection string")?;

    if !database_config_is_local(&config) {
        anyhow::bail!(
            "Remote DATABASE_URL connections are not supported by this build. Use an SSH tunnel and connect through localhost or a Unix socket."
        );
    }

    apply_connection_safety_defaults(&mut config);

    config
        .connect(NoTls)
        .context("Failed to connect to PostgreSQL")
}

fn apply_connection_safety_defaults(config: &mut PostgresConfig) {
    if config.get_connect_timeout().is_none() {
        config.connect_timeout(DEFAULT_CONNECT_TIMEOUT);
    }
}

pub(crate) fn database_config_is_local(config: &PostgresConfig) -> bool {
    config
        .get_hostaddrs()
        .iter()
        .all(|address| address.is_loopback())
        && config.get_hosts().iter().all(|host| match host {
            #[cfg(unix)]
            Host::Unix(_) => true,
            Host::Tcp(name) => is_local_host(name),
        })
}

pub(crate) fn ensure_supported_postgres_version(version: u32) -> Result<()> {
    if version < MIN_POSTGRES_VERSION_NUM {
        anyhow::bail!(
            "PostgreSQL {} is unsupported; safe-migrate sync requires PostgreSQL 14 or newer",
            version / 10_000
        );
    }
    Ok(())
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

fn sequence_kind_from_pg(
    dependency_type: Option<&str>,
    has_nextval_default: bool,
) -> Result<crate::model::sequence::SequenceKind> {
    match dependency_type {
        Some("i") => Ok(crate::model::sequence::SequenceKind::Identity),
        Some("a") if has_nextval_default => Ok(crate::model::sequence::SequenceKind::SerialLike),
        Some("a") => Ok(crate::model::sequence::SequenceKind::Owned),
        None => Ok(crate::model::sequence::SequenceKind::Standalone),
        Some(other) => anyhow::bail!("unsupported pg_depend type '{other}'"),
    }
}

fn relation_kind_from_pg(code: u8) -> Result<RelationKind> {
    match code {
        b'r' | b'p' => Ok(RelationKind::Table),
        b'v' => Ok(RelationKind::View),
        b'm' => Ok(RelationKind::MaterializedView),
        other => anyhow::bail!("unsupported pg_class.relkind byte {other}"),
    }
}

fn persistence_from_pg(code: u8) -> Result<Persistence> {
    match code {
        b'p' => Ok(Persistence::Permanent),
        b't' => Ok(Persistence::Temporary),
        b'u' => Ok(Persistence::Unlogged),
        other => anyhow::bail!("unsupported pg_class.relpersistence byte {other}"),
    }
}

fn partition_strategy_from_pg(code: Option<&str>) -> Result<Option<String>> {
    match code {
        None => Ok(None),
        Some("r") => Ok(Some("RANGE".to_string())),
        Some("l") => Ok(Some("LIST".to_string())),
        Some("h") => Ok(Some("HASH".to_string())),
        Some(other) => anyhow::bail!("unsupported partition strategy '{other}'"),
    }
}

fn routine_volatility_from_pg(code: &str) -> Result<crate::model::function::Volatility> {
    match code {
        "v" => Ok(crate::model::function::Volatility::Volatile),
        "s" => Ok(crate::model::function::Volatility::Stable),
        "i" => Ok(crate::model::function::Volatility::Immutable),
        other => anyhow::bail!("unknown pg_proc.provolatile value '{other}'"),
    }
}

fn routine_kind_from_pg(code: &str) -> Result<crate::model::function::RoutineKind> {
    match code {
        "f" => Ok(crate::model::function::RoutineKind::Function),
        "p" => Ok(crate::model::function::RoutineKind::Procedure),
        "a" => Ok(crate::model::function::RoutineKind::Aggregate),
        "w" => Ok(crate::model::function::RoutineKind::Window),
        other => anyhow::bail!("unknown pg_proc.prokind value '{other}'"),
    }
}

fn subscription_streaming_from_pg(code: &str) -> Result<&'static str> {
    match code {
        "t" | "true" => Ok("true"),
        "f" | "false" => Ok("false"),
        "p" => Ok("parallel"),
        other => anyhow::bail!("unknown subscription streaming mode '{other}'"),
    }
}

fn subscription_two_phase_from_pg(code: &str) -> Result<&'static str> {
    match code {
        "d" => Ok("false"),
        "e" => Ok("true"),
        "p" => Ok("pending"),
        other => anyhow::bail!("unknown subscription two-phase state '{other}'"),
    }
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
    write_cache_with_protection_and_limits(
        out_path,
        cache,
        protect,
        MAX_CACHE_FILE_BYTES,
        MAX_CACHE_DECODE_BYTES,
    )
}

fn write_cache_with_protection_and_limits(
    out_path: &Path,
    cache: DbCache,
    protect: impl FnOnce(Vec<u8>) -> Result<Vec<u8>>,
    max_file_bytes: u64,
    max_decode_bytes: usize,
) -> Result<()> {
    cache
        .validate_semantics()
        .map_err(anyhow::Error::msg)
        .context("Refusing to write a semantically invalid Cache V7 baseline")?;
    let parent = cache_parent(out_path);
    let mut temp_file = NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "Failed to create temporary cache file beside {}",
            out_path.display()
        )
    })?;
    let mut compressed = Vec::new();
    let encoder = zstd::stream::Encoder::new(&mut compressed, 3)
        .context("Failed to init zstd compression")?;
    let mut encoder = SizeLimitedWriter::new(encoder, max_decode_bytes);

    if let Err(error) = encoder.write_all(CACHE_V7_MAGIC) {
        if encoder.limit_exceeded() {
            anyhow::bail!(
                "Cache payload exceeds the {} MiB decoded-size limit",
                max_decode_bytes / (1024 * 1024)
            );
        }
        return Err(error).context("Failed to write cache V7 payload header");
    }

    let versioned = DbCacheVersioned::V7(Box::new(cache));
    let bincode_config = bincode::config::standard().with_variable_int_encoding();

    let encode_result =
        bincode::serde::encode_into_std_write(&versioned, &mut encoder, bincode_config);
    if encoder.limit_exceeded() {
        anyhow::bail!(
            "Cache payload exceeds the {} MiB decoded-size limit",
            max_decode_bytes / (1024 * 1024)
        );
    }
    encode_result.context("Failed bincode schema compilation and write")?;

    let encoder = encoder.into_inner();
    encoder
        .finish()
        .context("Failed to flush final zstd stream to disk")?;

    let cache_bytes = protect(compressed)?;
    let cache_file_bytes = u64::try_from(cache_bytes.len()).unwrap_or(u64::MAX);
    if cache_file_bytes > max_file_bytes {
        anyhow::bail!(
            "Cache payload exceeds the {} MiB encoded-size limit",
            max_file_bytes / (1024 * 1024)
        );
    }
    temp_file
        .write_all(&cache_bytes)
        .context("Failed to write cache payload")?;
    temp_file.flush().context("Failed to flush cache payload")?;
    temp_file
        .as_file()
        .sync_all()
        .context("Failed to synchronize cache payload before installation")?;

    replace_cache(temp_file, out_path)?;

    Ok(())
}

fn cache_parent(out_path: &Path) -> &Path {
    out_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

// This bounds decoded bytes entering zstd, not the compressed output size.
struct SizeLimitedWriter<W> {
    inner: W,
    bytes_written: usize,
    max_bytes: usize,
    limit_exceeded: bool,
}

impl<W> SizeLimitedWriter<W> {
    fn new(inner: W, max_bytes: usize) -> Self {
        Self {
            inner,
            bytes_written: 0,
            max_bytes,
            limit_exceeded: false,
        }
    }

    fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for SizeLimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.max_bytes.saturating_sub(self.bytes_written) {
            self.limit_exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache decoded-size limit exceeded",
            ));
        }

        let written = self.inner.write(bytes)?;
        self.bytes_written = self.bytes_written.saturating_add(written);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
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
    let parent = cache_parent(out_path);
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| {
            format!(
                "Installed cache but failed to synchronize its parent directory: {}",
                parent.display()
            )
        })?;
    Ok(())
}

#[cfg(windows)]
fn replace_cache(temp_file: NamedTempFile, out_path: &Path) -> Result<()> {
    let backup = out_path.with_extension("safe-migrate.backup");
    if backup.exists() {
        if out_path.exists() {
            fs::remove_file(&backup).with_context(|| {
                format!(
                    "Failed to remove stale cache backup before replacement: {}",
                    backup.display()
                )
            })?;
        } else {
            fs::rename(&backup, out_path).with_context(|| {
                format!(
                    "Failed to restore interrupted cache replacement from backup: {}",
                    backup.display()
                )
            })?;
        }
    }

    if !out_path.exists() {
        temp_file
            .persist(out_path)
            .map_err(|error| error.error)
            .with_context(|| format!("Failed to install cache file: {}", out_path.display()))?;
        return Ok(());
    }

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
pub fn populate_cache_in_current_transaction(
    client: &mut Client,
    schemas: Option<&[String]>,
) -> Result<DbCache> {
    populate_cache_from_client(client, schemas)
}

fn load_view_dependencies(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
) -> Result<Vec<ViewDependencyCache>> {
    let query = r#"
        SELECT DISTINCT
            vn.nspname AS obj_schema,
            vc.relname AS obj_name,
            tn.nspname AS ref_schema,
            tc.relname AS ref_name,
            a.attname AS ref_column
        FROM pg_rewrite rw
        JOIN pg_class vc ON vc.oid = rw.ev_class
        JOIN pg_namespace vn ON vn.oid = vc.relnamespace
        JOIN pg_depend d ON d.objid = rw.oid
        JOIN pg_class tc ON tc.oid = d.refobjid
        JOIN pg_namespace tn ON tn.oid = tc.relnamespace
        LEFT JOIN pg_attribute a
          ON a.attrelid = tc.oid
         AND a.attnum = d.refobjsubid
         AND NOT a.attisdropped
            WHERE vc.relkind IN ('v', 'm')
              AND d.classid = 'pg_rewrite'::regclass
              AND d.refclassid = 'pg_class'::regclass
              AND d.deptype = 'n'
              AND tc.oid <> vc.oid
              AND tc.relkind IN ('r', 'p', 'v', 'm')
              AND vn.nspname NOT LIKE 'pg\_%' ESCAPE '\'
              AND vn.nspname <> 'information_schema'
              AND tn.nspname NOT LIKE 'pg\_%' ESCAPE '\'
              AND tn.nspname <> 'information_schema'
              AND (
              $1::text[] IS NULL
              OR vn.nspname = ANY($1)
              OR tn.nspname = ANY($1)
          )
    "#;

    let rows = client
        .query(query, &[schema_values])
        .context("Failed to load view dependencies from pg_rewrite/pg_depend")?;
    rows.into_iter()
        .map(|row| {
            Ok(ViewDependencyCache {
                dependent: ObjectId::new(
                    row.try_get::<_, String>("obj_schema")
                        .context("view dependency schema")?,
                    row.try_get::<_, String>("obj_name")
                        .context("view dependency name")?,
                ),
                referenced: ObjectId::new(
                    row.try_get::<_, String>("ref_schema")
                        .context("view dependency referenced schema")?,
                    row.try_get::<_, String>("ref_name")
                        .context("view dependency referenced name")?,
                ),
                referenced_column: row
                    .try_get("ref_column")
                    .context("view dependency referenced column")?,
            })
        })
        .collect()
}

fn load_roles(
    client: &mut impl GenericClient,
    pg_version_num: u32,
) -> Result<std::collections::HashMap<ObjectId, crate::model::role::RoleState>> {
    let mut roles = std::collections::HashMap::new();
    let rows = client
        .query(
            "SELECT rolname, rolcanlogin, rolsuper FROM pg_roles ORDER BY rolname;",
            &[],
        )
        .context("Failed to load role identities from pg_roles")?;
    for row in rows {
        let name: String = row.try_get(0).context("role name")?;
        let id = ObjectId::new("", &name);
        roles.insert(
            id.clone(),
            crate::model::role::RoleState {
                id,
                can_login: row.try_get(1).context("role login capability")?,
                is_superuser: row.try_get(2).context("role superuser capability")?,
                member_of: Vec::new(),
                can_set_role_to: Vec::new(),
                granted_privileges: Vec::new(),
            },
        );
    }

    let membership_query = if pg_version_num >= 160_000 {
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
    let memberships = client
        .query(membership_query, &[])
        .context("Failed to load role memberships from pg_auth_members")?;
    for row in memberships {
        let member = ObjectId::new("", row.try_get::<_, String>(0).context("member role")?);
        let parent = ObjectId::new("", row.try_get::<_, String>(1).context("parent role")?);
        let set_option: bool = row.try_get(2).context("role membership SET option")?;
        if let Some(role) = roles.get_mut(&member) {
            role.member_of.push(parent.clone());
            if set_option {
                role.can_set_role_to.push(parent);
            }
        }
    }
    Ok(roles)
}

struct ProvenanceCatalog {
    pg_version_num: u32,
    metadata: crate::db::cache::CacheMetadata,
    search_path: Vec<String>,
}

fn load_provenance(
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

    let row = client
        .query_one(
            "SELECT current_database(), current_user, session_user, current_setting('search_path'),
                    (SELECT setting::bigint FROM pg_settings WHERE name = 'lock_timeout'),
                    (SELECT setting::bigint FROM pg_settings WHERE name = 'statement_timeout');",
            &[],
        )
        .context("Failed to load synchronization provenance and timeout settings")?;
    let search_path_setting: String = row
        .try_get(3)
        .context("synchronization provenance search_path")?;
    let lock_timeout_ms = row
        .try_get::<_, Option<i64>>(4)
        .context("synchronization provenance lock_timeout field")?
        .context("PostgreSQL did not report lock_timeout")?;
    let statement_timeout_ms = row
        .try_get::<_, Option<i64>>(5)
        .context("synchronization provenance statement_timeout field")?
        .context("PostgreSQL did not report statement_timeout")?;

    let search_path_row = client
        .query_one("SELECT current_schemas(false);", &[])
        .context("Failed to load the effective PostgreSQL search path")?;
    let effective_search_path = search_path_row
        .try_get(0)
        .context("effective PostgreSQL search path field")?;

    Ok(ProvenanceCatalog {
        pg_version_num,
        metadata: crate::db::cache::CacheMetadata {
            created_at_unix_secs: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
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

fn load_schemas(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter: &str,
) -> Result<std::collections::HashMap<String, crate::model::schema::SchemaState>> {
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
                crate::model::schema::SchemaState {
                    name,
                    owner: relation_owner_id(owner),
                    generation: 0,
                },
            ))
        })
        .collect()
}

fn load_sequences(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
) -> Result<std::collections::HashMap<ObjectId, crate::model::sequence::SequenceState>> {
    // Keep a sequence when either side of OWNED BY is in the requested
    // scope. A sequence can live in a different schema from its owning
    // table, and dropping it without that edge would make a later migration
    // look exact while missing PostgreSQL's ownership dependency.
    let schema_filter = "AND ($1::text[] IS NULL OR n.nspname = ANY($1) OR tn.nspname = ANY($1))";
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
    let rows = client
        .query(&query, &[schema_values])
        .context("Failed to load sequences and ownership from pg_class/pg_depend")?;
    rows.into_iter()
        .map(|row| {
            let id = ObjectId::new(
                row.try_get::<_, String>(0).context("sequence schema")?,
                row.try_get::<_, String>(1).context("sequence name")?,
            );
            let owner = relation_owner_id(row.try_get::<_, String>(2).context("sequence owner")?);
            let table_schema: Option<String> =
                row.try_get(3).context("sequence owner table schema")?;
            let table_name: Option<String> = row.try_get(4).context("sequence owner table name")?;
            let column_name: Option<String> =
                row.try_get(5).context("sequence owner column name")?;
            let dependency_type: Option<String> =
                row.try_get(6).context("sequence dependency type")?;
            let has_nextval_default: bool =
                row.try_get(7).context("sequence-backed default marker")?;
            let owned_by = table_schema
                .zip(table_name)
                .zip(column_name)
                .map(|((schema, table), column)| (ObjectId::new(schema, table), column));
            let kind = sequence_kind_from_pg(dependency_type.as_deref(), has_nextval_default)
                .with_context(|| format!("sequence '{}' dependency kind", id))?;
            Ok((
                id.clone(),
                crate::model::sequence::SequenceState {
                    id,
                    owner,
                    owned_by,
                    kind,
                    generation: 0,
                },
            ))
        })
        .collect()
}

fn load_relations_and_columns(
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
    let rows = client
        .query(&relation_query, &[schema_values])
        .context("Failed to load relations and statistics from pg_class")?;
    let mut relations = std::collections::HashMap::new();
    for row in rows {
        let schema_name: String = row.try_get("schema_name").context("relation schema")?;
        let relation_name: String = row.try_get("relation_name").context("relation name")?;
        let relkind: i8 = row.try_get("relation_kind").context("relation kind")?;
        let persistence_char: i8 = row.try_get("persistence").context("relation persistence")?;
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
        state.relpages = Some(
            relpages
                .try_into()
                .with_context(|| format!("relation '{}' has a negative page count", object_id))?,
        );
        state.last_analyze = last_analyze;
        state.last_autoanalyze = last_autoanalyze;
        let partition_strategy: Option<String> = row
            .try_get("partition_strategy")
            .context("relation partition strategy")?;
        state.partition_type = partition_strategy_from_pg(partition_strategy.as_deref())
            .with_context(|| format!("relation '{}' partition strategy", object_id))?;
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
        relation.columns.push(crate::model::column::Column {
            name: row.try_get("column_name").context("column name")?,
            data_type: Some(row.try_get("type_name").context("column type")?),
            type_id: None,
            is_nullable: !row
                .try_get::<_, bool>("not_null")
                .context("column nullability")?,
            default: None,
            avg_width: row.try_get("avg_width").context("column average width")?,
            default_expr_text: row
                .try_get("default_expr_text")
                .context("column default expression")?,
            type_modifier: row
                .try_get("type_modifier")
                .context("column type modifier")?,
        });
    }
    Ok(relations)
}

struct RelationDecoration {
    relation_id: ObjectId,
    triggers: Vec<String>,
    policies: Vec<String>,
}

struct RelationGrant {
    relation_id: ObjectId,
    grantee: ObjectId,
    privilege: crate::model::relation::Privilege,
}

fn load_relation_decorations(
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
            COALESCE(array_agg(DISTINCT p.polname) FILTER (WHERE p.polname IS NOT NULL), '{{}}') as policies
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_trigger t ON t.tgrelid = c.oid
        LEFT JOIN pg_policy p ON p.polrelid = c.oid
        WHERE c.relkind IN ('r', 'p', 'v', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        {schema_filter_with_fk}
        GROUP BY n.nspname, c.relname;
    "
    );
    let decorations = client
        .query(&topology_query, &[schema_values])
        .context("Failed to load relation triggers and policies")?
        .into_iter()
        .map(|row| {
            Ok(RelationDecoration {
                relation_id: ObjectId::new(
                    row.try_get::<_, String>("schema_name")
                        .context("decorated relation schema")?,
                    row.try_get::<_, String>("relation_name")
                        .context("decorated relation name")?,
                ),
                triggers: row.try_get("triggers").context("relation trigger names")?,
                policies: row.try_get("policies").context("relation policy names")?,
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
    let grants = client
        .query(&acl_query, &[schema_values])
        .context("Failed to load explicit relation privileges")?
        .into_iter()
        .map(|row| {
            let privilege_type: String = row
                .try_get("privilege_type")
                .context("relation privilege type")?;
            let privilege = match privilege_type.as_str() {
                "SELECT" => crate::model::relation::Privilege::Select,
                "INSERT" => crate::model::relation::Privilege::Insert,
                "UPDATE" => crate::model::relation::Privilege::Update,
                "DELETE" => crate::model::relation::Privilege::Delete,
                "TRUNCATE" => crate::model::relation::Privilege::Truncate,
                "REFERENCES" => crate::model::relation::Privilege::References,
                "TRIGGER" => crate::model::relation::Privilege::Trigger,
                "MAINTAIN" => crate::model::relation::Privilege::Maintain,
                other => anyhow::bail!("unsupported relation privilege type '{other}'"),
            };
            Ok(RelationGrant {
                relation_id: ObjectId::new(
                    row.try_get::<_, String>("schema_name")
                        .context("privileged relation schema")?,
                    row.try_get::<_, String>("relation_name")
                        .context("privileged relation name")?,
                ),
                grantee: ObjectId::new(
                    "",
                    row.try_get::<_, String>("grantee")
                        .context("relation privilege grantee")?,
                ),
                privilege,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((decorations, grants))
}

fn load_triggers(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<crate::db::cache::TriggerCache>> {
    let query = format!(
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
          AND c.relkind IN ('r', 'p', 'v', 'm')
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
            Ok(crate::db::cache::TriggerCache {
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
                enabled_mode: crate::model::trigger::TriggerEnableMode::from_pg_code(&enabled_mode)
                    .ok_or_else(|| {
                        anyhow::anyhow!("unknown pg_trigger.tgenabled value {enabled_mode}")
                    })?,
            })
        })
        .collect()
}

fn load_constraints(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<crate::model::constraint::ConstraintState>> {
    let query = format!(
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
          AND c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
        "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load table constraints from pg_constraint")?
        .into_iter()
        .map(|row| {
            let constraint_type: String =
                row.try_get("constraint_type").context("constraint type")?;
            let kind = match constraint_type.as_str() {
                "c" => crate::model::constraint::ConstraintKind::Check,
                "f" => crate::model::constraint::ConstraintKind::ForeignKey,
                "p" => crate::model::constraint::ConstraintKind::PrimaryKey,
                "u" => crate::model::constraint::ConstraintKind::Unique,
                "x" => crate::model::constraint::ConstraintKind::Exclusion,
                other => anyhow::bail!("unsupported pg_constraint.contype '{other}'"),
            };
            Ok(crate::model::constraint::ConstraintState {
                table_id: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("constraint table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("constraint table name")?,
                ),
                name: row.try_get("constraint_name").context("constraint name")?,
                kind,
                validated: row
                    .try_get("validated")
                    .context("constraint validation state")?,
            })
        })
        .collect()
}

fn load_constraint_keys(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<ConstraintKeyCache>> {
    let query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            con.conname AS constraint_name,
            (con.contype = 'p') AS is_primary,
            ARRAY(
                SELECT a.attname
                FROM unnest(con.conkey) WITH ORDINALITY AS key_column(attnum, ordinality)
                JOIN pg_attribute a
                  ON a.attrelid = con.conrelid
                 AND a.attnum = key_column.attnum
                 AND NOT a.attisdropped
                ORDER BY key_column.ordinality
            ) AS columns
        FROM pg_constraint con
        JOIN pg_class c ON c.oid = con.conrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE con.contype IN ('p', 'u')
          AND c.relkind IN ('r', 'p')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
    "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load primary and unique key columns from pg_constraint")?
        .into_iter()
        .map(|row| {
            Ok(ConstraintKeyCache {
                table_id: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("constraint-key table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("constraint-key table name")?,
                ),
                constraint_name: row
                    .try_get("constraint_name")
                    .context("constraint-key name")?,
                columns: row.try_get("columns").context("constraint-key columns")?,
                is_primary: row
                    .try_get("is_primary")
                    .context("constraint-key primary flag")?,
            })
        })
        .collect()
}

fn load_constraint_dependencies(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<ConstraintDependencyCache>> {
    let query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            con.conname AS constraint_name,
            ARRAY(
                SELECT DISTINCT a.attname
                FROM pg_depend d
                JOIN pg_attribute a
                  ON a.attrelid = d.refobjid
                 AND a.attnum = d.refobjsubid
                 AND NOT a.attisdropped
                WHERE d.classid = 'pg_constraint'::regclass
                  AND d.objid = con.oid
                  AND d.refclassid = 'pg_class'::regclass
                  AND d.refobjid = con.conrelid
                  AND d.refobjsubid > 0
                  AND d.deptype = 'n'
                ORDER BY a.attname
            ) AS dependency_columns
        FROM pg_constraint con
        JOIN pg_class c ON c.oid = con.conrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE con.contype IN ('c', 'x')
          AND c.relkind IN ('r', 'p')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
        "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load constraint expression dependencies")?
        .into_iter()
        .map(|row| {
            Ok(ConstraintDependencyCache {
                table_id: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("constraint dependency table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("constraint dependency table name")?,
                ),
                constraint_name: row
                    .try_get("constraint_name")
                    .context("constraint dependency name")?,
                columns: row
                    .try_get("dependency_columns")
                    .context("constraint dependency columns")?,
            })
        })
        .collect()
}

fn load_generated_column_dependencies(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<GeneratedColumnDependencyCache>> {
    let query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            a.attname AS column_name,
            source_a.attname AS depends_on_column
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        JOIN pg_depend d
          ON d.classid = 'pg_attrdef'::regclass
         AND d.objid = ad.oid
         AND d.refclassid = 'pg_class'::regclass
         AND d.refobjsubid > 0
         AND d.deptype = 'n'
        JOIN pg_attribute source_a
          ON source_a.attrelid = d.refobjid
         AND source_a.attnum = d.refobjsubid
         AND NOT source_a.attisdropped
        WHERE a.attnum > 0
          AND NOT a.attisdropped
          AND a.attgenerated = 's'
          AND c.relkind IN ('r', 'p')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk}
        ORDER BY n.nspname, c.relname, a.attname, source_a.attname;
        "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load generated-column dependencies")?
        .into_iter()
        .map(|row| {
            Ok(GeneratedColumnDependencyCache {
                table_id: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("generated dependency table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("generated dependency table name")?,
                ),
                column_name: row
                    .try_get("column_name")
                    .context("generated dependency column")?,
                depends_on_column: row
                    .try_get("depends_on_column")
                    .context("generated dependency source column")?,
            })
        })
        .collect()
}

fn load_default_sequence_dependencies(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<DefaultSequenceDependencyCache>> {
    let query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            a.attname AS column_name,
            seqn.nspname AS sequence_schema,
            seq.relname AS sequence_name
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        JOIN pg_depend d
          ON d.classid = 'pg_attrdef'::regclass
         AND d.objid = ad.oid
         AND d.refclassid = 'pg_class'::regclass
         AND d.refobjsubid = 0
         AND d.deptype = 'n'
        JOIN pg_class seq ON seq.oid = d.refobjid AND seq.relkind = 'S'
        JOIN pg_namespace seqn ON seqn.oid = seq.relnamespace
        WHERE a.attnum > 0
          AND NOT a.attisdropped
          AND a.attgenerated = ''
          AND c.relkind IN ('r', 'p')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk}
        ORDER BY n.nspname, c.relname, a.attname, seqn.nspname, seq.relname;
        "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load default sequence dependencies")?
        .into_iter()
        .map(|row| {
            Ok(DefaultSequenceDependencyCache {
                table_id: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("default dependency table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("default dependency table name")?,
                ),
                column_name: row
                    .try_get("column_name")
                    .context("default dependency column")?,
                sequence_id: ObjectId::new(
                    row.try_get::<_, String>("sequence_schema")
                        .context("default dependency sequence schema")?,
                    row.try_get::<_, String>("sequence_name")
                        .context("default dependency sequence name")?,
                ),
            })
        })
        .collect()
}

fn load_foreign_keys(
    client: &mut impl GenericClient,
    schemas: Option<&[String]>,
    schema_values: &Option<Vec<String>>,
    schema_filter_n1_or_n2: &str,
) -> Result<Vec<ForeignKeyCache>> {
    let query = format!(
        "
        SELECT
            c.conname AS constraint_name,
            n1.nspname AS from_schema, t1.relname AS from_table,
            n2.nspname AS to_schema, t2.relname AS to_table,
            ARRAY(
                SELECT a.attname
                FROM unnest(c.conkey) WITH ORDINALITY AS source_key(attnum, ordinality)
                JOIN pg_attribute a
                  ON a.attrelid = c.conrelid
                 AND a.attnum = source_key.attnum
                 AND NOT a.attisdropped
                ORDER BY source_key.ordinality
            ) AS from_columns,
            ARRAY(
                SELECT a.attname
                FROM unnest(c.confkey) WITH ORDINALITY AS target_key(attnum, ordinality)
                JOIN pg_attribute a
                  ON a.attrelid = c.confrelid
                 AND a.attnum = target_key.attnum
                 AND NOT a.attisdropped
                ORDER BY target_key.ordinality
            ) AS to_columns
        FROM pg_constraint c
        JOIN pg_class t1 ON t1.oid = c.conrelid
        JOIN pg_namespace n1 ON n1.oid = t1.relnamespace
        JOIN pg_class t2 ON t2.oid = c.confrelid
        JOIN pg_namespace n2 ON n2.oid = t2.relnamespace
        WHERE c.contype = 'f'
        {schema_filter_n1_or_n2};
    "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load foreign keys from pg_constraint")?
        .into_iter()
        .map(|row| {
            let constraint_name: String = row
                .try_get("constraint_name")
                .context("foreign-key constraint name")?;
            let from_schema: String = row
                .try_get("from_schema")
                .context("foreign-key source schema")?;
            let from_table: String = row
                .try_get("from_table")
                .context("foreign-key source table")?;
            let to_schema: String = row
                .try_get("to_schema")
                .context("foreign-key target schema")?;
            let to_table: String = row
                .try_get("to_table")
                .context("foreign-key target table")?;
            let from_columns: Vec<String> = row
                .try_get("from_columns")
                .context("foreign-key source columns")?;
            let to_columns: Vec<String> = row
                .try_get("to_columns")
                .context("foreign-key target columns")?;
            if let Some(scoped_schemas) = schemas
                && (!scoped_schemas.contains(&from_schema)
                    || !scoped_schemas.contains(&to_schema))
            {
                let (out_of_scope_schema, out_of_scope_table) =
                    if !scoped_schemas.contains(&from_schema) {
                        (&from_schema, &from_table)
                    } else {
                        (&to_schema, &to_table)
                    };
                eprintln!(
                    "[WARN] Foreign key '{}' crosses schema boundary. Table '{}.{}' was pulled into cache as a dependency to evaluate cross-team locks.",
                    constraint_name, out_of_scope_schema, out_of_scope_table
                );
            }
            Ok(ForeignKeyCache {
                constraint_name,
                from_table: ObjectId::new(from_schema, from_table),
                to_table: ObjectId::new(to_schema, to_table),
                from_columns,
                to_columns,
            })
        })
        .collect()
}

fn load_inheritances(
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
        WHERE child.relkind IN ('r', 'p')
          AND parent.relkind IN ('r', 'p')
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

fn load_indexes(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_nt: &str,
) -> Result<Vec<IndexCache>> {
    let query = format!(
        "
        SELECT
            n_i.nspname AS index_schema, i.relname AS index_name,
            n_t.nspname AS table_schema, t.relname AS table_name,
            am.amname AS using_method,
            x.indisvalid AS is_valid,
            x.indisready AS is_ready,
            x.indislive AS is_live,
            x.indisunique AS is_unique,
            x.indpred IS NOT NULL AS has_predicate,
            ARRAY(
                SELECT a.attname
                FROM unnest(x.indkey::smallint[]) WITH ORDINALITY AS key_part(attnum, ordinality)
                JOIN pg_attribute a
                  ON a.attrelid = x.indrelid
                 AND a.attnum = key_part.attnum
                 AND NOT a.attisdropped
                WHERE key_part.ordinality <= x.indnkeyatts
                ORDER BY key_part.ordinality
            ) AS key_columns,
            ARRAY(
                SELECT a.attname
                FROM unnest(x.indkey::smallint[]) WITH ORDINALITY AS included_part(attnum, ordinality)
                JOIN pg_attribute a
                  ON a.attrelid = x.indrelid
                 AND a.attnum = included_part.attnum
                 AND NOT a.attisdropped
                WHERE included_part.ordinality > x.indnkeyatts
                ORDER BY included_part.ordinality
            ) AS included_columns,
            ARRAY(
                SELECT a.attname
                FROM pg_depend d
                JOIN pg_attribute a
                  ON a.attrelid = d.refobjid
                 AND a.attnum = d.refobjsubid
                 AND NOT a.attisdropped
                WHERE d.classid = 'pg_class'::regclass
                  AND d.objid = x.indexrelid
                  AND d.refclassid = 'pg_class'::regclass
                  AND d.refobjid = x.indrelid
                  AND d.refobjsubid > 0
                ORDER BY a.attnum
            ) AS dependency_columns,
            EXISTS (
                SELECT 1
                FROM unnest(x.indkey::smallint[]) WITH ORDINALITY AS key_part(attnum, ordinality)
                WHERE key_part.ordinality <= x.indnkeyatts
                  AND key_part.attnum = 0
            ) AS has_expression_keys,
            NOT EXISTS (
                SELECT 1
                FROM unnest(x.indoption::smallint[]) AS option_part(flags)
                WHERE option_part.flags <> 0
            ) AS has_default_sort_order,
            NOT EXISTS (
                SELECT 1
                FROM unnest(x.indclass::oid[]) WITH ORDINALITY AS opclass_part(opclass_oid, ordinality)
                JOIN pg_opclass opclass ON opclass.oid = opclass_part.opclass_oid
                WHERE opclass_part.ordinality <= x.indnkeyatts
                  AND (NOT opclass.opcdefault OR opclass.opcmethod <> i.relam)
            ) AS has_default_opclasses,
            NOT EXISTS (
                SELECT 1
                FROM unnest(x.indcollation::oid[]) WITH ORDINALITY AS collation_part(collation_oid, ordinality)
                JOIN unnest(x.indkey::smallint[]) WITH ORDINALITY AS key_part(attnum, key_ordinality)
                  ON key_part.key_ordinality = collation_part.ordinality
                JOIN pg_attribute a
                  ON a.attrelid = x.indrelid
                 AND a.attnum = key_part.attnum
                 AND NOT a.attisdropped
                WHERE collation_part.ordinality <= x.indnkeyatts
                  AND key_part.attnum <> 0
                  AND collation_part.collation_oid <> a.attcollation
            ) AS has_default_collations
        FROM pg_index x
        JOIN pg_class i ON i.oid = x.indexrelid
        JOIN pg_namespace n_i ON n_i.oid = i.relnamespace
        JOIN pg_class t ON t.oid = x.indrelid
        JOIN pg_namespace n_t ON n_t.oid = t.relnamespace
        JOIN pg_am am ON am.oid = i.relam
        WHERE n_i.nspname !~ '^pg_'
          AND n_i.nspname <> 'information_schema'
          AND n_t.nspname !~ '^pg_'
          AND n_t.nspname <> 'information_schema'
        {schema_filter_nt};
    "
    );
    let rows = client
        .query(&query, &[schema_values])
        .context("Failed to load index definitions from pg_index")?;
    let mut indexes = Vec::with_capacity(rows.len());
    for row in rows {
        let index_schema: String = row.try_get("index_schema").context("index schema")?;
        let table_schema: String = row
            .try_get("table_schema")
            .context("indexed table schema")?;
        if is_system_schema(&index_schema) || is_system_schema(&table_schema) {
            continue;
        }
        indexes.push(IndexCache {
            index_id: ObjectId::new(
                index_schema,
                row.try_get::<_, String>("index_name")
                    .context("index name")?,
            ),
            table_id: ObjectId::new(
                table_schema,
                row.try_get::<_, String>("table_name")
                    .context("indexed table name")?,
            ),
            using_method: row.try_get("using_method").context("index access method")?,
            key_columns: row.try_get("key_columns").context("index key columns")?,
            included_columns: row
                .try_get("included_columns")
                .context("index included columns")?,
            dependency_columns: row
                .try_get("dependency_columns")
                .context("index dependency columns")?,
            dependency_columns_known: true,
            has_expression_keys: row
                .try_get("has_expression_keys")
                .context("index expression key flag")?,
            has_predicate: row
                .try_get("has_predicate")
                .context("index predicate flag")?,
            is_unique: row.try_get("is_unique").context("index uniqueness flag")?,
            is_valid: row.try_get("is_valid").context("index validity flag")?,
            is_ready: row.try_get("is_ready").context("index readiness flag")?,
            is_live: row.try_get("is_live").context("index liveness flag")?,
            has_default_sort_order: row
                .try_get("has_default_sort_order")
                .context("index sort ordering")?,
            has_default_opclasses: row
                .try_get("has_default_opclasses")
                .context("index operator classes")?,
            has_default_collations: row
                .try_get("has_default_collations")
                .context("index collations")?,
        });
    }
    Ok(indexes)
}

fn load_routines(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter: &str,
) -> Result<std::collections::HashMap<ObjectId, crate::model::function::FunctionState>> {
    let query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            p.proname AS func_name,
            ARRAY(
                SELECT pg_catalog.format_type(t, NULL)
                FROM unnest(p.proargtypes::oid[]) WITH ORDINALITY AS u(t, n)
                ORDER BY n
            )::text[] AS arg_types,
            pg_catalog.pg_get_function_result(p.oid) AS return_type,
            p.provolatile::text AS volatility,
            p.prokind::text AS routine_kind,
            l.lanname AS language,
            p.prosecdef AS security_definer
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_language l ON l.oid = p.prolang
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND p.prokind IN ('f', 'p', 'a', 'w')
          {schema_filter};
    "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load routines from pg_proc")?
        .into_iter()
        .map(|row| {
            let schema_name: String = row.try_get("schema_name").context("routine schema")?;
            let function_name: String = row.try_get("func_name").context("routine name")?;
            let raw_arg_types: Vec<String> =
                row.try_get("arg_types").context("routine argument types")?;
            let volatility_code: String =
                row.try_get("volatility").context("routine volatility")?;
            let volatility = routine_volatility_from_pg(&volatility_code)?;
            let routine_kind_code: String = row.try_get("routine_kind").context("routine kind")?;
            let routine_kind = routine_kind_from_pg(&routine_kind_code)?;
            let arg_types = raw_arg_types
                .iter()
                .map(|arg_type| {
                    crate::analysis::resolver::Resolver::normalize_function_arg_type(arg_type)
                })
                .collect::<Vec<_>>();
            let id = ObjectId::new(
                schema_name,
                format!("{}({})", function_name, arg_types.join(",")),
            );
            let security_definer: bool = row
                .try_get("security_definer")
                .context("routine security mode")?;
            Ok((
                id.clone(),
                crate::model::function::FunctionState {
                    id,
                    routine_kind,
                    arg_types,
                    arg_type_ids: Vec::new(),
                    return_type: row
                        .try_get::<_, Option<String>>("return_type")
                        .context("routine return type")?
                        .unwrap_or_default(),
                    return_type_id: None,
                    volatility,
                    language: row.try_get("language").context("routine language")?,
                    security: if security_definer {
                        crate::model::function::SecurityMode::Definer
                    } else {
                        crate::model::function::SecurityMode::Invoker
                    },
                },
            ))
        })
        .collect()
}

fn load_types(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter: &str,
) -> Result<std::collections::HashMap<ObjectId, crate::model::types::TypeState>> {
    let query = format!(
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
    client
        .query(&query, &[schema_values])
        .context("Failed to load user-defined enum and domain types")?
        .into_iter()
        .map(|row| {
            let type_kind: String = row.try_get("type_kind").context("type kind")?;
            let kind = match type_kind.as_str() {
                "e" => crate::model::types::TypeKind::Enum {
                    variants: row.try_get("enum_labels").context("enum labels")?,
                },
                "d" => crate::model::types::TypeKind::Domain {
                    base_type: row
                        .try_get::<_, Option<String>>("domain_base_type")
                        .context("domain base type")?
                        .context("PostgreSQL omitted the base type for a domain")?,
                    base_type_id: None,
                },
                other => anyhow::bail!("unsupported pg_type.typtype '{other}'"),
            };
            let id = ObjectId::new(
                row.try_get::<_, String>("schema_name")
                    .context("type schema")?,
                row.try_get::<_, String>("type_name").context("type name")?,
            );
            Ok((
                id.clone(),
                crate::model::types::TypeState {
                    id,
                    generation: 0,
                    kind,
                },
            ))
        })
        .collect()
}

fn load_publications(
    client: &mut impl GenericClient,
    pg_version_num: u32,
) -> Result<std::collections::HashMap<String, crate::model::replication::PublicationState>> {
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
            crate::analysis::facts::AttributeFact {
                name: "publish".to_string(),
                value: operations.join(", "),
            },
            crate::analysis::facts::AttributeFact {
                name: "publish_via_partition_root".to_string(),
                value: row
                    .try_get::<_, bool>("pubviaroot")
                    .context("publication partition-root mode")?
                    .to_string(),
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
            params.push(crate::analysis::facts::AttributeFact {
                name: "publish_generated_columns".to_string(),
                value: value.to_string(),
            });
        }
        let scope = if row
            .try_get::<_, bool>("puballtables")
            .context("publication all-tables mode")?
        {
            crate::analysis::facts::PublicationScope::AllTables { except: Vec::new() }
        } else {
            crate::analysis::facts::PublicationScope::Explicit(Vec::new())
        };
        names_by_oid.insert(oid, name.clone());
        publications.insert(
            name.clone(),
            crate::model::replication::PublicationState {
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
        let crate::analysis::facts::PublicationScope::Explicit(objects) = &mut publication.scope
        else {
            continue;
        };
        objects.push(crate::analysis::facts::PublicationObjectFact::Table {
            name: crate::ast::identifiers::QualifiedName::new(
                Some(crate::ast::identifiers::Ident::new(
                    row.try_get::<_, String>("schema_name")
                        .context("publication relation schema")?,
                    true,
                )),
                crate::ast::identifiers::Ident::new(
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
                .map(crate::analysis::facts::PublicationRowFilter::CatalogSql),
        });
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
            let crate::analysis::facts::PublicationScope::Explicit(objects) =
                &mut publication.scope
            else {
                continue;
            };
            objects.push(
                crate::analysis::facts::PublicationObjectFact::SchemaTables {
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

fn load_subscriptions(
    client: &mut impl GenericClient,
    pg_version_num: u32,
) -> Result<std::collections::HashMap<String, crate::model::replication::SubscriptionState>> {
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
                crate::analysis::facts::AttributeFact {
                    name: "binary".to_string(),
                    value: row
                        .try_get::<_, bool>("subbinary")
                        .with_context(|| format!("subscription '{name}' binary mode"))?
                        .to_string(),
                },
                crate::analysis::facts::AttributeFact {
                    name: "streaming".to_string(),
                    value: streaming.to_string(),
                },
                crate::analysis::facts::AttributeFact {
                    name: "synchronous_commit".to_string(),
                    value: row
                        .try_get("subsynccommit")
                        .with_context(|| format!("subscription '{name}' synchronous_commit"))?,
                },
            ];
            let two_phase = row
                .try_get::<_, Option<String>>("two_phase_state")
                .with_context(|| format!("subscription '{name}' two-phase state"))?
                .map(|state| subscription_two_phase_from_pg(&state).map(str::to_string))
                .transpose()?;
            let mut push_param = |param_name: &str, value: Option<String>| {
                if let Some(value) = value {
                    params.push(crate::analysis::facts::AttributeFact {
                        name: param_name.to_string(),
                        value,
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
                crate::model::replication::SubscriptionState {
                    name,
                    owner: Some(row.try_get("owner_name").context("subscription owner")?),
                    connection: crate::analysis::facts::ConnectionTarget::Redacted,
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

fn populate_cache_from_client(
    client: &mut impl GenericClient,
    schemas: Option<&[String]>,
) -> Result<DbCache> {
    let mut cache = DbCache::new();
    let schema_values = schemas.map(|items| items.to_vec());
    let provenance = load_provenance(client, schemas)?;
    cache.pg_version_num = Some(provenance.pg_version_num);
    cache.metadata = provenance.metadata;
    cache.coverage = CatalogCoverage::from_sync_scope(schemas);
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
    // A scoped request can name schemas that do not exist yet. PostgreSQL's
    // effective search path skips those entries, so do not let them become
    // inferred-present namespaces when the cache is hydrated.
    cache
        .search_path
        .retain(|schema| cache.schemas.contains_key(schema));

    cache.sequences = load_sequences(client, &schema_values)?;

    cache.relations =
        load_relations_and_columns(client, schemas, &schema_values, schema_filter_with_fk)?;

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
        relation
            .privileges
            .grant(grant.grantee, [grant.privilege].into_iter().collect());
    }

    cache.triggers = load_triggers(client, &schema_values, schema_filter_with_fk)?;

    cache.constraints = load_constraints(client, &schema_values, schema_filter_with_fk)?;
    cache.constraint_keys = load_constraint_keys(client, &schema_values, schema_filter_with_fk)?;
    cache.constraint_dependencies =
        load_constraint_dependencies(client, &schema_values, schema_filter_with_fk)?;
    cache.generated_column_dependencies =
        load_generated_column_dependencies(client, &schema_values, schema_filter_with_fk)?;
    cache.default_sequence_dependencies =
        load_default_sequence_dependencies(client, &schema_values, schema_filter_with_fk)?;

    cache.foreign_keys =
        load_foreign_keys(client, schemas, &schema_values, schema_filter_n1_or_n2)?;

    cache.inheritances = load_inheritances(client, &schema_values)?;

    cache.indexes = load_indexes(client, &schema_values, schema_filter_nt)?;

    cache.functions = load_routines(client, &schema_values, schema_filter)?;

    cache.publications = load_publications(client, cache.pg_version_num.unwrap_or_default())?;

    cache.subscriptions = load_subscriptions(client, cache.pg_version_num.unwrap_or_default())?;

    cache.types = load_types(client, &schema_values, schema_filter)?;

    // Only view dependencies are consumed by cache hydration. Generic
    // pg_depend rows use PostgreSQL dependency codes (n/a/i) and were ignored
    // after synchronization, so avoid loading them into Cache V7.
    cache.dependencies = load_view_dependencies(client, &schema_values)?;

    // Role identity and membership are required to distinguish a valid
    // `SET ROLE` from a migration that PostgreSQL would reject. pg_roles does
    // not expose password hashes or other credentials.
    cache.roles = load_roles(client, cache.pg_version_num.unwrap_or_default())?;

    cache
        .validate_semantics()
        .map_err(anyhow::Error::msg)
        .context("PostgreSQL catalogs produced a semantically invalid Cache V7 baseline")?;
    Ok(cache)
}

#[cfg(test)]
mod catalog_conversion_tests {
    use super::*;

    #[test]
    fn known_catalog_codes_convert_without_fallbacks() {
        assert!(matches!(
            sequence_kind_from_pg(Some("i"), false).unwrap(),
            crate::model::sequence::SequenceKind::Identity
        ));
        assert!(matches!(
            sequence_kind_from_pg(Some("a"), true).unwrap(),
            crate::model::sequence::SequenceKind::SerialLike
        ));
        assert!(matches!(
            relation_kind_from_pg(b'm').unwrap(),
            RelationKind::MaterializedView
        ));
        assert!(matches!(
            persistence_from_pg(b'u').unwrap(),
            Persistence::Unlogged
        ));
        assert_eq!(
            partition_strategy_from_pg(Some("h")).unwrap(),
            Some("HASH".to_string())
        );
        assert!(matches!(
            routine_volatility_from_pg("i").unwrap(),
            crate::model::function::Volatility::Immutable
        ));
        assert!(matches!(
            routine_kind_from_pg("a").unwrap(),
            crate::model::function::RoutineKind::Aggregate
        ));
        assert_eq!(subscription_streaming_from_pg("p").unwrap(), "parallel");
        assert_eq!(subscription_two_phase_from_pg("e").unwrap(), "true");
    }

    #[test]
    fn unknown_catalog_codes_are_actionable_errors() {
        for error in [
            sequence_kind_from_pg(Some("x"), false).unwrap_err(),
            relation_kind_from_pg(b'x').unwrap_err(),
            persistence_from_pg(b'x').unwrap_err(),
            partition_strategy_from_pg(Some("x")).unwrap_err(),
            routine_volatility_from_pg("x").unwrap_err(),
            routine_kind_from_pg("x").unwrap_err(),
            subscription_streaming_from_pg("x").unwrap_err(),
            subscription_two_phase_from_pg("x").unwrap_err(),
        ] {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn connection_timeout_default_preserves_an_explicit_value() {
        let mut defaulted = PostgresConfig::new();
        apply_connection_safety_defaults(&mut defaulted);
        assert_eq!(
            defaulted.get_connect_timeout(),
            Some(&DEFAULT_CONNECT_TIMEOUT)
        );

        let explicit = Duration::from_secs(3);
        let mut configured = PostgresConfig::new();
        configured.connect_timeout(explicit);
        apply_connection_safety_defaults(&mut configured);
        assert_eq!(configured.get_connect_timeout(), Some(&explicit));
    }
}

#[cfg(test)]
mod atomic_write_tests {
    use super::*;
    use crate::db::cache::DbCacheVersioned;
    use std::fs;
    use std::io::Read;

    fn decode_written_cache(path: &Path) -> DbCache {
        let encoded = fs::read(path).unwrap();
        let reader = std::io::Cursor::new(encoded);
        let mut decoder = zstd::stream::Decoder::new(reader).unwrap();
        let mut payload = Vec::new();
        decoder.read_to_end(&mut payload).unwrap();
        let payload = payload
            .strip_prefix(CACHE_V7_MAGIC)
            .expect("writer must prefix V7 cache payloads");
        let config = bincode::config::standard().with_variable_int_encoding();
        let versioned: DbCacheVersioned = bincode::serde::decode_from_slice(payload, config)
            .unwrap()
            .0;
        versioned.into_cache().unwrap()
    }

    #[test]
    fn bare_cache_filenames_use_the_current_directory_as_parent() {
        assert_eq!(cache_parent(Path::new("baseline.cache")), Path::new("."));
        assert_eq!(
            cache_parent(Path::new("cache/baseline.cache")),
            Path::new("cache")
        );
    }

    #[test]
    fn production_cache_writer_atomically_replaces_and_decodes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("baseline.cache");
        fs::write(&cache_path, b"old-cache").unwrap();

        let mut cache = DbCache::new();
        cache.pg_version_num = Some(180002);
        write_cache(&cache_path, cache, false).unwrap();

        assert_eq!(
            decode_written_cache(&cache_path).pg_version_num,
            Some(180002)
        );
        assert_eq!(fs::read_dir(temp_dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_cache_writers_leave_one_complete_decodable_payload() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("baseline.cache");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut writers = Vec::new();
        for version in [170_007, 180_002] {
            let cache_path = cache_path.clone();
            let barrier = barrier.clone();
            writers.push(std::thread::spawn(move || {
                let mut cache = DbCache::new();
                cache.pg_version_num = Some(version);
                barrier.wait();
                write_cache(&cache_path, cache, false)
            }));
        }
        barrier.wait();
        let results = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect::<Vec<_>>();

        assert!(results.iter().any(Result::is_ok));
        assert!(matches!(
            decode_written_cache(&cache_path).pg_version_num,
            Some(170_007 | 180_002)
        ));
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

    #[test]
    fn cache_writer_rejects_oversized_decoded_payload_before_replacement() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("baseline.cache");
        fs::write(&cache_path, b"known-good-cache").unwrap();

        let error = write_cache_with_protection_and_limits(
            &cache_path,
            DbCache::new(),
            Ok,
            MAX_CACHE_FILE_BYTES,
            CACHE_V7_MAGIC.len(),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("decoded-size limit"));
        assert_eq!(fs::read(&cache_path).unwrap(), b"known-good-cache");
        assert_eq!(fs::read_dir(temp_dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn cache_writer_rejects_oversized_encoded_payload_before_replacement() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("baseline.cache");
        fs::write(&cache_path, b"known-good-cache").unwrap();
        let max_file_bytes = 16_u64;

        let error = write_cache_with_protection_and_limits(
            &cache_path,
            DbCache::new(),
            |_| Ok(vec![0; max_file_bytes as usize + 1]),
            max_file_bytes,
            MAX_CACHE_DECODE_BYTES,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("encoded-size limit"));
        assert_eq!(fs::read(&cache_path).unwrap(), b"known-good-cache");
        assert_eq!(fs::read_dir(temp_dir.path()).unwrap().count(), 1);
    }
}
