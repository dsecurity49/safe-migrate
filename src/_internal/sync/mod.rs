use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::db::cache::{
    CACHE_MAGIC, CatalogCoverageBuilder, CatalogFamily, ConstraintDependencyCache,
    ConstraintKeyCache, DbCache, DbCacheVersioned, DefaultSequenceDependencyCache, ForeignKeyCache,
    GeneratedColumnDependencyCache, IndexAttachmentCache, IndexCache, InheritanceCache,
    ScopedDependencyEdge, ViewDependencyCache, ViewDependencyTarget,
};
use crate::_internal::db::cache_file::{
    MAX_CACHE_DECODE_BYTES, MAX_CACHE_FILE_BYTES, protect_cache_bytes,
    protect_cache_bytes_with_key, validate_cache_encryption_configuration,
};
use crate::_internal::model::builtin_type::BuiltinTypeCatalogue;
use crate::_internal::model::index::{
    IndexDefinition, IndexKey, IndexKeyKind, IndexOrder, IndexPredicate, KeyCollation, KeyOpclass,
    ResolvedName,
};
use crate::_internal::model::relation::{Persistence, RelationKind, RelationState};
use anyhow::{Context, Result};
use postgres::config::Host;
use postgres::{Client, Config as PostgresConfig, GenericClient, IsolationLevel, NoTls};
use std::collections::HashSet;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

#[cfg(windows)]
use std::fs;

const MIN_POSTGRES_VERSION_NUM: u32 = 140_000;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn sync_cache(
    out_path: &Path,
    schemas: Option<&[String]>,
    cache_encryption: bool,
) -> Result<()> {
    validate_cache_encryption_configuration(cache_encryption)
        .context("Invalid cache encryption configuration")?;
    let db_url = Zeroizing::new(
        std::env::var("DATABASE_URL")
            .context("DATABASE_URL environment variable is required to sync PostgreSQL schema metadata and statistics. Do not pass credentials via CLI flags or config files.")?,
    );
    if db_url.trim().is_empty() {
        anyhow::bail!("DATABASE_URL must not be empty or whitespace");
    }

    sync_cache_with_database_url(out_path, schemas, cache_encryption, &db_url)
}

pub(crate) fn validate_database_url(db_url: &str) -> Result<()> {
    parse_database_config(db_url).map(|_| ())
}

pub(crate) fn sync_cache_with_database_url(
    out_path: &Path,
    schemas: Option<&[String]>,
    cache_encryption: bool,
    db_url: &str,
) -> Result<()> {
    validate_cache_encryption_configuration(cache_encryption)
        .context("Invalid cache encryption configuration")?;
    let mut client = connect_database(db_url)?;

    let cache = populate_cache(&mut client, schemas)?;

    write_cache(out_path, cache, cache_encryption)
}

pub(crate) fn sync_cache_with_secrets(
    out_path: &Path,
    schemas: Option<&[String]>,
    db_url: &str,
    cache_key: Option<&[u8; 32]>,
) -> Result<()> {
    let mut client = connect_database(db_url)?;
    let cache = populate_cache(&mut client, schemas)?;
    match cache_key {
        Some(key) => write_cache_with_key(out_path, cache, key),
        None => write_cache(out_path, cache, false),
    }
}

fn connect_database(db_url: &str) -> Result<Client> {
    let mut config = parse_database_config(db_url)?;

    apply_connection_safety_defaults(&mut config);

    config
        .connect(NoTls)
        .context("Failed to connect to PostgreSQL")
}

fn parse_database_config(db_url: &str) -> Result<PostgresConfig> {
    if db_url.trim().is_empty() {
        anyhow::bail!("PostgreSQL connection string must not be empty or whitespace");
    }
    let config: PostgresConfig = db_url
        .parse()
        .context("Invalid PostgreSQL connection string")?;

    if !database_config_is_local(&config) {
        anyhow::bail!(
            "Remote DATABASE_URL connections are not supported by this build. Use an SSH tunnel and connect through localhost or a Unix socket."
        );
    }

    Ok(config)
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
) -> Result<crate::_internal::model::sequence::SequenceKind> {
    match dependency_type {
        Some("i") => Ok(crate::_internal::model::sequence::SequenceKind::Identity),
        Some("a") if has_nextval_default => {
            Ok(crate::_internal::model::sequence::SequenceKind::SerialLike)
        }
        Some("a") => Ok(crate::_internal::model::sequence::SequenceKind::Owned),
        None => Ok(crate::_internal::model::sequence::SequenceKind::Standalone),
        Some(other) => anyhow::bail!("unsupported pg_depend type '{other}'"),
    }
}

fn relation_kind_from_pg(code: u8) -> Result<RelationKind> {
    match code {
        b'r' | b'p' => Ok(RelationKind::Table),
        b'v' => Ok(RelationKind::View),
        b'm' => Ok(RelationKind::MaterializedView),
        b'f' => Ok(RelationKind::ForeignTable),
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

fn column_storage_from_pg(code: &str) -> Result<String> {
    match code {
        "p" => Ok("PLAIN".to_string()),
        "e" => Ok("EXTERNAL".to_string()),
        "x" => Ok("EXTENDED".to_string()),
        "m" => Ok("MAIN".to_string()),
        _ => anyhow::bail!("unknown pg_attribute.attstorage value '{code}'"),
    }
}

fn column_compression_from_pg(code: Option<&str>) -> Result<Option<String>> {
    match code {
        None | Some("") | Some("\0") => Ok(None),
        Some("p") => Ok(Some("pglz".to_string())),
        Some("l") => Ok(Some("lz4".to_string())),
        // PostgreSQL exposes named values on some drivers and releases; keep
        // those canonical rather than rejecting an otherwise valid catalog.
        Some("pglz") => Ok(Some("pglz".to_string())),
        Some("lz4") => Ok(Some("lz4".to_string())),
        Some(value) => anyhow::bail!("unknown pg_attribute.attcompression value '{value}'"),
    }
}

pub(crate) fn catalog_options(
    values: Option<Vec<String>>,
    object: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let mut options = std::collections::BTreeMap::new();
    for option in values.unwrap_or_default() {
        let Some((key, value)) = option.split_once('=') else {
            anyhow::bail!("PostgreSQL returned malformed {object} option '{option}'");
        };
        if key.is_empty() || value.is_empty() {
            anyhow::bail!("PostgreSQL returned malformed {object} option '{option}'");
        }
        if options.insert(key.to_string(), value.to_string()).is_some() {
            anyhow::bail!("PostgreSQL returned duplicate {object} option '{key}'");
        }
    }
    Ok(options)
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

fn routine_volatility_from_pg(code: &str) -> Result<crate::_internal::model::function::Volatility> {
    match code {
        "v" => Ok(crate::_internal::model::function::Volatility::Volatile),
        "s" => Ok(crate::_internal::model::function::Volatility::Stable),
        "i" => Ok(crate::_internal::model::function::Volatility::Immutable),
        other => anyhow::bail!("unknown pg_proc.provolatile value '{other}'"),
    }
}

fn routine_kind_from_pg(code: &str) -> Result<crate::_internal::model::function::RoutineKind> {
    match code {
        "f" => Ok(crate::_internal::model::function::RoutineKind::Function),
        "p" => Ok(crate::_internal::model::function::RoutineKind::Procedure),
        "a" => Ok(crate::_internal::model::function::RoutineKind::Aggregate),
        "w" => Ok(crate::_internal::model::function::RoutineKind::Window),
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

#[cfg(test)]
mod catalog_conversion_tests {
    use super::*;

    #[test]
    fn schema_scope_is_deduplicated_without_reordering() {
        let scope = vec!["app".to_string(), "public".to_string(), "app".to_string()];
        assert_eq!(
            normalize_schema_scope(Some(&scope)).unwrap(),
            Some(vec!["app".to_string(), "public".to_string()])
        );
    }

    #[test]
    fn schema_scope_rejects_empty_identity() {
        let scope = vec!["app".to_string(), String::new()];
        let error = normalize_schema_scope(Some(&scope)).unwrap_err();
        assert!(error.to_string().contains("empty schema identity"));
    }

    #[test]
    fn known_catalog_codes_convert_without_fallbacks() {
        assert!(matches!(
            sequence_kind_from_pg(Some("i"), false).unwrap(),
            crate::_internal::model::sequence::SequenceKind::Identity
        ));
        assert!(matches!(
            sequence_kind_from_pg(Some("a"), true).unwrap(),
            crate::_internal::model::sequence::SequenceKind::SerialLike
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
            crate::_internal::model::function::Volatility::Immutable
        ));
        assert!(matches!(
            routine_kind_from_pg("a").unwrap(),
            crate::_internal::model::function::RoutineKind::Aggregate
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

    /// The writer validates coverage before encoding, so writer tests need a
    /// The writer validates coverage before encoding, so writer tests need a
    /// cache that claims the families a real synchronization would record.
    fn writable_cache() -> DbCache {
        use crate::_internal::db::cache::{CatalogCoverage, SchemaCoverage};

        let mut cache = DbCache::new();
        cache.coverage = CatalogCoverage::for_families(
            SchemaCoverage::from_sync_scope(None),
            CatalogFamily::ALL,
        );
        cache
    }

    use crate::_internal::db::cache::DbCacheVersioned;
    use std::fs;
    use std::io::Read;

    fn decode_written_cache(path: &Path) -> DbCache {
        let encoded = fs::read(path).unwrap();
        let reader = std::io::Cursor::new(encoded);
        let mut decoder = zstd::stream::Decoder::new(reader).unwrap();
        let mut payload = Vec::new();
        decoder.read_to_end(&mut payload).unwrap();
        let payload = payload
            .strip_prefix(CACHE_MAGIC)
            .expect("writer must prefix cache payloads");
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

        let mut cache = writable_cache();
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
                let mut cache = writable_cache();
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

        let error = write_cache_with_protection(&cache_path, writable_cache(), |_| {
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
            writable_cache(),
            Ok,
            MAX_CACHE_FILE_BYTES,
            CACHE_MAGIC.len(),
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
            writable_cache(),
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

mod load_constraints;
mod load_dependencies;
mod load_indexes;
mod load_namespaces;
mod load_relations;
mod load_replication;
mod load_roles;
mod load_routines;
mod load_types;
mod populate;
mod writer;
use load_constraints::*;
use load_dependencies::*;
use load_indexes::*;
use load_namespaces::*;
use load_relations::*;
use load_replication::*;
use load_roles::*;
use load_routines::*;
use load_types::*;
pub(crate) use populate::populate_cache;
#[cfg(test)]
pub(crate) use populate::populate_cache_in_current_transaction;
#[cfg(test)]
use populate::*;
use writer::*;
