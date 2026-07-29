use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use safe_migrate::analysis::state::Confidence;
use safe_migrate::db::cache::{CacheMetadata, DbCacheVersioned};
use safe_migrate::db::cache_file::{
    MAX_CACHE_DECODE_BYTES, is_encrypted_cache_bytes, read_cache_bytes, unprotect_cache_bytes,
};
use safe_migrate::model::relation::RelationKind;
use safe_migrate::report::violations::{ReportFinding, Violation};
use safe_migrate::sync;
use safe_migrate::{AnalysisState, Config, DbCache, Reporter, SafeMigrateEngine};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const EXIT_BLOCKING_FINDINGS: i32 = 2;

#[derive(Parser, Debug)]
#[command(name = "safe-migrate")]
#[command(version)]
#[command(
    about = "Analyze PostgreSQL migrations for schema and locking risks",
    long_about = None
)]
struct Cli {
    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Lint a SQL migration file
    Lint {
        #[arg(short, long)]
        file: PathBuf,

        #[arg(long, default_value = "safe-migrate.toml")]
        config: PathBuf,

        #[arg(long, default_value = ".safe-migrate.cache")]
        cache: PathBuf,

        /// Bypass the local cache file and evaluate with default worst-case assumptions
        #[arg(long)]
        no_cache: bool,

        /// Output results in JSON format for CI/CD integration
        #[arg(long, conflicts_with_all = ["interactive", "markdown"])]
        json: bool,

        /// Output a deterministic Markdown report for pull-request artifacts
        #[arg(long, conflicts_with_all = ["interactive", "json"])]
        markdown: bool,

        /// Launch an interactive terminal UI to browse violations
        #[arg(short, long, conflicts_with_all = ["json", "markdown"])]
        interactive: bool,
    },
    /// Lint a chain of SQL migration files in order (state persists across files)
    LintChain {
        #[arg(short, long)]
        dir: PathBuf,

        #[arg(long, default_value = "safe-migrate.toml")]
        config: PathBuf,

        #[arg(long, default_value = ".safe-migrate.cache")]
        cache: PathBuf,

        /// Bypass the local cache file and evaluate with default worst-case assumptions
        #[arg(long)]
        no_cache: bool,

        /// Output results in JSON format for CI/CD integration
        #[arg(long, conflicts_with_all = ["interactive", "markdown"])]
        json: bool,

        /// Output a deterministic Markdown report for pull-request artifacts
        #[arg(long, conflicts_with_all = ["interactive", "json"])]
        markdown: bool,

        /// Launch an interactive terminal UI to browse violations
        #[arg(short, long, conflicts_with_all = ["json", "markdown"])]
        interactive: bool,
    },
    /// Sync PostgreSQL schema metadata and statistics into a local cache
    Sync {
        #[arg(long, default_value = ".safe-migrate.cache")]
        out: PathBuf,
        #[arg(long, default_value = "safe-migrate.toml")]
        config: PathBuf,
        /// Filter sync to specific schemas (comma-separated, e.g., --schemas public,auth)
        #[arg(long, value_delimiter = ',')]
        schemas: Option<Vec<String>>,
    },
    /// Inspect a local cache without connecting to PostgreSQL
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
}

#[derive(Subcommand, Debug)]
enum CacheCommands {
    /// Print cache provenance and a redacted contents summary
    Inspect {
        #[arg(long, default_value = ".safe-migrate.cache")]
        cache: PathBuf,
        #[arg(long, default_value = "safe-migrate.toml")]
        config: PathBuf,
        /// Output the redacted summary as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy)]
enum OutputMode {
    Human,
    Json,
    Markdown,
    Interactive,
}

#[derive(Clone, Copy)]
enum AutoSyncOutcome {
    NotRequested,
    Refreshed,
    Failed,
    Bypassed,
}

impl AutoSyncOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::Refreshed => "refreshed",
            Self::Failed => "failed",
            Self::Bypassed => "bypassed",
        }
    }
}

struct PreparedCache {
    cache: DbCache,
    baseline_unknown: bool,
    baseline_stale: bool,
    auto_sync: AutoSyncOutcome,
    metadata: CacheMetadata,
}

#[derive(serde::Serialize)]
struct CacheInspection {
    path: String,
    format_version: u32,
    encrypted: bool,
    created_at_unix_secs: Option<u64>,
    age_seconds: Option<u64>,
    source_database: Option<String>,
    schemas: Option<Vec<String>>,
    search_path: Vec<String>,
    postgresql_version_num: Option<u32>,
    contents: CacheContentsSummary,
}

#[derive(serde::Serialize)]
struct CacheContentsSummary {
    relations: usize,
    tables: usize,
    views: usize,
    materialized_views: usize,
    columns: usize,
    indexes: usize,
    foreign_keys: usize,
    constraints: usize,
    triggers: usize,
    functions: usize,
    types: usize,
    dependencies: usize,
}

impl OutputMode {
    fn from_flags(json: bool, markdown: bool, interactive: bool) -> Self {
        if json {
            Self::Json
        } else if markdown {
            Self::Markdown
        } else if interactive {
            Self::Interactive
        } else {
            Self::Human
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.no_color {
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
    }

    match cli.command {
        Commands::Lint {
            file,
            config,
            cache,
            no_cache,
            json,
            markdown,
            interactive,
        } => run_lint(
            &file,
            &config,
            &cache,
            no_cache,
            OutputMode::from_flags(json, markdown, interactive),
        ),
        Commands::LintChain {
            dir,
            config,
            cache,
            no_cache,
            json,
            markdown,
            interactive,
        } => run_lint_chain(
            &dir,
            &config,
            &cache,
            no_cache,
            OutputMode::from_flags(json, markdown, interactive),
        ),
        Commands::Sync {
            out,
            config,
            schemas,
        } => run_sync(&out, &config, schemas.as_deref()),
        Commands::Cache { command } => match command {
            CacheCommands::Inspect {
                cache,
                config,
                json,
            } => run_cache_inspect(&cache, &config, json),
        },
    }
}

fn run_lint(
    file: &Path,
    config_path: &Path,
    cache: &Path,
    no_cache: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let sql = fs::read_to_string(file)
        .with_context(|| format!("Failed to read migration file: {}", file.display()))?;
    let config = load_config(config_path)?;
    let PreparedCache {
        cache: db_cache,
        baseline_unknown,
        baseline_stale,
        auto_sync,
        metadata,
    } = prepare_cache(&config, cache, no_cache)?;

    eprintln!("Analyzing migration: {}", file.display());

    let engine = SafeMigrateEngine::new(config);
    let mut state = AnalysisState::with_baseline(db_cache, !baseline_unknown);
    let findings = engine
        .analyze_with_locations(file.display().to_string(), sql, &mut state)
        .map_err(analysis_error)?;

    finish_analysis(
        findings,
        &mut state,
        baseline_unknown,
        baseline_stale,
        auto_sync,
        metadata,
        output_mode,
    )
}

fn run_lint_chain(
    dir: &Path,
    config_path: &Path,
    cache: &Path,
    no_cache: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("sql"))
        })
        .collect();
    files.sort_by_key(|entry| entry.file_name());

    let mut migrations = Vec::new();
    for entry in files {
        let path = entry.path();
        let filename = path.display().to_string();
        let sql = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read migration file: {}", path.display()))?;
        migrations.push((filename, sql));
    }

    let config = load_config(config_path)?;
    let PreparedCache {
        cache: db_cache,
        baseline_unknown,
        baseline_stale,
        auto_sync,
        metadata,
    } = prepare_cache(&config, cache, no_cache)?;

    eprintln!("Analyzing migration chain in: {}", dir.display());

    let engine = SafeMigrateEngine::new(config);
    let mut state = AnalysisState::with_baseline(db_cache, !baseline_unknown);
    let findings = engine
        .analyze_chain_with_locations(&migrations, &mut state)
        .map_err(analysis_error)?;

    finish_analysis(
        findings,
        &mut state,
        baseline_unknown,
        baseline_stale,
        auto_sync,
        metadata,
        output_mode,
    )
}

fn run_sync(out: &Path, config_path: &Path, schemas: Option<&[String]>) -> Result<()> {
    std::env::var("DATABASE_URL")
        .context("DATABASE_URL environment variable must be set to run sync.")?;
    let config = load_config(config_path)?;
    let schemas = config.sync_schemas(schemas);

    println!("Syncing database stats...");
    if let Some(schemas) = schemas {
        println!("Filtering to schemas: {}", schemas.join(", "));
    }
    sync::sync_cache(out, schemas, config.cache_encryption)?;
    println!("[ SAFE ] Cache successfully written to {}", out.display());
    Ok(())
}

fn run_cache_inspect(cache_path: &Path, config_path: &Path, json: bool) -> Result<()> {
    let config = load_config(config_path)?;
    let (cache, format_version, encrypted) = decode_cache(cache_path, config.cache_encryption)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let inspection = CacheInspection {
        path: cache_path.display().to_string(),
        format_version,
        encrypted,
        created_at_unix_secs: cache.metadata.created_at_unix_secs,
        age_seconds: cache
            .metadata
            .created_at_unix_secs
            .map(|created_at| now.saturating_sub(created_at)),
        source_database: cache.metadata.source_database.clone(),
        schemas: cache.metadata.schemas.clone(),
        search_path: cache.search_path.clone(),
        postgresql_version_num: cache.pg_version_num,
        contents: summarize_cache(&cache),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&inspection)?);
    } else {
        print_cache_inspection(&inspection);
    }
    Ok(())
}

fn summarize_cache(cache: &DbCache) -> CacheContentsSummary {
    let mut tables = 0;
    let mut views = 0;
    let mut materialized_views = 0;
    let mut columns = 0;
    for relation in cache.relations.values() {
        columns += relation.columns.len();
        match &relation.kind {
            RelationKind::Table => tables += 1,
            RelationKind::View => views += 1,
            RelationKind::MaterializedView => materialized_views += 1,
        }
    }
    CacheContentsSummary {
        relations: cache.relations.len(),
        tables,
        views,
        materialized_views,
        columns,
        indexes: cache.indexes.len(),
        foreign_keys: cache.foreign_keys.len(),
        constraints: cache.constraints.len(),
        triggers: cache.triggers.len(),
        functions: cache.functions.len(),
        types: cache.types.len(),
        dependencies: cache.dependencies.len(),
    }
}

fn print_cache_inspection(inspection: &CacheInspection) {
    println!("Cache: {}", inspection.path);
    println!("Format version: {}", inspection.format_version);
    println!(
        "Encryption: {}",
        if inspection.encrypted {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "Created at (Unix seconds): {}",
        inspection
            .created_at_unix_secs
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    println!(
        "Age: {}",
        inspection.age_seconds.map_or_else(
            || "unknown".to_string(),
            |seconds| format!("{} seconds", seconds)
        )
    );
    println!(
        "Source database: {}",
        inspection.source_database.as_deref().unwrap_or("unknown")
    );
    println!(
        "Schema scope: {}",
        inspection
            .schemas
            .as_deref()
            .map(|schemas| schemas.join(", "))
            .unwrap_or_else(|| "all non-system schemas".to_string())
    );
    println!("Search path: {}", inspection.search_path.join(", "));
    println!(
        "PostgreSQL version: {}",
        inspection
            .postgresql_version_num
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    let contents = &inspection.contents;
    println!(
        "Contents (counts only): {} relations ({} tables, {} views, {} materialized views), {} columns, {} indexes, {} foreign keys, {} constraints, {} triggers, {} functions, {} types, {} dependencies",
        contents.relations,
        contents.tables,
        contents.views,
        contents.materialized_views,
        contents.columns,
        contents.indexes,
        contents.foreign_keys,
        contents.constraints,
        contents.triggers,
        contents.functions,
        contents.types,
        contents.dependencies,
    );
    println!(
        "Redaction: this summary intentionally omits object, column, role, and dependency names; cache files still contain that metadata and must be handled as sensitive."
    );
}

fn load_config(path: &Path) -> Result<Config> {
    Config::load_from_file(path)
        .with_context(|| format!("Failed to load configuration: {}", path.display()))
}

fn prepare_cache(config: &Config, cache: &Path, no_cache: bool) -> Result<PreparedCache> {
    let auto_sync = maybe_auto_sync(config, cache, no_cache);
    let (cache, baseline_unknown) = load_cache(cache, no_cache, config.cache_encryption)?;
    let baseline_stale =
        warn_if_stale_cache(&cache.metadata, baseline_unknown, config.stale_stats_days);
    let metadata = cache.metadata.clone();
    Ok(PreparedCache {
        cache,
        baseline_unknown,
        baseline_stale,
        auto_sync,
        metadata,
    })
}

fn maybe_auto_sync(config: &Config, cache: &Path, no_cache: bool) -> AutoSyncOutcome {
    if !config.auto_sync {
        return AutoSyncOutcome::NotRequested;
    }

    if no_cache {
        eprintln!("[ INFO ] --no-cache bypasses configured automatic cache sync.");
        return AutoSyncOutcome::Bypassed;
    }

    eprintln!(
        "[ INFO ] Automatic cache sync enabled. Refreshing {}.",
        cache.display()
    );
    match sync::sync_cache(cache, config.schemas.as_deref(), config.cache_encryption) {
        Ok(()) => AutoSyncOutcome::Refreshed,
        Err(error) => {
            eprintln!("[ WARN ] Automatic cache sync failed: {error}");
            if cache.exists() {
                eprintln!("         Continuing with the previous cache.");
            } else {
                eprintln!(
                    "         No usable cache is available; continuing with uncertain analysis."
                );
            }
            AutoSyncOutcome::Failed
        }
    }
}

fn warn_if_stale_cache(metadata: &CacheMetadata, baseline_unknown: bool, stale_days: u64) -> bool {
    if baseline_unknown {
        return false;
    }

    let Some(created_at) = metadata.created_at_unix_secs else {
        eprintln!(
            "[ WARN ] Cache has no creation timestamp. Refresh it before relying on baseline-aware results."
        );
        return true;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let age = now.saturating_sub(created_at);
    if age > stale_days.saturating_mul(24 * 60 * 60) {
        eprintln!(
            "[ WARN ] Database cache is {} days old (configured limit: {} days).",
            age / (24 * 60 * 60),
            stale_days
        );
        eprintln!("         Run `safe-migrate sync` to refresh lock evaluations.");
        true
    } else {
        false
    }
}

fn load_cache(cache: &Path, no_cache: bool, cache_encryption: bool) -> Result<(DbCache, bool)> {
    if !no_cache && cache.exists() {
        let (cache, _, _) = decode_cache(cache, cache_encryption)?;
        Ok((cache, false))
    } else {
        if no_cache {
            eprintln!("[ INFO ] --no-cache passed. Running with default worst-case assumptions.");
        } else {
            eprintln!("[ INFO ] No cache found. Running with default worst-case assumptions.");
        }
        Ok((DbCache::new(), true))
    }
}

fn decode_cache(cache_path: &Path, cache_encryption: bool) -> Result<(DbCache, u32, bool)> {
    let encoded = read_cache_bytes(cache_path)?;
    let encrypted = is_encrypted_cache_bytes(&encoded);
    let decrypted = unprotect_cache_bytes(encoded, cache_encryption)?;
    let reader = std::io::Cursor::new(decrypted);
    let decoder = zstd::stream::Decoder::new(reader).map_err(|error| {
        anyhow!(
            "Cache file '{}' is corrupted (zstd init): {}",
            cache_path.display(),
            error
        )
    })?;
    let mut decoder = decoder.take(MAX_CACHE_DECODE_BYTES as u64);
    let config = bincode::config::standard()
        .with_variable_int_encoding()
        .with_limit::<MAX_CACHE_DECODE_BYTES>();
    let versioned: DbCacheVersioned =
        bincode::serde::decode_from_std_read(&mut decoder, config).map_err(|error| {
            if matches!(&error, bincode::error::DecodeError::LimitExceeded) {
                return anyhow!(
                    "Cache file '{}' exceeds the {} MiB decoded-size limit",
                    cache_path.display(),
                    MAX_CACHE_DECODE_BYTES / (1024 * 1024)
                );
            }
            anyhow!(
                "Cache file '{}' is corrupted (bincode): {}. Run `safe-migrate sync` to rebuild it.",
                cache_path.display(),
                error
            )
        })?;
    let format_version = versioned.format_version();
    let cache = versioned.into_cache().map_err(|error| {
        anyhow!(
            "Cache file '{}' is incompatible: {}",
            cache_path.display(),
            error
        )
    })?;
    Ok((cache, format_version, encrypted))
}

fn analysis_error(errors: Vec<String>) -> anyhow::Error {
    anyhow!(
        "Failed to parse SQL migration:\n  - {}",
        errors.join("\n  - ")
    )
}

fn finish_analysis(
    findings: Vec<ReportFinding>,
    state: &mut AnalysisState,
    baseline_unknown: bool,
    baseline_stale: bool,
    auto_sync: AutoSyncOutcome,
    metadata: CacheMetadata,
    output_mode: OutputMode,
) -> Result<()> {
    // Preserve worst-case rule evaluation for an empty baseline, then disclose
    // that the final report has no verified database baseline. A failed
    // automatic refresh does not invalidate an otherwise fresh cache; its
    // outcome remains visible in the report's baseline metadata.
    if baseline_unknown || baseline_stale {
        state.local.confidence = Confidence::Tainted;
    }

    let violations: Vec<Violation> = findings
        .iter()
        .map(|finding| finding.violation.clone())
        .collect();
    let should_halt = Reporter::should_halt(&violations);
    let baseline = serde_json::json!({
        "status": if baseline_unknown { "unavailable" } else if baseline_stale { "stale" } else { "available" },
        "created_at_unix_secs": metadata.created_at_unix_secs,
        "source_database": metadata.source_database,
        "schemas": metadata.schemas,
        "auto_sync": auto_sync.label(),
    });
    match output_mode {
        OutputMode::Human => {
            Reporter::print_report(&violations, &state.local.confidence);
        }
        OutputMode::Json => {
            let mut report =
                Reporter::json_report_with_locations(&findings, &state.local.confidence);
            report["baseline"] = baseline.clone();
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputMode::Markdown => {
            let mut report = Reporter::markdown_report(&findings, &state.local.confidence);
            report.push_str("\n## Baseline\n\n");
            report.push_str(&format!(
                "- **Status:** `{}`\n- **Automatic sync:** `{}`\n",
                baseline["status"].as_str().unwrap_or("unknown"),
                baseline["auto_sync"].as_str().unwrap_or("unknown")
            ));
            if let Some(source_database) = baseline["source_database"].as_str() {
                report.push_str(&format!("- **Source database:** `{source_database}`\n"));
            }
            if let Some(schemas) = baseline["schemas"].as_array() {
                let schemas = schemas
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                report.push_str(&format!("- **Schemas:** `{schemas}`\n"));
            }
            println!("{report}");
        }
        OutputMode::Interactive => {
            safe_migrate::run_interactive(&violations, &state.local.confidence)?;
        }
    }

    if should_halt {
        std::process::exit(EXIT_BLOCKING_FINDINGS);
    }

    Ok(())
}
