use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use safe_migrate::analysis::state::Confidence;
use safe_migrate::db::cache::CacheMetadata;
use safe_migrate::db::cache_file::unprotect_cache_bytes;
use safe_migrate::report::violations::{ReportFinding, Violation};
use safe_migrate::sync;
use safe_migrate::{AnalysisState, Config, DbCache, Reporter, SafeMigrateEngine};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const EXIT_BLOCKING_FINDINGS: i32 = 2;

#[derive(Parser, Debug)]
#[command(name = "safe-migrate")]
#[command(version)]
#[command(about = "Lint PostgreSQL migrations to prevent blocking locks", long_about = None)]
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
    /// Sync database table statistics for accurate lock evaluation
    Sync {
        #[arg(long, default_value = ".safe-migrate.cache")]
        out: PathBuf,
        #[arg(long, default_value = "safe-migrate.toml")]
        config: PathBuf,
        /// Filter sync to specific schemas (comma-separated, e.g., --schemas public,auth)
        #[arg(long, value_delimiter = ',')]
        schemas: Option<Vec<String>>,
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
        let encoded = fs::read(cache)
            .with_context(|| format!("Failed to read cache file: {}", cache.display()))?;
        let decrypted = unprotect_cache_bytes(encoded, cache_encryption)?;
        let reader = std::io::Cursor::new(decrypted);
        let mut decoder = zstd::stream::Decoder::new(reader).map_err(|error| {
            anyhow!(
                "Cache file '{}' is corrupted (zstd init): {}",
                cache.display(),
                error
            )
        })?;
        let config = bincode::config::standard().with_variable_int_encoding();
        let versioned: safe_migrate::db::cache::DbCacheVersioned =
            bincode::serde::decode_from_std_read(&mut decoder, config).map_err(|error| {
                anyhow!(
                    "Cache file '{}' is corrupted (bincode): {}. Run `safe-migrate sync` to rebuild it.",
                    cache.display(),
                    error
                )
            })?;
        let cache = versioned.into_cache().map_err(|error| {
            anyhow!(
                "Cache file '{}' is incompatible: {}",
                cache.display(),
                error
            )
        })?;
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
