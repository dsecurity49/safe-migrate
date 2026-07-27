use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use safe_migrate::analysis::state::Confidence;
use safe_migrate::report::violations::Violation;
use safe_migrate::sync;
use safe_migrate::{AnalysisState, Config, DbCache, Reporter, SafeMigrateEngine};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CACHE_STALE_AFTER_SECS: u64 = 7 * 24 * 60 * 60;
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
        #[arg(long, conflicts_with = "interactive")]
        json: bool,

        /// Launch an interactive terminal UI to browse violations
        #[arg(short, long, conflicts_with = "json")]
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
        #[arg(long, conflicts_with = "interactive")]
        json: bool,

        /// Launch an interactive terminal UI to browse violations
        #[arg(short, long, conflicts_with = "json")]
        interactive: bool,
    },
    /// Sync database table statistics for accurate lock evaluation
    Sync {
        #[arg(long, default_value = ".safe-migrate.cache")]
        out: PathBuf,
        /// Filter sync to specific schemas (comma-separated, e.g., --schemas public,auth)
        #[arg(long, value_delimiter = ',')]
        schemas: Option<Vec<String>>,
    },
}

#[derive(Clone, Copy)]
enum OutputMode {
    Human,
    Json,
    Interactive,
}

impl OutputMode {
    fn from_flags(json: bool, interactive: bool) -> Self {
        if json {
            Self::Json
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
            interactive,
        } => run_lint(
            &file,
            &config,
            &cache,
            no_cache,
            OutputMode::from_flags(json, interactive),
        ),
        Commands::LintChain {
            dir,
            config,
            cache,
            no_cache,
            json,
            interactive,
        } => run_lint_chain(
            &dir,
            &config,
            &cache,
            no_cache,
            OutputMode::from_flags(json, interactive),
        ),
        Commands::Sync { out, schemas } => run_sync(&out, schemas.as_deref()),
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
    warn_if_stale_cache(cache, no_cache);
    let (db_cache, baseline_unknown) = load_cache(cache, no_cache)?;

    eprintln!("Analyzing migration: {}", file.display());

    let engine = SafeMigrateEngine::new(config);
    let mut state = AnalysisState::new(db_cache);
    let violations = engine.analyze(&sql, &mut state).map_err(analysis_error)?;

    finish_analysis(violations, &mut state, baseline_unknown, output_mode)
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
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_owned();
        let sql = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read migration file: {}", path.display()))?;
        migrations.push((filename, sql));
    }

    let config = load_config(config_path)?;
    warn_if_stale_cache(cache, no_cache);
    let (db_cache, baseline_unknown) = load_cache(cache, no_cache)?;

    eprintln!("Analyzing migration chain in: {}", dir.display());

    let engine = SafeMigrateEngine::new(config);
    let mut state = AnalysisState::new(db_cache);
    let violations = engine
        .analyze_chain(&migrations, &mut state)
        .map_err(analysis_error)?;

    finish_analysis(violations, &mut state, baseline_unknown, output_mode)
}

fn run_sync(out: &Path, schemas: Option<&[String]>) -> Result<()> {
    std::env::var("DATABASE_URL")
        .context("DATABASE_URL environment variable must be set to run sync.")?;

    println!("Syncing database stats...");
    if let Some(schemas) = schemas {
        println!("Filtering to schemas: {}", schemas.join(", "));
    }
    sync::sync_cache(out, schemas)?;
    println!("[ SAFE ] Cache successfully written to {}", out.display());
    Ok(())
}

fn load_config(path: &Path) -> Result<Config> {
    Config::load_from_file(path)
        .with_context(|| format!("Failed to load configuration: {}", path.display()))
}

fn warn_if_stale_cache(cache: &Path, no_cache: bool) {
    if no_cache || !cache.exists() {
        return;
    }

    let Ok(metadata) = fs::metadata(cache) else {
        return;
    };
    let Ok(modified) = metadata.modified() else {
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let modified = modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now.saturating_sub(modified) > CACHE_STALE_AFTER_SECS {
        eprintln!(
            "[ WARN ] Database stats cache ({}) is over 7 days old.",
            cache.display()
        );
        eprintln!("         Run `safe-migrate sync` to refresh lock evaluations.");
    }
}

fn load_cache(cache: &Path, no_cache: bool) -> Result<(DbCache, bool)> {
    if !no_cache && cache.exists() {
        let file = fs::File::open(cache)
            .with_context(|| format!("Failed to open cache file: {}", cache.display()))?;
        let reader = std::io::BufReader::new(file);
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
    violations: Vec<Violation>,
    state: &mut AnalysisState,
    baseline_unknown: bool,
    output_mode: OutputMode,
) -> Result<()> {
    // Preserve worst-case rule evaluation for an empty baseline, then disclose
    // that the final report has no verified database baseline.
    if baseline_unknown {
        state.local.confidence = Confidence::Tainted;
    }

    let should_halt = Reporter::should_halt(&violations);
    match output_mode {
        OutputMode::Human => {
            Reporter::print_report(&violations, &state.local.confidence);
        }
        OutputMode::Json => {
            let report = Reporter::json_report(&violations, &state.local.confidence);
            println!("{}", serde_json::to_string_pretty(&report)?);
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
