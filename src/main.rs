use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use safe_migrate::analysis::evidence::{EvidenceCode, EvidenceRecord, EvidenceScope};
use safe_migrate::analysis::outcome::AnalysisOutcome;
use safe_migrate::db::cache::{CACHE_V8_MAGIC, CacheMetadata, CatalogCoverage, DbCacheVersioned};
use safe_migrate::db::cache_file::{
    MAX_CACHE_DECODE_BYTES, is_encrypted_cache_bytes, read_cache_bytes, unprotect_cache_bytes,
};
use safe_migrate::model::relation::RelationKind;
use safe_migrate::report::violations::{ReportFinding, Violation};
use safe_migrate::rules::registry::{self, RuleDescriptor};
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
    about = "Sync PostgreSQL metadata, then lint migrations offline",
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

        /// Read configuration from this file; otherwise use safe-migrate.toml when present
        #[arg(long)]
        config: Option<PathBuf>,

        #[arg(long, default_value = ".safe-migrate.cache")]
        cache: PathBuf,

        /// Bypass the local cache file and evaluate with default worst-case assumptions
        #[arg(long)]
        no_cache: bool,

        /// Skip automatic synchronization configured in TOML for this run
        #[arg(long)]
        no_auto_sync: bool,

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

        /// Read configuration from this file; otherwise use safe-migrate.toml when present
        #[arg(long)]
        config: Option<PathBuf>,

        #[arg(long, default_value = ".safe-migrate.cache")]
        cache: PathBuf,

        /// Bypass the local cache file and evaluate with default worst-case assumptions
        #[arg(long)]
        no_cache: bool,

        /// Skip automatic synchronization configured in TOML for this run
        #[arg(long)]
        no_auto_sync: bool,

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
        /// Read configuration from this file; otherwise use safe-migrate.toml when present
        #[arg(long)]
        config: Option<PathBuf>,
        /// Filter sync to specific schemas (comma-separated, e.g., --schemas public,auth)
        #[arg(long, value_delimiter = ',')]
        schemas: Option<Vec<String>>,
    },
    /// Inspect a local cache without connecting to PostgreSQL
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// List primary migration safety rules and their guidance
    Rules {
        /// Show one primary rule by its stable ID
        #[arg(long)]
        rule: Option<String>,
        /// Output the rule catalog as JSON
        #[arg(long)]
        json: bool,
        /// Read configuration from this file; otherwise use safe-migrate.toml when present
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum CacheCommands {
    /// Print cache provenance and a redacted contents summary
    Inspect {
        #[arg(long, default_value = ".safe-migrate.cache")]
        cache: PathBuf,
        /// Read configuration from this file; otherwise use safe-migrate.toml when present
        #[arg(long)]
        config: Option<PathBuf>,
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
    coverage: CatalogCoverage,
    search_path: Vec<String>,
    postgresql_version_num: Option<u32>,
    observed_settings: ObservedSettings,
    contents: CacheContentsSummary,
}

#[derive(Clone, serde::Serialize)]
struct ObservedSettings {
    lock_timeout_ms: Option<u64>,
    statement_timeout_ms: Option<u64>,
}

#[derive(serde::Serialize)]
struct CacheContentsSummary {
    schemas: usize,
    sequences: usize,
    relations: usize,
    tables: usize,
    views: usize,
    materialized_views: usize,
    columns: usize,
    indexes: usize,
    foreign_keys: usize,
    constraints: usize,
    constraint_keys: usize,
    triggers: usize,
    functions: usize,
    procedures: usize,
    aggregates: usize,
    window_functions: usize,
    publications: usize,
    subscriptions: usize,
    types: usize,
    roles: usize,
    dependencies: usize,
    inheritances: usize,
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
            no_auto_sync,
            json,
            markdown,
            interactive,
        } => run_lint(
            &file,
            config.as_deref(),
            &cache,
            no_cache,
            no_auto_sync,
            OutputMode::from_flags(json, markdown, interactive),
        ),
        Commands::LintChain {
            dir,
            config,
            cache,
            no_cache,
            no_auto_sync,
            json,
            markdown,
            interactive,
        } => run_lint_chain(
            &dir,
            config.as_deref(),
            &cache,
            no_cache,
            no_auto_sync,
            OutputMode::from_flags(json, markdown, interactive),
        ),
        Commands::Sync {
            out,
            config,
            schemas,
        } => run_sync(&out, config.as_deref(), schemas.as_deref()),
        Commands::Cache { command } => match command {
            CacheCommands::Inspect {
                cache,
                config,
                json,
            } => run_cache_inspect(&cache, config.as_deref(), json),
        },
        Commands::Rules { rule, json, config } => {
            run_rules(rule.as_deref(), json, config.as_deref())
        }
    }
}

fn rule_descriptor_json(descriptor: &RuleDescriptor, config: &Config) -> serde_json::Value {
    use safe_migrate::rules::registry::RuleConfigurationField;

    let mut effective = serde_json::json!({
        "enabled": !config.is_rule_disabled(descriptor.id),
    });
    if descriptor.supports(RuleConfigurationField::Tier1ThresholdRows) {
        effective["tier1_threshold_rows"] =
            serde_json::json!(config.rule_tier1_threshold(descriptor.id));
    }
    if descriptor.supports(RuleConfigurationField::Tier2ThresholdRows) {
        effective["tier2_threshold_rows"] =
            serde_json::json!(config.rule_tier2_threshold(descriptor.id));
    }
    serde_json::json!({
        "id": descriptor.id,
        "title": descriptor.title,
        "summary": descriptor.summary,
        "impact": descriptor.impact,
        "default_tier": match descriptor.default_tier() {
            safe_migrate::report::violations::ViolationTier::Tier1 => "Tier1",
            safe_migrate::report::violations::ViolationTier::Tier2 => "Tier2",
            safe_migrate::report::violations::ViolationTier::Tier3 => "Tier3",
        },
        "remediation": descriptor.recipe(),
        "supported_configuration_fields": descriptor
            .supported_configuration_fields
            .iter()
            .map(|field| field.as_str())
            .collect::<Vec<_>>(),
        "effective": effective,
    })
}

fn rules_separator() -> String {
    let width = terminal_size::terminal_size()
        .map(|(width, _)| width.0 as usize)
        .unwrap_or(80)
        .max(60);
    "-".repeat((width as f32 * 0.82) as usize)
}

fn run_rules(rule_id: Option<&str>, json: bool, config_path: Option<&Path>) -> Result<()> {
    let config = load_config(config_path)?;
    let descriptors: Vec<_> = match rule_id {
        Some(id) => vec![registry::find_primary_rule(id).ok_or_else(|| {
            anyhow!(
                "Unknown primary rule ID '{}'. Valid primary rule IDs: {}",
                id,
                registry::primary_rule_ids().collect::<Vec<_>>().join(", ")
            )
        })?],
        None => registry::PRIMARY_RULES.iter().collect(),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 2,
                "rules": descriptors.iter().map(|descriptor| rule_descriptor_json(descriptor, &config)).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }

    for (index, descriptor) in descriptors.iter().enumerate() {
        if index > 0 {
            println!();
            println!("{}", rules_separator());
            println!();
        }
        println!("{} ({})", descriptor.title, descriptor.id);
        println!("  Summary: {}", descriptor.summary);
        println!("  Impact: {}", descriptor.impact);
        println!("  Default tier: {:?}", descriptor.default_tier());
        println!("  Remediation: {}", descriptor.recipe());
        println!(
            "  Configuration: {}",
            descriptor
                .supported_configuration_fields
                .iter()
                .map(|field| field.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let mut effective = vec![format!(
            "enabled={}",
            !config.is_rule_disabled(descriptor.id)
        )];
        use safe_migrate::rules::registry::RuleConfigurationField;
        if descriptor.supports(RuleConfigurationField::Tier1ThresholdRows) {
            effective.push(format!(
                "tier1_threshold_rows={}",
                config.rule_tier1_threshold(descriptor.id)
            ));
        }
        if descriptor.supports(RuleConfigurationField::Tier2ThresholdRows) {
            effective.push(format!(
                "tier2_threshold_rows={}",
                config.rule_tier2_threshold(descriptor.id)
            ));
        }
        println!("  Effective: {}", effective.join(", "));
    }
    Ok(())
}

fn run_lint(
    file: &Path,
    config_path: Option<&Path>,
    cache: &Path,
    no_cache: bool,
    no_auto_sync: bool,
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
    } = prepare_cache(&config, cache, no_cache, no_auto_sync)?;

    eprintln!("Analyzing migration: {}", file.display());

    let engine = SafeMigrateEngine::new(config);
    let mut state = AnalysisState::with_baseline(db_cache, !baseline_unknown);
    let outcome = engine
        .analyze_outcome_with_locations(file.display().to_string(), sql, &mut state)
        .map_err(analysis_error)?;
    let outcome = attach_baseline_evidence(outcome, baseline_unknown, baseline_stale);

    finish_analysis(
        outcome,
        baseline_unknown,
        baseline_stale,
        auto_sync,
        metadata,
        output_mode,
    )
}

fn run_lint_chain(
    dir: &Path,
    config_path: Option<&Path>,
    cache: &Path,
    no_cache: bool,
    no_auto_sync: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let mut files = Vec::new();
    for entry in
        fs::read_dir(dir).with_context(|| format!("Failed to read directory: {}", dir.display()))?
    {
        let entry = entry
            .with_context(|| format!("Failed to read an entry in directory: {}", dir.display()))?;
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sql"))
        {
            files.push(entry);
        }
    }
    files.sort_by_key(|entry| entry.file_name());

    if files.is_empty() {
        anyhow::bail!("No .sql migration files found in {}", dir.display());
    }

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
    } = prepare_cache(&config, cache, no_cache, no_auto_sync)?;

    eprintln!("Analyzing migration chain in: {}", dir.display());

    let engine = SafeMigrateEngine::new(config);
    let mut state = AnalysisState::with_baseline(db_cache, !baseline_unknown);
    let outcome = engine
        .analyze_chain_outcome_with_locations(&migrations, &mut state)
        .map_err(analysis_error)?;
    let outcome = attach_baseline_evidence(outcome, baseline_unknown, baseline_stale);

    finish_analysis(
        outcome,
        baseline_unknown,
        baseline_stale,
        auto_sync,
        metadata,
        output_mode,
    )
}

fn run_sync(out: &Path, config_path: Option<&Path>, schemas: Option<&[String]>) -> Result<()> {
    let config = load_config(config_path)?;
    let schemas = config.sync_schemas(schemas)?;

    println!("Syncing PostgreSQL schema metadata and statistics...");
    if let Some(schemas) = schemas {
        println!("Filtering to schemas: {}", schemas.join(", "));
    }
    sync::sync_cache(out, schemas, config.cache_encryption)?;
    println!("[ SAFE ] Cache successfully written to {}", out.display());
    Ok(())
}

fn run_cache_inspect(cache_path: &Path, config_path: Option<&Path>, json: bool) -> Result<()> {
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
        coverage: cache.coverage.clone(),
        search_path: cache.search_path.clone(),
        postgresql_version_num: cache.pg_version_num,
        observed_settings: ObservedSettings {
            lock_timeout_ms: Some(cache.metadata.source_lock_timeout_ms),
            statement_timeout_ms: Some(cache.metadata.source_statement_timeout_ms),
        },
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
    let mut functions = 0;
    let mut procedures = 0;
    let mut aggregates = 0;
    let mut window_functions = 0;
    for routine in cache.functions.values() {
        match routine.routine_kind {
            safe_migrate::model::function::RoutineKind::Function => functions += 1,
            safe_migrate::model::function::RoutineKind::Procedure => procedures += 1,
            safe_migrate::model::function::RoutineKind::Aggregate => aggregates += 1,
            safe_migrate::model::function::RoutineKind::Window => window_functions += 1,
        }
    }
    CacheContentsSummary {
        schemas: cache.schemas.len(),
        sequences: cache.sequences.len(),
        relations: cache.relations.len(),
        tables,
        views,
        materialized_views,
        columns,
        indexes: cache.indexes.len(),
        foreign_keys: cache.foreign_keys.len(),
        constraints: cache.constraints.len(),
        constraint_keys: cache.constraint_keys.len(),
        triggers: cache.triggers.len(),
        functions,
        procedures,
        aggregates,
        window_functions,
        publications: cache.publications.len(),
        subscriptions: cache.subscriptions.len(),
        types: cache.types.len(),
        roles: cache.roles.len(),
        dependencies: cache.dependencies.len(),
        inheritances: cache.inheritances.len(),
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
    println!(
        "Catalog coverage: {}",
        inspection
            .coverage
            .family_names()
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("Search path: {}", inspection.search_path.join(", "));
    println!(
        "PostgreSQL version: {}",
        inspection
            .postgresql_version_num
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    println!(
        "Observed lock_timeout: {}",
        inspection
            .observed_settings
            .lock_timeout_ms
            .map_or_else(|| "unknown".to_string(), |value| format!("{value} ms"))
    );
    println!(
        "Observed statement_timeout: {}",
        inspection
            .observed_settings
            .statement_timeout_ms
            .map_or_else(|| "unknown".to_string(), |value| format!("{value} ms"))
    );
    let contents = &inspection.contents;
    println!();
    println!("Contents (counts only):");
    println!("  Database objects");
    println!("    {:<22} {}", "Schemas:", contents.schemas);
    println!("    {:<22} {}", "Sequences:", contents.sequences);
    println!("    {:<22} {}", "Relations:", contents.relations);
    println!("      {:<20} {}", "Tables:", contents.tables);
    println!("      {:<20} {}", "Views:", contents.views);
    println!(
        "      {:<20} {}",
        "Materialized views:", contents.materialized_views
    );
    println!("    {:<22} {}", "Columns:", contents.columns);
    println!("    {:<22} {}", "Indexes:", contents.indexes);
    println!("    {:<22} {}", "Constraints:", contents.constraints);
    println!(
        "    {:<22} {}",
        "Constraint keys:", contents.constraint_keys
    );
    println!("    {:<22} {}", "Foreign keys:", contents.foreign_keys);
    println!("    {:<22} {}", "Triggers:", contents.triggers);
    println!("    {:<22} {}", "Types:", contents.types);
    println!();
    println!("  Routines");
    println!("    {:<22} {}", "Functions:", contents.functions);
    println!("    {:<22} {}", "Procedures:", contents.procedures);
    println!("    {:<22} {}", "Aggregates:", contents.aggregates);
    println!(
        "    {:<22} {}",
        "Window functions:", contents.window_functions
    );
    println!();
    println!("  Replication");
    println!("    {:<22} {}", "Publications:", contents.publications);
    println!("    {:<22} {}", "Subscriptions:", contents.subscriptions);
    println!();
    println!("  Security and graph");
    println!("    {:<22} {}", "Roles:", contents.roles);
    println!("    {:<22} {}", "Dependencies:", contents.dependencies);
    println!("    {:<22} {}", "Inheritance edges:", contents.inheritances);
    println!();
    println!(
        "Redaction: this summary intentionally omits object, column, role, and dependency names; cache files still contain that metadata and must be handled as sensitive."
    );
}

fn load_config(path: Option<&Path>) -> Result<Config> {
    let default_path = Path::new("safe-migrate.toml");
    let (config, loaded_path) = match path {
        Some(path) => (Config::load_required_from_file(path), path),
        None => (Config::load_from_file(default_path), default_path),
    };
    let config = config
        .with_context(|| format!("Failed to load configuration: {}", loaded_path.display()))?;
    let engine = SafeMigrateEngine::new(config.clone());
    config
        .validate_rule_ids(engine.primary_rule_ids())
        .with_context(|| {
            format!(
                "Failed to validate configuration: {}",
                loaded_path.display()
            )
        })?;
    registry::validate_rule_configuration(&config)
        .map_err(anyhow::Error::msg)
        .with_context(|| {
            format!(
                "Failed to validate configuration: {}",
                loaded_path.display()
            )
        })?;
    config.sync_schemas(None).with_context(|| {
        format!(
            "Failed to validate configuration: {}",
            loaded_path.display()
        )
    })?;
    Ok(config)
}

fn prepare_cache(
    config: &Config,
    cache: &Path,
    no_cache: bool,
    no_auto_sync: bool,
) -> Result<PreparedCache> {
    let auto_sync = maybe_auto_sync(config, cache, no_cache, no_auto_sync);
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

fn maybe_auto_sync(
    config: &Config,
    cache: &Path,
    no_cache: bool,
    no_auto_sync: bool,
) -> AutoSyncOutcome {
    if !config.auto_sync {
        return AutoSyncOutcome::NotRequested;
    }

    if no_cache {
        eprintln!("[ INFO ] --no-cache bypasses configured automatic cache sync.");
        return AutoSyncOutcome::Bypassed;
    }

    if no_auto_sync {
        eprintln!("[ INFO ] --no-auto-sync bypasses configured automatic cache sync.");
        return AutoSyncOutcome::Bypassed;
    }

    eprintln!(
        "[ INFO ] Automatic cache sync enabled. Refreshing {}.",
        cache.display()
    );
    let schemas = match config.sync_schemas(None) {
        Ok(schemas) => schemas,
        Err(error) => {
            eprintln!("[ WARN ] Automatic cache sync configuration is invalid: {error}");
            return AutoSyncOutcome::Failed;
        }
    };
    match sync::sync_cache(cache, schemas, config.cache_encryption) {
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
    let mut decoder = decoder.take(MAX_CACHE_DECODE_BYTES as u64 + 1);
    let mut header = vec![0; CACHE_V8_MAGIC.len()];
    let mut header_len = 0;
    while header_len < header.len() {
        let read = decoder.read(&mut header[header_len..]).map_err(|error| {
            anyhow!(
                "Cache file '{}' is corrupted while decompressing: {}",
                cache_path.display(),
                error
            )
        })?;
        if read == 0 {
            break;
        }
        header_len += read;
    }
    if header_len != CACHE_V8_MAGIC.len() || header != CACHE_V8_MAGIC {
        anyhow::bail!(
            "Cache file '{}' uses an unsupported cache format. Run `safe-migrate sync` to rebuild it.",
            cache_path.display()
        );
    }

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
    let remaining_before_trailing = decoder.limit();
    std::io::copy(&mut decoder, &mut std::io::sink()).map_err(|error| {
        anyhow!(
            "Cache file '{}' is corrupted while decompressing: {}",
            cache_path.display(),
            error
        )
    })?;
    let decompressed_bytes = (MAX_CACHE_DECODE_BYTES as u64 + 1) - decoder.limit();
    if decompressed_bytes > MAX_CACHE_DECODE_BYTES as u64 {
        anyhow::bail!(
            "Cache file '{}' exceeds the {} MiB decoded-size limit",
            cache_path.display(),
            MAX_CACHE_DECODE_BYTES / (1024 * 1024)
        );
    }
    if decoder.limit() != remaining_before_trailing {
        anyhow::bail!(
            "Cache file '{}' is corrupted (trailing payload data). Run `safe-migrate sync` to rebuild it.",
            cache_path.display()
        );
    }
    let header_version = 8;
    let format_version = versioned.format_version();
    if format_version != header_version {
        anyhow::bail!(
            "Cache file '{}' has a mismatched cache format header. Run `safe-migrate sync` to rebuild it.",
            cache_path.display()
        );
    }
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
    outcome: AnalysisOutcome<ReportFinding>,
    baseline_unknown: bool,
    baseline_stale: bool,
    auto_sync: AutoSyncOutcome,
    metadata: CacheMetadata,
    output_mode: OutputMode,
) -> Result<()> {
    let violations: Vec<Violation> = outcome
        .findings
        .iter()
        .map(|finding| finding.violation.clone())
        .collect();
    let should_halt = Reporter::should_halt(&violations);
    let observed_settings = ObservedSettings {
        lock_timeout_ms: (!baseline_unknown).then_some(metadata.source_lock_timeout_ms),
        statement_timeout_ms: (!baseline_unknown).then_some(metadata.source_statement_timeout_ms),
    };
    let baseline = serde_json::json!({
        "status": if baseline_unknown { "unavailable" } else if baseline_stale { "stale" } else { "available" },
        "created_at_unix_secs": metadata.created_at_unix_secs,
        "source_database": metadata.source_database,
        "schemas": metadata.schemas,
        "auto_sync": auto_sync.label(),
        "observed_settings": observed_settings,
    });
    match output_mode {
        OutputMode::Human => {
            Reporter::print_outcome(&outcome);
        }
        OutputMode::Json => {
            let mut report = Reporter::json_outcome_with_locations(&outcome);
            report["baseline"] = baseline.clone();
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputMode::Markdown => {
            let mut report = Reporter::markdown_outcome(&outcome);
            report.push_str("\n## Baseline\n\n");
            report.push_str(&format!(
                "- **Status:** `{}`\n- **Automatic sync:** `{}`\n",
                baseline["status"].as_str().unwrap_or("unknown"),
                baseline["auto_sync"].as_str().unwrap_or("unknown")
            ));
            if let Some(source_database) = baseline["source_database"].as_str() {
                report.push_str(&format!(
                    "- **Source database:** `{}`\n",
                    source_database.replace('`', "'")
                ));
            }
            if let Some(schemas) = baseline["schemas"].as_array() {
                let schemas = schemas
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                report.push_str(&format!("- **Schemas:** `{}`\n", schemas.replace('`', "'")));
            }
            report.push_str(&format!(
                "- **Observed lock timeout:** `{}`\n- **Observed statement timeout:** `{}`\n",
                baseline["observed_settings"]["lock_timeout_ms"]
                    .as_u64()
                    .map_or_else(|| "unknown".to_string(), |value| format!("{value} ms")),
                baseline["observed_settings"]["statement_timeout_ms"]
                    .as_u64()
                    .map_or_else(|| "unknown".to_string(), |value| format!("{value} ms")),
            ));
            println!("{report}");
        }
        OutputMode::Interactive => {
            safe_migrate::run_interactive(&violations, &outcome.confidence)?;
        }
    }

    if should_halt {
        std::process::exit(EXIT_BLOCKING_FINDINGS);
    }

    Ok(())
}

fn attach_baseline_evidence(
    mut outcome: AnalysisOutcome<ReportFinding>,
    baseline_unknown: bool,
    baseline_stale: bool,
) -> AnalysisOutcome<ReportFinding> {
    if baseline_unknown {
        outcome = outcome.with_evidence(EvidenceRecord::new(
            EvidenceCode::BaselineUnavailable,
            EvidenceScope::Chain,
        ));
    }
    if baseline_stale {
        outcome = outcome.with_evidence(EvidenceRecord::new(
            EvidenceCode::BaselineStale,
            EvidenceScope::Chain,
        ));
    }
    outcome
}
