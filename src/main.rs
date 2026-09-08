use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use safe_migrate::api::{
    self, AnalysisOutcome, AutoSyncStatus, Baseline, BaselineInspection, Config, Migration, Rule,
};
use std::fs;
use std::path::{Path, PathBuf};

const EXIT_BLOCKING_FINDINGS: i32 = 2;

fn terminal_inline(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}

fn display_path(path: &Path) -> String {
    terminal_inline(&path.display().to_string())
}

mod cli_init;
use cli_init::InitCommands;

#[derive(Parser, Debug)]
#[command(name = "safe-migrate")]
#[command(version)]
#[command(
    about = "Check PostgreSQL migrations against a synchronized database baseline",
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
    /// Create reviewed project integration files
    Init {
        #[command(subcommand)]
        command: InitCommands,
    },
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

struct PreparedCache {
    baseline: Baseline,
    auto_sync: AutoSyncStatus,
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

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", terminal_inline(&format!("{error:#}")));
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.no_color {
        // CLI parsing happens before safe-migrate creates any worker threads.
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
    }

    match cli.command {
        Commands::Init { command } => cli_init::run(command),
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

fn rule_descriptor_json(rule: &Rule) -> serde_json::Value {
    let mut effective = serde_json::json!({ "enabled": rule.enabled });
    if let Some(value) = rule.tier1_threshold_rows {
        effective["tier1_threshold_rows"] = serde_json::json!(value);
    }
    if let Some(value) = rule.tier2_threshold_rows {
        effective["tier2_threshold_rows"] = serde_json::json!(value);
    }
    serde_json::json!({
        "id": rule.id,
        "title": rule.title,
        "summary": rule.summary,
        "impact": rule.impact,
        "default_tier": format!("{:?}", rule.default_tier),
        "remediation": rule.remediation,
        "supported_configuration_fields": rule.supported_configuration_fields,
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
    let all_rules = api::rules(&config).map_err(anyhow::Error::new)?;
    let rules: Vec<_> = match rule_id {
        Some(id) => vec![
            all_rules
                .into_iter()
                .find(|rule| rule.id == id)
                .ok_or_else(|| {
                    anyhow!(
                        "Unknown primary rule ID '{}'. Valid primary rule IDs: {}",
                        id,
                        api::rules(&config)
                            .expect("validated configuration must list rules")
                            .iter()
                            .map(|rule| rule.id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?,
        ],
        None => all_rules,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 2,
                "rules": rules.iter().map(rule_descriptor_json).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }

    for (index, rule) in rules.iter().enumerate() {
        if index > 0 {
            println!();
            println!("{}", rules_separator());
            println!();
        }
        println!("{} ({})", rule.title, rule.id);
        println!("  Summary: {}", rule.summary);
        println!("  Impact: {}", rule.impact);
        println!("  Default tier: {:?}", rule.default_tier);
        println!("  Remediation: {}", rule.remediation);
        println!(
            "  Configuration: {}",
            rule.supported_configuration_fields
                .iter()
                .map(|field| field.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let mut effective = vec![format!("enabled={}", rule.enabled)];
        if let Some(value) = rule.tier1_threshold_rows {
            effective.push(format!("tier1_threshold_rows={value}"));
        }
        if let Some(value) = rule.tier2_threshold_rows {
            effective.push(format!("tier2_threshold_rows={value}"));
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
        baseline,
        auto_sync,
    } = prepare_cache(&config, cache, no_cache, no_auto_sync)?;

    eprintln!("Analyzing migration: {}", display_path(file));

    let outcome = api::analyze(&config, file.display().to_string(), sql, &baseline)
        .map_err(anyhow::Error::new)?;

    finish_analysis(outcome, auto_sync, output_mode)
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
        anyhow::bail!("No .sql migration files found in {}", display_path(dir));
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
        baseline,
        auto_sync,
    } = prepare_cache(&config, cache, no_cache, no_auto_sync)?;

    eprintln!("Analyzing migration chain in: {}", display_path(dir));

    let outcome = api::analyze_chain(
        &config,
        migrations
            .into_iter()
            .map(|(filename, sql)| Migration::new(filename, sql)),
        &baseline,
    )
    .map_err(anyhow::Error::new)?;

    finish_analysis(outcome, auto_sync, output_mode)
}

fn run_sync(out: &Path, config_path: Option<&Path>, schemas: Option<&[String]>) -> Result<()> {
    let config = load_config(config_path)?;
    let effective_schemas = schemas.or(config.schema_scope());

    println!("Syncing PostgreSQL schema metadata and statistics...");
    if let Some(schemas) = effective_schemas {
        println!(
            "Filtering to schemas: {}",
            terminal_inline(&schemas.join(", "))
        );
    }
    api::sync(out, &config, schemas).map_err(anyhow::Error::new)?;
    println!(
        "[ SAFE ] Cache successfully written to {}",
        display_path(out)
    );
    Ok(())
}

fn run_cache_inspect(cache_path: &Path, config_path: Option<&Path>, json: bool) -> Result<()> {
    let config = load_config(config_path)?;
    let inspection = Baseline::load(cache_path, &config)
        .map_err(anyhow::Error::new)?
        .inspect();

    if json {
        println!("{}", serde_json::to_string_pretty(&inspection)?);
    } else {
        print_cache_inspection(cache_path, &inspection);
    }
    Ok(())
}
fn print_cache_inspection(cache_path: &Path, inspection: &BaselineInspection) {
    println!("Cache: {}", display_path(cache_path));
    println!(
        "Format version: {}",
        inspection
            .format_version
            .map_or_else(|| "unavailable".to_owned(), |version| version.to_string())
    );
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
        terminal_inline(inspection.source_database.as_deref().unwrap_or("unknown"))
    );
    let schema_scope = inspection
        .schemas
        .as_deref()
        .map(|schemas| schemas.join(", "))
        .unwrap_or_else(|| "all non-system schemas".to_string());
    println!("Schema scope: {}", terminal_inline(&schema_scope));
    println!(
        "Catalog coverage: {}",
        inspection
            .coverage
            .families
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "Search path: {}",
        terminal_inline(&inspection.search_path.join(", "))
    );
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
    api::validate_config(&config)
        .map_err(anyhow::Error::new)
        .with_context(|| {
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
    let baseline = if !no_cache && cache.exists() {
        Baseline::load(cache, config).map_err(anyhow::Error::new)?
    } else {
        if no_cache {
            eprintln!("[ INFO ] --no-cache passed. Running with default worst-case assumptions.");
        } else {
            eprintln!("[ INFO ] No cache found. Running with default worst-case assumptions.");
        }
        Baseline::unavailable()
    };
    let baseline_stale = baseline.is_stale(config.stale_stats_days());
    if baseline_stale {
        eprintln!(
            "[ WARN ] Database cache is stale. Run `safe-migrate sync` before relying on baseline-aware results."
        );
    }
    Ok(PreparedCache {
        baseline,
        auto_sync,
    })
}

fn maybe_auto_sync(
    config: &Config,
    cache: &Path,
    no_cache: bool,
    no_auto_sync: bool,
) -> AutoSyncStatus {
    if !config.auto_sync() {
        return AutoSyncStatus::NotRequested;
    }

    if no_cache {
        eprintln!("[ INFO ] --no-cache bypasses configured automatic cache sync.");
        return AutoSyncStatus::Bypassed;
    }

    if no_auto_sync {
        eprintln!("[ INFO ] --no-auto-sync bypasses configured automatic cache sync.");
        return AutoSyncStatus::Bypassed;
    }

    eprintln!(
        "[ INFO ] Automatic cache sync enabled. Refreshing {}.",
        display_path(cache)
    );
    match api::sync(cache, config, None) {
        Ok(()) => AutoSyncStatus::Refreshed,
        Err(error) => {
            eprintln!("[ WARN ] Automatic cache sync failed: {error}");
            if cache.exists() {
                eprintln!("         Continuing with the previous cache.");
            } else {
                eprintln!(
                    "         No usable cache is available; continuing with uncertain analysis."
                );
            }
            AutoSyncStatus::Failed
        }
    }
}

fn finish_analysis(
    outcome: AnalysisOutcome,
    auto_sync: AutoSyncStatus,
    output_mode: OutputMode,
) -> Result<()> {
    let outcome = outcome.with_auto_sync_status(auto_sync);
    let should_halt = outcome.should_halt();
    match output_mode {
        OutputMode::Human => {
            outcome.print_human();
        }
        OutputMode::Json => {
            println!("{}", serde_json::to_string_pretty(&outcome.json())?);
        }
        OutputMode::Markdown => {
            println!("{}", outcome.markdown());
        }
        OutputMode::Interactive => {
            outcome.run_interactive().map_err(anyhow::Error::new)?;
        }
    }

    if should_halt {
        std::process::exit(EXIT_BLOCKING_FINDINGS);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{display_path, terminal_inline};
    use std::path::Path;

    #[test]
    fn terminal_values_render_controls_inertly() {
        assert_eq!(terminal_inline("cache\x1b[2J\r\n"), "cache\\u{1b}[2J\\r\\n");
        assert_eq!(terminal_inline("café_日本"), "café_日本");
        assert_eq!(display_path(Path::new("cache\x1b[2J")), "cache\\u{1b}[2J");
    }
}
