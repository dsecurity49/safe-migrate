// FILE: src/main.rs

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use safe_migrate::sync;
use safe_migrate::{AnalysisState, Config, DbCache, Reporter, SafeMigrateEngine};

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

        #[arg(long, default_value = ".safe-migrate-stats.json")]
        cache: PathBuf,

        /// Bypass the local cache file and evaluate with default worst-case assumptions
        #[arg(long)]
        no_cache: bool,

        /// Output results in JSON format for CI/CD integration
        #[arg(long)]
        json: bool,
    },
    /// Lint a chain of SQL migration files in order (state persists across files)
    LintChain {
        #[arg(short, long)]
        dir: PathBuf,

        #[arg(long, default_value = "safe-migrate.toml")]
        config: PathBuf,

        #[arg(long, default_value = ".safe-migrate-stats.json")]
        cache: PathBuf,

        /// Bypass the local cache file and evaluate with default worst-case assumptions
        #[arg(long)]
        no_cache: bool,

        /// Output results in JSON format for CI/CD integration
        #[arg(long)]
        json: bool,
    },
    /// Sync database table statistics for accurate lock evaluation
    Sync {
        #[arg(long, default_value = ".safe-migrate-stats.json")]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.no_color {
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
    }

    match &cli.command {
        Commands::Lint {
            file,
            config: config_path,
            cache,
            no_cache,
            json: _,
        } => {
            let sql = fs::read_to_string(file)
                .with_context(|| format!("Failed to read migration file: {}", file.display()))?;

            // 1. Load config
            let cfg = Config::load_from_file(config_path).unwrap_or_else(|e| {
                eprintln!("[ERROR] {}", e);
                std::process::exit(1);
            });

            // 2. Cache Expiry Warning (Only if we aren't bypassing it)
            if !*no_cache
                && cache.exists()
                && let Ok(metadata) = fs::metadata(cache)
                && let Ok(modified) = metadata.modified()
            {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let file_time = modified
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now.saturating_sub(604_800) > file_time {
                    println!(
                        "[ WARN ] Database stats cache (.safe-migrate-stats.json) is over 7 days old!"
                    );
                    println!(
                        "         Run `safe-migrate sync` to ensure accurate lock evaluations.\n"
                    );
                }
            }

            // 3. Safely Load Cache OR Fallback to Empty State
            let db_cache = if !*no_cache && cache.exists() {
                let json = fs::read_to_string(cache).context("Failed to read cache file")?;
                serde_json::from_str::<DbCache>(&json).map_err(|_| {
                    anyhow!("Cache file '{}' is corrupted (Invalid JSON). Run `safe-migrate sync` to rebuild it.", cache.display())
                })?
            } else {
                if *no_cache {
                    println!(
                        "[ INFO ] --no-cache passed. Running with default worst-case assumptions."
                    );
                } else {
                    println!(
                        "[ INFO ] No cache found. Running with default worst-case assumptions."
                    );
                }
                DbCache::new() // Pure empty state. No DB connection attempted.
            };

            println!("\nAnalyzing migration: {}\n", file.display());

            // 4. Initialize Engine and Analyze
            let engine = SafeMigrateEngine::new(cfg);
            let mut state = AnalysisState::new(db_cache);

            match engine.analyze(&sql, &mut state) {
                Ok(violations) => {
                    if let Commands::Lint { json: true, .. } = &cli.command {
                        Reporter::print_json_report(&violations, &state.local.confidence);
                        return Ok(());
                    }

                    let should_fail_ci =
                        Reporter::print_report(&violations, &state.local.confidence);

                    if should_fail_ci {
                        return Err(anyhow!("[ HALT ] Migration halted: Tier 1 lock detected."));
                    }
                }
                Err(parse_errors) => {
                    eprintln!("CRITICAL: Failed to parse SQL migration:");
                    for err in parse_errors {
                        eprintln!("  - {}", err);
                    }
                    std::process::exit(1);
                }
            }
        }
        Commands::LintChain {
            dir,
            config: config_path,
            cache,
            no_cache,
            json: _,
        } => {
            let mut files: Vec<_> = fs::read_dir(dir)
                .with_context(|| format!("Failed to read directory: {}", dir.display()))?
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("sql"))
                })
                .collect();
            files.sort_by_key(|e| e.file_name());

            let mut file_pairs = Vec::new();
            for entry in files {
                let path = entry.path();
                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                let sql = fs::read_to_string(&path).with_context(|| {
                    format!("Failed to read migration file: {}", path.display())
                })?;
                file_pairs.push((filename, sql));
            }

            println!("\nAnalyzing migration chain in: {}\n", dir.display());

            let cfg = Config::load_from_file(config_path).unwrap_or_else(|e| {
                eprintln!("[ERROR] {}", e);
                std::process::exit(1);
            });

            let db_cache = if !*no_cache && cache.exists() {
                let json = fs::read_to_string(cache).context("Failed to read cache file")?;
                serde_json::from_str::<DbCache>(&json).map_err(|_| {
                    anyhow!("Cache file '{}' is corrupted (Invalid JSON). Run `safe-migrate sync` to rebuild it.", cache.display())
                })?
            } else {
                if *no_cache {
                    println!(
                        "[ INFO ] --no-cache passed. Running with default worst-case assumptions."
                    );
                } else {
                    println!(
                        "[ INFO ] No cache found. Running with default worst-case assumptions."
                    );
                }
                DbCache::new()
            };

            let engine = SafeMigrateEngine::new(cfg);
            let mut state = AnalysisState::new(db_cache);

            match engine.analyze_chain(&file_pairs, &mut state) {
                Ok(violations) => {
                    if let Commands::LintChain { json: true, .. } = &cli.command {
                        Reporter::print_json_report(&violations, &state.local.confidence);
                        return Ok(());
                    }

                    let should_fail = Reporter::print_report(&violations, &state.local.confidence);

                    if should_fail {
                        return Err(anyhow!(
                            "[ HALT ] Migration chain halted: Tier 1 lock detected."
                        ));
                    }
                }
                Err(parse_errors) => {
                    eprintln!("CRITICAL: Failed to parse SQL migration:");
                    for err in parse_errors {
                        eprintln!("  - {}", err);
                    }
                    std::process::exit(1);
                }
            }
        }
        Commands::Sync { out } => {
            // DATABASE_URL is strictly isolated to the Sync command
            let _db_url = std::env::var("DATABASE_URL")
                .context("DATABASE_URL environment variable must be set to run sync.")?;

            println!("Syncing database stats...");
            sync::sync_cache(out)?; // sync_cache internally uses the env var
            println!("[ SAFE ] Cache successfully written to {}", out.display());
        }
    }

    Ok(())
}
