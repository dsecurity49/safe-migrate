// FILE: src/main.rs

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// Simply grab them directly from the root, exactly as you exported them in src/lib.rs!
use safe_migrate::{SafeMigrateEngine, Config, DbCache, AnalysisState, Reporter};
use safe_migrate::sync;

#[derive(Parser, Debug)]
#[command(name = "safe-migrate")]
#[command(version)]
#[command(about = "Lint PostgreSQL migrations to prevent blocking locks", long_about = None)]
struct Cli {
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
    },
    /// Sync database table statistics
    Sync {
        #[arg(long, default_value = ".safe-migrate-stats.json")]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Lint { file, config: config_path, cache } => {
            let sql = fs::read_to_string(&file)
                .with_context(|| format!("Failed to read migration file: {}", file.display()))?;

            // 1. Load config
            // Config::load_from_file will handle missing/invalid files by merging with defaults gracefully
            let cfg = Config::load_from_file(&config_path);

            // 2. Safely Load Cache
            let db_cache = if cache.exists() {
                let json = fs::read_to_string(&cache).context("Failed to read cache file")?;
                serde_json::from_str::<DbCache>(&json).map_err(|_| {
                    anyhow!("Cache file '{}' is corrupted (Invalid JSON). Run `safe-migrate sync` to rebuild it.", cache.display())
                })?
            } else {
                DbCache::new()
            };

            // 3. Cache Expiry Warning
            if let Ok(metadata) = fs::metadata(&cache) {
                if let Ok(modified) = metadata.modified() {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                    let file_time = modified.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                    if now.saturating_sub(file_time) > 604_800 {
                        println!("[WARN] Database stats cache (.safe-migrate-stats.json) is over 7 days old!");
                        println!("       Run `safe-migrate sync` to ensure accurate lock evaluations.\n");
                    }
                }
            }

            println!("\nAnalyzing migration: {}\n", file.display());

            // 4. Initialize Engine and Analyze
            let engine = SafeMigrateEngine::new(cfg);
            let mut state = AnalysisState::new(db_cache);

            match engine.analyze(&sql, &mut state) {
                Ok(violations) => {
                    let should_fail_ci = Reporter::print_report(&violations, &state.local.confidence);

                    if should_fail_ci {
                        return Err(anyhow!("Migration halted: Tier 1 lock detected."));
                    } else {
                        println!("[PASS] Migration safe to deploy.");
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
            let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set to run sync.")?;
            println!("Syncing database stats...");
            sync::sync_cache(&db_url, &out)?;
            println!("[ OK ] Cache successfully written to {}", out.display());
        }
    }

    Ok(())
}
