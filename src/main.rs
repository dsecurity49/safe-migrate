use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use safe_migrate::ast::parse_and_classify;
use safe_migrate::cache::load_cache;
use safe_migrate::config::Config;
use safe_migrate::model::{CacheData, LockTier};
use safe_migrate::rules::evaluate;
use squawk_syntax::ast::SourceFile;
use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "safe-migrate")]
#[command(version)]
#[command(about = "Lint PostgreSQL migrations to prevent blocking locks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Lint a SQL migration file
    Lint {
        /// Path to the SQL migration file
        #[arg(short, long)]
        file: String,

        /// Optional config override
        #[arg(long, default_value = "safe-migrate.toml")]
        config: String,

        /// Path to the JSON cache file
        #[arg(long, default_value = ".safe-migrate-stats.json")]
        cache: String,

        /// Default schema for unqualified tables
        #[arg(short, long, default_value = "public")]
        schema: String,
    },
    /// Sync database table statistics
    Sync {
        /// Path to output the JSON cache file
        #[arg(long, default_value = ".safe-migrate-stats.json")]
        out: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Lint {
            file,
            config,
            cache,
            schema,
        } => {
            let sql = fs::read_to_string(&file)
                .with_context(|| format!("Failed to read migration file: {}", file))?;

            // Load custom TOML rules if they exist
            let cfg = Config::load(&config)?;

            // FIX: Gracefully handle missing cache files, but immediately halt on corrupted JSON
            let cache_data = match load_cache(&cache) {
                Ok(data) => data,
                Err(safe_migrate::error::SafeMigrateError::Io(io_err))
                    if io_err.kind() == std::io::ErrorKind::NotFound =>
                {
                    CacheData {
                        last_updated: 0,
                        tables: HashMap::new(),
                        indexes: HashMap::new(),
                    }
                }
                Err(safe_migrate::error::SafeMigrateError::Io(io_err)) => {
                    return Err(anyhow!("IO Error reading cache: {}", io_err));
                }
                Err(_) => {
                    return Err(anyhow!(
                        "Cache file '{}' exists but is corrupted (Invalid JSON). Run `safe-migrate sync` to rebuild it.",
                        cache
                    ));
                }
            };

            println!("\nAnalyzing migration: {}\n", file);

            // FIX: Warn if the cache is older than 7 days
            if cache_data.last_updated > 0 {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now.saturating_sub(cache_data.last_updated) > 604_800 {
                    println!(
                        "[WARN] Database stats cache (.safe-migrate-stats.json) is over 7 days old!"
                    );
                    println!(
                        "       Run `safe-migrate sync` to ensure accurate lock evaluations.\n"
                    );
                }
            }

            let parse_result = SourceFile::parse(&sql);
            let ops = parse_and_classify(parse_result.tree())?;

            let records = evaluate(&file, ops, &cache_data, &schema, &cfg);

            let mut has_tier1 = false;

            // Top border
            println!("{:-<80}", "");

            for record in &records {
                // Strip all erratic source-code whitespace and perfectly pad each line
                let clean_recipe = record
                    .recipe
                    .lines()
                    .map(|line| line.trim())
                    .collect::<Vec<_>>()
                    .join("\n                                  ");

                match record.tier {
                    LockTier::Tier1 => {
                        has_tier1 = true;
                        println!("[FAIL] [TIER 1 - DANGER ] {}", record.message);
                        println!("                          Rule:   {}", record.rule_name);
                        println!("                          Recipe: {}", clean_recipe);
                    }
                    LockTier::Tier2 => {
                        println!("[WARN] [TIER 2 - WARNING] {}", record.message);
                        println!("                          Rule:   {}", record.rule_name);
                        println!("                          Recipe: {}", clean_recipe);
                    }
                    LockTier::Tier3 => {
                        println!("[ OK ] [TIER 3 - SAFE   ] {}", record.message);
                    }
                }
                // Separator between every evaluated statement
                println!("{:-<80}", "");
            }

            println!(); // Trailing newline for clean terminal output

            if has_tier1 {
                return Err(anyhow!("Migration halted: Tier 1 lock detected."));
            } else if records.iter().all(|r| r.tier == LockTier::Tier3) {
                println!("[PASS] Migration safe to deploy.");
            }
        }
        Commands::Sync { out } => {
            let db_url =
                std::env::var("DATABASE_URL").context("DATABASE_URL must be set to run sync.")?;
            println!("Syncing database stats from {}...", db_url);
            safe_migrate::sync::sync_cache(&db_url, std::path::Path::new(&out))?;
            println!("[ OK ] Cache successfully written to {}", out);
        }
    }

    Ok(())
}
