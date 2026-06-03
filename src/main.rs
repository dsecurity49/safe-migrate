use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use postgres::{Client, NoTls};
use serde::{Deserialize, Serialize};
use squawk_linter::{Linter, Rule};
use squawk_syntax::{SourceFile, ast, ast::AstNode};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "safe-migrate")]
#[command(about = "Lint PostgreSQL migrations to prevent blocking locks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Lint a SQL migration file
    Lint {
        #[arg(short, long)]
        file: String,

        /// Optional config override
        #[arg(short, long, default_value = "safe-migrate.toml")]
        config: String,
    },
    /// Sync database table statistics
    Sync,
}

#[derive(Deserialize, Serialize, Debug)]
struct StateFile {
    last_synced_at: u64,
    tables: HashMap<String, u64>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
enum LockTier {
    Tier1, // ACCESS EXCLUSIVE
    Tier2, // SHARE ROW EXCLUSIVE
    Tier3, // Safe
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct RuleConfig {
    tier: LockTier,
    threshold: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct PartialRuleConfig {
    tier: Option<LockTier>,
    threshold: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct PartialConfig {
    default_threshold: Option<u64>,
    rules: Option<HashMap<String, PartialRuleConfig>>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Config {
    default_threshold: u64,
    rules: HashMap<String, RuleConfig>,
}

impl Config {
    fn default_config() -> Self {
        let mut rules = HashMap::new();

        let tier1_rules = [
            "adding-field-with-default",
            "changing-column-type",
            "adding-not-nullable-field",
            "adding-serial-primary-key-field",
            "adding-required-field",
            "renaming-column",
            "renaming-table",
            "disallowed-unique-constraint",
            "ban-drop-table",
            "ban-drop-column",
        ];
        for r in tier1_rules {
            rules.insert(
                r.to_string(),
                RuleConfig {
                    tier: LockTier::Tier1,
                    threshold: None,
                },
            );
        }

        let tier2_rules = [
            "require-concurrent-index-creation",
            "require-concurrent-index-deletion",
            "adding-foreign-key-constraint",
            "constraint-missing-not-valid",
        ];
        for r in tier2_rules {
            rules.insert(
                r.to_string(),
                RuleConfig {
                    tier: LockTier::Tier2,
                    threshold: None,
                },
            );
        }

        Config {
            default_threshold: 1_000_000,
            rules,
        }
    }

    fn load(path: &str) -> Result<Self> {
        let mut config = Self::default_config();
        let path_obj = Path::new(path);

        if path_obj.exists() {
            let contents = fs::read_to_string(path_obj)
                .with_context(|| format!("Failed to read config file at {}", path))?;

            let partial: PartialConfig = toml::from_str(&contents)
                .context("Malformed safe-migrate.toml. Ensure it is valid TOML.")?;

            if let Some(dt) = partial.default_threshold {
                config.default_threshold = dt;
            }
            if let Some(user_rules) = partial.rules {
                for (k, v) in user_rules {
                    let existing = config.rules.get_mut(&k).ok_or_else(|| {
                        anyhow!(
                            "Unknown rule '{}' found in config. Please check for typos.",
                            k
                        )
                    })?;

                    if let Some(t) = v.tier {
                        existing.tier = t;
                    }
                    if let Some(th) = v.threshold {
                        existing.threshold = Some(th);
                    }
                }
            }
        }
        Ok(config)
    }
}

fn get_rule_name(rule: &Rule) -> &'static str {
    match rule {
        Rule::AddingFieldWithDefault => "adding-field-with-default",
        Rule::ChangingColumnType => "changing-column-type",
        Rule::AddingNotNullableField => "adding-not-nullable-field",
        Rule::AddingSerialPrimaryKeyField => "adding-serial-primary-key-field",
        Rule::AddingRequiredField => "adding-required-field",
        Rule::RenamingColumn => "renaming-column",
        Rule::RenamingTable => "renaming-table",
        Rule::DisallowedUniqueConstraint => "disallowed-unique-constraint",
        Rule::BanDropTable => "ban-drop-table",
        Rule::BanDropColumn => "ban-drop-column",
        Rule::RequireConcurrentIndexCreation => "require-concurrent-index-creation",
        Rule::RequireConcurrentIndexDeletion => "require-concurrent-index-deletion",
        Rule::AddingForeignKeyConstraint => "adding-foreign-key-constraint",
        Rule::ConstraintMissingNotValid => "constraint-missing-not-valid",
        _ => "unclassified-rule",
    }
}

fn get_recipe(rule: &Rule) -> &'static str {
    match rule {
        Rule::RequireConcurrentIndexCreation => {
            "Use CREATE INDEX CONCURRENTLY. Note: cannot run inside a transaction block."
        }
        Rule::RequireConcurrentIndexDeletion => "Use DROP INDEX CONCURRENTLY.",
        Rule::AddingFieldWithDefault => {
            "Expand-Contract Pattern:\n  1. Add nullable column.\n  2. Backfill rows in batches.\n  3. Add NOT NULL constraint separately."
        }
        Rule::ChangingColumnType => {
            "Add new column, backfill data, swap references, drop old column."
        }
        Rule::AddingForeignKeyConstraint => {
            "Use ADD CONSTRAINT ... NOT VALID, then VALIDATE CONSTRAINT separately."
        }
        _ => "Review PostgreSQL locking documentation.",
    }
}

struct StmtContext {
    table_name: Option<String>,
    is_concurrent: bool,
}

/// Strictly typed AST extraction using Squawk's native Path and PathSegment nodes
fn extract_context_from_ast(node: &squawk_syntax::SyntaxNode) -> StmtContext {
    let mut ctx = StmtContext {
        table_name: None,
        is_concurrent: false,
    };

    let rel_node = if let Some(alter_stmt) = ast::AlterTable::cast(node.clone()) {
        alter_stmt.relation_name()
    } else if let Some(idx_stmt) = ast::CreateIndex::cast(node.clone()) {
        ctx.is_concurrent = idx_stmt.concurrently_token().is_some();
        idx_stmt.relation_name()
    } else {
        None
    };

    if let Some(rel) = rel_node {
        if let Some(path) = rel.path() {
            // The segment of the top-level path is exactly the table name.
            // If the user wrote "public.users", the qualifier is "public" and the segment is "users".
            if let Some(segment) = path.segment() {
                let mut extracted = None;

                if let Some(name) = segment.name() {
                    extracted = Some(name.syntax().text().to_string());
                } else if let Some(name_ref) = segment.name_ref() {
                    extracted = Some(name_ref.syntax().text().to_string());
                }

                if let Some(name) = extracted {
                    ctx.table_name = Some(
                        name.trim_matches(|c| c == '"' || c == '\'' || c == ' ')
                            .to_string(),
                    );
                }
            }
        }
    }

    ctx
}

struct ViolationReport {
    table: String,
    rows: u64,
    rule_name: &'static str,
    severity: LockTier,
    recipe: &'static str,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Sync => {
            let db_url =
                std::env::var("DATABASE_URL").context("DATABASE_URL must be set to run sync.")?;

            let mut client = Client::connect(&db_url, NoTls)?;
            let mut tables = HashMap::new();

            let query = "SELECT n.nspname || '.' || c.relname, c.reltuples::bigint 
                         FROM pg_class c 
                         JOIN pg_namespace n ON n.oid = c.relnamespace 
                         WHERE c.relkind = 'r' 
                         AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast');";

            for row in client.query(query, &[])? {
                let full_name: String = row.get(0);
                let name = full_name.split('.').last().unwrap();
                let count: i64 = row.get(1);

                tables.insert(
                    name.to_string(),
                    (count.max(0) as u64).max(*tables.get(name).unwrap_or(&0)),
                );
            }

            let state = StateFile {
                last_synced_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                tables,
            };

            fs::write(
                ".safe-migrate-stats.json",
                serde_json::to_string_pretty(&state)?,
            )?;
            println!("[OK] Database statistics synced.");
        }

        Commands::Lint { file, config } => {
            let stats_path = Path::new(".safe-migrate-stats.json");
            if !stats_path.exists() {
                return Err(anyhow!(
                    "Could not find .safe-migrate-stats.json. Please run 'safe-migrate sync' before linting."
                ));
            }

            let cfg = Config::load(config)?;
            let full_sql = fs::read_to_string(file)
                .with_context(|| format!("Failed to read migration file: {}", file))?;

            let state: StateFile = serde_json::from_str(&fs::read_to_string(stats_path)?)
                .context("Failed to parse state file JSON.")?;

            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if now > state.last_synced_at + 604_800 {
                println!("[WARN] Stats are over 7 days old. Run 'safe-migrate sync' to update.\n");
            }

            println!("Analyzing file: {}\n", file);

            let mut reports: Vec<ViolationReport> = Vec::new();
            let mut unclassified_count = 0;
            let mut linter = Linter::with_default_rules();

            let parsed_file = SourceFile::parse(&full_sql);

            for stmt in parsed_file.tree().stmts() {
                let stmt_node = stmt.syntax();
                let stmt_text = stmt_node.text().to_string();

                if stmt_text.trim().is_empty() {
                    continue;
                }

                let ctx = extract_context_from_ast(stmt_node);

                if ctx.table_name.is_none() {
                    unclassified_count += 1;
                }

                let target_table = ctx.table_name.unwrap_or_else(|| "unclassified".to_string());
                let row_count = state.tables.get(&target_table).unwrap_or(&0);

                let stmt_parsed = SourceFile::parse(&stmt_text);
                let violations = linter.lint(&stmt_parsed, &stmt_text);

                for violation in violations {
                    let rule_name = get_rule_name(&violation.code);

                    let rule_cfg = cfg.rules.get(rule_name);
                    let tier = rule_cfg.map(|r| r.tier.clone()).unwrap_or(LockTier::Tier3);
                    let threshold = rule_cfg
                        .and_then(|r| r.threshold)
                        .unwrap_or(cfg.default_threshold);

                    if *row_count > threshold && tier != LockTier::Tier3 {
                        reports.push(ViolationReport {
                            table: target_table.clone(),
                            rows: *row_count,
                            rule_name,
                            severity: tier,
                            recipe: get_recipe(&violation.code),
                        });
                    }
                }
            }

            let fatal_reports: Vec<&ViolationReport> = reports
                .iter()
                .filter(|r| r.severity == LockTier::Tier1)
                .collect();
            let warning_reports: Vec<&ViolationReport> = reports
                .iter()
                .filter(|r| r.severity == LockTier::Tier2)
                .collect();

            if !warning_reports.is_empty() {
                println!("[WARN] Tier 2 Locks Detected (SHARE ROW EXCLUSIVE)");
                for report in warning_reports {
                    println!("  Table: {} (~{} rows)", report.table, report.rows);
                    println!("  Rule:  {}", report.rule_name);
                    println!("  Fix:   {}\n", report.recipe);
                }
            }

            if !fatal_reports.is_empty() {
                let mut msg = String::from(
                    "[HALT] Tier 1 Locks Detected (ACCESS EXCLUSIVE)\nImpact: Table rewrite required. All reads and writes will be blocked.\n\n",
                );

                for report in &fatal_reports {
                    msg.push_str(&format!(
                        "  Table: {} (~{} rows)\n  Rule:  {}\n  Fix:   {}\n\n",
                        report.table, report.rows, report.rule_name, report.recipe
                    ));
                }

                if unclassified_count > 0 {
                    msg.push_str(&format!(
                        "[INFO] {} unclassified statement(s) bypassed lock checks.\n",
                        unclassified_count
                    ));
                }

                return Err(anyhow!(msg));
            }

            if reports.is_empty() {
                println!("[OK] Migration safe to deploy.");
            }

            if unclassified_count > 0 {
                println!(
                    "[INFO] {} unclassified statement(s) bypassed lock checks.",
                    unclassified_count
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use squawk_syntax::SourceFile;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn parse_first_stmt(sql: &str) -> squawk_syntax::SyntaxNode {
        let parsed = SourceFile::parse(sql);
        parsed
            .tree()
            .stmts()
            .next()
            .expect("Failed to parse statement from SQL string")
            .syntax()
            .clone()
    }

    #[test]
    fn test_strict_ast_table_extraction() {
        let node = parse_first_stmt("ALTER TABLE public.users ADD COLUMN bio TEXT;");
        let ctx = extract_context_from_ast(&node);
        assert_eq!(ctx.table_name.unwrap(), "users");

        let node =
            parse_first_stmt("CREATE INDEX CONCURRENTLY idx_email ON public.\"tenants\" (email);");
        let ctx = extract_context_from_ast(&node);
        assert_eq!(ctx.table_name.unwrap(), "tenants");
        assert!(ctx.is_concurrent);
    }

    #[test]
    fn test_rule_mapping() {
        assert_eq!(
            get_rule_name(&Rule::AddingFieldWithDefault),
            "adding-field-with-default"
        );
        assert_eq!(
            get_rule_name(&Rule::RequireConcurrentIndexCreation),
            "require-concurrent-index-creation"
        );
        assert_eq!(get_rule_name(&Rule::BanDropColumn), "ban-drop-column");
    }

    #[test]
    fn test_valid_config_parsing() {
        let mut file = NamedTempFile::new().unwrap();
        let toml = r#"
        default_threshold = 500
        
        [rules.adding-field-with-default]
        tier = "Tier2"
        threshold = 1000
        "#;
        file.write_all(toml.as_bytes()).unwrap();

        let cfg = Config::load(file.path().to_str().unwrap()).unwrap();

        assert_eq!(cfg.default_threshold, 500);

        let rule_cfg = cfg.rules.get("adding-field-with-default").unwrap();
        assert_eq!(rule_cfg.tier, LockTier::Tier2);
        assert_eq!(rule_cfg.threshold, Some(1000));

        let untouched_rule = cfg.rules.get("ban-drop-column").unwrap();
        assert_eq!(untouched_rule.tier, LockTier::Tier1);
        assert_eq!(untouched_rule.threshold, None);
    }

    #[test]
    fn test_malformed_config_fails() {
        let mut file = NamedTempFile::new().unwrap();
        let toml = r#"
        default_threshold = 5000
        
        [rules.ban-drop-colum]
        tier = "Tier3"
        "#;
        file.write_all(toml.as_bytes()).unwrap();

        let result = Config::load(file.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown rule"));
    }
}
