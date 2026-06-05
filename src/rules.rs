use crate::config::{get_recipe, Config};
use crate::model::{AlterAction, CacheData, LintRecord, LockTier, MigrationOp, SpannedOp};

pub fn evaluate(
    file_path: &str,
    spanned_ops: Vec<SpannedOp>,
    cache: &CacheData,
    default_schema: &str,
    config: &Config,
) -> Vec<LintRecord> {
    let mut records = Vec::new();

    for spanned in spanned_ops {
        let SpannedOp { op, start, end } = spanned;

        let mut evaluate_rule = |rule_key: &str, is_large: bool, base_msg: String| {
            let rule_cfg = config.rules.get(rule_key);
            let tier = if is_large {
                rule_cfg.map(|r| r.tier.clone()).unwrap_or(LockTier::Tier1)
            } else {
                LockTier::Tier3
            };

            let recipe = if rule_cfg.is_some() {
                get_recipe(rule_key).to_string()
            } else {
                String::new()
            };

            records.push(LintRecord {
                file: file_path.to_string(),
                start,
                end,
                tier,
                op: op.clone(),
                message: base_msg,
                rule_name: rule_key.to_string(),
                recipe,
            });
        };

        match &op {
            MigrationOp::Ignored(cmd) => {
                evaluate_rule(
                    "benign-statement",
                    false,
                    format!("Benign statement '{}' is ignored.", cmd),
                );
            }
            MigrationOp::CreateTable(table) => {
                evaluate_rule(
                    "create-table",
                    false,
                    format!(
                        "CREATE TABLE '{}' is safe.",
                        table.canonical_key(default_schema)
                    ),
                );
            }
            MigrationOp::Unknown { reason, .. } => {
                evaluate_rule(
                    "executing-unclassified-statement",
                    true,
                    format!("Unclassified statement: {}", reason),
                );
            }
            MigrationOp::DropTable(table) => {
                let key = table.canonical_key(default_schema);
                let rows = cache
                    .tables
                    .get(&key)
                    .map(|s| s.estimated_rows)
                    .unwrap_or(u64::MAX);
                let threshold = config
                    .rules
                    .get("ban-drop-table")
                    .and_then(|r| r.threshold)
                    .unwrap_or(config.default_threshold);
                evaluate_rule(
                    "ban-drop-table",
                    rows > threshold,
                    format!("Dropping table '{}' (~{} rows).", key, rows),
                );
            }
            MigrationOp::CreateIndex {
                table,
                concurrently,
                ..
            } => {
                let key = table.canonical_key(default_schema);
                let rows = cache
                    .tables
                    .get(&key)
                    .map(|s| s.estimated_rows)
                    .unwrap_or(u64::MAX);
                let threshold = config
                    .rules
                    .get("require-concurrent-index-creation")
                    .and_then(|r| r.threshold)
                    .unwrap_or(config.default_threshold);

                if !concurrently {
                    evaluate_rule(
                        "require-concurrent-index-creation",
                        rows > threshold,
                        format!("Building index on '{}' without CONCURRENTLY.", key),
                    );
                } else {
                    evaluate_rule(
                        "require-concurrent-index-creation",
                        false,
                        format!("Building index on '{}' with CONCURRENTLY is safe.", key),
                    );
                }
            }
            MigrationOp::DropIndex {
                indexes,
                concurrently,
            } => {
                let threshold = config
                    .rules
                    .get("require-concurrent-index-deletion")
                    .and_then(|r| r.threshold)
                    .unwrap_or(config.default_threshold);

                for index in indexes {
                    let key = index.canonical_key(default_schema);
                    let rows = cache
                        .indexes
                        .get(&key)
                        .and_then(|table_key| cache.tables.get(table_key))
                        .map(|s| s.estimated_rows)
                        .unwrap_or(u64::MAX);

                    if !concurrently {
                        evaluate_rule(
                            "require-concurrent-index-deletion",
                            rows > threshold,
                            format!("Dropping index '{}' without CONCURRENTLY.", key),
                        );
                    } else {
                        evaluate_rule(
                            "require-concurrent-index-deletion",
                            false,
                            format!("Dropping index '{}' with CONCURRENTLY is safe.", key),
                        );
                    }
                }
            }
            MigrationOp::AlterTable { table, actions } => {
                let key = table.canonical_key(default_schema);
                let rows = cache
                    .tables
                    .get(&key)
                    .map(|s| s.estimated_rows)
                    .unwrap_or(u64::MAX);

                for action in actions {
                    // Removed the unreachable catch-all so the compiler strictly checks all future variants
                    match action {
                        AlterAction::AddColumn => {
                            let threshold = config
                                .rules
                                .get("adding-field-with-default")
                                .and_then(|r| r.threshold)
                                .unwrap_or(config.default_threshold);
                            evaluate_rule(
                                "adding-field-with-default",
                                rows > threshold,
                                format!(
                                    "Adding column to '{}'. Verify it lacks a VOLATILE default.",
                                    key
                                ),
                            );
                        }
                        AlterAction::AlterColumnUnspecified => {
                            let threshold = config
                                .rules
                                .get("changing-column-type")
                                .and_then(|r| r.threshold)
                                .unwrap_or(config.default_threshold);
                            evaluate_rule(
                                "changing-column-type",
                                rows > threshold,
                                format!("Altering column on '{}'.", key),
                            );
                        }
                        AlterAction::DropColumn => {
                            let threshold = config
                                .rules
                                .get("ban-drop-column")
                                .and_then(|r| r.threshold)
                                .unwrap_or(config.default_threshold);
                            evaluate_rule(
                                "ban-drop-column",
                                rows > threshold,
                                format!("Dropping column from '{}'.", key),
                            );
                        }
                        AlterAction::Other => {
                            evaluate_rule(
                                "executing-unclassified-statement",
                                true,
                                format!("Unclassified ALTER TABLE operation on '{}'.", key),
                            );
                        }
                    }
                }
            }
        }
    }

    records
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parse_and_classify;
    use crate::config::Config;
    use crate::model::{CacheData, CacheEntry};
    use squawk_syntax::ast::SourceFile;
    use std::collections::HashMap;

    fn setup_mock_env() -> (CacheData, Config) {
        let mut tables = HashMap::new();
        tables.insert(
            "public.users".to_string(),
            CacheEntry {
                estimated_rows: 5_000_000,
                relpages: Some(1000),
            },
        );
        tables.insert(
            "public.config".to_string(),
            CacheEntry {
                estimated_rows: 50,
                relpages: Some(1),
            },
        );

        let mut indexes = HashMap::new();
        indexes.insert(
            "public.idx_users_email".to_string(),
            "public.users".to_string(),
        );

        let cache = CacheData {
            last_updated: 0,
            tables,
            indexes,
        };
        let config = Config::default_config();

        (cache, config)
    }

    fn run_lint(sql: &str, cache: &CacheData, config: &Config) -> Vec<LintRecord> {
        let parse_result = SourceFile::parse(sql);
        let ops = parse_and_classify(parse_result.tree()).expect("AST parse failed");
        evaluate("test.sql", ops, cache, "public", config)
    }

    #[test]
    fn test_safe_statements_ignored() {
        let (cache, config) = setup_mock_env();
        let records = run_lint(
            "BEGIN; COMMIT; SET statement_timeout = '2s';",
            &cache,
            &config,
        );
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|r| r.tier == LockTier::Tier3));
    }

    #[test]
    fn test_add_column_large_table_fails() {
        let (cache, config) = setup_mock_env();
        let records = run_lint("ALTER TABLE users ADD COLUMN bio TEXT;", &cache, &config);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tier, LockTier::Tier1);
        assert_eq!(records[0].rule_name, "adding-field-with-default");
    }

    #[test]
    fn test_add_column_small_table_passes() {
        let (cache, config) = setup_mock_env();
        let records = run_lint(
            "ALTER TABLE config ADD COLUMN flag BOOLEAN;",
            &cache,
            &config,
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tier, LockTier::Tier3);
    }

    #[test]
    fn test_drop_index_concurrent_logic() {
        let (cache, config) = setup_mock_env();

        let bad = run_lint("DROP INDEX idx_users_email;", &cache, &config);
        assert_eq!(bad[0].tier, LockTier::Tier2);
        assert_eq!(bad[0].rule_name, "require-concurrent-index-deletion");

        let good = run_lint("DROP INDEX CONCURRENTLY idx_users_email;", &cache, &config);
        assert_eq!(good.len(), 1);
        assert_eq!(good[0].tier, LockTier::Tier3);
    }

    #[test]
    fn test_multi_table_drop_guardrail() {
        let sql = "DROP TABLE users, config;";
        let parse_result = SourceFile::parse(sql);
        let ops = parse_and_classify(parse_result.tree()).expect("AST parse failed");

        assert_eq!(ops.len(), 1);
        match &ops[0].op {
            crate::model::MigrationOp::Unknown { reason, .. } => {
                assert!(reason.contains("Multi-table DROP TABLE is not safely verified"));
            }
            _ => panic!("Parser failed to catch multi-table DROP and output Unknown"),
        }
    }
}
