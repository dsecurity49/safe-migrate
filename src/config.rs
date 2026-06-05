use crate::model::LockTier;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RuleConfig {
    pub tier: LockTier,
    pub threshold: Option<u64>,
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
pub struct Config {
    pub default_threshold: u64,
    pub rules: HashMap<String, RuleConfig>,
}

impl Config {
    pub fn default_config() -> Self {
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
            "executing-unclassified-statement", // FIX: Updated naming convention
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
            default_threshold: 100_000,
            rules,
        }
    }

    pub fn load(path: &str) -> Result<Self> {
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

pub fn get_recipe(rule: &str) -> &'static str {
    match rule {
        "require-concurrent-index-creation" => {
            "CREATE INDEX blocks all writes (INSERT/UPDATE/DELETE) to the table.\n\
            Safe Migration:\n\
            1. Use 'CREATE INDEX CONCURRENTLY'.\n\
            2. Remove any surrounding BEGIN/COMMIT blocks, as CONCURRENTLY cannot run inside a transaction."
        }
        "require-concurrent-index-deletion" => {
            "DROP INDEX requires an ACCESS EXCLUSIVE lock, blocking all reads and writes.\n\
            Safe Migration:\n\
            1. Use 'DROP INDEX CONCURRENTLY'.\n\
            2. Remove any surrounding BEGIN/COMMIT blocks."
        }
        "adding-field-with-default" => {
            "Since PostgreSQL 11, adding a column with a constant default is instant. However, volatile defaults (e.g., gen_random_uuid()) will rewrite the entire table.\n\
            Safe Migration (Expand/Contract):\n\
            1. Add the column as nullable.\n\
            2. Backfill existing rows in small batches to avoid long lock durations.\n\
            3. Add a check constraint using NOT VALID to avoid a table scan.\n\
            4. In a separate migration, validate the constraint."
        }
        "adding-not-nullable-field" | "adding-required-field" => {
            "Adding a NOT NULL column without a default will fail or rewrite the table.\n\
            Safe Migration:\n\
            1. Add the column as nullable.\n\
            2. Backfill existing rows in small batches.\n\
            3. Add a check constraint using NOT VALID.\n\
            4. Run VALIDATE CONSTRAINT in a separate migration."
        }
        "changing-column-type" => {
            "Changing a column type rewrites the entire table on disk, holding an ACCESS EXCLUSIVE lock.\n\
            Safe Migration:\n\
            1. Create a new column with the desired type.\n\
            2. Add a trigger to keep the new column in sync with the old one during writes.\n\
            3. Backfill existing data in batches.\n\
            4. Deploy app changes to read/write to the new column.\n\
            5. Drop the old column and rename the new one."
        }
        "renaming-column" => {
            "Renaming a column is instant but breaks concurrent queries using the old name.\n\
            Safe Migration:\n\
            1. Add a new column with the new name.\n\
            2. Add a trigger to sync writes between the old and new columns.\n\
            3. Backfill data in batches.\n\
            4. Deploy your application to use the new column.\n\
            5. Drop the old column."
        }
        "renaming-table" => {
            "Renaming a table is instant but breaks concurrent application queries using the old name.\n\
            Safe Migration:\n\
            1. Rename the table.\n\
            2. Immediately create a VIEW with the old table name pointing to the new table.\n\
            3. Update your application to use the new name.\n\
            4. Drop the view when ready."
        }
        "adding-foreign-key-constraint" | "constraint-missing-not-valid" => {
            "Adding a standard constraint acquires a ShareRowExclusiveLock and triggers a full table scan, blocking concurrent writes.\n\
            Safe Migration:\n\
            1. Add the constraint using the NOT VALID option. This skips the initial integrity check and commits immediately.\n\
            2. In a separate migration, run VALIDATE CONSTRAINT. This checks pre-existing rows without locking out concurrent updates."
        }
        "disallowed-unique-constraint" => {
            "Adding a UNIQUE constraint builds an index using an ACCESS EXCLUSIVE lock, blocking reads and writes.\n\
            Safe Migration:\n\
            1. Create a unique index concurrently: CREATE UNIQUE INDEX CONCURRENTLY idx_name ON table_name (column_name);\n\
            2. Add the unique constraint using the existing index: ALTER TABLE table_name ADD CONSTRAINT const_name UNIQUE USING INDEX idx_name;"
        }
        "adding-serial-primary-key-field" => {
            "Adding a SERIAL PRIMARY KEY rewrites the entire table to generate sequence values and build the index, locking it exclusively.\n\
            Safe Migration:\n\
            1. Add a nullable integer column.\n\
            2. Create a sequence and set the column default to the sequence.\n\
            3. Backfill existing rows in batches.\n\
            4. Create a UNIQUE INDEX CONCURRENTLY.\n\
            5. Add the PRIMARY KEY constraint USING INDEX."
        }
        "ban-drop-table" | "ban-drop-column" => {
            "Dropping data structures requires an ACCESS EXCLUSIVE lock.\n\
            Safe Migration:\n\
            1. Ensure application code completely ignores this object.\n\
            2. Always precede this command with 'SET lock_timeout = '2s';' so busy databases fail gracefully instead of taking down production.\n\
            3. Let the pipeline retry later."
        }
        "benign-statement" => {
            "Standard transactional, session, or DML block. No blocking schema lock required."
        }
        "create-table" => "Creating a new table does not block existing application queries.",
        _ => {
            "This statement triggers an unclassified heavy lock.\n\
            General DB Safety Rules:\n\
            1. Always run DDL with a short timeout (e.g., SET lock_timeout = '2s';).\n\
            2. Avoid running DDL in long-running transactions.\n\
            3. If a table rewrite is unavoidable, schedule downtime or use zero-downtime tools like pg_repack."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let cfg = Config::default_config();
        assert_eq!(cfg.default_threshold, 100_000);
        assert_eq!(
            cfg.rules.get("adding-field-with-default").unwrap().tier,
            LockTier::Tier1
        );
    }

    #[test]
    fn test_valid_toml_override() {
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

        // Untouched rules should remain at defaults
        let untouched = cfg.rules.get("ban-drop-column").unwrap();
        assert_eq!(untouched.tier, LockTier::Tier1);
        assert_eq!(untouched.threshold, None);
    }

    #[test]
    fn test_malformed_config_fails() {
        let mut file = NamedTempFile::new().unwrap();
        let toml = r#"
        default_threshold = 5000

        [rules.typo-fake-rule]
        tier = "Tier3"
        "#;
        file.write_all(toml.as_bytes()).unwrap();

        let result = Config::load(file.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown rule"));
    }
}
