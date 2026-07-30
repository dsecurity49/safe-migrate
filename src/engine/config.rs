// FILE: src/engine/config.rs
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub disabled: Option<bool>,
    pub tier1_threshold_rows: Option<u64>,
    pub tier2_threshold_rows: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub tier1_threshold_rows: u64,
    pub tier2_threshold_rows: u64,
    pub stale_stats_days: u64,
    pub toast_width_threshold_bytes: i32,
    pub default_rows: u64, // Fallback for offline/unanalyzed tables
    pub auto_sync: bool,
    pub cache_encryption: bool,
    pub rules: HashMap<String, RuleConfig>, // Per-rule configuration
    pub assume_pg_version: u32,
    pub disabled_rules: Vec<String>,
    pub schemas: Option<Vec<String>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tier1_threshold_rows: 100_000,
            tier2_threshold_rows: 10_000,
            stale_stats_days: 7,
            toast_width_threshold_bytes: 2048,
            default_rows: 10_000,
            auto_sync: false,
            cache_encryption: false,
            assume_pg_version: 100000,
            disabled_rules: Vec::new(),
            rules: HashMap::new(),
            schemas: None,
        }
    }
}

impl Config {
    pub fn load_from_file(path: &Path) -> Result<Self, anyhow::Error> {
        if path.exists() {
            let contents = fs::read_to_string(path)?;
            match toml::from_str(&contents) {
                Ok(config) => return Ok(config),
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to parse config at {}: {}",
                        path.display(),
                        e
                    ));
                }
            }
        }
        Ok(Self::default())
    }

    /// Checks if a rule is completely disabled
    pub fn is_rule_disabled(&self, rule_id: &str) -> bool {
        if self.disabled_rules.contains(&rule_id.to_string()) {
            return true;
        }
        self.rules
            .get(rule_id)
            .and_then(|r| r.disabled)
            .unwrap_or(false)
    }

    /// Gets the Tier 1 threshold for a specific rule, falling back to the global default
    pub fn rule_tier1_threshold(&self, rule_id: &str) -> u64 {
        self.rules
            .get(rule_id)
            .and_then(|r| r.tier1_threshold_rows)
            .unwrap_or(self.tier1_threshold_rows)
    }

    /// Gets the Tier 2 threshold for a specific rule, falling back to the global default
    pub fn rule_tier2_threshold(&self, rule_id: &str) -> u64 {
        self.rules
            .get(rule_id)
            .and_then(|r| r.tier2_threshold_rows)
            .unwrap_or(self.tier2_threshold_rows)
    }

    /// Returns the schema filter for a direct sync. An explicit CLI value wins
    /// over the team-wide configuration default.
    pub fn sync_schemas<'a>(
        &'a self,
        cli_schemas: Option<&'a [String]>,
    ) -> Result<Option<&'a [String]>> {
        let schemas = cli_schemas.or(self.schemas.as_deref());
        if schemas.is_some_and(|schemas| {
            schemas.is_empty() || schemas.iter().any(|schema| schema.trim().is_empty())
        }) {
            bail!("schemas must contain at least one non-empty schema name");
        }
        Ok(schemas)
    }

    /// Reject misspelled primary rule IDs instead of silently accepting no-op
    /// configuration. The engine supplies its canonical IDs so this module
    /// does not maintain a second rule catalog.
    pub fn validate_rule_ids<'a>(
        &self,
        primary_rule_ids: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), anyhow::Error> {
        let valid: BTreeSet<String> = primary_rule_ids.into_iter().map(str::to_owned).collect();
        let unknown: BTreeSet<&str> = self
            .rules
            .keys()
            .map(String::as_str)
            .chain(self.disabled_rules.iter().map(String::as_str))
            .filter(|rule_id| !valid.contains(*rule_id))
            .collect();

        if unknown.is_empty() {
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "Unknown primary rule ID(s): {}. Valid primary rule IDs: {}",
            unknown.into_iter().collect::<Vec<_>>().join(", "),
            valid.into_iter().collect::<Vec<_>>().join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_granular_rule_config() {
        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(
            file,
            r#"
            tier1_threshold_rows = 500000

            [rules.blocking-constraint]
            tier1_threshold_rows = 5000

            [rules.missing-idempotency]
            disabled = true
        "#
        )
        .expect("Failed to write temp config");

        let config = Config::load_from_file(file.path()).expect("Failed to load valid config");

        // Assert Global Overrides
        assert_eq!(config.tier1_threshold_rows, 500_000);

        // Assert Granular Fallbacks
        assert_eq!(config.rule_tier1_threshold("blocking-constraint"), 5000);
        assert_eq!(config.rule_tier1_threshold("unspecified-rule"), 500_000);
        assert!(!config.auto_sync);
        assert!(!config.cache_encryption);

        // Assert Rule Disabling
        assert!(config.is_rule_disabled("missing-idempotency"));
        assert!(!config.is_rule_disabled("blocking-constraint"));
    }

    #[test]
    fn test_direct_sync_prefers_cli_schema_filter_over_configured_default() {
        let config = Config {
            schemas: Some(vec!["public".to_string()]),
            ..Config::default()
        };
        let cli_schemas = vec!["auth".to_string()];

        assert_eq!(
            config.sync_schemas(None).unwrap(),
            Some(["public".to_string()].as_slice())
        );
        assert_eq!(
            config.sync_schemas(Some(&cli_schemas)).unwrap(),
            Some(["auth".to_string()].as_slice())
        );
    }

    #[test]
    fn test_direct_sync_rejects_empty_schema_scope() {
        let config = Config::default();
        assert!(config.sync_schemas(Some(&[])).is_err());
        assert!(config.sync_schemas(Some(&["".to_string()])).is_err());
    }

    #[test]
    fn rule_id_validation_rejects_unknown_rule_keys_and_disabled_ids() {
        let mut config = Config::default();
        config
            .rules
            .insert("typo-rule".to_string(), RuleConfig::default());
        config.disabled_rules = vec!["known-rule".to_string(), "other-typo".to_string()];

        let error = config
            .validate_rule_ids(["known-rule"])
            .expect_err("unknown rule IDs must fail validation")
            .to_string();

        assert!(error.contains("other-typo, typo-rule"));
        assert!(error.contains("Valid primary rule IDs: known-rule"));
    }

    #[test]
    fn rule_id_validation_accepts_known_rule_keys_and_disabled_ids() {
        let mut config = Config::default();
        config
            .rules
            .insert("known-rule".to_string(), RuleConfig::default());
        config.disabled_rules = vec!["known-rule".to_string()];

        config
            .validate_rule_ids(["known-rule"])
            .expect("known rule IDs must pass validation");
    }

    #[test]
    fn config_rejects_unknown_top_level_setting() {
        let error = toml::from_str::<Config>("auto_syn = true")
            .expect_err("unknown top-level settings must fail")
            .to_string();

        assert!(error.contains("unknown field `auto_syn`"));
        assert!(error.contains("auto_sync"));
    }

    #[test]
    fn config_rejects_unknown_per_rule_setting() {
        let error =
            toml::from_str::<Config>("[rules.blocking-constraint]\ntier1_threshold_row = 1")
                .expect_err("unknown per-rule settings must fail")
                .to_string();

        assert!(error.contains("unknown field `tier1_threshold_row`"));
        assert!(error.contains("tier1_threshold_rows"));
    }
}
