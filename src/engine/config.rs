// FILE: src/engine/config.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleConfig {
    pub disabled: Option<bool>,
    pub tier1_threshold_rows: Option<u64>,
    pub tier2_threshold_rows: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)] // Allows missing keys in TOML to fall back to Default::default()
pub struct Config {
    pub tier1_threshold_rows: u64,
    pub tier2_threshold_rows: u64,
    pub stale_stats_days: u64,
    pub toast_width_threshold_bytes: i32,
    pub default_rows: u64,           // Fallback for offline/unanalyzed tables
    pub assume_pg_version: u32,      // Fallback for offline PG version
    pub disabled_rules: Vec<String>, // Legacy global array
    pub rules: HashMap<String, RuleConfig>, // NEW: Granular per-rule configs
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tier1_threshold_rows: 100_000,
            tier2_threshold_rows: 10_000,
            stale_stats_days: 7,
            toast_width_threshold_bytes: 2048,
            default_rows: 10_000,
            assume_pg_version: 100000,
            disabled_rules: Vec::new(),
            rules: HashMap::new(),
        }
    }
}

impl Config {
    pub fn load_from_file(path: &Path) -> Self {
        if path.exists()
            && let Ok(contents) = fs::read_to_string(path)
        {
            if let Ok(config) = toml::from_str(&contents) {
                return config;
            } else {
                eprintln!(
                    "[WARN] Failed to parse config at {}. Using defaults.",
                    path.display()
                );
            }
        }
        Self::default()
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

        let config = Config::load_from_file(file.path());

        // Assert Global Overrides
        assert_eq!(config.tier1_threshold_rows, 500_000);

        // Assert Granular Fallbacks
        assert_eq!(config.rule_tier1_threshold("blocking-constraint"), 5000);
        assert_eq!(config.rule_tier1_threshold("unspecified-rule"), 500_000);

        // Assert Rule Disabling
        assert!(config.is_rule_disabled("missing-idempotency"));
        assert!(!config.is_rule_disabled("blocking-constraint"));
    }
}
