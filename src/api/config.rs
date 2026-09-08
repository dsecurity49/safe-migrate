use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use super::Error;

/// Per-rule configuration accepted by `safe-migrate.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub(crate) disabled: Option<bool>,
    pub(crate) tier1_threshold_rows: Option<u64>,
    pub(crate) tier2_threshold_rows: Option<u64>,
}

impl RuleConfig {
    /// Start an empty per-rule override.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable this rule without changing its thresholds.
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = Some(disabled);
        self
    }

    /// Override the row thresholds supported by this rule.
    pub fn tier_thresholds(mut self, tier1_rows: Option<u64>, tier2_rows: Option<u64>) -> Self {
        self.tier1_threshold_rows = tier1_rows;
        self.tier2_threshold_rows = tier2_rows;
        self
    }

    /// Return the explicit enabled/disabled override, if one was configured.
    pub fn disabled_override(&self) -> Option<bool> {
        self.disabled
    }

    /// Return the explicit Tier 1 row threshold, if one was configured.
    pub fn tier1_threshold_rows(&self) -> Option<u64> {
        self.tier1_threshold_rows
    }

    /// Return the explicit Tier 2 row threshold, if one was configured.
    pub fn tier2_threshold_rows(&self) -> Option<u64> {
        self.tier2_threshold_rows
    }
}

/// Complete safe-migrate configuration.
///
/// This type is defined by the supported API. Internal engine modules consume
/// it, so configuration behavior does not depend on an implementation type
/// leaking through a re-export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub(crate) tier1_threshold_rows: u64,
    pub(crate) tier2_threshold_rows: u64,
    pub(crate) stale_stats_days: u64,
    pub(crate) toast_width_threshold_bytes: i32,
    pub(crate) default_rows: u64,
    pub(crate) auto_sync: bool,
    pub(crate) cache_encryption: bool,
    pub(crate) rules: BTreeMap<String, RuleConfig>,
    pub(crate) assume_pg_version: u32,
    pub(crate) disabled_rules: Vec<String>,
    pub(crate) schemas: Option<Vec<String>>,
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
            rules: BTreeMap::new(),
            schemas: None,
        }
    }
}

impl Config {
    /// Validate rule IDs, per-rule settings, thresholds, and schema scope.
    ///
    /// # Errors
    ///
    /// Returns a configuration error describing every invalid rule ID or the
    /// first invalid setting.
    pub fn validate(&self) -> Result<(), Error> {
        super::validate_config(self)
    }

    /// Return whether baseline caches are expected to be encrypted.
    pub fn cache_encryption(&self) -> bool {
        self.cache_encryption
    }

    /// Return whether a CLI caller may refresh stale baselines automatically.
    pub fn auto_sync(&self) -> bool {
        self.auto_sync
    }

    /// Return the maximum accepted age of catalog statistics, in days.
    pub fn stale_stats_days(&self) -> u64 {
        self.stale_stats_days
    }

    /// Return the default Tier 1 row threshold.
    pub fn tier1_threshold_rows(&self) -> u64 {
        self.tier1_threshold_rows
    }

    /// Return the default Tier 2 row threshold.
    pub fn tier2_threshold_rows(&self) -> u64 {
        self.tier2_threshold_rows
    }

    /// Return the conservative row estimate used when statistics are absent.
    pub fn default_rows(&self) -> u64 {
        self.default_rows
    }

    /// Return the TOAST-width threshold used by rewrite analysis.
    pub fn toast_width_threshold_bytes(&self) -> i32 {
        self.toast_width_threshold_bytes
    }

    /// Return the PostgreSQL version assumed when no connected baseline provides one.
    ///
    /// The default `100000` is a conservative compatibility fallback, not a
    /// claim that PostgreSQL 10 is supported. A configured value must name a
    /// supported PostgreSQL 14–18 version.
    pub fn assumed_postgres_version(&self) -> u32 {
        self.assume_pg_version
    }

    /// Return the configured schema scope, or `None` for all non-system schemas.
    pub fn schema_scope(&self) -> Option<&[String]> {
        self.schemas.as_deref()
    }

    /// Set whether baseline caches are encrypted.
    pub fn with_cache_encryption(mut self, enabled: bool) -> Self {
        self.cache_encryption = enabled;
        self
    }

    /// Set whether a CLI caller may refresh stale baselines automatically.
    pub fn with_auto_sync(mut self, enabled: bool) -> Self {
        self.auto_sync = enabled;
        self
    }

    /// Set the maximum accepted age of catalog statistics, in days.
    pub fn with_stale_stats_days(mut self, days: u64) -> Self {
        self.stale_stats_days = days;
        self
    }

    /// Set the default row thresholds for Tier 1 and Tier 2 findings.
    pub fn with_tier_thresholds(mut self, tier1_rows: u64, tier2_rows: u64) -> Self {
        self.tier1_threshold_rows = tier1_rows;
        self.tier2_threshold_rows = tier2_rows;
        self
    }

    /// Set the conservative row estimate used when statistics are absent.
    pub fn with_default_rows(mut self, rows: u64) -> Self {
        self.default_rows = rows;
        self
    }

    /// Set the TOAST-width threshold used by rewrite analysis.
    pub fn with_toast_width_threshold_bytes(mut self, bytes: i32) -> Self {
        self.toast_width_threshold_bytes = bytes;
        self
    }

    /// Set the PostgreSQL version assumed when no connected baseline provides one.
    ///
    /// Use a PostgreSQL 14–18 server version number only when the deployment
    /// target is known. [`Config::validate`] rejects unsupported values.
    pub fn with_assumed_postgres_version(mut self, version_num: u32) -> Self {
        self.assume_pg_version = version_num;
        self
    }

    /// Restrict synchronization and analysis to the supplied non-empty schema names.
    pub fn with_schema_scope(
        mut self,
        schemas: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.schemas = Some(schemas.into_iter().map(Into::into).collect());
        self
    }

    /// Synchronize all visible non-system schemas.
    pub fn with_all_non_system_schemas(mut self) -> Self {
        self.schemas = None;
        self
    }

    /// Add or replace a per-rule configuration override.
    pub fn with_rule(mut self, rule_id: impl Into<String>, rule: RuleConfig) -> Self {
        self.rules.insert(rule_id.into(), rule);
        self
    }

    /// Return an explicit per-rule override, if configured.
    pub fn rule_config(&self, rule_id: &str) -> Option<&RuleConfig> {
        self.rules.get(rule_id)
    }

    /// Disable one primary rule by ID.
    pub fn disable_rule(mut self, rule_id: impl Into<String>) -> Self {
        let rule_id = rule_id.into();
        self.disabled_rules.retain(|disabled| disabled != &rule_id);
        self.rules.entry(rule_id).or_default().disabled = Some(true);
        self
    }

    /// Enable one primary rule by ID while preserving its threshold overrides.
    pub fn enable_rule(mut self, rule_id: impl Into<String>) -> Self {
        let rule_id = rule_id.into();
        self.disabled_rules.retain(|disabled| disabled != &rule_id);
        self.rules.entry(rule_id).or_default().disabled = Some(false);
        self
    }

    /// Load a TOML configuration, returning defaults when the file is absent.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when an existing file cannot be read,
    /// parsed, or validated.
    pub fn load_from_file(path: &Path) -> Result<Self, Error> {
        match fs::read_to_string(path) {
            Ok(contents) => Self::parse_file(path, &contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(Error::with_source(
                super::ErrorKind::Configuration,
                format!("failed to read {}", path.display()),
                error,
            )),
        }
    }

    /// Load a TOML configuration and fail when the file is absent.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the file cannot be read, parsed, or
    /// validated.
    pub fn load_required_from_file(path: &Path) -> Result<Self, Error> {
        let contents = fs::read_to_string(path).map_err(|error| {
            Error::with_source(
                super::ErrorKind::Configuration,
                format!("failed to read {}", path.display()),
                error,
            )
        })?;
        Self::parse_file(path, &contents)
    }

    fn parse_file(path: &Path, contents: &str) -> Result<Self, Error> {
        let config: Self = toml::from_str(contents).map_err(|error| {
            Error::with_source(
                super::ErrorKind::Configuration,
                format!("failed to parse {}", path.display()),
                error,
            )
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Return whether a rule is disabled by either configuration form.
    pub fn is_rule_disabled(&self, rule_id: &str) -> bool {
        if self
            .disabled_rules
            .iter()
            .any(|disabled| disabled == rule_id)
        {
            return true;
        }
        self.rules
            .get(rule_id)
            .and_then(|rule| rule.disabled)
            .unwrap_or(false)
    }

    /// Return a rule's effective Tier 1 threshold.
    pub fn rule_tier1_threshold(&self, rule_id: &str) -> u64 {
        self.rules
            .get(rule_id)
            .and_then(|rule| rule.tier1_threshold_rows)
            .unwrap_or(self.tier1_threshold_rows)
    }

    /// Return a rule's effective Tier 2 threshold.
    pub fn rule_tier2_threshold(&self, rule_id: &str) -> u64 {
        self.rules
            .get(rule_id)
            .and_then(|rule| rule.tier2_threshold_rows)
            .unwrap_or(self.tier2_threshold_rows)
    }

    /// Resolve a direct sync's schema scope. Explicit command input wins over
    /// the shared configuration.
    pub(crate) fn sync_schemas<'a>(
        &'a self,
        command_schemas: Option<&'a [String]>,
    ) -> Result<Option<&'a [String]>, Error> {
        let schemas = command_schemas.or(self.schemas.as_deref());
        if schemas.is_some_and(|schemas| {
            schemas.is_empty() || schemas.iter().any(|schema| schema.trim().is_empty())
        }) {
            return Err(Error::configuration(
                "schemas must not be empty and no schema name may be blank",
            ));
        }
        Ok(schemas)
    }

    pub(crate) fn validate_rule_ids<'a>(
        &self,
        primary_rule_ids: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), Error> {
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

        Err(Error::configuration(format!(
            "Unknown primary rule ID(s): {}. Valid primary rule IDs: {}",
            unknown.into_iter().collect::<Vec<_>>().join(", "),
            valid.into_iter().collect::<Vec<_>>().join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn granular_rule_configuration_is_loaded() {
        let mut file = NamedTempFile::new().expect("create temporary config");
        writeln!(
            file,
            r#"
            tier1_threshold_rows = 500000

            [rules.blocking-constraint]
            tier1_threshold_rows = 50000

            [rules.missing-idempotency]
            disabled = true
        "#
        )
        .expect("write temporary config");

        let config = Config::load_from_file(file.path()).expect("load valid config");
        assert_eq!(config.tier1_threshold_rows, 500_000);
        assert_eq!(config.rule_tier1_threshold("blocking-constraint"), 50_000);
        assert_eq!(config.rule_tier1_threshold("unspecified-rule"), 500_000);
        assert!(!config.auto_sync);
        assert!(!config.cache_encryption);
        assert!(config.is_rule_disabled("missing-idempotency"));
        assert!(!config.is_rule_disabled("blocking-constraint"));
    }

    #[test]
    fn command_schema_filter_takes_precedence() {
        let config = Config {
            schemas: Some(vec!["public".to_owned()]),
            ..Config::default()
        };
        let command_schemas = vec!["auth".to_owned()];

        assert_eq!(
            config.sync_schemas(None).unwrap(),
            Some(["public".to_owned()].as_slice())
        );
        assert_eq!(
            config.sync_schemas(Some(&command_schemas)).unwrap(),
            Some(["auth".to_owned()].as_slice())
        );
    }

    #[test]
    fn empty_schema_scope_is_rejected() {
        let config = Config::default();
        assert!(config.sync_schemas(Some(&[])).is_err());
        assert!(config.sync_schemas(Some(&[String::new()])).is_err());
    }

    #[test]
    fn optional_and_required_missing_config_have_distinct_behavior() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.toml");

        assert_eq!(
            Config::load_from_file(&missing)
                .unwrap()
                .tier1_threshold_rows,
            Config::default().tier1_threshold_rows
        );
        assert!(Config::load_required_from_file(&missing).is_err());
    }

    #[test]
    fn unknown_rule_ids_are_reported_together() {
        let mut config = Config::default();
        config
            .rules
            .insert("typo-rule".to_owned(), RuleConfig::default());
        config.disabled_rules = vec!["known-rule".to_owned(), "other-typo".to_owned()];

        let error = config
            .validate_rule_ids(["known-rule"])
            .expect_err("unknown rule IDs must fail validation")
            .to_string();
        assert!(error.contains("other-typo, typo-rule"));
        assert!(error.contains("Valid primary rule IDs: known-rule"));
    }

    #[test]
    fn known_rule_ids_are_accepted() {
        let mut config = Config::default();
        config
            .rules
            .insert("known-rule".to_owned(), RuleConfig::default());
        config.disabled_rules = vec!["known-rule".to_owned()];
        config.validate_rule_ids(["known-rule"]).unwrap();
    }

    #[test]
    fn unknown_configuration_fields_are_rejected() {
        let top_level = toml::from_str::<Config>("auto_syn = true")
            .expect_err("unknown top-level settings must fail")
            .to_string();
        assert!(top_level.contains("unknown field `auto_syn`"));
        assert!(top_level.contains("auto_sync"));

        let per_rule =
            toml::from_str::<Config>("[rules.blocking-constraint]\ntier1_threshold_row = 1")
                .expect_err("unknown per-rule settings must fail")
                .to_string();
        assert!(per_rule.contains("unknown field `tier1_threshold_row`"));
        assert!(per_rule.contains("tier1_threshold_rows"));
    }
}
