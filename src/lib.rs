pub mod analysis;
pub mod ast;
pub mod db;
pub mod engine;
pub mod model;
pub mod report;
pub mod rules;
pub mod sync;
#[cfg(test)]
pub mod sync_tests;
#[cfg(test)]
pub(crate) mod test_support;

pub use analysis::state::AnalysisState;
pub use analysis::{evidence, outcome};
pub use db::cache::DbCache;
pub use engine::config::Config;
pub use engine::engine::SafeMigrateEngine;
pub use report::interactive::run_interactive;
pub use report::reporter::Reporter;

/// Supported library entry points. Internal AST, resolver, state-map, and
/// cache-wire modules remain available for the CLI and integration tests while
/// consumers migrate to this intentionally small façade.
pub mod api {
    use std::fmt;

    pub use crate::analysis::evidence::{
        EvidenceCode, EvidenceLocation, EvidenceRecord, EvidenceScope,
    };
    pub use crate::analysis::outcome::AnalysisOutcome;
    pub use crate::engine::config::Config;
    pub use crate::engine::engine::SafeMigrateEngine;
    pub use crate::report::reporter::Reporter;
    pub use crate::report::violations::ReportFinding;
    pub use crate::rules::RuleCapability;
    pub use crate::{AnalysisState, DbCache};

    /// Stable error boundary for high-level library analysis helpers.
    #[derive(Debug)]
    pub enum AnalysisError {
        InvalidCache(String),
        Parse(Vec<String>),
    }

    impl fmt::Display for AnalysisError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidCache(error) => write!(formatter, "invalid cache: {error}"),
                Self::Parse(errors) => write!(formatter, "analysis failed: {}", errors.join("; ")),
            }
        }
    }

    impl std::error::Error for AnalysisError {}

    /// Analyze one migration using a validated cache and return immutable
    /// findings, confidence, and evidence. The helper owns the mutable state
    /// so callers cannot accidentally bypass cache validation or reuse state
    /// across unrelated analyses.
    pub fn analyze(
        config: Config,
        filename: impl Into<String>,
        sql: impl Into<String>,
        cache: DbCache,
    ) -> Result<AnalysisOutcome<ReportFinding>, AnalysisError> {
        analyze_chain(config, &[(filename.into(), sql.into())], cache)
    }

    /// Analyze an ordered migration chain with a fresh validated baseline.
    pub fn analyze_chain(
        config: Config,
        files: &[(String, String)],
        cache: DbCache,
    ) -> Result<AnalysisOutcome<ReportFinding>, AnalysisError> {
        let mut state =
            crate::AnalysisState::try_new(cache).map_err(AnalysisError::InvalidCache)?;
        let engine = SafeMigrateEngine::new(config);
        engine
            .analyze_chain_outcome_with_locations(files, &mut state)
            .map_err(AnalysisError::Parse)
    }
}

#[cfg(test)]
mod api_tests {
    use super::api;
    use crate::ast::identifiers::ObjectId;
    use crate::model::schema::SchemaState;

    #[test]
    fn high_level_api_owns_validated_state_and_returns_outcome() {
        let outcome = api::analyze(
            api::Config::default(),
            "migration.sql",
            "",
            api::DbCache::new(),
        )
        .expect("valid cache and SQL should analyze");

        assert!(outcome.findings.is_empty());
        assert!(outcome.evidence.is_empty());
    }

    #[test]
    fn high_level_api_rejects_invalid_cache_before_parsing_sql() {
        let mut cache = api::DbCache::new();
        cache.schemas.insert(
            "public".into(),
            SchemaState {
                name: "other".into(),
                owner: ObjectId::new("", "postgres"),
                generation: 0,
            },
        );

        let error = api::analyze(api::Config::default(), "migration.sql", "not sql", cache)
            .expect_err("invalid cache must fail before parsing");
        assert!(matches!(error, api::AnalysisError::InvalidCache(_)));
    }
}
