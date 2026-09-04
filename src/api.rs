use std::fmt;

pub use crate::_internal::analysis::evidence::{
    EvidenceCode, EvidenceLocation, EvidenceRecord, EvidenceScope,
};
pub use crate::_internal::analysis::outcome::AnalysisOutcome;
pub use crate::_internal::analysis::state::AnalysisState;
pub use crate::_internal::db::cache::DbCache;
pub use crate::_internal::engine::config::Config;
pub use crate::_internal::engine::engine::SafeMigrateEngine;
pub use crate::_internal::report::reporter::Reporter;
pub use crate::_internal::report::violations::ReportFinding;
pub use crate::_internal::rules::RuleCapability;

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
    let mut state = AnalysisState::try_new(cache).map_err(AnalysisError::InvalidCache)?;
    let engine = SafeMigrateEngine::new(config);
    engine
        .analyze_chain_outcome_with_locations(files, &mut state)
        .map_err(AnalysisError::Parse)
}
