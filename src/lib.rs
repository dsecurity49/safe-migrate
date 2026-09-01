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
    pub use crate::analysis::evidence::{
        EvidenceCode, EvidenceLocation, EvidenceRecord, EvidenceScope,
    };
    pub use crate::analysis::outcome::AnalysisOutcome;
    pub use crate::engine::config::Config;
    pub use crate::engine::engine::SafeMigrateEngine;
    pub use crate::report::reporter::Reporter;
    pub use crate::{AnalysisState, DbCache};
}
