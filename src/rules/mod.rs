// FILE: src/rules/mod.rs
pub mod constraints;
pub mod destructive;
pub mod drift;
pub mod expressions;
pub mod functions;
pub mod idempotency;
pub mod indexes;
pub mod opaque;
pub mod partitions;
pub mod policies;
pub mod transactions;
pub mod triggers;
pub mod views;
pub mod security;

use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};

pub trait Rule {
    fn id(&self) -> &'static str;
    fn default_tier(&self) -> ViolationTier;
    fn recipe(&self) -> &'static str;

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        config: &Config,
        cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation>;
}
