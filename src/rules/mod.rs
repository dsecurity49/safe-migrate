// FILE: src/rules/mod.rs
pub mod constraints;
pub mod destructive;
pub mod expressions;
pub mod idempotency;
pub mod indexes;
pub mod opaque;
pub mod partitions;
pub mod transactions;
pub mod views;

use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::ast::identifiers::ObjectId;
use crate::engine::config::Config;
use crate::model::relation::RelationState;
use crate::report::violations::{Violation, ViolationTier};
use std::collections::HashMap;

pub trait Rule {
    fn id(&self) -> &'static str;
    fn default_tier(&self) -> ViolationTier;
    fn recipe(&self) -> &'static str;

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        pre_relations: &HashMap<ObjectId, RelationState>,
        state: &AnalysisState, // ENFORCED: Upgraded to pass DB baseline context
        config: &Config,
        cascade_closure: Option<&CascadeResult>, // NEW: Orchestrator-managed pre-state
    ) -> Vec<Violation>;
}
