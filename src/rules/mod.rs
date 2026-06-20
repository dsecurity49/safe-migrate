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

use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::model::relation::RelationState;
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, MutationResult};
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
        pre_relations: &HashMap<ObjectId, RelationState>,
        state: &AnalysisState, // ENFORCED: Upgraded to pass DB baseline context
        config: &Config
    ) -> Vec<Violation>;
}


