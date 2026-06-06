// src/rules/mod.rs
use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;

pub mod destructive;

/// The core trait for all static analysis and safety rules.
/// INVARIANT: `state` is strictly read-only (`&AnalysisState`).
pub trait Rule {
    fn evaluate(
        &self, 
        mutation: &Mutation, 
        state: &AnalysisState, 
        reporter: &mut Reporter
    );
}
