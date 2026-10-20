use crate::common::*;
use safe_migrate::_internal::analysis::evidence::EvidenceCode;
use safe_migrate::_internal::analysis::state::{AnalysisState, Confidence, RelationOverlay};
use safe_migrate::_internal::ast::identifiers::ObjectId;
use safe_migrate::_internal::engine::engine::SafeMigrateEngine;
use safe_migrate::_internal::model::column::Column;
use safe_migrate::_internal::model::function::{FunctionOverlay, FunctionState, RoutineKind};
use safe_migrate::_internal::model::relation::{
    Persistence, RelationKind, RelationState, ViewUpdatability,
};
use safe_migrate::_internal::report::violations::ViolationTier;
use safe_migrate::api::{Certainty, Config, RuleConfig};

mod object_rules;
mod relation_rules;
