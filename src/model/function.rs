use crate::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Volatility {
    Volatile,
    Stable,
    Immutable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityMode {
    Invoker,
    Definer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutineKind {
    #[default]
    Function,
    Procedure,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionState {
    pub id: ObjectId,
    /// Synchronized entries are functions; this distinguishes procedures
    /// created during the analyzed migration chain.
    #[serde(skip, default)]
    pub routine_kind: RoutineKind,
    pub arg_types: Vec<String>,
    /// Derived from `arg_types` when a cache enters analysis. Keeping it out
    /// of the cache preserves the stable binary representation.
    #[serde(skip)]
    pub arg_type_ids: Vec<Option<ObjectId>>,
    pub return_type: String,
    /// Derived from `return_type` when a cache enters analysis. Keeping it out
    /// of the cache preserves the stable binary representation.
    #[serde(skip)]
    pub return_type_id: Option<ObjectId>,
    pub volatility: Volatility,
    pub language: String,
    pub security: SecurityMode,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // Overlay transitions stay allocation-free in the hot state path.
pub enum FunctionOverlay {
    Present(FunctionState),
    Dropped,
}
