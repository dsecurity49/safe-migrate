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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionState {
    pub id: ObjectId,
    pub arg_types: Vec<String>,
    pub return_type: String,
    pub volatility: Volatility,
    pub language: String,
    pub security: SecurityMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FunctionOverlay {
    Present(FunctionState),
    Dropped,
}