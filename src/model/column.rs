use crate::analysis::expr_ir::ExprIr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub data_type: Option<String>,
    pub is_nullable: bool,
    pub default: Option<ExprIr>,
    pub avg_width: Option<i32>,
    /// Raw default expression text from pg_get_expr(), unparsed.
    /// Used for display and heuristic volatility checks without an ExprIr parser.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_expr_text: Option<String>,
    /// Raw type modifier integer from pg_attribute.atttypmod.
    /// Used for precision comparisons (e.g., VARCHAR(n) narrowing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_modifier: Option<i32>,
}
