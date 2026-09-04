use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub data_type: Option<String>,
    /// Resolved identity for a tracked user-defined type. The display spelling
    /// remains for reports and cache compatibility; state transitions use this
    /// identity so same-named types in different schemas stay distinct.
    #[serde(skip)]
    pub type_id: Option<ObjectId>,
    pub is_nullable: bool,
    pub default: Option<ExprIr>,
    pub avg_width: Option<i32>,
    /// Raw default expression text from pg_get_expr(), unparsed.
    /// Used for display and heuristic volatility checks without an ExprIr parser.
    pub default_expr_text: Option<String>,
    /// Raw type modifier integer from pg_attribute.atttypmod.
    /// For VARCHAR(50), PostgreSQL stores the character limit plus VARHDRSZ: 54.
    pub type_modifier: Option<i32>,
}
