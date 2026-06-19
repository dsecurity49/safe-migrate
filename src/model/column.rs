// FILE: src/model/column.rs

use serde::{Serialize, Deserialize};
use crate::analysis::expr_ir::ExprIr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub data_type: Option<String>,
    pub is_nullable: bool,
    pub default: Option<ExprIr>,
    pub avg_width: Option<i32>,
}
