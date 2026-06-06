// src/model/column.rs
use crate::analysis::expr_ir::ExprIr;

#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    pub name: String,
    pub data_type: Option<String>,
    pub default: Option<ExprIr>,
    pub is_nullable: bool,
}
