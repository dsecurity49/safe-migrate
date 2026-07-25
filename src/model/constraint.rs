use crate::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConstraintKind {
    Check,
    ForeignKey,
    PrimaryKey,
    Unique,
    Exclusion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintState {
    pub table_id: ObjectId,
    pub name: String,
    pub kind: ConstraintKind,
    pub validated: bool,
}
