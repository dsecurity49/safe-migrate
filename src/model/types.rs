// FILE: ./src/model/types.rs
use crate::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypeState {
    pub id: ObjectId,
    pub generation: u64,
    pub kind: TypeKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TypeKind {
    Enum { variants: Vec<String> },
    Domain { base_type: String },
    Base,
    Composite,
    Range,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypeOverlay {
    Present(TypeState),
    Dropped,
}
