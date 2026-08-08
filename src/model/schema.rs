use crate::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaState {
    pub name: String,
    pub owner: ObjectId,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SchemaOverlay {
    Present(SchemaState),
    Dropped,
}
