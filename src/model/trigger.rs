use crate::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriggerState {
    pub id: ObjectId,
    pub table_id: ObjectId,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TriggerOverlay {
    Present(TriggerState),
    Dropped,
}
