use crate::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerEnableMode {
    Disabled,
    #[default]
    Origin,
    Replica,
    Always,
}

impl TriggerEnableMode {
    pub fn from_pg_code(code: &str) -> Option<Self> {
        match code {
            "D" => Some(Self::Disabled),
            "O" => Some(Self::Origin),
            "R" => Some(Self::Replica),
            "A" => Some(Self::Always),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriggerState {
    pub id: ObjectId,
    pub table_id: ObjectId,
    pub enabled_mode: TriggerEnableMode,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TriggerOverlay {
    Present(TriggerState),
    Dropped,
}
