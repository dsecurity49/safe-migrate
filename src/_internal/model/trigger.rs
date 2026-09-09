use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TriggerEnableMode {
    Disabled,
    #[default]
    Origin,
    Replica,
    Always,
}

impl TriggerEnableMode {
    pub(crate) fn from_pg_code(code: &str) -> Option<Self> {
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
pub(crate) struct TriggerState {
    /// PostgreSQL trigger names are scoped to their table, not their schema.
    /// `id` is an internal composite key; retain the display name separately
    /// for matching ALTER/DROP TRIGGER statements and diagnostics.
    pub name: String,
    pub id: ObjectId,
    pub table_id: ObjectId,
    pub function_id: ObjectId,
    #[serde(default)]
    pub row_level: bool,
    /// The parent trigger whose partition clone this trigger represents.
    #[serde(default)]
    pub parent_trigger_id: Option<ObjectId>,
    pub enabled_mode: TriggerEnableMode,
    pub generation: u64,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TriggerOverlay {
    Present(TriggerState),
    Dropped,
}
