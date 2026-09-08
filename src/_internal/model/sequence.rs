use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SequenceKind {
    Standalone,
    Owned,
    SerialLike,
    Identity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SequencePersistence {
    Permanent,
    Temporary,
    Unlogged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SequenceParameters {
    pub data_type: String,
    pub start_value: i64,
    pub increment: i64,
    pub min_value: i64,
    pub max_value: i64,
    pub cache_size: i64,
    pub cycle: bool,
    pub persistence: SequencePersistence,
}

impl Default for SequenceParameters {
    fn default() -> Self {
        Self {
            data_type: "bigint".to_string(),
            start_value: 1,
            increment: 1,
            min_value: 1,
            max_value: i64::MAX,
            cache_size: 1,
            cycle: false,
            persistence: SequencePersistence::Permanent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SequenceState {
    pub id: ObjectId,
    pub owner: ObjectId,
    pub owned_by: Option<(ObjectId, String)>,
    pub kind: SequenceKind,
    pub parameters: SequenceParameters,
    pub generation: u64,
}

// This mirrors the unboxed relation/type overlay API. SequenceState is larger
// because the cache keeps ownership identities inline, while boxing every hot-path
// lookup would add allocation and widespread indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SequenceOverlay {
    Present(SequenceState),
    Dropped,
}
