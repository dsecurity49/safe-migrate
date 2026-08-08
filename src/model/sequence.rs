// FILE: ./src/model/sequence.rs

use crate::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SequenceKind {
    Standalone,
    Owned,
    SerialLike,
    Identity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceState {
    pub id: ObjectId,
    pub owner: ObjectId,
    pub owned_by: Option<(ObjectId, String)>,
    pub kind: SequenceKind,
    pub generation: u64,
}

// This mirrors the unboxed relation/type overlay API. SequenceState is larger
// because V5 keeps ownership identities inline, while boxing every hot-path
// lookup would add allocation and widespread indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum SequenceOverlay {
    Present(SequenceState),
    Dropped,
}
