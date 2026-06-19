// FILE: ./src/model/sequence.rs

use crate::ast::identifiers::ObjectId;

#[derive(Debug, Clone, PartialEq)]
pub struct SequenceState {
    pub id: ObjectId,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SequenceOverlay {
    Present(SequenceState),
    Dropped,
}
