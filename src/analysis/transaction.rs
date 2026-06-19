// FILE: ./src/analysis/transaction.rs

use crate::ast::identifiers::ObjectId;
use crate::model::relation::RelationOverlay;
use crate::model::types::TypeOverlay;
use crate::model::sequence::SequenceOverlay;
use crate::analysis::graph::{FkEdge, IndexEdge, SequenceEdge, ViewEdge, PartitionEdge};

#[derive(Debug, Clone)]
pub enum StateChange {
    RelationSnapshot { id: ObjectId, previous: Option<RelationOverlay> },
    TypeSnapshot { id: ObjectId, previous: Option<TypeOverlay> },
    SequenceSnapshot { id: ObjectId, previous: Option<SequenceOverlay> },
    SearchPathSnapshot { previous: Vec<String> },
    FkGraphLengthMarker { len: usize },
    FkGraphSnapshot { previous: Vec<FkEdge> },
    ViewGraphLengthMarker { len: usize },
    ViewGraphSnapshot { previous: Vec<ViewEdge> },
    IndexGraphLengthMarker { len: usize },
    IndexGraphSnapshot { previous: Vec<IndexEdge> },
    RenameGraphLengthMarker { len: usize },
    SequenceGraphLengthMarker { len: usize },
    SequenceGraphSnapshot { previous: Vec<SequenceEdge> },
    PartitionGraphLengthMarker { len: usize },
    PartitionGraphSnapshot { previous: Vec<PartitionEdge> },
}

#[derive(Debug, Clone)]
pub struct TransactionFrame {
    pub name: String,
    pub undo_log: Vec<StateChange>,
}

impl TransactionFrame {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            undo_log: Vec::new(),
        }
    }
}
