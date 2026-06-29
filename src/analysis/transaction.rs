// FILE: src/analysis/transaction.rs

use crate::ast::identifiers::ObjectId;
use crate::model::relation::RelationOverlay;
use crate::model::sequence::SequenceOverlay;
use crate::model::types::TypeOverlay;
// Added RenameEdge here to support the new RenameGraphSnapshot
use crate::analysis::graph::{
    ColumnDependencyEdge, FkEdge, IndexEdge, PartitionEdge, PublicationEdge, RenameEdge, SequenceEdge, ViewEdge,
};
// Added HashSet to support the PendingValidationSnapshot
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub enum StateChange {
    RelationSnapshot {
        id: ObjectId,
        previous: Option<RelationOverlay>,
    },
    TypeSnapshot {
        id: ObjectId,
        previous: Option<TypeOverlay>,
    },
    SequenceSnapshot {
        id: ObjectId,
        previous: Option<SequenceOverlay>,
    },
    SearchPathSnapshot {
        previous: Vec<String>,
    },

    // Phase 2 FIX (BUG-001, BUG-002): Transactional integrity for counters and validations
    GenerationCounterSnapshot {
        previous: u64,
    },
    PendingValidationSnapshot {
        previous: HashSet<(ObjectId, String)>,
    },

    FkGraphLengthMarker {
        len: usize,
    },
    FkGraphSnapshot {
        previous: Vec<FkEdge>,
    },
    ViewGraphLengthMarker {
        len: usize,
    },
    ViewGraphSnapshot {
        previous: Vec<ViewEdge>,
    },
    IndexGraphLengthMarker {
        len: usize,
    },
    IndexGraphSnapshot {
        previous: Vec<IndexEdge>,
    },
    RenameGraphLengthMarker {
        len: usize,
    },

    // Phase 2 FIX (BUG-008): Missing snapshot for schema drops
    RenameGraphSnapshot {
        previous: Vec<RenameEdge>,
    },

    SequenceGraphLengthMarker {
        len: usize,
    },
    SequenceGraphSnapshot {
        previous: Vec<SequenceEdge>,
    },
    ColumnGraphLengthMarker {
        len: usize,
    },
    ColumnGraphSnapshot {
        previous: Vec<ColumnDependencyEdge>,
    },
    PartitionGraphMarker {
        len: usize,
    },
    PartitionGraphSnapshot {
        previous: Vec<PartitionEdge>,
    },
    FunctionSnapshot {
        id: ObjectId,
        previous: Option<crate::model::function::FunctionOverlay>,
    },
    PublicationSnapshot {
        id: ObjectId,
        previous: Option<crate::model::replication::PublicationOverlay>,
    },
    SubscriptionSnapshot {
        id: ObjectId,
        previous: Option<crate::model::replication::SubscriptionOverlay>,
    },
    RoleSnapshot {
        id: ObjectId,
        previous: Option<crate::model::role::RoleOverlay>,
    },
    TriggerSnapshot {
        id: ObjectId,
        previous: Option<crate::model::trigger::TriggerOverlay>,
    },
    TriggerGraphSnapshot {
        previous: Vec<crate::analysis::graph::TriggerEdge>,
    },
    PublicationGraphSnapshot {
        previous: Vec<PublicationEdge>,
    },
    CurrentRoleSnapshot {
        previous: String,
    },
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
