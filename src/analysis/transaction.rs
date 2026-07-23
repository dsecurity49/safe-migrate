// FILE: src/analysis/transaction.rs

use crate::analysis::graph::DependencyEdge;
use crate::ast::identifiers::ObjectId;
use crate::model::relation::RelationOverlay;
use crate::model::sequence::SequenceOverlay;
use crate::model::types::TypeOverlay;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub enum StateChange {
    RelationSnapshot {
        id: ObjectId,
        previous: Box<Option<RelationOverlay>>,
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
    GenerationCounterSnapshot {
        previous: u64,
    },
    PendingValidationSnapshot {
        previous: HashSet<(ObjectId, String)>,
    },
    GraphLengthMarker {
        len: usize,
    },
    GraphSnapshot {
        previous: Vec<DependencyEdge>,
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
    CurrentRoleSnapshot {
        previous: String,
    },
    ConfidenceSnapshot {
        previous: crate::analysis::state::Confidence,
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
