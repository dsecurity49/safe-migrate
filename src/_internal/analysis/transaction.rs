use crate::_internal::analysis::graph::DependencyEdge;
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::relation::RelationOverlay;
use crate::_internal::model::schema::SchemaOverlay;
use crate::_internal::model::sequence::SequenceOverlay;
use crate::_internal::model::types::TypeOverlay;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct NamespaceSnapshot {
    pub schemas: HashMap<String, SchemaOverlay>,
    pub relations: HashMap<ObjectId, RelationOverlay>,
    pub types: HashMap<ObjectId, TypeOverlay>,
    pub functions: HashMap<ObjectId, crate::_internal::model::function::FunctionOverlay>,
    pub sequences: HashMap<ObjectId, SequenceOverlay>,
    pub publications: HashMap<String, crate::_internal::model::replication::PublicationOverlay>,
    pub triggers: HashMap<ObjectId, crate::_internal::model::trigger::TriggerOverlay>,
    pub constraints: HashMap<(ObjectId, String), crate::_internal::model::constraint::ConstraintState>,
    pub graph: Vec<DependencyEdge>,
    pub pending_validation: HashSet<(ObjectId, String)>,
    pub baseline_relations: HashSet<ObjectId>,
    pub baseline_indexes: HashSet<ObjectId>,
    pub baseline_foreign_keys: HashSet<(ObjectId, String)>,
    pub baseline_fk_dependencies: HashSet<ObjectId>,
    pub baseline_sequences: HashSet<ObjectId>,
    pub scoped_external_relation_dependencies: HashSet<ObjectId>,
    pub scoped_external_type_dependencies: HashSet<ObjectId>,
    pub scoped_external_routine_dependencies: HashSet<ObjectId>,
    pub baseline_schemas: Option<HashSet<String>>,
    pub search_path: Vec<String>,
    pub search_path_template: Vec<String>,
    pub session_search_path_template: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum StateChange {
    SchemaSnapshot {
        name: String,
        previous: Option<SchemaOverlay>,
    },
    NamespaceSnapshot(Box<NamespaceSnapshot>),
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
        previous_template: Vec<String>,
        previous_session_template: Vec<String>,
    },
    TimeoutSettingsSnapshot {
        lock_timeout: crate::_internal::analysis::settings::ScopedSetting<Option<u64>>,
        statement_timeout: crate::_internal::analysis::settings::ScopedSetting<Option<u64>>,
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
        previous: Option<crate::_internal::model::function::FunctionOverlay>,
    },
    PublicationSnapshot {
        id: ObjectId,
        previous: Option<crate::_internal::model::replication::PublicationOverlay>,
    },
    SubscriptionSnapshot {
        id: ObjectId,
        previous: Option<crate::_internal::model::replication::SubscriptionOverlay>,
    },
    RoleSnapshot {
        id: ObjectId,
        previous: Option<crate::_internal::model::role::RoleOverlay>,
    },
    RoleMembershipGrantorsSnapshot {
        previous: Vec<crate::_internal::model::role::RoleMembershipGrantor>,
        previous_complete: bool,
    },
    TriggerSnapshot {
        id: ObjectId,
        previous: Option<crate::_internal::model::trigger::TriggerOverlay>,
    },
    ConstraintSnapshot {
        table_id: ObjectId,
        name: String,
        previous: Option<crate::_internal::model::constraint::ConstraintState>,
    },
    BaselineForeignKeysSnapshot {
        previous: HashSet<(ObjectId, String)>,
    },
    RoleContextSnapshot {
        current_role: String,
        current_role_known: bool,
        persistent_current_role: String,
        persistent_current_role_known: bool,
        session_role: String,
        session_role_known: bool,
        persistent_session_role: String,
        persistent_session_role_known: bool,
    },
    ConfidenceSnapshot {
        previous: crate::_internal::analysis::state::Confidence,
    },
    EvidenceSnapshot {
        previous: crate::_internal::analysis::evidence::EvidenceLog,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionFrameKind {
    Root,
    Savepoint(String),
}

#[derive(Debug, Clone)]
pub struct TransactionFrame {
    pub kind: TransactionFrameKind,
    pub undo_log: Vec<StateChange>,
}

impl TransactionFrame {
    pub fn root() -> Self {
        Self {
            kind: TransactionFrameKind::Root,
            undo_log: Vec::new(),
        }
    }

    pub fn savepoint(name: impl Into<String>) -> Self {
        Self {
            kind: TransactionFrameKind::Savepoint(name.into()),
            undo_log: Vec::new(),
        }
    }

    pub fn is_named_savepoint(&self, name: &str) -> bool {
        matches!(&self.kind, TransactionFrameKind::Savepoint(candidate) if candidate == name)
    }
}
