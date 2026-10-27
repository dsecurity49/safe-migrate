use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExtensionState {
    pub name: String,
    pub schema: Option<String>,
    pub version: Option<String>,
    pub relocatable: Option<bool>,
    pub owner: ObjectId,
    pub members: BTreeSet<ExtensionMember>,
    /// True only when every `pg_depend` member class maps to a modeled family
    /// and every member is inside the synchronized scope.
    pub members_complete: bool,
    pub config_tables: Vec<ExtensionConfigTable>,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct ExtensionMember {
    pub kind: ExtensionMemberKind,
    pub id: ObjectId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ExtensionMemberKind {
    Schema,
    Relation,
    Sequence,
    Index,
    Type,
    Routine,
    Constraint,
    Trigger,
    Collation,
    Cast,
    Unmodeled(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExtensionConfigTable {
    pub table: ObjectId,
    pub condition: Option<String>,
}

#[allow(dead_code)] // Consumed by extension transitions.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ExtensionOverlay {
    Present(ExtensionState),
    Dropped,
}
