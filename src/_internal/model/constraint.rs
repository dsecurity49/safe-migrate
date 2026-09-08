use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ConstraintKind {
    Check,
    ForeignKey,
    PrimaryKey,
    Unique,
    Exclusion,
    NotNull,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConstraintState {
    pub table_id: ObjectId,
    pub name: String,
    pub kind: ConstraintKind,
    pub validated: bool,
    /// PostgreSQL-normalized definition text for constraints whose expression
    /// identity affects inheritance and cloning semantics.
    #[serde(default)]
    pub definition: Option<String>,
    /// The PostgreSQL index adopted by a primary/unique/exclusion
    /// constraint, when catalog evidence provides `pg_constraint.conindid`.
    /// Local constraints and constraint kinds without a backing index retain
    /// `None` until an authoritative identity is available.
    pub backing_index: Option<ObjectId>,
}
