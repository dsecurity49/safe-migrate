use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct TypeState {
    pub id: ObjectId,
    pub generation: u64,
    pub kind: TypeKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum TypeKind {
    Enum {
        variants: Vec<String>,
    },
    Domain {
        base_type: String,
        /// Derived from `base_type` when a cache enters analysis. Keeping it
        /// out of the cache preserves the stable binary representation.
        #[serde(skip)]
        base_type_id: Option<ObjectId>,
    },
    Base,
    Composite {
        fields: Vec<CompositeFieldState>,
    },
    Range,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CompositeFieldState {
    pub name: String,
    pub data_type: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TypeOverlay {
    Present(TypeState),
    Dropped,
}
