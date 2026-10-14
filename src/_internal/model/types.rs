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
    /// A user-defined base type. `element` is `pg_type.typelem`, set when the
    /// type stores fixed-length elements; it is what `ALTER TYPE ... ADD
    /// ATTRIBUTE` and the shell-type protocol are written against.
    Base {
        element: Option<String>,
    },
    Composite {
        fields: Vec<CompositeFieldState>,
    },
    /// A range type. Its subtype (`pg_range.rngsubtype`) is what defines it.
    Range {
        subtype: Option<String>,
    },
    /// PostgreSQL's automatically created companion of a [`TypeKind::Range`]
    /// (`typtype = 'm'`). Renameable independently, so it needs its own row.
    Multirange,
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
