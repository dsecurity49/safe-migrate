use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct TypeState {
    pub id: ObjectId,
    pub generation: u64,
    pub owner: ObjectId,
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
        collation: Option<String>,
        collation_id: Option<ObjectId>,
        default: Option<ExprIr>,
        default_text: Option<String>,
        not_null: bool,
        not_null_constraint: Option<String>,
        constraints: BTreeMap<String, DomainConstraintState>,
    },
    /// A user-defined base type. `element` is `pg_type.typelem`, set when the
    /// type stores fixed-length elements; it is what `ALTER TYPE ... ADD
    /// ATTRIBUTE` and the shell-type protocol are written against.
    Base {
        shell: bool,
        options: BaseTypeOptions,
    },
    Composite {
        fields: Vec<CompositeFieldState>,
    },
    /// A range type. Its subtype (`pg_range.rngsubtype`) is what defines it.
    Range {
        subtype: Option<String>,
        /// Derived from `subtype` when a cache enters analysis. Keeping it
        /// out of the cache preserves the stable binary representation.
        #[serde(skip)]
        subtype_id: Option<ObjectId>,
        multirange: Option<ObjectId>,
        collation: Option<String>,
        collation_id: Option<ObjectId>,
        opclass: Option<String>,
        opclass_id: Option<ObjectId>,
        canonical: Option<String>,
        canonical_id: Option<ObjectId>,
        subtype_diff: Option<String>,
        subtype_diff_id: Option<ObjectId>,
    },
    /// PostgreSQL's automatically created companion of a [`TypeKind::Range`]
    /// (`typtype = 'm'`). Renameable independently, so it needs its own row.
    Multirange {
        range: Option<ObjectId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CompositeFieldState {
    pub name: String,
    pub data_type: String,
    /// Derived from `data_type` when a cache enters analysis. Keeping it out
    /// of the cache preserves the stable binary representation.
    #[serde(skip)]
    pub data_type_id: Option<ObjectId>,
    pub collation: Option<String>,
    pub collation_id: Option<ObjectId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DomainConstraintState {
    pub name: String,
    pub expression: Option<ExprIr>,
    pub expression_text: Option<String>,
    pub definition: String,
    pub validated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BaseTypeOptions {
    pub input: Option<String>,
    pub output: Option<String>,
    pub receive: Option<String>,
    pub send: Option<String>,
    pub typmod_in: Option<String>,
    pub typmod_out: Option<String>,
    pub analyze: Option<String>,
    pub subscript: Option<String>,
    pub internallength: Option<BaseTypeLength>,
    pub passed_by_value: Option<bool>,
    pub alignment: Option<String>,
    pub storage: Option<String>,
    pub like: Option<String>,
    pub category: Option<String>,
    pub preferred: Option<bool>,
    pub default: Option<String>,
    pub element: Option<String>,
    pub delimiter: Option<String>,
    pub collatable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum BaseTypeLength {
    Fixed(i16),
    Variable,
}

#[allow(clippy::large_enum_variant)] // Overlay transitions stay allocation-free in the hot state path.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TypeOverlay {
    Present(TypeState),
    Dropped,
}
