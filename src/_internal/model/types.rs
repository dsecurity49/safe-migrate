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

impl BaseTypeOptions {
    /// Merge updated options into existing options. PostgreSQL updates only the
    /// parameters specified in `ALTER TYPE ... SET (...)`.
    pub(crate) fn merge(&mut self, other: &Self) {
        if other.input.is_some() {
            self.input = other.input.clone();
        }
        if other.output.is_some() {
            self.output = other.output.clone();
        }
        if other.receive.is_some() {
            self.receive = other.receive.clone();
        }
        if other.send.is_some() {
            self.send = other.send.clone();
        }
        if other.typmod_in.is_some() {
            self.typmod_in = other.typmod_in.clone();
        }
        if other.typmod_out.is_some() {
            self.typmod_out = other.typmod_out.clone();
        }
        if other.analyze.is_some() {
            self.analyze = other.analyze.clone();
        }
        if other.subscript.is_some() {
            self.subscript = other.subscript.clone();
        }
        if other.internallength.is_some() {
            self.internallength = other.internallength.clone();
        }
        if other.passed_by_value.is_some() {
            self.passed_by_value = other.passed_by_value;
        }
        if other.alignment.is_some() {
            self.alignment = other.alignment.clone();
        }
        if other.storage.is_some() {
            self.storage = other.storage.clone();
        }
        if other.like.is_some() {
            self.like = other.like.clone();
        }
        if other.category.is_some() {
            self.category = other.category.clone();
        }
        if other.preferred.is_some() {
            self.preferred = other.preferred;
        }
        if other.default.is_some() {
            self.default = other.default.clone();
        }
        if other.element.is_some() {
            self.element = other.element.clone();
        }
        if other.delimiter.is_some() {
            self.delimiter = other.delimiter.clone();
        }
        if other.collatable.is_some() {
            self.collatable = other.collatable;
        }
    }

    /// The routine-valued options PostgreSQL records as dependencies on the
    /// base type. `element` is a type reference, not a routine.
    pub(crate) fn routine_references(&self) -> impl Iterator<Item = &String> {
        [
            &self.input,
            &self.output,
            &self.receive,
            &self.send,
            &self.typmod_in,
            &self.typmod_out,
            &self.analyze,
            &self.subscript,
        ]
        .into_iter()
        .flatten()
    }

    pub(crate) fn routine_references_mut(&mut self) -> impl Iterator<Item = &mut String> {
        [
            &mut self.input,
            &mut self.output,
            &mut self.receive,
            &mut self.send,
            &mut self.typmod_in,
            &mut self.typmod_out,
            &mut self.analyze,
            &mut self.subscript,
        ]
        .into_iter()
        .flatten()
    }
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
