use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum Volatility {
    Volatile,
    Stable,
    Immutable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum SecurityMode {
    Invoker,
    Definer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) enum RoutineKind {
    #[default]
    Function,
    Procedure,
    Aggregate,
    Window,
}

/// One `pg_proc.proargmodes` entry: how a parameter is passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) enum ParameterMode {
    #[default]
    In,
    Out,
    InOut,
    Variadic,
    /// A `RETURNS TABLE` column, which `proargmodes` spells `t`.
    Table,
}

impl ParameterMode {
    /// Whether the parameter is part of the call signature, which is what
    /// `proargtypes` and `get_func_input_arg_names` collect: `IN`, `INOUT`,
    /// and `VARIADIC`. A `TABLE` column is output only.
    pub(crate) const fn is_input(self) -> bool {
        matches!(self, Self::In | Self::InOut | Self::Variadic)
    }

    /// Whether the parameter contributes a column to the result row, which is
    /// what `build_function_result_tupdesc` collects: `OUT`, `INOUT`, and
    /// `TABLE`.
    pub(crate) const fn is_output(self) -> bool {
        matches!(self, Self::Out | Self::InOut | Self::Table)
    }

    pub(crate) fn from_pg(code: &str) -> Option<Self> {
        Some(match code {
            "i" => Self::In,
            "o" => Self::Out,
            "b" => Self::InOut,
            "v" => Self::Variadic,
            "t" => Self::Table,
            _ => return None,
        })
    }
}

/// One declared parameter, holding the `pg_proc` columns that describe it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RoutineParameter {
    pub name: Option<String>,
    pub mode: ParameterMode,
    pub ty: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FunctionState {
    pub id: ObjectId,
    pub routine_kind: RoutineKind,
    pub arg_types: Vec<String>,
    /// Derived from `arg_types` when a cache enters analysis. Keeping it out
    /// of the cache preserves the stable binary representation.
    #[serde(skip)]
    pub arg_type_ids: Vec<Option<ObjectId>>,
    pub return_type: String,
    /// `pg_proc.proretset`: `RETURNS SETOF`. PostgreSQL refuses a replacement
    /// that changes it, so it must not be folded into the rendered type.
    pub returns_set: bool,
    /// Every declared parameter as `pg_proc` records it, including `OUT`.
    /// `arg_types` holds only the input signature, so the two are read
    /// together: `arg_types` is this list restricted to input parameters.
    pub parameters: Vec<RoutineParameter>,
    /// `pg_proc.pronargdefaults`. A replacement may add defaults but never
    /// remove one.
    pub default_count: u32,

    /// Derived from `return_type` when a cache enters analysis. Keeping it out
    /// of the cache preserves the stable binary representation.
    #[serde(skip)]
    pub return_type_id: Option<ObjectId>,
    pub volatility: Volatility,
    pub language: String,
    pub security: SecurityMode,
    /// Set when `pg_depend` records an internal (`deptype = 'i'`) dependency on
    /// a type, which is how PostgreSQL marks the range constructors it creates
    /// for a range type. The type owns them: dropping the type drops them, and
    /// PostgreSQL refuses to drop them while the type exists.
    pub internal_type_owner: Option<ObjectId>,
}

impl FunctionState {
    /// A routine that declares `arg_types` as unnamed inputs and carries the
    /// catalog defaults for everything else. Deriving `parameters` here keeps
    /// the two from disagreeing about which parameters are inputs.
    #[cfg(test)]
    pub(crate) fn with_inputs(
        id: ObjectId,
        routine_kind: RoutineKind,
        arg_types: Vec<String>,
    ) -> Self {
        let parameters = arg_types
            .iter()
            .map(|ty| RoutineParameter {
                name: None,
                mode: ParameterMode::In,
                ty: ty.clone(),
            })
            .collect();
        Self {
            id,
            routine_kind,
            arg_types,
            arg_type_ids: Vec::new(),
            return_type: String::new(),
            returns_set: false,
            parameters,
            default_count: 0,
            return_type_id: None,
            volatility: Volatility::Volatile,
            language: "sql".to_string(),
            security: SecurityMode::Invoker,
            internal_type_owner: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // Overlay transitions stay allocation-free in the hot state path.
pub(crate) enum FunctionOverlay {
    Present(FunctionState),
    Dropped,
}
