use super::{AnalysisState, MutationResult, ObjectLookup};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::{
    AlterFunctionAction, FuncOptionFact, ParamModeFact, RetTypeFact, SecurityKind, VolatilityKind,
};
use crate::_internal::analysis::graph::{DependencyEdge, DependencyGraph, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterFunctionMutation, AlterProcedureMutation, CreateFunctionMutation, CreateProcedureMutation,
    DropFunctionMutation, DropProcedureMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::function::{
    FunctionOverlay, FunctionState, RoutineKind, SecurityMode, Volatility,
};
use crate::_internal::model::types::{TypeKind, TypeOverlay};
use std::collections::HashSet;

pub(super) type RoutineLookup = ObjectLookup;

/// A routine a drop would take, with the triggers and views that depend on it.
/// A view entry carries the written name when its reference never resolved to
/// a signature, because such a reference matches every overload of the name.
pub(super) type DropTarget = (
    ObjectId,
    Vec<(ObjectId, ObjectId)>,
    Vec<(ObjectId, Option<ObjectId>)>,
);

/// The `RETURNS` clause a routine's declaration spells.
#[derive(Clone, Debug)]
pub(super) enum DeclaredReturn {
    Record,
    Scalar(String),
    Table,
    None,
}

/// `pg_proc`'s view of a routine's result: `prorettype`, plus the descriptor
/// the output parameters define when that type is the anonymous `record`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RoutineResult {
    Void,
    Scalar(String),
    Record(Vec<(Option<String>, String)>),
}

/// The drop command PostgreSQL names in the hint of a replacement error.
pub(super) fn drop_command_for(kind: RoutineKind) -> &'static str {
    match kind {
        RoutineKind::Procedure => "DROP PROCEDURE",
        RoutineKind::Aggregate => "DROP AGGREGATE",
        RoutineKind::Function | RoutineKind::Window => "DROP FUNCTION",
    }
}

impl AnalysisState {
    pub(super) fn routine_lookup(
        &self,
        id: &ObjectId,
        expected: impl Fn(RoutineKind) -> bool,
    ) -> ObjectLookup {
        if self.lookup_shadowed(id) {
            return ObjectLookup::Unknown;
        }
        match self.local.functions.get(id) {
            Some(FunctionOverlay::Present(routine)) if expected(routine.routine_kind) => {
                ObjectLookup::Present
            }
            Some(FunctionOverlay::Present(_)) => ObjectLookup::WrongKind,
            Some(FunctionOverlay::Dropped) => ObjectLookup::Tombstone,
            None if id.schema == "pg_catalog" => {
                let bare = id.name.split('(').next().unwrap_or(id.name.as_str());
                let is_agg = self.local.aggregates.signatures(bare).is_some();
                let is_fn =
                    crate::_internal::model::builtin_routine::is_builtin_pg_catalog_routine(bare);
                if (is_agg && expected(RoutineKind::Aggregate))
                    || (is_fn && (expected(RoutineKind::Function) || expected(RoutineKind::Window)))
                {
                    ObjectLookup::Unknown
                } else if (is_agg || is_fn)
                    && !(expected(RoutineKind::Aggregate)
                        || expected(RoutineKind::Function)
                        || expected(RoutineKind::Window))
                {
                    ObjectLookup::WrongKind
                } else {
                    ObjectLookup::AuthoritativelyAbsent
                }
            }
            None if self.baseline_covers_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Routines,
            ) =>
            {
                ObjectLookup::AuthoritativelyAbsent
            }
            None => ObjectLookup::Unknown,
        }
    }

    /// The return type as `FunctionState` spells it: a scalar type, or the
    /// `TABLE(...)` form `pg_get_function_result` renders.
    pub(super) fn render_routine_return_type(return_type: Option<&RetTypeFact>) -> String {
        return_type
            .map(|return_type| match return_type {
                RetTypeFact::Scalar { ty, .. } => ty.clone(),
                RetTypeFact::Table(columns) => format!(
                    "TABLE({})",
                    columns
                        .iter()
                        .map(|column| {
                            format!(
                                "{} {}",
                                column.name,
                                column.ty.as_deref().unwrap_or("unknown")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
            .unwrap_or_default()
    }

    /// Whether a declaration returns a set, which PostgreSQL records in
    /// `pg_proc.proretset`; `RETURNS TABLE` is set-returning.
    pub(super) fn routine_declares_setof(return_type: Option<&RetTypeFact>) -> bool {
        matches!(
            return_type,
            Some(RetTypeFact::Scalar { setof: true, .. } | RetTypeFact::Table(_))
        )
    }

    /// What PostgreSQL derives from the declaration and its parameters: two or
    /// more output parameters make an anonymous `record`, exactly one makes
    /// that parameter's type, and none leaves the `RETURNS` clause in charge.
    /// A procedure has no clause, so its output parameters alone decide.
    pub(super) fn routine_result(
        kind: RoutineKind,
        parameters: &[crate::_internal::model::function::RoutineParameter],
        declared: DeclaredReturn,
    ) -> RoutineResult {
        let outputs = || {
            parameters
                .iter()
                .filter(|parameter| parameter.mode.is_output())
                .map(|parameter| (parameter.name.clone(), parameter.ty.clone()))
                .collect::<Vec<_>>()
        };
        if kind == RoutineKind::Procedure {
            return if parameters
                .iter()
                .any(|parameter| parameter.mode.is_output())
            {
                RoutineResult::Record(outputs())
            } else {
                RoutineResult::Void
            };
        }
        let outputs = outputs();
        match outputs.len() {
            0 => match declared {
                DeclaredReturn::Record | DeclaredReturn::Table => RoutineResult::Record(Vec::new()),
                DeclaredReturn::Scalar(ty) => RoutineResult::Scalar(ty),
                DeclaredReturn::None => RoutineResult::Void,
            },
            1 if matches!(declared, DeclaredReturn::Record) => RoutineResult::Record(outputs),
            1 => RoutineResult::Scalar(outputs[0].1.clone()),
            _ => RoutineResult::Record(outputs),
        }
    }

    /// Spell every type a result names the way the catalog does, so `int` and
    /// `integer` compare equal.
    pub(super) fn canonicalize_result(
        result: RoutineResult,
        canonical: &impl Fn(&str) -> String,
    ) -> RoutineResult {
        match result {
            RoutineResult::Void => RoutineResult::Void,
            RoutineResult::Scalar(ty) => RoutineResult::Scalar(canonical(&ty)),
            RoutineResult::Record(columns) => RoutineResult::Record(
                columns
                    .into_iter()
                    .map(|(name, ty)| (name, canonical(&ty)))
                    .collect(),
            ),
        }
    }

    /// The declared parameters as `pg_proc` records them: `OUT` parameters and
    /// `RETURNS TABLE` columns included, in declaration order.
    pub(super) fn routine_parameters(
        params: &[crate::_internal::analysis::facts::ParamFact],
        return_type: Option<&RetTypeFact>,
    ) -> Vec<crate::_internal::model::function::RoutineParameter> {
        use crate::_internal::model::function::{ParameterMode, RoutineParameter};
        let mut parameters: Vec<RoutineParameter> = params
            .iter()
            .map(|parameter| RoutineParameter {
                name: parameter.name.clone(),
                mode: match parameter.mode {
                    ParamModeFact::In => ParameterMode::In,
                    ParamModeFact::Out => ParameterMode::Out,
                    ParamModeFact::InOut => ParameterMode::InOut,
                    ParamModeFact::Variadic => ParameterMode::Variadic,
                },
                ty: parameter.ty.clone(),
            })
            .collect();
        // `RETURNS TABLE(a int)` declares output columns the same way, and
        // PostgreSQL records them with the table-column mode after the
        // declared parameters.
        if let Some(RetTypeFact::Table(columns)) = return_type {
            parameters.extend(columns.iter().map(|column| RoutineParameter {
                name: Some(column.name.clone()),
                mode: ParameterMode::Table,
                ty: column.ty.clone().unwrap_or_else(|| "unknown".to_string()),
            }));
        }
        parameters
    }

    /// The parameters that carry a default, counted as `pronargdefaults` is.
    pub(super) fn routine_default_count(
        params: &[crate::_internal::analysis::facts::ParamFact],
        return_type: Option<&RetTypeFact>,
    ) -> u32 {
        let declared = params
            .iter()
            .filter(|parameter| {
                parameter.default.is_some() && !matches!(parameter.mode, ParamModeFact::Out)
            })
            .count();
        let table = match return_type {
            Some(RetTypeFact::Table(columns)) => columns
                .iter()
                .filter(|column| column.default.is_some())
                .count(),
            _ => 0,
        };
        (declared + table) as u32
    }

    /// An existing routine's parameters, or `None` when nothing is known.
    pub(super) fn existing_routine(&self, id: &ObjectId) -> Option<FunctionState> {
        self.local
            .functions
            .get(id)
            .and_then(|overlay| match overlay {
                FunctionOverlay::Present(function) => Some(function.clone()),
                FunctionOverlay::Dropped => None,
            })
    }

    /// The identity constraints `CREATE OR REPLACE` places on an existing
    /// routine. The order and the wording of each rejection follow PostgreSQL.
    pub(super) fn check_routine_replacement(
        &mut self,
        existing: &FunctionState,
        id: &ObjectId,
        params: &[crate::_internal::analysis::facts::ParamFact],
        return_type: Option<&RetTypeFact>,
    ) -> Result<(), MutationResult> {
        let hint = format!(
            "Use {} {} first.",
            drop_command_for(existing.routine_kind),
            id
        );
        let declaration = Self::routine_parameters(params, return_type);

        // A migration may spell a type the way the user wrote it while the
        // catalog reports `format_type`'s spelling, so both sides are reduced
        // through the built-in catalogue before they are compared.
        let canonical = |raw: &str| {
            crate::_internal::analysis::resolver::Resolver::normalize_function_arg_type(
                raw,
                self.builtin_types(),
            )
            .render()
        };
        let declared = match return_type {
            Some(RetTypeFact::Table(_)) => DeclaredReturn::Table,
            Some(RetTypeFact::Scalar { ty, .. }) if canonical(ty) == "record" => {
                DeclaredReturn::Record
            }
            Some(RetTypeFact::Scalar { ty, .. }) => DeclaredReturn::Scalar(ty.clone()),
            None => DeclaredReturn::None,
        };
        let existing_declared = if existing.return_type.is_empty() {
            DeclaredReturn::None
        } else if existing.return_type.starts_with("TABLE(") {
            DeclaredReturn::Table
        } else if existing.return_type == "record" {
            DeclaredReturn::Record
        } else {
            DeclaredReturn::Scalar(existing.return_type.clone())
        };
        let new_result = Self::canonicalize_result(
            Self::routine_result(existing.routine_kind, &declaration, declared),
            &canonical,
        );
        let existing_result = Self::canonicalize_result(
            Self::routine_result(
                existing.routine_kind,
                &existing.parameters,
                existing_declared,
            ),
            &canonical,
        );

        // PostgreSQL reports a changed `prorettype`/`proretset` and a changed
        // output-parameter descriptor as different refusals.
        let category_message = if existing.routine_kind == RoutineKind::Procedure {
            "cannot change whether a procedure has output parameters"
        } else {
            "cannot change return type of existing function"
        };
        let refusal = match (&new_result, &existing_result) {
            _ if Self::routine_declares_setof(return_type) != existing.returns_set => {
                Some(category_message.to_string())
            }
            (RoutineResult::Record(new_columns), RoutineResult::Record(old_columns)) => {
                (new_columns != old_columns).then(|| {
                    "cannot change return type of existing function; \
                     row type defined by OUT parameters is different"
                        .to_string()
                })
            }
            (new_result, existing_result) => {
                (new_result != existing_result).then(|| category_message.to_string())
            }
        };
        if let Some(message) = refusal {
            return Err(MutationResult::conflict(format!("{message}; {hint}")));
        }

        // A parameter that already carries a name keeps it; PostgreSQL allows a
        // formerly unnamed input to be given one.
        let inputs = |parameters: &[crate::_internal::model::function::RoutineParameter]| {
            parameters
                .iter()
                .filter(|parameter| parameter.mode.is_input())
                .map(|parameter| parameter.name.clone())
                .collect::<Vec<_>>()
        };
        let previous_inputs = inputs(&existing.parameters);
        let new_inputs = inputs(&declaration);
        for (position, old_name) in previous_inputs.iter().enumerate() {
            let Some(old_name) = old_name else {
                continue;
            };
            match new_inputs.get(position) {
                Some(Some(new_name)) if new_name == old_name => {}
                _ => {
                    return Err(MutationResult::conflict(format!(
                        "cannot change name of input parameter \"{old_name}\"; {hint}"
                    )));
                }
            }
        }

        // Defaults may be added but never removed, because a call that relied on
        // one would stop resolving.
        let new_defaults = Self::routine_default_count(params, return_type);
        if new_defaults < existing.default_count {
            return Err(MutationResult::conflict(format!(
                "cannot remove parameter defaults from existing function; {hint}"
            )));
        }
        // PostgreSQL then compares the type of each retained default. Default
        // expressions are stored as parse trees only the server can type, so
        // with both sides carrying defaults that comparison is undecidable here
        // rather than assumed to hold.
        if existing.default_count > 0 && new_defaults > 0 {
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
        }
        Ok(())
    }

    pub(super) fn apply_routine_owner_change(
        &mut self,
        id: &ObjectId,
        owner: &crate::_internal::analysis::facts::RoleFact,
    ) -> MutationResult {
        let Some((owner_name, known)) = self.role_fact_identity(owner) else {
            return self.unresolved(EvidenceCode::UnresolvedReference);
        };
        if known && self.local.roles_known && self.present_role(&owner_name).is_none() {
            return MutationResult::conflict(format!("role '{owner_name}' does not exist"));
        }
        if known && !self.local.roles_known {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        self.snapshot_function(id);
        if let Some(FunctionOverlay::Present(existing)) = self.local.functions.get_mut(id) {
            existing.owner = Some(ObjectId::new("", owner_name));
        }
        MutationResult::Applied
    }

    pub(super) fn apply_routine_depends_on_extension(
        &mut self,
        id: &ObjectId,
        extension: &str,
        is_no: bool,
    ) -> MutationResult {
        match self.local.extensions.get(extension) {
            Some(crate::_internal::model::extension::ExtensionOverlay::Present(_)) => {}
            Some(crate::_internal::model::extension::ExtensionOverlay::Dropped) => {
                return MutationResult::conflict(format!(
                    "extension \"{extension}\" does not exist"
                ));
            }
            None if self.baseline_is_available()
                && self.baseline_has_coverage(
                    crate::_internal::db::cache::CatalogFamily::Extensions,
                ) =>
            {
                return MutationResult::conflict(format!(
                    "extension \"{extension}\" does not exist"
                ));
            }
            None => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
        }
        self.snapshot_function(id);
        if let Some(FunctionOverlay::Present(existing)) = self.local.functions.get_mut(id) {
            if is_no {
                existing.dependent_extensions.remove(extension);
            } else {
                existing.dependent_extensions.insert(extension.to_string());
            }
        }
        MutationResult::Applied
    }

    pub(super) fn validate_routine_options(
        &mut self,
        is_procedure: bool,
        returns_set: bool,
        options: &[FuncOptionFact],
    ) -> Result<Vec<ObjectId>, MutationResult> {
        let mut support_functions = Vec::new();
        for option in options {
            if is_procedure
                && matches!(
                    option,
                    FuncOptionFact::Volatility(_)
                        | FuncOptionFact::Strict(_)
                        | FuncOptionFact::Leakproof(_)
                        | FuncOptionFact::Cost(_)
                        | FuncOptionFact::Rows(_)
                        | FuncOptionFact::Support(_)
                        | FuncOptionFact::Parallel(_)
                        | FuncOptionFact::Window
                )
            {
                return Err(MutationResult::conflict(
                    "invalid attribute in procedure definition".to_string(),
                ));
            }
            match option {
                FuncOptionFact::Cost(Some(cost)) if *cost <= 0.0 => {
                    return Err(MutationResult::conflict(
                        "COST must be positive".to_string(),
                    ));
                }
                FuncOptionFact::Rows(rows) => {
                    if let Some(r) = rows
                        && *r <= 0.0
                    {
                        return Err(MutationResult::conflict(
                            "ROWS must be positive".to_string(),
                        ));
                    }
                    if !returns_set {
                        return Err(MutationResult::conflict(
                            "ROWS is not applicable when function does not return a set"
                                .to_string(),
                        ));
                    }
                }
                FuncOptionFact::Parallel(mode) => {
                    if !matches!(
                        mode.to_ascii_lowercase().as_str(),
                        "safe" | "restricted" | "unsafe"
                    ) {
                        return Err(MutationResult::conflict(
                            "parameter \"parallel\" must be SAFE, RESTRICTED, or UNSAFE"
                                .to_string(),
                        ));
                    }
                }
                FuncOptionFact::Support(Some(qname)) => {
                    let bare_name = qname.name.resolve();
                    let sig_name = format!("{bare_name}(internal)");
                    let schema = self.resolve_function_schema(qname, &sig_name);
                    let support_id = ObjectId::new(schema, sig_name);
                    let is_pg_catalog_builtin = qname
                        .schema
                        .as_ref()
                        .is_none_or(|s| s.resolve() == "pg_catalog")
                        && crate::_internal::model::builtin_routine::is_builtin_pg_catalog_support_for_version(
                            &bare_name,
                            self.pg_version_num,
                        );
                    match self.routine_lookup(&support_id, |kind| kind == RoutineKind::Function) {
                        RoutineLookup::Present => {
                            if let Some(FunctionOverlay::Present(support_fn)) =
                                self.local.functions.get(&support_id)
                                && !support_fn.return_type.is_empty()
                                && !support_fn.return_type.eq_ignore_ascii_case("internal")
                            {
                                return Err(MutationResult::conflict(format!(
                                    "support function {bare_name} must return type internal"
                                )));
                            }
                            support_functions.push(support_id);
                        }
                        RoutineLookup::WrongKind | RoutineLookup::Tombstone => {
                            return Err(MutationResult::conflict(format!(
                                "function '{}' does not exist",
                                support_id
                            )));
                        }
                        RoutineLookup::AuthoritativelyAbsent | RoutineLookup::Unknown
                            if is_pg_catalog_builtin => {}
                        RoutineLookup::AuthoritativelyAbsent => {
                            return Err(MutationResult::conflict(format!(
                                "function '{}' does not exist",
                                support_id
                            )));
                        }
                        RoutineLookup::Unknown => {
                            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                        }
                    }
                }
                FuncOptionFact::Set {
                    name,
                    value,
                    from_current_or_default,
                } => {
                    let key = name.to_ascii_lowercase();
                    if key == "transaction_timeout"
                        && self.pg_version_num.unwrap_or(180_000) < 170_000
                    {
                        return Err(MutationResult::conflict(format!(
                            "unrecognized configuration parameter \"{name}\""
                        )));
                    }
                    if matches!(
                        key.as_str(),
                        "statement_timeout"
                            | "lock_timeout"
                            | "idle_in_transaction_session_timeout"
                            | "transaction_timeout"
                    ) {
                        if !*from_current_or_default
                            && !value.as_deref().is_some_and(|v| {
                                crate::_internal::analysis::settings::parse_timeout_ms(v).is_ok()
                            })
                        {
                            return Err(MutationResult::conflict(format!(
                                "invalid value for parameter \"{name}\""
                            )));
                        }
                    } else if !matches!(
                        key.as_str(),
                        "search_path"
                            | "role"
                            | "work_mem"
                            | "temp_buffers"
                            | "maintenance_work_mem"
                            | "client_min_messages"
                            | "log_min_messages"
                            | "timezone"
                            | "datestyle"
                            | "intervalstyle"
                            | "application_name"
                            | "check_function_bodies"
                            | "row_security"
                            | "jit"
                            | "enable_seqscan"
                            | "enable_indexscan"
                            | "enable_bitmapscan"
                            | "enable_hashjoin"
                            | "enable_mergejoin"
                            | "enable_nestloop"
                            | "default_transaction_isolation"
                            | "default_transaction_read_only"
                            | "default_transaction_deferrable"
                    ) {
                        self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                    }
                }
                _ => {}
            }
        }
        Ok(support_functions)
    }

    /// Create or replace a function, enforcing replacement identity rules.
    pub(super) fn apply_create_function(
        &mut self,
        function: &CreateFunctionMutation,
    ) -> MutationResult {
        if let Err(result) = self.ensure_creation_target(&function.id) {
            return result;
        }
        let routine_kind = if function
            .options
            .iter()
            .any(|option| matches!(option, FuncOptionFact::Window))
        {
            RoutineKind::Window
        } else {
            RoutineKind::Function
        };
        match self.routine_lookup(&function.id, |kind| kind == routine_kind) {
            RoutineLookup::Present if !function.or_replace => {
                return MutationResult::conflict(format!(
                    "routine '{}' already exists",
                    function.id
                ));
            }
            // PostgreSQL reports these differently: a plain `CREATE` collides
            // on the routine's identity, while `OR REPLACE` reaches the kind
            // check inside the dependency update.
            RoutineLookup::WrongKind if function.or_replace => {
                return MutationResult::conflict(format!(
                    "cannot change routine kind for '{}'",
                    function.id
                ));
            }
            RoutineLookup::WrongKind => {
                return MutationResult::conflict(format!(
                    "routine '{}' already exists",
                    function.id
                ));
            }
            RoutineLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            _ => {}
        }
        if function.or_replace
            && let Some(existing) = self.existing_routine(&function.id)
            && let Err(result) = self.check_routine_replacement(
                &existing,
                &function.id,
                &function.params,
                function.return_type.as_ref(),
            )
        {
            return result;
        }
        let returns_set = Self::routine_declares_setof(function.return_type.as_ref());
        let support_functions =
            match self.validate_routine_options(false, returns_set, &function.options) {
                Ok(support) => support,
                Err(result) => return result,
            };
        if let Err(result) = self.validate_routine_body(
            false,
            &function.params,
            function.return_type.as_ref(),
            &function.validation_dependencies,
        ) {
            return result;
        }
        self.snapshot_function(&function.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;

        let volatility = function
            .options
            .iter()
            .find_map(|option| match option {
                FuncOptionFact::Volatility(volatility) => Some(match volatility {
                    VolatilityKind::Volatile => Volatility::Volatile,
                    VolatilityKind::Stable => Volatility::Stable,
                    VolatilityKind::Immutable => Volatility::Immutable,
                }),
                _ => None,
            })
            .unwrap_or(Volatility::Volatile);
        let security = function
            .options
            .iter()
            .find_map(|option| match option {
                FuncOptionFact::Security(security) => Some(match security {
                    SecurityKind::Invoker => SecurityMode::Invoker,
                    SecurityKind::Definer => SecurityMode::Definer,
                }),
                _ => None,
            })
            .unwrap_or(SecurityMode::Invoker);
        let language = function
            .options
            .iter()
            .find_map(|option| match option {
                FuncOptionFact::Language(language) => Some(language.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "sql".to_string());

        if function.options.iter().any(Self::function_option_unmodeled) {
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
        }

        // Ownership by a type is a property of the routine's identity, so a
        // replacement keeps it rather than dropping the fact.
        let (internal_type_owner, existing_owner) = match self.local.functions.get(&function.id) {
            Some(FunctionOverlay::Present(existing)) => (
                existing.internal_type_owner.clone(),
                Some(existing.owner.clone()),
            ),
            _ => (None, None),
        };
        let parameters = Self::routine_parameters(&function.params, function.return_type.as_ref());
        self.local.functions.insert(
            function.id.clone(),
            FunctionOverlay::Present(FunctionState {
                id: function.id.clone(),
                internal_type_owner,
                routine_kind,
                arg_types: parameters
                    .iter()
                    .filter(|parameter| parameter.mode.is_input())
                    .map(|parameter| parameter.ty.clone())
                    .collect(),
                arg_type_ids: parameters
                    .iter()
                    .filter(|parameter| parameter.mode.is_input())
                    .map(|parameter| self.resolve_type_reference(&parameter.ty))
                    .collect(),
                return_type: Self::render_routine_return_type(function.return_type.as_ref()),
                return_type_id: function.return_type.as_ref().and_then(|return_type| {
                    match return_type {
                        RetTypeFact::Scalar { ty, .. } => self.resolve_type_reference(ty),
                        RetTypeFact::Table(_) => None,
                    }
                }),
                returns_set: Self::routine_declares_setof(function.return_type.as_ref()),
                parameters,
                default_count: Self::routine_default_count(
                    &function.params,
                    function.return_type.as_ref(),
                ),
                volatility,
                language,
                security,
                aggregate: None,
                owner: existing_owner.unwrap_or_else(|| {
                    self.local
                        .current_role_known
                        .then(|| ObjectId::new("", &self.local.current_role))
                }),
                dependent_extensions: std::collections::BTreeSet::new(),
                support_function: support_functions.last().cloned(),
            }),
        );
        self.record_routine_body_dependencies(&function.id, &function.body_dependencies);
        for support_id in support_functions {
            self.local.graph.add_edge(DependencyEdge::new(
                function.id.clone(),
                support_id,
                DependencyKind::RoutineUsesRoutine {
                    unresolved_name: None,
                },
            ));
        }
        MutationResult::Applied
    }

    /// Apply ALTER FUNCTION changes while keeping the routine's identity.
    pub(super) fn apply_alter_function(
        &mut self,
        function: &AlterFunctionMutation,
    ) -> MutationResult {
        match self.routine_lookup(&function.id, |kind| {
            matches!(
                kind,
                RoutineKind::Function | RoutineKind::Window | RoutineKind::Aggregate
            )
        }) {
            RoutineLookup::Present => {}
            RoutineLookup::WrongKind => {
                return MutationResult::conflict(format!("'{}' is not a function", function.id));
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {
                return MutationResult::conflict(format!(
                    "function '{}' does not exist",
                    function.id
                ));
            }
            RoutineLookup::Unknown if function.id.schema == "pg_catalog" => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            RoutineLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
        }

        match &function.action {
            AlterFunctionAction::OptionsChange(options) => {
                if self
                    .existing_routine(&function.id)
                    .is_some_and(|existing| existing.routine_kind == RoutineKind::Aggregate)
                {
                    return MutationResult::conflict(format!(
                        "'{}' is an aggregate function",
                        function.id
                    ));
                }
                let returns_set = self
                    .existing_routine(&function.id)
                    .is_some_and(|existing| existing.returns_set);
                let support_functions =
                    match self.validate_routine_options(false, returns_set, options) {
                        Ok(support) => support,
                        Err(result) => return result,
                    };
                self.snapshot_function(&function.id);
                if let Some(FunctionOverlay::Present(existing)) =
                    self.local.functions.get_mut(&function.id)
                {
                    for option in options {
                        match option {
                            FuncOptionFact::Volatility(volatility) => {
                                existing.volatility = match volatility {
                                    VolatilityKind::Volatile => Volatility::Volatile,
                                    VolatilityKind::Stable => Volatility::Stable,
                                    VolatilityKind::Immutable => Volatility::Immutable,
                                };
                            }
                            FuncOptionFact::Language(language) => {
                                existing.language = language.clone();
                            }
                            // `SECURITY DEFINER` is stored so the state stays
                            // faithful to the definition, but no rule reads it:
                            // privilege escalation is a runtime property, not a
                            // schema transition, so there is nothing to
                            // conclude from it during analysis.
                            FuncOptionFact::Security(security) => {
                                existing.security = match security {
                                    SecurityKind::Invoker => SecurityMode::Invoker,
                                    SecurityKind::Definer => SecurityMode::Definer,
                                };
                            }
                            _ => {}
                        }
                    }
                }
                if options
                    .iter()
                    .any(|o| matches!(o, FuncOptionFact::Support(_)))
                {
                    let old_support = self.local.functions.get_mut(&function.id).and_then(
                        |overlay| match overlay {
                            FunctionOverlay::Present(existing) => {
                                let prev = existing.support_function.take();
                                existing.support_function = support_functions.last().cloned();
                                prev
                            }
                            _ => None,
                        },
                    );
                    self.snapshot_graph_full();
                    if let Some(prev_id) = old_support {
                        self.local.graph.retain_edges(|edge| {
                            !(edge.dependent == function.id
                                && edge.referenced == prev_id
                                && matches!(edge.kind, DependencyKind::RoutineUsesRoutine { .. }))
                        });
                    }
                    for support_id in support_functions {
                        self.local.graph.add_edge(DependencyEdge::new(
                            function.id.clone(),
                            support_id,
                            DependencyKind::RoutineUsesRoutine {
                                unresolved_name: None,
                            },
                        ));
                    }
                }
                if options.iter().any(Self::function_option_unmodeled) {
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                }
            }
            AlterFunctionAction::Rename { to, .. } => {
                let signature = function
                    .id
                    .name
                    .find('(')
                    .map(|index| &function.id.name[index..])
                    .unwrap_or("");
                let new_id = ObjectId::new(function.id.schema.clone(), format!("{to}{signature}"));
                if let Err(result) = self.validate_function_move(&function.id, &new_id) {
                    return result;
                }
                self.move_function(&function.id, &new_id);
            }
            AlterFunctionAction::SchemaChange { new_schema } => {
                let new_id = ObjectId::new(new_schema.clone(), function.id.name.clone());
                if let Err(result) = self.validate_function_move(&function.id, &new_id) {
                    return result;
                }
                self.move_function(&function.id, &new_id);
            }
            AlterFunctionAction::OwnerChange(owner) => {
                return self.apply_routine_owner_change(&function.id, owner);
            }
            AlterFunctionAction::DependsOnExtension { extension } => {
                return self.apply_routine_depends_on_extension(&function.id, extension, false);
            }
            AlterFunctionAction::NoDependsOnExtension { extension } => {
                return self.apply_routine_depends_on_extension(&function.id, extension, true);
            }
        }
        MutationResult::Applied
    }

    /// Present routines that share a written qualified name.
    pub(crate) fn routine_overloads_under(
        &self,
        name: &ObjectId,
    ) -> impl Iterator<Item = &ObjectId> {
        self.local
            .functions
            .iter()
            .filter_map(move |(id, overlay)| {
                (matches!(overlay, FunctionOverlay::Present(_))
                    && id.schema == name.schema
                    && DependencyGraph::split_routine_signature(id).1 == name.name)
                    .then_some(id)
            })
    }

    pub(super) fn types_requiring_routine(
        &self,
        routine: &ObjectId,
    ) -> Vec<(ObjectId, &'static str)> {
        self.local
            .types
            .iter()
            .filter_map(|(id, overlay)| {
                if self.co_dropped_objects.contains(id) {
                    return None;
                }
                let TypeOverlay::Present(state) = overlay else {
                    return None;
                };
                match &state.kind {
                    TypeKind::Range {
                        canonical_id,
                        subtype_diff_id,
                        ..
                    } => (canonical_id == &Some(routine.clone())
                        || subtype_diff_id == &Some(routine.clone()))
                        .then(|| (id.clone(), "range type")),
                    TypeKind::Base { options, .. }
                        if self.base_type_option_references_routine(options, routine) =>
                    {
                        Some((id.clone(), "base type"))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// Drop routines by identity, honoring dependencies and CASCADE.
    pub(super) fn apply_drop_function(
        &mut self,
        function: &DropFunctionMutation,
    ) -> MutationResult {
        // PostgreSQL resolves every target before applying a multi-target
        // DROP.  Preflight the complete set first so an unknown or invalid
        // later signature cannot leave an earlier function dropped in the
        // simulator when the statement itself would fail.
        let target_ids_in_stmt: HashSet<ObjectId> = function
            .signatures
            .iter()
            .map(|signature| {
                let signature_name = format!(
                    "{}({})",
                    signature.name.name.resolve(),
                    signature.params.join(",")
                );
                let schema = self.resolve_function_schema(&signature.name, &signature_name);
                ObjectId::new(schema, signature_name)
            })
            .collect();
        let mut targets: Vec<DropTarget> = Vec::new();
        let mut cascade_types: Vec<ObjectId> = Vec::new();
        for signature in &function.signatures {
            let signature_name = format!(
                "{}({})",
                signature.name.name.resolve(),
                signature.params.join(",")
            );
            let schema = self.resolve_function_schema(&signature.name, &signature_name);
            let id = ObjectId::new(schema, signature_name);
            if let Some(result) = self.extension_member_drop_conflict(
                crate::_internal::model::extension::ExtensionMemberKind::Routine,
                &id,
                "function",
            ) {
                return result;
            }
            match self.routine_lookup(&id, |kind| {
                matches!(kind, RoutineKind::Function | RoutineKind::Window)
            }) {
                RoutineLookup::WrongKind => {
                    return MutationResult::conflict(format!("function '{}' does not exist", id));
                }
                RoutineLookup::Tombstone if function.if_exists => {}
                RoutineLookup::Tombstone => {
                    return MutationResult::conflict(format!("function '{}' does not exist", id));
                }
                RoutineLookup::AuthoritativelyAbsent if !function.if_exists => {
                    return MutationResult::conflict(format!("function '{}' does not exist", id));
                }
                RoutineLookup::Unknown if id.schema == "pg_catalog" => {
                    return MutationResult::conflict(format!(
                        "cannot drop function {} because it is required by the database system",
                        id.name
                    ));
                }
                RoutineLookup::Unknown => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
                RoutineLookup::Present => {
                    // PostgreSQL created this routine as an internal part of a
                    // type (a range constructor) and refuses to drop it while
                    // that type exists.
                    if let Some(owner) = self.routine_internal_type_owner(&id)
                        && self.type_is_present(owner)
                        && !self.co_dropped_objects.contains(owner)
                    {
                        return MutationResult::conflict(format!(
                            "function '{}' cannot be dropped because type '{}' requires it",
                            id, owner
                        ));
                    }
                    let dependent_types = self.types_requiring_routine(&id);
                    if !dependent_types.is_empty() {
                        if !function.cascade {
                            return MutationResult::conflict(format!(
                                "function '{}' is required by {} '{}'; use CASCADE",
                                id, dependent_types[0].1, dependent_types[0].0
                            ));
                        }
                        cascade_types
                            .extend(dependent_types.into_iter().map(|(type_id, _)| type_id));
                    }
                    let dependent_triggers: Vec<(ObjectId, ObjectId)> = self
                        .local
                        .graph
                        .edges()
                        .iter()
                        .filter_map(|edge| {
                            let DependencyKind::TriggerOnTable { function_id, .. } = &edge.kind
                            else {
                                return None;
                            };
                            // A DROP EXTENSION removes member triggers together
                            // with the function, so they are not external here.
                            (function_id == &id
                                && !self.co_dropped_objects.contains(&edge.dependent))
                            .then(|| (edge.dependent.clone(), edge.referenced.clone()))
                        })
                        .collect();
                    if !dependent_triggers.is_empty() && !function.cascade {
                        return MutationResult::conflict(format!(
                            "function '{}' still has dependent triggers; use CASCADE",
                            id
                        ));
                    }
                    // PostgreSQL refuses the drop because a view depends on the
                    // routine, reporting `view ... depends on function`.
                    let dependent_views: Vec<(ObjectId, Option<ObjectId>)> = self
                        .local
                        .graph
                        .views_for_function(&id)
                        .into_iter()
                        .filter_map(|edge| {
                            let DependencyKind::ViewUsesRoutine { unresolved_name } = &edge.kind
                            else {
                                return None;
                            };
                            (!self.co_dropped_objects.contains(&edge.dependent))
                                .then(|| (edge.dependent.clone(), unresolved_name.clone()))
                        })
                        .collect();
                    if !dependent_views.is_empty() && !function.cascade {
                        // A reference that never resolved names the routine
                        // only; only when another overload shares the name is
                        // it undecidable which one the view calls.
                        let definite = dependent_views.iter().find(|(_, unresolved_name)| {
                            unresolved_name
                                .as_ref()
                                .is_none_or(|name| self.routine_overloads_under(name).count() <= 1)
                        });
                        if let Some((view, _)) = definite {
                            return MutationResult::conflict(format!(
                                "function '{}' is required by view '{}'; use CASCADE",
                                id, view
                            ));
                        }
                        return self.unresolved(EvidenceCode::UnresolvedReference);
                    }
                    let dependent_routines: Vec<ObjectId> = self
                        .local
                        .graph
                        .routines_for_function(&id)
                        .into_iter()
                        .filter(|edge| {
                            !self.co_dropped_objects.contains(&edge.dependent)
                                && !target_ids_in_stmt.contains(&edge.dependent)
                                && matches!(
                                    self.local.functions.get(&edge.dependent),
                                    Some(FunctionOverlay::Present(_))
                                )
                        })
                        .map(|edge| edge.dependent.clone())
                        .collect();
                    if !dependent_routines.is_empty() && !function.cascade {
                        return MutationResult::conflict(format!(
                            "function '{}' is required by routine '{}'; use CASCADE",
                            id, dependent_routines[0]
                        ));
                    }
                    let dependent_casts: Vec<(String, String)> = self
                        .local
                        .casts
                        .casts_using_function(&id)
                        .into_iter()
                        .filter(|(src, dst)| {
                            !self
                                .co_dropped_objects
                                .contains(&ObjectId::new("", format!("{src}->{dst}")))
                        })
                        .collect();
                    if !dependent_casts.is_empty() && !function.cascade {
                        return MutationResult::conflict(format!(
                            "cannot drop function {} because cast from {} to {} requires it; use CASCADE",
                            id, dependent_casts[0].0, dependent_casts[0].1
                        ));
                    }
                    let dependent_stats: Vec<ObjectId> = self
                        .local
                        .graph
                        .statistics_for_function(&id)
                        .into_iter()
                        .filter(|edge| {
                            !self.co_dropped_objects.contains(&edge.dependent)
                                && self.extended_statistics_is_present(&edge.dependent)
                        })
                        .map(|edge| edge.dependent.clone())
                        .collect();
                    if !dependent_stats.is_empty() && !function.cascade {
                        return MutationResult::conflict(format!(
                            "cannot drop function {} because statistics object {} requires it; use CASCADE",
                            id, dependent_stats[0]
                        ));
                    }
                    if !targets.iter().any(|(existing, _, _)| existing == &id) {
                        targets.push((id, dependent_triggers, dependent_views));
                    }
                }
                RoutineLookup::AuthoritativelyAbsent => {}
            }
        }

        if targets.is_empty() {
            return MutationResult::NoOp;
        }

        if self.baseline_is_available() && !self.local.casts.has_full_cast_coverage() {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }

        if targets.iter().any(|(id, _, _)| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Routines,
            )
        }) {
            return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
        }

        let any_applied = !targets.is_empty();
        let dropped_ids: HashSet<ObjectId> = targets.iter().map(|(id, _, _)| id.clone()).collect();
        let mut surviving_reference = false;
        for (id, dependent_triggers, dependent_views) in &targets {
            if function.cascade {
                if self.apply_routine_cascade_drop(
                    id,
                    dependent_triggers,
                    dependent_views,
                    &dropped_ids,
                ) {
                    surviving_reference = true;
                }
            } else {
                self.drop_routine_with_edges(id);
            }
        }
        if !cascade_types.is_empty() {
            cascade_types.sort();
            cascade_types.dedup();
            if !self.apply_type_cascade(&cascade_types) {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        }
        if surviving_reference {
            self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
        }
        if any_applied {
            MutationResult::Applied
        } else {
            MutationResult::NoOp
        }
    }

    /// Create or replace a procedure, recording its parameter identity and attributes.
    pub(super) fn apply_create_procedure(
        &mut self,
        procedure: &CreateProcedureMutation,
    ) -> MutationResult {
        if let Err(result) = self.ensure_creation_target(&procedure.id) {
            return result;
        }
        match self.routine_lookup(&procedure.id, |kind| kind == RoutineKind::Procedure) {
            RoutineLookup::Present if procedure.or_replace => {}
            RoutineLookup::Present | RoutineLookup::WrongKind => {
                return MutationResult::conflict(format!(
                    "routine '{}' already exists",
                    procedure.id
                ));
            }
            RoutineLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {}
        }
        if procedure.or_replace
            && let Some(existing) = self.existing_routine(&procedure.id)
            && let Err(result) =
                self.check_routine_replacement(&existing, &procedure.id, &procedure.params, None)
        {
            return result;
        }
        if let Err(result) = self.validate_routine_options(true, false, &procedure.options) {
            return result;
        }
        if let Err(result) = self.validate_routine_body(
            true,
            &procedure.params,
            None,
            &procedure.validation_dependencies,
        ) {
            return result;
        }
        self.snapshot_function(&procedure.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;

        let volatility = procedure
            .options
            .iter()
            .find_map(|option| match option {
                FuncOptionFact::Volatility(volatility) => Some(match volatility {
                    VolatilityKind::Volatile => Volatility::Volatile,
                    VolatilityKind::Stable => Volatility::Stable,
                    VolatilityKind::Immutable => Volatility::Immutable,
                }),
                _ => None,
            })
            .unwrap_or(Volatility::Volatile);
        let security = procedure
            .options
            .iter()
            .find_map(|option| match option {
                FuncOptionFact::Security(security) => Some(match security {
                    SecurityKind::Invoker => SecurityMode::Invoker,
                    SecurityKind::Definer => SecurityMode::Definer,
                }),
                _ => None,
            })
            .unwrap_or(SecurityMode::Invoker);
        let language = procedure
            .options
            .iter()
            .find_map(|option| match option {
                FuncOptionFact::Language(language) => Some(language.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "sql".to_string());
        if procedure
            .options
            .iter()
            .any(Self::function_option_unmodeled)
        {
            // Procedures share the catalog fields modeled by FunctionState,
            // but their AS body and other function options are not retained.
            // Preserve the useful attributes while making the uncertainty
            // visible to downstream verdicts.
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
        }

        let procedure_parameters = Self::routine_parameters(&procedure.params, None);
        let procedure_declares_outputs = procedure_parameters
            .iter()
            .any(|parameter| parameter.mode.is_output());
        self.local.functions.insert(
            procedure.id.clone(),
            FunctionOverlay::Present(FunctionState {
                id: procedure.id.clone(),
                // PostgreSQL only auto-creates range constructors, never a
                // procedure or aggregate, so neither can be type-owned.
                internal_type_owner: None,
                routine_kind: RoutineKind::Procedure,
                arg_types: procedure_parameters
                    .iter()
                    .filter(|parameter| parameter.mode.is_input())
                    .map(|parameter| parameter.ty.clone())
                    .collect(),
                arg_type_ids: procedure_parameters
                    .iter()
                    .filter(|parameter| parameter.mode.is_input())
                    .map(|parameter| self.resolve_type_reference(&parameter.ty))
                    .collect(),
                // `prorettype` is `void` unless the procedure declares output
                // parameters, which PostgreSQL records as `record`.
                return_type: if procedure_declares_outputs {
                    "record"
                } else {
                    "void"
                }
                .to_string(),
                return_type_id: None,
                returns_set: false,
                parameters: procedure_parameters,
                default_count: Self::routine_default_count(&procedure.params, None),
                volatility,
                language,
                security,
                aggregate: None,
                owner: self
                    .local
                    .functions
                    .get(&procedure.id)
                    .and_then(|overlay| match overlay {
                        FunctionOverlay::Present(existing) => Some(existing.owner.clone()),
                        FunctionOverlay::Dropped => None,
                    })
                    .unwrap_or_else(|| {
                        self.local
                            .current_role_known
                            .then(|| ObjectId::new("", &self.local.current_role))
                    }),
                dependent_extensions: std::collections::BTreeSet::new(),
                support_function: None,
            }),
        );
        self.record_routine_body_dependencies(&procedure.id, &procedure.body_dependencies);
        MutationResult::Applied
    }

    pub(super) fn apply_alter_procedure(
        &mut self,
        procedure: &AlterProcedureMutation,
    ) -> MutationResult {
        match self.routine_lookup(&procedure.id, |kind| kind == RoutineKind::Procedure) {
            RoutineLookup::Present => {}
            RoutineLookup::WrongKind => {
                return MutationResult::conflict(format!("'{}' is not a procedure", procedure.id));
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {
                return MutationResult::conflict(format!(
                    "procedure '{}' does not exist",
                    procedure.id
                ));
            }
            RoutineLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
        }

        match &procedure.action {
            AlterFunctionAction::Rename { to, .. } => {
                let signature = procedure
                    .id
                    .name
                    .find('(')
                    .map(|index| &procedure.id.name[index..])
                    .unwrap_or("");
                let new_id = ObjectId::new(procedure.id.schema.clone(), format!("{to}{signature}"));
                if let Err(result) = self.validate_function_move(&procedure.id, &new_id) {
                    return result;
                }
                self.move_function(&procedure.id, &new_id);
            }
            AlterFunctionAction::SchemaChange { new_schema } => {
                let new_id = ObjectId::new(new_schema.clone(), procedure.id.name.clone());
                if let Err(result) = self.validate_function_move(&procedure.id, &new_id) {
                    return result;
                }
                self.move_function(&procedure.id, &new_id);
            }
            AlterFunctionAction::OptionsChange(options) => {
                if let Err(result) = self.validate_routine_options(true, false, options) {
                    return result;
                }
                self.snapshot_function(&procedure.id);
                if let Some(FunctionOverlay::Present(existing)) =
                    self.local.functions.get_mut(&procedure.id)
                {
                    for option in options {
                        match option {
                            FuncOptionFact::Security(security) => {
                                existing.security = match security {
                                    SecurityKind::Invoker => SecurityMode::Invoker,
                                    SecurityKind::Definer => SecurityMode::Definer,
                                };
                            }
                            FuncOptionFact::Language(language) => {
                                existing.language = language.clone();
                            }
                            _ => {}
                        }
                    }
                }
                if options.iter().any(Self::function_option_unmodeled) {
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                }
            }
            AlterFunctionAction::OwnerChange(owner) => {
                return self.apply_routine_owner_change(&procedure.id, owner);
            }
            AlterFunctionAction::DependsOnExtension { extension } => {
                return self.apply_routine_depends_on_extension(&procedure.id, extension, false);
            }
            AlterFunctionAction::NoDependsOnExtension { extension } => {
                return self.apply_routine_depends_on_extension(&procedure.id, extension, true);
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_drop_procedure(
        &mut self,
        procedure: &DropProcedureMutation,
    ) -> MutationResult {
        let mut targets = Vec::new();
        for signature in &procedure.signatures {
            let signature_name = format!(
                "{}({})",
                signature.name.name.resolve(),
                signature.params.join(",")
            );
            let schema = self.resolve_function_schema(&signature.name, &signature_name);
            let id = ObjectId::new(schema, signature_name);
            if let Some(result) = self.extension_member_drop_conflict(
                crate::_internal::model::extension::ExtensionMemberKind::Routine,
                &id,
                "procedure",
            ) {
                return result;
            }
            match self.routine_lookup(&id, |kind| kind == RoutineKind::Procedure) {
                RoutineLookup::Present => {
                    if !targets.contains(&id) {
                        targets.push(id);
                    }
                }
                RoutineLookup::WrongKind => {
                    return MutationResult::conflict(format!("procedure '{}' does not exist", id));
                }
                RoutineLookup::Tombstone if procedure.if_exists => {}
                RoutineLookup::Tombstone => {
                    return MutationResult::conflict(format!("procedure '{}' does not exist", id));
                }
                RoutineLookup::AuthoritativelyAbsent if !procedure.if_exists => {
                    return MutationResult::conflict(format!("procedure '{}' does not exist", id));
                }
                RoutineLookup::Unknown => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
                RoutineLookup::AuthoritativelyAbsent => {}
            }
        }
        if targets.iter().any(|id| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Routines,
            )
        }) {
            return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
        }
        // PostgreSQL records no dependents of a procedure (CALL is not
        // allowed in atomic bodies and string bodies are untracked), so
        // CASCADE behaves like RESTRICT here.
        for id in &targets {
            let dependent_routines: Vec<ObjectId> = self
                .local
                .graph
                .routines_for_function(id)
                .into_iter()
                .filter(|edge| {
                    !self.co_dropped_objects.contains(&edge.dependent)
                        && !targets.contains(&edge.dependent)
                        && matches!(
                            self.local.functions.get(&edge.dependent),
                            Some(FunctionOverlay::Present(_))
                        )
                })
                .map(|edge| edge.dependent.clone())
                .collect();
            if !dependent_routines.is_empty() && !procedure.cascade {
                return MutationResult::conflict(format!(
                    "procedure '{}' is required by routine '{}'; use CASCADE",
                    id, dependent_routines[0]
                ));
            }
        }
        let dropped_ids: HashSet<ObjectId> = targets.iter().cloned().collect();
        for id in &targets {
            if procedure.cascade {
                let _ = self.apply_routine_cascade_drop(id, &[], &[], &dropped_ids);
            } else {
                self.drop_routine_with_edges(id);
            }
        }
        if !targets.is_empty() {
            MutationResult::Applied
        } else {
            MutationResult::NoOp
        }
    }
}

#[path = "apply_routine/aggregate.rs"]
mod aggregate;
