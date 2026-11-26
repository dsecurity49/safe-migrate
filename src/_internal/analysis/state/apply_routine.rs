use super::{AnalysisState, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::{
    AlterFunctionAction, FuncOptionFact, ParamModeFact, RetTypeFact, SecurityKind, VolatilityKind,
};
use crate::_internal::analysis::graph::{DependencyEdge, DependencyGraph, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterAggregateMutation, AlterFunctionMutation, AlterProcedureMutation, AlterRoutineMutation,
    CreateAggregateMutation, CreateFunctionMutation, CreateProcedureMutation,
    DropAggregateMutation, DropFunctionMutation, DropProcedureMutation, DropRoutineMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::function::{
    FunctionOverlay, FunctionState, RoutineKind, SecurityMode, Volatility,
};
use crate::_internal::model::trigger::TriggerOverlay;
use crate::_internal::model::types::{TypeKind, TypeOverlay};
use std::collections::HashSet;

type RoutineLookup = ObjectLookup;

/// A routine a drop would take, with the triggers and views that depend on it.
/// A view entry carries the written name when its reference never resolved to
/// a signature, because such a reference matches every overload of the name.
type DropTarget = (
    ObjectId,
    Vec<(ObjectId, ObjectId)>,
    Vec<(ObjectId, Option<ObjectId>)>,
);

/// The `RETURNS` clause a routine's declaration spells.
#[derive(Clone, Debug)]
enum DeclaredReturn {
    Record,
    Scalar(String),
    Table,
    None,
}

/// `pg_proc`'s view of a routine's result: `prorettype`, plus the descriptor
/// the output parameters define when that type is the anonymous `record`.
#[derive(Debug, PartialEq, Eq)]
enum RoutineResult {
    Void,
    Scalar(String),
    Record(Vec<(Option<String>, String)>),
}

/// The drop command PostgreSQL names in the hint of a replacement error.
fn drop_command_for(kind: RoutineKind) -> &'static str {
    match kind {
        RoutineKind::Procedure => "DROP PROCEDURE",
        RoutineKind::Aggregate => "DROP AGGREGATE",
        RoutineKind::Function | RoutineKind::Window => "DROP FUNCTION",
    }
}

impl AnalysisState {
    fn routine_lookup(
        &self,
        id: &ObjectId,
        expected: impl FnOnce(RoutineKind) -> bool,
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
    fn render_routine_return_type(return_type: Option<&RetTypeFact>) -> String {
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
    fn routine_declares_setof(return_type: Option<&RetTypeFact>) -> bool {
        matches!(
            return_type,
            Some(RetTypeFact::Scalar { setof: true, .. } | RetTypeFact::Table(_))
        )
    }

    /// What PostgreSQL derives from the declaration and its parameters: two or
    /// more output parameters make an anonymous `record`, exactly one makes
    /// that parameter's type, and none leaves the `RETURNS` clause in charge.
    /// A procedure has no clause, so its output parameters alone decide.
    fn routine_result(
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
    fn canonicalize_result(
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
    fn routine_parameters(
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
    fn routine_default_count(
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
    fn existing_routine(&self, id: &ObjectId) -> Option<FunctionState> {
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
    fn check_routine_replacement(
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

    fn apply_routine_owner_change(
        &mut self,
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
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
        MutationResult::Applied
    }

    fn apply_routine_depends_on_extension(&mut self, extension: &str) -> MutationResult {
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
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
        MutationResult::Applied
    }

    fn validate_routine_options(
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
                    let sig_name = format!("{}(internal)", qname.name.resolve());
                    let schema = self.resolve_function_schema(qname, &sig_name);
                    let support_id = ObjectId::new(schema, sig_name);
                    match self.routine_lookup(&support_id, |kind| kind == RoutineKind::Function) {
                        RoutineLookup::Present => {
                            if let Some(FunctionOverlay::Present(support_fn)) =
                                self.local.functions.get(&support_id)
                                && !support_fn.return_type.is_empty()
                                && !support_fn.return_type.eq_ignore_ascii_case("internal")
                            {
                                return Err(MutationResult::conflict(format!(
                                    "support function {} must return type internal",
                                    qname.name.resolve()
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
                        RoutineLookup::AuthoritativelyAbsent if qname.schema.is_some() => {
                            return Err(MutationResult::conflict(format!(
                                "function '{}' does not exist",
                                support_id
                            )));
                        }
                        RoutineLookup::AuthoritativelyAbsent | RoutineLookup::Unknown => {
                            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                        }
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
            // FunctionState intentionally stores only the attributes used by
            // current rules.  Keep the useful identity/volatility fields, but
            // taint the state when PostgreSQL attributes such as STRICT,
            // PARALLEL, COST, or SUPPORT cannot be represented.
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
        }

        // Ownership by a type is a property of the routine's identity, so a
        // replacement keeps it rather than dropping the fact.
        let internal_type_owner =
            self.local
                .functions
                .get(&function.id)
                .and_then(|overlay| match overlay {
                    FunctionOverlay::Present(existing) => existing.internal_type_owner.clone(),
                    FunctionOverlay::Dropped => None,
                });
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
            matches!(kind, RoutineKind::Function | RoutineKind::Window)
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
            RoutineLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
        }

        match &function.action {
            AlterFunctionAction::OptionsChange(options) => {
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
                if !support_functions.is_empty() {
                    self.snapshot_graph_full();
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
                return self.apply_routine_owner_change(owner);
            }
            AlterFunctionAction::DependsOnExtension { extension }
            | AlterFunctionAction::NoDependsOnExtension { extension } => {
                return self.apply_routine_depends_on_extension(extension);
            }
        }
        MutationResult::Applied
    }

    /// Present routines that share a written qualified name.
    pub(super) fn routine_overloads_under(
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

    fn types_requiring_routine(&self, routine: &ObjectId) -> Vec<(ObjectId, &'static str)> {
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
                return self.apply_routine_owner_change(owner);
            }
            AlterFunctionAction::DependsOnExtension { extension }
            | AlterFunctionAction::NoDependsOnExtension { extension } => {
                return self.apply_routine_depends_on_extension(extension);
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

    /// Whether a modeled routine answers to a bare name, ignoring its
    /// signature. A routine signature is `<name>(<types>)`, so the bare name
    /// is what precedes the first parenthesis.
    fn routine_named(&self, name: &str) -> bool {
        self.local.functions.iter().any(|(id, overlay)| {
            matches!(overlay, FunctionOverlay::Present(_))
                && id.name.split('(').next().is_some_and(|bare| bare == name)
        })
    }

    /// Refuse a `CREATE AGGREGATE` attribute whose name resolves to nothing in
    /// the modeled catalog.
    ///
    /// PostgreSQL resolves every support function and the state type before it
    /// records the aggregate, so an attribute that names an object nobody has
    /// is refused there too. Matching on the name alone is sound in one
    /// direction only, which is why a name that *is* present is left to the
    /// evidence rather than treated as proof.
    fn check_aggregate_attribute(
        &mut self,
        attribute: &crate::_internal::analysis::facts::AggregateOptionFact,
    ) -> Option<MutationResult> {
        let key = attribute.name.to_ascii_lowercase();
        if matches!(key.as_str(), "finalfunc_modify" | "mfinalfunc_modify") {
            let val = attribute
                .value
                .trim()
                .trim_matches('\'')
                .trim_matches('"')
                .to_ascii_lowercase();
            if !matches!(val.as_str(), "read_only" | "shareable" | "read_write") {
                return Some(MutationResult::conflict(format!(
                    "parameter \"{}\" must be READ_ONLY, SHAREABLE, or READ_WRITE",
                    attribute.name
                )));
            }
            return None;
        }
        if key == "parallel" {
            let val = attribute
                .value
                .trim()
                .trim_matches('\'')
                .trim_matches('"')
                .to_ascii_lowercase();
            if !matches!(val.as_str(), "safe" | "restricted" | "unsafe") {
                return Some(MutationResult::conflict(
                    "parameter \"parallel\" must be SAFE, RESTRICTED, or UNSAFE".to_string(),
                ));
            }
            return None;
        }
        let routine_option = matches!(
            key.as_str(),
            "sfunc"
                | "sfunc1"
                | "finalfunc"
                | "combinefunc"
                | "serialfunc"
                | "deserialfunc"
                | "msfunc"
                | "mfunc"
                | "minvfunc"
                | "mfinalfunc"
        );
        let type_option = matches!(key.as_str(), "stype" | "stype1" | "mstype" | "basetype");
        if !routine_option && !type_option {
            return None;
        }
        let name = attribute.value.trim();
        if key == "basetype" && matches!(name.to_ascii_lowercase().as_str(), "any" | "*") {
            return None;
        }
        // A qualified name is resolved against schemas this build may not hold.
        if name.contains('.') {
            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            return None;
        }
        let resolved = if type_option {
            self.resolve_type_reference(name).is_some()
                || self.builtin_types().resolve(name).is_some()
        } else {
            self.routine_named(name)
        };
        if resolved {
            return None;
        }
        // Absence is only provable for a name the baseline was able to answer
        // for. A routine can live in `pg_catalog`, which synchronization never
        // reads, so an unresolved routine name is never proof. A type is
        // different: the built-in catalogue is complete, so an unscoped
        // baseline plus no built-in match is a real absence.
        let provable = type_option
            && self.baseline_schemas.is_none()
            && self
                .baseline_coverage
                .has(crate::_internal::db::cache::CatalogFamily::Types);
        if provable {
            return Some(MutationResult::conflict(format!(
                "type \"{name}\" does not exist"
            )));
        }
        self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
        None
    }

    pub(super) fn apply_create_aggregate(
        &mut self,
        aggregate: &CreateAggregateMutation,
    ) -> MutationResult {
        if let Err(result) = self.ensure_creation_target(&aggregate.id) {
            return result;
        }
        match self.routine_lookup(&aggregate.id, |kind| kind == RoutineKind::Aggregate) {
            RoutineLookup::Present if aggregate.or_replace => {}
            RoutineLookup::WrongKind if aggregate.or_replace => {
                return MutationResult::conflict(format!(
                    "cannot change routine kind for '{}'",
                    aggregate.id
                ));
            }
            RoutineLookup::Present | RoutineLookup::WrongKind => {
                return MutationResult::conflict(format!(
                    "routine '{}' already exists",
                    aggregate.id
                ));
            }
            RoutineLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {}
        }
        // The definition is retained, and the parts PostgreSQL resolves by
        // name are checked here: a support function or a state type that no
        // modeled object carries is refused, exactly as `lookup_agg_function`
        // and the type lookup refuse it. Anything beyond a name — the
        // signature a transition function has to match, the state type it has
        // to return, and the aggregate's own operator set — cannot be decided
        // from a name alone and is left to the evidence below.
        if !aggregate.definition.is_empty() {
            let has_option = |names: &[&str]| {
                aggregate.definition.iter().any(|attr| {
                    names
                        .iter()
                        .any(|candidate| attr.name.eq_ignore_ascii_case(candidate))
                })
            };
            let hypothetical_enabled = aggregate.definition.iter().any(|attr| {
                attr.name.eq_ignore_ascii_case("hypothetical")
                    && !matches!(
                        attr.value.trim().to_ascii_lowercase().as_str(),
                        "false" | "f" | "0"
                    )
            });
            if hypothetical_enabled
                && aggregate.kind == crate::_internal::model::aggregate::AggregateKind::Normal
            {
                return MutationResult::conflict(
                    "only ordered-set aggregates can be hypothetical".to_string(),
                );
            }
            if !has_option(&["stype", "stype1"]) {
                return MutationResult::conflict("aggregate stype must be specified".to_string());
            }
            if !has_option(&["sfunc", "sfunc1"]) {
                return MutationResult::conflict("aggregate sfunc must be specified".to_string());
            }
            if has_option(&["mstype"]) {
                if !has_option(&["msfunc"]) {
                    return MutationResult::conflict(
                        "aggregate msfunc must be specified when mstype is specified".to_string(),
                    );
                }
                if !has_option(&["minvfunc"]) {
                    return MutationResult::conflict(
                        "aggregate minvfunc must be specified when mstype is specified".to_string(),
                    );
                }
            } else {
                for disallowed in ["msfunc", "minvfunc", "mfinalfunc", "msspace", "minitcond"] {
                    if has_option(&[disallowed]) {
                        return MutationResult::conflict(format!(
                            "aggregate {disallowed} must not be specified without mstype"
                        ));
                    }
                }
            }
        }
        if aggregate.kind == crate::_internal::model::aggregate::AggregateKind::Hypothetical
            && aggregate.direct_count < aggregate.params.len()
        {
            let num_aggregated = aggregate.params.len() - aggregate.direct_count;
            let has_variadic = aggregate
                .params
                .iter()
                .any(|p| matches!(p.mode, ParamModeFact::Variadic));
            let canonical = |raw: &str| {
                if let Some(id) = self.resolve_type_reference(raw) {
                    return id.to_string();
                }
                crate::_internal::analysis::resolver::Resolver::normalize_function_arg_type(
                    raw,
                    self.builtin_types(),
                )
                .render()
            };
            let direct_slice = &aggregate.params[..aggregate.direct_count];
            let aggregated_slice = &aggregate.params[aggregate.direct_count..];
            let matches_tail = aggregate.direct_count >= num_aggregated
                && direct_slice[aggregate.direct_count - num_aggregated..]
                    .iter()
                    .zip(aggregated_slice.iter())
                    .all(|(d, a)| canonical(&d.ty) == canonical(&a.ty));
            if has_variadic || !matches_tail {
                return MutationResult::conflict(
                    "a hypothetical-set aggregate must have direct arguments matching its aggregated arguments"
                        .to_string(),
                );
            }
        }
        for attribute in &aggregate.definition {
            if let Some(result) = self.check_aggregate_attribute(attribute) {
                return result;
            }
        }
        let stype_raw = aggregate
            .definition
            .iter()
            .find(|attr| {
                attr.name.eq_ignore_ascii_case("stype") || attr.name.eq_ignore_ascii_case("stype1")
            })
            .map(|attr| attr.value.trim().to_string());
        let finalfunc_raw = aggregate
            .definition
            .iter()
            .find(|attr| attr.name.eq_ignore_ascii_case("finalfunc"))
            .map(|attr| attr.value.trim().to_string());
        let (derived_return_type, derived_return_type_id) = match finalfunc_raw.as_deref() {
            Some(ff_name) => {
                if let Some(routine_id) = self.resolve_unique_routine_by_name(ff_name)
                    && let Some(FunctionOverlay::Present(ff_state)) =
                        self.local.functions.get(&routine_id)
                {
                    (
                        ff_state.return_type.clone(),
                        ff_state.return_type_id.clone(),
                    )
                } else {
                    (
                        stype_raw.clone().unwrap_or_default(),
                        stype_raw
                            .as_deref()
                            .and_then(|ty| self.resolve_type_reference(ty)),
                    )
                }
            }
            None => (
                stype_raw.clone().unwrap_or_default(),
                stype_raw
                    .as_deref()
                    .and_then(|ty| self.resolve_type_reference(ty)),
            ),
        };
        if aggregate.or_replace
            && let Some(existing) = self.existing_routine(&aggregate.id)
        {
            if let Some(existing_agg) = existing.aggregate {
                if existing_agg.kind != aggregate.kind {
                    return MutationResult::conflict(format!(
                        "cannot change routine kind for '{}'",
                        aggregate.id
                    ));
                }
                if existing_agg.direct_count != aggregate.direct_count {
                    return MutationResult::conflict(
                        "cannot change number of direct arguments of an aggregate function"
                            .to_string(),
                    );
                }
            }
            if !existing.return_type.is_empty()
                && !derived_return_type.is_empty()
                && let Err(result) = self.check_routine_replacement(
                    &existing,
                    &aggregate.id,
                    &aggregate.params,
                    Some(&RetTypeFact::Scalar {
                        ty: derived_return_type.clone(),
                        setof: false,
                    }),
                )
            {
                return result;
            }
        }
        if !aggregate.definition.is_empty() {
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        }
        self.snapshot_function(&aggregate.id);
        let aggregate_parameters = Self::routine_parameters(&aggregate.params, None);
        self.local.functions.insert(
            aggregate.id.clone(),
            FunctionOverlay::Present(FunctionState {
                id: aggregate.id.clone(),
                // PostgreSQL only auto-creates range constructors, never a
                // procedure or aggregate, so neither can be type-owned.
                internal_type_owner: None,
                routine_kind: RoutineKind::Aggregate,
                arg_types: aggregate_parameters
                    .iter()
                    .filter(|parameter| parameter.mode.is_input())
                    .map(|parameter| parameter.ty.clone())
                    .collect(),
                arg_type_ids: aggregate_parameters
                    .iter()
                    .filter(|parameter| parameter.mode.is_input())
                    .map(|parameter| self.resolve_type_reference(&parameter.ty))
                    .collect(),
                return_type: derived_return_type,
                return_type_id: derived_return_type_id,
                returns_set: false,
                parameters: aggregate_parameters,
                default_count: Self::routine_default_count(&aggregate.params, None),
                volatility: Volatility::Immutable,
                language: "internal".to_string(),
                security: SecurityMode::Invoker,
                aggregate: Some(crate::_internal::model::aggregate::AggregateMetadata::new(
                    aggregate.kind,
                    aggregate.direct_count,
                )),
            }),
        );
        self.record_aggregate_dependencies(aggregate);
        MutationResult::Applied
    }

    pub(super) fn apply_alter_aggregate(
        &mut self,
        aggregate: &AlterAggregateMutation,
    ) -> MutationResult {
        match self.routine_lookup(&aggregate.id, |kind| kind == RoutineKind::Aggregate) {
            RoutineLookup::Present => {}
            RoutineLookup::WrongKind => {
                return MutationResult::conflict(format!("'{}' is not an aggregate", aggregate.id));
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {
                return MutationResult::conflict(format!(
                    "aggregate '{}' does not exist",
                    aggregate.id
                ));
            }
            RoutineLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
        }
        match &aggregate.action {
            AlterFunctionAction::Rename { to, .. } => {
                let signature = aggregate
                    .id
                    .name
                    .find('(')
                    .map(|index| &aggregate.id.name[index..])
                    .unwrap_or("");
                let new_id = ObjectId::new(aggregate.id.schema.clone(), format!("{to}{signature}"));
                if let Err(result) = self.validate_function_move(&aggregate.id, &new_id) {
                    return result;
                }
                self.move_function(&aggregate.id, &new_id);
            }
            AlterFunctionAction::SchemaChange { new_schema } => {
                let new_id = ObjectId::new(new_schema.clone(), aggregate.id.name.clone());
                if let Err(result) = self.validate_function_move(&aggregate.id, &new_id) {
                    return result;
                }
                self.move_function(&aggregate.id, &new_id);
            }
            AlterFunctionAction::OwnerChange(owner) => {
                return self.apply_routine_owner_change(owner);
            }
            _ => unreachable!("aggregate extraction only emits rename, owner, or schema"),
        }
        MutationResult::Applied
    }

    /// Drop one routine and the objects a routine CASCADE takes with it: the
    /// views that call it, and every trigger defined on it.
    ///
    /// `dropped` carries every routine the statement is dropping, so a view
    /// whose call never resolved survives while any overload of its written
    /// name remains. Returns whether such a surviving reference exists.
    pub(super) fn apply_routine_cascade_drop(
        &mut self,
        id: &ObjectId,
        dependent_triggers: &[(ObjectId, ObjectId)],
        dependent_views: &[(ObjectId, Option<ObjectId>)],
        dropped: &HashSet<ObjectId>,
    ) -> bool {
        self.drop_routine_with_edges(id);

        // A name-only view reference is definitely cleared by this statement
        // only when every overload of its written name is being dropped.
        // Otherwise the view may call a surviving overload: it stays, and the
        // chain stops being exact.
        let mut surviving_reference = false;
        let mut dropped_views: Vec<ObjectId> = Vec::new();
        for (view_id, unresolved_name) in dependent_views {
            let covered = match unresolved_name {
                None => true,
                Some(name) => self
                    .routine_overloads_under(name)
                    .all(|overload| dropped.contains(overload)),
            };
            if covered {
                dropped_views.push(view_id.clone());
            } else {
                surviving_reference = true;
            }
        }
        self.drop_cascaded_views(&dropped_views);
        for (trigger_id, table_id) in dependent_triggers.iter() {
            let trigger_name =
                self.local
                    .triggers
                    .get(trigger_id)
                    .and_then(|overlay| match overlay {
                        TriggerOverlay::Present(trigger) => Some(trigger.name.clone()),
                        TriggerOverlay::Dropped => None,
                    });
            self.snapshot_trigger(trigger_id);
            self.local
                .triggers
                .insert(trigger_id.clone(), TriggerOverlay::Dropped);
            self.snapshot_relation(table_id);
            if let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(table_id)
                && let Some(trigger_name) = trigger_name
            {
                relation.triggers.remove(&trigger_name);
            }
        }
        if !dependent_triggers.is_empty() {
            self.snapshot_graph_full();
            self.local.graph.retain_edges(|edge| {
                !dependent_triggers
                    .iter()
                    .any(|(trigger_id, _)| edge.dependent == *trigger_id)
            });
        }
        let dependent_routines: Vec<ObjectId> = self
            .local
            .graph
            .routines_for_function(id)
            .into_iter()
            .filter(|edge| {
                !dropped.contains(&edge.dependent)
                    && matches!(
                        self.local.functions.get(&edge.dependent),
                        Some(FunctionOverlay::Present(_))
                    )
            })
            .map(|edge| edge.dependent.clone())
            .collect();
        if !dependent_routines.is_empty() {
            let mut next_dropped = dropped.clone();
            next_dropped.extend(dependent_routines.iter().cloned());
            for routine_id in dependent_routines {
                let triggers: Vec<(ObjectId, ObjectId)> = self
                    .local
                    .graph
                    .edges()
                    .iter()
                    .filter_map(|edge| {
                        let DependencyKind::TriggerOnTable { function_id, .. } = &edge.kind else {
                            return None;
                        };
                        (function_id == &routine_id)
                            .then(|| (edge.dependent.clone(), edge.referenced.clone()))
                    })
                    .collect();
                let views: Vec<(ObjectId, Option<ObjectId>)> = self
                    .local
                    .graph
                    .views_for_function(&routine_id)
                    .into_iter()
                    .filter_map(|edge| {
                        let DependencyKind::ViewUsesRoutine { unresolved_name } = &edge.kind else {
                            return None;
                        };
                        Some((edge.dependent.clone(), unresolved_name.clone()))
                    })
                    .collect();
                if self.apply_routine_cascade_drop(&routine_id, &triggers, &views, &next_dropped) {
                    surviving_reference = true;
                }
            }
        }
        surviving_reference
    }

    /// Drop views a routine cascade removes, together with everything that
    /// depends on them: PostgreSQL's CASCADE is transitive.
    fn drop_cascaded_views(&mut self, views: &[ObjectId]) {
        let mut seeds: Vec<ObjectId> = Vec::new();
        for view in views {
            if !seeds.contains(view) {
                seeds.push(view.clone());
            }
        }
        if seeds.is_empty() {
            return;
        }
        let _ = self.apply_drop_relation_family(&seeds, true, "view");
    }

    /// Drop aggregates after preflighting targets and cascading dependent views.
    pub(super) fn apply_drop_aggregate(
        &mut self,
        aggregate: &DropAggregateMutation,
    ) -> MutationResult {
        let mut targets = Vec::new();
        for signature in &aggregate.signatures {
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
                "aggregate",
            ) {
                return result;
            }
            match self.routine_lookup(&id, |kind| kind == RoutineKind::Aggregate) {
                RoutineLookup::Present => {
                    if !targets.contains(&id) {
                        targets.push(id);
                    }
                }
                RoutineLookup::WrongKind => {
                    return MutationResult::conflict(format!("aggregate '{}' does not exist", id));
                }
                RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent
                    if aggregate.if_exists => {}
                RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {
                    return MutationResult::conflict(format!("aggregate '{}' does not exist", id));
                }
                RoutineLookup::Unknown => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
            }
        }
        if targets.is_empty() {
            return MutationResult::NoOp;
        }
        if targets.iter().any(|id| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Routines,
            )
        }) {
            return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
        }
        let dependent_views: Vec<(ObjectId, Option<ObjectId>)> = targets
            .iter()
            .flat_map(|id| {
                self.local
                    .graph
                    .views_for_function(id)
                    .into_iter()
                    .filter_map(|edge| {
                        let DependencyKind::ViewUsesRoutine { unresolved_name } = &edge.kind else {
                            return None;
                        };
                        (!self.co_dropped_objects.contains(&edge.dependent))
                            .then(|| (edge.dependent.clone(), unresolved_name.clone()))
                    })
            })
            .collect();
        if !dependent_views.is_empty() && !aggregate.cascade {
            let definite = dependent_views.iter().find(|(_, unresolved_name)| {
                unresolved_name
                    .as_ref()
                    .is_none_or(|name| self.routine_overloads_under(name).count() <= 1)
            });
            if let Some((view, _)) = definite {
                return MutationResult::conflict(format!(
                    "aggregate '{}' is required by view '{}'; use CASCADE",
                    targets[0], view
                ));
            }
            return self.unresolved(EvidenceCode::UnresolvedReference);
        }
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
            if !dependent_routines.is_empty() && !aggregate.cascade {
                return MutationResult::conflict(format!(
                    "aggregate '{}' is required by routine '{}'; use CASCADE",
                    id, dependent_routines[0]
                ));
            }
        }
        let dropped_ids: HashSet<ObjectId> = targets.iter().cloned().collect();
        let mut surviving_reference = false;
        for id in &targets {
            if aggregate.cascade {
                let views_for_id: Vec<(ObjectId, Option<ObjectId>)> = self
                    .local
                    .graph
                    .views_for_function(id)
                    .into_iter()
                    .filter_map(|edge| {
                        let DependencyKind::ViewUsesRoutine { unresolved_name } = &edge.kind else {
                            return None;
                        };
                        (!self.co_dropped_objects.contains(&edge.dependent))
                            .then(|| (edge.dependent.clone(), unresolved_name.clone()))
                    })
                    .collect();
                if self.apply_routine_cascade_drop(id, &[], &views_for_id, &dropped_ids) {
                    surviving_reference = true;
                }
            } else {
                self.drop_routine_with_edges(id);
            }
        }
        if surviving_reference {
            self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
        }
        MutationResult::Applied
    }

    fn normalize_sql_identifier(raw: &str) -> String {
        let trimmed = raw.trim();
        if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
            trimmed[1..trimmed.len() - 1].replace("\"\"", "\"")
        } else {
            trimmed.to_ascii_lowercase()
        }
    }

    fn resolve_unique_routine_by_name(&self, raw_name: &str) -> Option<ObjectId> {
        let trimmed = raw_name.trim();
        let (schema_filter, bare_name) = match trimmed.split_once('.') {
            Some((schema, name)) => (
                Some(Self::normalize_sql_identifier(schema)),
                Self::normalize_sql_identifier(name),
            ),
            None => (None, Self::normalize_sql_identifier(trimmed)),
        };
        let matches: Vec<ObjectId> = self
            .local
            .functions
            .iter()
            .filter_map(|(id, overlay)| {
                if !matches!(overlay, FunctionOverlay::Present(_)) {
                    return None;
                }
                let (id_schema, id_bare) = DependencyGraph::split_routine_signature(id);
                if id_bare != bare_name {
                    return None;
                }
                if let Some(ref schema) = schema_filter
                    && id_schema != schema
                {
                    return None;
                }
                Some(id.clone())
            })
            .collect();
        (matches.len() == 1).then(|| matches[0].clone())
    }

    fn record_routine_body_dependencies(
        &mut self,
        routine_id: &ObjectId,
        deps: &crate::_internal::analysis::mutations::RoutineBodyDependencies,
    ) {
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !(edge.dependent == *routine_id
                && matches!(
                    edge.kind,
                    DependencyKind::RoutineUsesRoutine { .. }
                        | DependencyKind::RoutineUsesType
                        | DependencyKind::RoutineUsesRelation { .. }
                ))
        });
        for rel_dep in &deps.relations {
            if let Some(ref col) = rel_dep.column
                && let Some(RelationOverlay::Present(rel)) =
                    self.local.relations.get(&rel_dep.relation)
                && rel.columns_complete
                && !rel.has_column(col)
            {
                continue;
            }
            self.local.graph.add_edge(DependencyEdge::new(
                routine_id.clone(),
                rel_dep.relation.clone(),
                DependencyKind::RoutineUsesRelation {
                    referenced_column: rel_dep.column.clone(),
                },
            ));
        }
        for routine in &deps.routines {
            if routine.name.inferred_schema && self.path_shadows(&routine.name.schema) {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Statement);
            }
            let (referenced, unresolved_name) = match &routine.signature {
                Some(signature) => (signature.clone(), None),
                None => (routine.name.clone(), Some(routine.name.clone())),
            };
            self.local.graph.add_edge(DependencyEdge::new(
                routine_id.clone(),
                referenced,
                DependencyKind::RoutineUsesRoutine { unresolved_name },
            ));
        }
        for ty in &deps.types {
            self.local.graph.add_edge(DependencyEdge::new(
                routine_id.clone(),
                ty.clone(),
                DependencyKind::RoutineUsesType,
            ));
        }
    }

    fn record_aggregate_dependencies(&mut self, aggregate: &CreateAggregateMutation) {
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !(edge.dependent == aggregate.id
                && matches!(
                    edge.kind,
                    DependencyKind::RoutineUsesRoutine { .. }
                        | DependencyKind::RoutineUsesType
                        | DependencyKind::RoutineUsesRelation { .. }
                ))
        });
        for attr in &aggregate.definition {
            let key = attr.name.to_ascii_lowercase();
            if matches!(key.as_str(), "stype" | "stype1" | "mstype") {
                if let Some(type_id) = self.resolve_type_reference(attr.value.trim()) {
                    self.local.graph.add_edge(DependencyEdge::new(
                        aggregate.id.clone(),
                        type_id,
                        DependencyKind::RoutineUsesType,
                    ));
                }
            } else if matches!(
                key.as_str(),
                "sfunc"
                    | "sfunc1"
                    | "finalfunc"
                    | "combinefunc"
                    | "serialfunc"
                    | "deserialfunc"
                    | "msfunc"
                    | "mfunc"
                    | "minvfunc"
                    | "mfinalfunc"
            ) && let Some(routine_id) =
                self.resolve_unique_routine_by_name(attr.value.trim())
            {
                self.local.graph.add_edge(DependencyEdge::new(
                    aggregate.id.clone(),
                    routine_id,
                    DependencyKind::RoutineUsesRoutine {
                        unresolved_name: None,
                    },
                ));
            }
        }
    }

    pub(super) fn apply_alter_routine(&mut self, routine: &AlterRoutineMutation) -> MutationResult {
        match self.routine_lookup(&routine.id, |_| true) {
            RoutineLookup::Present => {}
            RoutineLookup::WrongKind => {
                return MutationResult::conflict(format!(
                    "routine '{}' does not exist",
                    routine.id
                ));
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {
                return MutationResult::conflict(format!(
                    "routine '{}' does not exist",
                    routine.id
                ));
            }
            RoutineLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
        }
        let Some(FunctionOverlay::Present(existing)) = self.local.functions.get(&routine.id) else {
            return self.unresolved(EvidenceCode::UnknownObjectState);
        };
        match existing.routine_kind {
            RoutineKind::Function | RoutineKind::Window => {
                self.apply_alter_function(&AlterFunctionMutation {
                    id: routine.id.clone(),
                    action: routine.action.clone(),
                })
            }
            RoutineKind::Procedure => self.apply_alter_procedure(&AlterProcedureMutation {
                id: routine.id.clone(),
                action: routine.action.clone(),
            }),
            RoutineKind::Aggregate => match &routine.action {
                AlterFunctionAction::OptionsChange(_) => {
                    MutationResult::conflict(format!("'{}' is an aggregate function", routine.id))
                }
                AlterFunctionAction::DependsOnExtension { extension }
                | AlterFunctionAction::NoDependsOnExtension { extension } => {
                    self.apply_routine_depends_on_extension(extension)
                }
                _ => self.apply_alter_aggregate(&AlterAggregateMutation {
                    id: routine.id.clone(),
                    action: routine.action.clone(),
                }),
            },
        }
    }

    pub(super) fn apply_drop_routine(&mut self, routine: &DropRoutineMutation) -> MutationResult {
        let mut targets: Vec<DropTarget> = Vec::new();
        let mut cascade_types: Vec<ObjectId> = Vec::new();
        for signature in &routine.signatures {
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
                "routine",
            ) {
                return result;
            }
            match self.routine_lookup(&id, |_| true) {
                RoutineLookup::WrongKind => {
                    return MutationResult::conflict(format!("routine '{}' does not exist", id));
                }
                RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent
                    if routine.if_exists => {}
                RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {
                    return MutationResult::conflict(format!("routine '{}' does not exist", id));
                }
                RoutineLookup::Unknown => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
                RoutineLookup::Present => {
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
                        if !routine.cascade {
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
                            (function_id == &id
                                && !self.co_dropped_objects.contains(&edge.dependent))
                            .then(|| (edge.dependent.clone(), edge.referenced.clone()))
                        })
                        .collect();
                    if !dependent_triggers.is_empty() && !routine.cascade {
                        return MutationResult::conflict(format!(
                            "function '{}' still has dependent triggers; use CASCADE",
                            id
                        ));
                    }
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
                    if !dependent_views.is_empty() && !routine.cascade {
                        let definite = dependent_views.iter().find(|(_, unresolved_name)| {
                            unresolved_name
                                .as_ref()
                                .is_none_or(|name| self.routine_overloads_under(name).count() <= 1)
                        });
                        if let Some((view, _)) = definite {
                            return MutationResult::conflict(format!(
                                "routine '{}' is required by view '{}'; use CASCADE",
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
                                && matches!(
                                    self.local.functions.get(&edge.dependent),
                                    Some(FunctionOverlay::Present(_))
                                )
                        })
                        .map(|edge| edge.dependent.clone())
                        .collect();
                    if !dependent_routines.is_empty() && !routine.cascade {
                        return MutationResult::conflict(format!(
                            "routine '{}' is required by routine '{}'; use CASCADE",
                            id, dependent_routines[0]
                        ));
                    }
                    if !targets.iter().any(|(existing, _, _)| existing == &id) {
                        targets.push((id, dependent_triggers, dependent_views));
                    }
                }
            }
        }
        if targets.is_empty() {
            return MutationResult::NoOp;
        }
        if targets.iter().any(|(id, _, _)| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Routines,
            )
        }) {
            return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
        }
        let dropped_ids: HashSet<ObjectId> = targets.iter().map(|(id, _, _)| id.clone()).collect();
        let mut surviving_reference = false;
        for (id, dependent_triggers, dependent_views) in &targets {
            if routine.cascade {
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
        MutationResult::Applied
    }

    fn function_option_unmodeled(option: &FuncOptionFact) -> bool {
        // `AS` bodies create no catalog dependencies; PostgreSQL parses
        // string bodies lazily.
        !matches!(
            option,
            FuncOptionFact::Language(_)
                | FuncOptionFact::Volatility(_)
                | FuncOptionFact::Security(_)
                | FuncOptionFact::As { .. }
                | FuncOptionFact::Window
        )
    }
}
