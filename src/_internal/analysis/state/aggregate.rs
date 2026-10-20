use super::*;

/// How an unqualified call the caller matched against PostgreSQL's built-in
/// aggregate set resolves on the routine search path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AggregateCandidateResolution {
    Aggregate,
    /// A modeled scalar routine, placed where the built-in aggregate's
    /// unknown signature cannot take the call back.
    Scalar,
    Uncertain,
}

/// Where a modeled routine's schema sits against the system catalog.
#[derive(Debug)]
pub(super) struct RoutineOrdinal {
    catalog: i64,
    catalog_shadowed: bool,
    schemas: HashMap<String, (i64, bool)>,
}

/// One routine that could take an aggregate-named call, at its search-path
/// position. The built-in aggregate is one of these.
struct AggregateCandidate {
    position: i64,
    shadowed: bool,
    kind: AggregateCandidateKind,
    exact: bool,
}

/// How closely a modeled routine competes for a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateMatch {
    /// Every written argument has the declared input type.
    Exact,
    /// An argument is castable or untypable, so the routine may still win.
    Coerce,
}

/// What a modeled routine makes a call that resolves to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregateCandidateKind {
    Aggregate,
    /// An ordinary scalar function, which can shadow the built-in aggregate.
    Scalar,
    /// A procedure, set-returning or bare window function: neither.
    Other,
}

/// A written argument typed as far as the model can resolve it. `identity` is
/// `None` when the argument is untyped; `variadic` records the explicit
/// PostgreSQL `VARIADIC` keyword, which changes which declared type applies.
struct CandidateArg {
    identity: Option<crate::_internal::model::data_type::TypeIdentity>,
    variadic: bool,
}

impl CandidateArg {
    fn new(typed: Option<&str>, variadic: bool, catalogue: &BuiltinTypeCatalogue) -> Self {
        let identity = typed.map(|typed| {
            let syntax = ParsedDataType::parse(typed, catalogue);
            crate::_internal::model::data_type::TypeIdentity::from_syntax(&syntax)
        });
        Self { identity, variadic }
    }
}

/// One written argument of an aggregate-named call, after the resolver has
/// substituted a column's type.
pub(crate) struct AggregateCallArgument {
    pub(crate) type_name: Option<String>,
    pub(crate) variadic: bool,
}

/// Whether a modeled routine can take a call with these argument types, and
/// how closely. `None` leaves the built-in aggregate of the name alone.
fn routine_match(
    routine: &crate::_internal::model::function::FunctionState,
    known: &[CandidateArg],
    catalogue: &BuiltinTypeCatalogue,
    casts: &CastCatalogue,
) -> Option<CandidateMatch> {
    use crate::_internal::model::function::ParameterMode;

    let declared = routine.arg_types.len();
    // Defaults let a call omit trailing inputs; a variadic parameter swallows
    // the rest. Input positions are what `arg_types` indexes.
    let variadic_index = routine
        .parameters
        .iter()
        .filter(|parameter| parameter.mode.is_input())
        .position(|parameter| parameter.mode == ParameterMode::Variadic);
    let variadic = variadic_index.is_some();
    let fixed = variadic_index.unwrap_or(declared);
    let minimum = declared
        .saturating_sub(routine.default_count as usize)
        .saturating_sub(usize::from(variadic));
    if known.len() < minimum || (!variadic && known.len() > declared) {
        return None;
    }

    // `VARIADIC ARRAY[...]` passes the array itself and must be the last
    // argument, exactly where the variadic parameter starts. Without the
    // keyword, every argument there is one element of the variadic array.
    let marked: Vec<usize> = known
        .iter()
        .enumerate()
        .filter(|(_, argument)| argument.variadic)
        .map(|(index, _)| index)
        .collect();
    if marked.len() > 1 {
        return None;
    }
    let marker = marked.first().copied();
    if let Some(marker) = marker
        && (!variadic || marker + 1 != known.len() || marker != fixed || known.len() != declared)
    {
        return None;
    }
    let element_type = if variadic {
        routine
            .arg_types
            .get(fixed)?
            .strip_suffix("[]")
            .map(str::to_owned)?
    } else {
        String::new()
    };

    let mut exact = true;
    for (index, argument) in known.iter().enumerate() {
        let declared_type = if !variadic || index < fixed {
            routine.arg_types.get(index)?
        } else if marker == Some(index) {
            routine.arg_types.get(fixed)?
        } else {
            &element_type
        };
        let declared = CandidateArg::new(Some(declared_type), false, catalogue);
        let Some(argument_identity) = argument.identity.as_ref() else {
            exact = false;
            continue;
        };
        let Some(declared_identity) = declared.identity.as_ref() else {
            exact = false;
            continue;
        };
        if argument_identity == declared_identity {
            continue;
        }
        exact = false;
        // A type the model could not resolve could still be coercible.
        if argument_identity.is_unknown() || declared_identity.is_unknown() {
            continue;
        }
        if !casts.coerces_implicitly(&argument_identity.render(), &declared_identity.render()) {
            return None;
        }
    }
    Some(if exact {
        CandidateMatch::Exact
    } else {
        CandidateMatch::Coerce
    })
}

/// Whether a built-in aggregate signature takes a call with these argument
/// types, and how closely. A polymorphic parameter accepts anything.
fn builtin_aggregate_match(
    signature: &[crate::_internal::model::aggregate::AggregateArg],
    known: &[CandidateArg],
    catalogue: &BuiltinTypeCatalogue,
    casts: &CastCatalogue,
) -> Option<CandidateMatch> {
    use crate::_internal::model::aggregate::AggregateArg;

    if signature.len() != known.len() || known.iter().any(|argument| argument.variadic) {
        return None;
    }
    let mut exact = true;
    for (argument, declared) in known.iter().zip(signature) {
        let Some(argument_identity) = argument.identity.as_ref() else {
            exact = false;
            continue;
        };
        let AggregateArg::Type(spelling) = declared else {
            continue;
        };
        let declared = CandidateArg::new(Some(spelling), false, catalogue);
        let Some(declared_identity) = declared.identity.as_ref() else {
            exact = false;
            continue;
        };
        if argument_identity == declared_identity {
            continue;
        }
        exact = false;
        if argument_identity.is_unknown() || declared_identity.is_unknown() {
            continue;
        }
        if !casts.coerces_implicitly(&argument_identity.render(), &declared_identity.render()) {
            return None;
        }
    }
    Some(if exact {
        CandidateMatch::Exact
    } else {
        CandidateMatch::Coerce
    })
}

impl AnalysisState {
    /// Place an unqualified call the caller matched against PostgreSQL's
    /// built-in aggregate set, over the argument types it resolved. `None`
    /// marks an argument the model cannot type.
    pub(crate) fn resolve_aggregate_candidate(
        &self,
        name: &str,
        arguments: &[AggregateCallArgument],
    ) -> AggregateCandidateResolution {
        use crate::_internal::model::function::RoutineKind;
        use AggregateCandidateKind::{Aggregate, Other, Scalar};

        let catalogue = self.builtin_types();
        let casts = self.casts();
        let known: Vec<CandidateArg> = arguments
            .iter()
            .map(|argument| {
                CandidateArg::new(argument.type_name.as_deref(), argument.variadic, catalogue)
            })
            .collect();

        let ordinal = self.routine_ordinal();
        let mut candidates: Vec<AggregateCandidate> = Vec::new();
        for (id, overlay) in &self.local.functions {
            let FunctionOverlay::Present(routine) = overlay else {
                continue;
            };
            if bare_routine_name(&id.name) != name {
                continue;
            }
            let Some(&(position, shadowed)) = ordinal.schemas.get(&id.schema) else {
                continue;
            };
            let kind = match routine.routine_kind {
                RoutineKind::Aggregate => Aggregate,
                RoutineKind::Function if !routine.returns_set => Scalar,
                _ => Other,
            };
            if let Some(matched) = routine_match(routine, &known, catalogue, casts) {
                candidates.push(AggregateCandidate {
                    position,
                    shadowed,
                    kind,
                    exact: matched == CandidateMatch::Exact,
                });
            }
        }
        // The built-in aggregate is a candidate in its own right, at
        // `pg_catalog`'s position, so an earlier same-signature routine is
        // chosen and a later one is not.
        match self.aggregates().signatures(name) {
            Some(signatures) => {
                for signature in signatures {
                    if let Some(matched) =
                        builtin_aggregate_match(signature, &known, catalogue, casts)
                    {
                        candidates.push(AggregateCandidate {
                            position: ordinal.catalog,
                            shadowed: ordinal.catalog_shadowed,
                            kind: Aggregate,
                            exact: matched == CandidateMatch::Exact,
                        });
                    }
                }
            }
            // A known built-in aggregate name the catalogue does not describe
            // (the window and ordered-set forms); assume it takes the call.
            None => candidates.push(AggregateCandidate {
                position: ordinal.catalog,
                shadowed: ordinal.catalog_shadowed,
                kind: Aggregate,
                exact: true,
            }),
        }

        // An exact match wins; among them the path-earliest does. An
        // unsearchable entry ahead of the winner leaves the call unsettled.
        if let Some(best) = candidates
            .iter()
            .filter(|candidate| candidate.exact)
            .min_by_key(|candidate| candidate.position)
        {
            if best.shadowed {
                return AggregateCandidateResolution::Uncertain;
            }
            return match best.kind {
                Aggregate => AggregateCandidateResolution::Aggregate,
                Scalar => AggregateCandidateResolution::Scalar,
                Other => AggregateCandidateResolution::Uncertain,
            };
        }

        // With no exact match the earliest coercible candidate decides, and
        // only if every candidate tied there is an aggregate.
        let Some(position) = candidates
            .iter()
            .filter(|candidate| !candidate.exact)
            .map(|candidate| candidate.position)
            .min()
        else {
            return AggregateCandidateResolution::Uncertain;
        };
        let tied: Vec<&AggregateCandidate> = candidates
            .iter()
            .filter(|candidate| !candidate.exact && candidate.position == position)
            .collect();
        if tied[0].shadowed {
            return AggregateCandidateResolution::Uncertain;
        }
        if tied.iter().all(|candidate| candidate.kind == Aggregate) {
            AggregateCandidateResolution::Aggregate
        } else {
            AggregateCandidateResolution::Uncertain
        }
    }

    /// Each search-path schema's position, and `pg_catalog`'s, with the flag for
    /// whether an unsearchable entry precedes it. `pg_catalog` is at `-1` when
    /// the path does not name it, because it is then searched first.
    pub(super) fn routine_ordinal(&self) -> RoutineOrdinal {
        let path = self.routine_search_path();
        let catalog_at = path
            .iter()
            .position(|entry| entry.searched_schema() == Some(SYSTEM_CATALOG_SCHEMA));
        let mut schemas = HashMap::new();
        let mut shadowed = false;
        for (position, entry) in path.iter().enumerate() {
            match entry {
                SearchPathEntry::Unresolved(_) => shadowed = true,
                SearchPathEntry::Schema(schema) => {
                    schemas
                        .entry(schema.clone())
                        .or_insert((position as i64, shadowed));
                }
            }
        }
        let catalog_shadowed = catalog_at.is_some_and(|catalog| {
            path[..catalog]
                .iter()
                .any(|entry| matches!(entry, SearchPathEntry::Unresolved(_)))
        });
        RoutineOrdinal {
            catalog: catalog_at.map_or(-1, |catalog| catalog as i64),
            catalog_shadowed,
            schemas,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::_internal::ast::identifiers::ObjectId;
    use crate::_internal::model::function::{FunctionState, ParameterMode, RoutineKind};

    fn routine(arg_types: &[&str]) -> FunctionState {
        FunctionState::with_inputs(
            ObjectId::new("public", "sum"),
            RoutineKind::Function,
            arg_types.iter().map(|ty| (*ty).to_string()).collect(),
        )
    }

    fn variadic_routine(arg_types: &[&str]) -> FunctionState {
        let mut routine = routine(arg_types);
        let last = routine.parameters.len() - 1;
        routine.parameters[last].mode = ParameterMode::Variadic;
        routine
    }

    fn match_arguments(
        routine: &FunctionState,
        arguments: &[(&str, bool)],
        catalogue: &BuiltinTypeCatalogue,
        casts: &CastCatalogue,
    ) -> Option<CandidateMatch> {
        let known: Vec<CandidateArg> = arguments
            .iter()
            .map(|(ty, variadic)| CandidateArg::new(Some(ty), *variadic, catalogue))
            .collect();
        routine_match(routine, &known, catalogue, casts)
    }

    #[test]
    fn variadic_scalar_arguments_use_the_element_type() {
        let routine = variadic_routine(&["integer[]"]);
        let catalogue = BuiltinTypeCatalogue::fallback();
        let casts = CastCatalogue::fallback();

        assert_eq!(
            match_arguments(&routine, &[("integer", false)], &catalogue, &casts),
            Some(CandidateMatch::Exact)
        );
        assert_eq!(
            match_arguments(
                &routine,
                &[("integer", false), ("integer", false)],
                &catalogue,
                &casts
            ),
            Some(CandidateMatch::Exact)
        );
    }

    #[test]
    fn an_array_argument_needs_the_variadic_keyword() {
        let routine = variadic_routine(&["integer[]"]);
        let catalogue = BuiltinTypeCatalogue::fallback();
        let casts = CastCatalogue::fallback();

        assert_eq!(
            match_arguments(&routine, &[("integer[]", false)], &catalogue, &casts),
            None
        );
        assert_eq!(
            match_arguments(&routine, &[("integer[]", true)], &catalogue, &casts),
            Some(CandidateMatch::Exact)
        );
    }

    #[test]
    fn omitted_trailing_defaults_still_match_exactly() {
        let mut routine = routine(&["integer", "integer"]);
        routine.default_count = 1;
        let catalogue = BuiltinTypeCatalogue::fallback();
        let casts = CastCatalogue::fallback();

        assert_eq!(
            match_arguments(&routine, &[("integer", false)], &catalogue, &casts),
            Some(CandidateMatch::Exact)
        );
    }

    #[test]
    fn the_variadic_keyword_must_be_last_and_at_the_variadic_parameter() {
        let routine = variadic_routine(&["text", "integer[]"]);
        let catalogue = BuiltinTypeCatalogue::fallback();
        let casts = CastCatalogue::fallback();

        assert_eq!(
            match_arguments(
                &routine,
                &[("text", false), ("integer[]", true)],
                &catalogue,
                &casts
            ),
            Some(CandidateMatch::Exact)
        );
        assert_eq!(
            match_arguments(
                &routine,
                &[("text", true), ("integer[]", false)],
                &catalogue,
                &casts
            ),
            None
        );
        assert_eq!(
            match_arguments(
                &routine,
                &[("text", false), ("integer[]", true), ("integer", false)],
                &catalogue,
                &casts
            ),
            None
        );
    }
}
