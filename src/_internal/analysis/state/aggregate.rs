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

/// A written argument typed as far as the model can resolve it.
struct CandidateArg {
    identity: crate::_internal::model::data_type::TypeIdentity,
}

impl CandidateArg {
    fn new(typed: &str, catalogue: &BuiltinTypeCatalogue) -> Self {
        let syntax = ParsedDataType::parse(typed, catalogue);
        Self {
            identity: crate::_internal::model::data_type::TypeIdentity::from_syntax(&syntax),
        }
    }
}

/// Whether a modeled routine can take a call with these argument types, and
/// how closely. `None` leaves the built-in aggregate of the name alone.
fn routine_match(
    routine: &crate::_internal::model::function::FunctionState,
    known: &[Option<CandidateArg>],
    catalogue: &BuiltinTypeCatalogue,
    casts: &CastCatalogue,
) -> Option<CandidateMatch> {
    use crate::_internal::model::function::ParameterMode;

    let declared = routine.arg_types.len();
    // Defaults let a call omit trailing inputs; a variadic parameter swallows
    // the rest.
    let variadic = routine
        .parameters
        .iter()
        .any(|parameter| parameter.mode == ParameterMode::Variadic);
    let minimum = declared
        .saturating_sub(routine.default_count as usize)
        .saturating_sub(usize::from(variadic));
    if variadic {
        if known.len() < minimum {
            return None;
        }
    } else if known.len() < minimum || known.len() > declared {
        return None;
    }

    let mut exact = true;
    for (index, argument) in known.iter().enumerate() {
        // Past the declared list only a variadic tail parameter applies.
        let declared_type = if index < declared {
            &routine.arg_types[index]
        } else {
            routine.arg_types.last()?
        };
        let declared = CandidateArg::new(declared_type, catalogue);
        let Some(argument) = argument else {
            exact = false;
            continue;
        };
        if argument.identity == declared.identity {
            continue;
        }
        exact = false;
        // A type the model could not resolve could still be coercible.
        if argument.identity.is_unknown() || declared.identity.is_unknown() {
            continue;
        }
        if !casts.coerces_implicitly(&argument.identity.render(), &declared.identity.render()) {
            return None;
        }
    }
    let exact = exact && !variadic && known.len() == declared;
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
    known: &[Option<CandidateArg>],
    catalogue: &BuiltinTypeCatalogue,
    casts: &CastCatalogue,
) -> Option<CandidateMatch> {
    use crate::_internal::model::aggregate::AggregateArg;

    if signature.len() != known.len() {
        return None;
    }
    let mut exact = true;
    for (argument, declared) in known.iter().zip(signature) {
        let Some(argument) = argument else {
            exact = false;
            continue;
        };
        let AggregateArg::Type(spelling) = declared else {
            continue;
        };
        let declared = CandidateArg::new(spelling, catalogue);
        if argument.identity == declared.identity {
            continue;
        }
        exact = false;
        if argument.identity.is_unknown() || declared.identity.is_unknown() {
            continue;
        }
        if !casts.coerces_implicitly(&argument.identity.render(), &declared.identity.render()) {
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
        arguments: &[Option<String>],
    ) -> AggregateCandidateResolution {
        use crate::_internal::model::function::RoutineKind;
        use AggregateCandidateKind::{Aggregate, Other, Scalar};

        let catalogue = self.builtin_types();
        let casts = self.casts();
        let known: Vec<Option<CandidateArg>> = arguments
            .iter()
            .map(|argument| {
                argument
                    .as_ref()
                    .map(|typed| CandidateArg::new(typed, catalogue))
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
