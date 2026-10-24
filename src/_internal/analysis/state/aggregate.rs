use super::*;

/// How an unqualified call the caller matched against PostgreSQL's built-in
/// aggregate set resolves on the routine search path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AggregateCandidateResolution {
    Aggregate,
    /// A modeled scalar routine, placed where the built-in aggregate's
    /// unknown signature cannot take the call back.
    Scalar,
    /// PostgreSQL has no function of this name and argument types.
    Invalid(String),
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
    /// How many written arguments this candidate consumed, counting the
    /// ordered arguments of a `WITHIN GROUP` call. Exact selection compares
    /// against this rather than the call's total.
    arity: usize,
    scores: CandidateMatch,
}

/// How closely a modeled routine competes for a call. `direct` counts exact
/// identities before domain reduction; `reduced` counts exact identities after
/// an input domain is treated as its base, which is the step PostgreSQL uses
/// for its maximum-exact-match rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateMatch {
    direct_exact: usize,
    reduced_exact: usize,
    preferred: usize,
}

impl CandidateMatch {
    fn all_direct(self, arguments: usize) -> bool {
        self.direct_exact == arguments
    }
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

#[derive(Clone, Debug)]
struct KnownCallType {
    identity: crate::_internal::model::data_type::TypeIdentity,
    id: Option<ObjectId>,
    base: Option<Box<KnownCallType>>,
    category: crate::_internal::model::builtin_type::TypeCategory,
    preferred: bool,
}

impl KnownCallType {
    fn effective(&self) -> &Self {
        self.base.as_deref().unwrap_or(self)
    }

    fn is_exact(&self, declared: &Self) -> bool {
        match (&self.id, &declared.id) {
            (Some(left), Some(right)) => left == right,
            (None, None) => self.identity.render() == declared.identity.render(),
            _ => false,
        }
    }

    fn is_polymorphic(&self) -> bool {
        matches!(
            self.identity.render().as_str(),
            "any"
                | "anyarray"
                | "anycompatible"
                | "anycompatiblearray"
                | "anycompatiblemultirange"
                | "anycompatiblenonarray"
                | "anycompatiblerange"
                | "anyelement"
                | "anyenum"
                | "anymultirange"
                | "anynonarray"
                | "anyrange"
                | "record"
        )
    }
}

#[derive(Clone, Debug)]
enum CallType {
    Known(KnownCallType),
    /// An untyped literal or expression. PostgreSQL resolves these against the
    /// candidate set rather than treating them as a named unknown type.
    UnknownLiteral,
    /// A written type the model cannot identify. It must not match an
    /// unrelated overload by default.
    Unresolved,
}

struct CallTypeResolver<'a> {
    catalogue: &'a BuiltinTypeCatalogue,
    local: Option<&'a HashMap<ObjectId, TypeOverlay>>,
}

impl<'a> CallTypeResolver<'a> {
    fn new(catalogue: &'a BuiltinTypeCatalogue, local: &'a HashMap<ObjectId, TypeOverlay>) -> Self {
        Self {
            catalogue,
            local: Some(local),
        }
    }

    #[cfg(test)]
    fn without_types(catalogue: &'a BuiltinTypeCatalogue) -> Self {
        Self {
            catalogue,
            local: None,
        }
    }

    fn resolve(&self, spelling: Option<&str>, id: Option<&ObjectId>) -> CallType {
        if let Some(id) = id
            && let Some(resolved) = self.resolve_id(id, spelling)
        {
            return CallType::Known(resolved);
        }
        match spelling {
            Some(spelling) => self.resolve_name(spelling),
            None => CallType::UnknownLiteral,
        }
    }

    fn resolve_id(&self, id: &ObjectId, spelling: Option<&str>) -> Option<KnownCallType> {
        use crate::_internal::model::builtin_type::TypeCategory;

        let Some(TypeOverlay::Present(state)) = self.local.and_then(|local| local.get(id)) else {
            return None;
        };
        let identity = self.identity(spelling.unwrap_or(&id.name));
        let (category, base) = match &state.kind {
            TypeKind::Domain {
                base_type,
                base_type_id,
            } => {
                let base = self.resolve(Some(base_type), base_type_id.as_ref());
                match base {
                    CallType::Known(base) => {
                        let base = base.effective().clone();
                        (base.category, Some(Box::new(base)))
                    }
                    _ => (TypeCategory::Unknown, None),
                }
            }
            TypeKind::Enum { .. } => (TypeCategory::Enum, None),
            TypeKind::Composite { .. } => (TypeCategory::Composite, None),
            TypeKind::Range { .. } | TypeKind::Multirange => (TypeCategory::Range, None),
            TypeKind::Base { .. } => (TypeCategory::User, None),
        };
        Some(KnownCallType {
            identity,
            id: Some(id.clone()),
            base,
            category,
            preferred: false,
        })
    }

    fn resolve_name(&self, raw: &str) -> CallType {
        use crate::_internal::model::builtin_type::TypeCategory;
        use crate::_internal::model::data_type::TypeIdentity;

        let syntax = ParsedDataType::parse(raw, self.catalogue);
        let identity = TypeIdentity::from_syntax(&syntax);
        if syntax.is_builtin() {
            let entry = self.catalogue.resolve(syntax.canonical_name());
            let array = syntax.array_dimensions > 0;
            let category = if array {
                TypeCategory::Array
            } else {
                entry
                    .map(|entry| entry.category)
                    .unwrap_or(TypeCategory::Unknown)
            };
            return CallType::Known(KnownCallType {
                identity,
                id: None,
                base: None,
                category,
                preferred: !array && entry.is_some_and(|entry| entry.preferred),
            });
        }
        let canonical = syntax.canonical_name();
        if matches!(
            canonical,
            "any"
                | "anyarray"
                | "anycompatible"
                | "anycompatiblearray"
                | "anycompatiblemultirange"
                | "anycompatiblenonarray"
                | "anycompatiblerange"
                | "anyelement"
                | "anyenum"
                | "anymultirange"
                | "anynonarray"
                | "anyrange"
                | "record"
        ) {
            return CallType::Known(KnownCallType {
                identity,
                id: None,
                base: None,
                category: TypeCategory::Pseudo,
                preferred: false,
            });
        }
        CallType::Unresolved
    }

    fn identity(&self, raw: &str) -> crate::_internal::model::data_type::TypeIdentity {
        use crate::_internal::model::data_type::TypeIdentity;
        TypeIdentity::from_syntax(&ParsedDataType::parse(raw, self.catalogue))
    }
}

/// A written argument typed as far as the model can resolve it. `variadic`
/// records the explicit PostgreSQL `VARIADIC` keyword, which changes which
/// declared type applies.
#[derive(Clone)]
struct CandidateArg {
    ty: CallType,
    variadic: bool,
}

impl CandidateArg {
    #[cfg(test)]
    fn new(typed: Option<&str>, variadic: bool, resolver: &CallTypeResolver<'_>) -> Self {
        Self {
            ty: resolver.resolve(typed, None),
            variadic,
        }
    }

    fn from_call_argument(
        argument: &AggregateCallArgument,
        resolver: &CallTypeResolver<'_>,
    ) -> Self {
        Self {
            ty: resolver.resolve(argument.type_name.as_deref(), argument.type_id.as_ref()),
            variadic: argument.variadic,
        }
    }
}

/// One written argument of an aggregate-named call, after the resolver has
/// substituted a column's type.
pub(crate) struct AggregateCallArgument {
    pub(crate) type_name: Option<String>,
    pub(crate) type_id: Option<ObjectId>,
    pub(crate) variadic: bool,
}

fn argument_match(
    argument: &CandidateArg,
    declared: &CallType,
    casts: &CastCatalogue,
) -> Option<(bool, bool)> {
    match (&argument.ty, declared) {
        (CallType::Known(argument), CallType::Known(declared)) => {
            if declared.is_polymorphic() {
                return Some((false, false));
            }
            if argument.is_exact(declared) {
                return Some((true, false));
            }
            let effective = argument.effective();
            let exact = effective.is_exact(declared);
            if exact {
                return Some((true, false));
            }
            if !casts.coerces_implicitly(&effective.identity.render(), &declared.identity.render())
            {
                return None;
            }
            let preferred = declared.preferred && declared.category == effective.category;
            Some((false, preferred))
        }
        (CallType::UnknownLiteral, CallType::Known(_)) => Some((false, false)),
        (CallType::Unresolved, CallType::Known(declared)) if declared.is_polymorphic() => {
            Some((false, false))
        }
        _ => None,
    }
}

fn score_match(
    arguments: &[CandidateArg],
    declared: impl Fn(usize) -> Option<CallType>,
    casts: &CastCatalogue,
) -> Option<CandidateMatch> {
    let mut scores = CandidateMatch {
        direct_exact: 0,
        reduced_exact: 0,
        preferred: 0,
    };
    for (index, argument) in arguments.iter().enumerate() {
        let declared = declared(index)?;
        let direct = match (&argument.ty, &declared) {
            (CallType::Known(argument), CallType::Known(declared)) => argument.is_exact(declared),
            _ => false,
        };
        let (exact, preferred) = argument_match(argument, &declared, casts)?;
        if direct {
            scores.direct_exact += 1;
        }
        if exact {
            scores.reduced_exact += 1;
        }
        if preferred {
            scores.preferred += 1;
        }
    }
    Some(scores)
}

/// Whether a modeled routine can take a call with these argument types, and
/// how closely. `None` leaves the built-in aggregate of the name alone.
fn routine_match(
    routine: &crate::_internal::model::function::FunctionState,
    known: &[CandidateArg],
    resolver: &CallTypeResolver<'_>,
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

    score_match(
        known,
        |index| {
            let declared_type = if !variadic || index < fixed {
                routine.arg_types.get(index)?
            } else if marker == Some(index) {
                routine.arg_types.get(fixed)?
            } else {
                &element_type
            };
            let declared_id = if !variadic || index < fixed {
                routine.arg_type_ids.get(index).and_then(Option::as_ref)
            } else {
                None
            };
            Some(resolver.resolve(Some(declared_type), declared_id))
        },
        casts,
    )
}

/// Whether a built-in aggregate signature takes a call with these direct and
/// ordered argument types. A polymorphic parameter accepts anything.
fn builtin_aggregate_match(
    signature: &crate::_internal::model::aggregate::AggregateSignature,
    direct: &[CandidateArg],
    ordered: &[CandidateArg],
    has_within_group: bool,
    resolver: &CallTypeResolver<'_>,
    casts: &CastCatalogue,
) -> Option<CandidateMatch> {
    use crate::_internal::model::aggregate::AggregateArg;

    let variadic_hypothetical = signature.is_variadic_hypothetical();
    if signature.kind.takes_within_group() != has_within_group
        || if variadic_hypothetical {
            direct.len() != ordered.len() || direct.is_empty()
        } else {
            signature.direct_count != direct.len()
                || signature.arguments.len() - signature.direct_count != ordered.len()
        }
    {
        return None;
    }
    let known: Vec<CandidateArg> = direct.iter().chain(ordered).cloned().collect();
    if known.iter().any(|argument| argument.variadic) {
        return None;
    }
    score_match(
        &known,
        |index| {
            let declared = if variadic_hypothetical {
                &AggregateArg::Any
            } else {
                &signature.arguments[index]
            };
            Some(match declared {
                AggregateArg::Any => CallType::Known(KnownCallType {
                    identity: resolver.identity("anyelement"),
                    id: None,
                    base: None,
                    category: crate::_internal::model::builtin_type::TypeCategory::Pseudo,
                    preferred: false,
                }),
                AggregateArg::Type(spelling) => resolver.resolve(Some(spelling), None),
            })
        },
        casts,
    )
}

/// Whether a modeled aggregate routine can take a call with these direct and
/// ordered argument types, and how many written arguments it consumed.
fn routine_aggregate_match(
    routine: &crate::_internal::model::function::FunctionState,
    known: &[CandidateArg],
    within_known: &[CandidateArg],
    has_within_group: bool,
    resolver: &CallTypeResolver<'_>,
    casts: &CastCatalogue,
) -> Option<(CandidateMatch, usize)> {
    use crate::_internal::model::aggregate::{AggregateKind, AggregateMetadata};
    use crate::_internal::model::function::ParameterMode;

    let AggregateMetadata { kind, direct_count } = routine.aggregate?;
    match kind {
        AggregateKind::Normal => {
            if has_within_group {
                return None;
            }
            routine_match(routine, known, resolver, casts).map(|scores| (scores, known.len()))
        }
        AggregateKind::OrderedSet | AggregateKind::Hypothetical => {
            if !has_within_group {
                return None;
            }
            let declared = routine.arg_types.len();
            let last = declared.checked_sub(1)?;
            let last_type = routine.arg_types.get(last)?;
            let last_id = routine.arg_type_ids.get(last).and_then(Option::as_ref);
            let variadic_last = routine
                .parameters
                .iter()
                .rfind(|parameter| parameter.mode.is_input())
                .is_some_and(|parameter| parameter.mode == ParameterMode::Variadic);
            let polymorphic_last = matches!(
                resolver.resolve(Some(last_type), last_id),
                CallType::Known(declared) if declared.is_polymorphic()
            );
            // A hypothetical aggregate written as `VARIADIC "any"` stores one
            // polymorphic parameter for both lists; its direct and ordered
            // counts must agree instead of using `direct_count`.
            if kind == AggregateKind::Hypothetical
                && direct_count == declared
                && variadic_last
                && polymorphic_last
            {
                if known.len() != within_known.len() || known.is_empty() {
                    return None;
                }
                let combined: Vec<CandidateArg> =
                    known.iter().chain(within_known).cloned().collect();
                if combined.iter().any(|argument| argument.variadic) {
                    return None;
                }
                let scores = score_match(
                    &combined,
                    |_| Some(resolver.resolve(Some("anyelement"), None)),
                    casts,
                )?;
                return Some((scores, combined.len()));
            }
            if direct_count != known.len() {
                return None;
            }
            let variadic = routine
                .parameters
                .iter()
                .any(|parameter| parameter.mode == ParameterMode::Variadic);
            if !variadic && declared - direct_count != within_known.len() {
                return None;
            }
            let combined: Vec<CandidateArg> = known.iter().chain(within_known).cloned().collect();
            routine_match(routine, &combined, resolver, casts)
                .map(|scores| (scores, combined.len()))
        }
    }
}

fn missing_call_message(
    name: &str,
    arguments: &[AggregateCallArgument],
    within_group: &[AggregateCallArgument],
    has_within_group: bool,
) -> String {
    let render = |arguments: &[AggregateCallArgument]| {
        arguments
            .iter()
            .map(|argument| argument.type_name.as_deref().unwrap_or("unknown"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut call = format!("function {name}({})", render(arguments));
    if has_within_group {
        call.push_str(&format!(
            " WITHIN GROUP (ORDER BY {})",
            render(within_group)
        ));
    }
    call.push_str(" does not exist");
    call
}

impl AnalysisState {
    /// Place an unqualified call the caller matched against PostgreSQL's
    /// built-in aggregate set, over the argument types it resolved. `None`
    /// marks an argument the model cannot type.
    pub(crate) fn resolve_aggregate_candidate(
        &self,
        name: &str,
        arguments: &[AggregateCallArgument],
        within_group: &[AggregateCallArgument],
        has_within_group: bool,
        explicit: bool,
    ) -> AggregateCandidateResolution {
        use crate::_internal::model::function::RoutineKind;
        use AggregateCandidateKind::{Aggregate, Other, Scalar};

        let catalogue = self.builtin_types();
        let casts = self.casts();
        let resolver = CallTypeResolver::new(catalogue, &self.local.types);
        let known: Vec<CandidateArg> = arguments
            .iter()
            .map(|argument| CandidateArg::from_call_argument(argument, &resolver))
            .collect();
        let within_known: Vec<CandidateArg> = within_group
            .iter()
            .map(|argument| CandidateArg::from_call_argument(argument, &resolver))
            .collect();
        // Local User/Unknown types may have casts outside pg_catalog, so an
        // unmatched call is not proof that the function is missing.
        let arguments_complete =
            known
                .iter()
                .chain(&within_known)
                .all(|argument| match &argument.ty {
                    CallType::Known(known) => {
                        !(known.id.is_some()
                            && matches!(
                                known.category,
                                crate::_internal::model::builtin_type::TypeCategory::User
                                    | crate::_internal::model::builtin_type::TypeCategory::Unknown
                            ))
                    }
                    _ => false,
                });

        let ordinal = self.routine_ordinal();
        let mut declarations_complete = true;
        let mut candidates: Vec<AggregateCandidate> = Vec::new();
        if !explicit {
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
                for (index, declared) in routine.arg_types.iter().enumerate() {
                    let id = routine.arg_type_ids.get(index).and_then(Option::as_ref);
                    if matches!(resolver.resolve(Some(declared), id), CallType::Unresolved) {
                        declarations_complete = false;
                    }
                }
                let (kind, matched) = match routine.routine_kind {
                    RoutineKind::Aggregate => {
                        if routine.aggregate.is_none() {
                            // A pre-metadata aggregate cannot settle a
                            // `WITHIN GROUP` call; keep it `Other` so a shadow
                            // leaves the call uncertain rather than accepted.
                            let kind = if has_within_group { Other } else { Aggregate };
                            (
                                kind,
                                routine_match(routine, &known, &resolver, casts)
                                    .map(|scores| (scores, known.len())),
                            )
                        } else {
                            (
                                Aggregate,
                                routine_aggregate_match(
                                    routine,
                                    &known,
                                    &within_known,
                                    has_within_group,
                                    &resolver,
                                    casts,
                                ),
                            )
                        }
                    }
                    RoutineKind::Function if !routine.returns_set => {
                        if has_within_group {
                            continue;
                        }
                        (
                            Scalar,
                            routine_match(routine, &known, &resolver, casts)
                                .map(|scores| (scores, known.len())),
                        )
                    }
                    _ => {
                        if has_within_group {
                            continue;
                        }
                        (
                            Other,
                            routine_match(routine, &known, &resolver, casts)
                                .map(|scores| (scores, known.len())),
                        )
                    }
                };
                if let Some((scores, arity)) = matched {
                    candidates.push(AggregateCandidate {
                        position,
                        shadowed,
                        kind,
                        arity,
                        scores,
                    });
                }
            }
        }
        // The built-in aggregate is a candidate in its own right, at
        // `pg_catalog`'s position, so an earlier same-signature routine is
        // chosen and a later one is not.
        match self.aggregates().signatures(name) {
            Some(signatures) => {
                for signature in signatures {
                    for argument in &signature.arguments {
                        if let crate::_internal::model::aggregate::AggregateArg::Type(spelling) =
                            argument
                            && matches!(
                                resolver.resolve(Some(spelling), None),
                                CallType::Unresolved
                            )
                        {
                            declarations_complete = false;
                        }
                    }
                    if let Some(scores) = builtin_aggregate_match(
                        signature,
                        &known,
                        &within_known,
                        has_within_group,
                        &resolver,
                        casts,
                    ) {
                        candidates.push(AggregateCandidate {
                            position: ordinal.catalog,
                            shadowed: ordinal.catalog_shadowed,
                            kind: Aggregate,
                            arity: signature.arguments.len(),
                            scores,
                        });
                    }
                }
            }
            // A known built-in aggregate name the catalogue does not describe;
            // assume it takes the call.
            None => {
                let arity = known.len() + within_known.len();
                candidates.push(AggregateCandidate {
                    position: ordinal.catalog,
                    shadowed: ordinal.catalog_shadowed,
                    kind: Aggregate,
                    arity,
                    scores: CandidateMatch {
                        direct_exact: arity,
                        reduced_exact: arity,
                        preferred: 0,
                    },
                });
            }
        }

        // An exact match wins; among them the path-earliest does. An
        // unsearchable entry ahead of the winner leaves the call unsettled.
        if let Some(best) = candidates
            .iter()
            .filter(|candidate| candidate.scores.all_direct(candidate.arity))
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

        let Some(max_exact) = candidates
            .iter()
            .map(|candidate| candidate.scores.reduced_exact)
            .max()
        else {
            let path_complete = !self
                .local
                .search_path
                .iter()
                .any(|entry| matches!(entry, SearchPathEntry::Unresolved(_)));
            return if arguments_complete && declarations_complete && path_complete {
                AggregateCandidateResolution::Invalid(missing_call_message(
                    name,
                    arguments,
                    within_group,
                    has_within_group,
                ))
            } else {
                AggregateCandidateResolution::Uncertain
            };
        };

        // PostgreSQL keeps the candidates with the most exact matches, then
        // those accepting preferred types where conversion is still required.
        let max_preferred = candidates
            .iter()
            .filter(|candidate| candidate.scores.reduced_exact == max_exact)
            .map(|candidate| candidate.scores.preferred)
            .max()
            .unwrap_or(0);
        let Some(position) = candidates
            .iter()
            .filter(|candidate| {
                candidate.scores.reduced_exact == max_exact
                    && candidate.scores.preferred == max_preferred
            })
            .map(|candidate| candidate.position)
            .min()
        else {
            return AggregateCandidateResolution::Uncertain;
        };
        let tied: Vec<&AggregateCandidate> = candidates
            .iter()
            .filter(|candidate| {
                candidate.scores.reduced_exact == max_exact
                    && candidate.scores.preferred == max_preferred
                    && candidate.position == position
            })
            .collect();
        if tied[0].shadowed {
            return AggregateCandidateResolution::Uncertain;
        }
        let kind = tied[0].kind;
        if tied.iter().all(|candidate| candidate.kind == kind) {
            match kind {
                Aggregate => AggregateCandidateResolution::Aggregate,
                Scalar => AggregateCandidateResolution::Scalar,
                Other => AggregateCandidateResolution::Uncertain,
            }
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
        let resolver = CallTypeResolver::without_types(catalogue);
        let known: Vec<CandidateArg> = arguments
            .iter()
            .map(|(ty, variadic)| CandidateArg::new(Some(ty), *variadic, &resolver))
            .collect();
        routine_match(routine, &known, &resolver, casts)
    }

    fn exact(arguments: usize) -> Option<CandidateMatch> {
        Some(CandidateMatch {
            direct_exact: arguments,
            reduced_exact: arguments,
            preferred: 0,
        })
    }

    #[test]
    fn variadic_scalar_arguments_use_the_element_type() {
        let routine = variadic_routine(&["integer[]"]);
        let catalogue = BuiltinTypeCatalogue::fallback();
        let casts = CastCatalogue::fallback();

        assert_eq!(
            match_arguments(&routine, &[("integer", false)], &catalogue, &casts),
            exact(1)
        );
        assert_eq!(
            match_arguments(
                &routine,
                &[("integer", false), ("integer", false)],
                &catalogue,
                &casts
            ),
            exact(2)
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
            exact(1)
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
            exact(1)
        );
    }

    fn aggregate_routine(
        arg_types: &[&str],
        kind: crate::_internal::model::aggregate::AggregateKind,
        direct_count: usize,
    ) -> FunctionState {
        let mut routine = FunctionState::with_inputs(
            ObjectId::new("public", "my_agg"),
            RoutineKind::Aggregate,
            arg_types.iter().map(|ty| (*ty).to_string()).collect(),
        );
        routine.aggregate = Some(crate::_internal::model::aggregate::AggregateMetadata::new(
            kind,
            direct_count,
        ));
        routine
    }

    fn candidate_arguments(types: &[&str], resolver: &CallTypeResolver<'_>) -> Vec<CandidateArg> {
        types
            .iter()
            .map(|ty| CandidateArg::new(Some(ty), false, resolver))
            .collect()
    }

    #[test]
    fn aggregate_metadata_selects_the_call_form() {
        use crate::_internal::model::aggregate::AggregateKind;

        let catalogue = BuiltinTypeCatalogue::fallback();
        let casts = CastCatalogue::fallback();
        let resolver = CallTypeResolver::without_types(&catalogue);
        let known = candidate_arguments(&["double precision"], &resolver);
        let ordered = candidate_arguments(&["double precision"], &resolver);
        let empty: Vec<CandidateArg> = Vec::new();

        let normal = aggregate_routine(&["double precision"], AggregateKind::Normal, 1);
        assert!(
            routine_aggregate_match(&normal, &known, &empty, false, &resolver, &casts).is_some()
        );
        assert!(
            routine_aggregate_match(&normal, &known, &ordered, true, &resolver, &casts).is_none(),
            "a normal aggregate has no ordered arguments"
        );

        let ordered_set = aggregate_routine(
            &["double precision", "double precision"],
            AggregateKind::OrderedSet,
            1,
        );
        assert!(
            routine_aggregate_match(&ordered_set, &known, &ordered, true, &resolver, &casts)
                .is_some()
        );
        assert!(
            routine_aggregate_match(&ordered_set, &known, &ordered, false, &resolver, &casts)
                .is_none(),
            "an ordered-set aggregate needs WITHIN GROUP"
        );
        assert!(
            routine_aggregate_match(&ordered_set, &empty, &ordered, true, &resolver, &casts)
                .is_none(),
            "the direct argument count is exact"
        );
        let ordered_text = candidate_arguments(&["text"], &resolver);
        assert!(
            routine_aggregate_match(&ordered_set, &known, &ordered_text, true, &resolver, &casts)
                .is_none(),
            "the ordered argument type is checked"
        );
    }

    #[test]
    fn a_variadic_hypothetical_uses_matching_direct_and_ordered_lists() {
        use crate::_internal::model::aggregate::AggregateKind;

        let catalogue = BuiltinTypeCatalogue::fallback();
        let casts = CastCatalogue::fallback();
        let resolver = CallTypeResolver::without_types(&catalogue);
        let mut routine = aggregate_routine(&["any"], AggregateKind::Hypothetical, 1);
        routine.parameters[0].mode = ParameterMode::Variadic;

        let direct = candidate_arguments(&["integer", "integer"], &resolver);
        assert!(
            routine_aggregate_match(&routine, &direct, &direct, true, &resolver, &casts).is_some(),
            "the direct and ordered lists must agree"
        );
        let shorter = candidate_arguments(&["integer"], &resolver);
        assert!(
            routine_aggregate_match(&routine, &direct, &shorter, true, &resolver, &casts).is_none()
        );
        let empty: Vec<CandidateArg> = Vec::new();
        assert!(
            routine_aggregate_match(&routine, &empty, &empty, true, &resolver, &casts).is_none()
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
            exact(2)
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
