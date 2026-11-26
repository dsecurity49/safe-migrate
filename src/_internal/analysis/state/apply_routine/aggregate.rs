use super::super::{AnalysisState, MutationResult, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::{
    AlterFunctionAction, FuncOptionFact, ParamModeFact, RetTypeFact,
};
use crate::_internal::analysis::graph::{DependencyEdge, DependencyGraph, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterAggregateMutation, AlterFunctionMutation, AlterProcedureMutation, AlterRoutineMutation,
    CreateAggregateMutation, DropAggregateMutation, DropRoutineMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::function::{
    FunctionOverlay, FunctionState, RoutineKind, SecurityMode, Volatility,
};
use crate::_internal::model::trigger::TriggerOverlay;
use std::collections::HashSet;

use super::{DropTarget, RoutineLookup};

impl AnalysisState {
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

    pub(in crate::_internal::analysis::state) fn apply_create_aggregate(
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

    pub(in crate::_internal::analysis::state) fn apply_alter_aggregate(
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
    pub(in crate::_internal::analysis::state) fn apply_routine_cascade_drop(
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
    pub(in crate::_internal::analysis::state) fn apply_drop_aggregate(
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

    pub(in crate::_internal::analysis::state) fn resolve_unique_routine_by_name(
        &self,
        raw_name: &str,
    ) -> Option<ObjectId> {
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

    pub(in crate::_internal::analysis::state) fn record_routine_body_dependencies(
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

    pub(in crate::_internal::analysis::state) fn apply_alter_routine(
        &mut self,
        routine: &AlterRoutineMutation,
    ) -> MutationResult {
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

    pub(in crate::_internal::analysis::state) fn apply_drop_routine(
        &mut self,
        routine: &DropRoutineMutation,
    ) -> MutationResult {
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
                    let dependent_casts = self.local.casts.casts_using_function(&id);
                    if !dependent_casts.is_empty() && !routine.cascade {
                        return MutationResult::conflict(format!(
                            "cannot drop function {} because cast from {} to {} requires it; use CASCADE",
                            id, dependent_casts[0].0, dependent_casts[0].1
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

    pub(in crate::_internal::analysis::state) fn function_option_unmodeled(
        option: &FuncOptionFact,
    ) -> bool {
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
