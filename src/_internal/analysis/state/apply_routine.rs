use super::{AnalysisState, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::{
    AlterFunctionAction, FuncOptionFact, ParamModeFact, RetTypeFact, SecurityKind, VolatilityKind,
};
use crate::_internal::analysis::graph::DependencyKind;
use crate::_internal::analysis::mutations::{
    AlterAggregateMutation, AlterFunctionMutation, AlterProcedureMutation, CreateAggregateMutation,
    CreateFunctionMutation, CreateProcedureMutation, DropAggregateMutation, DropFunctionMutation,
    DropProcedureMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::function::{
    FunctionOverlay, FunctionState, RoutineKind, SecurityMode, Volatility,
};
use crate::_internal::model::trigger::TriggerOverlay;

type RoutineLookup = ObjectLookup;

impl AnalysisState {
    fn routine_lookup(
        &self,
        id: &ObjectId,
        expected: impl FnOnce(RoutineKind) -> bool,
    ) -> ObjectLookup {
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

    pub(super) fn apply_create_function(
        &mut self,
        function: &CreateFunctionMutation,
    ) -> MutationResult {
        if let Err(result) = self.ensure_schema_target(&function.id.schema) {
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
                return MutationResult::Conflict {
                    reason: format!("routine '{}' already exists", function.id),
                };
            }
            RoutineLookup::WrongKind => {
                return MutationResult::Conflict {
                    reason: format!("routine '{}' already exists", function.id),
                };
            }
            RoutineLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            _ => {}
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
            // FunctionState intentionally stores only the attributes used by
            // current rules.  Keep the useful identity/volatility fields, but
            // taint the state when PostgreSQL attributes such as STRICT,
            // PARALLEL, COST, or SUPPORT cannot be represented.
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
        }

        self.local.functions.insert(
            function.id.clone(),
            FunctionOverlay::Present(FunctionState {
                id: function.id.clone(),
                routine_kind,
                arg_types: function
                    .params
                    .iter()
                    .filter(|parameter| !matches!(&parameter.mode, ParamModeFact::Out))
                    .map(|parameter| parameter.ty.clone())
                    .collect(),
                arg_type_ids: function
                    .params
                    .iter()
                    .filter(|parameter| !matches!(&parameter.mode, ParamModeFact::Out))
                    .map(|parameter| self.resolve_type_reference(&parameter.ty))
                    .collect(),
                return_type: function
                    .return_type
                    .as_ref()
                    .map(|return_type| match return_type {
                        RetTypeFact::Scalar(ty) => ty.clone(),
                        RetTypeFact::Table(columns) => columns
                            .iter()
                            .map(|column| {
                                format!(
                                    "{} {}",
                                    column.name,
                                    column.ty.as_deref().unwrap_or("unknown")
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(", "),
                    })
                    .unwrap_or_default(),
                return_type_id: function.return_type.as_ref().and_then(|return_type| {
                    match return_type {
                        RetTypeFact::Scalar(ty) => self.resolve_type_reference(ty),
                        RetTypeFact::Table(_) => None,
                    }
                }),
                volatility,
                language,
                security,
            }),
        );
        MutationResult::Applied
    }

    pub(super) fn apply_alter_function(
        &mut self,
        function: &AlterFunctionMutation,
    ) -> MutationResult {
        match self.routine_lookup(&function.id, |kind| {
            matches!(kind, RoutineKind::Function | RoutineKind::Window)
        }) {
            RoutineLookup::Present => {}
            RoutineLookup::WrongKind => {
                return MutationResult::Conflict {
                    reason: format!("'{}' is not a function", function.id),
                };
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {
                return MutationResult::Conflict {
                    reason: format!("function '{}' does not exist", function.id),
                };
            }
            RoutineLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
        }

        match &function.action {
            AlterFunctionAction::OptionsChange(options) => {
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
            AlterFunctionAction::OwnerChange(_)
            | AlterFunctionAction::DependsOnExtension { .. }
            | AlterFunctionAction::NoDependsOnExtension { .. } => {
                // Ownership and extension dependencies are not represented
                // by FunctionState, so retaining Applied would overstate the
                // precision of subsequent dependency checks.
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_drop_function(
        &mut self,
        function: &DropFunctionMutation,
    ) -> MutationResult {
        // PostgreSQL resolves every target before applying a multi-target
        // DROP.  Preflight the complete set first so an unknown or invalid
        // later signature cannot leave an earlier function dropped in the
        // simulator when the statement itself would fail.
        let mut targets: Vec<(ObjectId, Vec<(ObjectId, ObjectId)>)> = Vec::new();
        for signature in &function.signatures {
            let signature_name = format!(
                "{}({})",
                signature.name.name.resolve(),
                signature.params.join(",")
            );
            let schema = self.resolve_function_schema(&signature.name, &signature_name);
            let id = ObjectId::new(schema, signature_name);
            match self.routine_lookup(&id, |kind| {
                matches!(kind, RoutineKind::Function | RoutineKind::Window)
            }) {
                RoutineLookup::WrongKind => {
                    return MutationResult::Conflict {
                        reason: format!("function '{}' does not exist", id),
                    };
                }
                RoutineLookup::Tombstone if function.if_exists => {}
                RoutineLookup::Tombstone => {
                    return MutationResult::Conflict {
                        reason: format!("function '{}' does not exist", id),
                    };
                }
                RoutineLookup::AuthoritativelyAbsent if !function.if_exists => {
                    return MutationResult::Conflict {
                        reason: format!("function '{}' does not exist", id),
                    };
                }
                RoutineLookup::Unknown => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
                RoutineLookup::Present => {
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
                            (function_id == &id)
                                .then(|| (edge.dependent.clone(), edge.referenced.clone()))
                        })
                        .collect();
                    if !dependent_triggers.is_empty() && !function.cascade {
                        return MutationResult::Conflict {
                            reason: format!(
                                "function '{}' still has dependent triggers; use CASCADE",
                                id
                            ),
                        };
                    }
                    if !targets.iter().any(|(existing, _)| existing == &id) {
                        targets.push((id, dependent_triggers));
                    }
                }
                RoutineLookup::AuthoritativelyAbsent => {}
            }
        }

        if targets.is_empty() {
            return MutationResult::Skipped;
        }

        if targets.iter().any(|(id, _)| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Routines,
            )
        }) {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
            return MutationResult::Skipped;
        }

        let any_applied = !targets.is_empty();
        for (id, dependent_triggers) in &targets {
            self.snapshot_function(id);
            self.local
                .functions
                .insert(id.clone(), FunctionOverlay::Dropped);

            if function.cascade {
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
                    if let Some(RelationOverlay::Present(relation)) =
                        self.local.relations.get_mut(table_id)
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
            }
        }
        if any_applied {
            MutationResult::Applied
        } else {
            MutationResult::Skipped
        }
    }

    pub(super) fn apply_create_procedure(
        &mut self,
        procedure: &CreateProcedureMutation,
    ) -> MutationResult {
        if let Err(result) = self.ensure_schema_target(&procedure.id.schema) {
            return result;
        }
        match self.routine_lookup(&procedure.id, |kind| kind == RoutineKind::Procedure) {
            RoutineLookup::Present if procedure.or_replace => {}
            RoutineLookup::Present | RoutineLookup::WrongKind => {
                return MutationResult::Conflict {
                    reason: format!("routine '{}' already exists", procedure.id),
                };
            }
            RoutineLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {}
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

        self.local.functions.insert(
            procedure.id.clone(),
            FunctionOverlay::Present(FunctionState {
                id: procedure.id.clone(),
                routine_kind: RoutineKind::Procedure,
                arg_types: procedure
                    .params
                    .iter()
                    .filter(|parameter| !matches!(&parameter.mode, ParamModeFact::Out))
                    .map(|parameter| parameter.ty.clone())
                    .collect(),
                arg_type_ids: procedure
                    .params
                    .iter()
                    .filter(|parameter| !matches!(&parameter.mode, ParamModeFact::Out))
                    .map(|parameter| self.resolve_type_reference(&parameter.ty))
                    .collect(),
                return_type: "void".to_string(),
                return_type_id: None,
                volatility,
                language,
                security,
            }),
        );
        MutationResult::Applied
    }

    pub(super) fn apply_alter_procedure(
        &mut self,
        procedure: &AlterProcedureMutation,
    ) -> MutationResult {
        match self.routine_lookup(&procedure.id, |kind| kind == RoutineKind::Procedure) {
            RoutineLookup::Present => {}
            RoutineLookup::WrongKind => {
                return MutationResult::Conflict {
                    reason: format!("'{}' is not a procedure", procedure.id),
                };
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {
                return MutationResult::Conflict {
                    reason: format!("procedure '{}' does not exist", procedure.id),
                };
            }
            RoutineLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
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
            _ => {
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                return MutationResult::Skipped;
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
            match self.routine_lookup(&id, |kind| kind == RoutineKind::Procedure) {
                RoutineLookup::Present => {
                    if !targets.contains(&id) {
                        targets.push(id);
                    }
                }
                RoutineLookup::WrongKind => {
                    return MutationResult::Conflict {
                        reason: format!("procedure '{}' does not exist", id),
                    };
                }
                RoutineLookup::Tombstone if procedure.if_exists => {}
                RoutineLookup::Tombstone => {
                    return MutationResult::Conflict {
                        reason: format!("procedure '{}' does not exist", id),
                    };
                }
                RoutineLookup::AuthoritativelyAbsent if !procedure.if_exists => {
                    return MutationResult::Conflict {
                        reason: format!("procedure '{}' does not exist", id),
                    };
                }
                RoutineLookup::Unknown => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
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
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
            return MutationResult::Skipped;
        }
        if procedure.cascade && !targets.is_empty() {
            // Procedure dependents are not yet represented as typed graph
            // edges. Applying CASCADE would therefore remove only the routine
            // while leaving PostgreSQL-owned dependents in simulated state.
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            return MutationResult::Skipped;
        }
        for id in &targets {
            self.snapshot_function(id);
            self.local
                .functions
                .insert(id.clone(), FunctionOverlay::Dropped);
        }
        if !targets.is_empty() {
            MutationResult::Applied
        } else {
            MutationResult::Skipped
        }
    }

    pub(super) fn apply_create_aggregate(
        &mut self,
        aggregate: &CreateAggregateMutation,
    ) -> MutationResult {
        if let Err(result) = self.ensure_schema_target(&aggregate.id.schema) {
            return result;
        }
        match self.routine_lookup(&aggregate.id, |kind| kind == RoutineKind::Aggregate) {
            RoutineLookup::Present if aggregate.or_replace => {}
            RoutineLookup::Present | RoutineLookup::WrongKind => {
                return MutationResult::Conflict {
                    reason: format!("routine '{}' already exists", aggregate.id),
                };
            }
            RoutineLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {}
        }
        // Aggregate transition options (SFUNC/STYPE/final/combine state and
        // related catalog dependencies) are not carried by this mutation.
        // Keep the routine identity for conservative lookup, but never claim
        // the resulting aggregate state is exact.
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        self.snapshot_function(&aggregate.id);
        self.local.functions.insert(
            aggregate.id.clone(),
            FunctionOverlay::Present(FunctionState {
                id: aggregate.id.clone(),
                routine_kind: RoutineKind::Aggregate,
                arg_types: aggregate
                    .params
                    .iter()
                    .filter(|parameter| !matches!(parameter.mode, ParamModeFact::Out))
                    .map(|parameter| parameter.ty.clone())
                    .collect(),
                arg_type_ids: aggregate
                    .params
                    .iter()
                    .filter(|parameter| !matches!(parameter.mode, ParamModeFact::Out))
                    .map(|parameter| self.resolve_type_reference(&parameter.ty))
                    .collect(),
                return_type: String::new(),
                return_type_id: None,
                volatility: Volatility::Volatile,
                language: "internal".to_string(),
                security: SecurityMode::Invoker,
            }),
        );
        MutationResult::Applied
    }

    pub(super) fn apply_alter_aggregate(
        &mut self,
        aggregate: &AlterAggregateMutation,
    ) -> MutationResult {
        match self.routine_lookup(&aggregate.id, |kind| kind == RoutineKind::Aggregate) {
            RoutineLookup::Present => {}
            RoutineLookup::WrongKind => {
                return MutationResult::Conflict {
                    reason: format!("'{}' is not an aggregate", aggregate.id),
                };
            }
            RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {
                return MutationResult::Conflict {
                    reason: format!("aggregate '{}' does not exist", aggregate.id),
                };
            }
            RoutineLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
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
            AlterFunctionAction::OwnerChange(_) => {
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
            _ => unreachable!("aggregate extraction only emits rename, owner, or schema"),
        }
        MutationResult::Applied
    }

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
            match self.routine_lookup(&id, |kind| kind == RoutineKind::Aggregate) {
                RoutineLookup::Present => {
                    if !targets.contains(&id) {
                        targets.push(id);
                    }
                }
                RoutineLookup::WrongKind => {
                    return MutationResult::Conflict {
                        reason: format!("aggregate '{}' does not exist", id),
                    };
                }
                RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent
                    if aggregate.if_exists => {}
                RoutineLookup::Tombstone | RoutineLookup::AuthoritativelyAbsent => {
                    return MutationResult::Conflict {
                        reason: format!("aggregate '{}' does not exist", id),
                    };
                }
                RoutineLookup::Unknown => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
            }
        }
        if targets.iter().any(|id| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Routines,
            )
        }) {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
            return MutationResult::Skipped;
        }
        if aggregate.cascade && !targets.is_empty() {
            // Aggregate implementation-function and dependent-object edges
            // are not modeled yet; CASCADE must not claim a partial closure.
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            return MutationResult::Skipped;
        }
        for id in &targets {
            self.snapshot_function(id);
            self.local
                .functions
                .insert(id.clone(), FunctionOverlay::Dropped);
        }
        if !targets.is_empty() {
            MutationResult::Applied
        } else {
            MutationResult::Skipped
        }
    }

    fn function_option_unmodeled(option: &FuncOptionFact) -> bool {
        !matches!(
            option,
            FuncOptionFact::Language(_)
                | FuncOptionFact::Volatility(_)
                | FuncOptionFact::Security(_)
                | FuncOptionFact::Window
        )
    }
}
