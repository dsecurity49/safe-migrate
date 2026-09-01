use crate::analysis::mutations::Mutation;
use crate::ast::identifiers::ObjectId;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::{BASELINE_RELATION_CAPABILITIES, Rule, RuleCapability, RuleContext};

pub struct DriftDetectionRule;

impl Rule for DriftDetectionRule {
    fn id(&self) -> &'static str {
        "schema-drift"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "This migration references a database object that does not exist in the production baseline. If this object exists in production, sync the cache with `safe-migrate sync`. If it does not, this migration may fail."
    }

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        BASELINE_RELATION_CAPABILITIES
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        // A missing cache is not proof that production lacks an object. Keep
        // the stateful analyzer useful offline without turning every ALTER or
        // DROP into a false blocking baseline-drift finding.
        if !context.state().baseline_is_available() {
            return Vec::new();
        }

        let pre_state = context.pre_state();
        let state = context.state();

        let mut violations = Vec::new();

        match context.mutation() {
            Mutation::Opaque(crate::analysis::mutations::OpaqueMutation::UnresolvedReference {
                object_kind,
                object_name,
            }) => {
                violations.push(Violation { source_range: None,
                    rule_id: self.id(),
                        operation_kind: OperationKind::UnresolvedReference,
                    object_kind: object_kind.clone(),
                    object_name: object_name.clone(),
                    tier: self.default_tier(),
                    reason: format!(
                        "Migration references {} \"{}\" which does not exist in the production baseline",
                        object_kind,
                        object_name
                    ),
                    recipe: self.recipe(),
                    dedup_key: None,
                    sql: None,
                    fk_dependency_related: false,
                });
            }
            Mutation::DropTable(d) => {
                if !d.if_exists {
                    for id in &d.ids {
                        if !pre_state.relations.contains_key(id) {
                            violations.push(Violation { source_range: None,
                                rule_id: self.id(),
                                operation_kind: OperationKind::DropTable,
                                object_kind: ObjectKind::Table,
                                object_name: id.to_string(),
                                tier: self.default_tier(),
                                reason: format!(
                                    "Migration DROPs table \"{}\" which does not exist in the production baseline",
                                    id
                                ),
                                recipe: self.recipe(),
                                dedup_key: None,
                                sql: None,
                                fk_dependency_related: false,
                            });
                        }
                    }
                }
            }
            Mutation::AlterTable(a) => {
                if !pre_state.relations.contains_key(&a.id) {
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::Other("alter_table".to_string()),
                        object_kind: ObjectKind::Table,
                        object_name: a.id.to_string(),
                        tier: self.default_tier(),
                        reason: format!(
                            "Migration ALTERs table \"{}\" which does not exist in the production baseline",
                            a.id
                        ),
                        recipe: self.recipe(),
                        dedup_key: None,
                                    sql: None,
                                    fk_dependency_related: false,
                    });
                }
            }
            Mutation::DropView(d) => {
                for id in &d.ids {
                    if !d.if_exists && !pre_state.relations.contains_key(id) {
                        violations.push(Violation { source_range: None,
                            rule_id: self.id(),
                            operation_kind: OperationKind::DropView,
                            object_kind: ObjectKind::View,
                            object_name: id.to_string(),
                            tier: self.default_tier(),
                            reason: format!(
                                "Migration DROPs view \"{}\" which does not exist in the production baseline",
                                id
                            ),
                            recipe: self.recipe(),
                            dedup_key: None,
                                            sql: None,
                                            fk_dependency_related: false,
                        });
                    }
                }
            }
            Mutation::DropMaterializedView(d) => {
                for id in &d.ids {
                    if !d.if_exists && !pre_state.relations.contains_key(id) {
                        violations.push(Violation { source_range: None,
                            rule_id: self.id(),
                            operation_kind: OperationKind::DropMaterializedView,
                            object_kind: ObjectKind::MaterializedView,
                            object_name: id.to_string(),
                            tier: self.default_tier(),
                            reason: format!(
                                "Migration DROPs materialized view \"{}\" which does not exist in the production baseline",
                                id
                            ),
                            recipe: self.recipe(),
                            dedup_key: None,
                                            sql: None,
                                            fk_dependency_related: false,
                        });
                    }
                }
            }
            Mutation::DropSequence(d) => {
                for id in &d.ids {
                    if !d.if_exists && !pre_state.sequences.contains_key(id) {
                        violations.push(Violation { source_range: None,
                            rule_id: self.id(),
                            operation_kind: OperationKind::DropSequence,
                            object_kind: ObjectKind::Sequence,
                            object_name: id.to_string(),
                            tier: self.default_tier(),
                            reason: format!(
                                "Migration DROPs sequence \"{}\" which does not exist in the production baseline",
                                id
                            ),
                            recipe: self.recipe(),
                            dedup_key: None,
                                            sql: None,
                                            fk_dependency_related: false,
                        });
                    }
                }
            }
            Mutation::DropFunction(d) => {
                for sig in &d.signatures {
                    let sig_str = format!("{}({})", sig.name.name.resolve(), sig.params.join(","));
                    let schema = state.resolve_function_schema(&sig.name, &sig_str);
                    let id = ObjectId::new(schema, sig_str);
                    if !d.if_exists && !pre_state.functions.contains_key(&id) {
                        violations.push(Violation { source_range: None,
                            rule_id: self.id(),
                            operation_kind: OperationKind::DropFunction,
                            object_kind: ObjectKind::Function,
                            object_name: id.to_string(),
                            tier: self.default_tier(),
                            reason: format!(
                                "Migration DROPs function \"{}\" which does not exist in the production baseline",
                                id
                            ),
                            recipe: self.recipe(),
                            dedup_key: None,
                                            sql: None,
                                            fk_dependency_related: false,
                        });
                    }
                }
            }
            Mutation::DropIndex(d) => {
                for id in &d.ids {
                    if !d.if_exists && !pre_state.indexes.iter().any(|idx| idx.dependent == *id) {
                        violations.push(Violation { source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::DropIndex,
                        object_kind: ObjectKind::Index,
                        object_name: id.to_string(),
                        tier: self.default_tier(),
                        reason: format!(
                            "Migration DROPs index \"{}\" which does not exist in the production baseline",
                            id
                        ),
                        recipe: self.recipe(),
                        dedup_key: None,
                                    sql: None,
                                    fk_dependency_related: false,
                        });
                    }
                }
            }
            Mutation::DropDomain(d) => {
                for id in &d.ids {
                    if !d.if_exists && !pre_state.types.contains_key(id) {
                        violations.push(Violation { source_range: None,
                            rule_id: self.id(),
                            operation_kind: OperationKind::DropDomain,
                            object_kind: ObjectKind::Domain,
                            object_name: id.to_string(),
                            tier: self.default_tier(),
                            reason: format!(
                                "Migration DROPs domain \"{}\" which does not exist in the production baseline",
                                id
                            ),
                            recipe: self.recipe(),
                            dedup_key: None,
                                            sql: None,
                                            fk_dependency_related: false,
                        });
                    }
                }
            }
            Mutation::DropType(d) => {
                for id in &d.ids {
                    if !d.if_exists && !pre_state.types.contains_key(id) {
                        violations.push(Violation { source_range: None,
                            rule_id: self.id(),
                            operation_kind: OperationKind::DropType,
                            object_kind: ObjectKind::Type,
                            object_name: id.to_string(),
                            tier: self.default_tier(),
                            reason: format!(
                                "Migration DROPs type \"{}\" which does not exist in the production baseline",
                                id
                            ),
                            recipe: self.recipe(),
                            dedup_key: None,
                            sql: None,
                            fk_dependency_related: false,
                        });
                    }
                }
            }
            Mutation::Rename(r) => {
                if !pre_state.relations.contains_key(&r.old_id)
                    && !pre_state.types.contains_key(&r.old_id)
                    && !pre_state.sequences.contains_key(&r.old_id)
                    && !pre_state
                        .indexes
                        .iter()
                        .any(|idx| idx.dependent == r.old_id)
                {
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::Rename,
                        object_kind: ObjectKind::Table, // Or general
                        object_name: r.old_id.to_string(),
                        tier: self.default_tier(),
                        reason: format!(
                            "Migration RENAMEs object \"{}\" which does not exist in the production baseline",
                            r.old_id
                        ),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    });
                }
            }
            Mutation::AlterType(a) if !pre_state.types.contains_key(&a.id) => {
                violations.push(Violation { source_range: None,
                    rule_id: self.id(),
                    operation_kind: OperationKind::AlterType,
                    object_kind: ObjectKind::Type,
                    object_name: a.id.to_string(),
                    tier: self.default_tier(),
                    reason: format!(
                        "Migration ALTERs type \"{}\" which does not exist in the production baseline",
                        a.id
                    ),
                    recipe: self.recipe(),
                    dedup_key: None,
                            sql: None,
                            fk_dependency_related: false,
                });
            }
            Mutation::AlterFunction(f) if !pre_state.functions.contains_key(&f.id) => {
                violations.push(Violation { source_range: None,
                    rule_id: self.id(),
                    operation_kind: OperationKind::AlterFunction,
                    object_kind: ObjectKind::Function,
                    object_name: f.id.to_string(),
                    tier: self.default_tier(),
                    reason: format!(
                        "Migration ALTERs function \"{}\" which does not exist in the production baseline",
                        f.id
                    ),
                    recipe: self.recipe(),
                    dedup_key: None,
                            sql: None,
                            fk_dependency_related: false,
                });
            }
            Mutation::DropProcedure(d) => {
                for signature in &d.signatures {
                    let signature_name = format!(
                        "{}({})",
                        signature.name.name.resolve(),
                        signature.params.join(",")
                    );
                    let schema = state.resolve_function_schema(&signature.name, &signature_name);
                    let id = ObjectId::new(schema, signature_name);
                    let procedure_exists = pre_state.functions.get(&id).is_some_and(|routine| {
                        routine.routine_kind == crate::model::function::RoutineKind::Procedure
                    });
                    if !d.if_exists && !procedure_exists {
                        violations.push(Violation {
                            source_range: None,
                            rule_id: self.id(),
                            operation_kind: OperationKind::DropProcedure,
                            object_kind: ObjectKind::Procedure,
                            object_name: id.to_string(),
                            tier: self.default_tier(),
                            reason: format!(
                                "Migration DROPs procedure \"{}\" which does not exist in the production baseline",
                                id
                            ),
                            recipe: self.recipe(),
                            dedup_key: None,
                            sql: None,
                            fk_dependency_related: false,
                        });
                    }
                }
            }
            Mutation::AlterProcedure(procedure) => {
                let procedure_exists =
                    pre_state
                        .functions
                        .get(&procedure.id)
                        .is_some_and(|routine| {
                            routine.routine_kind == crate::model::function::RoutineKind::Procedure
                        });
                if !procedure_exists {
                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::AlterProcedure,
                        object_kind: ObjectKind::Procedure,
                        object_name: procedure.id.to_string(),
                        tier: self.default_tier(),
                        reason: format!(
                            "Migration ALTERs procedure \"{}\" which does not exist in the production baseline",
                            procedure.id
                        ),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    });
                }
            }
            Mutation::CreateTable(c) => {
                // Warn if parent table doesn't exist for partitioned tables
                if let Some(parent_id) = &c.partition_of
                    && !pre_state.relations.contains_key(parent_id)
                {
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::CreateTable,
                        object_kind: ObjectKind::Table,
                        object_name: c.id.to_string(),
                        tier: self.default_tier(),
                        reason: format!(
                            "Migration creates {} as a partition of parent \"{}\" which does not exist in the production baseline. Parent must be created first.",
                            c.id, parent_id
                        ),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    });
                }
            }
            _ => {}
        }

        // When sync was deliberately scoped, an omitted schema is unknown,
        // not proof of production drift. Keep the warning, but make it a
        // coverage warning rather than a false Tier 1 absence claim.
        for violation in &mut violations {
            if let Some(schema) =
                state.baseline_scope_omits_displayed_object(&violation.object_name)
            {
                violation.tier = ViolationTier::Tier2;
                violation.reason = format!(
                    "Cache does not cover schema \"{}\"; safe-migrate cannot verify whether {} exists in the production baseline",
                    schema, violation.object_name
                );
                violation.recipe = "Run `safe-migrate sync --schemas ...` with this schema included, or use an unscoped sync, before treating this as a production-drift result.";
            }
        }

        violations
    }
}
