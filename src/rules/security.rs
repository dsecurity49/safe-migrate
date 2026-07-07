use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult, PreState};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier, OperationKind, ObjectKind};
use crate::rules::Rule;

pub struct OverbroadGrantRule;

impl Rule for OverbroadGrantRule {
    fn id(&self) -> &'static str {
        "overbroad-grant"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier2
    }
    fn recipe(&self) -> &'static str {
        "Avoid GRANT ALL to public roles. Use granular privileges."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &PreState,
        state: &AnalysisState,
        _config: &Config,
        _cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Mutation::Grant(grant) = mutation {
            // Determine object_name and object_kind if possible
            let (obj_kind, obj_name) = match &grant.target {
                crate::analysis::mutations::ResolvedGrantTarget::Tables(tables) => {
                    (ObjectKind::Table, tables.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(", "))
                }
                crate::analysis::mutations::ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                    (ObjectKind::Schema, schemas.join(", "))
                }
            };

            // Case 1: GRANT ... TO PUBLIC -> Tier 1
            let is_public = grant.grantees.iter().any(|g| {
                if let crate::analysis::facts::RoleFact::Named { name, .. } = g {
                    name == "public"
                } else {
                    false
                }
            });
            if is_public {
                violations.push(Violation {
                    rule_id: self.id(),
                    operation_kind: OperationKind::Grant,
                    object_kind: obj_kind.clone(),
                    object_name: obj_name.clone(),
                    tier: ViolationTier::Tier1,
                    reason: "Grant to PUBLIC".to_string(),
                    recipe: "GRANT to PUBLIC is almost never intended as it applies to every role.",
                    dedup_key: None,
                            sql: None,
                });
            }

            // Case 2: GRANT ALL PRIVILEGES to a non-owner role -> Tier 2
            let is_all_privs = match &grant.privileges {
                crate::analysis::facts::PrivilegeSpec::All => true,
                crate::analysis::facts::PrivilegeSpec::List(privs) => {
                    privs.iter().any(|p| matches!(p, crate::analysis::facts::PrivilegeFact::All))
                }
            };

            if is_all_privs {
                let mut is_owner = false;
                if let crate::analysis::mutations::ResolvedGrantTarget::Tables(tables) = &grant.target {
                    for table_id in tables {
                        if let Some(crate::model::relation::RelationOverlay::Present(rel)) = state.local.relations.get(table_id)
                            && grant.grantees.iter().any(|g| {
                                if let crate::analysis::facts::RoleFact::Named { name, .. } = g {
                                    // Simple name match for owner check
                                    rel.owner.name == *name
                                } else {
                                    false
                                }
                              })
                        {
                            is_owner = true;
                            break;
                        }
                    }
                }
                if !is_owner {
                    violations.push(Violation {
                        rule_id: self.id(),
                        operation_kind: OperationKind::Grant,
                        object_kind: obj_kind.clone(),
                        object_name: obj_name.clone(),
                        tier: ViolationTier::Tier2,
                        reason: "Overbroad Grant: ALL PRIVILEGES".to_string(),
                        recipe: "GRANT ALL PRIVILEGES to a role that is not the owner is risky.",
                        dedup_key: None,
                                    sql: None,
                    });
                }
            }

            // Case 3: WITH GRANT OPTION -> Tier 2
            if grant.with_grant_option {
                violations.push(Violation {
                    rule_id: self.id(),
                    operation_kind: OperationKind::Grant,
                    object_kind: obj_kind,
                    object_name: obj_name,
                    tier: ViolationTier::Tier2,
                    reason: "Overbroad Grant: WITH GRANT OPTION".to_string(),
                    recipe: "WITH GRANT OPTION allows the grantee to re-grant privileges, widening the blast radius.",
                    dedup_key: None,
                            sql: None,
                });
            }
        }
        violations
    }
}
