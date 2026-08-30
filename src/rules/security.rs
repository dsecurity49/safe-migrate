use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult, PreState};
use crate::engine::config::Config;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
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
        result: &MutationResult,
        _pre_state: &PreState,
        state: &AnalysisState,
        _config: &Config,
        _cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        // `WITH GRANT OPTION` is itself the security-sensitive operation. The
        // state matrix intentionally skips it because grant chains are not
        // modeled, but that uncertainty must not suppress the syntax-level
        // warning for a statement PostgreSQL will execute.
        let skipped_grant_option = *result == MutationResult::Skipped
            && matches!(
                mutation,
                Mutation::Grant(grant) if grant.with_grant_option
            );
        if *result == MutationResult::Skipped && !skipped_grant_option {
            return vec![];
        }
        let mut violations = Vec::new();

        if let Mutation::Grant(grant) = mutation {
            let (obj_kind, obj_name) = match &grant.target {
                crate::analysis::mutations::ResolvedGrantTarget::Tables(tables) => (
                    ObjectKind::Table,
                    tables
                        .iter()
                        .map(|t| t.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                crate::analysis::mutations::ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                    (ObjectKind::Schema, schemas.join(", "))
                }
            };

            let is_public = grant.grantees.iter().any(|g| {
                if let crate::analysis::facts::RoleFact::Named { name, .. } = g {
                    name == "public"
                } else {
                    false
                }
            });
            if is_public {
                violations.push(Violation {
                    source_range: None,
                    rule_id: self.id(),
                    operation_kind: OperationKind::Grant,
                    object_kind: obj_kind.clone(),
                    object_name: obj_name.clone(),
                    tier: ViolationTier::Tier1,
                    reason: "Grant to PUBLIC".to_string(),
                    recipe: "GRANT to PUBLIC is almost never intended as it applies to every role.",
                    dedup_key: None,
                    sql: None,
                    fk_dependency_related: false,
                });
            }

            let is_all_privs = match &grant.privileges {
                crate::analysis::facts::PrivilegeSpec::All => true,
                crate::analysis::facts::PrivilegeSpec::List(privs) => privs
                    .iter()
                    .any(|p| matches!(p, crate::analysis::facts::PrivilegeFact::All)),
            };

            if is_all_privs {
                let every_grantee_owns_every_table = match &grant.target {
                    crate::analysis::mutations::ResolvedGrantTarget::Tables(tables)
                        if !tables.is_empty() && !grant.grantees.is_empty() =>
                    {
                        grant.grantees.iter().all(|grantee| {
                            let crate::analysis::facts::RoleFact::Named { name, .. } = grantee
                            else {
                                return false;
                            };
                            // PostgreSQL roles are global, so owner comparison
                            // uses the role name.
                            tables.iter().all(|table_id| {
                                matches!(
                                    state.local.relations.get(table_id),
                                    Some(crate::model::relation::RelationOverlay::Present(relation))
                                        if relation.owner.name == *name
                                )
                            })
                        })
                    }
                    _ => false,
                };
                if !every_grantee_owns_every_table {
                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::Grant,
                        object_kind: obj_kind.clone(),
                        object_name: obj_name.clone(),
                        tier: ViolationTier::Tier2,
                        reason: "Overbroad Grant: ALL PRIVILEGES".to_string(),
                        recipe: "GRANT ALL PRIVILEGES to a role that is not the owner is risky.",
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    });
                }
            }

            if grant.with_grant_option {
                violations.push(Violation { source_range: None,
                    rule_id: self.id(),
                    operation_kind: OperationKind::Grant,
                    object_kind: obj_kind,
                    object_name: obj_name,
                    tier: ViolationTier::Tier2,
                    reason: "Overbroad Grant: WITH GRANT OPTION".to_string(),
                    recipe: "WITH GRANT OPTION allows the grantee to re-grant privileges, widening the blast radius.",
                    dedup_key: None,
                            sql: None,
                            fk_dependency_related: false,
                });
            }
        }
        violations
    }
}
