use super::{AnalysisState, Confidence, MutationResult, ObjectLookup};
use crate::analysis::facts::RoleFact;
use crate::analysis::mutations::{
    AlterRoleMutation, CreateRoleMutation, DropRoleMutation, GrantMutation, ResolvedGrantTarget,
    RevokeMutation,
};
use crate::ast::identifiers::ObjectId;
use crate::model::role::{RoleOverlay, RoleState};

type RoleLookup = ObjectLookup;

impl AnalysisState {
    fn role_lookup(&self, id: &ObjectId) -> RoleLookup {
        match self.local.roles.get(id) {
            Some(RoleOverlay::Present(_)) => RoleLookup::Present,
            Some(RoleOverlay::Dropped) => RoleLookup::Tombstone,
            None if self.local.roles_known => RoleLookup::AuthoritativelyAbsent,
            None => RoleLookup::Unknown,
        }
    }

    pub(super) fn apply_create_role(&mut self, role: &CreateRoleMutation) -> MutationResult {
        let role_id = ObjectId::new("", &role.name);
        match self.role_lookup(&role_id) {
            RoleLookup::Present => {
                return MutationResult::Conflict {
                    reason: format!("role '{}' already exists", role.name),
                };
            }
            RoleLookup::Unknown => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
            }
            RoleLookup::Tombstone | RoleLookup::AuthoritativelyAbsent => {}
            RoleLookup::WrongKind => unreachable!("roles have a dedicated namespace"),
        }
        if !role.inherits {
            // RoleState intentionally does not carry the PostgreSQL INHERIT
            // bit yet; do not claim an exact state transition for NOINHERIT.
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
        }
        self.snapshot_role(&role_id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        self.local.roles.insert(
            role_id.clone(),
            RoleOverlay::Present(RoleState {
                id: role_id,
                can_login: role.can_login,
                is_superuser: false,
                member_of: Vec::new(),
                can_set_role_to: Vec::new(),
                granted_privileges: Vec::new(),
            }),
        );
        MutationResult::Applied
    }

    pub(super) fn apply_alter_role(&mut self, role: &AlterRoleMutation) -> MutationResult {
        let Some(role_id) = Self::resolve_role_name(
            &role.name,
            &self.local.current_role,
            &self.local.session_role,
        ) else {
            return MutationResult::Skipped;
        };
        self.snapshot_role(&role_id);
        match self.role_lookup(&role_id) {
            RoleLookup::Present => {}
            RoleLookup::Tombstone | RoleLookup::AuthoritativelyAbsent => {
                return MutationResult::Conflict {
                    reason: format!("role '{}' does not exist", role_id.name),
                };
            }
            RoleLookup::Unknown => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                return MutationResult::Skipped;
            }
            RoleLookup::WrongKind => unreachable!("roles have a dedicated namespace"),
        }
        if role.inherits.is_some() {
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
            return MutationResult::Skipped;
        }
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        MutationResult::Applied
    }

    pub(super) fn apply_drop_role(&mut self, role: &DropRoleMutation) -> MutationResult {
        let mut present_roles = Vec::new();
        for name in &role.names {
            if let Some(role_id) = Self::resolve_role_name(
                &RoleFact::Named {
                    name: name.clone(),
                    via_legacy_group_syntax: false,
                },
                &self.local.current_role,
                &self.local.session_role,
            ) {
                match self.role_lookup(&role_id) {
                    RoleLookup::Present => present_roles.push(role_id),
                    RoleLookup::Tombstone | RoleLookup::AuthoritativelyAbsent if role.if_exists => {
                        continue;
                    }
                    RoleLookup::Tombstone | RoleLookup::AuthoritativelyAbsent => {
                        return MutationResult::Conflict {
                            reason: format!("role '{}' does not exist", name),
                        };
                    }
                    RoleLookup::Unknown => {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                    RoleLookup::WrongKind => unreachable!("roles have a dedicated namespace"),
                }
            }
        }
        // DROP ROLE can fail because a role owns objects or has
        // memberships/privileges. Those dependencies are not represented
        // completely in RoleState, so do not claim an exact drop when a
        // catalog-backed role list is available.
        if self.local.roles_known && !present_roles.is_empty() {
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
            return MutationResult::Skipped;
        }
        for role_id in present_roles {
            self.snapshot_role(&role_id);
            self.local.roles.insert(role_id, RoleOverlay::Dropped);
        }
        MutationResult::Applied
    }

    pub(super) fn apply_grant(&mut self, grant: &GrantMutation) -> MutationResult {
        if let Err(result) = self.validate_grant_targets(&grant.target) {
            return result;
        }
        let grantees = match self.validate_role_facts(&grant.grantees) {
            Ok(roles) => roles,
            Err(result) => return result,
        };
        if let Some(granted_by) = grant.granted_by.as_ref() {
            if let Err(result) = self.validate_role_facts(std::slice::from_ref(granted_by)) {
                return result;
            }
            // GRANTED BY changes the authorization check, which is not part
            // of the privilege matrix.  Keep the matrix untouched rather
            // than silently treating an authorization-sensitive statement as
            // exact.
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
            return MutationResult::Skipped;
        }
        if grant.with_grant_option {
            // PrivilegeMatrix records effective privileges but not grant
            // options or grant chains.
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
            return MutationResult::Skipped;
        }
        let privileges = self.resolve_grant_privileges(&grant.privileges);
        match &grant.target {
            ResolvedGrantTarget::Tables(ids) => {
                for id in ids {
                    self.apply_grant_to_relation(id, &privileges, &grantees);
                }
            }
            ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                let target_ids: Vec<ObjectId> = self
                    .local
                    .relations
                    .keys()
                    .filter(|id| schemas.contains(&id.schema))
                    .cloned()
                    .collect();
                for id in &target_ids {
                    self.apply_grant_to_relation(id, &privileges, &grantees);
                }
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_revoke(&mut self, revoke: &RevokeMutation) -> MutationResult {
        if let Err(result) = self.validate_grant_targets(&revoke.target) {
            return result;
        }
        let revokees = match self.validate_role_facts(&revoke.revokees) {
            Ok(roles) => roles,
            Err(result) => return result,
        };
        if let Some(granted_by) = revoke.granted_by.as_ref() {
            if let Err(result) = self.validate_role_facts(std::slice::from_ref(granted_by)) {
                return result;
            }
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
            return MutationResult::Skipped;
        }
        if revoke.grant_option_only || revoke.cascade {
            // The matrix has no grant-option or dependency-chain state, so a
            // GRANT OPTION/CASCADE revoke cannot be represented exactly.
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
            return MutationResult::Skipped;
        }
        let privileges = self.resolve_grant_privileges(&revoke.privileges);
        match &revoke.target {
            ResolvedGrantTarget::Tables(ids) => {
                for id in ids {
                    self.apply_revoke_to_relation(id, &privileges, &revokees);
                }
            }
            ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                let target_ids: Vec<ObjectId> = self
                    .local
                    .relations
                    .keys()
                    .filter(|id| schemas.contains(&id.schema))
                    .cloned()
                    .collect();
                for id in &target_ids {
                    self.apply_revoke_to_relation(id, &privileges, &revokees);
                }
            }
        }
        MutationResult::Applied
    }

    fn validate_grant_targets(
        &mut self,
        target: &ResolvedGrantTarget,
    ) -> Result<(), MutationResult> {
        match target {
            ResolvedGrantTarget::Tables(ids) => {
                for id in ids {
                    self.ensure_relation_target(
                        id,
                        |kind| {
                            matches!(
                                kind,
                                crate::model::relation::RelationKind::Table
                                    | crate::model::relation::RelationKind::View
                                    | crate::model::relation::RelationKind::MaterializedView
                            )
                        },
                        format!("grant target relation '{}' does not exist", id),
                        format!("grant target '{}' is not grantable", id),
                    )?;
                }
            }
            ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                for schema in schemas {
                    self.ensure_schema_target(schema)?;
                }
            }
        }
        Ok(())
    }

    fn validate_role_facts(&mut self, facts: &[RoleFact]) -> Result<Vec<ObjectId>, MutationResult> {
        let mut ids = Vec::with_capacity(facts.len());
        for fact in facts {
            let Some((name, _identity_known)) = self.role_fact_identity(fact) else {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                return Err(MutationResult::Skipped);
            };
            // PUBLIC is a PostgreSQL pseudo-role, not a row in pg_roles.
            if name.eq_ignore_ascii_case("public") {
                ids.push(ObjectId::new("", "public"));
                continue;
            }
            let id = ObjectId::new("", name.clone());
            match self.role_lookup(&id) {
                RoleLookup::Present => ids.push(id),
                RoleLookup::Tombstone | RoleLookup::AuthoritativelyAbsent => {
                    return Err(MutationResult::Conflict {
                        reason: format!("role '{}' does not exist", name),
                    });
                }
                RoleLookup::Unknown => {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    // A cache without a complete role catalog cannot prove
                    // the role's existence, but the privilege grant itself
                    // is still useful state. Preserve it while making the
                    // uncertainty explicit instead of silently dropping it.
                    ids.push(id);
                }
                RoleLookup::WrongKind => unreachable!("roles have a dedicated namespace"),
            }
        }
        Ok(ids)
    }
}
