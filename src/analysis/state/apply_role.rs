use super::{AnalysisState, Confidence, MutationResult};
use crate::analysis::facts::RoleFact;
use crate::analysis::mutations::{
    AlterRoleMutation, CreateRoleMutation, DropRoleMutation, GrantMutation, ResolvedGrantTarget,
    RevokeMutation,
};
use crate::ast::identifiers::ObjectId;
use crate::model::role::{RoleOverlay, RoleState};

impl AnalysisState {
    pub(super) fn apply_create_role(&mut self, role: &CreateRoleMutation) -> MutationResult {
        let role_id = ObjectId::new("", &role.name);
        if matches!(
            self.local.roles.get(&role_id),
            Some(RoleOverlay::Present(_))
        ) {
            return MutationResult::Conflict {
                reason: format!("role '{}' already exists", role.name),
            };
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
        if !self.local.roles.contains_key(&role_id) {
            self.local.confidence = Confidence::Tainted;
            return MutationResult::Skipped;
        }
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        MutationResult::Applied
    }

    pub(super) fn apply_drop_role(&mut self, role: &DropRoleMutation) -> MutationResult {
        for name in &role.names {
            if let Some(role_id) = Self::resolve_role_name(
                &RoleFact::Named {
                    name: name.clone(),
                    via_legacy_group_syntax: false,
                },
                &self.local.current_role,
                &self.local.session_role,
            ) {
                self.snapshot_role(&role_id);
                if !role.if_exists
                    && !matches!(
                        self.local.roles.get(&role_id),
                        Some(RoleOverlay::Present(_))
                    )
                {
                    return MutationResult::Conflict {
                        reason: format!("role '{}' does not exist", name),
                    };
                }
                self.local.roles.insert(role_id, RoleOverlay::Dropped);
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_grant(&mut self, grant: &GrantMutation) -> MutationResult {
        let privileges = Self::resolve_grant_privileges(&grant.privileges);
        match &grant.target {
            ResolvedGrantTarget::Tables(ids) => {
                for id in ids {
                    self.apply_grant_to_relation(id, &privileges, &grant.grantees);
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
                    self.apply_grant_to_relation(id, &privileges, &grant.grantees);
                }
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_revoke(&mut self, revoke: &RevokeMutation) -> MutationResult {
        let privileges = Self::resolve_grant_privileges(&revoke.privileges);
        match &revoke.target {
            ResolvedGrantTarget::Tables(ids) => {
                for id in ids {
                    self.apply_revoke_to_relation(id, &privileges, &revoke.revokees);
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
                    self.apply_revoke_to_relation(id, &privileges, &revoke.revokees);
                }
            }
        }
        MutationResult::Applied
    }
}
