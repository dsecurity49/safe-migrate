use super::{AnalysisState, MutationResult, ObjectLookup};
use crate::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::analysis::facts::{RoleFact, RoleMembershipOptionFact};
use crate::analysis::mutations::{
    AlterRoleMutation, CreateRoleMutation, DropRoleMutation, GrantMutation, ResolvedGrantTarget,
    RevokeMutation,
};
use crate::ast::identifiers::ObjectId;
use crate::model::role::{RoleOverlay, RoleState};
use std::collections::{HashMap, HashSet};

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
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            RoleLookup::Tombstone | RoleLookup::AuthoritativelyAbsent => {}
            RoleLookup::WrongKind => unreachable!("roles have a dedicated namespace"),
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
                inherits: role.inherits,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
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
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
            RoleLookup::WrongKind => unreachable!("roles have a dedicated namespace"),
        }
        if let Some(inherits) = role.inherits
            && let Some(RoleOverlay::Present(current)) = self.local.roles.get_mut(&role_id)
        {
            current.inherits = inherits;
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
                        self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
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
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
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
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            return MutationResult::Skipped;
        }
        if grant.with_grant_option {
            // The matrix records the effective privilege and the local grant
            // option, but not the complete PostgreSQL authorization chain.
            // Preserve the useful state while keeping the result cautious.
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        let privileges = self.resolve_grant_privileges(&grant.privileges);
        match &grant.target {
            ResolvedGrantTarget::Tables(ids) => {
                for id in ids {
                    self.apply_grant_to_relation(
                        id,
                        &privileges,
                        &grantees,
                        grant.with_grant_option,
                    );
                }
            }
            ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                // The cache does not retain every PostgreSQL relation kind
                // eligible for ALL TABLES IN SCHEMA. Apply the modeled subset
                // but do not claim that the resulting privilege matrix is
                // complete.
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
                let target_ids: Vec<ObjectId> = self
                    .local
                    .relations
                    .iter()
                    .filter_map(|(id, overlay)| {
                        (schemas.contains(&id.schema)
                            && matches!(
                                overlay,
                                crate::model::relation::RelationOverlay::Present(_)
                            ))
                        .then_some(id.clone())
                    })
                    .collect();
                for id in &target_ids {
                    self.apply_grant_to_relation(
                        id,
                        &privileges,
                        &grantees,
                        grant.with_grant_option,
                    );
                }
            }
            ResolvedGrantTarget::Roles(parents) => {
                let mut admin_value = None;
                let mut inherit_value = None;
                let mut set_value = None;
                for option in &grant.role_options {
                    let slot = match option {
                        RoleMembershipOptionFact::Admin(_) => &mut admin_value,
                        RoleMembershipOptionFact::Inherit(_) => &mut inherit_value,
                        RoleMembershipOptionFact::Set(_) => &mut set_value,
                    };
                    if slot
                        .replace(match option {
                            RoleMembershipOptionFact::Admin(value)
                            | RoleMembershipOptionFact::Inherit(value)
                            | RoleMembershipOptionFact::Set(value) => *value,
                        })
                        .is_some()
                    {
                        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                        return MutationResult::Skipped;
                    }
                }
                // PostgreSQL defaults a newly granted membership to inherit
                // and permit SET ROLE; ADMIN remains opt-in. Explicit options
                // override only their own membership capability.
                let inherit_value =
                    inherit_value.or_else(|| grant.role_options.is_empty().then_some(true));
                let set_value = set_value.or_else(|| grant.role_options.is_empty().then_some(true));
                if (grant.role_options.is_empty() && grant.with_grant_option)
                    || grant.granted_by.is_some()
                {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
                if admin_value.is_some()
                    || inherit_value.is_some() && !grant.role_options.is_empty()
                {
                    // The normalized option state is retained for future
                    // authorization/inherited-privilege consumers, but the
                    // current privilege engine cannot yet prove those
                    // transitive effects exactly.
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                }
                if grantees.iter().any(|member| member.name == "public") {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
                // PostgreSQL rejects membership cycles. Validate the whole
                // batch against a proposed adjacency map before taking any
                // snapshots, so a later cyclic pair cannot partially apply
                // earlier grants in the same statement.
                let mut memberships: HashMap<ObjectId, Vec<ObjectId>> = self
                    .local
                    .roles
                    .iter()
                    .filter_map(|(id, overlay)| match overlay {
                        RoleOverlay::Present(role) => Some((id.clone(), role.member_of.clone())),
                        RoleOverlay::Dropped => None,
                    })
                    .collect();
                for member in &grantees {
                    for parent in parents {
                        let mut pending = vec![parent.clone()];
                        let mut visited = HashSet::new();
                        while let Some(role_id) = pending.pop() {
                            if role_id == *member {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "role membership '{}' in '{}' would create a cycle",
                                        member.name, parent
                                    ),
                                };
                            }
                            if !visited.insert(role_id.clone()) {
                                continue;
                            }
                            if let Some(next) = memberships.get(&role_id) {
                                pending.extend(next.iter().cloned());
                            }
                        }
                        memberships
                            .entry(member.clone())
                            .or_default()
                            .push(parent.clone());
                    }
                }
                for member in grantees {
                    self.snapshot_role(&member);
                    let Some(RoleOverlay::Present(role)) = self.local.roles.get_mut(&member) else {
                        continue;
                    };
                    for parent in parents {
                        if !role.member_of.contains(parent) {
                            role.member_of.push(parent.clone());
                        }
                        if admin_value == Some(true) {
                            if !role.can_administer_membership.contains(parent) {
                                role.can_administer_membership.push(parent.clone());
                            }
                        } else if admin_value == Some(false) {
                            role.can_administer_membership
                                .retain(|target| target != parent);
                        }
                        if inherit_value == Some(true) {
                            if !role.can_inherit_from.contains(parent) {
                                role.can_inherit_from.push(parent.clone());
                            }
                        } else if inherit_value == Some(false) {
                            role.can_inherit_from.retain(|target| target != parent);
                        }
                        if set_value == Some(true) {
                            if !role.can_set_role_to.contains(parent) {
                                role.can_set_role_to.push(parent.clone());
                            }
                        } else if set_value == Some(false) {
                            role.can_set_role_to.retain(|target| target != parent);
                        }
                    }
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
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            return MutationResult::Skipped;
        }
        if revoke.cascade {
            // CASCADE can remove privileges inherited through other grantors;
            // that dependency chain is not represented locally.
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            return MutationResult::Skipped;
        }
        if revoke.grant_option_only {
            // Revoke only the re-grant capability; the effective privilege
            // remains in place. The complete grantor dependency chain is
            // still unavailable, so retain conservative evidence.
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        let privileges = self.resolve_grant_privileges(&revoke.privileges);
        match &revoke.target {
            ResolvedGrantTarget::Tables(ids) => {
                for id in ids {
                    self.apply_revoke_to_relation(
                        id,
                        &privileges,
                        &revokees,
                        revoke.grant_option_only,
                    );
                }
            }
            ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
                let target_ids: Vec<ObjectId> = self
                    .local
                    .relations
                    .iter()
                    .filter_map(|(id, overlay)| {
                        (schemas.contains(&id.schema)
                            && matches!(
                                overlay,
                                crate::model::relation::RelationOverlay::Present(_)
                            ))
                        .then_some(id.clone())
                    })
                    .collect();
                for id in &target_ids {
                    self.apply_revoke_to_relation(
                        id,
                        &privileges,
                        &revokees,
                        revoke.grant_option_only,
                    );
                }
            }
            ResolvedGrantTarget::Roles(parents) => {
                if revoke.granted_by.is_some() || revoke.grant_option_only || revoke.cascade {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
                let revoke_option = match revoke.role_option.as_ref() {
                    None => None,
                    Some(RoleMembershipOptionFact::Admin(false)) => {
                        Some(RoleMembershipOptionFact::Admin(false))
                    }
                    Some(RoleMembershipOptionFact::Inherit(false)) => {
                        Some(RoleMembershipOptionFact::Inherit(false))
                    }
                    Some(RoleMembershipOptionFact::Set(false)) => {
                        Some(RoleMembershipOptionFact::Set(false))
                    }
                    Some(_) => {
                        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                        return MutationResult::Skipped;
                    }
                };
                if matches!(
                    revoke_option,
                    Some(RoleMembershipOptionFact::Admin(false))
                        | Some(RoleMembershipOptionFact::Inherit(false))
                ) {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                }
                if revokees.iter().any(|member| member.name == "public") {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
                for member in revokees {
                    self.snapshot_role(&member);
                    let Some(RoleOverlay::Present(role)) = self.local.roles.get_mut(&member) else {
                        continue;
                    };
                    for parent in parents {
                        match revoke_option {
                            Some(RoleMembershipOptionFact::Admin(false)) => {
                                role.can_administer_membership
                                    .retain(|target| target != parent);
                            }
                            Some(RoleMembershipOptionFact::Inherit(false)) => {
                                role.can_inherit_from.retain(|target| target != parent);
                            }
                            Some(RoleMembershipOptionFact::Set(false)) => {
                                role.can_set_role_to.retain(|target| target != parent);
                            }
                            None => {
                                role.can_administer_membership
                                    .retain(|target| target != parent);
                                role.can_inherit_from.retain(|target| target != parent);
                                role.can_set_role_to.retain(|target| target != parent);
                                role.member_of.retain(|target| target != parent);
                            }
                            Some(_) => unreachable!(),
                        }
                    }
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
            ResolvedGrantTarget::Roles(roles) => {
                for role in roles {
                    match self.role_lookup(role) {
                        RoleLookup::Present => {}
                        RoleLookup::Tombstone | RoleLookup::AuthoritativelyAbsent => {
                            return Err(MutationResult::Conflict {
                                reason: format!("role '{}' does not exist", role.name),
                            });
                        }
                        RoleLookup::Unknown => {
                            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                            return Err(MutationResult::Skipped);
                        }
                        RoleLookup::WrongKind => unreachable!("roles have a dedicated namespace"),
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_role_facts(&mut self, facts: &[RoleFact]) -> Result<Vec<ObjectId>, MutationResult> {
        let mut ids = Vec::with_capacity(facts.len());
        for fact in facts {
            let Some((name, _identity_known)) = self.role_fact_identity(fact) else {
                self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
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
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
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
