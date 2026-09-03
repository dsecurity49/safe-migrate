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

    fn validate_object_grantor(
        &mut self,
        explicit: bool,
        grantor: Option<&ObjectId>,
    ) -> Result<(), MutationResult> {
        if !explicit {
            return Ok(());
        }
        match (grantor, self.local.current_role_known) {
            (Some(grantor), true) if grantor.name != self.local.current_role => {
                Err(MutationResult::Conflict {
                    reason: format!(
                        "object privilege GRANTED BY '{}' must name current role '{}'",
                        grantor.name, self.local.current_role
                    ),
                })
            }
            (Some(_), false) | (None, _) => {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
                Ok(())
            }
            (Some(_), true) => Ok(()),
        }
    }

    /// Remove memberships delegated by roles whose ADMIN authority was
    /// withdrawn. PostgreSQL records one grantor per membership; the queue
    /// makes the dependency propagation transitive while each edge is removed
    /// exactly once.
    fn cascade_role_memberships(&mut self, initial_grantors: &[ObjectId]) {
        let mut pending = initial_grantors.to_vec();
        let mut visited = HashSet::new();
        let mut removals = Vec::new();
        while let Some(grantor) = pending.pop() {
            if !visited.insert(grantor.clone()) {
                continue;
            }
            for provenance in &self.local.role_membership_grantors {
                if provenance.grantor == grantor
                    && self
                        .local
                        .roles
                        .get(&provenance.member)
                        .is_some_and(|overlay| {
                            matches!(overlay, RoleOverlay::Present(role) if role
                                .member_of
                                .contains(&provenance.role))
                        })
                {
                    let edge = (provenance.member.clone(), provenance.role.clone());
                    if !removals.contains(&edge) {
                        removals.push(edge.clone());
                        pending.push(edge.0);
                    }
                }
            }
        }
        if removals.is_empty() {
            return;
        }
        self.snapshot_role_membership_grantors();
        for (member, role_id) in removals {
            self.snapshot_role(&member);
            if let Some(RoleOverlay::Present(role)) = self.local.roles.get_mut(&member) {
                role.member_of.retain(|role| role != &role_id);
                role.can_administer_membership
                    .retain(|role| role != &role_id);
                role.can_inherit_from.retain(|role| role != &role_id);
                role.can_set_role_to.retain(|role| role != &role_id);
            }
            self.local
                .role_membership_grantors
                .retain(|provenance| provenance.member != member || provenance.role != role_id);
        }
    }

    pub(super) fn apply_grant(&mut self, grant: &GrantMutation) -> MutationResult {
        if let Err(result) = self.validate_grant_targets(&grant.target) {
            return result;
        }
        let grantees = match self.validate_role_facts(&grant.grantees) {
            Ok(roles) => roles,
            Err(result) => return result,
        };
        if let Some(granted_by) = grant.granted_by.as_ref()
            && let Err(result) = self.validate_role_facts(std::slice::from_ref(granted_by))
        {
            return result;
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
                let grantor = self.grantor_identity(grant.granted_by.as_ref());
                if let Err(result) =
                    self.validate_object_grantor(grant.granted_by.is_some(), grantor.as_ref())
                {
                    return result;
                }
                for id in ids {
                    let authorization =
                        self.local
                            .relations
                            .get(id)
                            .and_then(|overlay| match overlay {
                                crate::model::relation::RelationOverlay::Present(relation) => self
                                    .authorize_relation_grant(
                                        relation,
                                        &privileges,
                                        grantor.as_ref(),
                                    ),
                                crate::model::relation::RelationOverlay::Dropped => Some(false),
                            });
                    match authorization {
                        Some(true) => {}
                        Some(false) => {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "role '{}' lacks grant option on relation '{}'",
                                    grantor
                                        .as_ref()
                                        .map_or_else(|| "unknown".to_string(), |r| r.name.clone()),
                                    id
                                ),
                            };
                        }
                        None if grantor.is_some() => self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        ),
                        None => {}
                    }
                    self.apply_grant_to_relation(
                        id,
                        &privileges,
                        &grantees,
                        grant.with_grant_option,
                        grantor.clone(),
                    );
                }
            }
            ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                let grantor = self.grantor_identity(grant.granted_by.as_ref());
                if let Err(result) =
                    self.validate_object_grantor(grant.granted_by.is_some(), grantor.as_ref())
                {
                    return result;
                }
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
                        grantor.clone(),
                    );
                }
            }
            ResolvedGrantTarget::Roles(parents) => {
                let grantor = self.grantor_identity(grant.granted_by.as_ref());
                if let Some(grantor) = grantor.as_ref() {
                    if self.local.roles_known {
                        let can_administer = self.present_role(&grantor.name).is_some_and(|role| {
                            role.is_superuser
                                || parents
                                    .iter()
                                    .all(|parent| role.can_administer_membership.contains(parent))
                        });
                        if !can_administer {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "role '{}' lacks ADMIN OPTION for the granted membership",
                                    grantor.name
                                ),
                            };
                        }
                    } else {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    }
                } else if grant.granted_by.is_some() || self.local.current_role_known {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
                let mut explicit_admin = None;
                let mut explicit_inherit = None;
                let mut explicit_set = None;
                for option in &grant.role_options {
                    let slot = match option {
                        RoleMembershipOptionFact::Admin(_) => &mut explicit_admin,
                        RoleMembershipOptionFact::Inherit(_) => &mut explicit_inherit,
                        RoleMembershipOptionFact::Set(_) => &mut explicit_set,
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
                if grant.role_options.is_empty() && grant.with_grant_option {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
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
                if let Some(grantor) = grantor.as_ref() {
                    self.snapshot_role_membership_grantors();
                    for member in &grantees {
                        for parent in parents {
                            let already_member =
                                self.local.roles.get(member).is_some_and(|overlay| {
                                    matches!(overlay, RoleOverlay::Present(role) if role
                                        .member_of
                                        .contains(parent))
                                });
                            if already_member
                                && self
                                    .local
                                    .role_membership_grantors
                                    .iter()
                                    .any(|provenance| {
                                        provenance.member == *member && provenance.role == *parent
                                    })
                            {
                                continue;
                            }
                            self.local.role_membership_grantors.retain(|provenance| {
                                provenance.member != *member || provenance.role != *parent
                            });
                            self.local.role_membership_grantors.push(
                                crate::model::role::RoleMembershipGrantor {
                                    member: member.clone(),
                                    role: parent.clone(),
                                    grantor: grantor.clone(),
                                },
                            );
                        }
                    }
                } else {
                    self.snapshot_role_membership_grantors();
                    self.local.role_membership_grantors_complete = false;
                }
                for member in grantees {
                    self.snapshot_role(&member);
                    let Some(RoleOverlay::Present(role)) = self.local.roles.get_mut(&member) else {
                        continue;
                    };
                    for parent in parents {
                        let is_new = !role.member_of.contains(parent);
                        if is_new {
                            role.member_of.push(parent.clone());
                        }

                        if explicit_admin == Some(true) {
                            if !role.can_administer_membership.contains(parent) {
                                role.can_administer_membership.push(parent.clone());
                            }
                        } else if explicit_admin == Some(false) {
                            role.can_administer_membership
                                .retain(|target| target != parent);
                        }

                        let inherit_opt =
                            explicit_inherit.or_else(|| is_new.then_some(role.inherits));
                        if inherit_opt == Some(true) {
                            if !role.can_inherit_from.contains(parent) {
                                role.can_inherit_from.push(parent.clone());
                            }
                        } else if inherit_opt == Some(false) {
                            role.can_inherit_from.retain(|target| target != parent);
                        }

                        let set_opt = explicit_set.or_else(|| is_new.then_some(true));
                        if set_opt == Some(true) {
                            if !role.can_set_role_to.contains(parent) {
                                role.can_set_role_to.push(parent.clone());
                            }
                        } else if set_opt == Some(false) {
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
        if let Some(granted_by) = revoke.granted_by.as_ref()
            && let Err(result) = self.validate_role_facts(std::slice::from_ref(granted_by))
        {
            return result;
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
                let grantor = self.grantor_identity(revoke.granted_by.as_ref());
                if let Err(result) =
                    self.validate_object_grantor(revoke.granted_by.is_some(), grantor.as_ref())
                {
                    return result;
                }
                for id in ids {
                    let authorization =
                        self.local
                            .relations
                            .get(id)
                            .and_then(|overlay| match overlay {
                                crate::model::relation::RelationOverlay::Present(relation) => self
                                    .authorize_relation_grant(
                                        relation,
                                        &privileges,
                                        grantor.as_ref(),
                                    ),
                                crate::model::relation::RelationOverlay::Dropped => Some(false),
                            });
                    match authorization {
                        Some(true) => {}
                        Some(false) => {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "role '{}' lacks grant option on relation '{}'",
                                    grantor
                                        .as_ref()
                                        .map_or_else(|| "unknown".to_string(), |r| r.name.clone()),
                                    id
                                ),
                            };
                        }
                        None if grantor.is_some() => self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        ),
                        None => {}
                    }
                    if grantor.is_some()
                        && self.local.relations.get(id).is_some_and(|overlay| {
                            matches!(
                                overlay,
                                crate::model::relation::RelationOverlay::Present(relation)
                                    if revokees.iter().any(|revokee| {
                                        if revoke.grant_option_only {
                                            !relation.privileges.targeted_grant_option_revoke_provenance_is_known(revokee, &privileges)
                                        } else {
                                            !relation.privileges.targeted_revoke_provenance_is_known(revokee, &privileges)
                                        }
                                    })
                            )
                        })
                    {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    }
                    self.apply_revoke_to_relation(
                        id,
                        &privileges,
                        &revokees,
                        revoke.grant_option_only,
                        grantor.as_ref(),
                        revoke.cascade,
                    );
                }
            }
            ResolvedGrantTarget::AllTablesInSchema(schemas) => {
                let grantor = self.grantor_identity(revoke.granted_by.as_ref());
                if let Err(result) =
                    self.validate_object_grantor(revoke.granted_by.is_some(), grantor.as_ref())
                {
                    return result;
                }
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
                    if grantor.is_some()
                        && self.local.relations.get(id).is_some_and(|overlay| {
                            matches!(
                                overlay,
                                crate::model::relation::RelationOverlay::Present(relation)
                                    if revokees.iter().any(|revokee| {
                                        if revoke.grant_option_only {
                                            !relation.privileges.targeted_grant_option_revoke_provenance_is_known(revokee, &privileges)
                                        } else {
                                            !relation.privileges.targeted_revoke_provenance_is_known(revokee, &privileges)
                                        }
                                    })
                            )
                        })
                    {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    }
                    self.apply_revoke_to_relation(
                        id,
                        &privileges,
                        &revokees,
                        revoke.grant_option_only,
                        grantor.as_ref(),
                        revoke.cascade,
                    );
                }
            }
            ResolvedGrantTarget::Roles(parents) => {
                if revoke.cascade && !self.local.role_membership_grantors_complete {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
                if let Some(grantor) = self.grantor_identity(revoke.granted_by.as_ref()) {
                    if self.local.roles_known {
                        let can_administer = self.present_role(&grantor.name).is_some_and(|role| {
                            role.is_superuser
                                || parents
                                    .iter()
                                    .all(|parent| role.can_administer_membership.contains(parent))
                        });
                        if !can_administer {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "role '{}' lacks ADMIN OPTION for the revoked membership",
                                    grantor.name
                                ),
                            };
                        }
                    } else {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    }
                } else if revoke.granted_by.is_some() || self.local.current_role_known {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
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
                if matches!(revoke_option, Some(RoleMembershipOptionFact::Admin(false)))
                    && revoke.cascade
                    && !self.local.role_membership_grantors_complete
                {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
                if revokees.iter().any(|member| member.name == "public") {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
                let mut cascade_grantors = Vec::new();
                if revoke.cascade
                    && (revoke_option.is_none()
                        || matches!(revoke_option, Some(RoleMembershipOptionFact::Admin(false))))
                {
                    cascade_grantors.extend(revokees.iter().cloned());
                }
                if !revokees.is_empty()
                    && (revoke.cascade || revoke_option.is_none())
                    && self
                        .local
                        .role_membership_grantors
                        .iter()
                        .any(|provenance| {
                            revokees.contains(&provenance.member)
                                && parents.contains(&provenance.role)
                        })
                {
                    self.snapshot_role_membership_grantors();
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
                                if revoke.cascade {
                                    cascade_grantors.push(member.clone());
                                }
                            }
                            Some(_) => unreachable!(),
                        }
                        if revoke_option.is_some()
                            && matches!(revoke_option, Some(RoleMembershipOptionFact::Admin(false)))
                            && revoke.cascade
                        {
                            cascade_grantors.push(member.clone());
                        }
                        if revoke_option.is_none() {
                            self.local.role_membership_grantors.retain(|provenance| {
                                provenance.member != member || provenance.role != *parent
                            });
                        }
                    }
                }
                if revoke.cascade && !cascade_grantors.is_empty() {
                    self.cascade_role_memberships(&cascade_grantors);
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
