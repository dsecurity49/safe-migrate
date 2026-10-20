use super::*;

impl AnalysisState {
    pub(super) fn resolve_grant_privileges(
        &mut self,
        spec: &crate::_internal::analysis::facts::PrivilegeSpec,
    ) -> Result<HashSet<Privilege>, MutationResult> {
        let version = self.pg_version();
        let supports_maintain = version.satisfies(|version| version >= 170_000);
        match spec {
            crate::_internal::analysis::facts::PrivilegeSpec::All => {
                let mut privileges = [
                    Privilege::Select,
                    Privilege::Insert,
                    Privilege::Update,
                    Privilege::Delete,
                    Privilege::Truncate,
                    Privilege::References,
                    Privilege::Trigger,
                ]
                .into_iter()
                .collect::<HashSet<_>>();
                if supports_maintain {
                    privileges.insert(Privilege::Maintain);
                } else if version.num().is_none() {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                }
                Ok(privileges)
            }
            crate::_internal::analysis::facts::PrivilegeSpec::List(list) => {
                let mut privileges = HashSet::new();
                for privilege in list {
                    match privilege {
                        crate::_internal::analysis::facts::PrivilegeFact::Select => {
                            privileges.insert(Privilege::Select);
                        }
                        crate::_internal::analysis::facts::PrivilegeFact::Insert => {
                            privileges.insert(Privilege::Insert);
                        }
                        crate::_internal::analysis::facts::PrivilegeFact::Update => {
                            privileges.insert(Privilege::Update);
                        }
                        crate::_internal::analysis::facts::PrivilegeFact::Delete => {
                            privileges.insert(Privilege::Delete);
                        }
                        crate::_internal::analysis::facts::PrivilegeFact::Truncate => {
                            privileges.insert(Privilege::Truncate);
                        }
                        crate::_internal::analysis::facts::PrivilegeFact::References => {
                            privileges.insert(Privilege::References);
                        }
                        crate::_internal::analysis::facts::PrivilegeFact::Trigger => {
                            privileges.insert(Privilege::Trigger);
                        }
                        crate::_internal::analysis::facts::PrivilegeFact::Maintain => {
                            match version.num() {
                                Some(version) if version < 170_000 => {
                                    return Err(MutationResult::conflict(
                                        "privilege MAINTAIN requires PostgreSQL 17+".to_string(),
                                    ));
                                }
                                Some(_) => {
                                    privileges.insert(Privilege::Maintain);
                                }
                                None => {
                                    return Err(self.unresolved(EvidenceCode::UnsupportedSemantics));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(privileges)
            }
        }
    }

    pub(super) fn resolve_role_name(
        role: &crate::_internal::analysis::facts::RoleFact,
        current_role: &str,
        session_role: &str,
    ) -> Option<ObjectId> {
        let name = match role {
            crate::_internal::analysis::facts::RoleFact::Named { name, .. } => Some(name.clone()),
            crate::_internal::analysis::facts::RoleFact::CurrentUser
            | crate::_internal::analysis::facts::RoleFact::CurrentRole => {
                Some(current_role.to_string())
            }
            crate::_internal::analysis::facts::RoleFact::SessionUser => {
                Some(session_role.to_string())
            }
            crate::_internal::analysis::facts::RoleFact::Unknown => None,
        }?;
        Some(ObjectId::new("", name))
    }

    pub(super) fn role_fact_identity(
        &self,
        role: &crate::_internal::analysis::facts::RoleFact,
    ) -> Option<(String, bool)> {
        match role {
            crate::_internal::analysis::facts::RoleFact::Named { name, .. } => {
                Some((name.clone(), true))
            }
            crate::_internal::analysis::facts::RoleFact::CurrentUser
            | crate::_internal::analysis::facts::RoleFact::CurrentRole => Some((
                self.local.current_role.clone(),
                self.local.current_role_known,
            )),
            crate::_internal::analysis::facts::RoleFact::SessionUser => Some((
                self.local.session_role.clone(),
                self.local.session_role_known,
            )),
            crate::_internal::analysis::facts::RoleFact::Unknown => None,
        }
    }

    pub(super) fn present_role(
        &self,
        name: &str,
    ) -> Option<&crate::_internal::model::role::RoleState> {
        match self.local.roles.get(&ObjectId::new("", name)) {
            Some(crate::_internal::model::role::RoleOverlay::Present(role)) => Some(role),
            _ => None,
        }
    }

    pub(super) fn can_set_role_to(&self, target: &str) -> Option<bool> {
        if !self.local.roles_known || !self.local.session_role_known {
            return None;
        }
        if self.present_role(target).is_none() {
            return Some(false);
        }
        if self.local.session_role == target {
            return Some(true);
        }
        let session = self.present_role(&self.local.session_role)?;
        if session.is_superuser {
            return Some(true);
        }

        let mut pending = session.can_set_role_to.clone();
        let mut visited = HashSet::new();
        while let Some(role_id) = pending.pop() {
            if !visited.insert(role_id.clone()) {
                continue;
            }
            if role_id.name == target {
                return Some(true);
            }
            if let Some(role) = self.present_role(&role_id.name) {
                pending.extend(role.can_set_role_to.iter().cloned());
            }
        }
        Some(false)
    }

    /// Resolve a direct or inherited relation privilege for a role. ACL rows
    /// are direct grants. PostgreSQL 15 and earlier gate every membership
    /// traversal on the member role's `INHERIT` attribute; PostgreSQL 16+
    /// instead gates it on each membership's `INHERIT` option. Unknown role
    /// catalogs or server versions deliberately return `None` rather than
    /// turning incomplete authorization evidence into an exact decision.
    pub(super) fn effective_relation_privilege(
        &self,
        relation: &crate::_internal::model::relation::RelationState,
        role: &ObjectId,
        privilege: Privilege,
        grant_option: bool,
    ) -> Option<bool> {
        if !self.local.roles_known {
            return None;
        }
        let mut pending = vec![role.clone()];
        let mut visited = HashSet::new();
        while let Some(candidate) = pending.pop() {
            if !visited.insert(candidate.clone()) {
                continue;
            }
            if if grant_option {
                relation
                    .privileges
                    .has_direct_grant_option(&candidate, privilege)
            } else {
                relation
                    .privileges
                    .has_direct_privilege(&candidate, privilege)
            } {
                return Some(true);
            }
            let role_state = self.present_role(&candidate.name)?;
            match self.pg_version().num() {
                Some(version) if version >= 160_000 => {
                    pending.extend(role_state.can_inherit_from.iter().cloned());
                }
                Some(_) if role_state.inherits => {
                    pending.extend(role_state.can_inherit_from.iter().cloned());
                }
                Some(_) => {}
                None => return None,
            }
        }
        Some(false)
    }

    /// Determine whether a role can administer a target role through its
    /// effective privilege path. PostgreSQL uses this check for role
    /// membership GRANT and REVOKE authorization.
    pub(super) fn has_admin_privileges_on_role(
        &self,
        member: &ObjectId,
        target: &ObjectId,
    ) -> Option<bool> {
        if !self.local.roles_known {
            return None;
        }
        let mut pending = vec![member.clone()];
        let mut visited = HashSet::new();
        while let Some(candidate) = pending.pop() {
            if !visited.insert(candidate.clone()) {
                continue;
            }
            let role = self.present_role(&candidate.name)?;
            if (candidate == *member && role.is_superuser)
                || role.can_administer_membership.contains(target)
            {
                return Some(true);
            }
            match self.pg_version().num() {
                Some(version) if version >= 160_000 => {
                    pending.extend(role.can_inherit_from.iter().cloned());
                }
                Some(_) if role.inherits => {
                    pending.extend(role.can_inherit_from.iter().cloned());
                }
                Some(_) => {}
                None => return None,
            }
        }
        Some(false)
    }

    pub(super) fn grantor_identity(
        &self,
        granted_by: Option<&crate::_internal::analysis::facts::RoleFact>,
    ) -> Option<ObjectId> {
        granted_by
            .and_then(|fact| {
                self.role_fact_identity(fact)
                    .map(|(name, _)| ObjectId::new("", name))
            })
            .or_else(|| {
                self.local
                    .current_role_known
                    .then(|| ObjectId::new("", self.local.current_role.clone()))
            })
    }

    /// Identity attributed to a role-membership grantor. Role grants differ
    /// from object grants: PostgreSQL 16 and later route an implicit grantor
    /// through `BOOTSTRAP_SUPERUSERID` when the session user is a superuser,
    /// so a superuser session records the *bootstrap* role instead of the
    /// session role. An explicit `GRANTED BY` always wins; otherwise a known
    /// superuser maps to the cached bootstrap name, and any other role uses
    /// itself. `None` means the attribution cannot be resolved statically.
    pub(super) fn role_membership_grantor(
        &self,
        granted_by: Option<&crate::_internal::analysis::facts::RoleFact>,
    ) -> Option<ObjectId> {
        granted_by
            .and_then(|fact| {
                self.role_fact_identity(fact)
                    .map(|(name, _)| ObjectId::new("", name))
            })
            .or_else(|| {
                if !self.local.current_role_known {
                    return None;
                }
                let current = ObjectId::new("", self.local.current_role.clone());
                let is_superuser = matches!(
                    self.local.roles.get(&current),
                    Some(crate::_internal::model::role::RoleOverlay::Present(role))
                        if role.is_superuser
                );
                if is_superuser {
                    match self.pg_version().num() {
                        Some(version) if version >= 160_000 => self
                            .local
                            .bootstrap_superuser
                            .as_ref()
                            .map(|name| ObjectId::new("", name.clone())),
                        Some(_) => Some(current),
                        None => None,
                    }
                } else {
                    Some(current)
                }
            })
    }

    /// Index of the role-membership record for this exact
    /// (member, role, grantor) triple, if present.
    pub(super) fn membership_record_index(
        &self,
        member: &ObjectId,
        role: &ObjectId,
        grantor: &ObjectId,
    ) -> Option<usize> {
        self.local
            .role_membership_grantors
            .iter()
            .position(|record| {
                &record.member == member && &record.role == role && &record.grantor == grantor
            })
    }

    /// Whether the member still holds the ADMIN option on `role` through a
    /// record other than `exclude`, mirroring PostgreSQL's
    /// `would_still_have_admin_option`.
    pub(super) fn membership_admin_from_other_record(
        &self,
        member: &ObjectId,
        role: &ObjectId,
        exclude: Option<usize>,
    ) -> bool {
        self.local
            .role_membership_grantors
            .iter()
            .enumerate()
            .any(|(index, record)| {
                Some(index) != exclude
                    && &record.member == member
                    && &record.role == role
                    && record.admin
            })
    }

    /// Rebuild a member's option-vector projection from its membership
    /// records.  The effective projection is the union of the per-grantor
    /// records, matching both `load_roles` aggregation and the live option
    /// vectors the differential harness compares against.  No-op when the
    /// provenance set is incomplete.
    pub(super) fn reconcile_membership_projection(&mut self, member: &ObjectId) {
        if !self.local.role_membership_grantors_complete {
            return;
        }
        let Some(crate::_internal::model::role::RoleOverlay::Present(role)) =
            self.local.roles.get_mut(member)
        else {
            return;
        };
        role.member_of.clear();
        role.can_administer_membership.clear();
        role.can_inherit_from.clear();
        role.can_set_role_to.clear();
        for record in &self.local.role_membership_grantors {
            if &record.member != member {
                continue;
            }
            if !role.member_of.contains(&record.role) {
                role.member_of.push(record.role.clone());
            }
            if record.admin && !role.can_administer_membership.contains(&record.role) {
                role.can_administer_membership.push(record.role.clone());
            }
            if record.inherit && !role.can_inherit_from.contains(&record.role) {
                role.can_inherit_from.push(record.role.clone());
            }
            if record.set && !role.can_set_role_to.contains(&record.role) {
                role.can_set_role_to.push(record.role.clone());
            }
        }
        // Reuse the role vector ordering the synchronizer produces: empty
        // edge lists carry no ordering constraint, and the harness compares
        // both live options and sim projections as unordered sets.
    }

    pub(super) fn authorize_relation_grant(
        &self,
        relation: &crate::_internal::model::relation::RelationState,
        privileges: &HashSet<Privilege>,
        grantor: Option<&ObjectId>,
    ) -> Option<bool> {
        let grantor = grantor?;
        let role = self.present_role(&grantor.name)?;
        if role.is_superuser || relation.owner == *grantor {
            return Some(true);
        }
        for privilege in privileges {
            if self.effective_relation_privilege(relation, grantor, *privilege, true) != Some(true)
            {
                return Some(false);
            }
        }
        Some(true)
    }

    pub(super) fn can_set_session_authorization_to(&self, target: &str) -> Option<bool> {
        if !self.local.roles_known || !self.local.authenticated_role_known {
            return None;
        }
        if self.present_role(target).is_none() {
            return Some(false);
        }
        if self.local.authenticated_role == target {
            return Some(true);
        }
        Some(
            self.present_role(&self.local.authenticated_role)
                .is_some_and(|role| role.is_superuser),
        )
    }
}
