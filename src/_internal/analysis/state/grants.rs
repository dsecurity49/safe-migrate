use super::*;

impl AnalysisState {
    pub(super) fn apply_grant_to_relation(
        &mut self,
        id: &ObjectId,
        privileges: &HashSet<Privilege>,
        grantees: &[ObjectId],
        with_grant_option: bool,
        grantor: Option<ObjectId>,
    ) {
        self.snapshot_relation(id);
        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(id) {
            for grantee in grantees {
                if with_grant_option {
                    rel.privileges.grant_from(
                        grantee.clone(),
                        privileges.clone(),
                        grantor.clone(),
                        true,
                    );
                } else {
                    rel.privileges.grant_from(
                        grantee.clone(),
                        privileges.clone(),
                        grantor.clone(),
                        false,
                    );
                }
            }
        }
    }

    pub(super) fn apply_revoke_to_relation(
        &mut self,
        id: &ObjectId,
        privileges: &HashSet<Privilege>,
        revokees: &[ObjectId],
        grant_option_only: bool,
        grantor: Option<&ObjectId>,
        cascade: bool,
    ) {
        self.snapshot_relation(id);
        if let Some(RelationOverlay::Present(rel)) = self.local.relations.get_mut(id) {
            for revokee in revokees {
                if grant_option_only {
                    rel.privileges
                        .revoke_grant_option_from(revokee, privileges, grantor);
                } else {
                    rel.privileges
                        .revoke_from_cascade(revokee, privileges, grantor, cascade);
                }
            }
        }
    }
}
