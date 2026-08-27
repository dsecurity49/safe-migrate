use super::{AnalysisState, Confidence, MutationResult};
use crate::analysis::mutations::{AlterSchemaMutation, CreateSchemaMutation};
use crate::ast::identifiers::ObjectId;
use crate::model::schema::{SchemaOverlay, SchemaState};

impl AnalysisState {
    pub(super) fn apply_create_schema(
        &mut self,
        create_schema: &CreateSchemaMutation,
    ) -> MutationResult {
        if self.schema_is_present(&create_schema.name) {
            return if create_schema.if_not_exists {
                MutationResult::Skipped
            } else {
                MutationResult::Conflict {
                    reason: format!("schema '{}' already exists", create_schema.name),
                }
            };
        }
        let (owner_name, owner_known) = match &create_schema.authorization {
            Some(role) => match self.role_fact_identity(role) {
                Some(identity) => identity,
                None => {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    (self.local.current_role.clone(), false)
                }
            },
            None => (
                self.local.current_role.clone(),
                self.local.current_role_known,
            ),
        };
        if owner_known && self.local.roles_known && self.present_role(&owner_name).is_none() {
            return MutationResult::Conflict {
                reason: format!("role '{}' does not exist", owner_name),
            };
        }
        if !owner_known || !self.local.roles_known {
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
        }
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        self.snapshot_schema(&create_schema.name);
        self.local.schemas.insert(
            create_schema.name.clone(),
            SchemaOverlay::Present(SchemaState {
                name: create_schema.name.clone(),
                owner: ObjectId::new("", owner_name),
                generation,
            }),
        );
        self.snapshot_search_path();
        self.refresh_role_sensitive_search_path();
        MutationResult::Applied
    }

    pub(super) fn apply_alter_schema(
        &mut self,
        alter_schema: &AlterSchemaMutation,
    ) -> MutationResult {
        match alter_schema {
            AlterSchemaMutation::OwnerTo { name, new_owner } => {
                if !self.schema_is_present(name) {
                    if self.schema_absence_is_authoritative(name) {
                        return MutationResult::Conflict {
                            reason: format!("schema '{}' does not exist", name),
                        };
                    }
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }
                let Some((owner_name, owner_known)) = self.role_fact_identity(new_owner) else {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                };
                if owner_known && self.local.roles_known && self.present_role(&owner_name).is_none()
                {
                    return MutationResult::Conflict {
                        reason: format!("role '{}' does not exist", owner_name),
                    };
                }
                if !owner_known || !self.local.roles_known {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                }
                self.snapshot_schema(name);
                if let Some(SchemaOverlay::Present(schema)) = self.local.schemas.get_mut(name) {
                    schema.owner = ObjectId::new("", owner_name);
                }
                MutationResult::Applied
            }
            AlterSchemaMutation::Rename { old_name, new_name } => {
                if !self.schema_is_present(old_name) {
                    if !self.schema_absence_is_authoritative(old_name) {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                        return MutationResult::Skipped;
                    }
                    return MutationResult::Conflict {
                        reason: format!("schema '{}' does not exist", old_name),
                    };
                }
                if self.schema_is_present(new_name) {
                    return MutationResult::Conflict {
                        reason: format!("schema '{}' already exists", new_name),
                    };
                }
                if !self.schema_absence_is_authoritative(new_name) {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                }
                self.snapshot_search_path();
                self.rename_schema_namespace(old_name, new_name);
                MutationResult::Applied
            }
        }
    }
}
