use super::{AnalysisState, Confidence, MutationResult};
use crate::analysis::facts::{PublicationObjectFact, PublicationScope};
use crate::analysis::graph::DependencyKind;
use crate::analysis::mutations::{AlterSchemaMutation, CreateSchemaMutation, DropSchemaMutation};
use crate::ast::identifiers::ObjectId;
use crate::model::function::FunctionOverlay;
use crate::model::relation::RelationOverlay;
use crate::model::replication::PublicationOverlay;
use crate::model::schema::{SchemaOverlay, SchemaState};
use crate::model::sequence::SequenceOverlay;
use crate::model::trigger::TriggerOverlay;
use crate::model::types::TypeOverlay;

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

    pub(super) fn apply_drop_schema(&mut self, drop_schema: &DropSchemaMutation) -> MutationResult {
        for name in &drop_schema.names {
            if !self.schema_is_present(name) && self.schema_absence_is_authoritative(name) {
                if !drop_schema.if_exists {
                    return MutationResult::Conflict {
                        reason: format!("schema '{}' does not exist", name),
                    };
                }
            } else if !self.schema_is_present(name) {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
            }
        }
        let present_names: Vec<String> = drop_schema
            .names
            .iter()
            .filter(|name| self.schema_is_present(name))
            .cloned()
            .collect();
        if present_names.is_empty() {
            return MutationResult::Skipped;
        }
        if drop_schema.cascade {
            self.snapshot_namespace();
            let relations_to_drop: Vec<ObjectId> = self
                .local
                .relations
                .keys()
                .filter(|id| drop_schema.names.contains(&id.schema))
                .cloned()
                .collect();
            for id in relations_to_drop {
                self.snapshot_relation(&id);
                self.local.relations.insert(id, RelationOverlay::Dropped);
            }

            let constraints_to_drop: Vec<(ObjectId, String)> = self
                .local
                .constraints
                .keys()
                .filter(|(table_id, _)| drop_schema.names.contains(&table_id.schema))
                .cloned()
                .collect();
            for (table_id, name) in constraints_to_drop {
                self.snapshot_constraint(&table_id, &name);
                self.local.constraints.remove(&(table_id, name));
            }

            let types_to_drop: Vec<ObjectId> = self
                .local
                .types
                .keys()
                .filter(|id| drop_schema.names.contains(&id.schema))
                .cloned()
                .collect();
            for id in types_to_drop {
                self.snapshot_type(&id);
                self.local.types.insert(id, TypeOverlay::Dropped);
            }

            let sequences_to_drop: Vec<ObjectId> = self
                .local
                .sequences
                .keys()
                .filter(|id| drop_schema.names.contains(&id.schema))
                .cloned()
                .collect();
            for id in sequences_to_drop {
                self.snapshot_sequence(&id);
                self.local.sequences.insert(id, SequenceOverlay::Dropped);
            }

            let functions_to_drop: Vec<ObjectId> = self
                .local
                .functions
                .keys()
                .filter(|id| drop_schema.names.contains(&id.schema))
                .cloned()
                .collect();
            for id in functions_to_drop {
                self.snapshot_function(&id);
                self.local.functions.insert(id, FunctionOverlay::Dropped);
            }

            let triggers_to_drop: Vec<ObjectId> = self
                .local
                .triggers
                .keys()
                .filter(|id| drop_schema.names.contains(&id.schema))
                .cloned()
                .collect();
            for id in triggers_to_drop {
                self.snapshot_trigger(&id);
                self.local.triggers.insert(id, TriggerOverlay::Dropped);
            }

            self.local
                .pending_validation
                .retain(|(table, _)| !drop_schema.names.contains(&table.schema));
            let publication_names: Vec<String> = self.local.publications.keys().cloned().collect();
            for publication_name in publication_names {
                self.snapshot_publication(&publication_name);
            }
            for overlay in self.local.publications.values_mut() {
                let PublicationOverlay::Present(publication) = overlay else {
                    continue;
                };
                let PublicationScope::Explicit(objects) = &mut publication.scope else {
                    continue;
                };
                objects.retain(|object| match object {
                    PublicationObjectFact::Table { name, .. } => name
                        .schema
                        .as_ref()
                        .is_none_or(|schema| !drop_schema.names.contains(&schema.resolve())),
                    PublicationObjectFact::SchemaTables { schema, .. } => {
                        !drop_schema.names.contains(schema)
                    }
                    _ => true,
                });
            }

            self.snapshot_graph_full();
            self.local.graph.retain_edges(|edge| {
                !drop_schema.names.contains(&edge.dependent.schema)
                    && !drop_schema.names.contains(&edge.referenced.schema)
                    && match &edge.kind {
                        DependencyKind::TriggerOnTable { function_id, .. } => {
                            !drop_schema.names.contains(&function_id.schema)
                        }
                        _ => true,
                    }
            });
        } else {
            let has_relation = self.local.relations.iter().any(|(id, overlay)| {
                drop_schema.names.contains(&id.schema)
                    && !matches!(overlay, RelationOverlay::Dropped)
            });
            let has_type = self.local.types.iter().any(|(id, overlay)| {
                drop_schema.names.contains(&id.schema) && !matches!(overlay, TypeOverlay::Dropped)
            });
            let has_sequence = self.local.sequences.iter().any(|(id, overlay)| {
                drop_schema.names.contains(&id.schema)
                    && !matches!(overlay, SequenceOverlay::Dropped)
            });
            let has_function = self.local.functions.iter().any(|(id, overlay)| {
                drop_schema.names.contains(&id.schema)
                    && !matches!(overlay, FunctionOverlay::Dropped)
            });
            let has_trigger = self.local.triggers.iter().any(|(id, overlay)| {
                drop_schema.names.contains(&id.schema)
                    && !matches!(overlay, TriggerOverlay::Dropped)
            });
            if has_relation || has_type || has_sequence || has_function || has_trigger {
                return MutationResult::Conflict {
                    reason: format!(
                        "schema(s) {:?} still contain objects; use CASCADE to drop them",
                        drop_schema.names
                    ),
                };
            }
        }
        for name in present_names {
            self.snapshot_schema(&name);
            self.local.schemas.insert(name, SchemaOverlay::Dropped);
        }
        self.snapshot_search_path();
        self.refresh_role_sensitive_search_path();
        MutationResult::Applied
    }
}
