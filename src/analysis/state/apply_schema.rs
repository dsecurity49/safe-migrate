use super::{AnalysisState, MutationResult, ObjectLookup};
use crate::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::analysis::facts::{PublicationObjectFact, PublicationScope};
use crate::analysis::graph::DependencyKind;
use crate::analysis::mutations::{AlterSchemaMutation, CreateSchemaMutation, DropSchemaMutation};
use crate::ast::identifiers::ObjectId;
use crate::model::function::FunctionOverlay;
use crate::model::relation::RelationOverlay;
use crate::model::replication::PublicationOverlay;
use crate::model::schema::{SchemaOverlay, SchemaState};
use crate::model::sequence::{SequenceKind, SequenceOverlay};
use crate::model::trigger::TriggerOverlay;
use crate::model::types::TypeOverlay;

type SchemaLookup = ObjectLookup;
type SequenceDrop = (ObjectId, SequenceKind, Option<(ObjectId, String)>);

impl AnalysisState {
    pub(super) fn apply_create_schema(
        &mut self,
        create_schema: &CreateSchemaMutation,
    ) -> MutationResult {
        match self.schema_lookup(&create_schema.name) {
            SchemaLookup::Present => {
                return if create_schema.if_not_exists {
                    MutationResult::Skipped
                } else {
                    MutationResult::Conflict {
                        reason: format!("schema '{}' already exists", create_schema.name),
                    }
                };
            }
            SchemaLookup::AuthoritativelyAbsent | SchemaLookup::Tombstone => {}
            SchemaLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
            SchemaLookup::WrongKind => unreachable!("schemas have a dedicated namespace"),
        }
        let (owner_name, owner_known) = match &create_schema.authorization {
            Some(role) => match self.role_fact_identity(role) {
                Some(identity) => identity,
                None => {
                    self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
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
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
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
                match self.schema_lookup(name) {
                    SchemaLookup::Present => {}
                    SchemaLookup::Tombstone | SchemaLookup::AuthoritativelyAbsent => {
                        return MutationResult::Conflict {
                            reason: format!("schema '{}' does not exist", name),
                        };
                    }
                    SchemaLookup::Unknown => {
                        self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                        return MutationResult::Skipped;
                    }
                    SchemaLookup::WrongKind => {
                        unreachable!("schemas do not share an overlay with other object kinds")
                    }
                }
                let Some((owner_name, owner_known)) = self.role_fact_identity(new_owner) else {
                    self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                };
                if owner_known && self.local.roles_known && self.present_role(&owner_name).is_none()
                {
                    return MutationResult::Conflict {
                        reason: format!("role '{}' does not exist", owner_name),
                    };
                }
                if !owner_known || !self.local.roles_known {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
                self.snapshot_schema(name);
                if let Some(SchemaOverlay::Present(schema)) = self.local.schemas.get_mut(name) {
                    schema.owner = ObjectId::new("", owner_name);
                }
                MutationResult::Applied
            }
            AlterSchemaMutation::Rename { old_name, new_name } => {
                match self.schema_lookup(old_name) {
                    SchemaLookup::Present => {}
                    SchemaLookup::Unknown => {
                        self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                        return MutationResult::Skipped;
                    }
                    SchemaLookup::Tombstone | SchemaLookup::AuthoritativelyAbsent => {
                        return MutationResult::Conflict {
                            reason: format!("schema '{}' does not exist", old_name),
                        };
                    }
                    SchemaLookup::WrongKind => {
                        unreachable!("schemas do not share an overlay with other object kinds")
                    }
                }
                match self.schema_lookup(new_name) {
                    SchemaLookup::Present => {
                        return MutationResult::Conflict {
                            reason: format!("schema '{}' already exists", new_name),
                        };
                    }
                    SchemaLookup::Unknown => {
                        self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                        return MutationResult::Skipped;
                    }
                    SchemaLookup::Tombstone | SchemaLookup::AuthoritativelyAbsent => {}
                    SchemaLookup::WrongKind => {
                        unreachable!("schemas do not share an overlay with other object kinds")
                    }
                }
                self.snapshot_search_path();
                self.rename_schema_namespace(old_name, new_name);
                MutationResult::Applied
            }
        }
    }

    pub(super) fn apply_drop_schema(&mut self, drop_schema: &DropSchemaMutation) -> MutationResult {
        let mut unknown_target = false;
        for name in &drop_schema.names {
            match self.schema_lookup(name) {
                SchemaLookup::Present => {}
                SchemaLookup::Tombstone | SchemaLookup::AuthoritativelyAbsent => {
                    if !drop_schema.if_exists {
                        return MutationResult::Conflict {
                            reason: format!("schema '{}' does not exist", name),
                        };
                    }
                }
                SchemaLookup::Unknown => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    unknown_target = true;
                }
                SchemaLookup::WrongKind => {
                    unreachable!("schemas do not share an overlay with other object kinds")
                }
            }
        }
        // PostgreSQL resolves the complete object list before applying the
        // DROP. A scoped cache cannot prove an unknown schema is absent even
        // with IF EXISTS, so it cannot safely remove the known siblings.
        if unknown_target {
            return MutationResult::Skipped;
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
            let dropped_schema_names: std::collections::HashSet<String> =
                present_names.iter().cloned().collect();
            let relation_roots: Vec<ObjectId> = self
                .local
                .relations
                .iter()
                .filter_map(|(id, overlay)| {
                    (dropped_schema_names.contains(&id.schema)
                        && matches!(overlay, RelationOverlay::Present(_)))
                    .then_some(id.clone())
                })
                .collect();
            let mut cascade = super::CascadeResult::default();
            for root in &relation_roots {
                let closure = self.get_cascade_closure(root);
                cascade.dropped_relations.extend(closure.dropped_relations);
                cascade.dropped_indexes.extend(closure.dropped_indexes);
                cascade
                    .dropped_constraints
                    .extend(closure.dropped_constraints);
            }
            let all_dropped_relations = cascade.dropped_relations;
            let dropped_relations: std::collections::HashSet<ObjectId> = all_dropped_relations
                .iter()
                .filter(|id| self.relation_is_present(id))
                .cloned()
                .collect();
            if all_dropped_relations
                .iter()
                .any(|id| !self.relation_is_present(id))
            {
                // A scoped cache may retain a dependency edge without the
                // dependent relation's catalog row. PostgreSQL would drop it,
                // but the simulator cannot reproduce its full state exactly.
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
            for id in &dropped_relations {
                self.local
                    .relations
                    .insert(id.clone(), RelationOverlay::Dropped);
            }

            let types_to_drop: Vec<ObjectId> = self
                .local
                .types
                .keys()
                .filter(|id| dropped_schema_names.contains(&id.schema))
                .cloned()
                .collect();
            for id in types_to_drop {
                self.local.types.insert(id, TypeOverlay::Dropped);
            }

            let sequences_to_drop: Vec<SequenceDrop> = self
                .local
                .sequences
                .iter()
                .filter_map(|(id, overlay)| {
                    let SequenceOverlay::Present(sequence) = overlay else {
                        return None;
                    };
                    let owned_by_dropped_relation =
                        sequence.owned_by.as_ref().is_some_and(|(table, _)| {
                            all_dropped_relations.contains(self.local.graph.resolve_rename(table))
                        });
                    (dropped_schema_names.contains(&id.schema) || owned_by_dropped_relation)
                        .then(|| (id.clone(), sequence.kind.clone(), sequence.owned_by.clone()))
                })
                .collect();
            for (id, kind, owned_by) in sequences_to_drop {
                self.clear_sequence_defaults_on_cascade(&id, kind, owned_by);
                self.local.sequences.insert(id, SequenceOverlay::Dropped);
            }

            let functions_to_drop: std::collections::HashSet<ObjectId> = self
                .local
                .functions
                .keys()
                .filter(|id| dropped_schema_names.contains(&id.schema))
                .cloned()
                .collect();
            for id in &functions_to_drop {
                self.local
                    .functions
                    .insert(id.clone(), FunctionOverlay::Dropped);
            }

            let triggers_to_drop: Vec<ObjectId> = self
                .local
                .triggers
                .iter()
                .filter_map(|(id, overlay)| {
                    let TriggerOverlay::Present(trigger) = overlay else {
                        return None;
                    };
                    let function_is_dropped = self.local.graph.edges().iter().any(|edge| {
                        matches!(
                            &edge.kind,
                            DependencyKind::TriggerOnTable { trigger_id, function_id }
                                if trigger_id == id && functions_to_drop.contains(function_id)
                        )
                    });
                    (dropped_schema_names.contains(&id.schema)
                        || all_dropped_relations
                            .contains(self.local.graph.resolve_rename(&trigger.table_id))
                        || function_is_dropped)
                        .then_some(id.clone())
                })
                .collect();
            let dropped_trigger_ids: std::collections::HashSet<ObjectId> =
                triggers_to_drop.iter().cloned().collect();
            for id in triggers_to_drop {
                self.local.triggers.insert(id, TriggerOverlay::Dropped);
            }

            self.remove_dropped_constraints(&all_dropped_relations, &cascade.dropped_constraints);

            self.local
                .pending_validation
                .retain(|(table, _)| !dropped_schema_names.contains(&table.schema));
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
                        .is_none_or(|schema| !dropped_schema_names.contains(&schema.resolve())),
                    PublicationObjectFact::SchemaTables { schema, .. } => {
                        !dropped_schema_names.contains(schema)
                    }
                    _ => true,
                });
            }

            self.snapshot_graph_full();
            let resolution_graph = self.local.graph.clone();
            self.local.graph.retain_edges(|edge| {
                let dependent = resolution_graph.resolve_rename(&edge.dependent);
                let referenced = resolution_graph.resolve_rename(&edge.referenced);
                if all_dropped_relations.contains(dependent)
                    || all_dropped_relations.contains(referenced)
                    || cascade.dropped_indexes.contains(dependent)
                    || dropped_schema_names.contains(&edge.dependent.schema)
                    || dropped_schema_names.contains(&edge.referenced.schema)
                {
                    return false;
                }
                match &edge.kind {
                    DependencyKind::ForeignKey {
                        constraint_name: Some(name),
                        ..
                    } => !cascade
                        .dropped_constraints
                        .contains(&(dependent.clone(), name.clone())),
                    DependencyKind::TriggerOnTable {
                        trigger_id,
                        function_id,
                    } => {
                        !dropped_trigger_ids.contains(trigger_id)
                            && !functions_to_drop.contains(function_id)
                    }
                    _ => true,
                }
            });
        } else {
            let has_external_dependents = self.local.graph.edges().iter().any(|edge| {
                !matches!(&edge.kind, DependencyKind::RenameTo)
                    && drop_schema.names.contains(&edge.referenced.schema)
                    && !drop_schema.names.contains(&edge.dependent.schema)
            });
            if has_external_dependents {
                return MutationResult::Conflict {
                    reason: format!(
                        "schema(s) {:?} have dependent objects outside the schema; use CASCADE",
                        drop_schema.names
                    ),
                };
            }
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
            // The state model deliberately omits several PostgreSQL object
            // families. With RESTRICT, any omitted object can make this
            // statement fail, so an apparently empty modeled namespace is not
            // sufficient evidence to drop the schema exactly.
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            return MutationResult::Skipped;
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
