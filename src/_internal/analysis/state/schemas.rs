use super::*;

impl AnalysisState {
    pub(super) fn schema_is_present(&self, name: &str) -> bool {
        matches!(
            self.local.schemas.get(name),
            Some(SchemaOverlay::Present(_))
        )
    }

    pub(super) fn schema_lookup(&self, name: &str) -> ObjectLookup {
        match self.local.schemas.get(name) {
            Some(SchemaOverlay::Present(_)) => ObjectLookup::Present,
            Some(SchemaOverlay::Dropped) => ObjectLookup::Tombstone,
            None if self.schema_absence_is_authoritative(name) => {
                ObjectLookup::AuthoritativelyAbsent
            }
            None => ObjectLookup::Unknown,
        }
    }

    pub(super) fn schema_absence_is_authoritative(&self, name: &str) -> bool {
        if matches!(self.local.schemas.get(name), Some(SchemaOverlay::Dropped)) {
            return true;
        }
        self.baseline_available
            && self
                .baseline_coverage
                .has(crate::_internal::db::cache::CatalogFamily::Schemas)
            && self
                .baseline_schemas
                .as_ref()
                .is_none_or(|schemas| schemas.contains(name))
    }

    /// Recompute the effective search path from the session template.
    ///
    /// PostgreSQL silently ignores a path entry that does not name an existing
    /// schema, so the model drops entries it can prove absent and keeps every
    /// other one — a schema it cannot prove anything about stays as an
    /// unresolved placeholder rather than disappearing. Absence is proven by
    /// the schema overlay or, outside a synchronized scope, by the
    /// synchronizer's namespace record. Nothing is tainted here: an unresolved
    /// entry only makes an answer uncertain when a lookup actually resolves
    /// past it (`path_shadows`), which is where the taint belongs.
    pub(super) fn refresh_role_sensitive_search_path(&mut self) {
        let template = self.local.search_path_template.clone();
        let mut effective: Vec<SearchPathEntry> = Vec::new();
        for entry in template {
            if entry == "$user" {
                if self.local.current_role_known {
                    let role_schema = self.local.current_role.clone();
                    self.push_path_entry(&mut effective, role_schema);
                } else if !effective.contains(&SearchPathEntry::Unresolved(None)) {
                    effective.push(SearchPathEntry::Unresolved(None));
                }
            } else {
                self.push_path_entry(&mut effective, entry);
            }
        }
        self.local.search_path = effective;
    }

    pub(super) fn push_path_entry(&self, effective: &mut Vec<SearchPathEntry>, schema: String) {
        let entry = if is_session_temp_schema(&schema) {
            // The alias names the session's own temporary schema and nothing
            // else, so a path naming it searches nothing until that namespace
            // exists; relation and type lookups add it themselves.
            if !self.temp_namespace_exists() {
                return;
            }
            SearchPathEntry::Schema(schema)
        } else if schema == SYSTEM_CATALOG_SCHEMA {
            // Every database has the system catalog even though sync models no
            // objects inside it; dropping the entry would misstate the search
            // order for what the model does know (operator classes).
            SearchPathEntry::Schema(schema)
        } else if self.schema_is_present(&schema) {
            SearchPathEntry::Schema(schema)
        } else if self.schema_absence_is_authoritative(&schema)
            || self.schema_did_not_exist_at_sync(&schema)
        {
            return;
        } else {
            SearchPathEntry::Unresolved(Some(schema))
        };
        if !effective.contains(&entry) {
            effective.push(entry);
        }
    }

    /// A default-template entry the record omits named no schema at sync
    /// time, so it is provably absent even outside the synchronized scope.
    pub(super) fn schema_did_not_exist_at_sync(&self, name: &str) -> bool {
        self.local
            .source_existing_schemas
            .as_ref()
            .is_some_and(|schemas| !schemas.contains(name))
    }

    pub(super) fn remap_schema_id(id: &mut ObjectId, old_name: &str, new_name: &str) {
        if id.schema == old_name {
            id.schema = new_name.to_string();
        }
    }

    pub(super) fn rename_schema_namespace(&mut self, old_name: &str, new_name: &str) {
        self.snapshot_namespace();

        let mut aliases = Vec::new();
        let mut relations = HashMap::new();
        for (mut id, mut overlay) in std::mem::take(&mut self.local.relations) {
            let old_id = id.clone();
            Self::remap_schema_id(&mut id, old_name, new_name);
            if let RelationOverlay::Present(state) = &mut overlay {
                Self::remap_schema_id(&mut state.id, old_name, new_name);
            }
            if id != old_id {
                aliases.push((old_id, id.clone()));
            }
            relations.insert(id, overlay);
        }
        self.local.relations = relations;

        let mut types = HashMap::new();
        for (mut id, mut overlay) in std::mem::take(&mut self.local.types) {
            let old_id = id.clone();
            Self::remap_schema_id(&mut id, old_name, new_name);
            if let TypeOverlay::Present(state) = &mut overlay {
                Self::remap_schema_id(&mut state.id, old_name, new_name);
            }
            if id != old_id {
                aliases.push((old_id, id.clone()));
            }
            types.insert(id, overlay);
        }
        self.local.types = types;

        let mut functions = HashMap::new();
        for (mut id, mut overlay) in std::mem::take(&mut self.local.functions) {
            let old_id = id.clone();
            Self::remap_schema_id(&mut id, old_name, new_name);
            if let crate::_internal::model::function::FunctionOverlay::Present(state) = &mut overlay
            {
                Self::remap_schema_id(&mut state.id, old_name, new_name);
            }
            if id != old_id {
                aliases.push((old_id, id.clone()));
            }
            functions.insert(id, overlay);
        }
        self.local.functions = functions;

        let mut sequences = HashMap::new();
        for (mut id, mut overlay) in std::mem::take(&mut self.local.sequences) {
            let old_id = id.clone();
            Self::remap_schema_id(&mut id, old_name, new_name);
            if let SequenceOverlay::Present(state) = &mut overlay {
                Self::remap_schema_id(&mut state.id, old_name, new_name);
                if let Some((table, _)) = &mut state.owned_by {
                    Self::remap_schema_id(table, old_name, new_name);
                }
            }
            if id != old_id {
                aliases.push((old_id, id.clone()));
            }
            sequences.insert(id, overlay);
        }
        self.local.sequences = sequences;

        let mut triggers = HashMap::new();
        for (mut id, mut overlay) in std::mem::take(&mut self.local.triggers) {
            let old_id = id.clone();
            Self::remap_schema_id(&mut id, old_name, new_name);
            if let TriggerOverlay::Present(state) = &mut overlay {
                Self::remap_schema_id(&mut state.id, old_name, new_name);
                Self::remap_schema_id(&mut state.table_id, old_name, new_name);
            }
            if id != old_id {
                aliases.push((old_id, id.clone()));
            }
            triggers.insert(id, overlay);
        }
        self.local.triggers = triggers;

        for overlay in self.local.publications.values_mut() {
            let crate::_internal::model::replication::PublicationOverlay::Present(publication) =
                overlay
            else {
                continue;
            };
            let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                &mut publication.scope
            else {
                continue;
            };
            for object in objects {
                match object {
                    crate::_internal::analysis::facts::PublicationObjectFact::Table {
                        name,
                        ..
                    } => {
                        if name
                            .schema
                            .as_ref()
                            .is_some_and(|schema| schema.resolve() == old_name)
                        {
                            name.schema = Some(crate::_internal::ast::identifiers::Ident::new(
                                new_name, true,
                            ));
                        }
                    }
                    crate::_internal::analysis::facts::PublicationObjectFact::SchemaTables {
                        schema,
                        ..
                    } if schema == old_name => *schema = new_name.to_string(),
                    _ => {}
                }
            }
        }

        self.local.constraints = std::mem::take(&mut self.local.constraints)
            .into_iter()
            .map(|((mut table, name), mut constraint)| {
                Self::remap_schema_id(&mut table, old_name, new_name);
                Self::remap_schema_id(&mut constraint.table_id, old_name, new_name);
                ((table, name), constraint)
            })
            .collect();
        self.local.pending_validation = std::mem::take(&mut self.local.pending_validation)
            .into_iter()
            .map(|(mut table, name)| {
                Self::remap_schema_id(&mut table, old_name, new_name);
                (table, name)
            })
            .collect();

        self.local.graph.remap_schema_namespace(old_name, new_name);
        for (old_id, new_id) in aliases {
            self.local.graph.add_edge(DependencyEdge::new(
                old_id,
                new_id,
                DependencyKind::RenameTo,
            ));
        }

        let remap_set = |set: &mut HashSet<ObjectId>| {
            *set = std::mem::take(set)
                .into_iter()
                .map(|mut id| {
                    Self::remap_schema_id(&mut id, old_name, new_name);
                    id
                })
                .collect();
        };
        // Both endpoints of a cross-scope edge carry a schema.
        let remap_edges = |set: &mut HashSet<ScopedDependencyEdge>| {
            *set = std::mem::take(set)
                .into_iter()
                .map(|mut edge| {
                    Self::remap_schema_id(&mut edge.scoped, old_name, new_name);
                    if let Some(external) = edge.external.as_mut() {
                        Self::remap_schema_id(external, old_name, new_name);
                    }
                    edge
                })
                .collect();
        };
        remap_set(&mut self.baseline_relations);
        remap_set(&mut self.baseline_indexes);
        remap_set(&mut self.baseline_fk_dependencies);
        remap_set(&mut self.baseline_sequences);
        remap_edges(&mut self.scoped_external_dependencies);
        self.baseline_foreign_keys = std::mem::take(&mut self.baseline_foreign_keys)
            .into_iter()
            .map(|(mut table, name)| {
                Self::remap_schema_id(&mut table, old_name, new_name);
                (table, name)
            })
            .collect();
        if let Some(schemas) = &mut self.baseline_schemas
            && schemas.remove(old_name)
        {
            schemas.insert(new_name.to_string());
        }

        if let Some(SchemaOverlay::Present(mut schema)) = self.local.schemas.remove(old_name) {
            schema.name = new_name.to_string();
            self.local
                .schemas
                .insert(new_name.to_string(), SchemaOverlay::Present(schema));
            // A rename proves the old namespace is absent for the rest of the
            // chain. Retain that fact explicitly: removing the entry makes an
            // old name outside a scoped baseline look unknown, which can keep
            // it in search_path and prevent an exact recreate.
            self.local
                .schemas
                .insert(old_name.to_string(), SchemaOverlay::Dropped);
        }
        self.refresh_role_sensitive_search_path();
    }

    pub(super) fn restore_persistent_role_context(&mut self) {
        self.local.current_role = self.local.persistent_current_role.clone();
        self.local.current_role_known = self.local.persistent_current_role_known;
        self.local.session_role = self.local.persistent_session_role.clone();
        self.local.session_role_known = self.local.persistent_session_role_known;
        self.local.search_path_template = self.local.session_search_path_template.clone();
        self.local.lock_timeout.reset_effective_to_session();
        self.local.statement_timeout.reset_effective_to_session();
        self.refresh_role_sensitive_search_path();
    }
}
