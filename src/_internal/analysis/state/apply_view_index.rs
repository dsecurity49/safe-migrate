use super::{
    AnalysisState, CascadeResult, ConflictKind, MutationResult, ObjectLookup, RelationOverlay,
};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterViewFamily, CreateIndex, CreateMaterializedView, CreateView, DropIndex,
    DropMaterializedViewMutation, DropViewMutation, RefreshMaterializedViewMutation,
    ReloptionTarget, ViewColumn, ViewRoutine,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::column::Column;
use crate::_internal::model::index::{IndexDefinition, index_keys};
use crate::_internal::model::relation::{
    Persistence, RelationKind, RelationState, ViewUpdatability,
};
use crate::_internal::model::reloption::{
    IndexMethod, ReloptionNamespace, ReloptionOutcome, ToastOptions, evaluate, is_known_option_name,
};
use std::collections::{BTreeSet, HashSet};

type RelationLookup = ObjectLookup;
type IndexLookup = ObjectLookup;

/// Record the options PostgreSQL keeps in the relation's own `reloptions`. A
/// `toast.` option configures the TOAST relation instead, so it is left out.
pub(super) fn store_relation_options(
    options: &mut std::collections::BTreeMap<String, String>,
    attributes: &[crate::_internal::analysis::facts::AttributeFact],
) {
    for attribute in attributes.iter().filter(|a| a.namespace.is_none()) {
        options.insert(
            attribute.key(),
            attribute
                .value
                .clone()
                .unwrap_or_else(|| "true".to_string()),
        );
    }
}

impl AnalysisState {
    /// Record or clear a view column default, which PostgreSQL applies to
    /// `INSERT` through the view.
    pub(super) fn apply_set_column_default(
        &mut self,
        id: &ObjectId,
        column: &str,
        default: Option<&crate::_internal::analysis::expr_ir::ExprIr>,
    ) -> MutationResult {
        if !matches!(
            self.local.relations.get(id),
            Some(RelationOverlay::Present(_))
        ) {
            return MutationResult::NoOp;
        }
        self.snapshot_relation(id);
        let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(id) else {
            return MutationResult::NoOp;
        };
        let Some(entry) = relation.columns.iter_mut().find(|c| c.name == column) else {
            return MutationResult::conflict(format!(
                "column '{column}' of view '{}' does not exist",
                id
            ));
        };
        entry.default = default.cloned();
        entry.default_expr_text = None;
        MutationResult::Applied
    }

    /// Apply `SET (...)` on a view or materialized view. A name the analyzer
    /// cannot place is stored but taints, since PostgreSQL's accepted surface
    /// grows between releases and a false conflict would be worse.
    pub(super) fn apply_set_reloptions(
        &mut self,
        id: &ObjectId,
        kind: ReloptionTarget,
        attributes: &[crate::_internal::analysis::facts::AttributeFact],
    ) -> MutationResult {
        if let Err(result) =
            self.validate_reloptions(attributes, kind, self.relation_toast_options(id, kind))
        {
            return result;
        }

        if matches!(kind, ReloptionTarget::View)
            && Self::has_check_option(attributes)
            && let Err(result) = self.validate_check_option(self.stored_view_updatability(id))
        {
            return result;
        }

        if !matches!(
            self.local.relations.get(id),
            Some(RelationOverlay::Present(_))
        ) {
            return MutationResult::NoOp;
        }
        self.snapshot_relation(id);
        if let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(id) {
            store_relation_options(&mut relation.table_options, attributes);
        }
        MutationResult::Applied
    }

    /// Whether `toast.` options on this relation are checked, ignored, or
    /// cannot be placed. A view has no storage and a partitioned table never
    /// has a TOAST table, so PostgreSQL drops them on both; a table's TOAST
    /// table presence is what decides.
    fn relation_toast_options(&self, id: &ObjectId, kind: ReloptionTarget) -> ToastOptions {
        match kind {
            ReloptionTarget::View
            | ReloptionTarget::PartitionedTable
            | ReloptionTarget::Column
            | ReloptionTarget::Index(_) => ToastOptions::Ignored,
            ReloptionTarget::Table | ReloptionTarget::MaterializedView => {
                match self.local.relations.get(id) {
                    Some(RelationOverlay::Present(relation)) => match relation.has_toast_table {
                        Some(true) => ToastOptions::Validated,
                        Some(false) => ToastOptions::Ignored,
                        None => ToastOptions::Unknown,
                    },
                    _ => ToastOptions::Unknown,
                }
            }
        }
    }

    /// The option set `ALTER TABLE ... SET/RESET (...)` targets, or `None` when
    /// PostgreSQL refuses the action on this relation kind, as it does for a
    /// foreign table.
    fn alter_table_reloption_target(relation: &RelationState) -> Option<ReloptionTarget> {
        Some(match relation.kind {
            RelationKind::View => ReloptionTarget::View,
            RelationKind::MaterializedView => ReloptionTarget::MaterializedView,
            RelationKind::Table if relation.partition_type.is_some() => {
                ReloptionTarget::PartitionedTable
            }
            RelationKind::Table => ReloptionTarget::Table,
            RelationKind::ForeignTable => return None,
        })
    }

    /// Validate `ALTER TABLE ... SET (...)` against the target's catalogue kind,
    /// which is what selects the option parser PostgreSQL runs.
    pub(super) fn validate_alter_table_set_options(
        &mut self,
        id: &ObjectId,
        attributes: &[crate::_internal::analysis::facts::AttributeFact],
    ) -> Result<(), MutationResult> {
        let (target, updatability) = {
            let Some(RelationOverlay::Present(relation)) = self.local.relations.get(id) else {
                return Ok(());
            };
            let Some(target) = Self::alter_table_reloption_target(relation) else {
                return Err(MutationResult::conflict(format!(
                    "ALTER action SET cannot be performed on relation \"{id}\""
                )));
            };
            (target, relation.view_updatability)
        };
        let toast = self.relation_toast_options(id, target);
        self.validate_reloptions(attributes, target, toast)?;
        if matches!(target, ReloptionTarget::View) && Self::has_check_option(attributes) {
            self.validate_check_option(updatability)?;
        }
        Ok(())
    }

    /// The stored verdict for a relation the analyzer may not have modeled;
    /// an absent or non-view relation is unknown rather than updatable.
    fn stored_view_updatability(&self, id: &ObjectId) -> ViewUpdatability {
        match self.local.relations.get(id) {
            Some(RelationOverlay::Present(relation)) => relation.view_updatability,
            _ => ViewUpdatability::Unknown,
        }
    }

    fn has_check_option(attributes: &[crate::_internal::analysis::facts::AttributeFact]) -> bool {
        attributes
            .iter()
            .any(|attribute| attribute.namespace.is_none() && attribute.name == "check_option")
    }

    /// PostgreSQL refuses `check_option` unless the view query is
    /// automatically updatable, reporting the query's fault as a hint. An
    /// unknown verdict only taints, so a view the analyzer did not define never
    /// becomes a false conflict.
    fn validate_check_option(
        &mut self,
        updatability: ViewUpdatability,
    ) -> Result<(), MutationResult> {
        match updatability {
            ViewUpdatability::Updatable => Ok(()),
            ViewUpdatability::NotUpdatable(reason) => Err(MutationResult::conflict(format!(
                "WITH CHECK OPTION is supported only on automatically updatable views; {}",
                reason.hint()
            ))),
            ViewUpdatability::Unknown => {
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
                Ok(())
            }
        }
    }

    fn view_updatability_state(
        fact: crate::_internal::analysis::facts::ViewUpdatabilityFact,
    ) -> ViewUpdatability {
        use crate::_internal::analysis::facts::ViewUpdatabilityFact;
        match fact {
            ViewUpdatabilityFact::Updatable => ViewUpdatability::Updatable,
            ViewUpdatabilityFact::NotUpdatable(reason) => ViewUpdatability::NotUpdatable(reason),
            ViewUpdatabilityFact::Unknown => ViewUpdatability::Unknown,
        }
    }

    /// `ALTER TABLE ... RESET (...)` checks no name, but PostgreSQL still
    /// refuses the action on a relation kind that cannot take options and
    /// refuses any option that carries a value.
    pub(super) fn validate_alter_table_reset_options(
        &self,
        id: &ObjectId,
        attributes: &[crate::_internal::analysis::facts::AttributeFact],
    ) -> Result<(), MutationResult> {
        if let Some(RelationOverlay::Present(relation)) = self.local.relations.get(id)
            && Self::alter_table_reloption_target(relation).is_none()
        {
            return Err(MutationResult::conflict(format!(
                "ALTER action RESET cannot be performed on relation \"{id}\""
            )));
        }
        Self::reset_reloption_names(attributes).map(|_| ())
    }

    /// Validate `ALTER COLUMN ... SET (options)`. Column options accept no
    /// namespace at all: the attribute parser has no `toast` set to route to.
    pub(super) fn validate_column_options(
        &mut self,
        attributes: &[crate::_internal::analysis::facts::AttributeFact],
    ) -> Result<(), MutationResult> {
        for attribute in attributes {
            if let Some(namespace) = attribute.namespace.as_deref() {
                return Err(MutationResult::conflict(format!(
                    "unrecognized parameter namespace \"{namespace}\""
                )));
            }
        }
        self.validate_option_set(
            attributes.iter(),
            ReloptionNamespace::Main,
            ReloptionTarget::Column,
        )
    }

    /// `ALTER COLUMN ... RESET (...)` checks no name, but it still refuses a
    /// value on an option.
    pub(super) fn validate_column_reset_options(
        &self,
        attributes: &[crate::_internal::analysis::facts::AttributeFact],
    ) -> Result<(), MutationResult> {
        Self::reset_reloption_names(attributes).map(|_| ())
    }

    /// Validate `ALTER INDEX ... SET (options)`. The access method selects the
    /// option table; a method the analyzer does not model can take any name, so
    /// it taints rather than guessing.
    pub(super) fn validate_index_set_options(
        &mut self,
        id: &ObjectId,
        attributes: &[crate::_internal::analysis::facts::AttributeFact],
    ) -> Result<(), MutationResult> {
        // The namespace is checked before the method's parser runs, except that
        // `toast` is valid everywhere and dropped on an index.
        for attribute in attributes {
            if let Some(namespace) = attribute.namespace.as_deref()
                && namespace != "toast"
            {
                return Err(MutationResult::conflict(format!(
                    "unrecognized parameter namespace \"{namespace}\""
                )));
            }
        }
        let method = self
            .index_definition_of(id)
            .and_then(|definition| definition.method.as_deref())
            .and_then(IndexMethod::from_name);
        let Some(method) = method else {
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
            return Ok(());
        };
        self.validate_reloptions(
            attributes,
            ReloptionTarget::Index(method),
            ToastOptions::Ignored,
        )
    }

    /// Validate a `WITH (...)` option list the way PostgreSQL does for `SET`
    /// and for creation: a repeated name, a value outside its domain, and a
    /// name the running version predates are conflicts; a name the option
    /// table cannot place taints, because the accepted surface grows between
    /// releases and a false conflict would be worse.
    fn validate_reloptions(
        &mut self,
        attributes: &[crate::_internal::analysis::facts::AttributeFact],
        kind: ReloptionTarget,
        toast: ToastOptions,
    ) -> Result<(), MutationResult> {
        // The namespace of every option is checked before any set is parsed.
        for attribute in attributes {
            if let Some(namespace) = attribute.namespace.as_deref()
                && namespace != "toast"
            {
                return Err(MutationResult::conflict(format!(
                    "unrecognized parameter namespace \"{namespace}\""
                )));
            }
        }

        // A partitioned table rejects any storage parameter outright, whatever
        // its name, so it is judged before the names are.
        if kind.rejects_storage_parameters() {
            if attributes
                .iter()
                .any(|attribute| attribute.namespace.is_none())
            {
                return Err(MutationResult::conflict(
                    "cannot specify storage parameters for a partitioned table".to_string(),
                ));
            }
        } else {
            self.validate_option_set(
                attributes
                    .iter()
                    .filter(|attribute| attribute.namespace.is_none()),
                ReloptionNamespace::Main,
                kind,
            )?;
        }

        // `toast.` options are only parsed when the relation has a TOAST table.
        if toast != ToastOptions::Ignored {
            self.validate_option_set(
                attributes
                    .iter()
                    .filter(|attribute| attribute.namespace.as_deref() == Some("toast")),
                ReloptionNamespace::Toast(toast),
                kind,
            )?;
        }
        Ok(())
    }

    /// Validate one namespace's options the way PostgreSQL parses a single
    /// option array. A `toast.` set whose TOAST table the analyzer cannot see
    /// may or may not be parsed, so its faults are uncertain rather than wrong.
    fn validate_option_set<'a>(
        &mut self,
        options: impl Iterator<Item = &'a crate::_internal::analysis::facts::AttributeFact>,
        namespace: ReloptionNamespace,
        kind: ReloptionTarget,
    ) -> Result<(), MutationResult> {
        let version = self.pg_version();
        let uncertain = matches!(namespace, ReloptionNamespace::Toast(ToastOptions::Unknown));
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for attribute in options {
            // PostgreSQL rejects a repeated option before applying anything.
            if !seen.insert(attribute.key()) {
                if uncertain {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
                    continue;
                }
                return Err(MutationResult::conflict(format!(
                    "parameter \"{}\" specified more than once",
                    attribute.name
                )));
            }
            match evaluate(
                &attribute.name,
                namespace,
                attribute.value.as_deref(),
                kind,
                version,
            ) {
                ReloptionOutcome::Unrecognized { name } => {
                    if is_known_option_name(&name) {
                        return Err(MutationResult::conflict(format!(
                            "unrecognized parameter \"{name}\""
                        )));
                    }
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
                }
                ReloptionOutcome::BadValue { name, value } => {
                    return Err(MutationResult::conflict(format!(
                        "invalid value for parameter \"{name}\": {value}"
                    )));
                }
                ReloptionOutcome::Unplaced => {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
                }
                ReloptionOutcome::Accepted => {}
            }
        }
        Ok(())
    }

    /// Apply an explicit output-column list to derived projection columns.
    /// PostgreSQL rejects a list longer than the projection and renames the
    /// prefix otherwise; the rest keep their derived names.
    fn name_view_columns(
        &self,
        id: &ObjectId,
        columns: &[ViewColumn],
        column_list: &[String],
        projection_complete: bool,
        too_many_message: &str,
    ) -> Result<Vec<ViewColumn>, MutationResult> {
        let mut columns = columns.to_vec();
        if column_list.is_empty() || !projection_complete {
            return Ok(columns);
        }
        if column_list.len() > columns.len() {
            return Err(MutationResult::conflict(format!(
                "{too_many_message} for '{id}'"
            )));
        }
        for (column, name) in columns.iter_mut().zip(column_list) {
            column.name = name.clone();
        }
        Ok(columns)
    }

    /// Apply `RESET (...)` on a view or materialized view. `RESET` of an option
    /// PostgreSQL does not accept is not an error, unlike `SET`.
    pub(super) fn apply_reset_reloptions(
        &mut self,
        id: &ObjectId,
        _kind: ReloptionTarget,
        attributes: &[crate::_internal::analysis::facts::AttributeFact],
    ) -> MutationResult {
        let names = match Self::reset_reloption_names(attributes) {
            Ok(names) => names,
            Err(result) => return result,
        };
        if !matches!(
            self.local.relations.get(id),
            Some(RelationOverlay::Present(_))
        ) {
            return MutationResult::NoOp;
        }
        self.snapshot_relation(id);
        if let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(id) {
            for name in names {
                relation.table_options.remove(&name);
            }
        }
        MutationResult::Applied
    }

    /// The keys a `RESET (...)` drops. A value on any option is an error the
    /// server raises before it changes anything.
    pub(super) fn reset_reloption_names(
        attributes: &[crate::_internal::analysis::facts::AttributeFact],
    ) -> Result<Vec<String>, MutationResult> {
        for attribute in attributes {
            if attribute.value.is_some() {
                return Err(MutationResult::conflict(
                    "RESET must not include values for parameters".to_string(),
                ));
            }
        }
        Ok(attributes.iter().map(|attribute| attribute.key()).collect())
    }

    fn validate_view_dependencies(
        &mut self,
        dependent: &ObjectId,
        dependencies: &[ObjectId],
    ) -> Result<(), MutationResult> {
        for dependency in dependencies {
            // Recursive views are represented by a self-reference in some
            // PostgreSQL catalog versions. It does not identify an external
            // object that must already exist.
            if dependency == dependent {
                continue;
            }
            self.ensure_relation_target(
                dependency,
                |_| true,
                format!("view dependency relation '{}' does not exist", dependency),
                format!("view dependency '{}' is not a relation", dependency),
            )?;
        }
        Ok(())
    }

    pub(crate) fn cascade_for_relations(&self, roots: &[ObjectId]) -> CascadeResult {
        let mut cascade = CascadeResult::default();
        for root in roots {
            let closure = self.get_cascade_closure(root);
            cascade.dropped_relations.extend(closure.dropped_relations);
            cascade.dropped_indexes.extend(closure.dropped_indexes);
            cascade
                .dropped_constraints
                .extend(closure.dropped_constraints);
        }
        cascade
    }

    pub(super) fn remove_dropped_relation_edges(
        &mut self,
        dropped_relations: &HashSet<ObjectId>,
        dropped_indexes: &HashSet<ObjectId>,
    ) {
        self.snapshot_graph_full();
        let resolution_graph = self.local.graph.clone();
        self.local.graph.retain_edges(|edge| {
            let dependent = resolution_graph.resolve_rename(&edge.dependent);
            let referenced = resolution_graph.resolve_rename(&edge.referenced);
            if dropped_indexes.contains(dependent) {
                return false;
            }
            if dropped_relations.contains(dependent) {
                return false;
            }
            if dropped_relations.contains(referenced) {
                return false;
            }
            true
        });
    }

    fn has_external_view_dependents(&self, roots: &HashSet<ObjectId>) -> bool {
        self.local.graph.edges().iter().any(|edge| {
            self.dependency_edge_is_current(edge)
                && matches!(edge.kind, DependencyKind::ViewDependency { .. })
                && roots.contains(self.local.graph.resolve_rename(&edge.referenced))
                && !roots.contains(self.local.graph.resolve_rename(&edge.dependent))
                && !self
                    .co_dropped_objects
                    .contains(self.local.graph.resolve_rename(&edge.dependent))
        })
    }

    pub(super) fn apply_drop_relation_family(
        &mut self,
        present: &[ObjectId],
        cascade: bool,
        kind_name: &str,
    ) -> MutationResult {
        let roots = present.iter().cloned().collect::<HashSet<_>>();
        // View dependency rows are scope-aware, but expression and extension
        // dependent objects outside the selected schemas are not yet a
        // complete catalog contract. That widens what CASCADE may remove; it
        // does not cancel the drop, which PostgreSQL performs either way.
        if present.iter().any(|id| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Relations,
            )
        }) {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        if !cascade && self.has_external_view_dependents(&roots) {
            return MutationResult::conflict(format!(
                "relation '{}' still has dependent views; use CASCADE",
                present
                    .first()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| kind_name.to_string())
            ));
        }

        let cascade_result = cascade.then(|| self.cascade_for_relations(present));
        if let Some(result) = &cascade_result
            && result
                .dropped_relations
                .iter()
                .any(|id| !self.local.relations.contains_key(id))
        {
            // A scoped cache can expose a dependency edge for a relation whose
            // metadata was intentionally omitted. CASCADE will remove that
            // relation in PostgreSQL, but the simulator cannot reproduce its
            // full state, so the result is necessarily tainted. A tombstone is
            // modeled state instead: the relation was known and a statement in
            // this session already removed it, so repeating the drop for
            // another root is exact.
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        let all_dropped_relations = cascade_result
            .as_ref()
            .map(|result| result.dropped_relations.clone())
            .unwrap_or_else(|| roots.clone());
        let dropped_relations = all_dropped_relations
            .iter()
            .filter(|id| self.relation_is_present(id))
            .cloned()
            .collect::<HashSet<_>>();
        let dropped_indexes = cascade_result
            .as_ref()
            .map(|result| result.dropped_indexes.clone())
            .unwrap_or_default();
        let dropped_constraints = cascade_result
            .as_ref()
            .map(|result| result.dropped_constraints.clone())
            .unwrap_or_default();

        for id in &dropped_relations {
            self.snapshot_relation(id);
            self.local
                .relations
                .insert(id.clone(), RelationOverlay::Dropped);
        }
        let resolution_graph = self.local.graph.clone();
        let triggers_to_drop = self
            .local
            .triggers
            .iter()
            .filter_map(|(id, overlay)| {
                let crate::_internal::model::trigger::TriggerOverlay::Present(trigger) = overlay
                else {
                    return None;
                };
                dropped_relations
                    .contains(resolution_graph.resolve_rename(&trigger.table_id))
                    .then(|| id.clone())
            })
            .collect::<Vec<_>>();
        for trigger_id in triggers_to_drop {
            self.snapshot_trigger(&trigger_id);
            self.local.triggers.insert(
                trigger_id,
                crate::_internal::model::trigger::TriggerOverlay::Dropped,
            );
        }
        // Even when a scoped cache omitted a dependent view, its dependency
        // edge is known and PostgreSQL CASCADE removes that edge. Use the full
        // closure for topology cleanup while only marking modeled overlays.
        self.remove_dropped_constraints(&all_dropped_relations, &dropped_constraints);
        self.remove_dropped_relation_edges(&all_dropped_relations, &dropped_indexes);
        MutationResult::Applied
    }

    fn index_lookup(&self, id: &ObjectId) -> IndexLookup {
        if self.lookup_shadowed(id) {
            return IndexLookup::Unknown;
        }
        if self.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexOnRelation { .. }) && edge.dependent == *id
        }) {
            IndexLookup::Present
        } else if self
            .baseline_covers_family_object(id, crate::_internal::db::cache::CatalogFamily::Indexes)
        {
            IndexLookup::AuthoritativelyAbsent
        } else {
            IndexLookup::Unknown
        }
    }

    pub(super) fn apply_create_view(&mut self, create: &CreateView) -> MutationResult {
        if let Some(message) = &create.invalid_aggregate {
            return MutationResult::conflict(message.clone());
        }
        if let Err(result) = self.ensure_creation_target(&create.id) {
            return result;
        }
        let existing_view = matches!(
            self.relation_lookup(&create.id, |kind| *kind == RelationKind::View),
            RelationLookup::Present
        );
        if self.relation_namespace_is_taken(&create.id) && (!create.or_replace || !existing_view) {
            return MutationResult::conflict(format!("relation '{}' already exists", create.id));
        }
        if let Err(result) = self.validate_view_dependencies(&create.id, &create.depends_on) {
            return result;
        }
        // `WITH [LOCAL] CHECK OPTION` is a `check_option` option and is checked
        // before the column list, as `DefineView` does.
        if Self::has_check_option(&create.options)
            && let Err(result) =
                self.validate_check_option(Self::view_updatability_state(create.updatability))
        {
            return result;
        }
        let columns = match self.name_view_columns(
            &create.id,
            &create.columns,
            &create.column_list,
            create.projection_complete,
            "CREATE VIEW specifies more column names than columns",
        ) {
            Ok(columns) => columns,
            Err(result) => return result,
        };
        if let Err(result) = self.validate_reloptions(
            &create.options,
            ReloptionTarget::View,
            ToastOptions::Ignored,
        ) {
            return result;
        }
        let owner = self
            .local
            .relations
            .get(&create.id)
            .and_then(|overlay| match overlay {
                RelationOverlay::Present(relation) => Some(relation.owner.clone()),
                RelationOverlay::Dropped => None,
            })
            .unwrap_or_else(|| ObjectId::new("", &self.local.current_role));
        self.snapshot_relation(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        let mut relation = if existing_view {
            match self.local.relations.get(&create.id) {
                Some(RelationOverlay::Present(existing)) => existing.clone(),
                _ => unreachable!("existing view lookup established presence"),
            }
        } else {
            RelationState::new(
                create.id.clone(),
                owner,
                generation,
                None,
                RelationKind::View,
                Persistence::Permanent,
                self.local.transactions.len(),
            )
        };
        // CREATE OR REPLACE VIEW keeps the relation identity, ownership,
        // privileges, triggers, and other relation metadata. Only the
        // generation records the replacement in the simulated state.
        relation.id = create.id.clone();
        relation.generation = generation;
        relation.kind = RelationKind::View;
        relation.persistence = Persistence::Permanent;
        relation.columns_complete = create.projection_complete;
        if !create.projection_complete {
            // A view whose output list could not be derived still exists, but
            // its columns are unknown, so any column-level claim is unsound.
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
        } else if create.or_replace && existing_view {
            if let Err(result) = self.check_replaced_view_columns(&create.id, &columns) {
                return result;
            }
            relation.columns = view_state_columns(&columns);
        } else {
            relation.columns = view_state_columns(&columns);
        }
        // `CREATE OR REPLACE VIEW` replaces the option list outright, even with
        // an empty one; a fresh view starts from the options it was given.
        relation.view_updatability = Self::view_updatability_state(create.updatability);
        relation.table_options.clear();
        store_relation_options(&mut relation.table_options, &create.options);
        self.local
            .relations
            .insert(create.id.clone(), RelationOverlay::Present(relation));
        self.snapshot_graph_full();
        if existing_view {
            self.local.graph.retain_edges(|edge| {
                !(edge.dependent == create.id
                    && matches!(
                        edge.kind,
                        DependencyKind::ViewDependency { .. }
                            | DependencyKind::ViewUsesRoutine { .. }
                            | DependencyKind::ViewUsesType
                    ))
            });
        }
        for dependency in &create.depends_on {
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                dependency.clone(),
                DependencyKind::ViewDependency {
                    view_generation: generation,
                    referenced_column: None,
                },
            ));
        }
        self.record_view_routine_dependencies(&create.id, &create.routines);
        self.add_view_type_dependencies(&create.id, &create.cast_types);
        MutationResult::Applied
    }

    pub(super) fn apply_create_materialized_view(
        &mut self,
        create: &CreateMaterializedView,
    ) -> MutationResult {
        if let Err(result) = self.ensure_creation_target(&create.id) {
            return result;
        }
        if create.if_not_exists && self.relation_namespace_is_taken(&create.id) {
            return MutationResult::NoOp;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::conflict(format!("relation '{}' already exists", create.id));
        }
        if let Err(result) = self.validate_view_dependencies(&create.id, &create.depends_on) {
            return result;
        }
        if let Err(result) = self.validate_reloptions(
            &create.options,
            ReloptionTarget::MaterializedView,
            ToastOptions::Validated,
        ) {
            return result;
        }
        let columns = match self.name_view_columns(
            &create.id,
            &create.columns,
            &create.column_list,
            create.projection_complete,
            "too many column names were specified",
        ) {
            Ok(columns) => columns,
            Err(result) => return result,
        };
        self.snapshot_relation(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        let mut relation = RelationState::new(
            create.id.clone(),
            ObjectId::new("", &self.local.current_role),
            generation,
            None,
            RelationKind::MaterializedView,
            Persistence::Permanent,
            self.local.transactions.len(),
        );
        relation.is_populated = Some(!create.with_no_data);
        relation.access_method = create.access_method.clone();
        relation.tablespace = create.tablespace.clone();
        store_relation_options(&mut relation.table_options, &create.options);
        if !create.projection_complete {
            // A view whose output list could not be derived still exists, but
            // its columns are unknown, so any column-level claim is unsound.
            relation.columns_complete = false;
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
        } else {
            relation.columns = view_state_columns(&columns);
        }
        self.local
            .relations
            .insert(create.id.clone(), RelationOverlay::Present(relation));
        self.snapshot_graph_full();
        for dependency in &create.depends_on {
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                dependency.clone(),
                DependencyKind::ViewDependency {
                    view_generation: generation,
                    referenced_column: None,
                },
            ));
        }
        self.record_view_routine_dependencies(&create.id, &create.routines);
        self.add_view_type_dependencies(&create.id, &create.cast_types);
        MutationResult::Applied
    }

    pub(super) fn apply_refresh_materialized_view(
        &mut self,
        refresh: &RefreshMaterializedViewMutation,
    ) -> MutationResult {
        if refresh.concurrently && self.in_transaction() {
            return MutationResult::Conflict(ConflictKind::ConcurrentInTransaction);
        }
        match self.relation_lookup(&refresh.id, |kind| *kind == RelationKind::MaterializedView) {
            RelationLookup::Present => {
                if refresh.concurrently {
                    match self.local.relations.get(&refresh.id) {
                        Some(RelationOverlay::Present(relation)) => match relation.is_populated {
                            Some(false) => {
                                return MutationResult::conflict(format!(
                                    "CONCURRENTLY cannot be used when the materialized view '{}' is not populated",
                                    refresh.id
                                ));
                            }
                            None => {
                                return self
                                    .unresolved_statement(EvidenceCode::CatalogCoverageIncomplete);
                            }
                            Some(true) => {}
                        },
                        _ => unreachable!("materialized-view lookup established presence"),
                    }
                }
                // PostgreSQL rejects the option pair before it looks for the
                // unique index a concurrent refresh requires.
                if refresh.concurrently && refresh.with_no_data {
                    return MutationResult::conflict(
                        "CONCURRENTLY and WITH NO DATA options cannot be used together".to_string(),
                    );
                }
                if refresh.concurrently {
                    match self.refresh_unique_index_state(&refresh.id) {
                        RefreshIndexState::Usable => {}
                        RefreshIndexState::Missing => {
                            return MutationResult::conflict(format!(
                                "cannot refresh materialized view '{}' concurrently; create a unique index with no WHERE clause on one or more columns of the materialized view",
                                refresh.id
                            ));
                        }
                        RefreshIndexState::Unknown => {
                            return self
                                .unresolved_statement(EvidenceCode::CatalogCoverageIncomplete);
                        }
                    }
                }
                self.snapshot_relation(&refresh.id);
                if let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(&refresh.id)
                {
                    relation.is_populated = Some(!refresh.with_no_data);
                }
                MutationResult::Applied
            }
            RelationLookup::WrongKind => {
                MutationResult::conflict(format!("'{}' is not a materialized view", refresh.id))
            }
            RelationLookup::AuthoritativelyAbsent | RelationLookup::Tombstone => {
                MutationResult::conflict(format!(
                    "materialized view '{}' does not exist",
                    refresh.id
                ))
            }
            RelationLookup::Unknown => self.unresolved(EvidenceCode::UnknownObjectState),
        }
    }

    /// Whether a concurrent refresh finds a unique index PostgreSQL can use,
    /// mirroring `is_usable_unique_index` (matview.c).
    fn refresh_unique_index_state(&self, matview: &ObjectId) -> RefreshIndexState {
        if self.has_usable_unique_index(matview) {
            return RefreshIndexState::Usable;
        }
        // A scoped cache may omit the index that would satisfy the check.
        if self.baseline_scoped_family_object(
            matview,
            crate::_internal::db::cache::CatalogFamily::Indexes,
        ) {
            return RefreshIndexState::Unknown;
        }
        RefreshIndexState::Missing
    }

    /// `ALTER VIEW` / `ALTER MATERIALIZED VIEW` with every action of the
    /// statement. `IF EXISTS` guards the relation lookup, and an action the
    /// model does not represent makes the statement opaque.
    /// Record the routines a view calls as dependency edges.
    ///
    /// A call PostgreSQL could have resolved in a schema the model cannot see
    /// leaves the recorded edge untrustworthy, so the statement's claims are
    /// tainted along with it.
    fn record_view_routine_dependencies(&mut self, view: &ObjectId, routines: &[ViewRoutine]) {
        for routine in routines {
            if routine.name.inferred_schema && self.path_shadows(&routine.name.schema) {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Statement);
            }
            let (referenced, unresolved_name) = match &routine.signature {
                Some(signature) => (signature.clone(), None),
                None => (routine.name.clone(), Some(routine.name.clone())),
            };
            self.local.graph.add_edge(DependencyEdge::new(
                view.clone(),
                referenced,
                DependencyKind::ViewUsesRoutine { unresolved_name },
            ));
        }
    }

    /// Record a view's dependency on each type its body casts to.
    fn add_view_type_dependencies(&mut self, view: &ObjectId, cast_types: &[ObjectId]) {
        for ty in cast_types {
            self.local.graph.add_edge(DependencyEdge::new(
                view.clone(),
                ty.clone(),
                DependencyKind::ViewUsesType,
            ));
        }
    }

    /// PostgreSQL only lets `CREATE OR REPLACE VIEW` append columns: every
    /// position it already had keeps its name and its exact type, typmod
    /// included.
    fn check_replaced_view_columns(
        &mut self,
        id: &ObjectId,
        columns: &[ViewColumn],
    ) -> Result<(), MutationResult> {
        let Some(RelationOverlay::Present(existing)) = self.local.relations.get(id) else {
            return Err(self.unresolved(EvidenceCode::CatalogCoverageIncomplete));
        };
        // A view always has at least one column, so an empty list means the
        // previous definition was never resolved.
        let previous = existing.columns.clone();
        if previous.is_empty() {
            return Err(self.unresolved(EvidenceCode::CatalogCoverageIncomplete));
        }
        if columns.len() < previous.len() {
            return Err(MutationResult::conflict(
                "cannot drop columns from view".to_string(),
            ));
        }
        for (old, new) in previous.iter().zip(columns) {
            if old.name != new.name {
                return Err(MutationResult::conflict(format!(
                    "cannot change name of view column \"{}\" to \"{}\"",
                    old.name, new.name
                )));
            }
            // The type string is `format_type`, so it already carries the
            // typmod exactly as PostgreSQL compares the pair of attributes.
            if old.data_type == new.data_type {
                continue;
            }
            // An unstated type on either side cannot prove a change happened.
            if old.data_type.is_none() || new.data_type.is_none() {
                return Err(self.unresolved(EvidenceCode::CatalogCoverageIncomplete));
            }
            return Err(MutationResult::conflict(format!(
                "cannot change data type of view column \"{}\" from {} to {}",
                old.name,
                old.data_type.as_deref().unwrap_or_default(),
                new.data_type.as_deref().unwrap_or_default(),
            )));
        }
        Ok(())
    }

    pub(super) fn apply_alter_view_family(&mut self, alter: &AlterViewFamily) -> MutationResult {
        match self.relation_lookup(&alter.id, |kind| *kind == alter.kind) {
            RelationLookup::WrongKind => {
                return MutationResult::conflict(format!(
                    "'{}' is not a {}",
                    alter.id,
                    match alter.kind {
                        RelationKind::View => "view",
                        _ => "materialized view",
                    }
                ));
            }
            RelationLookup::AuthoritativelyAbsent | RelationLookup::Tombstone => {
                if alter.if_exists {
                    return MutationResult::NoOp;
                }
                return MutationResult::conflict(format!("relation '{}' does not exist", alter.id));
            }
            RelationLookup::Unknown => return self.unresolved(EvidenceCode::UnknownObjectState),
            RelationLookup::Present => {}
        }
        // PostgreSQL applies every action of the statement, so an unmodeled
        // action still contributes its transparency signal.
        for action in &alter.actions {
            match self.apply(action, None) {
                MutationResult::Applied | MutationResult::NoOp => {}
                result => return result,
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_create_index(&mut self, create: &CreateIndex) -> MutationResult {
        if create.concurrently && self.in_transaction() {
            return MutationResult::Conflict(ConflictKind::ConcurrentInTransaction);
        }
        if let Err(result) = self.ensure_creation_target(&create.id) {
            return result;
        }
        // `IF NOT EXISTS` guards the whole name, not just an index: PostgreSQL emits
        // a notice and skips whatever relation already holds the name.
        if create.if_not_exists && self.relation_namespace_is_taken(&create.id) {
            return MutationResult::NoOp;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::conflict(format!("relation '{}' already exists", create.id));
        }
        if let Err(result) = self.ensure_relation_target(
            &create.table,
            |kind| matches!(kind, RelationKind::Table | RelationKind::MaterializedView),
            format!("index target relation '{}' does not exist", create.table),
            format!("index target '{}' cannot be indexed", create.table),
        ) {
            return result;
        }
        // PostgreSQL looks every named key and INCLUDE column up by name and
        // rejects an unknown one. An expression key is typed, not looked up,
        // and an incomplete column list cannot prove absence.
        let target_columns: Option<std::collections::HashSet<String>> =
            match self.local.relations.get(&create.table) {
                Some(RelationOverlay::Present(relation)) if relation.columns_complete => Some(
                    relation
                        .columns
                        .iter()
                        .map(|column| column.name.clone())
                        .collect(),
                ),
                _ => None,
            };
        if let Some(columns) = target_columns {
            for column in create.key_columns.iter().chain(&create.included_columns) {
                if !columns.contains(column) {
                    return MutationResult::conflict(format!("column \"{column}\" does not exist"));
                }
            }
        }
        if create.concurrently
            && self
                .local
                .relations
                .get(&create.table)
                .and_then(|overlay| match overlay {
                    RelationOverlay::Present(relation) => relation.partition_type.as_deref(),
                    RelationOverlay::Dropped => None,
                })
                .is_some()
        {
            return MutationResult::conflict(format!(
                "CREATE INDEX CONCURRENTLY cannot run on partitioned table '{}'",
                create.table
            ));
        }
        self.snapshot_graph();
        // `ON ONLY` declines recursion into partitions: the parent stays
        // invalid while partitions exist (indexcmds.c's INDEX_CREATE_INVALID),
        // and is valid with none to cover.
        let partitions: Vec<ObjectId> = self
            .local
            .graph
            .partitions_of(&create.table)
            .into_iter()
            .cloned()
            .collect();
        let declined = create.only && !partitions.is_empty();
        let kind = DependencyKind::IndexOnRelation {
            definition: IndexDefinition {
                method: create
                    .using_method
                    .clone()
                    .or_else(|| Some("btree".to_string())),
                keys: self.resolved_statement_index_keys(create),
                included: index_keys(create.included_columns.clone()),
                expression_keys: create
                    .key_expressions
                    .iter()
                    .filter(|key| key.is_some())
                    .count(),
                unique: create.unique,
                nulls_not_distinct: Some(create.nulls_not_distinct),
                predicate: create.predicate.clone(),
                unestablished: false,
                valid: !declined,
                ready: true,
                live: true,
            },
            dependency_columns: create
                .key_columns
                .iter()
                .chain(&create.included_columns)
                .cloned()
                .collect(),
            dependency_columns_known: create.key_expressions.iter().all(Option::is_none)
                && !create.predicate.has_predicate(),
            is_concurrent: create.concurrently,
            is_immediate: true,
            eligibility_known: true,
        };
        self.local.graph.add_edge(DependencyEdge::new(
            create.id.clone(),
            create.table.clone(),
            kind.clone(),
        ));
        if !declined && !partitions.is_empty() {
            for partition in &partitions {
                self.ensure_partition_index_child(
                    &create.id,
                    partition,
                    &kind,
                    super::index_topology::ChildReuseRule::Creation,
                );
            }
            // `DefineIndex` invalidates the parent when any partition's
            // resulting child is invalid; the children were ensured above, so
            // coverage is exactly the invalidate-parent check.
            let covered = self.index_is_fully_attached(&create.id);
            self.snapshot_graph_full();
            self.local
                .graph
                .update_index_definition(&create.id, |stored| stored.valid = covered);
        }
        MutationResult::Applied
    }

    pub(super) fn apply_drop_view(&mut self, drop: &DropViewMutation) -> MutationResult {
        let mut present = Vec::new();
        let mut unknown_target = false;
        for id in &drop.ids {
            match self.relation_lookup(id, |kind| *kind == RelationKind::View) {
                RelationLookup::Present => present.push(id.clone()),
                RelationLookup::WrongKind => {
                    return MutationResult::conflict(format!("'{}' is not a view", id));
                }
                RelationLookup::AuthoritativelyAbsent if drop.if_exists => {}
                RelationLookup::AuthoritativelyAbsent => {
                    return MutationResult::conflict(format!("view '{}' does not exist", id));
                }
                RelationLookup::Tombstone if drop.if_exists => {}
                RelationLookup::Tombstone => {
                    return MutationResult::conflict(format!("view '{}' does not exist", id));
                }
                RelationLookup::Unknown => {
                    unknown_target = true;
                    if !drop.if_exists {
                        return self.unresolved(EvidenceCode::UnknownObjectState);
                    }
                }
            }
        }
        if unknown_target {
            return self.unresolved(EvidenceCode::UnknownObjectState);
        }
        if present.is_empty() {
            return MutationResult::NoOp;
        }
        self.apply_drop_relation_family(&present, drop.cascade, "view")
    }

    pub(super) fn apply_drop_materialized_view(
        &mut self,
        drop: &DropMaterializedViewMutation,
    ) -> MutationResult {
        let mut present = Vec::new();
        let mut unknown_target = false;
        for id in &drop.ids {
            match self.relation_lookup(id, |kind| *kind == RelationKind::MaterializedView) {
                RelationLookup::Present => present.push(id.clone()),
                RelationLookup::WrongKind => {
                    return MutationResult::conflict(format!(
                        "'{}' is not a materialized view",
                        id
                    ));
                }
                RelationLookup::AuthoritativelyAbsent if drop.if_exists => {}
                RelationLookup::AuthoritativelyAbsent => {
                    return MutationResult::conflict(format!(
                        "materialized view '{}' does not exist",
                        id
                    ));
                }
                RelationLookup::Tombstone if drop.if_exists => {}
                RelationLookup::Tombstone => {
                    return MutationResult::conflict(format!(
                        "materialized view '{}' does not exist",
                        id
                    ));
                }
                RelationLookup::Unknown => {
                    unknown_target = true;
                    if !drop.if_exists {
                        return self.unresolved(EvidenceCode::UnknownObjectState);
                    }
                }
            }
        }
        if unknown_target {
            return self.unresolved(EvidenceCode::UnknownObjectState);
        }
        if present.is_empty() {
            return MutationResult::NoOp;
        }
        self.apply_drop_relation_family(&present, drop.cascade, "materialized view")
    }

    pub(super) fn apply_drop_index(&mut self, drop: &DropIndex) -> MutationResult {
        if drop.concurrently && self.in_transaction() {
            return MutationResult::Conflict(ConflictKind::ConcurrentInTransaction);
        }
        if drop.concurrently && drop.cascade {
            return MutationResult::conflict(
                "DROP INDEX CONCURRENTLY cannot use CASCADE".to_string(),
            );
        }
        // PostgreSQL resolves every target before it applies a multi-index
        // DROP. Preflight the complete statement so a later invalid target
        // cannot leave an earlier index removed from simulated state.
        let mut targets = Vec::new();
        for id in &drop.ids {
            match self.index_lookup(id) {
                IndexLookup::Present => {
                    if !targets.contains(id) {
                        targets.push(id.clone());
                    }
                }
                IndexLookup::AuthoritativelyAbsent if drop.if_exists => {}
                IndexLookup::AuthoritativelyAbsent => {
                    return MutationResult::conflict(format!("index '{}' does not exist", id));
                }
                IndexLookup::Unknown => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
                IndexLookup::WrongKind | IndexLookup::Tombstone => {
                    unreachable!("indexes have no overlay kind or tombstone")
                }
            }
        }

        if targets.is_empty() {
            return MutationResult::NoOp;
        }

        if targets.iter().any(|id| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Indexes,
            )
        }) {
            // Scoped index rows do not yet carry a complete backing-constraint
            // identity or every external dependency, so PostgreSQL's DROP
            // INDEX conflict semantics cannot be proven from the partial
            // graph. Leave the baseline unchanged until index ownership
            // coverage is object-complete.
            return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
        }

        for id in &targets {
            let Some(index_edge) = self.local.graph.edges().iter().find(|edge| {
                matches!(edge.kind, DependencyKind::IndexOnRelation { .. }) && edge.dependent == *id
            }) else {
                return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
            };
            let referenced_table = self.local.graph.resolve_rename(&index_edge.referenced);
            let resolved_index = self.local.graph.resolve_rename(id);
            if drop.concurrently
                && self
                    .local
                    .relations
                    .get(referenced_table)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => relation.partition_type.as_deref(),
                        RelationOverlay::Dropped => None,
                    })
                    .is_some()
            {
                return MutationResult::conflict(format!(
                    "DROP INDEX CONCURRENTLY cannot run on partitioned index '{}'",
                    id
                ));
            }
            let unresolved_constraint = self.baseline_indexes.contains(id)
                && self
                    .local
                    .constraints
                    .iter()
                    .any(|((table, _), constraint)| {
                        self.local.graph.resolve_rename(table) == referenced_table
                            && matches!(
                                constraint.kind,
                                crate::_internal::model::constraint::ConstraintKind::PrimaryKey
                                    | crate::_internal::model::constraint::ConstraintKind::Unique
                                    | crate::_internal::model::constraint::ConstraintKind::Exclusion
                            )
                            && constraint.backing_index.is_none()
                    });
            if unresolved_constraint {
                return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
            }
            let backs_constraint = self
                .local
                .constraints
                .iter()
                .any(|((table, _), constraint)| {
                    self.local.graph.resolve_rename(table) == referenced_table
                        && constraint.backing_index.as_ref() == Some(resolved_index)
                });
            if backs_constraint {
                return MutationResult::conflict(format!(
                    "cannot drop index '{}' because a constraint requires it",
                    id
                ));
            }
            if matches!(
                index_edge.kind,
                DependencyKind::IndexOnRelation {
                    eligibility_known: false,
                    ..
                }
            ) {
                return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
            }
        }
        // An attached child index cannot be dropped on its own. PostgreSQL
        // refuses unconditionally here: CASCADE does not help and IF EXISTS
        // does not downgrade it. A statement that drops the parent too is
        // exempt, because PostgreSQL applies a statement's targets as a batch.
        for target in &targets {
            if let Some(parent) = self.index_parent_of(target)
                && !targets.iter().any(|other| {
                    self.local.graph.resolve_rename(other)
                        == self.local.graph.resolve_rename(parent)
                })
            {
                return MutationResult::conflict(format!(
                    "cannot drop index '{}' because index '{}' requires it",
                    target.name, parent.name
                ));
            }
        }
        // An attached partition index goes with its parent, and an intermediate
        // partitioned index carries its own attached children.
        let mut attached_children: Vec<ObjectId> = Vec::new();
        let mut frontier: Vec<ObjectId> = targets.clone();
        while let Some(parent) = frontier.pop() {
            for child in self.index_partitions_of(&parent) {
                if !attached_children.contains(&child) {
                    frontier.push(child.clone());
                    attached_children.push(child);
                }
            }
        }
        let mut removed = targets.clone();
        removed.extend(attached_children);
        let table_indexes = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                    && removed.iter().any(|target| {
                        self.local.graph.resolve_rename(target)
                            == self.local.graph.resolve_rename(&edge.dependent)
                    })
            })
            .map(|edge| (edge.referenced.clone(), edge.dependent.name.clone()))
            .collect::<Vec<_>>();
        for (table, index_name) in table_indexes {
            self.snapshot_relation(&table);
            if let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(&table) {
                relation.clear_index_settings(&index_name);
            }
        }
        self.snapshot_graph_full();
        let resolution_graph = self.local.graph.clone();
        let dropped = |id: &ObjectId| {
            removed.iter().any(|target| {
                resolution_graph.resolve_rename(target) == resolution_graph.resolve_rename(id)
            })
        };
        self.local.graph.retain_edges(|edge| match edge.kind {
            DependencyKind::IndexOnRelation { .. } => !dropped(&edge.dependent),
            DependencyKind::IndexPartitionOf => {
                !dropped(&edge.dependent) && !dropped(&edge.referenced)
            }
            _ => true,
        });
        MutationResult::Applied
    }
}

/// The modelled verdict on a materialized view's concurrent-refresh index.
enum RefreshIndexState {
    Usable,
    Missing,
    Unknown,
}

/// A view's projected columns as relation columns.
fn view_state_columns(columns: &[ViewColumn]) -> Vec<Column> {
    columns
        .iter()
        .map(|column| Column {
            name: column.name.clone(),
            data_type: column.data_type.clone(),
            type_id: None,
            is_nullable: true,
            default: None,
            avg_width: None,
            default_expr_text: None,
            type_modifier: column.type_modifier,
            storage: None,
            compression: None,
            statistics_target: None,
            options: Default::default(),
            generated: None,
        })
        .collect()
}
