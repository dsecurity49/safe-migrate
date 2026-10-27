use super::{AnalysisState, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::{
    AlterDomainActionFact, DomainCheckFact, DomainConstraintFact, DomainDefaultFact,
};
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterDomainMutation, AlterTypeActionMutation, AlterTypeMutation, CreateDomainMutation,
    CreateTypeMutation, DropDomainMutation, DropTypeMutation, Rename,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::function::FunctionOverlay;
use crate::_internal::model::types::{DomainConstraintState, TypeKind, TypeOverlay, TypeState};
use std::collections::{BTreeMap, HashSet};

type TypeLookup = ObjectLookup;

impl AnalysisState {
    /// Reject a type the server would refuse to create: a duplicate enum
    /// label, or a component type that names nothing resolvable.
    fn check_created_type(&mut self, kind: &TypeKind) -> Result<(), MutationResult> {
        let declared: Vec<&str> = match kind {
            TypeKind::Enum { variants } => {
                let mut seen = HashSet::new();
                for label in variants {
                    if !seen.insert(label) {
                        return Err(MutationResult::conflict(format!(
                            "enum label \"{label}\" already exists"
                        )));
                    }
                }
                Vec::new()
            }
            TypeKind::Composite { fields } => fields
                .iter()
                .map(|field| field.data_type.as_str())
                .collect(),
            TypeKind::Domain { base_type, .. } => vec![base_type.as_str()],
            TypeKind::Range { subtype, .. } => subtype.as_deref().into_iter().collect(),
            TypeKind::Base { options, .. } => options.element.as_deref().into_iter().collect(),
            TypeKind::Multirange { .. } => Vec::new(),
        };
        for declared_type in declared {
            if let Some(result) = self.check_declared_type(declared_type) {
                return Err(result);
            }
        }
        Ok(())
    }

    /// What a reference to `old_id` becomes when the type is renamed: the new
    /// name, or its array form when the reference was written `name[]`.
    fn renamed_type_id(current: &ObjectId, rename: &Rename) -> Option<ObjectId> {
        if current == &rename.old_id {
            return Some(rename.new_id.clone());
        }
        (current == &Self::array_type_id(&rename.old_id))
            .then(|| Self::array_type_id(&rename.new_id))
    }

    pub(super) fn apply_create_type(&mut self, create: &CreateTypeMutation) -> MutationResult {
        if let Err(result) = self.ensure_creation_target(&create.id) {
            return result;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::conflict(format!("type '{}' already exists", create.id));
        }
        if let Err(result) = self.check_created_type(&create.kind) {
            return result;
        }
        self.snapshot_type(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        self.local.types.insert(
            create.id.clone(),
            TypeOverlay::Present(TypeState {
                id: create.id.clone(),
                generation,
                owner: ObjectId::new("", self.local.current_role.clone()),
                kind: create.kind.clone(),
            }),
        );
        MutationResult::Applied
    }

    pub(super) fn apply_rename_type(&mut self, rename: &Rename) -> MutationResult {
        match self.type_lookup(&rename.old_id, |_| true) {
            TypeLookup::Present => {}
            _ if self.baseline_covers_family_object(
                &rename.old_id,
                crate::_internal::db::cache::CatalogFamily::Types,
            ) =>
            {
                return MutationResult::conflict(format!(
                    "type '{}' does not exist",
                    rename.old_id
                ));
            }
            TypeLookup::Tombstone | TypeLookup::AuthoritativelyAbsent | TypeLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
            TypeLookup::WrongKind => unreachable!("all present type kinds are accepted"),
        }
        if rename.old_id != rename.new_id && self.relation_namespace_is_taken(&rename.new_id) {
            return MutationResult::conflict(format!("type '{}' already exists", rename.new_id));
        }
        if rename.old_id.schema != rename.new_id.schema
            && !self.schema_is_present(&rename.new_id.schema)
        {
            if self.schema_absence_is_authoritative(&rename.new_id.schema) {
                return MutationResult::conflict(format!(
                    "schema '{}' does not exist",
                    rename.new_id.schema
                ));
            }
            return self.unresolved(EvidenceCode::UnknownObjectState);
        }

        let mut remapped_functions = Vec::new();
        for (function_id, overlay) in &self.local.functions {
            let FunctionOverlay::Present(function) = overlay else {
                continue;
            };
            let new_arg_types = function
                .arg_types
                .iter()
                .enumerate()
                .map(|(index, raw)| {
                    if function
                        .arg_type_ids
                        .get(index)
                        .and_then(|id| id.as_ref())
                        .and_then(|id| Self::renamed_type_id(id, rename))
                        .is_some()
                    {
                        Self::remapped_type_display(
                            raw,
                            &rename.new_id,
                            rename.old_id.schema != rename.new_id.schema,
                        )
                    } else {
                        raw.clone()
                    }
                })
                .collect::<Vec<_>>();
            let new_return_type = match function
                .return_type_id
                .as_ref()
                .and_then(|id| Self::renamed_type_id(id, rename))
            {
                Some(_) => Self::remapped_type_display(
                    &function.return_type,
                    &rename.new_id,
                    rename.old_id.schema != rename.new_id.schema,
                ),
                None => function.return_type.clone(),
            };
            let base_name = function_id
                .name
                .split_once('(')
                .map(|(name, _)| name)
                .unwrap_or(&function_id.name);
            let mut new_function_id = ObjectId::new(
                &function_id.schema,
                format!("{}({})", base_name, new_arg_types.join(",")),
            );
            new_function_id.inferred_schema = function_id.inferred_schema;
            if new_function_id != *function_id
                || new_arg_types != function.arg_types
                || new_return_type != function.return_type
            {
                remapped_functions.push((
                    function_id.clone(),
                    new_function_id,
                    new_arg_types,
                    new_return_type,
                ));
            }
        }
        let moved_function_ids = remapped_functions
            .iter()
            .map(|(old_id, _, _, _)| old_id)
            .collect::<HashSet<_>>();
        let mut destinations = HashSet::new();
        for (_, new_id, _, _) in &remapped_functions {
            if !destinations.insert(new_id)
                || (self.local.functions.contains_key(new_id)
                    && !moved_function_ids.contains(new_id))
            {
                return MutationResult::conflict(format!(
                    "routine '{}' already exists after renaming type '{}'",
                    new_id, rename.old_id
                ));
            }
        }

        self.snapshot_namespace();
        self.local
            .graph
            .propagate_type_rename(&rename.old_id, &rename.new_id);
        if let Some(TypeOverlay::Present(mut state)) = self.local.types.remove(&rename.old_id) {
            state.id = rename.new_id.clone();
            self.local
                .types
                .insert(rename.new_id.clone(), TypeOverlay::Present(state));
        }
        for overlay in self.local.relations.values_mut() {
            if let RelationOverlay::Present(relation) = overlay {
                for column in &mut relation.columns {
                    let remapped = column
                        .type_id
                        .as_ref()
                        .and_then(|id| Self::renamed_type_id(id, rename));
                    if let Some(new_type_id) = remapped {
                        column.data_type = Some(Self::remapped_type_display(
                            column.data_type.as_deref().unwrap_or_default(),
                            &rename.new_id,
                            rename.old_id.schema != rename.new_id.schema,
                        ));
                        column.type_id = Some(new_type_id);
                    }
                }
            }
        }
        for overlay in self.local.types.values_mut() {
            let TypeOverlay::Present(TypeState { kind, .. }) = overlay else {
                continue;
            };
            match kind {
                TypeKind::Domain {
                    base_type,
                    base_type_id,
                    ..
                } => {
                    if let Some(new_id) = base_type_id
                        .as_ref()
                        .and_then(|id| Self::renamed_type_id(id, rename))
                    {
                        *base_type = Self::remapped_type_display(
                            base_type,
                            &rename.new_id,
                            rename.old_id.schema != rename.new_id.schema,
                        );
                        *base_type_id = Some(new_id);
                    }
                }
                TypeKind::Composite { fields } => {
                    for field in fields {
                        if let Some(new_id) = field
                            .data_type_id
                            .as_ref()
                            .and_then(|id| Self::renamed_type_id(id, rename))
                        {
                            field.data_type = Self::remapped_type_display(
                                &field.data_type,
                                &rename.new_id,
                                rename.old_id.schema != rename.new_id.schema,
                            );
                            field.data_type_id = Some(new_id);
                        }
                    }
                }
                TypeKind::Range {
                    subtype,
                    subtype_id,
                    ..
                } => {
                    if let Some(new_id) = subtype_id
                        .as_ref()
                        .and_then(|id| Self::renamed_type_id(id, rename))
                    {
                        if let Some(subtype) = subtype {
                            *subtype = Self::remapped_type_display(
                                subtype,
                                &rename.new_id,
                                rename.old_id.schema != rename.new_id.schema,
                            );
                        }
                        *subtype_id = Some(new_id);
                    }
                }
                TypeKind::Enum { .. } | TypeKind::Base { .. } | TypeKind::Multirange { .. } => {}
            }
        }
        for (old_id, new_id, arg_types, return_type) in remapped_functions {
            if let Some(FunctionOverlay::Present(mut function)) =
                self.local.functions.remove(&old_id)
            {
                function.id = new_id.clone();
                function.arg_types = arg_types;
                for type_id in &mut function.arg_type_ids {
                    if let Some(remapped) = type_id
                        .as_ref()
                        .and_then(|id| Self::renamed_type_id(id, rename))
                    {
                        *type_id = Some(remapped);
                    }
                }
                function.return_type = return_type;
                if let Some(remapped) = function
                    .return_type_id
                    .as_ref()
                    .and_then(|id| Self::renamed_type_id(id, rename))
                {
                    function.return_type_id = Some(remapped);
                }
                self.local
                    .functions
                    .insert(new_id.clone(), FunctionOverlay::Present(function));
                if old_id != new_id {
                    self.local.graph.propagate_function_rename(&old_id, &new_id);
                    self.local.graph.add_edge(DependencyEdge::new(
                        old_id,
                        new_id,
                        DependencyKind::RenameTo,
                    ));
                }
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_alter_type(&mut self, alter: &AlterTypeMutation) -> MutationResult {
        match self.type_lookup(&alter.id, |_| true) {
            TypeLookup::Present => {}
            TypeLookup::WrongKind => unreachable!("all present type kinds are accepted"),
            TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone => {
                return MutationResult::conflict(format!("type '{}' does not exist", alter.id));
            }
            TypeLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
        }
        if matches!(&alter.action, AlterTypeActionMutation::AddValue { .. })
            && !matches!(
                self.local.types.get(&alter.id),
                Some(TypeOverlay::Present(TypeState {
                    kind: TypeKind::Enum { .. },
                    ..
                }))
            )
        {
            return MutationResult::conflict(format!("type '{}' is not an enum", alter.id));
        }
        self.snapshot_type(&alter.id);
        if let Some(TypeOverlay::Present(existing)) = self.local.types.get_mut(&alter.id) {
            match &alter.action {
                AlterTypeActionMutation::AddValue {
                    new_value,
                    neighbor,
                    before,
                } => {
                    if let TypeKind::Enum { variants } = &mut existing.kind {
                        if variants.contains(new_value) {
                            return MutationResult::NoOp;
                        }
                        let insertion_index = if let Some(neighbor) = neighbor {
                            let Some(index) = variants.iter().position(|value| value == neighbor)
                            else {
                                return MutationResult::conflict(format!(
                                    "enum label '{}' does not exist on type '{}'",
                                    neighbor, alter.id
                                ));
                            };
                            if *before { index } else { index + 1 }
                        } else {
                            variants.len()
                        };
                        variants.insert(insertion_index, new_value.clone());
                    }
                }
                AlterTypeActionMutation::RenameValue {
                    old_value,
                    new_value,
                } => {
                    let TypeKind::Enum { variants } = &mut existing.kind else {
                        return MutationResult::conflict(format!(
                            "type '{}' is not an enum",
                            alter.id
                        ));
                    };
                    let Some(old_index) = variants.iter().position(|value| value == old_value)
                    else {
                        return MutationResult::conflict(format!(
                            "'{}' is not an existing label of enum '{}'",
                            old_value, alter.id
                        ));
                    };
                    if variants.iter().any(|value| value == new_value) {
                        return MutationResult::conflict(format!(
                            "enum label '{}' already exists on type '{}'",
                            new_value, alter.id
                        ));
                    }
                    variants[old_index] = new_value.clone();
                }
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_create_domain(&mut self, create: &CreateDomainMutation) -> MutationResult {
        if let Err(result) = self.ensure_creation_target(&create.id) {
            return result;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::conflict(format!("type '{}' already exists", create.id));
        }
        if let Some(result) = self.check_declared_type(&create.base_type) {
            return result;
        }
        let inherited_collation = self.effective_type_collation(&create.base_type);
        let (collation, collation_id) = match &create.collation {
            Some(written) => {
                if matches!(inherited_collation, Some((None, None))) {
                    return MutationResult::conflict(format!(
                        "collation specified for non-collatable type '{}'",
                        create.base_type
                    ));
                }
                match self
                    .local
                    .collations
                    .resolve(written, &self.local.search_path)
                {
                    Some(resolved) => (
                        Some(resolved.name.clone()),
                        Some(ObjectId::new(resolved.schema, resolved.name)),
                    ),
                    None => return self.unresolved(EvidenceCode::UnresolvedReference),
                }
            }
            None => match inherited_collation {
                Some(pair) => pair,
                None => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Statement);
                    (None, None)
                }
            },
        };

        let mut reserved = HashSet::new();
        let mut constraints = BTreeMap::new();
        let mut not_null_constraint = None;
        let mut saw_null = false;
        for constraint in &create.constraints {
            match constraint {
                DomainConstraintFact::Check(check) => {
                    let name = self.domain_constraint_name(&create.id, check, &mut reserved);
                    let name = match name {
                        Ok(name) => name,
                        Err(result) => return result,
                    };
                    constraints.insert(
                        name.clone(),
                        DomainConstraintState {
                            name,
                            expression: Some(check.expression.clone()),
                            expression_text: Some(check.expression_text.clone()),
                            definition: check.definition.clone(),
                            validated: !check.not_valid,
                        },
                    );
                }
                DomainConstraintFact::NotNull { name } => {
                    if not_null_constraint.is_some() {
                        return MutationResult::conflict(
                            "redundant NOT NULL constraint definition",
                        );
                    }
                    if saw_null {
                        return MutationResult::conflict("conflicting NULL/NOT NULL constraints");
                    }
                    not_null_constraint = Some(match name {
                        Some(name) => {
                            if !reserved.insert(name.clone()) {
                                return MutationResult::conflict(format!(
                                    "constraint '{}' for domain '{}' already exists",
                                    name, create.id
                                ));
                            }
                            name.clone()
                        }
                        None => self.allocate_domain_constraint_name(
                            &create.id,
                            None,
                            "not_null",
                            &mut reserved,
                        ),
                    });
                }
                DomainConstraintFact::Null => {
                    if not_null_constraint.is_some() {
                        return MutationResult::conflict("conflicting NULL/NOT NULL constraints");
                    }
                    saw_null = true;
                }
            }
        }

        let (default, default_text) = match &create.default {
            Some(default) if !default.is_null => {
                (Some(default.expression.clone()), Some(default.text.clone()))
            }
            _ => (None, None),
        };

        self.snapshot_type(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        self.local.types.insert(
            create.id.clone(),
            TypeOverlay::Present(TypeState {
                id: create.id.clone(),
                generation,
                owner: ObjectId::new("", self.local.current_role.clone()),
                kind: TypeKind::Domain {
                    base_type: create.base_type.clone(),
                    base_type_id: self.resolve_type_reference(&create.base_type),
                    collation,
                    collation_id,
                    default,
                    default_text,
                    not_null: not_null_constraint.is_some(),
                    not_null_constraint,
                    constraints,
                },
            }),
        );
        MutationResult::Applied
    }

    fn domain_constraint_name(
        &self,
        domain: &ObjectId,
        check: &DomainCheckFact,
        reserved: &mut HashSet<String>,
    ) -> Result<String, MutationResult> {
        if let Some(name) = &check.name {
            if !reserved.insert(name.clone()) {
                return Err(MutationResult::conflict(format!(
                    "constraint '{}' for domain '{}' already exists",
                    name, domain
                )));
            }
            return Ok(name.clone());
        }
        Ok(self.allocate_domain_constraint_name(domain, None, "check", reserved))
    }

    fn allocate_domain_constraint_name(
        &self,
        domain: &ObjectId,
        explicit: Option<&str>,
        label: &str,
        reserved: &mut HashSet<String>,
    ) -> String {
        if let Some(name) = explicit {
            reserved.insert(name.to_string());
            return name.to_string();
        }
        let name = (0..)
            .map(|suffix| {
                let label = if suffix == 0 {
                    label.to_string()
                } else {
                    format!("{label}{suffix}")
                };
                Self::postgres_object_name(&domain.name, None, &label)
            })
            .find(|candidate| {
                !reserved.contains(candidate)
                    && !self.namespace_constraint_name_is_taken(&domain.schema, candidate)
            })
            .expect("constraint suffix space is unbounded");
        reserved.insert(name.clone());
        name
    }

    fn domain_constraint_name_is_taken(&self, domain: &ObjectId, name: &str) -> bool {
        self.local.types.values().any(|overlay| {
            let TypeOverlay::Present(TypeState {
                id,
                kind:
                    TypeKind::Domain {
                        constraints,
                        not_null_constraint,
                        ..
                    },
                ..
            }) = overlay
            else {
                return false;
            };
            id == domain
                && (constraints.contains_key(name) || not_null_constraint.as_deref() == Some(name))
        })
    }

    fn namespace_constraint_name_is_taken(&self, schema: &str, name: &str) -> bool {
        self.local
            .constraints
            .keys()
            .any(|(owner, existing)| owner.schema == schema && existing == name)
            || self.local.types.values().any(|overlay| {
                let TypeOverlay::Present(TypeState {
                    id,
                    kind:
                        TypeKind::Domain {
                            constraints,
                            not_null_constraint,
                            ..
                        },
                    ..
                }) = overlay
                else {
                    return false;
                };
                id.schema == schema
                    && (constraints.keys().any(|existing| existing == name)
                        || not_null_constraint.as_deref() == Some(name))
            })
    }

    fn effective_type_collation(&self, raw: &str) -> Option<(Option<String>, Option<ObjectId>)> {
        let mut element = raw.trim();
        while let Some(stripped) = element.strip_suffix("[]") {
            element = stripped.trim_end();
        }
        let parsed = crate::_internal::model::data_type::ParsedDataType::parse(
            element,
            self.builtin_types(),
        );
        if let Some(builtin) = parsed.builtin() {
            return Some(if builtin.is_collatable() {
                default_collation()
            } else {
                (None, None)
            });
        }
        let id = self.resolve_type_reference(element)?;
        let Some(TypeOverlay::Present(TypeState { kind, .. })) = self.local.types.get(&id) else {
            return None;
        };
        Some(match kind {
            TypeKind::Domain {
                collation,
                collation_id,
                ..
            }
            | TypeKind::Range {
                collation,
                collation_id,
                ..
            } => (collation.clone(), collation_id.clone()),
            TypeKind::Base { options, .. } => match options.collatable {
                Some(true) => default_collation(),
                Some(false) => (None, None),
                None => return None,
            },
            TypeKind::Enum { .. } | TypeKind::Composite { .. } | TypeKind::Multirange { .. } => {
                (None, None)
            }
        })
    }

    pub(super) fn apply_alter_domain(&mut self, alter: &AlterDomainMutation) -> MutationResult {
        match self.type_lookup(&alter.id, |kind| matches!(kind, TypeKind::Domain { .. })) {
            TypeLookup::Present => {}
            TypeLookup::WrongKind => {
                return MutationResult::conflict(format!("type '{}' is not a domain", alter.id));
            }
            TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone => {
                return MutationResult::conflict(format!("domain '{}' does not exist", alter.id));
            }
            TypeLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
        }
        let Some(action) = &alter.action else {
            return self.unresolved(EvidenceCode::UnsupportedSemantics);
        };
        match action {
            AlterDomainActionFact::AddConstraint(constraint) => {
                self.apply_add_domain_constraint(alter, constraint)
            }
            AlterDomainActionFact::DropConstraint {
                name,
                if_exists,
                cascade: _,
            } => self.apply_drop_domain_constraint(alter, name, *if_exists),
            AlterDomainActionFact::DropDefault => {
                let Some(TypeOverlay::Present(TypeState {
                    kind:
                        TypeKind::Domain {
                            default,
                            default_text,
                            ..
                        },
                    ..
                })) = self.local.types.get(&alter.id)
                else {
                    unreachable!("domain presence checked above");
                };
                if default.is_none() && default_text.is_none() {
                    return MutationResult::NoOp;
                }
                self.snapshot_type(&alter.id);
                if let Some(TypeOverlay::Present(TypeState {
                    kind:
                        TypeKind::Domain {
                            default,
                            default_text,
                            ..
                        },
                    ..
                })) = self.local.types.get_mut(&alter.id)
                {
                    *default = None;
                    *default_text = None;
                }
                MutationResult::Applied
            }
            AlterDomainActionFact::DropNotNull => {
                let Some(TypeOverlay::Present(TypeState {
                    kind: TypeKind::Domain { not_null, .. },
                    ..
                })) = self.local.types.get(&alter.id)
                else {
                    unreachable!("domain presence checked above");
                };
                if !not_null {
                    return MutationResult::NoOp;
                }
                self.snapshot_type(&alter.id);
                if let Some(TypeOverlay::Present(TypeState {
                    kind:
                        TypeKind::Domain {
                            not_null,
                            not_null_constraint,
                            ..
                        },
                    ..
                })) = self.local.types.get_mut(&alter.id)
                {
                    *not_null = false;
                    *not_null_constraint = None;
                }
                MutationResult::Applied
            }
            AlterDomainActionFact::OwnerChange(owner) => {
                let Some((owner_name, known)) = self.role_fact_identity(owner) else {
                    return self.unresolved(EvidenceCode::UnresolvedReference);
                };
                if known && self.local.roles_known && self.present_role(&owner_name).is_none() {
                    return MutationResult::conflict(format!(
                        "role '{}' does not exist",
                        owner_name
                    ));
                }
                if known && !self.local.roles_known {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
                let Some(TypeOverlay::Present(TypeState { owner, .. })) =
                    self.local.types.get(&alter.id)
                else {
                    unreachable!("domain presence checked above");
                };
                if owner.name == owner_name {
                    return MutationResult::NoOp;
                }
                self.snapshot_type(&alter.id);
                if let Some(TypeOverlay::Present(TypeState { owner, .. })) =
                    self.local.types.get_mut(&alter.id)
                {
                    *owner = ObjectId::new("", owner_name);
                }
                MutationResult::Applied
            }
            AlterDomainActionFact::RenameConstraint { old_name, new_name } => {
                self.apply_rename_domain_constraint(alter, old_name, new_name)
            }
            AlterDomainActionFact::RenameTo { .. } | AlterDomainActionFact::SetSchema { .. } => {
                self.unresolved(EvidenceCode::UnsupportedSemantics)
            }
            AlterDomainActionFact::SetDefault(default) => {
                self.apply_set_domain_default(alter, default)
            }
            AlterDomainActionFact::SetNotNull => {
                let Some(TypeOverlay::Present(TypeState {
                    kind: TypeKind::Domain { not_null, .. },
                    ..
                })) = self.local.types.get(&alter.id)
                else {
                    unreachable!("domain presence checked above");
                };
                if *not_null {
                    return MutationResult::NoOp;
                }
                if let Some(message) = self.domain_container_validation_conflict(&alter.id) {
                    return MutationResult::conflict(message);
                }
                let mut reserved = HashSet::new();
                let name = self.allocate_domain_constraint_name(
                    &alter.id,
                    None,
                    "not_null",
                    &mut reserved,
                );
                let records_constraint = self.pg_version().satisfies(|version| version >= 180_000);
                self.snapshot_type(&alter.id);
                if let Some(TypeOverlay::Present(TypeState {
                    kind:
                        TypeKind::Domain {
                            not_null,
                            not_null_constraint,
                            ..
                        },
                    ..
                })) = self.local.types.get_mut(&alter.id)
                {
                    *not_null = true;
                    *not_null_constraint = records_constraint.then_some(name);
                }
                MutationResult::Applied
            }
            AlterDomainActionFact::ValidateConstraint { name } => {
                self.apply_validate_domain_constraint(alter, name)
            }
        }
    }

    fn apply_add_domain_constraint(
        &mut self,
        alter: &AlterDomainMutation,
        constraint: &DomainConstraintFact,
    ) -> MutationResult {
        let mut reserved = HashSet::new();
        match constraint {
            DomainConstraintFact::Check(check) => {
                let name = match self.domain_constraint_name(&alter.id, check, &mut reserved) {
                    Ok(name) => name,
                    Err(result) => return result,
                };
                if self.domain_constraint_name_is_taken(&alter.id, &name) {
                    return MutationResult::conflict(format!(
                        "constraint '{}' for domain '{}' already exists",
                        name, alter.id
                    ));
                }
                if !check.not_valid
                    && let Some(message) = self.domain_container_validation_conflict(&alter.id)
                {
                    return MutationResult::conflict(message);
                }
                self.snapshot_type(&alter.id);
                if let Some(TypeOverlay::Present(TypeState {
                    kind: TypeKind::Domain { constraints, .. },
                    ..
                })) = self.local.types.get_mut(&alter.id)
                {
                    constraints.insert(
                        name.clone(),
                        DomainConstraintState {
                            name,
                            expression: Some(check.expression.clone()),
                            expression_text: Some(check.expression_text.clone()),
                            definition: check.definition.clone(),
                            validated: !check.not_valid,
                        },
                    );
                }
                MutationResult::Applied
            }
            DomainConstraintFact::NotNull { name } => {
                let Some(TypeOverlay::Present(TypeState {
                    kind: TypeKind::Domain { not_null, .. },
                    ..
                })) = self.local.types.get(&alter.id)
                else {
                    unreachable!("domain presence checked above");
                };
                if *not_null {
                    return MutationResult::NoOp;
                }
                let generated = self.allocate_domain_constraint_name(
                    &alter.id,
                    name.as_deref(),
                    "not_null",
                    &mut reserved,
                );
                if self.namespace_constraint_name_is_taken(&alter.id.schema, &generated) {
                    return MutationResult::conflict(format!(
                        "constraint '{}' for domain '{}' already exists",
                        generated, alter.id
                    ));
                }
                if let Some(message) = self.domain_container_validation_conflict(&alter.id) {
                    return MutationResult::conflict(message);
                }
                let records_constraint = self.pg_version().satisfies(|version| version >= 180_000);
                self.snapshot_type(&alter.id);
                if let Some(TypeOverlay::Present(TypeState {
                    kind:
                        TypeKind::Domain {
                            not_null,
                            not_null_constraint,
                            ..
                        },
                    ..
                })) = self.local.types.get_mut(&alter.id)
                {
                    *not_null = true;
                    *not_null_constraint = records_constraint.then_some(generated);
                }
                MutationResult::Applied
            }
            DomainConstraintFact::Null => self.unresolved(EvidenceCode::UnsupportedSemantics),
        }
    }

    fn apply_drop_domain_constraint(
        &mut self,
        alter: &AlterDomainMutation,
        name: &str,
        if_exists: bool,
    ) -> MutationResult {
        let Some(TypeOverlay::Present(TypeState {
            kind:
                TypeKind::Domain {
                    constraints,
                    not_null_constraint,
                    ..
                },
            ..
        })) = self.local.types.get(&alter.id)
        else {
            unreachable!("domain presence checked above");
        };
        let drops_not_null = not_null_constraint.as_deref() == Some(name);
        if !drops_not_null && !constraints.contains_key(name) {
            return if if_exists {
                MutationResult::NoOp
            } else {
                MutationResult::conflict(format!(
                    "constraint '{}' of domain '{}' does not exist",
                    name, alter.id
                ))
            };
        }
        self.snapshot_type(&alter.id);
        if let Some(TypeOverlay::Present(TypeState {
            kind:
                TypeKind::Domain {
                    constraints,
                    not_null,
                    not_null_constraint,
                    ..
                },
            ..
        })) = self.local.types.get_mut(&alter.id)
        {
            if drops_not_null {
                *not_null = false;
                *not_null_constraint = None;
            } else {
                constraints.remove(name);
            }
        }
        MutationResult::Applied
    }

    fn apply_rename_domain_constraint(
        &mut self,
        alter: &AlterDomainMutation,
        old_name: &str,
        new_name: &str,
    ) -> MutationResult {
        let Some(TypeOverlay::Present(TypeState {
            kind:
                TypeKind::Domain {
                    constraints,
                    not_null_constraint,
                    ..
                },
            ..
        })) = self.local.types.get(&alter.id)
        else {
            unreachable!("domain presence checked above");
        };
        let renames_not_null = not_null_constraint.as_deref() == Some(old_name);
        if !renames_not_null && !constraints.contains_key(old_name) {
            return MutationResult::conflict(format!(
                "constraint '{}' for domain '{}' does not exist",
                old_name, alter.id
            ));
        }
        if constraints.contains_key(new_name) || not_null_constraint.as_deref() == Some(new_name) {
            return MutationResult::conflict(format!(
                "constraint '{}' for domain '{}' already exists",
                new_name, alter.id
            ));
        }
        self.snapshot_type(&alter.id);
        if let Some(TypeOverlay::Present(TypeState {
            kind:
                TypeKind::Domain {
                    constraints,
                    not_null_constraint,
                    ..
                },
            ..
        })) = self.local.types.get_mut(&alter.id)
        {
            if renames_not_null {
                *not_null_constraint = Some(new_name.to_string());
            } else if let Some(mut constraint) = constraints.remove(old_name) {
                constraint.name = new_name.to_string();
                constraints.insert(new_name.to_string(), constraint);
            }
        }
        MutationResult::Applied
    }

    fn apply_set_domain_default(
        &mut self,
        alter: &AlterDomainMutation,
        default: &DomainDefaultFact,
    ) -> MutationResult {
        let Some(TypeOverlay::Present(TypeState {
            kind:
                TypeKind::Domain {
                    default: existing,
                    default_text,
                    ..
                },
            ..
        })) = self.local.types.get(&alter.id)
        else {
            unreachable!("domain presence checked above");
        };
        if default.is_null {
            if existing.is_none() && default_text.is_none() {
                return MutationResult::NoOp;
            }
            self.snapshot_type(&alter.id);
            if let Some(TypeOverlay::Present(TypeState {
                kind:
                    TypeKind::Domain {
                        default,
                        default_text,
                        ..
                    },
                ..
            })) = self.local.types.get_mut(&alter.id)
            {
                *default = None;
                *default_text = None;
            }
            return MutationResult::Applied;
        }
        if existing.as_ref() == Some(&default.expression)
            && default_text.as_deref() == Some(default.text.as_str())
        {
            return MutationResult::NoOp;
        }
        self.snapshot_type(&alter.id);
        if let Some(TypeOverlay::Present(TypeState {
            kind:
                TypeKind::Domain {
                    default: value,
                    default_text: text,
                    ..
                },
            ..
        })) = self.local.types.get_mut(&alter.id)
        {
            *value = Some(default.expression.clone());
            *text = Some(default.text.clone());
        }
        MutationResult::Applied
    }

    fn apply_validate_domain_constraint(
        &mut self,
        alter: &AlterDomainMutation,
        name: &str,
    ) -> MutationResult {
        let Some(TypeOverlay::Present(TypeState {
            kind:
                TypeKind::Domain {
                    constraints,
                    not_null_constraint,
                    ..
                },
            ..
        })) = self.local.types.get(&alter.id)
        else {
            unreachable!("domain presence checked above");
        };
        if not_null_constraint.as_deref() == Some(name) {
            return MutationResult::conflict(format!(
                "constraint '{}' of domain '{}' is not a check constraint",
                name, alter.id
            ));
        }
        let Some(constraint) = constraints.get(name) else {
            return MutationResult::conflict(format!(
                "constraint '{}' of domain '{}' does not exist",
                name, alter.id
            ));
        };
        if let Some(message) = self.domain_container_validation_conflict(&alter.id) {
            return MutationResult::conflict(message);
        }
        if constraint.validated {
            return MutationResult::NoOp;
        }
        self.snapshot_type(&alter.id);
        if let Some(TypeOverlay::Present(TypeState {
            kind: TypeKind::Domain { constraints, .. },
            ..
        })) = self.local.types.get_mut(&alter.id)
            && let Some(constraint) = constraints.get_mut(name)
        {
            constraint.validated = true;
        }
        MutationResult::Applied
    }

    pub(super) fn apply_drop_domain(&mut self, drop: &DropDomainMutation) -> MutationResult {
        for id in &drop.ids {
            if let Some(result) = self.extension_member_drop_conflict(
                crate::_internal::model::extension::ExtensionMemberKind::Type,
                id,
                "type",
            ) {
                return result;
            }
        }
        let mut present = Vec::new();
        for id in &drop.ids {
            match self.type_lookup(id, |kind| matches!(kind, TypeKind::Domain { .. })) {
                TypeLookup::Present => present.push(id.clone()),
                TypeLookup::WrongKind => {
                    return MutationResult::conflict(format!("type '{}' is not a domain", id));
                }
                TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone if drop.if_exists => {}
                TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone => {
                    return MutationResult::conflict(format!("domain '{}' does not exist", id));
                }
                TypeLookup::Unknown => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
            }
        }
        if present.is_empty() {
            return MutationResult::NoOp;
        }
        self.finish_type_drop(&present, drop.cascade, "domain")
    }

    pub(super) fn apply_drop_type(&mut self, drop: &DropTypeMutation) -> MutationResult {
        for id in &drop.ids {
            if let Some(result) = self.extension_member_drop_conflict(
                crate::_internal::model::extension::ExtensionMemberKind::Type,
                id,
                "type",
            ) {
                return result;
            }
        }
        let mut present = Vec::new();
        for id in &drop.ids {
            match self.type_lookup(id, |kind| !matches!(kind, TypeKind::Domain { .. })) {
                TypeLookup::Present => present.push(id.clone()),
                TypeLookup::WrongKind => {
                    return MutationResult::conflict(format!(
                        "type '{}' is a domain; use DROP DOMAIN",
                        id
                    ));
                }
                TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone if drop.if_exists => {}
                TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone => {
                    return MutationResult::conflict(format!("type '{}' does not exist", id));
                }
                TypeLookup::Unknown => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
            }
        }
        if present.is_empty() {
            return MutationResult::NoOp;
        }
        self.finish_type_drop(&present, drop.cascade, "type")
    }

    /// Complete a type-family drop whose targets are known present.
    ///
    /// Without CASCADE a dependent blocks the drop, as PostgreSQL refuses it;
    /// with CASCADE the deletion closure is applied, and the chain stays exact
    /// unless a dependency could not be enumerated.
    fn finish_type_drop(
        &mut self,
        present: &[ObjectId],
        cascade: bool,
        label: &str,
    ) -> MutationResult {
        // A scoped baseline cannot enumerate every dependent, which widens what
        // CASCADE removes. PostgreSQL still drops the object.
        if present.iter().any(|id| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Types,
            )
        }) {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        let dependent = present.iter().find(|id| self.has_type_dependents(id));
        if let Some(dependent) = dependent
            && !cascade
        {
            return MutationResult::conflict(format!(
                "{label} '{}' has dependent objects; use CASCADE",
                dependent
            ));
        }
        if cascade {
            if !self.apply_type_cascade(present) {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        } else {
            for id in present {
                self.snapshot_type(id);
                self.local.types.insert(id.clone(), TypeOverlay::Dropped);
            }
        }
        MutationResult::Applied
    }

    /// Identities whose dependents block dropping `id`: the type itself and,
    /// for a range, its multirange companion — PostgreSQL reports a companion
    /// column as a dependent of the range.
    fn type_dependent_ids(&self, id: &ObjectId) -> Vec<ObjectId> {
        let mut ids = vec![id.clone()];
        if matches!(
            self.local.types.get(id),
            Some(TypeOverlay::Present(state)) if matches!(state.kind, TypeKind::Range { .. })
        ) {
            ids.push(Self::multirange_companion_id(id));
        }
        ids
    }

    pub(super) fn has_type_dependents(&self, id: &ObjectId) -> bool {
        // Extension drops call this after seeding co_dropped_objects, so a
        // dependent member scheduled in the same statement is not external.
        let ids = self.type_dependent_ids(id);
        let matches_id = |reference: Option<&ObjectId>| {
            ids.iter()
                .any(|id| Self::type_reference_matches(reference, id))
        };
        self.local.relations.iter().any(|(relation_id, overlay)| {
            !self.co_dropped_objects.contains(relation_id)
                && matches!(overlay, RelationOverlay::Present(relation)
                    if relation.of_type.as_ref() == Some(id)
                        || relation.columns.iter().any(|column| matches_id(column.type_id.as_ref())))
        }) || self.local.functions.iter().any(|(function_id, overlay)| {
            !self.co_dropped_objects.contains(function_id)
                && matches!(overlay, FunctionOverlay::Present(function)
                    // A routine PostgreSQL created as an internal part of the
                    // type (a range constructor) is dropped with it, so it
                    // does not require CASCADE.
                    if function.internal_type_owner.as_ref() != Some(id)
                        && (function.arg_type_ids.iter().flatten().any(|type_id| matches_id(Some(type_id)))
                            || matches_id(function.return_type_id.as_ref())))
        }) || self.local.types.iter().any(|(type_id, overlay)| {
            !self.co_dropped_objects.contains(type_id)
                && matches!(overlay, TypeOverlay::Present(TypeState {
                    kind: TypeKind::Domain { base_type_id: Some(base), .. },
                    ..
                }) if matches_id(Some(base)))
        }) || self.local.types.iter().any(|(type_id, overlay)| {
            !self.co_dropped_objects.contains(type_id)
                && matches!(overlay, TypeOverlay::Present(TypeState {
                    kind: TypeKind::Composite { fields },
                    ..
                }) if fields.iter().any(|f| matches_id(f.data_type_id.as_ref())))
        }) || self.local.types.iter().any(|(type_id, overlay)| {
            !self.co_dropped_objects.contains(type_id)
                && matches!(overlay, TypeOverlay::Present(TypeState {
                    kind: TypeKind::Range { subtype_id: Some(sub_id), .. },
                    ..
                }) if matches_id(Some(sub_id)))
        }) || ids.iter().any(|blocking| {
            [blocking.clone(), Self::array_type_id(blocking)]
                .iter()
                .any(|probe| {
                    self.local.graph.views_for_type(probe).iter().any(|edge| {
                        !self.co_dropped_objects.contains(&edge.dependent)
                            && matches!(
                                self.local.relations.get(&edge.dependent),
                                Some(RelationOverlay::Present(_))
                            )
                    })
                })
        })
    }
}

fn default_collation() -> (Option<String>, Option<ObjectId>) {
    (
        Some("default".to_string()),
        Some(ObjectId::new("pg_catalog", "default")),
    )
}
