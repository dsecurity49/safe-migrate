use super::super::{AnalysisState, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::analysis::facts::{
    AlterDomainActionFact, DomainCheckFact, DomainConstraintFact, DomainDefaultFact,
};
use crate::_internal::analysis::mutations::{
    AlterDomainMutation, CreateDomainMutation, DropDomainMutation, DropTypeMutation, Rename,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::builtin_type::BuiltinTypeCatalogue;
use crate::_internal::model::data_type::{ParsedDataType, TypeIdentity};
use crate::_internal::model::function::FunctionOverlay;
use crate::_internal::model::types::{
    BaseTypeLength, BaseTypeOptions, DomainConstraintState, TypeKind, TypeOverlay, TypeState,
};
use std::collections::{BTreeMap, HashSet};

type TypeLookup = ObjectLookup;

impl AnalysisState {
    pub(in crate::_internal::analysis::state) fn apply_create_domain(
        &mut self,
        create: &CreateDomainMutation,
    ) -> MutationResult {
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
        if let Some(default) = &create.default {
            self.taint_unproven_domain_default(&create.base_type, default);
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

    /// Resolves a type's effective collation through arrays and user types.
    /// `Some((None, None))` means non-collatable; `None` means unknown.
    pub(in crate::_internal::analysis::state) fn effective_type_collation(
        &self,
        raw: &str,
    ) -> Option<(Option<String>, Option<ObjectId>)> {
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
            } => (collation.clone(), collation_id.clone()),
            TypeKind::Base { options, .. } => match options.collatable {
                Some(true) => default_collation(),
                Some(false) => (None, None),
                None => return None,
            },
            TypeKind::Range { .. }
            | TypeKind::Enum { .. }
            | TypeKind::Composite { .. }
            | TypeKind::Multirange { .. } => (None, None),
        })
    }

    /// Validates an explicit composite-field collation or inherits the data
    /// type's collation; unknown inheritance taints the statement.
    pub(in crate::_internal::analysis::state) fn resolve_composite_field_collation(
        &mut self,
        data_type: &str,
        explicit: Option<&str>,
    ) -> Result<(Option<String>, Option<ObjectId>), MutationResult> {
        let inherited = self.effective_type_collation(data_type);
        match explicit {
            Some(written) => {
                if matches!(inherited, Some((None, None))) {
                    return Err(MutationResult::conflict(format!(
                        "collation specified for non-collatable type '{data_type}'"
                    )));
                }
                let w = if let Some((schema, name)) = written.split_once('.') {
                    crate::_internal::model::index::WrittenName {
                        schema: Some(schema.to_string()),
                        name: name.to_string(),
                    }
                } else {
                    crate::_internal::model::index::WrittenName {
                        schema: None,
                        name: written.to_string(),
                    }
                };
                match self.local.collations.resolve(&w, &self.local.search_path) {
                    Some(resolved) => Ok((
                        Some(resolved.name.clone()),
                        Some(ObjectId::new(resolved.schema, resolved.name)),
                    )),
                    None => Err(self.unresolved(EvidenceCode::UnresolvedReference)),
                }
            }
            None => match inherited {
                Some(pair) => Ok(pair),
                None => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Statement);
                    Ok((None, None))
                }
            },
        }
    }

    pub(in crate::_internal::analysis::state) fn apply_rename_domain(
        &mut self,
        rename: &Rename,
    ) -> MutationResult {
        match self.type_lookup(&rename.old_id, |kind| {
            matches!(kind, TypeKind::Domain { .. })
        }) {
            TypeLookup::Present => self.apply_rename_type(rename),
            TypeLookup::WrongKind => {
                MutationResult::conflict(format!("type '{}' is not a domain", rename.old_id))
            }
            TypeLookup::AuthoritativelyAbsent | TypeLookup::Tombstone => {
                MutationResult::conflict(format!("domain '{}' does not exist", rename.old_id))
            }
            TypeLookup::Unknown => self.unresolved(EvidenceCode::UnknownObjectState),
        }
    }

    /// Apply an ALTER DOMAIN action after checking the target is a domain.
    pub(in crate::_internal::analysis::state) fn apply_alter_domain(
        &mut self,
        alter: &AlterDomainMutation,
    ) -> MutationResult {
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
                self.taint_domain_validation_if_data_scanned(&alter.id);
                let mut reserved = HashSet::new();
                let name = self.allocate_domain_constraint_name(
                    &alter.id,
                    None,
                    "not_null",
                    &mut reserved,
                );
                // PG18 records domain NOT NULL in pg_constraint; older versions keep only the flag.
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

    fn taint_domain_validation_if_data_scanned(&mut self, domain: &ObjectId) {
        if !self.relations_using_domain(domain).is_empty() {
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
        }
    }

    /// Add a domain constraint, allocating a name when omitted.
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
                if !check.not_valid {
                    self.taint_domain_validation_if_data_scanned(&alter.id);
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
                let name_taken = if name.is_some() {
                    self.domain_constraint_name_is_taken(&alter.id, &generated)
                } else {
                    self.namespace_constraint_name_is_taken(&alter.id.schema, &generated)
                };
                if name_taken {
                    return MutationResult::conflict(format!(
                        "constraint '{}' for domain '{}' already exists",
                        generated, alter.id
                    ));
                }
                if let Some(message) = self.domain_container_validation_conflict(&alter.id) {
                    return MutationResult::conflict(message);
                }
                self.taint_domain_validation_if_data_scanned(&alter.id);
                // PG18 stores NOT NULL as a domain constraint, as with SET NOT NULL.
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

    /// Drops a domain check constraint or the synthetic NOT NULL constraint,
    /// honoring `IF EXISTS`.
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

    /// Renames a check constraint or the synthetic NOT NULL constraint,
    /// rejecting collisions.
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

    fn taint_unproven_domain_default(&mut self, base_type: &str, default: &DomainDefaultFact) {
        if default.is_null {
            return;
        }
        if !domain_default_is_provably_coercible(
            base_type,
            &default.expression,
            self.builtin_types(),
        ) {
            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Statement);
        }
    }

    /// Sets or clears a domain default, snapshotting only on change and
    /// tainting when coercion cannot be proven.
    fn apply_set_domain_default(
        &mut self,
        alter: &AlterDomainMutation,
        default: &DomainDefaultFact,
    ) -> MutationResult {
        let Some(TypeOverlay::Present(TypeState {
            kind:
                TypeKind::Domain {
                    base_type,
                    default: existing,
                    default_text,
                    ..
                },
            ..
        })) = self.local.types.get(&alter.id)
        else {
            unreachable!("domain presence checked above");
        };
        let base_type = base_type.clone();
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
        self.taint_unproven_domain_default(&base_type, default);
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

    /// Marks a check constraint validated; the synthetic NOT NULL constraint
    /// cannot be validated this way.
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
        self.taint_domain_validation_if_data_scanned(&alter.id);
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

    pub(in crate::_internal::analysis::state) fn apply_drop_domain(
        &mut self,
        drop: &DropDomainMutation,
    ) -> MutationResult {
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

    pub(in crate::_internal::analysis::state) fn apply_drop_type(
        &mut self,
        drop: &DropTypeMutation,
    ) -> MutationResult {
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
    pub(in crate::_internal::analysis::state) fn finish_type_drop(
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
        let saved_co_dropped = self.co_dropped_objects.clone();
        self.co_dropped_objects.extend(present.iter().cloned());
        let dependent = present
            .iter()
            .find(|id| self.has_type_dependents(id))
            .cloned();
        self.co_dropped_objects = saved_co_dropped;
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
            let mut implicit = present.to_vec();
            for id in present {
                if let Some(TypeOverlay::Present(state)) = self.local.types.get(id)
                    && let TypeKind::Range { multirange, .. } = &state.kind
                {
                    let companion = multirange
                        .clone()
                        .unwrap_or_else(|| Self::multirange_companion_id(id));
                    if self.type_is_present(&companion) {
                        implicit.push(companion);
                    }
                }
            }
            let implicit_set: HashSet<ObjectId> = implicit.iter().cloned().collect();
            for routine in self.routine_cascade_victims(&implicit_set) {
                self.drop_routine_with_edges(&routine);
            }
            for id in implicit {
                self.snapshot_type(&id);
                self.local.types.insert(id, TypeOverlay::Dropped);
            }
        }
        MutationResult::Applied
    }

    /// Identities whose dependents block dropping `id`: the type itself and,
    /// for a range, its multirange companion — PostgreSQL reports a companion
    /// column as a dependent of the range.
    pub(in crate::_internal::analysis::state) fn type_dependent_ids(
        &self,
        id: &ObjectId,
    ) -> Vec<ObjectId> {
        let mut ids = vec![id.clone()];
        if let Some(TypeOverlay::Present(state)) = self.local.types.get(id)
            && let TypeKind::Range { multirange, .. } = &state.kind
        {
            ids.push(
                multirange
                    .clone()
                    .unwrap_or_else(|| Self::multirange_companion_id(id)),
            );
        }
        ids
    }

    /// Whether any local relation, routine, or type still references `id`.
    /// Objects scheduled for the same drop do not count as external dependents.
    pub(in crate::_internal::analysis::state) fn has_type_dependents(&self, id: &ObjectId) -> bool {
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
                    // type (a range or multirange constructor) is dropped with
                    // the type it belongs to, so it does not require CASCADE.
                    if !function.internal_type_owner.as_ref().is_some_and(|owner| {
                        ids.iter()
                            .any(|id| Self::type_reference_matches(Some(owner), id))
                    })
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
                && type_id != id
                && matches!(overlay, TypeOverlay::Present(TypeState {
                    kind: TypeKind::Range { multirange: Some(companion), .. },
                    ..
                }) if matches_id(Some(companion)))
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
                    }) || self.local.graph.routines_for_type(probe).iter().any(|edge| {
                        !self.co_dropped_objects.contains(&edge.dependent)
                            && matches!(
                                self.local.functions.get(&edge.dependent),
                                Some(FunctionOverlay::Present(_))
                            )
                    }) || self.local.graph.statistics_for_type(probe).iter().any(|edge| {
                        !self.co_dropped_objects.contains(&edge.dependent)
                            && self.extended_statistics_is_present(&edge.dependent)
                    })
                })
        }) || {
            let group_names: Vec<String> = ids.iter().map(ToString::to_string).collect();
            ids.iter().any(|blocking| {
                self.local.casts.has_external_casts_for_type(
                    &blocking.to_string(),
                    &self.co_dropped_objects,
                    &group_names,
                )
            })
        }
    }
}

pub(in crate::_internal::analysis::state) fn base_type_option_conflict(
    options: &BaseTypeOptions,
) -> Option<MutationResult> {
    options
        .storage
        .as_deref()
        .and_then(|storage| base_type_storage_conflict(storage, options.internallength.as_ref()))
}

pub(in crate::_internal::analysis::state) fn base_type_storage_conflict(
    storage: &str,
    internallength: Option<&BaseTypeLength>,
) -> Option<MutationResult> {
    if !matches!(
        storage.to_ascii_lowercase().as_str(),
        "plain" | "external" | "extended" | "main"
    ) {
        return Some(MutationResult::conflict(format!(
            "storage \"{storage}\" not recognized"
        )));
    }
    if !storage.eq_ignore_ascii_case("plain")
        && matches!(internallength, Some(BaseTypeLength::Fixed(_)))
    {
        return Some(MutationResult::conflict(
            "fixed-size types must have storage PLAIN",
        ));
    }
    None
}

/// Options PostgreSQL only accepts at creation. `ALTER TYPE ... SET` may
/// change the I/O support routines and storage, not the type's physical shape.
pub(in crate::_internal::analysis::state) fn immutable_base_type_option(
    options: &BaseTypeOptions,
) -> Option<&'static str> {
    if options.input.is_some() {
        return Some("input");
    }
    if options.output.is_some() {
        return Some("output");
    }
    if options.internallength.is_some() {
        return Some("internallength");
    }
    if options.passed_by_value.is_some() {
        return Some("passedbyvalue");
    }
    if options.alignment.is_some() {
        return Some("alignment");
    }
    if options.like.is_some() {
        return Some("like");
    }
    if options.category.is_some() {
        return Some("category");
    }
    if options.preferred.is_some() {
        return Some("preferred");
    }
    if options.default.is_some() {
        return Some("default");
    }
    if options.element.is_some() {
        return Some("element");
    }
    if options.delimiter.is_some() {
        return Some("delimiter");
    }
    if options.collatable.is_some() {
        return Some("collatable");
    }
    None
}

pub(in crate::_internal::analysis::state) fn default_collation()
-> (Option<String>, Option<ObjectId>) {
    (
        Some("default".to_string()),
        Some(ObjectId::new("pg_catalog", "default")),
    )
}

fn domain_default_is_provably_coercible(
    base_type: &str,
    expression: &ExprIr,
    catalogue: &BuiltinTypeCatalogue,
) -> bool {
    match expression {
        ExprIr::Cast { target_type, .. } => {
            let base = ParsedDataType::parse(base_type, catalogue);
            let target = ParsedDataType::parse(target_type, catalogue);
            TypeIdentity::from_syntax(&base) == TypeIdentity::from_syntax(&target)
        }
        ExprIr::UnaryOp { op, expr } if op == "+" || op == "-" => match expr.as_ref() {
            ExprIr::Literal(literal) => {
                literal_is_provably_assignable(base_type, &format!("{op}{literal}"), catalogue)
            }
            _ => false,
        },
        ExprIr::Literal(literal) => literal_is_provably_assignable(base_type, literal, catalogue),
        _ => false,
    }
}

/// Conservative literal-to-builtin assignability check; `false` means not
/// proven, not necessarily invalid.
fn literal_is_provably_assignable(
    base_type: &str,
    literal: &str,
    catalogue: &BuiltinTypeCatalogue,
) -> bool {
    let base = ParsedDataType::parse(base_type, catalogue);
    if base.array_dimensions > 0 {
        return false;
    }
    let literal = literal.trim();
    let Some(builtin) = base.builtin() else {
        return false;
    };
    let name = builtin.typname.as_str();
    if matches!(name, "text" | "varchar" | "bpchar" | "name") {
        return true;
    }
    if is_string_literal(literal) {
        return false;
    }
    if literal.eq_ignore_ascii_case("true") || literal.eq_ignore_ascii_case("false") {
        return name == "bool";
    }
    if let Ok(value) = literal.parse::<i128>() {
        return match name {
            "int2" => i16::try_from(value).is_ok(),
            "int4" => i32::try_from(value).is_ok(),
            "int8" => i64::try_from(value).is_ok(),
            "oid" => u32::try_from(value).is_ok(),
            "numeric" => true,
            "float4" => literal.parse::<f32>().is_ok_and(f32::is_finite),
            "float8" => literal.parse::<f64>().is_ok_and(f64::is_finite),
            _ => false,
        };
    }
    match name {
        "float4" => literal.parse::<f32>().is_ok_and(f32::is_finite),
        "float8" => literal.parse::<f64>().is_ok_and(f64::is_finite),
        _ => false,
    }
}

fn is_string_literal(literal: &str) -> bool {
    if literal.starts_with('\'') {
        return true;
    }
    if let Some(tag) = literal.strip_prefix('$') {
        return tag.contains('$');
    }
    let lower = literal.to_ascii_lowercase();
    lower.starts_with("e'") || lower.starts_with("u&'") || lower.starts_with("n'")
}
