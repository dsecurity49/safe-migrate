use self::domain::{
    base_type_option_conflict, base_type_storage_conflict, immutable_base_type_option,
};
use super::{AnalysisState, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::graph::{
    DependencyEdge, DependencyGraph, DependencyKind, GraphRenamePlan,
};
use crate::_internal::analysis::mutations::{
    AlterTypeActionMutation, AlterTypeMutation, CreateTypeMutation, Rename,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::data_type::ParsedDataType;
use crate::_internal::model::extension::{ExtensionMemberKind, ExtensionOverlay};
use crate::_internal::model::function::FunctionOverlay;
use crate::_internal::model::types::{BaseTypeOptions, TypeKind, TypeOverlay, TypeState};
use std::collections::{BTreeSet, HashSet};

type TypeLookup = ObjectLookup;

#[derive(Default)]
struct TypeKindRemap {
    domain_base: Option<ObjectId>,
    composite_fields: Vec<(usize, ObjectId)>,
    range_subtype: Option<ObjectId>,
    range_multirange: bool,
    multirange_range: bool,
    base_element: bool,
}

impl TypeKindRemap {
    fn is_empty(&self) -> bool {
        self.domain_base.is_none()
            && self.composite_fields.is_empty()
            && self.range_subtype.is_none()
            && !self.range_multirange
            && !self.multirange_range
            && !self.base_element
    }

    /// Applies a cached rename remap to a type definition, rewriting references
    /// and schema-qualified spellings.
    fn apply(self, kind: &mut TypeKind, rename: &Rename) {
        let schema_changed = rename.old_id.schema != rename.new_id.schema;
        match kind {
            TypeKind::Domain {
                base_type,
                base_type_id,
                ..
            } => {
                if let Some(new_id) = self.domain_base {
                    *base_type = AnalysisState::remapped_type_display(
                        base_type,
                        &rename.new_id,
                        schema_changed,
                    );
                    *base_type_id = Some(new_id);
                }
            }
            TypeKind::Composite { fields } => {
                for (index, new_id) in self.composite_fields {
                    let field = &mut fields[index];
                    field.data_type = AnalysisState::remapped_type_display(
                        &field.data_type,
                        &rename.new_id,
                        schema_changed,
                    );
                    field.data_type_id = Some(new_id);
                }
            }
            TypeKind::Range {
                subtype,
                subtype_id,
                multirange,
                ..
            } => {
                if let Some(new_id) = self.range_subtype {
                    if let Some(subtype) = subtype {
                        *subtype = AnalysisState::remapped_type_display(
                            subtype,
                            &rename.new_id,
                            schema_changed,
                        );
                    }
                    *subtype_id = Some(new_id);
                }
                if self.range_multirange {
                    *multirange = Some(rename.new_id.clone());
                }
            }
            TypeKind::Multirange { range } => {
                if self.multirange_range {
                    *range = Some(rename.new_id.clone());
                }
            }
            TypeKind::Base { options, .. } => {
                if self.base_element {
                    options.element = Some(rename.new_id.name.clone());
                }
            }
            TypeKind::Enum { .. } => {}
        }
    }
}

impl AnalysisState {
    /// Reject a type the server would refuse to create: a duplicate enum
    /// label, or a component type that names nothing resolvable.
    pub(super) fn check_created_type(&mut self, kind: &TypeKind) -> Result<(), MutationResult> {
        if let TypeKind::Base { options, .. } = kind
            && let Some(result) = base_type_option_conflict(options)
        {
            return Err(result);
        }
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
    pub(super) fn renamed_type_id(current: &ObjectId, rename: &Rename) -> Option<ObjectId> {
        if current == &rename.old_id {
            return Some(rename.new_id.clone());
        }
        (current == &Self::array_type_id(&rename.old_id))
            .then(|| Self::array_type_id(&rename.new_id))
    }

    /// Precomputes references to the renamed type inside a type definition,
    /// including its array form.
    fn type_kind_remap(kind: &TypeKind, rename: &Rename) -> TypeKindRemap {
        let mut remap = TypeKindRemap::default();
        match kind {
            TypeKind::Domain { base_type_id, .. } => {
                remap.domain_base = base_type_id
                    .as_ref()
                    .and_then(|id| Self::renamed_type_id(id, rename));
            }
            TypeKind::Composite { fields } => {
                remap.composite_fields = fields
                    .iter()
                    .enumerate()
                    .filter_map(|(index, field)| {
                        field
                            .data_type_id
                            .as_ref()
                            .and_then(|id| Self::renamed_type_id(id, rename))
                            .map(|new_id| (index, new_id))
                    })
                    .collect();
            }
            TypeKind::Range {
                subtype_id,
                multirange,
                ..
            } => {
                remap.range_subtype = subtype_id
                    .as_ref()
                    .and_then(|id| Self::renamed_type_id(id, rename));
                remap.range_multirange = multirange.as_ref() == Some(&rename.old_id);
            }
            TypeKind::Multirange { range } => {
                remap.multirange_range = range.as_ref() == Some(&rename.old_id);
            }
            TypeKind::Base { options, .. } => {
                remap.base_element = options.element.as_ref().is_some_and(|element| {
                    element == &rename.old_id.name || element == &rename.old_id.to_string()
                });
            }
            TypeKind::Enum { .. } => {}
        }
        remap
    }

    pub(super) fn type_kind_references_rename(kind: &TypeKind, rename: &Rename) -> bool {
        !Self::type_kind_remap(kind, rename).is_empty()
    }

    /// Create a type, completing a shell and adding its companions.
    pub(super) fn apply_create_type(&mut self, create: &CreateTypeMutation) -> MutationResult {
        if let Err(result) = self.ensure_creation_target(&create.id) {
            return result;
        }
        if let Some(TypeOverlay::Present(existing)) = self.local.types.get(&create.id) {
            match (&existing.kind, &create.kind) {
                (
                    TypeKind::Base { shell: true, .. },
                    TypeKind::Base {
                        shell: false,
                        options,
                    },
                ) => {
                    if let Some(result) = base_type_option_conflict(options) {
                        return result;
                    }
                    let mut options = options.clone();
                    self.canonicalize_base_type_options(&mut options);
                    self.snapshot_type(&create.id);
                    if let Some(TypeOverlay::Present(target)) = self.local.types.get_mut(&create.id)
                    {
                        target.kind = TypeKind::Base {
                            shell: false,
                            options,
                        };
                    }
                    return MutationResult::Applied;
                }
                _ => {
                    return MutationResult::conflict(format!(
                        "type '{}' already exists",
                        create.id
                    ));
                }
            }
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::conflict(format!("type '{}' already exists", create.id));
        }
        if let Err(result) = self.check_created_type(&create.kind) {
            return result;
        }

        let mut kind = create.kind.clone();
        if let TypeKind::Base {
            shell: false,
            options,
        } = &mut kind
        {
            self.canonicalize_base_type_options(options);
        }
        let mut companion_id = None;

        if let TypeKind::Range {
            canonical,
            canonical_id,
            subtype,
            subtype_id,
            subtype_diff,
            subtype_diff_id,
            ..
        } = &mut kind
        {
            let subtype_signature = subtype_id
                .clone()
                .map(|id| id.to_string())
                .or_else(|| subtype.clone());
            if let Some(canonical) = canonical.as_deref() {
                *canonical_id = self.resolve_internal_routine_id(canonical, &create.id.to_string());
            }
            if let (Some(subtype_diff), Some(signature)) =
                (subtype_diff.as_deref(), subtype_signature)
            {
                *subtype_diff_id = self
                    .resolve_internal_routine_id(subtype_diff, &format!("{signature},{signature}"));
            }
        }

        if let TypeKind::Composite { fields } = &mut kind {
            for field in fields {
                let (collation, collation_id) = match self
                    .resolve_composite_field_collation(&field.data_type, field.collation.as_deref())
                {
                    Ok(resolved) => resolved,
                    Err(result) => return result,
                };
                field.collation = collation;
                field.collation_id = collation_id;
            }
        }

        if let TypeKind::Range {
            ref subtype,
            ref subtype_id,
            ref mut multirange,
            ..
        } = kind
        {
            let multirange_id = create
                .multirange_name
                .clone()
                .unwrap_or_else(|| Self::multirange_companion_id(&create.id));

            if self.relation_namespace_is_taken(&multirange_id) {
                return MutationResult::conflict(format!(
                    "type '{}' already exists",
                    multirange_id
                ));
            }
            if let Err(result) = self.ensure_creation_target(&multirange_id) {
                return result;
            }

            *multirange = Some(multirange_id.clone());
            companion_id = Some(multirange_id);

            // Register constructors for range and multirange.
            let subtype_name = subtype.as_deref().unwrap_or("anyelement");
            let range_schema = &create.id.schema;
            let range_name = &create.id.name;

            let make_constructor = |id: ObjectId,
                                    arg_types: Vec<String>,
                                    arg_type_ids: Vec<Option<ObjectId>>,
                                    ret_type: String,
                                    ret_id: Option<ObjectId>,
                                    owner: ObjectId| {
                crate::_internal::model::function::FunctionState {
                    id,
                    internal_type_owner: Some(owner),
                    routine_kind: crate::_internal::model::function::RoutineKind::Function,
                    arg_types,
                    arg_type_ids,
                    return_type: ret_type,
                    return_type_id: ret_id,
                    returns_set: false,
                    parameters: Vec::new(),
                    default_count: 0,
                    volatility: crate::_internal::model::function::Volatility::Immutable,
                    language: "internal".to_string(),
                    security: crate::_internal::model::function::SecurityMode::Invoker,
                    aggregate: None,
                }
            };

            // Range constructors: range(subtype, subtype), range(subtype, subtype, text)
            let r_ctor2_id = ObjectId::new(
                range_schema,
                format!("{range_name}({subtype_name},{subtype_name})"),
            );
            let r_ctor2 = make_constructor(
                r_ctor2_id.clone(),
                vec![subtype_name.to_string(), subtype_name.to_string()],
                vec![subtype_id.clone(), subtype_id.clone()],
                create.id.to_string(),
                Some(create.id.clone()),
                create.id.clone(),
            );
            self.snapshot_function(&r_ctor2_id);
            self.local
                .functions
                .insert(r_ctor2_id, FunctionOverlay::Present(r_ctor2));

            let r_ctor3_id = ObjectId::new(
                range_schema,
                format!("{range_name}({subtype_name},{subtype_name},text)"),
            );
            let r_ctor3 = make_constructor(
                r_ctor3_id.clone(),
                vec![
                    subtype_name.to_string(),
                    subtype_name.to_string(),
                    "text".to_string(),
                ],
                vec![
                    subtype_id.clone(),
                    subtype_id.clone(),
                    Some(ObjectId::new("pg_catalog", "text")),
                ],
                create.id.to_string(),
                Some(create.id.clone()),
                create.id.clone(),
            );
            self.snapshot_function(&r_ctor3_id);
            self.local
                .functions
                .insert(r_ctor3_id, FunctionOverlay::Present(r_ctor3));

            // Multirange constructors in range's schema: mr(), mr(range), mr(range[])
            let mr_id = companion_id.as_ref().unwrap();
            let mr_name = &mr_id.name;

            let mr_ctor0_id = ObjectId::new(range_schema, format!("{mr_name}()"));
            let mr_ctor0 = make_constructor(
                mr_ctor0_id.clone(),
                Vec::new(),
                Vec::new(),
                mr_id.to_string(),
                Some(mr_id.clone()),
                mr_id.clone(),
            );
            self.snapshot_function(&mr_ctor0_id);
            self.local
                .functions
                .insert(mr_ctor0_id, FunctionOverlay::Present(mr_ctor0));

            let mr_ctor1_id = ObjectId::new(range_schema, format!("{mr_name}({})", create.id.name));
            let mr_ctor1 = make_constructor(
                mr_ctor1_id.clone(),
                vec![create.id.name.clone()],
                vec![Some(create.id.clone())],
                mr_id.to_string(),
                Some(mr_id.clone()),
                mr_id.clone(),
            );
            self.snapshot_function(&mr_ctor1_id);
            self.local
                .functions
                .insert(mr_ctor1_id, FunctionOverlay::Present(mr_ctor1));

            let mr_ctor2_id = ObjectId::new(
                range_schema,
                format!("{mr_name}(VARIADIC {}[])", create.id.name),
            );
            let mr_ctor2 = make_constructor(
                mr_ctor2_id.clone(),
                vec![format!("{}[]", create.id.name)],
                vec![Some(Self::array_type_id(&create.id))],
                mr_id.to_string(),
                Some(mr_id.clone()),
                mr_id.clone(),
            );
            self.snapshot_function(&mr_ctor2_id);
            self.local
                .functions
                .insert(mr_ctor2_id, FunctionOverlay::Present(mr_ctor2));
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
                kind,
            }),
        );

        if let Some(multirange_id) = companion_id {
            self.snapshot_type(&multirange_id);
            self.local.generation_counter += 1;
            let mr_gen = self.local.generation_counter;
            self.local.types.insert(
                multirange_id.clone(),
                TypeOverlay::Present(TypeState {
                    id: multirange_id,
                    generation: mr_gen,
                    owner: ObjectId::new("", self.local.current_role.clone()),
                    kind: TypeKind::Multirange {
                        range: Some(create.id.clone()),
                    },
                }),
            );
        }

        MutationResult::Applied
    }

    /// Rename a type, its array form, and every reference that names it.
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
        let mut affected_functions: BTreeSet<ObjectId> = BTreeSet::new();
        for (function_id, overlay) in &self.local.functions {
            let FunctionOverlay::Present(function) = overlay else {
                continue;
            };
            let schema_changed = rename.old_id.schema != rename.new_id.schema;
            let args_changed = function.arg_type_ids.iter().any(|id| {
                id.as_ref()
                    .and_then(|id| Self::renamed_type_id(id, rename))
                    .is_some()
            });
            let return_changed = function
                .return_type_id
                .as_ref()
                .and_then(|id| Self::renamed_type_id(id, rename))
                .is_some();
            if function
                .internal_type_owner
                .as_ref()
                .and_then(|owner| Self::renamed_type_id(owner, rename))
                .is_some()
            {
                affected_functions.insert(function_id.clone());
            }
            if !args_changed && !return_changed {
                continue;
            }
            // Build only the pieces that actually change; an unrelated
            // routine must not clone its whole signature during a type rename.
            let new_arg_types = args_changed.then(|| {
                function
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
                            Self::remapped_type_display(raw, &rename.new_id, schema_changed)
                        } else {
                            raw.clone()
                        }
                    })
                    .collect::<Vec<_>>()
            });
            let new_return_type = return_changed.then(|| {
                Self::remapped_type_display(&function.return_type, &rename.new_id, schema_changed)
            });
            let effective_args = new_arg_types.as_deref().unwrap_or(&function.arg_types);
            let base_name = function_id
                .name
                .split_once('(')
                .map(|(name, _)| name)
                .unwrap_or(&function_id.name);
            let mut new_function_id = ObjectId::new(
                &function_id.schema,
                format!("{}({})", base_name, effective_args.join(",")),
            );
            new_function_id.inferred_schema = function_id.inferred_schema;
            let id_changed = new_function_id != *function_id;
            let args_differ = new_arg_types
                .as_ref()
                .is_some_and(|types| types != &function.arg_types);
            let return_differs = new_return_type
                .as_ref()
                .is_some_and(|return_type| return_type != &function.return_type);
            if !id_changed && !args_differ && !return_differs {
                continue;
            }
            affected_functions.insert(function_id.clone());
            affected_functions.insert(new_function_id.clone());
            remapped_functions.push((
                function_id.clone(),
                new_function_id,
                new_arg_types,
                new_return_type,
            ));
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
        // Keep graph edge insertion independent of hash-map iteration order.
        remapped_functions.sort_by(|left, right| left.0.cmp(&right.0));

        let mut affected_relations: Vec<ObjectId> = self
            .local
            .relations
            .iter()
            .filter_map(|(id, overlay)| {
                let RelationOverlay::Present(relation) = overlay else {
                    return None;
                };
                let relation_matches = relation.columns.iter().any(|column| {
                    column
                        .type_id
                        .as_ref()
                        .and_then(|type_id| Self::renamed_type_id(type_id, rename))
                        .is_some()
                }) || relation
                    .of_type
                    .as_ref()
                    .and_then(|type_id| Self::renamed_type_id(type_id, rename))
                    .is_some();
                relation_matches.then_some(id.clone())
            })
            .collect();
        affected_relations.sort();
        let mut affected_types: Vec<ObjectId> = self
            .local
            .types
            .iter()
            .filter_map(|(id, overlay)| {
                if id == &rename.old_id || id == &rename.new_id {
                    return None;
                }
                let TypeOverlay::Present(state) = overlay else {
                    return None;
                };
                let references_rename = Self::type_kind_references_rename(&state.kind, rename)
                    || match &state.kind {
                        TypeKind::Range {
                            canonical_id,
                            subtype_diff_id,
                            ..
                        } => remapped_functions.iter().any(|(old_func, new_func, _, _)| {
                            old_func != new_func
                                && (canonical_id.as_ref() == Some(old_func)
                                    || subtype_diff_id.as_ref() == Some(old_func))
                        }),
                        _ => false,
                    };
                references_rename.then_some(id.clone())
            })
            .collect();
        affected_types.sort();
        let mut affected_extensions: Vec<String> = self
            .local
            .extensions
            .iter()
            .filter_map(|(name, overlay)| {
                let ExtensionOverlay::Present(extension) = overlay else {
                    return None;
                };
                extension
                    .members
                    .iter()
                    .any(|member| {
                        member.kind == ExtensionMemberKind::Type && member.id == rename.old_id
                    })
                    .then(|| name.clone())
            })
            .collect();
        affected_extensions.sort();

        // A type rename touches the type, its dependents, and the graph; the
        // length marker covers appended rename edges and the plan records the
        // edges it actually rewrites.
        self.snapshot_graph();
        self.snapshot_type(&rename.old_id);
        self.snapshot_type(&rename.new_id);
        for id in &affected_types {
            self.snapshot_type(id);
        }
        for id in &affected_relations {
            self.snapshot_relation(id);
        }
        for id in &affected_functions {
            self.snapshot_function(id);
        }
        for name in &affected_extensions {
            self.snapshot_extension(name);
        }
        let mut graph_plan = GraphRenamePlan::default();
        graph_plan
            .types
            .insert(rename.old_id.clone(), rename.new_id.clone());
        graph_plan.types.insert(
            Self::array_type_id(&rename.old_id),
            Self::array_type_id(&rename.new_id),
        );
        for (old_id, new_id, _, _) in &remapped_functions {
            if old_id != new_id {
                graph_plan.routines.insert(old_id.clone(), new_id.clone());
            }
        }
        if let Some(delta) = self.local.graph.apply_rename_plan_recorded(&graph_plan) {
            self.record_graph_delta(delta);
        }
        if self
            .local
            .casts
            .has_casts_for_type(&rename.old_id.to_string())
            || remapped_functions
                .iter()
                .any(|(old_fn, _, _, _)| !self.local.casts.casts_using_function(old_fn).is_empty())
        {
            self.snapshot_casts();
            self.local
                .casts
                .rewire_type_name(&rename.old_id.to_string(), &rename.new_id.to_string());
            for (old_fn, new_fn, _, _) in &remapped_functions {
                if old_fn != new_fn {
                    self.local.casts.rewire_function_id(old_fn, new_fn);
                }
            }
        }
        if let Some(TypeOverlay::Present(mut state)) = self.local.types.remove(&rename.old_id) {
            state.id = rename.new_id.clone();
            self.local
                .types
                .insert(rename.new_id.clone(), TypeOverlay::Present(state));
        }
        for id in &affected_relations {
            let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(id) else {
                continue;
            };
            if let Some(remapped) = relation
                .of_type
                .as_ref()
                .and_then(|type_id| Self::renamed_type_id(type_id, rename))
            {
                relation.of_type = Some(remapped);
            }
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
        for id in &affected_types {
            let Some(TypeOverlay::Present(state)) = self.local.types.get_mut(id) else {
                continue;
            };
            let remap = Self::type_kind_remap(&state.kind, rename);
            remap.apply(&mut state.kind, rename);
        }
        for id in &affected_functions {
            if let Some(FunctionOverlay::Present(function)) = self.local.functions.get_mut(id)
                && let Some(owner) = function.internal_type_owner.as_mut()
                && let Some(remapped) = Self::renamed_type_id(owner, rename)
            {
                *owner = remapped;
            }
        }
        for (old_id, new_id, arg_types, return_type) in remapped_functions {
            if let Some(FunctionOverlay::Present(mut function)) =
                self.local.functions.remove(&old_id)
            {
                function.id = new_id.clone();
                if let Some(arg_types) = arg_types {
                    function.arg_types = arg_types;
                }
                for type_id in &mut function.arg_type_ids {
                    if let Some(remapped) = type_id
                        .as_ref()
                        .and_then(|id| Self::renamed_type_id(id, rename))
                    {
                        *type_id = Some(remapped);
                    }
                }
                if let Some(return_type) = return_type {
                    function.return_type = return_type;
                }
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
                    self.local.graph.add_edge(DependencyEdge::new(
                        old_id.clone(),
                        new_id.clone(),
                        DependencyKind::RenameTo,
                    ));
                    self.remap_range_routine_reference(&old_id, &new_id);
                }
            }
        }

        // Remap extension membership when a type is renamed or moved across schemas.
        for name in &affected_extensions {
            let Some(crate::_internal::model::extension::ExtensionOverlay::Present(ext)) =
                self.local.extensions.get_mut(name)
            else {
                continue;
            };
            let mut updated_members = std::collections::BTreeSet::new();
            for mut m in ext.members.iter().cloned() {
                if m.kind == crate::_internal::model::extension::ExtensionMemberKind::Type
                    && m.id == rename.old_id
                {
                    m.id = rename.new_id.clone();
                }
                updated_members.insert(m);
            }
            ext.members = updated_members;
        }

        MutationResult::Applied
    }

    /// Apply an ALTER TYPE action after checking the type kind.
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
        if matches!(
            &alter.action,
            AlterTypeActionMutation::AddValue { .. } | AlterTypeActionMutation::RenameValue { .. }
        ) && !matches!(
            self.local.types.get(&alter.id),
            Some(TypeOverlay::Present(TypeState {
                kind: TypeKind::Enum { .. },
                ..
            }))
        ) {
            return MutationResult::conflict(format!("type '{}' is not an enum", alter.id));
        }

        if matches!(
            &alter.action,
            AlterTypeActionMutation::AddAttribute { .. }
                | AlterTypeActionMutation::DropAttribute { .. }
                | AlterTypeActionMutation::AlterAttributeType { .. }
                | AlterTypeActionMutation::RenameAttribute { .. }
        ) && !matches!(
            self.local.types.get(&alter.id),
            Some(TypeOverlay::Present(TypeState {
                kind: TypeKind::Composite { .. },
                ..
            }))
        ) {
            return MutationResult::conflict(format!(
                "type '{}' is not a composite type",
                alter.id
            ));
        }

        if matches!(&alter.action, AlterTypeActionMutation::SetOptions { .. })
            && !matches!(
                self.local.types.get(&alter.id),
                Some(TypeOverlay::Present(TypeState {
                    kind: TypeKind::Base { .. },
                    ..
                }))
            )
        {
            return MutationResult::conflict(format!("type '{}' is not a base type", alter.id));
        }

        if let AlterTypeActionMutation::SetOptions { options } = &alter.action {
            let Some(TypeOverlay::Present(TypeState {
                kind:
                    TypeKind::Base {
                        shell,
                        options: current,
                    },
                ..
            })) = self.local.types.get(&alter.id)
            else {
                unreachable!("base type presence checked above");
            };
            if *shell {
                return MutationResult::conflict(format!("type '{}' is only a shell", alter.id));
            }
            if let Some(attribute) = immutable_base_type_option(options) {
                return MutationResult::conflict(format!(
                    "type attribute \"{attribute}\" cannot be changed"
                ));
            }
            if let Some(storage) = options.storage.as_deref()
                && let Some(result) =
                    base_type_storage_conflict(storage, current.internallength.as_ref())
            {
                return result;
            }
        }

        // Check if typed tables require CASCADE for attribute changes.
        let typed_tables: Vec<ObjectId> = self
            .local
            .relations
            .iter()
            .filter_map(|(id, overlay)| match overlay {
                RelationOverlay::Present(rel) if rel.of_type.as_ref() == Some(&alter.id) => {
                    Some(id.clone())
                }
                _ => None,
            })
            .collect();

        match &alter.action {
            AlterTypeActionMutation::DropAttribute { cascade, .. }
            | AlterTypeActionMutation::AlterAttributeType { cascade, .. }
            | AlterTypeActionMutation::AddAttribute { cascade, .. }
            | AlterTypeActionMutation::RenameAttribute { cascade, .. }
                if !typed_tables.is_empty() && !cascade =>
            {
                return MutationResult::conflict(format!(
                    "cannot alter type \"{}\" because it is the type of a typed table",
                    alter.id.name
                ));
            }
            _ => {}
        }

        if let AlterTypeActionMutation::AlterAttributeType { name, .. } = &alter.action {
            let (dependent_types, _) = self.type_cascade_closure(std::slice::from_ref(&alter.id));
            let mut transitive_types = dependent_types;
            loop {
                let mut grew = false;
                for (id, overlay) in &self.local.types {
                    if transitive_types.contains(id) {
                        continue;
                    }
                    let TypeOverlay::Present(state) = overlay else {
                        continue;
                    };
                    if let TypeKind::Composite { fields } = &state.kind
                        && fields.iter().any(|field| {
                            Self::type_reference_matches_victims(
                                field.data_type_id.as_ref(),
                                &transitive_types,
                            )
                        })
                    {
                        transitive_types.insert(id.clone());
                        grew = true;
                    }
                }
                if !grew {
                    break;
                }
            }
            for overlay in self.local.relations.values() {
                let RelationOverlay::Present(relation) = overlay else {
                    continue;
                };
                if !matches!(
                    relation.kind,
                    crate::_internal::model::relation::RelationKind::Table
                        | crate::_internal::model::relation::RelationKind::MaterializedView
                        | crate::_internal::model::relation::RelationKind::ForeignTable
                ) {
                    continue;
                }
                if let Some(column) = relation.columns.iter().find(|column| {
                    Self::type_reference_matches_victims(column.type_id.as_ref(), &transitive_types)
                }) {
                    return MutationResult::conflict(format!(
                        "cannot alter type \"{}\" because column \"{}.{}\" uses it",
                        alter.id.name, relation.id.name, column.name
                    ));
                }
            }
            for tbl_id in &typed_tables {
                let resolved_table = self.local.graph.resolve_rename(tbl_id);
                if self.local.graph.edges().iter().any(|edge| {
                    self.dependency_edge_is_current(edge)
                        && self.local.graph.resolve_rename(&edge.referenced) == resolved_table
                        && matches!(
                            &edge.kind,
                            DependencyKind::ViewDependency {
                                referenced_column: Some(col),
                                ..
                            } if col == name
                        )
                }) {
                    return MutationResult::conflict(
                        "cannot alter type of a column used by a view or rule".to_string(),
                    );
                }
            }
        }

        let resolved_attr_type_id = match &alter.action {
            AlterTypeActionMutation::AddAttribute { data_type, .. }
            | AlterTypeActionMutation::AlterAttributeType { data_type, .. } => {
                self.resolve_type_reference(data_type)
            }
            _ => None,
        };
        let resolved_attr_collation = match &alter.action {
            AlterTypeActionMutation::AddAttribute {
                data_type,
                collation,
                ..
            }
            | AlterTypeActionMutation::AlterAttributeType {
                data_type,
                collation,
                ..
            } => match self.resolve_composite_field_collation(data_type, collation.as_deref()) {
                Ok(resolved) => Some(resolved),
                Err(result) => return result,
            },
            _ => None,
        };

        let normalized_set_options = match &alter.action {
            AlterTypeActionMutation::SetOptions { options } => {
                let mut options = options.clone();
                self.canonicalize_base_type_options(&mut options);
                Some(options)
            }
            _ => None,
        };

        let resolved_owner = match &alter.action {
            AlterTypeActionMutation::OwnerTo { new_owner } => {
                let Some((owner_name, known)) = self.role_fact_identity(new_owner) else {
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
                Some(owner_name)
            }
            _ => None,
        };

        self.snapshot_type(&alter.id);
        if let Some(TypeOverlay::Present(existing)) = self.local.types.get_mut(&alter.id) {
            match &alter.action {
                AlterTypeActionMutation::OwnerTo { .. } => {
                    existing.owner =
                        ObjectId::new("", resolved_owner.expect("owner resolved above"));
                }
                AlterTypeActionMutation::SetOptions { .. } => {
                    if let TypeKind::Base {
                        options: base_opts,
                        shell,
                    } = &mut existing.kind
                    {
                        base_opts.merge(
                            normalized_set_options
                                .as_ref()
                                .expect("set options normalized above"),
                        );
                        *shell = false;
                    }
                }
                AlterTypeActionMutation::AddAttribute {
                    name, data_type, ..
                } => {
                    if let TypeKind::Composite { fields } = &mut existing.kind {
                        if fields.iter().any(|f| f.name == *name) {
                            return MutationResult::conflict(format!(
                                "column \"{}\" of relation \"{}\" already exists",
                                name, alter.id.name
                            ));
                        }
                        let (collation, collation_id) =
                            resolved_attr_collation.clone().unwrap_or((None, None));
                        fields.push(crate::_internal::model::types::CompositeFieldState {
                            name: name.clone(),
                            data_type: data_type.clone(),
                            data_type_id: resolved_attr_type_id.clone(),
                            collation,
                            collation_id,
                        });
                    }
                }
                AlterTypeActionMutation::DropAttribute {
                    name, if_exists, ..
                } => {
                    if let TypeKind::Composite { fields } = &mut existing.kind {
                        if let Some(idx) = fields.iter().position(|f| f.name == *name) {
                            fields.remove(idx);
                        } else if *if_exists {
                            return MutationResult::NoOp;
                        } else {
                            return MutationResult::conflict(format!(
                                "column \"{}\" of relation \"{}\" does not exist",
                                name, alter.id.name
                            ));
                        }
                    }
                }
                AlterTypeActionMutation::AlterAttributeType {
                    name, data_type, ..
                } => {
                    if let TypeKind::Composite { fields } = &mut existing.kind {
                        let Some(field) = fields.iter_mut().find(|f| f.name == *name) else {
                            return MutationResult::conflict(format!(
                                "column \"{}\" of relation \"{}\" does not exist",
                                name, alter.id.name
                            ));
                        };
                        field.data_type = data_type.clone();
                        field.data_type_id = resolved_attr_type_id.clone();
                        let (collation, collation_id) =
                            resolved_attr_collation.clone().unwrap_or((None, None));
                        field.collation = collation;
                        field.collation_id = collation_id;
                    }
                }
                AlterTypeActionMutation::RenameAttribute {
                    old_name, new_name, ..
                } => {
                    if let TypeKind::Composite { fields } = &mut existing.kind {
                        if fields.iter().any(|f| f.name == *new_name) {
                            return MutationResult::conflict(format!(
                                "column \"{}\" of relation \"{}\" already exists",
                                new_name, alter.id.name
                            ));
                        }
                        let Some(field) = fields.iter_mut().find(|f| f.name == *old_name) else {
                            return MutationResult::conflict(format!(
                                "column \"{}\" of relation \"{}\" does not exist",
                                old_name, alter.id.name
                            ));
                        };
                        field.name = new_name.clone();
                    }
                }
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

        // Synchronize typed tables with composite alterations
        if !typed_tables.is_empty() {
            match &alter.action {
                AlterTypeActionMutation::AddAttribute {
                    name, data_type, ..
                } => {
                    for tbl_id in &typed_tables {
                        self.snapshot_relation(tbl_id);
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(tbl_id)
                            && !rel.columns.iter().any(|c| c.name == *name)
                        {
                            rel.columns.push(crate::_internal::model::column::Column {
                                name: name.clone(),
                                data_type: Some(data_type.clone()),
                                type_id: resolved_attr_type_id.clone(),
                                is_nullable: true,
                                default: None,
                                avg_width: None,
                                default_expr_text: None,
                                type_modifier: None,
                                storage: None,
                                compression: None,
                                statistics_target: None,
                                options: Default::default(),
                                generated: None,
                            });
                            rel.column_inheritance.insert(
                                name.clone(),
                                crate::_internal::model::relation::ColumnInheritance {
                                    parent_count: 0,
                                    is_local: false,
                                },
                            );
                        }
                    }
                }
                AlterTypeActionMutation::DropAttribute { name, cascade, .. } => {
                    for tbl_id in &typed_tables {
                        let alter_tbl = crate::_internal::analysis::mutations::AlterTable {
                            id: tbl_id.clone(),
                            only: false,
                            if_exists: false,
                            action:
                                crate::_internal::analysis::mutations::AlterTableActionMutation::DropColumn {
                                    name: name.clone(),
                                    if_exists: true,
                                    cascade: *cascade,
                                },
                        };
                        match self.apply_alter_table(&alter_tbl) {
                            MutationResult::Applied | MutationResult::NoOp => {}
                            result => return result,
                        }
                    }
                }
                AlterTypeActionMutation::AlterAttributeType {
                    name, data_type, ..
                } => {
                    let typmod = ParsedDataType::parse(data_type, self.builtin_types()).atttypmod();
                    for tbl_id in &typed_tables {
                        self.snapshot_relation(tbl_id);
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(tbl_id)
                            && let Some(col) = rel.columns.iter_mut().find(|c| c.name == *name)
                        {
                            col.data_type = Some(data_type.clone());
                            col.type_id = resolved_attr_type_id.clone();
                            col.type_modifier = typmod;
                        }
                    }
                }
                AlterTypeActionMutation::RenameAttribute {
                    old_name, new_name, ..
                } => {
                    self.rename_relations_column_metadata_batch(&typed_tables, old_name, new_name);
                }
                _ => {}
            }
        }

        MutationResult::Applied
    }

    /// Resolve a range's canonical or subtype-diff routine by its written name
    /// and the exact argument identity PostgreSQL records for it. The routine
    /// must already exist when the range type is created.
    pub(crate) fn resolve_internal_routine_id(
        &self,
        written: &str,
        signature: &str,
    ) -> Option<ObjectId> {
        let (schema_hint, function_name) = match written.rsplit_once('.') {
            Some((schema, name)) => (Some(schema.trim_matches('"')), name.trim_matches('"')),
            None => (None, written.trim_matches('"')),
        };
        let object_name = format!("{function_name}({signature})");
        if let Some(schema) = schema_hint {
            let id = ObjectId::new(schema, object_name);
            return self.routine_is_present(&id).then_some(id);
        }
        self.routine_search_path().into_iter().find_map(|entry| {
            let schema = entry.searched_schema()?;
            let id = ObjectId::new(schema, object_name.clone());
            self.routine_is_present(&id).then_some(id)
        })
    }

    pub(super) fn canonicalize_base_type_options(&self, options: &mut BaseTypeOptions) {
        for written in options.routine_references_mut() {
            if let Some(id) = self.resolve_unique_routine_reference(written) {
                *written = id.to_string();
            }
        }
    }

    /// Resolve a base-type routine option written without an argument list.
    /// Ambiguous overloads stay unresolved rather than guessing.
    pub(super) fn resolve_unique_routine_reference(&self, written: &str) -> Option<ObjectId> {
        let (schema_hint, function_name, signature) = Self::split_routine_reference(written);
        let schemas: Vec<String> = match schema_hint {
            Some(schema) => vec![schema],
            None => self
                .routine_search_path()
                .into_iter()
                .filter_map(|entry| entry.searched_schema().map(str::to_string))
                .collect(),
        };
        for schema in schemas {
            if let Some(signature) = &signature {
                let id = ObjectId::new(&schema, format!("{function_name}{signature}"));
                if self.routine_is_present(&id) {
                    return Some(id);
                }
                continue;
            }
            let candidates = self
                .local
                .functions
                .keys()
                .filter(|id| {
                    id.schema == schema
                        && DependencyGraph::split_routine_signature(id).1 == function_name
                        && matches!(
                            self.local.functions.get(*id),
                            Some(FunctionOverlay::Present(_))
                        )
                })
                .collect::<Vec<_>>();
            if candidates.is_empty() {
                continue;
            }
            return (candidates.len() == 1).then(|| candidates[0].clone());
        }
        None
    }

    pub(super) fn split_routine_reference(
        written: &str,
    ) -> (Option<String>, String, Option<String>) {
        let (head, signature) = match written.split_once('(') {
            Some((head, args)) => (head, Some(format!("({args}"))),
            None => (written, None),
        };
        let (schema, name) = match head.rsplit_once('.') {
            Some((schema, name)) => (Some(Self::unquote_identifier(schema)), name),
            None => (None, head),
        };
        (schema, Self::unquote_identifier(name), signature)
    }

    pub(super) fn unquote_identifier(identifier: &str) -> String {
        identifier
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .map(|value| value.replace("\"\"", "\""))
            .unwrap_or_else(|| identifier.to_string())
    }

    /// Does this base-type routine option still name `routine`? Exact canonical
    /// IDs cover synchronized state; a bare written name is accepted only when
    /// it identifies a single live overload.
    pub(super) fn base_type_option_references_routine(
        &self,
        options: &BaseTypeOptions,
        routine: &ObjectId,
    ) -> bool {
        options.routine_references().any(|written| {
            let (schema_hint, function_name, signature) = Self::split_routine_reference(written);
            if signature.is_some() {
                return written == &routine.to_string();
            }
            if DependencyGraph::split_routine_signature(routine).1 != function_name {
                return false;
            }
            if let Some(ref schema) = schema_hint
                && schema != &routine.schema
            {
                return false;
            }
            let mut candidates = self.local.functions.keys().filter(|id| {
                DependencyGraph::split_routine_signature(id).1 == function_name
                    && schema_hint
                        .as_ref()
                        .is_none_or(|schema| &id.schema == schema)
                    && matches!(
                        self.local.functions.get(*id),
                        Some(FunctionOverlay::Present(_))
                    )
            });
            candidates.next() == Some(routine) && candidates.next().is_none()
        })
    }

    /// Repoint range canonical/subtype-diff IDs and base-type routine text
    /// after the routine they name has moved or been renamed.
    pub(super) fn remap_range_routine_reference(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        let affected: Vec<ObjectId> = self
            .local
            .types
            .iter()
            .filter_map(|(id, overlay)| {
                let TypeOverlay::Present(state) = overlay else {
                    return None;
                };
                let TypeKind::Range {
                    canonical_id,
                    subtype_diff_id,
                    ..
                } = &state.kind
                else {
                    return None;
                };
                (canonical_id == &Some(old_id.clone()) || subtype_diff_id == &Some(old_id.clone()))
                    .then(|| id.clone())
            })
            .collect();
        for id in affected {
            self.snapshot_type(&id);
            if let Some(TypeOverlay::Present(state)) = self.local.types.get_mut(&id)
                && let TypeKind::Range {
                    canonical_id,
                    subtype_diff_id,
                    ..
                } = &mut state.kind
            {
                if canonical_id.as_ref() == Some(old_id) {
                    *canonical_id = Some(new_id.clone());
                }
                if subtype_diff_id.as_ref() == Some(old_id) {
                    *subtype_diff_id = Some(new_id.clone());
                }
            }
        }

        let base_affected: Vec<ObjectId> = self
            .local
            .types
            .iter()
            .filter_map(|(id, overlay)| {
                let TypeOverlay::Present(state) = overlay else {
                    return None;
                };
                let TypeKind::Base { options, .. } = &state.kind else {
                    return None;
                };
                options
                    .routine_references()
                    .any(|written| written == &old_id.to_string())
                    .then(|| id.clone())
            })
            .collect();
        for id in base_affected {
            self.snapshot_type(&id);
            if let Some(TypeOverlay::Present(state)) = self.local.types.get_mut(&id)
                && let TypeKind::Base { options, .. } = &mut state.kind
            {
                for written in options.routine_references_mut() {
                    if written == &old_id.to_string() {
                        *written = new_id.to_string();
                    }
                }
            }
        }
    }
}

#[path = "apply_type/domain.rs"]
mod domain;
