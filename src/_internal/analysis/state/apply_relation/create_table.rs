use super::*;

impl AnalysisState {
    /// Apply CREATE TABLE, expanding inheritance, LIKE, and partition sources.
    pub(in crate::_internal::analysis::state) fn apply_create_table(
        &mut self,
        create: &CreateTable,
    ) -> MutationResult {
        if let Some(strategy) = &create.partition_strategy
            && !["range", "list", "hash"]
                .iter()
                .any(|valid| strategy.eq_ignore_ascii_case(valid))
        {
            return MutationResult::conflict(format!(
                "unrecognized partitioning strategy '{strategy}'"
            ));
        }
        if matches!(create.persistence, PersistenceMutation::Temporary)
            && !is_session_temp_schema(&create.id.schema)
        {
            return MutationResult::conflict(
                "cannot create temporary relation in non-temporary schema".to_string(),
            );
        }
        if let Err(result) = self.ensure_creation_target(&create.id) {
            return result;
        }
        if create.if_not_exists && self.relation_namespace_is_taken(&create.id) {
            return MutationResult::NoOp;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::conflict(format!("relation '{}' already exists", create.id));
        }
        if let Some(type_id) = &create.of_type {
            match self.local.types.get(type_id) {
                Some(crate::_internal::model::types::TypeOverlay::Present(
                    crate::_internal::model::types::TypeState {
                        kind: crate::_internal::model::types::TypeKind::Composite { .. },
                        ..
                    },
                )) => {}
                Some(crate::_internal::model::types::TypeOverlay::Present(_)) => {
                    return MutationResult::conflict(format!(
                        "type '{}' is not composite",
                        type_id
                    ));
                }
                Some(crate::_internal::model::types::TypeOverlay::Dropped) => {
                    return MutationResult::conflict(format!(
                        "composite type '{}' does not exist",
                        type_id
                    ));
                }
                None => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
            }
        }

        let mut inherited_columns = Vec::new();
        // Every column source must be complete for the result to be.
        let mut sources_complete = true;
        let mut inherited_names = HashSet::new();
        if let Some(type_id) = &create.of_type
            && let Some(crate::_internal::model::types::TypeOverlay::Present(
                crate::_internal::model::types::TypeState {
                    kind: crate::_internal::model::types::TypeKind::Composite { fields },
                    ..
                },
            )) = self.local.types.get(type_id)
        {
            for field in fields {
                inherited_names.insert(field.name.clone());
                let mut column = crate::_internal::model::column::Column::migration_created(
                    field.name.clone(),
                    Some(field.data_type.clone()),
                    true,
                    None,
                );
                column.type_id = field
                    .data_type_id
                    .clone()
                    .or_else(|| self.resolve_type_reference(&field.data_type));
                inherited_columns.push(column);
            }
        }
        let mut inherited_generated_columns = std::collections::HashMap::new();
        let mut inherited_check_constraints: std::collections::HashMap<
            String,
            (Vec<String>, String),
        > = std::collections::HashMap::new();
        let mut like_dependency_edges = Vec::new();
        let mut like_identity_columns = Vec::new();
        let mut like_generated_columns = Vec::new();
        let mut like_check_constraints = Vec::new();
        let mut like_indexes = Vec::new();
        let mut like_extended_statistics = Vec::new();
        let mut reserved_statistics_ids = HashSet::new();
        let mut partition_foreign_keys = Vec::new();
        for parent_id in &create.inherits {
            if let Err(result) = self.ensure_relation_target(
                parent_id,
                |kind| kind.is_table_like(),
                format!("inheritance parent relation '{}' does not exist", parent_id),
                format!("inheritance parent '{}' is not a table", parent_id),
            ) {
                return result;
            }
            if self
                .local
                .graph
                .check_inheritance_cycle(parent_id, &create.id)
            {
                return MutationResult::conflict(format!(
                    "inheriting '{}' into '{}' would create an inheritance cycle",
                    parent_id, create.id
                ));
            }
            let Some(RelationOverlay::Present(parent)) = self.local.relations.get(parent_id) else {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            };
            sources_complete &= parent.columns_complete;
            for column in &parent.columns {
                // Two parents may contribute the same column; PostgreSQL keeps
                // it only when the types and defaults agree, and NOT NULL is the
                // stricter of the two.
                if !inherited_names.insert(column.name.clone()) {
                    let existing = inherited_columns
                        .iter_mut()
                        .find(|candidate: &&mut crate::_internal::model::column::Column| {
                            candidate.name == column.name
                        })
                        .expect("an inherited name always has a column");
                    let compatible_type = match (
                        existing.type_id.as_ref(),
                        column.type_id.as_ref(),
                        existing.data_type.as_deref(),
                        column.data_type.as_deref(),
                    ) {
                        (Some(left), Some(right), _, _) => left == right,
                        (_, _, Some(left), Some(right)) => {
                            left.trim().eq_ignore_ascii_case(right.trim())
                        }
                        _ => false,
                    };
                    if !compatible_type
                        || (existing.default.is_some()
                            && column.default.is_some()
                            && existing.default != column.default)
                    {
                        return MutationResult::conflict(format!(
                            "inherited column '{}' has incompatible parent definitions",
                            column.name
                        ));
                    }
                    existing.is_nullable &= column.is_nullable;
                    if existing.default.is_none() {
                        existing.default = column.default.clone();
                        existing.default_expr_text = column.default_expr_text.clone();
                    }
                    continue;
                }
                inherited_columns.push(column.clone());
            }
            for (column, generated) in &parent.generated_columns {
                if let Some(existing) = inherited_generated_columns.get(column)
                    && existing != generated
                {
                    return MutationResult::conflict(format!(
                        "inherited generated column '{}' has incompatible parent definitions",
                        column
                    ));
                }
                inherited_generated_columns.insert(column.clone(), generated.clone());
            }
            for constraint in self.local.constraints.values().filter(|constraint| {
                constraint.table_id == *parent_id
                    && matches!(constraint.kind, ConstraintKind::Check)
            }) {
                let Some(definition) = constraint.definition.as_deref() else {
                    return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                };
                let Some(columns) =
                    self.local
                        .graph
                        .edges()
                        .iter()
                        .find_map(|edge| match &edge.kind {
                            DependencyKind::ConstraintDependency {
                                constraint_name,
                                columns,
                            } if edge.dependent == *parent_id
                                && edge.referenced == *parent_id
                                && constraint_name == &constraint.name =>
                            {
                                Some(columns.clone())
                            }
                            _ => None,
                        })
                else {
                    return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                };
                if let Some((_, existing)) = inherited_check_constraints.get(&constraint.name)
                    && Self::normalized_constraint_expression(existing)
                        != Self::normalized_constraint_expression(definition)
                {
                    return MutationResult::conflict(format!(
                        "inherited CHECK constraint '{}' has incompatible parent definitions",
                        constraint.name
                    ));
                }
                inherited_check_constraints
                    .insert(constraint.name.clone(), (columns, definition.to_string()));
            }
        }
        like_check_constraints.extend(inherited_check_constraints.iter().map(
            |(name, (columns, definition))| (name.clone(), columns.clone(), definition.clone()),
        ));

        // An unadorned LIKE copies only names, types, and NOT NULL markers.
        // Each selected property is copied independently, matching PostgreSQL's
        // `INCLUDING` contract without inventing unrelated catalog objects.
        for like_source in &create.like_sources {
            let source_id = &like_source.relation;
            // A composite type is also a valid row type, so LIKE can copy its
            // fields even though it is not a relation.
            if !self.relation_is_present(source_id)
                && let Some(crate::_internal::model::types::TypeOverlay::Present(
                    crate::_internal::model::types::TypeState {
                        kind: crate::_internal::model::types::TypeKind::Composite { fields },
                        ..
                    },
                )) = self.local.types.get(source_id)
            {
                for field in fields {
                    if !inherited_names.insert(field.name.clone()) {
                        return MutationResult::conflict(format!(
                            "column '{}' is copied from more than one source",
                            field.name
                        ));
                    }
                    inherited_columns.push(
                        crate::_internal::model::column::Column::migration_created(
                            field.name.clone(),
                            Some(field.data_type.clone()),
                            true,
                            None,
                        ),
                    );
                }
                continue;
            }
            if let Err(result) = self.ensure_relation_target(
                source_id,
                |kind| {
                    matches!(
                        kind,
                        RelationKind::Table | RelationKind::View | RelationKind::MaterializedView
                    )
                },
                format!("LIKE source relation '{}' does not exist", source_id),
                format!(
                    "LIKE source '{}' cannot provide a table row type",
                    source_id
                ),
            ) {
                return result;
            }
            let Some(RelationOverlay::Present(source)) = self.local.relations.get(source_id) else {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            };
            let source = source.clone();
            sources_complete &= source.columns_complete;
            if like_source.properties.statistics {
                for statistics in source.extended_statistics.values() {
                    let id = self.next_generated_statistics_name_avoiding(
                        &create.id.schema,
                        &create.id.name,
                        &statistics.columns,
                        &reserved_statistics_ids,
                    );
                    reserved_statistics_ids.insert(id.clone());
                    let mut cloned = statistics.clone();
                    cloned.id = id;
                    // LIKE copies the statistics definition, while PostgreSQL
                    // initializes the new object's target independently.
                    cloned.target = None;
                    like_extended_statistics.push(cloned);
                }
            }
            if like_source.properties.generated || like_source.properties.defaults {
                like_dependency_edges.extend(self.local.graph.edges().iter().filter_map(|edge| {
                    if edge.dependent != *source_id {
                        return None;
                    }
                    match &edge.kind {
                        DependencyKind::ColumnGeneratedFrom { .. }
                            if like_source.properties.generated =>
                        {
                            Some(DependencyEdge::new(
                                create.id.clone(),
                                create.id.clone(),
                                edge.kind.clone(),
                            ))
                        }
                        DependencyKind::ColumnDefaultOnSequence { .. }
                            if like_source.properties.defaults =>
                        {
                            Some(DependencyEdge::new(
                                create.id.clone(),
                                edge.referenced.clone(),
                                edge.kind.clone(),
                            ))
                        }
                        _ => None,
                    }
                }));
            }
            if like_source.properties.identity {
                for (column, generation) in &source.identity_columns {
                    let Some(parameters) = self.local.sequences.values().find_map(|overlay| {
                        let SequenceOverlay::Present(sequence) = overlay else {
                            return None;
                        };
                        (sequence.kind == SequenceKind::Identity
                            && sequence.owned_by.as_ref()
                                == Some(&(source_id.clone(), column.clone())))
                        .then(|| sequence.parameters.clone())
                    }) else {
                        return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                    };
                    like_identity_columns.push((column.clone(), *generation, parameters));
                }
            }
            if like_source.properties.generated {
                like_generated_columns.extend(
                    source
                        .generated_columns
                        .iter()
                        .map(|(column, state)| (column.clone(), state.clone())),
                );
            }
            if like_source.properties.constraints {
                let source_checks: Vec<ConstraintState> = self
                    .local
                    .constraints
                    .values()
                    .filter(|constraint| {
                        constraint.table_id == *source_id
                            && matches!(constraint.kind, ConstraintKind::Check)
                    })
                    .cloned()
                    .collect();
                for constraint in source_checks {
                    let Some(columns) = self.local.graph.edges().iter().find_map(|edge| {
                        if edge.dependent != *source_id || edge.referenced != *source_id {
                            return None;
                        }
                        match &edge.kind {
                            DependencyKind::ConstraintDependency {
                                constraint_name,
                                columns,
                            } if constraint_name == &constraint.name => Some(columns.clone()),
                            _ => None,
                        }
                    }) else {
                        return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                    };
                    let Some(definition) = constraint.definition.clone() else {
                        return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                    };
                    like_check_constraints.push((constraint.name.clone(), columns, definition));
                }
            }
            if like_source.properties.indexes {
                let source_constraints: Vec<ConstraintState> = self
                    .local
                    .constraints
                    .values()
                    .filter(|constraint| constraint.table_id == *source_id)
                    .cloned()
                    .collect();
                let mut copied_constraints = HashSet::new();
                for edge in self.local.graph.edges().iter().filter(|edge| {
                    edge.referenced == *source_id
                        && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                }) {
                    let constraint = source_constraints
                        .iter()
                        .find(|constraint| {
                            constraint.backing_index.as_ref() == Some(&edge.dependent)
                        })
                        .and_then(|constraint| {
                            let columns = self.local.graph.edges().iter().find_map(|key_edge| {
                                if key_edge.dependent != *source_id
                                    || key_edge.referenced != *source_id
                                {
                                    return None;
                                }
                                match &key_edge.kind {
                                    DependencyKind::ConstraintOnRelation {
                                        constraint_name,
                                        columns,
                                        ..
                                    }
                                    | DependencyKind::ConstraintDependency {
                                        constraint_name,
                                        columns,
                                    } if constraint_name == &constraint.name => {
                                        Some(columns.clone())
                                    }
                                    _ => None,
                                }
                            })?;
                            copied_constraints.insert(constraint.name.clone());
                            Some((constraint.kind, columns))
                        });
                    like_indexes.push((edge.kind.clone(), constraint));
                }
                for constraint in source_constraints.into_iter().filter(|constraint| {
                    matches!(
                        constraint.kind,
                        ConstraintKind::PrimaryKey
                            | ConstraintKind::Unique
                            | ConstraintKind::Exclusion
                    ) && !copied_constraints.contains(&constraint.name)
                }) {
                    let Some((columns, is_key)) =
                        self.local.graph.edges().iter().find_map(|edge| {
                            if edge.dependent != *source_id || edge.referenced != *source_id {
                                return None;
                            }
                            match &edge.kind {
                                DependencyKind::ConstraintOnRelation {
                                    constraint_name,
                                    columns,
                                    ..
                                } if constraint_name == &constraint.name => {
                                    Some((columns.clone(), true))
                                }
                                DependencyKind::ConstraintDependency {
                                    constraint_name,
                                    columns,
                                } if constraint_name == &constraint.name => {
                                    Some((columns.clone(), false))
                                }
                                _ => None,
                            }
                        })
                    else {
                        return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                    };
                    let is_unique = matches!(
                        constraint.kind,
                        ConstraintKind::PrimaryKey | ConstraintKind::Unique
                    );
                    like_indexes.push((
                        DependencyKind::IndexOnRelation {
                            definition: IndexDefinition {
                                method: is_key.then(|| "btree".to_string()),
                                keys: index_keys(columns.clone()),
                                included: index_keys(Vec::new()),
                                expression_keys: 0,
                                unique: is_unique,
                                nulls_not_distinct: Some(false),
                                predicate: IndexPredicate::None,
                                // An exclusion constraint's backing index carries
                                // operators, procedures and possibly expressions
                                // the constraint columns do not record.
                                unestablished: !is_key,
                                valid: true,
                                ready: true,
                                live: true,
                            },
                            dependency_columns: columns.clone(),
                            dependency_columns_known: true,
                            is_concurrent: false,
                            is_immediate: true,
                            eligibility_known: true,
                        },
                        Some((constraint.kind, columns)),
                    ));
                }
            }
            for source_column in &source.columns {
                if !inherited_names.insert(source_column.name.clone()) {
                    return MutationResult::conflict(format!(
                        "column '{}' is copied from more than one source relation",
                        source_column.name
                    ));
                }
                let mut column = source_column.clone();
                if !like_source.properties.defaults {
                    column.default = None;
                    column.default_expr_text = None;
                }
                if !like_source.properties.storage {
                    column.storage = None;
                }
                if !like_source.properties.compression {
                    column.compression = None;
                }
                column.statistics_target = None;
                column.options.clear();
                if !like_source.properties.generated {
                    column.generated = Some(false);
                }
                inherited_columns.push(column);
            }
        }

        if let Some(parent_id) = &create.partition_of {
            if let Err(result) = self.ensure_relation_target(
                parent_id,
                |kind| *kind == RelationKind::Table,
                format!("partition parent relation '{}' does not exist", parent_id),
                format!("partition parent '{}' is not a table", parent_id),
            ) {
                return result;
            }
            let Some(RelationOverlay::Present(parent)) = self.local.relations.get(parent_id) else {
                unreachable!("partition parent presence was checked above")
            };
            sources_complete &= parent.columns_complete;
            if parent.partition_type.is_none() {
                return MutationResult::conflict(format!(
                    "partition parent '{}' is not partitioned",
                    parent_id
                ));
            }
            // A partition takes the parent's columns and CHECK constraints;
            // parent indexes become templates for the child's attached indexes.
            for column in &parent.columns {
                if !inherited_names.insert(column.name.clone()) {
                    return MutationResult::conflict(format!(
                        "partition column '{}' conflicts with another table source",
                        column.name
                    ));
                }
                inherited_columns.push(column.clone());
            }
            inherited_generated_columns.extend(parent.generated_columns.clone());

            let parent_constraints: Vec<ConstraintState> = self
                .local
                .constraints
                .values()
                .filter(|constraint| constraint.table_id == *parent_id)
                .cloned()
                .collect();
            for constraint in parent_constraints
                .iter()
                .filter(|constraint| matches!(constraint.kind, ConstraintKind::Check))
            {
                let Some(definition) = constraint.definition.clone() else {
                    return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                };
                let Some(columns) =
                    self.local
                        .graph
                        .edges()
                        .iter()
                        .find_map(|edge| match &edge.kind {
                            DependencyKind::ConstraintDependency {
                                constraint_name,
                                columns,
                            } if edge.dependent == *parent_id
                                && edge.referenced == *parent_id
                                && constraint_name == &constraint.name =>
                            {
                                Some(columns.clone())
                            }
                            _ => None,
                        })
                else {
                    return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                };
                like_check_constraints.push((constraint.name.clone(), columns, definition));
            }

            for edge in self.local.graph.edges().iter().filter(|edge| {
                edge.referenced == *parent_id
                    && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
            }) {
                let constraint = parent_constraints
                    .iter()
                    .find(|constraint| constraint.backing_index.as_ref() == Some(&edge.dependent))
                    .and_then(|constraint| {
                        let columns =
                            self.local
                                .graph
                                .edges()
                                .iter()
                                .find_map(|key_edge| match &key_edge.kind {
                                    DependencyKind::ConstraintOnRelation {
                                        constraint_name,
                                        columns,
                                        ..
                                    }
                                    | DependencyKind::ConstraintDependency {
                                        constraint_name,
                                        columns,
                                    } if key_edge.dependent == *parent_id
                                        && key_edge.referenced == *parent_id
                                        && constraint_name == &constraint.name =>
                                    {
                                        Some(columns.clone())
                                    }
                                    _ => None,
                                })?;
                        Some((constraint.kind, columns))
                    });
                like_indexes.push((edge.kind.clone(), constraint));
            }

            partition_foreign_keys.extend(self.local.graph.edges().iter().filter_map(|edge| {
                let DependencyKind::ForeignKey {
                    constraint_name: Some(name),
                    ..
                } = &edge.kind
                else {
                    return None;
                };
                (edge.dependent == *parent_id).then(|| (name.clone(), edge.clone()))
            }));
        }

        let mut column_names = inherited_names;
        let mut explicit_names = HashSet::new();
        for column in &create.columns {
            if !explicit_names.insert(column.name.clone()) {
                return MutationResult::conflict(format!(
                    "column \"{}\" specified more than once",
                    column.name
                ));
            }
            if create.of_type.is_some() {
                if matches!(
                    column.generation,
                    crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                        | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual
                ) {
                    return MutationResult::conflict(
                        "generated columns are not supported on typed tables".to_string(),
                    );
                }
                if matches!(
                    column.generation,
                    crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
                        | crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault
                ) {
                    return MutationResult::conflict(
                        "identity columns are not supported on typed tables".to_string(),
                    );
                }
            }
            if (create.of_type.is_some() || create.partition_of.is_some() || column.ty.is_none())
                && !inherited_columns
                    .iter()
                    .any(|candidate| candidate.name == column.name)
            {
                return MutationResult::conflict(format!(
                    "column \"{}\" does not exist",
                    column.name
                ));
            }
            if !column_names.insert(column.name.clone()) {
                let Some(inherited) = inherited_columns
                    .iter()
                    .find(|candidate| candidate.name == column.name)
                else {
                    return MutationResult::conflict(format!(
                        "column \"{}\" specified more than once",
                        column.name
                    ));
                };
                let compatible = match (inherited.data_type.as_deref(), column.ty.as_deref()) {
                    (_, None) => create.of_type.is_some() || create.partition_of.is_some(),
                    (Some(left), Some(right)) => left.trim().eq_ignore_ascii_case(right.trim()),
                    _ => false,
                };
                if !compatible {
                    return MutationResult::conflict(format!(
                        "column '{}' conflicts with an inherited column type",
                        column.name
                    ));
                }
                let parent_generated = inherited_generated_columns.get(&column.name);
                let child_generated = match column.generation {
                    crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored => {
                        Some(crate::_internal::model::relation::GeneratedColumnKind::Stored)
                    }
                    crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => {
                        Some(crate::_internal::model::relation::GeneratedColumnKind::Virtual)
                    }
                    _ => None,
                };
                if let Some(parent_gen) = parent_generated {
                    if column.default.is_some() && child_generated.is_none() {
                        return MutationResult::conflict(format!(
                            "column \"{}\" inherits from generated column but specifies default",
                            column.name
                        ));
                    }
                    if matches!(
                        column.generation,
                        crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
                            | crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault
                    ) {
                        return MutationResult::conflict(format!(
                            "column \"{}\" inherits from generated column but specifies identity",
                            column.name
                        ));
                    }
                    if let Some(child_kind) = child_generated
                        && child_kind != parent_gen.kind
                    {
                        return MutationResult::conflict(format!(
                            "column \"{}\" inherits from generated column of different kind",
                            column.name
                        ));
                    }
                } else if child_generated.is_some() {
                    return MutationResult::conflict(format!(
                        "child column \"{}\" specifies generation expression",
                        column.name
                    ));
                }
            }
        }
        for column in &create.columns {
            let Some(expr) = &column.generated_expr else {
                continue;
            };
            let Some(references) = expr.referenced_columns() else {
                return self.unresolved_statement(EvidenceCode::UnsupportedSemantics);
            };
            if let Some(reference) = references
                .iter()
                .find(|reference| *reference == &column.name || !column_names.contains(*reference))
            {
                return MutationResult::conflict(format!(
                    "generated expression for '{}.{}' references invalid column '{}'",
                    create.id, column.name, reference
                ));
            }
        }
        let primary_declarations = create
            .columns
            .iter()
            .filter(|column| column.is_primary_key)
            .count()
            + create
                .table_constraints
                .iter()
                .filter(|constraint| matches!(constraint, TableConstraintFact::PrimaryKey { .. }))
                .count();
        if primary_declarations > 1 {
            return MutationResult::conflict(
                "multiple primary keys for table are not allowed".to_string(),
            );
        }
        for constraint in &create.table_constraints {
            let columns = match constraint {
                TableConstraintFact::PrimaryKey { columns, .. }
                | TableConstraintFact::Unique { columns, .. } => columns,
                TableConstraintFact::Check { .. } | TableConstraintFact::Exclude { .. } => {
                    continue;
                }
            };
            if columns.is_empty() {
                return MutationResult::conflict(
                    "key constraint must name at least one column".to_string(),
                );
            }
            let mut key_columns = HashSet::new();
            for column in columns {
                if !key_columns.insert(column) {
                    return MutationResult::conflict(format!(
                        "column '{}' appears more than once in a key constraint",
                        column
                    ));
                }
                if !column_names.contains(column) {
                    return MutationResult::conflict(format!(
                        "constraint references column '{}' which does not exist on relation '{}'",
                        column, create.id
                    ));
                }
            }
        }

        let mut effective_fk_target_columns = Vec::with_capacity(create.foreign_keys.len());
        for fk in &create.foreign_keys {
            if fk.from_columns.is_empty() {
                return MutationResult::conflict(format!(
                    "foreign key on relation '{}' has no source columns",
                    create.id
                ));
            }
            if !fk.to_columns.is_empty() && fk.from_columns.len() != fk.to_columns.len() {
                return MutationResult::conflict(format!(
                    "foreign key on '{}' has {} source columns but {} referenced columns",
                    create.id,
                    fk.from_columns.len(),
                    fk.to_columns.len()
                ));
            }
            let mut source_columns = HashSet::new();
            if let Some(column) = fk
                .from_columns
                .iter()
                .find(|column| !source_columns.insert(column.as_str()))
            {
                return MutationResult::conflict(format!(
                    "foreign key on '{}' repeats source column '{}'",
                    create.id, column
                ));
            }
            let mut target_columns = HashSet::new();
            if let Some(column) = fk
                .to_columns
                .iter()
                .find(|column| !target_columns.insert(column.as_str()))
            {
                return MutationResult::conflict(format!(
                    "foreign key on '{}' repeats referenced column '{}'",
                    create.id, column
                ));
            }
            if let Some(column) = fk
                .from_columns
                .iter()
                .find(|name| !column_names.contains(*name))
            {
                return MutationResult::conflict(format!(
                    "foreign key column '{}' does not exist on relation '{}'",
                    column, create.id
                ));
            }
            let target_columns: HashSet<String> = if fk.to_table == create.id {
                column_names.iter().cloned().collect()
            } else {
                if let Err(result) = self.ensure_relation_target(
                    &fk.to_table,
                    |kind| *kind == RelationKind::Table,
                    format!(
                        "foreign key references relation '{}' which does not exist",
                        fk.to_table
                    ),
                    format!(
                        "foreign key references '{}' which is not a table",
                        fk.to_table
                    ),
                ) {
                    return result;
                }
                let Some(RelationOverlay::Present(parent)) = self.local.relations.get(&fk.to_table)
                else {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                };
                parent
                    .columns
                    .iter()
                    .map(|column| column.name.clone())
                    .collect()
            };
            // A scoped/programmatic legacy baseline may omit column facts while
            // retaining the relation identity.  Do not turn that absence into
            // a false column conflict; key/index eligibility is checked
            // separately and remains conservative.
            let target_columns_known =
                !self.baseline_relation_is_known(&fk.to_table) || !target_columns.is_empty();
            if target_columns_known
                && let Some(column) = fk
                    .to_columns
                    .iter()
                    .find(|name| !target_columns.contains(*name))
            {
                return MutationResult::conflict(format!(
                    "foreign key references column '{}.{}' which does not exist",
                    fk.to_table, column
                ));
            }
            let target_keys = if fk.to_table == create.id {
                let mut keys = Vec::new();
                if primary_declarations == 1 {
                    let columns = create
                        .table_constraints
                        .iter()
                        .find_map(|constraint| match constraint {
                            TableConstraintFact::PrimaryKey { columns, .. } => {
                                Some(columns.clone())
                            }
                            _ => None,
                        })
                        .unwrap_or_else(|| {
                            create
                                .columns
                                .iter()
                                .filter(|column| column.is_primary_key)
                                .map(|column| column.name.clone())
                                .collect()
                        });
                    keys.push((columns, true));
                }
                keys.extend(create.table_constraints.iter().filter_map(
                    |constraint| match constraint {
                        TableConstraintFact::Unique { columns, .. } => {
                            Some((columns.clone(), false))
                        }
                        _ => None,
                    },
                ));
                keys.extend(
                    create
                        .columns
                        .iter()
                        .filter(|column| column.is_unique)
                        .map(|column| (vec![column.name.clone()], false)),
                );
                Some(keys)
            } else {
                self.unique_keys_for_relation(&fk.to_table)
            };
            let referenced_columns = if fk.to_columns.is_empty() {
                let primary_keys: Vec<&Vec<String>> = target_keys
                    .as_ref()
                    .map(|keys| {
                        keys.iter()
                            .filter_map(|(columns, primary)| primary.then_some(columns))
                            .collect()
                    })
                    .unwrap_or_default();
                if target_keys.is_some() && primary_keys.len() != 1 {
                    return MutationResult::conflict(format!(
                        "foreign key on '{}' omits referenced columns but target '{}' has no single primary key",
                        create.id, fk.to_table
                    ));
                }
                primary_keys.first().cloned().cloned().unwrap_or_default()
            } else {
                fk.to_columns.clone()
            };
            effective_fk_target_columns.push(referenced_columns.clone());
            if let Some(keys) = target_keys.as_ref()
                && !keys
                    .iter()
                    .any(|(columns, _)| columns == &referenced_columns)
            {
                return MutationResult::conflict(format!(
                    "foreign key on '{}' references columns on '{}' that are not backed by a primary key or unique key",
                    create.id, fk.to_table
                ));
            } else if target_keys.is_none() {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
            let source_types: Vec<Option<(Option<ObjectId>, Option<String>)>> = fk
                .from_columns
                .iter()
                .map(|column| {
                    create
                        .columns
                        .iter()
                        .find(|candidate| candidate.name == *column)
                        .map(|state| {
                            (
                                state
                                    .ty
                                    .as_deref()
                                    .and_then(|raw| self.resolve_type_reference(raw)),
                                state.ty.clone(),
                            )
                        })
                        .or_else(|| {
                            inherited_columns
                                .iter()
                                .find(|candidate| candidate.name == *column)
                                .map(|state| (state.type_id.clone(), state.data_type.clone()))
                        })
                })
                .collect();
            let target_types: Vec<Option<(Option<ObjectId>, Option<String>)>> = if fk.to_table
                == create.id
            {
                referenced_columns
                    .iter()
                    .map(|column| {
                        create
                            .columns
                            .iter()
                            .find(|candidate| candidate.name == *column)
                            .map(|state| {
                                (
                                    state
                                        .ty
                                        .as_deref()
                                        .and_then(|raw| self.resolve_type_reference(raw)),
                                    state.ty.clone(),
                                )
                            })
                            .or_else(|| {
                                inherited_columns
                                    .iter()
                                    .find(|candidate| candidate.name == *column)
                                    .map(|state| (state.type_id.clone(), state.data_type.clone()))
                            })
                    })
                    .collect()
            } else {
                self.local
                    .relations
                    .get(&fk.to_table)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(parent) => Some(
                            referenced_columns
                                .iter()
                                .map(|column| {
                                    parent.get_column(column).map(|state| {
                                        (state.type_id.clone(), state.data_type.clone())
                                    })
                                })
                                .collect(),
                        ),
                        RelationOverlay::Dropped => None,
                    })
                    .unwrap_or_default()
            };
            // Missing type evidence is not a mismatch: taint instead of
            // rejecting a statement PostgreSQL may accept.
            let mut type_evidence_unknown = false;
            let type_mismatch =
                source_types
                    .iter()
                    .zip(&target_types)
                    .any(|(source, target)| match (source, target) {
                        (Some((Some(source_id), _)), Some((Some(target_id), _))) => {
                            source_id != target_id
                        }
                        (Some((_, Some(source_ty))), Some((_, Some(target_ty)))) => {
                            !source_ty.trim().eq_ignore_ascii_case(target_ty.trim())
                        }
                        _ => {
                            type_evidence_unknown = true;
                            false
                        }
                    });
            if type_mismatch {
                return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
            }
            if type_evidence_unknown {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        }

        let resolved_persistence = match create.persistence {
            PersistenceMutation::Permanent => {
                crate::_internal::model::relation::Persistence::Permanent
            }
            PersistenceMutation::Temporary => {
                crate::_internal::model::relation::Persistence::Temporary
            }
            PersistenceMutation::Unlogged => {
                crate::_internal::model::relation::Persistence::Unlogged
            }
        };

        // PostgreSQL chooses all implicit sequence names before the
        // table becomes visible. Reserve them up front so a collision
        // or malformed statement cannot leave partial local state.
        let mut reserved_sequences = HashSet::new();
        let mut implicit_sequences = Vec::new();
        for column in &create.columns {
            let kind = match column.generation {
                crate::_internal::analysis::facts::ColumnGeneration::Serial => {
                    Some(SequenceKind::SerialLike)
                }
                crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
                | crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault => {
                    Some(SequenceKind::Identity)
                }
                crate::_internal::analysis::facts::ColumnGeneration::Ordinary
                | crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => None,
            };
            if let Some(kind) = kind {
                let sequence_id = column
                    .identity_sequence
                    .as_ref()
                    .and_then(|options| options.sequence_name.clone())
                    .unwrap_or_else(|| {
                        self.next_implicit_sequence_id(
                            &create.id,
                            &column.name,
                            &reserved_sequences,
                        )
                    });
                if self.relation_namespace_is_taken(&sequence_id)
                    || reserved_sequences.contains(&sequence_id)
                {
                    return MutationResult::conflict(format!(
                        "relation '{}' already exists",
                        sequence_id
                    ));
                }
                let parameters = if kind == SequenceKind::SerialLike {
                    Self::default_column_sequence_parameters(
                        column.ty.as_deref(),
                        &resolved_persistence,
                    )
                } else {
                    match Self::identity_sequence_parameters(
                        column.ty.as_deref(),
                        &resolved_persistence,
                        column.identity_sequence.as_ref(),
                    ) {
                        Ok(parameters) => parameters,
                        Err(result) => return result,
                    }
                };
                reserved_sequences.insert(sequence_id.clone());
                implicit_sequences.push((sequence_id, column.name.clone(), kind, parameters));
            }
        }
        for (column, _, parameters) in &like_identity_columns {
            let sequence_id =
                self.next_implicit_sequence_id(&create.id, column, &reserved_sequences);
            reserved_sequences.insert(sequence_id.clone());
            implicit_sequences.push((
                sequence_id,
                column.clone(),
                SequenceKind::Identity,
                parameters.clone(),
            ));
        }

        // Resolve every constraint name before mutating the relation. PostgreSQL
        // rejects duplicate names atomically, while a state map would otherwise
        // silently overwrite the earlier inline constraint.
        let mut reserved_constraint_names = HashSet::new();
        let mut reserved_index_ids = HashSet::new();
        for (name, _, _) in &like_check_constraints {
            if !reserved_constraint_names.insert(name.clone()) {
                return MutationResult::conflict(format!(
                    "constraint '{}' is copied more than once",
                    name
                ));
            }
        }
        for (name, _) in &partition_foreign_keys {
            if !reserved_constraint_names.insert(name.clone()) {
                return MutationResult::conflict(format!(
                    "constraint '{}' is inherited more than once",
                    name
                ));
            }
        }
        let primary_key_name = create
            .columns
            .iter()
            .find(|column| column.is_primary_key)
            .map(|column| column.primary_key_constraint_name.clone())
            .or_else(|| {
                create.table_constraints.iter().find_map(|constraint| {
                    if let TableConstraintFact::PrimaryKey {
                        constraint_name, ..
                    } = constraint
                    {
                        Some(constraint_name.clone())
                    } else {
                        None
                    }
                })
            });
        let primary_key_constraint_name = primary_key_name.map(|explicit_name| {
            explicit_name.unwrap_or_else(|| {
                self.next_generated_relation_name_avoiding(
                    &create.id.schema,
                    &create.id.name,
                    None,
                    "pkey",
                    &reserved_index_ids,
                )
                .name
            })
        });
        if let Some(name) = &primary_key_constraint_name
            && !reserved_constraint_names.insert(name.clone())
        {
            return MutationResult::conflict(format!(
                "constraint '{}' is specified more than once",
                name
            ));
        }
        if let Some(name) = &primary_key_constraint_name {
            let index_id = ObjectId::new(&create.id.schema, name);
            if self.relation_namespace_is_taken(&index_id) {
                return MutationResult::conflict(format!("relation '{}' already exists", index_id));
            }
            reserved_index_ids.insert(index_id);
        }

        let unique_constraints = create
            .columns
            .iter()
            .filter(|column| column.is_unique)
            .map(|column| {
                (
                    column.unique_constraint_name.clone(),
                    vec![column.name.clone()],
                )
            })
            .chain(create.table_constraints.iter().filter_map(|constraint| {
                if let TableConstraintFact::Unique {
                    constraint_name,
                    columns,
                } = constraint
                {
                    Some((constraint_name.clone(), columns.clone()))
                } else {
                    None
                }
            }))
            .collect::<Vec<_>>();
        let mut unique_constraint_names = Vec::with_capacity(unique_constraints.len());
        for (explicit_name, columns) in &unique_constraints {
            let name = explicit_name.clone().unwrap_or_else(|| {
                self.next_generated_relation_name_avoiding(
                    &create.id.schema,
                    &create.id.name,
                    Some(&columns.join("_")),
                    "key",
                    &reserved_index_ids,
                )
                .name
            });
            if !reserved_constraint_names.insert(name.clone()) {
                return MutationResult::conflict(format!(
                    "constraint '{}' is specified more than once",
                    name
                ));
            }
            let index_id = ObjectId::new(&create.id.schema, &name);
            if self.relation_namespace_is_taken(&index_id) {
                return MutationResult::conflict(format!("relation '{}' already exists", index_id));
            }
            reserved_index_ids.insert(index_id);
            unique_constraint_names.push((name, columns.clone()));
        }

        let mut foreign_key_constraint_names = Vec::with_capacity(create.foreign_keys.len());
        for fk in &create.foreign_keys {
            let name = fk.constraint_name.clone().unwrap_or_else(|| {
                self.next_generated_constraint_name_avoiding(
                    &create.id,
                    &create.id.name,
                    Some(&fk.from_columns.join("_")),
                    "fkey",
                    &reserved_constraint_names,
                )
            });
            if !reserved_constraint_names.insert(name.clone()) {
                return MutationResult::conflict(format!(
                    "constraint '{}' is specified more than once",
                    name
                ));
            }
            foreign_key_constraint_names.push(name);
        }

        let mut inline_constraint_names = Vec::new();
        for constraint in &create.table_constraints {
            let (kind, explicit_name, name_hint, label, definition, columns, columns_complete) =
                match constraint {
                    TableConstraintFact::Check {
                        constraint_name,
                        name_hint,
                        definition,
                        columns,
                        columns_complete,
                    } => (
                        ConstraintKind::Check,
                        constraint_name,
                        name_hint.clone(),
                        "check",
                        Some(definition.as_str()),
                        columns,
                        columns_complete,
                    ),
                    TableConstraintFact::Exclude {
                        constraint_name,
                        columns,
                        columns_complete,
                    } => (
                        ConstraintKind::Exclusion,
                        constraint_name,
                        (*columns_complete).then(|| columns.join("_")),
                        "excl",
                        None,
                        columns,
                        columns_complete,
                    ),
                    _ => continue,
                };
            let name = explicit_name.clone().unwrap_or_else(|| {
                if matches!(&kind, ConstraintKind::Exclusion) {
                    self.next_generated_relation_name_avoiding(
                        &create.id.schema,
                        &create.id.name,
                        name_hint.as_deref(),
                        label,
                        &reserved_index_ids,
                    )
                    .name
                } else {
                    self.next_generated_constraint_name_avoiding(
                        &create.id,
                        &create.id.name,
                        name_hint.as_deref(),
                        label,
                        &reserved_constraint_names,
                    )
                }
            });
            if !reserved_constraint_names.insert(name.clone()) {
                if matches!(&kind, ConstraintKind::Check)
                    && inherited_check_constraints.get(&name).is_some_and(
                        |(_, inherited_definition)| {
                            definition.is_some_and(|definition| {
                                Self::normalized_constraint_expression(definition)
                                    == Self::normalized_constraint_expression(inherited_definition)
                            })
                        },
                    )
                {
                    continue;
                }
                return MutationResult::conflict(format!(
                    "constraint '{}' is specified more than once",
                    name
                ));
            }
            let backing_index = if matches!(&kind, ConstraintKind::Exclusion) {
                let index_id = ObjectId::new(&create.id.schema, &name);
                if self.relation_namespace_is_taken(&index_id) {
                    return MutationResult::conflict(format!(
                        "relation '{}' already exists",
                        index_id
                    ));
                }
                reserved_index_ids.insert(index_id.clone());
                Some(index_id)
            } else {
                None
            };
            inline_constraint_names.push((
                kind,
                name,
                definition.map(str::to_string),
                columns.clone(),
                *columns_complete,
                backing_index,
            ));
        }

        let mut like_index_plans = Vec::new();
        for (index_kind, constraint) in like_indexes {
            let (name2, label) = match &constraint {
                Some((ConstraintKind::PrimaryKey, _)) => (None, "pkey"),
                Some((ConstraintKind::Unique, columns)) => (Some(columns.join("_")), "key"),
                Some((ConstraintKind::Exclusion, columns)) => (Some(columns.join("_")), "excl"),
                Some(_) => unreachable!("LIKE INDEXES clones only index-backed constraints"),
                None => {
                    let columns = match &index_kind {
                        DependencyKind::IndexOnRelation { definition, .. } => {
                            definition.key_column_names().join("_")
                        }
                        _ => unreachable!("LIKE index plan must contain an index edge"),
                    };
                    ((!columns.is_empty()).then_some(columns), "idx")
                }
            };
            let index_id = loop {
                let candidate = self.next_generated_relation_name_avoiding(
                    &create.id.schema,
                    &create.id.name,
                    name2.as_deref(),
                    label,
                    &reserved_index_ids,
                );
                if constraint.is_none() || !reserved_constraint_names.contains(&candidate.name) {
                    break candidate;
                }
                reserved_index_ids.insert(candidate);
            };
            reserved_index_ids.insert(index_id.clone());
            if constraint.is_some() {
                reserved_constraint_names.insert(index_id.name.clone());
            }
            like_index_plans.push((index_id, index_kind, constraint));
        }

        self.snapshot_relation(&create.id);

        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;

        let mut rel_state = RelationState::new(
            create.id.clone(),
            ObjectId::new("", &self.local.current_role),
            generation,
            if create.as_select { None } else { Some(0) },
            RelationKind::Table,
            resolved_persistence,
            self.local.transactions.len(),
        );
        if matches!(create.persistence, PersistenceMutation::Temporary) {
            self.note_temp_object_created();
        }
        rel_state.on_commit = create.on_commit.map(|action| match action {
            crate::_internal::analysis::mutations::OnCommitMutation::PreserveRows => {
                crate::_internal::model::relation::OnCommitAction::PreserveRows
            }
            crate::_internal::analysis::mutations::OnCommitMutation::DeleteRows => {
                crate::_internal::model::relation::OnCommitAction::DeleteRows
            }
            crate::_internal::analysis::mutations::OnCommitMutation::Drop => {
                crate::_internal::model::relation::OnCommitAction::Drop
            }
        });
        rel_state.of_type = create.of_type.clone();
        rel_state.columns = inherited_columns;
        rel_state.columns_complete =
            sources_complete && (!create.as_select || create.as_select_columns_known);
        rel_state.identity_columns.extend(
            like_identity_columns
                .iter()
                .map(|(column, generation, _)| (column.clone(), *generation)),
        );
        if let Some(parent_id) = &create.partition_of
            && let Some(RelationOverlay::Present(parent)) = self.local.relations.get(parent_id)
        {
            rel_state.identity_columns.extend(
                parent
                    .identity_columns
                    .iter()
                    .map(|(column, generation)| (column.clone(), *generation)),
            );
        }
        rel_state.generated_columns = inherited_generated_columns;
        rel_state.generated_columns.extend(like_generated_columns);
        rel_state.extended_statistics.extend(
            like_extended_statistics
                .into_iter()
                .map(|statistics| (statistics.id.clone(), statistics)),
        );

        if create.as_select && !create.as_select_columns_known {
            // CTAS derives its columns from a query that is intentionally not
            // represented in the current fact model. Keep the relation
            // identity for the destructive-operation rule, but make later
            // column-targeting transitions conservative.
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
        }

        rel_state.partition_type = create.partition_strategy.as_deref().map(str::to_uppercase);
        rel_state.partition_by = create.partition_by.clone();
        rel_state.partition_keys = create.partition_keys.clone();
        rel_state.partition_bound = create
            .partition_bound
            .as_deref()
            .map(canonical_partition_bound);

        let pk_columns: HashSet<&str> = create
            .table_constraints
            .iter()
            .filter_map(|tc| {
                if let TableConstraintFact::PrimaryKey { columns, .. } = tc {
                    Some(columns.iter().map(|s| s.as_str()))
                } else {
                    None
                }
            })
            .flatten()
            .collect();

        let mut not_null_columns: Vec<String> = rel_state
            .columns
            .iter()
            .filter(|column| !column.is_nullable)
            .map(|column| column.name.clone())
            .collect();
        for col in &create.columns {
            if let Some(ty) = &col.ty
                && let Some(conflict) = self.check_declared_type(ty)
            {
                return conflict;
            }
            let is_pk = col.is_primary_key || pk_columns.contains(col.name.as_str());
            if (col.not_null || is_pk) && !not_null_columns.contains(&col.name) {
                not_null_columns.push(col.name.clone());
            }
            rel_state.apply_column_action(&ColumnAction::Add {
                name: col.name.clone(),
                data_type: col.ty.clone(),
                not_null: col.not_null || is_pk,
                default: col.default.clone(),
            });
            if let Some(column) = rel_state
                .columns
                .iter_mut()
                .find(|column| column.name == col.name)
            {
                column.is_nullable &= !(col.not_null || is_pk);
                if col.default.is_some() {
                    column.default = RelationState::normalize_column_default(&col.default);
                    column.default_expr_text = None;
                }
            }
            if let Some(column) = rel_state
                .columns
                .iter_mut()
                .find(|column| column.name == col.name)
            {
                column.type_id = column
                    .data_type
                    .as_deref()
                    .and_then(|raw| self.resolve_type_reference(raw));
                column.type_modifier = col.type_modifier;
                if matches!(
                    col.generation,
                    crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                        | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual
                ) {
                    column.generated = Some(true);
                }
            }
            if matches!(
                col.generation,
                crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                    | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual
            ) {
                rel_state.generated_columns.insert(
                    col.name.clone(),
                    crate::_internal::model::relation::GeneratedColumnState {
                        kind: match col.generation {
                            crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored => {
                                crate::_internal::model::relation::GeneratedColumnKind::Stored
                            }
                            crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => {
                                crate::_internal::model::relation::GeneratedColumnKind::Virtual
                            }
                            _ => unreachable!("generated kind checked above"),
                        },
                        expression: col.generated_expr_sql.clone(),
                    },
                );
            }
            if matches!(
                col.generation,
                crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
                    | crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault
            ) {
                rel_state.identity_columns.insert(
                    col.name.clone(),
                    match col.generation {
                        crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways => {
                            crate::_internal::model::relation::IdentityGeneration::Always
                        }
                        crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault => {
                            crate::_internal::model::relation::IdentityGeneration::ByDefault
                        }
                        _ => unreachable!("identity generation checked above"),
                    },
                );
            }
        }

        for column in &rel_state.columns {
            let parent_count = create
                .inherits
                .iter()
                .chain(create.partition_of.iter())
                .filter(|parent| {
                    matches!(self.local.relations.get(*parent),
                    Some(RelationOverlay::Present(relation)) if relation.has_column(&column.name))
                })
                .count() as u32;
            let is_local = create.partition_of.is_none()
                && create.of_type.is_none()
                && (parent_count == 0
                    || create
                        .columns
                        .iter()
                        .any(|declared| declared.name == column.name));
            rel_state.column_inheritance.insert(
                column.name.clone(),
                crate::_internal::model::relation::ColumnInheritance {
                    parent_count,
                    is_local,
                },
            );
        }

        for (sequence_id, column_name, _, _) in &implicit_sequences {
            if let Some(column) = rel_state
                .columns
                .iter_mut()
                .find(|column| column.name == *column_name)
            {
                column.default = Some(Self::sequence_nextval_default(sequence_id));
                column.default_expr_text = Some(format!(
                    "nextval('{}.{}'::regclass)",
                    sequence_id.schema, sequence_id.name
                ));
                column.is_nullable = false;
            }
        }

        self.local
            .relations
            .insert(create.id.clone(), RelationOverlay::Present(rel_state));

        self.finish_create_table(
            create,
            generation,
            not_null_columns,
            like_dependency_edges,
            like_check_constraints,
            like_index_plans,
            implicit_sequences,
            primary_key_constraint_name,
            unique_constraint_names,
            foreign_key_constraint_names,
            effective_fk_target_columns,
            partition_foreign_keys,
            inline_constraint_names,
        )
    }
}

#[path = "create_table/finish.rs"]
mod finish;
