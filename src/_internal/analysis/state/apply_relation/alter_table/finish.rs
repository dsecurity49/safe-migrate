use super::*;

impl AnalysisState {
    pub(super) fn alter_table_finish(
        &mut self,
        alter: &AlterTable,
        context: AlterTableContext,
    ) -> MutationResult {
        let AlterTableContext {
            recursive_rename_descendants,
            relation_columns_known,
            effective_fk_target_columns,
            implicit_add,
            owned_sequences_for_column,
            drop_column_constraints,
            drop_column_indexes,
            drop_column_statistics,
            cascade_generated_columns,
            cascade_view_roots,
        } = context;
        let action_type_id = match &alter.action {
            AlterTableActionMutation::AddColumn { ty, .. } => ty
                .as_deref()
                .and_then(|raw| self.resolve_type_reference(raw)),
            AlterTableActionMutation::SetType { ty, .. } => self.resolve_type_reference(ty),
            _ => None,
        };
        // Not-null constraint state lives in `self.local.constraints` and the
        // graph, not the relation overlay. Collect the transitions applied to
        // `rel` here and replay them once the `rel` borrow (below) is released
        // so the `&mut self` calls do not contend with the overlay borrow.
        let mut deferred_not_null: Vec<(String, bool)> = Vec::new();
        // Before the overlay borrow: tainting needs `&mut self`.
        if let AlterTableActionMutation::SetType { ty, .. } = &alter.action
            && let Some(conflict) = self.check_declared_type(ty)
        {
            return conflict;
        }
        // Resolved before the mutable borrow below, which the catalogue lookup
        // cannot coexist with.
        let declared_type_modifier = match &alter.action {
            AlterTableActionMutation::SetType { ty, .. } => {
                ParsedDataType::parse(ty, self.builtin_types()).atttypmod()
            }
            _ => None,
        };
        // Reloption validation reads the target's catalogue kind and taints,
        // both of which the overlay borrow below would otherwise block.
        match &alter.action {
            AlterTableActionMutation::SetTableOptions { attributes } => {
                if let Err(result) = self.validate_alter_table_set_options(&alter.id, attributes) {
                    return result;
                }
            }
            AlterTableActionMutation::ResetTableOptions { attributes } => {
                if let Err(result) = self.validate_alter_table_reset_options(&alter.id, attributes)
                {
                    return result;
                }
            }
            AlterTableActionMutation::SetColumnOptions { attributes, .. } => {
                if let Err(result) = self.validate_column_options(attributes) {
                    return result;
                }
            }
            AlterTableActionMutation::ResetColumnOptions { attributes, .. } => {
                if let Err(result) = self.validate_column_reset_options(attributes) {
                    return result;
                }
            }
            _ => {}
        }

        let rel_overlay = self.local.relations.get_mut(&alter.id);
        #[allow(clippy::collapsible_if)]
        if let Some(RelationOverlay::Present(rel)) = rel_overlay {
            let generation = rel.generation;
            match &alter.action {
                AlterTableActionMutation::AddColumn {
                    name,
                    ty,
                    if_not_exists,
                    not_null,
                    default,
                    depends_on,
                    generation,
                    identity_sequence: _,
                    generated_expr,
                    generated_expr_sql,
                } => {
                    if let Some(existing_col) = rel.columns.iter().find(|c| c.name == *name) {
                        if *if_not_exists {
                            return MutationResult::NoOp;
                        }
                        return MutationResult::conflict(format!(
                            "column '{}' already exists with type {}; this statement adds it again with type {}",
                            name,
                            existing_col.data_type.as_deref().unwrap_or("unknown"),
                            ty.as_deref().unwrap_or("unknown")
                        ));
                    }
                    rel.apply_column_action(&ColumnAction::Add {
                        name: name.clone(),
                        data_type: ty.clone(),
                        not_null: *not_null,
                        default: default.clone(),
                    });
                    if *not_null {
                        deferred_not_null.push((name.clone(), true));
                    }
                    if let Some(column) = rel.columns.iter_mut().find(|column| column.name == *name)
                    {
                        column.type_id = action_type_id.clone();
                        if matches!(
                            generation,
                            crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                                | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual
                        ) {
                            column.generated = Some(true);
                        }
                    }
                    match generation {
                        crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                        | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => {
                            rel.generated_columns.insert(
                                name.clone(),
                                crate::_internal::model::relation::GeneratedColumnState {
                                    kind: match generation {
                                        crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored => crate::_internal::model::relation::GeneratedColumnKind::Stored,
                                        crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => crate::_internal::model::relation::GeneratedColumnKind::Virtual,
                                        _ => unreachable!("generated kind checked above"),
                                    },
                                    expression: generated_expr_sql.clone(),
                                },
                            );
                        }
                        crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways => {
                            rel.identity_columns.insert(
                                name.clone(),
                                crate::_internal::model::relation::IdentityGeneration::Always,
                            );
                        }
                        crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault => {
                            rel.identity_columns.insert(
                                name.clone(),
                                crate::_internal::model::relation::IdentityGeneration::ByDefault,
                            );
                        }
                        _ => {}
                    }

                    if let Some((sequence_id, column_name, _, _)) = &implicit_add
                        && column_name == name
                        && let Some(column) =
                            rel.columns.iter_mut().find(|column| column.name == *name)
                    {
                        column.default = Some(Self::sequence_nextval_default(sequence_id));
                        column.default_expr_text = Some(format!(
                            "nextval('{}.{}'::regclass)",
                            sequence_id.schema, sequence_id.name
                        ));
                        column.is_nullable = false;
                    }

                    if let Some((source_table, source_col)) = depends_on {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            alter.id.clone(),
                            source_table.clone(),
                            DependencyKind::ColumnGeneratedFrom {
                                column: name.clone(),
                                depends_on_column: source_col.clone(),
                            },
                        ));
                    }
                    if let Some(expr) = generated_expr
                        && let Some(references) = expr.referenced_columns()
                    {
                        self.snapshot_graph();
                        for depends_on_column in references {
                            self.local.graph.add_edge(DependencyEdge::new(
                                alter.id.clone(),
                                alter.id.clone(),
                                DependencyKind::ColumnGeneratedFrom {
                                    column: name.clone(),
                                    depends_on_column,
                                },
                            ));
                        }
                    }
                }
                AlterTableActionMutation::DropColumn {
                    name, if_exists, ..
                } => {
                    if !rel.has_column(name) {
                        if *if_exists {
                            // Column doesn't exist and IF EXISTS was specified: no-op
                            return MutationResult::NoOp;
                        }
                        return MutationResult::conflict(format!(
                            "column '{}' does not exist on relation '{}'",
                            name, alter.id
                        ));
                    }
                    rel.apply_column_action(&ColumnAction::Drop { name: name.clone() });
                    if !drop_column_statistics.is_empty() {
                        rel.extended_statistics
                            .retain(|id, _| !drop_column_statistics.contains(id));
                    }
                    for generated_column in &cascade_generated_columns {
                        if rel.has_column(generated_column) {
                            rel.apply_column_action(&ColumnAction::Drop {
                                name: generated_column.clone(),
                            });
                        }
                    }
                }
                AlterTableActionMutation::RenameColumn { from, to } => {
                    rel.apply_column_action(&ColumnAction::Rename {
                        from: from.clone(),
                        to: to.clone(),
                    });
                }
                AlterTableActionMutation::SetNotNull { column } => {
                    rel.apply_column_action(&ColumnAction::SetNotNull {
                        name: column.clone(),
                    });
                    deferred_not_null.push((column.clone(), true));
                }
                AlterTableActionMutation::DropNotNull { column } => {
                    rel.apply_column_action(&ColumnAction::DropNotNull {
                        name: column.clone(),
                    });
                    deferred_not_null.push((column.clone(), false));
                }
                AlterTableActionMutation::SetType { column, ty, .. } => {
                    rel.apply_column_action(&ColumnAction::SetType {
                        name: column.clone(),
                        data_type: ty.clone(),
                    });
                    if let Some(col) = rel.columns.iter_mut().find(|entry| entry.name == *column) {
                        col.type_id = action_type_id.clone();
                        // Keep type_modifier in sync with the new DDL-declared type so
                        // partition-column compatibility checks (which compare type_modifier
                        // between parent and child columns) remain correct after a type change.
                        col.type_modifier = declared_type_modifier;
                    }
                }
                AlterTableActionMutation::SetDefault { column, default } => {
                    rel.apply_column_action(&ColumnAction::SetDefault {
                        name: column.clone(),
                        default: default.clone(),
                    });
                }
                AlterTableActionMutation::SetStorage { column, mode } => {
                    rel.apply_column_action(&ColumnAction::SetStorage {
                        name: column.clone(),
                        mode: mode.clone(),
                    });
                }
                AlterTableActionMutation::SetCompression { column, method } => {
                    rel.apply_column_action(&ColumnAction::SetCompression {
                        name: column.clone(),
                        method: method.clone(),
                    });
                }
                AlterTableActionMutation::SetStatistics { column, target } => {
                    rel.apply_column_action(&ColumnAction::SetStatistics {
                        name: column.clone(),
                        target: *target,
                    });
                }
                AlterTableActionMutation::SetColumnOptions { column, attributes } => {
                    rel.apply_column_action(&ColumnAction::SetOptions {
                        name: column.clone(),
                        options: attributes
                            .iter()
                            .map(|attribute| {
                                (
                                    attribute.key(),
                                    attribute
                                        .value
                                        .clone()
                                        .unwrap_or_else(|| "true".to_string()),
                                )
                            })
                            .collect(),
                    });
                }
                AlterTableActionMutation::ResetColumnOptions { column, attributes } => {
                    rel.apply_column_action(&ColumnAction::ResetOptions {
                        name: column.clone(),
                        names: attributes.iter().map(|attribute| attribute.key()).collect(),
                    });
                }
                AlterTableActionMutation::DropGeneratedExpression { column, .. } => {
                    if let Some(entry) = rel.columns.iter_mut().find(|entry| entry.name == *column)
                    {
                        entry.generated = Some(false);
                    }
                    rel.generated_columns.remove(column);
                }
                AlterTableActionMutation::AddForeignKey {
                    constraint_name,
                    to_table,
                    from_columns,
                    to_columns,
                    not_valid,
                } => {
                    let constraint_name = constraint_name.clone().unwrap_or_else(|| {
                        self.next_generated_constraint_name_avoiding(
                            &alter.id,
                            &alter.id.name,
                            Some(&from_columns.join("_")),
                            "fkey",
                            &HashSet::new(),
                        )
                    });
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::ForeignKey,
                            validated: !not_valid,
                            definition: None,
                            backing_index: None,
                        },
                    );
                    if *not_valid {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .insert((alter.id.clone(), constraint_name.clone()));
                    }
                    self.snapshot_graph();
                    self.local.graph.add_edge(DependencyEdge::new(
                        alter.id.clone(),
                        to_table.clone(),
                        DependencyKind::ForeignKey {
                            constraint_name: Some(constraint_name),
                            from_columns: from_columns.clone(),
                            to_columns: effective_fk_target_columns
                                .clone()
                                .unwrap_or_else(|| to_columns.clone()),
                            operator_evidence: None,
                            from_generation: generation,
                        },
                    ));
                }
                AlterTableActionMutation::DropConstraint { name, .. } => {
                    self.snapshot_constraint(&alter.id, name);
                    let removed_constraint = self
                        .local
                        .constraints
                        .remove(&(alter.id.clone(), name.clone()));
                    if let Some(index) = removed_constraint
                        .as_ref()
                        .filter(|constraint| {
                            matches!(
                                constraint.kind,
                                ConstraintKind::PrimaryKey
                                    | ConstraintKind::Unique
                                    | ConstraintKind::Exclusion
                            )
                        })
                        .and_then(|constraint| constraint.backing_index.as_ref())
                    {
                        self.snapshot_relation(&alter.id);
                        if let Some(RelationOverlay::Present(relation)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            relation.clear_index_settings(&index.name);
                        }
                        self.snapshot_graph_full();
                        self.local.graph.retain_edges(|edge| {
                            !(edge.dependent == *index
                                && matches!(edge.kind, DependencyKind::IndexOnRelation { .. }))
                        });
                    }
                    if let Some(ref c) = removed_constraint
                        && c.kind == crate::_internal::model::constraint::ConstraintKind::NotNull
                    {
                        // A not-null constraint guards exactly one column; PG18
                        // allows it to be dropped by name like any other
                        // constraint, which releases the column's nullability.
                        let resolution_graph = self.local.graph.clone();
                        let guarded_column: Option<String> =
                            self.local.graph.edges().iter().find_map(|edge| {
                                if resolution_graph.resolve_rename(&edge.dependent) != &alter.id {
                                    return None;
                                }
                                if let DependencyKind::ConstraintOnRelation {
                                    constraint_name,
                                    columns,
                                    is_primary: false,
                                    ..
                                } = &edge.kind
                                    && constraint_name == name
                                    && columns.len() == 1
                                {
                                    Some(columns[0].clone())
                                } else {
                                    None
                                }
                            });
                        if let Some(column) = guarded_column {
                            self.snapshot_relation(&alter.id);
                            if let Some(RelationOverlay::Present(rel)) =
                                self.local.relations.get_mut(&alter.id)
                            {
                                if let Some(col) = rel.columns.iter_mut().find(|c| c.name == column)
                                {
                                    col.is_nullable = true;
                                }
                            }
                        }
                    }
                    if self
                        .local
                        .pending_validation
                        .contains(&(alter.id.clone(), name.clone()))
                    {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .remove(&(alter.id.clone(), name.clone()));
                    }
                    if self
                        .baseline_foreign_keys
                        .contains(&(alter.id.clone(), name.clone()))
                    {
                        self.snapshot_baseline_foreign_keys();
                        self.baseline_foreign_keys
                            .remove(&(alter.id.clone(), name.clone()));
                    }
                    self.snapshot_graph_full();
                    let resolution_graph = self.local.graph.clone();
                    self.local.graph.retain_edges(|e| {
                        let dependent = resolution_graph.resolve_rename(&e.dependent);
                        match &e.kind {
                            DependencyKind::ForeignKey {
                                constraint_name, ..
                            } => {
                                !(dependent == &alter.id && constraint_name.as_ref() == Some(name))
                            }
                            DependencyKind::ConstraintOnRelation {
                                constraint_name, ..
                            } => !(dependent == &alter.id && constraint_name == name),
                            DependencyKind::ConstraintDependency {
                                constraint_name, ..
                            } => !(dependent == &alter.id && constraint_name == name),
                            _ => true,
                        }
                    });
                }
                AlterTableActionMutation::RenameConstraint { old_name, new_name } => {
                    self.snapshot_constraint(&alter.id, old_name);
                    self.snapshot_constraint(&alter.id, new_name);
                    if let Some(mut constraint) = self
                        .local
                        .constraints
                        .remove(&(alter.id.clone(), old_name.clone()))
                    {
                        constraint.name = new_name.clone();
                        self.local
                            .constraints
                            .insert((alter.id.clone(), new_name.clone()), constraint);
                    }
                    if self
                        .local
                        .pending_validation
                        .contains(&(alter.id.clone(), old_name.clone()))
                    {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .remove(&(alter.id.clone(), old_name.clone()));
                        self.local
                            .pending_validation
                            .insert((alter.id.clone(), new_name.clone()));
                    }
                    if self
                        .baseline_foreign_keys
                        .contains(&(alter.id.clone(), old_name.clone()))
                    {
                        self.snapshot_baseline_foreign_keys();
                        self.baseline_foreign_keys
                            .remove(&(alter.id.clone(), old_name.clone()));
                        self.baseline_foreign_keys
                            .insert((alter.id.clone(), new_name.clone()));
                    }
                    self.snapshot_graph_full();
                    self.local
                        .graph
                        .rename_constraint(&alter.id, old_name, new_name);
                }
                AlterTableActionMutation::AddCheckConstraint {
                    constraint_name,
                    definition,
                    columns,
                    columns_complete,
                    not_valid,
                } => {
                    let constraint_name = constraint_name.clone().unwrap_or_else(|| {
                        self.next_generated_constraint_name_avoiding(
                            &alter.id,
                            &alter.id.name,
                            (*columns_complete && columns.len() == 1).then(|| columns[0].as_str()),
                            "check",
                            &HashSet::new(),
                        )
                    });
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::Check,
                            validated: !not_valid,
                            definition: Some(definition.clone()),
                            backing_index: None,
                        },
                    );
                    if *not_valid {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .insert((alter.id.clone(), constraint_name.clone()));
                    }
                    if !relation_columns_known || !columns_complete {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            alter.id.clone(),
                            alter.id.clone(),
                            DependencyKind::ConstraintDependency {
                                constraint_name,
                                columns: columns.clone(),
                            },
                        ));
                    }
                }
                AlterTableActionMutation::AddUniqueConstraint {
                    constraint_name,
                    columns,
                    using_index,
                } => {
                    let constraint_name = constraint_name
                        .clone()
                        .or_else(|| using_index.as_ref().map(|index| index.name.clone()))
                        .unwrap_or_else(|| {
                            self.next_generated_relation_name_avoiding(
                                &alter.id.schema,
                                &alter.id.name,
                                Some(&columns.join("_")),
                                "key",
                                &HashSet::new(),
                            )
                            .name
                        });
                    let backing_index = Some(ObjectId::new(&alter.id.schema, &constraint_name));
                    if let Some(index) = using_index {
                        self.adopt_index_for_constraint(index, &alter.id, &constraint_name);
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            ObjectId::new(&alter.id.schema, &constraint_name),
                            alter.id.clone(),
                            Self::constraint_index_dependency(columns.clone(), true),
                        ));
                    }
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::Unique,
                            validated: true,
                            definition: None,
                            backing_index,
                        },
                    );
                    if columns.is_empty() || !relation_columns_known {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            alter.id.clone(),
                            alter.id.clone(),
                            DependencyKind::ConstraintOnRelation {
                                constraint_name,
                                columns: columns.clone(),
                                is_primary: false,
                            },
                        ));
                    }
                }
                AlterTableActionMutation::AddPrimaryKeyConstraint {
                    constraint_name,
                    columns,
                    using_index,
                } => {
                    let constraint_name = constraint_name
                        .clone()
                        .or_else(|| using_index.as_ref().map(|index| index.name.clone()))
                        .unwrap_or_else(|| {
                            self.next_generated_relation_name_avoiding(
                                &alter.id.schema,
                                &alter.id.name,
                                None,
                                "pkey",
                                &HashSet::new(),
                            )
                            .name
                        });
                    let backing_index = Some(ObjectId::new(&alter.id.schema, &constraint_name));
                    if let Some(index) = using_index {
                        self.adopt_index_for_constraint(index, &alter.id, &constraint_name);
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            ObjectId::new(&alter.id.schema, &constraint_name),
                            alter.id.clone(),
                            Self::constraint_index_dependency(columns.clone(), true),
                        ));
                    }
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::PrimaryKey,
                            validated: true,
                            definition: None,
                            backing_index,
                        },
                    );
                    if columns.is_empty() || !relation_columns_known {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            alter.id.clone(),
                            alter.id.clone(),
                            DependencyKind::ConstraintOnRelation {
                                constraint_name,
                                columns: columns.clone(),
                                is_primary: true,
                            },
                        ));
                        for column in columns.iter() {
                            if let Some(RelationOverlay::Present(relation)) =
                                self.local.relations.get_mut(&alter.id)
                            {
                                relation.apply_column_action(&ColumnAction::SetNotNull {
                                    name: column.clone(),
                                });
                            }
                            self.register_not_null_constraint(&alter.id, column);
                        }
                    }
                }
                AlterTableActionMutation::AddExcludeConstraint {
                    constraint_name,
                    columns,
                    columns_complete,
                } => {
                    let constraint_name = constraint_name.clone().unwrap_or_else(|| {
                        let name2 = (*columns_complete).then(|| columns.join("_"));
                        self.next_generated_relation_name_avoiding(
                            &alter.id.schema,
                            &alter.id.name,
                            name2.as_deref(),
                            "excl",
                            &HashSet::new(),
                        )
                        .name
                    });
                    let backing_index = ObjectId::new(&alter.id.schema, &constraint_name);
                    if self.relation_namespace_is_taken(&backing_index) {
                        return MutationResult::conflict(format!(
                            "relation '{}' already exists",
                            backing_index
                        ));
                    }
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::Exclusion,
                            validated: true,
                            definition: None,
                            backing_index: Some(backing_index.clone()),
                        },
                    );
                    if !relation_columns_known || !columns_complete {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    } else {
                        self.snapshot_graph_full();
                        self.local.graph.add_edge(DependencyEdge::new(
                            backing_index,
                            alter.id.clone(),
                            DependencyKind::IndexOnRelation {
                                definition: IndexDefinition {
                                    method: None,
                                    keys: index_keys(columns.clone()),
                                    included: index_keys(Vec::new()),
                                    expression_keys: 0,
                                    unique: false,
                                    nulls_not_distinct: Some(false),
                                    predicate: IndexPredicate::None,
                                    // An exclusion constraint's backing index shape
                                    // is not established from the constraint columns
                                    // alone.
                                    unestablished: true,
                                    valid: true,
                                    ready: true,
                                    live: true,
                                },
                                dependency_columns: columns.clone(),
                                dependency_columns_known: true,
                                is_concurrent: false,
                                is_immediate: true,
                                eligibility_known: false,
                            },
                        ));
                        self.local.graph.add_edge(DependencyEdge::new(
                            alter.id.clone(),
                            alter.id.clone(),
                            DependencyKind::ConstraintDependency {
                                constraint_name,
                                columns: columns.clone(),
                            },
                        ));
                    }
                }
                AlterTableActionMutation::ValidateConstraint { constraint_name } => {
                    self.snapshot_constraint(&alter.id, constraint_name);
                    if let Some(constraint) = self
                        .local
                        .constraints
                        .get_mut(&(alter.id.clone(), constraint_name.clone()))
                    {
                        constraint.validated = true;
                    }
                    if self
                        .local
                        .pending_validation
                        .contains(&(alter.id.clone(), constraint_name.clone()))
                    {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .remove(&(alter.id.clone(), constraint_name.clone()));
                    }
                }
                AlterTableActionMutation::AttachPartition { child, .. } => {
                    // Validation above rejects cyclic attachments before state mutation.
                    if self.local.graph.check_partition_cycle(&alter.id, child) {
                        return MutationResult::conflict(format!(
                            "attaching partition '{}' to '{}' would create a partition cycle",
                            child, alter.id
                        ));
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            child.clone(),
                            alter.id.clone(),
                            DependencyKind::PartitionOf,
                        ));
                    }
                }
                AlterTableActionMutation::DetachPartition { child, mode } => {
                    self.snapshot_graph_full();
                    match mode {
                        crate::_internal::analysis::facts::DetachPartitionMode::Immediate
                        | crate::_internal::analysis::facts::DetachPartitionMode::Finalize => {
                            let kind = match mode {
                                crate::_internal::analysis::facts::DetachPartitionMode::Immediate => {
                                    DependencyKind::PartitionOf
                                }
                                crate::_internal::analysis::facts::DetachPartitionMode::Finalize => {
                                    DependencyKind::PartitionDetachPending
                                }
                                crate::_internal::analysis::facts::DetachPartitionMode::Concurrently => {
                                    unreachable!("concurrent detach is handled separately")
                                }
                            };
                            self.local.graph.retain_edges(|edge| {
                                !(edge.kind == kind
                                    && edge.dependent == *child
                                    && edge.referenced == alter.id)
                            });
                        }
                        crate::_internal::analysis::facts::DetachPartitionMode::Concurrently => {
                            self.local.graph.retain_edges(|edge| {
                                !(matches!(edge.kind, DependencyKind::PartitionOf)
                                    && edge.dependent == *child
                                    && edge.referenced == alter.id)
                            });
                            // PostgreSQL retains a CHECK duplicating the
                            // partition predicate on concurrent detach
                            // (DetachAddConstraintIfNeeded). Reproduce its
                            // exact deparse; otherwise stay conservative.
                            match self.retained_check_for_detached_partition(&alter.id, child) {
                                RetainedCheckSynthesis::NoCheck => {}
                                RetainedCheckSynthesis::CantResolve => {
                                    self.taint(
                                        EvidenceCode::UnsupportedSemantics,
                                        EvidenceScope::Chain,
                                    );
                                }
                                RetainedCheckSynthesis::Definition(definition) => {
                                    self.register_retained_partition_check(child, definition);
                                }
                            }
                        }
                    }
                }
                AlterTableActionMutation::InheritTable { parent } => {
                    self.snapshot_graph();
                    self.local.graph.add_edge(DependencyEdge::new(
                        alter.id.clone(),
                        parent.clone(),
                        DependencyKind::InheritanceOf,
                    ));
                }
                AlterTableActionMutation::NoInheritTable { parent } => {
                    self.snapshot_graph_full();
                    self.local.graph.retain_edges(|edge| {
                        !(edge.dependent == alter.id
                            && edge.referenced == *parent
                            && matches!(edge.kind, DependencyKind::InheritanceOf))
                    });
                }
                AlterTableActionMutation::SetTablespace { tablespace } => {
                    rel.tablespace = Some(tablespace.clone());
                }
                AlterTableActionMutation::SetAccessMethod { access_method } => {
                    rel.access_method = access_method.clone();
                }
                AlterTableActionMutation::SetPersistence { persistence } => {
                    rel.persistence = persistence.clone();
                }
                AlterTableActionMutation::SetCluster { index } => {
                    rel.cluster_index = index.as_ref().map(|index| index.name.clone());
                }
                AlterTableActionMutation::SetRowSecurity { enabled } => {
                    rel.row_security = Some(*enabled);
                }
                AlterTableActionMutation::SetForceRowSecurity { enabled } => {
                    rel.force_row_security = Some(*enabled);
                }
                AlterTableActionMutation::SetReplicaIdentity { option } => {
                    rel.replica_identity = Some(match option {
                        crate::_internal::analysis::mutations::ReplicaIdentityMutation::Default =>
                            "DEFAULT".to_string(),
                        crate::_internal::analysis::mutations::ReplicaIdentityMutation::Full =>
                            "FULL".to_string(),
                        crate::_internal::analysis::mutations::ReplicaIdentityMutation::Nothing =>
                            "NOTHING".to_string(),
                        crate::_internal::analysis::mutations::ReplicaIdentityMutation::UsingIndex(index) =>
                            format!("USING INDEX {}", index.name),
                    });
                }
                AlterTableActionMutation::SetOfType { type_id } => {
                    rel.of_type = type_id.clone();
                }
                AlterTableActionMutation::SetTableOptions { attributes } => {
                    crate::_internal::analysis::state::apply_view_index::store_relation_options(
                        &mut rel.table_options,
                        attributes,
                    );
                }
                AlterTableActionMutation::ResetTableOptions { attributes } => {
                    for attribute in attributes {
                        rel.table_options.remove(&attribute.key());
                    }
                }
                AlterTableActionMutation::SetGeneratedExpression {
                    column,
                    expression_sql,
                    ..
                } => {
                    if let Some(generated) = rel.generated_columns.get_mut(column) {
                        generated.expression = Some(expression_sql.clone());
                    }
                }
                AlterTableActionMutation::AlterColumnInheritance
                | AlterTableActionMutation::PartitionReshape => {
                    // These forms have a typed parse but change physical or
                    // inheritance metadata that RelationState cannot yet
                    // represent. Never leave subsequent statements exact.
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                }
                _ => {}
            }
        }
        for (column, register) in deferred_not_null {
            if register {
                self.register_not_null_constraint(&alter.id, &column);
            } else {
                self.drop_not_null_constraint(&alter.id, &column);
            }
        }
        match &alter.action {
            AlterTableActionMutation::InheritTable { parent }
            | AlterTableActionMutation::NoInheritTable { parent } => {
                let columns = match self.local.relations.get(parent) {
                    Some(RelationOverlay::Present(parent)) => parent
                        .columns
                        .iter()
                        .map(|column| column.name.clone())
                        .collect::<Vec<_>>(),
                    _ => Vec::new(),
                };
                let adding = matches!(alter.action, AlterTableActionMutation::InheritTable { .. });
                let mut incomplete = false;
                self.snapshot_relation(&alter.id);
                if let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(&alter.id)
                {
                    for column in columns {
                        let Some(provenance) = relation.column_inheritance.get_mut(&column) else {
                            incomplete = true;
                            continue;
                        };
                        let count = if adding {
                            provenance.parent_count.checked_add(1)
                        } else {
                            provenance.parent_count.checked_sub(1)
                        };
                        if let Some(count) = count {
                            provenance.parent_count = count;
                            if count == 0 {
                                provenance.is_local = true;
                            }
                        } else {
                            relation.column_inheritance.remove(&column);
                            incomplete = true;
                        }
                    }
                }
                if incomplete {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
            }
            AlterTableActionMutation::AttachPartition { child, bound, .. } => {
                self.invalidate_descendant_partition_predicates(child);
                let canonical_bound = bound.as_deref().map(canonical_partition_bound);
                let generated_partition_constraint = self
                    .local
                    .relations
                    .get(child)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => Some(relation),
                        RelationOverlay::Dropped => None,
                    })
                    .and_then(|relation| {
                        let parent_strategy = self.local.relations.get(&alter.id).and_then(
                            |overlay| match overlay {
                                RelationOverlay::Present(parent) => {
                                    parent.partition_type.as_deref()
                                }
                                RelationOverlay::Dropped => None,
                            },
                        )?;
                        let keys = self.partition_key_columns(&alter.id)?;
                        if canonical_bound
                            .as_deref()
                            .is_some_and(|value| value.eq_ignore_ascii_case("DEFAULT"))
                        {
                            return self.synthesize_default_partition_constraint(&alter.id);
                        }
                        self.synthesize_partition_check(
                            parent_strategy,
                            canonical_bound.as_deref()?,
                            &keys,
                            relation,
                        )
                    });
                self.snapshot_relation(child);
                if let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(child)
                {
                    relation.partition_bound = canonical_bound;
                    relation.partition_constraint = generated_partition_constraint;
                    for column in &relation.columns {
                        relation.column_inheritance.insert(
                            column.name.clone(),
                            crate::_internal::model::relation::ColumnInheritance {
                                parent_count: 1,
                                is_local: false,
                            },
                        );
                    }
                }
                self.refresh_default_partition_constraints(&alter.id);
                self.ensure_partition_indexes_and_constraints(&alter.id, child);
                let result = self.clone_row_triggers_to_partition(&alter.id, child);
                debug_assert!(matches!(result, MutationResult::Applied));
                if !matches!(result, MutationResult::Applied) {
                    return result;
                }
            }
            AlterTableActionMutation::DetachPartition { child, .. } => {
                // The retained CHECK for a concurrent detach is synthesized in
                // the apply arm; this block only resets partition metadata.
                self.invalidate_descendant_partition_predicates(child);
                self.snapshot_relation(child);
                if let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(child)
                {
                    relation.partition_bound = None;
                    relation.partition_constraint = None;
                    for column in &relation.columns {
                        relation.column_inheritance.insert(
                            column.name.clone(),
                            crate::_internal::model::relation::ColumnInheritance {
                                parent_count: 0,
                                is_local: true,
                            },
                        );
                    }
                }
                self.remove_partition_trigger_clones(&alter.id, child);
            }
            _ => {}
        }
        if let AlterTableActionMutation::SetDefault { column, default } = &alter.action {
            self.snapshot_graph_full();
            self.local.graph.retain_edges(|edge| {
                !matches!(
                    &edge.kind,
                    DependencyKind::ColumnDefaultOnSequence { column: edge_column }
                        if edge.dependent == alter.id && edge_column == column
                )
            });
            if let Some(default) = default {
                let matching_sequences = self
                    .local
                    .sequences
                    .iter()
                    .filter_map(|(id, overlay)| {
                        matches!(overlay, SequenceOverlay::Present(_)).then_some(id.clone())
                    })
                    .filter(|id| Self::expression_references_sequence(default, id))
                    .collect::<Vec<_>>();
                match matching_sequences.as_slice() {
                    [sequence] => self.local.graph.add_edge(DependencyEdge::new(
                        alter.id.clone(),
                        sequence.clone(),
                        DependencyKind::ColumnDefaultOnSequence {
                            column: column.clone(),
                        },
                    )),
                    [] if Self::expression_contains_nextval(default) => self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    ),
                    _ => self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    ),
                }
            }
        }
        match &alter.action {
            AlterTableActionMutation::SetGeneratedExpression { column, expr, .. } => {
                let references = expr
                    .referenced_columns()
                    .expect("generated expression was validated before state mutation");
                self.snapshot_graph_full();
                self.local.graph.retain_edges(|edge| {
                    !matches!(
                        &edge.kind,
                        DependencyKind::ColumnGeneratedFrom { column: generated_column, .. }
                            if edge.dependent == alter.id
                                && edge.referenced == alter.id
                                && generated_column == column
                    )
                });
                for source_column in references {
                    self.local.graph.add_edge(DependencyEdge::new(
                        alter.id.clone(),
                        alter.id.clone(),
                        DependencyKind::ColumnGeneratedFrom {
                            column: column.clone(),
                            depends_on_column: source_column,
                        },
                    ));
                }
            }
            AlterTableActionMutation::DropGeneratedExpression { column, .. } => {
                self.snapshot_graph_full();
                self.local.graph.retain_edges(|edge| {
                    !matches!(
                        &edge.kind,
                        DependencyKind::ColumnGeneratedFrom { column: generated_column, .. }
                            if edge.dependent == alter.id
                                && edge.referenced == alter.id
                                && generated_column == column
                    )
                });
            }
            _ => {}
        }
        if let AlterTableActionMutation::RenameColumn { from, to } = &alter.action {
            self.rename_relation_column_metadata(&alter.id, from, to);
            for descendant in recursive_rename_descendants {
                self.rename_relation_column_metadata(&descendant, from, to);
            }

            // Publication column lists are catalog identities, not merely
            // display text. PostgreSQL follows a renamed column in an
            // explicit publication list, so keep the modeled scope aligned.
            let publication_updates: Vec<(String, Vec<usize>)> = self
                .local
                .publications
                .iter()
                .filter_map(|(name, overlay)| {
                    let crate::_internal::model::replication::PublicationOverlay::Present(publication) =
                        overlay
                    else {
                        return None;
                    };
                    let indexes = match &publication.scope {
                        crate::_internal::analysis::facts::PublicationScope::Explicit(objects) => objects
                            .iter()
                            .enumerate()
                            .filter_map(|(index, object)| {
                                let crate::_internal::analysis::facts::PublicationObjectFact::Table {
                                    name: table_name,
                                    columns: Some(columns),
                                    ..
                                } = object
                                else {
                                    return None;
                                };
                                (self.resolve_relation_id(table_name) == alter.id
                                    && columns.iter().any(|column| column == from))
                                .then_some(index)
                            })
                            .collect::<Vec<_>>(),
                        _ => Vec::new(),
                    };
                    (!indexes.is_empty()).then(|| (name.clone(), indexes))
                })
                .collect();
            for (publication_name, object_indexes) in publication_updates {
                self.snapshot_publication(&publication_name);
                if let Some(crate::_internal::model::replication::PublicationOverlay::Present(
                    publication,
                )) = self.local.publications.get_mut(&publication_name)
                    && let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                        &mut publication.scope
                {
                    for index in object_indexes {
                        if let Some(
                            crate::_internal::analysis::facts::PublicationObjectFact::Table {
                                columns: Some(columns),
                                ..
                            },
                        ) = objects.get_mut(index)
                        {
                            for column in columns {
                                if column == from {
                                    *column = to.clone();
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some((sequence_id, column_name, kind, identity_options)) = implicit_add {
            let (column_type, persistence) = self
                .local
                .relations
                .get(&alter.id)
                .and_then(|overlay| match overlay {
                    RelationOverlay::Present(table) => Some((
                        table
                            .get_column(&column_name)
                            .and_then(|column| column.data_type.clone()),
                        table.persistence.clone(),
                    )),
                    RelationOverlay::Dropped => None,
                })
                .unwrap_or((
                    None,
                    crate::_internal::model::relation::Persistence::Permanent,
                ));
            let parameters = if kind == SequenceKind::SerialLike {
                Self::default_column_sequence_parameters(column_type.as_deref(), &persistence)
            } else {
                match Self::identity_sequence_parameters(
                    column_type.as_deref(),
                    &persistence,
                    identity_options.as_ref(),
                ) {
                    Ok(parameters) => parameters,
                    Err(result) => return result,
                }
            };
            self.snapshot_sequence(&sequence_id);
            self.snapshot_generation_counter();
            self.local.generation_counter += 1;
            self.local.sequences.insert(
                sequence_id.clone(),
                SequenceOverlay::Present(SequenceState {
                    id: sequence_id.clone(),
                    owner: self
                        .local
                        .relations
                        .get(&alter.id)
                        .and_then(|overlay| match overlay {
                            RelationOverlay::Present(table) => Some(table.owner.clone()),
                            RelationOverlay::Dropped => None,
                        })
                        .unwrap_or_else(|| ObjectId::new("", &self.local.current_role)),
                    owned_by: Some((alter.id.clone(), column_name.clone())),
                    kind,
                    parameters,
                    generation: self.local.generation_counter,
                }),
            );
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                sequence_id,
                alter.id.clone(),
                DependencyKind::SequenceOwnedBy {
                    column: column_name,
                },
            ));
        }
        if matches!(alter.action, AlterTableActionMutation::DropColumn { .. })
            && !drop_column_constraints.is_empty()
        {
            self.remove_dropped_constraints(&HashSet::new(), &drop_column_constraints);
            self.snapshot_graph_full();
            let resolution_graph = self.local.graph.clone();
            self.local.graph.retain_edges(|edge| {
                let dependent = resolution_graph.resolve_rename(&edge.dependent);
                match &edge.kind {
                    DependencyKind::ForeignKey {
                        constraint_name: Some(name),
                        ..
                    } => !drop_column_constraints.contains(&(dependent.clone(), name.clone())),
                    DependencyKind::ConstraintOnRelation {
                        constraint_name: name,
                        ..
                    } => !drop_column_constraints.contains(&(dependent.clone(), name.clone())),
                    DependencyKind::ConstraintDependency {
                        constraint_name: name,
                        ..
                    } => !drop_column_constraints.contains(&(dependent.clone(), name.clone())),
                    _ => {
                        // The preflight above has already rejected unknown
                        // column-bearing edges; this arm keeps unrelated
                        // topology intact.
                        true
                    }
                }
            });
        }
        if !cascade_view_roots.is_empty() {
            let views = cascade_view_roots.into_iter().collect::<Vec<_>>();
            // Preflight established a column-level dependency and CASCADE;
            // this applies the recursive view/index closure PostgreSQL drops.
            let _ = self.apply_drop_relation_family(&views, true, "view");
        }
        if let AlterTableActionMutation::DropColumn { name, .. } = &alter.action {
            let resolved_table = self.local.graph.resolve_rename(&alter.id).clone();
            let resolution_graph = self.local.graph.clone();
            if self.local.graph.edges().iter().any(|edge| {
                resolution_graph.resolve_rename(&edge.dependent) == &resolved_table
                    && matches!(
                        &edge.kind,
                        DependencyKind::ColumnGeneratedFrom { column, .. }
                            | DependencyKind::ColumnDefaultOnSequence { column }
                            if column == name || cascade_generated_columns.contains(column)
                    )
            }) {
                self.snapshot_graph_full();
                self.local.graph.retain_edges(|edge| {
                    !(resolution_graph.resolve_rename(&edge.dependent) == &resolved_table
                        && matches!(
                            &edge.kind,
                            DependencyKind::ColumnGeneratedFrom { column, .. }
                                | DependencyKind::ColumnDefaultOnSequence { column }
                                if column == name || cascade_generated_columns.contains(column)
                        ))
                });
            }
        }
        if matches!(alter.action, AlterTableActionMutation::DropColumn { .. })
            && !drop_column_indexes.is_empty()
        {
            self.snapshot_graph_full();
            self.local.graph.retain_edges(|edge| {
                !(matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                    && drop_column_indexes.contains(&edge.dependent))
            });
        }
        match &alter.action {
            AlterTableActionMutation::DropColumn { name, .. } => {
                self.drop_not_null_constraint(&alter.id, name);
                for sequence_id in owned_sequences_for_column {
                    self.snapshot_sequence(&sequence_id);
                    self.local
                        .sequences
                        .insert(sequence_id.clone(), SequenceOverlay::Dropped);
                    self.snapshot_graph_full();
                    self.local.graph.retain_edges(|edge| {
                        !(matches!(edge.kind, DependencyKind::SequenceOwnedBy { .. })
                            && edge.dependent == sequence_id)
                    });
                }
            }
            AlterTableActionMutation::RenameColumn { from, to } => {
                self.snapshot_graph_full();
                let resolved_table = self.local.graph.resolve_rename(&alter.id).clone();
                self.local
                    .graph
                    .rename_index_column(&resolved_table, from, to);
                for sequence_id in owned_sequences_for_column {
                    self.snapshot_sequence(&sequence_id);
                    if let Some(SequenceOverlay::Present(sequence)) =
                        self.local.sequences.get_mut(&sequence_id)
                        && let Some((_, column)) = &mut sequence.owned_by
                    {
                        *column = to.clone();
                    }
                    self.snapshot_graph_full();
                    self.local
                        .graph
                        .rename_owned_sequence_column(&sequence_id, from, to);
                }
            }
            _ => {}
        }
        MutationResult::Applied
    }
}
