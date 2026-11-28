use super::super::*;

type LikeCheckPlan = (String, Vec<String>, String);
type LikeIndexPlan = (
    ObjectId,
    DependencyKind,
    Option<(ConstraintKind, Vec<String>)>,
);
type ImplicitSequencePlan = (
    ObjectId,
    String,
    SequenceKind,
    crate::_internal::model::sequence::SequenceParameters,
);
type InlineConstraintPlan = (
    ConstraintKind,
    String,
    Option<String>,
    Vec<String>,
    bool,
    Option<ObjectId>,
);

impl AnalysisState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_create_table(
        &mut self,
        create: &CreateTable,
        generation: u64,
        not_null_columns: Vec<String>,
        like_dependency_edges: Vec<DependencyEdge>,
        like_check_constraints: Vec<LikeCheckPlan>,
        like_index_plans: Vec<LikeIndexPlan>,
        implicit_sequences: Vec<ImplicitSequencePlan>,
        primary_key_constraint_name: Option<String>,
        unique_constraint_names: Vec<(String, Vec<String>)>,
        foreign_key_constraint_names: Vec<String>,
        effective_fk_target_columns: Vec<Vec<String>>,
        partition_foreign_keys: Vec<(String, DependencyEdge)>,
        inline_constraint_names: Vec<InlineConstraintPlan>,
    ) -> MutationResult {
        if !like_dependency_edges.is_empty() {
            self.snapshot_graph();
            for edge in like_dependency_edges {
                self.local.graph.add_edge(edge);
            }
        }

        for column in &create.columns {
            let Some(expr) = &column.generated_expr else {
                continue;
            };
            let Some(references) = expr.referenced_columns() else {
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
                continue;
            };
            self.snapshot_graph();
            for depends_on_column in references {
                self.local.graph.add_edge(DependencyEdge::new(
                    create.id.clone(),
                    create.id.clone(),
                    DependencyKind::ColumnGeneratedFrom {
                        column: column.name.clone(),
                        depends_on_column,
                    },
                ));
            }
        }

        for column in &not_null_columns {
            self.register_not_null_constraint(&create.id, column);
        }

        for (name, columns, definition) in like_check_constraints {
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind: ConstraintKind::Check,
                    validated: true,
                    definition: Some(definition),
                    backing_index: None,
                },
            );
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                create.id.clone(),
                DependencyKind::ConstraintDependency {
                    constraint_name: name,
                    columns,
                },
            ));
        }

        for (index_id, index_kind, constraint) in like_index_plans {
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                index_id.clone(),
                create.id.clone(),
                index_kind,
            ));
            if let Some((kind, columns)) = constraint {
                let constraint_name = index_id.name.clone();
                self.snapshot_constraint(&create.id, &constraint_name);
                self.local.constraints.insert(
                    (create.id.clone(), constraint_name.clone()),
                    ConstraintState {
                        table_id: create.id.clone(),
                        name: constraint_name.clone(),
                        kind,
                        validated: true,
                        definition: None,
                        backing_index: Some(index_id),
                    },
                );
                self.snapshot_graph();
                self.local.graph.add_edge(DependencyEdge::new(
                    create.id.clone(),
                    create.id.clone(),
                    match kind {
                        ConstraintKind::PrimaryKey | ConstraintKind::Unique => {
                            DependencyKind::ConstraintOnRelation {
                                constraint_name,
                                columns,
                                is_primary: matches!(kind, ConstraintKind::PrimaryKey),
                            }
                        }
                        ConstraintKind::Exclusion => DependencyKind::ConstraintDependency {
                            constraint_name,
                            columns,
                        },
                        _ => unreachable!("LIKE INDEXES clones only index-backed constraints"),
                    },
                ));
            }
        }

        for (sequence_id, column_name, kind, parameters) in implicit_sequences {
            self.snapshot_sequence(&sequence_id);
            self.snapshot_generation_counter();
            self.local.generation_counter += 1;
            let runtime =
                crate::_internal::model::sequence::SequenceRuntime::fresh(parameters.start_value);
            self.local.sequences.insert(
                sequence_id.clone(),
                SequenceOverlay::Present(SequenceState {
                    id: sequence_id.clone(),
                    owner: ObjectId::new("", &self.local.current_role),
                    owned_by: Some((create.id.clone(), column_name.clone())),
                    kind,
                    parameters,
                    runtime,
                    runtime_exact: true,
                    generation: self.local.generation_counter,
                }),
            );
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                sequence_id,
                create.id.clone(),
                DependencyKind::SequenceOwnedBy {
                    column: column_name,
                },
            ));
        }

        if let Some(name) = primary_key_constraint_name.clone() {
            let index_id = ObjectId::new(&create.id.schema, &name);
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind: ConstraintKind::PrimaryKey,
                    validated: true,
                    definition: None,
                    backing_index: Some(index_id.clone()),
                },
            );
            let columns = create
                .table_constraints
                .iter()
                .find_map(|constraint| match constraint {
                    TableConstraintFact::PrimaryKey { columns, .. } => Some(columns.clone()),
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
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                index_id,
                create.id.clone(),
                Self::constraint_index_dependency(columns, true),
            ));
        }

        for (name, columns) in unique_constraint_names {
            let index_id = ObjectId::new(&create.id.schema, &name);
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind: ConstraintKind::Unique,
                    validated: true,
                    definition: None,
                    backing_index: Some(index_id.clone()),
                },
            );
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                index_id,
                create.id.clone(),
                Self::constraint_index_dependency(columns.clone(), true),
            ));
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                create.id.clone(),
                DependencyKind::ConstraintOnRelation {
                    constraint_name: name,
                    columns,
                    is_primary: false,
                },
            ));
        }

        if let Some(parent_id) = &create.partition_of {
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                parent_id.clone(),
                DependencyKind::PartitionOf,
            ));
        }
        for parent_id in &create.inherits {
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                parent_id.clone(),
                DependencyKind::InheritanceOf,
            ));
        }

        if !create.foreign_keys.is_empty() {
            self.snapshot_graph();
        }

        for ((fk, constraint_name), referenced_columns) in create
            .foreign_keys
            .iter()
            .zip(foreign_key_constraint_names)
            .zip(effective_fk_target_columns)
        {
            self.snapshot_constraint(&create.id, &constraint_name);
            self.local.constraints.insert(
                (create.id.clone(), constraint_name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: constraint_name.clone(),
                    kind: ConstraintKind::ForeignKey,
                    validated: true,
                    definition: None,
                    backing_index: None,
                },
            );
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                fk.to_table.clone(),
                DependencyKind::ForeignKey {
                    constraint_name: Some(constraint_name),
                    from_columns: fk.from_columns.clone(),
                    to_columns: referenced_columns,
                    operator_evidence: None,
                    from_generation: generation,
                },
            ));
        }
        for (constraint_name, edge) in partition_foreign_keys {
            let DependencyKind::ForeignKey {
                from_columns,
                to_columns,
                operator_evidence,
                ..
            } = edge.kind
            else {
                unreachable!("partition foreign-key plans contain only foreign keys")
            };
            self.snapshot_constraint(&create.id, &constraint_name);
            self.local.constraints.insert(
                (create.id.clone(), constraint_name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: constraint_name.clone(),
                    kind: ConstraintKind::ForeignKey,
                    validated: true,
                    definition: None,
                    backing_index: None,
                },
            );
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                edge.referenced,
                DependencyKind::ForeignKey {
                    constraint_name: Some(constraint_name),
                    from_columns,
                    to_columns,
                    operator_evidence,
                    from_generation: generation,
                },
            ));
        }
        for (kind, name, definition, columns, columns_complete, backing_index) in
            inline_constraint_names
        {
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind,
                    validated: true,
                    definition,
                    backing_index: backing_index.clone(),
                },
            );
            if let Some(index_id) = backing_index {
                self.snapshot_graph();
                self.local.graph.add_edge(DependencyEdge::new(
                    index_id,
                    create.id.clone(),
                    DependencyKind::IndexOnRelation {
                        definition: IndexDefinition {
                            method: None,
                            keys: index_keys(columns.clone()),
                            included: index_keys(Vec::new()),
                            expression_keys: 0,
                            unique: false,
                            nulls_not_distinct: Some(false),
                            predicate: IndexPredicate::None,
                            // An exclusion constraint's backing index shape is
                            // not established from the constraint columns alone.
                            unestablished: true,
                            valid: true,
                            ready: true,
                            live: true,
                        },
                        dependency_columns: columns.clone(),
                        dependency_columns_known: columns_complete,
                        is_concurrent: false,
                        is_immediate: true,
                        eligibility_known: false,
                    },
                ));
            }
            if columns_complete {
                self.snapshot_graph();
                self.local.graph.add_edge(DependencyEdge::new(
                    create.id.clone(),
                    create.id.clone(),
                    DependencyKind::ConstraintDependency {
                        constraint_name: name,
                        columns,
                    },
                ));
            } else {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        }
        if let Some(name) = primary_key_constraint_name {
            let columns = create
                .table_constraints
                .iter()
                .find_map(|constraint| match constraint {
                    TableConstraintFact::PrimaryKey { columns, .. } => Some(columns.clone()),
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
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                create.id.clone(),
                DependencyKind::ConstraintOnRelation {
                    constraint_name: name,
                    columns,
                    is_primary: true,
                },
            ));
        }
        if let Some(parent) = &create.partition_of {
            let generated_partition_constraint =
                self.local
                    .relations
                    .get(&create.id)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => Some(relation),
                        RelationOverlay::Dropped => None,
                    })
                    .and_then(|relation| {
                        let bound = relation.partition_bound.as_deref()?;
                        if bound.eq_ignore_ascii_case("DEFAULT") {
                            self.synthesize_default_partition_constraint(parent)
                        } else {
                            let strategy = self.local.relations.get(parent).and_then(
                                |overlay| match overlay {
                                    RelationOverlay::Present(parent) => {
                                        parent.partition_type.as_deref()
                                    }
                                    RelationOverlay::Dropped => None,
                                },
                            )?;
                            let keys = self.partition_key_columns(parent)?;
                            self.synthesize_partition_check(strategy, bound, &keys, relation)
                        }
                    });
            if generated_partition_constraint.is_some()
                && let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(&create.id)
            {
                relation.partition_constraint = generated_partition_constraint;
            }
            let result = self.clone_row_triggers_to_partition(parent, &create.id);
            debug_assert!(matches!(result, MutationResult::Applied));
            if !matches!(result, MutationResult::Applied) {
                return result;
            }
            // PostgreSQL creates and attaches the partition's indexes as part
            // of creating the partition, not as a separate step.
            self.ensure_partition_indexes_and_constraints(parent, &create.id);
        }
        MutationResult::Applied
    }

    /// `ALTER TABLE ... ADD CONSTRAINT ... USING INDEX` transfers ownership
    /// of the index to the constraint. PostgreSQL renames the index when an
    /// explicit constraint name differs, so keep the modeled index identity
    /// in sync with the catalog-visible name.
    pub(in crate::_internal::analysis::state) fn adopt_index_for_constraint(
        &mut self,
        index: &ObjectId,
        table: &ObjectId,
        constraint_name: &str,
    ) {
        let adopted = ObjectId::new(index.schema.clone(), constraint_name);
        if adopted == *index {
            return;
        }
        let Some(edge) = self
            .local
            .graph
            .edges()
            .iter()
            .find(|edge| {
                matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                    && edge.dependent == *index
                    && edge.referenced == *table
            })
            .cloned()
        else {
            return;
        };
        let DependencyKind::IndexOnRelation { .. } = edge.kind else {
            return;
        };
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|existing| {
            !(matches!(existing.kind, DependencyKind::IndexOnRelation { .. })
                && existing.dependent == *index)
        });
        self.local
            .graph
            .add_edge(DependencyEdge::new(adopted, table.clone(), edge.kind));
    }
}
