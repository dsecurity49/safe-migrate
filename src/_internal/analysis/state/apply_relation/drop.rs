use super::*;

impl AnalysisState {
    pub(in crate::_internal::analysis::state) fn apply_drop_table(
        &mut self,
        drop_table: &DropTable,
        precomputed_cascade: Option<&CascadeResult>,
    ) -> MutationResult {
        if drop_table.ids.is_empty() {
            return MutationResult::NoOp;
        }
        for id in &drop_table.ids {
            if let Some(result) = self.extension_member_drop_conflict(
                crate::_internal::model::extension::ExtensionMemberKind::Relation,
                id,
                "table",
            ) {
                return result;
            }
        }

        let renames: Vec<DependencyEdge> = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|e| matches!(e.kind, DependencyKind::RenameTo))
            .cloned()
            .collect();
        let resolve = |id: &ObjectId| -> ObjectId {
            let mut current = id;
            let mut visited = HashSet::new();
            loop {
                if !visited.insert(current.clone()) {
                    return id.clone();
                }
                match renames.iter().find(|r| &r.dependent == current) {
                    Some(edge) => current = &edge.referenced,
                    None => return current.clone(),
                }
            }
        };

        let display_names = drop_table
            .ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let mut present_targets = Vec::new();
        let mut unknown_target = false;
        for id in &drop_table.ids {
            // The server rejects `DROP TABLE` on a foreign table and points at
            // `DROP FOREIGN TABLE`, so the kind check stays table-only.
            match self.relation_lookup(id, |kind| *kind == RelationKind::Table) {
                RelationLookup::Present => present_targets.push(id.clone()),
                RelationLookup::WrongKind => {
                    return MutationResult::conflict(format!("'{}' is not a table", id));
                }
                RelationLookup::AuthoritativelyAbsent if drop_table.if_exists => {}
                RelationLookup::AuthoritativelyAbsent => {
                    return MutationResult::conflict(format!("table '{}' does not exist", id));
                }
                RelationLookup::Tombstone if drop_table.if_exists => {}
                RelationLookup::Tombstone => {
                    return MutationResult::conflict(format!("table '{}' does not exist", id));
                }
                RelationLookup::Unknown => {
                    unknown_target = true;
                    if !drop_table.if_exists {
                        return self.unresolved(EvidenceCode::UnknownObjectState);
                    }
                }
            }
        }

        present_targets.sort_unstable_by_key(ToString::to_string);
        present_targets.dedup();
        // `IF EXISTS` suppresses an absent-object error; it does not prove an
        // object outside a scoped baseline is absent. PostgreSQL can therefore
        // drop an unmodeled target (and its dependencies) in the same atomic
        // statement. Do not apply known siblings with an incomplete target
        // list.
        if unknown_target {
            return self.unresolved(EvidenceCode::UnknownObjectState);
        }
        if present_targets.is_empty() {
            return MutationResult::NoOp;
        }

        // Neither a baseline without dependency coverage nor a scoped one can
        // enumerate every dependent. The named targets still drop and the known
        // closure still follows; only the remainder is unknown, so record that
        // instead of refusing a drop PostgreSQL performs.
        let mut incomplete_closure = present_targets
            .iter()
            .any(|id| self.baseline_relation_is_known(id))
            && !self
                .baseline_has_coverage(crate::_internal::db::cache::CatalogFamily::Dependencies);

        // The FK loader only expands foreign-key boundaries, so a scoped
        // baseline cannot prove every cross-schema dependent was loaded.
        incomplete_closure |= present_targets.iter().any(|id| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Relations,
            )
        });

        let roots: HashSet<ObjectId> = present_targets.iter().map(&resolve).collect();
        let mut dropped_relations = roots.clone();
        let mut dropped_indexes = HashSet::new();
        let mut dropped_constraints = HashSet::new();

        if drop_table.cascade {
            let local_closure;
            let closure = match precomputed_cascade {
                Some(c) => c,
                None => {
                    local_closure = self.cascade_for_relations(&present_targets);
                    &local_closure
                }
            };
            let closure_touches_baseline = closure
                .dropped_relations
                .iter()
                .any(|id| self.baseline_relation_is_known(id) && !roots.contains(id))
                || closure
                    .dropped_constraints
                    .iter()
                    .any(|constraint| self.baseline_foreign_keys.contains(constraint));
            if closure_touches_baseline
                && !self
                    .baseline_has_coverage(crate::_internal::db::cache::CatalogFamily::Dependencies)
            {
                return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
            }
            if closure
                .dropped_relations
                .iter()
                .any(|id| !self.relation_is_present(id) && !self.baseline_relation_is_known(id))
            {
                // A scoped cache may retain a dependency edge to a relation
                // whose catalog row was omitted. CASCADE removes it in
                // PostgreSQL, but its unmodeled metadata makes the result
                // incomplete rather than exact.
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            dropped_relations = closure.dropped_relations.clone();
            dropped_indexes = closure.dropped_indexes.clone();
            dropped_constraints = closure.dropped_constraints.clone();

            for dropped_rel_id in &closure.dropped_relations {
                self.snapshot_relation(dropped_rel_id);
                self.local
                    .relations
                    .insert(dropped_rel_id.clone(), RelationOverlay::Dropped);
            }

            self.snapshot_graph_full();
            self.local.graph.retain_edges(|e| match &e.kind {
                DependencyKind::IndexOnRelation { .. } => {
                    !closure.dropped_indexes.contains(&resolve(&e.dependent))
                }
                DependencyKind::ForeignKey {
                    constraint_name, ..
                } => {
                    let from_dropped = closure.dropped_relations.contains(&resolve(&e.dependent));
                    let to_dropped = closure.dropped_relations.contains(&resolve(&e.referenced));
                    let constraint_explicitly_dropped = if let Some(cname) = constraint_name {
                        closure
                            .dropped_constraints
                            .contains(&(resolve(&e.dependent), cname.clone()))
                    } else {
                        false
                    };
                    !(from_dropped || to_dropped || constraint_explicitly_dropped)
                }
                DependencyKind::ViewDependency { .. } => {
                    !closure.dropped_relations.contains(&resolve(&e.dependent))
                }
                DependencyKind::SequenceOwnedBy { .. } => {
                    !closure.dropped_relations.contains(&resolve(&e.referenced))
                }
                _ => true,
            });
        } else {
            let has_view_deps = self.local.graph.edges().iter().any(|e| {
                self.dependency_edge_is_current(e)
                    && matches!(e.kind, DependencyKind::ViewDependency { .. })
                    && roots.contains(&resolve(&e.referenced))
                    && !roots.contains(&resolve(&e.dependent))
                    && !self.co_dropped_objects.contains(&resolve(&e.dependent))
            });
            let has_fk_deps = self.local.graph.edges().iter().any(|e| {
                self.dependency_edge_is_current(e)
                    && matches!(e.kind, DependencyKind::ForeignKey { .. })
                    && roots.contains(&resolve(&e.referenced))
                    && !roots.contains(&resolve(&e.dependent))
                    && !self.co_dropped_objects.contains(&resolve(&e.dependent))
            });
            let has_inheritance_deps = self.local.graph.edges().iter().any(|e| {
                matches!(
                    e.kind,
                    DependencyKind::InheritanceOf
                        | DependencyKind::PartitionOf
                        | DependencyKind::PartitionDetachPending
                ) && roots.contains(&resolve(&e.referenced))
                    && !roots.contains(&resolve(&e.dependent))
                    && !self.co_dropped_objects.contains(&resolve(&e.dependent))
            });

            if has_view_deps || has_fk_deps || has_inheritance_deps {
                let relation_word = if present_targets.len() == 1 {
                    "relation"
                } else {
                    "relations"
                };
                let dependent_verb = if present_targets.len() == 1 {
                    "has"
                } else {
                    "have"
                };
                return MutationResult::conflict(format!(
                    "{relation_word} '{}' still {dependent_verb} dependent objects; use CASCADE",
                    display_names,
                ));
            }

            for id in &roots {
                self.snapshot_relation(id);
                self.local
                    .relations
                    .insert(id.clone(), RelationOverlay::Dropped);
            }

            self.snapshot_graph_full();
            self.local.graph.retain_edges(|e| {
                if roots.contains(&resolve(&e.dependent)) {
                    return !matches!(
                        e.kind,
                        DependencyKind::ForeignKey { .. }
                            | DependencyKind::ColumnGeneratedFrom { .. }
                            | DependencyKind::ColumnDefaultOnSequence { .. }
                    );
                }
                if roots.contains(&resolve(&e.referenced)) {
                    return !matches!(
                        e.kind,
                        DependencyKind::IndexOnRelation { .. }
                            | DependencyKind::SequenceOwnedBy { .. }
                            | DependencyKind::ColumnGeneratedFrom { .. }
                    );
                }
                true
            });
        }

        let owned_sequences_to_drop: Vec<ObjectId> =
            self.local
                .sequences
                .iter()
                .filter_map(|(id, overlay)| match overlay {
                    SequenceOverlay::Present(sequence)
                        if sequence.owned_by.as_ref().is_some_and(|(table, _)| {
                            dropped_relations.contains(&resolve(table))
                        }) =>
                    {
                        Some(id.clone())
                    }
                    _ => None,
                })
                .collect();
        for sequence_id in owned_sequences_to_drop {
            self.snapshot_sequence(&sequence_id);
            self.local
                .sequences
                .insert(sequence_id, SequenceOverlay::Dropped);
        }

        self.remove_dropped_constraints(&dropped_relations, &dropped_constraints);

        let triggers_to_drop: Vec<ObjectId> = self
            .local
            .triggers
            .iter()
            .filter_map(|(id, overlay)| {
                let TriggerOverlay::Present(trigger) = overlay else {
                    return None;
                };
                let graph_matches = self.local.graph.edges().iter().any(|edge| {
                    matches!(edge.kind, DependencyKind::TriggerOnTable { .. })
                        && edge.dependent == *id
                        && dropped_relations.contains(&resolve(&edge.referenced))
                });
                (dropped_relations.contains(&resolve(&trigger.table_id)) || graph_matches)
                    .then(|| id.clone())
            })
            .collect();
        for trigger_id in triggers_to_drop {
            self.snapshot_trigger(&trigger_id);
            self.local
                .triggers
                .insert(trigger_id, TriggerOverlay::Dropped);
        }

        // PostgreSQL drops triggers only after the table drop succeeds.
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|e| {
            !(matches!(e.kind, DependencyKind::TriggerOnTable { .. })
                && dropped_relations.contains(&resolve(&e.referenced)))
        });

        // A successful relation drop removes every modeled edge that touches
        // the dropped relation (or a cascaded index).  Keep this final sweep
        // broad so newly added edge kinds cannot leak stale topology through
        // a table-drop path.
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            let dependent = resolve(&edge.dependent);
            let referenced = resolve(&edge.referenced);
            !dropped_relations.contains(&dependent)
                && !dropped_relations.contains(&referenced)
                && !dropped_indexes.contains(&dependent)
        });

        let publication_updates: Vec<(String, Vec<_>)> = self
            .local
            .publications
            .iter()
            .filter_map(|(name, overlay)| {
                let crate::_internal::model::replication::PublicationOverlay::Present(publication) =
                    overlay
                else {
                    return None;
                };
                let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                    &publication.scope
                else {
                    return None;
                };
                let retained = objects
                    .iter()
                    .filter(|object| {
                        let crate::_internal::analysis::facts::PublicationObjectFact::Table {
                            name,
                            ..
                        } = object
                        else {
                            return true;
                        };
                        !dropped_relations.contains(&resolve(&self.resolve_relation_id(name)))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                (retained.len() != objects.len()).then(|| (name.clone(), retained))
            })
            .collect();
        for (publication_name, retained) in publication_updates {
            self.snapshot_publication(&publication_name);
            if let Some(crate::_internal::model::replication::PublicationOverlay::Present(
                publication,
            )) = self.local.publications.get_mut(&publication_name)
                && let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                    &mut publication.scope
            {
                *objects = retained;
            }
        }
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !matches!(edge.kind, DependencyKind::PublicationIncludes { .. })
                || !dropped_relations.contains(&resolve(&edge.dependent))
        });

        if incomplete_closure {
            // Everything the known closure reached is gone. A dependent loaded
            // out of scope may have gone too, so nothing after this statement
            // can be called exact.
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }

        MutationResult::Applied
    }

    /// PostgreSQL records every NOT NULL column (whether declared inline,
    /// introduced by a PRIMARY KEY, or set later) as a `pg_constraint` row of
    /// `contype = 'n'` on PG18+. The normalized catalog represents it as a
    /// `ConstraintKind::NotNull` entry with its single column on a
    /// `ConstraintOnRelation` edge, mirroring the live sync so the differential
    /// harness and destructive-transition dependency checks agree with
    /// PostgreSQL.
    pub(super) fn register_not_null_constraint(&mut self, table: &ObjectId, column: &str) {
        // PostgreSQL only materializes NOT NULL columns as `pg_constraint`
        // rows (`contype = 'n'`) on PG18+. On PG17 and earlier a NOT NULL
        // column is tracked purely by its nullability attribute, so recording
        // it as a distinct constraint would add normalized state that the live
        // database never lists. Column nullability is still carried by the
        // column itself; only this separate constraint representation is
        // suppressed.
        if self.pg_version().conservative_num() < 180_000 {
            return;
        }
        if self.not_null_constraint_for_column(table, column).is_some() {
            return;
        }
        let name = self.next_generated_constraint_name_avoiding(
            table,
            &table.name,
            Some(column),
            "not_null",
            &HashSet::new(),
        );
        self.snapshot_constraint(table, &name);
        self.local.constraints.insert(
            (table.clone(), name.clone()),
            ConstraintState {
                table_id: table.clone(),
                name: name.clone(),
                kind: ConstraintKind::NotNull,
                validated: true,
                definition: None,
                backing_index: None,
            },
        );
        self.snapshot_graph();
        self.local.graph.add_edge(DependencyEdge::new(
            table.clone(),
            table.clone(),
            DependencyKind::ConstraintOnRelation {
                constraint_name: name,
                columns: vec![column.to_string()],
                is_primary: false,
            },
        ));
    }

    pub(super) fn drop_not_null_constraint(&mut self, table: &ObjectId, column: &str) {
        let Some((table_id, name)) = self.not_null_constraint_for_column(table, column) else {
            return;
        };
        self.snapshot_constraint(&table_id, &name);
        self.local
            .constraints
            .remove(&(table_id.clone(), name.clone()));
        self.snapshot_graph_full();
        let resolution_graph = self.local.graph.clone();
        let column_name = column.to_string();
        self.local.graph.retain_edges(|edge| {
            !matches!(
                &edge.kind,
                DependencyKind::ConstraintOnRelation {
                    constraint_name,
                    columns,
                    is_primary: false,
                    ..
                } if resolution_graph.resolve_rename(&edge.dependent) == &table_id
                    && constraint_name == &name
                    && columns.len() == 1
                    && columns[0] == column_name
            )
        });
    }

    /// Resolve the `ConstraintKind::NotNull` constraint (if any) that guards a
    /// single column on `table`, returning its identity. Not-null constraints
    /// carry exactly one column on a non-primary `ConstraintOnRelation` edge.
    pub(super) fn not_null_constraint_for_column(
        &self,
        table: &ObjectId,
        column: &str,
    ) -> Option<(ObjectId, String)> {
        let resolution_graph = self.local.graph.clone();
        self.local.graph.edges().iter().find_map(|edge| {
            let dependent = resolution_graph.resolve_rename(&edge.dependent);
            if dependent != table {
                return None;
            }
            if let DependencyKind::ConstraintOnRelation {
                constraint_name,
                columns,
                is_primary: false,
                ..
            } = &edge.kind
                && columns.len() == 1
                && columns[0] == column
            {
                Some((dependent.clone(), constraint_name.clone()))
            } else {
                None
            }
        })
    }
}
