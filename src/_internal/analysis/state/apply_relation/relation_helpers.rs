use super::*;

impl AnalysisState {
    /// Reject a declared type the server would refuse: a length or precision
    /// outside the server's range, a type no server can resolve, or a feature
    /// that postdates it. An unknown version or baseline taints instead.
    pub(in crate::_internal::analysis::state) fn check_declared_type(
        &mut self,
        declared: &str,
    ) -> Option<MutationResult> {
        let parsed = ParsedDataType::parse(declared, self.builtin_types());
        if !parsed.is_valid_declaration() {
            return Some(MutationResult::conflict(format!(
                "type '{declared}' is not a valid type declaration"
            )));
        }
        if !self.declared_type_resolves(declared) {
            let Some((schema, name, _)) = Self::parse_type_reference(declared) else {
                self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Statement);
                return None;
            };
            let id = ObjectId::new(schema.as_deref().unwrap_or_default(), &name);
            if schema
                .as_deref()
                .is_none_or(|schema| self.schema_absence_is_authoritative(schema))
                && self.baseline_covers_family_object(
                    &id,
                    crate::_internal::db::cache::CatalogFamily::Types,
                )
            {
                return Some(MutationResult::conflict(format!(
                    "type '{declared}' does not exist"
                )));
            }
            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Statement);
            return None;
        }
        if parsed.needs_widened_numeric_scale() {
            match self.pg_version().num() {
                Some(version) if version < WIDENED_NUMERIC_SCALE_VERSION => {
                    return Some(MutationResult::conflict(format!(
                        "type '{declared}' requires PostgreSQL 15 or later, \
                             but the baseline reports {version}"
                    )));
                }
                Some(_) => {}
                None => {
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
                }
            }
        }
        None
    }

    pub(super) fn inherited_descendants(&self, root: &ObjectId) -> Vec<ObjectId> {
        let mut pending = vec![root.clone()];
        let mut visited = HashSet::from([root.clone()]);
        let mut descendants = Vec::new();
        while let Some(parent) = pending.pop() {
            for edge in self.local.graph.edges() {
                if edge.referenced != parent
                    || !matches!(
                        edge.kind,
                        DependencyKind::InheritanceOf | DependencyKind::PartitionOf
                    )
                    || !visited.insert(edge.dependent.clone())
                {
                    continue;
                }
                pending.push(edge.dependent.clone());
                descendants.push(edge.dependent.clone());
            }
        }
        descendants
    }

    pub(super) fn rename_relation_column_metadata(
        &mut self,
        table: &ObjectId,
        from: &str,
        to: &str,
    ) {
        self.snapshot_relation(table);
        if let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(table) {
            relation.apply_column_action(&ColumnAction::Rename {
                from: from.to_string(),
                to: to.to_string(),
            });
        }
        let constraints = self
            .local
            .constraints
            .iter()
            .filter(|((owner, _), constraint)| {
                owner == table && constraint.kind == ConstraintKind::Check
            })
            .filter_map(|((_, name), constraint)| {
                constraint
                    .definition
                    .as_deref()
                    .map(|source| (name.clone(), source.to_string()))
            })
            .collect::<Vec<_>>();
        for (name, source) in constraints {
            self.snapshot_constraint(table, &name);
            if let Some(constraint) = self.local.constraints.get_mut(&(table.clone(), name)) {
                constraint.definition =
                    crate::_internal::analysis::expr_visitor::ExprVisitor::rename_column_source(
                        &source,
                        &table.name,
                        from,
                        to,
                    );
            }
        }
        self.snapshot_graph_full();
        self.local.graph.rename_column_dependencies(table, from, to);
        self.local.graph.rename_index_column(table, from, to);
        let sequences = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                matches!(&edge.kind, DependencyKind::SequenceOwnedBy { column } if column == from)
            })
            .map(|edge| (edge.dependent.clone(), edge.referenced == *table))
            .filter_map(|(sequence, owned)| owned.then_some(sequence))
            .collect::<Vec<_>>();
        for sequence in sequences {
            self.snapshot_sequence(&sequence);
            if let Some(SequenceOverlay::Present(state)) = self.local.sequences.get_mut(&sequence)
                && let Some((_, column)) = &mut state.owned_by
            {
                *column = to.to_string();
            }
            self.local
                .graph
                .rename_owned_sequence_column(&sequence, from, to);
        }
    }

    pub(super) fn default_column_sequence_parameters(
        data_type: Option<&str>,
        persistence: &crate::_internal::model::relation::Persistence,
    ) -> SequenceParameters {
        let data_type = match data_type
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("smallint" | "smallserial" | "serial2") => "smallint",
            Some("integer" | "int" | "int4" | "serial" | "serial4") => "integer",
            _ => "bigint",
        };
        let max_value = match data_type {
            "smallint" => i16::MAX as i64,
            "integer" => i32::MAX as i64,
            _ => i64::MAX,
        };
        SequenceParameters {
            data_type: data_type.to_string(),
            max_value,
            persistence: Self::sequence_persistence(persistence),
            ..SequenceParameters::default()
        }
    }

    /// The backing index of a locally created primary key or unique constraint.
    ///
    /// Constraint syntax admits neither expressions nor predicates, so the
    /// shape is fully determined by the columns. `NULLS NOT DISTINCT` is not
    /// modeled on constraint syntax, so the server default is recorded.
    pub(super) fn constraint_index_dependency(
        columns: Vec<String>,
        is_unique: bool,
    ) -> DependencyKind {
        DependencyKind::IndexOnRelation {
            definition: IndexDefinition {
                method: Some("btree".to_string()),
                keys: index_keys(columns.clone()),
                included: index_keys(Vec::new()),
                expression_keys: 0,
                unique: is_unique,
                nulls_not_distinct: Some(false),
                predicate: IndexPredicate::None,
                unestablished: false,
                valid: true,
                ready: true,
                live: true,
            },
            dependency_columns: columns,
            dependency_columns_known: true,
            is_concurrent: false,
            is_immediate: true,
            eligibility_known: true,
        }
    }

    pub(super) fn sequence_persistence(
        persistence: &crate::_internal::model::relation::Persistence,
    ) -> SequencePersistence {
        match persistence {
            crate::_internal::model::relation::Persistence::Permanent => {
                SequencePersistence::Permanent
            }
            crate::_internal::model::relation::Persistence::Temporary => {
                SequencePersistence::Temporary
            }
            crate::_internal::model::relation::Persistence::Unlogged => {
                SequencePersistence::Unlogged
            }
        }
    }

    /// Parameters for the sequence backing an identity column.
    ///
    /// PostgreSQL folds the column type into the option list as a synthetic
    /// `AS` clause, so the column type drives the bounds and a written `AS`
    /// is a duplicate option.
    pub(super) fn identity_sequence_parameters(
        column_type: Option<&str>,
        persistence: &crate::_internal::model::relation::Persistence,
        options: Option<&crate::_internal::analysis::mutations::IdentitySequenceOptionsMutation>,
    ) -> Result<SequenceParameters, MutationResult> {
        let data_type = match column_type {
            Some(column_type) => {
                match crate::_internal::analysis::state::apply_sequence::sequence_type(column_type)
                {
                    Some((data_type, _, _)) => data_type,
                    None => {
                        return Err(MutationResult::conflict(
                            "identity column type must be smallint, integer, or bigint".to_string(),
                        ));
                    }
                }
            }
            None => "bigint",
        };
        if options.is_some_and(|options| options.data_type.is_some()) {
            return Err(MutationResult::conflict(
                "conflicting or redundant options: \"as\" specified more than once".to_string(),
            ));
        }
        let mut option_set = options.map_or_else(
            crate::_internal::analysis::state::apply_sequence::SequenceOptionSet::default,
            crate::_internal::analysis::state::apply_sequence::SequenceOptionSet::from_identity_options,
        );
        // The column type is the synthetic `AS`; a written one is a duplicate.
        option_set.as_type = None;
        let mut parameters =
            crate::_internal::analysis::state::apply_sequence::init_sequence_parameters(
                &SequenceParameters {
                    data_type: data_type.to_string(),
                    persistence: Self::sequence_persistence(persistence),
                    ..Default::default()
                },
                &option_set,
                true,
            )?;
        if let Some(persistence) = option_set.persistence() {
            parameters.persistence = persistence;
        }
        Ok(parameters)
    }

    pub(super) fn normalized_constraint_expression(definition: &str) -> String {
        let mut offset = 0usize;
        let mut normalized = String::new();
        for token in squawk_lexer::tokenize(definition) {
            let end = offset + token.len as usize;
            let text = &definition[offset..end];
            offset = end;
            if matches!(
                token.kind,
                squawk_lexer::TokenKind::Whitespace
                    | squawk_lexer::TokenKind::LineComment
                    | squawk_lexer::TokenKind::BlockComment { .. }
                    | squawk_lexer::TokenKind::Eof
            ) {
                continue;
            }
            let text = if matches!(token.kind, squawk_lexer::TokenKind::Ident) {
                text.to_ascii_lowercase()
            } else {
                text.to_string()
            };
            use std::fmt::Write;
            let _ = write!(normalized, "{:?}:{}:{};", token.kind, text.len(), text);
        }
        normalized
    }

    pub(super) fn relation_or_index_lookup(&self, id: &ObjectId) -> RelationLookup {
        if self.relation_is_present(id) || self.index_is_present(id) {
            RelationLookup::Present
        } else if matches!(self.local.relations.get(id), Some(RelationOverlay::Dropped)) {
            RelationLookup::Tombstone
        } else if self.baseline_covers_family_object(
            id,
            crate::_internal::db::cache::CatalogFamily::Relations,
        ) || self
            .baseline_covers_family_object(id, crate::_internal::db::cache::CatalogFamily::Indexes)
        {
            RelationLookup::AuthoritativelyAbsent
        } else {
            RelationLookup::Unknown
        }
    }
}
