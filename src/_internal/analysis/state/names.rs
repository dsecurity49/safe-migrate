use super::*;

impl AnalysisState {
    /// Pick a generated name while also avoiding names reserved by other
    /// constraints in the same CREATE TABLE statement. The ordinary helper
    /// only sees already-applied state, which is not enough for a batch of
    /// inline constraints that becomes visible at the end of the statement.
    pub(super) fn next_generated_constraint_name_avoiding(
        &self,
        table: &ObjectId,
        name1: &str,
        name2: Option<&str>,
        label: &str,
        reserved: &HashSet<String>,
    ) -> String {
        (0..)
            .map(|suffix| {
                let label = if suffix == 0 {
                    label.to_string()
                } else {
                    format!("{label}{suffix}")
                };
                Self::postgres_object_name(name1, name2, &label)
            })
            .find(|candidate| {
                !reserved.contains(candidate)
                    // PostgreSQL's ChooseConstraintName checks the namespace,
                    // even though explicit constraint names are table-local.
                    && !self.local.constraints.keys().any(|(owner, name)| {
                        owner.schema == table.schema && name == candidate
                    })
            })
            .expect("constraint suffix space is unbounded")
    }

    pub(super) fn next_generated_relation_name_avoiding(
        &self,
        schema: &str,
        name1: &str,
        name2: Option<&str>,
        label: &str,
        reserved: &HashSet<ObjectId>,
    ) -> ObjectId {
        (0..)
            .map(|suffix| {
                let label = if suffix == 0 {
                    label.to_string()
                } else {
                    format!("{label}{suffix}")
                };
                ObjectId::new(schema, Self::postgres_object_name(name1, name2, &label))
            })
            .find(|candidate| {
                !reserved.contains(candidate) && !self.relation_namespace_is_taken(candidate)
            })
            .expect("relation suffix space is unbounded")
    }

    pub(super) fn next_generated_statistics_name_avoiding(
        &self,
        schema: &str,
        table: &str,
        columns: &[String],
        reserved: &HashSet<ObjectId>,
    ) -> ObjectId {
        (0..)
            .map(|suffix| {
                let label = if suffix == 0 {
                    "stat".to_string()
                } else {
                    format!("stat{suffix}")
                };
                ObjectId::new(
                    schema,
                    Self::postgres_object_name(table, Some(&columns.join("_")), &label),
                )
            })
            .find(|candidate| {
                !reserved.contains(candidate)
                    && !self.local.relations.values().any(|overlay| match overlay {
                        RelationOverlay::Present(relation) => {
                            relation.extended_statistics.contains_key(candidate)
                        }
                        RelationOverlay::Dropped => false,
                    })
            })
            .expect("extended-statistics suffix space is unbounded")
    }

    pub(super) fn postgres_object_name(name1: &str, name2: Option<&str>, label: &str) -> String {
        const MAX_IDENTIFIER_BYTES: usize = 63;

        fn truncate(value: &str, max_bytes: usize) -> &str {
            let mut end = max_bytes.min(value.len());
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            &value[..end]
        }

        let separators = usize::from(name2.is_some()) + 1;
        let available = MAX_IDENTIFIER_BYTES.saturating_sub(label.len() + separators);
        let mut name1_bytes = name1.len();
        let mut name2_bytes = name2.map_or(0, str::len);
        while name1_bytes + name2_bytes > available {
            if name1_bytes > name2_bytes {
                name1_bytes -= 1;
            } else {
                name2_bytes -= 1;
            }
        }

        let name1 = truncate(name1, name1_bytes);
        match name2 {
            Some(name2) => format!("{name1}_{}_{}", truncate(name2, name2_bytes), label),
            None => format!("{name1}_{label}"),
        }
    }

    pub(super) fn relation_namespace_is_taken(&self, id: &ObjectId) -> bool {
        self.relation_namespace_object_is_present(id) || self.type_is_present(id)
    }

    pub(super) fn next_implicit_sequence_id(
        &self,
        table: &ObjectId,
        column: &str,
        reserved: &HashSet<ObjectId>,
    ) -> ObjectId {
        (0..)
            .map(|suffix| {
                let label = if suffix == 0 {
                    "seq".to_string()
                } else {
                    format!("seq{suffix}")
                };
                ObjectId::new(
                    &table.schema,
                    Self::postgres_object_name(&table.name, Some(column), &label),
                )
            })
            .find(|candidate| {
                !reserved.contains(candidate) && !self.relation_namespace_is_taken(candidate)
            })
            .expect("implicit sequence suffix space is unbounded")
    }

    pub(super) fn sequence_nextval_default(
        id: &ObjectId,
    ) -> crate::_internal::analysis::expr_ir::ExprIr {
        crate::_internal::analysis::expr_ir::ExprIr::FunctionCall {
            name: "nextval".to_string(),
            args: vec![crate::_internal::analysis::expr_ir::ExprIr::Literal(
                format!("{}.{}", id.schema, id.name),
            )],
        }
    }
}
