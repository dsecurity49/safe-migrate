use super::*;
use crate::_internal::analysis::mutations::AlterTable;

mod finish;

struct AlterTableContext {
    recursive_rename_descendants: Vec<ObjectId>,
    relation_columns_known: bool,
    effective_fk_target_columns: Option<Vec<String>>,
    implicit_add: Option<(
        ObjectId,
        String,
        SequenceKind,
        Option<crate::_internal::analysis::mutations::IdentitySequenceOptionsMutation>,
    )>,
    owned_sequences_for_column: Vec<ObjectId>,
    drop_column_constraints: HashSet<(ObjectId, String)>,
    drop_column_indexes: HashSet<ObjectId>,
    drop_column_statistics: HashSet<ObjectId>,
    cascade_generated_columns: HashSet<String>,
    cascade_view_roots: HashSet<ObjectId>,
}

impl AnalysisState {
    pub(in crate::_internal::analysis::state) fn apply_alter_table(
        &mut self,
        alter: &AlterTable,
    ) -> MutationResult {
        let recursive_rename_descendants = if !alter.only
            && matches!(alter.action, AlterTableActionMutation::RenameColumn { .. })
        {
            self.inherited_descendants(&alter.id)
        } else {
            Vec::new()
        };
        if let AlterTableActionMutation::RenameColumn { from, to } = &alter.action {
            for descendant in &recursive_rename_descendants {
                let Some(RelationOverlay::Present(relation)) = self.local.relations.get(descendant)
                else {
                    return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                };
                if relation.has_column(to) {
                    return MutationResult::conflict(format!(
                        "column '{}' already exists on relation '{}'",
                        to, descendant
                    ));
                }
                if relation.generated_columns.values().any(|generated| {
                    generated.expression.as_deref().is_none_or(|source| {
                        crate::_internal::analysis::expr_visitor::ExprVisitor::rename_column_source(
                            source,
                            &descendant.name,
                            from,
                            to,
                        )
                        .is_none()
                    })
                }) {
                    return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                }
                let Some(provenance) = relation.column_inheritance.get(from) else {
                    return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                };
                let expected_parents = self
                    .local
                    .graph
                    .edges()
                    .iter()
                    .filter(|edge| {
                        edge.dependent == *descendant
                            && matches!(
                                edge.kind,
                                DependencyKind::InheritanceOf | DependencyKind::PartitionOf
                            )
                            && (edge.referenced == alter.id
                                || recursive_rename_descendants.contains(&edge.referenced))
                    })
                    .count() as u32;
                if provenance.parent_count > expected_parents {
                    return MutationResult::conflict(format!(
                        "cannot rename inherited column '{}'",
                        from
                    ));
                }
            }
        }
        if alter.only
            && matches!(alter.action, AlterTableActionMutation::RenameColumn { .. })
            && self.local.graph.edges().iter().any(|edge| {
                matches!(
                    edge.kind,
                    DependencyKind::InheritanceOf
                        | DependencyKind::PartitionOf
                        | DependencyKind::PartitionDetachPending
                ) && self.local.graph.resolve_rename(&edge.referenced)
                    == self.local.graph.resolve_rename(&alter.id)
            })
        {
            return MutationResult::conflict(
                "inherited columns must be renamed in child tables too",
            );
        }
        let concurrent_detach = matches!(
            alter.action,
            AlterTableActionMutation::DetachPartition {
                mode: crate::_internal::analysis::facts::DetachPartitionMode::Concurrently,
                ..
            }
        );
        if concurrent_detach && self.in_transaction() {
            return MutationResult::conflict(
                "DETACH PARTITION CONCURRENTLY cannot run inside a transaction",
            );
        }
        // `ALTER TABLE` is overloaded for views, materialized views and foreign
        // tables, but PostgreSQL admits each action only for specific relkinds
        // (`ATSimplePermissions`).  A partitioned table is a table for the
        // actions that include it and a distinct target for the ones that do not.
        match self.relation_lookup(&alter.id, |_| true) {
            ObjectLookup::Present => {}
            ObjectLookup::WrongKind => {
                return MutationResult::conflict(format!("object '{}' is not a table", alter.id));
            }
            ObjectLookup::AuthoritativelyAbsent | ObjectLookup::Tombstone => {
                return MutationResult::conflict(format!("relation '{}' does not exist", alter.id));
            }
            ObjectLookup::Unknown => {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
        }
        let target = self
            .local
            .relations
            .get(&alter.id)
            .and_then(|overlay| match overlay {
                RelationOverlay::Present(relation) => {
                    Some((relation.kind.clone(), relation.partition_type.is_some()))
                }
                RelationOverlay::Dropped => None,
            });
        let Some((kind, partitioned)) = target else {
            return self.unresolved(EvidenceCode::UnknownObjectState);
        };
        if !alter_table_action_permits(&alter.action, &kind, partitioned) {
            return MutationResult::conflict(format!(
                "ALTER action cannot be performed on relation '{}'",
                alter.id
            ));
        }

        if let AlterTableActionMutation::OwnerTo { new_owner } = &alter.action {
            let Some((owner, known)) = self.role_fact_identity(new_owner) else {
                return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
            };
            if !known {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
            if known && self.local.roles_known && self.present_role(&owner).is_none() {
                return MutationResult::conflict(format!("role '{}' does not exist", owner));
            }
            if known && !self.local.roles_known {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
            self.snapshot_relation(&alter.id);
            let result = match self.local.relations.get_mut(&alter.id) {
                Some(RelationOverlay::Present(relation)) => {
                    relation.owner = ObjectId::new("", owner.clone());
                    MutationResult::Applied
                }
                _ => MutationResult::conflict(format!("relation '{}' does not exist", alter.id)),
            };
            if matches!(result, MutationResult::Applied) {
                self.transfer_owned_sequence_owners(&alter.id, &ObjectId::new("", owner));
            }
            return result;
        }

        // Validate all targets before taking snapshots or creating implicit
        // sequences. RelationState's low-level column helper intentionally
        // ignores missing names, but PostgreSQL rejects those ALTER TABLE
        // actions; silently continuing would make later state look valid.
        let Some(RelationOverlay::Present(relation)) = self.local.relations.get(&alter.id) else {
            return MutationResult::conflict(format!("relation '{}' does not exist", alter.id));
        };
        let relation_columns_known =
            !relation.columns.is_empty() || relation.estimated_rows.is_some();
        if let AlterTableActionMutation::SetRuleMode { rule_name, mode } = &alter.action {
            let Some(rule_name) = rule_name else {
                return self.unresolved_statement(EvidenceCode::UnsupportedSemantics);
            };
            if !relation.rules.contains_key(rule_name) {
                return MutationResult::conflict(format!(
                    "rule '{}' does not exist on relation '{}'",
                    rule_name, alter.id
                ));
            }
            self.snapshot_relation(&alter.id);
            let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(&alter.id)
            else {
                unreachable!("relation presence was checked before rule mutation")
            };
            relation.rules.insert(rule_name.clone(), *mode);
            return MutationResult::Applied;
        }
        // Adding a column does not need to enumerate existing columns when the
        // baseline is incomplete; the new column is still represented in the
        // post-statement state.  Other column-targeting actions remain
        // conservative until their target list is known.
        if !relation_columns_known
            && matches!(
                alter.action,
                AlterTableActionMutation::DropColumn { .. }
                    | AlterTableActionMutation::RenameColumn { .. }
                    | AlterTableActionMutation::SetNotNull { .. }
                    | AlterTableActionMutation::DropNotNull { .. }
                    | AlterTableActionMutation::SetType { .. }
                    | AlterTableActionMutation::SetDefault { .. }
                    | AlterTableActionMutation::SetStorage { .. }
                    | AlterTableActionMutation::SetCompression { .. }
                    | AlterTableActionMutation::SetStatistics { .. }
                    | AlterTableActionMutation::SetGeneratedExpression { .. }
                    | AlterTableActionMutation::DropGeneratedExpression { .. }
                    | AlterTableActionMutation::SetColumnOptions { .. }
                    | AlterTableActionMutation::ResetColumnOptions { .. }
            )
        {
            return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
        }
        match &alter.action {
            AlterTableActionMutation::AddColumn {
                name,
                ty,
                if_not_exists,
                ..
            } if relation.has_column(name) => {
                return if *if_not_exists {
                    MutationResult::NoOp
                } else {
                    MutationResult::conflict(format!(
                        "column '{}' already exists with type {}; this statement adds it again with type {}",
                        name,
                        relation
                            .columns
                            .iter()
                            .find(|column| column.name == *name)
                            .and_then(|column| column.data_type.as_deref())
                            .unwrap_or("unknown"),
                        ty.as_deref().unwrap_or("unknown"),
                    ))
                };
            }
            AlterTableActionMutation::DropColumn {
                name, if_exists, ..
            } if !relation.has_column(name) => {
                return if *if_exists {
                    MutationResult::NoOp
                } else {
                    MutationResult::conflict(format!(
                        "column '{}' does not exist on relation '{}'",
                        name, alter.id
                    ))
                };
            }
            AlterTableActionMutation::RenameColumn { from, to } => {
                if !relation.has_column(from) {
                    return MutationResult::conflict(format!(
                        "column '{}' does not exist on relation '{}'",
                        from, alter.id
                    ));
                }
                if relation.has_column(to) {
                    return MutationResult::conflict(format!(
                        "column '{}' already exists on relation '{}'",
                        to, alter.id
                    ));
                }
                if relation.generated_columns.values().any(|generated| {
                    generated.expression.as_deref().is_none_or(|source| {
                        crate::_internal::analysis::expr_visitor::ExprVisitor::rename_column_source(
                            source,
                            &alter.id.name,
                            from,
                            to,
                        )
                        .is_none()
                    })
                }) {
                    return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                }
            }
            AlterTableActionMutation::SetNotNull { column }
            | AlterTableActionMutation::DropNotNull { column }
            | AlterTableActionMutation::SetType { column, .. }
            | AlterTableActionMutation::SetDefault { column, .. }
            | AlterTableActionMutation::SetStorage { column, .. }
            | AlterTableActionMutation::SetCompression { column, .. }
            | AlterTableActionMutation::SetStatistics { column, .. }
            | AlterTableActionMutation::SetGeneratedExpression { column, .. }
            | AlterTableActionMutation::DropGeneratedExpression { column, .. }
            | AlterTableActionMutation::SetColumnOptions { column, .. }
            | AlterTableActionMutation::ResetColumnOptions { column, .. }
                if !relation.has_column(column) =>
            {
                return MutationResult::conflict(format!(
                    "column '{}' does not exist on relation '{}'",
                    column, alter.id
                ));
            }
            AlterTableActionMutation::SetCompression {
                method: Some(method),
                ..
            } if !method.eq_ignore_ascii_case("pglz") => {
                // lz4 availability is a PostgreSQL build capability, not a
                // catalog fact carried by V8. Do not claim an exact result.
                return self.unresolved_statement(EvidenceCode::UnsupportedSemantics);
            }
            AlterTableActionMutation::SetGeneratedExpression { column, expr, .. } => {
                if !relation.generated_columns.contains_key(column) {
                    return MutationResult::conflict(format!(
                        "column '{}.{}' is not a generated column",
                        alter.id, column
                    ));
                }
                let Some(references) = expr.referenced_columns() else {
                    return self.unresolved_statement(EvidenceCode::UnsupportedSemantics);
                };
                if let Some(reference) = references
                    .iter()
                    .find(|reference| *reference == column || !relation.has_column(reference))
                {
                    return MutationResult::conflict(format!(
                        "generated expression for '{}.{}' references invalid column '{}'",
                        alter.id, column, reference
                    ));
                }
            }
            AlterTableActionMutation::DropGeneratedExpression { column, if_exists }
                if !relation.generated_columns.contains_key(column) =>
            {
                return if *if_exists {
                    MutationResult::NoOp
                } else {
                    MutationResult::conflict(format!(
                        "column '{}.{}' has no generated expression",
                        alter.id, column
                    ))
                };
            }
            _ => {}
        }

        match &alter.action {
            AlterTableActionMutation::DropConstraint {
                name, if_exists, ..
            } => {
                let member_id = ObjectId::new(
                    alter.id.schema.clone(),
                    format!("{}.{}", alter.id.name, name),
                );
                if let Some(result) = self.extension_member_drop_conflict(
                    crate::_internal::model::extension::ExtensionMemberKind::Constraint,
                    &member_id,
                    "constraint",
                ) {
                    return result;
                }
                if !self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return if *if_exists
                        && self.baseline_covers_family_object(
                            &alter.id,
                            crate::_internal::db::cache::CatalogFamily::Relations,
                        ) {
                        MutationResult::NoOp
                    } else if self.baseline_covers_family_object(
                        &alter.id,
                        crate::_internal::db::cache::CatalogFamily::Relations,
                    ) {
                        MutationResult::conflict(format!(
                            "constraint '{}' does not exist on relation '{}'",
                            name, alter.id
                        ))
                    } else {
                        self.unresolved(EvidenceCode::CatalogCoverageIncomplete)
                    };
                }
            }
            AlterTableActionMutation::ValidateConstraint {
                constraint_name: name,
            } => {
                if !self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::conflict(format!(
                        "constraint '{}' does not exist on relation '{}'",
                        name, alter.id
                    ));
                }
            }
            AlterTableActionMutation::RenameConstraint { old_name, new_name } => {
                if !self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), old_name.clone()))
                {
                    return MutationResult::conflict(format!(
                        "constraint '{}' does not exist on relation '{}'",
                        old_name, alter.id
                    ));
                }
                if self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), new_name.clone()))
                {
                    return MutationResult::conflict(format!(
                        "constraint '{}' already exists on relation '{}'",
                        new_name, alter.id
                    ));
                }
                let constraint = &self.local.constraints[&(alter.id.clone(), old_name.clone())];
                if matches!(
                    constraint.kind,
                    ConstraintKind::PrimaryKey | ConstraintKind::Unique | ConstraintKind::Exclusion
                ) && let Some(index) = &constraint.backing_index
                {
                    return self.apply_rename_relation(&Rename {
                        old_id: index.clone(),
                        new_id: ObjectId::new(index.schema.clone(), new_name.clone()),
                    });
                }
            }
            AlterTableActionMutation::AddForeignKey {
                constraint_name,
                from_columns,
                ..
            } => {
                let name = constraint_name.clone().unwrap_or_else(|| {
                    self.next_generated_constraint_name_avoiding(
                        &alter.id,
                        &alter.id.name,
                        Some(&from_columns.join("_")),
                        "fkey",
                        &HashSet::new(),
                    )
                });
                if self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::conflict(format!(
                        "constraint '{}' already exists on relation '{}'",
                        name, alter.id
                    ));
                }
            }
            AlterTableActionMutation::AddCheckConstraint {
                constraint_name,
                columns,
                columns_complete,
                ..
            } => {
                let name = constraint_name.clone().unwrap_or_else(|| {
                    self.next_generated_constraint_name_avoiding(
                        &alter.id,
                        &alter.id.name,
                        (*columns_complete && columns.len() == 1).then(|| columns[0].as_str()),
                        "check",
                        &HashSet::new(),
                    )
                });
                if self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::conflict(format!(
                        "constraint '{}' already exists on relation '{}'",
                        name, alter.id
                    ));
                }
            }
            AlterTableActionMutation::AddExcludeConstraint {
                constraint_name,
                columns,
                columns_complete,
            } => {
                let name = constraint_name.clone().unwrap_or_else(|| {
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
                if self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::conflict(format!(
                        "constraint '{}' already exists on relation '{}'",
                        name, alter.id
                    ));
                }
            }
            AlterTableActionMutation::AddUniqueConstraint {
                constraint_name,
                columns,
                using_index,
            }
            | AlterTableActionMutation::AddPrimaryKeyConstraint {
                constraint_name,
                columns,
                using_index,
            } => {
                if using_index.is_none() {
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
                        if relation_columns_known && !relation.has_column(column) {
                            return MutationResult::conflict(format!(
                                "constraint references column '{}' which does not exist on relation '{}'",
                                column, alter.id
                            ));
                        }
                    }
                }
                if matches!(
                    &alter.action,
                    AlterTableActionMutation::AddPrimaryKeyConstraint { .. }
                ) && self
                    .local
                    .constraints
                    .iter()
                    .any(|((table, _), constraint)| {
                        table == &alter.id && constraint.kind == ConstraintKind::PrimaryKey
                    })
                {
                    return MutationResult::conflict(format!(
                        "relation '{}' already has a primary key",
                        alter.id
                    ));
                }
                let name = constraint_name
                    .clone()
                    .or_else(|| using_index.as_ref().map(|index| index.name.clone()))
                    .unwrap_or_else(|| {
                        let primary = matches!(
                            &alter.action,
                            AlterTableActionMutation::AddPrimaryKeyConstraint { .. }
                        );
                        let name2 = (!primary).then(|| columns.join("_"));
                        self.next_generated_relation_name_avoiding(
                            &alter.id.schema,
                            &alter.id.name,
                            name2.as_deref(),
                            if primary { "pkey" } else { "key" },
                            &HashSet::new(),
                        )
                        .name
                    });
                if self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::conflict(format!(
                        "constraint '{}' already exists on relation '{}'",
                        name, alter.id
                    ));
                }
                if using_index.is_none()
                    && self.relation_namespace_object_is_present(&ObjectId::new(
                        &alter.id.schema,
                        &name,
                    ))
                {
                    return MutationResult::conflict(format!(
                        "constraint index '{}.{}' already exists",
                        alter.id.schema, name
                    ));
                }
            }
            AlterTableActionMutation::AlterConstraint { name, .. } => {
                let Some(name) = name else {
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                    return MutationResult::Applied;
                };
                if !self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::conflict(format!(
                        "constraint '{}' does not exist on relation '{}'",
                        name, alter.id
                    ));
                }
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                return MutationResult::Applied;
            }
            AlterTableActionMutation::AttachPartition {
                child, strategy, ..
            } => {
                if let Err(result) = self.ensure_relation_target(
                    child,
                    |kind| kind.is_table_like(),
                    format!("partition child relation '{}' does not exist", child),
                    format!("partition child '{}' is not a table", child),
                ) {
                    return result;
                }
                let Some(RelationOverlay::Present(parent)) = self.local.relations.get(&alter.id)
                else {
                    unreachable!("alter target presence established above")
                };
                let Some(partition_type) = &parent.partition_type else {
                    return MutationResult::conflict(format!(
                        "partition parent '{}' is not partitioned",
                        alter.id
                    ));
                };
                if strategy
                    .as_deref()
                    .is_some_and(|strategy| !strategy.eq_ignore_ascii_case(partition_type))
                {
                    return MutationResult::conflict(format!(
                        "partition strategy for '{}' does not match parent '{}' ({})",
                        child, alter.id, partition_type
                    ));
                }
                if self.local.graph.check_partition_cycle(&alter.id, child) {
                    return MutationResult::conflict(format!(
                        "attaching partition '{}' to '{}' would create a partition cycle",
                        child, alter.id
                    ));
                }
                let existing_parent = self.local.graph.edges().iter().find_map(|edge| {
                    (matches!(
                        edge.kind,
                        DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
                    ) && edge.dependent == *child)
                        .then_some(edge.referenced.clone())
                });
                if let Some(existing_parent) = existing_parent {
                    return MutationResult::conflict(format!(
                        "partition '{}' is already attached to '{}'",
                        child, existing_parent
                    ));
                }
                match self.partition_attachment_is_compatible(&alter.id, child) {
                    Ok(true) => {}
                    Ok(false) => {
                        // Missing catalog detail should lower confidence, not
                        // erase the attachment from the transition state. The
                        // taint keeps downstream findings conservative while
                        // the mutation retains the edge and bound.
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    }
                    Err(reason) => return MutationResult::conflict(reason),
                }
            }
            AlterTableActionMutation::DetachPartition { child, mode } => {
                if matches!(
                    mode,
                    crate::_internal::analysis::facts::DetachPartitionMode::Concurrently
                ) {
                    for edge in self
                        .local
                        .graph
                        .edges()
                        .iter()
                        .filter(|edge| edge.referenced == alter.id)
                    {
                        if matches!(edge.kind, DependencyKind::PartitionDetachPending) {
                            return MutationResult::conflict(format!(
                                "parent '{}' already has a partition pending detach",
                                alter.id
                            ));
                        }
                        if matches!(edge.kind, DependencyKind::PartitionOf)
                            && let Some(RelationOverlay::Present(partition)) =
                                self.local.relations.get(&edge.dependent)
                            && partition
                                .partition_bound
                                .as_deref()
                                .is_some_and(|bound| bound.trim().eq_ignore_ascii_case("DEFAULT"))
                        {
                            return MutationResult::conflict(format!(
                                "cannot detach concurrently from '{}' while it has a default partition",
                                alter.id
                            ));
                        }
                    }
                }
                if let Err(result) = self.ensure_relation_target(
                    child,
                    |kind| kind.is_table_like(),
                    format!("partition child relation '{}' does not exist", child),
                    format!("partition child '{}' is not a table", child),
                ) {
                    return result;
                }
                let expected_kind = match mode {
                    crate::_internal::analysis::facts::DetachPartitionMode::Finalize => {
                        DependencyKind::PartitionDetachPending
                    }
                    crate::_internal::analysis::facts::DetachPartitionMode::Immediate
                    | crate::_internal::analysis::facts::DetachPartitionMode::Concurrently => {
                        DependencyKind::PartitionOf
                    }
                };
                if !self.local.graph.edges().iter().any(|edge| {
                    edge.kind == expected_kind
                        && edge.dependent == *child
                        && edge.referenced == alter.id
                }) {
                    let action = match mode {
                        crate::_internal::analysis::facts::DetachPartitionMode::Finalize => {
                            "has no pending concurrent detach from"
                        }
                        _ => "is not attached to",
                    };
                    return MutationResult::conflict(format!(
                        "partition '{}' {} parent '{}'",
                        child, action, alter.id
                    ));
                }
                // Detaching a partition detaches its indexes too, so a later
                // DROP INDEX on either side must be allowed.
                self.detach_index_partitions_of_table(child);
            }
            AlterTableActionMutation::InheritTable { parent }
            | AlterTableActionMutation::NoInheritTable { parent } => {
                if let Err(result) = self.ensure_relation_target(
                    parent,
                    |kind| kind.is_table_like(),
                    format!("inheritance parent relation '{}' does not exist", parent),
                    format!("inheritance parent '{}' is not a table", parent),
                ) {
                    return result;
                }
                let has_edge = self.local.graph.edges().iter().any(|edge| {
                    matches!(edge.kind, DependencyKind::InheritanceOf)
                        && edge.dependent == alter.id
                        && edge.referenced == *parent
                });
                match &alter.action {
                    AlterTableActionMutation::InheritTable { .. } if has_edge => {
                        return MutationResult::conflict(format!(
                            "relation '{}' already inherits from '{}'",
                            alter.id, parent
                        ));
                    }
                    AlterTableActionMutation::NoInheritTable { .. } if !has_edge => {
                        return MutationResult::conflict(format!(
                            "relation '{}' does not inherit from '{}'",
                            alter.id, parent
                        ));
                    }
                    AlterTableActionMutation::InheritTable { .. }
                        if self.local.graph.check_inheritance_cycle(parent, &alter.id) =>
                    {
                        return MutationResult::conflict(format!(
                            "inheriting '{}' into '{}' would create an inheritance cycle",
                            parent, alter.id
                        ));
                    }
                    AlterTableActionMutation::InheritTable { .. } => {
                        let Some(RelationOverlay::Present(parent_relation)) =
                            self.local.relations.get(parent)
                        else {
                            unreachable!("inheritance parent presence was checked above")
                        };
                        let Some(RelationOverlay::Present(child_relation)) =
                            self.local.relations.get(&alter.id)
                        else {
                            unreachable!("alter target presence was checked above")
                        };
                        for parent_column in &parent_relation.columns {
                            let Some(child_column) = child_relation.get_column(&parent_column.name)
                            else {
                                return MutationResult::conflict(format!(
                                    "relation '{}' lacks inherited column '{}'",
                                    alter.id, parent_column.name
                                ));
                            };
                            let compatible_type = match (
                                parent_column.type_id.as_ref(),
                                child_column.type_id.as_ref(),
                                parent_column.data_type.as_deref(),
                                child_column.data_type.as_deref(),
                            ) {
                                (Some(left), Some(right), _, _) => left == right,
                                (_, _, Some(left), Some(right)) => {
                                    left.trim().eq_ignore_ascii_case(right.trim())
                                }
                                _ => false,
                            };
                            if !compatible_type
                                || (!parent_column.is_nullable && child_column.is_nullable)
                                || parent_relation.generated_columns.get(&parent_column.name)
                                    != child_relation.generated_columns.get(&parent_column.name)
                            {
                                return MutationResult::conflict(format!(
                                    "column '{}.{}' is incompatible with inheritance parent '{}'",
                                    alter.id, parent_column.name, parent
                                ));
                            }
                        }
                        for parent_constraint in
                            self.local.constraints.values().filter(|constraint| {
                                constraint.table_id == *parent
                                    && matches!(constraint.kind, ConstraintKind::Check)
                            })
                        {
                            let Some(child_constraint) = self
                                .local
                                .constraints
                                .get(&(alter.id.clone(), parent_constraint.name.clone()))
                            else {
                                return MutationResult::conflict(format!(
                                    "relation '{}' lacks inherited CHECK constraint '{}'",
                                    alter.id, parent_constraint.name
                                ));
                            };
                            let definitions_match = parent_constraint
                                .definition
                                .as_deref()
                                .zip(child_constraint.definition.as_deref())
                                .is_some_and(|(parent_definition, child_definition)| {
                                    Self::normalized_constraint_expression(parent_definition)
                                        == Self::normalized_constraint_expression(child_definition)
                                });
                            if !matches!(child_constraint.kind, ConstraintKind::Check)
                                || !definitions_match
                            {
                                return MutationResult::conflict(format!(
                                    "CHECK constraint '{}' is incompatible with inheritance parent '{}'",
                                    parent_constraint.name, parent
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
            AlterTableActionMutation::SetCluster { index: Some(index) } => {
                let owned = self.local.graph.edges().iter().any(|edge| {
                    matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                        && edge.dependent == *index
                        && edge.referenced == alter.id
                });
                if !owned {
                    return MutationResult::conflict(format!(
                        "index '{}' does not belong to relation '{}'",
                        index, alter.id
                    ));
                }
            }
            AlterTableActionMutation::SetReplicaIdentity {
                option:
                    crate::_internal::analysis::mutations::ReplicaIdentityMutation::UsingIndex(index),
            } => {
                let Some(edge) = self.local.graph.edges().iter().find(|edge| {
                    edge.dependent == *index
                        && edge.referenced == alter.id
                        && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                }) else {
                    return MutationResult::conflict(format!(
                        "replica identity index '{}' does not belong to relation '{}'",
                        index, alter.id
                    ));
                };
                let DependencyKind::IndexOnRelation {
                    definition,
                    dependency_columns_known,
                    is_immediate,
                    eligibility_known,
                    ..
                } = &edge.kind
                else {
                    unreachable!("index edge was checked above");
                };
                if !*eligibility_known || !*dependency_columns_known {
                    return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                }
                let all_keys_not_null = self
                    .local
                    .relations
                    .get(&alter.id)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => {
                            Some(definition.key_column_names().iter().all(|column| {
                                relation
                                    .columns
                                    .iter()
                                    .find(|candidate| candidate.name == *column)
                                    .is_some_and(|column| !column.is_nullable)
                            }))
                        }
                        RelationOverlay::Dropped => None,
                    })
                    .unwrap_or(false);
                if !definition.is_usable()
                    || !definition.unique
                    || definition.has_predicate()
                    || definition.has_expression_keys()
                    || !*is_immediate
                    || !all_keys_not_null
                {
                    return MutationResult::conflict(format!(
                        "index '{}' is not eligible for replica identity on relation '{}'",
                        index, alter.id
                    ));
                }
            }
            AlterTableActionMutation::SetOfType {
                type_id: Some(type_id),
            } => {
                if self
                    .local
                    .relations
                    .get(&alter.id)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => relation.of_type.as_ref(),
                        RelationOverlay::Dropped => None,
                    })
                    .is_some()
                {
                    return MutationResult::conflict(format!(
                        "relation '{}' is already a typed table",
                        alter.id
                    ));
                }
                let Some(crate::_internal::model::types::TypeOverlay::Present(
                    crate::_internal::model::types::TypeState {
                        kind: crate::_internal::model::types::TypeKind::Composite { fields },
                        ..
                    },
                )) = self.local.types.get(type_id)
                else {
                    return MutationResult::conflict(format!(
                        "type '{}' is not an existing composite type",
                        type_id
                    ));
                };
                let Some(RelationOverlay::Present(relation)) = self.local.relations.get(&alter.id)
                else {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                };
                let matches_layout = relation.columns.len() == fields.len()
                    && relation.columns.iter().zip(fields).all(|(column, field)| {
                        column.name == field.name
                            && column.data_type.as_deref().is_some_and(|data_type| {
                                data_type
                                    .trim()
                                    .eq_ignore_ascii_case(field.data_type.trim())
                            })
                    });
                if !matches_layout {
                    return MutationResult::conflict(format!(
                        "relation '{}' does not match composite type '{}' column layout",
                        alter.id, type_id
                    ));
                }
            }
            AlterTableActionMutation::SetOfType { type_id: None } => {
                let typed = self
                    .local
                    .relations
                    .get(&alter.id)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => relation.of_type.as_ref(),
                        RelationOverlay::Dropped => None,
                    });
                if typed.is_none() {
                    return MutationResult::conflict(format!(
                        "relation '{}' is not a typed table",
                        alter.id
                    ));
                }
            }
            _ => {}
        }

        let trigger_mode = match &alter.action {
            AlterTableActionMutation::DisableTrigger { trigger_name } => Some((
                trigger_name.as_deref(),
                crate::_internal::model::trigger::TriggerEnableMode::Disabled,
            )),
            AlterTableActionMutation::EnableTrigger { trigger_name } => Some((
                trigger_name.as_deref(),
                crate::_internal::model::trigger::TriggerEnableMode::Origin,
            )),
            AlterTableActionMutation::SetTriggerMode { trigger_name, mode } => {
                Some((trigger_name.as_deref(), *mode))
            }
            _ => None,
        };
        if let Some((trigger_name, enabled_mode)) = trigger_mode {
            let all = trigger_name.is_none_or(|name| {
                name.eq_ignore_ascii_case("all") || name.eq_ignore_ascii_case("user")
            });
            let trigger_ids: Vec<ObjectId> = self
                .local
                .triggers
                .iter()
                .filter_map(|(id, overlay)| {
                    let TriggerOverlay::Present(trigger) = overlay else {
                        return None;
                    };
                    (trigger.table_id == alter.id
                        && (all || trigger_name == Some(trigger.name.as_str())))
                    .then(|| id.clone())
                })
                .collect();
            if trigger_ids.is_empty() && !all {
                return MutationResult::conflict(format!(
                    "trigger '{}' does not exist on relation '{}'",
                    trigger_name.unwrap_or_default(),
                    alter.id
                ));
            }
            for trigger_id in trigger_ids {
                self.snapshot_trigger(&trigger_id);
                if let Some(TriggerOverlay::Present(trigger)) =
                    self.local.triggers.get_mut(&trigger_id)
                {
                    trigger.enabled_mode = enabled_mode;
                }
            }
            return MutationResult::Applied;
        }

        let mut effective_fk_target_columns: Option<Vec<String>> = None;
        if let AlterTableActionMutation::AddForeignKey {
            to_table,
            from_columns,
            to_columns,
            ..
        } = &alter.action
        {
            if from_columns.is_empty() {
                return MutationResult::conflict(format!(
                    "foreign key on relation '{}' has no source columns",
                    alter.id
                ));
            }
            if !to_columns.is_empty() && from_columns.len() != to_columns.len() {
                return MutationResult::conflict(format!(
                    "foreign key on '{}' has {} source columns but {} referenced columns",
                    alter.id,
                    from_columns.len(),
                    to_columns.len()
                ));
            }
            let mut source_columns = HashSet::new();
            if let Some(column) = from_columns
                .iter()
                .find(|column| !source_columns.insert(column.as_str()))
            {
                return MutationResult::conflict(format!(
                    "foreign key on '{}' repeats source column '{}'",
                    alter.id, column
                ));
            }
            let mut target_columns = HashSet::new();
            if let Some(column) = to_columns
                .iter()
                .find(|column| !target_columns.insert(column.as_str()))
            {
                return MutationResult::conflict(format!(
                    "foreign key on '{}' repeats referenced column '{}'",
                    alter.id, column
                ));
            }
            if let Some(RelationOverlay::Present(child)) = self.local.relations.get(&alter.id)
                && (!self.baseline_relation_is_known(&alter.id) || !child.columns.is_empty())
                && let Some(column) = from_columns.iter().find(|column| !child.has_column(column))
            {
                return MutationResult::conflict(format!(
                    "foreign key column '{}' does not exist on relation '{}'",
                    column, alter.id
                ));
            }

            if let Err(result) = self.ensure_relation_target(
                to_table,
                |kind| *kind == RelationKind::Table,
                format!(
                    "foreign key references relation '{}' which does not exist",
                    to_table
                ),
                format!("foreign key references '{}' which is not a table", to_table),
            ) {
                return result;
            }
            let Some(RelationOverlay::Present(parent)) = self.local.relations.get(to_table) else {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            };
            let target_columns_known =
                !self.baseline_relation_is_known(to_table) || !parent.columns.is_empty();
            if target_columns_known
                && let Some(column) = to_columns.iter().find(|column| !parent.has_column(column))
            {
                return MutationResult::conflict(format!(
                    "foreign key references column '{}.{}' which does not exist",
                    to_table, column
                ));
            }
            let target_keys = self.unique_keys_for_relation(to_table);
            let mut fk_evidence_unknown = target_keys.is_none();
            let referenced_columns = if to_columns.is_empty() {
                let primary_keys: Vec<&Vec<String>> = target_keys
                    .as_ref()
                    .map(|keys| {
                        keys.iter()
                            .filter_map(|(columns, is_primary)| is_primary.then_some(columns))
                            .collect()
                    })
                    .unwrap_or_default();
                if target_keys.is_some() && primary_keys.len() != 1 {
                    return MutationResult::conflict(format!(
                        "foreign key on '{}' omits referenced columns but target '{}' has no single primary key",
                        alter.id, to_table
                    ));
                }
                primary_keys.first().cloned().cloned().unwrap_or_default()
            } else {
                to_columns.clone()
            };
            effective_fk_target_columns = Some(referenced_columns.clone());
            if let Some(keys) = target_keys.as_ref()
                && !keys
                    .iter()
                    .any(|(columns, _)| columns == &referenced_columns)
            {
                return MutationResult::conflict(format!(
                    "foreign key on '{}' references columns on '{}' that are not backed by a primary key or unique key",
                    alter.id, to_table
                ));
            }
            let Some(child) =
                self.local
                    .relations
                    .get(&alter.id)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => Some(relation.clone()),
                        RelationOverlay::Dropped => None,
                    })
            else {
                unreachable!("alter target presence established above");
            };
            let source_types: Vec<Option<(Option<ObjectId>, Option<String>)>> = from_columns
                .iter()
                .map(|column| {
                    child
                        .get_column(column)
                        .map(|state| (state.type_id.clone(), state.data_type.clone()))
                })
                .collect();
            let target_types: Vec<Option<(Option<ObjectId>, Option<String>)>> = referenced_columns
                .iter()
                .map(|column| {
                    parent
                        .get_column(column)
                        .map(|state| (state.type_id.clone(), state.data_type.clone()))
                })
                .collect();
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
                // PostgreSQL permits some binary-compatible type pairs, but
                // the cache model does not carry the catalog cast graph.  A
                // mismatch therefore cannot be classified safely here.
                return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
            }
            if type_evidence_unknown {
                fk_evidence_unknown = true;
            }
            if fk_evidence_unknown {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        }

        let implicit_add = match &alter.action {
            AlterTableActionMutation::AddColumn {
                name,
                generation,
                identity_sequence,
                ..
            } => match generation {
                crate::_internal::analysis::facts::ColumnGeneration::Serial => Some((
                    self.next_implicit_sequence_id(&alter.id, name, &HashSet::new()),
                    name.clone(),
                    SequenceKind::SerialLike,
                    None,
                )),
                crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
                | crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault => Some((
                    identity_sequence
                        .as_ref()
                        .and_then(|options| options.sequence_name.clone())
                        .unwrap_or_else(|| {
                            self.next_implicit_sequence_id(&alter.id, name, &HashSet::new())
                        }),
                    name.clone(),
                    SequenceKind::Identity,
                    identity_sequence.clone(),
                )),
                crate::_internal::analysis::facts::ColumnGeneration::Ordinary
                | crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => None,
            },
            _ => None,
        };
        if let Some((sequence_id, _, _, _)) = &implicit_add
            && self.relation_namespace_is_taken(sequence_id)
        {
            return MutationResult::conflict(format!("relation '{}' already exists", sequence_id));
        }
        let owned_sequences_for_column: Vec<ObjectId> = match &alter.action {
            AlterTableActionMutation::DropColumn { name, .. }
            | AlterTableActionMutation::RenameColumn { from: name, .. } => self
                .local
                .sequences
                .iter()
                .filter_map(|(id, overlay)| match overlay {
                    SequenceOverlay::Present(sequence)
                        if sequence.owned_by.as_ref()
                            == Some(&(alter.id.clone(), name.clone())) =>
                    {
                        Some(id.clone())
                    }
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };

        let using_index = match &alter.action {
            AlterTableActionMutation::AddUniqueConstraint { using_index, .. }
            | AlterTableActionMutation::AddPrimaryKeyConstraint { using_index, .. } => {
                using_index.as_ref()
            }
            _ => None,
        };
        if let Some(index) = using_index {
            let Some(edge) = self
                .local
                .graph
                .edges()
                .iter()
                .find(|edge| {
                    matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                        && edge.dependent == *index
                })
                .cloned()
            else {
                return MutationResult::conflict(format!(
                    "constraint references index '{}' which does not exist",
                    index
                ));
            };
            if edge.referenced != alter.id {
                return MutationResult::conflict(format!(
                    "constraint index '{}' belongs to relation '{}', not '{}'",
                    index, edge.referenced, alter.id
                ));
            }
            if let DependencyKind::IndexOnRelation {
                definition,
                eligibility_known,
                ..
            } = &edge.kind
            {
                if !*eligibility_known {
                    return self.unresolved(EvidenceCode::CatalogCoverageIncomplete);
                }
                let is_btree = definition
                    .method
                    .as_deref()
                    .is_some_and(|method| method.eq_ignore_ascii_case("btree"));
                // A non-plain key means an explicit opclass, collation or sort
                // order, which a constraint index may not carry.
                if !definition.is_usable()
                    || !definition.unique
                    || definition.has_predicate()
                    || definition.has_expression_keys()
                    || !definition
                        .keys
                        .iter()
                        .all(crate::_internal::model::index::IndexKey::is_plain)
                    || !is_btree
                {
                    return MutationResult::conflict(format!(
                        "constraint index '{}' must be unique and non-partial, live/valid/ready, a btree with simple columns, and use the default definition",
                        index
                    ));
                }
            }

            let constraint_name = match &alter.action {
                AlterTableActionMutation::AddUniqueConstraint {
                    constraint_name, ..
                }
                | AlterTableActionMutation::AddPrimaryKeyConstraint {
                    constraint_name, ..
                } => constraint_name
                    .clone()
                    .unwrap_or_else(|| index.name.clone()),
                _ => unreachable!("using_index is only valid for key constraints"),
            };
            let adopted_index = ObjectId::new(index.schema.clone(), constraint_name);
            if adopted_index != *index && self.relation_namespace_object_is_present(&adopted_index)
            {
                return MutationResult::conflict(format!(
                    "constraint index '{}' already exists",
                    adopted_index
                ));
            }
        }

        let mut drop_column_constraints: HashSet<(ObjectId, String)> = HashSet::new();
        let mut drop_column_indexes: HashSet<ObjectId> = HashSet::new();
        let mut drop_column_statistics: HashSet<ObjectId> = HashSet::new();
        let mut cascade_generated_columns: HashSet<String> = HashSet::new();
        let mut cascade_view_roots: HashSet<ObjectId> = HashSet::new();
        if let AlterTableActionMutation::DropColumn { name, cascade, .. } = &alter.action {
            let resolved_table = self.local.graph.resolve_rename(&alter.id).clone();
            // The same rule as DROP TABLE: an unproven dependency set widens what the
            // drop may take with it, it does not cancel the drop. PostgreSQL
            // removes the column either way.
            let unproven_dependents = self.baseline_relation_is_known(&resolved_table)
                && (!self.baseline_has_coverage(
                    crate::_internal::db::cache::CatalogFamily::Dependencies,
                ) || self.baseline_scoped_family_object(
                    &resolved_table,
                    crate::_internal::db::cache::CatalogFamily::Relations,
                ));
            if unproven_dependents {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
            let mut unknown_dependency = false;
            let mut known_dependency = false;
            if let Some(RelationOverlay::Present(relation)) = self.local.relations.get(&alter.id) {
                for statistics in relation.extended_statistics.values() {
                    if statistics.columns.iter().any(|column| column == name) {
                        known_dependency = true;
                        if *cascade {
                            drop_column_statistics.insert(statistics.id.clone());
                        }
                    }
                }
            }
            for edge in self.local.graph.edges() {
                if !self.dependency_edge_is_current(edge) {
                    continue;
                }
                let dependent = self.local.graph.resolve_rename(&edge.dependent);
                let referenced = self.local.graph.resolve_rename(&edge.referenced);
                match &edge.kind {
                    DependencyKind::ForeignKey {
                        constraint_name,
                        from_columns,
                        to_columns,
                        ..
                    } if dependent == &resolved_table => {
                        if from_columns.is_empty() {
                            unknown_dependency = true;
                        } else if from_columns.iter().any(|column| column == name) {
                            known_dependency = true;
                            if let Some(constraint_name) = constraint_name {
                                drop_column_constraints
                                    .insert((resolved_table.clone(), constraint_name.clone()));
                            } else {
                                unknown_dependency = true;
                            }
                        }
                        // The source-side columns are the only columns on this
                        // relation represented by the edge. Keep this branch
                        // explicit so a future edge shape cannot be mistaken
                        // for a source-column dependency.
                        let _ = to_columns;
                    }
                    DependencyKind::ForeignKey {
                        constraint_name,
                        to_columns,
                        ..
                    } if referenced == &resolved_table => {
                        if to_columns.is_empty() {
                            unknown_dependency = true;
                        } else if to_columns.iter().any(|column| column == name) {
                            known_dependency = true;
                            if let Some(constraint_name) = constraint_name {
                                drop_column_constraints
                                    .insert((dependent.clone(), constraint_name.clone()));
                            } else {
                                unknown_dependency = true;
                            }
                        }
                    }
                    DependencyKind::ConstraintOnRelation {
                        constraint_name,
                        columns,
                        ..
                    } if dependent == &resolved_table => {
                        // A NOT NULL constraint is dropped implicitly with its
                        // column in PostgreSQL; it is not a dependent object
                        // that requires CASCADE on DROP COLUMN. The execution
                        // path removes the constraint state along with the
                        // column, so it must not gate or conflict here.
                        let is_not_null = self
                            .local
                            .constraints
                            .get(&(dependent.clone(), constraint_name.clone()))
                            .is_some_and(|constraint| {
                                matches!(constraint.kind, ConstraintKind::NotNull)
                            });
                        if is_not_null {
                            // Auto-dropped with the column; nothing to gate on.
                        } else if columns.is_empty() {
                            unknown_dependency = true;
                        } else if columns.iter().any(|column| column == name) {
                            known_dependency = true;
                            drop_column_constraints
                                .insert((resolved_table.clone(), constraint_name.clone()));
                        }
                    }
                    DependencyKind::IndexOnRelation {
                        definition,
                        dependency_columns,
                        dependency_columns_known,
                        ..
                    } if referenced == &resolved_table => {
                        // PostgreSQL automatically removes an index when a
                        // dependent column is dropped; it does not require
                        // CASCADE. Synchronized catalog rows prove expression
                        // and predicate columns through pg_depend. Locally
                        // parsed expression/predicate indexes do not have
                        // equivalent evidence and remain conservative.
                        if !*dependency_columns_known {
                            unknown_dependency = true;
                        } else if dependency_columns.iter().any(|column| column == name) {
                            drop_column_indexes.insert(dependent.clone());
                        } else if !definition.has_expression_keys() && !definition.has_predicate() {
                            debug_assert!(
                                definition
                                    .key_column_names()
                                    .into_iter()
                                    .chain(definition.included_column_names())
                                    .all(|column| dependency_columns.contains(&column))
                            );
                        }
                    }
                    DependencyKind::ViewDependency {
                        referenced_column, ..
                    } if referenced == &resolved_table => match referenced_column {
                        Some(column) if column == name => {
                            known_dependency = true;
                            if *cascade {
                                cascade_view_roots.insert(dependent.clone());
                            }
                        }
                        Some(_) => {}
                        None => unknown_dependency = true,
                    },
                    DependencyKind::ConstraintDependency {
                        constraint_name,
                        columns,
                    } if dependent == &resolved_table => {
                        if columns.iter().any(|column| column == name) {
                            known_dependency = true;
                            drop_column_constraints
                                .insert((resolved_table.clone(), constraint_name.clone()));
                        }
                    }
                    DependencyKind::ColumnGeneratedFrom {
                        column,
                        depends_on_column,
                    } if (dependent == &resolved_table || referenced == &resolved_table)
                        && column != name
                        && depends_on_column == name =>
                    {
                        known_dependency = true;
                        if *cascade {
                            cascade_generated_columns.insert(column.clone());
                        }
                    }
                    _ => {}
                }
            }

            // A generated dependent can itself participate in another
            // dependency. Compute the complete generated-column closure first
            // so CASCADE does not drop the source and leave a typed edge
            // referring to a generated column that PostgreSQL also removes.
            loop {
                let additional: Vec<String> = self
                    .local
                    .graph
                    .edges()
                    .iter()
                    .filter_map(|edge| {
                        let dependent = self.local.graph.resolve_rename(&edge.dependent);
                        let referenced = self.local.graph.resolve_rename(&edge.referenced);
                        match &edge.kind {
                            DependencyKind::ColumnGeneratedFrom {
                                column,
                                depends_on_column,
                            } if dependent == &resolved_table
                                && referenced == &resolved_table
                                && cascade_generated_columns.contains(depends_on_column)
                                && column != name
                                && !cascade_generated_columns.contains(column) =>
                            {
                                Some(column.clone())
                            }
                            _ => None,
                        }
                    })
                    .collect();
                if additional.is_empty() {
                    break;
                }
                cascade_generated_columns.extend(additional);
            }

            // A generated dependent can itself participate in another
            // dependency. Preserve exactness only for closures whose
            // dependent constraint identity is available; otherwise leave the
            // operation conservative rather than dropping a column while
            // retaining a typed foreign-key/constraint edge.
            if !cascade_generated_columns.is_empty() {
                for edge in self.local.graph.edges() {
                    if !self.dependency_edge_is_current(edge) {
                        continue;
                    }
                    let dependent = self.local.graph.resolve_rename(&edge.dependent);
                    let referenced = self.local.graph.resolve_rename(&edge.referenced);
                    match &edge.kind {
                        DependencyKind::IndexOnRelation {
                            dependency_columns,
                            dependency_columns_known,
                            ..
                        } if referenced == &resolved_table => {
                            if !*dependency_columns_known {
                                unknown_dependency = true;
                            } else if dependency_columns
                                .iter()
                                .any(|column| cascade_generated_columns.contains(column))
                            {
                                drop_column_indexes.insert(dependent.clone());
                            }
                        }
                        DependencyKind::ViewDependency {
                            referenced_column, ..
                        } if referenced == &resolved_table => match referenced_column {
                            Some(column) if cascade_generated_columns.contains(column) => {
                                cascade_view_roots.insert(dependent.clone());
                            }
                            Some(_) => {}
                            None => unknown_dependency = true,
                        },
                        DependencyKind::ForeignKey {
                            constraint_name,
                            from_columns,
                            to_columns,
                            ..
                        } if (dependent == &resolved_table
                            && from_columns
                                .iter()
                                .any(|column| cascade_generated_columns.contains(column)))
                            || (referenced == &resolved_table
                                && to_columns
                                    .iter()
                                    .any(|column| cascade_generated_columns.contains(column))) =>
                        {
                            if let Some(constraint_name) = constraint_name {
                                known_dependency = true;
                                drop_column_constraints
                                    .insert((dependent.clone(), constraint_name.clone()));
                            } else {
                                unknown_dependency = true;
                            }
                        }
                        DependencyKind::ConstraintOnRelation {
                            constraint_name,
                            columns,
                            ..
                        }
                        | DependencyKind::ConstraintDependency {
                            constraint_name,
                            columns,
                        } if dependent == &resolved_table
                            && columns
                                .iter()
                                .any(|column| cascade_generated_columns.contains(column)) =>
                        {
                            known_dependency = true;
                            drop_column_constraints
                                .insert((dependent.clone(), constraint_name.clone()));
                        }
                        DependencyKind::ColumnGeneratedFrom {
                            column,
                            depends_on_column,
                        } if referenced == &resolved_table
                            && cascade_generated_columns.contains(depends_on_column)
                            && !cascade_generated_columns.contains(column) => {}
                        _ => {}
                    }
                }
            }

            // Every CHECK/EXCLUDE constraint must have a typed dependency edge.
            // An empty edge is authoritative for a constant expression; a
            // missing edge means the cache is incomplete.
            for (table_id, constraint_name) in self.local.constraints.keys() {
                if self.local.graph.resolve_rename(table_id) != &resolved_table {
                    continue;
                }
                let represented = self.local.graph.edges().iter().any(|edge| {
                    (edge.dependent == resolved_table
                        && matches!(
                            &edge.kind,
                            DependencyKind::ConstraintOnRelation {
                                constraint_name: name,
                                ..
                            } if name == constraint_name
                        ))
                        || matches!(
                            &edge.kind,
                            DependencyKind::ConstraintDependency {
                                constraint_name: name,
                                ..
                            } if edge.dependent == resolved_table && name == constraint_name
                        )
                        || matches!(
                            &edge.kind,
                            DependencyKind::ForeignKey {
                                constraint_name: Some(name),
                                ..
                            } if (edge.dependent == resolved_table
                                || edge.referenced == resolved_table)
                                && name == constraint_name
                        )
                });
                if !represented {
                    unknown_dependency = true;
                }
            }

            if known_dependency && !cascade {
                return MutationResult::conflict(format!(
                    "column '{}.{}' has dependent objects; use CASCADE",
                    alter.id, name
                ));
            }
            if unknown_dependency {
                // PostgreSQL drops the column; only the fate of dependents the
                // pre-scan could not classify is open. Record that and fall
                // through, because abandoning the mutation would claim the
                // column survives when it cannot.
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        }

        self.snapshot_relation(&alter.id);
        let context = AlterTableContext {
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
        };
        self.alter_table_finish(alter, context)
    }
}
