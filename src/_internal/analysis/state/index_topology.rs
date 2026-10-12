//! The single owner of index-to-index partition topology.
//!
//! PostgreSQL keeps index attachments in `pg_inherits`, so an attached child
//! index is a partition of its parent index: dropping the parent drops the
//! child, and the child cannot be dropped alone. Every path that creates,
//! removes or inspects that relationship comes through here, so the graph and
//! the catalog cannot drift apart.

use super::AnalysisState;
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::index::IndexComparability;

/// Why an attachment was refused.
pub(crate) enum AttachRefusal {
    /// The child index's table is not a partition of the parent's table.
    NotAPartition,
    /// The child is already attached to some other parent index.
    AttachedElsewhere,
    /// The two definitions do not match.
    DefinitionsDiffer,
    /// The parent has a constraint the child lacks.
    ConstraintMismatch,
}

/// Build the definition's keys, resolving written operator classes.
///
/// PostgreSQL records the resolved class whether or not one was written, so a
/// class that names the type's default is recorded as absent here too. That is
/// what makes a simulator comparison agree with the catalog.
impl AnalysisState {
    pub(super) fn resolved_statement_index_keys(
        &self,
        create: &crate::_internal::analysis::mutations::CreateIndex,
    ) -> Vec<crate::_internal::model::index::IndexKey> {
        let method = create
            .using_method
            .clone()
            .unwrap_or_else(|| "btree".to_string());
        let search_path = self.local.search_path.to_vec();
        // Column types decide whether a written class is the default one.
        let types: Vec<Option<Option<String>>> = create
            .key_columns
            .iter()
            .map(|column| {
                self.local
                    .relations
                    .get(&create.table)
                    .and_then(|overlay| match overlay {
                        super::RelationOverlay::Present(relation) => relation
                            .columns
                            .iter()
                            .find(|candidate| &candidate.name == column)
                            .map(|found| found.data_type.clone()),
                        super::RelationOverlay::Dropped => None,
                    })
            })
            .collect();
        let opclasses: Vec<Option<String>> = create
            .key_opclasses
            .iter()
            .enumerate()
            .map(|(position, written)| {
                let Some(name) = written else { return None };
                // An expression key has no column type to resolve against, so a
                // written class stays recorded.
                let Some(Some(Some(intype))) = types.get(position) else {
                    return Some(name.clone());
                };
                match self
                    .local
                    .opclasses
                    .is_default_for(name, intype, &method, &search_path)
                {
                    Some(false) | None => Some(name.clone()),
                    Some(true) => None,
                }
            })
            .collect();
        crate::_internal::model::index::statement_index_keys(
            &create.key_columns,
            &create.key_expressions,
            &create.key_orders,
            &opclasses,
            &create.key_collations,
        )
    }

    /// The index definition recorded for `id`, if the index is present.
    pub(super) fn index_definition_of(
        &self,
        id: &ObjectId,
    ) -> Option<&crate::_internal::model::index::IndexDefinition> {
        self.local
            .graph
            .edges()
            .iter()
            .find(|edge| {
                edge.dependent == *id && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
            })
            .and_then(|edge| match &edge.kind {
                DependencyKind::IndexOnRelation { definition, .. } => Some(definition),
                _ => None,
            })
    }

    /// The parent index `child` is currently attached to, if any.
    pub(super) fn index_parent_of(&self, child: &ObjectId) -> Option<&ObjectId> {
        self.local
            .graph
            .edges()
            .iter()
            .find(|edge| {
                edge.dependent == *child && matches!(edge.kind, DependencyKind::IndexPartitionOf)
            })
            .map(|edge| &edge.referenced)
    }

    /// The table an index is defined on.
    pub(super) fn index_table_of(&self, index: &ObjectId) -> Option<&ObjectId> {
        self.local.graph.index_table_of(index)
    }

    /// Whether the definitions describe the same index shape.
    ///
    /// Mirrors PostgreSQL's `CompareIndexInfo`: equal key counts (INCLUDE
    /// included, via the total key count), equal opclasses, equal collations
    /// and equal sort order, with columns paired by name through the
    /// partition's attribute map. Sort order is compared normalized, so
    /// `ASC NULLS LAST` matches `DESC NULLS FIRST` — verified live.
    pub(super) fn index_definitions_match(&self, parent: &ObjectId, child: &ObjectId) -> bool {
        let (Some(parent_definition), Some(child_definition)) = (
            self.index_definition_of(parent),
            self.index_definition_of(child),
        ) else {
            return false;
        };
        if parent_definition.comparability(child_definition) != IndexComparability::Comparable {
            return false;
        }
        // A partitioned parent is invalid until every partition is attached, so
        // an unusable definition never counts as a match.
        parent_definition.is_usable()
            && child_definition.is_usable()
            && parent_definition == child_definition
    }

    /// Why an attachment cannot proceed, in PostgreSQL's check order.
    pub(super) fn index_attach_refusal(
        &self,
        parent: &ObjectId,
        child: &ObjectId,
    ) -> Option<AttachRefusal> {
        if let Some(current) = self.index_parent_of(child) {
            let same =
                self.local.graph.resolve_rename(current) == self.local.graph.resolve_rename(parent);
            // Re-attaching to the same parent is a no-op, not an error.
            if !same {
                return Some(AttachRefusal::AttachedElsewhere);
            }
            return None;
        }
        let (Some(parent_table), Some(child_table)) =
            (self.index_table_of(parent), self.index_table_of(child))
        else {
            return Some(AttachRefusal::NotAPartition);
        };
        let is_partition = self
            .local
            .graph
            .partitions_of(parent_table)
            .into_iter()
            .any(|partition| {
                self.local.graph.resolve_rename(partition)
                    == self.local.graph.resolve_rename(child_table)
            });
        if !is_partition {
            return Some(AttachRefusal::NotAPartition);
        }
        if !self.index_definitions_match(parent, child) {
            return Some(AttachRefusal::DefinitionsDiffer);
        }
        if self.constraint_backing(parent) != self.constraint_backing(child) {
            return Some(AttachRefusal::ConstraintMismatch);
        }
        None
    }

    /// The constraint name backing an index, if any.
    ///
    /// PostgreSQL refuses to attach when the parent index backs a constraint
    /// and the child does not, and attaches the constraint alongside the
    /// indexes when both have it.
    fn constraint_backing(&self, index: &ObjectId) -> Option<String> {
        self.local
            .constraints
            .values()
            .find(|constraint| {
                constraint.backing_index.as_ref() == Some(index)
                    && matches!(
                        constraint.kind,
                        crate::_internal::model::constraint::ConstraintKind::PrimaryKey
                            | crate::_internal::model::constraint::ConstraintKind::Unique
                            | crate::_internal::model::constraint::ConstraintKind::Exclusion
                    )
            })
            .map(|constraint| constraint.name.clone())
    }

    /// Record `child` as a partition of `parent`.
    pub(super) fn record_index_partition(&mut self, parent: &ObjectId, child: &ObjectId) {
        self.snapshot_graph();
        self.local.graph.add_edge(DependencyEdge::new(
            child.clone(),
            parent.clone(),
            DependencyKind::IndexPartitionOf,
        ));
    }

    /// Drop every attachment whose child index lives on `table`.
    ///
    /// PostgreSQL detaches a partition's indexes as soon as the partition is
    /// detached, including on the first phase of `DETACH PARTITION
    /// CONCURRENTLY`, so a later `DROP INDEX` on either side must succeed.
    pub(super) fn detach_index_partitions_of_table(&mut self, table: &ObjectId) {
        let doomed: Vec<ObjectId> = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                matches!(edge.kind, DependencyKind::IndexPartitionOf)
                    && self
                        .index_table_of(&edge.dependent)
                        .is_some_and(|owner| owner == table)
            })
            .map(|edge| edge.dependent.clone())
            .collect();
        if doomed.is_empty() {
            return;
        }
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !(matches!(edge.kind, DependencyKind::IndexPartitionOf)
                && doomed.contains(&edge.dependent))
        });
    }

    /// The child indexes that would fall if `parent` were dropped.
    pub(super) fn index_partitions_of(&self, parent: &ObjectId) -> Vec<ObjectId> {
        self.local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                matches!(edge.kind, DependencyKind::IndexPartitionOf)
                    && self.local.graph.resolve_rename(&edge.referenced)
                        == self.local.graph.resolve_rename(parent)
            })
            .map(|edge| edge.dependent.clone())
            .collect()
    }
}
