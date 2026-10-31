//! The single owner of index-to-index partition topology.
//!
//! PostgreSQL keeps index attachments in `pg_inherits`, so an attached child
//! index is a partition of its parent index: dropping the parent drops the
//! child, and the child cannot be dropped alone. Every path that creates,
//! removes or inspects that relationship comes through here, so the graph and
//! the catalog cannot drift apart.

use super::AnalysisState;
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::CreateIndex;
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::builtin_type::TypeCategory;
use crate::_internal::model::column::Column;
use crate::_internal::model::constraint::ConstraintKind;
use crate::_internal::model::data_type::ParsedDataType;
use crate::_internal::model::index::{
    IndexEquivalence, IndexKey, KeyCollation, KeyOpclass, ResolvedName, WrittenName,
    statement_index_keys,
};
use crate::_internal::model::types::{TypeKind, TypeOverlay};
use std::collections::HashSet;

/// The outcome of comparing two index shapes.
#[derive(PartialEq, Eq)]
enum IndexComparison {
    Match,
    Mismatch,
    Undecidable,
}

/// Why an attachment was refused.
pub(crate) enum AttachRefusal {
    /// The child index's table is not a partition of the parent's table.
    NotAPartition,
    /// The child is already attached to some other parent index.
    AttachedElsewhere,
    /// The partition's table already carries an index attached to this parent.
    DuplicateAttachment,
    /// The two definitions do not match.
    DefinitionsDiffer,
    /// An opaque expression leaves equivalence undecidable, not unequal.
    EquivalenceUnknown,
    /// The parent index backs a constraint but the child backs none.
    MissingConstraint,
    /// The parent index backs a primary key and a covered column is nullable.
    PrimaryKeyNotNull { column: String },
}

/// The reuse rules a partition-child lookup follows.
///
/// Creating an index only requires a constraint to exist on the child when the
/// parent backs one (`DefineIndex`); attaching a partition table requires the
/// kinds to match as well (`AttachPartitionEnsureIndexes`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ChildReuseRule {
    Creation,
    TableAttach,
}

/// Build the definition's keys, resolving written operator classes and
/// collations the way PostgreSQL would.
impl AnalysisState {
    pub(super) fn resolved_statement_index_keys(&self, create: &CreateIndex) -> Vec<IndexKey> {
        let method = create
            .using_method
            .clone()
            .unwrap_or_else(|| "btree".to_string());
        let mut column_names = create.key_columns.iter();
        let mut opclasses = Vec::with_capacity(create.key_expressions.len());
        let mut collations = Vec::with_capacity(create.key_expressions.len());
        for (position, expression) in create.key_expressions.iter().enumerate() {
            // An expression key consumes no column, so the names must be
            // paired position by position rather than indexed alike.
            let column = if expression.is_some() {
                None
            } else {
                column_names
                    .next()
                    .and_then(|name| self.column_of(&create.table, name))
            };
            opclasses.push(self.statement_key_opclass(
                create.key_opclasses.get(position).and_then(Option::as_ref),
                column,
                &method,
            ));
            collations.push(self.statement_key_collation(
                create.key_collations.get(position).and_then(Option::as_ref),
            ));
        }
        statement_index_keys(
            &create.key_columns,
            &create.key_expressions,
            &create.key_orders,
            &opclasses,
            &collations,
        )
    }

    fn column_of(&self, table: &ObjectId, name: &str) -> Option<&Column> {
        match self.local.relations.get(table)? {
            super::RelationOverlay::Present(relation) => {
                relation.columns.iter().find(|column| column.name == name)
            }
            super::RelationOverlay::Dropped => None,
        }
    }

    /// One key's operator-class identity, with a written class normalized to
    /// the default exactly where the resolution lands in the default family.
    fn statement_key_opclass(
        &self,
        written: Option<&WrittenName>,
        column: Option<&Column>,
        method: &str,
    ) -> KeyOpclass {
        let default_family = column.and_then(|column| {
            self.default_family_for_column(
                column.data_type.as_deref(),
                column.type_id.as_ref(),
                method,
            )
        });
        match written {
            None => KeyOpclass::Default(default_family),
            Some(written) => {
                match self
                    .local
                    .opclasses
                    .resolve(written, method, &self.local.search_path)
                {
                    Some(entry) => {
                        // A written class that resolves into the type's default
                        // family is the same identity as omitting it, which is
                        // how the catalog records both spellings.
                        if default_family.as_ref() == Some(&entry.family) {
                            KeyOpclass::Default(Some(entry.family.clone()))
                        } else {
                            KeyOpclass::Explicit(entry.family.clone())
                        }
                    }
                    None => KeyOpclass::Unresolved,
                }
            }
        }
    }

    fn statement_key_collation(&self, written: Option<&WrittenName>) -> KeyCollation {
        match written {
            None => KeyCollation::Derived,
            Some(written) => match self
                .local
                .collations
                .resolve(written, &self.local.search_path)
            {
                Some(resolved) => KeyCollation::Resolved(resolved),
                None => KeyCollation::Unresolved,
            },
        }
    }

    /// The family of the class PostgreSQL would choose for a column type.
    ///
    /// `None` is an unestablished default: PostgreSQL still chooses a class,
    /// but the model cannot name its family with certainty, and an
    /// unestablished default must not be equated with a written one.
    /// Partition-linked tables share their column definitions, so two
    /// unestablished defaults are the same choice.
    fn default_family_for_column(
        &self,
        data_type: Option<&str>,
        type_id: Option<&ObjectId>,
        method: &str,
    ) -> Option<ResolvedName> {
        let raw = data_type?;
        if let Some(id) = type_id {
            match self.local.types.get(id) {
                Some(TypeOverlay::Present(state)) => {
                    return self.default_family_for_user_type(state, method);
                }
                Some(TypeOverlay::Dropped) => return None,
                None => {}
            }
        }
        self.default_family_for_builtin(raw, method)
    }

    fn default_family_for_user_type(
        &self,
        state: &crate::_internal::model::types::TypeState,
        method: &str,
    ) -> Option<ResolvedName> {
        let candidates: &[&str] = match &state.kind {
            TypeKind::Domain {
                base_type,
                base_type_id,
                ..
            } => {
                return self.default_family_for_column(
                    Some(base_type),
                    base_type_id.as_ref(),
                    method,
                );
            }
            TypeKind::Enum { .. } => &["anyenum"],
            TypeKind::Range { .. } => &["anyrange"],
            TypeKind::Multirange { .. } => &["anymultirange"],
            TypeKind::Composite { .. } => &["record"],
            // A user base type has no pseudo-type fallback; only a class
            // written for it exactly can be its default.
            TypeKind::Base { .. } => &[],
        };
        // A class created for the type itself wins over the pseudo-type
        // fallback, exactly as `GetDefaultOpClass` prefers the exact match.
        self.local
            .opclasses
            .default_class(Some(&state.id.name), method, candidates)
            .map(|entry| entry.family.clone())
    }

    fn default_family_for_builtin(&self, raw: &str, method: &str) -> Option<ResolvedName> {
        let parsed = ParsedDataType::parse(raw, &self.local.builtin_types);
        // Every array type is binary-coercible to `anyarray`, whatever its
        // element type, so the element need not resolve.
        if parsed.array_dimensions > 0 {
            return self
                .local
                .opclasses
                .default_class(None, method, &["anyarray"])
                .map(|entry| entry.family.clone());
        }
        let builtin = parsed.builtin()?;
        let exact = self
            .local
            .opclasses
            .default_class(Some(&builtin.canonical), method, &[])
            .map(|entry| entry.family.clone());
        if exact.is_some() {
            return exact;
        }
        // `varchar` has no class of its own; PostgreSQL's binary-compatible
        // fallback lands on `text`, the preferred type of its category.
        if builtin.is_named("varchar") {
            return self
                .local
                .opclasses
                .default_class(Some("text"), method, &[])
                .map(|entry| entry.family.clone());
        }
        if builtin.category == TypeCategory::Range {
            // The catalogue does not distinguish a built-in range from its
            // multirange (`typtype` is not recorded), so the two
            // pseudo-typed defaults refuse to decide between themselves.
            return self
                .local
                .opclasses
                .default_class(None, method, &["anyrange", "anymultirange"])
                .map(|entry| entry.family.clone());
        }
        None
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
    /// The comparison is exactly [`IndexDefinition::attach_equivalence`], so it
    /// covers the properties PostgreSQL's `CompareIndexInfo` covers and no
    /// others — notably not sort order, which server and simulator both ignore
    /// when attaching. Lifecycle state plays no part either: PostgreSQL
    /// attaches to a parent that is invalid precisely because partitions are
    /// still missing.
    fn compare_index_definitions(&self, parent: &ObjectId, child: &ObjectId) -> IndexComparison {
        let (Some(parent_definition), Some(child_definition)) = (
            self.index_definition_of(parent),
            self.index_definition_of(child),
        ) else {
            return IndexComparison::Mismatch;
        };
        match parent_definition.attach_equivalence(child_definition) {
            IndexEquivalence::Identical => IndexComparison::Match,
            IndexEquivalence::Different => IndexComparison::Mismatch,
            // Undecidable is not unequal; a conflict would claim more than is known.
            IndexEquivalence::Unknown => IndexComparison::Undecidable,
        }
    }

    /// Why an attachment cannot proceed, in PostgreSQL's check order.
    pub(super) fn index_attach_refusal(
        &self,
        parent: &ObjectId,
        child: &ObjectId,
    ) -> Option<AttachRefusal> {
        let resolved_parent = self.local.graph.resolve_rename(parent);
        let attached_here = self
            .index_parent_of(child)
            .is_some_and(|current| self.local.graph.resolve_rename(current) == resolved_parent);
        // Re-attaching to the same parent is not an error; it re-triggers the
        // parent's validation.
        if attached_here {
            return None;
        }
        // `refuseDupeIndexAttach`: the partition's table already carries some
        // index attached to this parent, whichever index that is.
        if let Some(child_table) = self.index_table_of(child) {
            let child_table = self.local.graph.resolve_rename(child_table);
            let duplicate = self.local.graph.edges().iter().any(|edge| {
                matches!(edge.kind, DependencyKind::IndexPartitionOf)
                    && self.local.graph.resolve_rename(&edge.referenced) == resolved_parent
                    && self.local.graph.resolve_rename(&edge.dependent)
                        != self.local.graph.resolve_rename(child)
                    && self
                        .index_table_of(&edge.dependent)
                        .is_some_and(|owner| self.local.graph.resolve_rename(owner) == child_table)
            });
            if duplicate {
                return Some(AttachRefusal::DuplicateAttachment);
            }
        }
        if self.index_parent_of(child).is_some() {
            return Some(AttachRefusal::AttachedElsewhere);
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
        match self.compare_index_definitions(parent, child) {
            IndexComparison::Mismatch => return Some(AttachRefusal::DefinitionsDiffer),
            IndexComparison::Undecidable => return Some(AttachRefusal::EquivalenceUnknown),
            IndexComparison::Match => {}
        }
        let parent_backing = self.constraint_backing(parent);
        let child_backing = self.constraint_backing(child);
        // `CompareIndexInfo` compares exclusion-op presence and content, which
        // the model records nowhere; an exclusion index on either side leaves
        // that comparison unsettled.
        match (
            parent_backing == Some(ConstraintKind::Exclusion),
            child_backing == Some(ConstraintKind::Exclusion),
        ) {
            (true, true) => return Some(AttachRefusal::EquivalenceUnknown),
            (true, false) | (false, true) => return Some(AttachRefusal::DefinitionsDiffer),
            (false, false) => {}
        }
        // A parent that backs a constraint requires the child to back one too;
        // this path does not compare their kinds.
        if parent_backing.is_some() && child_backing.is_none() {
            return Some(AttachRefusal::MissingConstraint);
        }
        if parent_backing == Some(ConstraintKind::PrimaryKey)
            && let Some(refusal) = self.partition_key_nullability(child)
        {
            return Some(refusal);
        }
        None
    }

    /// `verifyPartitionIndexNotNull`: every column a primary-key partition
    /// index covers must be NOT NULL on the partition's table.
    fn partition_key_nullability(&self, child: &ObjectId) -> Option<AttachRefusal> {
        let (Some(table), Some(definition)) =
            (self.index_table_of(child), self.index_definition_of(child))
        else {
            return Some(AttachRefusal::EquivalenceUnknown);
        };
        let Some(super::RelationOverlay::Present(relation)) = self.local.relations.get(table)
        else {
            return Some(AttachRefusal::EquivalenceUnknown);
        };
        definition
            .key_column_names()
            .into_iter()
            .find_map(|column_name| {
                match relation
                    .columns
                    .iter()
                    .find(|column| column.name == column_name)
                {
                    Some(column) if column.is_nullable => Some(AttachRefusal::PrimaryKeyNotNull {
                        column: column_name,
                    }),
                    Some(_) => None,
                    // A covered column the model cannot see settles nothing.
                    None => Some(AttachRefusal::EquivalenceUnknown),
                }
            })
    }

    /// The kind of constraint an index backs, if any.
    ///
    /// The direct attachment path only asks whether a constraint exists; the
    /// kind matters when reusing an index while a partition table is attached,
    /// and when a primary key imposes NOT NULL on the partition.
    pub(super) fn constraint_backing(&self, index: &ObjectId) -> Option<ConstraintKind> {
        self.local
            .constraints
            .values()
            .find(|constraint| {
                constraint.backing_index.as_ref() == Some(index)
                    && matches!(
                        constraint.kind,
                        ConstraintKind::PrimaryKey
                            | ConstraintKind::Unique
                            | ConstraintKind::Exclusion
                    )
            })
            .map(|constraint| constraint.kind)
    }

    /// Whether every partition carries an attached child index that is itself
    /// valid.
    ///
    /// PostgreSQL's `validatePartitionedIndex` counts attached children whose
    /// `indisvalid` is set against the parent table's partition count; a child
    /// that is attached but invalid does not cover its partition.
    pub(super) fn index_is_fully_attached(&self, index: &ObjectId) -> bool {
        let Some(table) = self.index_table_of(index) else {
            return false;
        };
        let partitions = self.local.graph.partitions_of(table);
        if partitions.is_empty() {
            return true;
        }
        let attached = self.index_partitions_of(index);
        partitions.iter().all(|partition| {
            attached.iter().any(|child| {
                self.index_table_of(child).is_some_and(|owner| {
                    self.local.graph.resolve_rename(owner)
                        == self.local.graph.resolve_rename(partition)
                }) && self
                    .index_definition_of(child)
                    .is_some_and(|definition| definition.valid)
            })
        })
    }

    /// Record `child` as a partition of `parent`.
    ///
    /// Whether this revalidates the parent is the caller's decision:
    /// `ALTER INDEX ... ATTACH PARTITION` does, while creating a parent index
    /// or attaching a partition table does not, matching PostgreSQL, which
    /// only calls `validatePartitionedIndex` from the attach path.
    pub(super) fn record_index_partition(&mut self, parent: &ObjectId, child: &ObjectId) {
        self.snapshot_graph();
        self.local.graph.add_edge(DependencyEdge::new(
            child.clone(),
            parent.clone(),
            DependencyKind::IndexPartitionOf,
        ));
    }

    /// PostgreSQL's `validatePartitionedIndex`: an invalid parent becomes valid
    /// once every partition carries an attached valid child; a parent that is
    /// itself attached then revalidates its own parent in turn.
    pub(super) fn validate_partitioned_index(&mut self, index: &ObjectId) {
        let Some(definition) = self.index_definition_of(index) else {
            return;
        };
        if definition.valid {
            return;
        }
        if !self.index_is_fully_attached(index) {
            return;
        }
        self.snapshot_graph_full();
        self.local.graph.update_index_definition(index, |stored| {
            stored.valid = true;
            stored.ready = true;
            stored.live = true;
        });
        if let Some(parent) = self.index_parent_of(index).cloned() {
            self.validate_partitioned_index(&parent);
        }
    }

    /// PostgreSQL's partition-index recursion: ensure `table` carries a child
    /// index for the partitioned `parent`, reusing an unattached equivalent
    /// index when one qualifies and otherwise creating a clone, recursively
    /// when the table is itself partitioned. Returns the chosen child and
    /// whether it is valid.
    pub(super) fn ensure_partition_index_child(
        &mut self,
        parent: &ObjectId,
        table: &ObjectId,
        template: &DependencyKind,
        rule: ChildReuseRule,
    ) -> (ObjectId, bool) {
        let DependencyKind::IndexOnRelation {
            definition: template_definition,
            ..
        } = template
        else {
            unreachable!("partition index templates are index edges")
        };
        let resolved_table = self.local.graph.resolve_rename(table).clone();
        let parent_backing = self.constraint_backing(parent);
        let reused = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                    && self.index_parent_of(&edge.dependent).is_none()
                    && self.index_table_of(&edge.dependent).is_some_and(|owner| {
                        self.local.graph.resolve_rename(owner) == &resolved_table
                    })
            })
            .find(|edge| {
                let DependencyKind::IndexOnRelation { definition, .. } = &edge.kind else {
                    return false;
                };
                // A synthetic constraint marker settles nothing, so it never
                // reuses or is reused through the shape comparison.
                if template_definition.attach_equivalence(definition) != IndexEquivalence::Identical
                {
                    return false;
                }
                match (parent_backing, self.constraint_backing(&edge.dependent)) {
                    (Some(_), None) => false,
                    (Some(parent_kind), Some(child_kind)) => {
                        rule == ChildReuseRule::Creation || parent_kind == child_kind
                    }
                    (None, _) => true,
                }
            })
            .map(|edge| edge.dependent.clone());
        if let Some(existing) = reused {
            self.record_index_partition(parent, &existing);
            return (
                existing.clone(),
                self.index_definition_of(&existing)
                    .is_some_and(|definition| definition.valid),
            );
        }
        let columns = template_definition.key_column_names();
        let id = self.next_generated_relation_name_avoiding(
            &table.schema,
            &table.name,
            (!columns.is_empty()).then(|| columns.join("_")).as_deref(),
            "idx",
            &HashSet::new(),
        );
        let mut kind = template.clone();
        if let DependencyKind::IndexOnRelation { definition, .. } = &mut kind {
            // The clone is freshly built; its own partitions decide whether it
            // stays valid.
            definition.valid = true;
            definition.ready = true;
            definition.live = true;
        }
        self.snapshot_graph();
        self.local
            .graph
            .add_edge(DependencyEdge::new(id.clone(), table.clone(), kind));
        self.record_index_partition(parent, &id);
        let mut valid = true;
        let partitions: Vec<ObjectId> = self
            .local
            .graph
            .partitions_of(table)
            .into_iter()
            .cloned()
            .collect();
        for partition in partitions {
            let (_, child_valid) =
                self.ensure_partition_index_child(&id, &partition, template, rule);
            valid &= child_valid;
        }
        if !valid {
            self.snapshot_graph_full();
            self.local
                .graph
                .update_index_definition(&id, |stored| stored.valid = false);
        }
        (id, valid)
    }

    /// Record that a leaf index has finished being built and is usable.
    ///
    /// REINDEX rebuilds a broken index; a partitioned parent's validity
    /// instead follows its attached children, so only attach events set it.
    pub(super) fn mark_index_valid(&mut self, index: &ObjectId) {
        let Some(definition) = self.index_definition_of(index).cloned() else {
            return;
        };
        if definition.is_usable() {
            return;
        }
        if self
            .index_table_of(index)
            .is_some_and(|table| !self.local.graph.partitions_of(table).is_empty())
        {
            return;
        }
        self.snapshot_graph_full();
        self.local.graph.update_index_definition(index, |stored| {
            stored.valid = true;
            stored.ready = true;
            stored.live = true;
        });
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
