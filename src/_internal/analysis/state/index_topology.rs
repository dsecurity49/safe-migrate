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
    /// The two definitions do not match.
    DefinitionsDiffer,
    /// An opaque expression leaves equivalence undecidable, not unequal.
    EquivalenceUnknown,
    /// The two indexes are not backed by the same kind of constraint.
    ConstraintMismatch,
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
            } => {
                return self.default_family_for_column(
                    Some(base_type),
                    base_type_id.as_ref(),
                    method,
                );
            }
            TypeKind::Enum { .. } => &["anyenum"],
            TypeKind::Range { .. } => &["anyrange"],
            TypeKind::Multirange => &["anymultirange"],
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
        match self.compare_index_definitions(parent, child) {
            IndexComparison::Mismatch => return Some(AttachRefusal::DefinitionsDiffer),
            IndexComparison::Undecidable => return Some(AttachRefusal::EquivalenceUnknown),
            IndexComparison::Match => {}
        }
        let backing = (
            self.constraint_backing(parent),
            self.constraint_backing(child),
        );
        if backing.0 != backing.1 {
            return Some(AttachRefusal::ConstraintMismatch);
        }
        // Exclusion constraints are the one thing `CompareIndexInfo` reads that
        // the definition does not model — each key's operator, procedure and
        // strategy. For two exclusion-backed indexes neither equality nor
        // difference can be claimed.
        if backing.0 == Some(ConstraintKind::Exclusion) {
            return Some(AttachRefusal::EquivalenceUnknown);
        }
        None
    }

    /// The kind of constraint backing an index, if any.
    ///
    /// PostgreSQL attaches a constraint alongside the indexes when both sides
    /// have one of the same kind. Cloned partition constraints are renamed, so
    /// the name cannot decide it.
    fn constraint_backing(&self, index: &ObjectId) -> Option<ConstraintKind> {
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

    /// A partitioned parent carries no rows: it is valid exactly when its
    /// partitions are covered. A leaf index has none to cover.
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
                })
            })
        })
    }

    /// Record `child` as a partition of `parent`.
    ///
    /// Attaching the last partition is what makes a parent valid, which is why
    /// re-attaching an already-attached child is not merely a no-op.
    pub(super) fn record_index_partition(&mut self, parent: &ObjectId, child: &ObjectId) {
        self.snapshot_graph();
        self.local.graph.add_edge(DependencyEdge::new(
            child.clone(),
            parent.clone(),
            DependencyKind::IndexPartitionOf,
        ));
        self.mark_index_valid(parent);
    }

    /// Record that an index has finished being built and is usable.
    ///
    /// REINDEX rebuilds a broken index; a partitioned parent reaches the same
    /// state once every partition is attached.
    pub(super) fn mark_index_valid(&mut self, index: &ObjectId) {
        let Some(definition) = self.index_definition_of(index).cloned() else {
            return;
        };
        // A leaf index is rebuilt by REINDEX; a partitioned parent only once
        // every partition is attached.
        if definition.is_usable() || !self.index_is_fully_attached(index) {
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
