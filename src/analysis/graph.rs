// FILE: src/analysis/graph.rs
use crate::ast::identifiers::ObjectId;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq)]
pub enum DependencyKind {
    ForeignKey {
        constraint_name: Option<String>,
        from_columns: Vec<String>,
        to_columns: Vec<String>,
        from_generation: u64,
    },
    ViewDependency {
        view_generation: u64,
    },
    IndexOnRelation {
        using_method: Option<String>,
        has_predicate: bool,
        is_concurrent: bool,
        is_unique: bool,
    },
    RenameTo,
    PartitionOf,
    SequenceOwnedBy {
        column: String,
    },
    ColumnGeneratedFrom {
        column: String,
        depends_on_column: String,
    },
    TriggerOnTable {
        trigger_id: ObjectId,
        function_id: ObjectId,
    },
    PublicationIncludes {
        publication_name: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct DependencyEdge {
    pub dependent: ObjectId,
    pub referenced: ObjectId,
    pub kind: DependencyKind,
}

impl DependencyEdge {
    pub fn new(dependent: ObjectId, referenced: ObjectId, kind: DependencyKind) -> Self {
        Self {
            dependent,
            referenced,
            kind,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
    pub edges: Vec<DependencyEdge>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    // Phase 3 FIX (BUG-004): Traverse rename chains dynamically for accurate topology reads
    pub fn is_referenced_by_view(&self, id: &ObjectId) -> Vec<&ObjectId> {
        let target = self.resolve_rename(id);
        self.edges
            .iter()
            .filter(|e| {
                matches!(e.kind, DependencyKind::ViewDependency { .. })
                    && (self.resolve_rename(&e.referenced) == target || &e.referenced == id)
            })
            .map(|e| self.resolve_rename(&e.dependent))
            .collect()
    }

    pub fn is_referenced_by_fk(&self, id: &ObjectId) -> Vec<(&ObjectId, u64)> {
        let target = self.resolve_rename(id);
        self.edges
            .iter()
            .filter_map(|e| {
                if let DependencyKind::ForeignKey {
                    from_generation, ..
                } = &e.kind
                    && (self.resolve_rename(&e.referenced) == target || &e.referenced == id)
                {
                    Some((self.resolve_rename(&e.dependent), *from_generation))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn is_referenced_by_index(&self, id: &ObjectId) -> Vec<&ObjectId> {
        let target = self.resolve_rename(id);
        self.edges
            .iter()
            .filter(|e| {
                matches!(e.kind, DependencyKind::IndexOnRelation { .. })
                    && (self.resolve_rename(&e.referenced) == target || &e.referenced == id)
            })
            .map(|e| self.resolve_rename(&e.dependent))
            .collect()
    }

    pub fn partitions_of(&self, id: &ObjectId) -> Vec<&ObjectId> {
        let target = self.resolve_rename(id);
        self.edges
            .iter()
            .filter(|e| {
                matches!(e.kind, DependencyKind::PartitionOf)
                    && (self.resolve_rename(&e.referenced) == target || &e.referenced == id)
            })
            .map(|e| self.resolve_rename(&e.dependent))
            .collect()
    }

    pub fn resolve_rename<'a>(&'a self, id: &'a ObjectId) -> &'a ObjectId {
        let mut current = id;
        let mut visited = HashSet::new();
        loop {
            // A rename back to an earlier name is valid PostgreSQL. The graph
            // retains historical aliases, so resolve only acyclic paths; a
            // cycle has no unique alias target and must leave the supplied
            // identity unchanged.
            if !visited.insert(current.clone()) {
                return id;
            }
            match self
                .edges
                .iter()
                .find(|e| matches!(e.kind, DependencyKind::RenameTo) && &e.dependent == current)
            {
                Some(edge) => current = &edge.referenced,
                None => return current,
            }
        }
    }

    // Phase 3 FIX (BUG-012): Reject cycle topologies
    pub fn check_partition_cycle(&self, parent: &ObjectId, child: &ObjectId) -> bool {
        let resolved_parent = self.resolve_rename(parent);
        let resolved_child = self.resolve_rename(child);
        if resolved_parent == resolved_child {
            return true;
        }

        let mut current_parent = resolved_parent;
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current_parent.clone()) {
                // The existing ancestry is already malformed. Reject another
                // attachment instead of looping or extending the cycle.
                return true;
            }
            let maybe_edge = self.edges.iter().find(|e| {
                matches!(e.kind, DependencyKind::PartitionOf)
                    && self.resolve_rename(&e.dependent) == current_parent
            });
            if let Some(edge) = maybe_edge {
                let p = self.resolve_rename(&edge.referenced);
                if p == resolved_child {
                    return true;
                }
                current_parent = p;
            } else {
                break;
            }
        }
        false
    }

    pub fn propagate_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        for edge in &mut self.edges {
            if matches!(edge.kind, DependencyKind::RenameTo) {
                continue;
            }
            if edge.dependent == *old_id {
                edge.dependent = new_id.clone();
            }
            if edge.referenced == *old_id {
                edge.referenced = new_id.clone();
            }
            if let DependencyKind::TriggerOnTable {
                trigger_id,
                function_id,
            } = &mut edge.kind
            {
                if *trigger_id == *old_id {
                    *trigger_id = new_id.clone();
                }
                if *function_id == *old_id {
                    *function_id = new_id.clone();
                }
            }
        }
    }

    pub fn triggers_on(&self, table_id: &ObjectId) -> Vec<&DependencyEdge> {
        self.edges
            .iter()
            .filter(|e| {
                matches!(e.kind, DependencyKind::TriggerOnTable { .. }) && &e.referenced == table_id
            })
            .collect()
    }

    pub fn triggers_for_function(&self, function_id: &ObjectId) -> Vec<&DependencyEdge> {
        let normalize = |id: &ObjectId| -> ObjectId {
            let name = if let Some(idx) = id.name.find('(') {
                format!("{}()", &id.name[..idx])
            } else {
                id.name.clone()
            };
            ObjectId {
                schema: id.schema.clone(),
                name,
                inferred_schema: id.inferred_schema,
            }
        };
        let target_id = normalize(function_id);
        self.edges
            .iter()
            .filter(|e| {
                if let DependencyKind::TriggerOnTable {
                    function_id: fid, ..
                } = &e.kind
                {
                    normalize(fid) == target_id
                } else {
                    false
                }
            })
            .collect()
    }
}
