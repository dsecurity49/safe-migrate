// FILE: src/analysis/graph.rs
use crate::ast::identifiers::ObjectId;

#[derive(Debug, Clone, PartialEq)]
pub struct FkEdge {
    pub constraint_name: Option<String>,
    pub from_table: ObjectId,
    pub from_columns: Vec<String>,
    pub to_table: ObjectId,
    pub to_columns: Vec<String>,
    pub from_generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ViewEdge {
    pub view_id: ObjectId,
    pub depends_on: Vec<ObjectId>,
    pub view_generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IndexEdge {
    pub index_id: ObjectId,
    pub relation_id: ObjectId,
    pub using_method: Option<String>,
    pub has_predicate: bool,
    pub is_concurrent: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenameEdge {
    pub from: ObjectId,
    pub to: ObjectId,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PartitionEdge {
    pub parent: ObjectId,
    pub child: ObjectId,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SequenceEdge {
    pub sequence_id: ObjectId,
    pub table_id: ObjectId,
    pub column: String,
}

#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
    pub foreign_keys: Vec<FkEdge>,
    pub views: Vec<ViewEdge>,
    pub indexes: Vec<IndexEdge>,
    pub renames: Vec<RenameEdge>,
    pub partitions: Vec<PartitionEdge>,
    pub sequences: Vec<SequenceEdge>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    // Phase 3 FIX (BUG-004): Traverse rename chains dynamically for accurate topology reads
    pub fn is_referenced_by_view(&self, id: &ObjectId) -> Vec<&ObjectId> {
        let target = self.resolve_rename(id);
        self.views
            .iter()
            .filter(|v| {
                v.depends_on
                    .iter()
                    .any(|dep| self.resolve_rename(dep) == target || dep == id)
            })
            .map(|v| self.resolve_rename(&v.view_id))
            .collect()
    }

    pub fn is_referenced_by_fk(&self, id: &ObjectId) -> Vec<(&ObjectId, u64)> {
        let target = self.resolve_rename(id);
        self.foreign_keys
            .iter()
            .filter(|fk| self.resolve_rename(&fk.to_table) == target || &fk.to_table == id)
            .map(|fk| (self.resolve_rename(&fk.from_table), fk.from_generation))
            .collect()
    }

    pub fn is_referenced_by_index(&self, id: &ObjectId) -> Vec<&ObjectId> {
        let target = self.resolve_rename(id);
        self.indexes
            .iter()
            .filter(|ix| self.resolve_rename(&ix.relation_id) == target || &ix.relation_id == id)
            .map(|ix| self.resolve_rename(&ix.index_id))
            .collect()
    }

    pub fn partitions_of(&self, id: &ObjectId) -> Vec<&ObjectId> {
        let target = self.resolve_rename(id);
        self.partitions
            .iter()
            .filter(|p| self.resolve_rename(&p.parent) == target || &p.parent == id)
            .map(|p| self.resolve_rename(&p.child))
            .collect()
    }

    pub fn resolve_rename<'a>(&'a self, id: &'a ObjectId) -> &'a ObjectId {
        let mut current = id;
        loop {
            match self.renames.iter().find(|r| &r.from == current) {
                Some(edge) => current = &edge.to,
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
        loop {
            let maybe_edge = self
                .partitions
                .iter()
                .find(|p| self.resolve_rename(&p.child) == current_parent);
            if let Some(edge) = maybe_edge {
                let p = self.resolve_rename(&edge.parent);
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
}
