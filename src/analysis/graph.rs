// FILE: ./src/analysis/graph.rs

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
    
    pub fn is_referenced_by_view(&self, id: &ObjectId) -> Vec<&ObjectId> {
        self.views
            .iter()
            .filter(|v| v.depends_on.contains(id))
            .map(|v| &v.view_id)
            .collect()
    }
    
    pub fn is_referenced_by_fk(&self, id: &ObjectId) -> Vec<(&ObjectId, u64)> {
        self.foreign_keys
            .iter()
            .filter(|fk| &fk.to_table == id)
            .map(|fk| (&fk.from_table, fk.from_generation))
            .collect()
    }
    
    pub fn is_referenced_by_index(&self, id: &ObjectId) -> Vec<&ObjectId> {
        self.indexes
            .iter()
            .filter(|ix| &ix.relation_id == id)
            .map(|ix| &ix.index_id)
            .collect()
    }
    
    pub fn partitions_of(&self, id: &ObjectId) -> Vec<&ObjectId> {
        self.partitions
            .iter()
            .filter(|p| &p.parent == id)
            .map(|p| &p.child)
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
}
