// src/analysis/graph.rs
use crate::model::relation::ObjectId;

#[derive(Debug, Clone, PartialEq)]
pub struct FkEdge {
    pub from_table: ObjectId,
    pub from_columns: Vec<String>,
    pub to_table: ObjectId,
    pub to_columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ViewEdge {
    pub view_id: ObjectId,
    pub depends_on: Vec<ObjectId>,
}

#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
    pub foreign_keys: Vec<FkEdge>,
    pub views: Vec<ViewEdge>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if a given object is being referenced by any View.
    pub fn is_referenced_by_view(&self, id: &ObjectId) -> Vec<&ObjectId> {
        self.views
            .iter()
            .filter(|v| v.depends_on.contains(id))
            .map(|v| &v.view_id)
            .collect()
    }

    /// Checks if a given table is referenced by another table's Foreign Key.
    pub fn is_referenced_by_fk(&self, id: &ObjectId) -> Vec<&ObjectId> {
        self.foreign_keys
            .iter()
            .filter(|fk| &fk.to_table == id)
            .map(|fk| &fk.from_table)
            .collect()
    }
}
