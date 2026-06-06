use crate::model::column::Column;

/// The canonical, unambiguous identity of a database object.
/// This is the ONLY key type used in the AnalysisState cache and local overlays.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectId {
    pub schema: String,
    pub name: String,
}

impl ObjectId {
    pub fn new(schema: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            schema: schema.into(),
            name: name.into(),
        }
    }
}

/// Represents the actual simulated state of a relation (Table, View, etc.).
#[derive(Debug, Clone, PartialEq)]
pub struct RelationState {
    pub id: ObjectId,
    pub columns: Vec<Column>,
}

/// CRITICAL FIX: The Tombstone model.
/// Dropped objects are never removed from state, they are shadowed.
#[derive(Debug, Clone, PartialEq)]
pub enum RelationOverlay {
    Present(RelationState),
    Dropped,
}
