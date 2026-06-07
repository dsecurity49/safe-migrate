use crate::model::column::Column;

// ObjectId — canonical identity
//
// INVARIANT: This is the ONLY key type used in
// AnalysisState, DbCache, and DependencyGraph.
// QualifiedName (AST form) is NEVER used for
// lookups — only for resolution input.

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

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.schema, self.name)
    }
}

// ─────────────────────────────────────────────
// RelationState — simulated live schema of one
// table or view at a point in migration execution
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct RelationState {
    pub id: ObjectId,
    pub columns: Vec<Column>,
}

impl RelationState {
    /// Create a new empty relation with the given identity.
    pub fn new(id: ObjectId) -> Self {
        Self {
            id,
            columns: Vec::new(),
        }
    }

    /// Apply a column-level mutation to this relation's live state.
    /// Called by AnalysisState::apply() after rule evaluation.
    pub fn apply_column_action(&mut self, action: &ColumnAction) {
        match action {
            ColumnAction::Add { name, data_type } => {
                // Idempotency: skip if column already exists (e.g. IF NOT EXISTS path).
                // The rule engine is responsible for emitting a violation before we get here;
                // the apply phase just keeps state consistent.
                if !self.columns.iter().any(|c| c.name == *name) {
                    self.columns.push(Column {
                        name: name.clone(),
                        data_type: data_type.clone(),
                        default: None,
                        is_nullable: true, // safe default until constraints are extracted
                    });
                }
            }
            ColumnAction::Drop { name } => {
                self.columns.retain(|c| c.name != *name);
            }
        }
    }

    /// Returns true if a column with this name exists in the current state.
    pub fn has_column(&self, name: &str) -> bool {
        self.columns.iter().any(|c| c.name == name)
    }
}

// ─────────────────────────────────────────────
// ColumnAction — the resolved column-level
// mutation passed from state.apply() into
// RelationState::apply_column_action().
//
// This is separate from AlterTableActionMutation
// to keep the model layer independent of the
// analysis layer.
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ColumnAction {
    Add {
        name: String,
        data_type: Option<String>,
    },
    Drop {
        name: String,
    },
}

// ─────────────────────────────────────────────
// RelationOverlay — tombstone model
//
// INVARIANT: Dropped objects are NEVER removed
// from state. They are shadowed as Dropped so
// that subsequent statements referencing the
// same object can be correctly diagnosed.
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RelationOverlay {
    Present(RelationState),
    Dropped,
}
