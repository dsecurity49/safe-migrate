use crate::model::column::Column;

// ─────────────────────────────────────────────
// ObjectId — canonical identity
//
// INVARIANT: This is the ONLY key type used in
// AnalysisState, DbCache, and DependencyGraph.
// QualifiedName (AST form) is NEVER used for
// lookups — only for resolution input.
// ─────────────────────────────────────────────

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
    /// Monotonically increasing generation counter.
    /// Incremented each time a new incarnation of this ObjectId is created
    /// (i.e. when CREATE TABLE/VIEW overwrites a tombstone with the same name).
    /// Graph edges carry the generation of the relation they were created for.
    /// Rules filter edges whose generation does not match the current relation's
    /// generation — preventing ABA phantom dependencies.
    pub generation: u64,
}

impl RelationState {
    /// Create a new relation with the given identity and generation.
    pub fn new(id: ObjectId, generation: u64) -> Self {
        Self { id, columns: Vec::new(), generation }
    }

    /// Apply a column-level mutation to this relation's live state.
    /// Called by AnalysisState::apply() after rule evaluation.
    pub fn apply_column_action(&mut self, action: &ColumnAction) {
        match action {
            ColumnAction::Add { name, data_type, not_null, default } => {
                if !self.columns.iter().any(|c| c.name == *name) {
                    self.columns.push(Column {
                        name: name.clone(),
                        data_type: data_type.clone(),
                        default: default.clone(),
                        is_nullable: !not_null,
                    });
                }
            }
            ColumnAction::Drop { name } => {
                self.columns.retain(|c| c.name != *name);
            }
            ColumnAction::Rename { from, to } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *from) {
                    col.name = to.clone();
                }
            }
            ColumnAction::SetNotNull { name } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.is_nullable = false;
                }
            }
            ColumnAction::DropNotNull { name } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.is_nullable = true;
                }
            }
            ColumnAction::SetType { name, data_type } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.data_type = Some(data_type.clone());
                }
            }
            ColumnAction::SetDefault { name, default } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.default = default.clone();
                }
            }
        }
    }

    /// Returns true if a column with this name exists in the current state.
    pub fn has_column(&self, name: &str) -> bool {
        self.columns.iter().any(|c| c.name == name)
    }

    /// Returns the column with this name if it exists.
    pub fn get_column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
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
        not_null: bool,
        /// Default expression for this column.
        /// Stored on Column::default for future VolatileDefaultRule evaluation.
        default: Option<crate::analysis::expr_ir::ExprIr>,
    },
    Drop {
        name: String,
    },
    /// RENAME COLUMN old TO new
    Rename {
        from: String,
        to: String,
    },
    /// ALTER COLUMN name SET NOT NULL
    SetNotNull {
        name: String,
    },
    /// ALTER COLUMN name DROP NOT NULL
    DropNotNull {
        name: String,
    },
    /// ALTER COLUMN name SET DATA TYPE ty
    SetType {
        name: String,
        data_type: String,
    },
    /// ALTER COLUMN name SET DEFAULT expr
    SetDefault {
        name: String,
        default: Option<crate::analysis::expr_ir::ExprIr>,
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
