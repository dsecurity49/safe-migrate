// FILE: ./src/model/relation.rs

use crate::model::column::Column;
use crate::ast::identifiers::ObjectId;
use std::collections::HashSet;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationKind {
    Table,
    View,
    MaterializedView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Persistence {
    Permanent,
    Temporary,
    Unlogged,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelationState {
    pub id: ObjectId,
    pub columns: Vec<Column>,
    pub generation: u64,
    pub estimated_rows: Option<u64>,
    pub relpages: Option<u64>, // Added to support PostgreSQL page statistics in sync.rs
    pub kind: RelationKind,
    pub persistence: Persistence,
    pub triggers: HashSet<String>,
    pub policies: HashSet<String>,
    pub last_analyze: Option<String>,
    pub last_autoanalyze: Option<String>,
}

impl Default for RelationState {
    fn default() -> Self {
        Self {
            id: ObjectId::new("public", "dummy"), // Fallback for struct updates
            columns: Vec::new(),
            generation: 0,
            estimated_rows: Some(0),
            relpages: None,
            kind: RelationKind::Table,
            persistence: Persistence::Permanent,
            triggers: HashSet::new(),
            policies: HashSet::new(),
            last_analyze: None,
            last_autoanalyze: None,
        }
    }
}

impl RelationState {
    pub fn new(
        id: ObjectId,
        generation: u64,
        estimated_rows: Option<u64>,
        kind: RelationKind,
        persistence: Persistence
    ) -> Self {
        Self {
            id,
            columns: Vec::new(),
            generation,
            estimated_rows,
            relpages: None,
            kind,
            persistence,
            triggers: HashSet::new(),
            policies: HashSet::new(),
            last_analyze: None,
            last_autoanalyze: None,
        }
    }

    pub fn apply_column_action(&mut self, action: &ColumnAction) {
        match action {
            ColumnAction::Add { name, data_type, not_null, default } => {
                if !self.columns.iter().any(|c| c.name == *name) {
                    self.columns.push(Column {
                        name: name.clone(),
                        data_type: data_type.clone(),
                        default: default.clone(),
                        is_nullable: !not_null,
                        avg_width: None,
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

    pub fn has_column(&self, name: &str) -> bool {
        self.columns.iter().any(|c| c.name == name)
    }

    pub fn get_column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }

    pub fn is_stale(&self) -> bool {
        self.last_analyze.is_none() && self.last_autoanalyze.is_none()
    }
}

// NOTE: ColumnAction does not need Serialize/Deserialize as it is only used during the in-memory execution loop!
#[derive(Debug, Clone, PartialEq)]
pub enum ColumnAction {
    Add {
        name: String,
        data_type: Option<String>,
        not_null: bool,
        default: Option<crate::analysis::expr_ir::ExprIr>,
    },
    Drop {
        name: String,
    },
    Rename {
        from: String,
        to: String,
    },
    SetNotNull {
        name: String,
    },
    DropNotNull {
        name: String,
    },
    SetType {
        name: String,
        data_type: String,
    },
    SetDefault {
        name: String,
        default: Option<crate::analysis::expr_ir::ExprIr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum RelationOverlay {
    Present(RelationState),
    Dropped,
}
