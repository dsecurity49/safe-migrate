// FILE: src/model/relation.rs
use crate::ast::identifiers::ObjectId;
use crate::model::column::Column;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Privilege {
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    References,
    Trigger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrivilegeMatrix {
    /// Maps role identity to the set of privileges they possess on this relation
    pub grants: HashMap<ObjectId, HashSet<Privilege>>,
}

impl PrivilegeMatrix {
    pub fn grant(&mut self, role: ObjectId, privileges: HashSet<Privilege>) {
        self.grants.entry(role).or_default().extend(privileges);
    }

    pub fn revoke(&mut self, role: &ObjectId, privileges: &HashSet<Privilege>) {
        if let Some(owned) = self.grants.get_mut(role) {
            for p in privileges {
                owned.remove(p);
            }
        }
    }

    pub fn has_privilege(&self, role: &ObjectId, privilege: Privilege) -> bool {
        self.grants
            .get(role)
            .is_some_and(|set| set.contains(&privilege))
    }
}

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
    pub owner: ObjectId,
    pub columns: Vec<Column>,
    pub generation: u64,
    pub estimated_rows: Option<u64>,
    pub relpages: Option<u64>,
    pub kind: RelationKind,
    pub persistence: Persistence,
    pub triggers: HashSet<String>,
    pub policies: HashSet<String>,
    pub last_analyze: Option<String>,
    pub last_autoanalyze: Option<String>,
    pub created_at_tx_depth: usize, // Phase 1 FIX: Same-Transaction index tracking
    pub privileges: PrivilegeMatrix,
    pub partition_type: Option<String>, // e.g., "RANGE", "LIST", "HASH"
    pub partition_by: Option<String>,   // The partition key expression
}

impl Default for RelationState {
    fn default() -> Self {
        Self {
            id: ObjectId::new("public", "dummy"),
            owner: ObjectId::new("public", "postgres"),
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
            created_at_tx_depth: 0,
            privileges: PrivilegeMatrix::default(),
            partition_type: None,
            partition_by: None,
        }
    }
}

impl RelationState {
    pub fn new(
        id: ObjectId,
        owner: ObjectId,
        generation: u64,
        estimated_rows: Option<u64>,
        kind: RelationKind,
        persistence: Persistence,
        created_at_tx_depth: usize,
    ) -> Self {
        Self {
            id,
            owner,
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
            created_at_tx_depth,
            privileges: PrivilegeMatrix::default(),
            partition_type: None,
            partition_by: None,
        }
    }

    pub fn apply_column_action(&mut self, action: &ColumnAction) {
        match action {
            ColumnAction::Add {
                name,
                data_type,
                not_null,
                default,
            } => {
                if !self.columns.iter().any(|c| c.name == *name) {
                    self.columns.push(Column {
                        name: name.clone(),
                        data_type: data_type.clone(),
                        default: default.clone(),
                        is_nullable: !not_null,
                        avg_width: None,
                        default_expr_text: None,
                        type_modifier: None,
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

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum RelationOverlay {
    Present(RelationState),
    Dropped,
}
