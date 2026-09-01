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
    All,
    /// PostgreSQL 17's table-maintenance privilege.
    ///
    /// Keep this variant after the historical variants so V6 cache enum
    /// discriminants remain stable for caches written before PostgreSQL 17.
    Maintain,
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
            if privileges.contains(&Privilege::All) {
                owned.clear();
            } else {
                for p in privileges {
                    owned.remove(p);
                }
            }
        }
    }

    pub fn has_privilege(&self, role: &ObjectId, privilege: Privilege) -> bool {
        self.grants.get(role).is_some_and(|set| {
            set.contains(&privilege)
                || (privilege != Privilege::All && set.contains(&Privilege::All))
        })
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
    /// Transaction depth at creation, used for same-transaction index checks.
    pub created_at_tx_depth: usize,
    pub privileges: PrivilegeMatrix,
    pub partition_type: Option<String>, // e.g., "RANGE", "LIST", "HASH"
    pub partition_by: Option<String>,   // The partition key expression
    pub is_fk_dependency: bool,
    /// Whether a materialized view has been populated. `None` means the
    /// catalog did not provide this relation-specific fact; it is ignored for
    /// tables and ordinary views and treated conservatively for refreshes.
    pub is_populated: Option<bool>,
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
            is_fk_dependency: false,
            is_populated: None,
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
            is_fk_dependency: false,
            is_populated: None,
        }
    }

    pub fn mark_fk_dependency(&mut self) {
        self.is_fk_dependency = true;
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
                    let serial_type = data_type
                        .as_deref()
                        .map(str::trim)
                        .map(str::to_ascii_lowercase)
                        .and_then(|ty| match ty.as_str() {
                            "smallserial" | "serial2" => Some("smallint"),
                            "serial" | "serial4" => Some("integer"),
                            "bigserial" | "serial8" => Some("bigint"),
                            _ => None,
                        });
                    let is_serial = serial_type.is_some();
                    let normalized_default = if is_serial {
                        Some(crate::analysis::expr_ir::ExprIr::FunctionCall {
                            name: "nextval".to_string(),
                            args: Vec::new(),
                        })
                    } else if matches!(
                        default,
                        Some(crate::analysis::expr_ir::ExprIr::Literal(value))
                            if value.trim().eq_ignore_ascii_case("null")
                    ) {
                        None
                    } else {
                        default.clone()
                    };
                    self.columns.push(Column {
                        name: name.clone(),
                        data_type: serial_type
                            .map(str::to_string)
                            .or_else(|| data_type.clone()),
                        type_id: None,
                        default: normalized_default,
                        is_nullable: !(*not_null || is_serial),
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
                if let Some(pos) = self.columns.iter().position(|c| c.name == *from)
                    && !self.columns.iter().any(|c| c.name == *to)
                {
                    self.columns[pos].name = to.clone();
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
                    // A type change invalidates catalog-derived identity and
                    // statistics for the old type. The state layer resolves
                    // the new identity after this helper returns.
                    col.type_id = None;
                    col.type_modifier = None;
                    col.avg_width = None;
                }
            }
            ColumnAction::SetDefault { name, default } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.default = if matches!(
                        default,
                        Some(crate::analysis::expr_ir::ExprIr::Literal(value))
                            if value.trim().eq_ignore_ascii_case("null")
                    ) {
                        None
                    } else {
                        default.clone()
                    };
                    // A migration mutation supersedes raw baseline catalog text.
                    col.default_expr_text = None;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changing_column_type_clears_stale_catalog_metadata() {
        let id = ObjectId::new("public", "items");
        let mut relation = RelationState::new(
            id,
            ObjectId::new("", "postgres"),
            0,
            Some(10),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        relation.columns.push(Column {
            name: "value".into(),
            data_type: Some("varchar(255)".into()),
            type_id: Some(ObjectId::new("public", "varchar")),
            is_nullable: true,
            default: None,
            avg_width: Some(32),
            default_expr_text: None,
            type_modifier: Some(259),
        });

        relation.apply_column_action(&ColumnAction::SetType {
            name: "value".into(),
            data_type: "integer".into(),
        });

        let column = relation
            .get_column("value")
            .expect("column remains present");
        assert_eq!(column.data_type.as_deref(), Some("integer"));
        assert_eq!(column.type_id, None);
        assert_eq!(column.type_modifier, None);
        assert_eq!(column.avg_width, None);
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
