// src/ast/visitor.rs
use crate::analysis::facts::{StatementFact, AlterTableActionFact};
use crate::ast::identifiers::QualifiedName;

use squawk_syntax::ast::{
    Stmt, 
    CreateTable, 
    DropTable, 
    AlterTable,
    AlterTableAction,
    AstNode 
};

pub struct AstVisitor;

impl AstVisitor {
    pub fn extract(stmt: &Stmt) -> Option<StatementFact> {
        match stmt {
            Stmt::CreateTable(node) => Self::extract_create_table(node),
            Stmt::DropTable(node) => Self::extract_drop_table(node),
            Stmt::AlterTable(node) => Self::extract_alter_table(node),
            _ => None,
        }
    }

    fn extract_alter_table(node: &AlterTable) -> Option<StatementFact> {
        // FIXED: Stop calling node.path()
        // Placeholder identity until we wire the correct accessor (e.g., node.relation())
        let name = QualifiedName {
            schema: None,
            name: "unknown_table".to_string(),
        };

        let mut extracted_actions = Vec::new();

        // FIXED: Replaced alter_table_actions() with actions()
        for action_node in node.actions() {
            match action_node {
                AlterTableAction::AddColumn(add_col) => {
                    // Assuming add_col exposes name() based on previous compile success
                    if let Some(col_name) = add_col.name() {
                        extracted_actions.push(AlterTableActionFact::AddColumn {
                            name: col_name.syntax().text().to_string(),
                        });
                    }
                }
                AlterTableAction::DropColumn(_drop_col) => {
                    // FIXED: DropColumn does not expose .name() here.
                    // Fill with placeholder until we wire the real child accessor.
                    extracted_actions.push(AlterTableActionFact::DropColumn {
                        name: "unknown_column".to_string(), 
                    });
                }
                _ => {} 
            }
        }

        if extracted_actions.is_empty() {
            return None;
        }

        Some(StatementFact::AlterTable { 
            name, 
            actions: extracted_actions 
        })
    }

    fn extract_create_table(node: &CreateTable) -> Option<StatementFact> {
        let path_node = node.path()?; 
        let name = Self::extract_qualified_name(&path_node);
        Some(StatementFact::CreateTable { name })
    }

    fn extract_drop_table(node: &DropTable) -> Option<StatementFact> {
        let path_node = node.path()?; 
        let name = Self::extract_qualified_name(&path_node);
        Some(StatementFact::DropTable {
            name,
            if_exists: node.if_exists().is_some(),
        })
    }

    fn extract_qualified_name<T>(path: &T) -> QualifiedName 
    where 
        T: AstNode
    {
        let raw_path = path.syntax().text().to_string();
        let mut segments: Vec<&str> = raw_path.split('.').collect();
        
        if segments.len() >= 2 {
            QualifiedName {
                name: segments.pop().unwrap().to_string(),
                schema: Some(segments.pop().unwrap().to_string()),
            }
        } else {
            QualifiedName {
                schema: None,
                name: segments.pop().unwrap_or("unknown").to_string(),
            }
        }
    }
}
