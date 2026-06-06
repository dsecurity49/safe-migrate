use crate::ast::identifiers::QualifiedName;

#[derive(Debug, Clone)]
pub enum StatementFact {
    CreateTable { name: QualifiedName },
    DropTable { name: QualifiedName, if_exists: bool },
    // CHANGED: 'action' is now 'actions: Vec<...>'
    AlterTable { name: QualifiedName, actions: Vec<AlterTableActionFact> }, 
    SetSearchPath { paths: Vec<String> },
    CreateView { name: QualifiedName, dependencies: Vec<QualifiedName> },
    BeginTransaction,
    CommitTransaction,
    RollbackTransaction,
    OpaqueBlock,
}

#[derive(Debug, Clone)]
pub enum AlterTableActionFact {
    AddColumn { name: String },
    DropColumn { name: String }, // ADDED based on your AST tree
}
