use crate::model::relation::ObjectId;

#[derive(Debug, Clone)]
pub enum Mutation {
    CreateTable { id: ObjectId },
    DropTable { id: ObjectId },
    // Notice how AlterTable takes a specific action
    AlterTable { id: ObjectId, action: AlterTableActionMutation }, 
    SearchPath { paths: Vec<String> },
    CreateView { id: ObjectId, dependencies: Vec<ObjectId> },
    
    BeginTransaction,
    CommitTransaction,
    RollbackTransaction,
    Savepoint(String),
    RollbackToSavepoint(String),
    Opaque(OpaqueMutation),
}

#[derive(Debug, Clone)]
pub enum AlterTableActionMutation {
    AddColumn { name: String },
    DropColumn { name: String }, // ADDED
}

#[derive(Debug, Clone)]
pub enum OpaqueMutation {
    DoBlock,
    Execute,
    DynamicSql,
}
