use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ... (TableIdentity, IndexIdentity, AlterAction, MigrationOp, SpannedOp remain exactly the same) ...

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TableIdentity {
    pub schema: Option<String>,
    pub name: String,
}

impl TableIdentity {
    pub fn canonical_key(&self, default_schema: &str) -> String {
        let schema_name = self.schema.as_deref().unwrap_or(default_schema);
        format!("{}.{}", schema_name, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IndexIdentity {
    pub schema: Option<String>,
    pub name: String,
}

impl IndexIdentity {
    pub fn canonical_key(&self, default_schema: &str) -> String {
        let schema_name = self.schema.as_deref().unwrap_or(default_schema);
        format!("{}.{}", schema_name, self.name)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlterAction {
    AddColumn,
    DropColumn,
    AlterColumnUnspecified,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationOp {
    CreateTable(TableIdentity),
    DropTable(TableIdentity),
    CreateIndex {
        index_name: Option<String>,
        table: TableIdentity,
        concurrently: bool,
    },
    DropIndex {
        indexes: Vec<IndexIdentity>,
        concurrently: bool,
    },
    AlterTable {
        table: TableIdentity,
        actions: Vec<AlterAction>,
    },
    Ignored(String),
    Unknown {
        raw: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpannedOp {
    pub op: MigrationOp,
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockTier {
    Tier1,
    Tier2,
    Tier3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry {
    pub estimated_rows: u64,
    pub relpages: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheData {
    pub last_updated: u64,
    pub tables: HashMap<String, CacheEntry>,
    pub indexes: HashMap<String, String>,
}

// FIX: Added rule_name and recipe to the output
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LintRecord {
    pub file: String,
    pub start: u32,
    pub end: u32,
    pub tier: LockTier,
    pub op: MigrationOp,
    pub message: String,
    pub rule_name: String,
    pub recipe: String,
}
