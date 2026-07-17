// FILE: ./src/report/violations.rs

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum OperationKind {
    DropColumn,
    DropTable,
    DropIndex,
    DropView,
    DropMaterializedView,
    DropFunction,
    DropProcedure,
    DropSchema,
    DropDatabase,
    DropSequence,
    DropDomain,
    DropPublication,
    DropTrigger,
    DropPolicy,
    AddColumn,
    AlterColumnType,
    AddConstraint,
    CreateIndex,
    CreateTable,
    CreateView,
    CreateFunction,
    CreateProcedure,
    AlterFunction,
    AlterProcedure,
    RefreshMaterializedView,
    AttachPartition,
    DetachPartition,
    VacuumFull,
    Grant,
    RevokeGrant,
    AlterType,
    CreateTrigger,
    CreatePolicy,
    DisableTrigger,
    EnableTrigger,
    RenameTable,
    RenameColumn,
    OpaqueSql,
    CreateSchema,
    SetDefault,
    CreateSequence,
    CreateDomain,
    AlterSchema,
    Conflict,
    Irreversible,
    UnresolvedReference,
    Other(String),
}

impl std::fmt::Display for OperationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationKind::DropColumn => write!(f, "drop_column"),
            OperationKind::DropTable => write!(f, "drop_table"),
            OperationKind::DropIndex => write!(f, "drop_index"),
            OperationKind::DropView => write!(f, "drop_view"),
            OperationKind::DropMaterializedView => write!(f, "drop_materialized_view"),
            OperationKind::DropFunction => write!(f, "drop_function"),
            OperationKind::DropProcedure => write!(f, "drop_procedure"),
            OperationKind::DropSchema => write!(f, "drop_schema"),
            OperationKind::DropDatabase => write!(f, "drop_database"),
            OperationKind::DropSequence => write!(f, "drop_sequence"),
            OperationKind::DropDomain => write!(f, "drop_domain"),
            OperationKind::DropPublication => write!(f, "drop_publication"),
            OperationKind::DropTrigger => write!(f, "drop_trigger"),
            OperationKind::DropPolicy => write!(f, "drop_policy"),
            OperationKind::AddColumn => write!(f, "add_column"),
            OperationKind::AlterColumnType => write!(f, "alter_column_type"),
            OperationKind::AddConstraint => write!(f, "add_constraint"),
            OperationKind::CreateIndex => write!(f, "create_index"),
            OperationKind::CreateTable => write!(f, "create_table"),
            OperationKind::CreateView => write!(f, "create_view"),
            OperationKind::CreateFunction => write!(f, "create_function"),
            OperationKind::CreateProcedure => write!(f, "create_procedure"),
            OperationKind::AlterFunction => write!(f, "alter_function"),
            OperationKind::AlterProcedure => write!(f, "alter_procedure"),
            OperationKind::RefreshMaterializedView => write!(f, "refresh_materialized_view"),
            OperationKind::AttachPartition => write!(f, "attach_partition"),
            OperationKind::DetachPartition => write!(f, "detach_partition"),
            OperationKind::VacuumFull => write!(f, "vacuum_full"),
            OperationKind::Grant => write!(f, "grant"),
            OperationKind::RevokeGrant => write!(f, "revoke_grant"),
            OperationKind::AlterType => write!(f, "alter_type"),
            OperationKind::CreateTrigger => write!(f, "create_trigger"),
            OperationKind::CreatePolicy => write!(f, "create_policy"),
            OperationKind::DisableTrigger => write!(f, "disable_trigger"),
            OperationKind::EnableTrigger => write!(f, "enable_trigger"),
            OperationKind::RenameTable => write!(f, "rename_table"),
            OperationKind::RenameColumn => write!(f, "rename_column"),
            OperationKind::OpaqueSql => write!(f, "opaque_sql"),
            OperationKind::CreateSchema => write!(f, "create_schema"),
            OperationKind::SetDefault => write!(f, "set_default"),
            OperationKind::CreateSequence => write!(f, "create_sequence"),
            OperationKind::CreateDomain => write!(f, "create_domain"),
            OperationKind::AlterSchema => write!(f, "alter_schema"),
            OperationKind::Conflict => write!(f, "conflict"),
            OperationKind::Irreversible => write!(f, "irreversible"),
            OperationKind::UnresolvedReference => write!(f, "unresolved_reference"),
            OperationKind::Other(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum ObjectKind {
    Table,
    Index,
    View,
    MaterializedView,
    Function,
    Procedure,
    Trigger,
    Sequence,
    Schema,
    Role,
    Publication,
    Subscription,
    Database,
    Domain,
    Policy,
    Type,
    Opaque,
    Unknown,
}

impl std::fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectKind::Table => write!(f, "table"),
            ObjectKind::Index => write!(f, "index"),
            ObjectKind::View => write!(f, "view"),
            ObjectKind::MaterializedView => write!(f, "materialized view"),
            ObjectKind::Function => write!(f, "function"),
            ObjectKind::Procedure => write!(f, "procedure"),
            ObjectKind::Trigger => write!(f, "trigger"),
            ObjectKind::Sequence => write!(f, "sequence"),
            ObjectKind::Schema => write!(f, "schema"),
            ObjectKind::Role => write!(f, "role"),
            ObjectKind::Publication => write!(f, "publication"),
            ObjectKind::Subscription => write!(f, "subscription"),
            ObjectKind::Database => write!(f, "database"),
            ObjectKind::Domain => write!(f, "domain"),
            ObjectKind::Policy => write!(f, "policy"),
            ObjectKind::Type => write!(f, "type"),
            ObjectKind::Opaque => write!(f, "opaque"),
            ObjectKind::Unknown => write!(f, "object"),
        }
    }
}

/// ViolationTier represents the severity of a finding.
/// Tier1 is declared first so `derive(Ord)` sorts it before Tier2 and Tier3.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum ViolationTier {
    Tier1, // HALT — Access Exclusive / data-destructive, sorts first
    Tier2, // WARN — Share Row Exclusive / cautious
    Tier3, // SAFE — informational / low risk, sorts last
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Violation {
    #[serde(skip)]
    pub source_range: Option<rowan::TextRange>,
    pub rule_id: &'static str,
    pub operation_kind: OperationKind,
    pub object_kind: ObjectKind,
    pub object_name: String,
    pub tier: ViolationTier,
    pub reason: String,
    pub recipe: &'static str,
    pub dedup_key: Option<String>,
    pub sql: Option<String>,
    #[serde(default)]
    pub fk_dependency_related: bool,
}
