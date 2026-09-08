use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Column {
    pub name: String,
    pub data_type: Option<String>,
    /// Resolved identity for a tracked user-defined type. The display spelling
    /// remains for reports and cache compatibility; state transitions use this
    /// identity so same-named types in different schemas stay distinct.
    #[serde(skip)]
    pub type_id: Option<ObjectId>,
    pub is_nullable: bool,
    pub default: Option<ExprIr>,
    pub avg_width: Option<i32>,
    /// Raw default expression text from pg_get_expr(), unparsed.
    /// Used for display and heuristic volatility checks without an ExprIr parser.
    pub default_expr_text: Option<String>,
    /// Raw type modifier integer from pg_attribute.atttypmod.
    /// For VARCHAR(50), PostgreSQL stores the character limit plus VARHDRSZ: 54.
    pub type_modifier: Option<i32>,
    /// PostgreSQL TOAST storage mode, when catalog or migration evidence is available.
    #[serde(default)]
    pub storage: Option<String>,
    /// Explicit per-column compression method. `None` means the relation default.
    #[serde(default)]
    pub compression: Option<String>,
    /// Per-column statistics target. PostgreSQL uses `-1` for its default.
    #[serde(default)]
    pub statistics_target: Option<i32>,
    /// Non-default per-column planner options such as `n_distinct`.
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    /// Whether PostgreSQL stores this column as a generated column.
    ///
    /// `None` represents a V7 cache written before this metadata was captured.
    #[serde(default)]
    pub generated: Option<bool>,
}

impl Column {
    /// Construct a migration-created column without catalog-only metadata.
    pub(crate) fn migration_created(
        name: String,
        data_type: Option<String>,
        is_nullable: bool,
        default: Option<ExprIr>,
    ) -> Self {
        Self {
            name,
            data_type,
            type_id: None,
            is_nullable,
            default,
            avg_width: None,
            default_expr_text: None,
            type_modifier: None,
            storage: None,
            compression: None,
            statistics_target: None,
            options: BTreeMap::new(),
            generated: Some(false),
        }
    }
}
