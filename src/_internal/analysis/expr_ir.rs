use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum ExprIr {
    Literal(String),
    ColumnRef(String),
    FunctionCall {
        name: String,
        args: Vec<ExprIr>,
    },
    BinaryOp {
        left: Box<ExprIr>,
        op: String,
        right: Box<ExprIr>,
    },
    Cast {
        expr: Box<ExprIr>,
        target_type: String,
    },
    Sentinel(String),
    Omitted,
    UnaryOp {
        op: String,
        expr: Box<ExprIr>,
    },
}

impl ExprIr {
    /// Returns referenced unqualified columns when the expression conversion is
    /// complete. Callers must retain conservative evidence for `None`.
    pub(crate) fn referenced_columns(&self) -> Option<BTreeSet<String>> {
        fn collect(expression: &ExprIr, columns: &mut BTreeSet<String>) -> Option<()> {
            match expression {
                ExprIr::Literal(_) => Some(()),
                ExprIr::ColumnRef(column) => {
                    columns.insert(column.clone());
                    Some(())
                }
                ExprIr::FunctionCall { args, .. } => args
                    .iter()
                    .try_for_each(|argument| collect(argument, columns)),
                ExprIr::BinaryOp { left, right, .. } => {
                    collect(left, columns)?;
                    collect(right, columns)
                }
                ExprIr::Cast { expr, .. } | ExprIr::UnaryOp { expr, .. } => collect(expr, columns),
                ExprIr::Sentinel(_) | ExprIr::Omitted => None,
            }
        }

        let mut columns = BTreeSet::new();
        collect(self, &mut columns)?;
        Some(columns)
    }

    /// Returns whether conversion lost part of the source expression. The
    /// expression visitor uses these sentinel literals for syntax it cannot
    /// represent yet; callers that need dependency proof must not treat an
    /// empty column list from such an expression as a proven constant.
    pub(crate) fn contains_opaque(&self) -> bool {
        const SENTINELS: &[&str] = &[
            "<array>",
            "<between>",
            "<case>",
            "<cast_inner>",
            "<collation>",
            "<complex>",
            "<field>",
            "<fn>",
            "<index>",
            "<lhs>",
            "<op>",
            "<paren>",
            "<postfix>",
            "<prefix>",
            "<rhs>",
            "<slice>",
            "<type>",
        ];
        let is_sentinel = |value: &str| SENTINELS.contains(&value);
        match self {
            Self::Sentinel(_) => true,
            Self::Literal(_) | Self::ColumnRef(_) => false,
            Self::FunctionCall { name, args } => {
                is_sentinel(name) || args.iter().any(Self::contains_opaque)
            }
            Self::BinaryOp { left, op, right } => {
                is_sentinel(op) || left.contains_opaque() || right.contains_opaque()
            }
            Self::Cast { expr, target_type } => is_sentinel(target_type) || expr.contains_opaque(),
            Self::UnaryOp { op, expr } => {
                !matches!(op.as_str(), "+" | "-" | "NOT") || expr.contains_opaque()
            }
            Self::Omitted => true,
        }
    }

    pub(crate) fn is_volatile(&self) -> bool {
        match self {
            ExprIr::FunctionCall { name, args } => {
                const VOLATILE: &[&str] = &[
                    "clock_timestamp",
                    "timeofday",
                    "random",
                    "setseed",
                    "txid_current",
                    "txid_current_snapshot",
                    "txid_snapshot_xip",
                    "txid_snapshot_xmax",
                    "txid_snapshot_xmin",
                    "nextval",
                    "currval",
                    "lastval",
                    "setval",
                    "gen_random_uuid",
                    "uuid_generate_v1",
                    "uuid_generate_v1mc",
                    "uuid_generate_v4",
                ];

                // The lookup contains only VOLATILE functions; nested calls
                // are classified recursively below.
                let normalized = name.to_ascii_lowercase();
                let known_volatile = VOLATILE.contains(&normalized.as_str())
                    || normalized
                        .strip_prefix("pg_catalog.")
                        .is_some_and(|name| VOLATILE.contains(&name));
                known_volatile || args.iter().any(ExprIr::is_volatile)
            }
            ExprIr::BinaryOp { left, right, .. } => left.is_volatile() || right.is_volatile(),
            ExprIr::Cast { expr, .. } | ExprIr::UnaryOp { expr, .. } => expr.is_volatile(),
            ExprIr::Sentinel(_) | ExprIr::Literal(_) | ExprIr::ColumnRef(_) | ExprIr::Omitted => {
                false
            }
        }
    }
}
