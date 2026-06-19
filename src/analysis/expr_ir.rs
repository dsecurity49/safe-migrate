// FILE: src/analysis/expr_ir.rs
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExprIr {
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
    Omitted, // Added to prevent positional shifting in incomplete expressions (e.g., arr[2:])
}

impl ExprIr {
    pub fn is_volatile(&self) -> bool {
        match self {
            ExprIr::FunctionCall { name, args } => {
                // Synthetic wrapper functions for nested expressions
                // e.g. <case>, <array>, <between>, <slice>
                if name.starts_with('<') && name.ends_with('>') {
                    return args.iter().any(|a| a.is_volatile());
                }

                const VOLATILE: &[&str] = &[
                    "now",
                    "clock_timestamp",
                    "transaction_timestamp",
                    "statement_timestamp",
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

                VOLATILE.contains(&name.to_lowercase().as_str())
            }
            ExprIr::BinaryOp { left, right, .. } => left.is_volatile() || right.is_volatile(),
            ExprIr::Cast { expr, .. } => expr.is_volatile(),
            ExprIr::Literal(_) | ExprIr::ColumnRef(_) | ExprIr::Omitted => false,
        }
    }
}

