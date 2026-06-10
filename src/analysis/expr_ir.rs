// src/analysis/expr_ir.rs

#[derive(Debug, Clone, PartialEq)]
pub enum ExprIr {
    /// A raw value: `42`, `'John'`, `true`
    Literal(String),

    /// Reference to another column: `age`
    ColumnRef(String),

    /// A function call: `now()`, `concat(first, last)`
    /// Also used as a synthetic container for CASE and ARRAY expressions
    /// (name = "<case>" or "<array>") so volatility recursion can work
    /// without adding new variants.
    FunctionCall {
        name: String,
        args: Vec<ExprIr>,
    },

    /// An operation: `price * 1.2`, `age >= 18`
    BinaryOp {
        left: Box<ExprIr>,
        op: String,
        right: Box<ExprIr>,
    },

    /// A type cast: `'2024-01-01'::date`, `CAST(id AS text)`
    Cast {
        expr: Box<ExprIr>,
        target_type: String,
    },
}

impl ExprIr {
    /// Returns true if this expression is known to be volatile —
    /// i.e. returns different results on each call, which causes a full
    /// table rewrite when used as a column DEFAULT on PostgreSQL < 11.
    pub fn is_volatile(&self) -> bool {
        match self {
            ExprIr::FunctionCall { name, args } => {
                // Synthetic container names from CaseExpr/ArrayExpr walking.
                // The name itself is not a real function; recurse into args.
                if name == "<case>" || name == "<array>" {
                    return args.iter().any(|a| a.is_volatile());
                }

                // Known volatile built-in functions.
                //
                // PostgreSQL volatility categories:
                //   VOLATILE: returns different results on successive calls,
                //              even with the same arguments.
                //   STABLE:   returns the same result within a single statement.
                //   IMMUTABLE: always returns the same result for the same args.
                //
                // Only VOLATILE causes a table rewrite on ADD COLUMN DEFAULT.
                //
                // This list is not exhaustive — user-defined volatile functions
                // and extensions are not covered. False negatives are possible.
                const VOLATILE: &[&str] = &[
                    // Time functions — change on every call
                    "now",
                    "clock_timestamp",
                    "transaction_timestamp",
                    "statement_timestamp",
                    "timeofday",
                    // Random
                    "random",
                    "setseed",
                    // Transaction ID
                    "txid_current",
                    "txid_current_snapshot",
                    "txid_snapshot_xip",
                    "txid_snapshot_xmax",
                    "txid_snapshot_xmin",
                    // Sequences — each call advances the sequence
                    "nextval",
                    "currval",
                    "lastval",
                    "setval",
                    // UUID generation
                    "gen_random_uuid",
                    "uuid_generate_v1",
                    "uuid_generate_v1mc",
                    "uuid_generate_v4",
                ];

                VOLATILE.contains(&name.to_lowercase().as_str())
            }

            // Recursively check sub-expressions.
            ExprIr::BinaryOp { left, right, .. } => left.is_volatile() || right.is_volatile(),
            ExprIr::Cast { expr, .. } => expr.is_volatile(),

            // Literals and column references are never volatile.
            ExprIr::Literal(_) | ExprIr::ColumnRef(_) => false,
        }
    }
}
