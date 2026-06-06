// src/analysis/expr_ir.rs

#[derive(Debug, Clone, PartialEq)]
pub enum ExprIr {
    /// A raw value: `42`, `'John'`, `true`
    Literal(String),
    
    /// Reference to another column: `age`
    ColumnRef(String),
    
    /// A function call: `now()`, `concat(first, last)`
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
    /// Helper to quickly check if an expression is known to be volatile
    /// (returns different results on each call, causing table rewrites).
    pub fn is_volatile(&self) -> bool {
        match self {
            ExprIr::FunctionCall { name, .. } => {
                let volatile_funcs = ["now", "random", "transaction_timestamp", "clock_timestamp"];
                volatile_funcs.contains(&name.to_lowercase().as_str())
            }
            ExprIr::BinaryOp { left, right, .. } => left.is_volatile() || right.is_volatile(),
            ExprIr::Cast { expr, .. } => expr.is_volatile(),
            _ => false,
        }
    }
}
