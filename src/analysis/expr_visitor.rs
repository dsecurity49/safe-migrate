use crate::analysis::expr_ir::ExprIr;
use squawk_syntax::ast::{AstNode, Expr};

/// Converts a squawk AST `Expr` node into our `ExprIr` representation.
///
/// ## Design invariants
///
/// - Never panics — all failures return `ExprIr::Literal("<unknown>".into())`
///   so the caller always gets a usable value.
/// - No state access — pure syntax → IR conversion.
/// - Recursion depth is bounded by SQL expression depth in practice.
///   Pathological nesting (>100 levels) is extremely rare in migration defaults.
///
/// ## Coverage
///
/// | Expr variant    | ExprIr output           | Notes                          |
/// |-----------------|-------------------------|--------------------------------|
/// | Literal         | Literal(text)           | Raw token text, quotes kept    |
/// | NameRef         | ColumnRef(name)         | Column or function name ref    |
/// | CallExpr        | FunctionCall { name }   | Function name from inner Expr  |
/// | BinExpr         | BinaryOp { lhs, op, rhs }| Operator as string            |
/// | CastExpr        | Cast { expr, ty }       | Both CAST() and :: forms       |
/// | PrefixExpr      | recurse inner expr      | Discards operator (NOT, -)     |
/// | ParenExpr       | recurse inner expr      | Unwraps parentheses            |
/// | others          | Literal("<complex>")    | Safe fallback                  |

pub struct ExprVisitor;

impl ExprVisitor {
    /// Entry point — convert any `Expr` node to `ExprIr`.
    pub fn convert(expr: Expr) -> ExprIr {
        match expr {
            Expr::Literal(lit) => Self::convert_literal(lit),
            Expr::NameRef(nr)  => Self::convert_name_ref(nr),
            Expr::CallExpr(ce) => Self::convert_call_expr(ce),
            Expr::BinExpr(be)  => Self::convert_bin_expr(be),
            Expr::CastExpr(ce) => Self::convert_cast_expr(ce),

            // Unwrap — the operator is irrelevant for volatility analysis.
            Expr::PrefixExpr(pe) => {
                pe.expr()
                    .map(Self::convert)
                    .unwrap_or(ExprIr::Literal("<prefix>".into()))
            }

            // Unwrap parentheses transparently using the generated expr() accessor.
            Expr::ParenExpr(pe) => {
                pe.expr()
                    .map(Self::convert)
                    .unwrap_or(ExprIr::Literal("<paren>".into()))
            }

            // All other variants (FieldExpr, IndexExpr, TupleExpr, ArrayExpr,
            // BetweenExpr, PostfixExpr, CaseExpr, SliceExpr) are not relevant
            // for volatility analysis of column defaults. Treat as opaque.
            _ => ExprIr::Literal("<complex>".into()),
        }
    }

    // ── Literal ───────────────────────────────────────────────────────

    fn convert_literal(lit: squawk_syntax::ast::Literal) -> ExprIr {
        // Literal::kind() gives us a typed token. We use the raw text
        // for ExprIr::Literal since we only need it for volatility checking
        // (which only cares about function calls, not literal values).
        ExprIr::Literal(lit.syntax().text().to_string())
    }

    // ── NameRef ───────────────────────────────────────────────────────

    fn convert_name_ref(nr: squawk_syntax::ast::NameRef) -> ExprIr {
        let name = nr
            .ident_token()
            .map(|t| t.text().to_string())
            .unwrap_or_else(|| "<name>".into());
        ExprIr::ColumnRef(name)
    }

    // ── CallExpr ──────────────────────────────────────────────────────
    //
    // CallExpr structure:
    //   CallExpr {
    //     expr: Expr   ← the function path (NameRef or FieldExpr)
    //     arg_list: ArgList {
    //       args: AstChildren<Expr>
    //     }
    //   }

    fn convert_call_expr(ce: squawk_syntax::ast::CallExpr) -> ExprIr {
        // Extract the function name from the inner expr.
        // Most calls: Expr::NameRef("now") → "now"
        // Schema-qualified: Expr::FieldExpr → use raw text
        let name = ce.expr().map(|e| match e {
            Expr::NameRef(nr) => nr
                .ident_token()
                .map(|t| t.text().to_string())
                .unwrap_or_else(|| "<fn>".into()),
            other => other.syntax().text().to_string(),
        }).unwrap_or_else(|| "<fn>".into());

        // Convert each argument recursively.
        let args = ce
            .arg_list()
            .map(|al| al.args().map(Self::convert).collect())
            .unwrap_or_default();

        ExprIr::FunctionCall { name, args }
    }

    // ── BinExpr ───────────────────────────────────────────────────────
    //
    // BinExpr has handwritten accessors:
    //   lhs() → Option<Expr>   (nth(0))
    //   rhs() → Option<Expr>   (nth(1))
    //   op()  → Option<BinOp>  (token-based enum)
    //
    // We convert the operator to a string for ExprIr::BinaryOp.

    fn convert_bin_expr(be: squawk_syntax::ast::BinExpr) -> ExprIr {
        let left = be
            .lhs()
            .map(Self::convert)
            .unwrap_or(ExprIr::Literal("<lhs>".into()));

        let right = be
            .rhs()
            .map(Self::convert)
            .unwrap_or(ExprIr::Literal("<rhs>".into()));

        // BinOp is a mixed enum — SyntaxToken variants and AST node variants.
        // No impl BinOp exists. Extract operator text by matching each variant.
        use squawk_syntax::ast::BinOp;
        let op = be.op().map(|o| match o {
            BinOp::And(t)       => t.text().to_string(),
            BinOp::Caret(t)     => t.text().to_string(),
            BinOp::Collate(t)   => t.text().to_string(),
            BinOp::ColonEq(t)   => t.text().to_string(),
            BinOp::Eq(t)        => t.text().to_string(),
            BinOp::FatArrow(t)  => t.text().to_string(),
            BinOp::Gteq(t)      => t.text().to_string(),
            BinOp::Ilike(t)     => t.text().to_string(),
            BinOp::In(t)        => t.text().to_string(),
            BinOp::Is(t)        => t.text().to_string(),
            BinOp::LAngle(t)    => t.text().to_string(),
            BinOp::Like(t)      => t.text().to_string(),
            BinOp::Lteq(t)      => t.text().to_string(),
            BinOp::Minus(t)     => t.text().to_string(),
            BinOp::Neq(t)       => t.text().to_string(),
            BinOp::Neqb(t)      => t.text().to_string(),
            BinOp::Or(t)        => t.text().to_string(),
            BinOp::Overlaps(t)  => t.text().to_string(),
            BinOp::Percent(t)   => t.text().to_string(),
            BinOp::Plus(t)      => t.text().to_string(),
            BinOp::RAngle(t)    => t.text().to_string(),
            BinOp::Slash(t)     => t.text().to_string(),
            BinOp::Star(t)      => t.text().to_string(),
            // AST node variants
            BinOp::AtTimeZone(n)           => n.syntax().text().to_string(),
            BinOp::ColonColon(n)           => n.syntax().text().to_string(),
            BinOp::CustomOp(n)             => n.syntax().text().to_string(),
            BinOp::IsDistinctFrom(n)       => n.syntax().text().to_string(),
            BinOp::IsNot(n)                => n.syntax().text().to_string(),
            BinOp::IsNotDistinctFrom(n)    => n.syntax().text().to_string(),
            BinOp::NotIlike(n)             => n.syntax().text().to_string(),
            BinOp::NotIn(n)                => n.syntax().text().to_string(),
            BinOp::NotLike(n)              => n.syntax().text().to_string(),
            BinOp::NotSimilarTo(n)         => n.syntax().text().to_string(),
            BinOp::OperatorCall(n)         => n.syntax().text().to_string(),
            BinOp::SimilarTo(n)            => n.syntax().text().to_string(),
        }).unwrap_or_else(|| "<op>".into());

        ExprIr::BinaryOp {
            left: Box::new(left),
            op,
            right: Box::new(right),
        }
    }

    // ── CastExpr ──────────────────────────────────────────────────────
    //
    // Handles both CAST(expr AS type) and expr::type forms.
    // CastExpr::expr() → the inner expression
    // CastExpr::ty()   → the target type

    fn convert_cast_expr(ce: squawk_syntax::ast::CastExpr) -> ExprIr {
        let inner = ce
            .expr()
            .map(Self::convert)
            .unwrap_or(ExprIr::Literal("<cast_inner>".into()));

        let target_type = ce
            .ty()
            .map(|t| t.syntax().text().to_string())
            .unwrap_or_else(|| "<type>".into());

        ExprIr::Cast {
            expr: Box::new(inner),
            target_type,
        }
    }
}
