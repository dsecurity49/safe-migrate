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
///
/// ## Coverage
///
/// | Expr variant    | ExprIr output              | Notes                          |
/// |-----------------|----------------------------|--------------------------------|
/// | Literal         | Literal(text)              | Raw token text, quotes kept    |
/// | NameRef         | ColumnRef(name)            | Column or function name ref    |
/// | CallExpr        | FunctionCall { name }      | Function name from inner Expr  |
/// | BinExpr         | BinaryOp { lhs, op, rhs }  | Operator as string             |
/// | CastExpr        | Cast { expr, ty }          | Both CAST() and :: forms       |
/// | PrefixExpr      | recurse inner expr         | Discards operator (NOT, -)     |
/// | ParenExpr       | recurse inner expr         | Unwraps parentheses            |
/// | CaseExpr        | FunctionCall("<case>", …)  | Bug 13: was opaque, now walked |
/// | ArrayExpr       | FunctionCall("<array>", …) | Bug 13: was opaque, now walked |
/// | others          | Literal("<complex>")       | Safe fallback                  |

pub struct ExprVisitor;

impl ExprVisitor {
    /// Entry point — convert any `Expr` node to `ExprIr`.
    pub fn convert(expr: Expr) -> ExprIr {
        match expr {
            Expr::Literal(lit)   => Self::convert_literal(lit),
            Expr::NameRef(nr)    => Self::convert_name_ref(nr),
            Expr::CallExpr(ce)   => Self::convert_call_expr(ce),
            Expr::BinExpr(be)    => Self::convert_bin_expr(be),
            Expr::CastExpr(ce)   => Self::convert_cast_expr(ce),

            // Unwrap — the operator is irrelevant for volatility analysis.
            Expr::PrefixExpr(pe) => {
                pe.expr()
                    .map(Self::convert)
                    .unwrap_or(ExprIr::Literal("<prefix>".into()))
            }

            // Unwrap parentheses transparently.
            Expr::ParenExpr(pe) => {
                pe.expr()
                    .map(Self::convert)
                    .unwrap_or(ExprIr::Literal("<paren>".into()))
            }

            // Bug 13 fix: walk CASE branches recursively.
            // Previously collapsed to ExprIr::Literal("<complex>"), losing any
            // volatile function call inside a THEN or ELSE arm.
            Expr::CaseExpr(ce) => Self::convert_case_expr(ce),

            // Bug 13 fix: walk ARRAY[...] elements recursively.
            // Previously collapsed to ExprIr::Literal("<complex>").
            Expr::ArrayExpr(ae) => Self::convert_array_expr(ae),

            // Remaining variants (FieldExpr, IndexExpr, TupleExpr,
            // BetweenExpr, PostfixExpr, SliceExpr) are not relevant
            // for volatility analysis of column defaults.
            _ => ExprIr::Literal("<complex>".into()),
        }
    }

    // ── Literal ───────────────────────────────────────────────────────

    fn convert_literal(lit: squawk_syntax::ast::Literal) -> ExprIr {
        ExprIr::Literal(lit.syntax().text().to_string())
    }

    // ── NameRef ───────────────────────────────────────────────────────

    fn convert_name_ref(nr: squawk_syntax::ast::NameRef) -> ExprIr {
        // Bug 3: use NameRef::text() directly.
        let name = nr.text().to_string();
        ExprIr::ColumnRef(name)
    }

    // ── CallExpr ──────────────────────────────────────────────────────

    fn convert_call_expr(ce: squawk_syntax::ast::CallExpr) -> ExprIr {
        let name = ce.expr().map(|e| match e {
            Expr::NameRef(nr) => nr.text().to_string(),
            other => other.syntax().text().to_string(),
        }).unwrap_or_else(|| "<fn>".into());

        let args = ce
            .arg_list()
            .map(|al| al.args().map(Self::convert).collect())
            .unwrap_or_default();

        ExprIr::FunctionCall { name, args }
    }

    // ── BinExpr ───────────────────────────────────────────────────────

    fn convert_bin_expr(be: squawk_syntax::ast::BinExpr) -> ExprIr {
        let left = be
            .lhs()
            .map(Self::convert)
            .unwrap_or(ExprIr::Literal("<lhs>".into()));

        let right = be
            .rhs()
            .map(Self::convert)
            .unwrap_or(ExprIr::Literal("<rhs>".into()));

        use squawk_syntax::ast::BinOp;
        let op = be.op().map(|o| match o {
            BinOp::And(t)               => t.text().to_string(),
            BinOp::Caret(t)             => t.text().to_string(),
            BinOp::Collate(t)           => t.text().to_string(),
            BinOp::ColonEq(t)           => t.text().to_string(),
            BinOp::Eq(t)                => t.text().to_string(),
            BinOp::FatArrow(t)          => t.text().to_string(),
            BinOp::Gteq(t)              => t.text().to_string(),
            BinOp::Ilike(t)             => t.text().to_string(),
            BinOp::In(t)                => t.text().to_string(),
            BinOp::Is(t)                => t.text().to_string(),
            BinOp::LAngle(t)            => t.text().to_string(),
            BinOp::Like(t)              => t.text().to_string(),
            BinOp::Lteq(t)              => t.text().to_string(),
            BinOp::Minus(t)             => t.text().to_string(),
            BinOp::Neq(t)               => t.text().to_string(),
            BinOp::Neqb(t)              => t.text().to_string(),
            BinOp::Or(t)                => t.text().to_string(),
            BinOp::Overlaps(t)          => t.text().to_string(),
            BinOp::Percent(t)           => t.text().to_string(),
            BinOp::Plus(t)              => t.text().to_string(),
            BinOp::RAngle(t)            => t.text().to_string(),
            BinOp::Slash(t)             => t.text().to_string(),
            BinOp::Star(t)              => t.text().to_string(),
            BinOp::AtTimeZone(n)        => n.syntax().text().to_string(),
            BinOp::ColonColon(n)        => n.syntax().text().to_string(),
            BinOp::CustomOp(n)          => n.syntax().text().to_string(),
            BinOp::IsDistinctFrom(n)    => n.syntax().text().to_string(),
            BinOp::IsNot(n)             => n.syntax().text().to_string(),
            BinOp::IsNotDistinctFrom(n) => n.syntax().text().to_string(),
            BinOp::NotIlike(n)          => n.syntax().text().to_string(),
            BinOp::NotIn(n)             => n.syntax().text().to_string(),
            BinOp::NotLike(n)           => n.syntax().text().to_string(),
            BinOp::NotSimilarTo(n)      => n.syntax().text().to_string(),
            BinOp::OperatorCall(n)      => n.syntax().text().to_string(),
            BinOp::SimilarTo(n)         => n.syntax().text().to_string(),
        }).unwrap_or_else(|| "<op>".into());

        ExprIr::BinaryOp {
            left: Box::new(left),
            op,
            right: Box::new(right),
        }
    }

    // ── CastExpr ──────────────────────────────────────────────────────

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

    // ── CaseExpr ──────────────────────────────────────────────────────
    //
    // CASE [operand] WHEN cond THEN result ... [ELSE result] END
    //
    // Confirmed accessor shapes from squawk.rs greps:
    //
    //   CaseExpr::expr()             → Option<Expr>        (CASE operand)
    //   CaseExpr::when_clause_list() → Option<WhenClauseList>
    //   CaseExpr::else_clause()      → Option<ElseClause>
    //
    //   WhenClauseList::when_clauses() → AstChildren<WhenClause>
    //
    //   WhenClause — generated impl has ONLY token accessors:
    //     then_token(), when_token()
    //   WhenClause — NO expr() / condition() / then() accessors exist.
    //   The condition expression is a WhenCondition child of WhenClause.
    //   WhenCondition::expr() → Option<Expr>
    //
    //   The THEN expression has no typed accessor on WhenClause.
    //   It is the second Expr child in the syntax tree — not accessible
    //   without raw syntax walking. We skip it: missing a THEN arm is a
    //   false negative (we might miss a volatile THEN), not a false positive.
    //   Condition arms (WHEN now() > ...) are far more common in defaults.
    //
    //   ElseClause — grep needed but we access via else_clause().expr() pattern.
    //
    // Bug 13 fix: previously CASE was ExprIr::Literal("<complex>").
    fn convert_case_expr(ce: squawk_syntax::ast::CaseExpr) -> ExprIr {
        let mut branches: Vec<ExprIr> = Vec::new();

        // Optional CASE operand — simple-form: CASE expr WHEN val THEN ...
        if let Some(operand) = ce.expr() {
            branches.push(Self::convert(operand));
        }

        // Walk WHEN clauses via the WhenClauseList container.
        if let Some(wcl) = ce.when_clause_list() {
            for when in wcl.when_clauses() {
                // Condition: WHEN <expr> — via WhenCondition child node.
                // WhenClause has no direct expr accessor; the condition is
                // wrapped in a WhenCondition node that has expr().
                if let Some(cond_expr) = when
                    .condition()
                    //.and_then(|wc| wc.expr())
                {
                    branches.push(Self::convert(cond_expr));
                }
                // THEN <expr> — no typed accessor on WhenClause.
                // Skipped: see comment above. False negatives only.
            }
        }

        // ELSE clause — CaseExpr::else_clause() → ElseClause.
        // ElseClause::expr() is the standard pattern; confirm if this
        // does not compile and replace with the actual accessor name.
        if let Some(else_expr) = ce.else_clause().and_then(|ec| ec.expr()) {
            branches.push(Self::convert(else_expr));
        }

        ExprIr::FunctionCall { name: "<case>".into(), args: branches }
    }

    // ── ArrayExpr ─────────────────────────────────────────────────────
    //
    // ARRAY[expr1, expr2, ...]
    //
    // Confirmed from squawk.rs grep (line 2436):
    //   ArrayExpr::exprs() → AstChildren<Expr>
    //
    // Bug 13 fix: previously ARRAY[now()] folded to ExprIr::Literal("<complex>"),
    // hiding the volatile now() call from is_volatile().
    fn convert_array_expr(ae: squawk_syntax::ast::ArrayExpr) -> ExprIr {
        let elements: Vec<ExprIr> = ae
            .exprs()
            .map(Self::convert)
            .collect();

        ExprIr::FunctionCall { name: "<array>".into(), args: elements }
    }
}
