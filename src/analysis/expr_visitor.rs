// FILE: ./src/analysis/expr_visitor.rs

use crate::analysis::expr_ir::ExprIr;
use squawk_syntax::ast::{AstNode, Expr};

pub struct ExprVisitor;

impl ExprVisitor {
    pub fn convert(expr: Expr) -> ExprIr {
        match expr {
            Expr::Literal(lit)    => Self::convert_literal(lit),
            Expr::NameRef(nr)     => Self::convert_name_ref(nr),
            Expr::CallExpr(ce)    => Self::convert_call_expr(ce),
            Expr::BinExpr(be)     => Self::convert_bin_expr(be),
            Expr::CastExpr(ce)    => Self::convert_cast_expr(ce),
            Expr::PrefixExpr(pe)  => {
                pe.expr()
                    .map(Self::convert)
                    .unwrap_or(ExprIr::Literal("<prefix>".into()))
            }
            Expr::ParenExpr(pe)   => {
                pe.expr()
                    .map(Self::convert)
                    .unwrap_or(ExprIr::Literal("<paren>".into()))
            }
            Expr::CaseExpr(ce)    => Self::convert_case_expr(ce),
            Expr::ArrayExpr(ae)   => Self::convert_array_expr(ae),
            Expr::BetweenExpr(be) => Self::convert_between_expr(be),
            Expr::IndexExpr(ie)   => Self::convert_index_expr(ie),
            Expr::SliceExpr(se)   => Self::convert_slice_expr(se),
            Expr::FieldExpr(fe)   => Self::convert_field_expr(fe),
            Expr::PostfixExpr(pe) => Self::convert_postfix_expr(pe),
            _                     => ExprIr::Literal("<complex>".into()),
        }
    }

    fn convert_literal(lit: squawk_syntax::ast::Literal) -> ExprIr {
        ExprIr::Literal(lit.syntax().text().to_string())
    }

    fn convert_name_ref(nr: squawk_syntax::ast::NameRef) -> ExprIr {
        let name = nr.text().to_string();
        ExprIr::ColumnRef(name)
    }

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

    fn convert_bin_expr(be: squawk_syntax::ast::BinExpr) -> ExprIr {
        let left = be.lhs().map(Self::convert).unwrap_or(ExprIr::Literal("<lhs>".into()));
        let right = be.rhs().map(Self::convert).unwrap_or(ExprIr::Literal("<rhs>".into()));

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

    fn convert_cast_expr(ce: squawk_syntax::ast::CastExpr) -> ExprIr {
        let inner = ce.expr().map(Self::convert).unwrap_or(ExprIr::Literal("<cast_inner>".into()));
        let target_type = ce.ty().map(|t| t.syntax().text().to_string()).unwrap_or_else(|| "<type>".into());
        ExprIr::Cast { expr: Box::new(inner), target_type }
    }

    fn convert_case_expr(ce: squawk_syntax::ast::CaseExpr) -> ExprIr {
        let mut branches: Vec<ExprIr> = Vec::new();
        
        // Index 0: Base expression (or omitted if standalone WHEN clauses)
        branches.push(ce.expr().map(Self::convert).unwrap_or(ExprIr::Omitted));
        
        if let Some(wcl) = ce.when_clause_list() {
            for when in wcl.when_clauses() {
                branches.push(when.condition().map(Self::convert).unwrap_or(ExprIr::Omitted));
                branches.push(when.then().map(Self::convert).unwrap_or(ExprIr::Omitted));
            }
        }
        
        // Final Index: Else clause (or omitted)
        branches.push(
            ce.else_clause()
                .and_then(|ec| ec.expr())
                .map(Self::convert)
                .unwrap_or(ExprIr::Omitted)
        );
        
        ExprIr::FunctionCall { name: "<case>".into(), args: branches }
    }

    fn convert_array_expr(ae: squawk_syntax::ast::ArrayExpr) -> ExprIr {
        let elements: Vec<ExprIr> = ae.exprs().map(Self::convert).collect();
        ExprIr::FunctionCall { name: "<array>".into(), args: elements }
    }

    fn convert_between_expr(be: squawk_syntax::ast::BetweenExpr) -> ExprIr {
        let mut args = Vec::new();
        args.push(be.target().map(Self::convert).unwrap_or(ExprIr::Omitted));
        args.push(be.start().map(Self::convert).unwrap_or(ExprIr::Omitted));
        args.push(be.end().map(Self::convert).unwrap_or(ExprIr::Omitted));
        ExprIr::FunctionCall { name: "<between>".into(), args }
    }

    fn convert_index_expr(ie: squawk_syntax::ast::IndexExpr) -> ExprIr {
        let mut args = Vec::new();
        args.push(ie.base().map(Self::convert).unwrap_or(ExprIr::Omitted));
        args.push(ie.index().map(Self::convert).unwrap_or(ExprIr::Omitted));
        ExprIr::FunctionCall { name: "<index>".into(), args }
    }

    fn convert_slice_expr(se: squawk_syntax::ast::SliceExpr) -> ExprIr {
        let mut args = Vec::new();
        args.push(se.base().map(Self::convert).unwrap_or(ExprIr::Omitted));
        args.push(se.start().map(Self::convert).unwrap_or(ExprIr::Omitted));
        args.push(se.end().map(Self::convert).unwrap_or(ExprIr::Omitted));
        ExprIr::FunctionCall { name: "<slice>".into(), args }
    }

    fn convert_field_expr(fe: squawk_syntax::ast::FieldExpr) -> ExprIr {
        let mut args = Vec::new();
        args.push(fe.base().map(Self::convert).unwrap_or(ExprIr::Omitted));
        args.push(fe.field().map(|f| ExprIr::Literal(f.text().to_string())).unwrap_or(ExprIr::Omitted));
        ExprIr::FunctionCall { name: "<field>".into(), args }
    }

    fn convert_postfix_expr(pe: squawk_syntax::ast::PostfixExpr) -> ExprIr {
        let mut args = Vec::new();
        for child in pe.syntax().children() {
            if let Some(expr) = Expr::cast(child) {
                args.push(Self::convert(expr));
            }
        }
        ExprIr::FunctionCall { name: "<postfix>".into(), args }
    }
}
