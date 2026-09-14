use crate::_internal::analysis::expr_ir::ExprIr;
use squawk_syntax::ast::{AstNode, Expr};

pub(crate) struct ExprVisitor;

impl ExprVisitor {
    pub(crate) fn rename_partition_key_source(
        source: &str,
        table: &str,
        from: &str,
        to: &str,
    ) -> Option<String> {
        use squawk_syntax::ast::{PartitionBy, SourceFile};
        let prefix = "CREATE TABLE __partition_key () ";
        let parsed = SourceFile::parse(&format!("{prefix}{source}"));
        if !parsed.errors().is_empty() || parsed.tree().stmts().count() != 1 {
            return None;
        }
        let partition = parsed
            .tree()
            .syntax()
            .descendants()
            .find_map(PartitionBy::cast)?;
        let mut replacements = Vec::new();
        for item in partition.partition_item_list()?.partition_items() {
            let expr = item.expr()?;
            let range = expr.syntax().text_range();
            let replacement =
                Self::rename_column_source(&expr.syntax().text().to_string(), table, from, to)?;
            replacements.push((
                usize::from(range.start()).checked_sub(prefix.len())?,
                usize::from(range.end()).checked_sub(prefix.len())?,
                replacement,
            ));
        }
        let mut result = source.to_string();
        for (start, end, replacement) in replacements.into_iter().rev() {
            result.replace_range(start..end, &replacement);
        }
        Some(result)
    }

    pub(crate) fn rename_column_source(
        source: &str,
        table: &str,
        from: &str,
        to: &str,
    ) -> Option<String> {
        use squawk_syntax::ast::{CallExpr, FieldExpr, NameRef, SourceFile};
        let prefix = "SELECT ";
        let parsed = SourceFile::parse(&format!("{prefix}{source}"));
        if !parsed.errors().is_empty() || parsed.tree().stmts().count() != 1 {
            return None;
        }
        let mut ranges = Vec::new();
        // A statistics expression list is valid SELECT target syntax too, so
        // scan every target rather than assuming a single expression.
        for name in parsed
            .tree()
            .syntax()
            .descendants()
            .filter_map(NameRef::cast)
        {
            if name.text() != from {
                continue;
            }
            // A qualified callee contains NameRefs too, but none refer to columns.
            if name
                .syntax()
                .ancestors()
                .filter_map(CallExpr::cast)
                .any(|call| {
                    call.expr().is_some_and(|callee| {
                        callee
                            .syntax()
                            .text_range()
                            .contains_range(name.syntax().text_range())
                    })
                })
            {
                continue;
            }
            if let Some(parent) = name.syntax().parent()
                && let Some(field) = FieldExpr::cast(parent)
            {
                let qualified_table = field.base().is_some_and(
                    |base| matches!(base, Expr::NameRef(base) if base.text() == table),
                );
                let is_field = field
                    .field()
                    .is_some_and(|field| field.syntax() == name.syntax());
                if (is_field && !qualified_table) || (!is_field && qualified_table) {
                    continue;
                }
            }
            let range = name.syntax().text_range();
            ranges.push((
                usize::from(range.start()).checked_sub(prefix.len())?,
                usize::from(range.end()).checked_sub(prefix.len())?,
            ));
        }
        // Preserve the normal PostgreSQL deparse for ordinary identifiers, but
        // quote names whose spelling cannot safely be parsed unquoted.
        let replacement = if Self::can_render_unquoted_identifier(to) {
            to.to_string()
        } else {
            format!("\"{}\"", to.replace('"', "\"\""))
        };
        let mut result = source.to_string();
        ranges.sort_unstable();
        for (start, end) in ranges.into_iter().rev() {
            result.replace_range(start..end, &replacement);
        }
        Some(result)
    }

    fn can_render_unquoted_identifier(identifier: &str) -> bool {
        use squawk_syntax::ast::{NameRef, SourceFile, Target};

        let mut chars = identifier.chars();
        if !matches!(chars.next(), Some('a'..='z' | '_'))
            || !chars.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '_' | '$'))
        {
            return false;
        }
        let parsed = SourceFile::parse(&format!("SELECT {identifier}"));
        parsed.errors().is_empty()
            && parsed.tree().stmts().count() == 1
            && parsed
                .tree()
                .syntax()
                .descendants()
                .find_map(Target::cast)
                .and_then(|target| target.expr())
                .and_then(|expr| NameRef::cast(expr.syntax().clone()))
                .is_some_and(|name| name.text() == identifier && !name.is_quoted())
    }

    pub(crate) fn convert(expr: Expr) -> ExprIr {
        match expr {
            Expr::Literal(lit) => Self::convert_literal(lit),
            Expr::NameRef(nr) => Self::convert_name_ref(nr),
            Expr::CallExpr(ce) => Self::convert_call_expr(ce),
            Expr::BinExpr(be) => Self::convert_bin_expr(be),
            Expr::CastExpr(ce) => Self::convert_cast_expr(ce),
            Expr::PrefixExpr(pe) => {
                use squawk_syntax::ast::PrefixOp;
                let op = match pe.op() {
                    Some(PrefixOp::Minus(_)) => "-".into(),
                    Some(PrefixOp::Plus(_)) => "+".into(),
                    Some(PrefixOp::Not(_)) => "NOT".into(),
                    Some(PrefixOp::CustomOp(op)) => op.syntax().text().to_string(),
                    Some(PrefixOp::OperatorCall(op)) => op.syntax().text().to_string(),
                    None => return ExprIr::Sentinel("<prefix>".into()),
                };
                ExprIr::UnaryOp {
                    op,
                    expr: Box::new(pe.expr().map(Self::convert).unwrap_or(ExprIr::Omitted)),
                }
            }
            Expr::ParenExpr(pe) => pe
                .expr()
                .map(Self::convert)
                .unwrap_or(ExprIr::Sentinel("<paren>".into())),
            Expr::CaseExpr(ce) => Self::convert_case_expr(ce),
            Expr::ArrayExpr(ae) => Self::convert_array_expr(ae),
            Expr::BetweenExpr(be) => Self::convert_between_expr(be),
            Expr::IndexExpr(ie) => Self::convert_index_expr(ie),
            Expr::SliceExpr(se) => Self::convert_slice_expr(se),
            Expr::FieldExpr(fe) => Self::convert_field_expr(fe),
            Expr::PostfixExpr(pe) => Self::convert_postfix_expr(pe),
            Expr::Collate(ce) => {
                let left = ce
                    .expr()
                    .map(Self::convert)
                    .unwrap_or(ExprIr::Sentinel("<lhs>".into()));
                let right = ce
                    .collation_ref()
                    .map(|c| c.syntax().text().to_string())
                    .unwrap_or_else(|| "<collation>".into());
                ExprIr::BinaryOp {
                    left: Box::new(left),
                    op: "COLLATE".to_string(),
                    right: Box::new(ExprIr::Literal(right)),
                }
            }
            _ => ExprIr::Sentinel("<complex>".into()),
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
        let name = ce
            .expr()
            .map(|e| match e {
                Expr::NameRef(nr) => nr.text().to_string(),
                other => other.syntax().text().to_string(),
            })
            .unwrap_or_else(|| "<fn>".into());

        let args = ce
            .arg_list()
            .map(|al| {
                al.args()
                    .filter_map(|arg| arg.expr())
                    .map(Self::convert)
                    .collect()
            })
            .unwrap_or_default();

        ExprIr::FunctionCall { name, args }
    }

    fn convert_bin_expr(be: squawk_syntax::ast::BinExpr) -> ExprIr {
        let left = be
            .lhs()
            .map(Self::convert)
            .unwrap_or(ExprIr::Sentinel("<lhs>".into()));
        let right = be
            .rhs()
            .map(Self::convert)
            .unwrap_or(ExprIr::Sentinel("<rhs>".into()));

        use squawk_syntax::ast::BinOp;
        let op = be
            .op()
            .map(|o| match o {
                BinOp::And(t) => t.text().to_string(),
                BinOp::Caret(t) => t.text().to_string(),
                BinOp::ColonEq(t) => t.text().to_string(),
                BinOp::Eq(t) => t.text().to_string(),
                BinOp::FatArrow(t) => t.text().to_string(),
                BinOp::Gteq(t) => t.text().to_string(),
                BinOp::Ilike(t) => t.text().to_string(),
                BinOp::In(t) => t.text().to_string(),
                BinOp::Is(t) => t.text().to_string(),
                BinOp::LAngle(t) => t.text().to_string(),
                BinOp::Like(t) => t.text().to_string(),
                BinOp::Lteq(t) => t.text().to_string(),
                BinOp::Minus(t) => t.text().to_string(),
                BinOp::Neq(t) => t.text().to_string(),
                BinOp::Neqb(t) => t.text().to_string(),
                BinOp::Or(t) => t.text().to_string(),
                BinOp::Overlaps(t) => t.text().to_string(),
                BinOp::Percent(t) => t.text().to_string(),
                BinOp::Plus(t) => t.text().to_string(),
                BinOp::RAngle(t) => t.text().to_string(),
                BinOp::Slash(t) => t.text().to_string(),
                BinOp::Star(t) => t.text().to_string(),
                BinOp::AtTimeZone(n) => n.syntax().text().to_string(),
                BinOp::ColonColon(n) => n.syntax().text().to_string(),
                BinOp::CustomOp(n) => n.syntax().text().to_string(),
                BinOp::IsDistinctFrom(n) => n.syntax().text().to_string(),
                BinOp::IsNot(n) => n.syntax().text().to_string(),
                BinOp::IsNotDistinctFrom(n) => n.syntax().text().to_string(),
                BinOp::NotIlike(n) => n.syntax().text().to_string(),
                BinOp::NotIn(n) => n.syntax().text().to_string(),
                BinOp::NotLike(n) => n.syntax().text().to_string(),
                BinOp::NotSimilarTo(n) => n.syntax().text().to_string(),
                BinOp::OperatorCall(n) => n.syntax().text().to_string(),
                BinOp::SimilarTo(n) => n.syntax().text().to_string(),
                BinOp::Escape(t) => t.text().to_string(),
            })
            .unwrap_or_else(|| "<op>".into());

        ExprIr::BinaryOp {
            left: Box::new(left),
            op,
            right: Box::new(right),
        }
    }

    fn convert_cast_expr(ce: squawk_syntax::ast::CastExpr) -> ExprIr {
        let inner = ce
            .expr()
            .map(Self::convert)
            .unwrap_or(ExprIr::Sentinel("<cast_inner>".into()));
        let target_type = ce
            .ty()
            .map(|t| t.syntax().text().to_string())
            .unwrap_or_else(|| "<type>".into());
        ExprIr::Cast {
            expr: Box::new(inner),
            target_type,
        }
    }

    fn convert_case_expr(ce: squawk_syntax::ast::CaseExpr) -> ExprIr {
        let mut branches: Vec<ExprIr> = Vec::new();

        branches.push(ce.expr().map(Self::convert).unwrap_or(ExprIr::Omitted));

        if let Some(wcl) = ce.when_clause_list() {
            for when in wcl.when_clauses() {
                branches.push(
                    when.condition()
                        .map(Self::convert)
                        .unwrap_or(ExprIr::Omitted),
                );
                branches.push(when.then().map(Self::convert).unwrap_or(ExprIr::Omitted));
            }
        }

        branches.push(
            ce.else_clause()
                .and_then(|ec| ec.expr())
                .map(Self::convert)
                .unwrap_or(ExprIr::Omitted),
        );

        ExprIr::FunctionCall {
            name: "<case>".into(),
            args: branches,
        }
    }

    fn convert_array_expr(ae: squawk_syntax::ast::ArrayExpr) -> ExprIr {
        let elements: Vec<ExprIr> = ae.exprs().map(Self::convert).collect();
        ExprIr::FunctionCall {
            name: "<array>".into(),
            args: elements,
        }
    }

    fn convert_between_expr(be: squawk_syntax::ast::BetweenExpr) -> ExprIr {
        let args = vec![
            be.target().map(Self::convert).unwrap_or(ExprIr::Omitted),
            be.start().map(Self::convert).unwrap_or(ExprIr::Omitted),
            be.end().map(Self::convert).unwrap_or(ExprIr::Omitted),
        ];
        ExprIr::FunctionCall {
            name: "<between>".into(),
            args,
        }
    }

    fn convert_index_expr(ie: squawk_syntax::ast::IndexExpr) -> ExprIr {
        let args = vec![
            ie.base().map(Self::convert).unwrap_or(ExprIr::Omitted),
            ie.index().map(Self::convert).unwrap_or(ExprIr::Omitted),
        ];
        ExprIr::FunctionCall {
            name: "<index>".into(),
            args,
        }
    }

    fn convert_slice_expr(se: squawk_syntax::ast::SliceExpr) -> ExprIr {
        let args = vec![
            se.base().map(Self::convert).unwrap_or(ExprIr::Omitted),
            se.start().map(Self::convert).unwrap_or(ExprIr::Omitted),
            se.end().map(Self::convert).unwrap_or(ExprIr::Omitted),
        ];
        ExprIr::FunctionCall {
            name: "<slice>".into(),
            args,
        }
    }

    fn convert_field_expr(fe: squawk_syntax::ast::FieldExpr) -> ExprIr {
        let args = vec![
            fe.base().map(Self::convert).unwrap_or(ExprIr::Omitted),
            fe.field()
                .map(|f| ExprIr::Literal(f.text().to_string()))
                .unwrap_or(ExprIr::Omitted),
        ];
        ExprIr::FunctionCall {
            name: "<field>".into(),
            args,
        }
    }

    fn convert_postfix_expr(pe: squawk_syntax::ast::PostfixExpr) -> ExprIr {
        let mut args = Vec::new();
        for child in pe.syntax().children() {
            if let Some(expr) = Expr::cast(child) {
                args.push(Self::convert(expr));
            }
        }
        ExprIr::FunctionCall {
            name: "<postfix>".into(),
            args,
        }
    }
}
