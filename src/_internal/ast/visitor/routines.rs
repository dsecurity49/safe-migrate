use super::*;

impl AstVisitor {
    pub(super) fn extract_param(
        param: &squawk_syntax::ast::Param,
    ) -> crate::_internal::analysis::facts::ParamFact {
        crate::_internal::analysis::facts::ParamFact {
            mode: match param.mode() {
                Some(ast::ParamMode::ParamVariadic(_)) => {
                    crate::_internal::analysis::facts::ParamModeFact::Variadic
                }
                Some(ast::ParamMode::ParamInOut(_)) => {
                    crate::_internal::analysis::facts::ParamModeFact::InOut
                }
                Some(ast::ParamMode::ParamOut(_)) => {
                    crate::_internal::analysis::facts::ParamModeFact::Out
                }
                _ => crate::_internal::analysis::facts::ParamModeFact::In,
            },
            name: param
                .name()
                .and_then(|n| n.syntax().first_token())
                .map(|t| Self::resolve_identifier_token(t.text())),
            ty: param
                .func_type()
                .map(|t| t.syntax().text().to_string())
                .unwrap_or_else(|| "unknown".into()),
            default: param.param_default().and_then(|pd| {
                pd.expr()
                    .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
            }),
        }
    }

    pub(super) fn extract_ret_type(
        ret: &squawk_syntax::ast::RetType,
    ) -> crate::_internal::analysis::facts::RetTypeFact {
        if let Some(tal) = ret.return_table_arg_list() {
            let cols = tal
                .args()
                .filter_map(|column| {
                    Some(ColumnFact {
                        name: Self::resolve_ast_identifier(&column.name()?),
                        ty: column.func_type().map(|ty| ty.syntax().text().to_string()),
                        not_null: false,
                        is_primary_key: false,
                        primary_key_constraint_name: None,
                        is_unique: false,
                        unique_constraint_name: None,
                        default: None,
                        generation: crate::_internal::analysis::facts::ColumnGeneration::Ordinary,
                        identity_sequence: None,
                        generated_expr: None,
                        generated_expr_sql: None,
                    })
                })
                .collect();
            crate::_internal::analysis::facts::RetTypeFact::Table(cols)
        } else {
            // `FuncType` wraps `Type`, and `SETOF` sits on the inner
            // `PathType`, so the flag has to be read from the parse tree
            // rather than recovered from the rendered text. The type is kept
            // without the keyword, matching `pg_proc.prorettype`.
            match ret.func_type() {
                Some(func_type) => {
                    let setof_token = match &func_type {
                        ast::FuncType::Type(ast::Type::PathType(path_type)) => {
                            path_type.setof_token()
                        }
                        _ => None,
                    };
                    let text = func_type.syntax().text().to_string();
                    let ty = match &setof_token {
                        Some(token) => text[token.text().len()..].trim_start().to_string(),
                        None => text,
                    };
                    crate::_internal::analysis::facts::RetTypeFact::Scalar {
                        ty,
                        setof: setof_token.is_some(),
                    }
                }
                None => crate::_internal::analysis::facts::RetTypeFact::Scalar {
                    ty: "unknown".to_string(),
                    setof: false,
                },
            }
        }
    }

    pub(super) fn extract_func_option(
        opt: &squawk_syntax::ast::FuncOption,
    ) -> crate::_internal::analysis::facts::FuncOptionFact {
        match opt {
            ast::FuncOption::LanguageFuncOption(f) => {
                crate::_internal::analysis::facts::FuncOptionFact::Language(
                    f.language_name()
                        .map(|language| language.name.to_string())
                        .unwrap_or_default(),
                )
            }
            ast::FuncOption::VolatilityFuncOption(f) => {
                let vol = match f {
                    ast::VolatilityFuncOption::Immutable(_) => {
                        crate::_internal::analysis::facts::VolatilityKind::Immutable
                    }
                    ast::VolatilityFuncOption::Stable(_) => {
                        crate::_internal::analysis::facts::VolatilityKind::Stable
                    }
                    ast::VolatilityFuncOption::Volatile(_) => {
                        crate::_internal::analysis::facts::VolatilityKind::Volatile
                    }
                };
                crate::_internal::analysis::facts::FuncOptionFact::Volatility(vol)
            }
            ast::FuncOption::SecurityInvokerFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Security(
                    crate::_internal::analysis::facts::SecurityKind::Invoker,
                )
            }
            ast::FuncOption::SecurityDefinerFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Security(
                    crate::_internal::analysis::facts::SecurityKind::Definer,
                )
            }
            ast::FuncOption::StrictFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Strict(
                    crate::_internal::analysis::facts::StrictKind::Strict,
                )
            }
            ast::FuncOption::CalledOnNullInputFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Strict(
                    crate::_internal::analysis::facts::StrictKind::CalledOnNull,
                )
            }
            ast::FuncOption::ReturnsNullOnNullInputFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Strict(
                    crate::_internal::analysis::facts::StrictKind::ReturnsNullOnNull,
                )
            }
            ast::FuncOption::LeakproofFuncOption(f) => {
                let is_leakproof = f.leakproof_token().is_some();
                crate::_internal::analysis::facts::FuncOptionFact::Leakproof(is_leakproof)
            }
            ast::FuncOption::NotLeakproofFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Leakproof(false)
            }
            ast::FuncOption::ParallelFuncOption(f) => {
                crate::_internal::analysis::facts::FuncOptionFact::Parallel(
                    f.ident_token()
                        .map(|token| Self::resolve_identifier_token(token.text()))
                        .unwrap_or_default(),
                )
            }
            ast::FuncOption::CostFuncOption(f) => {
                let value = f
                    .literal()
                    .map(|l| l.syntax().text().to_string())
                    .or_else(|| {
                        f.syntax()
                            .children()
                            .find_map(ast::PrefixExpr::cast)
                            .map(|pe| pe.syntax().text().to_string())
                    })
                    .and_then(|raw| raw.replace([' ', '\t', '\n'], "").parse::<f64>().ok());
                crate::_internal::analysis::facts::FuncOptionFact::Cost(value)
            }
            ast::FuncOption::RowsFuncOption(f) => {
                let value = f
                    .literal()
                    .map(|l| l.syntax().text().to_string())
                    .or_else(|| {
                        f.syntax()
                            .children()
                            .find_map(ast::PrefixExpr::cast)
                            .map(|pe| pe.syntax().text().to_string())
                    })
                    .and_then(|raw| raw.replace([' ', '\t', '\n'], "").parse::<f64>().ok());
                crate::_internal::analysis::facts::FuncOptionFact::Rows(value)
            }
            ast::FuncOption::SetFuncOption(f) => {
                let name = f
                    .set_config_param()
                    .and_then(|scp| scp.config_parameter_ref())
                    .and_then(|cpr| cpr.path_ref())
                    .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                    .map(|qn| match qn.schema {
                        Some(schema) => format!("{}.{}", schema.resolve(), qn.name.resolve()),
                        None => qn.name.resolve(),
                    })
                    .unwrap_or_default();
                let mut value = None;
                let mut from_current_or_default = false;
                if let Some(scp) = f.set_config_param() {
                    match scp.config_assignment() {
                        Some(ast::ConfigAssignment::FromCurrent(_)) => {
                            from_current_or_default = true;
                        }
                        Some(ast::ConfigAssignment::ToConfigValue(assignment))
                            if assignment.default_token().is_some() =>
                        {
                            from_current_or_default = true;
                        }
                        Some(ast::ConfigAssignment::ToConfigValue(assignment)) => {
                            let vals: Vec<String> = assignment
                                .config_values()
                                .filter_map(|v| match v {
                                    ast::ConfigValue::ConfigValueName(n) => {
                                        n.ident_token().map(|t| t.text().to_string())
                                    }
                                    ast::ConfigValue::Literal(lit) => {
                                        Self::resolve_string_literal(&lit)
                                            .or_else(|| Some(lit.syntax().text().to_string()))
                                    }
                                    ast::ConfigValue::PrefixExpr(pe) => {
                                        Some(pe.syntax().text().to_string())
                                    }
                                })
                                .collect();
                            if !vals.is_empty() {
                                value = Some(vals.join(", "));
                            }
                        }
                        None => {}
                    }
                }
                crate::_internal::analysis::facts::FuncOptionFact::Set {
                    name,
                    value,
                    from_current_or_default,
                }
            }
            ast::FuncOption::ResetFuncOption(f) => {
                let target = if f.all_token().is_some() {
                    "all".to_string()
                } else {
                    f.config_parameter_ref()
                        .and_then(|cpr| cpr.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| match qn.schema {
                            Some(schema) => format!("{}.{}", schema.resolve(), qn.name.resolve()),
                            None => qn.name.resolve(),
                        })
                        .unwrap_or_default()
                };
                crate::_internal::analysis::facts::FuncOptionFact::Reset(target)
            }
            ast::FuncOption::AsFuncOption(f) => {
                let (definition, obj_file, link_symbol) = match f.as_func_target() {
                    Some(ast::AsFuncTarget::AsDefinition(definition)) => (
                        definition
                            .literal()
                            .and_then(|literal| Self::resolve_string_literal(&literal)),
                        None,
                        None,
                    ),
                    Some(ast::AsFuncTarget::AsObjFile(obj_file)) => (
                        None,
                        obj_file
                            .obj_file()
                            .and_then(|literal| Self::resolve_string_literal(&literal)),
                        obj_file
                            .link_symbol()
                            .and_then(|literal| Self::resolve_string_literal(&literal)),
                    ),
                    None => (None, None, None),
                };
                crate::_internal::analysis::facts::FuncOptionFact::As {
                    definition,
                    obj_file,
                    link_symbol,
                }
            }
            ast::FuncOption::TransformFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Transform
            }
            ast::FuncOption::WindowFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Window
            }
            ast::FuncOption::SupportFuncOption(f) => {
                let support_fn = f
                    .function_name_ref()
                    .and_then(|fnr| fnr.path_ref())
                    .and_then(|pr| Self::path_ref_to_qualified_name(&pr));
                crate::_internal::analysis::facts::FuncOptionFact::Support(support_fn)
            }
        }
    }

    pub(super) fn is_sql_special_value_ident(name: &str) -> bool {
        matches!(
            name,
            "current_user"
                | "session_user"
                | "current_role"
                | "user"
                | "current_catalog"
                | "current_schema"
                | "current_date"
                | "current_time"
                | "current_timestamp"
                | "localtime"
                | "localtimestamp"
                | "null"
                | "true"
                | "false"
        ) || (name.starts_with('$') && name[1..].chars().all(|c| c.is_ascii_digit()))
    }

    pub(super) fn name_ref_in_non_column_position(
        name_ref: &ast::NameRef,
        root: &squawk_syntax::SyntaxNode,
    ) -> bool {
        for ancestor in name_ref.syntax().ancestors() {
            if &ancestor == root {
                break;
            }
            if ast::FromClause::can_cast(ancestor.kind())
                || ast::Type::can_cast(ancestor.kind())
                || ast::FuncType::can_cast(ancestor.kind())
                || ast::TableArgList::can_cast(ancestor.kind())
                || ast::WithTable::can_cast(ancestor.kind())
                || ast::SetClause::can_cast(ancestor.kind())
            {
                return true;
            }
        }
        false
    }

    fn infer_return_expr_fact(
        expr: ast::Expr,
        param_types: &std::collections::HashMap<String, String>,
        scope: &AggregateScopeFact,
        single_binding: Option<&QualifiedName>,
    ) -> Option<crate::_internal::analysis::facts::RoutineReturnExprFact> {
        use crate::_internal::analysis::facts::RoutineReturnExprFact;
        let mut current = expr;
        while let ast::Expr::ParenExpr(pe) = current {
            current = pe.expr()?;
        }
        match current {
            ast::Expr::CastExpr(ce) => ce
                .ty()
                .map(|t| RoutineReturnExprFact::ExplicitCast(t.syntax().text().to_string())),
            ast::Expr::Literal(lit) => {
                let raw = lit.syntax().text().to_string();
                let trimmed = raw.trim();
                if trimmed.eq_ignore_ascii_case("null") {
                    None
                } else if trimmed.eq_ignore_ascii_case("true")
                    || trimmed.eq_ignore_ascii_case("false")
                {
                    Some(RoutineReturnExprFact::LiteralType("boolean".to_string()))
                } else if trimmed.starts_with('$')
                    && trimmed[1..].chars().all(|c| c.is_ascii_digit())
                {
                    param_types
                        .get(trimmed)
                        .map(|pty| RoutineReturnExprFact::ParameterType(pty.clone()))
                } else if trimmed.starts_with('\'')
                    || trimmed.starts_with("E\'")
                    || trimmed.starts_with("e\'")
                    || (trimmed.starts_with('$') && trimmed.ends_with('$') && trimmed.len() >= 2)
                {
                    Some(RoutineReturnExprFact::LiteralType("text".to_string()))
                } else if trimmed.chars().all(|c| c.is_ascii_digit() || c == '_') {
                    Some(RoutineReturnExprFact::LiteralType("integer".to_string()))
                } else if trimmed
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-' | '_'))
                {
                    Some(RoutineReturnExprFact::LiteralType("numeric".to_string()))
                } else {
                    None
                }
            }
            ast::Expr::NameRef(nr) => {
                let ident = Self::resolve_name_ref(&nr);
                if ident == "null" {
                    None
                } else if ident == "true" || ident == "false" {
                    Some(RoutineReturnExprFact::LiteralType("boolean".to_string()))
                } else if !ident.starts_with('$')
                    && let Some(rel) = single_binding
                {
                    Some(RoutineReturnExprFact::Column {
                        relation: Some(rel.clone()),
                        column: ident,
                    })
                } else {
                    param_types
                        .get(&ident)
                        .map(|pty| RoutineReturnExprFact::ParameterType(pty.clone()))
                }
            }
            ast::Expr::FieldExpr(fe) => {
                if fe.star_token().is_some() {
                    return None;
                }
                let field_name = fe
                    .field()
                    .and_then(|f| f.syntax().first_token())
                    .map(|t| Self::resolve_identifier_token(t.text()))?;
                let ast::Expr::NameRef(base_name) = fe.base()? else {
                    return None;
                };
                let qualifier = base_name
                    .syntax()
                    .first_token()
                    .map(|t| Self::resolve_identifier_token(t.text()))?;
                let binding = scope.bindings.iter().find(|b| b.alias == qualifier)?;
                Some(RoutineReturnExprFact::Column {
                    relation: binding.relation.clone(),
                    column: field_name,
                })
            }
            ast::Expr::CallExpr(ce) => {
                let callee = ce.expr()?;
                let qname = match callee {
                    ast::Expr::NameRef(nr) => {
                        QualifiedName::new(None, Ident::new(Self::resolve_name_ref(&nr), true))
                    }
                    ast::Expr::FieldExpr(fe) => {
                        let fn_name = fe
                            .field()
                            .and_then(|f| f.syntax().first_token())
                            .map(|t| Self::resolve_identifier_token(t.text()))?;
                        let ast::Expr::NameRef(base) = fe.base()? else {
                            return None;
                        };
                        let schema = Self::resolve_name_ref(&base);
                        QualifiedName::new(
                            Some(Ident::new(schema, true)),
                            Ident::new(fn_name, true),
                        )
                    }
                    _ => return None,
                };
                Some(RoutineReturnExprFact::RoutineCall(qname))
            }
            _ => None,
        }
    }

    pub(super) fn extract_routine_body_dependencies(
        body: Option<squawk_syntax::ast::RoutineBody>,
        params: &[crate::_internal::analysis::facts::ParamFact],
    ) -> crate::_internal::analysis::facts::RoutineBodyDependenciesFact {
        let Some(body) = body else {
            return crate::_internal::analysis::facts::RoutineBodyDependenciesFact::default();
        };
        Self::extract_routine_body_dependencies_from_syntax(body.syntax(), params, false)
    }

    pub(super) fn extract_routine_body_dependencies_from_syntax(
        syntax: &squawk_syntax::SyntaxNode,
        params: &[crate::_internal::analysis::facts::ParamFact],
        has_syntax_error: bool,
    ) -> crate::_internal::analysis::facts::RoutineBodyDependenciesFact {
        let mut param_names = std::collections::HashSet::new();
        let mut param_types = std::collections::HashMap::new();
        for (idx, p) in params.iter().enumerate() {
            let pos_key = format!("${}", idx + 1);
            param_names.insert(pos_key.clone());
            param_types.insert(pos_key, p.ty.clone());
            if let Some(ref name) = p.name {
                param_names.insert(name.clone());
                param_types.insert(name.clone(), p.ty.clone());
            }
        }
        let mut cte_names = std::collections::HashSet::new();
        for cte_name in syntax.descendants().filter_map(CteName::cast) {
            if let Some(token) = cte_name.ident_token() {
                cte_names.insert(Self::resolve_identifier_token(token.text()));
            }
        }
        let mut relations: Vec<crate::_internal::analysis::facts::RoutineRelationReferenceFact> =
            Vec::new();
        for qname in Self::extract_view_dependencies(syntax) {
            if qname.schema.is_none() && cte_names.contains(&qname.name.resolve()) {
                continue;
            }
            let rel_fact = crate::_internal::analysis::facts::RoutineRelationReferenceFact {
                relation: qname,
                column: None,
            };
            if !relations.contains(&rel_fact) {
                relations.push(rel_fact);
            }
        }
        let mut unqualified_columns = Vec::new();
        let mut return_expr = None;

        for ret_stmt in syntax.descendants().filter_map(ast::ReturnStmt::cast) {
            if let Some(expr) = ret_stmt.expr() {
                let empty_scope = AggregateScopeFact {
                    bindings: Vec::new(),
                    unknown: false,
                };
                return_expr =
                    Self::infer_return_expr_fact(expr.clone(), &param_types, &empty_scope, None);
                let mut field_children = std::collections::HashSet::new();
                let mut callees = std::collections::HashSet::new();
                for node in expr.syntax().descendants() {
                    if let Some(call) = ast::CallExpr::cast(node.clone())
                        && let Some(callee) = call.expr()
                    {
                        callees.insert(callee.syntax().clone());
                    }
                    if let Some(field) = ast::FieldExpr::cast(node) {
                        if let Some(b) = field.base() {
                            field_children.insert(b.syntax().clone());
                        }
                        if let Some(f) = field.field() {
                            field_children.insert(f.syntax().clone());
                        }
                    }
                }
                for name_ref in expr.syntax().descendants().filter_map(ast::NameRef::cast) {
                    if field_children.contains(name_ref.syntax())
                        || callees.contains(name_ref.syntax())
                        || Self::name_ref_in_non_column_position(&name_ref, expr.syntax())
                    {
                        continue;
                    }
                    let col_name = Self::resolve_name_ref(&name_ref);
                    if param_names.contains(&col_name)
                        || cte_names.contains(&col_name)
                        || Self::is_sql_special_value_ident(&col_name)
                    {
                        continue;
                    }
                    if !unqualified_columns.contains(&col_name) {
                        unqualified_columns.push(col_name);
                    }
                }
            }
        }

        let has_intermediate_select =
            |node: &squawk_syntax::SyntaxNode, limit: &squawk_syntax::SyntaxNode| -> bool {
                node.ancestors()
                    .skip(1)
                    .take_while(|a| a != limit)
                    .any(|a| ast::Select::can_cast(a.kind()))
            };
        let is_top_level_select = |select: &ast::Select| -> bool {
            !select
                .syntax()
                .ancestors()
                .skip(1)
                .take_while(|a| a != syntax)
                .any(|a| {
                    ast::Select::can_cast(a.kind())
                        || ast::ReturnStmt::can_cast(a.kind())
                        || ast::WithTable::can_cast(a.kind())
                        || ast::Insert::can_cast(a.kind())
                        || ast::Update::can_cast(a.kind())
                        || ast::Delete::can_cast(a.kind())
                })
        };
        let any_enclosing_select_has_from = |select: &ast::Select| -> bool {
            select
                .syntax()
                .ancestors()
                .skip(1)
                .take_while(|a| a != syntax)
                .filter_map(ast::Select::cast)
                .any(|parent_sel| parent_sel.from_clause().is_some())
        };
        for select in syntax.descendants().filter_map(ast::Select::cast) {
            let mut scope = AggregateScopeFact {
                bindings: Vec::new(),
                unknown: false,
            };
            if let Some(from) = select.from_clause() {
                for item in from.items() {
                    Self::collect_scope_item(&item, &mut scope);
                }
            }
            let single_binding = if !scope.unknown && scope.bindings.len() == 1 {
                scope.bindings[0].relation.clone()
            } else {
                None
            };
            let mut target_aliases = std::collections::HashSet::new();
            if let Some(sc) = select.select_clause()
                && let Some(tl) = sc.target_list()
            {
                let targets: Vec<_> = tl.targets().collect();
                for t in &targets {
                    if let Some(as_name) = t.as_name()
                        && let Some(tok) = as_name.syntax().first_token()
                    {
                        target_aliases.insert(Self::resolve_identifier_token(tok.text()));
                    }
                }
                if is_top_level_select(&select) {
                    if targets.len() > 1 {
                        return_expr = Some(
                            crate::_internal::analysis::facts::RoutineReturnExprFact::MultiColumn,
                        );
                    } else if targets.len() == 1
                        && let Some(expr) = targets[0].expr()
                    {
                        return_expr = Self::infer_return_expr_fact(
                            expr,
                            &param_types,
                            &scope,
                            single_binding.as_ref(),
                        );
                    }
                }
            }
            let binding_aliases: std::collections::HashSet<String> =
                scope.bindings.iter().map(|b| b.alias.clone()).collect();
            for field in select
                .syntax()
                .descendants()
                .filter_map(ast::FieldExpr::cast)
            {
                if field.star_token().is_some()
                    || has_intermediate_select(field.syntax(), select.syntax())
                {
                    continue;
                }
                let Some(field_name) = field
                    .field()
                    .and_then(|f| f.syntax().first_token())
                    .map(|t| Self::resolve_identifier_token(t.text()))
                else {
                    continue;
                };
                let Some(ast::Expr::NameRef(base_name)) = field.base() else {
                    continue;
                };
                let Some(qualifier) = base_name
                    .syntax()
                    .first_token()
                    .map(|t| Self::resolve_identifier_token(t.text()))
                else {
                    continue;
                };
                if let Some(binding) = scope.bindings.iter().find(|b| b.alias == qualifier)
                    && let Some(ref rel_qname) = binding.relation
                {
                    if rel_qname.schema.is_none() && cte_names.contains(&rel_qname.name.resolve()) {
                        continue;
                    }
                    let rel_fact =
                        crate::_internal::analysis::facts::RoutineRelationReferenceFact {
                            relation: rel_qname.clone(),
                            column: Some(field_name),
                        };
                    if !relations.contains(&rel_fact) {
                        relations.push(rel_fact);
                    }
                }
            }
            let mut field_children = std::collections::HashSet::new();
            let mut callees = std::collections::HashSet::new();
            for node in select.syntax().descendants() {
                if let Some(call) = ast::CallExpr::cast(node.clone())
                    && let Some(callee) = call.expr()
                {
                    callees.insert(callee.syntax().clone());
                }
                if let Some(field) = ast::FieldExpr::cast(node) {
                    if let Some(b) = field.base() {
                        field_children.insert(b.syntax().clone());
                    }
                    if let Some(f) = field.field() {
                        field_children.insert(f.syntax().clone());
                    }
                }
            }
            if let Some(rel_qname) = single_binding {
                if !(rel_qname.schema.is_none() && cte_names.contains(&rel_qname.name.resolve())) {
                    for name_ref in select.syntax().descendants().filter_map(ast::NameRef::cast) {
                        if has_intermediate_select(name_ref.syntax(), select.syntax())
                            || field_children.contains(name_ref.syntax())
                            || callees.contains(name_ref.syntax())
                            || Self::name_ref_in_non_column_position(&name_ref, select.syntax())
                        {
                            continue;
                        }
                        let col_name = Self::resolve_name_ref(&name_ref);
                        if col_name.starts_with('$')
                            || cte_names.contains(&col_name)
                            || target_aliases.contains(&col_name)
                            || binding_aliases.contains(&col_name)
                            || Self::is_sql_special_value_ident(&col_name)
                        {
                            continue;
                        }
                        let rel_fact =
                            crate::_internal::analysis::facts::RoutineRelationReferenceFact {
                                relation: rel_qname.clone(),
                                column: Some(col_name),
                            };
                        if !relations.contains(&rel_fact) {
                            relations.push(rel_fact);
                        }
                    }
                }
            } else if !scope.unknown
                && scope.bindings.is_empty()
                && !any_enclosing_select_has_from(&select)
            {
                for name_ref in select.syntax().descendants().filter_map(ast::NameRef::cast) {
                    if has_intermediate_select(name_ref.syntax(), select.syntax())
                        || field_children.contains(name_ref.syntax())
                        || callees.contains(name_ref.syntax())
                        || Self::name_ref_in_non_column_position(&name_ref, select.syntax())
                    {
                        continue;
                    }
                    let col_name = Self::resolve_name_ref(&name_ref);
                    if param_names.contains(&col_name)
                        || cte_names.contains(&col_name)
                        || target_aliases.contains(&col_name)
                        || Self::is_sql_special_value_ident(&col_name)
                    {
                        continue;
                    }
                    if !unqualified_columns.contains(&col_name) {
                        unqualified_columns.push(col_name);
                    }
                }
            }
        }
        crate::_internal::analysis::facts::RoutineBodyDependenciesFact {
            relations,
            routines: Self::extract_view_routines(syntax),
            types: Self::extract_view_cast_types(syntax),
            unqualified_columns,
            return_expr,
            has_syntax_error,
        }
    }

    fn extract_sql_string_validation_dependencies(
        options: &[crate::_internal::analysis::facts::FuncOptionFact],
        params: &[crate::_internal::analysis::facts::ParamFact],
    ) -> crate::_internal::analysis::facts::RoutineBodyDependenciesFact {
        let language = options
            .iter()
            .find_map(|opt| match opt {
                crate::_internal::analysis::facts::FuncOptionFact::Language(l) => Some(l.as_str()),
                _ => None,
            })
            .unwrap_or("sql");
        if !language.eq_ignore_ascii_case("sql") {
            return crate::_internal::analysis::facts::RoutineBodyDependenciesFact::default();
        }
        let Some(sql_def) = options.iter().find_map(|opt| match opt {
            crate::_internal::analysis::facts::FuncOptionFact::As {
                definition: Some(def),
                obj_file: None,
                ..
            } => Some(def.as_str()),
            _ => None,
        }) else {
            return crate::_internal::analysis::facts::RoutineBodyDependenciesFact::default();
        };
        let trimmed = sql_def.trim();
        if trimmed.is_empty() {
            return crate::_internal::analysis::facts::RoutineBodyDependenciesFact::default();
        }
        let parsed = squawk_syntax::SourceFile::parse(trimmed);
        let has_syntax_error = !parsed.errors().is_empty();
        Self::extract_routine_body_dependencies_from_syntax(
            parsed.tree().syntax(),
            params,
            has_syntax_error,
        )
    }

    pub(super) fn extract_create_function(
        node: &squawk_syntax::ast::CreateFunction,
    ) -> Option<StatementFact> {
        let path = node.name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;
        let or_replace = node.or_replace().is_some();
        let params: Vec<_> = node
            .param_list()
            .map(|pl| pl.params().map(|p| Self::extract_param(&p)).collect())
            .unwrap_or_default();
        let return_type = node.ret_type().map(|r| Self::extract_ret_type(&r));
        let options: Vec<_> = node
            .option_list()
            .map(|ol| {
                ol.options()
                    .map(|o| Self::extract_func_option(&o))
                    .collect()
            })
            .unwrap_or_default();

        let body_dependencies = Self::extract_routine_body_dependencies(node.body(), &params);
        let validation_dependencies = if node.body().is_some() {
            body_dependencies.clone()
        } else {
            Self::extract_sql_string_validation_dependencies(&options, &params)
        };
        Some(StatementFact::CreateFunction(
            crate::_internal::analysis::facts::CreateFunctionFact {
                name,
                or_replace,
                params,
                return_type,
                options,
                body_dependencies,
                validation_dependencies,
            },
        ))
    }

    pub(super) fn extract_alter_function(node: &ast::AlterFunction) -> Option<StatementFact> {
        let path = node.function_sig()?.function_name_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let params =
            Self::extract_signature_params(node.function_sig().and_then(|sig| sig.param_list()));

        let action = node.action().and_then(|a| match a {
            ast::AlterFunctionAction::FunctionRenameTo(rt) => {
                let new_name = Self::resolve_name(rt.function_name()?.path()?.segment()?);
                Some(
                    crate::_internal::analysis::facts::AlterFunctionAction::Rename {
                        from: name.name.resolve(),
                        to: new_name,
                    },
                )
            }
            ast::AlterFunctionAction::OwnerTo(ot) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::OwnerChange(
                    Self::extract_role(&ot.role_ref()?),
                ),
            ),
            ast::AlterFunctionAction::SetSchema(ss) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::SchemaChange {
                    new_schema: Self::resolve_ast_identifier(&ss.schema_ref()?),
                },
            ),
            ast::AlterFunctionAction::DependsOnExtension(de) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::DependsOnExtension {
                    extension: Self::resolve_ast_identifier(&de.extension_ref()?),
                },
            ),
            ast::AlterFunctionAction::NoDependsOnExtension(nde) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::NoDependsOnExtension {
                    extension: Self::resolve_ast_identifier(&nde.extension_ref()?),
                },
            ),
            ast::AlterFunctionAction::FuncOptionList(ol) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::OptionsChange(
                    ol.options()
                        .map(|o| Self::extract_func_option(&o))
                        .collect(),
                ),
            ),
        });

        Some(StatementFact::AlterFunction(
            crate::_internal::analysis::facts::AlterFunctionFact {
                name,
                params,
                action: action?,
            },
        ))
    }

    pub(super) fn extract_drop_function(
        node: &squawk_syntax::ast::DropFunction,
    ) -> Option<StatementFact> {
        let sigs = node
            .function_sig_list()
            .map(|sl| {
                sl.function_sigs()
                    .filter_map(|sig| {
                        let path = sig.function_name_ref()?.path_ref()?;
                        Some(crate::_internal::analysis::facts::FunctionSigFact {
                            name: Self::path_ref_to_qualified_name(&path).unwrap_or_else(|| {
                                QualifiedName::new(None, Ident::new("unknown".to_string(), false))
                            }),
                            params: Self::extract_signature_params(sig.param_list()),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Some(StatementFact::DropFunction(
            crate::_internal::analysis::facts::DropFunctionFact {
                signatures: sigs,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    pub(super) fn extract_create_procedure(
        node: &squawk_syntax::ast::CreateProcedure,
    ) -> Option<StatementFact> {
        let path = node.name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;
        let or_replace = node.or_replace().is_some();
        let params: Vec<_> = node
            .param_list()
            .map(|pl| pl.params().map(|p| Self::extract_param(&p)).collect())
            .unwrap_or_default();
        let options: Vec<_> = node
            .option_list()
            .map(|ol| {
                ol.options()
                    .map(|o| Self::extract_func_option(&o))
                    .collect()
            })
            .unwrap_or_default();

        let body_dependencies = Self::extract_routine_body_dependencies(node.body(), &params);
        let validation_dependencies = if node.body().is_some() {
            body_dependencies.clone()
        } else {
            Self::extract_sql_string_validation_dependencies(&options, &params)
        };
        Some(StatementFact::CreateProcedure(
            crate::_internal::analysis::facts::CreateProcedureFact {
                name,
                or_replace,
                params,
                options,
                body_dependencies,
                validation_dependencies,
            },
        ))
    }

    pub(super) fn extract_alter_procedure(node: &ast::AlterProcedure) -> Option<StatementFact> {
        let path = node.procedure_sig()?.procedure_name_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let params =
            Self::extract_signature_params(node.procedure_sig().and_then(|sig| sig.param_list()));

        let action = node.action().and_then(|a| match a {
            ast::AlterProcedureAction::ProcedureRenameTo(rt) => {
                let new_name = Self::resolve_name(rt.procedure_name()?.path()?.segment()?);
                Some(
                    crate::_internal::analysis::facts::AlterFunctionAction::Rename {
                        from: name.name.resolve(),
                        to: new_name,
                    },
                )
            }
            ast::AlterProcedureAction::OwnerTo(ot) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::OwnerChange(
                    Self::extract_role(&ot.role_ref()?),
                ),
            ),
            ast::AlterProcedureAction::SetSchema(ss) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::SchemaChange {
                    new_schema: Self::resolve_ast_identifier(&ss.schema_ref()?),
                },
            ),
            ast::AlterProcedureAction::DependsOnExtension(de) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::DependsOnExtension {
                    extension: Self::resolve_ast_identifier(&de.extension_ref()?),
                },
            ),
            ast::AlterProcedureAction::NoDependsOnExtension(nde) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::NoDependsOnExtension {
                    extension: Self::resolve_ast_identifier(&nde.extension_ref()?),
                },
            ),
            // A procedure takes the same option list a function does, so
            // dropping it here turned `ALTER PROCEDURE ... SECURITY DEFINER`
            // into an unmodeled statement even though PostgreSQL applies it.
            ast::AlterProcedureAction::FuncOptionList(ol) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::OptionsChange(
                    ol.options()
                        .map(|option| Self::extract_func_option(&option))
                        .collect(),
                ),
            ),
        });

        Some(StatementFact::AlterProcedure(
            crate::_internal::analysis::facts::AlterProcedureFact {
                name,
                params,
                action: action?,
            },
        ))
    }

    pub(super) fn extract_drop_procedure(
        node: &squawk_syntax::ast::DropProcedure,
    ) -> Option<StatementFact> {
        let sigs = node
            .procedure_sig_list()
            .map(|sl| {
                sl.procedure_sigs()
                    .filter_map(|sig| {
                        let path = sig.procedure_name_ref()?.path_ref()?;
                        Some(crate::_internal::analysis::facts::FunctionSigFact {
                            name: Self::path_ref_to_qualified_name(&path).unwrap_or_else(|| {
                                QualifiedName::new(None, Ident::new("unknown".to_string(), false))
                            }),
                            params: Self::extract_signature_params(sig.param_list()),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Some(StatementFact::DropProcedure(
            crate::_internal::analysis::facts::DropProcedureFact {
                signatures: sigs,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    pub(super) fn extract_signature_params(params: Option<ast::ParamList>) -> Vec<String> {
        params
            .map(|params| {
                let direct = params.params().collect::<Vec<_>>();
                let ordered = params
                    .aggregate_order_by()
                    .into_iter()
                    .flat_map(|order_by| order_by.params())
                    .collect::<Vec<_>>();
                let ordered = if Self::folds_ordered_variadic(&direct, &ordered) {
                    Vec::new()
                } else {
                    ordered
                };
                direct
                    .into_iter()
                    .chain(ordered)
                    .filter_map(|param| {
                        if matches!(param.mode(), Some(ast::ParamMode::ParamOut(_))) {
                            return None;
                        }
                        Some(
                            param
                                .func_type()
                                .map(|ty| ty.syntax().text().to_string())
                                .unwrap_or_else(|| "unknown".to_string()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn folds_ordered_variadic(
        direct: &[squawk_syntax::ast::Param],
        ordered: &[squawk_syntax::ast::Param],
    ) -> bool {
        let Some(last_direct) = direct.last() else {
            return false;
        };
        if !matches!(last_direct.mode(), Some(ast::ParamMode::ParamVariadic(_)))
            || ordered.len() != 1
            || !matches!(ordered[0].mode(), Some(ast::ParamMode::ParamVariadic(_)))
        {
            return false;
        }
        last_direct
            .func_type()
            .map(|ty| ty.syntax().text().to_string())
            == ordered[0]
                .func_type()
                .map(|ty| ty.syntax().text().to_string())
    }

    /// Extract an aggregate's signature, kind, and direct-argument count.
    pub(super) fn extract_create_aggregate(node: &ast::CreateAggregate) -> Option<StatementFact> {
        let name = Self::path_to_qualified_name(&node.aggregate_name()?.path()?)?;
        let attributes = Self::extract_attribute_list(node.attribute_list());
        let hypothetical = attributes.iter().any(|attribute| {
            attribute.name.eq_ignore_ascii_case("hypothetical")
                && !matches!(
                    attribute
                        .value
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase()
                        .as_str(),
                    "false" | "f" | "0"
                )
        });
        let (params, kind, direct_count) = if let Some(params) = node.param_list() {
            let direct_params = params.params().collect::<Vec<_>>();
            let ordered_params = params
                .aggregate_order_by()
                .into_iter()
                .flat_map(|order_by| order_by.params())
                .collect::<Vec<_>>();
            let fold_ordered = Self::folds_ordered_variadic(&direct_params, &ordered_params);
            let direct = direct_params
                .iter()
                .map(Self::extract_param)
                .collect::<Vec<_>>();
            let ordered = ordered_params
                .iter()
                .map(Self::extract_param)
                .collect::<Vec<_>>();
            let kind = if ordered.is_empty() {
                crate::_internal::model::aggregate::AggregateKind::Normal
            } else if hypothetical {
                crate::_internal::model::aggregate::AggregateKind::Hypothetical
            } else {
                crate::_internal::model::aggregate::AggregateKind::OrderedSet
            };
            let direct_count = direct.len();
            let params = if fold_ordered {
                direct
            } else {
                direct.into_iter().chain(ordered).collect()
            };
            (params, kind, direct_count)
        } else {
            let params = attributes
                .iter()
                .find(|attribute| attribute.name.eq_ignore_ascii_case("basetype"))
                .filter(|attribute| {
                    !matches!(
                        attribute
                            .value
                            .as_deref()
                            .unwrap_or("")
                            .to_ascii_lowercase()
                            .as_str(),
                        "any" | "*"
                    )
                })
                .map(|attribute| {
                    vec![crate::_internal::analysis::facts::ParamFact {
                        mode: crate::_internal::analysis::facts::ParamModeFact::In,
                        name: None,
                        ty: attribute.value.clone().unwrap_or_default(),
                        default: None,
                    }]
                })
                .unwrap_or_default();
            let direct_count = params.len();
            (
                params,
                crate::_internal::model::aggregate::AggregateKind::Normal,
                direct_count,
            )
        };
        Some(StatementFact::CreateAggregate(
            crate::_internal::analysis::facts::CreateAggregateFact {
                name,
                or_replace: node.or_replace().is_some(),
                params,
                kind,
                direct_count,
                // The parser keeps the transition functions, state type, and
                // initial condition as attribute options. Recording them keeps
                // the definition honest about what it knows, so the state's
                // limits follow from the fact rather than from a blanket
                // statement that the whole definition was discarded.
                definition: attributes
                    .into_iter()
                    .map(
                        |attribute| crate::_internal::analysis::facts::AggregateOptionFact {
                            name: attribute.name,
                            value: attribute.value.unwrap_or_default(),
                        },
                    )
                    .collect(),
            },
        ))
    }

    pub(super) fn extract_alter_aggregate(node: &ast::AlterAggregate) -> Option<StatementFact> {
        let aggregate = node.aggregate()?;
        let name = Self::path_ref_to_qualified_name(&aggregate.path_ref()?)?;
        let params = Self::extract_signature_params(aggregate.param_list());
        let action = match node.action()? {
            ast::AlterAggregateAction::AggregateRenameTo(rename) => {
                let to = Self::path_to_qualified_name(&rename.aggregate_name()?.path()?)?
                    .name
                    .resolve();
                crate::_internal::analysis::facts::AlterFunctionAction::Rename {
                    from: name.name.resolve(),
                    to,
                }
            }
            ast::AlterAggregateAction::OwnerTo(owner) => {
                crate::_internal::analysis::facts::AlterFunctionAction::OwnerChange(
                    Self::extract_role(&owner.role_ref()?),
                )
            }
            ast::AlterAggregateAction::SetSchema(set_schema) => {
                crate::_internal::analysis::facts::AlterFunctionAction::SchemaChange {
                    new_schema: Self::resolve_ast_identifier(&set_schema.schema_ref()?),
                }
            }
        };
        Some(StatementFact::AlterAggregate(
            crate::_internal::analysis::facts::AlterAggregateFact {
                name,
                params,
                action,
            },
        ))
    }

    pub(super) fn extract_drop_aggregate(node: &ast::DropAggregate) -> Option<StatementFact> {
        let signatures = node
            .aggregates()
            .filter_map(|aggregate| {
                Some(crate::_internal::analysis::facts::FunctionSigFact {
                    name: Self::path_ref_to_qualified_name(&aggregate.path_ref()?)?,
                    params: Self::extract_signature_params(aggregate.param_list()),
                })
            })
            .collect();
        Some(StatementFact::DropAggregate(
            crate::_internal::analysis::facts::DropAggregateFact {
                signatures,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    pub(super) fn extract_alter_routine(node: &ast::AlterRoutine) -> Option<StatementFact> {
        let sig = node.routine_sig()?;
        let path = sig.routine_name_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let params = Self::extract_signature_params(sig.param_list());

        let action = node.action().and_then(|a| match a {
            ast::AlterRoutineAction::RoutineRenameTo(rt) => {
                let new_name = Self::resolve_name(rt.routine_name()?.path()?.segment()?);
                Some(
                    crate::_internal::analysis::facts::AlterFunctionAction::Rename {
                        from: name.name.resolve(),
                        to: new_name,
                    },
                )
            }
            ast::AlterRoutineAction::OwnerTo(ot) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::OwnerChange(
                    Self::extract_role(&ot.role_ref()?),
                ),
            ),
            ast::AlterRoutineAction::SetSchema(ss) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::SchemaChange {
                    new_schema: Self::resolve_ast_identifier(&ss.schema_ref()?),
                },
            ),
            ast::AlterRoutineAction::DependsOnExtension(de) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::DependsOnExtension {
                    extension: Self::resolve_ast_identifier(&de.extension_ref()?),
                },
            ),
            ast::AlterRoutineAction::NoDependsOnExtension(nde) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::NoDependsOnExtension {
                    extension: Self::resolve_ast_identifier(&nde.extension_ref()?),
                },
            ),
            ast::AlterRoutineAction::FuncOptionList(ol) => Some(
                crate::_internal::analysis::facts::AlterFunctionAction::OptionsChange(
                    ol.options()
                        .map(|o| Self::extract_func_option(&o))
                        .collect(),
                ),
            ),
        });

        Some(StatementFact::AlterRoutine(
            crate::_internal::analysis::facts::AlterRoutineFact {
                name,
                params,
                action: action?,
            },
        ))
    }

    pub(super) fn extract_drop_routine(node: &ast::DropRoutine) -> Option<StatementFact> {
        let signatures = node
            .routine_sig_list()
            .map(|sl| {
                sl.routine_sigs()
                    .filter_map(|sig| {
                        let path = sig.routine_name_ref()?.path_ref()?;
                        Some(crate::_internal::analysis::facts::FunctionSigFact {
                            name: Self::path_ref_to_qualified_name(&path)?,
                            params: Self::extract_signature_params(sig.param_list()),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Some(StatementFact::DropRoutine(
            crate::_internal::analysis::facts::DropRoutineFact {
                signatures,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    fn extract_cast_sig_types(sig: &ast::CastSig) -> Option<(String, String)> {
        let mut types = sig.syntax().children().filter_map(ast::Type::cast);
        let source = types.next()?.syntax().text().to_string();
        let target = types.next()?.syntax().text().to_string();
        Some((source, target))
    }

    pub(super) fn extract_create_cast(node: &ast::CreateCast) -> Option<StatementFact> {
        let (source_type, target_type) = Self::extract_cast_sig_types(&node.cast_sig()?)?;
        let method = match node.cast_method()? {
            ast::CastMethod::WithoutFunction(_) => {
                crate::_internal::analysis::facts::CastMethodFact::WithoutFunction
            }
            ast::CastMethod::WithInout(_) => {
                crate::_internal::analysis::facts::CastMethodFact::WithInout
            }
            ast::CastMethod::WithFunction(wf) => {
                let sig = wf.function_sig()?;
                let path = sig.function_name_ref()?.path_ref()?;
                let name = Self::path_ref_to_qualified_name(&path)?;
                let params = Self::extract_signature_params(sig.param_list());
                crate::_internal::analysis::facts::CastMethodFact::WithFunction(
                    crate::_internal::analysis::facts::FunctionSigFact { name, params },
                )
            }
        };
        let context = match node.cast_context() {
            Some(ast::CastContext::AsImplicit(_)) => {
                crate::_internal::analysis::facts::CastContextFact::Implicit
            }
            Some(ast::CastContext::AsAssignment(_)) => {
                crate::_internal::analysis::facts::CastContextFact::Assignment
            }
            None => crate::_internal::analysis::facts::CastContextFact::Explicit,
        };
        Some(StatementFact::CreateCast(
            crate::_internal::analysis::facts::CreateCastFact {
                source_type,
                target_type,
                method,
                context,
            },
        ))
    }

    pub(super) fn extract_drop_cast(node: &ast::DropCast) -> Option<StatementFact> {
        let (source_type, target_type) = Self::extract_cast_sig_types(&node.cast_sig()?)?;
        Some(StatementFact::DropCast(
            crate::_internal::analysis::facts::DropCastFact {
                source_type,
                target_type,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    pub(super) fn extract_create_statistics(node: &ast::CreateStatistics) -> Option<StatementFact> {
        let name = node
            .statistics()
            .and_then(|s| s.path())
            .and_then(|p| Self::path_to_qualified_name(&p));
        let if_not_exists = node.if_not_exists().is_some();
        let kinds = node
            .stat_types()
            .map(|st| {
                st.statistics_kinds()
                    .filter_map(|k| {
                        k.ident_token()
                            .map(|t| Self::resolve_identifier_token(t.text()))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let on_clause = node.statistics_on_clause()?;
        let mut columns = Vec::new();
        let mut expression_columns = Vec::new();
        let mut expr_texts = Vec::new();
        for expr in on_clause.exprs() {
            let mut unwrapped = expr.clone();
            while let ast::Expr::ParenExpr(pe) = &unwrapped {
                if let Some(inner) = pe.expr() {
                    unwrapped = inner;
                } else {
                    break;
                }
            }
            match &unwrapped {
                ast::Expr::NameRef(nr) => {
                    columns.push(Self::resolve_name_ref(nr));
                }
                _ => {
                    if let Some(refs) =
                        crate::_internal::analysis::expr_visitor::ExprVisitor::convert(
                            unwrapped.clone(),
                        )
                        .referenced_columns()
                    {
                        for col in refs {
                            if !expression_columns.contains(&col) {
                                expression_columns.push(col);
                            }
                        }
                    }
                    expr_texts.push(unwrapped.syntax().text().to_string().trim().to_string());
                }
            }
        }
        let expression_count = expr_texts.len();
        let expressions_sql = (!expr_texts.is_empty()).then(|| expr_texts.join(", "));
        let table_path = node.from_table()?.table_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&table_path)?;
        let expression_routines = Self::extract_view_routines(on_clause.syntax());
        let expression_types = Self::extract_view_cast_types(on_clause.syntax());
        Some(StatementFact::CreateStatistics(
            crate::_internal::analysis::facts::CreateStatisticsFact {
                name,
                if_not_exists,
                kinds,
                columns,
                expression_columns,
                expressions: expr_texts,
                expression_count,
                expressions_sql,
                expression_routines,
                expression_types,
                table,
            },
        ))
    }

    pub(super) fn extract_alter_statistics(node: &ast::AlterStatistics) -> Option<StatementFact> {
        let path = node.statistics_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let action = match node.action()? {
            ast::AlterStatisticsAction::StatisticsRenameTo(rt) => {
                let seg = rt.statistics()?.path()?.segment()?;
                crate::_internal::analysis::facts::AlterStatisticsActionFact::RenameTo(
                    Self::resolve_name(seg),
                )
            }
            ast::AlterStatisticsAction::OwnerTo(ot) => {
                crate::_internal::analysis::facts::AlterStatisticsActionFact::OwnerTo(
                    Self::extract_role(&ot.role_ref()?),
                )
            }
            ast::AlterStatisticsAction::SetSchema(ss) => {
                crate::_internal::analysis::facts::AlterStatisticsActionFact::SetSchema(
                    Self::resolve_ast_identifier(&ss.schema_ref()?),
                )
            }
            ast::AlterStatisticsAction::SetStatistics(ss) => {
                let target = if ss.default_token().is_some() {
                    crate::_internal::analysis::facts::StatisticsTarget::Default
                } else {
                    let raw = ss.expr()?.syntax().text().to_string();
                    let val = raw.trim().parse::<i32>().ok()?;
                    crate::_internal::analysis::facts::StatisticsTarget::Value(val)
                };
                crate::_internal::analysis::facts::AlterStatisticsActionFact::SetStatistics(target)
            }
        };
        let if_exists = node
            .syntax()
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
            .any(|t| {
                t.kind() == squawk_syntax::SyntaxKind::COMMENT && t.text().starts_with("/*IF_EX")
            });
        Some(StatementFact::AlterStatistics(
            crate::_internal::analysis::facts::AlterStatisticsFact {
                name,
                if_exists,
                action,
            },
        ))
    }

    pub(super) fn extract_drop_statistics(node: &ast::DropStatistics) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .statistics_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(StatementFact::DropStatistics(
            crate::_internal::analysis::facts::DropStatisticsFact {
                names,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    pub(super) fn extract_analyze(node: &ast::Analyze) -> Option<StatementFact> {
        let mut options = Vec::new();
        if node.verbose_token().is_some() {
            options.push(crate::_internal::analysis::facts::AttributeFact {
                name: "verbose".to_string(),
                value: None,
                namespace: None,
            });
        }
        if let Some(opt_list) = node.option_item_list() {
            for item in opt_list.option_items() {
                let Some(key) = item
                    .option_item_key()
                    .and_then(|k| k.syntax().first_token())
                    .map(|t| Self::resolve_identifier_token(t.text()))
                else {
                    continue;
                };
                let value = item.option_item_value().map(|v| {
                    if let Some(expr) = v.expr() {
                        if let ast::Expr::Literal(lit) = &expr
                            && let Some(s) = Self::resolve_string_literal(lit)
                        {
                            return s;
                        }
                        expr.syntax().text().to_string().trim().to_string()
                    } else if let Some(vn) = v.option_item_value_name() {
                        vn.syntax().text().to_string().trim().to_string()
                    } else {
                        v.syntax().text().to_string().trim().to_string()
                    }
                });
                options.push(crate::_internal::analysis::facts::AttributeFact {
                    name: key,
                    value,
                    namespace: None,
                });
            }
        }
        let mut targets = Vec::new();
        if let Some(list) = node.table_and_columns_list() {
            for tc in list.table_and_columnss() {
                let path = tc.table_relation_name()?.table_name_ref()?.path_ref()?;
                let relation = Self::path_ref_to_qualified_name(&path)?;
                let columns = tc
                    .column_ref_list()
                    .map(|cl| {
                        cl.column_name_refs()
                            .filter_map(|c| {
                                c.ident_token()
                                    .map(|t| Self::resolve_identifier_token(t.text()))
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                targets.push(crate::_internal::analysis::facts::AnalyzeTargetFact {
                    relation,
                    columns,
                });
            }
        }
        Some(StatementFact::Analyze(
            crate::_internal::analysis::facts::AnalyzeFact { options, targets },
        ))
    }
}
