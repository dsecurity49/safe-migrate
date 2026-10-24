use super::*;

impl AstVisitor {
    /// Output columns of a `SELECT`, or `None` when the projection is anything
    /// other than plain column references. A view's column types come from
    /// analysing the query, so an expression output cannot be typed offline.
    pub(super) fn extract_select_outputs(
        select: &ast::SelectClause,
    ) -> Option<Vec<crate::_internal::analysis::facts::SelectOutputFact>> {
        select
            .target_list()?
            .targets()
            .map(|target| {
                if target.star_token().is_some() {
                    return Some(crate::_internal::analysis::facts::SelectOutputFact::AllColumns);
                }
                let ast::Expr::NameRef(name) = target.expr()? else {
                    return None;
                };
                let source_name =
                    Self::resolve_identifier_token(name.syntax().first_token()?.text());
                let output_name = target
                    .as_name()
                    .and_then(|alias| alias.name())
                    .and_then(|name| name.syntax().first_token())
                    .map(|token| Self::resolve_identifier_token(token.text()))
                    .unwrap_or_else(|| source_name.clone());
                Some(
                    crate::_internal::analysis::facts::SelectOutputFact::Column {
                        source_name,
                        output_name,
                    },
                )
            })
            .collect::<Option<Vec<_>>>()
    }

    pub(super) fn extract_create_view(node: &CreateView) -> Option<StatementFact> {
        let path = node.view()?.path()?;
        let query = node.query();
        let (select_source, select_outputs) = Self::extract_single_source_projection(query.clone());
        let projection_was_complete = select_outputs.is_some();
        let select_outputs = select_outputs.unwrap_or_default();
        let mut options = node
            .with_params()
            .and_then(|params| params.attribute_list())
            .map(|attribute_list| Self::extract_attribute_list(Some(attribute_list)))
            .unwrap_or_default();
        // `WITH [LOCAL] CHECK OPTION` is a `check_option` reloption, and is
        // what makes the auto-updatable precondition apply.
        if let Some(check) = node.with_check_option() {
            let local = matches!(
                check.check_option_level(),
                Some(ast::CheckOptionLevel::LocalCheckOption(_))
            );
            options.push(crate::_internal::analysis::facts::AttributeFact {
                name: "check_option".to_string(),
                value: Some(if local { "local" } else { "cascaded" }.to_string()),
                namespace: None,
            });
        }
        let outcome = Self::view_updatability(query);
        Some(StatementFact::CreateView {
            name: Self::path_to_qualified_name(&path)?,
            or_replace: node.or_replace().is_some(),
            depends_on: Self::extract_view_dependencies(node.syntax()),
            column_list: node
                .column_list()
                .map(|list| {
                    list.column_names()
                        .filter_map(|name| {
                            Some(Self::resolve_identifier_token(name.ident_token()?.text()))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            options,
            updatability: outcome.with_aggregates,
            updatability_without_aggregates: outcome.without_aggregates,
            aggregate_candidates: outcome.aggregate_candidates,
            select_projection_complete: select_source.is_some() && projection_was_complete,
            select_outputs,
            select_source,
            select_source_name: outcome.select_source_name,
            routines: Self::extract_view_routines(node.syntax()),
            cast_types: Self::extract_view_cast_types(node.syntax()),
        })
    }

    /// Whether PostgreSQL would accept `WITH CHECK OPTION` on this view query,
    /// mirroring `view_query_is_auto_updatable(query, true)`. Only the
    /// unambiguous syntax is settled here; a query whose verdict depends on
    /// the search path is read twice, and an unplaceable target stays unknown.
    pub(super) fn view_updatability(query: Option<ast::SelectVariant>) -> ViewUpdatabilityOutcome {
        use crate::_internal::analysis::facts::ViewUpdatabilityFact as V;
        use crate::_internal::model::relation::ViewUpdatabilityReason as R;
        match query {
            Some(ast::SelectVariant::Select(select)) => Self::select_updatability(&select),
            Some(ast::SelectVariant::ParenSelect(paren)) => Self::view_updatability(paren.select()),
            Some(ast::SelectVariant::CompoundSelect(_)) => {
                ViewUpdatabilityOutcome::settled(V::NotUpdatable(R::SetOperation))
            }
            Some(ast::SelectVariant::Values(_)) => {
                ViewUpdatabilityOutcome::settled(V::NotUpdatable(R::SingleRelation))
            }
            // `TABLE t` and `SELECT ... INTO` are not a plain projection the
            // rest of the analysis expects, so do not claim a verdict.
            Some(ast::SelectVariant::Table(_)) | Some(ast::SelectVariant::SelectInto(_)) | None => {
                ViewUpdatabilityOutcome::settled(V::Unknown)
            }
        }
    }

    pub(super) fn select_updatability(select: &ast::Select) -> ViewUpdatabilityOutcome {
        use crate::_internal::analysis::facts::ViewUpdatabilityFact as V;
        use crate::_internal::model::relation::ViewUpdatabilityReason as R;
        if select
            .select_clause()
            .and_then(|clause| clause.select_quantifier())
            .is_some_and(|quantifier| {
                matches!(quantifier, ast::SelectQuantifier::DistinctClause(_))
            })
        {
            return ViewUpdatabilityOutcome::settled(V::NotUpdatable(R::Distinct));
        }
        if select.group_by_clause().is_some() {
            return ViewUpdatabilityOutcome::settled(V::NotUpdatable(R::GroupBy));
        }
        if select.having_clause().is_some() {
            return ViewUpdatabilityOutcome::settled(V::NotUpdatable(R::Having));
        }
        if select.with_clause().is_some() {
            return ViewUpdatabilityOutcome::settled(V::NotUpdatable(R::With));
        }
        if select.limit_clause().is_some()
            || select.offset_clause().is_some()
            || select.fetch_clause().is_some()
        {
            return ViewUpdatabilityOutcome::settled(V::NotUpdatable(R::Limit));
        }
        // An aggregate or window function in the target list makes each row a
        // summary; a set-returning function multiplies rows. An explicit
        // `pg_catalog` aggregate is settled here, an unqualified possible
        // aggregate is settled by the resolver, and a call that is neither
        // might be a set-returning function the analyzer cannot identify.
        let targets = select
            .select_clause()
            .and_then(|clause| clause.target_list())
            .map(|list| list.targets().collect::<Vec<_>>())
            .unwrap_or_default();
        let source = Self::single_source_relation(select);
        let source_name = source.as_ref().ok().cloned();
        let mut aggregate = false;
        let mut window = false;
        let mut unknown_call = false;
        let mut aggregate_candidates: Vec<AggregateCandidateFact> = Vec::new();
        for target in targets.iter() {
            for (call, nested) in Self::target_list_calls(target) {
                if nested && call.over_clause().is_some() {
                    continue;
                }
                if call.over_clause().is_some() {
                    window = true;
                } else if Self::is_pg_catalog_aggregate(&call) {
                    if !nested {
                        aggregate = true;
                    } else if let Some(candidate) =
                        Self::aggregate_candidate(&call, target, true, true)
                        && Self::candidate_may_be_outer(&candidate, source_name.as_deref())
                    {
                        aggregate_candidates.push(candidate);
                    }
                } else if let Some(candidate) =
                    Self::aggregate_candidate(&call, target, nested, false)
                {
                    if !nested || Self::candidate_may_be_outer(&candidate, source_name.as_deref()) {
                        aggregate_candidates.push(candidate);
                    }
                } else if call.expr().is_some() && !nested {
                    // An identifier call the analyzer cannot identify might be
                    // a set-returning function. A keyword form (`EXISTS`,
                    // `ANY`, `substring`, ...) has no callee and never is.
                    unknown_call = true;
                }
            }
        }
        let structural = match &source {
            Ok(whole_row) => {
                // With `check_cols`, PostgreSQL requires at least one updatable
                // column: a star, or a reference to a user column of the base
                // relation.
                if targets.iter().any(|target| {
                    target.star_token().is_some() || Self::is_column_reference(target, whole_row)
                }) {
                    V::Updatable
                } else {
                    V::NotUpdatable(R::NoUpdatableColumns)
                }
            }
            Err(reason) => V::NotUpdatable(*reason),
        };
        // The reading that ignores the unqualified calls still honours an
        // explicit aggregate, which no path can redirect.
        let without_aggregates = if aggregate {
            V::NotUpdatable(R::Aggregate)
        } else if window {
            V::NotUpdatable(R::Window)
        } else if unknown_call {
            V::Unknown
        } else {
            structural
        };
        // PostgreSQL checks aggregates before window functions and before the
        // from-shape, so any aggregate-named call decides the reading that
        // counts them.
        let with_aggregates = if aggregate || !aggregate_candidates.is_empty() {
            V::NotUpdatable(R::Aggregate)
        } else {
            without_aggregates
        };
        ViewUpdatabilityOutcome {
            with_aggregates,
            without_aggregates,
            aggregate_candidates,
            select_source_name: source_name,
        }
    }

    /// Whether a target is a user column of the single base relation. A
    /// whole-row or system-column reference is not, and neither is an
    /// expression.
    pub(super) fn is_column_reference(target: &ast::Target, whole_row: &str) -> bool {
        let Some(expr) = target.expr() else {
            return false;
        };
        let name = match expr.unparen() {
            ast::Expr::NameRef(name) => name.syntax().first_token(),
            // `t.a` and `t.*` address the base relation's columns; PostgreSQL
            // spells a qualified reference this way.
            ast::Expr::FieldExpr(field) => {
                if field.star_token().is_some() {
                    return true;
                }
                field.field().and_then(|field| field.syntax().first_token())
            }
            _ => return false,
        };
        match name {
            Some(token) => {
                let name = Self::resolve_identifier_token(token.text());
                !Self::is_system_column(&name) && name != whole_row
            }
            None => false,
        }
    }

    /// The name a bare reference to the single base relation denotes as a
    /// whole row: the table alias when given, otherwise the relation's own
    /// name. Also reports the from clauses PostgreSQL refuses.
    pub(super) fn single_source_relation(
        select: &ast::Select,
    ) -> Result<String, crate::_internal::model::relation::ViewUpdatabilityReason> {
        use crate::_internal::model::relation::ViewUpdatabilityReason as R;
        let Some(from) = select.from_clause() else {
            return Err(R::SingleRelation);
        };
        let mut items = from.items();
        let Some(item) = items.next() else {
            return Err(R::SingleRelation);
        };
        if items.next().is_some() {
            return Err(R::SingleRelation);
        }
        let ast::FromListItem::FromItem(ast::FromItem::RelationFromItem(relation)) = item else {
            return Err(R::SingleRelation);
        };
        if relation.tablesample_clause().is_some() {
            return Err(R::Tablesample);
        }
        if let Some(alias) = relation.alias().and_then(|alias| alias.name()) {
            return alias
                .ident_token()
                .map(|token| Self::resolve_identifier_token(token.text()))
                .ok_or(R::SingleRelation);
        }
        let qualified = relation
            .relation_name_ref()
            .and_then(|name| name.path_ref())
            .and_then(|path| Self::path_ref_to_qualified_name(&path))
            .ok_or(R::SingleRelation)?;
        Ok(qualified.name.resolve())
    }

    /// PostgreSQL's system columns, which a view cannot update.
    pub(super) fn is_system_column(name: &str) -> bool {
        matches!(
            name,
            "tableoid" | "ctid" | "xmin" | "cmin" | "xmax" | "cmax"
        )
    }

    /// Every call a target's expression makes, tagged with whether it sits
    /// inside a nested query. A local nested call belongs to that query; an
    /// aggregate-named call there is only promoted to the view when its
    /// argument consumes the view's source relation.
    pub(super) fn target_list_calls(target: &ast::Target) -> Vec<(ast::CallExpr, bool)> {
        let boundary = target.syntax();
        target
            .syntax()
            .descendants()
            .filter_map(ast::CallExpr::cast)
            .map(|call| {
                let nested = call
                    .syntax()
                    .ancestors()
                    .skip(1)
                    .take_while(|ancestor| ancestor != boundary)
                    .any(|ancestor| {
                        matches!(
                            ancestor.kind(),
                            SyntaxKind::SELECT
                                | SyntaxKind::PAREN_SELECT
                                | SyntaxKind::COMPOUND_SELECT
                                | SyntaxKind::SELECT_INTO
                                | SyntaxKind::VALUES
                                | SyntaxKind::TABLE
                        )
                    });
                (call, nested)
            })
            .collect()
    }

    /// Whether a call spells `pg_catalog.<aggregate>`, which no search path can
    /// redirect to another schema.
    pub(super) fn is_pg_catalog_aggregate(call: &ast::CallExpr) -> bool {
        let Some(qualified) = call.expr().and_then(Self::expr_to_qualified_name) else {
            return false;
        };
        qualified
            .schema
            .is_some_and(|schema| schema.resolve() == "pg_catalog")
            && Self::is_aggregate_name(&qualified.name.resolve())
    }

    /// Candidate facts for a call that spells a built-in aggregate: its name,
    /// argument types, and the references and query scopes needed to tell a
    /// correlated call from a local nested one.
    pub(super) fn aggregate_candidate(
        call: &ast::CallExpr,
        target: &ast::Target,
        nested: bool,
        explicit: bool,
    ) -> Option<AggregateCandidateFact> {
        let qualified = Self::expr_to_qualified_name(call.expr()?)?;
        if explicit {
            if qualified
                .schema
                .as_ref()
                .is_none_or(|schema| schema.resolve() != "pg_catalog")
            {
                return None;
            }
        } else if qualified.schema.is_some() {
            return None;
        }
        let name = qualified.name.resolve();
        if !Self::is_aggregate_name(&name) {
            return None;
        }
        // `count(*)` is a star form with no arguments; a named-notation
        // argument pins a type the visitor cannot see.
        let args = call.arg_list();
        let star = args
            .as_ref()
            .is_some_and(|args| args.star_token().is_some());
        let aggregate_only_clause = if args.as_ref().is_some_and(|args| {
            matches!(
                args.all_or_distinct(),
                Some(ast::AllOrDistinct::Distinct(_))
            )
        }) {
            Some(AggregateOnlyClauseFact::Distinct)
        } else if call.filter_clause().is_some() {
            Some(AggregateOnlyClauseFact::Filter)
        } else if args
            .as_ref()
            .is_some_and(|args| args.args().any(|arg| arg.order_by_clause().is_some()))
        {
            Some(AggregateOnlyClauseFact::OrderBy)
        } else if call.within_clause().is_some() {
            Some(AggregateOnlyClauseFact::WithinGroup)
        } else {
            None
        };
        let mut references = Vec::new();
        let mut contains_subquery = false;
        let arguments = match args {
            Some(args) if !star => args
                .args()
                .map(|arg| {
                    let argument = match arg.func_arg_expr() {
                        Some(ast::FuncArgExpr::Expr(expr)) => {
                            Self::collect_expression_references(
                                &expr,
                                &mut references,
                                &mut contains_subquery,
                            );
                            Self::aggregate_argument(expr)
                        }
                        _ => AggregateArgumentFact::Unknown,
                    };
                    if arg.variadic_token().is_some() {
                        AggregateArgumentFact::Variadic(Box::new(argument))
                    } else {
                        argument
                    }
                })
                .collect(),
            _ => Vec::new(),
        };
        let within_group = call
            .within_clause()
            .and_then(|clause| clause.order_by_clause())
            .and_then(|clause| clause.sort_by_list())
            .map(|list| {
                list.sort_bys()
                    .map(|sort| {
                        let Some(expr) = sort.expr() else {
                            return AggregateArgumentFact::Unknown;
                        };
                        Self::collect_expression_references(
                            &expr,
                            &mut references,
                            &mut contains_subquery,
                        );
                        Self::aggregate_argument(expr)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(AggregateCandidateFact {
            name,
            explicit,
            star,
            aggregate_only_clause,
            arguments,
            within_group,
            nested,
            references,
            scopes: if nested {
                Self::query_scopes(target, call)
            } else {
                Vec::new()
            },
            contains_subquery,
        })
    }

    /// One argument of a candidate call, typed as far as the visitor can see
    /// without the schema.
    pub(super) fn aggregate_argument(expr: ast::Expr) -> AggregateArgumentFact {
        use AggregateArgumentFact as A;
        match expr.unparen() {
            // A cast is the type it converts to.
            ast::Expr::CastExpr(cast) => cast
                .ty()
                .map(|ty| A::Typed(ty.syntax().text().to_string()))
                .unwrap_or(A::Unknown),
            ast::Expr::NameRef(name) => A::Column(Self::resolve_identifier_token(
                name.syntax().text().to_string(),
            )),
            // `t.amount` keeps both parts: the base may name the view's source
            // relation or a composite-typed column. `t.*` is not a value.
            ast::Expr::FieldExpr(field) if field.star_token().is_none() => {
                let Some(field_name) = field.field() else {
                    return A::Unknown;
                };
                let base = field
                    .base()
                    .map(Self::aggregate_argument)
                    .unwrap_or(A::Unknown);
                A::Field {
                    base: Box::new(base),
                    field: Self::resolve_identifier_token(field_name.syntax().text().to_string()),
                }
            }
            _ => A::Unknown,
        }
    }

    /// Whether a nested call could reach the view's source relation. A call
    /// whose every reference is bound by an inner range variable stays local;
    /// an unqualified reference or an unbound composite qualifier needs the
    /// resolver's column knowledge.
    fn candidate_may_be_outer(
        candidate: &AggregateCandidateFact,
        source_name: Option<&str>,
    ) -> bool {
        if candidate.contains_subquery {
            return true;
        }
        for reference in &candidate.references {
            if let Some(qualifier) = &reference.qualifier {
                if candidate.scopes.iter().any(|scope| {
                    scope
                        .bindings
                        .iter()
                        .any(|binding| &binding.alias == qualifier)
                }) {
                    continue;
                }
                if source_name == Some(qualifier.as_str()) {
                    return true;
                }
                // An unbound qualifier can name a composite column of the
                // source, so the resolver must decide.
                return true;
            }
            return true;
        }
        false
    }

    /// Every column reference in an expression, without descending into a
    /// nested query or mistaking a cast type or callee for a column.
    fn collect_expression_references(
        expr: &ast::Expr,
        references: &mut Vec<AggregateReferenceFact>,
        contains_subquery: &mut bool,
    ) {
        let root = expr.syntax().clone();
        let mut field_bases = Vec::new();
        let mut field_names = Vec::new();
        let mut callees = Vec::new();
        for node in root.descendants() {
            if Self::is_query_node(&node) {
                *contains_subquery = true;
                continue;
            }
            if let Some(call) = ast::CallExpr::cast(node.clone())
                && let Some(callee) = call.expr()
            {
                callees.push(callee.syntax().clone());
            }
            let Some(field) = ast::FieldExpr::cast(node.clone()) else {
                continue;
            };
            let Some(field_name) = field.field() else {
                continue;
            };
            field_names.push(field_name.syntax().clone());
            let name = Self::resolve_identifier_token(field_name.syntax().text().to_string());
            if let Some(ast::Expr::NameRef(base)) = field.base() {
                field_bases.push(base.syntax().clone());
                let qualifier = Self::resolve_identifier_token(base.syntax().text().to_string());
                references.push(AggregateReferenceFact {
                    qualifier: Some(qualifier),
                    name,
                });
            }
        }
        for node in root.descendants() {
            if Self::is_query_node(&node) {
                continue;
            }
            let Some(name_ref) = ast::NameRef::cast(node.clone()) else {
                continue;
            };
            if field_bases.contains(&node)
                || field_names.contains(&node)
                || callees
                    .iter()
                    .any(|callee| Self::node_within(&node, callee))
            {
                continue;
            }
            if node
                .ancestors()
                .take_while(|ancestor| *ancestor != root)
                .any(|ancestor| ast::Type::cast(ancestor).is_some())
            {
                continue;
            }
            references.push(AggregateReferenceFact {
                qualifier: None,
                name: Self::resolve_identifier_token(name_ref.syntax().text().to_string()),
            });
        }
    }

    fn node_within(node: &squawk_syntax::SyntaxNode, ancestor: &squawk_syntax::SyntaxNode) -> bool {
        node == ancestor || node.ancestors().any(|parent| &parent == ancestor)
    }

    fn is_query_node(node: &squawk_syntax::SyntaxNode) -> bool {
        matches!(
            node.kind(),
            SyntaxKind::SELECT
                | SyntaxKind::PAREN_SELECT
                | SyntaxKind::COMPOUND_SELECT
                | SyntaxKind::SELECT_INTO
                | SyntaxKind::VALUES
                | SyntaxKind::TABLE
        )
    }

    /// Query levels between a nested call and the view's target list, innermost
    /// first.
    fn query_scopes(target: &ast::Target, call: &ast::CallExpr) -> Vec<AggregateScopeFact> {
        let boundary = target.syntax();
        call.syntax()
            .ancestors()
            .skip(1)
            .take_while(|node| node != boundary)
            .filter_map(ast::Select::cast)
            .map(Self::scope_for_select)
            .collect()
    }

    fn scope_for_select(select: ast::Select) -> AggregateScopeFact {
        let mut scope = AggregateScopeFact {
            bindings: Vec::new(),
            unknown: false,
        };
        if let Some(from) = select.from_clause() {
            for item in from.items() {
                Self::collect_scope_item(&item, &mut scope);
            }
        }
        scope
    }

    fn collect_scope_item(item: &ast::FromListItem, scope: &mut AggregateScopeFact) {
        match item {
            ast::FromListItem::JoinExpr(join) => {
                if let Some(item) = join.from_list_item() {
                    Self::collect_scope_item(&item, scope);
                }
                if let Some(item) = join.join().and_then(|join| join.from_list_item()) {
                    Self::collect_scope_item(&item, scope);
                }
            }
            ast::FromListItem::FromItem(item) => match item {
                ast::FromItem::RelationFromItem(relation) => {
                    let alias = Self::from_alias_name(relation.alias().as_ref());
                    let relation_name = relation
                        .relation_name_ref()
                        .and_then(|name| name.path_ref())
                        .and_then(|path| Self::path_ref_to_qualified_name(&path));
                    match (alias, relation_name) {
                        (Some(alias), Some(relation)) => {
                            scope.bindings.push(AggregateBindingFact {
                                alias,
                                relation: Some(relation),
                            });
                        }
                        (Some(alias), None) => {
                            scope.bindings.push(AggregateBindingFact {
                                alias,
                                relation: None,
                            });
                            scope.unknown = true;
                        }
                        (None, Some(relation)) => {
                            scope.bindings.push(AggregateBindingFact {
                                alias: relation.name.resolve(),
                                relation: Some(relation),
                            });
                        }
                        (None, None) => scope.unknown = true,
                    }
                }
                ast::FromItem::ParenFromItem(paren) => {
                    if let Some(alias) = Self::from_alias_name(paren.alias().as_ref()) {
                        scope.bindings.push(AggregateBindingFact {
                            alias,
                            relation: None,
                        });
                    }
                    scope.unknown = true;
                }
                item => {
                    if let Some(alias) = Self::from_alias_name(item.alias().as_ref()) {
                        scope.bindings.push(AggregateBindingFact {
                            alias,
                            relation: None,
                        });
                    }
                    scope.unknown = true;
                }
            },
        }
    }

    fn from_alias_name(alias: Option<&ast::FromAlias>) -> Option<String> {
        alias
            .and_then(|alias| alias.name())
            .and_then(|name| name.ident_token())
            .map(|token| Self::resolve_identifier_token(token.text()))
    }

    pub(super) fn is_aggregate_name(name: &str) -> bool {
        BUILTIN_AGGREGATES.contains(&name)
    }

    /// The qualified name a cast target writes.
    pub(super) fn qualified_name_from_type(
        cast_type: &ast::Type,
    ) -> Option<crate::_internal::analysis::facts::CastTypeReferenceFact> {
        let mut ty = cast_type.clone();
        let mut array_dimensions = 0;
        while let ast::Type::ArrayType(array) = ty {
            array_dimensions += 1;
            ty = array.ty()?;
        }
        let mut name = Self::path_ref_to_qualified_name(&ty.path_ref()?)?;
        if array_dimensions > 0 {
            name.name = Ident::new(
                format!("{}{}", name.name.text, "[]".repeat(array_dimensions)),
                name.name.quoted,
            );
        }
        Some(crate::_internal::analysis::facts::CastTypeReferenceFact { name })
    }

    /// The routines a view calls, wherever they appear in the query.
    ///
    /// The whole query is scanned rather than the target list alone, because
    /// PostgreSQL records the dependency from anywhere in the definition —
    /// `WHERE`, `HAVING`, `JOIN ... ON` and the grouping clauses all hold one.
    /// The types a view body casts to, which a drop of that type must clear.
    pub(super) fn extract_view_cast_types(
        syntax: &squawk_syntax::SyntaxNode,
    ) -> Vec<crate::_internal::analysis::facts::CastTypeReferenceFact> {
        let mut references: Vec<crate::_internal::analysis::facts::CastTypeReferenceFact> =
            Vec::new();
        for cast in syntax.descendants().filter_map(ast::CastExpr::cast) {
            let Some(cast_type) = cast.ty() else { continue };
            let Some(reference) = Self::qualified_name_from_type(&cast_type) else {
                continue;
            };
            if !references.contains(&reference) {
                references.push(reference);
            }
        }
        references
    }

    /// The routine and cast references a view query makes.
    pub(super) fn extract_view_routines(
        syntax: &squawk_syntax::SyntaxNode,
    ) -> Vec<crate::_internal::analysis::facts::RoutineReferenceFact> {
        let mut references: Vec<crate::_internal::analysis::facts::RoutineReferenceFact> =
            Vec::new();
        for call in syntax.descendants().filter_map(ast::CallExpr::cast) {
            let Some(expr) = call.expr() else {
                continue;
            };
            let Some(qualified) = Self::expr_to_qualified_name(expr) else {
                continue;
            };
            // Argument types are stated only for plain column references,
            // which are the arguments whose type the source relation fixes.
            // A qualified column reference is not one of them.
            let argument_types = call.arg_list().and_then(|args| {
                args.args()
                    .map(|argument| match argument.expr() {
                        Some(ast::Expr::NameRef(column)) => Some(Self::resolve_identifier_token(
                            column.syntax().first_token()?.text(),
                        )),
                        _ => None,
                    })
                    .collect::<Option<Vec<String>>>()
            });
            let reference = crate::_internal::analysis::facts::RoutineReferenceFact {
                name: qualified,
                argument_types,
            };
            if !references.contains(&reference) {
                references.push(reference);
            }
        }
        references
    }

    /// The source relation and target list of a query that selects from a
    /// single plain relation.
    ///
    /// Only a plain `SELECT` exposes a target list. Compound, parenthesized
    /// and `VALUES` queries still create the relation, but its columns are
    /// then unknown, so the projection is left incomplete.
    pub(super) fn extract_single_source_projection(
        query: Option<ast::SelectVariant>,
    ) -> (
        Option<QualifiedName>,
        Option<Vec<crate::_internal::analysis::facts::SelectOutputFact>>,
    ) {
        match query {
            Some(ast::SelectVariant::Select(select)) => {
                let source = select.from_clause().and_then(|from| {
                    let mut items = from.items();
                    let item = items.next()?;
                    if items.next().is_some() {
                        return None;
                    }
                    let ast::FromListItem::FromItem(ast::FromItem::RelationFromItem(relation)) =
                        item
                    else {
                        return None;
                    };
                    if relation.tablesample_clause().is_some() {
                        return None;
                    }
                    relation
                        .relation_name_ref()?
                        .path_ref()
                        .and_then(|path| Self::path_ref_to_qualified_name(&path))
                });
                let outputs = select
                    .select_clause()
                    .and_then(|clause| Self::extract_select_outputs(&clause));
                (source, outputs)
            }
            _ => (None, None),
        }
    }

    pub(super) fn extract_alter_view(node: &ast::AlterView) -> Option<StatementFact> {
        let path = node.view_ref()?.path_ref()?;
        let action_node = node.action()?;
        Some(StatementFact::AlterView {
            name: Self::path_ref_to_qualified_name(&path)?,
            action: Self::extract_alter_view_action(action_node)?,
            if_exists: node.if_exists().is_some(),
        })
    }

    pub(super) fn extract_alter_view_action(
        action_node: ast::AlterViewAction,
    ) -> Option<crate::_internal::analysis::facts::AlterViewAction> {
        Some(match action_node {
            ast::AlterViewAction::ViewRenameTo(rt) => {
                let new_name_node = rt.view()?.path()?;
                crate::_internal::analysis::facts::AlterViewAction::RenameTo {
                    new_name: Self::path_to_qualified_name(&new_name_node)?.name,
                }
            }
            ast::AlterViewAction::OwnerTo(ot) => {
                crate::_internal::analysis::facts::AlterViewAction::OwnerTo {
                    new_owner: Self::extract_role(&ot.role_ref()?),
                }
            }
            ast::AlterViewAction::SetSchema(ss) => {
                let token = ss.schema_ref()?.ident_token()?;
                crate::_internal::analysis::facts::AlterViewAction::SetSchema {
                    new_schema: Self::resolve_identifier_token(token.text()),
                }
            }
            ast::AlterViewAction::AlterViewColumn(avc) => {
                let col_token = avc.name()?.ident_token()?;
                let column = Self::resolve_identifier_token(col_token.text());
                match avc.alter_view_column_action()? {
                    ast::AlterViewColumnAction::SetDefault(sd) => {
                        crate::_internal::analysis::facts::AlterViewAction::SetDefault {
                            column,
                            default: sd.expr().map(
                                crate::_internal::analysis::expr_visitor::ExprVisitor::convert,
                            ),
                        }
                    }
                    ast::AlterViewColumnAction::DropDefault(_) => {
                        crate::_internal::analysis::facts::AlterViewAction::DropDefault { column }
                    }
                }
            }
            ast::AlterViewAction::RenameColumn(rc) => {
                let from_token = rc.column_name_ref()?.ident_token()?;
                let from = Self::identifier_from_token(from_token.text());

                let to_token = rc.column_name()?.ident_token()?;
                let to = Self::identifier_from_token(to_token.text());

                crate::_internal::analysis::facts::AlterViewAction::RenameColumn { from, to }
            }
            ast::AlterViewAction::SetOptions(so) => {
                crate::_internal::analysis::facts::AlterViewAction::SetOptions {
                    options: Self::extract_attribute_list(so.attribute_list()),
                }
            }
            ast::AlterViewAction::ResetOptions(ro) => {
                crate::_internal::analysis::facts::AlterViewAction::ResetOptions {
                    options: Self::extract_attribute_options_raw(ro.attribute_list())
                        .unwrap_or_default(),
                }
            }
        })
    }

    pub(super) fn extract_create_materialized_view(
        node: &CreateMaterializedView,
    ) -> Option<StatementFact> {
        let path = node.view()?.path()?;
        let (select_source, select_outputs) = Self::extract_single_source_projection(node.query());
        let projection_was_complete = select_outputs.is_some();
        let select_outputs = select_outputs.unwrap_or_default();
        Some(StatementFact::CreateMaterializedView {
            name: Self::path_to_qualified_name(&path)?,
            depends_on: Self::extract_view_dependencies(node.syntax()),
            if_not_exists: node.if_not_exists().is_some(),
            with_no_data: node
                .data_option()
                .is_some_and(|option| matches!(option, ast::DataOption::WithNoData(_))),
            column_list: node
                .column_list()
                .map(|list| {
                    list.column_names()
                        .filter_map(|name| {
                            Some(Self::resolve_identifier_token(name.ident_token()?.text()))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            access_method: node
                .using_method()
                .and_then(|method| method.access_method_ref())
                .and_then(|reference| reference.ident_token())
                .map(|token| Self::resolve_identifier_token(token.text())),
            tablespace: node
                .tablespace_clause()
                .and_then(|clause| clause.tablespace_ref())
                .and_then(|reference| reference.ident_token())
                .map(|token| Self::resolve_identifier_token(token.text())),
            options: node
                .with_params()
                .and_then(|params| params.attribute_list())
                .map(|attribute_list| Self::extract_attribute_list(Some(attribute_list)))
                .unwrap_or_default(),
            select_projection_complete: select_source.is_some() && projection_was_complete,
            select_outputs,
            select_source,
            routines: Self::extract_view_routines(node.syntax()),
            cast_types: Self::extract_view_cast_types(node.syntax()),
        })
    }

    pub(super) fn extract_alter_materialized_view(
        node: &ast::AlterMaterializedView,
    ) -> Option<StatementFact> {
        let path = node.view_ref()?.path_ref()?;
        // An action the model does not represent makes the whole statement
        // opaque, rather than silently applying the remaining actions.
        let actions: Option<Vec<_>> = node
            .action()
            .map(Self::extract_alter_materialized_view_action)
            .collect();
        Some(StatementFact::AlterMaterializedView {
            name: Self::path_ref_to_qualified_name(&path)?,
            actions: actions?,
            if_exists: node.if_exists().is_some(),
        })
    }

    pub(super) fn extract_alter_materialized_view_action(
        action_node: ast::AlterMaterializedViewAction,
    ) -> Option<crate::_internal::analysis::facts::AlterMaterializedViewActionFact> {
        Some(match action_node {
            ast::AlterMaterializedViewAction::ViewRenameTo(rt) => {
                let segment = rt.view()?.path()?.segment()?;
                crate::_internal::analysis::facts::AlterMaterializedViewActionFact::RenameTo {
                    new_name: Self::identifier_from_name(segment.text(), segment.is_quoted()),
                }
            }
            ast::AlterMaterializedViewAction::SetSchema(ss) => {
                let token = ss.schema_ref()?.ident_token()?;
                crate::_internal::analysis::facts::AlterMaterializedViewActionFact::SetSchema {
                    new_schema: Self::resolve_identifier_token(token.text()),
                }
            }
            ast::AlterMaterializedViewAction::RenameColumn(rc) => {
                let from_token = rc.column_name_ref()?.ident_token()?;
                let from = Self::identifier_from_token(from_token.text());

                let to_token = rc.column_name()?.ident_token()?;
                let to = Self::identifier_from_token(to_token.text());

                crate::_internal::analysis::facts::AlterMaterializedViewActionFact::RenameColumn {
                    from,
                    to,
                }
            }
            ast::AlterMaterializedViewAction::DependsOnExtension(d) => {
                let ext_token = d.extension_ref()?.ident_token()?;
                crate::_internal::analysis::facts::AlterMaterializedViewActionFact::DependsOnExtension {
                    extension_name: Self::identifier_from_token(ext_token.text()),
                }
            }
            ast::AlterMaterializedViewAction::NoDependsOnExtension(nd) => {
                let ext_token = nd.extension_ref()?.ident_token()?;
                crate::_internal::analysis::facts::AlterMaterializedViewActionFact::NoDependsOnExtension {
                    extension_name: Self::identifier_from_token(ext_token.text()),
                }
            }
            ast::AlterMaterializedViewAction::AlterTableAction(ata) => {
                match ata {
                    ast::AlterTableAction::SetOptions(so) => {
                        crate::_internal::analysis::facts::AlterMaterializedViewActionFact::SetOptions {
                            options: Self::extract_attribute_list(so.attribute_list()),
                        }
                    }
                    ast::AlterTableAction::ResetOptions(ro) => {
                        crate::_internal::analysis::facts::AlterMaterializedViewActionFact::ResetOptions {
                            options: Self::extract_attribute_options_raw(ro.attribute_list())
                                .unwrap_or_default(),
                        }
                    }
                    ast::AlterTableAction::ClusterOn(co) => {
                        let idx_path = co.index_ref()?.path_ref()?;
                        crate::_internal::analysis::facts::AlterMaterializedViewActionFact::ClusterOn {
                            index_name: Self::path_ref_to_qualified_name(&idx_path)?.name,
                        }
                    }
                    ast::AlterTableAction::SetWithoutCluster(_) => {
                        crate::_internal::analysis::facts::AlterMaterializedViewActionFact::SetWithoutCluster
                    }
                    ast::AlterTableAction::SetTablespace(st) => {
                        let ts = st.tablespace_ref()?.ident_token()?;
                        crate::_internal::analysis::facts::AlterMaterializedViewActionFact::SetTablespace {
                            new_tablespace: Self::identifier_from_token(ts.text()),
                        }
                    }
                    ast::AlterTableAction::SetAccessMethod(sam) => {
                        let am = sam.access_method_ref()?.ident_token()?;
                        crate::_internal::analysis::facts::AlterMaterializedViewActionFact::SetAccessMethod {
                            new_access_method: Self::identifier_from_token(am.text()),
                        }
                    }
                    ast::AlterTableAction::AlterColumn(ac) => {
                        let col_name_ref = ac.column_name_ref()?;
                        let col_name = Self::resolve_identifier_token(col_name_ref.ident_token()?.text());
                        match ac.option()? {
                            ast::AlterColumnOption::SetStorage(ss) => {
                                crate::_internal::analysis::facts::AlterMaterializedViewActionFact::SetStorage {
                                    column: col_name,
                                    storage: ss.storage_mode()?.syntax().text().to_string(),
                                }
                            }
                            ast::AlterColumnOption::SetCompression(sc) => {
                                crate::_internal::analysis::facts::AlterMaterializedViewActionFact::SetCompression {
                                    column: col_name,
                                    compression: sc.compression_method_name()?.syntax().text().to_string(),
                                }
                            }
                            _ => return None,
                        }
                    }
                    ast::AlterTableAction::OwnerTo(ot) => {
                        crate::_internal::analysis::facts::AlterMaterializedViewActionFact::OwnerTo {
                            new_owner: Self::extract_role(&ot.role_ref()?),
                        }
                    }
                    _ => return None,
                }
            }
        })
    }

    pub(super) fn extract_refresh(node: &ast::Refresh) -> Option<StatementFact> {
        let path = node.view_ref()?.path_ref()?;
        Some(StatementFact::RefreshMaterializedView {
            name: Self::path_ref_to_qualified_name(&path)?,
            concurrently: node.concurrently_token().is_some(),
            with_no_data: node
                .data_option()
                .is_some_and(|option| matches!(option, ast::DataOption::WithNoData(_))),
        })
    }

    pub(super) fn extract_drop_view(node: &DropView) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .view_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(StatementFact::DropView {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    pub(super) fn extract_drop_materialized_view(
        node: &DropMaterializedView,
    ) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .view_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(StatementFact::DropMaterializedView {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    pub(super) fn extract_view_dependencies(
        syntax: &squawk_syntax::SyntaxNode,
    ) -> Vec<QualifiedName> {
        let mut depends_on = Vec::new();
        let keywords = [
            "SELECT",
            "FROM",
            "WHERE",
            "JOIN",
            "ON",
            "AND",
            "OR",
            "AS",
            "WITH",
            "GROUP",
            "BY",
            "HAVING",
            "LIMIT",
            "OFFSET",
            "ORDER",
            "ASC",
            "DESC",
            "IN",
            "NOT",
            "IS",
            "NULL",
            "UNION",
            "ALL",
            "EXCEPT",
            "INTERSECT",
            "TRUE",
            "FALSE",
        ];

        let mut local_declarations = Vec::new();
        for cte_name in syntax.descendants().filter_map(CteName::cast) {
            if let Some(tok) = cte_name.ident_token() {
                local_declarations.push(Self::resolve_identifier_token(tok.text()));
            }
        }

        for n in syntax.descendants().filter_map(PathSegmentRef::cast) {
            let text = n.text().to_string();
            let upper = text.to_uppercase();
            let is_quoted = n.is_quoted();
            let clean_text = Self::identifier_from_token(&text).text;

            if !is_quoted && keywords.contains(&upper.as_str()) {
                continue;
            }

            if local_declarations.contains(&clean_text) {
                continue;
            }

            let Some(relation) = n
                .syntax()
                .ancestors()
                .skip(1)
                .find_map(RelationNameRef::cast)
            else {
                // Path segments outside a relation name are expressions,
                // casts, function calls, aliases, or CTE internals. They are
                // not relation dependencies (for example, `regclass` in a
                // `nextval(...::regclass)` cast), so do not turn them into
                // phantom graph edges.
                continue;
            };

            let qname = if let Some(pr) = relation.path_ref() {
                if let Some(qn) = Self::path_ref_to_qualified_name(&pr) {
                    qn
                } else {
                    QualifiedName::new(None, Ident::new(clean_text.clone(), is_quoted))
                }
            } else {
                QualifiedName::new(None, Ident::new(clean_text.clone(), is_quoted))
            };

            if !depends_on.contains(&qname) {
                depends_on.push(qname);
            }
        }
        depends_on
    }
}
