use super::*;

impl AstVisitor {
    pub(super) fn extract_reindex_fact(node: &ast::Reindex) -> Option<StatementFact> {
        let target = node.reindex_target()?;
        let concurrently = node.is_concurrently();

        let (target_kind, target_name) = match target {
            ast::ReindexTarget::ReindexTargetDatabase(db) => {
                let name = db
                    .database_ref()
                    .and_then(|r| r.ident_token())
                    .map(|t| QualifiedName::new(None, Self::identifier_from_token(t.text())));
                (ReindexTargetKindFact::Database, name)
            }
            ast::ReindexTarget::ReindexTargetIndex(idx) => {
                let name = idx
                    .index_ref()
                    .and_then(|r| Self::path_ref_to_qualified_name(&r.path_ref()?));
                (ReindexTargetKindFact::Index, name)
            }
            ast::ReindexTarget::ReindexTargetSchema(schema) => {
                let name = schema
                    .schema_ref()
                    .and_then(|r| r.ident_token())
                    .map(|t| QualifiedName::new(None, Self::identifier_from_token(t.text())));
                (ReindexTargetKindFact::Schema, name)
            }
            ast::ReindexTarget::ReindexTargetSystem(sys) => {
                let name = sys
                    .database_ref()
                    .and_then(|r| r.ident_token())
                    .map(|t| QualifiedName::new(None, Self::identifier_from_token(t.text())));
                (ReindexTargetKindFact::System, name)
            }
            ast::ReindexTarget::ReindexTargetTable(table) => {
                let name = table
                    .table_name_ref()
                    .and_then(|r| Self::path_ref_to_qualified_name(&r.path_ref()?));
                (ReindexTargetKindFact::Table, name)
            }
        };

        Some(StatementFact::Reindex {
            target_kind,
            target_name,
            concurrently,
        })
    }

    /// PostgreSQL stores both bits absolutely, so `ASC NULLS LAST` and
    /// `DESC NULLS FIRST` are one order; saying nothing means `ASC NULLS LAST`.
    pub(super) fn index_key_order(
        sort_order: Option<ast::SortOrder>,
        nulls_order: Option<ast::NullsOrder>,
    ) -> IndexOrder {
        let descending = matches!(sort_order, Some(ast::SortOrder::SortDesc(_)));
        // PostgreSQL defaults to NULLS LAST for ASC and NULLS FIRST for DESC,
        // so a bare `DESC` is the default order, not a non-default one.
        let nulls_first = match nulls_order {
            Some(ast::NullsOrder::NullsFirst(_)) => true,
            Some(ast::NullsOrder::NullsLast(_)) => false,
            None => descending,
        };
        match (descending, nulls_first) {
            (false, false) | (true, true) => IndexOrder::Default,
            (true, false) => IndexOrder::DescNullsLast,
            (false, true) => IndexOrder::AscNullsFirst,
        }
    }

    /// Strip the wrappers PostgreSQL removes before deciding an index key's
    /// kind, so `(col)`, `col COLLATE c`, and their compositions reduce the
    /// same way the server reduces them.
    pub(super) fn strip_index_key_wrappers(expression: Option<ast::Expr>) -> Option<ast::Expr> {
        match expression {
            Some(ast::Expr::ParenExpr(paren)) => Self::strip_index_key_wrappers(paren.expr()),
            Some(ast::Expr::Collate(collate)) => Self::strip_index_key_wrappers(collate.expr()),
            other => other,
        }
    }

    /// A dotted reference's written name, keeping the schema qualifier: a
    /// collation or operator class resolved through the path is a different
    /// identity from the same trailing name in the catalog.
    pub(super) fn index_item_written_name<T: AstNode>(
        reference: Option<T>,
        child: impl Fn(&T) -> Option<PathRef>,
    ) -> Option<WrittenName> {
        let reference = reference?;
        let qualified = Self::path_ref_to_qualified_name(&child(&reference)?)?;
        Some(WrittenName {
            schema: qualified.schema.map(|schema| schema.resolve()),
            name: qualified.name.resolve(),
        })
    }

    pub(super) fn extract_create_index(node: &CreateIndex) -> Option<StatementFact> {
        let table_relation = node.table_relation_name()?;
        let relation = table_relation.table_name_ref()?.path_ref()?;
        let relation = Self::path_ref_to_qualified_name(&relation)?;

        let index_ident = if let Some(name) = node
            .index()
            .and_then(|i| i.path())
            .and_then(|p| Self::path_to_qualified_name(&p))
        {
            name.name
        } else {
            Ident::new(
                format!("<unnamed_idx_on_{}>", relation.name.resolve()),
                false,
            )
        };

        let using_method = node.using_method().map(|um| {
            um.access_method_ref()
                .and_then(|nr| nr.ident_token())
                .map(|nr| nr.text().to_string().to_uppercase())
                .unwrap_or_default()
        });

        let predicate = match node.where_clause() {
            None => IndexPredicate::None,
            Some(clause) => match clause.expr() {
                Some(expr) => IndexPredicate::Parsed(
                    crate::_internal::analysis::expr_visitor::ExprVisitor::convert(expr),
                ),
                None => IndexPredicate::Opaque,
            },
        };
        // `NULLS NOT DISTINCT` is the `false` case of the catalog's
        // `indnullsnotdistinct`, which reads "distinct is false".
        let nulls_not_distinct = matches!(
            node.nulls_distinct_option(),
            Some(ast::NullsDistinctOption::NullsNotDistinct(_))
        );
        let unique = node.unique_token().is_some();
        let included_columns = node
            .index_include_clause()
            .and_then(|include| include.partition_item_list())
            .into_iter()
            .flat_map(|items| items.partition_items())
            .filter_map(|item| match item.expr() {
                Some(ast::Expr::NameRef(name)) => Some(Self::resolve_identifier_token(name.text())),
                _ => None,
            })
            .collect();
        let mut key_columns = Vec::new();
        let mut key_expressions: Vec<Option<ExprIr>> = Vec::new();
        let mut key_orders: Vec<IndexOrder> = Vec::new();
        let mut key_opclasses: Vec<Option<WrittenName>> = Vec::new();
        let mut key_collations: Vec<Option<WrittenName>> = Vec::new();
        for item in node
            .partition_item_list()
            .into_iter()
            .flat_map(|items| items.partition_items())
        {
            // `DefineIndex` strips top-level `COLLATE` (and parentheses)
            // before deciding a key is a column or an expression, so a
            // collated bare column is a column key carrying the collation,
            // not an expression.
            let collate = match item.expr() {
                Some(ast::Expr::Collate(collate)) => Some(collate),
                _ => item.collate(),
            };
            let mut expression = match item.expr() {
                Some(ast::Expr::Collate(collate)) => collate.expr(),
                expression => expression,
            };
            expression = Self::strip_index_key_wrappers(expression);
            match expression {
                Some(ast::Expr::NameRef(name)) => {
                    key_columns.push(Self::resolve_identifier_token(name.text()));
                    key_expressions.push(None);
                }
                Some(expr) => key_expressions.push(Some(
                    crate::_internal::analysis::expr_visitor::ExprVisitor::convert(expr),
                )),
                None => key_expressions.push(None),
            }
            key_orders.push(Self::index_key_order(item.sort_order(), item.nulls_order()));
            key_opclasses.push(Self::index_item_written_name(item.op_class_ref(), |r| {
                r.path_ref()
            }));
            key_collations.push(Self::index_item_written_name(
                collate.and_then(|collate| collate.collation_ref()),
                |r| r.path_ref(),
            ));
        }

        Some(StatementFact::CreateIndex {
            name: QualifiedName::new(None, index_ident),
            relation,
            if_not_exists: node.if_not_exists().is_some(),
            concurrently: node.concurrently_token().is_some(),
            only: table_relation.only_token().is_some(),
            using_method,
            predicate,
            unique,
            nulls_not_distinct,
            key_columns,
            key_expressions,
            key_orders,
            key_opclasses,
            key_collations,
            included_columns,
        })
    }

    pub(super) fn extract_alter_index(node: &AlterIndex) -> Option<StatementFact> {
        // Two grammar shapes: a per-index action list (IndexRef child), and the
        // bulk relocation form `ALL IN TABLESPACE src SET TABLESPACE dst`
        // (AllInTablespace child; no index_ref). The bulk form has no single
        // index to validate, so it becomes its own advisory fact.
        if let Some(all) = node.all_in_tablespace() {
            let source = all.tablespace_ref()?.ident_token()?;
            let target = all.set_tablespace()?.tablespace_ref()?.ident_token()?;
            return Some(StatementFact::AlterIndexAllInTablespace {
                source_tablespace: Self::identifier_from_token(source.text()),
                target_tablespace: Self::identifier_from_token(target.text()),
            });
        }

        let path = node.index_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let if_exists = node.if_exists().is_some();
        let mut actions = Vec::new();

        match node.action()? {
            squawk_syntax::ast::AlterIndexAction::IndexRenameTo(rt) => {
                let new_name = rt
                    .index()
                    .and_then(|i| i.path())
                    .and_then(|p| Self::path_to_qualified_name(&p))?;
                actions.push(AlterIndexActionFact::RenameTo {
                    new_name: new_name.name,
                });
            }
            squawk_syntax::ast::AlterIndexAction::SetTablespace(st) => {
                let ts = st.tablespace_ref()?.ident_token()?;
                actions.push(AlterIndexActionFact::SetTablespace {
                    new_tablespace: Self::identifier_from_token(ts.text()),
                });
            }
            squawk_syntax::ast::AlterIndexAction::AttachIndexPartition(ap) => {
                let partition_path = ap.index_ref()?.path_ref()?;
                let partition_name = Self::path_ref_to_qualified_name(&partition_path)?;
                actions.push(AlterIndexActionFact::AttachPartition { partition_name });
            }
            squawk_syntax::ast::AlterIndexAction::DependsOnExtension(dep) => {
                let ext = dep.extension_ref()?.ident_token()?;
                actions.push(AlterIndexActionFact::DependsOnExtension {
                    extension_name: Self::identifier_from_token(ext.text()),
                });
            }
            squawk_syntax::ast::AlterIndexAction::NoDependsOnExtension(dep) => {
                let ext = dep.extension_ref()?.ident_token()?;
                actions.push(AlterIndexActionFact::NoDependsOnExtension {
                    extension_name: Self::identifier_from_token(ext.text()),
                });
            }
            squawk_syntax::ast::AlterIndexAction::AlterSetStatistics(ss) => {
                // PostgreSQL requires a column, by name or 1-based number;
                // the bare form is a syntax error.
                let column = if let Some(name_ref) = ss.column_name_ref() {
                    let name = name_ref.ident_token()?.text().to_string();
                    IndexStatisticsColumn::Name(Self::identifier_from_token(&name).resolve())
                } else {
                    let number = ss.expr()?.syntax().text().to_string();
                    IndexStatisticsColumn::Number(number.parse::<i32>().ok()?)
                };
                if let Some(stat_node) = ss.set_statistics() {
                    let target = if stat_node.default_token().is_some() {
                        crate::_internal::analysis::facts::StatisticsTarget::Default
                    } else {
                        let n = stat_node
                            .expr()?
                            .syntax()
                            .text()
                            .to_string()
                            .parse::<i32>()
                            .ok()?;
                        crate::_internal::analysis::facts::StatisticsTarget::Value(n)
                    };
                    actions.push(AlterIndexActionFact::SetStatistics { column, target });
                } else {
                    // The SetOptions child may be absent from an unannotated
                    // degenerate form; propagating None models nothing rather
                    // than silently degrading a reachable SET (options) form.
                    let so = ss.set_options()?;
                    let options = Self::extract_attribute_list(so.attribute_list());
                    actions.push(AlterIndexActionFact::SetOptions { options });
                }
            }
            squawk_syntax::ast::AlterIndexAction::SetOptions(so) => {
                let options = Self::extract_attribute_list(so.attribute_list());
                actions.push(AlterIndexActionFact::SetOptions { options });
            }
            squawk_syntax::ast::AlterIndexAction::ResetOptions(ro) => {
                let options =
                    Self::extract_attribute_options_raw(ro.attribute_list()).unwrap_or_default();
                actions.push(AlterIndexActionFact::ResetOptions { options });
            }
        }

        if actions.is_empty() {
            return None;
        }
        Some(StatementFact::AlterIndex {
            name,
            if_exists,
            actions,
        })
    }

    pub(super) fn extract_drop_index(node: &DropIndex) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .index_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(StatementFact::DropIndex {
            names,
            if_exists: node.if_exists().is_some(),
            concurrently: node.concurrently_token().is_some(),
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }
}
