use super::*;

impl AstVisitor {
    pub(super) fn extract_create_table(node: &CreateTable) -> Option<StatementFact> {
        let path = node.table_name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;

        let persistence = match node.persistence() {
            Some(squawk_syntax::ast::Persistence::Temp(_)) => PersistenceFact::Temporary,
            Some(squawk_syntax::ast::Persistence::Unlogged(_)) => PersistenceFact::Unlogged,
            _ => PersistenceFact::Permanent,
        };
        let on_commit = match node
            .on_commit()
            .and_then(|clause| clause.on_commit_action())
        {
            Some(ast::OnCommitAction::PreserveRows(_)) => {
                Some(crate::_internal::analysis::facts::OnCommitFact::PreserveRows)
            }
            Some(ast::OnCommitAction::DeleteRows(_)) => {
                Some(crate::_internal::analysis::facts::OnCommitFact::DeleteRows)
            }
            Some(ast::OnCommitAction::Drop(_)) => {
                Some(crate::_internal::analysis::facts::OnCommitFact::Drop)
            }
            None => None,
        };
        if on_commit.is_some() && !matches!(persistence, PersistenceFact::Temporary) {
            return None;
        }

        let partition_by = node.partition_by().map(|p| p.syntax().text().to_string());
        let partition_keys = node
            .partition_by()
            .map(|p| Self::partition_keys_from_partition_by(&p))
            .unwrap_or_default();
        let partition_strategy = node
            .partition_by()
            .and_then(|partition| partition.partition_strategy())
            .and_then(|strategy| strategy.range_token().or_else(|| strategy.ident_token()))
            .map(|token| Self::resolve_identifier_token(token.text()));
        let partition_of = node
            .partition_of()
            .and_then(|po| po.table_name_ref())
            .and_then(|t| t.path_ref())
            .and_then(|p| Self::path_ref_to_qualified_name(&p));
        let partition_bound = node
            .partition_type()
            .map(|pt| pt.syntax().text().to_string());
        let inherits = match node.inherits() {
            Some(inherits) => inherits
                .table_name_refs()
                .map(|table| {
                    table
                        .path_ref()
                        .and_then(|path| Self::path_ref_to_qualified_name(&path))
                })
                .collect::<Option<Vec<_>>>()?,
            None => Vec::new(),
        };
        let of_type = node
            .of_type()
            .and_then(|of_type| of_type.ty())
            .and_then(|ty| match ty {
                ast::Type::PathType(path_type)
                    if path_type.arg_list().is_none() && path_type.setof_token().is_none() =>
                {
                    path_type
                        .path_ref()
                        .and_then(|path| Self::path_ref_to_qualified_name(&path))
                }
                _ => None,
            });
        if node.of_type().is_some() && of_type.is_none() {
            return None;
        }

        let (columns, foreign_keys, table_constraints, like_sources) = match node.table_arg_list() {
            Some(args) => Self::extract_table_body(args.args())?,
            None => (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
        };

        Some(StatementFact::CreateTable {
            name,
            if_not_exists: node.if_not_exists().is_some(),
            as_select: false,
            persistence,
            on_commit,
            columns,
            foreign_keys,
            table_constraints,
            partition_by,
            partition_keys,
            partition_strategy,
            partition_of,
            partition_bound,
            inherits,
            like_sources,
            of_type,
            select_source: None,
            select_outputs: Vec::new(),
            select_projection_complete: false,
        })
    }

    pub(super) fn extract_create_table_as(node: &CreateTableAs) -> Option<StatementFact> {
        let path = node.table_name()?.path()?;
        let persistence = match node.persistence() {
            Some(squawk_syntax::ast::Persistence::Temp(_)) => PersistenceFact::Temporary,
            Some(squawk_syntax::ast::Persistence::Unlogged(_)) => PersistenceFact::Unlogged,
            _ => PersistenceFact::Permanent,
        };
        let on_commit = match node
            .on_commit()
            .and_then(|clause| clause.on_commit_action())
        {
            Some(ast::OnCommitAction::PreserveRows(_)) => {
                Some(crate::_internal::analysis::facts::OnCommitFact::PreserveRows)
            }
            Some(ast::OnCommitAction::DeleteRows(_)) => {
                Some(crate::_internal::analysis::facts::OnCommitFact::DeleteRows)
            }
            Some(ast::OnCommitAction::Drop(_)) => {
                Some(crate::_internal::analysis::facts::OnCommitFact::Drop)
            }
            None => None,
        };
        if on_commit.is_some() && !matches!(persistence, PersistenceFact::Temporary) {
            return None;
        }

        Some(StatementFact::CreateTable {
            name: Self::path_to_qualified_name(&path)?,
            if_not_exists: node.if_not_exists().is_some(),
            as_select: true,
            persistence,
            on_commit,
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),
            partition_by: None,
            partition_keys: Vec::new(),
            partition_strategy: None,
            partition_of: None,
            partition_bound: None,
            inherits: Vec::new(),
            like_sources: Vec::new(),
            of_type: None,
            select_source: None,
            select_outputs: Vec::new(),
            select_projection_complete: false,
        })
    }

    pub(super) fn extract_select_into(node: &SelectInto) -> Option<StatementFact> {
        let into = node.into_clause()?;
        let name = into.table_name()?.path()?;
        let persistence = match into.persistence() {
            Some(squawk_syntax::ast::Persistence::Temp(_)) => PersistenceFact::Temporary,
            Some(squawk_syntax::ast::Persistence::Unlogged(_)) => PersistenceFact::Unlogged,
            _ => PersistenceFact::Permanent,
        };
        let select_source = node.from_clause().and_then(|from| {
            let mut items = from.items();
            let item = items.next()?;
            if items.next().is_some() {
                return None;
            }
            let ast::FromListItem::FromItem(ast::FromItem::RelationFromItem(relation)) = item
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
        let select_outputs = node
            .select_clause()
            .and_then(|select| Self::extract_select_outputs(&select));
        let select_projection_complete = select_source.is_some() && select_outputs.is_some();
        Some(StatementFact::CreateTable {
            name: Self::path_to_qualified_name(&name)?,
            if_not_exists: false,
            as_select: true,
            persistence,
            on_commit: None,
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),
            partition_by: None,
            partition_keys: Vec::new(),
            partition_strategy: None,
            partition_of: None,
            partition_bound: None,
            inherits: Vec::new(),
            like_sources: Vec::new(),
            of_type: None,
            select_source,
            select_outputs: select_outputs.unwrap_or_default(),
            select_projection_complete,
        })
    }

    pub(super) fn extract_drop_table(node: &DropTable) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .table_name_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(StatementFact::DropTable {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    pub(super) fn extract_lock(node: &Lock) -> Option<StatementFact> {
        let targets = node
            .relation_list()?
            .relation_names()
            .map(|relation| {
                Some(RelationTargetFact {
                    name: Self::path_ref_to_qualified_name(
                        &relation.relation_name_ref()?.path_ref()?,
                    )?,
                    only: relation.only_token().is_some(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let mode = match node.lock_mode_clause()?.lock_mode()? {
            ast::LockMode::AccessShare(_) => LockModeFact::AccessShare,
            ast::LockMode::RowShare(_) => LockModeFact::RowShare,
            ast::LockMode::RowExclusive(_) => LockModeFact::RowExclusive,
            ast::LockMode::ShareUpdateExclusive(_) => LockModeFact::ShareUpdateExclusive,
            ast::LockMode::Share(_) => LockModeFact::Share,
            ast::LockMode::ShareRowExclusive(_) => LockModeFact::ShareRowExclusive,
            ast::LockMode::Exclusive(_) => LockModeFact::Exclusive,
            ast::LockMode::AccessExclusive(_) => LockModeFact::AccessExclusive,
        };
        (!targets.is_empty()).then_some(StatementFact::Lock {
            targets,
            mode,
            nowait: node.nowait().is_some(),
        })
    }

    pub(super) fn extract_truncate(node: &Truncate) -> Option<StatementFact> {
        let targets = node
            .table_list()?
            .table_relation_names()
            .map(|relation| {
                Some(RelationTargetFact {
                    name: Self::path_ref_to_qualified_name(
                        &relation.table_name_ref()?.path_ref()?,
                    )?,
                    only: relation.only_token().is_some(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        (!targets.is_empty()).then_some(StatementFact::Truncate {
            targets,
            cascade: Self::is_cascade(node.drop_behavior()),
            restart_identity: matches!(
                node.identity_action(),
                Some(ast::IdentityAction::RestartIdentity(_))
            ),
        })
    }

    pub(super) fn extract_like_properties(like: &ast::LikeClause) -> Option<LikePropertiesFact> {
        let mut properties = LikePropertiesFact::default();
        for option in like.like_options() {
            let (including, property) = match option {
                ast::LikeOption::IncludingProperty(option) => (true, option.table_property()?),
                ast::LikeOption::ExcludingProperty(option) => (false, option.table_property()?),
            };
            match property {
                ast::TableProperty::PropertyAll(_) => {
                    properties = LikePropertiesFact {
                        defaults: including,
                        generated: including,
                        storage: including,
                        compression: including,
                        statistics: including,
                        constraints: including,
                        indexes: including,
                        identity: including,
                    };
                }
                // Comments are not catalog semantics consumed by the analyzer.
                ast::TableProperty::PropertyComments(_) => {}
                ast::TableProperty::PropertyDefaults(_) => properties.defaults = including,
                ast::TableProperty::PropertyGenerated(_) => properties.generated = including,
                ast::TableProperty::PropertyStorage(_) => properties.storage = including,
                ast::TableProperty::PropertyCompression(_) => properties.compression = including,
                ast::TableProperty::PropertyStatistics(_) => properties.statistics = including,
                ast::TableProperty::PropertyConstraints(_) => properties.constraints = including,
                ast::TableProperty::PropertyIndexes(_) => properties.indexes = including,
                ast::TableProperty::PropertyIdentity(_) => properties.identity = including,
            }
        }
        Some(properties)
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn extract_table_body(
        args: impl Iterator<Item = TableArg>,
    ) -> Option<(
        Vec<ColumnFact>,
        Vec<FkFact>,
        Vec<TableConstraintFact>,
        Vec<LikeSourceFact>,
    )> {
        let mut columns = Vec::new();
        let mut foreign_keys = Vec::new();
        let mut table_constraints = Vec::new();
        let mut like_sources = Vec::new();
        for arg in args {
            match arg {
                TableArg::Column(col) => {
                    for fk in Self::extract_column_fk_facts(&col) {
                        foreign_keys.push(fk);
                    }
                    let column_name = col
                        .name()
                        .and_then(|name| name.ident_token())
                        .or_else(|| {
                            col.syntax()
                                .descendants_with_tokens()
                                .filter_map(|element| element.into_token())
                                .find(|token| token.kind() != SyntaxKind::WHITESPACE)
                        })
                        .map(|token| Self::resolve_identifier_token(token.text()))?;
                    for constraint in Self::column_constraints(&col) {
                        let ColumnConstraint::CheckConstraint(check) = constraint else {
                            continue;
                        };
                        let (columns, columns_complete) = check
                            .expr()
                            .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                            .map(Self::expr_columns_with_completeness)
                            .unwrap_or((Vec::new(), false));
                        table_constraints.push(TableConstraintFact::Check {
                            constraint_name: check
                                .constraint_name_clause()
                                .and_then(|clause| clause.constraint_name())
                                .and_then(|name| name.ident_token())
                                .map(|token| Self::resolve_identifier_token(token.text())),
                            name_hint: Some(column_name.clone()),
                            definition: check.expr()?.syntax().text().to_string(),
                            columns,
                            columns_complete,
                        });
                    }
                    if let Some(fact) = Self::extract_column_fact(&col) {
                        columns.push(fact);
                    }
                }
                TableArg::LikeClause(like) => {
                    let properties = Self::extract_like_properties(&like)?;
                    let source = like
                        .relation_name_ref()
                        .and_then(|name| name.path_ref())
                        .and_then(|path| Self::path_ref_to_qualified_name(&path))?;
                    like_sources.push(LikeSourceFact {
                        relation: source,
                        properties,
                    });
                }
                TableArg::TableConstraint(tc) => {
                    if let Some(fk) = Self::extract_table_fk_fact(&tc) {
                        foreign_keys.push(fk);
                    }
                    if let Some(tc_fact) = Self::extract_table_constraint_fact(&tc) {
                        table_constraints.push(tc_fact);
                    }
                }
            }
        }
        Some((columns, foreign_keys, table_constraints, like_sources))
    }

    pub(super) fn column_constraints(col: &Column) -> impl Iterator<Item = ColumnConstraint> + '_ {
        col.clauses().filter_map(|clause| match clause {
            ast::ColumnClause::ColumnConstraint(constraint) => Some(constraint),
            _ => None,
        })
    }

    pub(super) fn identity_sequence_options(
        identity: &ast::GeneratedIdentity,
    ) -> Option<crate::_internal::analysis::facts::IdentitySequenceOptionsFact> {
        let Some(options) = identity.sequence_option_list() else {
            return Some(Default::default());
        };
        Self::extract_sequence_options(options.sequence_options())
    }

    pub(super) fn extract_sequence_options(
        options: impl Iterator<Item = ast::SequenceOption>,
    ) -> Option<crate::_internal::analysis::facts::IdentitySequenceOptionsFact> {
        let mut result = crate::_internal::analysis::facts::IdentitySequenceOptionsFact::default();
        let integer = |expr: ast::Expr| expr.syntax().text().to_string().trim().parse::<i64>().ok();
        for option in options {
            match option {
                ast::SequenceOption::OptionAsType(option) => {
                    result.data_type = Some(option.ty()?.syntax().text().to_string());
                }
                ast::SequenceOption::OptionCache(option) => {
                    result.cache_size = Some(integer(option.expr()?)?);
                }
                ast::SequenceOption::OptionCycle(_) => result.cycle = Some(true),
                ast::SequenceOption::OptionNoCycle(_) => result.cycle = Some(false),
                ast::SequenceOption::OptionIncrement(option) => {
                    result.increment = Some(integer(option.expr()?)?);
                }
                ast::SequenceOption::OptionMaxValue(option) => {
                    result.max_value = Some(Some(integer(option.expr()?)?));
                }
                ast::SequenceOption::OptionNoMaxValue(_) => result.max_value = Some(None),
                ast::SequenceOption::OptionMinValue(option) => {
                    result.min_value = Some(Some(integer(option.expr()?)?));
                }
                ast::SequenceOption::OptionNoMinValue(_) => result.min_value = Some(None),
                ast::SequenceOption::OptionStart(option) => {
                    result.start_value = Some(integer(option.expr()?)?);
                }
                ast::SequenceOption::OptionLogged(_) => result.persistence = Some(true),
                ast::SequenceOption::OptionUnlogged(_) => result.persistence = Some(false),
                ast::SequenceOption::OptionSequenceName(option) => {
                    result.sequence_name = option
                        .sequence()
                        .and_then(|sequence| sequence.path())
                        .and_then(|path| Self::path_to_qualified_name(&path));
                    result.sequence_name.as_ref()?;
                }
                ast::SequenceOption::OptionOwnedBy(_) => {}
                ast::SequenceOption::OptionRestart(_) => return None,
            }
        }
        Some(result)
    }

    pub(super) fn extract_column_fact(col: &Column) -> Option<ColumnFact> {
        let name_token = col.name().and_then(|n| n.ident_token()).or_else(|| {
            col.syntax()
                .descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() != SyntaxKind::WHITESPACE)
        })?;
        let name = Self::resolve_identifier_token(name_token.text());
        let is_serial = Self::is_serial_type(col.ty());
        let ty = col.ty().map(|t| t.syntax().text().to_string());
        let generated_as = Self::column_constraints(col).find_map(|constraint| {
            let ColumnConstraint::GeneratedConstraint(generated) = constraint else {
                return None;
            };
            generated.generated_as()
        });
        let is_identity = matches!(generated_as, Some(ast::GeneratedAs::GeneratedIdentity(_)));
        let is_stored_generated =
            matches!(generated_as, Some(ast::GeneratedAs::GeneratedStored(_)));
        let not_null = is_identity
            || Self::column_constraints(col)
                .any(|c| matches!(c, ColumnConstraint::NotNullConstraint(_)));
        let primary_key_constraint_name = Self::column_constraints(col).find_map(|constraint| {
            let ColumnConstraint::PrimaryKeyConstraint(primary_key) = constraint else {
                return None;
            };
            Some(
                primary_key
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text())),
            )
        });
        let is_primary_key = primary_key_constraint_name.is_some();
        let primary_key_constraint_name = primary_key_constraint_name.flatten();
        let unique_constraint_name = Self::column_constraints(col).find_map(|constraint| {
            let ColumnConstraint::UniqueConstraint(unique) = constraint else {
                return None;
            };
            Some(
                unique
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text())),
            )
        });
        let is_unique = unique_constraint_name.is_some();
        let unique_constraint_name = unique_constraint_name.flatten();
        let default = Self::column_constraints(col).find_map(|c| {
            if let ColumnConstraint::DefaultConstraint(dc) = c {
                Some(crate::_internal::analysis::expr_visitor::ExprVisitor::convert(dc.expr()?))
            } else {
                None
            }
        });
        let generation = if is_serial {
            crate::_internal::analysis::facts::ColumnGeneration::Serial
        } else if let Some(ast::GeneratedAs::GeneratedIdentity(identity)) = &generated_as {
            match identity.generated_when() {
                Some(ast::GeneratedWhen::GeneratedAlways(_)) => {
                    crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
                }
                Some(ast::GeneratedWhen::GeneratedByDefault(_)) => {
                    crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault
                }
                None => return None,
            }
        } else if is_stored_generated {
            let Some(ast::GeneratedAs::GeneratedStored(generated)) = &generated_as else {
                unreachable!("generated-expression guard checked above")
            };
            match generated.generated_kind() {
                Some(ast::GeneratedKind::Stored(_)) => {
                    crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                }
                Some(ast::GeneratedKind::Virtual(_)) => {
                    crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual
                }
                None => return None,
            }
        } else {
            crate::_internal::analysis::facts::ColumnGeneration::Ordinary
        };
        let identity_sequence = match &generated_as {
            Some(ast::GeneratedAs::GeneratedIdentity(identity)) => {
                Some(Self::identity_sequence_options(identity)?)
            }
            _ => None,
        };
        Some(ColumnFact {
            name,
            ty,
            not_null,
            is_primary_key,
            primary_key_constraint_name,
            is_unique,
            unique_constraint_name,
            default,
            generation,
            identity_sequence,
            generated_expr_sql: match &generated_as {
                Some(ast::GeneratedAs::GeneratedStored(stored)) => {
                    stored.expr().map(|expr| expr.syntax().text().to_string())
                }
                _ => None,
            },
            generated_expr: match generated_as {
                Some(ast::GeneratedAs::GeneratedStored(stored)) => stored
                    .expr()
                    .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert),
                _ => None,
            },
        })
    }

    /// PostgreSQL's serial pseudo-types are unquoted path types. A quoted
    /// `"serial"` is an ordinary user type, not a serial column.
    pub(super) fn is_serial_type(ty: Option<ast::Type>) -> bool {
        let Some(segment) = ty
            .and_then(|ty| ty.path_ref())
            .and_then(|path| path.unqualified_segment())
        else {
            return false;
        };
        !segment.is_quoted()
            && matches!(
                segment.text().to_ascii_lowercase().as_str(),
                "smallserial" | "serial2" | "serial" | "serial4" | "bigserial" | "serial8"
            )
    }

    pub(super) fn extract_table_constraint_fact(
        tc: &TableConstraint,
    ) -> Option<TableConstraintFact> {
        match tc {
            TableConstraint::PrimaryKeyConstraint(pkc) => Some(TableConstraintFact::PrimaryKey {
                constraint_name: pkc
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text())),
                columns: pkc
                    .index_parameters()
                    .and_then(|params| params.column_list())
                    .map(Self::extract_constraint_column_list_names)
                    .or_else(|| pkc.using_index().map(|_| Vec::new()))?,
            }),
            TableConstraint::UniqueConstraint(uc) => Some(TableConstraintFact::Unique {
                constraint_name: uc
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text())),
                columns: uc
                    .index_parameters()
                    .and_then(|params| params.column_list())
                    .map(Self::extract_constraint_column_list_names)
                    .or_else(|| uc.using_index().map(|_| Vec::new()))?,
            }),
            TableConstraint::CheckConstraint(check) => {
                let (columns, columns_complete) = check
                    .expr()
                    .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                    .map(Self::expr_columns_with_completeness)
                    .unwrap_or((Vec::new(), false));
                Some(TableConstraintFact::Check {
                    constraint_name: check
                        .constraint_name_clause()
                        .and_then(|clause| clause.constraint_name())
                        .and_then(|name| name.ident_token())
                        .map(|token| Self::resolve_identifier_token(token.text())),
                    name_hint: (columns_complete && columns.len() == 1).then(|| columns[0].clone()),
                    definition: check.expr()?.syntax().text().to_string(),
                    columns,
                    columns_complete,
                })
            }
            TableConstraint::ExcludeConstraint(exclude) => {
                let mut columns_complete = true;
                let columns = exclude
                    .constraint_exclusion_list()
                    .map(|list| {
                        list.constraint_exclusions()
                            .filter_map(|item| item.partition_item()?.expr())
                            .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                            .map(Self::expr_columns_with_completeness)
                            .inspect(|(_, complete)| columns_complete &= *complete)
                            .flat_map(|(columns, _)| columns)
                            .collect()
                    })
                    .unwrap_or_else(|| {
                        columns_complete = false;
                        Vec::new()
                    });
                Some(TableConstraintFact::Exclude {
                    constraint_name: exclude
                        .constraint_name_clause()
                        .and_then(|clause| clause.constraint_name())
                        .and_then(|name| name.ident_token())
                        .map(|token| Self::resolve_identifier_token(token.text())),
                    columns,
                    columns_complete,
                })
            }
            _ => None,
        }
    }

    pub(super) fn extract_column_fk_facts(col: &Column) -> Vec<FkFact> {
        let col_name = col
            .name()
            .and_then(|n| n.ident_token())
            .or_else(|| {
                col.name().and_then(|cn| {
                    cn.syntax()
                        .descendants_with_tokens()
                        .filter_map(|e| e.into_token())
                        .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                })
            })
            .map(|t| Self::resolve_identifier_token(t.text()));
        Self::column_constraints(col)
            .filter_map(|c| {
                if let ColumnConstraint::ReferencesConstraint(rc) = c {
                    let ref_path = rc
                        .table()
                        .and_then(|t| t.path_ref())
                        .and_then(|path| Self::path_ref_to_qualified_name(&path))
                        .or_else(|| {
                            rc.syntax()
                                .descendants()
                                .find_map(Path::cast)
                                .and_then(|p| Self::path_to_qualified_name(&p))
                        })?;
                    Some(FkFact {
                        constraint_name: None,
                        references: ref_path,
                        from_columns: col_name.iter().cloned().collect(),
                        to_columns: Vec::new(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    pub(super) fn extract_table_fk_fact(tc: &TableConstraint) -> Option<FkFact> {
        if let TableConstraint::ForeignKeyConstraint(fkc) = tc {
            let constraint_name = fkc
                .constraint_name_clause()
                .and_then(|cn| cn.constraint_name())
                .and_then(|cn| cn.ident_token())
                .map(|t| Self::resolve_identifier_token(t.text()));
            let path = fkc
                .table_name_ref()
                .and_then(|t| t.path_ref())
                .and_then(|p| Self::path_ref_to_qualified_name(&p))?;
            let references = path;
            let column_lists = Self::extract_foreign_key_column_lists(fkc);
            let from_columns = column_lists.first().cloned().unwrap_or_default();
            let to_columns = column_lists.get(1).cloned().unwrap_or_default();

            return Some(FkFact {
                constraint_name,
                references,
                from_columns,
                to_columns,
            });
        }
        None
    }

    pub(super) fn extract_constraint_column_list_names(
        cl: ast::ConstraintColumnRefList,
    ) -> Vec<String> {
        cl.column_name_refs()
            // Squawk's pg_name keeps legal keyword names as keyword tokens.
            .filter_map(|column| column.syntax().first_token())
            .map(|token| Self::resolve_identifier_token(token.text()))
            .collect()
    }

    pub(super) fn extract_foreign_key_column_lists(
        constraint: &ast::ForeignKeyConstraint,
    ) -> Vec<Vec<String>> {
        // PostgreSQL lists the referencing columns first and referenced columns
        // second. Later lists, such as ON DELETE SET NULL (columns), must not
        // change that positional contract.
        constraint
            .syntax()
            .children()
            .filter_map(ast::ForeignKeyColumnList::cast)
            .map(|list| {
                list.column_name_refs()
                    .filter_map(|column| column.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text()))
                    .collect()
            })
            .collect()
    }

    /// Extract `(resolved_name, raw_spelling)` partition key columns directly
    /// from a typed `PartitionBy` node, without requiring a synthetic re-parse.
    /// Returns an empty `Vec` when any key uses unsupported modifiers (collate,
    /// op-class, expression keys, nulls ordering) so callers fall back to the
    /// text-based `partition_by` field for those cases.
    pub(super) fn partition_keys_from_partition_by(
        partition_by: &PartitionBy,
    ) -> Vec<(String, String)> {
        use squawk_syntax::ast::Expr;
        let Some(list) = partition_by.partition_item_list() else {
            return Vec::new();
        };
        let mut keys = Vec::new();
        for item in list.partition_items() {
            if item.op_class_ref().is_some()
                || item.attribute_list().is_some()
                || item.nulls_order().is_some()
            {
                return Vec::new();
            }
            let Some(expr) = item.expr() else {
                return Vec::new();
            };
            // Walk through any parenthesisation to the inner NameRef.
            let mut current = expr;
            loop {
                match current {
                    Expr::ParenExpr(paren) => match paren.expr() {
                        Some(inner) => current = inner,
                        None => return Vec::new(),
                    },
                    Expr::NameRef(name) => {
                        keys.push((name.text().to_string(), name.syntax().text().to_string()));
                        break;
                    }
                    _ => return Vec::new(),
                }
            }
        }
        keys
    }
}
