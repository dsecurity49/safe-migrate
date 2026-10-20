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
                .and_then(|n| n.ident_token())
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
                    f.language_ref()
                        .and_then(|lr| lr.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
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
            ast::FuncOption::CostFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Cost
            }
            ast::FuncOption::RowsFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Rows
            }
            ast::FuncOption::ResetFuncOption(f) => {
                crate::_internal::analysis::facts::FuncOptionFact::Reset(
                    f.config_parameter_ref()
                        .and_then(|cpr| cpr.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve())
                        .unwrap_or_default(),
                )
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
            ast::FuncOption::SupportFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Support
            }
            _ => crate::_internal::analysis::facts::FuncOptionFact::Unknown,
        }
    }

    pub(super) fn extract_create_function(
        node: &squawk_syntax::ast::CreateFunction,
    ) -> Option<StatementFact> {
        let path = node.name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;
        let or_replace = node.or_replace().is_some();
        let params = node
            .param_list()
            .map(|pl| pl.params().map(|p| Self::extract_param(&p)).collect())
            .unwrap_or_default();
        let return_type = node.ret_type().map(|r| Self::extract_ret_type(&r));
        let options = node
            .option_list()
            .map(|ol| {
                ol.options()
                    .map(|o| Self::extract_func_option(&o))
                    .collect()
            })
            .unwrap_or_default();

        Some(StatementFact::CreateFunction(
            crate::_internal::analysis::facts::CreateFunctionFact {
                name,
                or_replace,
                params,
                return_type,
                options,
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
            ast::AlterFunctionAction::SetSchema(ss) => {
                let token = ss.schema_ref()?.ident_token()?;
                Some(
                    crate::_internal::analysis::facts::AlterFunctionAction::SchemaChange {
                        new_schema: Self::resolve_identifier_token(token.text()),
                    },
                )
            }
            ast::AlterFunctionAction::DependsOnExtension(de) => {
                let ext = Self::resolve_identifier_token(de.extension_ref()?.ident_token()?.text());
                Some(
                    crate::_internal::analysis::facts::AlterFunctionAction::DependsOnExtension {
                        extension: ext,
                    },
                )
            }
            ast::AlterFunctionAction::NoDependsOnExtension(nde) => {
                let ext =
                    Self::resolve_identifier_token(nde.extension_ref()?.ident_token()?.text());
                Some(
                    crate::_internal::analysis::facts::AlterFunctionAction::NoDependsOnExtension {
                        extension: ext,
                    },
                )
            }
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
        let params = node
            .param_list()
            .map(|pl| pl.params().map(|p| Self::extract_param(&p)).collect())
            .unwrap_or_default();
        let options = node
            .option_list()
            .map(|ol| {
                ol.options()
                    .map(|o| Self::extract_func_option(&o))
                    .collect()
            })
            .unwrap_or_default();

        Some(StatementFact::CreateProcedure(
            crate::_internal::analysis::facts::CreateProcedureFact {
                name,
                or_replace,
                params,
                options,
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
                    new_schema: Self::resolve_identifier_token(
                        ss.schema_ref()?.ident_token()?.text(),
                    ),
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
            _ => None,
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
                params
                    .params()
                    .chain(
                        params
                            .aggregate_order_by()
                            .into_iter()
                            .flat_map(|order_by| order_by.params()),
                    )
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

    pub(super) fn extract_create_aggregate(node: &ast::CreateAggregate) -> Option<StatementFact> {
        let name = Self::path_to_qualified_name(&node.aggregate_name()?.path()?)?;
        let attributes = Self::extract_attribute_list(node.attribute_list());
        let params = if let Some(params) = node.param_list() {
            params
                .params()
                .map(|param| Self::extract_param(&param))
                .collect()
        } else {
            attributes
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
                .unwrap_or_default()
        };
        Some(StatementFact::CreateAggregate(
            crate::_internal::analysis::facts::CreateAggregateFact {
                name,
                or_replace: node.or_replace().is_some(),
                params,
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
}
