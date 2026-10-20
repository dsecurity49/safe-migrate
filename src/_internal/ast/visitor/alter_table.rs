use super::*;

impl AstVisitor {
    pub(super) fn extract_alter_table(node: &AlterTable) -> Option<StatementFact> {
        let path = node.table_relation_name()?.table_name_ref()?.path_ref()?;
        let table_name = Self::path_ref_to_qualified_name(&path)?;
        let mut actions = Vec::new();
        let mut unsupported_action = false;

        for action in node.actions() {
            if let Some(ap) = AttachPartition::cast(action.syntax().clone()) {
                if let Some(child) = ap
                    .table_name_ref()
                    .and_then(|tn| tn.path_ref())
                    .and_then(|p| Self::path_ref_to_qualified_name(&p))
                {
                    let strategy = match ap.partition_type() {
                        Some(PartitionType::PartitionForValuesIn(_)) => Some("LIST".to_string()),
                        Some(PartitionType::PartitionForValuesFrom(_)) => Some("RANGE".to_string()),
                        Some(PartitionType::PartitionForValuesWith(_)) => Some("HASH".to_string()),
                        Some(PartitionType::PartitionDefault(_)) | None => None,
                    };
                    let bound = ap
                        .partition_type()
                        .map(|bound| bound.syntax().text().to_string());
                    actions.push(AlterTableActionFact::AttachPartition {
                        child,
                        strategy,
                        bound,
                    });
                }
                continue;
            }
            if let Some(dp) = DetachPartition::cast(action.syntax().clone()) {
                if let Some(child) = dp
                    .table_name_ref()
                    .and_then(|tn| tn.path_ref())
                    .and_then(|p| Self::path_ref_to_qualified_name(&p))
                {
                    let mode = match dp.detach_partition_option() {
                        Some(ast::DetachPartitionOption::DetachConcurrently(_)) => {
                            crate::_internal::analysis::facts::DetachPartitionMode::Concurrently
                        }
                        Some(ast::DetachPartitionOption::DetachFinalize(_)) => {
                            crate::_internal::analysis::facts::DetachPartitionMode::Finalize
                        }
                        None => crate::_internal::analysis::facts::DetachPartitionMode::Immediate,
                    };
                    actions.push(AlterTableActionFact::DetachPartition { child, mode });
                }
                continue;
            }
            if let Some(ac) = AlterConstraint::cast(action.syntax().clone()) {
                let deferrable = ac.constraint_options().any(|option| {
                    matches!(option, ast::ConstraintOption::DeferrableConstraintOption(_))
                });
                let name = ac
                    .constraint_name_ref()
                    .and_then(|name| name.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path))
                    .map(|name| name.name.resolve());
                actions.push(AlterTableActionFact::AlterConstraint { name, deferrable });
                continue;
            }
            if let Some(rc) = ast::RenameConstraint::cast(action.syntax().clone()) {
                let old_name = rc
                    .constraint_name_ref()
                    .and_then(|name| name.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path))
                    .map(|name| name.name.resolve());
                let new_name = rc
                    .constraint_name()
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text()));
                if let (Some(old_name), Some(new_name)) = (old_name, new_name) {
                    actions.push(AlterTableActionFact::RenameConstraint { old_name, new_name });
                }
                continue;
            }

            match action {
                AlterTableAction::AddColumn(add) => {
                    if let Some(name) = add
                        .column_name()
                        .and_then(|n| n.ident_token())
                        .or_else(|| {
                            add.column_name().and_then(|cn| {
                                cn.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                            })
                        })
                        .map(|n| Self::resolve_identifier_token(n.text()))
                    {
                        let mut not_null = false;
                        let mut default = None;
                        let mut generation =
                            crate::_internal::analysis::facts::ColumnGeneration::Ordinary;
                        let mut identity_sequence = None;
                        let mut generated_expr = None;
                        let mut generated_expr_sql = None;
                        for c in add.constraints() {
                            match c {
                                Constraint::NotNullConstraint(_) => not_null = true,
                                Constraint::PrimaryKeyConstraint(_) => not_null = true,
                                Constraint::DefaultConstraint(dc) => default = dc.expr().map(
                                    crate::_internal::analysis::expr_visitor::ExprVisitor::convert,
                                ),
                                Constraint::GeneratedConstraint(generated)
                                    if matches!(
                                        generated.generated_as(),
                                        Some(ast::GeneratedAs::GeneratedIdentity(_))
                                    ) =>
                                {
                                    let Some(ast::GeneratedAs::GeneratedIdentity(identity)) =
                                        generated.generated_as()
                                    else {
                                        unreachable!("guard requires an identity clause")
                                    };
                                    generation = match identity.generated_when() {
                                        Some(ast::GeneratedWhen::GeneratedAlways(_)) => crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways,
                                        Some(ast::GeneratedWhen::GeneratedByDefault(_)) => crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault,
                                        None => return None,
                                    };
                                    identity_sequence =
                                        Some(Box::new(Self::identity_sequence_options(&identity)?));
                                    not_null = true;
                                }
                                Constraint::GeneratedConstraint(generated)
                                    if matches!(
                                        generated.generated_as(),
                                        Some(ast::GeneratedAs::GeneratedStored(_))
                                    ) =>
                                {
                                    generation = match generated.generated_as() {
                                        Some(ast::GeneratedAs::GeneratedStored(stored)) => match stored.generated_kind() {
                                            Some(ast::GeneratedKind::Stored(_)) => crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored,
                                            Some(ast::GeneratedKind::Virtual(_)) => crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual,
                                            None => return None,
                                        },
                                        _ => unreachable!("guard requires a generated expression"),
                                    };
                                    generated_expr_sql = match generated.generated_as() {
                                        Some(ast::GeneratedAs::GeneratedStored(stored)) => stored
                                            .expr()
                                            .map(|expr| expr.syntax().text().to_string()),
                                        _ => None,
                                    };
                                    generated_expr = match generated.generated_as() {
                                        Some(ast::GeneratedAs::GeneratedStored(stored)) => stored.expr().map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert),
                                        _ => None,
                                    };
                                }
                                _ => {}
                            }
                        }
                        actions.push(AlterTableActionFact::AddColumn {
                            name,
                            ty: add.ty().map(|t| t.syntax().text().to_string()),
                            if_not_exists: add.if_not_exists().is_some(),
                            not_null,
                            default,
                            generation: if Self::is_serial_type(
                                add.ty().map(|ty| ty.syntax().text().to_string()).as_deref(),
                            ) {
                                crate::_internal::analysis::facts::ColumnGeneration::Serial
                            } else {
                                generation
                            },
                            identity_sequence,
                            generated_expr,
                            generated_expr_sql,
                        });
                    }
                }
                AlterTableAction::DropColumn(drop) => {
                    if let Some(name) = drop
                        .column_name_ref()
                        .and_then(|n| n.ident_token())
                        .or_else(|| {
                            drop.column_name_ref().and_then(|cnr| {
                                cnr.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                            })
                        })
                        .map(|n| Self::resolve_identifier_token(n.text()))
                    {
                        actions.push(AlterTableActionFact::DropColumn {
                            name,
                            if_exists: drop.if_exists().is_some(),
                            cascade: Self::is_cascade(drop.drop_behavior()),
                        });
                    }
                }
                AlterTableAction::RenameColumn(rc) => {
                    let from_ident = rc
                        .column_name_ref()
                        .and_then(|nr| nr.ident_token())
                        .map(|nr| Self::identifier_from_token(nr.text()))
                        .or_else(|| {
                            rc.syntax()
                                .descendants()
                                .find_map(NameRef::cast)
                                .map(|nr| Self::identifier_from_name(nr.text(), nr.is_quoted()))
                        })
                        .or_else(|| {
                            rc.column_name_ref().and_then(|cnr| {
                                cnr.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                                    .map(|t| Self::identifier_from_token(t.text()))
                            })
                        });

                    let to_ident = rc
                        .column_name()
                        .and_then(|n| n.ident_token())
                        .map(|nr| Self::identifier_from_token(nr.text()))
                        .or_else(|| {
                            rc.syntax()
                                .descendants()
                                .find_map(PathSegment::cast)
                                .map(|n| Self::identifier_from_name(n.text(), n.is_quoted()))
                        })
                        .or_else(|| {
                            rc.column_name().and_then(|cn| {
                                cn.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                                    .map(|t| Self::identifier_from_token(t.text()))
                            })
                        });

                    if let (Some(from), Some(to)) = (from_ident, to_ident) {
                        actions.push(AlterTableActionFact::RenameColumn { from, to });
                    }
                }
                AlterTableAction::TableRenameTo(rt) => {
                    if let Some(new_name) = rt
                        .table_name()
                        .and_then(|t| t.path())
                        .and_then(|p| Self::path_to_qualified_name(&p))
                    {
                        actions.push(AlterTableActionFact::RenameTo {
                            new_name: new_name.name,
                        });
                    }
                }
                AlterTableAction::AddConstraint(ac) => {
                    if let Some(fact) = Self::extract_add_constraint_fact(&ac) {
                        actions.push(fact);
                    } else {
                        // A typed but unmodeled constraint kind must not be
                        // mistaken for an exact no-op.
                        unsupported_action = true;
                    }
                }
                AlterTableAction::DropConstraint(dc) => {
                    if let Some(name) = dc
                        .constraint_name_ref()
                        .and_then(|nr| nr.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve())
                    {
                        actions.push(AlterTableActionFact::DropConstraint {
                            name,
                            if_exists: dc.if_exists().is_some(),
                            cascade: Self::is_cascade(dc.drop_behavior()),
                        });
                    }
                }
                AlterTableAction::AlterColumn(alter_col) => {
                    let col_ident = alter_col
                        .column_name_ref()
                        .and_then(|c| c.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
                        .or_else(|| {
                            alter_col
                                .syntax()
                                .descendants()
                                .find_map(PathSegment::cast)
                                .map(Self::resolve_name)
                        })
                        .or_else(|| {
                            alter_col.column_name_ref().and_then(|cnr| {
                                cnr.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                                    .map(|t| Self::resolve_identifier_token(t.text()))
                            })
                        });

                    if let (Some(col_name), Some(opt)) = (col_ident, alter_col.option()) {
                        if let Some(fact) = Self::extract_alter_column_option(col_name, opt) {
                            actions.push(fact);
                        } else {
                            // A typed but unmodeled column option must not be
                            // mistaken for an exact no-op.
                            unsupported_action = true;
                        }
                    } else {
                        unsupported_action = true;
                    }
                }
                AlterTableAction::ValidateConstraint(vc) => {
                    if let Some(constraint_name) = vc
                        .constraint_name_ref()
                        .and_then(|name| name.path_ref())
                        .and_then(|path| Self::path_ref_to_qualified_name(&path))
                        .map(|name| name.name.resolve())
                    {
                        actions.push(AlterTableActionFact::ValidateConstraint { constraint_name });
                    }
                }
                AlterTableAction::SetAccessMethod(sam) => {
                    let access_method = sam
                        .access_method_ref()
                        .and_then(|method| method.ident_token())
                        .map(|token| Self::resolve_identifier_token(token.text()));
                    actions.push(AlterTableActionFact::SetAccessMethod { access_method });
                }
                AlterTableAction::DisableTrigger(dt) => {
                    let trigger_name = match dt.trigger_target() {
                        Some(ast::TriggerTarget::TriggerRef(trigger)) => trigger
                            .ident_token()
                            .map(|name| Self::resolve_identifier_token(name.text())),
                        Some(ast::TriggerTarget::All(_)) => Some("ALL".to_string()),
                        // Constraint triggers are modeled as constraints, not
                        // entries in the user-trigger catalog. Preserve USER
                        // so state can target every tracked user trigger.
                        Some(ast::TriggerTarget::User(_)) => Some("USER".to_string()),
                        None => {
                            unsupported_action = true;
                            continue;
                        }
                    };
                    actions.push(AlterTableActionFact::DisableTrigger { trigger_name });
                }
                AlterTableAction::EnableTrigger(et) => {
                    let trigger_name = match et.trigger_target() {
                        Some(ast::TriggerTarget::TriggerRef(trigger)) => trigger
                            .ident_token()
                            .map(|name| Self::resolve_identifier_token(name.text())),
                        Some(ast::TriggerTarget::All(_)) => Some("ALL".to_string()),
                        Some(ast::TriggerTarget::User(_)) => Some("USER".to_string()),
                        None => {
                            unsupported_action = true;
                            continue;
                        }
                    };
                    actions.push(AlterTableActionFact::EnableTrigger { trigger_name });
                }
                AlterTableAction::SetSchema(ss) => match ss.schema_ref() {
                    Some(schema_ref) => actions.push(AlterTableActionFact::SetSchema {
                        new_schema: Self::resolve_schema_ref(&schema_ref),
                    }),
                    None => unsupported_action = true,
                },
                AlterTableAction::SetTablespace(st) => {
                    match st.tablespace_ref().and_then(|tr| tr.ident_token()) {
                        Some(token) => {
                            let tablespace = Self::resolve_identifier_token(token.text());
                            actions.push(AlterTableActionFact::SetTablespace { tablespace });
                        }
                        None => unsupported_action = true,
                    }
                }
                AlterTableAction::OwnerTo(ot) => match ot.role_ref() {
                    Some(role) => {
                        actions.push(AlterTableActionFact::OwnerTo {
                            new_owner: Self::extract_role(&role),
                        });
                    }
                    None => unsupported_action = true,
                },
                AlterTableAction::SetLogged(_) => {
                    actions.push(AlterTableActionFact::SetLogged);
                }
                AlterTableAction::SetUnlogged(_) => {
                    actions.push(AlterTableActionFact::SetUnlogged);
                }
                AlterTableAction::ReplicaIdentity(ri) => {
                    let option = match ri.replica_identity_option() {
                        Some(ast::ReplicaIdentityOption::ReplicaIdentityDefault(_)) => {
                            ReplicaIdentityFact::Default
                        }
                        Some(ast::ReplicaIdentityOption::ReplicaIdentityFull(_)) => {
                            ReplicaIdentityFact::Full
                        }
                        Some(ast::ReplicaIdentityOption::ReplicaIdentityNothing(_)) => {
                            ReplicaIdentityFact::Nothing
                        }
                        Some(ast::ReplicaIdentityOption::UsingIndexName(using_index)) => {
                            using_index
                                .index_ref()
                                .and_then(|index| index.path_ref())
                                .and_then(|path| Self::path_ref_to_qualified_name(&path))
                                .map(ReplicaIdentityFact::UsingIndex)
                                .unwrap_or_else(|| {
                                    unsupported_action = true;
                                    ReplicaIdentityFact::Default
                                })
                        }
                        None => {
                            unsupported_action = true;
                            ReplicaIdentityFact::Default
                        }
                    };
                    actions.push(AlterTableActionFact::ReplicaIdentity { option });
                }
                AlterTableAction::ClusterOn(co) => {
                    let index = co
                        .index_ref()
                        .and_then(|ir| ir.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr));
                    if let Some(index) = index {
                        actions.push(AlterTableActionFact::ClusterOn { index });
                    } else {
                        unsupported_action = true;
                    }
                }
                AlterTableAction::SetWithoutCluster(_) => {
                    actions.push(AlterTableActionFact::SetWithoutCluster);
                }
                AlterTableAction::SetOptions(options) => {
                    if let Some(attributes) =
                        Self::extract_attribute_options(options.attribute_list())
                    {
                        actions.push(AlterTableActionFact::SetTableOptions { attributes });
                    } else {
                        unsupported_action = true;
                    }
                }
                AlterTableAction::ResetOptions(options) => {
                    if let Some(attributes) =
                        Self::extract_attribute_options_raw(options.attribute_list())
                    {
                        actions.push(AlterTableActionFact::ResetTableOptions { attributes });
                    } else {
                        unsupported_action = true;
                    }
                }
                AlterTableAction::InheritTable(it) => {
                    if let Some(path) = it.table_name_ref().and_then(|t| t.path_ref())
                        && let Some(parent) = Self::path_ref_to_qualified_name(&path)
                    {
                        actions.push(AlterTableActionFact::InheritTable { parent });
                    }
                }
                AlterTableAction::NoInheritTable(nit) => {
                    if let Some(path) = nit.table_name_ref().and_then(|t| t.path_ref())
                        && let Some(parent) = Self::path_ref_to_qualified_name(&path)
                    {
                        actions.push(AlterTableActionFact::NoInheritTable { parent });
                    }
                }
                AlterTableAction::OfType(of_type) => {
                    let type_name = of_type.ty().and_then(|ty| match ty {
                        ast::Type::PathType(path_type)
                            if path_type.arg_list().is_none()
                                && path_type.setof_token().is_none() =>
                        {
                            path_type
                                .path_ref()
                                .and_then(|path| Self::path_ref_to_qualified_name(&path))
                        }
                        _ => None,
                    });
                    if let Some(type_name) = type_name {
                        actions.push(AlterTableActionFact::OfType { type_name });
                    } else {
                        unsupported_action = true;
                    }
                }
                AlterTableAction::NotOf(_) => actions.push(AlterTableActionFact::NotOf),
                AlterTableAction::MergePartitions(mp) => {
                    if let Some(path) = mp.table_name().and_then(|t| t.path())
                        && let Some(parent) = Self::path_to_qualified_name(&path)
                    {
                        actions.push(AlterTableActionFact::MergePartitions { parent });
                    }
                }
                AlterTableAction::SplitPartition(_sp) => {
                    actions.push(AlterTableActionFact::SplitPartition);
                }
                AlterTableAction::ForceRls(_) => {
                    actions.push(AlterTableActionFact::ForceRls);
                }
                AlterTableAction::NoForceRls(_) => {
                    actions.push(AlterTableActionFact::NoForceRls);
                }
                AlterTableAction::EnableRls(_) => {
                    actions.push(AlterTableActionFact::EnableRls);
                }
                AlterTableAction::DisableRls(_) => {
                    actions.push(AlterTableActionFact::DisableRls);
                }
                AlterTableAction::EnableRule(rule) => {
                    actions.push(AlterTableActionFact::SetRuleMode {
                        rule_name: rule
                            .rule_ref()
                            .and_then(|rule| rule.ident_token())
                            .map(|token| Self::resolve_identifier_token(token.text())),
                        mode: crate::_internal::analysis::facts::RuleEnableModeFact::Origin,
                    });
                }
                AlterTableAction::DisableRule(rule) => {
                    actions.push(AlterTableActionFact::SetRuleMode {
                        rule_name: rule
                            .rule_ref()
                            .and_then(|rule| rule.ident_token())
                            .map(|token| Self::resolve_identifier_token(token.text())),
                        mode: crate::_internal::analysis::facts::RuleEnableModeFact::Disabled,
                    });
                }
                AlterTableAction::EnableReplicaRule(rule) => {
                    actions.push(AlterTableActionFact::SetRuleMode {
                        rule_name: rule
                            .rule_ref()
                            .and_then(|rule| rule.ident_token())
                            .map(|token| Self::resolve_identifier_token(token.text())),
                        mode: crate::_internal::analysis::facts::RuleEnableModeFact::Replica,
                    });
                }
                AlterTableAction::EnableAlwaysRule(rule) => {
                    actions.push(AlterTableActionFact::SetRuleMode {
                        rule_name: rule
                            .rule_ref()
                            .and_then(|rule| rule.ident_token())
                            .map(|token| Self::resolve_identifier_token(token.text())),
                        mode: crate::_internal::analysis::facts::RuleEnableModeFact::Always,
                    });
                }
                AlterTableAction::EnableAlwaysTrigger(eat) => {
                    let trigger_name = eat
                        .trigger_ref()
                        .and_then(|tr| tr.ident_token())
                        .map(|n| Self::resolve_identifier_token(n.text()))
                        .or_else(|| {
                            eat.syntax()
                                .descendants()
                                .find_map(NameRef::cast)
                                .map(|nr| Self::resolve_name_ref(&nr))
                        });
                    actions.push(AlterTableActionFact::EnableAlwaysTrigger { trigger_name });
                }
                AlterTableAction::EnableReplicaTrigger(ert) => {
                    let trigger_name = ert
                        .trigger_ref()
                        .and_then(|tr| tr.ident_token())
                        .map(|n| Self::resolve_identifier_token(n.text()))
                        .or_else(|| {
                            ert.syntax()
                                .descendants()
                                .find_map(NameRef::cast)
                                .map(|nr| Self::resolve_name_ref(&nr))
                        });
                    actions.push(AlterTableActionFact::EnableReplicaTrigger { trigger_name });
                }
                _ => {
                    let txt = action.syntax().text().to_string().to_lowercase();

                    if txt.contains("set storage") {
                        // A storage clause belongs to the typed ALTER COLUMN
                        // option path. If Squawk does not expose that child,
                        // preserve conservative handling instead of guessing
                        // its target or mode from source text.
                        unsupported_action = true;
                    } else {
                        // Parser-accepted actions that are not represented in
                        // our fact model must take the engine's explicit
                        // opaque path instead of becoming an exact no-op.
                        unsupported_action = true;
                    }
                }
            }
        }

        // The parser does not always put SET SCHEMA in the action list, so
        // fall back to the direct child when the loop did not supply one.
        for child in node.syntax().children() {
            if let Some(ss) = SetSchema::cast(child)
                && !actions
                    .iter()
                    .any(|a| matches!(a, AlterTableActionFact::SetSchema { .. }))
                && let Some(schema_ref) = ss.schema_ref()
            {
                actions.push(AlterTableActionFact::SetSchema {
                    new_schema: Self::resolve_schema_ref(&schema_ref),
                });
            }
        }
        if unsupported_action {
            return None;
        }

        Some(StatementFact::AlterTable {
            name: table_name,
            only: node.table_relation_name()?.only_token().is_some(),
            actions,
        })
    }

    pub(super) fn extract_alter_column_option(
        col_name: String,
        opt: AlterColumnOption,
    ) -> Option<AlterTableActionFact> {
        match opt {
            AlterColumnOption::SetStorage(storage) => Some(AlterTableActionFact::SetStorage {
                column: col_name,
                mode: storage
                    .storage_mode()?
                    .syntax()
                    .text()
                    .to_string()
                    .to_ascii_uppercase(),
            }),
            AlterColumnOption::SetCompression(compression) => {
                let method = compression.compression_method_name()?;
                Some(AlterTableActionFact::SetCompression {
                    column: col_name,
                    method: method
                        .ident_token()
                        .map(|token| Self::resolve_identifier_token(token.text())),
                })
            }
            AlterColumnOption::SetStatistics(statistics) => {
                let target = if statistics.default_token().is_some() {
                    None
                } else {
                    Some(
                        statistics
                            .expr()?
                            .syntax()
                            .text()
                            .to_string()
                            .parse::<i32>()
                            .ok()?,
                    )
                };
                Some(AlterTableActionFact::SetStatistics {
                    column: col_name,
                    target,
                })
            }
            AlterColumnOption::DropExpression(drop_expression) => {
                Some(AlterTableActionFact::DropExpression {
                    column: col_name,
                    if_exists: drop_expression.if_exists().is_some(),
                })
            }
            AlterColumnOption::SetNotNull(_) => {
                Some(AlterTableActionFact::SetNotNull { column: col_name })
            }
            AlterColumnOption::DropNotNull(_) => {
                Some(AlterTableActionFact::DropNotNull { column: col_name })
            }
            AlterColumnOption::SetType(st) => {
                let has_using = st.using_expr().is_some();
                Some(AlterTableActionFact::SetType {
                    column: col_name,
                    ty: st.ty()?.syntax().text().to_string(),
                    has_using,
                })
            }
            AlterColumnOption::SetDefault(sd) => Some(AlterTableActionFact::SetDefault {
                column: col_name,
                default: sd
                    .expr()
                    .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert),
            }),
            AlterColumnOption::DropDefault(_) => Some(AlterTableActionFact::SetDefault {
                column: col_name,
                default: None,
            }),
            AlterColumnOption::SetExpression(se) => Some(AlterTableActionFact::SetExpression {
                column: col_name,
                expression_sql: se.expr()?.syntax().text().to_string(),
                expr: se
                    .expr()
                    .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                    .unwrap_or(ExprIr::Omitted),
            }),
            AlterColumnOption::SetOptions(options) => Some(AlterTableActionFact::SetOptions {
                column: col_name,
                attributes: Self::extract_attribute_options(options.attribute_list())?,
            }),
            AlterColumnOption::ResetOptions(options) => Some(AlterTableActionFact::ResetOptions {
                column: col_name,
                attributes: Self::extract_attribute_options_raw(options.attribute_list())?,
            }),
            AlterColumnOption::Inherit(i) => Some(AlterTableActionFact::Inherit {
                column: col_name,
                parent: i
                    .syntax()
                    .descendants()
                    .find_map(Path::cast)
                    .and_then(|p| Self::path_to_qualified_name(&p))
                    .unwrap_or_else(|| {
                        QualifiedName::new(None, Ident::new("unknown".to_string(), false))
                    }),
            }),
            AlterColumnOption::NoInherit(ni) => Some(AlterTableActionFact::NoInherit {
                column: col_name,
                parent: ni
                    .syntax()
                    .descendants()
                    .find_map(Path::cast)
                    .and_then(|p| Self::path_to_qualified_name(&p))
                    .unwrap_or_else(|| {
                        QualifiedName::new(None, Ident::new("unknown".to_string(), false))
                    }),
            }),
            _ => None,
        }
    }

    /// The option's namespace, normalized the way PostgreSQL folds an
    /// unquoted identifier. `None` when the SQL gave a bare name.
    pub(super) fn attribute_namespace(option: &ast::AttributeOption) -> Option<String> {
        option.namespace().map(|namespace| {
            Self::resolve_identifier_token(namespace.syntax().text().to_string().trim())
        })
    }

    /// The options of a `SET (...)` list. A name written without a value means
    /// `true`, as the server's `transformRelOptions` reads it.
    pub(super) fn extract_attribute_options(
        list: Option<ast::AttributeList>,
    ) -> Option<Vec<crate::_internal::analysis::facts::AttributeFact>> {
        let mut attributes = Self::extract_attribute_options_raw(list)?;
        for attribute in &mut attributes {
            if attribute.value.is_none() {
                attribute.value = Some("true".to_string());
            }
        }
        Some(attributes)
    }

    /// The options of a `SET`/`RESET` list with the value exactly as written. A
    /// missing value stays `None`, which is how a `RESET` tells that PostgreSQL
    /// would refuse the value it carries.
    pub(super) fn extract_attribute_options_raw(
        list: Option<ast::AttributeList>,
    ) -> Option<Vec<crate::_internal::analysis::facts::AttributeFact>> {
        let attributes = list?
            .attribute_options()
            .map(|option| {
                Some(crate::_internal::analysis::facts::AttributeFact {
                    name: Self::resolve_identifier_token(
                        option.name()?.syntax().text().to_string().trim(),
                    ),
                    // A string literal is read as the value it spells, so an
                    // explicitly empty one is the empty string, not its quotes.
                    value: option.attribute_value().map(|value| {
                        value
                            .literal()
                            .and_then(|literal| Self::resolve_string_literal(&literal))
                            .unwrap_or_else(|| value.syntax().text().to_string().trim().to_string())
                    }),
                    namespace: Self::attribute_namespace(&option),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        (!attributes.is_empty()).then_some(attributes)
    }

    pub(super) fn extract_add_constraint_fact(
        ac: &squawk_syntax::ast::AddConstraint,
    ) -> Option<AlterTableActionFact> {
        let constraint = ac.constraint()?;
        match constraint {
            ast::Constraint::ForeignKeyConstraint(fkc) => {
                let not_valid = fkc
                    .constraint_options()
                    .any(|option| matches!(option, ast::ConstraintOption::NotValid(_)));
                let constraint_name = fkc
                    .constraint_name_clause()
                    .and_then(|cn| cn.constraint_name())
                    .and_then(|cn| cn.ident_token())
                    .map(|t| Self::resolve_identifier_token(t.text()))
                    .or_else(|| {
                        fkc.syntax()
                            .descendants()
                            .find_map(ast::ConstraintName::cast)
                            .and_then(|cn| cn.ident_token())
                            .map(|t| Self::resolve_identifier_token(t.text()))
                    });
                let path = fkc.table_name_ref()?.path_ref()?;
                let references = Self::path_ref_to_qualified_name(&path)?;
                let column_lists = Self::extract_foreign_key_column_lists(&fkc);
                Some(AlterTableActionFact::AddForeignKey {
                    constraint_name,
                    references,
                    from_columns: column_lists.first().cloned().unwrap_or_default(),
                    to_columns: column_lists.get(1).cloned().unwrap_or_default(),
                    not_valid,
                })
            }
            ast::Constraint::CheckConstraint(cc) => {
                let not_valid = cc
                    .constraint_options()
                    .any(|option| matches!(option, ast::ConstraintOption::NotValid(_)));
                let constraint_name = cc
                    .constraint_name_clause()
                    .and_then(|cn| cn.constraint_name())
                    .and_then(|cn| cn.ident_token())
                    .map(|t| Self::resolve_identifier_token(t.text()))
                    .or_else(|| {
                        cc.syntax()
                            .descendants()
                            .find_map(ast::ConstraintName::cast)
                            .and_then(|cn| cn.ident_token())
                            .map(|t| Self::resolve_identifier_token(t.text()))
                    });
                let (columns, columns_complete) = cc
                    .expr()
                    .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                    .map(Self::expr_columns_with_completeness)
                    .unwrap_or((Vec::new(), false));
                Some(AlterTableActionFact::AddCheckConstraint {
                    constraint_name,
                    definition: cc.expr()?.syntax().text().to_string(),
                    columns,
                    columns_complete,
                    not_valid,
                })
            }
            ast::Constraint::UniqueConstraint(unique) => {
                let constraint_name = unique
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text()));
                let using_index = unique
                    .using_index()
                    .and_then(|using_index| using_index.index_ref())
                    .and_then(|index_ref| index_ref.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path));
                let columns = unique
                    .index_parameters()
                    .and_then(|params| params.column_list())
                    .map(Self::extract_constraint_column_list_names)
                    .unwrap_or_default();
                Some(AlterTableActionFact::AddUniqueConstraint {
                    constraint_name,
                    columns,
                    using_index,
                })
            }
            ast::Constraint::PrimaryKeyConstraint(primary_key) => {
                let constraint_name = primary_key
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text()));
                let using_index = primary_key
                    .using_index()
                    .and_then(|using_index| using_index.index_ref())
                    .and_then(|index_ref| index_ref.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path));
                let columns = primary_key
                    .index_parameters()
                    .and_then(|params| params.column_list())
                    .map(Self::extract_constraint_column_list_names)
                    .unwrap_or_default();
                Some(AlterTableActionFact::AddPrimaryKeyConstraint {
                    constraint_name,
                    columns,
                    using_index,
                })
            }
            ast::Constraint::ExcludeConstraint(exclusion) => {
                let constraint_name = exclusion
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text()));
                let mut columns_complete = true;
                let columns = exclusion
                    .constraint_exclusion_list()
                    .map(|list| {
                        list.constraint_exclusions()
                            .filter_map(|item| item.expr())
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
                Some(AlterTableActionFact::AddExcludeConstraint {
                    constraint_name,
                    columns,
                    columns_complete,
                })
            }
            _ => None,
        }
    }
}
