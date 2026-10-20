use super::*;

impl AstVisitor {
    pub(super) fn extract_create_policy(node: &CreatePolicy) -> Option<StatementFact> {
        let semantics_complete = node.policy_roles().is_none()
            && node.using_expr_clause().is_none()
            && node.with_check_expr_clause().is_none();
        let name_token = node.policy()?.ident_token()?;
        let name = Self::resolve_identifier_token(name_token.text());
        let path = node.on_table()?.table_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&path)?;

        let permissive = if let Some(as_type) = node.as_policy_type() {
            as_type
                .ident_token()
                .map(|t| t.text().to_lowercase())
                .map(|t| t == "permissive")
                .unwrap_or(true)
        } else {
            true
        };

        let command = match node.policy_command().and_then(|command| command.command()) {
            Some(ast::PolicyCommandKind::PolicyCommandSelect(_)) => {
                crate::_internal::analysis::facts::PolicyCommand::Select
            }
            Some(ast::PolicyCommandKind::PolicyCommandInsert(_)) => {
                crate::_internal::analysis::facts::PolicyCommand::Insert
            }
            Some(ast::PolicyCommandKind::PolicyCommandUpdate(_)) => {
                crate::_internal::analysis::facts::PolicyCommand::Update
            }
            Some(ast::PolicyCommandKind::PolicyCommandDelete(_)) => {
                crate::_internal::analysis::facts::PolicyCommand::Delete
            }
            Some(ast::PolicyCommandKind::PolicyCommandAll(_)) | None => {
                crate::_internal::analysis::facts::PolicyCommand::All
            }
        };

        Some(StatementFact::CreatePolicy {
            name,
            table,
            permissive,
            command,
            semantics_complete,
        })
    }

    pub(super) fn extract_drop_policy(node: &DropPolicy) -> Option<StatementFact> {
        let path = node.on_table()?.table_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&path)?;
        let name_token = node.policy_ref()?.ident_token()?;
        let name = Self::resolve_identifier_token(name_token.text());
        Some(StatementFact::DropPolicy {
            name,
            table,
            if_exists: node.if_exists().is_some(),
        })
    }

    pub(super) fn extract_create_trigger(node: &CreateTrigger) -> Option<StatementFact> {
        let name_token = node.trigger()?.ident_token()?;
        let name = Self::resolve_identifier_token(name_token.text());
        let path = node.on_relation()?.relation_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&path)?;
        let function = node
            .call_expr()
            .and_then(|call| call.expr())
            .and_then(Self::expr_to_qualified_name);
        Some(StatementFact::CreateTrigger {
            name,
            table,
            function,
            row_level: matches!(node.trigger_level(), Some(ast::TriggerLevel::ForEachRow(_))),
        })
    }

    pub(super) fn extract_drop_trigger(node: &DropTrigger) -> Option<StatementFact> {
        let trigger_token = node.trigger_ref()?.ident_token()?;
        let trigger_name = Self::resolve_identifier_token(trigger_token.text());
        let table_path = node.on_relation()?.relation_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&table_path)?;
        Some(StatementFact::DropTrigger {
            name: trigger_name,
            table,
            if_exists: node.if_exists().is_some(),
        })
    }

    pub(super) fn extract_alter_trigger(node: &AlterTrigger) -> Option<StatementFact> {
        let name = Self::resolve_identifier_token(node.trigger_ref()?.ident_token()?.text());
        let table_path = node.on_relation()?.relation_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&table_path)?;
        let ast::AlterTriggerAction::TriggerRenameTo(rename) = node.action()? else {
            return None;
        };
        let new_name = Self::resolve_identifier_token(rename.trigger()?.ident_token()?.text());
        Some(StatementFact::AlterTrigger {
            name,
            table,
            new_name,
        })
    }
}
