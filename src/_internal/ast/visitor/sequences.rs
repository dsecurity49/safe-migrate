use super::*;

impl AstVisitor {
    pub(super) fn extract_create_sequence(node: &CreateSequence) -> Option<StatementFact> {
        let path = node.sequence()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;
        Some(StatementFact::CreateSequence {
            name,
            if_not_exists: node.if_not_exists().is_some(),
            owned_by: node.sequence_options().find_map(|option| match option {
                ast::SequenceOption::OptionOwnedBy(owned_by) => Self::extract_owned_by(&owned_by),
                _ => None,
            }),
            persistence: match node.persistence() {
                Some(squawk_syntax::ast::Persistence::Temp(_)) => PersistenceFact::Temporary,
                Some(squawk_syntax::ast::Persistence::Unlogged(_)) => PersistenceFact::Unlogged,
                _ => PersistenceFact::Permanent,
            },
            options: Self::extract_sequence_options(node.sequence_options())?,
        })
    }

    pub(super) fn extract_alter_sequence(node: &AlterSequence) -> Option<StatementFact> {
        let path = node.sequence_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;

        use crate::_internal::analysis::facts::{
            AlterSequenceActionFact, SequenceOptionFact as OptionFact,
        };
        let integer = |expr: ast::Expr| expr.syntax().text().to_string().trim().parse::<i64>().ok();

        let mut options = Vec::new();
        let mut action: Option<AlterSequenceActionFact> = None;
        for entry in node.actions() {
            let singular = match entry {
                ast::AlterSequenceAction::OwnerTo(owner) => Some(AlterSequenceActionFact::OwnerTo(
                    Self::extract_role(&owner.role_ref()?),
                )),
                ast::AlterSequenceAction::SequenceRenameTo(rename) => {
                    let new_name = Self::path_to_qualified_name(&rename.sequence()?.path()?)?;
                    Some(AlterSequenceActionFact::RenameTo(new_name.name))
                }
                ast::AlterSequenceAction::SetSchema(set_schema) => {
                    let token = set_schema.schema_ref()?.ident_token()?;
                    Some(AlterSequenceActionFact::SetSchema(
                        Self::resolve_identifier_token(token.text()),
                    ))
                }
                ast::AlterSequenceAction::SetLogged(_) => {
                    options.push(OptionFact::Logged(true));
                    None
                }
                ast::AlterSequenceAction::SetUnlogged(_) => {
                    options.push(OptionFact::Logged(false));
                    None
                }
                ast::AlterSequenceAction::SequenceOption(option) => {
                    let option = match option {
                        ast::SequenceOption::OptionAsType(o) => {
                            OptionFact::As(o.ty()?.syntax().text().to_string())
                        }
                        ast::SequenceOption::OptionCache(o) => {
                            OptionFact::Cache(integer(o.expr()?)?)
                        }
                        ast::SequenceOption::OptionCycle(_) => OptionFact::Cycle(true),
                        ast::SequenceOption::OptionNoCycle(_) => OptionFact::Cycle(false),
                        ast::SequenceOption::OptionIncrement(o) => {
                            OptionFact::Increment(integer(o.expr()?)?)
                        }
                        ast::SequenceOption::OptionMaxValue(o) => {
                            OptionFact::MaxValue(Some(integer(o.expr()?)?))
                        }
                        ast::SequenceOption::OptionNoMaxValue(_) => OptionFact::MaxValue(None),
                        ast::SequenceOption::OptionMinValue(o) => {
                            OptionFact::MinValue(Some(integer(o.expr()?)?))
                        }
                        ast::SequenceOption::OptionNoMinValue(_) => OptionFact::MinValue(None),
                        ast::SequenceOption::OptionStart(o) => {
                            OptionFact::Start(integer(o.expr()?)?)
                        }
                        ast::SequenceOption::OptionRestart(o) => {
                            OptionFact::Restart(match o.expr() {
                                Some(expr) => Some(integer(expr)?),
                                None => None,
                            })
                        }
                        ast::SequenceOption::OptionLogged(_) => OptionFact::Logged(true),
                        ast::SequenceOption::OptionUnlogged(_) => OptionFact::Logged(false),
                        ast::SequenceOption::OptionOwnedBy(o) => match o.owned_by_target() {
                            Some(ast::OwnedByTarget::OwnedByNone(_)) => OptionFact::OwnedBy(None),
                            Some(_) => OptionFact::OwnedBy(Some(Self::extract_owned_by(&o)?)),
                            None => return None,
                        },
                        ast::SequenceOption::OptionSequenceName(o) => OptionFact::SequenceName(
                            Self::path_to_qualified_name(&o.sequence()?.path()?)?
                                .name
                                .resolve(),
                        ),
                    };
                    options.push(option);
                    None
                }
            };
            if let Some(singular) = singular {
                // PostgreSQL parses ownership, rename, and schema changes as
                // their own statement kinds, so a statement carrying two of
                // them is not a form it accepts.
                if action.is_some() {
                    return None;
                }
                action = Some(singular);
            }
        }

        // PostgreSQL gives `OWNER TO`, `RENAME TO`, and `SET SCHEMA` their own
        // statement kinds, each of which ends at its own name; a parameter
        // option in the same statement is a syntax error rather than an
        // ordering choice.
        if action.is_some() && !options.is_empty() {
            return None;
        }

        Some(StatementFact::AlterSequence {
            name,
            if_exists: node.if_exists().is_some(),
            options,
            action,
        })
    }

    pub(super) fn extract_drop_sequence(node: &DropSequence) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .sequence_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();

        Some(StatementFact::DropSequence {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    pub(super) fn extract_owned_by(opt: &ast::OptionOwnedBy) -> Option<(QualifiedName, String)> {
        let ast::OwnedByTarget::QualifiedColumnNameRef(name) = opt.owned_by_target()? else {
            return None;
        };
        let path_ref = name.path_ref()?;
        let mut segments = Vec::new();
        let mut current_ref = Some(path_ref);

        while let Some(pr) = current_ref {
            if let Some(segment) = pr.segment() {
                segments.push(Self::identifier_from_name(
                    segment.text(),
                    segment.is_quoted(),
                ));
            }
            current_ref = pr.qualifier();
        }

        segments.reverse();

        if segments.len() < 2 {
            return None;
        }
        let col_name = segments.pop()?.resolve();
        let table_len = segments.len();
        let table_name = if table_len == 1 {
            QualifiedName::new(None, segments[0].clone())
        } else {
            QualifiedName::new(
                Some(segments[table_len - 2].clone()),
                segments[table_len - 1].clone(),
            )
        };
        Some((table_name, col_name))
    }
}
