use super::*;

impl AstVisitor {
    pub(super) fn extract_rollback(node: &Rollback) -> Option<StatementFact> {
        match node {
            Rollback::RollbackPrepared(_) => Some(StatementFact::OpaqueBlock),
            Rollback::RollbackToSavepoint(rollback) => rollback
                .savepoint_ref()
                .and_then(|savepoint| savepoint.ident_token())
                .map(|token| StatementFact::RollbackToSavepoint {
                    name: Self::resolve_identifier_token(token.text()),
                }),
            Rollback::RollbackTransaction(rollback)
                if Self::is_and_chain(rollback.chain_clause()) =>
            {
                Some(StatementFact::RollbackAndChain)
            }
            Rollback::RollbackTransaction(_) => Some(StatementFact::RollbackTransaction),
        }
    }

    pub(super) fn extract_savepoint(node: &squawk_syntax::ast::SavepointCreate) -> StatementFact {
        StatementFact::Savepoint {
            name: node
                .savepoint()
                .and_then(|s| s.ident_token())
                .map(|n| Self::resolve_identifier_token(n.text()))
                .unwrap_or_default(),
        }
    }

    pub(super) fn extract_release_savepoint(node: &ReleaseSavepoint) -> StatementFact {
        StatementFact::ReleaseSavepoint {
            name: node
                .savepoint_ref()
                .and_then(|s| s.ident_token())
                .map(|t| Self::resolve_identifier_token(t.text()))
                .unwrap_or_default(),
        }
    }
}
