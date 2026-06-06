// src/analysis/resolver.rs
use crate::analysis::facts::{StatementFact, AlterTableActionFact};
use crate::analysis::mutations::{Mutation, AlterTableActionMutation};
use crate::analysis::state::AnalysisState;
use crate::ast::identifiers::QualifiedName;
use crate::model::relation::ObjectId;

pub struct Resolver;

impl Resolver {
    /// Converts a stream of AST facts into canonical state Mutations.
    /// Needs read access to AnalysisState to resolve search paths.
    pub fn resolve(fact: &StatementFact, state: &AnalysisState) -> Vec<Mutation> {
        let mut mutations = Vec::new();
        
        match fact {
            StatementFact::CreateTable { name } => {
                let id = Self::resolve_identity(name, &state.local.search_path);
                mutations.push(Mutation::CreateTable { id });
            }
            StatementFact::DropTable { name, if_exists: _ } => {
                let id = Self::resolve_identity(name, &state.local.search_path);
                mutations.push(Mutation::DropTable { id });
            }
            StatementFact::AlterTable { name, actions } => {
                let id = Self::resolve_identity(name, &state.local.search_path);
                
                // We explode a single ALTER TABLE statement into multiple discrete 
                // state mutations. This makes the Rule Engine's job much easier!
                for action in actions {
                    let action_mutation = match action {
                        AlterTableActionFact::AddColumn { name: col_name } => {
                            AlterTableActionMutation::AddColumn { name: col_name.clone() }
                        }
                        AlterTableActionFact::DropColumn { name: col_name } => {
                            AlterTableActionMutation::DropColumn { name: col_name.clone() }
                        }
                    };
                    
                    mutations.push(Mutation::AlterTable { 
                        id: id.clone(), 
                        action: action_mutation 
                    });
                }
            }
            // Ignore transactions/views for a moment until we map them
            _ => {}
        }
        
        mutations
    }

    /// The Core Semantic Boundary:
    /// Canonicalizes a syntactic QualifiedName into an unambiguous ObjectId
    /// using PostgreSQL's search_path rules.
    fn resolve_identity(name: &QualifiedName, search_path: &[String]) -> ObjectId {
        let schema = name.schema.clone().unwrap_or_else(|| {
            // If the user didn't specify a schema (e.g., just `users`), 
            // we take the first item in the current search_path.
            // If the search path is somehow empty, we fallback to "public".
            search_path.first().cloned().unwrap_or_else(|| "public".to_string())
        });

        ObjectId {
            schema,
            name: name.name.clone(),
        }
    }
}
