#[cfg(test)]
mod tests {
    use crate::analysis::expr_ir::ExprIr;
    use crate::analysis::facts::{AlterTableActionFact, ColumnFact, FkFact, StatementFact};
    use crate::analysis::resolver::Resolver;
    use crate::analysis::state::AnalysisState;
    use crate::ast::identifiers::{ObjectId, QualifiedName};
    use crate::db::cache::DbCache;
    use crate::model::relation::RelationOverlay;
    use crate::report::reporter::Reporter;
    use crate::rules::constraints::{
        MissingValidateConstraintRule, NotValidConstraintRule, SetNotNullRule,
    };
    use crate::rules::destructive::DestructiveDropRule;
    use crate::rules::expressions::{SetTypeRule, VolatileDefaultRule};
    use crate::rules::indexes::ConcurrentIndexRule;
    use crate::rules::Rule;

    // ── Helpers ───────────────────────────────────────────────────────

    fn fresh_state() -> AnalysisState {
        AnalysisState::new(DbCache::new())
    }

    fn object_id(schema: &str, name: &str) -> ObjectId {
        ObjectId::new(schema, name)
    }

    fn apply_fact(state: &mut AnalysisState, fact: &StatementFact) {
        for m in Resolver::resolve(fact, state) {
            state.apply(m);
        }
    }

    fn create_table_fact(schema: Option<&str>, name: &str) -> StatementFact {
        StatementFact::CreateTable {
            name: QualifiedName::new(schema.map(|s| s.to_string()), name),
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: Vec::new(),
        }
    }

    fn fk_fact(references_name: &str) -> FkFact {
        FkFact {
            references: QualifiedName::new(None, references_name),
            from_columns: Vec::new(),
            to_columns: Vec::new(),
        }
    }

    fn alter_table_fact(table: &str, actions: Vec<AlterTableActionFact>) -> StatementFact {
        StatementFact::AlterTable {
            name: QualifiedName::new(None, table),
            actions,
        }
    }

    /// Build a ColumnFact with no default.
    fn col_fact(name: &str, ty: &str, not_null: bool, pk: bool) -> ColumnFact {
        ColumnFact {
            name: name.to_string(),
            ty: Some(ty.to_string()),
            not_null,
            is_primary_key: pk,
            default: None,
        }
    }

    // ── Phase 1 regression tests ──────────────────────────────────────

    #[test]
    fn test_destructive_drop_rule_tombstones() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(DestructiveDropRule)];

        let fact = StatementFact::DropTable {
            name: QualifiedName::new(None, "users"),
            if_exists: false,
        };
        let mutations = Resolver::resolve(&fact, &state);
        for m in mutations {
            for rule in &rules { rule.evaluate(&m, &state, &mut reporter); }
            state.apply(m);
        }

        let id = object_id("public", "users");
        assert!(matches!(state.get_relation(&id), Some(RelationOverlay::Dropped)));
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("public.users"));
    }

    #[test]
    fn test_begin_rollback_restores_state() {
        let mut state = fresh_state();

        apply_fact(&mut state, &create_table_fact(Some("public"), "orders"));
        apply_fact(&mut state, &StatementFact::BeginTransaction);
        apply_fact(&mut state, &StatementFact::DropTable {
            name: QualifiedName::new(Some("public".to_string()), "orders"),
            if_exists: false,
        });

        let id = object_id("public", "orders");
        assert!(matches!(state.get_relation(&id), Some(RelationOverlay::Dropped)));

        apply_fact(&mut state, &StatementFact::RollbackTransaction);
        assert!(matches!(state.get_relation(&id), Some(RelationOverlay::Present(_))));
    }

    #[test]
    fn test_create_view_inserts_view_edge() {
        let mut state = fresh_state();
        apply_fact(&mut state, &StatementFact::CreateView {
            name: QualifiedName::new(None, "user_summary"),
            or_replace: false,
        });
        let id = object_id("public", "user_summary");
        assert!(state.relation_is_present(&id));
        assert!(state.local.graph.views.iter().any(|v| v.view_id == id));
    }

    #[test]
    fn test_search_path_expands_unqualified_name() {
        let mut state = fresh_state();
        apply_fact(&mut state, &StatementFact::SetSearchPath {
            schemas: vec!["myschema".to_string()],
        });
        apply_fact(&mut state, &create_table_fact(None, "accounts"));
        assert!(state.relation_is_present(&object_id("myschema", "accounts")));
        assert!(!state.relation_is_present(&object_id("public", "accounts")));
    }

    // ── Phase 2 regression tests ──────────────────────────────────────

    #[test]
    fn test_create_table_populates_columns() {
        let mut state = fresh_state();
        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "products"),
            if_not_exists: false,
            columns: vec![
                col_fact("id",   "integer", true,  true),
                col_fact("name", "text",    false, false),
            ],
            foreign_keys: Vec::new(),
        });

        let id = object_id("public", "products");
        if let Some(RelationOverlay::Present(rel)) = state.get_relation(&id) {
            assert!(rel.has_column("id"));
            assert!(rel.has_column("name"));
            assert!(!rel.has_column("price"));
        } else { panic!("products should be Present"); }
    }

    #[test]
    fn test_create_table_inserts_fk_edge() {
        let mut state = fresh_state();
        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "orders"),
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: vec![fk_fact("users")],
        });

        let orders = object_id("public", "orders");
        let users  = object_id("public", "users");
        assert!(state.local.graph.foreign_keys.iter()
            .any(|fk| fk.from_table == orders && fk.to_table == users));
    }

    #[test]
    fn test_orphaned_fk_rule_fires_on_drop() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "orders"),
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: vec![fk_fact("users")],
        });

        let drop_fact = StatementFact::DropTable {
            name: QualifiedName::new(None, "users"),
            if_exists: false,
        };
        let mutations = Resolver::resolve(&drop_fact, &state);
        let all_rules = crate::rules::rules();
        for m in &mutations {
            for rule in &all_rules { rule.evaluate(m, &state, &mut reporter); }
        }
        assert!(reporter.violations.iter().any(|v| v.message.contains("foreign key")));
    }

    #[test]
    fn test_concurrent_index_rule_fires_without_concurrently() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        apply_fact(&mut state, &create_table_fact(None, "events"));

        let mutations = Resolver::resolve(&StatementFact::CreateIndex {
            name: QualifiedName::new(None, "idx_events_created_at"),
            relation: QualifiedName::new(None, "events"),
            if_not_exists: false,
            concurrently: false,
        }, &state);
        let rule = ConcurrentIndexRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("ACCESS EXCLUSIVE"));
    }

    #[test]
    fn test_concurrent_index_correct_usage_no_violation() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        apply_fact(&mut state, &create_table_fact(None, "events"));

        let mutations = Resolver::resolve(&StatementFact::CreateIndex {
            name: QualifiedName::new(None, "idx_events_user_id"),
            relation: QualifiedName::new(None, "events"),
            if_not_exists: false,
            concurrently: true,
        }, &state);
        let rule = ConcurrentIndexRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert!(reporter.violations.is_empty());
    }

    // ── Phase 3 regression tests ──────────────────────────────────────

    #[test]
    fn test_rename_column_updates_state() {
        let mut state = fresh_state();

        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: false,
            columns: vec![col_fact("email_addr", "text", false, false)],
            foreign_keys: Vec::new(),
        });

        apply_fact(&mut state, &alter_table_fact("users", vec![
            AlterTableActionFact::RenameColumn {
                from: "email_addr".to_string(),
                to: "email".to_string(),
            },
        ]));

        let id = object_id("public", "users");
        if let Some(RelationOverlay::Present(rel)) = state.get_relation(&id) {
            assert!(!rel.has_column("email_addr"));
            assert!(rel.has_column("email"));
        } else { panic!("users should be Present"); }
    }

    #[test]
    fn test_rename_table_moves_overlay() {
        let mut state = fresh_state();
        apply_fact(&mut state, &create_table_fact(None, "old_name"));
        apply_fact(&mut state, &alter_table_fact("old_name", vec![
            AlterTableActionFact::RenameTo { new_name: "new_name".to_string() },
        ]));
        assert!(!state.relation_is_present(&object_id("public", "old_name")));
        assert!(state.relation_is_present(&object_id("public", "new_name")));
        assert!(state.local.graph.renames.iter().any(|r| {
            r.from == object_id("public", "old_name") &&
            r.to   == object_id("public", "new_name")
        }));
    }

    #[test]
    fn test_set_not_null_rule_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: false,
            columns: vec![col_fact("email", "text", false, false)],
            foreign_keys: Vec::new(),
        });

        let mutations = Resolver::resolve(
            &alter_table_fact("users", vec![
                AlterTableActionFact::SetNotNull { column: "email".to_string() },
            ]),
            &state,
        );
        let rule = SetNotNullRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("full table scan"));
    }

    #[test]
    fn test_set_not_null_already_constrained_no_warning() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: false,
            columns: vec![col_fact("id", "integer", true, true)],
            foreign_keys: Vec::new(),
        });

        let mutations = Resolver::resolve(
            &alter_table_fact("users", vec![
                AlterTableActionFact::SetNotNull { column: "id".to_string() },
            ]),
            &state,
        );
        let rule = SetNotNullRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert!(reporter.violations.is_empty());
    }

    #[test]
    fn test_not_valid_constraint_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &create_table_fact(None, "orders"));

        let mutations = Resolver::resolve(
            &alter_table_fact("orders", vec![
                AlterTableActionFact::AddForeignKey {
                    references: QualifiedName::new(None, "users"),
                    from_columns: Vec::new(),
                    to_columns: Vec::new(),
                    not_valid: true,
                },
            ]),
            &state,
        );
        let rule = NotValidConstraintRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("NOT VALID"));
    }

    #[test]
    fn test_rollback_to_savepoint_partial_restore() {
        let mut state = fresh_state();

        apply_fact(&mut state, &create_table_fact(None, "baseline"));
        apply_fact(&mut state, &StatementFact::BeginTransaction);
        apply_fact(&mut state, &create_table_fact(None, "sp1_table"));
        apply_fact(&mut state, &StatementFact::Savepoint { name: "sp1".to_string() });
        apply_fact(&mut state, &create_table_fact(None, "sp2_table"));

        assert!(state.relation_is_present(&object_id("public", "sp1_table")));
        assert!(state.relation_is_present(&object_id("public", "sp2_table")));

        apply_fact(&mut state, &StatementFact::RollbackToSavepoint { name: "sp1".to_string() });

        assert!(state.relation_is_present(&object_id("public", "sp1_table")));
        assert!(!state.relation_is_present(&object_id("public", "sp2_table")));
        assert!(state.relation_is_present(&object_id("public", "baseline")));
    }

    #[test]
    fn test_add_fk_via_alter_inserts_edge() {
        let mut state = fresh_state();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &create_table_fact(None, "posts"));
        apply_fact(&mut state, &alter_table_fact("posts", vec![
            AlterTableActionFact::AddForeignKey {
                references: QualifiedName::new(None, "users"),
                from_columns: vec!["user_id".to_string()],
                to_columns: vec!["id".to_string()],
                not_valid: false,
            },
        ]));

        let posts = object_id("public", "posts");
        let users = object_id("public", "users");
        let edge = state.local.graph.foreign_keys.iter()
            .find(|fk| fk.from_table == posts && fk.to_table == users);
        assert!(edge.is_some());
        let edge = edge.unwrap();
        assert_eq!(edge.from_columns, vec!["user_id"]);
        assert_eq!(edge.to_columns,   vec!["id"]);
    }

    // ── Phase 4 new tests ─────────────────────────────────────────────

    #[test]
    fn test_volatile_default_rule_fires_on_now() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "events"));

        // ADD COLUMN with now() default — should fire VolatileDefaultRule.
        let volatile_default = ExprIr::FunctionCall {
            name: "now".to_string(),
            args: vec![],
        };
        let mutations = Resolver::resolve(
            &alter_table_fact("events", vec![
                AlterTableActionFact::AddColumn {
                    name: "created_at".to_string(),
                    ty: Some("timestamptz".to_string()),
                    if_not_exists: false,
                    default: Some(volatile_default),
                },
            ]),
            &state,
        );
        let rule = VolatileDefaultRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("volatile default"));
    }

    #[test]
    fn test_volatile_default_rule_silent_on_literal() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "events"));

        // ADD COLUMN with literal default — should NOT fire.
        let stable_default = ExprIr::Literal("0".to_string());
        let mutations = Resolver::resolve(
            &alter_table_fact("events", vec![
                AlterTableActionFact::AddColumn {
                    name: "count".to_string(),
                    ty: Some("integer".to_string()),
                    if_not_exists: false,
                    default: Some(stable_default),
                },
            ]),
            &state,
        );
        let rule = VolatileDefaultRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert!(reporter.violations.is_empty(), "literal default should not trigger volatile rule");
    }

    #[test]
    fn test_set_type_rule_always_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: false,
            columns: vec![col_fact("email", "varchar", false, false)],
            foreign_keys: Vec::new(),
        });

        let mutations = Resolver::resolve(
            &alter_table_fact("users", vec![
                AlterTableActionFact::SetType {
                    column: "email".to_string(),
                    ty: "text".to_string(),
                },
            ]),
            &state,
        );
        let rule = SetTypeRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("ACCESS EXCLUSIVE"));
        // Should include the old type in the message.
        assert!(reporter.violations[0].message.contains("varchar"));
    }

    #[test]
    fn test_missing_validate_constraint_fires_at_finalize() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &create_table_fact(None, "orders"));

        // Add FK with NOT VALID — never validated.
        apply_fact(&mut state, &alter_table_fact("orders", vec![
            AlterTableActionFact::AddForeignKey {
                references: QualifiedName::new(None, "users"),
                from_columns: Vec::new(),
                to_columns: Vec::new(),
                not_valid: true,
            },
        ]));

        // Verify it's in pending_validation before finalize.
        assert!(!state.local.pending_validation.is_empty());

        // finalize() should fire the rule.
        let rule = MissingValidateConstraintRule;
        rule.finalize(&state, &mut reporter);

        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("NOT VALID") ||
                reporter.violations[0].message.contains("not be checked"));
    }

    #[test]
    fn test_validate_constraint_clears_pending() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &create_table_fact(None, "orders"));

        // Add FK with NOT VALID.
        apply_fact(&mut state, &alter_table_fact("orders", vec![
            AlterTableActionFact::AddForeignKey {
                references: QualifiedName::new(None, "users"),
                from_columns: Vec::new(),
                to_columns: Vec::new(),
                not_valid: true,
            },
        ]));

        // Validate it — pending_validation should be cleared.
        // The synthetic key is __fk__public.users
        apply_fact(&mut state, &alter_table_fact("orders", vec![
            AlterTableActionFact::ValidateConstraint {
                constraint_name: "__fk__public.users".to_string(),
            },
        ]));

        let rule = MissingValidateConstraintRule;
        rule.finalize(&state, &mut reporter);

        // No violations — constraint was validated.
        assert!(reporter.violations.is_empty(),
            "validated constraint should not fire MissingValidateConstraintRule");
    }
}
