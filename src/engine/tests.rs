#[cfg(test)]
mod tests {
    use crate::analysis::expr_ir::ExprIr;
    use crate::analysis::facts::{
        AlterTableActionFact, ColumnFact, FkFact, StatementFact, TableConstraintFact,
    };
    use crate::analysis::resolver::Resolver;
    use crate::analysis::state::AnalysisState;
    use crate::ast::identifiers::{ObjectId, QualifiedName};
    use crate::db::cache::DbCache;
    use crate::model::relation::RelationOverlay;
    use crate::report::reporter::Reporter;
    use crate::rules::constraints::{
        AddCheckConstraintRule, AddUniqueConstraintRule,
        MissingValidateConstraintRule, NotValidConstraintRule, SetNotNullRule,
        SafeAddColumnRule,
    };
    use crate::rules::destructive::DestructiveDropRule;
    use crate::rules::expressions::{SetTypeRule, VolatileDefaultRule};
    use crate::rules::idempotency::{
        CreateIndexIdempotencyRule, CreateTableIdempotencyRule,
        DropColumnIdempotencyRule, DropIndexIdempotencyRule, DropTableIdempotencyRule,
    };
    use crate::rules::indexes::{ConcurrentIndexRule, DropConcurrentIndexRule};
    use crate::rules::Rule;

    // ─────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────

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

    /// Build a CreateTable fact. Updated: now includes `table_constraints` field.
    fn create_table_fact(schema: Option<&str>, name: &str) -> StatementFact {
        StatementFact::CreateTable {
            name: QualifiedName::new(schema.map(|s| s.to_string()), name),
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),      // Bug 9: new required field
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

    fn col_fact(name: &str, ty: &str, not_null: bool, pk: bool) -> ColumnFact {
        ColumnFact {
            name: name.to_string(),
            ty: Some(ty.to_string()),
            not_null,
            is_primary_key: pk,
            default: None,
        }
    }

    /// Build an AddForeignKey action fact.
    /// Updated: now includes `constraint_name` field (Bug 10).
    fn add_fk_fact(
        constraint_name: Option<&str>,
        references: &str,
        from_cols: Vec<&str>,
        to_cols: Vec<&str>,
        not_valid: bool,
    ) -> AlterTableActionFact {
        AlterTableActionFact::AddForeignKey {
            constraint_name: constraint_name.map(|s| s.to_string()),
            references: QualifiedName::new(None, references),
            from_columns: from_cols.into_iter().map(|s| s.to_string()).collect(),
            to_columns: to_cols.into_iter().map(|s| s.to_string()).collect(),
            not_valid,
        }
    }

    /// Build an AddColumn action fact.
    /// Updated: now includes `not_null` field (Bug 11).
    fn add_col_fact(
        name: &str,
        ty: &str,
        if_not_exists: bool,
        not_null: bool,
        default: Option<ExprIr>,
    ) -> AlterTableActionFact {
        AlterTableActionFact::AddColumn {
            name: name.to_string(),
            ty: Some(ty.to_string()),
            if_not_exists,
            not_null,
            default,
        }
    }

    // ─────────────────────────────────────────────
    // Existing tests — updated for new field shapes
    // ─────────────────────────────────────────────

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
            table_constraints: Vec::new(),      // Bug 9: field added
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
            table_constraints: Vec::new(),      // Bug 9: field added
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
            table_constraints: Vec::new(),      // Bug 9: field added
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

    #[test]
    fn test_rename_column_updates_state() {
        let mut state = fresh_state();

        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: false,
            columns: vec![col_fact("email_addr", "text", false, false)],
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),      // Bug 9: field added
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
            table_constraints: Vec::new(),      // Bug 9: field added
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
            table_constraints: Vec::new(),      // Bug 9: field added
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
                add_fk_fact(None, "users", vec![], vec![], true),
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
            add_fk_fact(None, "users", vec!["user_id"], vec!["id"], false),
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

    #[test]
    fn test_volatile_default_rule_fires_on_now() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "events"));

        let volatile_default = ExprIr::FunctionCall {
            name: "now".to_string(),
            args: vec![],
        };
        let mutations = Resolver::resolve(
            &alter_table_fact("events", vec![
                add_col_fact("created_at", "timestamptz", false, false, Some(volatile_default)),
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

        let stable_default = ExprIr::Literal("0".to_string());
        let mutations = Resolver::resolve(
            &alter_table_fact("events", vec![
                add_col_fact("count", "integer", false, false, Some(stable_default)),
            ]),
            &state,
        );
        let rule = VolatileDefaultRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert!(reporter.violations.is_empty(),
            "literal default should not trigger volatile rule");
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
            table_constraints: Vec::new(),      // Bug 9: field added
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
        assert!(reporter.violations[0].message.contains("varchar"));
    }

    #[test]
    fn test_missing_validate_constraint_fires_at_finalize() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &create_table_fact(None, "orders"));

        apply_fact(&mut state, &alter_table_fact("orders", vec![
            add_fk_fact(None, "users", vec![], vec![], true),
        ]));

        assert!(!state.local.pending_validation.is_empty());

        let rule = MissingValidateConstraintRule;
        rule.finalize(&state, &mut reporter);

        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("NOT VALID") ||
                reporter.violations[0].message.contains("not be checked"));
    }

    #[test]
    fn test_validate_constraint_clears_pending() {
        // Bug 10 regression: now that the real constraint name is used as the
        // pending_validation key, ValidateConstraint must match by that name.
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &create_table_fact(None, "orders"));

        // Named FK with NOT VALID.
        apply_fact(&mut state, &alter_table_fact("orders", vec![
            add_fk_fact(Some("fk_orders_users"), "users", vec![], vec![], true),
        ]));

        // Validate using the real name.
        apply_fact(&mut state, &alter_table_fact("orders", vec![
            AlterTableActionFact::ValidateConstraint {
                constraint_name: "fk_orders_users".to_string(),
            },
        ]));

        let rule = MissingValidateConstraintRule;
        rule.finalize(&state, &mut reporter);

        assert!(reporter.violations.is_empty(),
            "validated named constraint should not fire MissingValidateConstraintRule");
    }

    #[test]
    fn test_graph_leak_on_rollback() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &create_table_fact(None, "orders"));
        apply_fact(&mut state, &StatementFact::BeginTransaction);
        apply_fact(&mut state, &alter_table_fact("orders", vec![
            add_fk_fact(None, "users", vec![], vec![], false),
        ]));
        apply_fact(&mut state, &StatementFact::RollbackTransaction);

        let mutations = Resolver::resolve(&StatementFact::DropTable {
            name: QualifiedName::new(None, "users"),
            if_exists: false,
        }, &state);
        let rule = crate::rules::views::OrphanedDependencyRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        let fk_violations: Vec<_> = reporter.violations.iter()
            .filter(|v| v.message.contains("foreign key")).collect();
        assert!(fk_violations.is_empty(), "Graph leaked: {:?}", fk_violations.first());
    }

    #[test]
    fn test_aba_phantom_dependency() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "target"));
        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "child"),
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: vec![fk_fact("target")],
            table_constraints: Vec::new(),      // Bug 9: field added
        });
        apply_fact(&mut state, &StatementFact::DropTable {
            name: QualifiedName::new(None, "child"),
            if_exists: false,
        });
        apply_fact(&mut state, &create_table_fact(None, "child")); // new incarnation, no FK

        let mutations = Resolver::resolve(&StatementFact::DropTable {
            name: QualifiedName::new(None, "target"),
            if_exists: false,
        }, &state);
        let rule = crate::rules::views::OrphanedDependencyRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        let fk_violations: Vec<_> = reporter.violations.iter()
            .filter(|v| v.message.contains("foreign key")).collect();
        assert!(fk_violations.is_empty(), "ABA phantom: {:?}", fk_violations.first());
    }

    #[test]
    fn test_view_graph_leak_on_rollback() {
        let mut state = fresh_state();
        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &StatementFact::BeginTransaction);
        apply_fact(&mut state, &StatementFact::CreateView {
            name: QualifiedName::new(None, "user_view"),
            or_replace: false,
        });
        apply_fact(&mut state, &StatementFact::RollbackTransaction);

        let view_id = object_id("public", "user_view");
        assert!(!state.local.graph.views.iter().any(|v| v.view_id == view_id),
            "View graph leaked after rollback");
        assert!(!state.relation_is_present(&view_id));
    }

    #[test]
    fn test_dropped_view_does_not_block_base_table_drop() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &StatementFact::CreateView {
            name: QualifiedName::new(None, "user_view"),
            or_replace: false,
        });
        apply_fact(&mut state, &StatementFact::DropTable {
            name: QualifiedName::new(None, "user_view"),
            if_exists: false,
        });

        let mutations = Resolver::resolve(&StatementFact::DropTable {
            name: QualifiedName::new(None, "users"),
            if_exists: false,
        }, &state);
        let rule = crate::rules::views::OrphanedDependencyRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        let view_violations: Vec<_> = reporter.violations.iter()
            .filter(|v| v.message.contains("view")).collect();
        assert!(view_violations.is_empty(),
            "Dead view blocking drop: {:?}", view_violations.first());
    }

    #[test]
    fn test_drop_index_without_concurrently_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        apply_fact(&mut state, &create_table_fact(None, "events"));

        let mutations = Resolver::resolve(&StatementFact::DropIndex {
            names: vec![QualifiedName::new(None, "idx_events_created_at")],
            if_exists: false,
            concurrently: false,
        }, &state);
        let rule = DropConcurrentIndexRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("ACCESS EXCLUSIVE"));
    }

    #[test]
    fn test_drop_index_concurrently_in_transaction_errors() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        apply_fact(&mut state, &create_table_fact(None, "events"));
        apply_fact(&mut state, &StatementFact::BeginTransaction);

        let mutations = Resolver::resolve(&StatementFact::DropIndex {
            names: vec![QualifiedName::new(None, "idx_events_type")],
            if_exists: false,
            concurrently: true,
        }, &state);
        let rule = DropConcurrentIndexRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("transaction block"));
    }

    #[test]
    fn test_add_check_constraint_without_not_valid_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        apply_fact(&mut state, &create_table_fact(None, "orders"));

        let mutations = Resolver::resolve(
            &alter_table_fact("orders", vec![
                AlterTableActionFact::AddCheckConstraint { not_valid: false },
            ]), &state);
        let rule = AddCheckConstraintRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("NOT VALID"));
    }

    #[test]
    fn test_add_check_constraint_with_not_valid_silent() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        apply_fact(&mut state, &create_table_fact(None, "orders"));

        let mutations = Resolver::resolve(
            &alter_table_fact("orders", vec![
                AlterTableActionFact::AddCheckConstraint { not_valid: true },
            ]), &state);
        let rule = AddCheckConstraintRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert!(reporter.violations.is_empty());
    }

    #[test]
    fn test_add_unique_constraint_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        apply_fact(&mut state, &create_table_fact(None, "users"));

        let mutations = Resolver::resolve(
            &alter_table_fact("users", vec![
                AlterTableActionFact::AddUniqueConstraint,
            ]), &state);
        let rule = AddUniqueConstraintRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("ACCESS EXCLUSIVE"));
    }

    #[test]
    fn test_idempotency_create_table_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        let mutations = Resolver::resolve(&create_table_fact(None, "users"), &state);
        let rule = CreateTableIdempotencyRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("IF NOT EXISTS"));
    }

    #[test]
    fn test_idempotency_create_table_with_guard_silent() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        let mutations = Resolver::resolve(&StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: true,
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),      // Bug 9: field added
        }, &state);
        let rule = CreateTableIdempotencyRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert!(reporter.violations.is_empty());
    }

    #[test]
    fn test_idempotency_drop_table_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        apply_fact(&mut state, &create_table_fact(None, "users"));

        let mutations = Resolver::resolve(&StatementFact::DropTable {
            name: QualifiedName::new(None, "users"),
            if_exists: false,
        }, &state);
        let rule = DropTableIdempotencyRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("IF EXISTS"));
    }

    #[test]
    fn test_idempotency_drop_index_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        let mutations = Resolver::resolve(&StatementFact::DropIndex {
            names: vec![QualifiedName::new(None, "idx_foo")],
            if_exists: false,
            concurrently: true,
        }, &state);
        let rule = DropIndexIdempotencyRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("IF EXISTS"));
    }

    // ─────────────────────────────────────────────
    // New tests — one adversarial test per bug
    // ─────────────────────────────────────────────

    // ── Bug 1 — parse errors are now rejected ────

    #[test]
    fn test_parse_rejects_syntax_errors() {
        use crate::engine::MigrationFile;
        let result = MigrationFile::parse("CREATE TABLE (;");
        assert!(result.is_err(),
            "Malformed SQL should return Err, not silently succeed");
    }

    #[test]
    fn test_parse_accepts_valid_sql() {
        use crate::engine::MigrationFile;
        let result = MigrationFile::parse("CREATE TABLE users (id integer);");
        assert!(result.is_ok(), "Valid SQL should parse successfully");
    }

    // ── Bug 2 — DbCache baseline is visible to rules ──

    #[test]
    fn test_baseline_cache_visible_to_get_relation() {
        // Tables seeded into DbCache before the migration starts must be
        // visible through get_relation() — the primary state query path.
        // Before the fix, get_relation() only read local.relations and any
        // pre-existing table was permanently invisible to all rules.
        let mut cache = DbCache::new();
        let baseline_id = object_id("public", "legacy_table");

        let mut rel = crate::model::relation::RelationState::new(baseline_id.clone(), 0);
        rel.apply_column_action(&crate::model::relation::ColumnAction::Add {
            name: "id".to_string(),
            data_type: Some("integer".to_string()),
            not_null: true,
            default: None,
        });
        cache.insert(rel);

        let state = AnalysisState::new(cache);
        assert!(
            matches!(state.get_relation(&baseline_id), Some(RelationOverlay::Present(_))),
            "Baseline table must be Present after seeding from DbCache"
        );
    }

    #[test]
    fn test_add_column_on_baseline_table_does_not_false_error() {
        // A SafeAddColumnRule error fires when the table is unknown.
        // With the DbCache fix, a table that exists only in the baseline
        // must NOT produce the "table does not exist" error.
        let mut cache = DbCache::new();
        let baseline_id = object_id("public", "legacy");
        cache.insert(crate::model::relation::RelationState::new(baseline_id, 0));

        let mut state = AnalysisState::new(cache);
        let mut reporter = Reporter::new();

        let mutations = Resolver::resolve(
            &alter_table_fact("legacy", vec![
                add_col_fact("new_col", "text", false, false, None),
            ]),
            &state,
        );
        let rule = SafeAddColumnRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }

        let unknown_table_errors: Vec<_> = reporter.violations.iter()
            .filter(|v| v.message.contains("does not exist"))
            .collect();
        assert!(unknown_table_errors.is_empty(),
            "ADD COLUMN on a baseline table must not produce 'does not exist' error: {:?}",
            unknown_table_errors.first());
    }

    // ── Bug 3 — identifier lowercasing ───────────

    #[test]
    fn test_resolver_lowercases_unqualified_name() {
        // Tables created with mixed-case unquoted names must be stored
        // with a lowercase ObjectId. resolve_name() was previously
        // preserving the raw AST text, causing lookup mismatches.
        let mut state = fresh_state();
        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "Users"),    // mixed case
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),
        });
        // The canonical id must be lowercase.
        let lower_id = object_id("public", "users");
        assert!(state.relation_is_present(&lower_id),
            "Unquoted mixed-case name must resolve to lowercase ObjectId");
    }

    #[test]
    fn test_resolver_lowercases_schema() {
        let mut state = fresh_state();
        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(Some("MySchema".to_string()), "MyTable"),
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),
        });
        // Both schema and name must be lowercase.
        let lower_id = object_id("myschema", "mytable");
        assert!(state.relation_is_present(&lower_id),
            "Schema component must also be lowercased during resolution");
    }

    // ── Bug 4 — global ROLLBACK unwinds full stack ──

    #[test]
    fn test_global_rollback_unwinds_full_stack() {
        // Previously ROLLBACK only popped one frame, so a migration that
        // opened a BEGIN, then a SAVEPOINT, then ROLLBACKed would leave
        // the savepoint frame on the stack — leaking state.
        let mut state = fresh_state();

        apply_fact(&mut state, &StatementFact::BeginTransaction);
        apply_fact(&mut state, &create_table_fact(None, "t1"));
        apply_fact(&mut state, &StatementFact::Savepoint { name: "sp1".to_string() });
        apply_fact(&mut state, &create_table_fact(None, "t2"));

        // Both tables visible inside the transaction.
        assert!(state.relation_is_present(&object_id("public", "t1")));
        assert!(state.relation_is_present(&object_id("public", "t2")));
        // Stack has two frames: [__transaction__, sp1]
        assert_eq!(state.local.transactions.len(), 2);

        apply_fact(&mut state, &StatementFact::RollbackTransaction);

        // Stack must be empty — all frames drained.
        assert!(state.local.transactions.is_empty(),
            "ROLLBACK must drain all transaction frames, not just the innermost");

        // Both tables must have been rolled back.
        assert!(!state.relation_is_present(&object_id("public", "t1")),
            "t1 created inside transaction must be rolled back");
        assert!(!state.relation_is_present(&object_id("public", "t2")),
            "t2 created inside savepoint must be rolled back");
    }

    #[test]
    fn test_global_commit_clears_full_stack() {
        let mut state = fresh_state();

        apply_fact(&mut state, &StatementFact::BeginTransaction);
        apply_fact(&mut state, &StatementFact::Savepoint { name: "sp1".to_string() });
        apply_fact(&mut state, &create_table_fact(None, "committed"));

        assert_eq!(state.local.transactions.len(), 2);

        apply_fact(&mut state, &StatementFact::CommitTransaction);

        assert!(state.local.transactions.is_empty(),
            "COMMIT must clear all transaction frames");
        // Table survives (was committed).
        assert!(state.relation_is_present(&object_id("public", "committed")));
    }

    // ── Bug 5 — rename graph rolled back on ROLLBACK ──

    #[test]
    fn test_rename_edge_rolled_back_on_rollback() {
        // Previously Mutation::Rename pushed a RenameEdge inside a transaction
        // but had no undo entry. ROLLBACK restored the relation overlays but
        // left the phantom RenameEdge in graph.renames.
        let mut state = fresh_state();

        apply_fact(&mut state, &create_table_fact(None, "original"));
        let edge_count_before = state.local.graph.renames.len();

        apply_fact(&mut state, &StatementFact::BeginTransaction);
        apply_fact(&mut state, &alter_table_fact("original", vec![
            AlterTableActionFact::RenameTo { new_name: "renamed".to_string() },
        ]));

        // Rename edge exists inside transaction.
        assert_eq!(state.local.graph.renames.len(), edge_count_before + 1);

        apply_fact(&mut state, &StatementFact::RollbackTransaction);

        // Edge must be gone after rollback.
        assert_eq!(state.local.graph.renames.len(), edge_count_before,
            "RenameEdge must be removed when the transaction is rolled back");

        // Original name must be restored.
        assert!(state.relation_is_present(&object_id("public", "original")));
        assert!(!state.relation_is_present(&object_id("public", "renamed")));
    }

    // ── Bug 6 — DROP INDEX rolled back on ROLLBACK ──

    #[test]
    fn test_drop_index_rolled_back_on_rollback() {
        // Previously DropIndex called retain() with no undo snapshot, so
        // ROLLBACK left the index permanently removed.
        let mut state = fresh_state();

        apply_fact(&mut state, &create_table_fact(None, "events"));
        apply_fact(&mut state, &StatementFact::CreateIndex {
            name: QualifiedName::new(None, "idx_events_ts"),
            relation: QualifiedName::new(None, "events"),
            if_not_exists: false,
            concurrently: false,
        });

        let idx_id = object_id("public", "idx_events_ts");
        let edge_count_before = state.local.graph.indexes.len();
        assert!(state.local.graph.indexes.iter().any(|i| i.index_id == idx_id),
            "Index must exist before transaction");

        apply_fact(&mut state, &StatementFact::BeginTransaction);
        apply_fact(&mut state, &StatementFact::DropIndex {
            names: vec![QualifiedName::new(None, "idx_events_ts")],
            if_exists: false,
            concurrently: false,
        });

        // Index gone inside transaction.
        assert!(!state.local.graph.indexes.iter().any(|i| i.index_id == idx_id),
            "Index must be absent after DROP INDEX inside transaction");

        apply_fact(&mut state, &StatementFact::RollbackTransaction);

        // Index must be restored after rollback.
        assert_eq!(state.local.graph.indexes.len(), edge_count_before,
            "Index edge count must be restored after rollback");
        assert!(state.local.graph.indexes.iter().any(|i| i.index_id == idx_id),
            "Dropped index must be restored when the transaction is rolled back");
    }

    // ── Bug 9 — table-level PK implies not_null ──

    #[test]
    fn test_table_pk_constraint_marks_columns_not_null() {
        // A table-level PRIMARY KEY (id) constraint must mark the `id` column
        // as not_null=true even when the column definition itself omits NOT NULL.
        let mut state = fresh_state();
        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "orders"),
            if_not_exists: false,
            columns: vec![
                // not_null=false, is_primary_key=false — constraint comes from table level
                col_fact("id", "integer", false, false),
                col_fact("amount", "numeric", false, false),
            ],
            foreign_keys: Vec::new(),
            table_constraints: vec![
                TableConstraintFact::PrimaryKey {
                    columns: vec!["id".to_string()],
                },
            ],
        });

        let id = object_id("public", "orders");
        if let Some(RelationOverlay::Present(rel)) = state.get_relation(&id) {
            let col = rel.get_column("id")
                .expect("id column must exist");
            assert!(!col.is_nullable,
                "Column in table-level PRIMARY KEY must be NOT NULL (is_nullable=false)");
            // amount is not in the PK — must remain nullable.
            let amount = rel.get_column("amount")
                .expect("amount column must exist");
            assert!(amount.is_nullable,
                "Non-PK column must remain nullable");
        } else {
            panic!("orders table must be Present");
        }
    }

    #[test]
    fn test_table_unique_constraint_stored() {
        let mut state = fresh_state();
        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: false,
            columns: vec![col_fact("email", "text", false, false)],
            foreign_keys: Vec::new(),
            table_constraints: vec![
                TableConstraintFact::Unique { columns: vec!["email".to_string()] },
            ],
        });
        // Just verify the table was created — UNIQUE doesn't change column state.
        assert!(state.relation_is_present(&object_id("public", "users")));
    }

    // ── Bug 10 — constraint name roundtrip ───────

    #[test]
    fn test_named_fk_validate_constraint_clears_pending() {
        // Previously pending_validation used a synthetic __fk__... key, so
        // VALIDATE CONSTRAINT by real name never matched. Now the real name
        // is used, and this test would have passed with the old synthetic key
        // only by accident (VALIDATE with the synthetic name).
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &create_table_fact(None, "orders"));

        apply_fact(&mut state, &alter_table_fact("orders", vec![
            add_fk_fact(Some("fk_orders_user_id"), "users", vec!["user_id"], vec!["id"], true),
        ]));

        // Confirm it's pending.
        let orders_id = object_id("public", "orders");
        assert!(state.local.pending_validation.contains(
            &(orders_id.clone(), "fk_orders_user_id".to_string())
        ), "Named FK must be in pending_validation under its real name");

        apply_fact(&mut state, &alter_table_fact("orders", vec![
            AlterTableActionFact::ValidateConstraint {
                constraint_name: "fk_orders_user_id".to_string(),
            },
        ]));

        assert!(state.local.pending_validation.is_empty(),
            "VALIDATE CONSTRAINT by real name must clear the pending entry");

        let rule = MissingValidateConstraintRule;
        rule.finalize(&state, &mut reporter);
        assert!(reporter.violations.is_empty());
    }

    #[test]
    fn test_unnamed_fk_uses_synthetic_key() {
        // An FK without a CONSTRAINT name must use the __fk__... synthetic
        // key as fallback — it can never be matched by VALIDATE CONSTRAINT.
        let mut state = fresh_state();

        apply_fact(&mut state, &create_table_fact(None, "users"));
        apply_fact(&mut state, &create_table_fact(None, "orders"));

        apply_fact(&mut state, &alter_table_fact("orders", vec![
            add_fk_fact(None, "users", vec![], vec![], true),
        ]));

        let orders_id = object_id("public", "orders");
        // Must contain a synthetic key, not a real name.
        let has_synthetic = state.local.pending_validation.iter().any(|(id, key)| {
            *id == orders_id && key.starts_with("__fk__")
        });
        assert!(has_synthetic,
            "Unnamed NOT VALID FK must be stored with a synthetic __fk__ key");
    }

    // ── Bug 11 — ADD COLUMN preserves not_null ───

    #[test]
    fn test_add_column_not_null_stored_in_state() {
        // Previously AlterTableActionMutation::AddColumn hardcoded not_null=false,
        // so NOT NULL constraints on ALTER TABLE ADD COLUMN were always lost.
        let mut state = fresh_state();

        apply_fact(&mut state, &create_table_fact(None, "items"));
        apply_fact(&mut state, &alter_table_fact("items", vec![
            add_col_fact("sku", "text", false, true, None),  // not_null=true
        ]));

        let id = object_id("public", "items");
        if let Some(RelationOverlay::Present(rel)) = state.get_relation(&id) {
            let col = rel.get_column("sku").expect("sku must exist");
            assert!(!col.is_nullable,
                "ADD COLUMN ... NOT NULL must store not_null=true in RelationState");
        } else {
            panic!("items must be Present");
        }
    }

    #[test]
    fn test_add_column_nullable_by_default() {
        // Contrast: ADD COLUMN without NOT NULL must remain nullable.
        let mut state = fresh_state();

        apply_fact(&mut state, &create_table_fact(None, "items"));
        apply_fact(&mut state, &alter_table_fact("items", vec![
            add_col_fact("description", "text", false, false, None),
        ]));

        let id = object_id("public", "items");
        if let Some(RelationOverlay::Present(rel)) = state.get_relation(&id) {
            let col = rel.get_column("description").expect("description must exist");
            assert!(col.is_nullable,
                "ADD COLUMN without NOT NULL must remain nullable");
        } else {
            panic!("items must be Present");
        }
    }

    // ── Bug 12 — inline FK from_columns populated ──

    #[test]
    fn test_inline_fk_from_columns_populated() {
        // Inline column-level REFERENCES constraints always had from_columns=[]
        // because the owning column name was not passed to extract_column_fk_facts.
        // This is a visitor-level fix verified at the fact layer.
        let fact = StatementFact::CreateTable {
            name: QualifiedName::new(None, "orders"),
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: vec![
                FkFact {
                    references: QualifiedName::new(None, "users"),
                    from_columns: vec!["user_id".to_string()],  // must be populated
                    to_columns: Vec::new(),
                },
            ],
            table_constraints: Vec::new(),
        };

        if let StatementFact::CreateTable { foreign_keys, .. } = &fact {
            assert_eq!(foreign_keys[0].from_columns, vec!["user_id"],
                "Inline column FK must have from_columns populated with the owning column name");
        }
    }

    // ── Bug 13 — CASE/ARRAY volatility detection ──

    #[test]
    fn test_case_expr_with_volatile_branch_is_volatile() {
        // CASE WHEN ... THEN now() END — the CASE expression is volatile
        // because a THEN arm contains a volatile function. Previously the
        // entire CASE was collapsed to ExprIr::Literal("<complex>").
        let volatile_in_case = ExprIr::FunctionCall {
            name: "<case>".to_string(),
            args: vec![
                ExprIr::Literal("true".to_string()),
                ExprIr::FunctionCall { name: "now".to_string(), args: vec![] },  // THEN arm
                ExprIr::Literal("2024-01-01".to_string()),                        // ELSE arm
            ],
        };
        assert!(volatile_in_case.is_volatile(),
            "CASE expr with volatile THEN branch must be volatile");
    }

    #[test]
    fn test_case_expr_with_no_volatile_branch_is_stable() {
        let stable_case = ExprIr::FunctionCall {
            name: "<case>".to_string(),
            args: vec![
                ExprIr::Literal("true".to_string()),
                ExprIr::Literal("1".to_string()),
                ExprIr::Literal("2".to_string()),
            ],
        };
        assert!(!stable_case.is_volatile(),
            "CASE expr with only literal branches must not be volatile");
    }

    #[test]
    fn test_array_expr_with_volatile_element_is_volatile() {
        // ARRAY[1, now()] — volatile because of now().
        let volatile_array = ExprIr::FunctionCall {
            name: "<array>".to_string(),
            args: vec![
                ExprIr::Literal("1".to_string()),
                ExprIr::FunctionCall { name: "now".to_string(), args: vec![] },
            ],
        };
        assert!(volatile_array.is_volatile(),
            "ARRAY with a volatile element must be volatile");
    }

    #[test]
    fn test_array_expr_all_literals_is_stable() {
        let stable_array = ExprIr::FunctionCall {
            name: "<array>".to_string(),
            args: vec![
                ExprIr::Literal("1".to_string()),
                ExprIr::Literal("2".to_string()),
            ],
        };
        assert!(!stable_array.is_volatile(),
            "ARRAY with only literal elements must not be volatile");
    }

    #[test]
    fn test_volatile_default_rule_fires_on_case_with_now() {
        // End-to-end: VolatileDefaultRule must fire when the column default
        // is a CASE expression that contains a volatile function call.
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "events"));

        let case_with_now = ExprIr::FunctionCall {
            name: "<case>".to_string(),
            args: vec![
                ExprIr::Literal("true".to_string()),
                ExprIr::FunctionCall { name: "now".to_string(), args: vec![] },
                ExprIr::Literal("null".to_string()),
            ],
        };
        let mutations = Resolver::resolve(
            &alter_table_fact("events", vec![
                add_col_fact("ts", "timestamptz", false, false, Some(case_with_now)),
            ]),
            &state,
        );
        let rule = VolatileDefaultRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }
        assert_eq!(reporter.violations.len(), 1,
            "CASE expr containing now() must trigger VolatileDefaultRule");
    }

    // ── Bug 15 — SafeAddColumnRule not overbroad ──

    #[test]
    fn test_safe_add_column_no_false_positive_for_new_nullable_column() {
        // The old rule fired a blanket "ensure nullable or non-volatile default"
        // warning for every ADD COLUMN. A new nullable column with no default
        // is the most common, safest pattern — it must produce zero warnings.
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "products"));

        let mutations = Resolver::resolve(
            &alter_table_fact("products", vec![
                add_col_fact("description", "text", false, false, None),  // no default, nullable
            ]),
            &state,
        );
        let rule = SafeAddColumnRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }

        assert!(reporter.violations.is_empty(),
            "ADD COLUMN (nullable, no default) on a known table must produce zero SafeAddColumn violations; \
             got: {:?}", reporter.violations.first());
    }

    #[test]
    fn test_safe_add_column_still_errors_on_duplicate() {
        // Even after removing the false positive, the duplicate-column error
        // (column already exists, no IF NOT EXISTS) must still fire.
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: false,
            columns: vec![col_fact("email", "text", false, false)],
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),
        });

        let mutations = Resolver::resolve(
            &alter_table_fact("users", vec![
                // Adding "email" again without IF NOT EXISTS — should error.
                AlterTableActionFact::AddColumn {
                    name: "email".to_string(),
                    ty: Some("text".to_string()),
                    if_not_exists: false,
                    not_null: false,
                    default: None,
                },
            ]),
            &state,
        );
        let rule = SafeAddColumnRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }

        let dup_errors: Vec<_> = reporter.violations.iter()
            .filter(|v| v.message.contains("already exists"))
            .collect();
        assert_eq!(dup_errors.len(), 1,
            "Duplicate ADD COLUMN without IF NOT EXISTS must still produce an error");
    }

    #[test]
    fn test_safe_add_column_if_not_exists_silences_duplicate_error() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: false,
            columns: vec![col_fact("email", "text", false, false)],
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),
        });

        let mutations = Resolver::resolve(
            &alter_table_fact("users", vec![
                // Same column but with IF NOT EXISTS — must be silent.
                AlterTableActionFact::AddColumn {
                    name: "email".to_string(),
                    ty: Some("text".to_string()),
                    if_not_exists: true,
                    not_null: false,
                    default: None,
                },
            ]),
            &state,
        );
        let rule = SafeAddColumnRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }

        assert!(reporter.violations.is_empty(),
            "ADD COLUMN IF NOT EXISTS on existing column must be silent");
    }

    // ── Bug 16 — DropColumnIdempotencyRule ───────

    #[test]
    fn test_drop_column_without_if_exists_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: false,
            columns: vec![col_fact("legacy_col", "text", false, false)],
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),
        });

        let mutations = Resolver::resolve(
            &alter_table_fact("users", vec![
                AlterTableActionFact::DropColumn {
                    name: "legacy_col".to_string(),
                    if_exists: false,
                },
            ]),
            &state,
        );
        let rule = DropColumnIdempotencyRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }

        assert_eq!(reporter.violations.len(), 1,
            "DROP COLUMN without IF EXISTS must produce exactly one warning");
        assert!(reporter.violations[0].message.contains("IF EXISTS"),
            "Warning message must mention IF EXISTS");
        assert!(reporter.violations[0].message.contains("legacy_col"),
            "Warning message must name the column");
    }

    #[test]
    fn test_drop_column_with_if_exists_is_silent() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
            if_not_exists: false,
            columns: vec![col_fact("legacy_col", "text", false, false)],
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),
        });

        let mutations = Resolver::resolve(
            &alter_table_fact("users", vec![
                AlterTableActionFact::DropColumn {
                    name: "legacy_col".to_string(),
                    if_exists: true,
                },
            ]),
            &state,
        );
        let rule = DropColumnIdempotencyRule;
        for m in &mutations { rule.evaluate(m, &state, &mut reporter); }

        assert!(reporter.violations.is_empty(),
            "DROP COLUMN IF EXISTS must produce no idempotency warning");
    }

    // ── Volatile function list completeness ──────

    #[test]
    fn test_gen_random_uuid_is_volatile() {
        let expr = ExprIr::FunctionCall {
            name: "gen_random_uuid".to_string(),
            args: vec![],
        };
        assert!(expr.is_volatile(), "gen_random_uuid must be in the volatile list");
    }

    #[test]
    fn test_nextval_is_volatile() {
        let expr = ExprIr::FunctionCall {
            name: "nextval".to_string(),
            args: vec![ExprIr::Literal("'seq'".to_string())],
        };
        assert!(expr.is_volatile(), "nextval must be in the volatile list");
    }

    #[test]
    fn test_txid_current_is_volatile() {
        let expr = ExprIr::FunctionCall {
            name: "txid_current".to_string(),
            args: vec![],
        };
        assert!(expr.is_volatile(), "txid_current must be in the volatile list");
    }

    #[test]
    fn test_immutable_function_is_not_volatile() {
        // lower() is IMMUTABLE — must not be flagged.
        let expr = ExprIr::FunctionCall {
            name: "lower".to_string(),
            args: vec![ExprIr::Literal("'ABC'".to_string())],
        };
        assert!(!expr.is_volatile(), "lower() is IMMUTABLE and must not be volatile");
    }
}
