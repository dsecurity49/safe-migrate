// FILE: ./src/engine/tests.rs

#![allow(unused_imports)]

#[cfg(test)]
pub mod helpers {
    use crate::engine::config::Config;
    use crate::engine::engine::SafeMigrateEngine;
    use crate::db::cache::DbCache;
    use crate::ast::identifiers::ObjectId;

    pub fn setup_engine() -> SafeMigrateEngine {
        let config = Config::default(); // Tier1: 100k, Tier2: 10k, Toast: 2048 bytes
        SafeMigrateEngine::new(config)
    }

    pub fn object_id(schema: &str, name: &str) -> ObjectId {
        ObjectId::new(schema, name)
    }
}

// ─────────────────────────────────────────────
// 1. State Machine Skip Guards (No-Op Tests)
// ─────────────────────────────────────────────
#[cfg(test)]
mod state_machine_guards_tests {
    use super::helpers::*;
    use crate::analysis::state::AnalysisState;
    use crate::model::relation::{RelationState, RelationOverlay, RelationKind, Persistence};

    #[test]
    fn test_skip_guard_create_table() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE t(id INT);", &mut state).unwrap();
        // Skip guard prevents the second statement from overwriting 'id' with 'new_col'
        engine.analyze("CREATE TABLE IF NOT EXISTS t(new_col INT);", &mut state).unwrap();

        let rel = state.get_relation(&object_id("public", "t")).unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert!(r.has_column("id"));
            assert!(!r.has_column("new_col"));
        }
    }

    #[test]
    fn test_skip_guard_add_column() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE t(id INT);", &mut state).unwrap();
        engine.analyze("ALTER TABLE t ADD COLUMN IF NOT EXISTS id TEXT;", &mut state).unwrap();

        let rel = state.get_relation(&object_id("public", "t")).unwrap();
        if let RelationOverlay::Present(r) = rel {
            let col = r.get_column("id").unwrap();
            assert_eq!(col.data_type.as_deref(), Some("INT")); // Must not be overwritten to TEXT
        }
    }

    #[test]
    fn test_skip_guard_drop_column() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE t(id INT);", &mut state).unwrap();
        // Should bypass without panicking
        let result = engine.analyze("ALTER TABLE t DROP COLUMN IF EXISTS missing;", &mut state);
        assert!(result.is_ok());
    }

    #[test]
    fn test_skip_guard_drop_missing_objects() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        
        assert!(engine.analyze("DROP TABLE IF EXISTS missing;", &mut state).is_ok());
        assert!(engine.analyze("DROP VIEW IF EXISTS missing;", &mut state).is_ok());
        assert!(engine.analyze("DROP MATERIALIZED VIEW IF EXISTS missing;", &mut state).is_ok());
        assert!(engine.analyze("DROP INDEX IF EXISTS missing;", &mut state).is_ok());
        assert!(engine.analyze("DROP SEQUENCE IF EXISTS missing;", &mut state).is_ok());
        assert!(engine.analyze("DROP DOMAIN IF EXISTS missing;", &mut state).is_ok());
    }

    #[test]
    fn test_skip_guard_create_index() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE t(id int);", &mut state).unwrap();
        engine.analyze("CREATE INDEX idx ON t(id);", &mut state).unwrap();
        
        let edge_count = state.local.graph.indexes.len();
        engine.analyze("CREATE INDEX IF NOT EXISTS idx ON t(id);", &mut state).unwrap();
        assert_eq!(state.local.graph.indexes.len(), edge_count, "Duplicate index creation should be skipped");
    }

    #[test]
    fn test_skip_guard_create_sequence() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE SEQUENCE s;", &mut state).unwrap();
        engine.analyze("CREATE SEQUENCE IF NOT EXISTS s OWNED BY foo.bar;", &mut state).unwrap();
        
        assert!(state.local.graph.sequences.is_empty(), "Second creation skipped, ownership should not be added");
    }
}

// ─────────────────────────────────────────────
// 2. Rule Evaluation Exhaustion
// ─────────────────────────────────────────────
#[cfg(test)]
mod rule_evaluation_tests {
    use super::helpers::*;
    use crate::analysis::state::AnalysisState;
    use crate::report::violations::ViolationTier;
    use crate::model::relation::{RelationState, RelationKind, Persistence};
    use crate::model::column::Column;

    #[test]
    fn test_rule_idempotency() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        let violations = engine.analyze("CREATE TABLE t(id int); DROP TABLE t; CREATE INDEX i ON t(id);", &mut state).unwrap();
        
        let idem: Vec<_> = violations.into_iter().filter(|v| v.rule_id == "missing-idempotency").collect();
        assert_eq!(idem.len(), 3);
        
        let safe = engine.analyze("CREATE TABLE IF NOT EXISTS x(id int); DROP TABLE IF EXISTS x; CREATE INDEX IF NOT EXISTS ix ON x(id);", &mut state).unwrap();
        assert!(!safe.iter().any(|v| v.rule_id == "missing-idempotency"));
    }

    #[test]
    fn test_rule_cascading_drop() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        
        engine.analyze("CREATE TABLE data(id INT); CREATE VIEW v AS SELECT * FROM data;", &mut state).unwrap();
        let v1 = engine.analyze("DROP TABLE data CASCADE;", &mut state).unwrap();
        assert!(v1.iter().any(|v| v.rule_id == "destructive-cascade" && v.tier == ViolationTier::Tier1));

        engine.analyze("CREATE TABLE safe(id INT);", &mut state).unwrap();
        let v2 = engine.analyze("DROP TABLE safe CASCADE;", &mut state).unwrap();
        assert!(!v2.iter().any(|v| v.rule_id == "destructive-cascade"), "Unreferenced table cascade is safe");
    }

    #[test]
    fn test_rule_size_aware_toast_escalation() {
        let engine = setup_engine();
        let mut cache = crate::db::cache::DbCache::new();
        
        // Setup Tier 2 table (50k rows) with a wide TOAST column (3000 avg bytes)
        let tid = object_id("public", "t_toast");
        let mut rel = RelationState::new(tid.clone(), 0, Some(50_000), RelationKind::Table, Persistence::Permanent);
        rel.columns.push(Column { name: "data".into(), data_type: Some("text".into()), is_nullable: true, default: None, avg_width: Some(3000) });
        cache.insert_baseline(tid, rel);
        let mut state = AnalysisState::new(cache);

        let violations = engine.analyze("ALTER TABLE t_toast ADD COLUMN c INT DEFAULT random();", &mut state).unwrap();
        let v = violations.iter().find(|v| v.rule_id == "size-aware-add-column" && v.dedup_key.is_none()).unwrap();
        
        // Because of the TOAST column, it should escalate from Tier 2 -> Tier 1
        assert_eq!(v.tier, ViolationTier::Tier1);
        assert!(v.title.contains("Escalated due to wide TOAST"));
    }

    #[test]
    fn test_rule_blocking_constraint_check_and_fk() {
        let engine = setup_engine();
        let mut cache = crate::db::cache::DbCache::new();
        cache.insert_baseline(object_id("public", "t"), RelationState::new(object_id("public", "t"), 0, Some(500_000), RelationKind::Table, Persistence::Permanent));
        let mut state = AnalysisState::new(cache);

        let v1 = engine.analyze("ALTER TABLE t ADD CONSTRAINT c CHECK (id > 0);", &mut state).unwrap();
        assert!(v1.iter().any(|v| v.rule_id == "blocking-constraint" && v.tier == ViolationTier::Tier1 && v.dedup_key.is_none()));

        let v2 = engine.analyze("ALTER TABLE t ADD CONSTRAINT c CHECK (id > 0) NOT VALID;", &mut state).unwrap();
        assert!(!v2.iter().any(|v| v.rule_id == "blocking-constraint" && v.dedup_key.is_none()));
    }

    #[test]
    fn test_rule_blocking_constraint_pk_and_unique() {
        let engine = setup_engine();
        let mut cache = crate::db::cache::DbCache::new();
        cache.insert_baseline(object_id("public", "t"), RelationState::new(object_id("public", "t"), 0, Some(500_000), RelationKind::Table, Persistence::Permanent));
        let mut state = AnalysisState::new(cache);

        let v1 = engine.analyze("ALTER TABLE t ADD PRIMARY KEY (id);", &mut state).unwrap();
        assert!(v1.iter().any(|v| v.rule_id == "blocking-index-constraint" && v.tier == ViolationTier::Tier1 && v.dedup_key.is_none()));
    }

    #[test]
    fn test_rule_concurrent_index() {
        let engine = setup_engine();
        let mut cache = crate::db::cache::DbCache::new();
        cache.insert_baseline(object_id("public", "t"), RelationState::new(object_id("public", "t"), 0, Some(500_000), RelationKind::Table, Persistence::Permanent));
        let mut state = AnalysisState::new(cache);

        let v1 = engine.analyze("CREATE INDEX i ON t(id);", &mut state).unwrap();
        assert!(v1.iter().any(|v| v.rule_id == "require-concurrent-index" && v.tier == ViolationTier::Tier1 && v.dedup_key.is_none()));
        
        let v2 = engine.analyze("CREATE INDEX CONCURRENTLY i2 ON t(id);", &mut state).unwrap();
        assert!(!v2.iter().any(|v| v.rule_id == "require-concurrent-index" && v.dedup_key.is_none()));
    }

    #[test]
    fn test_rule_temporary_table_bypass() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        let v = engine.analyze("CREATE TEMPORARY TABLE temp(id int); CREATE INDEX i ON temp(id); ALTER TABLE temp ADD UNIQUE(id);", &mut state).unwrap();
        
        assert!(!v.iter().any(|v| v.rule_id == "require-concurrent-index"));
        assert!(!v.iter().any(|v| v.rule_id == "blocking-index-constraint"));
    }

    #[test]
    fn test_rule_mat_view_refresh() {
        let engine = setup_engine();
        let mut cache = crate::db::cache::DbCache::new();
        cache.insert_baseline(object_id("public", "mv"), RelationState::new(object_id("public", "mv"), 0, Some(150_000), RelationKind::MaterializedView, Persistence::Permanent));
        let mut state = AnalysisState::new(cache);

        let v1 = engine.analyze("REFRESH MATERIALIZED VIEW mv;", &mut state).unwrap();
        assert!(v1.iter().any(|v| v.rule_id == "blocking-mat-view-refresh" && v.tier == ViolationTier::Tier1 && v.dedup_key.is_none()));
        
        let v2 = engine.analyze("REFRESH MATERIALIZED VIEW CONCURRENTLY mv;", &mut state).unwrap();
        assert!(!v2.iter().any(|v| v.rule_id == "blocking-mat-view-refresh" && v.dedup_key.is_none()));
    }

    #[test]
    fn test_rule_partition_attach_detach() {
        let engine = setup_engine();
        let mut cache = crate::db::cache::DbCache::new();
        cache.insert_baseline(object_id("public", "p"), RelationState::new(object_id("public", "p"), 0, Some(500_000), RelationKind::Table, Persistence::Permanent));
        let mut state = AnalysisState::new(cache);

        engine.analyze("CREATE TABLE c(id int);", &mut state).unwrap();
        let v1 = engine.analyze("ALTER TABLE p ATTACH PARTITION c FOR VALUES IN (1);", &mut state).unwrap();
        assert!(v1.iter().any(|v| v.rule_id == "blocking-partition-mutation" && v.tier == ViolationTier::Tier1 && v.dedup_key.is_none()));

        let v2 = engine.analyze("ALTER TABLE p DETACH PARTITION c;", &mut state).unwrap();
        assert!(v2.iter().any(|v| v.rule_id == "blocking-partition-mutation" && v.tier == ViolationTier::Tier1 && v.dedup_key.is_none()));
    }

    #[test]
    fn test_rule_concurrent_inside_txn() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        
        let v = engine.analyze("BEGIN; CREATE INDEX CONCURRENTLY i ON t(id); DROP INDEX CONCURRENTLY i; COMMIT;", &mut state).unwrap();
        let count = v.iter().filter(|v| v.rule_id == "concurrent-in-transaction").count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_rule_opaque_sql() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        let v = engine.analyze("EXECUTE plan;", &mut state).unwrap();
        assert_eq!(v.iter().filter(|v| v.rule_id == "opaque-dynamic-sql").count(), 1);
        assert_eq!(state.local.confidence, crate::analysis::state::Confidence::Tainted);
    }

    #[test]
    fn test_rule_volatile_default_create() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        let v = engine.analyze("CREATE TABLE t(id int DEFAULT random());", &mut state).unwrap();
        assert!(v.iter().any(|v| v.rule_id == "volatile-default" && v.tier == ViolationTier::Tier3));
    }
}

// ─────────────────────────────────────────────
// 3. Graph & State Topology Exhaustion
// ─────────────────────────────────────────────
#[cfg(test)]
mod graph_topology_tests {
    use super::helpers::*;
    use crate::analysis::state::AnalysisState;
    use crate::model::relation::RelationOverlay;
    use crate::model::types::{TypeOverlay, TypeKind};
    use crate::model::sequence::SequenceOverlay;

    #[test]
    fn test_topology_create_table_as() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE t AS SELECT 1 AS id;", &mut state).unwrap();
        let rel = state.get_relation(&object_id("public", "t")).unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert_eq!(r.estimated_rows, None); // Should default to None (Unknown)
        }
    }

    #[test]
    fn test_topology_rename_table_and_column() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE a(col1 INT); ALTER TABLE a RENAME TO b; ALTER TABLE b RENAME COLUMN col1 TO col2;", &mut state).unwrap();
        
        assert!(!state.relation_is_present(&object_id("public", "a")));
        assert!(state.relation_is_present(&object_id("public", "b")));
        
        let rel = state.get_relation(&object_id("public", "b")).unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert!(r.has_column("col2"));
            assert!(!r.has_column("col1"));
        }
        assert!(state.local.graph.renames.iter().any(|e| e.from == object_id("public", "a") && e.to == object_id("public", "b")));
    }

    #[test]
    fn test_topology_rename_index() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE t(id int); CREATE INDEX i ON t(id); ALTER INDEX i RENAME TO i2;", &mut state).unwrap();
        
        assert!(state.local.graph.indexes.iter().any(|i| i.index_id == object_id("public", "i2")));
        assert!(!state.local.graph.indexes.iter().any(|i| i.index_id == object_id("public", "i")));
    }

    #[test]
    fn test_topology_foreign_key_graph() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE p(id int); CREATE TABLE c(p_id int); ALTER TABLE c ADD CONSTRAINT fk FOREIGN KEY (p_id) REFERENCES p(id);", &mut state).unwrap();
        
        assert!(state.local.graph.foreign_keys.iter().any(|fk| fk.from_table == object_id("public", "c") && fk.to_table == object_id("public", "p")));
        
        engine.analyze("ALTER TABLE c DROP CONSTRAINT fk;", &mut state).unwrap();
        assert!(state.local.graph.foreign_keys.is_empty());
    }

    #[test]
    fn test_topology_view_graph() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE t(id int); CREATE VIEW v AS SELECT * FROM t;", &mut state).unwrap();
        
        assert!(state.local.graph.views.iter().any(|v| v.view_id == object_id("public", "v") && v.depends_on.contains(&object_id("public", "t"))));
        
        engine.analyze("DROP VIEW v;", &mut state).unwrap();
        assert!(state.local.graph.views.is_empty());
    }

    #[test]
    fn test_topology_sequence_graph() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE t(id int); CREATE SEQUENCE s OWNED BY t.id;", &mut state).unwrap();
        
        assert!(state.local.graph.sequences.iter().any(|s| s.sequence_id == object_id("public", "s") && s.table_id == object_id("public", "t")));
        
        engine.analyze("DROP SEQUENCE s;", &mut state).unwrap();
        assert!(matches!(state.local.sequences.get(&object_id("public", "s")), Some(SequenceOverlay::Dropped)));
        assert!(state.local.graph.sequences.is_empty(), "Drop sequence must remove graph edges");
    }

    #[test]
    fn test_topology_type_and_domain() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TYPE e AS ENUM('a'); ALTER TYPE e ADD VALUE 'b'; CREATE DOMAIN d AS INT; ALTER DOMAIN d SET DEFAULT 1;", &mut state).unwrap();
        
        if let Some(TypeOverlay::Present(t)) = state.local.types.get(&object_id("public", "e")) {
            if let TypeKind::Enum { variants } = &t.kind { assert!(variants.contains(&"b".to_string())); }
        } else { panic!("Type e missing"); }

        engine.analyze("DROP DOMAIN d;", &mut state).unwrap();
        assert!(matches!(state.local.types.get(&object_id("public", "d")), Some(TypeOverlay::Dropped)));
    }

    #[test]
    fn test_topology_trigger_and_policy() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE t(id int); CREATE POLICY p ON t FOR SELECT USING(true); CREATE TRIGGER tr BEFORE INSERT ON t EXECUTE FUNCTION f();", &mut state).unwrap();
        
        if let Some(RelationOverlay::Present(r)) = state.get_relation(&object_id("public", "t")) {
            assert!(r.policies.contains("p"));
            assert!(r.triggers.contains("tr"));
        }
        
        engine.analyze("DROP POLICY p ON t; DROP TRIGGER tr ON t;", &mut state).unwrap();
        if let Some(RelationOverlay::Present(r)) = state.get_relation(&object_id("public", "t")) {
            assert!(!r.policies.contains("p"));
            assert!(!r.triggers.contains("tr"));
        }
    }

    #[test]
    fn test_topology_search_path() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("SET search_path TO myschema, public; CREATE TABLE t(id int);", &mut state).unwrap();
        assert!(state.relation_is_present(&object_id("myschema", "t")));
    }

    #[test]
    fn test_state_alter_column_types() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE t(id INT NOT NULL); ALTER TABLE t ALTER COLUMN id SET DATA TYPE text; ALTER TABLE t ALTER COLUMN id DROP NOT NULL; ALTER TABLE t ALTER COLUMN id SET DEFAULT 'x';", &mut state).unwrap();
        
        if let Some(RelationOverlay::Present(r)) = state.get_relation(&object_id("public", "t")) {
            let col = r.get_column("id").unwrap();
            assert_eq!(col.data_type.as_deref(), Some("text"));
            assert!(col.is_nullable);
            assert!(col.default.is_some());
        }
    }

    #[test]
    fn test_state_storage_and_access_method() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        // Just verify parsing and silent state pass-through
        assert!(engine.analyze("CREATE TABLE t(id int); ALTER TABLE t ALTER COLUMN id SET STORAGE MAIN; ALTER TABLE t SET ACCESS METHOD heap;", &mut state).is_ok());
    }
}

// ─────────────────────────────────────────────
// 4. Transaction Lifecycle Rollback Exhaustion
// ─────────────────────────────────────────────
#[cfg(test)]
mod transaction_lifecycle_tests {
    use super::helpers::*;
    use crate::analysis::state::AnalysisState;

    #[test]
    fn test_txn_commit() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("BEGIN; CREATE TABLE t(id int); COMMIT;", &mut state).unwrap();
        assert!(state.local.transactions.is_empty());
        assert!(state.relation_is_present(&object_id("public", "t")));
    }

    #[test]
    fn test_txn_rollback() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("BEGIN; CREATE TABLE t(id int); ROLLBACK;", &mut state).unwrap();
        assert!(state.local.transactions.is_empty());
        assert!(!state.relation_is_present(&object_id("public", "t")));
    }

    #[test]
    fn test_txn_savepoint_rollback_and_release() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        
        engine.analyze("BEGIN; CREATE TABLE t1(id int); SAVEPOINT sp1; CREATE TABLE t2(id int);", &mut state).unwrap();
        engine.analyze("ROLLBACK TO SAVEPOINT sp1;", &mut state).unwrap();
        assert!(state.relation_is_present(&object_id("public", "t1")));
        assert!(!state.relation_is_present(&object_id("public", "t2")));
        
        engine.analyze("CREATE TABLE t3(id int); RELEASE SAVEPOINT sp1;", &mut state).unwrap();
        assert_eq!(state.local.transactions.len(), 1); // Only main txn left
        assert!(state.relation_is_present(&object_id("public", "t3")));
    }
}

// ─────────────────────────────────────────────
// 5. AST Expression Parsing Exhaustion
// ─────────────────────────────────────────────
#[cfg(test)]
mod expression_parsing_tests {
    use super::helpers::*;
    use crate::analysis::state::AnalysisState;

    fn assert_expr(expr: &str) {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        assert!(engine.analyze(&format!("CREATE TABLE t(val INT DEFAULT {});", expr), &mut state).is_ok());
    }

    #[test] fn test_expr_literal() { assert_expr("42"); }
    #[test] fn test_expr_name_ref() { assert_expr("some_col"); }
    #[test] fn test_expr_call() { assert_expr("COALESCE(1, 2)"); }
    #[test] fn test_expr_bin_op() { assert_expr("1 + 2 * 3 = 7"); }
    #[test] fn test_expr_cast() { assert_expr("1::text"); }
    #[test] fn test_expr_prefix() { assert_expr("-42"); }
    #[test] fn test_expr_paren() { assert_expr("(1 + 2)"); }
    #[test] fn test_expr_case() { assert_expr("CASE WHEN true THEN 1 ELSE 0 END"); }
    #[test] fn test_expr_array() { assert_expr("ARRAY[1, 2, 3]"); }
    #[test] fn test_expr_between() { assert_expr("5 BETWEEN 1 AND 10"); }
    #[test] fn test_expr_index() { assert_expr("arr[1]"); }
    #[test] fn test_expr_slice() { assert_expr("arr[1:3]"); }
    #[test] fn test_expr_slice_omitted() { assert_expr("arr[2:]"); } // Tests ExprIr::Omitted
    #[test] fn test_expr_field() { assert_expr("(my_record).my_field"); }
    #[test] fn test_parser_syntax_error_rejection() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        assert!(engine.analyze("CREATE TABLE (;", &mut state).is_err());
    }
}

// ─────────────────────────────────────────────
// 6. Identifier Casing & Quoting Isolation
// ─────────────────────────────────────────────
#[cfg(test)]
mod identifier_casing_tests {
    use super::helpers::*;
    use crate::analysis::state::AnalysisState;
    use crate::model::relation::RelationOverlay;

    #[test]
    fn test_ident_unquoted_lowercase() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE Users (Id int);", &mut state).unwrap();
        assert!(state.relation_is_present(&object_id("public", "users")));
    }

    #[test]
    fn test_ident_quoted_preserve() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE \"MyTable\" (\"MyCol\" int);", &mut state).unwrap();
        let mixed_id = object_id("public", "MyTable");
        assert!(state.relation_is_present(&mixed_id));

        engine.analyze("ALTER TABLE \"MyTable\" RENAME TO \"NewTable\";", &mut state).unwrap();
        assert!(!state.relation_is_present(&mixed_id));
        assert!(state.relation_is_present(&object_id("public", "NewTable")));

        engine.analyze("ALTER TABLE \"NewTable\" RENAME COLUMN \"MyCol\" TO \"NewCol\";", &mut state).unwrap();
        let rel = state.get_relation(&object_id("public", "NewTable")).unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert!(r.has_column("NewCol"));
            assert!(!r.has_column("MyCol"));
        } else {
            panic!("NewTable must be Present");
        }
    }

    #[test]
    fn test_ident_schema_resolution() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(crate::db::cache::DbCache::new());
        engine.analyze("CREATE TABLE MySchema.MyTable (id int);", &mut state).unwrap();
        assert!(state.relation_is_present(&object_id("myschema", "mytable")));
    }
}
