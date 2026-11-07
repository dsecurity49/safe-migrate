use super::pre_state_footprint::for_mutation;
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterTable, AlterTableActionMutation, AlterTypeActionMutation, AlterTypeMutation,
    DropFunctionMutation, DropIndex, DropTable, Mutation, Rename,
};
use crate::_internal::analysis::state::{
    AnalysisState, CascadeResult, PreStateReadSet, ReadScope, RelationOverlay,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::db::cache::DbCache;
use crate::_internal::engine::engine::SafeMigrateEngine;
use crate::_internal::model::column::Column;
use crate::_internal::model::index::{IndexDefinition, IndexPredicate, index_keys};
use crate::_internal::model::relation::{Persistence, RelationKind, RelationState};
use crate::_internal::report::violations::Violation;
use crate::api::config::Config;
use std::collections::HashSet;

fn relation_id(name: &str) -> ObjectId {
    ObjectId::new("public", name)
}

fn insert_relation(state: &mut AnalysisState, name: &str, rows: u64) {
    let id = relation_id(name);
    state.local.relations.insert(
        id.clone(),
        RelationOverlay::Present(RelationState::new(
            id,
            ObjectId::new("public", "postgres"),
            0,
            Some(rows),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        )),
    );
}

fn selected_ids<K>(scope: &ReadScope<K>) -> &HashSet<K> {
    match scope {
        ReadScope::Selected(ids) => ids,
        _ => panic!("expected selected scope"),
    }
}

fn assert_no_reads(reads: &PreStateReadSet) {
    for (family, is_none) in [
        ("relations", matches!(reads.relations, ReadScope::None)),
        ("functions", matches!(reads.functions, ReadScope::None)),
        ("roles", matches!(reads.roles, ReadScope::None)),
        (
            "publications",
            matches!(reads.publications, ReadScope::None),
        ),
        (
            "subscriptions",
            matches!(reads.subscriptions, ReadScope::None),
        ),
        ("sequences", matches!(reads.sequences, ReadScope::None)),
        ("extensions", matches!(reads.extensions, ReadScope::None)),
        ("types", matches!(reads.types, ReadScope::None)),
        ("indexes", matches!(reads.indexes, ReadScope::None)),
        (
            "baseline_foreign_keys",
            matches!(reads.baseline_foreign_keys, ReadScope::None),
        ),
    ] {
        assert!(is_none, "{family} should not be captured");
    }
}

#[test]
fn mutations_without_pre_state_readers_capture_nothing() {
    let state = AnalysisState::new(DbCache::new());
    let reads = for_mutation(&state, &Mutation::BeginTransaction, None);
    assert_no_reads(&reads);
}

#[test]
fn alter_table_reads_only_its_target_and_foreign_key_parent() {
    let state = AnalysisState::new(DbCache::new());
    let target = relation_id("orders");
    let parent = relation_id("customers");
    let mutation = Mutation::AlterTable(AlterTable {
        id: target.clone(),
        only: false,
        action: AlterTableActionMutation::AddForeignKey {
            constraint_name: Some("orders_customer_fk".to_string()),
            to_table: parent.clone(),
            from_columns: vec!["customer_id".to_string()],
            to_columns: vec!["id".to_string()],
            not_valid: false,
        },
    });

    let reads = for_mutation(&state, &mutation, None);

    let relations = selected_ids(&reads.relations);
    assert_eq!(relations.len(), 2);
    assert!(relations.contains(&target));
    assert!(relations.contains(&parent));
    assert!(matches!(reads.types, ReadScope::None));
    assert!(matches!(reads.indexes, ReadScope::None));
}

#[test]
fn composite_type_changes_require_the_whole_relation_and_type_family() {
    let state = AnalysisState::new(DbCache::new());
    for action in [
        AlterTypeActionMutation::DropAttribute {
            name: "street".to_string(),
            if_exists: false,
            cascade: false,
        },
        AlterTypeActionMutation::AlterAttributeType {
            name: "street".to_string(),
            data_type: "text".to_string(),
            collation: None,
            cascade: false,
        },
    ] {
        let reads = for_mutation(
            &state,
            &Mutation::AlterType(AlterTypeMutation {
                id: ObjectId::new("public", "address"),
                action,
            }),
            None,
        );
        assert!(matches!(reads.relations, ReadScope::All));
        assert!(matches!(reads.types, ReadScope::All));
    }

    let reads = for_mutation(
        &state,
        &Mutation::AlterType(AlterTypeMutation {
            id: ObjectId::new("public", "mood"),
            action: AlterTypeActionMutation::AddValue {
                new_value: "happy".to_string(),
                neighbor: None,
                before: false,
            },
        }),
        None,
    );
    assert!(matches!(reads.relations, ReadScope::None));
    assert_eq!(
        selected_ids(&reads.types),
        &HashSet::from([ObjectId::new("public", "mood")])
    );
}

#[test]
fn drop_index_reads_the_index_attachment_and_its_relation() {
    let mut state = AnalysisState::new(DbCache::new());
    let table = relation_id("users");
    let index = relation_id("users_idx");
    insert_relation(&mut state, "users", 100);
    state.local.graph.add_edge(DependencyEdge::new(
        index.clone(),
        table.clone(),
        DependencyKind::IndexOnRelation {
            definition: IndexDefinition {
                method: Some("btree".into()),
                keys: index_keys(vec!["id".into()]),
                included: index_keys(Vec::new()),
                expression_keys: 0,
                unique: false,
                nulls_not_distinct: Some(false),
                predicate: IndexPredicate::None,
                unestablished: false,
                valid: true,
                ready: true,
                live: true,
            },
            dependency_columns: vec!["id".into()],
            dependency_columns_known: true,
            is_concurrent: false,
            is_immediate: true,
            eligibility_known: true,
        },
    ));

    let reads = for_mutation(
        &state,
        &Mutation::DropIndex(DropIndex {
            ids: vec![index.clone()],
            if_exists: false,
            concurrently: false,
            cascade: false,
        }),
        None,
    );

    assert_eq!(selected_ids(&reads.indexes), &HashSet::from([index]));
    assert_eq!(selected_ids(&reads.relations), &HashSet::from([table]));
}

#[test]
fn drop_table_cascade_reads_only_the_constraints_in_the_closure() {
    let state = AnalysisState::new(DbCache::new());
    let table = relation_id("orders");
    let constraint = (relation_id("line_items"), "line_items_order_fk".to_string());
    let cascade = CascadeResult {
        dropped_relations: HashSet::from([table.clone()]),
        dropped_indexes: HashSet::new(),
        dropped_constraints: HashSet::from([constraint.clone()]),
    };

    let reads = for_mutation(
        &state,
        &Mutation::DropTable(DropTable {
            ids: vec![table.clone()],
            if_exists: false,
            cascade: true,
        }),
        Some(&cascade),
    );

    assert_eq!(selected_ids(&reads.relations), &HashSet::from([table]));
    assert_eq!(
        selected_ids(&reads.baseline_foreign_keys),
        &HashSet::from([constraint])
    );
}

#[test]
fn dropping_routines_keeps_the_whole_function_family() {
    let state = AnalysisState::new(DbCache::new());
    let reads = for_mutation(
        &state,
        &Mutation::DropFunction(DropFunctionMutation {
            signatures: Vec::new(),
            if_exists: false,
            cascade: false,
        }),
        None,
    );
    assert!(matches!(reads.functions, ReadScope::All));
}

#[test]
fn rename_checks_every_keyed_family_for_the_old_identity() {
    let state = AnalysisState::new(DbCache::new());
    let old = relation_id("legacy_orders");
    let reads = for_mutation(
        &state,
        &Mutation::Rename(Rename {
            old_id: old.clone(),
            new_id: relation_id("orders"),
        }),
        None,
    );

    assert_eq!(
        selected_ids(&reads.relations),
        &HashSet::from([old.clone()])
    );
    assert_eq!(selected_ids(&reads.types), &HashSet::from([old.clone()]));
    assert_eq!(
        selected_ids(&reads.sequences),
        &HashSet::from([old.clone()])
    );
    assert_eq!(selected_ids(&reads.indexes), &HashSet::from([old.clone()]));
}

#[test]
fn alter_domain_reads_the_domain_and_every_relation_using_it() {
    let mut state = AnalysisState::new(DbCache::new());
    let domain = ObjectId::new("public", "positive_int");
    let table = relation_id("scores");
    insert_relation(&mut state, "scores", 100);
    let Some(RelationOverlay::Present(relation)) = state.local.relations.get_mut(&table) else {
        panic!("scores must exist");
    };
    let mut column =
        Column::migration_created("score".into(), Some("positive_int".into()), true, None);
    column.type_id = Some(domain.clone());
    relation.columns.push(column);

    let reads = for_mutation(
        &state,
        &Mutation::AlterDomain(crate::_internal::analysis::mutations::AlterDomainMutation {
            id: domain.clone(),
            action: None,
        }),
        None,
    );

    assert_eq!(selected_ids(&reads.types), &HashSet::from([domain]));
    assert_eq!(selected_ids(&reads.relations), &HashSet::from([table]));
}

#[test]
fn selective_capture_matches_full_capture_for_every_pre_state_reader() {
    let mut selective_state = AnalysisState::new(differential_cache());
    let mut full_state = AnalysisState::new(differential_cache());
    let selective = SafeMigrateEngine::new(Config::default());
    let full = SafeMigrateEngine::new(Config::default()).with_full_pre_state_for_tests();
    let mut observed_rules = HashSet::new();

    for statement in differential_chain() {
        let selective_violations = selective
            .analyze(statement, &mut selective_state)
            .unwrap_or_else(|errors| panic!("selective failed on {statement}: {errors:?}"));
        let full_violations = full
            .analyze(statement, &mut full_state)
            .unwrap_or_else(|errors| panic!("full failed on {statement}: {errors:?}"));
        assert_eq!(
            comparable(&selective_violations),
            comparable(&full_violations),
            "selective pre-state diverged from full pre-state after: {statement}"
        );
        observed_rules.extend(
            full_violations
                .iter()
                .map(|violation| violation.rule_id.to_string()),
        );
    }

    assert!(
        observed_rules.contains("type-change-rewrite"),
        "differential chain did not exercise type-change pre-state reads: {observed_rules:?}"
    );
    assert!(
        observed_rules.contains("require-concurrent-drop-index"),
        "differential chain did not exercise index pre-state reads: {observed_rules:?}"
    );
}

#[test]
fn statement_undo_journal_matches_full_checkpoint_after_every_statement() {
    let mut journal_state = AnalysisState::new(differential_cache());
    let mut full_state = AnalysisState::new(differential_cache());
    let journal = SafeMigrateEngine::new(Config::default());
    let full = SafeMigrateEngine::new(Config::default()).with_full_statement_checkpoint_for_tests();

    let statements = [
        "CREATE TABLE users (id integer PRIMARY KEY, name text);",
        "ALTER TABLE users ADD COLUMN retained text, ADD COLUMN also_retained integer;",
        "ALTER TABLE users ADD COLUMN rolled_back text, DROP COLUMN missing_column;",
        "ALTER TABLE users ADD COLUMN after_conflict integer;",
        "CREATE INDEX users_after_conflict_idx ON users (after_conflict);",
        "DROP INDEX users_after_conflict_idx;",
        "SAVEPOINT outside_transaction;",
        "COMMIT AND CHAIN;",
        "BEGIN;",
        "SAVEPOINT sp;",
        "ROLLBACK TO missing;",
        "ROLLBACK;",
        "BEGIN;",
        "SAVEPOINT sp;",
        "CREATE TABLE control_table (id integer);",
        "ROLLBACK TO sp;",
        "RELEASE sp;",
        "COMMIT;",
        "ALTER TABLE users RENAME TO users_renamed;",
        "DROP TABLE users_renamed;",
    ];
    let mut saw_conflict = false;

    for statement in statements {
        let journal_violations = journal
            .analyze(statement, &mut journal_state)
            .unwrap_or_else(|errors| panic!("journal failed on {statement}: {errors:?}"));
        let full_violations = full
            .analyze(statement, &mut full_state)
            .unwrap_or_else(|errors| panic!("full failed on {statement}: {errors:?}"));
        assert_eq!(
            comparable(&journal_violations),
            comparable(&full_violations),
            "journal findings diverged from full checkpoint after: {statement}"
        );
        assert_eq!(
            journal_state, full_state,
            "statement journal state diverged after: {statement}"
        );
        saw_conflict |= journal_violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict");
    }

    assert!(
        saw_conflict,
        "chain did not exercise a rolled-back statement"
    );
}

fn differential_cache() -> DbCache {
    let mut cache = crate::common::synced_cache();
    for (name, rows) in [("baseline_orders", 5_000_u64), ("baseline_users", 25)] {
        let id = ObjectId::new("public", name);
        cache.insert_baseline(
            id.clone(),
            RelationState::new(
                id,
                ObjectId::new("public", "postgres"),
                0,
                Some(rows),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
    }
    cache
}

fn differential_chain() -> &'static [&'static str] {
    &[
        "ALTER TABLE baseline_orders ADD COLUMN note text DEFAULT 'x';",
        "ALTER TABLE baseline_orders ALTER COLUMN id TYPE bigint;",
        "CREATE TYPE address AS (city text, zip text);",
        "CREATE DOMAIN positive_int AS integer CHECK (VALUE > 0);",
        "CREATE TABLE users (id integer PRIMARY KEY, addr address, score positive_int);",
        "CREATE INDEX users_idx ON users (id);",
        "CREATE SEQUENCE users_seq;",
        "CREATE FUNCTION f() RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT 1';",
        "ALTER TABLE users ADD COLUMN name text;",
        "ALTER TABLE users ALTER COLUMN id TYPE bigint;",
        "ALTER TABLE users ADD CONSTRAINT users_fk FOREIGN KEY (score) REFERENCES users(id);",
        "CREATE MATERIALIZED VIEW users_mv AS SELECT id FROM users;",
        "REFRESH MATERIALIZED VIEW users_mv;",
        "DROP INDEX users_idx;",
        "ALTER DOMAIN positive_int SET NOT NULL;",
        "TRUNCATE users;",
        "ALTER TYPE address DROP ATTRIBUTE zip;",
        "ALTER TABLE users RENAME TO users_renamed;",
        "DROP TABLE users_renamed CASCADE;",
        "DROP SEQUENCE users_seq;",
        "DROP FUNCTION f();",
        "DROP TYPE address;",
        "DROP DOMAIN positive_int;",
        "DROP TABLE baseline_orders;",
    ]
}

fn comparable(violations: &[Violation]) -> Vec<String> {
    violations
        .iter()
        .map(|violation| {
            format!(
                "{}|{}|{:?}|{:?}|{}|{:?}",
                violation.rule_id,
                violation.object_name,
                violation.tier,
                violation.object_kind,
                violation.reason,
                violation.source_range
            )
        })
        .collect()
}
