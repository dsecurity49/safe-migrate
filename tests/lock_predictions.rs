use crate::common::*;
use safe_migrate::_internal::analysis::state::AnalysisState;
use safe_migrate::_internal::report::violations::{ObjectKind, Violation, ViolationTier};

fn lock_findings(setup: &str, sql: &str) -> Vec<Violation> {
    let engine = setup_engine();
    let mut state = AnalysisState::new(synced_cache());
    engine.analyze(setup, &mut state).unwrap();
    engine.analyze(sql, &mut state).unwrap()
}

fn lock_reasons(setup: &str, sql: &str) -> Vec<String> {
    lock_findings(setup, sql)
        .into_iter()
        .filter(|violation| violation.rule_id == "lock-risk")
        .map(|violation| violation.reason)
        .collect()
}

fn assert_reason_contains(setup: &str, sql: &str, expected: &[&str]) {
    let reasons = lock_reasons(setup, sql);
    assert!(
        reasons
            .iter()
            .any(|reason| expected.iter().all(|needle| reason.contains(needle))),
        "expected a lock-risk reason containing {expected:?}, got {reasons:?}"
    );
}

const TABLES: &str = "
    CREATE TABLE parent (id integer PRIMARY KEY);
    CREATE TABLE child (id integer, parent_id integer, note text);
";

#[test]
fn check_constraint_predicts_access_exclusive() {
    let findings = lock_findings(
        TABLES,
        "ALTER TABLE child ADD CONSTRAINT child_check CHECK (id > 0);",
    );
    let v = findings
        .iter()
        .find(|v| v.rule_id == "lock-risk" && v.reason.contains("ACCESS EXCLUSIVE"))
        .expect("lock-risk ACCESS EXCLUSIVE finding for valid CHECK");
    assert_eq!(
        v.tier,
        ViolationTier::Tier3,
        "lock-risk must be Tier3: {v:?}"
    );
    assert_eq!(v.object_kind, ObjectKind::Table, "{v:?}");
    assert!(v.object_name.contains("child"), "{v:?}");
    assert!(!v.recipe.is_empty(), "recipe must not be empty: {v:?}");
}

#[test]
fn foreign_key_predicts_share_row_exclusive_on_both_tables() {
    let findings = lock_findings(
        TABLES,
        "ALTER TABLE child ADD CONSTRAINT child_fk FOREIGN KEY (parent_id) REFERENCES parent(id);",
    );
    let v = findings
        .iter()
        .find(|v| {
            v.rule_id == "lock-risk"
                && v.reason.contains("SHARE ROW EXCLUSIVE")
                && v.reason.contains("table public.child")
                && v.reason.contains("referenced table public.parent")
        })
        .expect("lock-risk SHARE ROW EXCLUSIVE on both tables");
    assert_eq!(v.tier, ViolationTier::Tier3, "{v:?}");
    assert_eq!(v.object_kind, ObjectKind::Table, "{v:?}");
    assert!(!v.recipe.is_empty(), "{v:?}");
}

#[test]
fn validate_constraint_predicts_share_update_exclusive() {
    let findings = lock_findings(
        TABLES,
        "ALTER TABLE child ADD CONSTRAINT child_check CHECK (id > 0) NOT VALID;
         ALTER TABLE child VALIDATE CONSTRAINT child_check;",
    );
    let v = findings
        .iter()
        .find(|v| v.rule_id == "lock-risk" && v.reason.contains("SHARE UPDATE EXCLUSIVE"))
        .expect("lock-risk SHARE UPDATE EXCLUSIVE for VALIDATE");
    assert_eq!(v.tier, ViolationTier::Tier3, "{v:?}");
    assert_eq!(v.object_kind, ObjectKind::Table, "{v:?}");
    assert!(v.object_name.contains("child"), "{v:?}");
    assert!(!v.recipe.is_empty(), "{v:?}");
}

#[test]
fn set_storage_predicts_access_exclusive() {
    let findings = lock_findings(
        TABLES,
        "ALTER TABLE child ALTER COLUMN note SET STORAGE EXTERNAL;",
    );
    assert!(
        findings.iter().any(|violation| {
            violation.rule_id == "set-storage-lock"
                && violation.reason.contains("ACCESS EXCLUSIVE")
                && violation.reason.contains("table public.child")
        }),
        "SET STORAGE must report its own lock advisory: {findings:?}"
    );
}

#[test]
fn set_storage_emits_one_lock_finding() {
    let findings = lock_findings(
        TABLES,
        "ALTER TABLE child ALTER COLUMN note SET STORAGE EXTERNAL;",
    );
    let lock_findings = findings
        .iter()
        .filter(|violation| {
            violation.rule_id == "lock-risk" || violation.rule_id == "set-storage-lock"
        })
        .count();
    assert_eq!(
        lock_findings, 1,
        "SET STORAGE must not emit both the specific and generic lock advisories: {findings:?}"
    );
}

#[test]
fn set_access_method_predicts_access_exclusive() {
    assert_reason_contains(
        TABLES,
        "ALTER TABLE child SET ACCESS METHOD heap;",
        &["ACCESS EXCLUSIVE", "table public.child"],
    );
}

#[test]
fn unique_constraint_predicts_access_exclusive_and_share() {
    assert_reason_contains(
        TABLES,
        "ALTER TABLE child ADD CONSTRAINT child_unique UNIQUE (note);",
        &["ACCESS EXCLUSIVE", "SHARE on table public.child"],
    );
}

#[test]
fn create_index_predicts_share() {
    assert_reason_contains(
        TABLES,
        "CREATE INDEX child_note_idx ON child(note);",
        &["SHARE on table public.child"],
    );
}

#[test]
fn drop_index_predicts_access_exclusive_on_table() {
    let findings = lock_findings(
        TABLES,
        "CREATE INDEX child_note_idx ON child(note); DROP INDEX child_note_idx;",
    );
    assert!(
        findings.iter().any(|violation| {
            violation.rule_id == "lock-risk"
                && violation.reason.contains("Dropping an index")
                && violation.reason.contains("ACCESS EXCLUSIVE")
                && violation.reason.contains("table public.child")
        }),
        "missing drop-index lock prediction: {findings:?}"
    );
}

#[test]
fn reindex_table_predicts_share() {
    assert_reason_contains(
        TABLES,
        "REINDEX TABLE child;",
        &["SHARE on table public.child"],
    );
}

#[test]
fn refresh_materialized_view_predicts_access_exclusive() {
    assert_reason_contains(
        TABLES,
        "CREATE MATERIALIZED VIEW child_mv AS SELECT id FROM child;
         REFRESH MATERIALIZED VIEW child_mv;",
        &["ACCESS EXCLUSIVE", "materialized view public.child_mv"],
    );
}

#[test]
fn type_change_predicts_access_exclusive() {
    assert_reason_contains(
        TABLES,
        "ALTER TABLE child ALTER COLUMN note TYPE varchar(20);",
        &["ACCESS EXCLUSIVE", "table public.child"],
    );
}

#[test]
fn type_change_lock_reason_does_not_claim_a_rewrite() {
    let reasons = lock_reasons(
        TABLES,
        "ALTER TABLE child ALTER COLUMN note TYPE varchar(20);",
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("ACCESS EXCLUSIVE") && !reason.contains("rewriting")),
        "type-change lock risk must not duplicate rewrite cost: {reasons:?}"
    );
}

#[test]
fn set_not_null_lock_reason_does_not_claim_a_scan() {
    let reasons = lock_reasons(TABLES, "ALTER TABLE child ALTER COLUMN note SET NOT NULL;");
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("ACCESS EXCLUSIVE") && !reason.contains("scanning")),
        "set-not-null lock risk must not duplicate scan cost: {reasons:?}"
    );
}

#[test]
fn attach_partition_predicts_access_exclusive_on_partition_and_share_update_on_parent() {
    assert_reason_contains(
        "CREATE TABLE part_parent (id integer) PARTITION BY RANGE (id);
         CREATE TABLE part_child (id integer);",
        "ALTER TABLE part_parent ATTACH PARTITION part_child FOR VALUES FROM (0) TO (10);",
        &[
            "ACCESS EXCLUSIVE on partition public.part_child",
            "SHARE UPDATE EXCLUSIVE on parent table public.part_parent",
        ],
    );
}

#[test]
fn detach_partition_concurrently_predicts_share_update_exclusive_on_parent() {
    // DETACH PARTITION CONCURRENTLY (PG 14+) cannot run inside a transaction
    // block, so a live pg_locks probe is not feasible. The unit test covers the
    // prediction directly.
    let setup = "CREATE TABLE part_parent (id integer) PARTITION BY RANGE (id);
                 CREATE TABLE part_child (id integer);
                 ALTER TABLE part_parent ATTACH PARTITION part_child FOR VALUES FROM (0) TO (10);";
    let findings = lock_findings(
        setup,
        "ALTER TABLE part_parent DETACH PARTITION part_child CONCURRENTLY;",
    );
    let v = findings
        .iter()
        .find(|v| {
            v.rule_id == "lock-risk"
                && v.reason.contains("SHARE UPDATE EXCLUSIVE")
                && v.reason.contains("parent table public.part_parent")
        })
        .expect("DETACH CONCURRENTLY must predict SHARE UPDATE EXCLUSIVE on parent");
    assert_eq!(v.tier, ViolationTier::Tier3, "{v:?}");
    // Child still gets ACCESS EXCLUSIVE during the first phase.
    assert!(
        v.reason.contains("ACCESS EXCLUSIVE") && v.reason.contains("partition public.part_child"),
        "child must still get ACCESS EXCLUSIVE: {v:?}"
    );
}

#[test]
fn detach_partition_predicts_access_exclusive_on_both() {
    assert_reason_contains(
        "CREATE TABLE part_parent (id integer) PARTITION BY RANGE (id);
         CREATE TABLE part_child (id integer);
         ALTER TABLE part_parent ATTACH PARTITION part_child FOR VALUES FROM (0) TO (10);",
        "ALTER TABLE part_parent DETACH PARTITION part_child;",
        &[
            "ACCESS EXCLUSIVE on parent table public.part_parent",
            "and partition public.part_child",
        ],
    );
}

#[test]
fn truncate_predicts_access_exclusive() {
    assert_reason_contains(
        TABLES,
        "TRUNCATE child;",
        &["ACCESS EXCLUSIVE", "table public.child"],
    );
}

#[test]
fn temporary_index_drop_does_not_report_lock_risk() {
    let findings = lock_findings(
        "CREATE TEMP TABLE temp_child (id integer);",
        "CREATE INDEX temp_child_idx ON temp_child(id); DROP INDEX temp_child_idx;",
    );
    assert!(
        !findings.iter().any(|violation| {
            violation.rule_id == "lock-risk" || violation.rule_id == "set-storage-lock"
        }),
        "temporary relations must not report lock risk: {findings:?}"
    );
}

#[test]
fn small_table_check_keeps_lock_risk_but_drops_scan_warning() {
    let engine = setup_engine();
    let mut state = AnalysisState::new(synced_cache());
    engine
        .analyze("CREATE TABLE small_table (id integer);", &mut state)
        .unwrap();
    for overlay in state.local.relations.values_mut() {
        if let safe_migrate::_internal::model::relation::RelationOverlay::Present(relation) =
            overlay
        {
            relation.estimated_rows = Some(10);
            relation.last_analyze = Some("2026-01-01 00:00:00".to_string());
        }
    }

    let findings = engine
        .analyze(
            "ALTER TABLE small_table ADD CONSTRAINT small_check CHECK (id > 0);",
            &mut state,
        )
        .unwrap();
    assert!(
        findings.iter().any(|violation| {
            violation.rule_id == "lock-risk" && violation.reason.contains("ACCESS EXCLUSIVE")
        }),
        "small tables must still report the lock: {findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|violation| violation.rule_id == "blocking-constraint"),
        "small tables must not get a size-based scan warning: {findings:?}"
    );
}

#[test]
fn domain_constraint_predicts_share_on_using_tables() {
    assert_reason_contains(
        "CREATE DOMAIN posint AS integer;
         CREATE TABLE domtab (value posint);",
        "ALTER DOMAIN posint ADD CONSTRAINT pos_check CHECK (VALUE > 0);",
        &["SHARE on table public.domtab"],
    );
}

#[test]
fn not_valid_check_still_predicts_access_exclusive() {
    assert_reason_contains(
        TABLES,
        "ALTER TABLE child ADD CONSTRAINT child_check CHECK (id > 0) NOT VALID;",
        &[
            "Adding a CHECK constraint as NOT VALID",
            "ACCESS EXCLUSIVE on table public.child",
        ],
    );
}

#[test]
fn not_valid_foreign_key_predicts_share_row_exclusive_on_both_tables() {
    assert_reason_contains(
        TABLES,
        "ALTER TABLE child ADD CONSTRAINT child_fk
           FOREIGN KEY (parent_id) REFERENCES parent(id) NOT VALID;",
        &[
            "Adding a FOREIGN KEY constraint as NOT VALID",
            "SHARE ROW EXCLUSIVE",
            "referenced table public.parent",
        ],
    );
}

#[test]
fn validate_foreign_key_predicts_row_share_on_referenced_table() {
    assert_reason_contains(
        TABLES,
        "ALTER TABLE child ADD CONSTRAINT child_fk
           FOREIGN KEY (parent_id) REFERENCES parent(id) NOT VALID;
         ALTER TABLE child VALIDATE CONSTRAINT child_fk;",
        &[
            "SHARE UPDATE EXCLUSIVE on table public.child",
            "ROW SHARE on referenced table public.parent",
        ],
    );
}

#[test]
fn attach_partition_predicts_default_partition_lock() {
    assert_reason_contains(
        "CREATE TABLE part_parent (id integer) PARTITION BY RANGE (id);
         CREATE TABLE part_default PARTITION OF part_parent DEFAULT;
         CREATE TABLE part_child (id integer);",
        "ALTER TABLE part_parent ATTACH PARTITION part_child FOR VALUES FROM (0) TO (10);",
        &["default partition public.part_default"],
    );
}

#[test]
fn attach_partition_predicts_subpartition_locks() {
    assert_reason_contains(
        "CREATE TABLE part_parent (id integer) PARTITION BY RANGE (id);
         CREATE TABLE part_child (id integer) PARTITION BY RANGE (id);
         CREATE TABLE part_child_a (id integer);
         ALTER TABLE part_child ATTACH PARTITION part_child_a
           FOR VALUES FROM (0) TO (10);",
        "ALTER TABLE part_parent ATTACH PARTITION part_child FOR VALUES FROM (0) TO (100);",
        &["partition public.part_child_a"],
    );
}

#[test]
fn primary_key_using_index_on_nullable_column_predicts_scan() {
    assert_reason_contains(
        "CREATE TABLE pk_t (id integer);
         CREATE UNIQUE INDEX pk_t_id_key ON pk_t (id);",
        "ALTER TABLE pk_t ADD CONSTRAINT pk_t_pkey PRIMARY KEY USING INDEX pk_t_id_key;",
        &[
            "Adding a PRIMARY KEY constraint using an existing index",
            "ACCESS EXCLUSIVE on table public.pk_t",
            "scanning the table",
        ],
    );
}

#[test]
fn primary_key_using_index_on_not_null_column_does_not_claim_scan() {
    let reasons = lock_reasons(
        "CREATE TABLE pk_t (id integer NOT NULL);
         CREATE UNIQUE INDEX pk_t_id_key ON pk_t (id);",
        "ALTER TABLE pk_t ADD CONSTRAINT pk_t_pkey PRIMARY KEY USING INDEX pk_t_id_key;",
    );
    let reason = reasons
        .iter()
        .find(|reason| reason.contains("PRIMARY KEY constraint using an existing index"))
        .expect("PRIMARY KEY USING INDEX lock finding");
    assert!(
        !reason.contains("scanning the table"),
        "a NOT NULL index must not claim a scan: {reason}"
    );
}

#[test]
fn unique_using_index_predicts_access_exclusive() {
    assert_reason_contains(
        "CREATE TABLE uq_t (id integer);
         CREATE UNIQUE INDEX uq_t_id_key ON uq_t (id);",
        "ALTER TABLE uq_t ADD CONSTRAINT uq_t_key UNIQUE USING INDEX uq_t_id_key;",
        &[
            "Adding a UNIQUE constraint using an existing index",
            "ACCESS EXCLUSIVE on table public.uq_t",
        ],
    );
}

#[test]
fn reindex_index_predicts_share_on_table_and_access_exclusive_on_index() {
    assert_reason_contains(
        "CREATE TABLE re_t (id integer);
         CREATE INDEX re_t_idx ON re_t (id);",
        "REINDEX INDEX re_t_idx;",
        &[
            "SHARE on table public.re_t",
            "ACCESS EXCLUSIVE on index public.re_t_idx",
        ],
    );
}

#[test]
fn reindex_schema_predicts_each_index_lock() {
    assert_reason_contains(
        "CREATE SCHEMA re_schema;
         CREATE TABLE re_schema.re_t (id integer);
         CREATE INDEX re_schema.re_t_idx ON re_schema.re_t (id);",
        "REINDEX SCHEMA re_schema;",
        &[
            "SHARE on table re_schema.re_t",
            "ACCESS EXCLUSIVE on index re_schema.re_t_idx",
        ],
    );
}

#[test]
fn detach_partition_predicts_share_on_referencing_table() {
    assert_reason_contains(
        "CREATE TABLE det_parent (id integer PRIMARY KEY) PARTITION BY RANGE (id);
         CREATE TABLE det_child (id integer NOT NULL);
         ALTER TABLE det_parent ATTACH PARTITION det_child FOR VALUES FROM (0) TO (10);
         CREATE TABLE det_ref (parent_id integer REFERENCES det_parent(id));",
        "ALTER TABLE det_parent DETACH PARTITION det_child;",
        &["SHARE on referencing table public.det_ref"],
    );
}

#[test]
fn lock_reason_mentions_transaction_lifetime() {
    assert_reason_contains(
        TABLES,
        "ALTER TABLE child ADD CONSTRAINT child_check CHECK (id > 0);",
        &["held until the transaction ends"],
    );
}
