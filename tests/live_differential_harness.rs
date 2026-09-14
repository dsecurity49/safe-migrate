use crate::common::database_hosts_are_local;
use postgres::{Client, Config as PostgresConfig, NoTls};
use safe_migrate::_internal::analysis::graph::DependencyKind;
use safe_migrate::_internal::analysis::state::AnalysisState;
use safe_migrate::_internal::ast::identifiers::ObjectId;
use safe_migrate::_internal::db::cache::DbCache;
use safe_migrate::_internal::engine::engine::SafeMigrateEngine;
use safe_migrate::_internal::model::constraint::ConstraintKind;
use safe_migrate::_internal::model::function::{FunctionOverlay, Volatility};
use safe_migrate::_internal::model::relation::{Privilege, RelationKind, RelationOverlay};
use safe_migrate::_internal::model::schema::SchemaOverlay;
use safe_migrate::_internal::model::sequence::{SequenceKind, SequenceOverlay};
use safe_migrate::_internal::model::trigger::TriggerOverlay;
use safe_migrate::_internal::model::types::{TypeKind, TypeOverlay};
use safe_migrate::_internal::sync::{populate_cache, populate_cache_in_current_transaction};
use safe_migrate::api::Config;
use serde::Deserialize;
use squawk_syntax::ast::{self, AstNode};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const VERBOSITY_ENV: &str = "SAFE_MIGRATE_DIFF_VERBOSITY";
const RULE_FILTER_ENV: &str = "SAFE_MIGRATE_DIFF_RULE";
const FIXTURE_FILTER_ENV: &str = "SAFE_MIGRATE_DIFF_FIXTURE";
const DATABASE_NAME_ENV: &str = "SAFE_MIGRATE_DIFF_DATABASE";
const REQUIRE_LIVE_ENV: &str = "SAFE_MIGRATE_REQUIRE_LIVE";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DifferentialManifest {
    rules: Vec<RuleManifest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleManifest {
    rule_dir: String,
    enabled: bool,
    fixtures: Vec<String>,
    #[serde(default = "default_transactional")]
    transactional: bool,
    #[serde(default)]
    fixture_transactional: BTreeMap<String, bool>,
    #[serde(default)]
    fixture_autocommit: BTreeSet<String>,
    #[serde(default)]
    fixture_min_pg_version: BTreeMap<String, u32>,
    #[serde(default)]
    excluded_fixtures: Vec<FixtureExclusion>,
    schemas: Vec<String>,
    scope: Vec<ComparisonScope>,
    #[serde(default)]
    fixture_scopes: BTreeMap<String, Vec<ComparisonScope>>,
    #[serde(default)]
    expected_live_errors: BTreeMap<String, ExpectedLiveError>,
    #[serde(default)]
    required_relations: Vec<String>,
    #[serde(default)]
    required_role_edges: Vec<RequiredRoleEdge>,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredRoleEdge {
    member: String,
    role: String,
    kind: RequiredRoleEdgeKind,
    #[serde(default)]
    min_pg_version_num: Option<u32>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RequiredRoleEdgeKind {
    CanSetRoleTo,
    CanAdministerMembership,
    CanInheritFrom,
    MemberOfWithoutSet,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedLiveError {
    sqlstate: String,
    simulator_rule: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureExclusion {
    fixture: String,
    reason: String,
}

fn default_transactional() -> bool {
    true
}

fn split_fixture_statements(sql: &str) -> Result<Vec<String>, String> {
    let parsed = ast::SourceFile::parse(sql);
    if !parsed.errors().is_empty() {
        return Err(format!("SQL parse errors: {:?}", parsed.errors()));
    }
    // Typed statement boundaries preserve semicolons inside bodies and literals.
    Ok(parsed
        .tree()
        .stmts()
        .map(|stmt| stmt.syntax().text().to_string())
        .collect())
}

#[test]
fn autocommit_fixture_split_preserves_bodies_and_literals() {
    let statements = split_fixture_statements("-- leading ;\n CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $$ SELECT ';'; $$; SELECT ';'; -- trailing ;").unwrap();
    assert_eq!(statements.len(), 2);
    assert!(statements[0].contains("$$ SELECT ';'; $$"));
    assert_eq!(statements[1], "SELECT ';';");
    assert!(split_fixture_statements("CREATE TABLE broken (").is_err());
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ComparisonScope {
    Schemas,
    Roles,
    Sequences,
    Relations,
    Columns,
    Indexes,
    Constraints,
    ForeignKeys,
    Functions,
    Types,
    Privileges,
    Policies,
    Triggers,
    ViewDependencies,
    Partitions,
    Publications,
    Subscriptions,
    ExtendedStatistics,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NormalizedState {
    schemas: BTreeMap<String, String>,
    roles: BTreeSet<NormalizedRoleMembership>,
    sequences: BTreeMap<String, NormalizedSequence>,
    relations: BTreeMap<String, NormalizedRelation>,
    indexes: BTreeSet<NormalizedIndex>,
    foreign_keys: BTreeSet<NormalizedForeignKey>,
    constraints: BTreeSet<NormalizedConstraint>,
    functions: BTreeMap<String, String>,
    types: BTreeMap<String, NormalizedType>,
    privileges: BTreeSet<NormalizedPrivilege>,
    policies: BTreeSet<NormalizedPolicy>,
    triggers: BTreeMap<(String, String), NormalizedTrigger>,
    partition_edges: BTreeSet<(String, String, bool, bool)>,
    view_dependencies: BTreeSet<(String, String)>,
    publications: BTreeMap<String, NormalizedPublication>,
    subscriptions: BTreeMap<String, NormalizedSubscription>,
    extended_statistics: BTreeMap<String, NormalizedExtendedStatistics>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedRoleMembership {
    member: String,
    role: String,
    admin: bool,
    inherit: bool,
    set: bool,
    grantor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedSequence {
    owner: String,
    owned_by: Option<String>,
    kind: SequenceKind,
    data_type: String,
    start_value: i64,
    increment: i64,
    min_value: i64,
    max_value: i64,
    cache_size: i64,
    cycle: bool,
    persistence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedRelation {
    kind: NormalizedRelationKind,
    owner: String,
    partition_strategy: Option<String>,
    partition_is_default: Option<bool>,
    partition_bound: Option<String>,
    partition_constraint: Option<String>,
    persistence: String,
    tablespace: Option<String>,
    access_method: Option<String>,
    cluster_index: Option<String>,
    row_security: Option<bool>,
    force_row_security: Option<bool>,
    replica_identity: Option<String>,
    table_options: BTreeMap<String, String>,
    of_type: Option<String>,
    rules: BTreeMap<String, String>,
    columns: BTreeMap<String, NormalizedColumn>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum NormalizedRelationKind {
    Table,
    View,
    MaterializedView,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedColumn {
    data_type: String,
    is_nullable: bool,
    has_default: bool,
    generated: Option<bool>,
    generation: Option<String>,
    identity_generation: Option<String>,
    storage: Option<String>,
    compression: Option<String>,
    statistics_target: Option<i32>,
    options: BTreeMap<String, String>,
}

fn normalize_statistics_target(target: Option<i32>) -> Option<i32> {
    target.filter(|value| *value != -1)
}

fn normalize_partition_constraint(constraint: Option<&str>) -> Option<String> {
    constraint
        .filter(|value| !value.trim_start().starts_with("satisfies_hash_partition("))
        .map(str::to_owned)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedIndex {
    index: String,
    table: String,
    using_method: Option<String>,
    key_columns: Vec<String>,
    included_columns: Vec<String>,
    has_expression_keys: bool,
    has_predicate: bool,
    is_unique: bool,
    is_immediate: bool,
    is_valid: bool,
    is_ready: bool,
    is_live: bool,
    has_default_sort_order: bool,
    has_default_opclasses: bool,
    has_default_collations: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedForeignKey {
    from_table: String,
    to_table: String,
    constraint_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedConstraint {
    table: String,
    name: String,
    kind: String,
    validated: bool,
    definition: Option<String>,
    backing_index: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedPolicy {
    table: String,
    policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedTrigger {
    function: String,
    enabled_mode: String,
    row_level: bool,
    parent_trigger: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedExtendedStatistics {
    table: String,
    kinds: Vec<String>,
    columns: Vec<String>,
    expressions: Option<String>,
    target: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum NormalizedType {
    Enum { variants: Vec<String> },
    Domain { base_type: String },
    Base,
    Composite,
    Range,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedPrivilege {
    table: String,
    grantee: String,
    privilege: String,
    grantable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedPublication {
    owner: Option<String>,
    scope: String,
    params: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedSubscription {
    owner: Option<String>,
    publications: Vec<String>,
    params: String,
    enabled: bool,
    slot_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MismatchCategory {
    MissingSchemaInSimulator,
    ExtraSchemaInSimulator,
    SchemaOwnerMismatch,
    MissingSequenceInSimulator,
    ExtraSequenceInSimulator,
    SequenceDefinitionMismatch,
    MissingObjectInSimulator,
    ExtraObjectInSimulator,
    RelationKindMismatch,
    RelationOwnerMismatch,
    PartitionStrategyMismatch,
    RelationDefinitionMismatch,
    ColumnMismatch,
    MissingIndexInSimulator,
    ExtraIndexInSimulator,
    MissingForeignKeyInSimulator,
    ExtraForeignKeyInSimulator,
    MissingConstraintInSimulator,
    ExtraConstraintInSimulator,
    MissingFunctionInSimulator,
    ExtraFunctionInSimulator,
    FunctionVolatilityMismatch,
    MissingTypeInSimulator,
    ExtraTypeInSimulator,
    TypeDefinitionMismatch,
    MissingPrivilegeInSimulator,
    ExtraPrivilegeInSimulator,
    MissingPolicyInSimulator,
    ExtraPolicyInSimulator,
    MissingTriggerInSimulator,
    ExtraTriggerInSimulator,
    TriggerFunctionMismatch,
    TriggerEnableModeMismatch,
    TriggerDefinitionMismatch,
    MissingExtendedStatisticsInSimulator,
    ExtraExtendedStatisticsInSimulator,
    ExtendedStatisticsDefinitionMismatch,
    MissingPartitionEdgeInSimulator,
    ExtraPartitionEdgeInSimulator,
    MissingViewDependencyInSimulator,
    ExtraViewDependencyInSimulator,
    MissingPublicationInSimulator,
    ExtraPublicationInSimulator,
    PublicationDefinitionMismatch,
    MissingSubscriptionInSimulator,
    ExtraSubscriptionInSimulator,
    SubscriptionDefinitionMismatch,
    RoleMembershipMismatch,
    BaselineObjectAbsent,
    LiveExecutionFailed,
    ExpectedLiveErrorMismatch,
    MissingExpectedSimulatorFinding,
    UnexpectedLiveSuccess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RootCauseClassification {
    SimulatorBug,
    BaselineSetupGap,
    EnvironmentIssue,
    HarnessBug,
    #[allow(dead_code)]
    UnsupportedNondifferentiableBehavior,
}

#[derive(Debug, Clone)]
struct Mismatch {
    rule_dir: String,
    fixture: String,
    category: MismatchCategory,
    root_cause: RootCauseClassification,
    note: String,
}

#[test]
#[ignore = "requires a live local PostgreSQL database via DATABASE_URL"]
fn live_postgres_differential_harness() {
    let verbosity = differential_verbosity();
    let harness_started = Instant::now();
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(value) => value,
        Err(_) => {
            assert!(
                !live_database_is_required(),
                "live differential harness requires DATABASE_URL"
            );
            eprintln!("skipping live differential harness: DATABASE_URL is not set");
            return;
        }
    };

    assert!(
        !database_url.trim().is_empty(),
        "live differential harness requires a nonempty DATABASE_URL"
    );
    let database_config: PostgresConfig = database_url
        .parse()
        .expect("live differential DATABASE_URL is invalid");
    assert!(
        database_hosts_are_local(&database_config),
        "live differential harness accepts only localhost or Unix-socket databases"
    );

    let mut client = match database_config.connect(NoTls) {
        Ok(client) => client,
        Err(error) => {
            assert!(
                !live_database_is_required(),
                "live differential harness requires reachable PostgreSQL: {error}"
            );
            eprintln!("skipping live differential harness: PostgreSQL is unreachable: {error}");
            return;
        }
    };
    let connected_database: String = client
        .query_one("SELECT current_database()", &[])
        .expect("failed to identify the live differential database")
        .get(0);
    let expected_database =
        std::env::var(DATABASE_NAME_ENV).unwrap_or_else(|_| "safe_migrate".to_string());
    assert!(
        !expected_database.trim().is_empty()
            && expected_database
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_'),
        "{DATABASE_NAME_ENV} must be a nonempty unquoted database identifier"
    );
    assert_eq!(
        connected_database, expected_database,
        "live differential harness refuses to modify an unexpected database; set {DATABASE_NAME_ENV} explicitly for a disposable local database"
    );
    if verbosity >= 1 {
        let row = client
            .query_one(
                "SELECT current_database(), current_user, current_setting('server_version'), current_schemas(false)",
                &[],
            )
            .expect("failed to inspect connected PostgreSQL server");
        let database: String = row.get(0);
        let user: String = row.get(1);
        let version: String = row.get(2);
        let search_path: Vec<String> = row.get(3);
        verbose(
            verbosity,
            1,
            format!(
                "connected database={database} user={user} PostgreSQL={version} search_path={search_path:?}"
            ),
        );
    }

    let manifest_path = repo_path("live_tests/differential_manifest.json");
    let baseline_path = repo_path("live_tests/differential_baseline.sql");
    let manifest = load_manifest(&manifest_path);
    let baseline_sql = fs::read_to_string(&baseline_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", baseline_path.display()));
    let server_version_num: u32 = client
        .query_one("SHOW server_version_num", &[])
        .expect("failed to inspect PostgreSQL version")
        .get::<_, String>(0)
        .parse()
        .expect("server_version_num must be numeric");
    let engine = SafeMigrateEngine::new(Config::default());
    let mut mismatches = Vec::new();
    let rule_filter = std::env::var(RULE_FILTER_ENV).ok();
    let fixture_filter = std::env::var(FIXTURE_FILTER_ENV).ok();
    let selected_rules = || {
        manifest.rules.iter().filter(|rule| {
            rule.enabled
                && rule_filter
                    .as_deref()
                    .is_none_or(|selected| selected == rule.rule_dir)
        })
    };
    let enabled_rules = selected_rules().count();
    let enabled_fixtures = selected_rules()
        .map(|rule| {
            rule.fixtures
                .iter()
                .filter(|fixture| {
                    fixture_is_selected(&fixture_filter, &rule.rule_dir, fixture)
                        && rule
                            .fixture_min_pg_version
                            .get(*fixture)
                            .is_none_or(|minimum| server_version_num >= *minimum)
                })
                .count()
        })
        .sum::<usize>();
    if enabled_rules == 0 || enabled_fixtures == 0 {
        panic!(
            "no enabled differential fixture matched {}={:?}, {}={:?}",
            RULE_FILTER_ENV, rule_filter, FIXTURE_FILTER_ENV, fixture_filter
        );
    }
    verbose(
        verbosity,
        1,
        format!(
            "loaded manifest={} enabled_rules={enabled_rules} enabled_fixtures={enabled_fixtures}",
            manifest_path.display()
        ),
    );

    for rule in selected_rules() {
        verbose(
            verbosity,
            1,
            format!(
                "rule={} fixtures={} schemas={} transactional={}",
                rule.rule_dir,
                rule.fixtures.len(),
                rule.schemas.len(),
                rule.transactional
            ),
        );
        verbose(
            verbosity,
            2,
            format!(
                "rule={} scope={:?} schemas={:?} notes={}",
                rule.rule_dir,
                rule.scope,
                rule.schemas,
                rule.notes.as_deref().unwrap_or("<none>")
            ),
        );
        if verbosity >= 2 {
            for exclusion in &rule.excluded_fixtures {
                verbose(
                    verbosity,
                    2,
                    format!(
                        "rule={} excluded_fixture={} reason={}",
                        rule.rule_dir, exclusion.fixture, exclusion.reason
                    ),
                );
            }
        }
        for fixture in rule.fixtures.iter().filter(|fixture| {
            fixture_is_selected(&fixture_filter, &rule.rule_dir, fixture)
                && rule
                    .fixture_min_pg_version
                    .get(*fixture)
                    .is_none_or(|minimum| server_version_num >= *minimum)
        }) {
            let transactional = rule
                .fixture_transactional
                .get(fixture)
                .copied()
                .unwrap_or(rule.transactional);
            let scope = rule
                .fixture_scopes
                .get(fixture)
                .map(Vec::as_slice)
                .unwrap_or(&rule.scope);
            let fixture_started = Instant::now();
            let mismatches_before = mismatches.len();
            let fixture_path = repo_path(&format!("live_tests/{}/{}", rule.rule_dir, fixture));
            let sql = fs::read_to_string(&fixture_path).unwrap_or_else(|error| {
                panic!("failed to read {}: {error}", fixture_path.display())
            });
            let live_statements = if rule.fixture_autocommit.contains(fixture) {
                split_fixture_statements(&sql).unwrap_or_else(|error| {
                    panic!(
                        "invalid autocommit fixture {}: {error}",
                        fixture_path.display()
                    )
                })
            } else {
                vec![sql.clone()]
            };
            verbose(
                verbosity,
                1,
                format!("case={}/{} phase=start", rule.rule_dir, fixture),
            );
            verbose(
                verbosity,
                2,
                format!(
                    "case={}/{} comparison_scope={scope:?}",
                    rule.rule_dir, fixture
                ),
            );
            verbose(
                verbosity,
                3,
                format!(
                    "case={}/{} migration_sql:\n{}",
                    rule.rule_dir,
                    fixture,
                    sql.trim()
                ),
            );

            if let Err(error) = client.batch_execute(&baseline_sql) {
                mismatches.push(Mismatch {
                    rule_dir: rule.rule_dir.clone(),
                    fixture: fixture.clone(),
                    category: MismatchCategory::LiveExecutionFailed,
                    root_cause: classify_live_execution_error(&error),
                    note: format!(
                        "failed to rebuild baseline before fixture: {}",
                        format_postgres_error(&error)
                    ),
                });
                continue;
            }
            verbose(
                verbosity,
                2,
                format!("case={}/{} phase=baseline-rebuilt", rule.rule_dir, fixture),
            );

            let baseline_cache = match populate_cache(&mut client, Some(&rule.schemas)) {
                Ok(cache) => cache,
                Err(error) => {
                    mismatches.push(Mismatch {
                        rule_dir: rule.rule_dir.clone(),
                        fixture: fixture.clone(),
                        category: MismatchCategory::LiveExecutionFailed,
                        root_cause: RootCauseClassification::EnvironmentIssue,
                        note: format!(
                            "failed to sync baseline cache from live PostgreSQL: {error}"
                        ),
                    });
                    continue;
                }
            };
            verbose(
                verbosity,
                2,
                format!(
                    "case={}/{} baseline relations={} indexes={} constraints={} foreign_keys={} triggers={} functions={} dependencies={} search_path={:?}",
                    rule.rule_dir,
                    fixture,
                    baseline_cache.relations.len(),
                    baseline_cache.indexes.len(),
                    baseline_cache.constraints.len(),
                    baseline_cache.foreign_keys.len(),
                    baseline_cache.triggers.len(),
                    baseline_cache.functions.len(),
                    baseline_cache.dependencies.len(),
                    baseline_cache.search_path
                ),
            );

            mismatches.extend(check_required_relations(rule, fixture, &baseline_cache));
            mismatches.extend(check_role_membership_cache(rule, fixture, &baseline_cache));

            let mut simulator_state = AnalysisState::new(baseline_cache);
            let simulator_violations = match engine.analyze(&sql, &mut simulator_state) {
                Ok(violations) => violations,
                Err(parse_errors) => {
                    mismatches.push(Mismatch {
                        rule_dir: rule.rule_dir.clone(),
                        fixture: fixture.clone(),
                        category: MismatchCategory::LiveExecutionFailed,
                        root_cause: RootCauseClassification::HarnessBug,
                        note: format!(
                            "fixture failed to parse in simulator: {}",
                            parse_errors.join("; ")
                        ),
                    });
                    continue;
                }
            };
            verbose(
                verbosity,
                2,
                format!("case={}/{} phase=simulated", rule.rule_dir, fixture),
            );

            if transactional {
                if let Err(error) = client.batch_execute("BEGIN") {
                    mismatches.push(Mismatch {
                        rule_dir: rule.rule_dir.clone(),
                        fixture: fixture.clone(),
                        category: MismatchCategory::LiveExecutionFailed,
                        root_cause: RootCauseClassification::EnvironmentIssue,
                        note: format!(
                            "failed to begin rollback-isolated live fixture: {}",
                            format_postgres_error(&error)
                        ),
                    });
                    continue;
                }
                verbose(
                    verbosity,
                    2,
                    format!(
                        "case={}/{} phase=live-transaction-begun",
                        rule.rule_dir, fixture
                    ),
                );
            }

            if let Err(error) = live_statements
                .iter()
                .try_for_each(|statement| client.batch_execute(statement))
            {
                // Recover the shared harness connection even when a fixture
                // owns its transaction boundaries and leaves one aborted.
                let _ = client.batch_execute("ROLLBACK");
                if let Some(expected) = rule.expected_live_errors.get(fixture) {
                    let actual_sqlstate = error
                        .as_db_error()
                        .map(|db_error| db_error.code().code())
                        .unwrap_or("<none>");
                    if actual_sqlstate != expected.sqlstate {
                        mismatches.push(Mismatch {
                            rule_dir: rule.rule_dir.clone(),
                            fixture: fixture.clone(),
                            category: MismatchCategory::ExpectedLiveErrorMismatch,
                            root_cause: RootCauseClassification::HarnessBug,
                            note: format!(
                                "expected PostgreSQL SQLSTATE {}, got {}: {}",
                                expected.sqlstate,
                                actual_sqlstate,
                                format_postgres_error(&error)
                            ),
                        });
                    } else if !simulator_violations
                        .iter()
                        .any(|violation| violation.rule_id == expected.simulator_rule)
                    {
                        mismatches.push(Mismatch {
                            rule_dir: rule.rule_dir.clone(),
                            fixture: fixture.clone(),
                            category: MismatchCategory::MissingExpectedSimulatorFinding,
                            root_cause: RootCauseClassification::SimulatorBug,
                            note: format!(
                                "PostgreSQL rejected with SQLSTATE {}, but safe-migrate did not emit rule {}",
                                expected.sqlstate, expected.simulator_rule
                            ),
                        });
                    }
                    let case_mismatches = mismatches.len() - mismatches_before;
                    verbose(
                        verbosity,
                        1,
                        format!(
                            "case={}/{} result={} expected_sqlstate={} simulator_rule={} mismatches={} elapsed={}",
                            rule.rule_dir,
                            fixture,
                            if case_mismatches == 0 {
                                "match"
                            } else {
                                "mismatch"
                            },
                            expected.sqlstate,
                            expected.simulator_rule,
                            case_mismatches,
                            format_duration(fixture_started.elapsed())
                        ),
                    );
                    continue;
                }
                let root_cause = classify_live_execution_error(&error);
                mismatches.push(Mismatch {
                    rule_dir: rule.rule_dir.clone(),
                    fixture: fixture.clone(),
                    category: MismatchCategory::LiveExecutionFailed,
                    root_cause,
                    note: format!(
                        "live PostgreSQL rejected fixture: {}",
                        format_postgres_error(&error)
                    ),
                });
                continue;
            }

            if let Some(expected) = rule.expected_live_errors.get(fixture) {
                if transactional {
                    let _ = client.batch_execute("ROLLBACK");
                }
                mismatches.push(Mismatch {
                    rule_dir: rule.rule_dir.clone(),
                    fixture: fixture.clone(),
                    category: MismatchCategory::UnexpectedLiveSuccess,
                    root_cause: RootCauseClassification::HarnessBug,
                    note: format!(
                        "expected PostgreSQL SQLSTATE {}, but the fixture executed successfully",
                        expected.sqlstate
                    ),
                });
                continue;
            }
            verbose(
                verbosity,
                2,
                format!("case={}/{} phase=postgres-applied", rule.rule_dir, fixture),
            );

            let live_state_result =
                snapshot_live_state(&mut client, &rule.schemas, scope, transactional);
            if transactional {
                if let Err(error) = client.batch_execute("ROLLBACK") {
                    mismatches.push(Mismatch {
                        rule_dir: rule.rule_dir.clone(),
                        fixture: fixture.clone(),
                        category: MismatchCategory::LiveExecutionFailed,
                        root_cause: RootCauseClassification::EnvironmentIssue,
                        note: format!(
                            "failed to roll back live fixture: {}",
                            format_postgres_error(&error)
                        ),
                    });
                    continue;
                }
                verbose(
                    verbosity,
                    2,
                    format!(
                        "case={}/{} phase=live-transaction-rolled-back",
                        rule.rule_dir, fixture
                    ),
                );
            }

            let live_state = match live_state_result {
                Ok(state) => state,
                Err(error) => {
                    mismatches.push(Mismatch {
                        rule_dir: rule.rule_dir.clone(),
                        fixture: fixture.clone(),
                        category: MismatchCategory::LiveExecutionFailed,
                        root_cause: RootCauseClassification::EnvironmentIssue,
                        note: format!("failed to snapshot live PostgreSQL state: {error:#}"),
                    });
                    continue;
                }
            };

            let simulator_projection =
                snapshot_simulator_state(&simulator_state, &rule.schemas, scope);
            verbose(
                verbosity,
                2,
                format!(
                    "case={}/{} live={} simulator={}",
                    rule.rule_dir,
                    fixture,
                    state_counts(&live_state),
                    state_counts(&simulator_projection)
                ),
            );
            verbose(
                verbosity,
                3,
                format!(
                    "case={}/{} live_state={live_state:#?}",
                    rule.rule_dir, fixture
                ),
            );
            verbose(
                verbosity,
                3,
                format!(
                    "case={}/{} simulator_state={simulator_projection:#?}",
                    rule.rule_dir, fixture
                ),
            );
            mismatches.extend(compare_states(
                &rule.rule_dir,
                fixture,
                scope,
                &live_state,
                &simulator_projection,
            ));
            let case_mismatches = mismatches.len() - mismatches_before;
            verbose(
                verbosity,
                1,
                format!(
                    "case={}/{} result={} mismatches={} elapsed={}",
                    rule.rule_dir,
                    fixture,
                    if case_mismatches == 0 {
                        "match"
                    } else {
                        "mismatch"
                    },
                    case_mismatches,
                    format_duration(fixture_started.elapsed())
                ),
            );
        }
    }

    if !mismatches.is_empty() {
        panic!("{}", format_mismatch_report(&mismatches, &manifest_path));
    }
    verbose(
        verbosity,
        1,
        format!(
            "result=match fixtures={enabled_fixtures} elapsed={}",
            format_duration(harness_started.elapsed())
        ),
    );
}

fn fixture_is_selected(filter: &Option<String>, rule_dir: &str, fixture: &str) -> bool {
    filter.as_deref().is_none_or(|selected| {
        selected
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == format!("{rule_dir}/{fixture}"))
    })
}

fn differential_verbosity() -> u8 {
    std::env::var(VERBOSITY_ENV)
        .ok()
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0)
        .min(3)
}

fn live_database_is_required() -> bool {
    std::env::var_os(REQUIRE_LIVE_ENV).is_some()
}

fn verbose(verbosity: u8, level: u8, message: impl std::fmt::Display) {
    if verbosity >= level {
        eprintln!("[live-diff:v{level}] {message}");
    }
}

fn state_counts(state: &NormalizedState) -> String {
    format!(
        "schemas:{} sequences:{} relations:{} indexes:{} constraints:{} foreign_keys:{} functions:{} types:{} privileges:{} policies:{} triggers:{} partitions:{} view_dependencies:{} publications:{} subscriptions:{} extended_statistics:{}",
        state.schemas.len(),
        state.sequences.len(),
        state.relations.len(),
        state.indexes.len(),
        state.constraints.len(),
        state.foreign_keys.len(),
        state.functions.len(),
        state.types.len(),
        state.privileges.len(),
        state.policies.len(),
        state.triggers.len(),
        state.partition_edges.len(),
        state.view_dependencies.len(),
        state.publications.len(),
        state.subscriptions.len(),
        state.extended_statistics.len()
    )
}

fn format_duration(duration: Duration) -> String {
    format!("{:.3}s", duration.as_secs_f64())
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

#[test]
#[ignore = "requires a disposable local PostgreSQL database via DATABASE_URL"]
fn live_interrupted_partition_detach_finalize() {
    let config: PostgresConfig = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL")
        .parse()
        .expect("database configuration");
    assert!(database_hosts_are_local(&config));
    let mut client = config.connect(NoTls).expect("local PostgreSQL");
    let database: String = client
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database,
        std::env::var(DATABASE_NAME_ENV).unwrap_or_else(|_| "safe_migrate".into())
    );
    let schema = format!("sm_detach_interrupt_{}", std::process::id());
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for (strategy, bound) in [("RANGE", "FROM (0) TO (10)"), ("LIST", "IN (1, 2, 3)")] {
            client
                .batch_execute(&format!(
                    "CREATE TABLE {schema}.parent(id integer) PARTITION BY {strategy}(id);
                CREATE TABLE {schema}.child PARTITION OF {schema}.parent FOR VALUES {bound};"
                ))
                .unwrap();
            let mut blocker = config.connect(NoTls).unwrap();
            blocker
                .batch_execute(&format!(
                    "BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT * FROM {schema}.parent;"
                ))
                .unwrap();
            let mut detacher = config.connect(NoTls).unwrap();
            detacher
                .batch_execute("SET statement_timeout = '15s'")
                .unwrap();
            let cancel = detacher.cancel_token();
            let sql =
                format!("ALTER TABLE {schema}.parent DETACH PARTITION {schema}.child CONCURRENTLY");
            let worker = std::thread::spawn(move || detacher.batch_execute(&sql));
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut pending = false;
            while Instant::now() < deadline {
                pending = client.query_one("SELECT EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid = to_regclass($1) AND inhdetachpending)", &[&format!("{schema}.child")]).unwrap().get(0);
                if pending {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let cancellation = cancel.cancel_query(NoTls);
            let detached = worker.join().expect("detach worker");
            blocker.batch_execute("ROLLBACK").unwrap();
            assert!(pending, "detach never committed its pending state");
            cancellation.expect("cancel blocked detach");
            assert_eq!(
                detached.unwrap_err().code(),
                Some(&postgres::error::SqlState::QUERY_CANCELED)
            );

            let scopes = vec![schema.clone()];
            let cache = populate_cache(&mut client, Some(&scopes)).expect("sync interrupted state");
            cache.validate_semantics().expect("valid interrupted cache");
            let child = safe_migrate::_internal::ast::identifiers::ObjectId::new(&schema, "child");
            let mut state = AnalysisState::with_baseline(cache, true);
            assert!(
                state
                    .local
                    .graph
                    .edges()
                    .iter()
                    .any(|edge| edge.dependent == child
                        && matches!(edge.kind, DependencyKind::PartitionDetachPending))
            );
            let checks_before: Vec<_> = state
                .local
                .constraints
                .values()
                .filter(|check| check.table_id == child && check.kind == ConstraintKind::Check)
                .cloned()
                .collect();
            assert_eq!(checks_before.len(), 1);
            let finalize =
                format!("ALTER TABLE {schema}.parent DETACH PARTITION {schema}.child FINALIZE;");
            let findings = SafeMigrateEngine::new(Config::default())
                .analyze(&finalize, &mut state)
                .unwrap();
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict"),
                "{findings:?}"
            );
            client.batch_execute(&finalize).expect("live FINALIZE");
            let live = AnalysisState::with_baseline(
                populate_cache(&mut client, Some(&scopes)).unwrap(),
                true,
            );
            for snapshot in [&state, &live] {
                assert!(
                    !snapshot
                        .local
                        .graph
                        .edges()
                        .iter()
                        .any(|edge| edge.dependent == child
                            && matches!(
                                edge.kind,
                                DependencyKind::PartitionOf
                                    | DependencyKind::PartitionDetachPending
                            ))
                );
                let checks: Vec<_> = snapshot
                    .local
                    .constraints
                    .values()
                    .filter(|check| check.table_id == child && check.kind == ConstraintKind::Check)
                    .cloned()
                    .collect();
                assert_eq!(checks, checks_before);
            }
            client
                .batch_execute(&format!(
                    "DROP TABLE {schema}.child; DROP TABLE {schema}.parent;"
                ))
                .unwrap();
        }
    }));
    client
        .batch_execute(&format!(
            "SET lock_timeout = '3s'; DROP SCHEMA {schema} CASCADE;"
        ))
        .expect("cleanup interruption schema");
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn differential_database_guard_accepts_only_local_hosts() {
    for url in [
        "postgresql://localhost/safe_migrate",
        "postgresql://127.0.0.1/safe_migrate",
        "postgresql://[::1]/safe_migrate",
        "postgresql:///safe_migrate?host=%2Ftmp",
    ] {
        let config: PostgresConfig = url.parse().unwrap();
        assert!(database_hosts_are_local(&config), "{url}");
    }

    let remote: PostgresConfig = "postgresql://db.example/safe_migrate".parse().unwrap();
    assert!(!database_hosts_are_local(&remote));
}

#[test]
fn differential_manifest_accounts_for_every_sql_fixture() {
    load_manifest(&repo_path("live_tests/differential_manifest.json"));
}

#[test]
fn constraint_definition_boolean_operands_are_paren_insensitive() {
    assert_eq!(
        canonical_constraint_expression("(id > 0) AND (id < 100)"),
        "id > 0 AND id < 100"
    );
    assert_eq!(
        canonical_constraint_expression("id > 0 AND id < 100"),
        "id > 0 AND id < 100"
    );
    assert_eq!(
        canonical_constraint_expression("((id > 0)) AND (id < 100)"),
        "id > 0 AND id < 100"
    );
    assert_eq!(
        canonical_constraint_expression("(a = 1 OR b = 2) AND c = 3"),
        "(a = 1 OR b = 2) AND c = 3"
    );
    assert_eq!(
        canonical_constraint_expression("land = 1 AND id > 0"),
        "land = 1 AND id > 0"
    );
    assert_eq!(canonical_constraint_expression("(id > 0)"), "id > 0");
    assert_eq!(
        canonical_constraint_expression("status IN ('on', 'off') AND (id > 0)"),
        "status IN ('on', 'off') AND id > 0"
    );
}

#[test]
fn publication_option_normalization_ignores_catalog_order() {
    let first = vec![
        safe_migrate::_internal::analysis::facts::AttributeFact {
            name: "publish".into(),
            value: "insert".into(),
        },
        safe_migrate::_internal::analysis::facts::AttributeFact {
            name: "publish_via_partition_root".into(),
            value: "false".into(),
        },
    ];
    let mut second = first.clone();
    second.reverse();
    assert_eq!(normalize_attributes(&first), normalize_attributes(&second));
}

#[test]
fn publication_scope_normalization_ignores_catalog_order() {
    use safe_migrate::_internal::analysis::facts::{PublicationObjectFact, PublicationScope};
    use safe_migrate::_internal::ast::identifiers::{Ident, QualifiedName};

    let table = |name: &str, columns: Vec<&str>| PublicationObjectFact::Table {
        name: QualifiedName::new(None, Ident::new(name.to_string(), true)),
        only: true,
        include_partitions: false,
        columns: Some(columns.into_iter().map(str::to_string).collect()),
        row_filter: None,
    };
    let first = PublicationScope::Explicit(vec![table("b", vec!["z", "a"]), table("a", vec!["x"])]);
    let second =
        PublicationScope::Explicit(vec![table("a", vec!["x"]), table("b", vec!["a", "z"])]);
    assert_eq!(
        normalize_publication_scope(&first),
        normalize_publication_scope(&second)
    );
}

#[test]
fn subscription_normalization_redacts_connection_and_orders_publications() {
    use safe_migrate::_internal::analysis::facts::ConnectionTarget;
    use safe_migrate::_internal::model::replication::SubscriptionState;

    let first = SubscriptionState {
        name: "sub".into(),
        owner: Some("owner".into()),
        connection: ConnectionTarget::Redacted,
        publications: vec!["z_pub".into(), "a_pub".into()],
        params: None,
        enabled: false,
        slot_name: None,
        generation: 0,
    };
    let mut second = first.clone();
    second.connection = ConnectionTarget::Server(Some("publisher".into()));
    second.publications.reverse();
    assert_eq!(
        normalize_subscription(&first),
        normalize_subscription(&second)
    );
}

#[test]
fn subscription_scope_reports_semantic_mismatch_without_connection_metadata() {
    let mut live = NormalizedState::default();
    let mut simulator = NormalizedState::default();
    live.subscriptions.insert(
        "sub".into(),
        NormalizedSubscription {
            owner: Some("owner".into()),
            publications: vec!["pub".into()],
            params: "[]".into(),
            enabled: false,
            slot_name: None,
        },
    );
    simulator.subscriptions = live.subscriptions.clone();
    simulator
        .subscriptions
        .get_mut("sub")
        .expect("subscription inserted")
        .enabled = true;
    let mismatches = compare_states(
        "rule",
        "fixture.sql",
        &[ComparisonScope::Subscriptions],
        &live,
        &simulator,
    );
    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        mismatches[0].category,
        MismatchCategory::SubscriptionDefinitionMismatch
    );
}

#[test]
fn state_counts_include_every_replication_family() {
    let mut state = NormalizedState::default();
    state.subscriptions.insert(
        "sub".into(),
        NormalizedSubscription {
            owner: None,
            publications: Vec::new(),
            params: String::new(),
            enabled: false,
            slot_name: None,
        },
    );
    let counts = state_counts(&state);
    assert!(counts.ends_with("publications:0 subscriptions:1 extended_statistics:0"));
}

fn load_manifest(path: &Path) -> DifferentialManifest {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let manifest = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
    validate_manifest(&manifest, path);
    manifest
}

fn validate_manifest(manifest: &DifferentialManifest, path: &Path) {
    let live_tests_dir = path
        .parent()
        .unwrap_or_else(|| panic!("manifest has no parent directory: {}", path.display()));
    let actual_rule_dirs = directory_names(live_tests_dir);
    let mut manifest_rule_dirs = BTreeSet::new();
    let valid_rule_ids = SafeMigrateEngine::new(Config::default())
        .primary_rule_ids()
        .into_iter()
        .collect::<BTreeSet<_>>();

    for rule in &manifest.rules {
        assert!(
            manifest_rule_dirs.insert(rule.rule_dir.clone()),
            "duplicate differential manifest rule directory: {}",
            rule.rule_dir
        );

        let included = unique_fixture_names(
            &rule.rule_dir,
            "fixtures",
            rule.fixtures.iter().map(String::as_str),
        );
        let excluded = unique_fixture_names(
            &rule.rule_dir,
            "excluded_fixtures",
            rule.excluded_fixtures
                .iter()
                .map(|exclusion| exclusion.fixture.as_str()),
        );
        for exclusion in &rule.excluded_fixtures {
            assert!(
                !exclusion.reason.trim().is_empty(),
                "excluded fixture {}/{} has no reason",
                rule.rule_dir,
                exclusion.fixture
            );
        }

        let overlap = included
            .intersection(&excluded)
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            overlap.is_empty(),
            "differential fixtures cannot be both included and excluded for {}: {overlap:?}",
            rule.rule_dir
        );

        for fixture in rule.fixture_scopes.keys() {
            assert!(
                included.contains(fixture),
                "fixture scope references a non-included fixture: {}/{}",
                rule.rule_dir,
                fixture
            );
        }
        for fixture in rule.fixture_transactional.keys() {
            assert!(
                included.contains(fixture),
                "fixture transaction override references a non-included fixture: {}/{}",
                rule.rule_dir,
                fixture
            );
        }
        for fixture in &rule.fixture_autocommit {
            assert!(
                included.contains(fixture),
                "autocommit references a non-included fixture: {}/{}",
                rule.rule_dir,
                fixture
            );
            assert!(
                !rule
                    .fixture_transactional
                    .get(fixture)
                    .copied()
                    .unwrap_or(rule.transactional),
                "autocommit fixture cannot use the rollback wrapper: {}/{}",
                rule.rule_dir,
                fixture
            );
        }
        for fixture in rule.fixture_min_pg_version.keys() {
            assert!(
                included.contains(fixture),
                "fixture minimum version references a non-included fixture: {}/{}",
                rule.rule_dir,
                fixture
            );
        }

        validate_expected_live_errors(rule, &included, &valid_rule_ids);

        let rule_dir = live_tests_dir.join(&rule.rule_dir);
        let actual_fixtures = sql_fixture_names(&rule_dir);
        let accounted_for = included.union(&excluded).cloned().collect::<BTreeSet<_>>();
        let unlisted = actual_fixtures
            .difference(&accounted_for)
            .cloned()
            .collect::<Vec<_>>();
        let missing = accounted_for
            .difference(&actual_fixtures)
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            unlisted.is_empty() && missing.is_empty(),
            "differential manifest mismatch for {}: unlisted={unlisted:?}, missing={missing:?}",
            rule.rule_dir
        );
    }

    assert_eq!(
        manifest_rule_dirs, actual_rule_dirs,
        "differential manifest rule directories do not match live_tests"
    );
}

fn validate_expected_live_errors(
    rule: &RuleManifest,
    included: &BTreeSet<String>,
    valid_rule_ids: &BTreeSet<&str>,
) {
    for (fixture, expected) in &rule.expected_live_errors {
        assert!(
            included.contains(fixture),
            "expected live error references a non-included fixture: {}/{}",
            rule.rule_dir,
            fixture
        );
        assert!(
            expected.sqlstate.len() == 5
                && expected
                    .sqlstate
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric()),
            "expected live error has invalid SQLSTATE for {}/{}: {}",
            rule.rule_dir,
            fixture,
            expected.sqlstate
        );
        assert!(
            valid_rule_ids.contains(expected.simulator_rule.as_str()),
            "expected live error has unknown simulator rule for {}/{}: {}",
            rule.rule_dir,
            fixture,
            expected.simulator_rule
        );
    }
}

#[test]
fn expected_live_error_schema_rejects_unknown_fields() {
    let result = serde_json::from_str::<ExpectedLiveError>(
        r#"{"sqlstate":"42703","simulator_rule":"chain-conflict","typo":true}"#,
    );
    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "expected live error references a non-included fixture")]
fn expected_live_error_must_reference_an_included_fixture() {
    let rule = RuleManifest {
        rule_dir: "rule".to_string(),
        enabled: true,
        fixtures: Vec::new(),
        transactional: true,
        fixture_transactional: BTreeMap::new(),
        fixture_autocommit: BTreeSet::new(),
        fixture_min_pg_version: BTreeMap::new(),
        excluded_fixtures: Vec::new(),
        schemas: Vec::new(),
        scope: Vec::new(),
        fixture_scopes: BTreeMap::new(),
        expected_live_errors: BTreeMap::from([(
            "missing.sql".to_string(),
            ExpectedLiveError {
                sqlstate: "42703".to_string(),
                simulator_rule: "chain-conflict".to_string(),
            },
        )]),
        required_relations: Vec::new(),
        required_role_edges: Vec::new(),
        notes: None,
    };
    validate_expected_live_errors(&rule, &BTreeSet::new(), &BTreeSet::from(["chain-conflict"]));
}

#[test]
#[should_panic(expected = "expected live error has unknown simulator rule")]
fn expected_live_error_must_reference_a_known_simulator_rule() {
    let rule = RuleManifest {
        rule_dir: "rule".to_string(),
        enabled: true,
        fixtures: vec!["case.sql".to_string()],
        transactional: true,
        fixture_transactional: BTreeMap::new(),
        fixture_autocommit: BTreeSet::new(),
        fixture_min_pg_version: BTreeMap::new(),
        excluded_fixtures: Vec::new(),
        schemas: Vec::new(),
        scope: Vec::new(),
        fixture_scopes: BTreeMap::new(),
        expected_live_errors: BTreeMap::from([(
            "case.sql".to_string(),
            ExpectedLiveError {
                sqlstate: "42703".to_string(),
                simulator_rule: "typo-rule".to_string(),
            },
        )]),
        required_relations: Vec::new(),
        required_role_edges: Vec::new(),
        notes: None,
    };
    validate_expected_live_errors(
        &rule,
        &BTreeSet::from(["case.sql".to_string()]),
        &BTreeSet::from(["chain-conflict"]),
    );
}

fn unique_fixture_names<'a>(
    rule_dir: &str,
    field: &str,
    fixtures: impl Iterator<Item = &'a str>,
) -> BTreeSet<String> {
    let mut unique = BTreeSet::new();
    for fixture in fixtures {
        assert!(
            unique.insert(fixture.to_string()),
            "duplicate fixture in {rule_dir}.{field}: {fixture}"
        );
    }
    unique
}

fn directory_names(path: &Path) -> BTreeSet<String> {
    fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .map(|entry| {
            entry.unwrap_or_else(|error| {
                panic!(
                    "failed to read directory entry in {}: {error}",
                    path.display()
                )
            })
        })
        .filter(|entry| {
            entry
                .file_type()
                .unwrap_or_else(|error| {
                    panic!("failed to inspect {}: {error}", entry.path().display())
                })
                .is_dir()
        })
        .map(|entry| {
            entry.file_name().into_string().unwrap_or_else(|name| {
                panic!("non-UTF-8 directory name in {}: {name:?}", path.display())
            })
        })
        .filter(|name| name.starts_with("rule_"))
        .collect()
}

fn sql_fixture_names(path: &Path) -> BTreeSet<String> {
    fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .map(|entry| {
            entry.unwrap_or_else(|error| {
                panic!(
                    "failed to read directory entry in {}: {error}",
                    path.display()
                )
            })
        })
        .filter(|entry| {
            entry
                .file_type()
                .unwrap_or_else(|error| {
                    panic!("failed to inspect {}: {error}", entry.path().display())
                })
                .is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "sql")
        })
        .map(|entry| {
            entry.file_name().into_string().unwrap_or_else(|name| {
                panic!("non-UTF-8 fixture name in {}: {name:?}", path.display())
            })
        })
        .collect()
}

fn check_required_relations(rule: &RuleManifest, fixture: &str, cache: &DbCache) -> Vec<Mismatch> {
    let mut mismatches = Vec::new();
    for relation in &rule.required_relations {
        let (schema, name) = split_qualified_name(relation);
        let object_id = safe_migrate::_internal::ast::identifiers::ObjectId::new(schema, name);
        if !cache.relations.contains_key(&object_id) {
            mismatches.push(Mismatch {
                rule_dir: rule.rule_dir.clone(),
                fixture: fixture.to_string(),
                category: MismatchCategory::BaselineObjectAbsent,
                root_cause: RootCauseClassification::BaselineSetupGap,
                note: format!(
                    "baseline is missing required relation {relation}; check live_tests/differential_baseline.sql"
                ),
            });
        }
    }
    mismatches
}

fn check_role_membership_cache(
    rule: &RuleManifest,
    fixture: &str,
    cache: &DbCache,
) -> Vec<Mismatch> {
    let role = |name: &str| {
        cache
            .roles
            .get(&safe_migrate::_internal::ast::identifiers::ObjectId::new(
                "", name,
            ))
    };
    let edge = |ids: &[safe_migrate::_internal::ast::identifiers::ObjectId], target: &str| {
        ids.iter()
            .any(|id| id.schema.is_empty() && id.name == target)
    };
    let active_edges: Vec<&RequiredRoleEdge> = rule
        .required_role_edges
        .iter()
        .filter(|required| {
            required.min_pg_version_num.is_none_or(|minimum| {
                cache
                    .pg_version_num
                    .is_some_and(|version| version >= minimum)
            })
        })
        .collect();
    let required_roles: BTreeSet<&str> = active_edges
        .iter()
        .flat_map(|required| [required.member.as_str(), required.role.as_str()])
        .collect();
    let mut mismatches: Vec<Mismatch> = required_roles
        .into_iter()
        .filter(|name| role(name).is_none())
        .map(|name| Mismatch {
            rule_dir: rule.rule_dir.clone(),
            fixture: fixture.to_string(),
            category: MismatchCategory::BaselineObjectAbsent,
            root_cause: RootCauseClassification::BaselineSetupGap,
            note: format!(
                "baseline is missing required role {name}; check live_tests/differential_baseline.sql"
            ),
        })
        .collect();

    for required in active_edges {
        let (Some(member), Some(_)) = (role(&required.member), role(&required.role)) else {
            continue;
        };
        let matches = match required.kind {
            RequiredRoleEdgeKind::CanSetRoleTo => edge(&member.can_set_role_to, &required.role),
            RequiredRoleEdgeKind::CanAdministerMembership => {
                edge(&member.can_administer_membership, &required.role)
            }
            RequiredRoleEdgeKind::CanInheritFrom => edge(&member.can_inherit_from, &required.role),
            RequiredRoleEdgeKind::MemberOfWithoutSet => {
                edge(&member.member_of, &required.role)
                    && !edge(&member.can_set_role_to, &required.role)
            }
        };
        if !matches {
            mismatches.push(Mismatch {
                rule_dir: rule.rule_dir.clone(),
                fixture: fixture.to_string(),
                category: MismatchCategory::RoleMembershipMismatch,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "role {} does not satisfy {:?} edge to {}",
                    required.member, required.kind, required.role
                ),
            });
        }
    }

    mismatches
}

#[test]
fn required_role_edges_distinguish_missing_roles_from_incorrect_edges() {
    let rule: RuleManifest = serde_json::from_str(
        r#"{
            "rule_dir": "rule",
            "enabled": true,
            "fixtures": [],
            "schemas": [],
            "scope": [],
            "required_role_edges": [
                {
                    "member": "member",
                    "role": "target",
                    "kind": "can_set_role_to"
                }
            ]
        }"#,
    )
    .expect("role edge manifest");
    let missing = check_role_membership_cache(&rule, "fixture.sql", &DbCache::new());
    assert_eq!(missing.len(), 2);
    assert!(missing.iter().all(|mismatch| {
        mismatch.category == MismatchCategory::BaselineObjectAbsent
            && mismatch.root_cause == RootCauseClassification::BaselineSetupGap
    }));

    let mut cache = DbCache::new();
    for name in ["member", "target"] {
        let id = safe_migrate::_internal::ast::identifiers::ObjectId::new("", name);
        cache.roles.insert(
            id.clone(),
            safe_migrate::_internal::model::role::RoleState {
                id,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    let incorrect = check_role_membership_cache(&rule, "fixture.sql", &cache);
    assert_eq!(incorrect.len(), 1);
    assert_eq!(
        incorrect[0].category,
        MismatchCategory::RoleMembershipMismatch
    );
    assert_eq!(
        incorrect[0].root_cause,
        RootCauseClassification::SimulatorBug
    );
}

fn classify_live_execution_error(error: &postgres::Error) -> RootCauseClassification {
    if error
        .code()
        .is_some_and(|code| matches!(code.code(), "42710" | "42712" | "42723"))
    {
        return RootCauseClassification::BaselineSetupGap;
    }
    match error.code() {
        Some(&postgres::error::SqlState::UNDEFINED_TABLE)
        | Some(&postgres::error::SqlState::UNDEFINED_OBJECT)
        | Some(&postgres::error::SqlState::UNDEFINED_COLUMN)
        | Some(&postgres::error::SqlState::UNDEFINED_FUNCTION)
        | Some(&postgres::error::SqlState::UNDEFINED_SCHEMA) => {
            RootCauseClassification::BaselineSetupGap
        }
        _ => RootCauseClassification::EnvironmentIssue,
    }
}

fn format_postgres_error(error: &postgres::Error) -> String {
    let Some(db_error) = error.as_db_error() else {
        return error.to_string();
    };

    let mut message = format!(
        "{} (SQLSTATE {})",
        db_error.message(),
        db_error.code().code()
    );
    if let Some(detail) = db_error.detail() {
        message.push_str(&format!(" detail={detail}"));
    }
    if let Some(hint) = db_error.hint() {
        message.push_str(&format!(" hint={hint}"));
    }
    message
}

fn snapshot_live_state(
    client: &mut Client,
    schemas: &[String],
    scope: &[ComparisonScope],
    transaction_is_active: bool,
) -> anyhow::Result<NormalizedState> {
    let cache = if transaction_is_active {
        populate_cache_in_current_transaction(client, Some(schemas))?
    } else {
        populate_cache(client, Some(schemas))?
    };
    let mut state = NormalizedState::default();
    // `format_type` is search_path-sensitive for user-defined types. Resolve
    // each cached column to its catalog identity before projecting it so a
    // fixture that changes search_path cannot turn the same type into two
    // different textual representations.
    let resolved_cache_state = AnalysisState::with_baseline(cache.clone(), true);
    let known_function_ids = cache.functions.keys().cloned().collect::<Vec<_>>();

    if scope.contains(&ComparisonScope::Schemas) {
        for (name, schema) in &cache.schemas {
            state
                .schemas
                .insert(name.clone(), schema.owner.name.clone());
        }
    }

    if scope.contains(&ComparisonScope::Roles) {
        for (member, role) in &cache.roles {
            for parent in &role.member_of {
                let grantor = cache
                    .role_membership_grantors
                    .iter()
                    .find(|provenance| provenance.member == *member && provenance.role == *parent)
                    .map(|provenance| provenance.grantor.name.clone());
                state.roles.insert(NormalizedRoleMembership {
                    member: member.name.clone(),
                    role: parent.name.clone(),
                    admin: role.can_administer_membership.contains(parent),
                    inherit: role.can_inherit_from.contains(parent),
                    set: role.can_set_role_to.contains(parent),
                    grantor,
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Publications) {
        for (name, publication) in &cache.publications {
            state.publications.insert(
                name.clone(),
                NormalizedPublication {
                    owner: publication.owner.clone(),
                    scope: normalize_publication_scope(&publication.scope),
                    params: normalize_attributes(&publication.params),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Subscriptions) {
        for (name, subscription) in &cache.subscriptions {
            state
                .subscriptions
                .insert(name.clone(), normalize_subscription(subscription));
        }
    }

    if scope.contains(&ComparisonScope::Sequences) {
        for (id, sequence) in &cache.sequences {
            state.sequences.insert(
                qualified_name(&id.schema, &id.name),
                NormalizedSequence {
                    owner: sequence.owner.name.clone(),
                    owned_by: sequence.owned_by.as_ref().map(|(table, column)| {
                        format!("{}.{}", qualified_name(&table.schema, &table.name), column)
                    }),
                    kind: sequence.kind.clone(),
                    data_type: normalize_data_type(&sequence.parameters.data_type),
                    start_value: sequence.parameters.start_value,
                    increment: sequence.parameters.increment,
                    min_value: sequence.parameters.min_value,
                    max_value: sequence.parameters.max_value,
                    cache_size: sequence.parameters.cache_size,
                    cycle: sequence.parameters.cycle,
                    persistence: normalize_sequence_persistence(sequence.parameters.persistence),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Policies) {
        for (id, relation) in &cache.relations {
            for policy in &relation.policies {
                state.policies.insert(NormalizedPolicy {
                    table: qualified_name(&id.schema, &id.name),
                    policy: policy.clone(),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Functions) {
        for (id, function) in &cache.functions {
            state.functions.insert(
                qualified_name(&id.schema, &id.name),
                normalize_volatility(&function.volatility),
            );
        }
    }

    if scope.contains(&ComparisonScope::Types) {
        for (id, type_state) in &cache.types {
            state.types.insert(
                qualified_name(&id.schema, &id.name),
                normalize_type_kind(&type_state.kind),
            );
        }
    }

    if scope.contains(&ComparisonScope::Privileges) {
        for (id, relation) in &cache.relations {
            for (grantee, privileges) in &relation.privileges.grants {
                for privilege in privileges {
                    state.privileges.insert(NormalizedPrivilege {
                        table: qualified_name(&id.schema, &id.name),
                        grantee: grantee.name.clone(),
                        privilege: normalize_privilege(*privilege),
                        grantable: relation.privileges.has_grant_option(grantee, *privilege),
                    });
                }
            }
        }
    }

    if scope.contains(&ComparisonScope::Constraints) {
        for constraint in &cache.constraints {
            if constraint.kind == ConstraintKind::NotNull {
                continue;
            }
            state.constraints.insert(NormalizedConstraint {
                table: qualified_name(&constraint.table_id.schema, &constraint.table_id.name),
                name: constraint.name.clone(),
                kind: normalize_constraint_kind(constraint.kind),
                validated: constraint.validated,
                definition: normalize_constraint_definition(constraint.definition.as_deref()),
                backing_index: constraint
                    .backing_index
                    .as_ref()
                    .map(|id| qualified_name(&id.schema, &id.name)),
            });
        }
    }

    if scope.contains(&ComparisonScope::Triggers) {
        for trigger in &cache.triggers {
            state.triggers.insert(
                (
                    qualified_name(&trigger.table_id.schema, &trigger.table_id.name),
                    trigger.trigger_id.name.clone(),
                ),
                NormalizedTrigger {
                    function: qualified_name(
                        &trigger.function_id.schema,
                        &trigger.function_id.name,
                    ),
                    enabled_mode: normalize_trigger_mode(trigger.enabled_mode),
                    row_level: trigger.row_level,
                    parent_trigger: trigger
                        .parent_trigger_id
                        .as_ref()
                        .map(|id| qualified_name(&id.schema, &id.name)),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Relations) || scope.contains(&ComparisonScope::Columns) {
        for (id, relation) in &cache.relations {
            let mut normalized = NormalizedRelation {
                kind: normalize_relation_kind(relation.kind.clone()),
                owner: relation.owner.name.clone(),
                partition_strategy: relation.partition_type.clone(),
                partition_is_default: relation
                    .partition_bound
                    .as_deref()
                    .map(|bound| bound.trim().eq_ignore_ascii_case("DEFAULT")),
                partition_bound: relation.partition_bound.clone(),
                partition_constraint: normalize_partition_constraint(
                    relation.partition_constraint.as_deref(),
                ),
                persistence: normalize_relation_persistence(relation.persistence.clone()),
                tablespace: relation.tablespace.clone(),
                access_method: normalize_access_method(
                    &relation.kind,
                    relation.access_method.as_deref(),
                ),
                cluster_index: relation.cluster_index.clone(),
                row_security: normalize_table_flag(&relation.kind, relation.row_security),
                force_row_security: normalize_table_flag(
                    &relation.kind,
                    relation.force_row_security,
                ),
                replica_identity: normalize_replica_identity(
                    &relation.kind,
                    relation.replica_identity.as_deref(),
                ),
                table_options: relation.table_options.clone(),
                of_type: relation
                    .of_type
                    .as_ref()
                    .map(|id| qualified_name(&id.schema, &id.name)),
                rules: relation
                    .rules
                    .iter()
                    .map(|(name, mode)| (name.clone(), format!("{mode:?}")))
                    .collect(),
                columns: BTreeMap::new(),
            };
            if scope.contains(&ComparisonScope::Columns) {
                let resolved_relation = resolved_cache_state.local.relations.get(id);
                for column in &relation.columns {
                    let type_id = resolved_relation.and_then(|overlay| match overlay {
                        RelationOverlay::Present(resolved) => resolved
                            .columns
                            .iter()
                            .find(|resolved_column| resolved_column.name == column.name)
                            .and_then(|resolved_column| resolved_column.type_id.as_ref()),
                        RelationOverlay::Dropped => None,
                    });
                    let data_type = normalize_data_type_with_identity(
                        &column
                            .data_type
                            .clone()
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        type_id,
                    );
                    normalized.columns.insert(
                        column.name.clone(),
                        NormalizedColumn {
                            data_type: data_type.clone(),
                            is_nullable: column.is_nullable,
                            has_default: !relation.identity_columns.contains_key(&column.name)
                                && (column.default.is_some() || column.default_expr_text.is_some()),
                            generated: column.generated,
                            generation: normalize_generated_column(
                                relation.generated_columns.get(&column.name),
                                &known_function_ids,
                                &cache.search_path,
                            ),
                            identity_generation: relation
                                .identity_columns
                                .get(&column.name)
                                .map(|generation| format!("{generation:?}")),
                            storage: column.storage.clone(),
                            compression: column.compression.clone(),
                            statistics_target: normalize_statistics_target(
                                column.statistics_target,
                            ),
                            options: column.options.clone(),
                        },
                    );
                }
            }
            state
                .relations
                .insert(qualified_name(&id.schema, &id.name), normalized);
        }
    }

    if scope.contains(&ComparisonScope::Indexes) {
        for index in cache.indexes {
            state.indexes.insert(NormalizedIndex {
                index: qualified_name(&index.index_id.schema, &index.index_id.name),
                table: qualified_name(&index.table_id.schema, &index.table_id.name),
                using_method: Some(index.using_method.to_ascii_lowercase()),
                key_columns: index.key_columns,
                included_columns: index.included_columns,
                has_expression_keys: index.has_expression_keys,
                has_predicate: index.has_predicate,
                is_unique: index.is_unique,
                is_immediate: index.is_immediate,
                is_valid: index.is_valid,
                is_ready: index.is_ready,
                is_live: index.is_live,
                has_default_sort_order: index.has_default_sort_order,
                has_default_opclasses: index.has_default_opclasses,
                has_default_collations: index.has_default_collations,
            });
        }
    }

    if scope.contains(&ComparisonScope::ExtendedStatistics) {
        for (table_id, relation) in &cache.relations {
            for (stats_id, statistics) in &relation.extended_statistics {
                state.extended_statistics.insert(
                    qualified_name(&stats_id.schema, &stats_id.name),
                    NormalizedExtendedStatistics {
                        table: qualified_name(&table_id.schema, &table_id.name),
                        kinds: statistics.kinds.clone(),
                        columns: statistics.columns.clone(),
                        expressions: statistics.expressions.clone(),
                        target: normalize_statistics_target(statistics.target),
                    },
                );
            }
        }
    }

    if scope.contains(&ComparisonScope::ForeignKeys) {
        for fk in cache.foreign_keys {
            state.foreign_keys.insert(NormalizedForeignKey {
                from_table: qualified_name(&fk.from_table.schema, &fk.from_table.name),
                to_table: qualified_name(&fk.to_table.schema, &fk.to_table.name),
                constraint_name: fk.constraint_name,
            });
        }
    }

    if scope.contains(&ComparisonScope::Partitions) {
        let schema_names = schemas.to_vec();
        for row in client.query(
            "
            SELECT
                pn.nspname AS parent_schema,
                pc.relname AS parent_name,
                cn.nspname AS child_schema,
                cc.relname AS child_name,
                cc.relispartition AS is_partition,
                i.inhdetachpending AS detach_pending
            FROM pg_inherits i
            JOIN pg_class pc ON pc.oid = i.inhparent
            JOIN pg_namespace pn ON pn.oid = pc.relnamespace
            JOIN pg_class cc ON cc.oid = i.inhrelid
            JOIN pg_namespace cn ON cn.oid = cc.relnamespace
            WHERE pn.nspname = ANY($1) AND cn.nspname = ANY($1)
              AND pc.relkind IN ('r', 'p')
              AND cc.relkind IN ('r', 'p')
            ",
            &[&schema_names],
        )? {
            let parent_schema: String = row.get("parent_schema");
            let parent_name: String = row.get("parent_name");
            let child_schema: String = row.get("child_schema");
            let child_name: String = row.get("child_name");
            state.partition_edges.insert((
                qualified_name(&parent_schema, &parent_name),
                qualified_name(&child_schema, &child_name),
                row.get("is_partition"),
                row.get("detach_pending"),
            ));
        }
    }

    if scope.contains(&ComparisonScope::ViewDependencies) {
        let schema_names = schemas.to_vec();
        for row in client.query(
            "
            SELECT DISTINCT
                vn.nspname AS view_schema,
                vc.relname AS view_name,
                tn.nspname AS table_schema,
                tc.relname AS table_name
            FROM pg_rewrite rw
            JOIN pg_class vc ON vc.oid = rw.ev_class
            JOIN pg_namespace vn ON vn.oid = vc.relnamespace
            JOIN pg_depend d ON d.objid = rw.oid
            JOIN pg_class tc ON tc.oid = d.refobjid
            JOIN pg_namespace tn ON tn.oid = tc.relnamespace
            WHERE vc.relkind IN ('v', 'm')
              AND vn.nspname = ANY($1)
              AND tn.nspname = ANY($1)
              AND d.deptype = 'n'
              -- PostgreSQL 14/15 expose an internal rewrite-rule self-edge
              -- here. It is not a view-to-relation dependency that the
              -- simulator should model.
              AND tc.oid <> vc.oid
            ",
            &[&schema_names],
        )? {
            let view_schema: String = row.get("view_schema");
            let view_name: String = row.get("view_name");
            let table_schema: String = row.get("table_schema");
            let table_name: String = row.get("table_name");
            state.view_dependencies.insert((
                qualified_name(&view_schema, &view_name),
                qualified_name(&table_schema, &table_name),
            ));
        }
    }

    Ok(state)
}

fn snapshot_simulator_state(
    state: &AnalysisState,
    schema_scope: &[String],
    scope: &[ComparisonScope],
) -> NormalizedState {
    let mut projection = NormalizedState::default();
    let known_function_ids = state
        .local
        .functions
        .iter()
        .filter_map(|(id, overlay)| {
            matches!(overlay, FunctionOverlay::Present(_)).then_some(id.clone())
        })
        .collect::<Vec<_>>();

    if scope.contains(&ComparisonScope::Schemas) {
        for (name, overlay) in &state.local.schemas {
            let SchemaOverlay::Present(schema) = overlay else {
                continue;
            };
            // The state hydrator may retain an inferred namespace for an
            // out-of-scope relationship endpoint.  That evidence is needed
            // internally for dependency resolution, but the differential
            // projection must match the manifest's authoritative schema
            // scope, just like the live catalog snapshot does.
            if schema_scope.iter().any(|scoped| scoped == name) {
                projection
                    .schemas
                    .insert(name.clone(), schema.owner.name.clone());
            }
        }
    }

    if scope.contains(&ComparisonScope::Roles) {
        for (member, overlay) in &state.local.roles {
            let safe_migrate::_internal::model::role::RoleOverlay::Present(role) = overlay else {
                continue;
            };
            for parent in &role.member_of {
                let grantor = state
                    .local
                    .role_membership_grantors
                    .iter()
                    .find(|provenance| provenance.member == *member && provenance.role == *parent)
                    .map(|provenance| provenance.grantor.name.clone());
                projection.roles.insert(NormalizedRoleMembership {
                    member: member.name.clone(),
                    role: parent.name.clone(),
                    admin: role.can_administer_membership.contains(parent),
                    inherit: role.can_inherit_from.contains(parent),
                    set: role.can_set_role_to.contains(parent),
                    grantor,
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Publications) {
        for (name, overlay) in &state.local.publications {
            let safe_migrate::_internal::model::replication::PublicationOverlay::Present(
                publication,
            ) = overlay
            else {
                continue;
            };
            projection.publications.insert(
                name.clone(),
                NormalizedPublication {
                    owner: publication.owner.clone(),
                    scope: normalize_publication_scope(&publication.scope),
                    params: normalize_attributes(&publication.params),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Subscriptions) {
        for (name, overlay) in &state.local.subscriptions {
            let safe_migrate::_internal::model::replication::SubscriptionOverlay::Present(
                subscription,
            ) = overlay
            else {
                continue;
            };
            projection
                .subscriptions
                .insert(name.clone(), normalize_subscription(subscription));
        }
    }

    if scope.contains(&ComparisonScope::Sequences) {
        for (id, overlay) in &state.local.sequences {
            let SequenceOverlay::Present(sequence) = overlay else {
                continue;
            };
            projection.sequences.insert(
                qualified_name(&id.schema, &id.name),
                NormalizedSequence {
                    owner: sequence.owner.name.clone(),
                    owned_by: sequence.owned_by.as_ref().map(|(table, column)| {
                        format!("{}.{}", qualified_name(&table.schema, &table.name), column)
                    }),
                    kind: sequence.kind.clone(),
                    data_type: normalize_data_type(&sequence.parameters.data_type),
                    start_value: sequence.parameters.start_value,
                    increment: sequence.parameters.increment,
                    min_value: sequence.parameters.min_value,
                    max_value: sequence.parameters.max_value,
                    cache_size: sequence.parameters.cache_size,
                    cycle: sequence.parameters.cycle,
                    persistence: normalize_sequence_persistence(sequence.parameters.persistence),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Policies) {
        for (id, overlay) in &state.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            for policy in &relation.policies {
                projection.policies.insert(NormalizedPolicy {
                    table: qualified_name(&id.schema, &id.name),
                    policy: policy.clone(),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Functions) {
        for (id, overlay) in &state.local.functions {
            let FunctionOverlay::Present(function) = overlay else {
                continue;
            };
            projection.functions.insert(
                qualified_name(&id.schema, &id.name),
                normalize_volatility(&function.volatility),
            );
        }
    }

    if scope.contains(&ComparisonScope::Types) {
        for (id, overlay) in &state.local.types {
            let TypeOverlay::Present(type_state) = overlay else {
                continue;
            };
            projection.types.insert(
                qualified_name(&id.schema, &id.name),
                normalize_type_kind(&type_state.kind),
            );
        }
    }

    if scope.contains(&ComparisonScope::Privileges) {
        for (id, overlay) in &state.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            for (grantee, privileges) in &relation.privileges.grants {
                for privilege in privileges {
                    projection.privileges.insert(NormalizedPrivilege {
                        table: qualified_name(&id.schema, &id.name),
                        grantee: grantee.name.clone(),
                        privilege: normalize_privilege(*privilege),
                        grantable: relation.privileges.has_grant_option(grantee, *privilege),
                    });
                }
            }
        }
    }

    if scope.contains(&ComparisonScope::Constraints) {
        for constraint in state.local.constraints.values() {
            if constraint.kind == ConstraintKind::NotNull {
                continue;
            }
            projection.constraints.insert(NormalizedConstraint {
                table: qualified_name(&constraint.table_id.schema, &constraint.table_id.name),
                name: constraint.name.clone(),
                kind: normalize_constraint_kind(constraint.kind),
                validated: constraint.validated,
                definition: normalize_constraint_definition(constraint.definition.as_deref()),
                backing_index: constraint
                    .backing_index
                    .as_ref()
                    .map(|id| qualified_name(&id.schema, &id.name)),
            });
        }
    }

    if scope.contains(&ComparisonScope::Triggers) {
        for edge in state.local.graph.edges() {
            let DependencyKind::TriggerOnTable {
                trigger_id,
                function_id,
                ..
            } = &edge.kind
            else {
                continue;
            };
            let Some(TriggerOverlay::Present(trigger)) = state.local.triggers.get(trigger_id)
            else {
                continue;
            };
            projection.triggers.insert(
                (
                    qualified_name(&edge.referenced.schema, &edge.referenced.name),
                    trigger.name.clone(),
                ),
                NormalizedTrigger {
                    function: qualified_name(&function_id.schema, &function_id.name),
                    enabled_mode: normalize_trigger_mode(trigger.enabled_mode),
                    row_level: trigger.row_level,
                    parent_trigger: trigger
                        .parent_trigger_id
                        .as_ref()
                        .map(|id| qualified_name(&id.schema, &id.name)),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Relations) || scope.contains(&ComparisonScope::Columns) {
        for (id, overlay) in &state.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            let mut normalized = NormalizedRelation {
                kind: normalize_relation_kind(relation.kind.clone()),
                owner: relation.owner.name.clone(),
                partition_strategy: relation.partition_type.clone(),
                partition_is_default: relation
                    .partition_bound
                    .as_deref()
                    .map(|bound| bound.trim().eq_ignore_ascii_case("DEFAULT")),
                partition_bound: relation.partition_bound.clone(),
                partition_constraint: normalize_partition_constraint(
                    relation.partition_constraint.as_deref(),
                ),
                persistence: normalize_relation_persistence(relation.persistence.clone()),
                tablespace: relation.tablespace.clone(),
                access_method: normalize_access_method(
                    &relation.kind,
                    relation.access_method.as_deref(),
                ),
                cluster_index: relation.cluster_index.clone(),
                row_security: normalize_table_flag(&relation.kind, relation.row_security),
                force_row_security: normalize_table_flag(
                    &relation.kind,
                    relation.force_row_security,
                ),
                replica_identity: normalize_replica_identity(
                    &relation.kind,
                    relation.replica_identity.as_deref(),
                ),
                table_options: relation.table_options.clone(),
                of_type: relation
                    .of_type
                    .as_ref()
                    .map(|id| qualified_name(&id.schema, &id.name)),
                rules: relation
                    .rules
                    .iter()
                    .map(|(name, mode)| (name.clone(), format!("{mode:?}")))
                    .collect(),
                columns: BTreeMap::new(),
            };
            if scope.contains(&ComparisonScope::Columns) {
                for column in &relation.columns {
                    let data_type = normalize_data_type_with_identity(
                        &column
                            .data_type
                            .clone()
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        column.type_id.as_ref(),
                    );
                    normalized.columns.insert(
                        column.name.clone(),
                        NormalizedColumn {
                            data_type: data_type.clone(),
                            is_nullable: column.is_nullable,
                            has_default: !relation.identity_columns.contains_key(&column.name)
                                && (column.default.is_some() || column.default_expr_text.is_some()),
                            generated: column.generated,
                            generation: normalize_generated_column(
                                relation.generated_columns.get(&column.name),
                                &known_function_ids,
                                state.search_path(),
                            ),
                            identity_generation: relation
                                .identity_columns
                                .get(&column.name)
                                .map(|generation| format!("{generation:?}")),
                            storage: normalize_column_storage(
                                state,
                                &data_type,
                                column.storage.as_deref(),
                            ),
                            compression: column.compression.clone(),
                            statistics_target: normalize_statistics_target(
                                column.statistics_target,
                            ),
                            options: column.options.clone(),
                        },
                    );
                }
            }
            projection
                .relations
                .insert(qualified_name(&id.schema, &id.name), normalized);
        }
    }

    for edge in state.local.graph.edges() {
        match &edge.kind {
            DependencyKind::IndexOnRelation {
                using_method,
                key_columns,
                included_columns,
                has_expression_keys,
                has_predicate,
                is_unique,
                is_immediate,
                is_valid,
                is_ready,
                is_live,
                has_default_sort_order,
                has_default_opclasses,
                has_default_collations,
                ..
            } if scope.contains(&ComparisonScope::Indexes) => {
                projection.indexes.insert(NormalizedIndex {
                    index: qualified_name(&edge.dependent.schema, &edge.dependent.name),
                    table: qualified_name(&edge.referenced.schema, &edge.referenced.name),
                    using_method: using_method
                        .as_ref()
                        .map(|method| method.to_ascii_lowercase()),
                    key_columns: key_columns.clone(),
                    included_columns: included_columns.clone(),
                    has_expression_keys: *has_expression_keys,
                    has_predicate: *has_predicate,
                    is_unique: *is_unique,
                    is_immediate: *is_immediate,
                    is_valid: *is_valid,
                    is_ready: *is_ready,
                    is_live: *is_live,
                    has_default_sort_order: *has_default_sort_order,
                    has_default_opclasses: *has_default_opclasses,
                    has_default_collations: *has_default_collations,
                });
            }
            DependencyKind::ForeignKey {
                constraint_name, ..
            } if scope.contains(&ComparisonScope::ForeignKeys) => {
                projection.foreign_keys.insert(NormalizedForeignKey {
                    from_table: qualified_name(&edge.dependent.schema, &edge.dependent.name),
                    to_table: qualified_name(&edge.referenced.schema, &edge.referenced.name),
                    constraint_name: constraint_name
                        .clone()
                        .unwrap_or_else(|| "<unnamed>".to_string()),
                });
            }
            DependencyKind::PartitionOf
            | DependencyKind::PartitionDetachPending
            | DependencyKind::InheritanceOf
                if scope.contains(&ComparisonScope::Partitions) =>
            {
                projection.partition_edges.insert((
                    qualified_name(&edge.referenced.schema, &edge.referenced.name),
                    qualified_name(&edge.dependent.schema, &edge.dependent.name),
                    !matches!(edge.kind, DependencyKind::InheritanceOf),
                    matches!(edge.kind, DependencyKind::PartitionDetachPending),
                ));
            }
            DependencyKind::ViewDependency { .. }
                if scope.contains(&ComparisonScope::ViewDependencies) =>
            {
                projection.view_dependencies.insert((
                    qualified_name(&edge.dependent.schema, &edge.dependent.name),
                    qualified_name(&edge.referenced.schema, &edge.referenced.name),
                ));
            }
            _ => {}
        }
    }

    if scope.contains(&ComparisonScope::ExtendedStatistics) {
        for (table_id, overlay) in &state.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            for (stats_id, statistics) in &relation.extended_statistics {
                projection.extended_statistics.insert(
                    qualified_name(&stats_id.schema, &stats_id.name),
                    NormalizedExtendedStatistics {
                        table: qualified_name(&table_id.schema, &table_id.name),
                        kinds: statistics.kinds.clone(),
                        columns: statistics.columns.clone(),
                        expressions: statistics.expressions.clone(),
                        target: normalize_statistics_target(statistics.target),
                    },
                );
            }
        }
    }

    projection
}

#[test]
fn relation_comparison_detects_partition_metadata_differences() {
    let relation = NormalizedRelation {
        kind: NormalizedRelationKind::Table,
        owner: "owner".into(),
        partition_strategy: None,
        partition_is_default: Some(false),
        partition_bound: Some("FOR VALUES FROM (0) TO (10)".into()),
        partition_constraint: Some("(id IS NOT NULL) AND (id >= 0) AND (id < 10)".into()),
        persistence: "permanent".into(),
        tablespace: None,
        access_method: None,
        cluster_index: None,
        row_security: None,
        force_row_security: None,
        replica_identity: None,
        table_options: BTreeMap::new(),
        of_type: None,
        rules: BTreeMap::new(),
        columns: BTreeMap::new(),
    };
    let mut live = NormalizedState::default();
    live.relations
        .insert("public.child".into(), relation.clone());
    for field in 0..3 {
        let mut changed = relation.clone();
        match field {
            0 => changed.partition_bound = Some("FOR VALUES FROM (0) TO (20)".into()),
            1 => changed.partition_constraint = None,
            _ => changed.partition_is_default = Some(true),
        }
        let mut simulator = NormalizedState::default();
        simulator.relations.insert("public.child".into(), changed);
        for scope in [ComparisonScope::Relations, ComparisonScope::Partitions] {
            let mismatches = compare_states("regression", "partition", &[scope], &live, &simulator);
            assert!(
                mismatches
                    .iter()
                    .any(|mismatch| mismatch.category
                        == MismatchCategory::RelationDefinitionMismatch)
            );
        }
    }
}

fn compare_states(
    rule_dir: &str,
    fixture: &str,
    scope: &[ComparisonScope],
    live: &NormalizedState,
    simulator: &NormalizedState,
) -> Vec<Mismatch> {
    let mut mismatches = Vec::new();

    if scope.contains(&ComparisonScope::Publications) {
        for (name, live_publication) in &live.publications {
            let Some(simulator_publication) = simulator.publications.get(name) else {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingPublicationInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept publication '{name}'"),
                });
                continue;
            };
            if live_publication != simulator_publication {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::PublicationDefinitionMismatch,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "publication '{name}' differs: live={live_publication:?}, simulator={simulator_publication:?}"
                    ),
                });
            }
        }
        for name in simulator.publications.keys() {
            if !live.publications.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraPublicationInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept publication '{name}'"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Subscriptions) {
        for (name, live_subscription) in &live.subscriptions {
            let Some(simulator_subscription) = simulator.subscriptions.get(name) else {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingSubscriptionInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept subscription '{name}'"),
                });
                continue;
            };
            if live_subscription != simulator_subscription {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::SubscriptionDefinitionMismatch,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "subscription '{name}' differs (connection metadata intentionally excluded): live={live_subscription:?}, simulator={simulator_subscription:?}"
                    ),
                });
            }
        }
        for name in simulator.subscriptions.keys() {
            if !live.subscriptions.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraSubscriptionInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept subscription '{name}'"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Roles) {
        for membership in live.roles.difference(&simulator.roles) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::RoleMembershipMismatch,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept role membership {} -> {} with ADMIN={}, INHERIT={}, SET={}, grantor={:?}",
                    membership.member,
                    membership.role,
                    membership.admin,
                    membership.inherit,
                    membership.set,
                    membership.grantor
                ),
            });
        }
        for membership in simulator.roles.difference(&live.roles) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::RoleMembershipMismatch,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "simulator kept role membership {} -> {} with ADMIN={}, INHERIT={}, SET={}, grantor={:?}",
                    membership.member,
                    membership.role,
                    membership.admin,
                    membership.inherit,
                    membership.set,
                    membership.grantor
                ),
            });
        }
    }

    if scope.contains(&ComparisonScope::Schemas) {
        for (name, live_owner) in &live.schemas {
            match simulator.schemas.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingSchemaInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept schema {name}, but simulator removed it"),
                }),
                Some(simulator_owner) if simulator_owner != live_owner => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::SchemaOwnerMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "schema {name} owner mismatch: live={live_owner}, simulator={simulator_owner}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.schemas.keys() {
            if !live.schemas.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraSchemaInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept schema {name}, but live PostgreSQL removed it"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Sequences) {
        for (name, live_sequence) in &live.sequences {
            match simulator.sequences.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingSequenceInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept sequence {name}, but simulator removed it"),
                }),
                Some(simulator_sequence) if simulator_sequence != live_sequence => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::SequenceDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "sequence {name} mismatch: live={live_sequence:?}, simulator={simulator_sequence:?}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.sequences.keys() {
            if !live.sequences.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraSequenceInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept sequence {name}, but live PostgreSQL removed it"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Relations) || scope.contains(&ComparisonScope::Partitions) {
        for (name, live_relation) in &live.relations {
            let Some(sim_relation) = simulator.relations.get(name) else {
                continue;
            };
            if sim_relation.partition_is_default != live_relation.partition_is_default
                || sim_relation.partition_bound != live_relation.partition_bound
                || normalize_constraint_definition(sim_relation.partition_constraint.as_deref())
                    != normalize_constraint_definition(
                        live_relation.partition_constraint.as_deref(),
                    )
            {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::RelationDefinitionMismatch,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("partition metadata mismatch for {name}: live={live_relation:?}, simulator={sim_relation:?}"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Relations) {
        for (name, live_relation) in &live.relations {
            match simulator.relations.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingObjectInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept relation {name}, but simulator removed it"),
                }),
                Some(sim_relation) if sim_relation.kind != live_relation.kind => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::RelationKindMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "relation kind mismatch for {name}: live={:?}, simulator={:?}",
                            live_relation.kind, sim_relation.kind
                        ),
                    });
                }
                Some(sim_relation) if sim_relation.owner != live_relation.owner => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::RelationOwnerMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "relation owner mismatch for {name}: live={}, simulator={}",
                            live_relation.owner, sim_relation.owner
                        ),
                    });
                }
                Some(sim_relation)
                    if sim_relation.partition_strategy != live_relation.partition_strategy =>
                {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::PartitionStrategyMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "partition strategy mismatch for {name}: live={:?}, simulator={:?}",
                            live_relation.partition_strategy, sim_relation.partition_strategy
                        ),
                    });
                }
                Some(sim_relation)
                    if sim_relation.persistence != live_relation.persistence
                        || sim_relation.tablespace != live_relation.tablespace
                        || sim_relation.access_method != live_relation.access_method
                        || sim_relation.cluster_index != live_relation.cluster_index
                        || sim_relation.row_security != live_relation.row_security
                        || sim_relation.force_row_security != live_relation.force_row_security
                        || sim_relation.replica_identity != live_relation.replica_identity
                        || sim_relation.table_options != live_relation.table_options
                        || sim_relation.of_type != live_relation.of_type
                        || sim_relation.rules != live_relation.rules =>
                {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::RelationDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "relation metadata mismatch for {name}: live={live_relation:?}, simulator={sim_relation:?}"
                        ),
                    });
                }
                Some(sim_relation)
                    if scope.contains(&ComparisonScope::Columns)
                        && sim_relation.columns != live_relation.columns =>
                {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::ColumnMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "column projection mismatch for {name}: live={:?}, simulator={:?}",
                            live_relation.columns, sim_relation.columns
                        ),
                    });
                }
                Some(_) => {}
            }
        }

        for name in simulator.relations.keys() {
            if !live.relations.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraObjectInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept relation {name}, but live PostgreSQL removed it"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Indexes) {
        for index in live.indexes.difference(&simulator.indexes) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingIndexInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("live PostgreSQL kept index {index:?}"),
            });
        }
        for index in simulator.indexes.difference(&live.indexes) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraIndexInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("simulator kept index {index:?}"),
            });
        }
    }

    if scope.contains(&ComparisonScope::ForeignKeys) {
        for fk in live.foreign_keys.difference(&simulator.foreign_keys) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingForeignKeyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept FK {} ({} -> {})",
                    fk.constraint_name, fk.from_table, fk.to_table
                ),
            });
        }
        for fk in simulator.foreign_keys.difference(&live.foreign_keys) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraForeignKeyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "simulator kept FK {} ({} -> {})",
                    fk.constraint_name, fk.from_table, fk.to_table
                ),
            });
        }
    }

    if scope.contains(&ComparisonScope::Constraints) {
        for constraint in live.constraints.difference(&simulator.constraints) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingConstraintInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("live PostgreSQL kept constraint {constraint:?}"),
            });
        }
        for constraint in simulator.constraints.difference(&live.constraints) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraConstraintInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("simulator kept constraint {constraint:?}"),
            });
        }
    }

    if scope.contains(&ComparisonScope::Functions) {
        for (name, live_volatility) in &live.functions {
            match simulator.functions.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingFunctionInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept function {name}, but simulator removed it"),
                }),
                Some(simulator_volatility) if simulator_volatility != live_volatility => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::FunctionVolatilityMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "function {name} volatility mismatch: live={live_volatility}, simulator={simulator_volatility}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.functions.keys() {
            if !live.functions.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraFunctionInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept function {name}, but live PostgreSQL removed it"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Types) {
        for (name, live_type) in &live.types {
            match simulator.types.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingTypeInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept type {name}, but simulator removed it"),
                }),
                Some(simulator_type) if simulator_type != live_type => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::TypeDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "type {name} definition mismatch: live={live_type:?}, simulator={simulator_type:?}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.types.keys() {
            if !live.types.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraTypeInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept type {name}, but live PostgreSQL removed it"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Privileges) {
        for privilege in live.privileges.difference(&simulator.privileges) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingPrivilegeInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept {} on {} for {} (grantable={})",
                    privilege.privilege, privilege.table, privilege.grantee, privilege.grantable
                ),
            });
        }
        for privilege in simulator.privileges.difference(&live.privileges) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraPrivilegeInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "simulator kept {} on {} for {} (grantable={})",
                    privilege.privilege, privilege.table, privilege.grantee, privilege.grantable
                ),
            });
        }
    }

    if scope.contains(&ComparisonScope::Policies) {
        for policy in live.policies.difference(&simulator.policies) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingPolicyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept policy {} on {}",
                    policy.policy, policy.table
                ),
            });
        }
        for policy in simulator.policies.difference(&live.policies) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraPolicyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "simulator kept policy {} on {}",
                    policy.policy, policy.table
                ),
            });
        }
    }

    if scope.contains(&ComparisonScope::Triggers) {
        for (key, live_trigger) in &live.triggers {
            match simulator.triggers.get(key) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingTriggerInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "live PostgreSQL kept trigger {} on {}, but simulator removed it",
                        key.1, key.0
                    ),
                }),
                Some(simulator_trigger) if simulator_trigger.function != live_trigger.function => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::TriggerFunctionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "trigger {} on {} function mismatch: live={}, simulator={}",
                            key.1, key.0, live_trigger.function, simulator_trigger.function
                        ),
                    });
                }
                Some(simulator_trigger)
                    if simulator_trigger.enabled_mode != live_trigger.enabled_mode =>
                {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::TriggerEnableModeMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "trigger {} on {} enabled-mode mismatch: live={}, simulator={}",
                            key.1, key.0, live_trigger.enabled_mode, simulator_trigger.enabled_mode
                        ),
                    });
                }
                Some(simulator_trigger)
                    if simulator_trigger.row_level != live_trigger.row_level
                        || simulator_trigger.parent_trigger != live_trigger.parent_trigger =>
                {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::TriggerDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "trigger {} on {} definition mismatch: live={live_trigger:?}, simulator={simulator_trigger:?}",
                            key.1, key.0
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for key in simulator.triggers.keys() {
            if !live.triggers.contains_key(key) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraTriggerInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "simulator kept trigger {} on {}, but live PostgreSQL removed it",
                        key.1, key.0
                    ),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::ExtendedStatistics) {
        for (name, live_statistics) in &live.extended_statistics {
            match simulator.extended_statistics.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingExtendedStatisticsInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "live PostgreSQL kept extended statistics {name} on {}",
                        live_statistics.table
                    ),
                }),
                Some(simulator_statistics) if simulator_statistics != live_statistics => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::ExtendedStatisticsDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "extended statistics {name} mismatch: live={live_statistics:?}, simulator={simulator_statistics:?}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.extended_statistics.keys() {
            if !live.extended_statistics.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraExtendedStatisticsInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "simulator kept extended statistics {name}, but live PostgreSQL removed it"
                    ),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Partitions) {
        for edge in live.partition_edges.difference(&simulator.partition_edges) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingPartitionEdgeInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept partition edge {} -> {}",
                    edge.0, edge.1
                ),
            });
        }
        for edge in simulator.partition_edges.difference(&live.partition_edges) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraPartitionEdgeInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("simulator kept partition edge {} -> {}", edge.0, edge.1),
            });
        }
    }

    if scope.contains(&ComparisonScope::ViewDependencies) {
        for edge in live
            .view_dependencies
            .difference(&simulator.view_dependencies)
        {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingViewDependencyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept view dependency {} -> {}",
                    edge.0, edge.1
                ),
            });
        }
        for edge in simulator
            .view_dependencies
            .difference(&live.view_dependencies)
        {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraViewDependencyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("simulator kept view dependency {} -> {}", edge.0, edge.1),
            });
        }
    }

    mismatches
}

fn normalize_relation_kind(kind: RelationKind) -> NormalizedRelationKind {
    match kind {
        RelationKind::Table => NormalizedRelationKind::Table,
        RelationKind::View => NormalizedRelationKind::View,
        RelationKind::MaterializedView => NormalizedRelationKind::MaterializedView,
    }
}

fn normalize_access_method(kind: &RelationKind, method: Option<&str>) -> Option<String> {
    match kind {
        RelationKind::Table | RelationKind::MaterializedView => {
            Some(method.unwrap_or("heap").to_ascii_lowercase())
        }
        RelationKind::View => None,
    }
}

fn normalize_table_flag(kind: &RelationKind, value: Option<bool>) -> Option<bool> {
    matches!(kind, RelationKind::Table).then_some(value.unwrap_or(false))
}

fn normalize_replica_identity(kind: &RelationKind, value: Option<&str>) -> Option<String> {
    matches!(kind, RelationKind::Table).then(|| value.unwrap_or("DEFAULT").to_string())
}

#[test]
fn generated_expression_comparison_preserves_operators_and_literals() {
    use safe_migrate::_internal::model::relation::{GeneratedColumnKind, GeneratedColumnState};
    let normalize = |expression: &str| {
        normalize_generated_column(
            Some(&GeneratedColumnState {
                kind: GeneratedColumnKind::Stored,
                expression: Some(expression.into()),
            }),
            &[],
            &[],
        )
    };
    assert_eq!(normalize("((value * 2))"), normalize("value*2"));
    assert_ne!(normalize("-value"), normalize("value"));
    assert_ne!(normalize("value * 2"), normalize("value * 3"));
    assert_ne!(normalize("'a b'"), normalize("'ab'"));
}

#[test]
fn generated_expression_comparison_resolves_only_unambiguous_known_functions() {
    use safe_migrate::_internal::model::relation::{GeneratedColumnKind, GeneratedColumnState};
    let generated = |expression: &str| GeneratedColumnState {
        kind: GeneratedColumnKind::Stored,
        expression: Some(expression.into()),
    };
    let one_overload = vec![ObjectId::new("app", "visible(integer)")];
    assert_eq!(
        normalize_generated_column(
            Some(&generated("app.visible(value)")),
            &one_overload,
            &["app".into()]
        ),
        normalize_generated_column(
            Some(&generated("visible(value)")),
            &one_overload,
            &["app".into()]
        ),
    );

    let overloaded = vec![
        ObjectId::new("app", "visible(integer)"),
        ObjectId::new("app", "visible(text)"),
    ];
    assert_ne!(
        normalize_generated_column(
            Some(&generated("app.visible(value)")),
            &overloaded,
            &["app".into()]
        ),
        normalize_generated_column(
            Some(&generated("visible(value)")),
            &overloaded,
            &["app".into()]
        ),
    );
}

fn normalize_generated_column(
    generated: Option<&safe_migrate::_internal::model::relation::GeneratedColumnState>,
    known_function_ids: &[ObjectId],
    search_path: &[String],
) -> Option<String> {
    let generated = generated?;
    let Some(expression) = &generated.expression else {
        return Some(format!("{:?}:<missing expression>", generated.kind));
    };
    let expression = normalize_constraint_definition(Some(expression)).unwrap();
    let parsed = ast::SourceFile::parse(&format!("SELECT {expression}"));
    let callee_identities = parsed
        .tree()
        .syntax()
        .descendants()
        .filter_map(ast::CallExpr::cast)
        .filter_map(|call| {
            let callee = call.expr()?;
            canonical_generated_function_identity(&callee, known_function_ids, search_path)
                .map(|identity| (callee.syntax().text_range(), identity))
        })
        .collect::<Vec<_>>();
    let normalized = parsed
        .tree()
        .syntax()
        .descendants_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| !token.kind().is_trivia())
        .filter_map(|token| {
            if let Some((callee_range, identity)) = callee_identities
                .iter()
                .find(|(callee_range, _)| callee_range.contains_range(token.text_range()))
            {
                return (token.text_range().start() == callee_range.start())
                    .then(|| format!("function:{identity}"));
            }
            token
                .parent()
                .and_then(ast::NameRef::cast)
                .map(|name| format!("name:{}", name.text()))
                .or_else(|| Some(token.text().to_string()))
        })
        .collect::<Vec<_>>();
    Some(format!("{:?}:{normalized:?}", generated.kind))
}

fn canonical_generated_function_identity(
    callee: &ast::Expr,
    known_function_ids: &[ObjectId],
    search_path: &[String],
) -> Option<String> {
    let id = match callee {
        ast::Expr::NameRef(name) => {
            let name = name.text();
            search_path
                .iter()
                .find_map(|schema| known_generated_function(schema, &name, known_function_ids))?
        }
        ast::Expr::FieldExpr(field) => {
            let ast::Expr::NameRef(schema) = field.base()? else {
                return None;
            };
            let name = field.field()?;
            let schema = schema.text();
            let name = name.text();
            known_generated_function(&schema, &name, known_function_ids)?
        }
        _ => return None,
    };
    Some(qualified_name(&id.schema, &id.name))
}

fn known_generated_function(
    schema: &str,
    name: &str,
    known_function_ids: &[ObjectId],
) -> Option<ObjectId> {
    let prefix = format!("{name}(");
    let mut candidates = known_function_ids
        .iter()
        .filter(|id| id.schema == schema && id.name.starts_with(&prefix));
    let candidate = candidates.next()?.clone();
    candidates.next().is_none().then_some(candidate)
}

fn normalize_column_storage(
    state: &AnalysisState,
    data_type: &str,
    storage: Option<&str>,
) -> Option<String> {
    if let Some(storage) = storage {
        return Some(storage.to_ascii_uppercase());
    }
    let mut data_type = data_type.to_string();
    let mut visited = BTreeSet::new();
    loop {
        if data_type.ends_with("[]") {
            return Some("EXTENDED".into());
        }
        if !visited.insert(data_type.clone()) {
            return None;
        }
        let Some((schema, name)) = data_type.split_once('.') else {
            break;
        };
        let id = safe_migrate::_internal::ast::identifiers::ObjectId::new(schema, name);
        match state.local.types.get(&id) {
            Some(TypeOverlay::Present(ty)) => match &ty.kind {
                TypeKind::Domain {
                    base_type,
                    base_type_id,
                } => {
                    data_type = normalize_data_type_with_identity(base_type, base_type_id.as_ref());
                    continue;
                }
                TypeKind::Composite { .. } | TypeKind::Range => return Some("EXTENDED".into()),
                TypeKind::Enum { .. } => return Some("PLAIN".into()),
                TypeKind::Base => return None,
            },
            _ if matches!(
                state.local.relations.get(&id),
                Some(RelationOverlay::Present(_))
            ) =>
            {
                return Some("EXTENDED".into());
            }
            _ => break,
        }
    }
    let base = data_type.split('(').next()?.trim().to_ascii_lowercase();
    let inferred = match base.as_str() {
        "text" | "bytea" | "json" | "jsonb" | "xml" | "character varying" | "varchar"
        | "character" | "char" | "bpchar" | "bit" | "bit varying" | "varbit" | "jsonpath"
        | "path" | "polygon" | "tsvector" | "refcursor" => "EXTENDED",
        "numeric" | "decimal" | "inet" | "cidr" => "MAIN",
        "<unknown>" => return None,
        _ => "PLAIN",
    };
    Some(inferred.into())
}

fn normalize_attributes(
    attributes: &[safe_migrate::_internal::analysis::facts::AttributeFact],
) -> String {
    let mut normalized = attributes.to_vec();
    normalized.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
    });
    serde_json::to_string(&normalized).expect("attribute facts must be serializable")
}

fn normalize_publication_scope(
    scope: &safe_migrate::_internal::analysis::facts::PublicationScope,
) -> String {
    use safe_migrate::_internal::analysis::facts::{PublicationObjectFact, PublicationScope};

    let mut normalized = scope.clone();
    match &mut normalized {
        PublicationScope::AllTables { except } => except.sort(),
        PublicationScope::Explicit(objects) => {
            for object in objects.iter_mut() {
                if let PublicationObjectFact::Table {
                    columns: Some(columns),
                    ..
                } = object
                {
                    columns.sort();
                }
            }
            objects.sort_by(|left, right| {
                let left =
                    serde_json::to_string(left).expect("publication object must be serializable");
                let right =
                    serde_json::to_string(right).expect("publication object must be serializable");
                left.cmp(&right)
            });
        }
    }
    serde_json::to_string(&normalized).expect("publication scope must be serializable")
}

fn normalize_subscription(
    subscription: &safe_migrate::_internal::model::replication::SubscriptionState,
) -> NormalizedSubscription {
    let mut publications = subscription.publications.clone();
    publications.sort();
    NormalizedSubscription {
        owner: subscription.owner.clone(),
        publications,
        params: subscription
            .params
            .as_deref()
            .map(normalize_attributes)
            .unwrap_or_default(),
        enabled: subscription.enabled,
        slot_name: subscription.slot_name.clone(),
    }
}

fn normalize_trigger_mode(
    mode: safe_migrate::_internal::model::trigger::TriggerEnableMode,
) -> String {
    match mode {
        safe_migrate::_internal::model::trigger::TriggerEnableMode::Disabled => "disabled",
        safe_migrate::_internal::model::trigger::TriggerEnableMode::Origin => "origin",
        safe_migrate::_internal::model::trigger::TriggerEnableMode::Replica => "replica",
        safe_migrate::_internal::model::trigger::TriggerEnableMode::Always => "always",
    }
    .to_string()
}

fn normalize_sequence_persistence(
    persistence: safe_migrate::_internal::model::sequence::SequencePersistence,
) -> String {
    use safe_migrate::_internal::model::sequence::SequencePersistence;
    match persistence {
        SequencePersistence::Permanent => "permanent",
        SequencePersistence::Temporary => "temporary",
        SequencePersistence::Unlogged => "unlogged",
    }
    .to_string()
}

fn normalize_relation_persistence(
    persistence: safe_migrate::_internal::model::relation::Persistence,
) -> String {
    use safe_migrate::_internal::model::relation::Persistence;
    match persistence {
        Persistence::Permanent => "permanent",
        Persistence::Temporary => "temporary",
        Persistence::Unlogged => "unlogged",
    }
    .to_string()
}

fn normalize_volatility(volatility: &Volatility) -> String {
    match volatility {
        Volatility::Volatile => "volatile",
        Volatility::Stable => "stable",
        Volatility::Immutable => "immutable",
    }
    .to_string()
}

fn normalize_type_kind(kind: &TypeKind) -> NormalizedType {
    match kind {
        TypeKind::Enum { variants } => NormalizedType::Enum {
            variants: variants.clone(),
        },
        TypeKind::Domain { base_type, .. } => NormalizedType::Domain {
            base_type: normalize_data_type(base_type),
        },
        TypeKind::Base => NormalizedType::Base,
        TypeKind::Composite { .. } => NormalizedType::Composite,
        TypeKind::Range => NormalizedType::Range,
    }
}

fn normalize_privilege(privilege: Privilege) -> String {
    match privilege {
        Privilege::Select => "select",
        Privilege::Insert => "insert",
        Privilege::Update => "update",
        Privilege::Delete => "delete",
        Privilege::Truncate => "truncate",
        Privilege::References => "references",
        Privilege::Trigger => "trigger",
        Privilege::All => "all",
        Privilege::Maintain => "maintain",
    }
    .to_string()
}

fn normalize_constraint_kind(kind: ConstraintKind) -> String {
    match kind {
        ConstraintKind::Check => "check",
        ConstraintKind::ForeignKey => "foreign_key",
        ConstraintKind::PrimaryKey => "primary_key",
        ConstraintKind::Unique => "unique",
        ConstraintKind::Exclusion => "exclusion",
        ConstraintKind::NotNull => "not_null",
    }
    .to_string()
}

fn normalize_constraint_definition(definition: Option<&str>) -> Option<String> {
    definition.map(canonical_constraint_expression)
}

/// PostgreSQL's `pg_get_expr(conbin)` deparse wraps every operand of a
/// top-level `AND`/`OR` in parentheses regardless of how the author spelled
/// the constraint. Canonicalize both sides to a parenthesis-insensitive
/// boolean form: a parenthesized operand that is not itself a boolean
/// combination loses its parens; a parenthesized `AND`/`OR` group keeps them.
fn canonical_constraint_expression(expression: &str) -> String {
    let trimmed = expression.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut current = trimmed;
    while current.starts_with('(')
        && current.ends_with(')')
        && outer_parentheses_wrap_expression(current)
    {
        current = current[1..current.len() - 1].trim();
    }
    let separators = top_level_boolean_separators(current);
    if separators.is_empty() {
        return current.to_string();
    }
    let mut parts = Vec::new();
    let mut cursor = 0usize;
    for separator in &separators {
        parts.push(&current[cursor..separator.start]);
        cursor = separator.end;
    }
    parts.push(&current[cursor..]);
    let mut canonical = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            canonical.push(' ');
            canonical.push_str(separators[index - 1].word);
            canonical.push(' ');
        }
        canonical.push_str(&canonical_boolean_part(part));
    }
    canonical
}

fn canonical_boolean_part(part: &str) -> String {
    let trimmed = part.trim();
    if trimmed.starts_with('(')
        && trimmed.ends_with(')')
        && outer_parentheses_wrap_expression(trimmed)
    {
        let inner = &trimmed[1..trimmed.len() - 1];
        if top_level_boolean_separators(inner.trim()).is_empty() {
            canonical_constraint_expression(inner)
        } else {
            format!("({})", canonical_constraint_expression(inner))
        }
    } else {
        canonical_constraint_expression(trimmed)
    }
}

struct BooleanSeparator {
    start: usize,
    end: usize,
    word: &'static str,
}

/// Byte offsets of top-level `AND`/`OR` keywords (whitespace-delimited) in a
/// SQL expression, ignoring quoted strings. `'a'`/`'o'` inside identifiers
/// such as `land` are rejected by requiring surrounding whitespace.
fn top_level_boolean_separators(expression: &str) -> Vec<BooleanSeparator> {
    let mut separators = Vec::new();
    let bytes = expression.as_bytes();
    let mut depth = 0usize;
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut index = 0usize;
    while index < bytes.len() {
        let ch = bytes[index];
        if single_quoted {
            if ch == b'\'' {
                single_quoted = false;
            }
            index += 1;
            continue;
        }
        if double_quoted {
            if ch == b'"' {
                double_quoted = false;
            }
            index += 1;
            continue;
        }
        match ch {
            b'\'' => single_quoted = true,
            b'"' => double_quoted = true,
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        let len =
            if depth == 0 && (ch.eq_ignore_ascii_case(&b'a') || ch.eq_ignore_ascii_case(&b'o')) {
                bytes
                    .get(index..index + 3)
                    .is_some_and(|word| word.eq_ignore_ascii_case(b"and"))
                    .then_some(3)
                    .or_else(|| {
                        bytes
                            .get(index..index + 2)
                            .is_some_and(|word| word.eq_ignore_ascii_case(b"or"))
                            .then_some(2)
                    })
            } else {
                None
            };
        if let Some(len) = len {
            let before = index == 0 || bytes[index - 1].is_ascii_whitespace();
            let after = index + len;
            let after_whitespace = after >= bytes.len() || bytes[after].is_ascii_whitespace();
            if before && after_whitespace {
                let word = if len == 3 { "AND" } else { "OR" };
                separators.push(BooleanSeparator {
                    start: index,
                    end: after,
                    word,
                });
                index = after;
                continue;
            }
        }
        index += 1;
    }
    separators
}

fn outer_parentheses_wrap_expression(expression: &str) -> bool {
    let mut depth = 0usize;
    let mut single_quoted = false;
    let mut double_quoted = false;
    let bytes = expression.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' if !double_quoted => {
                if single_quoted && bytes.get(index + 1) == Some(&b'\'') {
                    index += 1;
                } else {
                    single_quoted = !single_quoted;
                }
            }
            b'"' if !single_quoted => {
                if double_quoted && bytes.get(index + 1) == Some(&b'"') {
                    index += 1;
                } else {
                    double_quoted = !double_quoted;
                }
            }
            b'(' if !single_quoted && !double_quoted => depth += 1,
            b')' if !single_quoted && !double_quoted => {
                depth = depth.saturating_sub(1);
                if depth == 0 && index + 1 != bytes.len() {
                    return false;
                }
            }
            _ => {}
        }
        index += 1;
    }
    depth == 0 && !single_quoted && !double_quoted
}

fn normalize_data_type(data_type: &str) -> String {
    let normalized = data_type.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "int" | "int4" => "integer".to_string(),
        "int2" => "smallint".to_string(),
        "int8" => "bigint".to_string(),
        "bool" => "boolean".to_string(),
        "float4" => "real".to_string(),
        "float8" => "double precision".to_string(),
        "decimal" => "numeric".to_string(),
        "varchar" => "character varying".to_string(),
        "timestamp" => "timestamp without time zone".to_string(),
        "timestamptz" => "timestamp with time zone".to_string(),
        "time" => "time without time zone".to_string(),
        "timetz" => "time with time zone".to_string(),
        _ if normalized.starts_with("varchar(") => {
            normalized.replacen("varchar(", "character varying(", 1)
        }
        _ => normalized,
    }
}

fn normalize_data_type_with_identity(
    data_type: &str,
    type_id: Option<&safe_migrate::_internal::ast::identifiers::ObjectId>,
) -> String {
    let normalized = normalize_data_type(data_type);
    let Some(type_id) = type_id else {
        return normalized;
    };

    // Keep type modifiers and array dimensions from the display string while
    // replacing the search_path-dependent base name with its stable identity.
    let suffix = normalized
        .find(|character| ['(', '['].contains(&character))
        .map(|index| &normalized[index..])
        .unwrap_or("");
    format!("{}.{}{}", type_id.schema, type_id.name, suffix)
}

#[test]
fn normalized_type_identity_preserves_modifiers_and_arrays() {
    let type_id = safe_migrate::_internal::ast::identifiers::ObjectId::new("public", "amount");
    assert_eq!(
        normalize_data_type_with_identity("numeric(10,2)[]", Some(&type_id)),
        "public.amount(10,2)[]"
    );
}

fn qualified_name(schema: &str, name: &str) -> String {
    format!("{schema}.{name}")
}

fn split_qualified_name(name: &str) -> (&str, &str) {
    name.split_once('.')
        .unwrap_or_else(|| panic!("qualified relation name must be schema.object, got {name}"))
}

fn format_mismatch_report(mismatches: &[Mismatch], manifest_path: &Path) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "live differential harness found {} mismatch(es) using {}",
        mismatches.len(),
        manifest_path.display()
    ));
    for mismatch in mismatches {
        lines.push(format!(
            "[{} / {}] {:?} [{:?}] {}",
            mismatch.rule_dir,
            mismatch.fixture,
            mismatch.category,
            mismatch.root_cause,
            mismatch.note
        ));
    }
    lines.join("\n")
}
