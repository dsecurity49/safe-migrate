use crate::common::{database_hosts_are_local, synced_cache};
use postgres::{Client, Config as PostgresConfig, NoTls};
use safe_migrate::_internal::analysis::graph::DependencyKind;
use safe_migrate::_internal::analysis::state::AnalysisState;
use safe_migrate::_internal::ast::identifiers::ObjectId;
use safe_migrate::_internal::db::cache::DbCache;
use safe_migrate::_internal::engine::engine::SafeMigrateEngine;
use safe_migrate::_internal::model::constraint::ConstraintKind;
use safe_migrate::_internal::model::function::{FunctionOverlay, Volatility};
use safe_migrate::_internal::model::index::{IndexOrder, KeyCollation, KeyOpclass};
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

mod normalize;
mod snapshot;

use normalize::*;
use snapshot::*;

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
    fixture_requires_extensions: BTreeMap<String, Vec<String>>,
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
    pending_detach_setup: BTreeMap<String, PendingDetachSetup>,
    #[serde(default)]
    notes: Option<String>,
}

/// Certificate that a fixture begins from a genuinely-pending concurrent detach
/// (PostgreSQL `inhdetachpending = true`) instead of a steady-state baseline.
/// The harness plants this real catalog state by starting a blocked
/// `DETACH PARTITION ... CONCURRENTLY` and terminating the backend after its
/// first internal transaction commits, matching how an interrupted or crashed
/// detach leaves `pg_inherits` behind.  `FINALIZE` fixtures then validate
/// against the true crash-recovery catalog.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingDetachSetup {
    schema: String,
    parent: String,
    child: String,
    strategy: String,
    column: String,
    bound: String,
    // Interrupt via `pg_terminate_backend` (backend crash) instead of a
    // protocol-level query cancel.  The committed pending row is identical;
    // the distinction exercises the crash-recovery catalog path.
    #[serde(default)]
    crash: bool,
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
    IndexPartitions,
    Publications,
    Subscriptions,
    ExtendedStatistics,
    Extensions,
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
    index_attachment_edges: BTreeSet<(String, String)>,
    view_dependencies: BTreeSet<(String, String)>,
    publications: BTreeMap<String, NormalizedPublication>,
    subscriptions: BTreeMap<String, NormalizedSubscription>,
    extended_statistics: BTreeMap<String, NormalizedExtendedStatistics>,
    extensions: BTreeMap<String, NormalizedExtension>,
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
    ForeignTable,
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
    nulls_not_distinct: Option<bool>,
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
    Enum {
        variants: Vec<String>,
    },
    Domain {
        base_type: String,
        collation: Option<String>,
        default: Option<String>,
        not_null: bool,
        constraints: BTreeMap<String, (String, bool)>,
    },
    Base {
        shell: bool,
    },
    Composite {
        fields: Vec<(String, String, Option<String>)>,
    },
    Range {
        subtype: Option<String>,
        multirange: Option<String>,
        collation: Option<String>,
    },
    Multirange {
        range: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedExtension {
    owner: String,
    schema: Option<String>,
    version: Option<String>,
    relocatable: Option<bool>,
    members: BTreeSet<(String, String)>,
    config_tables: Vec<String>,
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
    MissingIndexAttachmentInSimulator,
    ExtraPartitionEdgeInSimulator,
    ExtraIndexAttachmentInSimulator,
    MissingViewDependencyInSimulator,
    ExtraViewDependencyInSimulator,
    MissingPublicationInSimulator,
    ExtraPublicationInSimulator,
    PublicationDefinitionMismatch,
    MissingSubscriptionInSimulator,
    ExtraSubscriptionInSimulator,
    SubscriptionDefinitionMismatch,
    MissingExtensionInSimulator,
    ExtraExtensionInSimulator,
    ExtensionDefinitionMismatch,
    RoleMembershipMismatch,
    BaselineObjectAbsent,
    BaselineSearchPathMismatch,
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
    let live = crate::internal_tests::live_database_test_lock();
    let verbosity = differential_verbosity();
    let harness_started = Instant::now();
    let database_url = match live.url() {
        Some(value) => value,
        None => {
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
    let any_extension_requirement = manifest
        .rules
        .iter()
        .any(|rule| !rule.fixture_requires_extensions.is_empty());
    let available_extensions: BTreeSet<String> = if any_extension_requirement {
        client
            .query("SELECT name FROM pg_available_extensions", &[])
            .expect("failed to inspect available extensions")
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect()
    } else {
        BTreeSet::new()
    };
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
            if let Some(required) = rule.fixture_requires_extensions.get(fixture) {
                let missing = required
                    .iter()
                    .filter(|extension| !available_extensions.contains(*extension))
                    .cloned()
                    .collect::<Vec<_>>();
                if !missing.is_empty() {
                    verbose(
                        verbosity,
                        1,
                        format!(
                            "case={}/{} phase=skip unavailable_extensions={missing:?}",
                            rule.rule_dir, fixture
                        ),
                    );
                    continue;
                }
            }
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

            if let Some(setup) = rule.pending_detach_setup.get(fixture) {
                let planted = plant_pending_detach(&mut client, database_config.clone(), setup);
                match planted {
                    Ok(child) => {
                        verbose(
                            verbosity,
                            2,
                            format!(
                                "case={}/{} phase=pending-detach-planted child={child}",
                                rule.rule_dir, fixture
                            ),
                        );
                    }
                    Err(error) => {
                        mismatches.push(Mismatch {
                            rule_dir: rule.rule_dir.clone(),
                            fixture: fixture.clone(),
                            category: MismatchCategory::LiveExecutionFailed,
                            root_cause: RootCauseClassification::HarnessBug,
                            note: format!("failed to plant pending concurrent detach: {error:#}"),
                        });
                        continue;
                    }
                }
            }

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
            mismatches.extend(check_recorded_search_path(
                rule,
                fixture,
                &mut client,
                &baseline_cache,
            ));

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
        "schemas:{} sequences:{} relations:{} indexes:{} constraints:{} foreign_keys:{} functions:{} types:{} privileges:{} policies:{} triggers:{} partitions:{} view_dependencies:{} publications:{} subscriptions:{} extended_statistics:{} extensions:{}",
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
        state.extended_statistics.len(),
        state.extensions.len()
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
    let live = crate::internal_tests::live_database_test_lock();
    let config: PostgresConfig = live
        .url()
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
        let setups = [
            PendingDetachSetup {
                schema: schema.clone(),
                parent: "parent".to_string(),
                child: "child".to_string(),
                strategy: "RANGE".to_string(),
                column: "id".to_string(),
                bound: "FROM (0) TO (10)".to_string(),
                crash: false,
            },
            PendingDetachSetup {
                schema: schema.clone(),
                parent: "parent".to_string(),
                child: "child".to_string(),
                strategy: "LIST".to_string(),
                column: "id".to_string(),
                bound: "IN (1, 2, 3)".to_string(),
                crash: true,
            },
        ];
        for setup in setups {
            plant_pending_detach(&mut client, config.clone(), &setup)
                .expect("plant pending detach");
            let qualified_parent = format!("{}.{}", setup.schema, setup.parent);
            let qualified_child = format!("{}.{}", setup.schema, setup.child);

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
            let finalize = format!(
                "ALTER TABLE {qualified_parent} DETACH PARTITION {qualified_child} FINALIZE;"
            );
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
                    "DROP TABLE {qualified_child}; DROP TABLE {qualified_parent};"
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
            value: Some("insert".into()),
            namespace: None,
        },
        safe_migrate::_internal::analysis::facts::AttributeFact {
            name: "publish_via_partition_root".into(),
            value: Some("false".into()),
            namespace: None,
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
    assert!(counts.ends_with("publications:0 subscriptions:1 extended_statistics:0 extensions:0"));
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
        for fixture in rule.fixture_requires_extensions.keys() {
            assert!(
                included.contains(fixture),
                "extension requirement references a non-included fixture: {}/{}",
                rule.rule_dir,
                fixture
            );
        }
        for fixture in rule.pending_detach_setup.keys() {
            assert!(
                rule.fixture_autocommit.contains(fixture),
                "pending-detach fixture must be autocommit (DETACH CONCURRENTLY cannot run in a transaction): {}/{}",
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

        for (fixture, setup) in &rule.pending_detach_setup {
            assert!(
                included.contains(fixture),
                "pending-detach setup references a non-included fixture: {}/{}",
                rule.rule_dir,
                fixture
            );
            assert!(
                !rule
                    .excluded_fixtures
                    .iter()
                    .any(|exclusion| exclusion.fixture == *fixture),
                "pending-detach fixture cannot also be excluded: {}/{}",
                rule.rule_dir,
                fixture
            );
            for identity in [
                &setup.schema,
                &setup.parent,
                &setup.child,
                &setup.strategy,
                &setup.column,
                &setup.bound,
            ] {
                assert!(
                    !identity.trim().is_empty(),
                    "pending-detach setup has an empty field for {}/{}",
                    rule.rule_dir,
                    fixture
                );
            }
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
        fixture_requires_extensions: BTreeMap::new(),
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
        pending_detach_setup: BTreeMap::new(),
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
        fixture_requires_extensions: BTreeMap::new(),
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
        pending_detach_setup: BTreeMap::new(),
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
    let missing = check_role_membership_cache(&rule, "fixture.sql", &synced_cache());
    assert_eq!(missing.len(), 2);
    assert!(missing.iter().all(|mismatch| {
        mismatch.category == MismatchCategory::BaselineObjectAbsent
            && mismatch.root_cause == RootCauseClassification::BaselineSetupGap
    }));

    let mut cache = synced_cache();
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

#[test]
fn normalized_type_identity_preserves_modifiers_and_arrays() {
    let type_id = safe_migrate::_internal::ast::identifiers::ObjectId::new("public", "amount");
    assert_eq!(
        normalize_data_type_with_identity("numeric(10,2)[]", Some(&type_id)),
        "public.amount(10,2)[]"
    );
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
