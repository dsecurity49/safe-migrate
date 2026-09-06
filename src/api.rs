//! Stable, supported Rust API for safe-migrate.
//!
//! The public API deliberately owns its configuration, baseline, and report
//! types. The analyzer implementation and its mutable schema model remain
//! crate-private implementation details.
//!
//! ```no_run
//! # fn main() -> Result<(), safe_migrate::api::Error> {
//! use safe_migrate::api::{self, Baseline, Config};
//! use std::path::Path;
//!
//! let config = Config::load_from_file(Path::new("safe-migrate.toml"))?;
//! let baseline = Baseline::load_optional(Path::new(".safe-migrate.cache"), &config)?;
//! let outcome = api::analyze(&config, "001.sql", "CREATE TABLE users (id bigint);", &baseline)?;
//! if outcome.should_halt() {
//!     eprintln!("{}", outcome.markdown());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ```compile_fail
//! // Internal state-machine types are intentionally not a downstream API.
//! use safe_migrate::_internal::analysis::state::AnalysisState;
//! ```
//!
//! Analysis outcomes preserve their internal reporting invariants:
//!
//! ```compile_fail
//! # use safe_migrate::api::{self, Baseline, Config};
//! # fn example() -> Result<(), api::Error> {
//! let config = Config::default();
//! let baseline = Baseline::unavailable();
//! let mut outcome = api::analyze(&config, "001.sql", "", &baseline)?;
//! outcome.findings.clear();
//! # Ok(())
//! # }
//! ```

pub(crate) mod config;

pub use config::{Config, RuleConfig};

/// Current schema version emitted by [`AnalysisOutcome::json`].
pub const REPORT_SCHEMA_VERSION: u32 = InternalReporter::JSON_SCHEMA_VERSION;

use crate::_internal::analysis::evidence as internal_evidence;
use crate::_internal::analysis::outcome::AnalysisOutcome as InternalOutcome;
use crate::_internal::analysis::state::{
    AnalysisState as InternalAnalysisState, Confidence as InternalConfidence,
};
use crate::_internal::db::cache::{
    CACHE_FORMAT_VERSION, CACHE_V7_MAGIC, DbCache as InternalDbCache, DbCacheVersioned,
};
use crate::_internal::db::cache_file::{
    MAX_CACHE_DECODE_BYTES, is_encrypted_cache_bytes, read_cache_bytes, unprotect_cache_bytes,
};
use crate::_internal::engine::engine::SafeMigrateEngine;
use crate::_internal::model::function::RoutineKind;
use crate::_internal::model::relation::RelationKind;
use crate::_internal::report::reporter::{
    Reporter as InternalReporter, Verdict as InternalVerdict, compute_verdict,
};
use crate::_internal::report::violations::{
    ObjectKind as InternalObjectKind, OperationKind as InternalOperationKind,
    ReportFinding as InternalFinding, Violation as InternalViolation,
    ViolationTier as InternalTier,
};
use crate::_internal::rules::registry::{
    self, RuleConfigurationField as InternalRuleConfigurationField,
};
use serde::Serialize;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Broad category of a supported API failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Configuration could not be read, parsed, or validated.
    Configuration,
    /// A baseline could not be read, authenticated, decoded, or validated.
    Cache,
    /// A requested primary rule ID does not exist.
    UnknownRule,
    /// One or more SQL sources could not be analyzed.
    Analysis,
    /// A report could not be rendered or presented.
    Report,
    /// PostgreSQL metadata synchronization failed.
    Sync,
}

/// Error returned by the supported API.
///
/// The stable [`ErrorKind`] supports programmatic handling while [`Self::message`]
/// and [`std::error::Error::source`] retain diagnostic detail.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    fn with_source(
        kind: ErrorKind,
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    fn configuration(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Configuration, message)
    }

    fn cache(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Cache, message)
    }

    fn analysis(errors: Vec<String>) -> Self {
        Self::new(ErrorKind::Analysis, errors.join("; "))
    }

    /// Return the stable category of this failure.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Return the operation context without its category prefix.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self {
                kind: ErrorKind::Configuration,
                message,
                ..
            } => write!(formatter, "invalid configuration: {message}"),
            Self {
                kind: ErrorKind::Cache,
                message,
                ..
            } => write!(formatter, "invalid baseline cache: {message}"),
            Self {
                kind: ErrorKind::UnknownRule,
                message,
                ..
            } => write!(formatter, "unknown primary rule: {message}"),
            Self {
                kind: ErrorKind::Analysis,
                message,
                ..
            } => write!(formatter, "analysis failed: {message}"),
            Self {
                kind: ErrorKind::Report,
                message,
                ..
            } => write!(formatter, "report failed: {message}"),
            Self {
                kind: ErrorKind::Sync,
                message,
                ..
            } => write!(formatter, "baseline sync failed: {message}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Confidence in the final migration result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum Confidence {
    /// The result is fully supported by the available modeled evidence.
    Exact,
    /// At least one relevant fact was unavailable or could not be modeled exactly.
    Tainted,
}

/// Stable severity assigned to a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[non_exhaustive]
pub enum Tier {
    /// Blocking safety problem.
    Tier1,
    /// Risk requiring explicit review.
    Tier2,
    /// Informational or operability guidance.
    Tier3,
}

/// Stable category of the SQL operation that produced a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum OperationKind {
    DropColumn,
    DropTable,
    DropIndex,
    DropView,
    DropMaterializedView,
    DropFunction,
    DropProcedure,
    DropSchema,
    DropDatabase,
    DropSequence,
    DropDomain,
    DropType,
    DropPublication,
    DropTrigger,
    DropPolicy,
    AddColumn,
    AlterColumnType,
    AddConstraint,
    CreateIndex,
    CreateTable,
    CreateView,
    CreateFunction,
    CreateProcedure,
    AlterFunction,
    AlterProcedure,
    RefreshMaterializedView,
    AttachPartition,
    DetachPartition,
    VacuumFull,
    Grant,
    RevokeGrant,
    AlterType,
    CreateTrigger,
    CreatePolicy,
    DisableTrigger,
    EnableTrigger,
    RenameTable,
    RenameColumn,
    Rename,
    /// SQL whose effects cannot be modeled precisely.
    OpaqueSql,
    CreateSchema,
    SetDefault,
    CreateSequence,
    CreateDomain,
    AlterSchema,
    Conflict,
    Irreversible,
    UnresolvedReference,
    /// A named operation outside the stable categories above.
    Other(String),
}

/// Stable category of the database object associated with a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum ObjectKind {
    Table,
    Index,
    View,
    MaterializedView,
    Function,
    Procedure,
    Trigger,
    Sequence,
    Schema,
    Role,
    Publication,
    Subscription,
    Database,
    Domain,
    Policy,
    Type,
    /// Object whose identity is opaque to the analyzer.
    Opaque,
    /// Unknown object category.
    Unknown,
}

/// Overall deployment verdict derived from all findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum Verdict {
    /// At least one Tier 1 finding blocks deployment.
    #[serde(rename = "HALT")]
    Halt,
    /// At least one Tier 2 finding requires review and no Tier 1 finding exists.
    #[serde(rename = "CAUTIOUS")]
    Cautious,
    /// Only non-blocking findings exist, including an irreversible operation.
    #[serde(rename = "SAFE WITH RISK")]
    SafeWithRisk,
    /// No modeled blocking or irreversible finding exists.
    #[serde(rename = "SAFE")]
    Safe,
}

impl Verdict {
    /// Return the stable human and JSON report label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Halt => "HALT",
            Self::Cautious => "CAUTIOUS",
            Self::SafeWithRisk => "SAFE WITH RISK",
            Self::Safe => "SAFE",
        }
    }
}

/// Counts of findings by severity tier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct FindingSummary {
    /// Total number of findings.
    pub total: usize,
    /// Number of blocking Tier 1 findings.
    pub tier1: usize,
    /// Number of review-required Tier 2 findings.
    pub tier2: usize,
    /// Number of informational Tier 3 findings.
    pub tier3: usize,
}

/// Stable reason why analysis had to be conservative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvidenceCode {
    /// No synchronized database baseline was supplied.
    BaselineUnavailable,
    /// The supplied baseline exceeded the configured maximum age.
    BaselineStale,
    /// A required catalog family was absent from the baseline.
    CatalogCoverageIncomplete,
    /// The parser accepted a statement for which no typed extractor exists.
    UnsupportedStatement,
    /// The statement was recognized but some behavior could not be modeled.
    UnsupportedSemantics,
    /// An object reference could not be resolved exactly.
    UnresolvedReference,
    /// The relevant object state could not be proven.
    UnknownObjectState,
    /// Transaction state became uncertain.
    TransactionStateUnknown,
    /// A state transition was deliberately treated as opaque.
    UnmodeledState,
}

/// Whether evidence affects one statement or the entire migration chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvidenceScope {
    /// Evidence applies to one statement.
    Statement,
    /// Evidence applies to the complete ordered migration chain.
    Chain,
}

/// Location of conservative-analysis evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[non_exhaustive]
pub struct EvidenceLocation {
    /// Source filename supplied by the caller.
    pub file: String,
    /// One-based statement position within the source file.
    pub statement_index: usize,
}

/// Stable explanation for a conservative analysis decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[non_exhaustive]
pub struct Evidence {
    /// Machine-readable reason code.
    pub code: EvidenceCode,
    /// Portion of the analysis affected by this evidence.
    pub scope: EvidenceScope,
    /// Human-readable explanation without SQL or credentials.
    pub summary: String,
    /// Source location when the evidence belongs to one statement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<EvidenceLocation>,
}

/// One-based source position of a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SourceLocation {
    /// Source filename supplied by the caller.
    pub file: String,
    /// One-based source line.
    pub line: usize,
    /// One-based source column.
    pub column: usize,
}

/// A source-aware, machine-readable migration finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Finding {
    /// Stable primary rule identifier.
    pub rule_id: String,
    /// Stable operation category.
    pub operation_kind: OperationKind,
    /// Stable database-object category.
    pub object_kind: ObjectKind,
    /// Qualified object name when known.
    pub object_name: String,
    /// Effective finding severity.
    pub tier: Tier,
    /// Explanation of the detected risk.
    pub reason: String,
    /// Recommended remediation.
    pub recipe: String,
    /// Optional key used to deduplicate equivalent findings.
    pub dedup_key: Option<String>,
    /// SQL statement associated with the finding, when available.
    pub sql: Option<String>,
    /// Whether a foreign-key dependency contributed to the finding.
    #[serde(rename = "fk_dependency_related")]
    pub foreign_key_dependency_related: bool,
    /// Current human-readable rule title, when the rule is registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_title: Option<String>,
    /// Current short rule description, when the rule is registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_summary: Option<String>,
    /// Risk category associated with the rule, when registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    /// Source line and column, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
    /// One-based statement position within the source file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_index: Option<usize>,
}

/// One named SQL migration in its intended analysis order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    filename: String,
    sql: String,
}

impl Migration {
    /// Create one named SQL migration for [`analyze_chain`].
    pub fn new(filename: impl Into<String>, sql: impl Into<String>) -> Self {
        Self {
            filename: filename.into(),
            sql: sql.into(),
        }
    }

    /// Return the migration's source name, used in finding locations.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Return the SQL source submitted for analysis.
    pub fn sql(&self) -> &str {
        &self.sql
    }
}

/// Immutable analysis result with API-owned snapshots and built-in renderers.
#[derive(Clone)]
pub struct AnalysisOutcome {
    findings: Vec<Finding>,
    confidence: Confidence,
    evidence: Vec<Evidence>,
    baseline: BaselineReport,
    inner: InternalOutcome<InternalFinding>,
}

impl fmt::Debug for AnalysisOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnalysisOutcome")
            .field("findings", &self.findings)
            .field("confidence", &self.confidence)
            .field("evidence", &self.evidence)
            .field("baseline", &self.baseline)
            .finish()
    }
}

impl AnalysisOutcome {
    /// Return findings in deterministic report order.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Return the confidence of the complete analysis.
    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Return the evidence explaining conservative analysis decisions.
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    /// Return the baseline provenance attached to every report format.
    pub fn baseline(&self) -> &BaselineReport {
        &self.baseline
    }

    /// Return whether any finding is a blocking Tier 1 result.
    pub fn should_halt(&self) -> bool {
        self.verdict() == Verdict::Halt
    }

    /// Return the overall deployment verdict.
    pub fn verdict(&self) -> Verdict {
        compute_verdict(&self.violations()).into()
    }

    /// Return the canonical deployment recommendation for this result.
    pub fn recommendation(&self) -> &'static str {
        compute_verdict(&self.violations()).recommendation(&self.inner.confidence)
    }

    /// Return finding counts by severity tier.
    pub fn summary(&self) -> FindingSummary {
        self.findings.iter().fold(
            FindingSummary {
                total: self.findings.len(),
                ..FindingSummary::default()
            },
            |mut summary, finding| {
                match finding.tier {
                    Tier::Tier1 => summary.tier1 += 1,
                    Tier::Tier2 => summary.tier2 += 1,
                    Tier::Tier3 => summary.tier3 += 1,
                }
                summary
            },
        )
    }

    /// Render the stable JSON report consumed by automation.
    pub fn json(&self) -> serde_json::Value {
        let mut report = InternalReporter::json_outcome_with_locations(&self.inner);
        report["baseline"] = serde_json::to_value(&self.baseline)
            .expect("API-owned baseline report is always serializable");
        report
    }

    /// Render the Markdown report used in pull-request summaries.
    pub fn markdown(&self) -> String {
        let mut report = InternalReporter::markdown_outcome(&self.inner);
        report.push_str("\n## Baseline\n\n");
        report.push_str(&format!(
            "- **Status:** `{}`\n- **Automatic sync:** `{}`\n",
            self.baseline.status.label(),
            self.baseline.auto_sync.label()
        ));
        if let Some(source_database) = &self.baseline.source_database {
            report.push_str(&format!(
                "- **Source database:** `{}`\n",
                source_database.replace('`', "'")
            ));
        }
        if let Some(schemas) = &self.baseline.schemas {
            report.push_str(&format!(
                "- **Schemas:** `{}`\n",
                schemas.join(", ").replace('`', "'")
            ));
        }
        report.push_str(&format!(
            "- **Observed lock timeout:** `{}`\n- **Observed statement timeout:** `{}`\n",
            format_timeout(self.baseline.observed_settings.lock_timeout_ms),
            format_timeout(self.baseline.observed_settings.statement_timeout_ms)
        ));
        report
    }

    /// Print the human report and return whether it contains a halt result.
    pub fn print_human(&self) -> bool {
        InternalReporter::print_outcome(&self.inner)
    }

    /// Run the terminal report viewer.
    pub fn run_interactive(&self) -> Result<(), Error> {
        crate::_internal::report::interactive::run_interactive(
            &self.violations(),
            &self.inner.confidence,
        )
        .map_err(|error| Error::new(ErrorKind::Report, error.to_string()))
    }

    /// Add explicit conservative evidence before rendering an outcome.
    ///
    /// This is useful for callers that know a prerequisite was unavailable
    /// outside safe-migrate's SQL analysis.
    pub fn with_evidence(mut self, code: EvidenceCode, scope: EvidenceScope) -> Self {
        self.inner = self
            .inner
            .with_evidence(internal_evidence::EvidenceRecord::new(
                code.into(),
                scope.into(),
            ));
        self.evidence = self.inner.evidence.iter().map(Evidence::from).collect();
        self.confidence = self.inner.confidence.clone().into();
        self
    }

    /// Attach the result of a caller-managed automatic baseline refresh.
    pub fn with_auto_sync_status(mut self, status: AutoSyncStatus) -> Self {
        self.baseline.auto_sync = status;
        self
    }

    fn violations(&self) -> Vec<InternalViolation> {
        self.inner
            .findings
            .iter()
            .map(|finding| finding.violation.clone())
            .collect()
    }
}

/// Opaque, validated database baseline used for analysis.
#[derive(Clone)]
pub struct Baseline {
    inner: InternalDbCache,
    available: bool,
    encrypted: bool,
    format_version: Option<u32>,
    path: Option<std::path::PathBuf>,
}

impl fmt::Debug for Baseline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Baseline")
            .field("inspection", &self.inspect())
            .finish()
    }
}

impl Default for Baseline {
    fn default() -> Self {
        Self::unavailable()
    }
}

impl Baseline {
    /// Use default worst-case assumptions when no synchronized baseline exists.
    pub fn unavailable() -> Self {
        Self {
            inner: InternalDbCache::new(),
            available: false,
            encrypted: false,
            format_version: None,
            path: None,
        }
    }

    /// Load a synchronized cache, validate its structure, and keep its internal
    /// representation opaque to callers.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Cache`] when the file cannot be read, its encryption
    /// configuration or key is wrong, or its encoded contents fail validation.
    pub fn load(path: &Path, config: &Config) -> Result<Self, Error> {
        let (inner, format_version, encrypted) = decode_cache(path, config.cache_encryption())?;
        Ok(Self {
            inner,
            available: true,
            encrypted,
            format_version: Some(format_version),
            path: Some(path.to_path_buf()),
        })
    }

    /// Load a baseline when it exists, while preserving every other loading
    /// or validation failure.
    ///
    /// A missing path produces [`Baseline::unavailable`]. Every other error is
    /// returned, so callers cannot silently downgrade a damaged baseline.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Cache`] for any failure other than a missing file.
    pub fn load_optional(path: &Path, config: &Config) -> Result<Self, Error> {
        match std::fs::metadata(path) {
            Ok(_) => Self::load(path, config),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::unavailable()),
            Err(error) => Err(Error::with_source(
                ErrorKind::Cache,
                format!("failed to inspect {}", path.display()),
                error,
            )),
        }
    }

    /// Return whether this value contains a synchronized baseline.
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Return whether the baseline is older than the supplied number of days.
    pub fn is_stale(&self, stale_days: u64) -> bool {
        self.available
            && self
                .inner
                .metadata
                .created_at_unix_secs
                .is_none_or(|created_at| {
                    now_unix_seconds().saturating_sub(created_at)
                        > stale_days.saturating_mul(24 * 60 * 60)
                })
    }

    /// Return a redacted, serializable description of baseline contents.
    pub fn inspect(&self) -> BaselineInspection {
        BaselineInspection::from_baseline(self)
    }

    fn report(&self, stale_days: u64) -> BaselineReport {
        BaselineReport {
            status: if !self.available {
                BaselineStatus::Unavailable
            } else if self.is_stale(stale_days) {
                BaselineStatus::Stale
            } else {
                BaselineStatus::Available
            },
            created_at_unix_secs: self.inner.metadata.created_at_unix_secs,
            source_database: self.inner.metadata.source_database.clone(),
            schemas: self.inner.metadata.schemas.clone(),
            auto_sync: AutoSyncStatus::NotRequested,
            observed_settings: ObservedSettings {
                lock_timeout_ms: self
                    .available
                    .then_some(self.inner.metadata.source_lock_timeout_ms),
                statement_timeout_ms: self
                    .available
                    .then_some(self.inner.metadata.source_statement_timeout_ms),
            },
        }
    }
}

/// Session settings observed while synchronizing a baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ObservedSettings {
    /// Effective `lock_timeout` in milliseconds.
    pub lock_timeout_ms: Option<u64>,
    /// Effective `statement_timeout` in milliseconds.
    pub statement_timeout_ms: Option<u64>,
}

/// Availability of the baseline used for an analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BaselineStatus {
    /// A fresh synchronized baseline was used.
    Available,
    /// A synchronized baseline older than the configured maximum was used.
    Stale,
    /// Analysis used conservative defaults without a synchronized baseline.
    Unavailable,
}

impl BaselineStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Stale => "stale",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Result of an optional caller-managed baseline refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AutoSyncStatus {
    /// No automatic refresh was requested.
    NotRequested,
    /// The caller refreshed the baseline before analysis.
    Refreshed,
    /// A requested refresh failed and analysis continued conservatively.
    Failed,
    /// The caller explicitly bypassed a configured refresh.
    Bypassed,
}

impl AutoSyncStatus {
    fn label(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::Refreshed => "refreshed",
            Self::Failed => "failed",
            Self::Bypassed => "bypassed",
        }
    }
}

/// Redacted baseline context included in every machine-readable report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BaselineReport {
    /// Availability of the baseline used for analysis.
    pub status: BaselineStatus,
    /// Baseline creation time as Unix seconds.
    pub created_at_unix_secs: Option<u64>,
    /// Redacted source database name, when captured.
    pub source_database: Option<String>,
    /// Explicit synchronized schema scope, when configured.
    pub schemas: Option<Vec<String>>,
    /// Result of caller-managed automatic synchronization.
    pub auto_sync: AutoSyncStatus,
    /// Timeouts observed during synchronization.
    pub observed_settings: ObservedSettings,
}

/// Redacted object counts contained in a baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BaselineContents {
    /// Number of schemas.
    pub schemas: usize,
    /// Number of sequences.
    pub sequences: usize,
    /// Number of all relations.
    pub relations: usize,
    /// Number of tables.
    pub tables: usize,
    /// Number of views.
    pub views: usize,
    /// Number of materialized views.
    pub materialized_views: usize,
    /// Number of relation columns.
    pub columns: usize,
    /// Number of indexes.
    pub indexes: usize,
    /// Number of foreign keys.
    pub foreign_keys: usize,
    /// Number of constraints.
    pub constraints: usize,
    /// Number of cached constraint-key records.
    pub constraint_keys: usize,
    /// Number of triggers.
    pub triggers: usize,
    /// Number of functions.
    pub functions: usize,
    /// Number of procedures.
    pub procedures: usize,
    /// Number of aggregates.
    pub aggregates: usize,
    /// Number of window functions.
    pub window_functions: usize,
    /// Number of publications.
    pub publications: usize,
    /// Number of subscriptions.
    pub subscriptions: usize,
    /// Number of PostgreSQL types.
    pub types: usize,
    /// Number of roles.
    pub roles: usize,
    /// Number of dependency edges.
    pub dependencies: usize,
    /// Number of inheritance edges.
    pub inheritances: usize,
}

/// Redacted baseline inspection suitable for display or serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BaselineInspection {
    /// Whether a synchronized baseline is present.
    pub available: bool,
    /// Source cache path, when loaded from disk.
    pub path: Option<String>,
    /// On-disk cache format version, when a cache is present.
    pub format_version: Option<u32>,
    /// Whether the source cache was encrypted.
    pub encrypted: bool,
    /// Baseline creation time as Unix seconds.
    pub created_at_unix_secs: Option<u64>,
    /// Saturating age of the baseline in seconds.
    pub age_seconds: Option<u64>,
    /// Redacted source database name.
    pub source_database: Option<String>,
    /// Explicit synchronized schema scope, when configured.
    pub schemas: Option<Vec<String>>,
    /// Catalog coverage captured by synchronization.
    pub coverage: BaselineCoverage,
    /// Effective PostgreSQL search path.
    pub search_path: Vec<String>,
    /// PostgreSQL numeric server version.
    pub postgresql_version_num: Option<u32>,
    /// Timeouts observed during synchronization.
    pub observed_settings: ObservedSettings,
    /// Redacted object counts.
    pub contents: BaselineContents,
}

/// Catalog families and schema scope represented by a baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BaselineCoverage {
    /// Whether all non-system or only explicitly selected schemas were read.
    pub schema_scope: BaselineSchemaScope,
    /// Stable names of captured catalog families.
    pub families: Vec<String>,
}

/// Schema scope captured when the baseline was synchronized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BaselineSchemaScope {
    /// All visible non-system schemas were synchronized.
    AllNonSystem,
    /// Synchronization was restricted to an explicit schema list.
    Explicit,
}

impl BaselineInspection {
    fn from_baseline(baseline: &Baseline) -> Self {
        let cache = &baseline.inner;
        let mut tables = 0;
        let mut views = 0;
        let mut materialized_views = 0;
        let mut columns = 0;
        for relation in cache.relations.values() {
            columns += relation.columns.len();
            match relation.kind {
                RelationKind::Table => tables += 1,
                RelationKind::View => views += 1,
                RelationKind::MaterializedView => materialized_views += 1,
            }
        }
        let mut functions = 0;
        let mut procedures = 0;
        let mut aggregates = 0;
        let mut window_functions = 0;
        for routine in cache.functions.values() {
            match routine.routine_kind {
                RoutineKind::Function => functions += 1,
                RoutineKind::Procedure => procedures += 1,
                RoutineKind::Aggregate => aggregates += 1,
                RoutineKind::Window => window_functions += 1,
            }
        }
        Self {
            available: baseline.available,
            path: baseline
                .path
                .as_ref()
                .map(|path| path.display().to_string()),
            format_version: baseline.format_version,
            encrypted: baseline.encrypted,
            created_at_unix_secs: cache.metadata.created_at_unix_secs,
            age_seconds: cache
                .metadata
                .created_at_unix_secs
                .map(|created_at| now_unix_seconds().saturating_sub(created_at)),
            source_database: cache.metadata.source_database.clone(),
            schemas: cache.metadata.schemas.clone(),
            coverage: BaselineCoverage {
                schema_scope: match cache.coverage.schema_scope {
                    crate::_internal::db::cache::SchemaCoverage::AllNonSystem => {
                        BaselineSchemaScope::AllNonSystem
                    }
                    crate::_internal::db::cache::SchemaCoverage::Explicit(_) => {
                        BaselineSchemaScope::Explicit
                    }
                },
                families: cache.coverage.family_names().map(str::to_owned).collect(),
            },
            search_path: cache.search_path.clone(),
            postgresql_version_num: cache.pg_version_num,
            observed_settings: ObservedSettings {
                lock_timeout_ms: baseline
                    .available
                    .then_some(cache.metadata.source_lock_timeout_ms),
                statement_timeout_ms: baseline
                    .available
                    .then_some(cache.metadata.source_statement_timeout_ms),
            },
            contents: BaselineContents {
                schemas: cache.schemas.len(),
                sequences: cache.sequences.len(),
                relations: cache.relations.len(),
                tables,
                views,
                materialized_views,
                columns,
                indexes: cache.indexes.len(),
                foreign_keys: cache.foreign_keys.len(),
                constraints: cache.constraints.len(),
                constraint_keys: cache.constraint_keys.len(),
                triggers: cache.triggers.len(),
                functions,
                procedures,
                aggregates,
                window_functions,
                publications: cache.publications.len(),
                subscriptions: cache.subscriptions.len(),
                types: cache.types.len(),
                roles: cache.roles.len(),
                dependencies: cache.dependencies.len(),
                inheritances: cache.inheritances.len(),
            },
        }
    }
}

/// Descriptor and effective configuration of one primary rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Rule {
    /// Stable rule identifier.
    pub id: String,
    /// Human-readable rule title.
    pub title: String,
    /// Short description of the unsafe pattern.
    pub summary: String,
    /// Risk category.
    pub impact: String,
    /// Default severity before confidence adjustment.
    pub default_tier: Tier,
    /// Recommended remediation.
    pub remediation: String,
    /// Configuration fields accepted by this rule.
    pub supported_configuration_fields: Vec<RuleConfigurationField>,
    /// Whether the rule is enabled by the supplied configuration.
    pub enabled: bool,
    /// Effective Tier 1 row threshold when supported.
    pub tier1_threshold_rows: Option<u64>,
    /// Effective Tier 2 row threshold when supported.
    pub tier2_threshold_rows: Option<u64>,
}

/// Configuration field supported by an individual rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleConfigurationField {
    /// Enable or disable the rule.
    Disabled,
    /// Override its Tier 1 row threshold.
    Tier1ThresholdRows,
    /// Override its Tier 2 row threshold.
    Tier2ThresholdRows,
}

impl RuleConfigurationField {
    /// Return the `safe-migrate.toml` field name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Tier1ThresholdRows => "tier1_threshold_rows",
            Self::Tier2ThresholdRows => "tier2_threshold_rows",
        }
    }
}

/// Validate configuration against the rule catalog and sync settings.
///
/// # Errors
///
/// Returns [`ErrorKind::Configuration`] for unknown rule IDs, unsupported
/// per-rule settings, invalid thresholds, or an invalid schema scope.
pub fn validate_config(config: &Config) -> Result<(), Error> {
    if config.default_rows() == 0 {
        return Err(Error::configuration(
            "default_rows must be greater than zero",
        ));
    }
    if config.toast_width_threshold_bytes() <= 0 {
        return Err(Error::configuration(
            "toast_width_threshold_bytes must be greater than zero",
        ));
    }
    config
        .validate_rule_ids(registry::primary_rule_ids())
        .and_then(|_| config.sync_schemas(None).map(|_| ()))?;
    registry::validate_rule_configuration(config).map_err(Error::configuration)
}

/// Return every primary rule with its effective configuration.
///
/// # Errors
///
/// Returns [`ErrorKind::Configuration`] when `config` is invalid.
pub fn rules(config: &Config) -> Result<Vec<Rule>, Error> {
    validate_config(config)?;
    Ok(registry::PRIMARY_RULES
        .iter()
        .map(|descriptor| Rule {
            id: descriptor.id.to_owned(),
            title: descriptor.title.to_owned(),
            summary: descriptor.summary.to_owned(),
            impact: descriptor.impact.to_owned(),
            default_tier: descriptor.default_tier().into(),
            remediation: descriptor.recipe().to_owned(),
            supported_configuration_fields: descriptor
                .supported_configuration_fields
                .iter()
                .copied()
                .map(RuleConfigurationField::from)
                .collect(),
            enabled: !config.is_rule_disabled(descriptor.id),
            tier1_threshold_rows: descriptor
                .supports(InternalRuleConfigurationField::Tier1ThresholdRows)
                .then(|| config.rule_tier1_threshold(descriptor.id)),
            tier2_threshold_rows: descriptor
                .supports(InternalRuleConfigurationField::Tier2ThresholdRows)
                .then(|| config.rule_tier2_threshold(descriptor.id)),
        })
        .collect())
}

/// Look up one primary rule and include its effective configuration.
///
/// # Errors
///
/// Returns [`ErrorKind::Configuration`] when `config` is invalid, or
/// [`ErrorKind::UnknownRule`] when `rule_id` is not registered.
pub fn rule(config: &Config, rule_id: &str) -> Result<Rule, Error> {
    rules(config)?
        .into_iter()
        .find(|rule| rule.id == rule_id)
        .ok_or_else(|| Error::new(ErrorKind::UnknownRule, rule_id))
}

/// Synchronize PostgreSQL metadata into a cache that can later be loaded as a
/// [`Baseline`].
///
/// The connection is read from `DATABASE_URL` and must target localhost or a
/// Unix socket. Encrypted caches read `SAFE_MIGRATE_CACHE_KEY` from the process
/// environment.
///
/// # Errors
///
/// Returns [`ErrorKind::Configuration`] for invalid settings and
/// [`ErrorKind::Sync`] when the connection, catalog read, or durable cache
/// replacement fails.
pub fn sync(out: &Path, config: &Config, schemas: Option<&[String]>) -> Result<(), Error> {
    validate_config(config)?;
    let schemas = config.sync_schemas(schemas)?;
    crate::_internal::sync::sync_cache(out, schemas, config.cache_encryption())
        .map_err(|error| Error::new(ErrorKind::Sync, error.to_string()))
}

/// Analyze a single migration against an opaque baseline.
///
/// # Errors
///
/// Returns [`ErrorKind::Configuration`], [`ErrorKind::Cache`], or
/// [`ErrorKind::Analysis`] when validation, state hydration, or SQL analysis
/// fails.
pub fn analyze(
    config: &Config,
    filename: impl Into<String>,
    sql: impl Into<String>,
    baseline: &Baseline,
) -> Result<AnalysisOutcome, Error> {
    analyze_chain(config, [Migration::new(filename, sql)], baseline)
}

/// Analyze an ordered migration chain against an opaque baseline.
///
/// # Errors
///
/// Returns [`ErrorKind::Configuration`], [`ErrorKind::Cache`], or
/// [`ErrorKind::Analysis`] when validation, state hydration, or SQL analysis
/// fails.
pub fn analyze_chain(
    config: &Config,
    migrations: impl IntoIterator<Item = Migration>,
    baseline: &Baseline,
) -> Result<AnalysisOutcome, Error> {
    validate_config(config)?;
    let baseline_unavailable = !baseline.available;
    let baseline_stale = baseline.is_stale(config.stale_stats_days());
    let files: Vec<(String, String)> = migrations
        .into_iter()
        .map(|migration| (migration.filename, migration.sql))
        .collect();
    let mut state =
        InternalAnalysisState::try_with_baseline(baseline.inner.clone(), baseline.available)
            .map_err(Error::cache)?;
    let engine = SafeMigrateEngine::new(config.clone());
    let inner = engine
        .analyze_chain_outcome_with_locations(&files, &mut state)
        .map_err(Error::analysis)?;
    let mut outcome =
        AnalysisOutcome::from_internal(inner, baseline.report(config.stale_stats_days()));
    if baseline_unavailable {
        outcome = outcome.with_evidence(EvidenceCode::BaselineUnavailable, EvidenceScope::Chain);
    } else if baseline_stale {
        outcome = outcome.with_evidence(EvidenceCode::BaselineStale, EvidenceScope::Chain);
    }
    Ok(outcome)
}

fn decode_cache(
    path: &Path,
    cache_encryption: bool,
) -> Result<(InternalDbCache, u32, bool), Error> {
    let encoded = read_cache_bytes(path).map_err(|error| Error::cache(error.to_string()))?;
    let encrypted = is_encrypted_cache_bytes(&encoded);
    let decrypted = unprotect_cache_bytes(encoded, cache_encryption)
        .map_err(|error| Error::cache(error.to_string()))?;
    let decoder = zstd::stream::Decoder::new(std::io::Cursor::new(decrypted)).map_err(|error| {
        Error::cache(format!(
            "{}: zstd initialization failed: {error}",
            path.display()
        ))
    })?;
    let mut decoder = decoder.take(MAX_CACHE_DECODE_BYTES as u64 + 1);
    let mut header = vec![0; CACHE_V7_MAGIC.len()];
    if decoder.read_exact(&mut header).is_err() || header != CACHE_V7_MAGIC {
        return Err(Error::cache(format!(
            "{} uses an unsupported cache format; run `safe-migrate sync`",
            path.display()
        )));
    }
    let codec = bincode::config::standard()
        .with_variable_int_encoding()
        .with_limit::<MAX_CACHE_DECODE_BYTES>();
    let versioned: DbCacheVersioned = bincode::serde::decode_from_std_read(&mut decoder, codec)
        .map_err(|error| {
            let detail = if matches!(&error, bincode::error::DecodeError::LimitExceeded) {
                format!(
                    "exceeds the {} MiB decoded-size limit",
                    MAX_CACHE_DECODE_BYTES / (1024 * 1024)
                )
            } else {
                error.to_string()
            };
            Error::cache(format!(
                "{} is corrupted (bincode): {detail}",
                path.display()
            ))
        })?;
    let remaining_before_trailing = decoder.limit();
    std::io::copy(&mut decoder, &mut std::io::sink()).map_err(|error| {
        Error::cache(format!(
            "{} is corrupted while decompressing: {error}",
            path.display()
        ))
    })?;
    let decompressed = (MAX_CACHE_DECODE_BYTES as u64 + 1) - decoder.limit();
    if decompressed > MAX_CACHE_DECODE_BYTES as u64 {
        return Err(Error::cache(format!(
            "{} exceeds the {} MiB decoded-size limit",
            path.display(),
            MAX_CACHE_DECODE_BYTES / (1024 * 1024)
        )));
    }
    if decoder.limit() != remaining_before_trailing {
        return Err(Error::cache(format!(
            "{} contains trailing payload data",
            path.display()
        )));
    }
    let format_version = versioned.format_version();
    if format_version != CACHE_FORMAT_VERSION {
        return Err(Error::cache(format!(
            "{} has a mismatched cache format header",
            path.display()
        )));
    }
    let cache = versioned.into_cache().map_err(Error::cache)?;
    Ok((cache, format_version, encrypted))
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl AnalysisOutcome {
    fn from_internal(inner: InternalOutcome<InternalFinding>, baseline: BaselineReport) -> Self {
        Self {
            findings: inner.findings.iter().map(Finding::from).collect(),
            confidence: inner.confidence.clone().into(),
            evidence: inner.evidence.iter().map(Evidence::from).collect(),
            baseline,
            inner,
        }
    }
}

fn format_timeout(timeout_ms: Option<u64>) -> String {
    timeout_ms.map_or_else(|| "unknown".to_owned(), |value| format!("{value} ms"))
}

impl From<&InternalFinding> for Finding {
    fn from(finding: &InternalFinding) -> Self {
        let violation = &finding.violation;
        let descriptor = registry::find_primary_rule(violation.rule_id);
        Self {
            rule_id: violation.rule_id.to_owned(),
            operation_kind: (&violation.operation_kind).into(),
            object_kind: (&violation.object_kind).into(),
            object_name: violation.object_name.clone(),
            tier: violation.tier.clone().into(),
            reason: violation.reason.clone(),
            recipe: violation.recipe.to_owned(),
            dedup_key: violation.dedup_key.clone(),
            sql: violation.sql.clone(),
            foreign_key_dependency_related: violation.fk_dependency_related,
            rule_title: descriptor.map(|descriptor| descriptor.title.to_owned()),
            rule_summary: descriptor.map(|descriptor| descriptor.summary.to_owned()),
            impact: descriptor.map(|descriptor| descriptor.impact.to_owned()),
            location: finding.location.as_ref().map(|location| SourceLocation {
                file: location.file.clone(),
                line: location.line,
                column: location.column,
            }),
            statement_index: finding.statement_index,
        }
    }
}

impl From<InternalConfidence> for Confidence {
    fn from(value: InternalConfidence) -> Self {
        match value {
            InternalConfidence::Exact => Self::Exact,
            InternalConfidence::Tainted => Self::Tainted,
        }
    }
}

impl From<InternalTier> for Tier {
    fn from(value: InternalTier) -> Self {
        match value {
            InternalTier::Tier1 => Self::Tier1,
            InternalTier::Tier2 => Self::Tier2,
            InternalTier::Tier3 => Self::Tier3,
        }
    }
}

impl From<InternalVerdict> for Verdict {
    fn from(value: InternalVerdict) -> Self {
        match value {
            InternalVerdict::Halt => Self::Halt,
            InternalVerdict::Cautious => Self::Cautious,
            InternalVerdict::SafeWithRisk => Self::SafeWithRisk,
            InternalVerdict::Safe => Self::Safe,
        }
    }
}

impl From<InternalRuleConfigurationField> for RuleConfigurationField {
    fn from(value: InternalRuleConfigurationField) -> Self {
        match value {
            InternalRuleConfigurationField::Disabled => Self::Disabled,
            InternalRuleConfigurationField::Tier1ThresholdRows => Self::Tier1ThresholdRows,
            InternalRuleConfigurationField::Tier2ThresholdRows => Self::Tier2ThresholdRows,
        }
    }
}

impl From<&InternalOperationKind> for OperationKind {
    fn from(value: &InternalOperationKind) -> Self {
        match value {
            InternalOperationKind::DropColumn => Self::DropColumn,
            InternalOperationKind::DropTable => Self::DropTable,
            InternalOperationKind::DropIndex => Self::DropIndex,
            InternalOperationKind::DropView => Self::DropView,
            InternalOperationKind::DropMaterializedView => Self::DropMaterializedView,
            InternalOperationKind::DropFunction => Self::DropFunction,
            InternalOperationKind::DropProcedure => Self::DropProcedure,
            InternalOperationKind::DropSchema => Self::DropSchema,
            InternalOperationKind::DropDatabase => Self::DropDatabase,
            InternalOperationKind::DropSequence => Self::DropSequence,
            InternalOperationKind::DropDomain => Self::DropDomain,
            InternalOperationKind::DropType => Self::DropType,
            InternalOperationKind::DropPublication => Self::DropPublication,
            InternalOperationKind::DropTrigger => Self::DropTrigger,
            InternalOperationKind::DropPolicy => Self::DropPolicy,
            InternalOperationKind::AddColumn => Self::AddColumn,
            InternalOperationKind::AlterColumnType => Self::AlterColumnType,
            InternalOperationKind::AddConstraint => Self::AddConstraint,
            InternalOperationKind::CreateIndex => Self::CreateIndex,
            InternalOperationKind::CreateTable => Self::CreateTable,
            InternalOperationKind::CreateView => Self::CreateView,
            InternalOperationKind::CreateFunction => Self::CreateFunction,
            InternalOperationKind::CreateProcedure => Self::CreateProcedure,
            InternalOperationKind::AlterFunction => Self::AlterFunction,
            InternalOperationKind::AlterProcedure => Self::AlterProcedure,
            InternalOperationKind::RefreshMaterializedView => Self::RefreshMaterializedView,
            InternalOperationKind::AttachPartition => Self::AttachPartition,
            InternalOperationKind::DetachPartition => Self::DetachPartition,
            InternalOperationKind::VacuumFull => Self::VacuumFull,
            InternalOperationKind::Grant => Self::Grant,
            InternalOperationKind::RevokeGrant => Self::RevokeGrant,
            InternalOperationKind::AlterType => Self::AlterType,
            InternalOperationKind::CreateTrigger => Self::CreateTrigger,
            InternalOperationKind::CreatePolicy => Self::CreatePolicy,
            InternalOperationKind::DisableTrigger => Self::DisableTrigger,
            InternalOperationKind::EnableTrigger => Self::EnableTrigger,
            InternalOperationKind::RenameTable => Self::RenameTable,
            InternalOperationKind::RenameColumn => Self::RenameColumn,
            InternalOperationKind::Rename => Self::Rename,
            InternalOperationKind::OpaqueSql => Self::OpaqueSql,
            InternalOperationKind::CreateSchema => Self::CreateSchema,
            InternalOperationKind::SetDefault => Self::SetDefault,
            InternalOperationKind::CreateSequence => Self::CreateSequence,
            InternalOperationKind::CreateDomain => Self::CreateDomain,
            InternalOperationKind::AlterSchema => Self::AlterSchema,
            InternalOperationKind::Conflict => Self::Conflict,
            InternalOperationKind::Irreversible => Self::Irreversible,
            InternalOperationKind::UnresolvedReference => Self::UnresolvedReference,
            InternalOperationKind::Other(name) => Self::Other(name.clone()),
        }
    }
}

impl From<&InternalObjectKind> for ObjectKind {
    fn from(value: &InternalObjectKind) -> Self {
        match value {
            InternalObjectKind::Table => Self::Table,
            InternalObjectKind::Index => Self::Index,
            InternalObjectKind::View => Self::View,
            InternalObjectKind::MaterializedView => Self::MaterializedView,
            InternalObjectKind::Function => Self::Function,
            InternalObjectKind::Procedure => Self::Procedure,
            InternalObjectKind::Trigger => Self::Trigger,
            InternalObjectKind::Sequence => Self::Sequence,
            InternalObjectKind::Schema => Self::Schema,
            InternalObjectKind::Role => Self::Role,
            InternalObjectKind::Publication => Self::Publication,
            InternalObjectKind::Subscription => Self::Subscription,
            InternalObjectKind::Database => Self::Database,
            InternalObjectKind::Domain => Self::Domain,
            InternalObjectKind::Policy => Self::Policy,
            InternalObjectKind::Type => Self::Type,
            InternalObjectKind::Opaque => Self::Opaque,
            InternalObjectKind::Unknown => Self::Unknown,
        }
    }
}

impl From<&internal_evidence::EvidenceRecord> for Evidence {
    fn from(record: &internal_evidence::EvidenceRecord) -> Self {
        Self {
            code: record.code.into(),
            scope: record.scope.into(),
            summary: record.summary.to_owned(),
            location: record.location.as_ref().map(|location| EvidenceLocation {
                file: location.file.clone(),
                statement_index: location.statement_index,
            }),
        }
    }
}

impl From<internal_evidence::EvidenceCode> for EvidenceCode {
    fn from(value: internal_evidence::EvidenceCode) -> Self {
        match value {
            internal_evidence::EvidenceCode::BaselineUnavailable => Self::BaselineUnavailable,
            internal_evidence::EvidenceCode::BaselineStale => Self::BaselineStale,
            internal_evidence::EvidenceCode::CatalogCoverageIncomplete => {
                Self::CatalogCoverageIncomplete
            }
            internal_evidence::EvidenceCode::UnsupportedStatement => Self::UnsupportedStatement,
            internal_evidence::EvidenceCode::UnsupportedSemantics => Self::UnsupportedSemantics,
            internal_evidence::EvidenceCode::UnresolvedReference => Self::UnresolvedReference,
            internal_evidence::EvidenceCode::UnknownObjectState => Self::UnknownObjectState,
            internal_evidence::EvidenceCode::TransactionStateUnknown => {
                Self::TransactionStateUnknown
            }
            internal_evidence::EvidenceCode::UnmodeledState => Self::UnmodeledState,
        }
    }
}

impl From<EvidenceCode> for internal_evidence::EvidenceCode {
    fn from(value: EvidenceCode) -> Self {
        match value {
            EvidenceCode::BaselineUnavailable => Self::BaselineUnavailable,
            EvidenceCode::BaselineStale => Self::BaselineStale,
            EvidenceCode::CatalogCoverageIncomplete => Self::CatalogCoverageIncomplete,
            EvidenceCode::UnsupportedStatement => Self::UnsupportedStatement,
            EvidenceCode::UnsupportedSemantics => Self::UnsupportedSemantics,
            EvidenceCode::UnresolvedReference => Self::UnresolvedReference,
            EvidenceCode::UnknownObjectState => Self::UnknownObjectState,
            EvidenceCode::TransactionStateUnknown => Self::TransactionStateUnknown,
            EvidenceCode::UnmodeledState => Self::UnmodeledState,
        }
    }
}

impl From<internal_evidence::EvidenceScope> for EvidenceScope {
    fn from(value: internal_evidence::EvidenceScope) -> Self {
        match value {
            internal_evidence::EvidenceScope::Statement => Self::Statement,
            internal_evidence::EvidenceScope::Chain => Self::Chain,
        }
    }
}

impl From<EvidenceScope> for internal_evidence::EvidenceScope {
    fn from(value: EvidenceScope) -> Self {
        match value {
            EvidenceScope::Statement => Self::Statement,
            EvidenceScope::Chain => Self::Chain,
        }
    }
}
