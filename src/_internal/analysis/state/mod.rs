use crate::_internal::analysis::evidence::{
    EvidenceCode, EvidenceLocation, EvidenceLog, EvidenceRecord, EvidenceScope,
};
use crate::_internal::analysis::graph::{DependencyEdge, DependencyGraph, DependencyKind};
use crate::_internal::analysis::mutations::Mutation;
use crate::_internal::analysis::namespace::{
    SESSION_TEMP_SCHEMA, SYSTEM_CATALOG_SCHEMA, SearchPathEntry, is_session_temp_schema,
};
use crate::_internal::analysis::settings::ScopedSetting;
use crate::_internal::analysis::transaction::{NamespaceSnapshot, StateChange, TransactionFrame};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::db::cache::CatalogCoverage;
use crate::_internal::db::cache::DbCache;
use crate::_internal::db::cache::ScopedDependencyEdge;
use crate::_internal::model::aggregate::AggregateCatalogue;
use crate::_internal::model::builtin_type::BuiltinTypeCatalogue;
use crate::_internal::model::cast::CastCatalogue;
use crate::_internal::model::constraint::{ConstraintKind, ConstraintState};
use crate::_internal::model::data_type::ParsedDataType;
use crate::_internal::model::function::FunctionOverlay;
pub(crate) use crate::_internal::model::relation::RelationOverlay;
use crate::_internal::model::relation::{Persistence, Privilege, RelationKind};
use crate::_internal::model::replication::{SUBSCRIPTION_PARAMS, SubscriptionValue};
use crate::_internal::model::schema::SchemaOverlay;
use crate::_internal::model::sequence::SequenceOverlay;
use crate::_internal::model::trigger::TriggerOverlay;
use crate::_internal::model::types::{TypeKind, TypeOverlay, TypeState};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;

mod apply_misc;
mod apply_policy_trigger;
mod apply_relation;
mod apply_replication;
mod apply_role;
mod apply_routine;
mod apply_schema;
mod apply_sequence;
mod apply_settings;
mod apply_transaction;
mod apply_type;
mod apply_view_index;
mod index_topology;
mod type_cascade;

mod accessors;
mod aggregate;
mod apply;
mod cascade;
mod evidence;
mod grants;
mod hydrate;
mod lookup;
mod names;
mod pre_state;
mod publication;
mod roles;
mod rollback;
mod schemas;
mod snapshots;
mod types;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) enum Confidence {
    Exact,
    Tainted,
}

/// Why PostgreSQL rejects a statement against known state.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConflictKind {
    /// A `CONCURRENTLY` operation cannot run inside a transaction block.
    ConcurrentInTransaction,
    /// Any other statement PostgreSQL rejects.
    Rejected { reason: String },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MutationResult {
    Applied,
    /// PostgreSQL executed the statement but nothing in the modeled state
    /// changed, so no dependent rule can observe a difference.
    NoOp,
    /// PostgreSQL did not execute this statement because an earlier statement
    /// aborted the active transaction.
    NotExecuted,
    /// The modeled outcome cannot be stated, and this is the evidence recorded
    /// for it. The cause rides on the result so a rule never re-derives it.
    Unresolved(EvidenceCode),
    Conflict(ConflictKind),
}

impl MutationResult {
    pub(crate) fn is_unresolved(&self) -> bool {
        matches!(self, Self::Unresolved(_))
    }

    /// The recorded cause when unresolved, so a caller never has to match on
    /// the variant and invent a fallback for a case that cannot occur.
    pub(crate) fn unresolved_cause(&self) -> Option<EvidenceCode> {
        match self {
            Self::Unresolved(cause) => Some(*cause),
            _ => None,
        }
    }

    /// PostgreSQL ran the statement but the modeled state did not change, so a
    /// rule whose finding depends on a transition cannot have observed one.
    pub(crate) fn is_noop(&self) -> bool {
        matches!(self, Self::NoOp)
    }

    pub(crate) fn conflict(reason: impl Into<String>) -> Self {
        Self::Conflict(ConflictKind::Rejected {
            reason: reason.into(),
        })
    }

    pub(crate) fn is_concurrent_transaction_conflict(&self) -> bool {
        matches!(self, Self::Conflict(ConflictKind::ConcurrentInTransaction))
    }

    /// The PostgreSQL-facing message for a rejected statement.
    pub(crate) fn conflict_reason(&self) -> Option<&str> {
        match self {
            Self::Conflict(ConflictKind::Rejected { reason }) => Some(reason.as_str()),
            Self::Conflict(ConflictKind::ConcurrentInTransaction) => {
                Some("CONCURRENTLY operation cannot run inside a transaction block")
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectLookup {
    Present,
    WrongKind,
    Tombstone,
    AuthoritativelyAbsent,
    Unknown,
}

fn sync_present_map<K, V, O, F>(target: &mut HashMap<K, V>, source: &HashMap<K, O>, present: F)
where
    K: Clone + Eq + Hash,
    V: Clone + PartialEq,
    F: for<'a> Fn(&'a O) -> Option<&'a V> + Copy,
{
    target.retain(|key, value| {
        let Some(current) = source.get(key).and_then(present) else {
            return false;
        };
        if value != current {
            value.clone_from(current);
        }
        true
    });
    target.reserve(source.len().saturating_sub(target.len()));
    for (key, overlay) in source {
        if !target.contains_key(key)
            && let Some(value) = present(overlay)
        {
            target.insert(key.clone(), value.clone());
        }
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct CascadeResult {
    pub dropped_relations: HashSet<ObjectId>,
    pub dropped_indexes: HashSet<ObjectId>,
    pub dropped_constraints: HashSet<(ObjectId, String)>,
}

#[derive(Clone)]
pub(crate) struct LocalState {
    pub schemas: HashMap<String, SchemaOverlay>,
    pub relations: HashMap<ObjectId, RelationOverlay>,
    pub types: HashMap<ObjectId, TypeOverlay>,
    pub functions: HashMap<ObjectId, crate::_internal::model::function::FunctionOverlay>,
    pub sequences: HashMap<ObjectId, SequenceOverlay>,
    pub extensions: HashMap<String, crate::_internal::model::extension::ExtensionOverlay>,
    pub publications: HashMap<String, crate::_internal::model::replication::PublicationOverlay>,
    pub subscriptions: HashMap<String, crate::_internal::model::replication::SubscriptionOverlay>,
    pub roles: HashMap<ObjectId, crate::_internal::model::role::RoleOverlay>,
    pub role_membership_grantors: Vec<crate::_internal::model::role::RoleMembershipGrantor>,
    pub role_membership_grantors_complete: bool,
    /// The cluster's bootstrap superuser, attributed with modern PostgreSQL's
    /// implicit superuser grantor. Absent when unknown or unset.
    pub bootstrap_superuser: Option<String>,
    pub triggers: HashMap<ObjectId, TriggerOverlay>,
    pub constraints: HashMap<(ObjectId, String), ConstraintState>,
    pub graph: DependencyGraph,
    pub search_path: Vec<SearchPathEntry>,
    /// Built-in types of the synchronized cluster, used to resolve written
    /// type names. Empty only when no baseline supplied one.
    pub builtin_types: BuiltinTypeCatalogue,
    pub opclasses: crate::_internal::model::opclass::OpclassCatalogue,
    pub casts: crate::_internal::model::cast::CastCatalogue,
    pub aggregates: crate::_internal::model::aggregate::AggregateCatalogue,
    /// Collations of the synchronized cluster, used to resolve written
    /// `COLLATE` names. Empty only when no baseline supplied one.
    pub collations: crate::_internal::model::collation::CollationCatalogue,
    /// Performance hint: a temporary object has been created in this session.
    /// `temp_namespace_exists` derives the real answer, so this only has to be
    /// a superset to stay correct across rollback and `ON COMMIT DROP`.
    pub saw_temp_object: bool,
    pub search_path_template: Vec<String>,
    pub session_search_path_template: Vec<String>,
    pub default_search_path_template: Vec<String>,
    /// Schemas that existed at synchronization time, before the scope filter.
    /// Absence proves a default-template entry named no schema.
    pub source_existing_schemas: Option<HashSet<String>>,
    pub lock_timeout: ScopedSetting<Option<u64>>,
    pub statement_timeout: ScopedSetting<Option<u64>>,
    /// Role currently active for this session context (updated by SET ROLE /
    /// SET SESSION AUTHORIZATION). Begins equal to `session_role`.
    pub current_role: String,
    /// Whether `current_role` is statically known. False when no synchronized cache was
    /// loaded and no SET ROLE statement has been processed yet.
    pub current_role_known: bool,
    /// Effective role setting that survives transaction commit. A LOCAL role
    /// change updates `current_role` without changing this value.
    pub persistent_current_role: String,
    pub persistent_current_role_known: bool,
    /// The session-level role as captured from the cache's `source_role`. This
    /// is the value `SET ROLE NONE` / `SET SESSION AUTHORIZATION DEFAULT`
    /// reverts to.
    pub session_role: String,
    /// Whether `session_role` is statically known (mirrors `current_role_known`
    /// at baseline; a SET SESSION AUTHORIZATION updates this too).
    pub session_role_known: bool,
    /// Session authorization that survives transaction commit.
    pub persistent_session_role: String,
    pub persistent_session_role_known: bool,
    /// Login identity restored by `SET SESSION AUTHORIZATION DEFAULT`.
    pub authenticated_role: String,
    pub authenticated_role_known: bool,
    /// Whether the cache contains a complete PostgreSQL role catalog.
    pub roles_known: bool,
    pub confidence: Confidence,
    pub evidence: EvidenceLog,
    pub current_evidence_location: Option<EvidenceLocation>,
    pub transactions: Vec<TransactionFrame>,
    pub transaction_aborted: bool,
    pub pending_validation: HashSet<(ObjectId, String)>,
    pub generation_counter: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct PreState {
    pub relations: HashMap<ObjectId, crate::_internal::model::relation::RelationState>,
    pub functions: HashMap<ObjectId, crate::_internal::model::function::FunctionState>,
    pub roles: HashMap<ObjectId, crate::_internal::model::role::RoleState>,
    pub publications: HashMap<String, crate::_internal::model::replication::PublicationState>,
    pub subscriptions: HashMap<String, crate::_internal::model::replication::SubscriptionState>,
    pub sequences: HashMap<ObjectId, crate::_internal::model::sequence::SequenceState>,
    pub extensions: HashMap<String, crate::_internal::model::extension::ExtensionState>,
    pub types: HashMap<ObjectId, crate::_internal::model::types::TypeState>,
    pub indexes: Vec<crate::_internal::analysis::graph::DependencyEdge>,
    pub baseline_foreign_keys: HashSet<(ObjectId, String)>,
}

struct HydratedRelationTypes {
    relations: HashMap<ObjectId, RelationOverlay>,
    baseline_relations: HashSet<ObjectId>,
    baseline_fk_dependencies: HashSet<ObjectId>,
    types: HashMap<ObjectId, TypeOverlay>,
}

#[derive(Clone)]
pub(crate) struct AnalysisState {
    pub pg_version_num: Option<u32>,
    /// Rules that could not state a finding because their evidence was missing.
    not_evaluated: Vec<crate::_internal::report::violations::NotEvaluated>,
    /// Version asserted by configuration, used only when the cache lacks one.
    asserted_pg_version_num: Option<u32>,
    /// Database the migrations are applied to, as stated by configuration.
    target_database: Option<String>,
    /// Whether the initial cache was loaded from a real cache file. An empty
    /// cache can be a valid baseline for an empty database, so availability
    /// must not be inferred from the number of modeled objects.
    pub baseline_available: bool,
    /// Whether scoped cross-catalog boundary queries were run by the
    /// synchronizer. Programmatic caches lack this provenance and remain
    /// conservative for destructive scoped transitions.
    pub baseline_boundary_queries_complete: bool,
    /// V7 catalog completeness used for authoritative absence decisions.
    /// Family-specific legacy fields remain only while their consumers migrate.
    pub baseline_coverage: CatalogCoverage,
    /// `None` means the cache covered all non-system schemas. A populated set
    /// records an explicitly scoped sync, for which objects outside the set
    /// are unknown rather than known absent.
    pub baseline_schemas: Option<HashSet<String>>,
    pub baseline_relations: HashSet<ObjectId>,
    pub baseline_indexes: HashSet<ObjectId>,
    pub baseline_foreign_keys: HashSet<(ObjectId, String)>,
    pub baseline_fk_dependencies: HashSet<ObjectId>,
    pub baseline_sequences: HashSet<ObjectId>,
    pub scoped_external_dependencies: HashSet<ScopedDependencyEdge>,
    /// Out-of-scope schemas that reference the scope through a catalog class
    /// the model does not hold, so no edge can attribute them to a family.
    pub external_referencing_schemas: BTreeSet<String>,
    pub local: LocalState,
}

/// Where the PostgreSQL version used for semantic decisions came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PgVersion {
    Observed(u32),
    Assumed(u32),
    Unresolved,
}

/// Oldest release we support. Assuming an older server reports more risk.
pub(crate) const OLDEST_SUPPORTED_PG_VERSION_NUM: u32 = 140_000;

impl PgVersion {
    pub(crate) fn num(self) -> Option<u32> {
        match self {
            Self::Observed(version) | Self::Assumed(version) => Some(version),
            Self::Unresolved => None,
        }
    }

    /// Whether the effective version satisfies `predicate`. An unresolved
    /// version cannot place a feature, so it answers false.
    pub(crate) fn satisfies(self, predicate: impl FnOnce(u32) -> bool) -> bool {
        match self {
            Self::Observed(version) | Self::Assumed(version) => predicate(version),
            Self::Unresolved => false,
        }
    }

    /// Whether this version came from the user rather than from the server.
    pub(crate) fn is_asserted(self) -> bool {
        !matches!(self, Self::Observed(_))
    }

    /// Version to branch on, defaulting to the oldest supported release so an
    /// unanswerable version question reports risk rather than safety.
    pub(crate) fn conservative_num(self) -> u32 {
        self.num().unwrap_or(OLDEST_SUPPORTED_PG_VERSION_NUM)
    }
}

/// Renders a `server_version_num` as the major release, e.g. `160_002` to
/// `"16"`, so a diagnostic can name the release that introduced a feature.
pub(crate) fn pg_version_label(version_num: u32) -> String {
    (version_num / 10_000).to_string()
}

/// The routine name in `name(arguments)`, which is how a routine identity is
/// spelled.
pub(crate) fn bare_routine_name(identity: &str) -> &str {
    match identity.split_once('(') {
        Some((name, _)) => name,
        None => identity,
    }
}

#[cfg(test)]
mod pre_state_tests;

#[cfg(test)]
mod evidence_tests;

pub(crate) use aggregate::{AggregateCallArgument, AggregateCandidateResolution};
