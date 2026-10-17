//! The reloptions the analyzer recognises, mirroring PostgreSQL's own tables.
//!
//! PostgreSQL keeps several option tables in `reloptions.c` and selects between
//! them by relation kind, so a name is only meaningful together with the kind it
//! is set on. This module keeps that shape: every option records the kinds it
//! applies to, the domain of its value, and the release that introduced it.
//!
//! An option this module does not know is reported as unplaceable rather than
//! invalid. The accepted surface grows between releases, and a false conflict
//! on a valid migration is worse than a stated uncertainty.

use crate::_internal::analysis::state::PgVersion;

/// The domain an option's value must fall in.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ReloptionValue {
    /// `parse_bool`, which accepts any unambiguous prefix.
    Bool,
    /// A boolean that also carries "unset"; only whole-relation options use it.
    Ternary,
    /// Compared case-insensitively against the whole value, never a prefix.
    Enum(&'static [&'static str]),
    Int {
        min: i64,
        max: i64,
    },
    Real {
        min: f64,
        max: f64,
    },
}

/// Which relation kinds an option may be set on.
///
/// PostgreSQL applies the heap options to materialized views and ordinary
/// tables alike, and the view options only to views, so the two sets do not
/// overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReloptionKinds {
    pub heap: bool,
    pub view: bool,
}

const HEAP: ReloptionKinds = ReloptionKinds {
    heap: true,
    view: false,
};
const VIEW: ReloptionKinds = ReloptionKinds {
    heap: false,
    view: true,
};

/// One recognised option.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReloptionSpec {
    pub name: &'static str,
    pub value: ReloptionValue,
    /// The release that introduced the option. `None` means it predates the
    /// oldest supported release, so no gate applies.
    pub since: Option<u32>,
    pub kinds: ReloptionKinds,
}

/// PostgreSQL 15 added `security_invoker` alongside `security_barrier`.
const SECURITY_INVOKER_VERSION: u32 = 150_000;
/// PostgreSQL 18 added eager-freeze scanning and its server-side trigger.
const EAGER_FREEZE_VERSION: u32 = 180_000;

const CHECK_OPTION_VALUES: &[&str] = &["local", "cascaded"];
const VACUUM_INDEX_CLEANUP_VALUES: &[&str] = &["auto", "on", "off"];

const INT_MAX: i64 = i32::MAX as i64;

/// PostgreSQL's option tables, in the order `reloptions.c` declares them.
///
/// The bounds and defaults are the server's; the analyzer only checks bounds,
/// because a default it never applies cannot make a claim wrong.
const OPTIONS: &[ReloptionSpec] = &[
    // Views hold no storage, so their whole option set is this small.
    ReloptionSpec {
        name: "security_barrier",
        value: ReloptionValue::Bool,
        since: None,
        kinds: VIEW,
    },
    ReloptionSpec {
        name: "security_invoker",
        value: ReloptionValue::Bool,
        since: Some(SECURITY_INVOKER_VERSION),
        kinds: VIEW,
    },
    ReloptionSpec {
        name: "check_option",
        value: ReloptionValue::Enum(CHECK_OPTION_VALUES),
        since: None,
        kinds: VIEW,
    },
    // Heap options, which a materialized view inherits because it has storage.
    ReloptionSpec {
        name: "fillfactor",
        value: ReloptionValue::Int { min: 10, max: 100 },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_enabled",
        value: ReloptionValue::Bool,
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_threshold",
        value: ReloptionValue::Int {
            min: 0,
            max: INT_MAX,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_max_threshold",
        value: ReloptionValue::Int {
            min: -1,
            max: INT_MAX,
        },
        since: Some(EAGER_FREEZE_VERSION),
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_insert_threshold",
        value: ReloptionValue::Int {
            min: -1,
            max: INT_MAX,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_analyze_threshold",
        value: ReloptionValue::Int {
            min: 0,
            max: INT_MAX,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_cost_limit",
        value: ReloptionValue::Int {
            min: 1,
            max: 10_000,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_cost_delay",
        value: ReloptionValue::Real {
            min: 0.0,
            max: 100.0,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_scale_factor",
        value: ReloptionValue::Real {
            min: 0.0,
            max: 100.0,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_insert_scale_factor",
        value: ReloptionValue::Real {
            min: 0.0,
            max: 100.0,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_analyze_scale_factor",
        value: ReloptionValue::Real {
            min: 0.0,
            max: 100.0,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_freeze_min_age",
        value: ReloptionValue::Int {
            min: 0,
            max: 1_000_000_000,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_freeze_max_age",
        value: ReloptionValue::Int {
            min: 100_000,
            max: 2_000_000_000,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_freeze_table_age",
        value: ReloptionValue::Int {
            min: 0,
            max: 2_000_000_000,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_multixact_freeze_min_age",
        value: ReloptionValue::Int {
            min: 0,
            max: 1_000_000_000,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_multixact_freeze_max_age",
        value: ReloptionValue::Int {
            min: 10_000,
            max: 2_000_000_000,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "autovacuum_multixact_freeze_table_age",
        value: ReloptionValue::Int {
            min: 0,
            max: 2_000_000_000,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "log_autovacuum_min_duration",
        value: ReloptionValue::Int {
            min: -1,
            max: INT_MAX,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "vacuum_index_cleanup",
        value: ReloptionValue::Enum(VACUUM_INDEX_CLEANUP_VALUES),
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "vacuum_truncate",
        value: ReloptionValue::Ternary,
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "vacuum_max_eager_freeze_failure_rate",
        value: ReloptionValue::Real { min: 0.0, max: 1.0 },
        since: Some(EAGER_FREEZE_VERSION),
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "parallel_workers",
        value: ReloptionValue::Int { min: 0, max: 1024 },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "toast_tuple_target",
        value: ReloptionValue::Int {
            min: 128,
            max: 8160,
        },
        since: None,
        kinds: HEAP,
    },
    ReloptionSpec {
        name: "user_catalog_table",
        value: ReloptionValue::Bool,
        since: None,
        kinds: HEAP,
    },
];

/// The relation an option is being set on.
///
/// Declared once, in the mutation layer, so that a target cannot be expressed
/// two ways.
pub(crate) use crate::_internal::analysis::mutations::ReloptionTarget;

impl ReloptionTarget {
    const fn kinds(self) -> ReloptionKinds {
        match self {
            Self::View => VIEW,
            Self::MaterializedView => HEAP,
        }
    }
}

/// What can be concluded about one option of a statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReloptionOutcome {
    Accepted,
    /// The server rejects the name on this kind of relation.
    Unrecognized {
        name: String,
    },
    /// The name is right for this kind but its release cannot be placed.
    Unplaced,
    /// The name is right but the value is outside the option's domain.
    BadValue {
        name: String,
        value: String,
    },
}

/// Whether `value` is a `parse_bool` input.
pub(crate) fn parses_as_bool(value: &str) -> bool {
    crate::_internal::analysis::state::AnalysisState::reloption_parses_bool(value)
}

/// The `toast.` prefix PostgreSQL namespaces heap options under.
const TOAST_NAMESPACE: &str = "toast.";

/// Whether the option table holds `name`, whatever kind it belongs to.
///
/// An unrecognized name that is absent here is one this build does not model,
/// which is different from one a known version cannot place.
pub(crate) fn spec_by_name(name: &str) -> Option<&'static ReloptionSpec> {
    let lookup = name.strip_prefix(TOAST_NAMESPACE).unwrap_or(name);
    OPTIONS.iter().find(|spec| spec.name == lookup)
}

/// Resolve one option against a target and version.
pub(crate) fn evaluate(
    name: &str,
    value: Option<&str>,
    target: ReloptionTarget,
    version: PgVersion,
) -> ReloptionOutcome {
    let kinds = target.kinds();
    // A namespaced name must resolve to an option of that namespace's kind,
    // which is why a view can never carry `toast.` options.
    let (lookup_name, lookup_kinds) = match name.strip_prefix(TOAST_NAMESPACE) {
        Some(inner) => (inner, HEAP),
        None => (name, kinds),
    };
    let Some(spec) = OPTIONS
        .iter()
        .find(|spec| spec.name == lookup_name && spec.kinds == lookup_kinds)
    else {
        return ReloptionOutcome::Unrecognized {
            name: name.to_string(),
        };
    };
    if let Some(since) = spec.since {
        match version {
            PgVersion::Observed(found) | PgVersion::Assumed(found) if found >= since => {}
            PgVersion::Observed(_) | PgVersion::Assumed(_) => {
                return ReloptionOutcome::Unrecognized {
                    name: name.to_string(),
                };
            }
            PgVersion::Unresolved => return ReloptionOutcome::Unplaced,
        }
    }
    let Some(value) = value else {
        return ReloptionOutcome::Accepted;
    };
    let rejection = match spec.value {
        ReloptionValue::Bool | ReloptionValue::Ternary => {
            if parses_as_bool(value) {
                None
            } else {
                Some("boolean")
            }
        }
        ReloptionValue::Enum(members) => {
            if members
                .iter()
                .any(|member| member.eq_ignore_ascii_case(value.trim()))
            {
                None
            } else {
                Some("enum")
            }
        }
        ReloptionValue::Int { min, max } => match value.trim().parse::<i64>() {
            Ok(parsed) if (min..=max).contains(&parsed) => None,
            Ok(_) => Some("integer bounds"),
            Err(_) => Some("integer"),
        },
        ReloptionValue::Real { min, max } => match value.trim().parse::<f64>() {
            Ok(parsed) if parsed.is_finite() && (min..=max).contains(&parsed) => None,
            Ok(_) => Some("real bounds"),
            Err(_) => Some("real"),
        },
    };
    match rejection {
        None => ReloptionOutcome::Accepted,
        Some(kind) => ReloptionOutcome::BadValue {
            name: name.to_string(),
            value: format!("{value} is not a valid {kind}"),
        },
    }
}
