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
/// overlap. `toast` is a separate axis: an option under the `toast.` namespace
/// is only valid when the relation has a TOAST table, and that table accepts a
/// strict subset of the heap set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReloptionKinds {
    pub heap: bool,
    pub view: bool,
    pub toast: bool,
    /// A column's `attoptions`, a set of its own.
    pub attribute: bool,
}

const HEAP: ReloptionKinds = ReloptionKinds {
    heap: true,
    view: false,
    toast: false,
    attribute: false,
};
/// A heap option the TOAST relation also accepts.
const HEAP_TOAST: ReloptionKinds = ReloptionKinds {
    heap: true,
    view: false,
    toast: true,
    attribute: false,
};
const VIEW: ReloptionKinds = ReloptionKinds {
    heap: false,
    view: true,
    toast: false,
    attribute: false,
};
const ATTRIBUTE: ReloptionKinds = ReloptionKinds {
    heap: false,
    view: false,
    toast: false,
    attribute: true,
};
/// A kind with no option parser, so no name is ever accepted for it.
const NONE: ReloptionKinds = ReloptionKinds {
    heap: false,
    view: false,
    toast: false,
    attribute: false,
};

impl ReloptionKinds {
    /// Whether an option belongs to the target's own option set, ignoring the
    /// toast axis.
    const fn applies_to(self, target: ReloptionKinds) -> bool {
        (self.heap && target.heap)
            || (self.view && target.view)
            || (self.attribute && target.attribute)
    }
}

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
// `auto`/`on`/`off` plus the boolean spellings an enum option also accepts.
const VACUUM_INDEX_CLEANUP_VALUES: &[&str] =
    &["auto", "on", "off", "true", "false", "yes", "no", "1", "0"];

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
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_threshold",
        value: ReloptionValue::Int {
            min: 0,
            max: INT_MAX,
        },
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_max_threshold",
        value: ReloptionValue::Int {
            min: -1,
            max: INT_MAX,
        },
        since: Some(EAGER_FREEZE_VERSION),
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_insert_threshold",
        value: ReloptionValue::Int {
            min: -1,
            max: INT_MAX,
        },
        since: None,
        kinds: HEAP_TOAST,
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
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_cost_delay",
        value: ReloptionValue::Real {
            min: 0.0,
            max: 100.0,
        },
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_scale_factor",
        value: ReloptionValue::Real {
            min: 0.0,
            max: 100.0,
        },
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_vacuum_insert_scale_factor",
        value: ReloptionValue::Real {
            min: 0.0,
            max: 100.0,
        },
        since: None,
        kinds: HEAP_TOAST,
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
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_freeze_max_age",
        value: ReloptionValue::Int {
            min: 100_000,
            max: 2_000_000_000,
        },
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_freeze_table_age",
        value: ReloptionValue::Int {
            min: 0,
            max: 2_000_000_000,
        },
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_multixact_freeze_min_age",
        value: ReloptionValue::Int {
            min: 0,
            max: 1_000_000_000,
        },
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_multixact_freeze_max_age",
        value: ReloptionValue::Int {
            min: 10_000,
            max: 2_000_000_000,
        },
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "autovacuum_multixact_freeze_table_age",
        value: ReloptionValue::Int {
            min: 0,
            max: 2_000_000_000,
        },
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "log_autovacuum_min_duration",
        value: ReloptionValue::Int {
            min: -1,
            max: INT_MAX,
        },
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "vacuum_index_cleanup",
        value: ReloptionValue::Enum(VACUUM_INDEX_CLEANUP_VALUES),
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "vacuum_truncate",
        value: ReloptionValue::Ternary,
        since: None,
        kinds: HEAP_TOAST,
    },
    ReloptionSpec {
        name: "vacuum_max_eager_freeze_failure_rate",
        value: ReloptionValue::Real { min: 0.0, max: 1.0 },
        since: Some(EAGER_FREEZE_VERSION),
        kinds: HEAP_TOAST,
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
    // Column options (`pg_attribute.attoptions`).
    ReloptionSpec {
        name: "n_distinct",
        value: ReloptionValue::Real {
            min: -1.0,
            max: f64::MAX,
        },
        since: None,
        kinds: ATTRIBUTE,
    },
    ReloptionSpec {
        name: "n_distinct_inherited",
        value: ReloptionValue::Real {
            min: -1.0,
            max: f64::MAX,
        },
        since: None,
        kinds: ATTRIBUTE,
    },
];

/// The relation an option is being set on.
///
/// Declared once, in the mutation layer, so that a target cannot be expressed
/// two ways.
pub(crate) use crate::_internal::analysis::mutations::ReloptionTarget;

/// The built-in index access methods, each with its own option parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexMethod {
    Btree,
    Hash,
    Gin,
    Gist,
    Spgist,
    Brin,
}

impl IndexMethod {
    /// The access method PostgreSQL names in `pg_am.amname`. Statements store
    /// it folded to upper case, the catalog keeps it lower case.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("btree") {
            Some(Self::Btree)
        } else if name.eq_ignore_ascii_case("hash") {
            Some(Self::Hash)
        } else if name.eq_ignore_ascii_case("gin") {
            Some(Self::Gin)
        } else if name.eq_ignore_ascii_case("gist") {
            Some(Self::Gist)
        } else if name.eq_ignore_ascii_case("spgist") {
            Some(Self::Spgist)
        } else if name.eq_ignore_ascii_case("brin") {
            Some(Self::Brin)
        } else {
            None
        }
    }
}

/// One option of an index access method.
struct IndexOptionSpec {
    name: &'static str,
    value: ReloptionValue,
    since: Option<u32>,
    methods: &'static [IndexMethod],
}

const BTREE_OPTIONS: &[IndexMethod] = &[IndexMethod::Btree];
const GIN_OPTIONS: &[IndexMethod] = &[IndexMethod::Gin];
const GIST_OPTIONS: &[IndexMethod] = &[IndexMethod::Gist];
const BRIN_OPTIONS: &[IndexMethod] = &[IndexMethod::Brin];
/// `fillfactor` is the one option several methods share, with the same bounds.
const FILLFACTOR_METHODS: &[IndexMethod] = &[
    IndexMethod::Btree,
    IndexMethod::Hash,
    IndexMethod::Gist,
    IndexMethod::Spgist,
];

/// PostgreSQL 13 added btree deduplication.
const DEDUPLICATE_ITEMS_VERSION: u32 = 130_000;

const INDEX_OPTIONS: &[IndexOptionSpec] = &[
    IndexOptionSpec {
        name: "fillfactor",
        value: ReloptionValue::Int { min: 10, max: 100 },
        since: None,
        methods: FILLFACTOR_METHODS,
    },
    IndexOptionSpec {
        name: "deduplicate_items",
        value: ReloptionValue::Bool,
        since: Some(DEDUPLICATE_ITEMS_VERSION),
        methods: BTREE_OPTIONS,
    },
    IndexOptionSpec {
        name: "vacuum_cleanup_index_scale_factor",
        value: ReloptionValue::Real {
            min: 0.0,
            max: 1e10,
        },
        since: None,
        methods: BTREE_OPTIONS,
    },
    IndexOptionSpec {
        name: "fastupdate",
        value: ReloptionValue::Bool,
        since: None,
        methods: GIN_OPTIONS,
    },
    IndexOptionSpec {
        name: "gin_pending_list_limit",
        value: ReloptionValue::Int {
            min: 64,
            max: INT_MAX,
        },
        since: None,
        methods: GIN_OPTIONS,
    },
    IndexOptionSpec {
        name: "buffering",
        value: ReloptionValue::Enum(&["auto", "on", "off"]),
        since: None,
        methods: GIST_OPTIONS,
    },
    IndexOptionSpec {
        name: "pages_per_range",
        value: ReloptionValue::Int {
            min: 1,
            max: 131_072,
        },
        since: None,
        methods: BRIN_OPTIONS,
    },
    IndexOptionSpec {
        name: "autosummarize",
        value: ReloptionValue::Bool,
        since: None,
        methods: BRIN_OPTIONS,
    },
];

impl ReloptionTarget {
    const fn kinds(self) -> ReloptionKinds {
        match self {
            Self::Table | Self::MaterializedView => HEAP,
            Self::View => VIEW,
            Self::PartitionedTable => NONE,
            Self::Column => ATTRIBUTE,
            // Index methods are matched against their own table in `evaluate`.
            Self::Index(_) => NONE,
        }
    }

    /// Whether PostgreSQL refuses every storage parameter on this kind, as it
    /// does for a partitioned table, rather than judging each name.
    pub(crate) const fn rejects_storage_parameters(self) -> bool {
        matches!(self, Self::PartitionedTable)
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

/// The namespace an option was written under. PostgreSQL accepts only the
/// `toast` namespace besides the default one, and it rejects any other in the
/// transform stage before the option parsers run, so `evaluate` never sees an
/// unknown namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloptionNamespace {
    /// No namespace: the ordinary option set for the target's kind.
    Main,
    /// The `toast.` namespace.
    Toast(ToastOptions),
}

/// Whether the target has a TOAST table, which decides if `toast.` options are
/// checked, silently dropped, or cannot be placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToastOptions {
    /// A TOAST table exists, so the option is validated against its set.
    Validated,
    /// No TOAST table, so PostgreSQL silently ignores the option.
    Ignored,
    /// The analyzer cannot tell whether a TOAST table exists.
    Unknown,
}

/// Whether `value` is a `parse_bool` input.
pub(crate) fn parses_as_bool(value: &str) -> bool {
    crate::_internal::analysis::state::AnalysisState::reloption_parses_bool(value)
}

/// The `toast.` prefix PostgreSQL namespaces heap options under.
const TOAST_NAMESPACE: &str = "toast.";

/// Whether either option table holds `name`, whatever kind or access method it
/// belongs to.
///
/// An unrecognized name that is absent here is one this build does not model,
/// which is different from one a known version cannot place.
pub(crate) fn is_known_option_name(name: &str) -> bool {
    let lookup = name.strip_prefix(TOAST_NAMESPACE).unwrap_or(name);
    OPTIONS.iter().any(|spec| spec.name == lookup)
        || INDEX_OPTIONS.iter().any(|spec| spec.name == lookup)
}

/// Resolve one option against a target, version, and namespace scope.
pub(crate) fn evaluate(
    name: &str,
    namespace: ReloptionNamespace,
    value: Option<&str>,
    target: ReloptionTarget,
    version: PgVersion,
) -> ReloptionOutcome {
    let unrecognized = || ReloptionOutcome::Unrecognized {
        name: name.to_string(),
    };
    match namespace {
        ReloptionNamespace::Main => match target {
            ReloptionTarget::Index(method) => match INDEX_OPTIONS
                .iter()
                .find(|spec| spec.name == name && spec.methods.contains(&method))
            {
                Some(spec) => check_option(name, value, spec.value, spec.since, version),
                None => unrecognized(),
            },
            _ => match OPTIONS
                .iter()
                .find(|spec| spec.name == name && spec.kinds.applies_to(target.kinds()))
            {
                Some(spec) => check_value(spec, name, value, version),
                None => unrecognized(),
            },
        },
        ReloptionNamespace::Toast(ToastOptions::Ignored) => ReloptionOutcome::Accepted,
        ReloptionNamespace::Toast(ToastOptions::Validated) => {
            match OPTIONS
                .iter()
                .find(|spec| spec.name == name && spec.kinds.toast)
            {
                Some(spec) => check_value(spec, name, value, version),
                None => unrecognized(),
            }
        }
        ReloptionNamespace::Toast(ToastOptions::Unknown) => {
            // Whether the option is checked at all hinges on a TOAST table the
            // analyzer cannot see, so only a cleanly accepted option is certain.
            match OPTIONS
                .iter()
                .find(|spec| spec.name == name && spec.kinds.toast)
            {
                Some(spec) => match check_value(spec, name, value, version) {
                    ReloptionOutcome::Accepted => ReloptionOutcome::Accepted,
                    _ => ReloptionOutcome::Unplaced,
                },
                None => ReloptionOutcome::Unplaced,
            }
        }
    }
}

/// Check a recognised option's release and value domain.
fn check_value(
    spec: &ReloptionSpec,
    name: &str,
    value: Option<&str>,
    version: PgVersion,
) -> ReloptionOutcome {
    check_option(name, value, spec.value, spec.since, version)
}

/// Check one option's release and the domain its value must fall in.
fn check_option(
    name: &str,
    value: Option<&str>,
    domain: ReloptionValue,
    since: Option<u32>,
    version: PgVersion,
) -> ReloptionOutcome {
    if let Some(since) = since {
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
    let rejection = match domain {
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
