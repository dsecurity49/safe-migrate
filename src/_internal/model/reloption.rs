//! Which reloptions the analyzer recognises, per object kind and version.
//!
//! An unplaceable name is reported as unknown rather than invalid: the accepted
//! surface grows between releases, and a false conflict is worse than a stated
//! uncertainty.

/// What can be concluded about a reloption name, before a version is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloptionVerdict {
    /// Accepted on every supported version.
    Always,
    /// Accepted only from `introduced` onward, and rejected before it.
    Since(u32),
    /// Accepted only up to `removed`, and rejected from it onward.
    Until(u32),
    /// The analyzer cannot say.
    Unknown,
}

/// A verdict resolved against a concrete server version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloptionOutcome {
    Accepted,
    Rejected,
    Unknown,
}

/// PostgreSQL 15 replaced `security_definer` views with `security_invoker`.
const SECURITY_INVOKER_VERSION: u32 = 150_000;

/// Verdict for a reloption on a view. Views have no storage of their own, so
/// only the view-specific options and TOAST options are recognised.
pub(crate) fn view_reloption(name: &str) -> ReloptionVerdict {
    match name {
        "check_option" | "security_barrier" => ReloptionVerdict::Always,
        "security_invoker" => ReloptionVerdict::Since(SECURITY_INVOKER_VERSION),
        "security_definer" => ReloptionVerdict::Until(SECURITY_INVOKER_VERSION),
        _ => ReloptionVerdict::Unknown,
    }
}

/// Verdict for a reloption on a materialized view, which does have storage.
pub(crate) fn materialized_view_reloption(name: &str) -> ReloptionVerdict {
    match name {
        "fillfactor" | "autovacuum_enabled" | "toast.autovacuum_enabled" => {
            ReloptionVerdict::Always
        }
        _ => view_reloption(name),
    }
}

/// Resolve a verdict against a server version. An unknown version cannot
/// justify rejecting a name, so it is treated as unplaceable.
pub(crate) fn classify(verdict: ReloptionVerdict, pg_version_num: Option<u32>) -> ReloptionOutcome {
    match verdict {
        ReloptionVerdict::Always => ReloptionOutcome::Accepted,
        ReloptionVerdict::Unknown => ReloptionOutcome::Unknown,
        _ => match pg_version_num {
            Some(version) => match verdict {
                ReloptionVerdict::Since(v) if version >= v => ReloptionOutcome::Accepted,
                ReloptionVerdict::Until(v) if version < v => ReloptionOutcome::Accepted,
                _ => ReloptionOutcome::Rejected,
            },
            None => ReloptionOutcome::Unknown,
        },
    }
}
