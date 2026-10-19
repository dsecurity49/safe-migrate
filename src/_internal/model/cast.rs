//! PostgreSQL's implicit casts (`pg_cast.castcontext = 'i'`), which routine
//! resolution consults; `typcategory` is neither necessary nor sufficient.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Implicit casts among built-in types, keyed by `format_type` spelling.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CastCatalogue {
    implicit: BTreeMap<String, BTreeSet<String>>,
}

impl CastCatalogue {
    pub(crate) fn new(edges: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut implicit: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (source, target) in edges {
            implicit.entry(source).or_default().insert(target);
        }
        Self { implicit }
    }

    /// The generated static table, used only on the `--no-cache` path.
    pub(crate) fn fallback() -> Self {
        super::cast_fallback::catalogue()
    }

    /// Whether a value of type `from` coerces to `to` without an explicit cast.
    pub(crate) fn coerces_implicitly(&self, from: &str, to: &str) -> bool {
        from == to
            || self
                .implicit
                .get(from)
                .is_some_and(|targets| targets.contains(to))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalogue() -> CastCatalogue {
        CastCatalogue::new(
            [("integer", "bigint"), ("character varying", "text")]
                .into_iter()
                .map(|(source, target)| (source.to_string(), target.to_string())),
        )
    }

    #[test]
    fn a_recorded_cast_is_implicit() {
        let catalogue = catalogue();
        assert!(catalogue.coerces_implicitly("integer", "bigint"));
        assert!(catalogue.coerces_implicitly("character varying", "text"));
    }

    #[test]
    fn a_type_coerces_to_itself() {
        assert!(catalogue().coerces_implicitly("integer", "integer"));
    }

    #[test]
    fn an_unrecorded_cast_is_not_implicit() {
        let catalogue = catalogue();
        assert!(!catalogue.coerces_implicitly("bigint", "integer"));
        assert!(!catalogue.coerces_implicitly("integer", "text"));
    }
}
