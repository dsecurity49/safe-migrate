//! Built-in `pg_catalog` aggregate signatures, so a call can be matched against
//! the real overloads rather than the bare name.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One parameter of a built-in aggregate. A polymorphic parameter
/// (`anyelement`, `"any"`, `record`, ...) accepts whatever the call supplies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AggregateArg {
    Type(String),
    Any,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct AggregateCatalogue {
    signatures: BTreeMap<String, Vec<Vec<AggregateArg>>>,
}

impl AggregateCatalogue {
    pub(crate) fn new(entries: Vec<(String, Vec<AggregateArg>)>) -> Self {
        let mut signatures: BTreeMap<String, Vec<Vec<AggregateArg>>> = BTreeMap::new();
        for (name, signature) in entries {
            signatures.entry(name).or_default().push(signature);
        }
        Self { signatures }
    }

    /// The declared signatures of `name`, or `None` when the catalogue does not
    /// describe it.
    pub(crate) fn signatures(&self, name: &str) -> Option<&[Vec<AggregateArg>]> {
        self.signatures.get(name).map(Vec::as_slice)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    pub(crate) fn fallback() -> Self {
        super::aggregate_fallback::catalogue()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_group_by_name() {
        let catalogue = AggregateCatalogue::new(vec![
            (
                "sum".to_string(),
                vec![AggregateArg::Type("integer".to_string())],
            ),
            (
                "sum".to_string(),
                vec![AggregateArg::Type("bigint".to_string())],
            ),
        ]);
        assert_eq!(catalogue.signatures("sum").unwrap().len(), 2);
        assert!(catalogue.signatures("absent").is_none());
    }

    #[test]
    fn the_fallback_covers_the_common_aggregates() {
        let catalogue = AggregateCatalogue::fallback();
        assert!(!catalogue.is_empty());
        assert!(catalogue.signatures("sum").is_some());
        assert!(catalogue.signatures("count").is_some());
    }
}
