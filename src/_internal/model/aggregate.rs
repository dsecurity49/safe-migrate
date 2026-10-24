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

/// `pg_aggregate.aggkind`: how PostgreSQL reads the aggregate's input list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AggregateKind {
    #[default]
    Normal,
    OrderedSet,
    Hypothetical,
}

impl AggregateKind {
    pub(crate) fn from_catalog(value: &str) -> Option<Self> {
        match value {
            "n" => Some(Self::Normal),
            "o" => Some(Self::OrderedSet),
            "h" => Some(Self::Hypothetical),
            _ => None,
        }
    }

    pub(crate) fn takes_within_group(self) -> bool {
        self != Self::Normal
    }
}

/// The `pg_aggregate` facts a routine carries when it is an aggregate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AggregateMetadata {
    pub kind: AggregateKind,
    pub direct_count: usize,
}

impl AggregateMetadata {
    pub(crate) fn new(kind: AggregateKind, direct_count: usize) -> Self {
        Self { kind, direct_count }
    }

    #[cfg(test)]
    pub(crate) fn normal(direct_count: usize) -> Self {
        Self::new(AggregateKind::Normal, direct_count)
    }
}

/// One `pg_proc` overload of an aggregate. `arguments` holds every input
/// parameter; the first `direct_count` are ordinary call arguments and the rest
/// are the `ORDER BY` inputs of an ordered-set or hypothetical aggregate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AggregateSignature {
    pub kind: AggregateKind,
    pub direct_count: usize,
    pub arguments: Vec<AggregateArg>,
}

impl AggregateSignature {
    #[cfg(test)]
    pub(crate) fn normal(arguments: Vec<AggregateArg>) -> Self {
        Self {
            kind: AggregateKind::Normal,
            direct_count: arguments.len(),
            arguments,
        }
    }

    pub(crate) fn new(
        kind: AggregateKind,
        direct_count: usize,
        arguments: Vec<AggregateArg>,
    ) -> Self {
        let direct_count = match kind {
            AggregateKind::Normal => arguments.len(),
            AggregateKind::OrderedSet | AggregateKind::Hypothetical => direct_count,
        };
        debug_assert!(direct_count <= arguments.len());
        Self {
            kind,
            direct_count,
            arguments,
        }
    }

    #[cfg(test)]
    pub(crate) fn ordered_arguments(&self) -> &[AggregateArg] {
        &self.arguments[self.direct_count.min(self.arguments.len())..]
    }

    /// A hypothetical aggregate written as `VARIADIC "any"` stores one
    /// polymorphic parameter for both the direct and the ordered list. Its
    /// direct and ordered counts must agree instead of using `direct_count`.
    pub(crate) fn is_variadic_hypothetical(&self) -> bool {
        self.kind == AggregateKind::Hypothetical
            && self.arguments.len() == self.direct_count
            && matches!(self.arguments.last(), Some(AggregateArg::Any))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct AggregateCatalogue {
    signatures: BTreeMap<String, Vec<AggregateSignature>>,
}

impl AggregateCatalogue {
    pub(crate) fn new(entries: Vec<(String, AggregateSignature)>) -> Self {
        let mut signatures: BTreeMap<String, Vec<AggregateSignature>> = BTreeMap::new();
        for (name, signature) in entries {
            signatures.entry(name).or_default().push(signature);
        }
        Self { signatures }
    }

    /// The declared signatures of `name`, or `None` when the catalogue does not
    /// describe it.
    pub(crate) fn signatures(&self, name: &str) -> Option<&[AggregateSignature]> {
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
                AggregateSignature::normal(vec![AggregateArg::Type("integer".to_string())]),
            ),
            (
                "sum".to_string(),
                AggregateSignature::normal(vec![AggregateArg::Type("bigint".to_string())]),
            ),
        ]);
        assert_eq!(catalogue.signatures("sum").unwrap().len(), 2);
        assert!(catalogue.signatures("absent").is_none());
    }

    #[test]
    fn ordered_set_signatures_split_direct_and_ordered_arguments() {
        let signature = AggregateSignature::new(
            AggregateKind::OrderedSet,
            1,
            vec![
                AggregateArg::Type("double precision".to_string()),
                AggregateArg::Type("interval".to_string()),
            ],
        );
        assert_eq!(
            signature.arguments[..signature.direct_count],
            [AggregateArg::Type("double precision".to_string())]
        );
        assert_eq!(
            signature.ordered_arguments(),
            [AggregateArg::Type("interval".to_string())]
        );
    }

    #[test]
    fn the_fallback_covers_the_common_aggregates() {
        let catalogue = AggregateCatalogue::fallback();
        assert!(!catalogue.is_empty());
        assert!(catalogue.signatures("sum").is_some());
        assert!(catalogue.signatures("count").is_some());
        let percentile = catalogue
            .signatures("percentile_cont")
            .expect("ordered-set aggregate");
        assert!(percentile.iter().all(|signature| {
            signature.kind == AggregateKind::OrderedSet
                && signature.direct_count == 1
                && signature.arguments.len() == 2
        }));
        let rank = catalogue
            .signatures("rank")
            .expect("hypothetical aggregate");
        assert!(
            rank.iter()
                .all(AggregateSignature::is_variadic_hypothetical)
        );
    }
}
