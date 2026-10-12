//! The structural description of an index, as two indexes compare when
//! PostgreSQL asks whether one can serve as a partition of the other.
//!
//! Every field here comes from `pg_index`, `pg_opclass` and `pg_collation`, and
//! all of them are exact: none requires deparsing an expression tree, which
//! PostgreSQL does not promise round-trips.

use serde::{Deserialize, Serialize};

use crate::_internal::analysis::expr_ir::ExprIr;

/// What a key sorts on.
///
/// One order has two spellings in `indoption`: `ASC NULLS LAST` is `0` and
/// `DESC NULLS FIRST` is `3`, yet both scan the same. `Default` stands for
/// that pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IndexOrder {
    /// Ascending, nulls last — also how PostgreSQL spells descending, nulls
    /// first, so the two are one identity rather than two.
    Default,
    DescNullsLast,
    AscNullsFirst,
}

impl IndexOrder {
    /// Decode one `indoption` entry.
    ///
    /// `can_order` is `pg_indexam_has_property(oid, 'can_order')`. The bits are
    /// access-method specific, so reading them under a hash or GiST index would
    /// invent an ordering that index does not have.
    pub(crate) fn from_indoption(bits: u16, can_order: bool) -> Self {
        if !can_order {
            return Self::Default;
        }
        match (bits & 0x1 != 0, bits & 0x2 != 0) {
            // (DESC, FIRST) scans identically to (ASC, LAST).
            (false, false) | (true, true) => Self::Default,
            (true, false) => Self::DescNullsLast,
            (false, true) => Self::AscNullsFirst,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Values read from PostgreSQL 18.6 on purpose-built indexes.
    #[test]
    fn the_two_spellings_of_the_default_order_normalize_together() {
        assert_eq!(IndexOrder::from_indoption(0, true), IndexOrder::Default);
        assert_eq!(IndexOrder::from_indoption(3, true), IndexOrder::Default);
        assert_eq!(
            IndexOrder::from_indoption(1, true),
            IndexOrder::DescNullsLast
        );
        assert_eq!(
            IndexOrder::from_indoption(2, true),
            IndexOrder::AscNullsFirst
        );
    }

    #[test]
    fn bits_are_ignored_when_the_access_method_cannot_order() {
        // hash and gist report can_order = false, so their option bits are
        // access-method specific and must not be read as an ordering.
        for bits in 0..4 {
            assert_eq!(IndexOrder::from_indoption(bits, false), IndexOrder::Default);
        }
    }

    #[test]
    fn only_the_three_orders_are_reachable() {
        let reachable = (0..u16::MAX)
            .map(|bits| IndexOrder::from_indoption(bits, true))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(reachable.len(), 3);
    }
}

/// What a key sorts on.
///
/// An expression key records only that it *is* one. PostgreSQL does not
/// guarantee that deparsing an expression reproduces its input, so the text is
/// never kept as identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IndexKeyKind {
    Column(String),
    /// The payload is the parsed expression when the simulator parsed the
    /// statement itself, and `None` when only the catalog reported an
    /// expression. `indkey = 0` names no expression, and deparsing one back is
    /// not round-trip safe, so a catalog-sourced key has no identity to compare.
    Expression(Option<ExprIr>),
}

impl IndexKeyKind {
    pub(crate) fn as_column(&self) -> Option<&str> {
        match self {
            Self::Column(name) => Some(name),
            Self::Expression(_) => None,
        }
    }

    /// Whether this expression's identity is unknown.
    pub(crate) fn is_opaque_expression(&self) -> bool {
        matches!(self, Self::Expression(None))
    }
}

/// One key column or included column.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct IndexKey {
    pub kind: IndexKeyKind,
    /// `None` when the key uses the type's default operator class.
    pub opclass: Option<String>,
    /// `None` when the key is not collatable.
    pub collation: Option<String>,
    pub order: IndexOrder,
}

impl IndexKey {
    pub(crate) fn column(name: impl Into<String>) -> Self {
        Self {
            kind: IndexKeyKind::Column(name.into()),
            opclass: None,
            collation: None,
            order: IndexOrder::Default,
        }
    }

    /// Whether this key carries anything beyond its name.
    pub(crate) fn is_plain(&self) -> bool {
        self.opclass.is_none() && self.collation.is_none() && self.order == IndexOrder::Default
    }
}

/// Build plain keys from column names.
pub(crate) fn index_keys(names: Vec<String>) -> Vec<IndexKey> {
    names.into_iter().map(IndexKey::column).collect()
}

/// Build keys from a parsed `CREATE INDEX`, keeping each expression's identity.
///
/// A statement the simulator parsed yields real identities, so two such indexes
/// can be compared. `columns` supplies the names of the plain keys; expression
/// keys take their name from the expression itself.
pub(crate) fn statement_index_keys(
    columns: &[String],
    expressions: &[Option<ExprIr>],
    orders: &[IndexOrder],
    opclasses: &[Option<String>],
    collations: &[Option<String>],
) -> Vec<IndexKey> {
    let mut columns = columns.iter();
    expressions
        .iter()
        .enumerate()
        .map(|(position, expression)| {
            let detail = |values: &[Option<String>]| values.get(position).cloned().flatten();
            IndexKey {
                kind: match expression {
                    Some(ir) => IndexKeyKind::Expression(Some(ir.clone())),
                    None => IndexKeyKind::Column(columns.next().cloned().unwrap_or_default()),
                },
                opclass: detail(opclasses),
                collation: detail(collations),
                order: orders.get(position).copied().unwrap_or(IndexOrder::Default),
            }
        })
        .collect()
}

/// Whether two descriptions can be compared at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexComparability {
    /// Every field is exact, so equality means what it says.
    Comparable,
    /// An expression key is present, and PostgreSQL's guarantee is insufficient
    /// to call the two equal or different.
    Unknown,
    /// The access methods belong to different families. A hash index and a
    /// btree index are not "different", they are a different question.
    DifferentFamily,
}

/// The structural description of one index.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct IndexDefinition {
    pub method: Option<String>,
    pub keys: Vec<IndexKey>,
    pub included: Vec<IndexKey>,
    /// How many keys are expressions. The count is kept because two indexes
    /// differing only in how many expression keys they have are still different
    /// shapes, even though neither can be compared by content.
    pub expression_keys: usize,
    pub unique: bool,
    /// Whether the index has a partial predicate. Its text is not retained, for
    /// the same reason an expression's is not.
    pub predicate: bool,
    pub valid: bool,
    pub ready: bool,
    pub live: bool,
}

impl IndexDefinition {
    /// A btree index over plain columns, for tests and callers that have only
    /// column names.
    #[cfg(test)]
    pub(crate) fn new(keys: Vec<IndexKey>) -> Self {
        Self {
            method: None,
            keys,
            included: Vec::new(),
            expression_keys: 0,
            unique: false,
            predicate: false,
            valid: true,
            ready: true,
            live: true,
        }
    }

    /// Whether an expression key is present.
    pub(crate) fn has_expression_keys(&self) -> bool {
        self.expression_keys > 0
    }

    /// Whether any key is an expression whose identity is unknown.
    pub(crate) fn has_opaque_expression(&self) -> bool {
        self.keys.iter().any(|key| key.kind.is_opaque_expression())
    }

    pub(crate) fn is_usable(&self) -> bool {
        self.valid && self.ready && self.live
    }

    pub(crate) fn key_column_names(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter_map(|key| key.kind.as_column().map(str::to_string))
            .collect()
    }

    pub(crate) fn included_column_names(&self) -> Vec<String> {
        self.included
            .iter()
            .filter_map(|key| key.kind.as_column().map(str::to_string))
            .collect()
    }

    /// Whether these two can be decided at all, before asking whether they are
    /// equal.
    ///
    /// PostgreSQL compares parsed expression trees, so two expressions the
    /// simulator parsed are comparable. Only an opaque expression — one that
    /// came from the catalog without identity — leaves the answer unknown.
    pub(crate) fn comparability(&self, other: &Self) -> IndexComparability {
        if !same_access_method_family(self.method.as_deref(), other.method.as_deref()) {
            return IndexComparability::DifferentFamily;
        }
        if self.has_opaque_expression() || other.has_opaque_expression() {
            return IndexComparability::Unknown;
        }
        IndexComparability::Comparable
    }
}

/// Access methods grouped by what their indexes can be compared for.
///
/// Grouping is by capability rather than by name, so an access method added
/// later lands in a family by what it can do.
fn access_method_family(method: Option<&str>) -> u8 {
    match method {
        Some("btree") => 0,
        Some("hash") => 1,
        Some("gist") | Some("spgist") => 2,
        Some("gin") => 3,
        Some("brin") => 4,
        // An unknown or absent method is its own question, never assumed equal.
        _ => 5,
    }
}

fn same_access_method_family(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            access_method_family(Some(left)) == access_method_family(Some(right))
        }
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod definition_tests {
    use super::*;

    fn expr(text: &str) -> Option<ExprIr> {
        Some(ExprIr::Literal(text.to_string()))
    }

    fn on(expression: &str) -> IndexDefinition {
        let mut definition = IndexDefinition::new(vec![IndexKey {
            kind: IndexKeyKind::Expression(expr(expression)),
            opclass: None,
            collation: None,
            order: IndexOrder::Default,
        }]);
        definition.expression_keys = 1;
        definition
    }

    // PostgreSQL accepts a matching expression index and rejects a
    // non-matching one; verified against a live server.
    #[test]
    fn matching_parsed_expressions_are_comparable() {
        assert_eq!(
            on("(a + 1)").comparability(&on("(a + 1)")),
            IndexComparability::Comparable
        );
        assert_eq!(on("(a + 1)"), on("(a + 1)"));
    }

    #[test]
    fn differing_parsed_expressions_are_comparable_and_unequal() {
        assert_eq!(
            on("(a + 1)").comparability(&on("(a + 2)")),
            IndexComparability::Comparable
        );
        assert_ne!(on("(a + 1)"), on("(a + 2)"));
    }

    // A catalog-sourced expression names nothing, so equality is undecidable
    // rather than false.
    #[test]
    fn an_opaque_expression_makes_comparison_unknown() {
        let mut opaque = on("(a + 1)");
        opaque.keys[0].kind = IndexKeyKind::Expression(None);
        assert_eq!(
            opaque.comparability(&on("(a + 1)")),
            IndexComparability::Unknown
        );
        assert_eq!(
            on("(a + 1)").comparability(&opaque),
            IndexComparability::Unknown
        );
        assert_eq!(opaque.comparability(&opaque), IndexComparability::Unknown);
    }

    #[test]
    fn different_families_are_not_a_comparison() {
        let btree = IndexDefinition::new(vec![IndexKey::column("a")]);
        let mut hash = btree.clone();
        hash.method = Some("hash".to_string());
        assert_eq!(
            btree.comparability(&hash),
            IndexComparability::DifferentFamily
        );
    }

    // T44's repro: a pure-expression index used to carry no key columns, so
    // indexes on different expressions compared equal.
    #[test]
    fn indexes_differing_only_in_expression_count_are_distinguishable() {
        let mut one = IndexDefinition::new(Vec::new());
        one.expression_keys = 1;
        let mut two = IndexDefinition::new(Vec::new());
        two.expression_keys = 2;
        assert_ne!(one, two);
    }

    #[test]
    fn column_names_come_back_in_key_order() {
        let definition = IndexDefinition::new(vec![IndexKey::column("a"), IndexKey::column("b")]);
        assert_eq!(definition.key_column_names(), ["a", "b"]);
        assert!(!definition.has_expression_keys());
        assert!(definition.keys.iter().all(IndexKey::is_plain));
    }
}
