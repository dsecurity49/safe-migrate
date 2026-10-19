//! The structural description of an index, as two indexes compare when
//! PostgreSQL asks whether one can serve as a partition of the other.
//!
//! Every identity here comes from `pg_index`, `pg_opfamily` and
//! `pg_collation`; nothing requires deparsing an expression tree, which
//! PostgreSQL does not promise round-trips.

use serde::{Deserialize, Serialize};

use crate::_internal::analysis::expr_ir::ExprIr;

/// A catalog object's name, resolved to the schema it lives in.
///
/// Operator families and collations are compared by identity, and a bare name
/// is ambiguous across schemas.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct ResolvedName {
    pub schema: String,
    pub name: String,
}

/// A name as a statement wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WrittenName {
    /// The schema the statement qualified it with, when it did.
    pub schema: Option<String>,
    pub name: String,
}

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
}

/// The operator-class identity of one key.
///
/// PostgreSQL compares the resolved class by its operator family, so a class
/// is recorded as the family it belongs to. Whether a class was written only
/// survives for the default case, where the resolution of an omitted side is
/// the one thing the two sides cannot settle by name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KeyOpclass {
    /// No class was written, so PostgreSQL takes the access method's default
    /// class for the key's type. The family is carried when it could be
    /// established. An unestablished default still equals any default of the
    /// same key: partition-linked tables share their column definitions, so
    /// the same class is chosen on both sides.
    Default(Option<ResolvedName>),
    /// A written class, by the family it belongs to.
    Explicit(ResolvedName),
    /// A written class whose name does not resolve.
    Unresolved,
}

/// The collation identity of one key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KeyCollation {
    /// `indcollation = 0`: the key's type is not collatable.
    NotCollatable,
    /// The key takes its collation from its own definition — the column's
    /// collation for a column key, the expression's derivation for an
    /// expression key — and no separate name was written. Partition rules make
    /// the value agree between attached indexes, so the value itself is not
    /// needed to compare two of these.
    Derived,
    Resolved(ResolvedName),
    /// A written collation whose name does not resolve.
    Unresolved,
}

/// One key column or included column.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct IndexKey {
    pub kind: IndexKeyKind,
    pub opclass: KeyOpclass,
    pub collation: KeyCollation,
    /// Recorded for order-sensitive checks outside attachment. PostgreSQL
    /// never compares `indoption` when attaching, so attachment ignores it.
    pub order: IndexOrder,
}

impl IndexKey {
    pub(crate) fn column(name: impl Into<String>) -> Self {
        Self {
            kind: IndexKeyKind::Column(name.into()),
            opclass: KeyOpclass::Default(None),
            collation: KeyCollation::Derived,
            order: IndexOrder::Default,
        }
    }

    /// Whether this key carries anything beyond its name.
    pub(crate) fn is_plain(&self) -> bool {
        matches!(self.opclass, KeyOpclass::Default(_))
            && matches!(
                self.collation,
                KeyCollation::NotCollatable | KeyCollation::Derived
            )
            && self.order == IndexOrder::Default
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
/// keys take their identity from the expression itself.
pub(crate) fn statement_index_keys(
    columns: &[String],
    expressions: &[Option<ExprIr>],
    orders: &[IndexOrder],
    opclasses: &[KeyOpclass],
    collations: &[KeyCollation],
) -> Vec<IndexKey> {
    let mut columns = columns.iter();
    expressions
        .iter()
        .enumerate()
        .map(|(position, expression)| IndexKey {
            kind: match expression {
                Some(ir) => IndexKeyKind::Expression(Some(ir.clone())),
                None => IndexKeyKind::Column(columns.next().cloned().unwrap_or_default()),
            },
            opclass: opclasses
                .get(position)
                .cloned()
                .unwrap_or(KeyOpclass::Default(None)),
            collation: collations
                .get(position)
                .cloned()
                .unwrap_or(KeyCollation::Derived),
            order: orders.get(position).copied().unwrap_or(IndexOrder::Default),
        })
        .collect()
}

/// A partial index's predicate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IndexPredicate {
    None,
    /// Parsed from the statement, so its identity is available.
    Parsed(ExprIr),
    /// Present, but with no identity to compare: only the catalog stated it,
    /// and a deparse is not promised to reproduce the input.
    Opaque,
}

impl IndexPredicate {
    pub(crate) fn has_predicate(&self) -> bool {
        !matches!(self, Self::None)
    }
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
    /// `pg_index.indnullsnotdistinct`. `None` when the layout predates the
    /// column, so the value is not known rather than false.
    pub nulls_not_distinct: Option<bool>,
    pub predicate: IndexPredicate,
    /// Whether this description is a placeholder for an index PostgreSQL built
    /// from a constraint, whose real shape the model does not establish. No
    /// attachment decision may rest on such a description.
    pub unestablished: bool,
    pub valid: bool,
    pub ready: bool,
    pub live: bool,
}

/// The outcome of comparing two descriptions for attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexEquivalence {
    /// Nothing distinguishes them; PostgreSQL would attach them.
    Identical,
    /// A compared property differs; PostgreSQL would refuse.
    Different,
    /// A property cannot be established, so neither answer is claimed.
    Unknown,
}

impl IndexEquivalence {
    /// Fold one property's verdict into the running one, with a definite
    /// difference outranking an unknown, as PostgreSQL's checks do: it stops
    /// at the first definite inequality and never lets an unestablished
    /// property make two indexes look different.
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Different, _) | (_, Self::Different) => Self::Different,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Identical,
        }
    }

    fn from_equal(equal: bool) -> Self {
        if equal {
            Self::Identical
        } else {
            Self::Different
        }
    }
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
            nulls_not_distinct: Some(false),
            predicate: IndexPredicate::None,
            unestablished: false,
            valid: true,
            ready: true,
            live: true,
        }
    }

    /// Whether an expression key is present.
    pub(crate) fn has_expression_keys(&self) -> bool {
        self.expression_keys > 0
    }

    /// Whether a predicate is present. The dependency bookkeeping only needs
    /// presence; [`Self::attach_equivalence`] compares content.
    pub(crate) fn has_predicate(&self) -> bool {
        self.predicate.has_predicate()
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

    /// Whether PostgreSQL's `CompareIndexInfo` would hold between these two.
    ///
    /// The comparison covers what that function covers — uniqueness, NULLS NOT
    /// DISTINCT, the exact access method, the attribute count, the keys paired
    /// by name, each key's collation and operator family, expressions,
    /// predicates and the expression count — and deliberately not what it does
    /// not: sort order and lifecycle state. Only meaningful between indexes
    /// PostgreSQL would consider for the same attachment, where the two
    /// tables' column definitions are forced to agree; that is what lets an
    /// unestablished default class still match its resolved counterpart.
    ///
    /// A description whose shape is not established — a statement-created
    /// constraint backing — settles nothing, since its recorded fields are
    /// placeholders rather than facts.
    pub(crate) fn attach_equivalence(&self, other: &Self) -> IndexEquivalence {
        if self.unestablished || other.unestablished {
            return IndexEquivalence::Unknown;
        }
        let mut verdict = match (self.method.as_deref(), other.method.as_deref()) {
            (Some(left), Some(right)) => IndexEquivalence::from_equal(left == right),
            (None, None) => IndexEquivalence::Identical,
            _ => IndexEquivalence::Unknown,
        };
        verdict = verdict.and(IndexEquivalence::from_equal(self.unique == other.unique));
        verdict = verdict.and(
            match (
                self.nulls_not_distinct.as_ref(),
                other.nulls_not_distinct.as_ref(),
            ) {
                (Some(left), Some(right)) => IndexEquivalence::from_equal(left == right),
                _ => IndexEquivalence::Unknown,
            },
        );
        verdict = verdict.and(IndexEquivalence::from_equal(
            self.keys.len() == other.keys.len() && self.included.len() == other.included.len(),
        ));
        verdict = verdict.and(IndexEquivalence::from_equal(
            self.expression_keys == other.expression_keys,
        ));
        if verdict == IndexEquivalence::Different {
            return verdict;
        }
        if self.keys.len() == other.keys.len() {
            for (left, right) in self.keys.iter().zip(&other.keys) {
                verdict = verdict.and(compare_keys(left, right));
            }
        }
        if self.included.len() == other.included.len() {
            for (left, right) in self.included.iter().zip(&other.included) {
                verdict = verdict.and(compare_keys(left, right));
            }
        }
        verdict = verdict.and(match (&self.predicate, &other.predicate) {
            (IndexPredicate::None, IndexPredicate::None) => IndexEquivalence::Identical,
            (IndexPredicate::Parsed(left), IndexPredicate::Parsed(right)) => {
                IndexEquivalence::from_equal(left == right)
            }
            (IndexPredicate::None, _) | (_, IndexPredicate::None) => IndexEquivalence::Different,
            _ => IndexEquivalence::Unknown,
        });
        verdict
    }
}

fn compare_keys(left: &IndexKey, right: &IndexKey) -> IndexEquivalence {
    let kind = match (&left.kind, &right.kind) {
        (IndexKeyKind::Column(left), IndexKeyKind::Column(right)) => {
            IndexEquivalence::from_equal(left == right)
        }
        (IndexKeyKind::Expression(Some(left)), IndexKeyKind::Expression(Some(right))) => {
            IndexEquivalence::from_equal(left == right)
        }
        // An expression the catalog reported without identity. PostgreSQL
        // compares parsed trees; without one, neither equality nor difference
        // can be claimed.
        (IndexKeyKind::Expression(_), IndexKeyKind::Expression(_)) => IndexEquivalence::Unknown,
        _ => IndexEquivalence::Different,
    };
    kind.and(compare_opclasses(&left.opclass, &right.opclass))
        .and(compare_collations(&left.collation, &right.collation))
}

fn compare_opclasses(left: &KeyOpclass, right: &KeyOpclass) -> IndexEquivalence {
    fn names(left: &ResolvedName, right: &ResolvedName) -> IndexEquivalence {
        IndexEquivalence::from_equal(left == right)
    }
    match (left, right) {
        (KeyOpclass::Default(Some(left)), KeyOpclass::Default(Some(right)))
        | (KeyOpclass::Explicit(left), KeyOpclass::Explicit(right))
        | (KeyOpclass::Default(Some(left)), KeyOpclass::Explicit(right))
        | (KeyOpclass::Explicit(left), KeyOpclass::Default(Some(right))) => names(left, right),
        // Two omitted classes choose the same class, because the two tables'
        // column definitions are forced to agree.
        (KeyOpclass::Default(None), KeyOpclass::Default(_))
        | (KeyOpclass::Default(_), KeyOpclass::Default(None)) => IndexEquivalence::Identical,
        _ => IndexEquivalence::Unknown,
    }
}

fn compare_collations(left: &KeyCollation, right: &KeyCollation) -> IndexEquivalence {
    use KeyCollation::{Derived, NotCollatable, Resolved, Unresolved};
    match (left, right) {
        (NotCollatable | Derived, NotCollatable | Derived) => IndexEquivalence::Identical,
        (Resolved(left), Resolved(right)) => IndexEquivalence::from_equal(left == right),
        (Unresolved, _) | (_, Unresolved) => IndexEquivalence::Unknown,
        (NotCollatable, Resolved(_)) | (Resolved(_), NotCollatable) => IndexEquivalence::Different,
        (Derived, Resolved(_)) | (Resolved(_), Derived) => IndexEquivalence::Unknown,
    }
}

#[cfg(test)]
mod definition_tests {
    use super::*;

    fn expr(text: &str) -> Option<ExprIr> {
        Some(ExprIr::Literal(text.to_string()))
    }

    fn name(schema: &str, name: &str) -> ResolvedName {
        ResolvedName {
            schema: schema.to_string(),
            name: name.to_string(),
        }
    }

    fn on(expression: &str) -> IndexDefinition {
        let mut definition = IndexDefinition::new(vec![IndexKey {
            kind: IndexKeyKind::Expression(expr(expression)),
            opclass: KeyOpclass::Default(None),
            collation: KeyCollation::Derived,
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
            on("(a + 1)").attach_equivalence(&on("(a + 1)")),
            IndexEquivalence::Identical
        );
        assert_eq!(on("(a + 1)"), on("(a + 1)"));
    }

    #[test]
    fn differing_parsed_expressions_are_unequal() {
        assert_eq!(
            on("(a + 1)").attach_equivalence(&on("(a + 2)")),
            IndexEquivalence::Different
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
            opaque.attach_equivalence(&on("(a + 1)")),
            IndexEquivalence::Unknown
        );
        assert_eq!(
            on("(a + 1)").attach_equivalence(&opaque),
            IndexEquivalence::Unknown
        );
        assert_eq!(
            opaque.attach_equivalence(&opaque),
            IndexEquivalence::Unknown
        );
    }

    #[test]
    fn different_access_methods_are_unequal() {
        let btree = IndexDefinition::new(vec![IndexKey::column("a")]);
        let mut hash = btree.clone();
        hash.method = Some("hash".to_string());
        let mut btree = btree;
        btree.method = Some("btree".to_string());
        assert_eq!(btree.attach_equivalence(&hash), IndexEquivalence::Different);
    }

    #[test]
    fn an_absent_access_method_cannot_be_compared() {
        let unstated = IndexDefinition::new(vec![IndexKey::column("a")]);
        let mut btree = unstated.clone();
        btree.method = Some("btree".to_string());
        assert_eq!(
            unstated.attach_equivalence(&btree),
            IndexEquivalence::Unknown
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
        assert_eq!(one.attach_equivalence(&two), IndexEquivalence::Different);
    }

    #[test]
    fn sort_order_plays_no_part_in_attachment() {
        let mut ascending = IndexDefinition::new(vec![IndexKey::column("a")]);
        ascending.method = Some("btree".to_string());
        let mut descending = ascending.clone();
        descending.keys[0].order = IndexOrder::DescNullsLast;
        // PostgreSQL never compares indoption when attaching; verified live.
        assert_eq!(
            ascending.attach_equivalence(&descending),
            IndexEquivalence::Identical
        );
        // The structural identity still separates them.
        assert_ne!(ascending, descending);
    }

    #[test]
    fn a_null_treatment_mismatch_is_different() {
        let mut distinct = IndexDefinition::new(vec![IndexKey::column("a")]);
        distinct.method = Some("btree".to_string());
        let mut not_distinct = distinct.clone();
        not_distinct.nulls_not_distinct = Some(true);
        assert_eq!(
            distinct.attach_equivalence(&not_distinct),
            IndexEquivalence::Different
        );
        let mut unknown = distinct.clone();
        unknown.nulls_not_distinct = None;
        assert_eq!(
            distinct.attach_equivalence(&unknown),
            IndexEquivalence::Unknown
        );
    }

    #[test]
    fn an_unestablished_shape_settles_nothing() {
        let mut marker = IndexDefinition::new(vec![IndexKey::column("a")]);
        marker.unestablished = true;
        let mut real = marker.clone();
        real.unestablished = false;
        real.method = Some("btree".to_string());
        assert_eq!(marker.attach_equivalence(&real), IndexEquivalence::Unknown);
        assert_eq!(
            marker.attach_equivalence(&marker),
            IndexEquivalence::Unknown
        );
    }

    #[test]
    fn predicates_compare_by_identity() {
        let mut base = IndexDefinition::new(vec![IndexKey::column("a")]);
        base.method = Some("btree".to_string());
        let mut left = base.clone();
        left.predicate = IndexPredicate::Parsed(ExprIr::Literal("(a > 1)".to_string()));
        let mut right = base.clone();
        right.predicate = IndexPredicate::Parsed(ExprIr::Literal("(a > 2)".to_string()));
        assert_eq!(left.attach_equivalence(&left), IndexEquivalence::Identical);
        assert_eq!(left.attach_equivalence(&right), IndexEquivalence::Different);
        assert_eq!(left.attach_equivalence(&base), IndexEquivalence::Different);
        let mut opaque = base.clone();
        opaque.predicate = IndexPredicate::Opaque;
        assert_eq!(left.attach_equivalence(&opaque), IndexEquivalence::Unknown);
        assert_eq!(
            opaque.attach_equivalence(&opaque),
            IndexEquivalence::Unknown
        );
    }

    #[test]
    fn opclass_identity_is_the_operator_family() {
        let mut base = IndexDefinition::new(vec![IndexKey::column("a")]);
        base.method = Some("btree".to_string());
        // inet's default class and cidr_ops share the network_ops family, so
        // PostgreSQL attaches an index written either way; verified live.
        let mut default = base.clone();
        default.keys[0].opclass = KeyOpclass::Default(Some(name("pg_catalog", "network_ops")));
        let mut written = base.clone();
        written.keys[0].opclass = KeyOpclass::Explicit(name("pg_catalog", "network_ops"));
        assert_eq!(
            default.attach_equivalence(&written),
            IndexEquivalence::Identical
        );
        let mut other = base.clone();
        other.keys[0].opclass = KeyOpclass::Explicit(name("pg_catalog", "text_ops"));
        assert_eq!(
            default.attach_equivalence(&other),
            IndexEquivalence::Different
        );
        let mut unestablished = base.clone();
        unestablished.keys[0].opclass = KeyOpclass::Default(None);
        assert_eq!(
            unestablished.attach_equivalence(&default),
            IndexEquivalence::Identical
        );
        assert_eq!(
            unestablished.attach_equivalence(&other),
            IndexEquivalence::Unknown
        );
        let mut unresolved = base.clone();
        unresolved.keys[0].opclass = KeyOpclass::Unresolved;
        assert_eq!(
            unresolved.attach_equivalence(&default),
            IndexEquivalence::Unknown
        );
    }

    #[test]
    fn collation_identity_is_the_resolved_name() {
        let mut base = IndexDefinition::new(vec![IndexKey::column("a")]);
        base.method = Some("btree".to_string());
        let mut derived = base.clone();
        derived.keys[0].collation = KeyCollation::Derived;
        let mut resolved = base.clone();
        resolved.keys[0].collation = KeyCollation::Resolved(name("pg_catalog", "C"));
        assert_eq!(
            derived.attach_equivalence(&derived),
            IndexEquivalence::Identical
        );
        assert_eq!(
            derived.attach_equivalence(&resolved),
            IndexEquivalence::Unknown
        );
        let mut same = resolved.clone();
        same.keys[0].collation = KeyCollation::Resolved(name("pg_catalog", "C"));
        assert_eq!(
            resolved.attach_equivalence(&same),
            IndexEquivalence::Identical
        );
        let mut other = resolved.clone();
        other.keys[0].collation = KeyCollation::Resolved(name("pg_catalog", "default"));
        assert_eq!(
            resolved.attach_equivalence(&other),
            IndexEquivalence::Different
        );
        // A non-collatable column's key can never carry an explicit collation.
        let mut none = base.clone();
        none.keys[0].collation = KeyCollation::NotCollatable;
        assert_eq!(
            none.attach_equivalence(&derived),
            IndexEquivalence::Identical
        );
        assert_eq!(
            none.attach_equivalence(&resolved),
            IndexEquivalence::Different
        );
        let mut unresolved = base.clone();
        unresolved.keys[0].collation = KeyCollation::Unresolved;
        assert_eq!(
            unresolved.attach_equivalence(&none),
            IndexEquivalence::Unknown
        );
    }

    #[test]
    fn column_names_come_back_in_key_order() {
        let definition = IndexDefinition::new(vec![IndexKey::column("a"), IndexKey::column("b")]);
        assert_eq!(definition.key_column_names(), ["a", "b"]);
        assert!(!definition.has_expression_keys());
        assert!(definition.keys.iter().all(IndexKey::is_plain));
    }
}
