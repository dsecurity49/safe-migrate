use serde::Serialize;

/// Stable, machine-readable causes for conservative analysis.
///
/// New variants are additive. Callers should use the serialized snake-case
/// value as the compatibility contract rather than matching display text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCode {
    BaselineUnavailable,
    BaselineStale,
    CatalogCoverageIncomplete,
    UnsupportedStatement,
    UnsupportedSemantics,
    UnresolvedReference,
    UnknownObjectState,
    TransactionStateUnknown,
    UnmodeledState,
}

impl EvidenceCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaselineUnavailable => "baseline_unavailable",
            Self::BaselineStale => "baseline_stale",
            Self::CatalogCoverageIncomplete => "catalog_coverage_incomplete",
            Self::UnsupportedStatement => "unsupported_statement",
            Self::UnsupportedSemantics => "unsupported_semantics",
            Self::UnresolvedReference => "unresolved_reference",
            Self::UnknownObjectState => "unknown_object_state",
            Self::TransactionStateUnknown => "transaction_state_unknown",
            Self::UnmodeledState => "unmodeled_state",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::BaselineUnavailable => "no synchronized baseline was available",
            Self::BaselineStale => "the synchronized baseline may be stale",
            Self::CatalogCoverageIncomplete => {
                "the synchronized catalog does not contain all required evidence"
            }
            Self::UnsupportedStatement => "the statement has no typed semantic model",
            Self::UnsupportedSemantics => "the statement contains unsupported semantics",
            Self::UnresolvedReference => "an object reference could not be resolved exactly",
            Self::UnknownObjectState => "the required object state is unknown",
            Self::TransactionStateUnknown => "transaction state cannot be modeled exactly",
            Self::UnmodeledState => {
                "required PostgreSQL state is deliberately outside the semantic model"
            }
        }
    }
}

/// Whether uncertainty affects only one transition or subsequent statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceScope {
    Statement,
    Chain,
}

/// Safe source context attached by the engine while it evaluates a statement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EvidenceLocation {
    pub file: String,
    pub statement_index: usize,
}

/// One durable reason why the analyzer had to be conservative.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EvidenceRecord {
    pub code: EvidenceCode,
    pub scope: EvidenceScope,
    pub summary: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<EvidenceLocation>,
}

impl EvidenceRecord {
    pub fn new(code: EvidenceCode, scope: EvidenceScope) -> Self {
        Self {
            code,
            scope,
            summary: code.summary(),
            location: None,
        }
    }

    pub fn at(mut self, location: EvidenceLocation) -> Self {
        self.location = Some(location);
        self
    }
}

/// Ordered, deduplicated evidence carried by analysis state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceLog {
    records: Vec<EvidenceRecord>,
}

impl EvidenceLog {
    pub fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }

    pub fn contains(&self, record: &EvidenceRecord) -> bool {
        self.records.contains(record)
    }

    /// Returns whether the record was newly inserted.
    pub fn insert(&mut self, record: EvidenceRecord) -> bool {
        if self.contains(&record) {
            return false;
        }
        self.records.push(record);
        self.records.sort();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_is_deduplicated_and_stably_ordered() {
        let mut log = EvidenceLog::default();
        let stale = EvidenceRecord::new(EvidenceCode::BaselineStale, EvidenceScope::Chain);
        let unsupported =
            EvidenceRecord::new(EvidenceCode::UnsupportedStatement, EvidenceScope::Statement).at(
                EvidenceLocation {
                    file: "001.sql".to_string(),
                    statement_index: 2,
                },
            );

        assert!(log.insert(unsupported.clone()));
        assert!(log.insert(stale.clone()));
        assert!(!log.insert(unsupported.clone()));
        assert_eq!(log.records(), &[stale, unsupported]);
    }
}
