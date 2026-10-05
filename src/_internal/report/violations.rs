use crate::_internal::analysis::evidence::{EvidenceRecord, EvidenceScope};
use crate::api::Certainty;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) enum ObjectKind {
    Table,
    Index,
    View,
    MaterializedView,
    Function,
    Procedure,
    Trigger,
    Sequence,
    Schema,
    Role,
    Publication,
    Subscription,
    Database,
    Domain,
    Policy,
    Type,
    Opaque,
    Unknown,
}

impl std::fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectKind::Table => write!(f, "table"),
            ObjectKind::Index => write!(f, "index"),
            ObjectKind::View => write!(f, "view"),
            ObjectKind::MaterializedView => write!(f, "materialized view"),
            ObjectKind::Function => write!(f, "function"),
            ObjectKind::Procedure => write!(f, "procedure"),
            ObjectKind::Trigger => write!(f, "trigger"),
            ObjectKind::Sequence => write!(f, "sequence"),
            ObjectKind::Schema => write!(f, "schema"),
            ObjectKind::Role => write!(f, "role"),
            ObjectKind::Publication => write!(f, "publication"),
            ObjectKind::Subscription => write!(f, "subscription"),
            ObjectKind::Database => write!(f, "database"),
            ObjectKind::Domain => write!(f, "domain"),
            ObjectKind::Policy => write!(f, "policy"),
            ObjectKind::Type => write!(f, "type"),
            ObjectKind::Opaque => write!(f, "opaque"),
            ObjectKind::Unknown => write!(f, "object"),
        }
    }
}

/// ViolationTier represents the severity of a finding.
/// Tier1 is declared first so `derive(Ord)` sorts it before Tier2 and Tier3.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub(crate) enum ViolationTier {
    Tier1, // HALT — Access Exclusive / data-destructive, sorts first
    Tier2, // WARN — Share Row Exclusive / cautious
    Tier3, // SAFE — informational / low risk, sorts last
}

fn certainty_is_exact(&c: &Certainty) -> bool {
    c.is_exact()
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct Violation {
    #[serde(skip)]
    pub source_range: Option<rowan::TextRange>,
    pub rule_id: &'static str,
    pub object_kind: ObjectKind,
    pub object_name: String,
    pub tier: ViolationTier,
    pub reason: String,
    pub recipe: &'static str,
    /// Internal warning-grouping hint. Never part of the report contract.
    #[serde(skip)]
    pub dedup_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
}

/// Stable source location attached at reporting time. Rules remain independent
/// of file layout; the engine derives this from the parsed statement range.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

/// A rule that could not state a finding for want of evidence. Reported apart
/// from findings, because nothing is wrong with the migration.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct NotEvaluated {
    pub rule_id: &'static str,
    pub tier: ViolationTier,
    pub cause: crate::_internal::analysis::evidence::EvidenceCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    /// What would make this rule evaluable.
    pub recipe: String,
    /// Out-of-scope schemas the boundary query actually observed, so the
    /// remedy can name them instead of asking the reader to find them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_schemas: Vec<String>,
}

impl NotEvaluated {
    /// The command or setting that would supply the missing evidence.
    pub(crate) fn recipe_for(
        cause: crate::_internal::analysis::evidence::EvidenceCode,
        missing_schemas: &[String],
    ) -> String {
        use crate::_internal::analysis::evidence::EvidenceCode;
        match cause {
            EvidenceCode::BaselineUnavailable => {
                "Run `safe-migrate sync` to build a baseline.".to_string()
            }
            EvidenceCode::CatalogCoverageIncomplete if !missing_schemas.is_empty() => {
                format!(
                    "Add {} to `schemas` in safe-migrate.toml, then re-sync.",
                    quote_schema_list(missing_schemas)
                )
            }
            EvidenceCode::CatalogCoverageIncomplete => {
                "Add the referenced schema to `schemas` in safe-migrate.toml, then re-sync."
                    .to_string()
            }
            EvidenceCode::UnsupportedStatement | EvidenceCode::UnsupportedSemantics => {
                "This statement has no semantic model yet; no configuration resolves it."
                    .to_string()
            }
            EvidenceCode::UnmodeledState => {
                "This PostgreSQL state is deliberately outside the model.".to_string()
            }
            EvidenceCode::BaselineStale => {
                "Run `safe-migrate sync` to refresh the stale baseline.".to_string()
            }
            EvidenceCode::UnresolvedReference => {
                "Widen the baseline scope to include the referenced object, then re-sync."
                    .to_string()
            }
            EvidenceCode::UnknownObjectState | EvidenceCode::TransactionStateUnknown => {
                "Re-run `safe-migrate sync` with a wider schema scope so the object state is known, then re-run the analysis."
                    .to_string()
            }
        }
    }
}

/// Render schema names as a readable list, quoting any that need it.
fn quote_schema_list(schemas: &[String]) -> String {
    let rendered: Vec<String> = schemas
        .iter()
        .map(|schema| {
            let needs_quotes = schema.is_empty()
                || !schema
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                || schema.chars().next().is_some_and(|c| c.is_ascii_digit());
            if needs_quotes {
                format!("\"{}\"", schema.replace('"', "\"\""))
            } else {
                schema.clone()
            }
        })
        .collect();
    match rendered.as_slice() {
        [] => String::new(),
        [only] => only.clone(),
        [first, second] => format!("{first} and {second}"),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// A violation paired with the file and line that produced it. The flattened
/// serialization keeps the JSON violation schema additive.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ReportFinding {
    #[serde(flatten)]
    pub violation: Violation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
    /// One-based statement position within the source file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_index: Option<usize>,
    /// Certainty is independent of `violation.tier`: severity describes the
    /// operation, certainty describes the evidence behind it.
    #[serde(skip_serializing_if = "certainty_is_exact")]
    pub certainty: Certainty,
}

/// Certainty of a finding produced at `statement_index` of `file_index`.
///
/// Chain evidence taints later statements, never earlier ones nor its own.
/// Statement evidence taints only its own statement. Anything unplaceable on
/// either side taints conservatively.
pub(crate) fn certainty_for_statement(
    evidence: &[EvidenceRecord],
    file_order: &[String],
    file_index: usize,
    statement_index: Option<usize>,
    asserted_inputs: bool,
) -> Certainty {
    let here = statement_index.map(|index| (file_index, index));
    let mut unattributed_statement_evidence = false;

    for record in evidence {
        let at = record_position(record, file_order);
        match record.scope {
            EvidenceScope::Chain => match (at, here) {
                (Some(at), Some(here)) if at >= here => {}
                _ => return Certainty::Tainted,
            },
            EvidenceScope::Statement => match (at, here) {
                (Some(at), Some(here)) if at == here => return Certainty::Tainted,
                (Some(_), Some(_)) => {}
                _ => unattributed_statement_evidence = true,
            },
        }
    }

    if unattributed_statement_evidence {
        return Certainty::Tainted;
    }
    if asserted_inputs {
        return Certainty::Assumed;
    }
    Certainty::Exact
}

fn record_position(record: &EvidenceRecord, file_order: &[String]) -> Option<(usize, usize)> {
    let location = record.location.as_ref()?;
    let file_index = file_order.iter().position(|name| name == &location.file)?;
    Some((file_index, location.statement_index))
}
