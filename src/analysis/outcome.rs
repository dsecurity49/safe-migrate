use crate::analysis::evidence::EvidenceRecord;
use crate::analysis::state::Confidence;

/// Immutable result of an analysis run.
#[derive(Debug, Clone)]
pub struct AnalysisOutcome<T> {
    pub findings: Vec<T>,
    pub confidence: Confidence,
    pub evidence: Vec<EvidenceRecord>,
}

impl<T> AnalysisOutcome<T> {
    pub fn new(findings: Vec<T>, confidence: Confidence, evidence: Vec<EvidenceRecord>) -> Self {
        Self {
            findings,
            confidence,
            evidence,
        }
    }

    /// Attach chain-level evidence after analysis without mutating the state
    /// machine that produced the findings. This is used for invocation facts
    /// such as a missing or stale baseline, which must taint the verdict but
    /// must not downgrade the severity of the SQL being analyzed.
    pub fn with_evidence(mut self, record: EvidenceRecord) -> Self {
        if !self.evidence.contains(&record) {
            self.evidence.push(record);
            self.evidence.sort();
        }
        self.confidence = Confidence::Tainted;
        self
    }
}
