use super::*;

impl AnalysisState {
    /// Adds conservative-analysis evidence and marks later chain state tainted.
    pub(crate) fn record_evidence(&mut self, mut record: EvidenceRecord) {
        if record.location.is_none() {
            record.location = self.local.current_evidence_location.clone();
        }
        if self.local.evidence.contains(&record) {
            return;
        }
        self.snapshot_evidence();
        if self.local.confidence != Confidence::Tainted {
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
        }
        self.local.evidence.insert(record);
    }

    pub(crate) fn taint(&mut self, code: EvidenceCode, scope: EvidenceScope) {
        self.record_evidence(EvidenceRecord::new(code, scope));
    }

    /// Record `code` and return the outcome carrying it, so the reported
    /// evidence and the rule-visible cause cannot disagree.
    pub(crate) fn unresolved(&mut self, code: EvidenceCode) -> MutationResult {
        self.taint(code, EvidenceScope::Chain);
        MutationResult::Unresolved(code)
    }

    /// `unresolved` for a cause that stays scoped to its own statement.
    pub(crate) fn unresolved_statement(&mut self, code: EvidenceCode) -> MutationResult {
        self.taint(code, EvidenceScope::Statement);
        MutationResult::Unresolved(code)
    }

    pub(crate) fn set_evidence_location(&mut self, location: Option<EvidenceLocation>) {
        self.local.current_evidence_location = location;
    }

    pub(crate) fn evidence(&self) -> &[EvidenceRecord] {
        self.local.evidence.records()
    }

    pub(crate) fn confidence(&self) -> &Confidence {
        &self.local.confidence
    }
}
