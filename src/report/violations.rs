// FILE: ./src/report/violations.rs

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum ViolationTier {
    Tier3, // Silent pass / Information
    Tier2, // Warning, Share Row Exclusive
    Tier1, // Halts build, Access Exclusive
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Violation {
    pub rule_id: &'static str,
    pub title: String,
    pub tier: ViolationTier,
    pub recipe: &'static str,
    pub dedup_key: Option<String>,
}
