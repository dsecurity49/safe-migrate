
#[cfg(test)]
mod tests {
    use crate::report::reporter::Reporter;
    use crate::report::violations::{Violation, ViolationTier};
    use crate::analysis::state::Confidence;

    #[test]
    fn test_reporter_print_empty() {
        let violations: Vec<Violation> = vec![];
        let confidence = Confidence::Exact;
        let has_failures = Reporter::print_report(&violations, &confidence);
        assert!(!has_failures);
    }

    #[test]
    fn test_reporter_print_violations() {
        let violations = vec![
            Violation {
                rule_id: "VolatileDefaultRule",
                tier: ViolationTier::Tier1,
                title: "Tier 1 violation title".to_string(),
                recipe: "recipe line 1\nrecipe line 2",
                dedup_key: None,
            },
            Violation {
                rule_id: "LockScaleRule",
                tier: ViolationTier::Tier2,
                title: "Tier 2 violation title".to_string(),
                recipe: "recipe detail",
                dedup_key: None,
            },
            Violation {
                rule_id: "SafeRule",
                tier: ViolationTier::Tier3,
                title: "Tier 3 violation title".to_string(),
                recipe: "safe recipe",
                dedup_key: None,
            },
        ];

        let confidence = Confidence::Tainted;
        let has_failures = Reporter::print_report(&violations, &confidence);
        assert!(has_failures);

        // Also call the JSON output function to cover that branch
        Reporter::print_json_report(&violations, &confidence);
    }
}
