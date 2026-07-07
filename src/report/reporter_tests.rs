
#[cfg(test)]
mod tests {
    use crate::analysis::state::Confidence;
    use crate::report::reporter::{compute_verdict, Reporter, Verdict};
    use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};

    fn make_violation(rule_id: &'static str, tier: ViolationTier, reason: &str) -> Violation {
        Violation {
            rule_id,
            operation_kind: OperationKind::Other("test".to_string()),
            object_kind: ObjectKind::Unknown,
            object_name: "test.object".to_string(),
            tier,
            reason: reason.to_string(),
            recipe: "test recipe",
            dedup_key: None,
            sql: None,
        }
    }

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
            make_violation("VolatileDefaultRule", ViolationTier::Tier1, "Tier 1 violation"),
            make_violation("LockScaleRule", ViolationTier::Tier2, "Tier 2 violation"),
            make_violation("SafeRule", ViolationTier::Tier3, "Tier 3 violation"),
        ];

        let confidence = Confidence::Tainted;
        let has_failures = Reporter::print_report(&violations, &confidence);
        assert!(has_failures);

        // Also call the JSON output function to cover that branch
        Reporter::print_json_report(&violations, &confidence);
    }

    #[test]
    fn test_verdict_halt_tier1() {
        let violations = vec![make_violation("test-rule", ViolationTier::Tier1, "halt")];
        assert_eq!(compute_verdict(&violations), Verdict::Halt);
    }

    #[test]
    fn test_verdict_cautious_tier2() {
        let violations = vec![
            make_violation("test-rule", ViolationTier::Tier2, "warn"),
            make_violation("test-rule", ViolationTier::Tier3, "safe"),
        ];
        assert_eq!(compute_verdict(&violations), Verdict::Cautious);
    }

    #[test]
    fn test_verdict_safe_with_risk() {
        let violations = vec![Violation {
            rule_id: "irreversible-migration",
            operation_kind: OperationKind::DropColumn,
            object_kind: ObjectKind::Table,
            object_name: "public.test".to_string(),
            tier: ViolationTier::Tier3,
            reason: "irreversible operation on empty table".to_string(),
            recipe: "ensure backups exist before deploying",
            dedup_key: None,
            sql: None,
        }];
        assert_eq!(compute_verdict(&violations), Verdict::SafeWithRisk);
    }

    #[test]
    fn test_verdict_safe() {
        let violations = vec![make_violation("test-rule", ViolationTier::Tier3, "safe info")];
        assert_eq!(compute_verdict(&violations), Verdict::Safe);
    }

    #[test]
    fn test_verdict_empty() {
        let violations: Vec<Violation> = vec![];
        assert_eq!(compute_verdict(&violations), Verdict::Safe);
    }
}
