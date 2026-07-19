#[cfg(test)]
mod tests {
    use crate::analysis::state::Confidence;
    use crate::report::reporter::{Reporter, Verdict, compute_verdict};
    use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};

    fn make_violation(rule_id: &'static str, tier: ViolationTier, reason: &str) -> Violation {
        Violation {
            source_range: None,
            rule_id,
            operation_kind: OperationKind::Other("test".to_string()),
            object_kind: ObjectKind::Unknown,
            object_name: "test.object".to_string(),
            tier,
            reason: reason.to_string(),
            recipe: "test recipe",
            dedup_key: None,
            sql: None,
            fk_dependency_related: false,
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
            make_violation(
                "VolatileDefaultRule",
                ViolationTier::Tier1,
                "Tier 1 violation",
            ),
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
            source_range: None,
            rule_id: "irreversible-migration",
            operation_kind: OperationKind::DropColumn,
            object_kind: ObjectKind::Table,
            object_name: "public.test".to_string(),
            tier: ViolationTier::Tier3,
            reason: "irreversible operation on empty table".to_string(),
            recipe: "ensure backups exist before deploying",
            dedup_key: None,
            sql: None,
            fk_dependency_related: false,
        }];
        assert_eq!(compute_verdict(&violations), Verdict::SafeWithRisk);
    }

    #[test]
    fn test_verdict_safe() {
        let violations = vec![make_violation(
            "test-rule",
            ViolationTier::Tier3,
            "safe info",
        )];
        assert_eq!(compute_verdict(&violations), Verdict::Safe);
    }

    #[test]
    fn test_verdict_empty() {
        let violations: Vec<Violation> = vec![];
        assert_eq!(compute_verdict(&violations), Verdict::Safe);
    }

    #[test]
    fn test_no_color_toggling() {
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
        let tier1_colored = crate::report::reporter::tier_label_colored(&ViolationTier::Tier1);
        assert_eq!(tier1_colored, "HALT");

        unsafe {
            std::env::remove_var("NO_COLOR");
        }
        let tier1_colored_style =
            crate::report::reporter::tier_label_colored(&ViolationTier::Tier1);
        assert!(tier1_colored_style.contains("HALT"));
        assert!(tier1_colored_style.contains("\x1b["));
    }

    #[test]
    fn test_inferred_schema_label() {
        use crate::DbCache;
        use crate::analysis::state::AnalysisState;
        use crate::ast::identifiers::{Ident, QualifiedName};

        let state = AnalysisState::new(DbCache::new());
        // Resolve relation ID without schema
        let name = QualifiedName::new(None, Ident::new("accounts", false));
        let resolved = state.resolve_relation_id(&name);
        assert!(resolved.inferred_schema);
        assert_eq!(resolved.to_string(), "public.accounts (inferred)");

        // Resolve relation ID with schema
        let name_with_schema = QualifiedName::new(
            Some(Ident::new("public", false)),
            Ident::new("accounts", false),
        );
        let resolved_with_schema = state.resolve_relation_id(&name_with_schema);
        assert!(!resolved_with_schema.inferred_schema);
        assert_eq!(resolved_with_schema.to_string(), "public.accounts");
    }

    #[test]
    fn test_reporter_clean_names() {
        let violations = vec![
            Violation {
                source_range: None,
                rule_id: "test-rule",
                operation_kind: OperationKind::Other("test".to_string()),
                object_kind: ObjectKind::Database,
                object_name: "public.production_db (inferred)".to_string(),
                tier: ViolationTier::Tier3,
                reason: "testing".to_string(),
                recipe: "recipe",
                dedup_key: None,
                sql: None,
                fk_dependency_related: false,
            },
            Violation {
                source_range: None,
                rule_id: "test-rule-unknown",
                operation_kind: OperationKind::Other("test".to_string()),
                object_kind: ObjectKind::Unknown,
                object_name: "<dynamic>".to_string(),
                tier: ViolationTier::Tier3,
                reason: "testing".to_string(),
                recipe: "recipe",
                dedup_key: None,
                sql: None,
                fk_dependency_related: false,
            },
        ];
        let confidence = Confidence::Exact;
        let has_failures = Reporter::print_report(&violations, &confidence);
        assert!(!has_failures);
    }
}
