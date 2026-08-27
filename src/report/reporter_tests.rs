#[cfg(test)]
mod tests {
    use crate::analysis::state::Confidence;
    use crate::report::reporter::{Reporter, Verdict, compute_verdict};
    use crate::report::violations::{
        ObjectKind, OperationKind, ReportFinding, SourceLocation, Violation, ViolationTier,
    };

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

        let report = Reporter::json_report(&violations, &confidence);
        assert_eq!(report["schema_version"], Reporter::JSON_SCHEMA_VERSION);
        assert_eq!(report["confidence"], "Tainted");
        assert_eq!(report["verdict"], "HALT");
        assert_eq!(report["summary"]["total"], 3);
        assert_eq!(report["summary"]["tier1"], 1);
        assert_eq!(report["summary"]["tier2"], 1);
        assert_eq!(report["summary"]["tier3"], 1);
        assert_eq!(report["violations"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_markdown_report_includes_the_same_finding_and_location_data() {
        let finding = ReportFinding {
            violation: make_violation("test-rule", ViolationTier::Tier2, "needs review"),
            location: Some(SourceLocation {
                file: "migrations/001.sql".to_string(),
                line: 3,
                column: 5,
            }),
            statement_index: Some(1),
        };

        let markdown = Reporter::markdown_report(&[finding], &Confidence::Exact);
        assert!(markdown.starts_with("# safe-migrate report\n"));
        assert!(markdown.contains("**Verdict:** CAUTIOUS"));
        assert!(markdown.contains("### WARN — test-rule (`test-rule`)"));
        assert!(markdown.contains("`migrations/001.sql:3:5`"));
        assert!(markdown.contains("**Statement:** 1"));
        assert!(markdown.contains("needs review"));
    }

    #[test]
    fn location_aware_json_adds_registry_metadata_without_changing_schema_version() {
        let finding = ReportFinding {
            violation: make_violation(
                "require-concurrent-index",
                ViolationTier::Tier1,
                "index requires a safer strategy",
            ),
            location: None,
            statement_index: Some(1),
        };

        let report = Reporter::json_report_with_locations(&[finding], &Confidence::Exact);
        assert_eq!(report["schema_version"], Reporter::JSON_SCHEMA_VERSION);
        assert_eq!(
            report["violations"][0]["rule_title"],
            "Require concurrent index"
        );
        assert_eq!(report["violations"][0]["impact"], "locking");
        assert_eq!(report["violations"][0]["statement_index"], 1);
        assert!(report["violations"][0]["rule_summary"].is_string());
    }

    #[test]
    fn representative_reports_match_complete_goldens() {
        let finding = ReportFinding {
            violation: make_violation("test-rule", ViolationTier::Tier2, "needs review"),
            location: Some(SourceLocation {
                file: "migrations/001.sql".to_string(),
                line: 3,
                column: 5,
            }),
            statement_index: Some(1),
        };

        let json = Reporter::json_report_with_locations(
            std::slice::from_ref(&finding),
            &Confidence::Exact,
        );
        assert_eq!(
            json,
            serde_json::json!({
                "schema_version": 1,
                "confidence": "Exact",
                "verdict": "CAUTIOUS",
                "summary": {"total": 1, "tier1": 0, "tier2": 1, "tier3": 0},
                "violations": [{
                    "rule_id": "test-rule",
                    "operation_kind": {"Other": "test"},
                    "object_kind": "Unknown",
                    "object_name": "test.object",
                    "tier": "Tier2",
                    "reason": "needs review",
                    "recipe": "test recipe",
                    "dedup_key": null,
                    "sql": null,
                    "fk_dependency_related": false,
                    "location": {
                        "file": "migrations/001.sql",
                        "line": 3,
                        "column": 5
                    },
                    "statement_index": 1
                }]
            })
        );

        let markdown = Reporter::markdown_report(&[finding], &Confidence::Exact);
        assert_eq!(
            markdown,
            "# safe-migrate report\n\n\
**Verdict:** CAUTIOUS  \n\
**Confidence:** Exact\n\n\
| Severity | Findings |\n\
| --- | ---: |\n\
| HALT (Tier 1) | 0 |\n\
| WARN (Tier 2) | 1 |\n\
| SAFE (Tier 3) | 0 |\n\n\
## Findings\n\n\
### WARN — test-rule (`test-rule`)\n\n\
**Location:** `migrations/001.sql:3:5`  \n\
**Statement:** 1  \n\
**Object:** object test.object  \n\
**Reason:** needs review  \n\
**Recommendation:** test recipe\n"
        );
    }

    #[test]
    fn markdown_report_uses_a_safe_fence_for_sql_containing_backticks() {
        let finding = ReportFinding {
            location: None,
            statement_index: None,
            violation: Violation {
                source_range: None,
                rule_id: "test-rule",
                operation_kind: OperationKind::Other("test".to_string()),
                object_kind: ObjectKind::Table,
                object_name: "example".to_string(),
                tier: ViolationTier::Tier2,
                reason: "needs review".to_string(),
                recipe: "review it",
                dedup_key: None,
                sql: Some("SELECT '```';".to_string()),
                fk_dependency_related: false,
            },
        };

        let markdown = Reporter::markdown_report(&[finding], &Confidence::Exact);
        assert!(markdown.contains("\n````sql\nSELECT '```';\n````\n"));
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
    fn test_tainted_safe_verdict_requires_review() {
        assert_eq!(
            Verdict::Safe.recommendation(&Confidence::Tainted),
            "no blocking finding, but baseline evidence is uncertain — review before deploying"
        );
    }

    #[test]
    fn test_tainted_safe_with_risk_keeps_backup_guidance() {
        assert_eq!(
            Verdict::SafeWithRisk.recommendation(&Confidence::Tainted),
            "irreversible operations present and baseline evidence is uncertain — ensure backups exist and review before deploying"
        );
    }

    #[test]
    fn test_exact_safe_verdict_does_not_guarantee_deployment() {
        let recommendation = Verdict::Safe.recommendation(&Confidence::Exact);
        assert_eq!(recommendation, "no modeled blocking findings");
        assert!(!recommendation.contains("safe to deploy"));
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
