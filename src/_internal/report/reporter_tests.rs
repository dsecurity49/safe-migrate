#[cfg(test)]
mod tests {
    use crate::_internal::analysis::evidence::{
        EvidenceCode, EvidenceLocation, EvidenceRecord, EvidenceScope,
    };
    use crate::_internal::analysis::outcome::AnalysisOutcome;
    use crate::_internal::analysis::state::Confidence;
    use crate::_internal::report::reporter::{Reporter, Verdict, compute_verdict};
    use crate::_internal::report::violations::{
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

        let markdown =
            Reporter::markdown_report(std::slice::from_ref(&finding), &Confidence::Exact);
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
    fn outcome_reports_include_structured_evidence() {
        let finding = ReportFinding {
            violation: make_violation("test-rule", ViolationTier::Tier2, "needs review"),
            location: None,
            statement_index: Some(1),
        };
        let outcome = AnalysisOutcome::new(
            vec![finding],
            Confidence::Tainted,
            vec![
                EvidenceRecord::new(EvidenceCode::UnsupportedStatement, EvidenceScope::Chain).at(
                    EvidenceLocation {
                        file: "migrations/001.sql".to_string(),
                        statement_index: 1,
                    },
                ),
            ],
        );

        let json = Reporter::json_outcome_with_locations(&outcome);
        assert_eq!(json["schema_version"], 2);
        assert_eq!(json["evidence"][0]["code"], "unsupported_statement");
        assert_eq!(json["evidence"][0]["location"]["statement_index"], 1);

        let markdown = Reporter::markdown_outcome(&outcome);
        assert!(markdown.contains("## Analysis evidence"));
        assert!(markdown.contains("`unsupported_statement`"));
        assert!(markdown.contains("migrations/001.sql"));
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
        let expected_json: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/golden/representative-report.json"
        ))
        .expect("JSON golden must be valid");
        assert_eq!(json, expected_json);

        let markdown =
            Reporter::markdown_report(std::slice::from_ref(&finding), &Confidence::Exact);
        assert_eq!(
            markdown,
            include_str!("../../../tests/golden/representative-report.md")
        );

        let canonical_json = serde_json::to_string_pretty(&json).expect("serialize report");
        for _ in 0..32 {
            assert_eq!(
                serde_json::to_string_pretty(&Reporter::json_report_with_locations(
                    std::slice::from_ref(&finding),
                    &Confidence::Exact,
                ))
                .expect("serialize repeated report"),
                canonical_json,
                "JSON output must be byte-stable across repeated runs"
            );
            assert_eq!(
                Reporter::markdown_report(std::slice::from_ref(&finding), &Confidence::Exact),
                markdown,
                "Markdown output must be byte-stable across repeated runs"
            );
        }
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
        let tier1_colored = crate::_internal::report::reporter::tier_label_colored(&ViolationTier::Tier1);
        assert_eq!(tier1_colored, "HALT");

        unsafe {
            std::env::remove_var("NO_COLOR");
        }
        let tier1_colored_style =
            crate::_internal::report::reporter::tier_label_colored(&ViolationTier::Tier1);
        assert!(tier1_colored_style.contains("HALT"));
        assert!(tier1_colored_style.contains("\x1b["));
    }

    #[test]
    fn test_inferred_schema_label() {
        use crate::_internal::db::cache::DbCache;
        use crate::_internal::analysis::state::AnalysisState;
        use crate::_internal::ast::identifiers::{Ident, QualifiedName};

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
