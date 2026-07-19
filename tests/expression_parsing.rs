mod common;

mod expression_parsing_tests {
    use crate::common::*;
    use safe_migrate::analysis::state::AnalysisState;

    fn assert_expr(expr: &str) {
        let engine = setup_engine();
        let mut state = setup_state();
        assert!(
            engine
                .analyze(
                    &format!("CREATE TABLE t(val INT DEFAULT {});", expr),
                    &mut state
                )
                .is_ok()
        );
    }

    #[test]
    fn test_expr_literal() {
        assert_expr("42");
    }
    #[test]
    fn test_expr_name_ref() {
        assert_expr("some_col");
    }
    #[test]
    fn test_expr_call() {
        assert_expr("COALESCE(1, 2)");
    }
    #[test]
    fn test_expr_bin_op() {
        assert_expr("1 + 2 * 3 = 7");
    }
    #[test]
    fn test_expr_cast() {
        assert_expr("1::text");
    }
    #[test]
    fn test_expr_prefix() {
        assert_expr("-42");
    }
    #[test]
    fn test_expr_paren() {
        assert_expr("(1 + 2)");
    }
    #[test]
    fn test_expr_case() {
        assert_expr("CASE WHEN true THEN 1 ELSE 0 END");
    }
    #[test]
    fn test_expr_array() {
        assert_expr("ARRAY[1, 2, 3]");
    }
    #[test]
    fn test_expr_between() {
        assert_expr("5 BETWEEN 1 AND 10");
    }
    #[test]
    fn test_expr_index() {
        assert_expr("arr[1]");
    }
    #[test]
    fn test_expr_slice() {
        assert_expr("arr[1:3]");
    }
    #[test]
    fn test_expr_slice_omitted() {
        assert_expr("arr[2:]");
    }
    #[test]
    fn test_expr_field() {
        assert_expr("(my_record).my_field");
    }

    #[test]
    fn test_parser_syntax_error_rejection() {
        let engine = setup_engine();
        let mut state = AnalysisState::new(safe_migrate::db::cache::DbCache::new());
        assert!(engine.analyze("CREATE TABLE (;", &mut state).is_err());
    }
}

// ─────────────────────────────────────────────
// 6. Identifier Casing & Quoting Isolation
// ─────────────────────────────────────────────
