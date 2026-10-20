use super::*;

#[test]
fn test_expr_ir_is_volatile_literal() {
    let expr = ExprIr::Literal("static_value".into());
    assert!(!expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_omitted() {
    let expr = ExprIr::Omitted;
    assert!(!expr.is_volatile());
    assert!(expr.contains_opaque());
}

#[test]
fn test_expr_ir_opaque_sentinel_is_not_dependency_proof() {
    assert!(ExprIr::Sentinel("<complex>".into()).contains_opaque());
    assert!(!ExprIr::Literal("<case>".into()).contains_opaque());
    assert!(!ExprIr::Literal("'<'".into()).contains_opaque());
}

#[test]
fn test_expr_ir_nested_opaque_sentinel_is_detected() {
    let expr = ExprIr::BinaryOp {
        left: Box::new(ExprIr::ColumnRef("id".into())),
        op: "=".into(),
        right: Box::new(ExprIr::Sentinel("<complex>".into())),
    };
    assert!(expr.contains_opaque());
}

#[test]
fn test_expr_ir_structural_sentinels_are_detected() {
    assert!(
        ExprIr::FunctionCall {
            name: "<fn>".into(),
            args: vec![]
        }
        .contains_opaque()
    );
    assert!(
        ExprIr::BinaryOp {
            left: Box::new(ExprIr::ColumnRef("id".into())),
            op: "<op>".into(),
            right: Box::new(ExprIr::Literal("1".into())),
        }
        .contains_opaque()
    );
    assert!(
        ExprIr::Cast {
            expr: Box::new(ExprIr::ColumnRef("id".into())),
            target_type: "<type>".into(),
        }
        .contains_opaque()
    );
}

#[test]
fn test_expr_ir_is_volatile_now() {
    let expr = ExprIr::FunctionCall {
        name: "now".into(),
        args: vec![],
    };
    assert!(!expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_random() {
    let expr = ExprIr::FunctionCall {
        name: "random".into(),
        args: vec![],
    };
    assert!(expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_gen_random_uuid() {
    let expr = ExprIr::FunctionCall {
        name: "gen_random_uuid".into(),
        args: vec![],
    };
    assert!(expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_case_expr() {
    let expr = ExprIr::FunctionCall {
        name: "<case>".into(),
        args: vec![ExprIr::FunctionCall {
            name: "random".into(),
            args: vec![],
        }],
    };
    assert!(expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_binary_op() {
    let expr = ExprIr::BinaryOp {
        left: Box::new(ExprIr::FunctionCall {
            name: "random".into(),
            args: vec![],
        }),
        op: "||".into(),
        right: Box::new(ExprIr::Literal("test".into())),
    };
    assert!(expr.is_volatile());
}

#[test]
fn test_expr_ir_is_volatile_cast() {
    let expr = ExprIr::Cast {
        expr: Box::new(ExprIr::FunctionCall {
            name: "random".into(),
            args: vec![],
        }),
        target_type: "text".into(),
    };
    assert!(expr.is_volatile());
}

#[test]
fn test_clock_timestamp_is_volatile() {
    let expr = ExprIr::FunctionCall {
        name: "clock_timestamp".to_string(),
        args: vec![],
    };
    assert!(expr.is_volatile(), "clock_timestamp() should be VOLATILE");
}
