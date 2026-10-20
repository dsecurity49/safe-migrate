use super::{AnalysisState, CascadeResult, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::TableConstraintFact;
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterTableActionMutation, CreateTable, DropTable, PersistenceMutation, Rename,
};
use crate::_internal::analysis::namespace::is_session_temp_schema;
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::builtin_type::BuiltinTypeCatalogue;
use crate::_internal::model::constraint::{ConstraintKind, ConstraintState};
use crate::_internal::model::data_type::{ParsedDataType, WIDENED_NUMERIC_SCALE_VERSION};
use crate::_internal::model::index::{IndexDefinition, IndexPredicate, index_keys};
use crate::_internal::model::relation::{ColumnAction, RelationKind, RelationState};
use crate::_internal::model::sequence::{
    SequenceKind, SequenceOverlay, SequenceParameters, SequencePersistence, SequenceState,
};
use crate::_internal::model::trigger::{TriggerOverlay, TriggerState};
use std::collections::HashSet;

type RelationLookup = ObjectLookup;

mod alter_table;
mod create_table;
mod drop;
mod partition;
mod rename;
mod support;

/// Match PostgreSQL's stable `pg_get_expr(relpartbound, ...)` spelling for
/// the bound forms represented by the typed Squawk node.
fn canonical_partition_bound(bound: &str) -> String {
    let trimmed = bound.trim();
    let Some(typed) = parse_typed_bound(trimmed) else {
        return trimmed.to_string();
    };
    match typed {
        TypedBound::Default => "DEFAULT".to_string(),
        TypedBound::In(datums) => {
            let values = datums
                .into_iter()
                .map(|d| d.text)
                .collect::<Vec<_>>()
                .join(", ");
            format!("FOR VALUES IN ({values})")
        }
        TypedBound::FromTo { from, to } => {
            let from_str = from
                .into_iter()
                .map(|d| d.text)
                .collect::<Vec<_>>()
                .join(", ");
            let to_str = to
                .into_iter()
                .map(|d| d.text)
                .collect::<Vec<_>>()
                .join(", ");
            format!("FOR VALUES FROM ({from_str}) TO ({to_str})")
        }
        TypedBound::With { modulus, remainder } => {
            format!("FOR VALUES WITH ({modulus}, {remainder})")
        }
    }
}

/// Whether PostgreSQL retains a CHECK constraint on `DETACH PARTITION
/// CONCURRENTLY` and whether the local model can reproduce its exact text.
#[derive(Debug)]
enum RetainedCheckSynthesis {
    /// HASH partitions never gain a retained constraint.
    NoCheck,
    /// Exact `pg_get_expr(conbin)` text of the retained CHECK.
    Definition(String),
    /// The predicate is not representable exactly; callers keep the
    /// conservative `UnsupportedSemantics` taint.
    CantResolve,
}

/// Split `input` on `separator` at the top nesting level of `()`, `[]`, `{}`
/// and single-quoted SQL string literals (with doubled-quote handling).
fn split_top_level(input: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth: i32 = 0;
    let mut chars = input.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            '\'' => {
                while let Some((_, quoted)) = chars.next() {
                    if quoted == '\'' {
                        match chars.peek() {
                            Some((_, '\'')) => {
                                chars.next();
                            }
                            _ => break,
                        }
                    }
                }
            }
            _ => {}
        }
        if ch == separator && depth <= 0 {
            parts.push(&input[start..index]);
            start = index + ch.len_utf8();
        }
    }
    parts.push(&input[start..]);
    parts
}

/// Return the SQL string value of a bound/constraint literal token, unwrapping
/// a leading `'...'` (doubled quotes) and any `::type` suffix. Bare tokens
/// (numbers, booleans, identifiers) pass through unchanged.
fn decode_sql_literal(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let raw = raw.split("::").next().unwrap_or(raw).trim();
    if let Some(inner) = raw.strip_prefix('\'') {
        let mut value = String::new();
        let mut chars = inner.char_indices().peekable();
        while let Some((_, ch)) = chars.next() {
            if ch == '\'' {
                match chars.peek() {
                    Some((_, '\'')) => {
                        chars.next();
                        value.push('\'');
                    }
                    _ => return Some(value),
                }
            } else {
                value.push(ch);
            }
        }
        None
    } else if !raw.chars().any(|ch| matches!(ch, '(' | ')' | '\'')) {
        Some(raw.to_string())
    } else {
        None
    }
}

/// Choose the array element type for a folded `ARRAY[...]` constant. When
/// elements carry homogeneous `::type` casts that cast is used; otherwise the
/// key column type applies. Mixed casts conservatively fail (`None`).
fn array_element_type(elements: &[&str], fallback: &str) -> Option<String> {
    let first_cast = elements
        .first()?
        .split("::")
        .nth(1)
        .map(str::trim)
        .map(str::to_owned);
    for element in elements.iter().skip(1) {
        let cast = element.split("::").nth(1).map(str::trim).map(str::to_owned);
        if cast != first_cast {
            return None;
        }
    }
    Some(first_cast.unwrap_or_else(|| fallback.to_string()))
}

/// Render partition-list values in the array-constant element syntax for the
/// key column type (`t`/`f` for booleans, otherwise the element text as-is).
fn elements_for_array(
    values: &[String],
    column_type: &str,
    catalogue: &BuiltinTypeCatalogue,
) -> Option<Vec<String>> {
    let parsed = ParsedDataType::parse(column_type, catalogue);
    if !parsed.is_builtin() {
        return None;
    }
    if parsed.is_named("bool") {
        values
            .iter()
            .map(|value| {
                if value.eq_ignore_ascii_case("true") {
                    Some("t".to_string())
                } else if value.eq_ignore_ascii_case("false") {
                    Some("f".to_string())
                } else {
                    None
                }
            })
            .collect()
    } else if parsed.is_named("numeric") {
        let scale = parsed.numeric_scale();
        Some(
            values
                .iter()
                .map(|value| {
                    if is_plain_integer(value)
                        && let Some(scale) = scale
                    {
                        let zeros = "0".repeat(scale.zero_padding());
                        return format!("{value}.{zeros}");
                    }
                    value.clone()
                })
                .collect(),
        )
    } else if matches!(
        parsed.builtin().map(|b| b.typname.as_str()),
        Some(
            "int2"
                | "int4"
                | "int8"
                | "text"
                | "name"
                | "varchar"
                | "bpchar"
                | "date"
                | "timestamp"
        )
    ) {
        Some(values.to_vec())
    } else {
        None
    }
}

/// Serialize array element values into the `{...}` array-literal text with
/// PostgreSQL's element quoting (double quotes around elements containing
/// specials, `"` and `\` backslash-escaped) and single-quote doubling for the
/// enclosing string literal.
fn serialize_array_literal(values: &[String]) -> String {
    let inner = values
        .iter()
        .map(|value| {
            let special = value.is_empty()
                || value.contains([',', '"', '\\', '{', '}'])
                || value.contains(char::is_whitespace);
            let token = if special {
                let mut quoted = String::from("\"");
                for ch in value.chars() {
                    if ch == '"' || ch == '\\' {
                        quoted.push('\\');
                    }
                    quoted.push(ch);
                }
                quoted.push('"');
                quoted
            } else {
                value.to_string()
            };
            token.replace('\'', "''")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{inner}}}")
}

/// Fold a single-datum boolean LIST predicate (`X = true` -> `X`,
/// `X = false` -> `NOT X`). Non-boolean single-datum predicates are already in
/// final form and are returned unchanged.
fn fold_boolean_equality(predicate: &str) -> Option<String> {
    let equality = predicate
        .find("= true")
        .map(|position| (position, "= true", true))
        .or_else(|| {
            predicate
                .find("= false")
                .map(|position| (position, "= false", false))
        });
    let Some((position, needle, is_true)) = equality else {
        return Some(predicate.to_string());
    };
    let open = predicate[..position].rfind('(')?;
    let variable = predicate[open + 1..position].trim();
    if variable.is_empty() || !variable.chars().all(|ch| ch.is_alphanumeric() || ch == '_') {
        return None;
    }
    let after = &predicate[position + needle.len()..];
    let close = after.find(')')?;
    let replacement = if is_true {
        variable.to_string()
    } else {
        format!("(NOT {variable})")
    };
    Some(format!(
        "{}{}{}",
        &predicate[..open],
        replacement,
        &after[close + 1..]
    ))
}

/// Extract the column variable referenced by an `= ANY (...)`/`= true` clause
/// from a fully-deparsed predicate (`((col IS NOT NULL) AND (col = ...))` or
/// `((col IS NULL) OR (col = ANY (...)))`).
fn predicate_column_name(predicate: &str) -> Option<String> {
    let start = predicate
        .find(" IS NOT NULL)")
        .or_else(|| predicate.find(" IS NULL)"))?;
    let open = predicate[..start].rfind('(')?;
    let name = predicate[open + 1..start].trim();
    if name.is_empty() || !name.chars().all(|ch| ch.is_alphanumeric() || ch == '_') {
        None
    } else {
        Some(name.to_string())
    }
}

/// Deparse a single bound literal exactly as `get_const_expr`/`ruleutils`
/// would for the column's data type: booleans bare, INT4 bare when
/// non-negative and quoted otherwise, smallint/bigint/real/double always
/// quoted, numeric quoted unless it looks like a float literal, and
/// text-like/uuid/ISO-date values quoted with a `::type` cast.
fn deparse_partition_literal(
    data_type: &str,
    raw: &str,
    catalogue: &BuiltinTypeCatalogue,
) -> Option<String> {
    let decoded = decode_sql_literal(raw)?;
    let parsed = ParsedDataType::parse(data_type, catalogue);
    if !parsed.is_builtin() {
        return None;
    }
    let typname = parsed
        .builtin()
        .map(|b| b.typname.as_str())
        .unwrap_or_default();
    if typname == "bool" {
        if decoded.eq_ignore_ascii_case("true") {
            Some("true".to_string())
        } else if decoded.eq_ignore_ascii_case("false") {
            Some("false".to_string())
        } else {
            None
        }
    } else if typname == "int4" {
        let value: i64 = decoded.parse().ok()?;
        if (i32::MIN as i64..=i32::MAX as i64).contains(&value) {
            Some(if value >= 0 {
                value.to_string()
            } else {
                format!("'{value}'::integer")
            })
        } else {
            None
        }
    } else if typname == "int2" {
        let value: i16 = decoded.parse().ok()?;
        Some(format!("'{value}'::smallint"))
    } else if typname == "int8" {
        let value: i64 = decoded.parse().ok()?;
        Some(format!("'{value}'::bigint"))
    } else if typname == "numeric" {
        // When the column type carries a typmod (e.g. numeric(10,2)), PostgreSQL's
        // get_const_expr casts and applies the column scale: an integer input `5`
        // is rendered as `5.00::numeric(10,2)` when scale=2.  Bare `numeric` with
        // a float-like constant is printed without a cast.
        if parsed.has_typmod() {
            let scale = parsed.numeric_scale().map_or(0, |s| s.zero_padding());
            let scaled = if is_plain_integer(&decoded) && scale > 0 {
                format!("{decoded}.{}", "0".repeat(scale))
            } else {
                decoded
            };
            Some(format!("{scaled}::{data_type}"))
        } else if numeric_float_like(&decoded) {
            Some(decoded)
        } else {
            Some(format!("'{decoded}'::numeric"))
        }
    } else if typname == "float4" || typname == "float8" {
        numeric_float_like(&decoded).then(|| format!("'{decoded}'::{data_type}"))
    } else if typname == "date" {
        is_iso_date(&decoded).then(|| format!("'{decoded}'::date"))
    } else if typname == "uuid" {
        is_uuid(&decoded).then(|| format!("'{decoded}'::uuid"))
    } else if matches!(
        typname,
        "text" | "name" | "varchar" | "bpchar" | "timestamp"
    ) {
        // `timestamptz` is deliberately absent: how it renders depends on the
        // session TimeZone setting, so a concrete bound would be fabricated.
        Some(format!("'{}'::{}", decoded.replace('\'', "''"), parsed))
    } else {
        None
    }
}

/// `YYYY-MM-DD` with digits everywhere else.
fn is_iso_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .chars()
            .enumerate()
            .all(|(index, ch)| (index == 4 || index == 7) || ch.is_ascii_digit())
}

/// Canonical 8-4-4-4-12 hexadecimal form.
fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23]
            .iter()
            .all(|index| value.as_bytes()[*index] == b'-')
        && value.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-')
}
/// `get_const_expr` prints a NUMERIC constant bare when it looks like a float
/// literal (starts with a digit and contains `.`, `e`, or `E`).
fn numeric_float_like(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_digit()
        && value[first.len_utf8()..]
            .chars()
            .any(|ch| matches!(ch, '.' | 'e' | 'E'))
}

/// True when the value is a plain signed or unsigned integer literal: all ASCII
/// digits with an optional leading sign. This is the only numeric text that
/// PostgreSQL's `get_const_expr` rewrites to a scale-padded form; values in
/// exponent (`5e2`) or decimal (`5.0`) notation must pass through unchanged.
fn is_plain_integer(value: &str) -> bool {
    let digits = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit())
}

enum DatumKind {
    UnboundedMin,
    UnboundedMax,
    Null,
    Const,
}

struct BoundDatum {
    kind: DatumKind,
    text: String,
}

enum TypedBound {
    Default,
    In(Vec<BoundDatum>),
    FromTo {
        from: Vec<BoundDatum>,
        to: Vec<BoundDatum>,
    },
    With {
        modulus: String,
        remainder: String,
    },
}

fn parse_typed_bound(bound: &str) -> Option<TypedBound> {
    use squawk_syntax::SyntaxKind;
    use squawk_syntax::ast::{AstNode, Expr, PartitionType, SourceFile, Stmt};

    // Fast-path DEFAULT matching current canonical_partition_bound case-insensitivity
    if bound.trim().eq_ignore_ascii_case("DEFAULT") {
        return Some(TypedBound::Default);
    }

    // Some callers (e.g. tests) may pass a bound without the prefix.
    let wrap = if bound.trim().to_ascii_uppercase().starts_with("FOR VALUES ") {
        format!("CREATE TABLE __key PARTITION OF __parent () {bound}")
    } else {
        format!("CREATE TABLE __key PARTITION OF __parent () FOR VALUES {bound}")
    };

    let parsed = SourceFile::parse(&wrap);
    let pt = match parsed.tree().stmts().next()? {
        Stmt::CreateTable(c) => c.partition_type()?,
        _ => return None,
    };

    let parse_datum = |expr: Expr| -> Option<BoundDatum> {
        // Detect MINVALUE/MAXVALUE keyword token presence.
        if let Some(tok) = expr.syntax().first_token() {
            if tok.kind() == SyntaxKind::MINVALUE_KW {
                return Some(BoundDatum {
                    kind: DatumKind::UnboundedMin,
                    text: expr.syntax().text().to_string(),
                });
            }
            if tok.kind() == SyntaxKind::MAXVALUE_KW {
                return Some(BoundDatum {
                    kind: DatumKind::UnboundedMax,
                    text: expr.syntax().text().to_string(),
                });
            }
            if tok.kind() == SyntaxKind::NULL_KW {
                return Some(BoundDatum {
                    kind: DatumKind::Null,
                    text: expr.syntax().text().to_string(),
                });
            }
        }
        match expr {
            Expr::Literal(_) => Some(BoundDatum {
                kind: DatumKind::Const,
                text: expr.syntax().text().to_string(),
            }),
            Expr::PrefixExpr(pre) => {
                let inner = pre.expr()?;
                if matches!(inner, Expr::Literal(_))
                    && pre
                        .syntax()
                        .first_token()
                        .is_some_and(|t| t.kind() == SyntaxKind::MINUS)
                {
                    Some(BoundDatum {
                        kind: DatumKind::Const,
                        text: pre.syntax().text().to_string(),
                    })
                } else {
                    None
                }
            }
            Expr::CastExpr(cast) => {
                let inner = cast.expr()?;
                if matches!(inner, Expr::Literal(_) | Expr::PrefixExpr(_)) {
                    Some(BoundDatum {
                        kind: DatumKind::Const,
                        text: cast.syntax().text().to_string(),
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    };

    match pt {
        PartitionType::PartitionForValuesFrom(f) => {
            let from_node = f
                .syntax()
                .children()
                .find_map(squawk_syntax::ast::PartitionFromValues::cast)?;
            let to_node = f
                .syntax()
                .children()
                .find_map(squawk_syntax::ast::PartitionToValues::cast)?;
            let mut from_datums = Vec::new();
            for expr in from_node.exprs() {
                from_datums.push(parse_datum(expr)?);
            }
            let mut to_datums = Vec::new();
            for expr in to_node.exprs() {
                to_datums.push(parse_datum(expr)?);
            }
            Some(TypedBound::FromTo {
                from: from_datums,
                to: to_datums,
            })
        }
        PartitionType::PartitionForValuesIn(l) => {
            let mut datums = Vec::new();
            for expr in l.exprs() {
                datums.push(parse_datum(expr)?);
            }
            Some(TypedBound::In(datums))
        }
        PartitionType::PartitionForValuesWith(w) => {
            let mut mod_text = None;
            let mut rem_text = None;
            for bound in w.bounds() {
                if let (Some(ident), Some(literal)) = (bound.ident_token(), bound.literal()) {
                    let text = format!(
                        "{} {}",
                        ident.text().to_ascii_lowercase(),
                        literal.syntax().text()
                    );
                    match ident.text().to_ascii_uppercase().as_str() {
                        "MODULUS" => mod_text = Some(text),
                        "REMAINDER" => rem_text = Some(text),
                        _ => {}
                    }
                }
            }
            Some(TypedBound::With {
                modulus: mod_text?,
                remainder: rem_text?,
            })
        }
        PartitionType::PartitionDefault(_) => Some(TypedBound::Default),
    }
}

/// The relation kinds PostgreSQL's `ATSimplePermissions` admits for each
/// `ALTER TABLE` action.  A partitioned table is tracked separately because
/// some actions accept only plain tables and some only partitioned ones.
fn alter_table_action_permits(
    action: &AlterTableActionMutation,
    kind: &RelationKind,
    partitioned: bool,
) -> bool {
    use AlterTableActionMutation as Action;
    let table = *kind == RelationKind::Table && !partitioned;
    let partitioned_table = *kind == RelationKind::Table && partitioned;
    let view = *kind == RelationKind::View;
    let matview = *kind == RelationKind::MaterializedView;
    let foreign = *kind == RelationKind::ForeignTable;
    let table_like = table || partitioned_table || foreign;
    match action {
        Action::AddColumn { .. } | Action::DropColumn { .. } | Action::SetType { .. } => table_like,
        Action::RenameColumn { .. } => table_like || view || matview,
        Action::AddForeignKey { .. }
        | Action::AddCheckConstraint { .. }
        | Action::AddExcludeConstraint { .. }
        | Action::DropConstraint { .. }
        | Action::ValidateConstraint { .. }
        | Action::InheritTable { .. }
        | Action::NoInheritTable { .. }
        | Action::AlterColumnInheritance
        | Action::SetNotNull { .. }
        | Action::DropNotNull { .. }
        | Action::SetGeneratedExpression { .. }
        | Action::DropGeneratedExpression { .. }
        | Action::DisableTrigger { .. }
        | Action::EnableTrigger { .. }
        | Action::SetTriggerMode { .. } => table_like,
        Action::AddUniqueConstraint { using_index, .. }
        | Action::AddPrimaryKeyConstraint { using_index, .. } => {
            table || partitioned_table || (using_index.is_none() && foreign)
        }
        Action::SetDefault { .. } => table || partitioned_table || view || foreign,
        Action::SetColumnOptions { .. }
        | Action::ResetColumnOptions { .. }
        | Action::SetStorage { .. } => table || partitioned_table || matview || foreign,
        Action::SetTableOptions { .. } | Action::ResetTableOptions { .. } => {
            table || partitioned_table || view || matview
        }
        Action::SetCompression { .. }
        | Action::SetAccessMethod { .. }
        | Action::SetTablespace { .. }
        | Action::SetCluster { .. }
        | Action::SetReplicaIdentity { .. } => table || partitioned_table || matview,
        Action::SetStatistics { .. } => table || partitioned_table || matview || foreign,
        Action::SetPersistence { .. } => table,
        Action::AlterConstraint { .. }
        | Action::SetRowSecurity { .. }
        | Action::SetForceRowSecurity { .. }
        | Action::SetRuleMode { .. }
        | Action::SetOfType { .. }
        | Action::PartitionReshape => table || partitioned_table,
        Action::RenameConstraint { .. } => table_like,
        Action::AttachPartition { .. } | Action::DetachPartition { .. } => partitioned_table,
        Action::OwnerTo { .. } => table_like || view || matview,
    }
}
