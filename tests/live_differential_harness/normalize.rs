use super::*;

pub(super) fn normalize_statistics_target(target: Option<i32>) -> Option<i32> {
    target.filter(|value| *value != -1)
}

pub(super) fn normalize_partition_constraint(constraint: Option<&str>) -> Option<String> {
    constraint
        .filter(|value| !value.trim_start().starts_with("satisfies_hash_partition("))
        .map(str::to_owned)
}

pub(super) fn normalize_relation_kind(kind: RelationKind) -> NormalizedRelationKind {
    match kind {
        RelationKind::Table => NormalizedRelationKind::Table,
        RelationKind::View => NormalizedRelationKind::View,
        RelationKind::MaterializedView => NormalizedRelationKind::MaterializedView,
        // Remote rows; no local storage or access method.
        RelationKind::ForeignTable => NormalizedRelationKind::ForeignTable,
    }
}

pub(super) fn normalize_access_method(kind: &RelationKind, method: Option<&str>) -> Option<String> {
    match kind {
        RelationKind::Table | RelationKind::MaterializedView => {
            Some(method.unwrap_or("heap").to_ascii_lowercase())
        }
        RelationKind::View | RelationKind::ForeignTable => None,
    }
}

pub(super) fn normalize_table_flag(kind: &RelationKind, value: Option<bool>) -> Option<bool> {
    matches!(kind, RelationKind::Table).then_some(value.unwrap_or(false))
}

pub(super) fn normalize_replica_identity(
    kind: &RelationKind,
    value: Option<&str>,
) -> Option<String> {
    matches!(kind, RelationKind::Table).then(|| value.unwrap_or("DEFAULT").to_string())
}

pub(super) fn normalize_generated_column(
    generated: Option<&safe_migrate::_internal::model::relation::GeneratedColumnState>,
    known_function_ids: &[ObjectId],
    search_path: &[String],
) -> Option<String> {
    let generated = generated?;
    let Some(expression) = &generated.expression else {
        return Some(format!("{:?}:<missing expression>", generated.kind));
    };
    let expression = normalize_constraint_definition(Some(expression)).unwrap();
    let parsed = ast::SourceFile::parse(&format!("SELECT {expression}"));
    let callee_identities = parsed
        .tree()
        .syntax()
        .descendants()
        .filter_map(ast::CallExpr::cast)
        .filter_map(|call| {
            let callee = call.expr()?;
            canonical_generated_function_identity(&callee, known_function_ids, search_path)
                .map(|identity| (callee.syntax().text_range(), identity))
        })
        .collect::<Vec<_>>();
    let normalized = parsed
        .tree()
        .syntax()
        .descendants_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| !token.kind().is_trivia())
        .filter_map(|token| {
            if let Some((callee_range, identity)) = callee_identities
                .iter()
                .find(|(callee_range, _)| callee_range.contains_range(token.text_range()))
            {
                return (token.text_range().start() == callee_range.start())
                    .then(|| format!("function:{identity}"));
            }
            token
                .parent()
                .and_then(ast::NameRef::cast)
                .map(|name| format!("name:{}", name.text()))
                .or_else(|| Some(token.text().to_string()))
        })
        .collect::<Vec<_>>();
    Some(format!("{:?}:{normalized:?}", generated.kind))
}

pub(super) fn canonical_generated_function_identity(
    callee: &ast::Expr,
    known_function_ids: &[ObjectId],
    search_path: &[String],
) -> Option<String> {
    let id = match callee {
        ast::Expr::NameRef(name) => {
            let name = name.text();
            search_path
                .iter()
                .find_map(|schema| known_generated_function(schema, &name, known_function_ids))?
        }
        ast::Expr::FieldExpr(field) => {
            let ast::Expr::NameRef(schema) = field.base()? else {
                return None;
            };
            let name = field.field()?;
            let schema = schema.text();
            let name = name.text();
            known_generated_function(&schema, &name, known_function_ids)?
        }
        _ => return None,
    };
    Some(qualified_name(&id.schema, &id.name))
}

pub(super) fn known_generated_function(
    schema: &str,
    name: &str,
    known_function_ids: &[ObjectId],
) -> Option<ObjectId> {
    let prefix = format!("{name}(");
    let mut candidates = known_function_ids
        .iter()
        .filter(|id| id.schema == schema && id.name.starts_with(&prefix));
    let candidate = candidates.next()?.clone();
    candidates.next().is_none().then_some(candidate)
}

pub(super) fn normalize_column_storage(
    state: &AnalysisState,
    data_type: &str,
    storage: Option<&str>,
) -> Option<String> {
    if let Some(storage) = storage {
        return Some(storage.to_ascii_uppercase());
    }
    let mut data_type = data_type.to_string();
    let mut visited = BTreeSet::new();
    loop {
        if data_type.ends_with("[]") {
            return Some("EXTENDED".into());
        }
        if !visited.insert(data_type.clone()) {
            return None;
        }
        let Some((schema, name)) = data_type.split_once('.') else {
            break;
        };
        let id = safe_migrate::_internal::ast::identifiers::ObjectId::new(schema, name);
        match state.local.types.get(&id) {
            Some(TypeOverlay::Present(ty)) => match &ty.kind {
                TypeKind::Domain {
                    base_type,
                    base_type_id,
                    ..
                } => {
                    data_type = normalize_data_type_with_identity(base_type, base_type_id.as_ref());
                    continue;
                }
                TypeKind::Composite { .. }
                | TypeKind::Range { .. }
                | TypeKind::Multirange { .. } => {
                    return Some("EXTENDED".into());
                }
                TypeKind::Enum { .. } => return Some("PLAIN".into()),
                TypeKind::Base { .. } => return None,
            },
            _ if matches!(
                state.local.relations.get(&id),
                Some(RelationOverlay::Present(_))
            ) =>
            {
                return Some("EXTENDED".into());
            }
            _ => break,
        }
    }
    let base = data_type.split('(').next()?.trim().to_ascii_lowercase();
    let inferred = match base.as_str() {
        "text" | "bytea" | "json" | "jsonb" | "xml" | "character varying" | "varchar"
        | "character" | "char" | "bpchar" | "bit" | "bit varying" | "varbit" | "jsonpath"
        | "path" | "polygon" | "tsvector" | "refcursor" => "EXTENDED",
        "numeric" | "decimal" | "inet" | "cidr" => "MAIN",
        "<unknown>" => return None,
        _ => "PLAIN",
    };
    Some(inferred.into())
}

pub(super) fn normalize_attributes(
    attributes: &[safe_migrate::_internal::analysis::facts::AttributeFact],
) -> String {
    let mut normalized = attributes.to_vec();
    normalized.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
    });
    serde_json::to_string(&normalized).expect("attribute facts must be serializable")
}

pub(super) fn normalize_publication_scope(
    scope: &safe_migrate::_internal::analysis::facts::PublicationScope,
) -> String {
    use safe_migrate::_internal::analysis::facts::{PublicationObjectFact, PublicationScope};

    let mut normalized = scope.clone();
    match &mut normalized {
        PublicationScope::AllTables { except } => except.sort(),
        PublicationScope::Explicit(objects) => {
            for object in objects.iter_mut() {
                if let PublicationObjectFact::Table {
                    columns: Some(columns),
                    ..
                } = object
                {
                    columns.sort();
                }
            }
            objects.sort_by(|left, right| {
                let left =
                    serde_json::to_string(left).expect("publication object must be serializable");
                let right =
                    serde_json::to_string(right).expect("publication object must be serializable");
                left.cmp(&right)
            });
        }
    }
    serde_json::to_string(&normalized).expect("publication scope must be serializable")
}

pub(super) fn normalize_subscription(
    subscription: &safe_migrate::_internal::model::replication::SubscriptionState,
) -> NormalizedSubscription {
    let mut publications = subscription.publications.clone();
    publications.sort();
    NormalizedSubscription {
        owner: subscription.owner.clone(),
        publications,
        params: subscription
            .params
            .as_deref()
            .map(normalize_attributes)
            .unwrap_or_default(),
        enabled: subscription.enabled,
        slot_name: subscription.slot_name.clone(),
    }
}

pub(super) fn normalize_trigger_mode(
    mode: safe_migrate::_internal::model::trigger::TriggerEnableMode,
) -> String {
    match mode {
        safe_migrate::_internal::model::trigger::TriggerEnableMode::Disabled => "disabled",
        safe_migrate::_internal::model::trigger::TriggerEnableMode::Origin => "origin",
        safe_migrate::_internal::model::trigger::TriggerEnableMode::Replica => "replica",
        safe_migrate::_internal::model::trigger::TriggerEnableMode::Always => "always",
    }
    .to_string()
}

pub(super) fn normalize_sequence_persistence(
    persistence: safe_migrate::_internal::model::sequence::SequencePersistence,
) -> String {
    use safe_migrate::_internal::model::sequence::SequencePersistence;
    match persistence {
        SequencePersistence::Permanent => "permanent",
        SequencePersistence::Temporary => "temporary",
        SequencePersistence::Unlogged => "unlogged",
    }
    .to_string()
}

pub(super) fn normalize_relation_persistence(
    persistence: safe_migrate::_internal::model::relation::Persistence,
) -> String {
    use safe_migrate::_internal::model::relation::Persistence;
    match persistence {
        Persistence::Permanent => "permanent",
        Persistence::Temporary => "temporary",
        Persistence::Unlogged => "unlogged",
    }
    .to_string()
}

pub(super) fn normalize_volatility(volatility: &Volatility) -> String {
    match volatility {
        Volatility::Volatile => "volatile",
        Volatility::Stable => "stable",
        Volatility::Immutable => "immutable",
    }
    .to_string()
}

pub(super) fn normalize_type_kind(kind: &TypeKind) -> NormalizedType {
    match kind {
        TypeKind::Enum { variants } => NormalizedType::Enum {
            variants: variants.clone(),
        },
        TypeKind::Domain {
            base_type,
            collation,
            default_text,
            not_null,
            constraints,
            ..
        } => NormalizedType::Domain {
            base_type: normalize_data_type(base_type),
            collation: collation.clone(),
            default: default_text.clone(),
            not_null: *not_null,
            constraints: constraints
                .iter()
                .map(|(name, constraint)| {
                    (
                        name.clone(),
                        (
                            canonical_constraint_expression(
                                constraint
                                    .expression_text
                                    .as_deref()
                                    .unwrap_or(&constraint.definition),
                            ),
                            constraint.validated,
                        ),
                    )
                })
                .collect(),
        },
        TypeKind::Base { shell, .. } => NormalizedType::Base { shell: *shell },
        TypeKind::Composite { fields } => NormalizedType::Composite {
            fields: fields
                .iter()
                .map(|field| {
                    (
                        field.name.clone(),
                        normalize_data_type(&field.data_type),
                        field.collation.clone(),
                    )
                })
                .collect(),
        },
        TypeKind::Range {
            subtype,
            multirange,
            collation,
            ..
        } => NormalizedType::Range {
            subtype: subtype.as_ref().map(|s| normalize_data_type(s)),
            multirange: multirange
                .as_ref()
                .map(|id| format!("{}.{}", id.schema, id.name)),
            collation: collation.clone(),
        },
        TypeKind::Multirange { range } => NormalizedType::Multirange {
            range: range
                .as_ref()
                .map(|id| format!("{}.{}", id.schema, id.name)),
        },
    }
}

pub(super) fn normalize_privilege(privilege: Privilege) -> String {
    match privilege {
        Privilege::Select => "select",
        Privilege::Insert => "insert",
        Privilege::Update => "update",
        Privilege::Delete => "delete",
        Privilege::Truncate => "truncate",
        Privilege::References => "references",
        Privilege::Trigger => "trigger",
        Privilege::All => "all",
        Privilege::Maintain => "maintain",
    }
    .to_string()
}

pub(super) fn normalize_constraint_kind(kind: ConstraintKind) -> String {
    match kind {
        ConstraintKind::Check => "check",
        ConstraintKind::ForeignKey => "foreign_key",
        ConstraintKind::PrimaryKey => "primary_key",
        ConstraintKind::Unique => "unique",
        ConstraintKind::Exclusion => "exclusion",
        ConstraintKind::NotNull => "not_null",
    }
    .to_string()
}

pub(super) fn normalize_constraint_definition(definition: Option<&str>) -> Option<String> {
    definition.map(canonical_constraint_expression)
}

/// PostgreSQL's `pg_get_expr(conbin)` deparse wraps every operand of a
/// top-level `AND`/`OR` in parentheses regardless of how the author spelled
/// the constraint. Canonicalize both sides to a parenthesis-insensitive
/// boolean form: a parenthesized operand that is not itself a boolean
/// combination loses its parens; a parenthesized `AND`/`OR` group keeps them.
pub(super) fn canonical_constraint_expression(expression: &str) -> String {
    let trimmed = expression.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut current = trimmed;
    while current.starts_with('(')
        && current.ends_with(')')
        && outer_parentheses_wrap_expression(current)
    {
        current = current[1..current.len() - 1].trim();
    }
    let separators = top_level_boolean_separators(current);
    if separators.is_empty() {
        return current.to_string();
    }
    let mut parts = Vec::new();
    let mut cursor = 0usize;
    for separator in &separators {
        parts.push(&current[cursor..separator.start]);
        cursor = separator.end;
    }
    parts.push(&current[cursor..]);
    let mut canonical = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            canonical.push(' ');
            canonical.push_str(separators[index - 1].word);
            canonical.push(' ');
        }
        canonical.push_str(&canonical_boolean_part(part));
    }
    canonical
}

pub(super) fn canonical_boolean_part(part: &str) -> String {
    let trimmed = part.trim();
    if trimmed.starts_with('(')
        && trimmed.ends_with(')')
        && outer_parentheses_wrap_expression(trimmed)
    {
        let inner = &trimmed[1..trimmed.len() - 1];
        if top_level_boolean_separators(inner.trim()).is_empty() {
            canonical_constraint_expression(inner)
        } else {
            format!("({})", canonical_constraint_expression(inner))
        }
    } else {
        canonical_constraint_expression(trimmed)
    }
}

pub(super) struct BooleanSeparator {
    start: usize,
    end: usize,
    word: &'static str,
}

/// Byte offsets of top-level `AND`/`OR` keywords (whitespace-delimited) in a
/// SQL expression, ignoring quoted strings. `'a'`/`'o'` inside identifiers
/// such as `land` are rejected by requiring surrounding whitespace.
pub(super) fn top_level_boolean_separators(expression: &str) -> Vec<BooleanSeparator> {
    let mut separators = Vec::new();
    let mut depth = 0usize;
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut chars = expression.char_indices();
    let mut last_char_was_whitespace = true;

    while let Some((index, ch)) = chars.next() {
        if single_quoted {
            if ch == '\'' {
                single_quoted = false;
            }
            last_char_was_whitespace = ch.is_whitespace();
            continue;
        }
        if double_quoted {
            if ch == '"' {
                double_quoted = false;
            }
            last_char_was_whitespace = ch.is_whitespace();
            continue;
        }
        match ch {
            '\'' => single_quoted = true,
            '"' => double_quoted = true,
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }

        if depth == 0 && last_char_was_whitespace {
            let tail = &expression[index..];
            let len = if tail.get(..3).is_some_and(|s| s.eq_ignore_ascii_case("and")) {
                Some(3)
            } else if tail.get(..2).is_some_and(|s| s.eq_ignore_ascii_case("or")) {
                Some(2)
            } else {
                None
            };

            if let Some(len) = len {
                let after = index + len;
                let after_whitespace = expression[after..]
                    .chars()
                    .next()
                    .is_none_or(|c| c.is_whitespace());
                if after_whitespace {
                    let word = if len == 3 { "AND" } else { "OR" };
                    separators.push(BooleanSeparator {
                        start: index,
                        end: after,
                        word,
                    });
                    for _ in 0..len - 1 {
                        chars.next();
                    }
                    last_char_was_whitespace = false;
                    continue;
                }
            }
        }
        last_char_was_whitespace = ch.is_whitespace();
    }
    separators
}

pub(super) fn outer_parentheses_wrap_expression(expression: &str) -> bool {
    let mut depth = 0usize;
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut chars = expression.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        match ch {
            '\'' if !double_quoted => {
                if single_quoted && chars.peek().map(|&(_, c)| c) == Some('\'') {
                    chars.next();
                } else {
                    single_quoted = !single_quoted;
                }
            }
            '"' if !single_quoted => {
                if double_quoted && chars.peek().map(|&(_, c)| c) == Some('"') {
                    chars.next();
                } else {
                    double_quoted = !double_quoted;
                }
            }
            '(' if !single_quoted && !double_quoted => depth += 1,
            ')' if !single_quoted && !double_quoted => {
                depth = depth.saturating_sub(1);
                if depth == 0 && index + ch.len_utf8() != expression.len() {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !single_quoted && !double_quoted
}

pub(super) fn normalize_data_type(data_type: &str) -> String {
    let normalized = data_type.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "int" | "int4" => "integer".to_string(),
        "int2" => "smallint".to_string(),
        "int8" => "bigint".to_string(),
        "bool" => "boolean".to_string(),
        "float4" => "real".to_string(),
        "float8" => "double precision".to_string(),
        "decimal" => "numeric".to_string(),
        "varchar" => "character varying".to_string(),
        "timestamp" => "timestamp without time zone".to_string(),
        "timestamptz" => "timestamp with time zone".to_string(),
        "time" => "time without time zone".to_string(),
        "timetz" => "time with time zone".to_string(),
        _ => match normalized.strip_prefix("varchar(") {
            Some(inner) => format!("character varying({inner}"),
            None => normalized,
        },
    }
}

pub(super) fn normalize_data_type_with_identity(
    data_type: &str,
    type_id: Option<&safe_migrate::_internal::ast::identifiers::ObjectId>,
) -> String {
    let normalized = normalize_data_type(data_type);
    let Some(type_id) = type_id else {
        return normalized;
    };

    // Keep type modifiers and array dimensions from the display string while
    // replacing the search_path-dependent base name with its stable identity.
    let suffix = normalized
        .find(|character| ['(', '['].contains(&character))
        .map(|index| &normalized[index..])
        .unwrap_or("");
    format!("{}.{}{}", type_id.schema, type_id.name, suffix)
}

pub(super) fn qualified_name(schema: &str, name: &str) -> String {
    format!("{schema}.{name}")
}

pub(super) fn split_qualified_name(name: &str) -> (&str, &str) {
    name.split_once('.')
        .unwrap_or_else(|| panic!("qualified relation name must be schema.object, got {name}"))
}
