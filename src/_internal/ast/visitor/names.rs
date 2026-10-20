use super::*;

impl AstVisitor {
    // Schema name from a SchemaRef, which the parser builds either as a leaf
    // node or one wrapping an identifier token.
    pub(super) fn resolve_schema_ref(schema_ref: &SchemaRef) -> String {
        schema_ref.ident_token().map_or_else(
            || Self::resolve_identifier_token(schema_ref.syntax().text().to_string()),
            |token| Self::resolve_identifier_token(token.text()),
        )
    }

    pub(super) fn resolve_identifier_token(text: impl AsRef<str>) -> String {
        Self::identifier_from_token(text).resolve()
    }

    pub(super) fn identifier_from_token(text: impl AsRef<str>) -> Ident {
        Self::identifier_from_name(text, false)
    }

    pub(super) fn identifier_from_name(text: impl AsRef<str>, quoted: bool) -> Ident {
        let text = text.as_ref();
        match text
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
        {
            Some(inner) => Ident::new(inner.replace("\"\"", "\""), true),
            None => Ident::new(text.to_string(), quoted),
        }
    }

    pub(super) fn segment_ident(segment: PathSegment) -> Option<Ident> {
        Some(Self::identifier_from_name(
            segment.text(),
            segment.is_quoted(),
        ))
    }

    pub(super) fn path_ref_to_qualified_name(
        path_ref: &squawk_syntax::ast::PathRef,
    ) -> Option<QualifiedName> {
        let mut segments = Vec::new();
        let mut current_ref = Some(path_ref.clone());

        while let Some(pr) = current_ref {
            if let Some(segment) = pr.segment() {
                segments.push(Self::identifier_from_name(
                    segment.text(),
                    segment.is_quoted(),
                ));
            }
            current_ref = pr.qualifier();
        }

        segments.reverse();

        if segments.is_empty() {
            return None;
        }

        let last = segments.len() - 1;
        if segments.len() >= 2 {
            Some(QualifiedName::new(
                Some(segments[last - 1].clone()),
                segments[last].clone(),
            ))
        } else {
            Some(QualifiedName::new(None, segments[last].clone()))
        }
    }

    pub(super) fn expr_to_qualified_name(expr: ast::Expr) -> Option<QualifiedName> {
        fn collect_segments(expr: ast::Expr, segments: &mut Vec<Ident>) -> bool {
            match expr {
                ast::Expr::NameRef(name) => {
                    segments.push(AstVisitor::identifier_from_name(
                        name.text(),
                        name.is_quoted(),
                    ));
                    true
                }
                ast::Expr::FieldExpr(field) => {
                    let Some(base) = field.base() else {
                        return false;
                    };
                    if !collect_segments(base, segments) {
                        return false;
                    }
                    let Some(name) = field.field() else {
                        return false;
                    };
                    segments.push(AstVisitor::identifier_from_name(
                        name.text(),
                        name.is_quoted(),
                    ));
                    true
                }
                _ => false,
            }
        }

        let mut segments = Vec::new();
        if !collect_segments(expr, &mut segments) || segments.is_empty() {
            return None;
        }

        if segments.len() >= 2 {
            Some(QualifiedName::new(
                Some(segments[0].clone()),
                segments[1].clone(),
            ))
        } else {
            Some(QualifiedName::new(None, segments[0].clone()))
        }
    }

    pub(super) fn path_to_qualified_name(path: &Path) -> Option<QualifiedName> {
        let mut segments: Vec<Ident> = Vec::new();

        if let Some(pr) = path.qualifier() {
            let mut current_ref = Some(pr);
            while let Some(r) = current_ref {
                if let Some(seg) = r.segment() {
                    segments.push(Self::identifier_from_name(seg.text(), seg.is_quoted()));
                }
                current_ref = r.qualifier();
            }
            segments.reverse();
        }

        if let Some(ps) = path.segment()
            && let Some(ident) = Self::segment_ident(ps)
        {
            segments.push(ident);
        }

        if segments.is_empty() {
            return None;
        }

        let last = segments.len() - 1;
        if segments.len() >= 2 {
            Some(QualifiedName::new(
                Some(segments[last - 1].clone()),
                segments[last].clone(),
            ))
        } else {
            Some(QualifiedName::new(None, segments[last].clone()))
        }
    }
}
