use crate::error::{Result, SafeMigrateError};
use crate::model::{IndexIdentity, TableIdentity};
use squawk_syntax::ast::{self, AstNode};

pub fn normalize_ident(ident: &str) -> String {
    let ident = ident.trim();
    if ident.starts_with('"') && ident.ends_with('"') && ident.len() >= 2 {
        ident[1..ident.len() - 1].to_string()
    } else {
        ident.to_ascii_lowercase()
    }
}

fn extract_segment_text(seg: &ast::PathSegment) -> String {
    if let Some(name) = seg.name() {
        if let Some(ident) = name.ident_token() {
            return ident.text().to_string();
        }
    } else if let Some(name_ref) = seg.name_ref()
        && let Some(ident) = name_ref.ident_token() {
            return ident.text().to_string();
        }
    seg.syntax().text().to_string()
}

pub fn extract_path_components(path: ast::Path) -> Result<(Option<String>, String)> {
    let mut segments = Vec::new();
    let mut current_path = Some(path);

    while let Some(p) = current_path {
        if let Some(seg) = p.segment() {
            segments.push(extract_segment_text(&seg));
        }
        current_path = p.qualifier();
    }
    segments.reverse();

    match segments.as_slice() {
        [name] => Ok((None, normalize_ident(name))),
        [schema, name] => Ok((Some(normalize_ident(schema)), normalize_ident(name))),
        _ => Err(SafeMigrateError::Parse(format!(
            "Unsupported identifier length (got {}): {}",
            segments.len(),
            segments.join(".")
        ))),
    }
}

pub fn extract_table_identity(path: ast::Path) -> Result<TableIdentity> {
    let (schema, name) = extract_path_components(path)?;
    Ok(TableIdentity { schema, name })
}

pub fn extract_index_identity(path: ast::Path) -> Result<IndexIdentity> {
    let (schema, name) = extract_path_components(path)?;
    Ok(IndexIdentity { schema, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_ident_standard() {
        // Standard identifiers should be downcased
        assert_eq!(normalize_ident("Users"), "users");
        assert_eq!(normalize_ident("CamelCaseTable"), "camelcasetable");
    }

    #[test]
    fn test_normalize_ident_quoted() {
        // Quoted identifiers should preserve their exact case and strip the quotes
        assert_eq!(normalize_ident("\"Users\""), "Users");
        assert_eq!(normalize_ident("\"CamelCaseTable\""), "CamelCaseTable");
        assert_eq!(
            normalize_ident("\"weird-table-name!\""),
            "weird-table-name!"
        );
    }
}
