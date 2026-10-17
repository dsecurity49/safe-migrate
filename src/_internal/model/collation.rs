//! Collations, as `pg_collation` records them.
//!
//! A `COLLATE` clause names a collation, and PostgreSQL resolves it through the
//! search path and stores the resolved OID. Comparing two indexes needs the
//! resolved identity, because a bare name means different collations in
//! different schemas.

use crate::_internal::analysis::namespace::{SearchPathEntry, resolve_unqualified};
use crate::_internal::model::index::{ResolvedName, WrittenName};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Every collation PostgreSQL knows, by resolved name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CollationCatalogue {
    entries: BTreeSet<ResolvedName>,
}

impl CollationCatalogue {
    pub(crate) fn from_entries(entries: Vec<ResolvedName>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    fn lookup(&self, schema: &str, name: &str) -> Option<ResolvedName> {
        self.entries
            .get(&ResolvedName {
                schema: schema.to_string(),
                name: name.to_string(),
            })
            .cloned()
    }

    /// The collation a written name denotes, as PostgreSQL's lookup resolves it.
    ///
    /// An explicit schema is exact. An unqualified name follows the effective
    /// search path, where `pg_catalog` is searched before every explicit entry
    /// unless the path names it. A name that resolves past an unsearchable
    /// entry may not be the collation PostgreSQL chose, so it stays unresolved.
    pub(crate) fn resolve(
        &self,
        written: &WrittenName,
        search_path: &[SearchPathEntry],
    ) -> Option<ResolvedName> {
        match &written.schema {
            Some(schema) => self.lookup(schema, &written.name),
            None => resolve_unqualified(search_path, |schema| self.lookup(schema, &written.name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(schema: &str, name: &str) -> ResolvedName {
        ResolvedName {
            schema: schema.to_string(),
            name: name.to_string(),
        }
    }

    fn written(schema: Option<&str>, name: &str) -> WrittenName {
        WrittenName {
            schema: schema.map(str::to_string),
            name: name.to_string(),
        }
    }

    fn path(names: &[&str]) -> Vec<SearchPathEntry> {
        SearchPathEntry::from_catalog_names(
            &names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn an_unqualified_name_resolves_through_the_path() {
        let catalogue = CollationCatalogue::from_entries(vec![
            name("pg_catalog", "C"),
            name("public", "app_collation"),
        ]);
        assert_eq!(
            catalogue.resolve(&written(None, "C"), &path(&["public"])),
            Some(name("pg_catalog", "C"))
        );
        assert_eq!(
            catalogue.resolve(&written(None, "app_collation"), &path(&["public"])),
            Some(name("public", "app_collation"))
        );
        assert_eq!(
            catalogue.resolve(&written(None, "missing"), &path(&["public"])),
            None
        );
    }

    #[test]
    fn an_explicit_schema_is_exact() {
        let catalogue =
            CollationCatalogue::from_entries(vec![name("pg_catalog", "C"), name("public", "C")]);
        assert_eq!(
            catalogue.resolve(&written(Some("public"), "C"), &path(&["pg_catalog"])),
            Some(name("public", "C"))
        );
        assert_eq!(
            catalogue.resolve(&written(Some("other"), "C"), &path(&["public"])),
            None
        );
    }

    #[test]
    fn the_catalog_answers_before_any_path_entry_unless_listed() {
        let catalogue =
            CollationCatalogue::from_entries(vec![name("pg_catalog", "C"), name("public", "C")]);
        assert_eq!(
            catalogue.resolve(&written(None, "C"), &path(&["public"])),
            Some(name("pg_catalog", "C")),
            "an unlisted pg_catalog is searched first"
        );
        assert_eq!(
            catalogue.resolve(&written(None, "C"), &path(&["public", "pg_catalog"])),
            Some(name("public", "C")),
            "a listed pg_catalog is searched at its written position"
        );
    }

    #[test]
    fn a_name_resolved_past_an_unresolved_entry_is_unknown() {
        let catalogue = CollationCatalogue::from_entries(vec![name("public", "app_collation")]);
        let mut path = path(&["public"]);
        path.insert(0, SearchPathEntry::Unresolved(Some("app".to_string())));
        assert_eq!(
            catalogue.resolve(&written(None, "app_collation"), &path),
            None,
            "the collation PostgreSQL chose may live in the unresolved schema"
        );
    }
}
