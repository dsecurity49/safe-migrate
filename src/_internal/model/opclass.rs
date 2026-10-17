//! Operator classes, as `pg_opclass` records them.
//!
//! An index key names an operator class or nothing, and PostgreSQL stores the
//! *resolved* class either way: `CREATE INDEX ON t (c text_ops)` and
//! `CREATE INDEX ON t (c)` both record the same OID, and both attach to each
//! other. So the catalogue is what tells a written class apart from an omitted
//! one, and which operator family the resolution lands in — PostgreSQL compares
//! families, never class OIDs.

use crate::_internal::analysis::namespace::{SearchPathEntry, resolve_unqualified};
use crate::_internal::model::index::{ResolvedName, WrittenName};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One operator class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpclassEntry {
    pub name: String,
    /// The schema the class is visible in.
    pub namespace: String,
    /// The operator family the class belongs to.
    pub family: ResolvedName,
    /// The data type the class indexes, by `typname`.
    pub intype: String,
    /// SQL spellings that name the same type as `intype`, so a column written
    /// `integer` matches the catalogue's `int4`.
    pub aliases: Vec<String>,
    /// The access method it belongs to, by `amname`.
    pub method: String,
    /// Whether this is the access method's default class for `intype`.
    pub is_default: bool,
}

/// Every operator class PostgreSQL knows, keyed by `namespace.name.method`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpclassCatalogue {
    entries: BTreeMap<String, OpclassEntry>,
}

impl OpclassCatalogue {
    pub(crate) fn from_entries(entries: Vec<OpclassEntry>) -> Self {
        let mut catalogue = Self::default();
        for entry in entries {
            catalogue.entries.insert(
                Self::key(&entry.namespace, &entry.name, &entry.method),
                entry,
            );
        }
        catalogue
    }

    fn key(namespace: &str, name: &str, method: &str) -> String {
        // One class name exists per access method, so the method is part of the
        // identity: `int4_ops` is both the btree and the hash class.
        format!("{namespace}.{name}.{method}")
    }

    /// The class a written name denotes, as PostgreSQL's lookup resolves it.
    ///
    /// An explicit schema is exact. An unqualified name follows the effective
    /// search path, where `pg_catalog` is searched before every explicit entry
    /// unless the path names it. A name that resolves past an unsearchable
    /// entry may not be the class PostgreSQL chose, so it stays unresolved.
    pub(crate) fn resolve(
        &self,
        written: &WrittenName,
        method: &str,
        search_path: &[SearchPathEntry],
    ) -> Option<&OpclassEntry> {
        match &written.schema {
            Some(schema) => self.entries.get(&Self::key(schema, &written.name, method)),
            None => resolve_unqualified(search_path, |schema| {
                self.entries.get(&Self::key(schema, &written.name, method))
            }),
        }
    }

    /// The access method's default class for a key, as `GetDefaultOpClass`
    /// establishes it.
    ///
    /// `intype` names the key's type the way the catalogue records it (a
    /// `typname` or one of its recorded spellings), and `candidates` names the
    /// pseudo-types PostgreSQL resolves a type through when no class names the
    /// type exactly — `anyenum` for an enum, `anyrange` for a range. An exact
    /// match decides only when it is unique; the candidate phase likewise.
    /// Anything less certain stays `None` rather than being guessed at.
    pub(crate) fn default_class(
        &self,
        intype: Option<&str>,
        method: &str,
        candidates: &[&str],
    ) -> Option<&OpclassEntry> {
        if let Some(intype) = intype {
            let mut exact = self
                .entries
                .values()
                .filter(|entry| entry.is_default && entry.serves(intype, method));
            match (exact.next(), exact.next()) {
                (Some(entry), None) => return Some(entry),
                (Some(_), Some(_)) => return None,
                (None, _) => {}
            }
        }
        let mut candidate = self.entries.values().filter(|entry| {
            entry.is_default
                && candidates
                    .iter()
                    .any(|candidate| entry.serves(candidate, method))
        });
        match (candidate.next(), candidate.next()) {
            (Some(entry), None) => Some(entry),
            _ => None,
        }
    }
}

impl OpclassEntry {
    /// Whether this class serves the given input type and access method.
    ///
    /// The catalogue records `pg_type.typname` (`int4`), while a column carries
    /// the SQL spelling (`integer`), so both spellings name the same type.
    fn serves(&self, intype: &str, method: &str) -> bool {
        self.method == method
            && (self.intype == intype || self.aliases.iter().any(|alias| alias == intype))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn family(name: &str) -> ResolvedName {
        ResolvedName {
            schema: "pg_catalog".to_string(),
            name: name.to_string(),
        }
    }

    fn class(
        name: &str,
        namespace: &str,
        intype: &str,
        aliases: &[&str],
        family_name: &str,
        is_default: bool,
    ) -> OpclassEntry {
        OpclassEntry {
            name: name.to_string(),
            namespace: namespace.to_string(),
            family: family(family_name),
            intype: intype.to_string(),
            aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
            method: "btree".to_string(),
            is_default,
        }
    }

    fn catalogue() -> OpclassCatalogue {
        OpclassCatalogue::from_entries(vec![
            class("text_ops", "pg_catalog", "text", &[], "text_ops", true),
            class(
                "varchar_pattern_ops",
                "pg_catalog",
                "text",
                &[],
                "varchar_ops",
                false,
            ),
            class("enum_ops", "pg_catalog", "anyenum", &[], "enum_ops", true),
        ])
    }

    fn path(names: &[&str]) -> Vec<SearchPathEntry> {
        SearchPathEntry::from_catalog_names(
            &names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        )
    }

    fn written(schema: Option<&str>, name: &str) -> WrittenName {
        WrittenName {
            schema: schema.map(str::to_string),
            name: name.to_string(),
        }
    }

    #[test]
    fn an_unqualified_written_class_resolves_through_the_path() {
        let catalogue = catalogue();
        assert_eq!(
            catalogue
                .resolve(&written(None, "text_ops"), "btree", &path(&["public"]))
                .map(|entry| &entry.family),
            Some(&family("text_ops"))
        );
        assert_eq!(
            catalogue.resolve(&written(None, "mystery_ops"), "btree", &path(&["public"])),
            None
        );
    }

    #[test]
    fn an_explicit_schema_is_exact() {
        let mut catalogue = catalogue();
        catalogue.entries.insert(
            OpclassCatalogue::key("public", "text_ops", "btree"),
            class("text_ops", "public", "text", &[], "public_text_ops", true),
        );
        assert_eq!(
            catalogue
                .resolve(
                    &written(Some("public"), "text_ops"),
                    "btree",
                    &path(&["public"])
                )
                .map(|entry| &entry.family),
            Some(&family("public_text_ops"))
        );
        assert_eq!(
            catalogue.resolve(
                &written(Some("private"), "text_ops"),
                "btree",
                &path(&["public"])
            ),
            None
        );
    }

    #[test]
    fn the_catalog_answers_before_any_path_entry_unless_listed() {
        let mut catalogue = catalogue();
        catalogue.entries.insert(
            OpclassCatalogue::key("public", "text_ops", "btree"),
            class("text_ops", "public", "text", &[], "public_text_ops", true),
        );
        assert_eq!(
            catalogue
                .resolve(&written(None, "text_ops"), "btree", &path(&["public"]))
                .map(|entry| &entry.family),
            Some(&family("text_ops")),
            "an unlisted pg_catalog is searched first"
        );
        assert_eq!(
            catalogue
                .resolve(
                    &written(None, "text_ops"),
                    "btree",
                    &path(&["public", "pg_catalog"])
                )
                .map(|entry| &entry.family),
            Some(&family("public_text_ops")),
            "a listed pg_catalog is searched at its written position"
        );
    }

    #[test]
    fn a_class_resolved_past_an_unresolved_entry_is_unknown() {
        let mut catalogue = catalogue();
        catalogue.entries.insert(
            OpclassCatalogue::key("public", "custom_ops", "btree"),
            class("custom_ops", "public", "text", &[], "custom_ops", true),
        );
        let mut path = path(&["public"]);
        path.insert(0, SearchPathEntry::Unresolved(Some("app".to_string())));
        assert_eq!(
            catalogue.resolve(&written(None, "custom_ops"), "btree", &path),
            None,
            "the class PostgreSQL chose may live in the unresolved schema"
        );
    }

    #[test]
    fn a_unique_exact_default_decides_alone() {
        let catalogue = catalogue();
        assert_eq!(
            catalogue
                .default_class(Some("text"), "btree", &[])
                .map(|entry| &entry.family),
            Some(&family("text_ops"))
        );
        assert_eq!(
            catalogue.default_class(Some("int4"), "btree", &[]),
            None,
            "no class serves an integer's type"
        );
    }

    #[test]
    fn an_alias_spelling_reaches_the_same_default_class() {
        let mut catalogue = catalogue();
        catalogue.entries.insert(
            OpclassCatalogue::key("pg_catalog", "int8_ops", "btree"),
            OpclassEntry {
                aliases: vec!["bigint".to_string(), "int8".to_string()],
                ..class("int8_ops", "pg_catalog", "int8", &[], "integer_ops", true)
            },
        );
        assert_eq!(
            catalogue
                .default_class(Some("bigint"), "btree", &[])
                .map(|entry| entry.name.as_str()),
            Some("int8_ops")
        );
    }

    #[test]
    fn an_ambiguous_exact_match_claims_nothing() {
        let mut catalogue = catalogue();
        catalogue.entries.insert(
            OpclassCatalogue::key("public", "text_ops", "btree"),
            class("text_ops", "public", "text", &[], "public_text_ops", true),
        );
        assert_eq!(
            catalogue.default_class(Some("text"), "btree", &[]),
            None,
            "PostgreSQL refuses a duplicate default class rather than guessing"
        );
    }

    #[test]
    fn a_candidate_pseudo_type_supplies_the_default() {
        let catalogue = catalogue();
        assert_eq!(
            catalogue
                .default_class(None, "btree", &["anyenum"])
                .map(|entry| &entry.family),
            Some(&family("enum_ops"))
        );
        assert_eq!(catalogue.default_class(None, "btree", &["anyarray"]), None);
    }

    #[test]
    fn an_ambiguous_candidate_set_claims_nothing() {
        let mut catalogue = catalogue();
        catalogue.entries.insert(
            OpclassCatalogue::key("pg_catalog", "range_ops", "btree"),
            class(
                "range_ops",
                "pg_catalog",
                "anyrange",
                &[],
                "range_ops",
                true,
            ),
        );
        assert_eq!(
            catalogue
                .default_class(None, "btree", &["anyenum"])
                .map(|entry| entry.name.as_str()),
            Some("enum_ops")
        );
        assert_eq!(
            catalogue.default_class(None, "btree", &["anyenum", "anyrange"]),
            None,
            "a builtin range's category spans two pseudo-typed defaults"
        );
    }

    #[test]
    fn a_class_of_another_access_method_is_not_the_default() {
        let catalogue = catalogue();
        assert_eq!(
            catalogue
                .default_class(Some("text"), "hash", &[])
                .map(|entry| entry.name.as_str()),
            None,
            "the class must belong to the access method"
        );
    }
}
