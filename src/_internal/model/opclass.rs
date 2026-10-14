//! Operator classes, as `pg_opclass` records them.
//!
//! An index key names an operator class or nothing, and PostgreSQL stores the
//! *resolved* class either way: `CREATE INDEX ON t (c text_ops)` and
//! `CREATE INDEX ON t (c)` both record the same OID, and both attach to each
//! other. So the catalogue is what tells a written class apart from an omitted
//! one.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One operator class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpclassEntry {
    pub name: String,
    /// The schema the class is visible in.
    pub namespace: String,
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

/// Every operator class PostgreSQL knows, keyed by `namespace.name`.
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

    /// Resolve a written class name, honouring `search_path` order.
    ///
    /// Returns `None` when the name is unknown: an unresolvable class is not
    /// evidence of a non-default class.
    pub(crate) fn resolve(
        &self,
        name: &str,
        method: &str,
        search_path: &[String],
    ) -> Option<&OpclassEntry> {
        search_path
            .iter()
            .find_map(|schema| self.entries.get(&Self::key(schema, name, method)))
            .or_else(|| self.entries.get(&Self::key("pg_catalog", name, method)))
    }

    /// Whether a written class means "the default for this type and method".
    ///
    /// PostgreSQL cannot tell an explicitly written default class from an
    /// omitted one, so treating them alike is what makes a simulator
    /// comparison agree with the catalog.
    pub(crate) fn is_default_for(
        &self,
        name: &str,
        intype: &str,
        method: &str,
        search_path: &[String],
    ) -> Option<bool> {
        let entry = self.resolve(name, method, search_path)?;
        if entry.serves(intype, method) {
            Some(entry.is_default)
        } else {
            // A class for another type or method is written explicitly, and an
            // explicit class that is not the default stays recorded.
            Some(false)
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

    fn catalogue() -> OpclassCatalogue {
        OpclassCatalogue::from_entries(vec![
            OpclassEntry {
                name: "text_ops".to_string(),
                namespace: "pg_catalog".to_string(),
                intype: "text".to_string(),
                aliases: Vec::new(),
                method: "btree".to_string(),
                is_default: true,
            },
            OpclassEntry {
                name: "varchar_pattern_ops".to_string(),
                namespace: "pg_catalog".to_string(),
                intype: "text".to_string(),
                aliases: Vec::new(),
                method: "btree".to_string(),
                is_default: false,
            },
        ])
    }

    #[test]
    fn a_written_default_class_is_the_same_as_omitting_it() {
        // Verified live: both spellings record opclass OID 3126 for text, and
        // PostgreSQL attaches one to the other.
        let catalogue = catalogue();
        let path = vec!["public".to_string()];
        assert_eq!(
            catalogue.is_default_for("text_ops", "text", "btree", &path),
            Some(true)
        );
    }

    #[test]
    fn a_non_default_class_stays_recorded() {
        let catalogue = catalogue();
        let path = vec!["public".to_string()];
        assert_eq!(
            catalogue.is_default_for("varchar_pattern_ops", "text", "btree", &path),
            Some(false)
        );
    }

    #[test]
    fn an_unknown_class_is_not_evidence_of_a_non_default_class() {
        let catalogue = catalogue();
        assert_eq!(
            catalogue.is_default_for("mystery_ops", "text", "btree", &["public".to_string()]),
            None
        );
    }
}
