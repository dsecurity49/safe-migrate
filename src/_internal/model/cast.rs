//! PostgreSQL's cast catalogue (`pg_cast`), covering implicit, assignment,
//! and explicit casts alongside their coercion methods and function
//! dependencies.

use crate::_internal::analysis::facts::CastContextFact;
use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum CastEntryMethod {
    WithFunction(Option<ObjectId>),
    WithoutFunction,
    WithInout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CastEntry {
    pub source: String,
    pub target: String,
    pub context: CastContextFact,
    pub method: CastEntryMethod,
}

/// Casts among built-in and user-defined types, keyed by canonical type spelling.
///
/// The base `DbCache` V12 payload serializes `implicit` so `12.0` caches decode
/// unchanged, while `DbCacheVersioned::V12_1` persists the full typed `entries`
/// map inside `CacheExtensionV12_1` without string-packing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CastCatalogue {
    implicit: BTreeMap<String, BTreeSet<String>>,
    #[serde(skip)]
    entries: BTreeMap<(String, String), CastEntry>,
}

impl CastCatalogue {
    #[cfg(test)]
    pub(crate) fn new(edges: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut catalogue = Self::default();
        for (source, target) in edges {
            catalogue.insert_cast(CastEntry {
                source,
                target,
                context: CastContextFact::Implicit,
                method: CastEntryMethod::WithoutFunction,
            });
        }
        catalogue
    }

    pub(crate) fn from_entries(entries: impl IntoIterator<Item = CastEntry>) -> Self {
        let mut catalogue = Self::default();
        for entry in entries {
            catalogue.insert_cast(entry);
        }
        catalogue
    }

    pub(crate) fn entries(&self) -> Vec<CastEntry> {
        self.entries.values().cloned().collect()
    }

    /// True when the catalogue carries the full `pg_cast` entry map (from a
    /// V12.1+ cache or the static fallback), rather than a legacy V12.0 cache
    /// that recorded only `implicit` casts.
    pub(crate) fn has_full_cast_coverage(&self) -> bool {
        !self.entries.is_empty() || self.implicit.is_empty()
    }

    pub(crate) fn hydrate_extension_entries(&mut self, entries: Vec<CastEntry>) {
        self.entries.clear();
        for entry in entries {
            self.insert_cast(entry);
        }
    }

    /// The generated static table, used only on the `--no-cache` path.
    pub(crate) fn fallback() -> Self {
        super::cast_fallback::catalogue()
    }

    /// Whether a value of type `from` coerces to `to` without an explicit cast.
    pub(crate) fn coerces_implicitly(&self, from: &str, to: &str) -> bool {
        from == to
            || self
                .implicit
                .get(from)
                .is_some_and(|targets| targets.contains(to))
    }

    /// Whether any cast (`IMPLICIT`, `AS ASSIGNMENT`, or explicit) is recorded
    /// from `from` to `to`.
    pub(crate) fn has_cast(&self, from: &str, to: &str) -> bool {
        self.entries
            .contains_key(&(from.to_string(), to.to_string()))
            || self
                .implicit
                .get(from)
                .is_some_and(|targets| targets.contains(to))
    }

    /// Whether two types are binary-coercible (`castcontext = 'i'` and
    /// `castmethod = 'b'`, or identical types).
    pub(crate) fn is_binary_coercible(&self, from: &str, to: &str) -> bool {
        if from == to {
            return true;
        }
        if let Some(entry) = self.entries.get(&(from.to_string(), to.to_string())) {
            return entry.context == CastContextFact::Implicit
                && entry.method == CastEntryMethod::WithoutFunction;
        }
        false
    }

    pub(crate) fn insert_cast(&mut self, entry: CastEntry) {
        self.remove_cast(&entry.source, &entry.target);
        if entry.context == CastContextFact::Implicit {
            self.implicit
                .entry(entry.source.clone())
                .or_default()
                .insert(entry.target.clone());
        }
        self.entries
            .insert((entry.source.clone(), entry.target.clone()), entry);
    }

    pub(crate) fn remove_cast(&mut self, from: &str, to: &str) -> bool {
        let mut removed = false;
        if let Some(targets) = self.implicit.get_mut(from) {
            if targets.remove(to) {
                removed = true;
            }
            if targets.is_empty() {
                self.implicit.remove(from);
            }
        }
        if self
            .entries
            .remove(&(from.to_string(), to.to_string()))
            .is_some()
        {
            removed = true;
        }
        removed
    }

    pub(crate) fn casts_using_function(&self, func_id: &ObjectId) -> Vec<(String, String)> {
        self.entries
            .values()
            .filter_map(|entry| match &entry.method {
                CastEntryMethod::WithFunction(Some(id)) if id == func_id => {
                    Some((entry.source.clone(), entry.target.clone()))
                }
                _ => None,
            })
            .collect()
    }

    pub(crate) fn remove_casts_using_function(&mut self, func_id: &ObjectId) -> bool {
        let matches = self.casts_using_function(func_id);
        let mut changed = false;
        for (source, target) in matches {
            if self.remove_cast(&source, &target) {
                changed = true;
            }
        }
        changed
    }

    pub(crate) fn has_casts_for_type(&self, type_name: &str) -> bool {
        let array_name = format!("{type_name}[]");
        self.entries.keys().any(|(source, target)| {
            source == type_name
                || target == type_name
                || source == &array_name
                || target == &array_name
        }) || self.implicit.iter().any(|(src, targets)| {
            src == type_name
                || src == &array_name
                || targets.contains(type_name)
                || targets.contains(&array_name)
        })
    }

    pub(crate) fn remove_casts_for_type(&mut self, type_name: &str) -> bool {
        let array_name = format!("{type_name}[]");
        let pairs: Vec<(String, String)> = self
            .entries
            .keys()
            .filter(|(source, target)| {
                source == type_name
                    || target == type_name
                    || source == &array_name
                    || target == &array_name
            })
            .cloned()
            .collect();
        let mut changed = false;
        for (source, target) in pairs {
            if self.remove_cast(&source, &target) {
                changed = true;
            }
        }
        for key in [type_name, array_name.as_str()] {
            if self.implicit.remove(key).is_some() {
                changed = true;
            }
        }
        let empty_sources: Vec<String> = self
            .implicit
            .iter_mut()
            .filter_map(|(src, targets)| {
                if targets.remove(type_name) {
                    changed = true;
                }
                if targets.remove(&array_name) {
                    changed = true;
                }
                targets.is_empty().then(|| src.clone())
            })
            .collect();
        for src in empty_sources {
            self.implicit.remove(&src);
        }
        changed
    }

    pub(crate) fn rewire_function_id(&mut self, old_id: &ObjectId, new_id: &ObjectId) -> bool {
        let mut changed = false;
        for entry in self.entries.values_mut() {
            if let CastEntryMethod::WithFunction(Some(id)) = &mut entry.method
                && id == old_id
            {
                *id = new_id.clone();
                changed = true;
            }
        }
        changed
    }

    pub(crate) fn rewire_type_name(&mut self, old_name: &str, new_name: &str) -> bool {
        if old_name == new_name {
            return false;
        }
        let old_array = format!("{old_name}[]");
        let new_array = format!("{new_name}[]");
        let remap = |name: &str| -> Option<String> {
            if name == old_name {
                Some(new_name.to_string())
            } else if name == old_array {
                Some(new_array.clone())
            } else {
                None
            }
        };
        let mut updated = Vec::new();
        let mut to_remove = Vec::new();
        for entry in self.entries.values() {
            let src_new = remap(&entry.source);
            let dst_new = remap(&entry.target);
            if src_new.is_some() || dst_new.is_some() {
                let mut cloned = entry.clone();
                to_remove.push((cloned.source.clone(), cloned.target.clone()));
                if let Some(s) = src_new {
                    cloned.source = s;
                }
                if let Some(t) = dst_new {
                    cloned.target = t;
                }
                updated.push(cloned);
            }
        }
        let changed = !updated.is_empty();
        for (s, t) in to_remove {
            self.remove_cast(&s, &t);
        }
        for entry in updated {
            self.insert_cast(entry);
        }
        changed
    }

    pub(crate) fn rewire_schema(&mut self, old_schema: &str, new_schema: &str) -> bool {
        if old_schema == new_schema {
            return false;
        }
        let prefix = format!("{old_schema}.");
        let remap_type = |name: &str| -> Option<String> {
            name.strip_prefix(&prefix)
                .map(|rest| format!("{new_schema}.{rest}"))
        };
        let mut updated = Vec::new();
        let mut to_remove = Vec::new();
        for entry in self.entries.values() {
            let src_new = remap_type(&entry.source);
            let dst_new = remap_type(&entry.target);
            let fn_new = match &entry.method {
                CastEntryMethod::WithFunction(Some(id)) if id.schema == old_schema => {
                    Some(ObjectId::new(new_schema, id.name.clone()))
                }
                _ => None,
            };
            if src_new.is_some() || dst_new.is_some() || fn_new.is_some() {
                let mut cloned = entry.clone();
                to_remove.push((cloned.source.clone(), cloned.target.clone()));
                if let Some(s) = src_new {
                    cloned.source = s;
                }
                if let Some(t) = dst_new {
                    cloned.target = t;
                }
                if let Some(f) = fn_new {
                    cloned.method = CastEntryMethod::WithFunction(Some(f));
                }
                updated.push(cloned);
            }
        }
        let changed = !updated.is_empty();
        for (s, t) in to_remove {
            self.remove_cast(&s, &t);
        }
        for entry in updated {
            self.insert_cast(entry);
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalogue() -> CastCatalogue {
        CastCatalogue::new(
            [("integer", "bigint"), ("character varying", "text")]
                .into_iter()
                .map(|(source, target)| (source.to_string(), target.to_string())),
        )
    }

    #[test]
    fn a_recorded_cast_is_implicit() {
        let catalogue = catalogue();
        assert!(catalogue.coerces_implicitly("integer", "bigint"));
        assert!(catalogue.coerces_implicitly("character varying", "text"));
    }

    #[test]
    fn a_type_coerces_to_itself() {
        assert!(catalogue().coerces_implicitly("integer", "integer"));
    }

    #[test]
    fn an_unrecorded_cast_is_not_implicit() {
        let catalogue = catalogue();
        assert!(!catalogue.coerces_implicitly("bigint", "integer"));
        assert!(!catalogue.coerces_implicitly("integer", "text"));
    }
}
