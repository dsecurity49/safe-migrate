//! PostgreSQL's cast catalogue (`pg_cast`), covering implicit, assignment,
//! and explicit casts alongside their coercion methods and function
//! dependencies.

use crate::_internal::analysis::facts::CastContextFact;
use crate::_internal::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const SENTINEL_CASTS_KEY: &str = "\0casts";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CastEntryMethod {
    WithFunction(Option<ObjectId>),
    WithoutFunction,
    WithInout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CastEntry {
    pub source: String,
    pub target: String,
    pub context: CastContextFact,
    pub method: CastEntryMethod,
}

/// Casts among built-in and user-defined types, keyed by canonical type spelling.
///
/// To preserve binary cache V12 compatibility (`SMCACHE12`), full cast records
/// are serialized under the reserved sentinel key `"\0casts"` inside `implicit`
/// while implicit `(source -> target)` pairs remain directly accessible.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CastCatalogue {
    implicit: BTreeMap<String, BTreeSet<String>>,
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

    /// The generated static table, used only on the `--no-cache` path.
    pub(crate) fn fallback() -> Self {
        super::cast_fallback::catalogue()
    }

    /// Whether a value of type `from` coerces to `to` without an explicit cast.
    pub(crate) fn coerces_implicitly(&self, from: &str, to: &str) -> bool {
        from == to
            || (from != SENTINEL_CASTS_KEY
                && self
                    .implicit
                    .get(from)
                    .is_some_and(|targets| targets.contains(to)))
    }

    /// Whether any cast (`IMPLICIT`, `AS ASSIGNMENT`, or explicit) is recorded
    /// from `from` to `to`.
    pub(crate) fn has_cast(&self, from: &str, to: &str) -> bool {
        if self.has_encoded_cast(from, to) {
            return true;
        }
        from != SENTINEL_CASTS_KEY
            && self
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
        for entry in self.decoded_entries() {
            if entry.source == from && entry.target == to {
                return entry.context == CastContextFact::Implicit
                    && entry.method == CastEntryMethod::WithoutFunction;
            }
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
        self.implicit
            .entry(SENTINEL_CASTS_KEY.to_string())
            .or_default()
            .insert(Self::encode_entry(&entry));
    }

    pub(crate) fn remove_cast(&mut self, from: &str, to: &str) -> bool {
        let mut removed = false;
        if from != SENTINEL_CASTS_KEY
            && let Some(targets) = self.implicit.get_mut(from)
        {
            if targets.remove(to) {
                removed = true;
            }
            if targets.is_empty() {
                self.implicit.remove(from);
            }
        }
        if let Some(records) = self.implicit.get_mut(SENTINEL_CASTS_KEY) {
            let before = records.len();
            records.retain(|raw| {
                Self::decode_entry(raw)
                    .is_none_or(|entry| !(entry.source == from && entry.target == to))
            });
            if records.len() != before {
                removed = true;
            }
            if records.is_empty() {
                self.implicit.remove(SENTINEL_CASTS_KEY);
            }
        }
        removed
    }

    pub(crate) fn casts_using_function(&self, func_id: &ObjectId) -> Vec<(String, String)> {
        self.decoded_entries()
            .into_iter()
            .filter_map(|entry| match entry.method {
                CastEntryMethod::WithFunction(Some(ref id)) if id == func_id => {
                    Some((entry.source, entry.target))
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
        self.decoded_entries().iter().any(|entry| {
            entry.source == type_name
                || entry.target == type_name
                || entry.source == array_name
                || entry.target == array_name
        }) || self.implicit.iter().any(|(src, targets)| {
            src != SENTINEL_CASTS_KEY
                && (src == type_name
                    || src == &array_name
                    || targets.contains(type_name)
                    || targets.contains(&array_name))
        })
    }

    pub(crate) fn remove_casts_for_type(&mut self, type_name: &str) -> bool {
        let array_name = format!("{type_name}[]");
        let pairs: Vec<(String, String)> = self
            .decoded_entries()
            .into_iter()
            .filter_map(|entry| {
                (entry.source == type_name
                    || entry.target == type_name
                    || entry.source == array_name
                    || entry.target == array_name)
                    .then_some((entry.source, entry.target))
            })
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
                if src == SENTINEL_CASTS_KEY {
                    return None;
                }
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
        let entries: Vec<CastEntry> = self
            .decoded_entries()
            .into_iter()
            .filter_map(|mut entry| match &mut entry.method {
                CastEntryMethod::WithFunction(Some(id)) if id == old_id => {
                    *id = new_id.clone();
                    Some(entry)
                }
                _ => None,
            })
            .collect();
        let changed = !entries.is_empty();
        for entry in entries {
            self.insert_cast(entry);
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
        for mut entry in self.decoded_entries() {
            let src_new = remap(&entry.source);
            let dst_new = remap(&entry.target);
            if src_new.is_some() || dst_new.is_some() {
                to_remove.push((entry.source.clone(), entry.target.clone()));
                if let Some(s) = src_new {
                    entry.source = s;
                }
                if let Some(t) = dst_new {
                    entry.target = t;
                }
                updated.push(entry);
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
        for mut entry in self.decoded_entries() {
            let src_new = remap_type(&entry.source);
            let dst_new = remap_type(&entry.target);
            let fn_new = match &entry.method {
                CastEntryMethod::WithFunction(Some(id)) if id.schema == old_schema => {
                    Some(ObjectId::new(new_schema, id.name.clone()))
                }
                _ => None,
            };
            if src_new.is_some() || dst_new.is_some() || fn_new.is_some() {
                to_remove.push((entry.source.clone(), entry.target.clone()));
                if let Some(s) = src_new {
                    entry.source = s;
                }
                if let Some(t) = dst_new {
                    entry.target = t;
                }
                if let Some(f) = fn_new {
                    entry.method = CastEntryMethod::WithFunction(Some(f));
                }
                updated.push(entry);
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

    fn has_encoded_cast(&self, from: &str, to: &str) -> bool {
        self.implicit
            .get(SENTINEL_CASTS_KEY)
            .is_some_and(|records| {
                records.iter().any(|raw| {
                    Self::decode_entry(raw)
                        .is_some_and(|entry| entry.source == from && entry.target == to)
                })
            })
    }

    fn decoded_entries(&self) -> Vec<CastEntry> {
        let Some(records) = self.implicit.get(SENTINEL_CASTS_KEY) else {
            return Vec::new();
        };
        records
            .iter()
            .filter_map(|raw| Self::decode_entry(raw))
            .collect()
    }

    fn encode_entry(entry: &CastEntry) -> String {
        let ctx = match entry.context {
            CastContextFact::Implicit => "i",
            CastContextFact::Assignment => "a",
            CastContextFact::Explicit => "e",
        };
        let (method, func) = match &entry.method {
            CastEntryMethod::WithoutFunction => ("b", String::new()),
            CastEntryMethod::WithInout => ("i", String::new()),
            CastEntryMethod::WithFunction(None) => ("f", String::new()),
            CastEntryMethod::WithFunction(Some(id)) => ("f", format!("{}\0{}", id.schema, id.name)),
        };
        format!(
            "{}\0{}\0{}\0{}\0{}",
            entry.source, entry.target, ctx, method, func
        )
    }

    fn decode_entry(raw: &str) -> Option<CastEntry> {
        let mut parts = raw.splitn(5, '\0');
        let source = parts.next()?.to_string();
        let target = parts.next()?.to_string();
        let context = match parts.next()? {
            "i" => CastContextFact::Implicit,
            "a" => CastContextFact::Assignment,
            "e" => CastContextFact::Explicit,
            _ => return None,
        };
        let method_code = parts.next()?;
        let rest = parts.next().unwrap_or("");
        let method = match method_code {
            "b" => CastEntryMethod::WithoutFunction,
            "i" => CastEntryMethod::WithInout,
            "f" => {
                if rest.is_empty() {
                    CastEntryMethod::WithFunction(None)
                } else {
                    let (schema, name) = rest.split_once('\0')?;
                    CastEntryMethod::WithFunction(Some(ObjectId::new(schema, name)))
                }
            }
            _ => return None,
        };
        Some(CastEntry {
            source,
            target,
            context,
            method,
        })
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
