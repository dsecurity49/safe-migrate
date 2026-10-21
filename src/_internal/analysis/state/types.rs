use super::*;

impl AnalysisState {
    pub(super) fn resolve_type_reference_from_catalog(
        raw: &str,
        types: &HashMap<ObjectId, TypeOverlay>,
        search_path: &[SearchPathEntry],
        row_type_exists: impl Fn(&ObjectId) -> bool,
    ) -> Option<ObjectId> {
        let (schema, name, is_array) = Self::parse_type_reference(raw)?;
        // PostgreSQL names an array type after its element and renders it with
        // one `[]`, which is the spelling `format_type` gives the catalog.
        let array_name = is_array.then(|| format!("{name}[]"));
        let as_array = move |element: ObjectId| match &array_name {
            Some(array_name) => ObjectId::new(&element.schema, array_name.clone()),
            None => element,
        };
        if let Some(schema) = schema {
            let candidate = ObjectId::new(schema, name);
            return (matches!(types.get(&candidate), Some(TypeOverlay::Present(_)))
                || row_type_exists(&candidate))
            .then(|| as_array(candidate));
        }
        search_path.iter().find_map(|entry| {
            let schema = entry.searched_schema()?;
            let candidate = ObjectId::new(schema, &name);
            (matches!(types.get(&candidate), Some(TypeOverlay::Present(_)))
                || row_type_exists(&candidate))
            .then(|| as_array(candidate))
        })
    }

    /// Parse a SQL type name exactly enough to resolve modeled named types.
    /// Quoted identifiers retain their case, unquoted identifiers fold to
    /// lowercase. Array suffixes name the element's own array type, and any
    /// number of them collapse onto that one type.
    pub(super) fn parse_type_reference(raw: &str) -> Option<(Option<String>, String, bool)> {
        let mut token = raw.trim();
        let mut is_array = false;
        while let Some(without_array) = token.strip_suffix("[]") {
            is_array = true;
            token = without_array.trim_end();
        }

        let mut parts = Vec::new();
        let mut current = String::new();
        let mut quoted = false;
        let mut part_is_quoted = false;
        let mut chars = token.chars().peekable();
        while let Some(character) = chars.next() {
            match character {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    current.push('"');
                    chars.next();
                }
                '"' => {
                    quoted = !quoted;
                    part_is_quoted = true;
                }
                '.' if !quoted => {
                    parts.push(Self::resolve_type_identifier(&current, part_is_quoted)?);
                    current.clear();
                    part_is_quoted = false;
                }
                character if !quoted && character.is_whitespace() => {}
                character => current.push(character),
            }
        }
        if quoted {
            return None;
        }
        parts.push(Self::resolve_type_identifier(&current, part_is_quoted)?);
        match parts.as_slice() {
            [name] => Some((None, name.clone(), is_array)),
            [schema, name] => Some((Some(schema.clone()), name.clone(), is_array)),
            _ => None,
        }
    }

    pub(super) fn resolve_type_identifier(identifier: &str, quoted: bool) -> Option<String> {
        (!identifier.is_empty()).then(|| {
            if quoted {
                identifier.to_string()
            } else {
                identifier.to_lowercase()
            }
        })
    }

    /// Whether the server can resolve a declared type: a built-in, a type the
    /// migration created, or one the baseline holds.
    pub(crate) fn declared_type_resolves(&self, declared: &str) -> bool {
        ParsedDataType::parse(declared, self.builtin_types()).is_builtin()
            || self.resolve_type_reference(declared).is_some()
    }

    pub(crate) fn resolve_type_reference(&self, raw: &str) -> Option<ObjectId> {
        // PostgreSQL searches the session temporary schema before every explicit
        // path entry for types as well as relations, so this must agree with
        // `resolve_type_lookup_name` or one type has two identities.
        let search_path = self.relation_search_path();
        Self::resolve_type_reference_from_catalog(raw, &self.local.types, &search_path, |id| {
            matches!(
                self.local.relations.get(id),
                Some(RelationOverlay::Present(_))
            )
        })
    }

    /// The base type of a modeled domain, following chains of domains. An
    /// unresolved or non-domain reference returns `None`.
    pub(crate) fn domain_base_type(&self, raw: &str) -> Option<String> {
        let mut current = self.resolve_type_reference(raw)?;
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(current.clone()) {
                return None;
            }
            let Some(TypeOverlay::Present(TypeState {
                kind:
                    TypeKind::Domain {
                        base_type,
                        base_type_id,
                    },
                ..
            })) = self.local.types.get(&current)
            else {
                return None;
            };
            let Some(base_type_id) = base_type_id else {
                return Some(base_type.clone());
            };
            if matches!(
                self.local.types.get(base_type_id),
                Some(TypeOverlay::Present(TypeState {
                    kind: TypeKind::Domain { .. },
                    ..
                }))
            ) {
                current = base_type_id.clone();
            } else {
                return Some(base_type.clone());
            }
        }
    }

    /// The type of a field on a modeled composite type, following a domain
    /// over that composite type. An unknown field or non-composite type
    /// returns `None`.
    pub(crate) fn composite_field_type(&self, raw: &str, field: &str) -> Option<String> {
        let base = self
            .domain_base_type(raw)
            .unwrap_or_else(|| raw.to_string());
        let id = self.resolve_type_reference(&base)?;
        let Some(TypeOverlay::Present(TypeState {
            kind: TypeKind::Composite { fields },
            ..
        })) = self.local.types.get(&id)
        else {
            return None;
        };
        let data_type = fields
            .iter()
            .find(|entry| entry.name == field)
            .map(|entry| entry.data_type.clone())?;
        Some(self.domain_base_type(&data_type).unwrap_or(data_type))
    }

    pub(super) fn type_reference_name(id: &ObjectId, qualified: bool) -> String {
        let quote = |identifier: &str| {
            let unquoted = identifier
                .chars()
                .enumerate()
                .all(|(index, character)| match index {
                    0 => character.is_ascii_lowercase() || character == '_',
                    _ => {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '_'
                            || character == '$'
                    }
                });
            if unquoted {
                identifier.to_string()
            } else {
                format!("\"{}\"", identifier.replace('"', "\"\""))
            }
        };

        if qualified {
            format!("{}.{}", quote(&id.schema), quote(&id.name))
        } else {
            quote(&id.name)
        }
    }

    /// The identity a declaration `name[]` resolves to. PostgreSQL has one array
    /// type per element, so however many `[]` were written, they name this.
    pub(crate) fn array_type_id(element: &ObjectId) -> ObjectId {
        ObjectId::new(&element.schema, format!("{}[]", element.name))
    }

    /// PostgreSQL replaces the first `range` with `multirange`, otherwise
    /// appends `_multirange`, then clips the result at 63 bytes.
    pub(crate) fn multirange_companion_id(range: &ObjectId) -> ObjectId {
        const MAX_BYTES: usize = 63;
        const SUFFIX: &str = "_multirange";
        let mut name = if let Some(index) = range.name.find("range") {
            format!("{}multi{}", &range.name[..index], &range.name[index..])
        } else {
            let mut end = range.name.len().min(MAX_BYTES - SUFFIX.len());
            while end > 0 && !range.name.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}{}", &range.name[..end], SUFFIX)
        };
        if name.len() > MAX_BYTES {
            let mut end = MAX_BYTES;
            while end > 0 && !name.is_char_boundary(end) {
                end -= 1;
            }
            name.truncate(end);
        }
        ObjectId::new(&range.schema, name)
    }

    /// Whether a resolved type reference names `id` or its array form.
    pub(crate) fn type_reference_matches(reference: Option<&ObjectId>, id: &ObjectId) -> bool {
        reference.is_some_and(|reference| reference == id || reference == &Self::array_type_id(id))
    }

    /// Whether a resolved type reference names any of `ids` or an array form.
    pub(crate) fn type_reference_matches_victims(
        reference: Option<&ObjectId>,
        ids: &HashSet<ObjectId>,
    ) -> bool {
        ids.iter()
            .any(|id| Self::type_reference_matches(reference, id))
    }

    pub(super) fn remapped_type_display(
        raw: &str,
        new_id: &ObjectId,
        schema_changed: bool,
    ) -> String {
        let suffix = raw.find('[').map(|index| &raw[index..]).unwrap_or("");
        // Keep the qualification the reference was written with; a moved type
        // gains one, or the reference would no longer resolve.
        let was_qualified =
            Self::parse_type_reference(raw).is_some_and(|(schema, _, _)| schema.is_some());
        format!(
            "{}{}",
            Self::type_reference_name(new_id, was_qualified || schema_changed),
            suffix
        )
    }

    /// Whether `id` names a partitioned table, which has no storage of its own.
    pub(crate) fn relation_is_partitioned(&self, id: &ObjectId) -> bool {
        match self.local.relations.get(id) {
            Some(RelationOverlay::Present(relation)) => relation.partition_type.is_some(),
            _ => false,
        }
    }

    /// Whether `target` names a relation in `pg_catalog`.
    ///
    /// The server refuses a concurrent reindex only for a catalog relation
    /// (`IsCatalogRelation` is a namespace test); a TOAST table named directly
    /// reindexes concurrently like any other. The analyzer does not carry a
    /// catalog flag, so this recognizes the schema the server uses.
    pub(crate) fn target_is_catalog(
        &self,
        target: &crate::_internal::analysis::mutations::ReindexTargetMutation,
    ) -> bool {
        use crate::_internal::analysis::mutations::ReindexTargetMutation;
        let id = match target {
            ReindexTargetMutation::Table(id) | ReindexTargetMutation::Index(id) => id,
            ReindexTargetMutation::Database(_)
            | ReindexTargetMutation::Schema(_)
            | ReindexTargetMutation::System(_) => return false,
        };
        id.schema == "pg_catalog"
    }

    pub(crate) fn index_is_present(&self, id: &ObjectId) -> bool {
        self.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexOnRelation { .. }) && edge.dependent == *id
        })
    }

    pub(crate) fn relation_namespace_object_is_present(&self, id: &ObjectId) -> bool {
        self.relation_is_present(id) || self.sequence_is_present(id) || self.index_is_present(id)
    }

    /// Whether a miss on `id` proves the object is absent from the baseline
    /// rather than merely unknown. Only a synced baseline with relation
    /// coverage can support a `schema-drift` claim.
    pub(crate) fn relation_absence_is_authoritative(&self, id: &ObjectId) -> bool {
        self.schema_absence_is_authoritative(&id.schema)
            && self
                .baseline_coverage
                .has(crate::_internal::db::cache::CatalogFamily::Relations)
    }
}
