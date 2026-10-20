use super::*;

/// Catalog families whose completeness is independently meaningful to the
/// analyzer. The cache records this explicitly instead of treating one
/// optional schema list as evidence for every object class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CatalogFamily {
    Schemas,
    Relations,
    Sequences,
    Indexes,
    Constraints,
    Triggers,
    Routines,
    Types,
    Dependencies,
    Inheritance,
    Roles,
    Publications,
    Subscriptions,
}

impl CatalogFamily {
    /// Every family a full synchronization retrieves. Kept as the single list
    /// so validation and hand-built baselines cannot disagree about it.
    pub(crate) const ALL: &'static [CatalogFamily] = &[
        CatalogFamily::Schemas,
        CatalogFamily::Relations,
        CatalogFamily::Sequences,
        CatalogFamily::Indexes,
        CatalogFamily::Constraints,
        CatalogFamily::Triggers,
        CatalogFamily::Routines,
        CatalogFamily::Types,
        CatalogFamily::Dependencies,
        CatalogFamily::Inheritance,
        CatalogFamily::Roles,
        CatalogFamily::Publications,
        CatalogFamily::Subscriptions,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Schemas => "schemas",
            Self::Relations => "relations",
            Self::Sequences => "sequences",
            Self::Indexes => "indexes",
            Self::Constraints => "constraints",
            Self::Triggers => "triggers",
            Self::Routines => "routines",
            Self::Types => "types",
            Self::Dependencies => "dependencies",
            Self::Inheritance => "inheritance",
            Self::Roles => "roles",
            Self::Publications => "publications",
            Self::Subscriptions => "subscriptions",
        }
    }
}

/// Schema boundary for the schema-scoped catalog families in [`CatalogCoverage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SchemaCoverage {
    AllNonSystem,
    Explicit(BTreeSet<String>),
}

impl SchemaCoverage {
    pub(crate) fn from_sync_scope(schemas: Option<&[String]>) -> Self {
        match schemas {
            Some(schemas) => Self::Explicit(schemas.iter().cloned().collect()),
            None => Self::AllNonSystem,
        }
    }

    pub(crate) fn covers(&self, schema: &str) -> bool {
        match self {
            Self::AllNonSystem => true,
            Self::Explicit(schemas) => schemas.contains(schema),
        }
    }

    pub(crate) fn explicit_schemas(&self) -> Option<Vec<String>> {
        match self {
            Self::AllNonSystem => None,
            Self::Explicit(schemas) => Some(schemas.iter().cloned().collect()),
        }
    }
}

/// Completeness contract emitted by synchronization and consumed by cache
/// validation. The schema boundary applies to schema-scoped families; role,
/// publication, and subscription rows are recorded separately in `families`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CatalogCoverage {
    pub schema_scope: SchemaCoverage,
    pub families: BTreeSet<CatalogFamily>,
}

impl CatalogCoverage {
    /// Coverage for a baseline known to have retrieved exactly `families`.
    /// Naming them keeps a hand-built baseline honest: an unlisted family
    /// proves nothing, so absence raises a taint rather than a finding.
    #[cfg(test)]
    pub(crate) fn for_families(schema_scope: SchemaCoverage, families: &[CatalogFamily]) -> Self {
        Self {
            schema_scope,
            families: families.iter().copied().collect(),
        }
    }

    pub(crate) fn has(&self, family: CatalogFamily) -> bool {
        self.families.contains(&family)
    }

    pub(crate) fn family_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.families.iter().copied().map(CatalogFamily::as_str)
    }
}

/// Accumulates catalog coverage as loaders run. A family becomes covered when
/// its loader completes, so the claim cannot drift from what was retrieved.
#[derive(Debug, Clone)]
pub(crate) struct CatalogCoverageBuilder {
    schema_scope: SchemaCoverage,
    families: BTreeSet<CatalogFamily>,
}

impl CatalogCoverageBuilder {
    pub(crate) fn from_sync_scope(schemas: Option<&[String]>) -> Self {
        Self {
            schema_scope: SchemaCoverage::from_sync_scope(schemas),
            families: BTreeSet::new(),
        }
    }

    pub(crate) fn record(&mut self, family: CatalogFamily) {
        self.families.insert(family);
    }

    pub(crate) fn finish(self) -> CatalogCoverage {
        CatalogCoverage {
            schema_scope: self.schema_scope,
            families: self.families,
        }
    }
}

impl Default for CatalogCoverage {
    fn default() -> Self {
        // A hand-built cache retrieved nothing, so it covers no family and can
        // never prove absence. Synchronization replaces this with what its
        // loaders actually read.
        CatalogCoverageBuilder::from_sync_scope(None).finish()
    }
}
