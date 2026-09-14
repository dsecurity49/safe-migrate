use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::column::Column;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum Privilege {
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    References,
    Trigger,
    All,
    /// PostgreSQL 17's table-maintenance privilege.
    ///
    /// Keep this variant after the historical variants so V6 cache enum
    /// discriminants remain stable for caches written before PostgreSQL 17.
    Maintain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub(crate) struct PrivilegeMatrix {
    /// Maps role identity to the set of privileges they possess on this relation
    pub grants: HashMap<ObjectId, HashSet<Privilege>>,
    /// Maps role identity to privileges that role may re-grant. This is kept
    /// separate from effective privileges because PostgreSQL can revoke the
    /// grant option while retaining the privilege itself.
    pub grant_options: HashMap<ObjectId, HashSet<Privilege>>,
    /// Grant provenance keyed by `(grantee, privilege)`.  PostgreSQL uses the
    /// grantor identity when processing targeted REVOKE/CASCADE operations;
    /// retaining it prevents those transitions from silently removing an
    /// unrelated grant.
    #[serde(default)]
    pub grantors: HashMap<(ObjectId, Privilege), HashSet<ObjectId>>,
    #[serde(default)]
    pub grant_option_grantors: HashMap<(ObjectId, Privilege), HashSet<ObjectId>>,
}

impl PrivilegeMatrix {
    pub(crate) fn grant(&mut self, role: ObjectId, privileges: HashSet<Privilege>) {
        self.grants.entry(role).or_default().extend(privileges);
    }

    pub(crate) fn grant_with_option(&mut self, role: ObjectId, privileges: HashSet<Privilege>) {
        self.grant(role.clone(), privileges.clone());
        self.grant_options
            .entry(role)
            .or_default()
            .extend(privileges);
    }

    pub(crate) fn grant_from(
        &mut self,
        role: ObjectId,
        privileges: HashSet<Privilege>,
        grantor: Option<ObjectId>,
        with_grant_option: bool,
    ) {
        if with_grant_option {
            self.grant_with_option(role.clone(), privileges.clone());
        } else {
            self.grant(role.clone(), privileges.clone());
        }
        if let Some(grantor) = grantor {
            for privilege in privileges {
                self.grantors
                    .entry((role.clone(), privilege))
                    .or_default()
                    .insert(grantor.clone());
                if with_grant_option {
                    self.grant_option_grantors
                        .entry((role.clone(), privilege))
                        .or_default()
                        .insert(grantor.clone());
                }
            }
        }
    }

    pub(crate) fn revoke(&mut self, role: &ObjectId, privileges: &HashSet<Privilege>) {
        if let Some(owned) = self.grants.get_mut(role) {
            if privileges.contains(&Privilege::All) {
                owned.clear();
            } else {
                for p in privileges {
                    owned.remove(p);
                }
            }
        }
        // PostgreSQL cannot retain a re-grant capability after the underlying
        // privilege is revoked. Keep the two maps coherent for direct model
        // callers as well as the migration state transition helper.
        self.revoke_grant_option(role, privileges);
        self.remove_grant_provenance(role, privileges, None);
    }

    pub(crate) fn has_privilege(&self, role: &ObjectId, privilege: Privilege) -> bool {
        self.grants.get(role).is_some_and(|set| {
            set.contains(&privilege)
                || (privilege != Privilege::All && set.contains(&Privilege::All))
        })
    }

    pub(crate) fn has_grant_option(&self, role: &ObjectId, privilege: Privilege) -> bool {
        self.grant_options.get(role).is_some_and(|set| {
            set.contains(&privilege)
                || (privilege != Privilege::All && set.contains(&Privilege::All))
        })
    }

    /// Return whether `role` has a direct privilege that can be used as an
    /// authorization input.  Role inheritance is resolved by the analysis
    /// state, because the relation matrix intentionally stores only direct
    /// ACL entries.
    pub(crate) fn has_direct_privilege(&self, role: &ObjectId, privilege: Privilege) -> bool {
        self.has_privilege(role, privilege)
            || self.has_privilege(&ObjectId::new("", "public"), privilege)
    }

    pub(crate) fn has_direct_grant_option(&self, role: &ObjectId, privilege: Privilege) -> bool {
        self.has_grant_option(role, privilege)
            || self.has_grant_option(&ObjectId::new("", "public"), privilege)
    }

    /// Returns whether a targeted revoke can identify every known source for
    /// the requested privilege(s). A missing entry is meaningful only for a
    /// privilege that is actually present; absent privileges need no
    /// provenance to revoke.
    pub(crate) fn targeted_revoke_provenance_is_known(
        &self,
        role: &ObjectId,
        privileges: &HashSet<Privilege>,
    ) -> bool {
        self.grants.get(role).is_none_or(|grants| {
            grants.iter().all(|privilege| {
                let requested = privileges.contains(&Privilege::All)
                    || privileges.contains(privilege)
                    || (*privilege == Privilege::All
                        && privileges
                            .iter()
                            .any(|requested| *requested != Privilege::All));
                !requested || self.grantors.contains_key(&(role.clone(), *privilege))
            })
        })
    }

    /// Equivalent provenance check for `REVOKE ... GRANT OPTION FOR`, which
    /// changes only the grant-option map and therefore uses its separate
    /// source index.
    pub(crate) fn targeted_grant_option_revoke_provenance_is_known(
        &self,
        role: &ObjectId,
        privileges: &HashSet<Privilege>,
    ) -> bool {
        self.grant_options.get(role).is_none_or(|options| {
            options.iter().all(|privilege| {
                let requested = privileges.contains(&Privilege::All)
                    || privileges.contains(privilege)
                    || (*privilege == Privilege::All
                        && privileges
                            .iter()
                            .any(|requested| *requested != Privilege::All));
                !requested
                    || self
                        .grant_option_grantors
                        .contains_key(&(role.clone(), *privilege))
            })
        })
    }

    pub(crate) fn revoke_grant_option(&mut self, role: &ObjectId, privileges: &HashSet<Privilege>) {
        if let Some(options) = self.grant_options.get_mut(role) {
            if privileges.contains(&Privilege::All) {
                options.clear();
            } else {
                for privilege in privileges {
                    options.remove(privilege);
                }
            }
        }
        // Keep grant-option provenance synchronized with the capability set.
        // Leaving these sources behind would let later targeted revoke or
        // CASCADE logic observe a capability that was already removed.
        let keys: Vec<_> = self
            .grant_option_grantors
            .keys()
            .filter(|(grantee, privilege)| {
                grantee == role
                    && (privileges.contains(&Privilege::All) || privileges.contains(privilege))
            })
            .cloned()
            .collect();
        for key in keys {
            self.grant_option_grantors.remove(&key);
        }
    }

    /// Remove provenance for a revoke.  `grantor = Some(x)` limits the
    /// operation to grants made by x; `None` removes all known sources.
    pub(crate) fn remove_grant_provenance(
        &mut self,
        role: &ObjectId,
        privileges: &HashSet<Privilege>,
        grantor: Option<&ObjectId>,
    ) {
        let keys: Vec<_> = self
            .grantors
            .keys()
            .filter(|(grantee, privilege)| {
                grantee == role
                    && (privileges.contains(&Privilege::All) || privileges.contains(privilege))
            })
            .cloned()
            .collect();
        for key in keys {
            if let Some(sources) = self.grantors.get_mut(&key) {
                if let Some(grantor) = grantor {
                    sources.remove(grantor);
                } else {
                    sources.clear();
                }
                if sources.is_empty() {
                    self.grantors.remove(&key);
                }
            }
        }
        let option_keys: Vec<_> = self
            .grant_option_grantors
            .keys()
            .filter(|(grantee, privilege)| {
                grantee == role
                    && (privileges.contains(&Privilege::All) || privileges.contains(privilege))
            })
            .cloned()
            .collect();
        for key in option_keys {
            if let Some(sources) = self.grant_option_grantors.get_mut(&key) {
                if let Some(grantor) = grantor {
                    sources.remove(grantor);
                } else {
                    sources.clear();
                }
                if sources.is_empty() {
                    self.grant_option_grantors.remove(&key);
                }
            }
        }
    }

    pub(crate) fn expand_privileges(
        &self,
        role: &ObjectId,
        privileges: &HashSet<Privilege>,
    ) -> HashSet<Privilege> {
        if privileges.contains(&Privilege::All) {
            self.grants
                .get(role)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|privilege| *privilege != Privilege::All)
                .collect()
        } else {
            privileges.clone()
        }
    }

    pub(crate) fn revoke_from(
        &mut self,
        role: &ObjectId,
        privileges: &HashSet<Privilege>,
        grantor: Option<&ObjectId>,
    ) {
        if grantor.is_none() {
            self.revoke(role, privileges);
            return;
        }
        let grantor = grantor.expect("checked above");
        let expanded = self.expand_privileges(role, privileges);
        for privilege in &expanded {
            let key = (role.clone(), *privilege);
            let remove_effective = if let Some(sources) = self.grantors.get_mut(&key) {
                sources.remove(grantor);
                let remove_effective = sources.is_empty();
                if remove_effective {
                    self.grantors.remove(&key);
                }
                remove_effective
            } else {
                // Provenance-free V7 rows are legacy/hand-built evidence. A
                // targeted revoke cannot prove another source exists.
                true
            };
            if let Some(sources) = self.grant_option_grantors.get_mut(&key) {
                sources.remove(grantor);
                if sources.is_empty() {
                    self.grant_option_grantors.remove(&key);
                    if let Some(options) = self.grant_options.get_mut(role) {
                        options.remove(privilege);
                    }
                }
            }
            if remove_effective {
                if let Some(owned) = self.grants.get_mut(role) {
                    owned.remove(privilege);
                }
                if !self.grant_option_grantors.contains_key(&key)
                    && let Some(options) = self.grant_options.get_mut(role)
                {
                    options.remove(privilege);
                }
            }
        }
    }

    /// Revoke a grant and, when requested, recursively remove grants whose
    /// grantor lost its last known grant option for the same privilege.
    pub(crate) fn revoke_from_cascade(
        &mut self,
        role: &ObjectId,
        privileges: &HashSet<Privilege>,
        grantor: Option<&ObjectId>,
        cascade: bool,
    ) {
        let expanded = self.expand_privileges(role, privileges);
        self.revoke_from(role, &expanded, grantor);
        if !cascade {
            return;
        }
        let mut pending: Vec<(ObjectId, Privilege)> = expanded
            .iter()
            .map(|privilege| (role.clone(), *privilege))
            .collect();
        let mut visited = HashSet::new();
        while let Some((lost_grantor, privilege)) = pending.pop() {
            if !visited.insert((lost_grantor.clone(), privilege)) {
                continue;
            }
            if self.has_grant_option(&lost_grantor, privilege) {
                continue;
            }
            let downstream: Vec<ObjectId> = self
                .grantors
                .iter()
                .filter_map(|((grantee, candidate), sources)| {
                    (*candidate == privilege && sources.contains(&lost_grantor))
                        .then_some(grantee.clone())
                })
                .collect();
            let single = [privilege].into_iter().collect();
            for grantee in downstream {
                self.revoke_from(&grantee, &single, Some(&lost_grantor));
                pending.push((grantee, privilege));
            }
        }
    }

    pub(crate) fn revoke_grant_option_from(
        &mut self,
        role: &ObjectId,
        privileges: &HashSet<Privilege>,
        grantor: Option<&ObjectId>,
    ) {
        let Some(grantor) = grantor else {
            self.revoke_grant_option(role, privileges);
            return;
        };
        let expanded = self.expand_privileges(role, privileges);
        for privilege in &expanded {
            let key = (role.clone(), *privilege);
            if let Some(sources) = self.grant_option_grantors.get_mut(&key) {
                sources.remove(grantor);
                if sources.is_empty() {
                    self.grant_option_grantors.remove(&key);
                    if let Some(options) = self.grant_options.get_mut(role) {
                        options.remove(privilege);
                    }
                }
            } else if let Some(options) = self.grant_options.get_mut(role) {
                options.remove(privilege);
            }
        }
        // Grant-option provenance is part of the same invariant as the
        // option set.  Clearing only `grant_options` leaves stale sources
        // that targeted revoke/cascade logic could later mistake for a live
        // delegation.
        let keys: Vec<_> = self
            .grant_option_grantors
            .keys()
            .filter(|(grantee, privilege)| {
                grantee == role
                    && (privileges.contains(&Privilege::All) || privileges.contains(privilege))
            })
            .cloned()
            .collect();
        for key in keys {
            self.grant_option_grantors.remove(&key);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RelationKind {
    Table,
    View,
    MaterializedView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Persistence {
    Permanent,
    Temporary,
    Unlogged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OnCommitAction {
    PreserveRows,
    DeleteRows,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RuleEnableMode {
    Origin,
    Disabled,
    Replica,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum IdentityGeneration {
    Always,
    ByDefault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum GeneratedColumnKind {
    Stored,
    Virtual,
}

impl GeneratedColumnKind {
    pub(crate) fn from_pg_code(code: char) -> Option<Self> {
        match code {
            's' => Some(Self::Stored),
            'v' => Some(Self::Virtual),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GeneratedColumnState {
    pub kind: GeneratedColumnKind,
    /// Canonical catalog text when synchronized; local AST dependencies remain
    /// authoritative for mutations in the current analysis chain.
    pub expression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExtendedStatisticsState {
    pub id: ObjectId,
    pub kinds: Vec<String>,
    pub columns: Vec<String>,
    pub expressions: Option<String>,
    pub target: Option<i32>,
}

impl IdentityGeneration {
    pub(crate) fn from_pg_code(code: char) -> Option<Self> {
        match code {
            'a' => Some(Self::Always),
            'd' => Some(Self::ByDefault),
            _ => None,
        }
    }
}

impl RuleEnableMode {
    pub(crate) fn from_pg_code(code: char) -> Option<Self> {
        match code {
            'O' => Some(Self::Origin),
            'D' => Some(Self::Disabled),
            'R' => Some(Self::Replica),
            'A' => Some(Self::Always),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ColumnInheritance {
    pub parent_count: u32,
    pub is_local: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RelationState {
    pub id: ObjectId,
    pub owner: ObjectId,
    pub columns: Vec<Column>,
    /// Missing entries mean inheritance provenance has not been captured.
    #[serde(default)]
    pub column_inheritance: std::collections::HashMap<String, ColumnInheritance>,
    pub generation: u64,
    pub estimated_rows: Option<u64>,
    pub relpages: Option<u64>,
    pub kind: RelationKind,
    pub persistence: Persistence,
    /// Present only for locally-created temporary relations.
    #[serde(default)]
    pub on_commit: Option<OnCommitAction>,
    pub triggers: HashSet<String>,
    pub policies: HashSet<String>,
    #[serde(default)]
    pub rules: std::collections::HashMap<String, RuleEnableMode>,
    #[serde(default)]
    pub identity_columns: std::collections::HashMap<String, IdentityGeneration>,
    #[serde(default)]
    pub generated_columns: std::collections::HashMap<String, GeneratedColumnState>,
    #[serde(default)]
    pub extended_statistics: std::collections::HashMap<ObjectId, ExtendedStatisticsState>,
    pub last_analyze: Option<String>,
    pub last_autoanalyze: Option<String>,
    /// Transaction depth at creation, used for same-transaction index checks.
    pub created_at_tx_depth: usize,
    pub privileges: PrivilegeMatrix,
    pub partition_type: Option<String>, // e.g., "RANGE", "LIST", "HASH"
    pub partition_by: Option<String>,   // The partition key expression
    #[serde(default)]
    pub partition_bound: Option<String>,
    /// PostgreSQL's effective partition predicate, including ancestor bounds.
    #[serde(default)]
    pub partition_constraint: Option<String>,
    pub is_fk_dependency: bool,
    /// Whether a materialized view has been populated. `None` means the
    /// catalog did not provide this relation-specific fact; it is ignored for
    /// tables and ordinary views and treated conservatively for refreshes.
    pub is_populated: Option<bool>,
    /// Physical/catalog attributes are optional for caches produced before
    /// this metadata was synchronized.
    #[serde(default)]
    pub tablespace: Option<String>,
    #[serde(default)]
    pub access_method: Option<String>,
    #[serde(default)]
    pub cluster_index: Option<String>,
    #[serde(default)]
    pub row_security: Option<bool>,
    #[serde(default)]
    pub force_row_security: Option<bool>,
    #[serde(default)]
    pub replica_identity: Option<String>,
    #[serde(default)]
    pub table_options: std::collections::BTreeMap<String, String>,
    /// Composite row type selected by `CREATE TABLE ... OF`.
    #[serde(default)]
    pub of_type: Option<ObjectId>,
}

impl Default for RelationState {
    fn default() -> Self {
        Self {
            id: ObjectId::new("public", "dummy"),
            owner: ObjectId::new("public", "postgres"),
            columns: Vec::new(),
            generation: 0,
            estimated_rows: Some(0),
            relpages: None,
            kind: RelationKind::Table,
            persistence: Persistence::Permanent,
            on_commit: None,
            triggers: HashSet::new(),
            policies: HashSet::new(),
            rules: Default::default(),
            column_inheritance: Default::default(),
            identity_columns: Default::default(),
            generated_columns: Default::default(),
            extended_statistics: Default::default(),
            last_analyze: None,
            last_autoanalyze: None,
            created_at_tx_depth: 0,
            privileges: PrivilegeMatrix::default(),
            partition_type: None,
            partition_by: None,
            partition_bound: None,
            partition_constraint: None,
            is_fk_dependency: false,
            is_populated: None,
            tablespace: None,
            access_method: None,
            cluster_index: None,
            row_security: None,
            force_row_security: None,
            replica_identity: None,
            table_options: Default::default(),
            of_type: None,
        }
    }
}

impl RelationState {
    pub(crate) fn normalize_column_default(default: &Option<ExprIr>) -> Option<ExprIr> {
        if matches!(
            default,
            Some(ExprIr::Literal(value)) if value.trim().eq_ignore_ascii_case("null")
        ) {
            None
        } else {
            default.clone()
        }
    }

    pub(crate) fn new(
        id: ObjectId,
        owner: ObjectId,
        generation: u64,
        estimated_rows: Option<u64>,
        kind: RelationKind,
        persistence: Persistence,
        created_at_tx_depth: usize,
    ) -> Self {
        Self {
            id,
            owner,
            columns: Vec::new(),
            generation,
            estimated_rows,
            relpages: None,
            kind,
            persistence,
            on_commit: None,
            triggers: HashSet::new(),
            policies: HashSet::new(),
            rules: Default::default(),
            column_inheritance: Default::default(),
            identity_columns: Default::default(),
            generated_columns: Default::default(),
            extended_statistics: Default::default(),
            last_analyze: None,
            last_autoanalyze: None,
            created_at_tx_depth,
            privileges: PrivilegeMatrix::default(),
            partition_type: None,
            partition_by: None,
            partition_bound: None,
            partition_constraint: None,
            is_fk_dependency: false,
            is_populated: None,
            tablespace: None,
            access_method: None,
            cluster_index: None,
            row_security: None,
            force_row_security: None,
            replica_identity: None,
            table_options: Default::default(),
            of_type: None,
        }
    }

    pub(crate) fn mark_fk_dependency(&mut self) {
        self.is_fk_dependency = true;
    }

    pub(crate) fn clear_index_settings(&mut self, index_name: &str) {
        if self.cluster_index.as_deref() == Some(index_name) {
            self.cluster_index = None;
        }
        if self.replica_identity.as_deref() == Some(format!("USING INDEX {index_name}").as_str()) {
            // PostgreSQL retains relreplident='i' after its identity index is dropped.
            self.replica_identity = Some("USING INDEX".into());
        }
    }

    pub(crate) fn apply_column_action(&mut self, action: &ColumnAction) {
        match action {
            ColumnAction::Add {
                name,
                data_type,
                not_null,
                default,
            } => {
                if !self.columns.iter().any(|c| c.name == *name) {
                    let serial_type = data_type
                        .as_deref()
                        .map(str::trim)
                        .map(str::to_ascii_lowercase)
                        .and_then(|ty| match ty.as_str() {
                            "smallserial" | "serial2" => Some("smallint"),
                            "serial" | "serial4" => Some("integer"),
                            "bigserial" | "serial8" => Some("bigint"),
                            _ => None,
                        });
                    let is_serial = serial_type.is_some();
                    let normalized_default = if is_serial {
                        Some(crate::_internal::analysis::expr_ir::ExprIr::FunctionCall {
                            name: "nextval".to_string(),
                            args: Vec::new(),
                        })
                    } else {
                        Self::normalize_column_default(default)
                    };
                    self.columns.push(Column::migration_created(
                        name.clone(),
                        serial_type
                            .map(str::to_string)
                            .or_else(|| data_type.clone()),
                        !(*not_null || is_serial),
                        normalized_default,
                    ));
                    self.column_inheritance.insert(
                        name.clone(),
                        ColumnInheritance {
                            parent_count: 0,
                            is_local: true,
                        },
                    );
                }
            }
            ColumnAction::Drop { name } => {
                self.columns.retain(|c| c.name != *name);
                self.column_inheritance.remove(name);
                self.identity_columns.remove(name);
                self.generated_columns.remove(name);
            }
            ColumnAction::Rename { from, to } => {
                if let Some(pos) = self.columns.iter().position(|c| c.name == *from)
                    && !self.columns.iter().any(|c| c.name == *to)
                {
                    self.columns[pos].name = to.clone();
                    if let Some(provenance) = self.column_inheritance.remove(from) {
                        self.column_inheritance.insert(to.clone(), provenance);
                    }
                    self.partition_by = self.partition_by.as_deref().and_then(|source| {
                        crate::_internal::analysis::expr_visitor::ExprVisitor::rename_partition_key_source(source, &self.id.name, from, to)
                    });
                    self.partition_constraint = self.partition_constraint.as_deref().and_then(|source| {
                        crate::_internal::analysis::expr_visitor::ExprVisitor::rename_column_source(source, &self.id.name, from, to)
                    });
                    if let Some(generation) = self.identity_columns.remove(from) {
                        self.identity_columns.insert(to.clone(), generation);
                    }
                    if let Some(generated) = self.generated_columns.remove(from) {
                        self.generated_columns.insert(to.clone(), generated);
                    }
                    for generated in self.generated_columns.values_mut() {
                        generated.expression = generated.expression.as_deref().and_then(|source| {
                            crate::_internal::analysis::expr_visitor::ExprVisitor::rename_column_source(source, &self.id.name, from, to)
                        });
                    }
                    for statistics in self.extended_statistics.values_mut() {
                        for column in &mut statistics.columns {
                            if column == from {
                                *column = to.clone();
                            }
                        }
                        statistics.expressions = statistics
                            .expressions
                            .as_deref()
                            .and_then(|source| {
                                crate::_internal::analysis::expr_visitor::ExprVisitor::rename_column_source(
                                    source,
                                    &self.id.name,
                                    from,
                                    to,
                                )
                            });
                    }
                }
            }
            ColumnAction::SetNotNull { name } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.is_nullable = false;
                }
            }
            ColumnAction::DropNotNull { name } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.is_nullable = true;
                }
            }
            ColumnAction::SetType { name, data_type } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.data_type = Some(data_type.clone());
                    // A type change invalidates catalog-derived identity and
                    // statistics for the old type. The state layer resolves
                    // the new identity after this helper returns.
                    col.type_id = None;
                    col.type_modifier = None;
                    col.avg_width = None;
                    // ALTER TYPE resets these to the destination type's defaults.
                    col.storage = None;
                    col.compression = None;
                }
            }
            ColumnAction::SetDefault { name, default } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.default = Self::normalize_column_default(default);
                    // A migration mutation supersedes raw baseline catalog text.
                    col.default_expr_text = None;
                }
            }
            ColumnAction::SetStorage { name, mode } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.storage = (!mode.eq_ignore_ascii_case("default")).then(|| mode.clone());
                }
            }
            ColumnAction::SetCompression { name, method } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.compression = method.clone();
                }
            }
            ColumnAction::SetStatistics { name, target } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.statistics_target = *target;
                }
            }
            ColumnAction::SetOptions { name, options } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.options.extend(options.clone());
                }
            }
            ColumnAction::ResetOptions { name, names } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    for option in names {
                        col.options.remove(option);
                    }
                }
            }
        }
    }

    pub(crate) fn has_column(&self, name: &str) -> bool {
        self.columns.iter().any(|c| c.name == name)
    }

    pub(crate) fn get_column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }

    pub(crate) fn is_stale(&self) -> bool {
        self.last_analyze.is_none() && self.last_autoanalyze.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changing_column_type_clears_stale_catalog_metadata() {
        let id = ObjectId::new("public", "items");
        let mut relation = RelationState::new(
            id,
            ObjectId::new("", "postgres"),
            0,
            Some(10),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        relation.columns.push(Column {
            name: "value".into(),
            data_type: Some("varchar(255)".into()),
            type_id: Some(ObjectId::new("public", "varchar")),
            is_nullable: true,
            default: None,
            avg_width: Some(32),
            default_expr_text: None,
            type_modifier: Some(259),
            storage: None,
            compression: None,
            statistics_target: None,
            options: Default::default(),
            generated: None,
        });

        relation.apply_column_action(&ColumnAction::SetType {
            name: "value".into(),
            data_type: "integer".into(),
        });

        let column = relation
            .get_column("value")
            .expect("column remains present");
        assert_eq!(column.data_type.as_deref(), Some("integer"));
        assert_eq!(column.type_id, None);
        assert_eq!(column.type_modifier, None);
        assert_eq!(column.avg_width, None);
    }

    #[test]
    fn targeted_revoke_preserves_a_privilege_from_another_grantor() {
        let role = ObjectId::new("", "reader");
        let first = ObjectId::new("", "owner");
        let second = ObjectId::new("", "delegate");
        let mut matrix = PrivilegeMatrix::default();
        let select: HashSet<_> = [Privilege::Select].into_iter().collect();
        matrix.grant_from(role.clone(), select.clone(), Some(first.clone()), false);
        matrix.grant_from(role.clone(), select.clone(), Some(second.clone()), false);

        matrix.revoke_from(&role, &select, Some(&first));
        assert!(matrix.has_privilege(&role, Privilege::Select));
        assert_eq!(
            matrix
                .grantors
                .get(&(role.clone(), Privilege::Select))
                .map(|sources| sources.len()),
            Some(1)
        );

        matrix.revoke_from(&role, &select, Some(&second));
        assert!(!matrix.has_privilege(&role, Privilege::Select));
    }

    #[test]
    fn direct_grant_option_revoke_removes_provenance() {
        let role = ObjectId::new("", "reader");
        let grantor = ObjectId::new("", "owner");
        let select: HashSet<_> = [Privilege::Select].into_iter().collect();
        let mut matrix = PrivilegeMatrix::default();
        matrix.grant_from(role.clone(), select.clone(), Some(grantor), true);

        matrix.revoke_grant_option(&role, &select);

        assert!(!matrix.has_grant_option(&role, Privilege::Select));
        assert!(matrix.grant_option_grantors.is_empty());
    }

    #[test]
    fn targeted_revoke_detects_missing_grantor_provenance() {
        let role = ObjectId::new("", "reader");
        let select: HashSet<_> = [Privilege::Select].into_iter().collect();
        let mut matrix = PrivilegeMatrix::default();
        matrix.grant(role.clone(), select.clone());

        assert!(!matrix.targeted_revoke_provenance_is_known(&role, &select));
    }

    #[test]
    fn targeted_grant_option_revoke_detects_missing_provenance() {
        let role = ObjectId::new("", "reader");
        let select: HashSet<_> = [Privilege::Select].into_iter().collect();
        let mut matrix = PrivilegeMatrix::default();
        matrix.grant_with_option(role.clone(), select.clone());

        assert!(!matrix.targeted_grant_option_revoke_provenance_is_known(&role, &select));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ColumnAction {
    Add {
        name: String,
        data_type: Option<String>,
        not_null: bool,
        default: Option<crate::_internal::analysis::expr_ir::ExprIr>,
    },
    Drop {
        name: String,
    },
    Rename {
        from: String,
        to: String,
    },
    SetNotNull {
        name: String,
    },
    DropNotNull {
        name: String,
    },
    SetType {
        name: String,
        data_type: String,
    },
    SetDefault {
        name: String,
        default: Option<crate::_internal::analysis::expr_ir::ExprIr>,
    },
    SetStorage {
        name: String,
        mode: String,
    },
    SetCompression {
        name: String,
        method: Option<String>,
    },
    SetStatistics {
        name: String,
        target: Option<i32>,
    },
    SetOptions {
        name: String,
        options: std::collections::BTreeMap<String, String>,
    },
    ResetOptions {
        name: String,
        names: Vec<String>,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RelationOverlay {
    Present(RelationState),
    Dropped,
}
