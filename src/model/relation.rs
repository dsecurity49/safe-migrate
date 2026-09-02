use crate::ast::identifiers::ObjectId;
use crate::model::column::Column;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Privilege {
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
pub struct PrivilegeMatrix {
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
    pub fn grant(&mut self, role: ObjectId, privileges: HashSet<Privilege>) {
        self.grants.entry(role).or_default().extend(privileges);
    }

    pub fn grant_with_option(&mut self, role: ObjectId, privileges: HashSet<Privilege>) {
        self.grant(role.clone(), privileges.clone());
        self.grant_options
            .entry(role)
            .or_default()
            .extend(privileges);
    }

    pub fn grant_from(
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

    pub fn revoke(&mut self, role: &ObjectId, privileges: &HashSet<Privilege>) {
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

    pub fn has_privilege(&self, role: &ObjectId, privilege: Privilege) -> bool {
        self.grants.get(role).is_some_and(|set| {
            set.contains(&privilege)
                || (privilege != Privilege::All && set.contains(&Privilege::All))
        })
    }

    pub fn has_grant_option(&self, role: &ObjectId, privilege: Privilege) -> bool {
        self.grant_options.get(role).is_some_and(|set| {
            set.contains(&privilege)
                || (privilege != Privilege::All && set.contains(&Privilege::All))
        })
    }

    /// Return whether `role` has a direct privilege that can be used as an
    /// authorization input.  Role inheritance is resolved by the analysis
    /// state, because the relation matrix intentionally stores only direct
    /// ACL entries.
    pub fn has_direct_privilege(&self, role: &ObjectId, privilege: Privilege) -> bool {
        self.has_privilege(role, privilege)
            || self.has_privilege(&ObjectId::new("", "public"), privilege)
    }

    pub fn has_direct_grant_option(&self, role: &ObjectId, privilege: Privilege) -> bool {
        self.has_grant_option(role, privilege)
            || self.has_grant_option(&ObjectId::new("", "public"), privilege)
    }

    pub fn revoke_grant_option(&mut self, role: &ObjectId, privileges: &HashSet<Privilege>) {
        if let Some(options) = self.grant_options.get_mut(role) {
            if privileges.contains(&Privilege::All) {
                options.clear();
            } else {
                for privilege in privileges {
                    options.remove(privilege);
                }
            }
        }
    }

    /// Remove provenance for a revoke.  `grantor = Some(x)` limits the
    /// operation to grants made by x; `None` removes all known sources.
    pub fn remove_grant_provenance(
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
            self.grant_option_grantors.remove(&key);
        }
    }

    pub fn revoke_from(
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
        for privilege in privileges {
            if *privilege == Privilege::All {
                continue;
            }
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
        if privileges.contains(&Privilege::All) {
            self.revoke(role, privileges);
        }
    }

    /// Revoke a grant and, when requested, recursively remove grants whose
    /// grantor lost its last known grant option for the same privilege.
    pub fn revoke_from_cascade(
        &mut self,
        role: &ObjectId,
        privileges: &HashSet<Privilege>,
        grantor: Option<&ObjectId>,
        cascade: bool,
    ) {
        self.revoke_from(role, privileges, grantor);
        if !cascade {
            return;
        }
        let mut pending: Vec<(ObjectId, Privilege)> = privileges
            .iter()
            .filter(|privilege| **privilege != Privilege::All)
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

    pub fn revoke_grant_option_from(
        &mut self,
        role: &ObjectId,
        privileges: &HashSet<Privilege>,
        grantor: Option<&ObjectId>,
    ) {
        let Some(grantor) = grantor else {
            self.revoke_grant_option(role, privileges);
            for key in self
                .grant_option_grantors
                .keys()
                .cloned()
                .collect::<Vec<_>>()
            {
                if &key.0 == role
                    && (privileges.contains(&Privilege::All) || privileges.contains(&key.1))
                {
                    self.grant_option_grantors.remove(&key);
                }
            }
            return;
        };
        for privilege in privileges {
            if *privilege == Privilege::All {
                continue;
            }
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
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationKind {
    Table,
    View,
    MaterializedView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Persistence {
    Permanent,
    Temporary,
    Unlogged,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelationState {
    pub id: ObjectId,
    pub owner: ObjectId,
    pub columns: Vec<Column>,
    pub generation: u64,
    pub estimated_rows: Option<u64>,
    pub relpages: Option<u64>,
    pub kind: RelationKind,
    pub persistence: Persistence,
    pub triggers: HashSet<String>,
    pub policies: HashSet<String>,
    pub last_analyze: Option<String>,
    pub last_autoanalyze: Option<String>,
    /// Transaction depth at creation, used for same-transaction index checks.
    pub created_at_tx_depth: usize,
    pub privileges: PrivilegeMatrix,
    pub partition_type: Option<String>, // e.g., "RANGE", "LIST", "HASH"
    pub partition_by: Option<String>,   // The partition key expression
    pub is_fk_dependency: bool,
    /// Whether a materialized view has been populated. `None` means the
    /// catalog did not provide this relation-specific fact; it is ignored for
    /// tables and ordinary views and treated conservatively for refreshes.
    pub is_populated: Option<bool>,
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
            triggers: HashSet::new(),
            policies: HashSet::new(),
            last_analyze: None,
            last_autoanalyze: None,
            created_at_tx_depth: 0,
            privileges: PrivilegeMatrix::default(),
            partition_type: None,
            partition_by: None,
            is_fk_dependency: false,
            is_populated: None,
        }
    }
}

impl RelationState {
    pub fn new(
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
            triggers: HashSet::new(),
            policies: HashSet::new(),
            last_analyze: None,
            last_autoanalyze: None,
            created_at_tx_depth,
            privileges: PrivilegeMatrix::default(),
            partition_type: None,
            partition_by: None,
            is_fk_dependency: false,
            is_populated: None,
        }
    }

    pub fn mark_fk_dependency(&mut self) {
        self.is_fk_dependency = true;
    }

    pub fn apply_column_action(&mut self, action: &ColumnAction) {
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
                        Some(crate::analysis::expr_ir::ExprIr::FunctionCall {
                            name: "nextval".to_string(),
                            args: Vec::new(),
                        })
                    } else if matches!(
                        default,
                        Some(crate::analysis::expr_ir::ExprIr::Literal(value))
                            if value.trim().eq_ignore_ascii_case("null")
                    ) {
                        None
                    } else {
                        default.clone()
                    };
                    self.columns.push(Column {
                        name: name.clone(),
                        data_type: serial_type
                            .map(str::to_string)
                            .or_else(|| data_type.clone()),
                        type_id: None,
                        default: normalized_default,
                        is_nullable: !(*not_null || is_serial),
                        avg_width: None,
                        default_expr_text: None,
                        type_modifier: None,
                    });
                }
            }
            ColumnAction::Drop { name } => {
                self.columns.retain(|c| c.name != *name);
            }
            ColumnAction::Rename { from, to } => {
                if let Some(pos) = self.columns.iter().position(|c| c.name == *from)
                    && !self.columns.iter().any(|c| c.name == *to)
                {
                    self.columns[pos].name = to.clone();
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
                }
            }
            ColumnAction::SetDefault { name, default } => {
                if let Some(col) = self.columns.iter_mut().find(|c| c.name == *name) {
                    col.default = if matches!(
                        default,
                        Some(crate::analysis::expr_ir::ExprIr::Literal(value))
                            if value.trim().eq_ignore_ascii_case("null")
                    ) {
                        None
                    } else {
                        default.clone()
                    };
                    // A migration mutation supersedes raw baseline catalog text.
                    col.default_expr_text = None;
                }
            }
        }
    }

    pub fn has_column(&self, name: &str) -> bool {
        self.columns.iter().any(|c| c.name == name)
    }

    pub fn get_column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }

    pub fn is_stale(&self) -> bool {
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
}

#[derive(Debug, Clone, PartialEq)]
pub enum ColumnAction {
    Add {
        name: String,
        data_type: Option<String>,
        not_null: bool,
        default: Option<crate::analysis::expr_ir::ExprIr>,
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
        default: Option<crate::analysis::expr_ir::ExprIr>,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum RelationOverlay {
    Present(RelationState),
    Dropped,
}
