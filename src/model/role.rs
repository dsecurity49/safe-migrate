use crate::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleState {
    pub id: ObjectId, // role name, no schema
    pub can_login: bool,
    pub is_superuser: bool,
    /// Whether memberships contribute privileges to this role. PostgreSQL's
    /// `NOINHERIT` is role state, not a property of an individual grant.
    pub inherits: bool,
    pub member_of: Vec<ObjectId>, // roles this role is a member of
    /// Memberships for which this role has the PostgreSQL ADMIN option.
    pub can_administer_membership: Vec<ObjectId>,
    /// Memberships whose privileges this role inherits directly.
    pub can_inherit_from: Vec<ObjectId>,
    /// Roles this role may select with `SET ROLE`. PostgreSQL 16+ can grant
    /// membership without the SET option, so this is deliberately distinct
    /// from inherited membership.
    pub can_set_role_to: Vec<ObjectId>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RoleOverlay {
    Present(RoleState),
    Dropped,
}
