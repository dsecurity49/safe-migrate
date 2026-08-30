use crate::ast::identifiers::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    Maintain,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivilegeGrant {
    pub on: ObjectId,               // table/schema/database the grant targets
    pub privileges: Vec<Privilege>, // SELECT, INSERT, UPDATE, DELETE, ALL, etc.
    pub grantee: ObjectId,          // the role receiving it
    pub with_grant_option: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleState {
    pub id: ObjectId, // role name, no schema
    pub can_login: bool,
    pub is_superuser: bool,
    pub member_of: Vec<ObjectId>, // roles this role is a member of
    /// Roles this role may select with `SET ROLE`. PostgreSQL 16+ can grant
    /// membership without the SET option, so this is deliberately distinct
    /// from inherited membership.
    pub can_set_role_to: Vec<ObjectId>,
    pub granted_privileges: Vec<PrivilegeGrant>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RoleOverlay {
    Present(RoleState),
    Dropped,
}
