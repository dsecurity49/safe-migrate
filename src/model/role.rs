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
    pub member_of: Vec<ObjectId>, // roles this role inherits from
    pub granted_privileges: Vec<PrivilegeGrant>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RoleOverlay {
    Present(RoleState),
    Dropped,
}
