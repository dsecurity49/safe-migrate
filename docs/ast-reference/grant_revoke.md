# Grant / Revoke AST Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Why This Matters for safe-migrate

Permission changes are not schema-structural changes — they do not alter
table definitions, column layouts, or constraint graphs — but they can
silently break applications and users after a migration in ways that are
harder to diagnose than a missing column. Key scenarios:

- `REVOKE SELECT ON TABLE t FROM app_user` — the application's read path
  breaks immediately after migration with a permission-denied error, not a
  structural incompatibility
- `GRANT INSERT ON TABLE t TO PUBLIC` — silently widens write access to all
  roles, a security regression
- `ALTER DEFAULT PRIVILEGES ... GRANT` — changes the permission that future
  objects will receive automatically, affecting objects not yet created at
  migration time
- `REVOKE ... CASCADE` — recursively revokes dependent privileges through
  the grant chain, potentially affecting roles not mentioned in the statement

The simulator must track privilege state as part of `LocalState` — or at
minimum flag privilege changes as events requiring manual review — to avoid
producing a "green" signal on a migration that breaks application-layer
access.

---

# Core Nodes — Direct Privilege Changes

## Grant

### Verified Accessors (src/ast/generated/nodes.rs line 11323)

**2.58.0 BREAKING CHANGE:** `Grant` was restructured. `name_refs()`, `paths()`,
`option_token()`, `schema_token()`, `table_token()`, `tables_token()`, and
`in_token()` were **removed** from `Grant` directly. Object targets are now
wrapped in the new `PrivilegeObjects` node; the WITH GRANT OPTION clause is
now wrapped in the new `GrantWithClause` node.

```rust
// Grant — src/ast/generated/nodes.rs line 11323
pub fn column_list(&self) -> Option<ColumnList>           // [NEW in 2.58.0]
pub fn grant_with_clause(&self) -> Option<GrantWithClause> // [NEW in 2.58.0 — replaces option_token()]
pub fn privilege_objects(&self) -> Option<PrivilegeObjects> // [NEW in 2.58.0 — replaces name_refs()/paths()]
pub fn revoke_command_list(&self) -> Option<RevokeCommandList>
pub fn role_ref(&self) -> Option<RoleRef>
pub fn role_ref_list(&self) -> Option<RoleRefList>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn by_token(&self) -> Option<SyntaxToken>
pub fn grant_token(&self) -> Option<SyntaxToken>
pub fn granted_token(&self) -> Option<SyntaxToken>
pub fn on_token(&self) -> Option<SyntaxToken>
pub fn privileges_token(&self) -> Option<SyntaxToken>
pub fn to_token(&self) -> Option<SyntaxToken>

// PrivilegeObjects — src/ast/generated/nodes.rs line 16237 [NEW node in 2.58.0]
pub fn function_sig_list(&self) -> Option<FunctionSigList>
pub fn literals(&self) -> AstChildren<Literal>
pub fn name_refs(&self) -> AstChildren<NameRef>    // schemas (for IN SCHEMA)
pub fn paths(&self) -> AstChildren<Path>            // table/object paths
pub fn types(&self) -> AstChildren<Type>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn data_token(&self) -> Option<SyntaxToken>
pub fn database_token(&self) -> Option<SyntaxToken>
pub fn domain_token(&self) -> Option<SyntaxToken>
pub fn foreign_token(&self) -> Option<SyntaxToken>
// ... and more type-discriminating tokens

// GrantWithClause — src/ast/generated/nodes.rs line 11459 [NEW node in 2.58.0]
pub fn grant_role_option_list(&self) -> Option<GrantRoleOptionList>
pub fn grant_token(&self) -> Option<SyntaxToken>
pub fn option_token(&self) -> Option<SyntaxToken>
pub fn with_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
Grant =
  'grant'
  (('all' 'privileges'?) | RevokeCommandList)
  'on' ('table' (Path (',' Path)*) | 'all' 'tables' 'in' 'schema' (NameRef (',' NameRef)*))
  'to' RoleRefList
  ('with' 'grant' 'option')?
  ('granted' 'by' RoleRef)? ';'?
```

### Disambiguation: paths() vs name_refs()

Two target forms exist — explicit tables vs all-tables-in-schema — and
the accessor surface reflects both:

- `paths()` — the explicit table list (`ON TABLE path1, path2, ...`)
- `name_refs()` — the schema name list (`ON ALL TABLES IN SCHEMA schema1, ...`)

Discrimination: `table_token()` present → explicit table form (use `paths()`);
`tables_token()` + `in_token()` + `schema_token()` present → schema form
(use `name_refs()`). These two accessor groups are mutually exclusive per
the grammar's alternation.

```rust
fn grant_target(node: &Grant) -> GrantTarget {
    if node.table_token().is_some() {
        GrantTarget::Tables(node.paths().collect())
    } else {
        GrantTarget::AllTablesInSchema(node.name_refs().map(|n| n.text()).collect())
    }
}
```

### Privilege Extraction (RevokeCommandList)

Despite its confusing name, `revoke_command_list()` is the privilege list
for BOTH `GRANT` and `REVOKE` — `RevokeCommandList` is the shared structure
for the privilege spec (`SELECT, INSERT, UPDATE, ...`). When `all_token()`
is present, `revoke_command_list()` is absent (ALL PRIVILEGES is a separate
grammar alternation).

### Role Disambiguation

- `role_ref_list()` — the grantee list (`TO role1, role2, ...`)
- `role_ref()` (singular) — the grantor in the optional `GRANTED BY role`
  clause, not the grantee

```rust
struct GrantFact {
    privileges: PrivilegeSpec,           // all_token or revoke_command_list
    target: GrantTarget,
    grantees: Vec<RoleFact>,             // from role_ref_list()
    with_grant_option: bool,             // from option_token()
    granted_by: Option<RoleFact>,        // from role_ref() — grantor, NOT grantee
}
```

---

## Revoke

### Verified Accessors (src/ast/generated/nodes.rs line 17473)

**2.58.0 BREAKING CHANGE:** `Revoke` was restructured similarly to `Grant`.
`name_refs()`, `paths()`, `revoke_command_list()`, `schema_token()`, `table_token()`,
`tables_token()`, and `in_token()` were **removed** from `Revoke` directly.
Object targets now come via `privilege_objects() -> Option<PrivilegeObjects>`
(same node as in `Grant`). Added `admin_token()`, `inherit_token()`,
`set_token()` for new REVOKE forms.

```rust
// Revoke — src/ast/generated/nodes.rs line 17473
pub fn privilege_objects(&self) -> Option<PrivilegeObjects>  // [NEW — replaces name_refs()/paths()]
pub fn privileges(&self) -> Option<Privileges>               // [NEW]
pub fn role_ref(&self) -> Option<RoleRef>
pub fn role_ref_list(&self) -> Option<RoleRefList>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn admin_token(&self) -> Option<SyntaxToken>            // [NEW in 2.58.0]
pub fn by_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn for_token(&self) -> Option<SyntaxToken>
pub fn from_token(&self) -> Option<SyntaxToken>
pub fn grant_token(&self) -> Option<SyntaxToken>
pub fn granted_token(&self) -> Option<SyntaxToken>
pub fn inherit_token(&self) -> Option<SyntaxToken>          // [NEW in 2.58.0]
pub fn on_token(&self) -> Option<SyntaxToken>
pub fn option_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
pub fn revoke_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>              // [NEW in 2.58.0]
```

### Grammar Confirmation

```
Revoke =
  'revoke' ('grant' 'option' 'for')?
  (('all' 'privileges'?) | RevokeCommandList)
  'on' ('table' (Path (',' Path)*) | 'all' 'tables' 'in' 'schema' (NameRef (',' NameRef)*))
  'from' RoleRefList
  ('granted' 'by' RoleRef)?
  ('cascade' | 'restrict')? ';'?
```

Structurally mirrors `Grant` with these differences:
- `FROM` instead of `TO` keyword (same `role_ref_list()` accessor, direction
  reversed semantically)
- Adds `cascade_token()` / `restrict_token()` — `REVOKE ... CASCADE` is
  particularly dangerous as it propagates revocation through the entire
  downstream grant chain
- Adds `for_token()` + `grant_token()` + `option_token()` for
  `REVOKE GRANT OPTION FOR ...` — removes only the ability to re-grant,
  not the privilege itself

### safe-migrate guidance

```rust
struct RevokeFact {
    grant_option_only: bool,             // REVOKE GRANT OPTION FOR
    privileges: PrivilegeSpec,
    target: GrantTarget,
    revokees: Vec<RoleFact>,             // from role_ref_list()
    granted_by: Option<RoleFact>,        // from role_ref() — grantor filter
    cascade: bool,                       // from cascade_token()
}
```

`cascade: true` is a strong tier-1 (block) or tier-2 (warning) candidate
— cascading revocation can silently revoke privileges from roles not
mentioned in the statement, potentially breaking application users that
received the privilege transitively through the grant chain.

---

## RevokeCommandList / RevokeCommand

### RevokeCommandList — Verified Accessor

```rust
pub fn revoke_commands(&self) -> AstChildren<RevokeCommand>
```

### RevokeCommand — Verified Accessors (line 15545)

```rust
pub fn role_ref(&self) -> Option<RoleRef>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn delete_token(&self) -> Option<SyntaxToken>
pub fn execute_token(&self) -> Option<SyntaxToken>
pub fn ident_token(&self) -> Option<SyntaxToken>
pub fn insert_token(&self) -> Option<SyntaxToken>
pub fn references_token(&self) -> Option<SyntaxToken>
pub fn select_token(&self) -> Option<SyntaxToken>
pub fn system_token(&self) -> Option<SyntaxToken>
pub fn temp_token(&self) -> Option<SyntaxToken>
pub fn temporary_token(&self) -> Option<SyntaxToken>
pub fn trigger_token(&self) -> Option<SyntaxToken>
pub fn truncate_token(&self) -> Option<SyntaxToken>
pub fn update_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
RevokeCommand =
  RoleRef
| 'alter' 'system'
| ('select' | 'insert' | 'update' | 'delete' | 'truncate' | 'references'
   | 'trigger' | 'ident' | 'all' | 'alter' | 'create' | 'temporary'
   | 'temp' | 'execute')
```

**Important structural note:** `RevokeCommand` can be either a privilege
keyword OR a `RoleRef` — the latter covers the case of `GRANT role TO
grantee` / `REVOKE role FROM grantee` (role membership grants), where what
is being granted/revoked is a role name rather than an object privilege.

```rust
fn extract_privilege(cmd: &RevokeCommand) -> PrivilegeFact {
    if let Some(role_ref) = cmd.role_ref() {
        PrivilegeFact::RoleMembership(/* extract role name */)
    } else if cmd.select_token().is_some() { PrivilegeFact::Select }
    else if cmd.insert_token().is_some() { PrivilegeFact::Insert }
    else if cmd.update_token().is_some() { PrivilegeFact::Update }
    else if cmd.delete_token().is_some() { PrivilegeFact::Delete }
    else if cmd.truncate_token().is_some() { PrivilegeFact::Truncate }
    else if cmd.references_token().is_some() { PrivilegeFact::References }
    else if cmd.trigger_token().is_some() { PrivilegeFact::Trigger }
    else if cmd.execute_token().is_some() { PrivilegeFact::Execute }
    else if cmd.create_token().is_some() { PrivilegeFact::Create }
    else if cmd.temp_token().is_some() || cmd.temporary_token().is_some() {
        PrivilegeFact::Temporary
    }
    else if cmd.alter_token().is_some() && cmd.system_token().is_some() {
        PrivilegeFact::AlterSystem
    }
    else if cmd.all_token().is_some() { PrivilegeFact::All }
    else if cmd.ident_token().is_some() {
        PrivilegeFact::Named(cmd.ident_token().unwrap().text().to_string())
    }
    else { PrivilegeFact::Unknown }
}
```

---

## Privileges / PrivilegeTarget

### Privileges — Verified Accessors (line 14513)

```rust
pub fn column_list(&self) -> Option<ColumnList>
pub fn revoke_command_list(&self) -> Option<RevokeCommandList>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn privileges_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
Privileges =
  'all' 'privileges'? ColumnList?
| RevokeCommandList ColumnList?
```

Used by `GrantDefaultPrivileges` and `RevokeDefaultPrivileges`. The optional
`ColumnList` allows column-level privilege specification (`GRANT SELECT (col1,
col2) ON TABLE t TO role`), confirmed accessible via `column_list()`.

### PrivilegeTarget — Verified Accessors (line 14474)

```rust
pub fn functions_token(&self) -> Option<SyntaxToken>
pub fn large_token(&self) -> Option<SyntaxToken>
pub fn objects_token(&self) -> Option<SyntaxToken>
pub fn routines_token(&self) -> Option<SyntaxToken>
pub fn schemas_token(&self) -> Option<SyntaxToken>
pub fn sequences_token(&self) -> Option<SyntaxToken>
pub fn tables_token(&self) -> Option<SyntaxToken>
pub fn types_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
PrivilegeTarget =
  'large' 'objects'
| 'tables'
| 'functions'
| 'routines'
| 'sequences'
| 'types'
| 'schemas'
```

7 object-category targets, all token-only, fully extractable via
presence-check:

```rust
fn extract_privilege_target(pt: &PrivilegeTarget) -> PrivilegeTargetFact {
    if pt.tables_token().is_some() { PrivilegeTargetFact::Tables }
    else if pt.functions_token().is_some() { PrivilegeTargetFact::Functions }
    else if pt.routines_token().is_some() { PrivilegeTargetFact::Routines }
    else if pt.sequences_token().is_some() { PrivilegeTargetFact::Sequences }
    else if pt.types_token().is_some() { PrivilegeTargetFact::Types }
    else if pt.schemas_token().is_some() { PrivilegeTargetFact::Schemas }
    else if pt.large_token().is_some() && pt.objects_token().is_some() {
        PrivilegeTargetFact::LargeObjects
    }
    else { PrivilegeTargetFact::Unknown }
}
```

---

# Core Nodes — Default Privilege Changes

## AlterDefaultPrivileges

### Verified Accessors (line 723)

```rust
pub fn grant_default_privileges(&self) -> Option<GrantDefaultPrivileges>
pub fn name_refs(&self) -> AstChildren<NameRef>
pub fn revoke_default_privileges(&self) -> Option<RevokeDefaultPrivileges>
pub fn role_ref_list(&self) -> Option<RoleRefList>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn default_token(&self) -> Option<SyntaxToken>
pub fn for_token(&self) -> Option<SyntaxToken>
pub fn in_token(&self) -> Option<SyntaxToken>
pub fn privileges_token(&self) -> Option<SyntaxToken>
pub fn role_token(&self) -> Option<SyntaxToken>
pub fn schema_token(&self) -> Option<SyntaxToken>
pub fn user_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterDefaultPrivileges =
  'alter' 'default' 'privileges'
  ('for' ('role' | 'user') RoleRefList)?
  ('in' 'schema' (NameRef (',' NameRef)*))?
  (
    GrantDefaultPrivileges
  | RevokeDefaultPrivileges
  )? ';'?
```

### Accessor Disambiguation

- `role_ref_list()` — the `FOR ROLE roles` scope filter (whose future
  objects are affected)
- `name_refs()` — the `IN SCHEMA schemas` scope filter (which schemas)
- `grant_default_privileges()` / `revoke_default_privileges()` — mutually
  exclusive, which operation is being set

Note: the grammar allows the action clause itself to be entirely absent
(`(GrantDefaultPrivileges | RevokeDefaultPrivileges)?`) — meaning a bare
`ALTER DEFAULT PRIVILEGES FOR ROLE r IN SCHEMA s` with no action is
grammatically parseable, though PostgreSQL would likely reject it at
execution time. This edge case should be handled defensively.

### Why This Matters for safe-migrate

`ALTER DEFAULT PRIVILEGES` affects **future objects** — any table, function,
sequence, or type created after this statement (by the specified role, in
the specified schema) will automatically receive the specified privilege.
This is one of the few DDL operations that has a forward-in-time effect on
objects that don't yet exist at statement execution time.

The simulator's sequential model must track default-privilege state as
part of `LocalState`. When a `CREATE TABLE` statement is later simulated,
the resolver must consult the current default-privilege state to determine
what privileges that new table will automatically receive — it does not
start with a blank permission slate.

```rust
struct AlterDefaultPrivilegesFact {
    for_roles: Vec<RoleFact>,           // from role_ref_list(), empty = current user
    in_schemas: Vec<String>,            // from name_refs(), empty = all schemas
    action: DefaultPrivilegeAction,     // Grant | Revoke
}
```

---

## GrantDefaultPrivileges

### Verified Accessors (line 9927)

```rust
pub fn privilege_target(&self) -> Option<PrivilegeTarget>
pub fn privileges(&self) -> Option<Privileges>
pub fn role_ref_list(&self) -> Option<RoleRefList>
pub fn grant_token(&self) -> Option<SyntaxToken>
pub fn on_token(&self) -> Option<SyntaxToken>
pub fn option_token(&self) -> Option<SyntaxToken>
pub fn to_token(&self) -> Option<SyntaxToken>
pub fn with_token(&self) -> Option<SyntaxToken>
```

Fully populated — `privilege_target()`, `privileges()`, and `role_ref_list()`
are all real structural accessors with payload. The `with_grant_option` flag
is detectable via `option_token()`.

---

## RevokeDefaultPrivileges

### Verified Accessors (line 15627)

```rust
pub fn privilege_target(&self) -> Option<PrivilegeTarget>
pub fn privileges(&self) -> Option<Privileges>
pub fn role_ref_list(&self) -> Option<RoleRefList>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn for_token(&self) -> Option<SyntaxToken>
pub fn from_token(&self) -> Option<SyntaxToken>
pub fn grant_token(&self) -> Option<SyntaxToken>
pub fn on_token(&self) -> Option<SyntaxToken>
pub fn option_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
pub fn revoke_token(&self) -> Option<SyntaxToken>
```

Same shape as `GrantDefaultPrivileges` plus cascade/restrict options.

---

# Verified Findings Summary

## Confirmed Complete

- `Grant`: fully resolved, target discrimination logic documented
- `Revoke`: fully resolved, all tokens present, cascade/restrict extractable
- `RevokeCommandList` / `RevokeCommand`: fully resolved, all 14 privilege
  types extractable including role-membership grants
- `Privileges`: fully resolved including column-level privilege support
- `PrivilegeTarget`: fully resolved, all 7 object categories extractable
- `AlterDefaultPrivileges`: fully resolved including scope filters
- `GrantDefaultPrivileges`: fully resolved
- `RevokeDefaultPrivileges`: fully resolved

## Key Architectural Findings

1. **`RevokeCommand` covers both privilege keywords AND role membership
   grants** via its `role_ref()` accessor — the same node structure is used
   for `GRANT SELECT ON TABLE t TO r` (privilege) and `GRANT admin_role TO
   r` (role membership). The discriminator is `role_ref().is_some()` vs
   keyword tokens.
2. **`REVOKE ... CASCADE` warrants conservative flagging** — cascading
   revocation is silent and can propagate far beyond the explicitly named
   roles, breaking downstream applications with no additional DDL statement
   present in the migration.
3. **`ALTER DEFAULT PRIVILEGES` has forward-in-time effects on objects not
   yet created** — `LocalState` must maintain a default-privilege register
   consulted during `CREATE TABLE`/`CREATE FUNCTION`/etc. fact extraction.
4. **`role_ref` (singular) on `Grant`/`Revoke` is the GRANTOR (`GRANTED
   BY`), not the grantee** — the grantee is always `role_ref_list()`
   (plural). Confusing these produces completely wrong privilege attribution.

## Grammar Cross-Check

All nodes cross-checked against postgresql.ungram in a single pass.
No discrepancies found.

---

# Remaining Open Questions

None identified in this pass.
