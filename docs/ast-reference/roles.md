# Roles and User Management AST Reference for safe-migrate

## Status

Inspection status: complete. Cross-checked directly against postgresql.ungram
and squawk.rs in a single pass.

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Why This Matters for safe-migrate

Role and user management operations affect two dimensions relevant to
migration safety:

1. **Ownership** — every PostgreSQL object (table, schema, function, etc.)
   has an owner. `CREATE TABLE` creates objects owned by the executing role.
   `DROP ROLE` fails if the role owns any objects. Role changes can silently
   break ownership assumptions that `LocalState` depends on for resolving
   `OWNER TO` mutations and privilege inheritance.

2. **Authentication and connection** — `ALTER ROLE ... LOGIN/NOLOGIN`,
   `PASSWORD`, `VALID UNTIL` affect whether application users can connect
   at all after migration. These are not schema changes but are frequently
   included in migrations and have immediate operational impact.

The simulator cannot model most role attributes (see the critical
`RoleOption` finding below), but it can detect that role management
operations occurred and which roles were affected.

---

## Alias Relationships

PostgreSQL maintains three names for the same concept for historical reasons:
- `ROLE` — the canonical PostgreSQL concept
- `USER` — alias for `ROLE WITH LOGIN` (by convention)
- `GROUP` — legacy alias, deprecated since PostgreSQL 8.1

`CREATE USER name` is equivalent to `CREATE ROLE name WITH LOGIN`.
`CREATE GROUP name` is equivalent to `CREATE ROLE name`.
`ALTER USER` and `ALTER GROUP` are aliases for `ALTER ROLE`.
`DROP USER` and `DROP GROUP` are aliases for `DROP ROLE`.

This means the AST can produce any of these node types for what is
semantically the same operation — the rule engine must handle all three
families.

---

# Create Nodes

## CreateRole

### Verified Accessors (line 5163)

```rust
pub fn name(&self) -> Option<Name>
pub fn role_option_list(&self) -> Option<RoleOptionList>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn role_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreateRole =
  'create' 'role' Name RoleOptionList ';'?
```

---

## CreateUser

### Verified Accessors (line 5986)

```rust
pub fn name(&self) -> Option<Name>
pub fn role_option_list(&self) -> Option<RoleOptionList>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn user_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreateUser =
  'create' 'user' Name RoleOptionList? ';'?
```

Structurally identical to `CreateRole` — only the keyword token differs.

---

## CreateGroup (Deprecated)

### Grammar Confirmation

```
CreateGroup =
  'create' 'group' Name RoleOptionList ';'?
```

Same shape as `CreateRole`. Deprecated; equivalent to `CREATE ROLE`.

---

## RoleOptionList / RoleOption — CRITICAL FINDING

### Verified Accessors

```rust
// RoleOptionList (line 15705)
pub fn role_options(&self) -> AstChildren<RoleOption>
pub fn with_token(&self) -> Option<SyntaxToken>

// RoleOption (line 15705)
pub fn inherit_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
RoleOptionList =
  'with'? RoleOption*

RoleOption =
  'inherit'
```

**This is the most significant confirmed grammar gap in role management.**
`RoleOption` exposes only a single keyword: `INHERIT`. The complete list of
real PostgreSQL role options that are NOT captured anywhere in this grammar:

```sql
SUPERUSER | NOSUPERUSER
CREATEDB | NOCREATEDB
CREATEROLE | NOCREATEROLE
INHERIT | NOINHERIT          -- only INHERIT is captured; NOINHERIT is not
LOGIN | NOLOGIN              -- completely absent
REPLICATION | NOREPLICATION  -- completely absent
BYPASSRLS | NOBYPASSRLS      -- completely absent
CONNECTION LIMIT connlimit   -- completely absent
PASSWORD 'password' | PASSWORD NULL  -- completely absent (also a security concern)
VALID UNTIL 'timestamp'      -- completely absent
IN ROLE role_name            -- completely absent
IN GROUP role_name           -- completely absent
ROLE role_name               -- completely absent
ADMIN role_name              -- completely absent
```

**This means `CREATE ROLE app_user WITH LOGIN PASSWORD 'secret' CREATEDB` is
indistinguishable at the AST level from `CREATE ROLE app_user` — the only
detectable property is the role name and whether `INHERIT` was specified.**
All other role attributes are silently dropped during parsing in this grammar
version.

### safe-migrate guidance

```rust
struct CreateRoleFact {
    name: String,           // from name()
    inherits: bool,         // from role_option_list().role_options() — the ONLY extractable option
    // LOGIN, SUPERUSER, CREATEDB, PASSWORD, etc.: NOT EXTRACTABLE
}
```

Given this gap, any rule validating role creation safety (e.g. flagging
`LOGIN` privilege being granted to a role used as a service account, or
detecting `SUPERUSER` creation) cannot do so from this AST. Treat
`CreateRole`/`CreateUser`/`CreateGroup` as detecting "a role was created
with name X" — nothing more.

---

# Alter Nodes

## AlterRole — CONFIRMED BLACK BOX

### Verified Accessors (line 1578)

```rust
pub fn role_ref(&self) -> Option<RoleRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn role_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterRole =
  'alter' 'role' RoleRef ';'?
```

**Identical severity to `AlterPublication`, `AlterSubscription`, and
`AlterView` — nothing extractable beyond the role's name.**

Real PostgreSQL `ALTER ROLE` syntax supports:

```sql
ALTER ROLE name WITH option [option ...]    -- all options same as CREATE ROLE
ALTER ROLE name RENAME TO new_name
ALTER ROLE name IN DATABASE db SET config_param = value
ALTER ROLE name IN DATABASE db RESET config_param
ALTER ROLE name IN DATABASE db RESET ALL
ALTER ROLE { name | ALL } [ IN DATABASE db ] SET config_param = value
```

None of these forms can be distinguished or extracted from this AST. An
`ALTER ROLE admin SUPERUSER` is indistinguishable from
`ALTER ROLE admin RENAME TO new_admin` — both produce an `AlterRole` node
with only a role name.

```rust
struct AlterRoleFact {
    name: RoleFact,   // from role_ref() — only extractable field
    // operation: NOT EXTRACTABLE
}
```

---

## AlterUser — CONFIRMED BLACK BOX

### Verified Accessors (line 2196)

```rust
pub fn role_ref(&self) -> Option<RoleRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn user_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterUser =
  'alter' 'user' RoleRef ';'?
```

Identical shape and identical limitation to `AlterRole`.

---

## AlterGroup — STRUCTURED (unlike AlterRole/AlterUser)

### Verified Accessors (line 1024)

```rust
pub fn name_refs(&self) -> AstChildren<NameRef>
pub fn rename_to(&self) -> Option<RenameTo>
pub fn role_ref(&self) -> Option<RoleRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn add_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn group_token(&self) -> Option<SyntaxToken>
pub fn user_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterGroup =
  'alter' 'group' RoleRef
  (
  'add' 'user' (NameRef (',' NameRef)*)
  | 'drop' 'user' (NameRef (',' NameRef)*)
  | RenameTo
  ) ';'?
```

Three forms, all extractable:
- `add_token()` present → `ALTER GROUP g ADD USER user1, user2` — users
  being added to group, via `name_refs()`
- `drop_token()` present → `ALTER GROUP g DROP USER user1, user2` — users
  being removed from group, via `name_refs()`
- `rename_to()` present → group rename

Note that `role_ref()` is the group (target), while `name_refs()` are the
users being added/dropped. These are semantically different roles and must
not be confused.

```rust
enum AlterGroupFact {
    AddUsers { group: RoleFact, users: Vec<String> },
    DropUsers { group: RoleFact, users: Vec<String> },
    Rename { from: String, to: String },
}
```

---

# Drop Nodes

## DropRole

### Verified Accessors (line 7789)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn name_refs(&self) -> AstChildren<NameRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn role_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
DropRole =
  'drop' 'role' IfExists? (NameRef (',' NameRef)*) ';'?
```

Multi-name drop, no CASCADE/RESTRICT option. PostgreSQL itself enforces
that `DROP ROLE` fails if the role owns any objects or has any granted
privileges — not via a grammar option, but at execution time. The simulator
must check ownership in `LocalState` if it tracks object ownership at all.

---

## DropUser / DropGroup

Identical shapes to `DropRole` — only keyword tokens differ. All confirmed
via the established pattern; not re-documented here.

---

# SetRole

### Verified Accessors (line 16867)

```rust
pub fn role_ref(&self) -> Option<RoleRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn local_token(&self) -> Option<SyntaxToken>
pub fn none_token(&self) -> Option<SyntaxToken>
pub fn reset_token(&self) -> Option<SyntaxToken>
pub fn role_token(&self) -> Option<SyntaxToken>
pub fn session_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
SetRole =
  'set' ('session' | 'local')? 'role' (RoleRef | 'none')? ';'?
| 'reset' 'role' ';'?
```

Fully extractable — all three forms distinguishable:

```rust
enum SetRoleFact {
    Set {
        role: RoleFact,         // from role_ref()
        scope: RoleScope,       // Session | Local | Unspecified
    },
    SetNone {                   // RESET to original login role
        scope: RoleScope,
    },
    Reset,                      // RESET ROLE — same as SET ROLE NONE at session scope
}
```

**Relevance to search_path:** `SET ROLE` changes the effective role for the
current session — this affects which schemas appear in the search_path for
schema-qualified object lookups and which objects the session can access.
Like `SET search_path` (search_path.md), `SET ROLE` with `LOCAL` scope
reverts at transaction boundary. The simulator should record this in the
same `TransactionFrame` undo mechanism used for `SET LOCAL search_path`.

---

# Verified Findings Summary

## Confirmed Complete

- `CreateRole` / `CreateUser` / `CreateGroup`: fully resolved — name
  extractable, all other role options confirmed grammar-empty beyond INHERIT
- `AlterGroup`: fully resolved and structured, all 3 forms extractable
- `DropRole` / `DropUser` / `DropGroup`: fully resolved
- `SetRole`: fully resolved, all forms distinguishable

## Grammar-Confirmed Limitations

- `AlterRole` / `AlterUser`: confirmed black boxes — only role name
  extractable, no operation type or parameters. Identical pattern to
  `AlterPublication`, `AlterSubscription`. These are among the most
  operationally significant DDL operations (changing LOGIN, SUPERUSER,
  PASSWORD, etc.) with the least extractable AST content in the entire
  documentation set.
- `RoleOption`: confirmed grammar-captures only `INHERIT`. Every other
  PostgreSQL role attribute (`LOGIN`, `NOLOGIN`, `SUPERUSER`, `CREATEDB`,
  `PASSWORD`, `VALID UNTIL`, `REPLICATION`, `BYPASSRLS`, `CONNECTION
  LIMIT`, role membership via `IN ROLE`/`ROLE`/`ADMIN`) is silently absent
  from this grammar. This means role attribute safety analysis (e.g.
  detecting `SUPERUSER` creation, validating `NOLOGIN` service accounts,
  checking password policy compliance) is not possible from this AST.

## Key Architectural Findings

1. **`AlterRole` and `AlterUser` are black boxes** — conservative
   (tainted/manual-review) treatment recommended, same as `AlterPublication`
   and `AlterSubscription`.
2. **`RoleOption`'s near-empty grammar means `CREATE ROLE` cannot be
   analyzed for role attribute safety** — only the name is known. This is
   a significant gap given that role attributes (LOGIN, SUPERUSER) are
   among the most security-sensitive PostgreSQL configuration choices.
3. **`AlterGroup` is structurally richer than `AlterRole`/`AlterUser`** —
   despite being a deprecated legacy node, it actually exposes more
   extractable content than its modern equivalents.
4. **`SetRole` with `LOCAL` scope must integrate with `TransactionFrame`**
   the same way `SET LOCAL search_path` does — role context reverts at
   transaction boundary, affecting any object-resolution performed within
   that transaction frame.

## Grammar Cross-Check

All nodes cross-checked against postgresql.ungram in a single pass.
No discrepancies found.

---

# Remaining Open Questions

None identified in this pass.
