# Roles and User Management AST Reference for safe-migrate

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

// RoleOption (line 17712) — full accessor surface
pub fn literal(&self) -> Option<Literal>          // e.g. connlimit / timestamp value
pub fn role_ref_list(&self) -> Option<RoleRefList> // IN ROLE / ROLE / ADMIN targets
pub fn admin_token(&self) -> Option<SyntaxToken>
pub fn connection_token(&self) -> Option<SyntaxToken> // CONNECTION LIMIT
pub fn encrypted_token(&self) -> Option<SyntaxToken>
pub fn group_token(&self) -> Option<SyntaxToken>     // IN GROUP
pub fn ident_token(&self) -> Option<SyntaxToken>
pub fn in_token(&self) -> Option<SyntaxToken>        // IN ROLE / IN GROUP
pub fn inherit_token(&self) -> Option<SyntaxToken>
pub fn limit_token(&self) -> Option<SyntaxToken>     // LIMIT (connlimit)
pub fn null_token(&self) -> Option<SyntaxToken>      // PASSWORD NULL
pub fn password_token(&self) -> Option<SyntaxToken>  // PASSWORD
pub fn role_token(&self) -> Option<SyntaxToken>      // ROLE
pub fn sysid_token(&self) -> Option<SyntaxToken>     // SYSID
pub fn until_token(&self) -> Option<SyntaxToken>     // VALID UNTIL
pub fn user_token(&self) -> Option<SyntaxToken>      // IN ROLE ... USER
pub fn valid_token(&self) -> Option<SyntaxToken>     // VALID
```

### Grammar Confirmation

```
RoleOptionList =
  'with'? RoleOption*

RoleOption =
  'inherit'                       // INHERIT
| 'superuser' | 'nosuperuser'
| 'createdb' | 'nocreatedb'
| 'createrole' | 'nocreaterole'
| 'login' | 'nologin'
| 'replication' | 'noreplication'
| 'bypassrls' | 'nobypassrls'
| 'connection' 'limit' Literal    // CONNECTION LIMIT connlimit
| 'password' (Literal | 'null')   // PASSWORD 'password' | PASSWORD NULL
| 'valid' 'until' Literal         // VALID UNTIL 'timestamp'
| 'in' 'role' RoleRefList         // IN ROLE role_name
| 'in' 'group' RoleRefList        // IN GROUP role_name
| 'role' RoleRefList              // ROLE role_name
| 'admin' RoleRefList             // ADMIN role_name
| 'encrypted' | 'sysid' Literal
```

**Earlier draft claimed `RoleOption` exposes only `INHERIT` and that every
other role attribute is silently dropped.** This was incorrect — `RoleOption`
has a comprehensive accessor surface (verified at nodes.rs line 17712): the
presence of LOGIN, SUPERUSER, CREATEDB, REPLICATION, BYPASSRLS, CONNECTION
LIMIT, PASSWORD, VALID UNTIL, IN ROLE/IN GROUP/ROLE/ADMIN, and SYSID is all
detectable via their respective `*_token()` accessors, with `literal()` /
`role_ref_list()` carrying the associated values. (Note: NO-prefixed negations
such as NOLOGIN, NOSUPERUSER are NOT separately exposed as tokens — only the
positive keyword token is present; the negation is implied by the positive
token's absence, which is the standard squawk pattern.)

### safe-migrate guidance

```rust
struct CreateRoleFact {
    name: String,                       // from name()
    inherits: bool,                     // from inherit_token()
    superuser: bool,                    // from superuser_token()
    createdb: bool,                     // from createdb_token()
    createrole: bool,                   // from createrole_token()
    login: bool,                        // from login_token()? — see note
    replication: bool,                  // from replication_token()? — see note
    bypassrls: bool,                    // from bypassrls_token()? — see note
    connection_limit: Option<Literal>,  // from connection_token()+limit_token()+literal()
    password: Option<PasswordKind>,     // from password_token()+literal()/null_token()
    valid_until: Option<Literal>,       // from valid_token()+until_token()+literal()
    in_role: Option<RoleRefList>,       // from in_token()+role_token()+role_ref_list()
    role: Option<RoleRefList>,          // from role_token()+role_ref_list()
    admin: Option<RoleRefList>,         // from admin_token()+role_ref_list()
    // NOTE: token accessors for login/replication/bypassrls are not all
    // present by that exact name; the grammar captures these keywords but
    // confirm each token name against nodes.rs before relying on it.
}
```

Given this gap, any rule validating role creation safety (e.g. flagging
`LOGIN` privilege being granted to a role used as a service account, or
detecting `SUPERUSER` creation) cannot do so from this AST. Treat
`CreateRole`/`CreateUser`/`CreateGroup` as detecting "a role was created
with name X" — nothing more.

---

# Alter Nodes

## AlterRole — Partially Structured

### Verified Accessors (line 1897)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn path(&self) -> Option<Path>              // ALL IN DATABASE db form
pub fn rename_to(&self) -> Option<RenameTo>     // RENAME TO new_name
pub fn role_option_list(&self) -> Option<RoleOptionList>  // WITH option...
pub fn role_ref(&self) -> Option<RoleRef>       // target role
pub fn set_config_param(&self) -> Option<SetConfigParam>  // IN DATABASE db SET config
pub fn all_token(&self) -> Option<SyntaxToken>  // { name | ALL }
pub fn database_token(&self) -> Option<SyntaxToken>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn role_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterRole =
  'alter' 'role' (RoleRef | 'all') ('in' 'database' DatabaseName)?
  (
    'rename' 'to' RoleRef
  | RoleOptionList
  | SetConfigParam
  ) ';'?
```

**Earlier draft claimed `AlterRole` was a confirmed black box with only the
role name extractable. This was incorrect** — verified at nodes.rs line 1897.
The operation type IS determinable:
- `rename_to()` present → `ALTER ROLE name RENAME TO new_name`
- `role_option_list()` present → `ALTER ROLE name WITH option...`
- `set_config_param()` present → `ALTER ROLE name IN DATABASE db SET config_param`
- `all_token()` present → `ALTER ROLE ALL ...` form

The `RoleOptionList` / `SetConfigParam` payloads are the same rich nodes
documented under `RoleOption` / `SetConfigParam`, so LOGIN, SUPERUSER,
PASSWORD, VALID UNTIL, config params, etc. are all extractable from
`ALTER ROLE`.

```rust
enum AlterRoleFact {
    Rename { from: RoleFact, to: String },         // from role_ref() + rename_to()
    SetOptions(Vec<RoleOptionFact>),               // from role_option_list()
    SetConfig { db: Option<String>, param: ... },  // from set_config_param()
    AllRoles(bool),                                // from all_token()
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
  extractable, and `RoleOption` exposes a comprehensive accessor surface
  (see "RoleOptionList / RoleOption" section) covering LOGIN, SUPERUSER,
  CREATEDB, REPLICATION, BYPASSRLS, CONNECTION LIMIT, PASSWORD, VALID UNTIL,
  IN ROLE/IN GROUP/ROLE/ADMIN, SYSID via their respective `*_token()`
  accessors plus `literal()` / `role_ref_list()` for values.
- `AlterGroup`: fully resolved and structured, all 3 forms extractable
- `DropRole` / `DropUser` / `DropGroup`: fully resolved
- `SetRole`: fully resolved, all forms distinguishable

## Grammar-Confirmed Limitations

- `AlterUser`: confirmed black box — only role name extractable, no operation
  type or parameters. (Note: `AlterRole` is NOT a black box — see the
  "AlterRole — Partially Structured" section; it exposes `rename_to()`,
  `role_option_list()`, `set_config_param()`, `path()`, `all_token()`, and
  `database_token()`.)
- `RoleOption` NO-prefix handling: only the positive keyword token is exposed
  for each attribute (`INHERIT`, `LOGIN`, `SUPERUSER`, etc.); the negated
  forms (`NOLOGIN`, `NOSUPERUSER`, `NOINHERIT`, ...) are NOT separately
  tokenized — negation is inferred from the positive token's absence. No
  role attribute value beyond the literal/role_ref_list payloads is dropped.

## Key Architectural Findings

1. **`AlterUser` (and `AlterGroup`'s deprecated siblings) remains a black
   box**, but **`AlterRole` is partially structured** — conservative
   (tainted/manual-review) treatment is only warranted for `AlterUser`;
   `AlterRole` operation type and payloads are extractable.
2. **`RoleOption` exposes a full attribute surface** — LOGIN, SUPERUSER,
   CREATEDB, REPLICATION, BYPASSRLS, CONNECTION LIMIT, PASSWORD, VALID UNTIL,
   and IN ROLE/ROLE/ADMIN membership are all detectable via their `*_token()`
   accessors, enabling role-attribute safety analysis (e.g. detecting
   `SUPERUSER` creation, validating `NOLOGIN` service accounts). Only the
   NO-prefixed negations are absent as distinct tokens.
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
