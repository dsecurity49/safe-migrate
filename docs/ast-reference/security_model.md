# Security Model Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

---

## Scope

This document addresses a specific subset of safe-migrate's concern space:

**"How should the simulator treat mutations that affect access control,
privilege state, role context, or authentication — rather than purely
structural schema changes?"**

These operations share a common characteristic: they can silently break
applications or introduce security regressions without changing any table,
column, constraint, or index. They require different handling in the
confidence model than structural DDL.

This document does NOT cover:
- The structural schema safety rules (see individual AST reference files)
- The full `Confidence` model mechanics (see architecture phase)
- PostgreSQL's full RBAC semantics (those are PostgreSQL documentation, not
  safe-migrate AST documentation)

---

## Two Orthogonal Risk Axes

All operations in safe-migrate's rule engine should be classified on two
independent axes:

### Axis 1: Structural Schema Risk
Does this change the schema in a way that breaks existing queries, data, or
constraints?
- `DROP COLUMN` — high structural risk
- `ADD COLUMN NOT NULL` — medium structural risk (requires default)
- `CREATE INDEX` — low structural risk
- `GRANT SELECT` — zero structural risk

### Axis 2: Access Control / Security Risk
Does this change who can access or modify what?
- `REVOKE SELECT ON TABLE t FROM app_user` — high access-control risk
- `ALTER ROLE admin SUPERUSER` — extremely high security risk
- `GRANT SELECT ON TABLE t TO PUBLIC` — medium access-control risk (widens)
- `DROP TABLE t` — zero access-control risk (structural only)

**These axes are independent.** A migration can be structurally safe but
access-control dangerous (`REVOKE ... CASCADE`), or structurally dangerous
but access-control neutral (`DROP COLUMN`). Safe-migrate must evaluate and
report both axes separately rather than collapsing everything into a single
tier.

---

## Confidence Taint Sources — Privilege and Auth

The following AST-verified operations should trigger `Confidence::Tainted`
on affected objects or the overall migration, because the simulator cannot
fully determine their effect:

### 1. AlterRole / AlterUser — Mixed Capability (roles.md)

```
AlterRole = 'alter' 'role' (RoleRef | 'all') ('in' 'database' DatabaseName)?
            ( 'rename' 'to' RoleRef | RoleOptionList | SetConfigParam ) ';'?
AlterUser  = 'alter' 'user' RoleRef ';'?   -- still a black box
```

**`AlterRole` is partially structured** (verified at nodes.rs line 1897): it
exposes `rename_to()`, `role_option_list()`, `set_config_param()`, `path()`,
`all_token()`, and `database_token()`. The operation type and payload ARE
determinable — `ALTER ROLE x RENAME TO y`, `ALTER ROLE x WITH LOGIN/SUPERUSER/
PASSWORD ...`, and `ALTER ROLE x IN DATABASE db SET config` are all
distinguishable, and the `RoleOptionList`/`SetConfigParam` payloads carry the
same rich attribute surface as `CREATE ROLE`. (`AlterUser` remains a true
black box — only the role name is extractable.)

For `AlterRole`, safe-migrate CAN know whether a login-capable role changed
password, gained SUPERUSER, or was renamed. For `AlterUser`, the operation
(granting SUPERUSER, changing PASSWORD, setting NOLOGIN) cannot be determined
and the simulator cannot know whether a login-capable role became unable to
connect or gained dangerous privileges — `AlterUser` should be treated as
`Confidence::Tainted`.

**Taint scope:** the named role and any objects owned by or accessible to
that role should be considered "potentially affected" with no further
specificity possible.

### 2. Session-Dependent Role References (schemas.md)

```rust
RoleFact::CurrentRole     // session-dependent, unresolvable statically
RoleFact::CurrentUser     // session-dependent, unresolvable statically
RoleFact::SessionUser     // session-dependent, unresolvable statically
```

Any `GRANT`, `REVOKE`, `CREATE SCHEMA AUTHORIZATION`, or other operation
targeting `CURRENT_USER`/`CURRENT_ROLE`/`SESSION_USER` cannot be
statically resolved to a concrete role. The simulator does not know the
executing role's identity.

**Taint scope:** the statement's privilege target becomes opaque.

### 3. SetConfigParam Value Gap (database.md, search_path.md)

`ALTER DATABASE db SET param = value` — param name extractable, value is
not. When the param is `search_path`, this means the new search_path for
all future connections to `db` is unknown.

**Taint scope:** `Confidence::Tainted` for any subsequent object resolution
that might depend on search_path if this statement targets the current
database.

### 4. SetRole / SET LOCAL ROLE (roles.md, transactions.md)

`SET ROLE name` changes the effective role for the current session. With
`LOCAL` scope, this reverts at transaction boundary. This changes which
objects the simulator's effective "actor" can access — but since the
simulator does not model a live PostgreSQL session, it cannot follow the
implications of role switching fully.

**Taint scope:** the effective-role context within the current
`TransactionFrame` should be noted as having changed. If the simulator
ever evaluates ownership-dependent rules (e.g. "can the current role
execute this DDL?"), it must use the overridden role during this frame.

### 5. SECURITY DEFINER Functions (functions.md)

`CREATE FUNCTION f() ... SECURITY DEFINER` causes the function to execute
with its owner's privileges, not the caller's. This is a privilege
escalation vector when combined with unqualified names in the function body
(allowing search_path manipulation attacks), or when the function owner has
elevated privileges.

The `SecurityFuncOption` accessor from functions.md:
```rust
// Detected via security_token() + definer_token() in FuncOption
```

**Taint scope:** any `SECURITY DEFINER` function should be flagged as a
privilege-escalation-relevant object requiring manual review of its body
(which the AST cannot analyze unless it uses `BEGIN ATOMIC` — see
functions.md's architectural finding).

---

## Privilege State Model

### What the Simulator CAN Track

Based on the verified AST surface in grant_revoke.md:

```rust
struct PrivilegeState {
    // Per-table privilege grants, tracked per-role
    table_grants: HashMap<ObjectId, HashMap<RoleFact, Vec<PrivilegeFact>>>,
    // Default privilege rules, tracked by (for_role, in_schema) scope
    default_privileges: Vec<DefaultPrivilegeRule>,
}

struct DefaultPrivilegeRule {
    for_roles: Vec<RoleFact>,        // empty = current user
    in_schemas: Vec<String>,          // empty = all schemas
    action: DefaultPrivilegeAction,   // Grant | Revoke
    target: PrivilegeTargetFact,
    privileges: PrivilegeSpec,
    grantees: Vec<RoleFact>,
}
```

### What the Simulator CANNOT Track

Due to confirmed grammar gaps:

- **Role attributes** (`LOGIN`, `SUPERUSER`, `CREATEDB`, etc.) — not
  captured, see roles.md. The privilege state model cannot know which roles
  have login access, superuser rights, etc.
- **ALTER ROLE operations** — the change being made is unknown, so
  `PrivilegeState` cannot be updated correctly when `AlterUser` is
  encountered. Can only record "this role was modified, state is tainted."
- **REVOKE CASCADE downstream effects** — the grammar exposes `cascade_token()`
  on `Revoke` but cannot enumerate which downstream roles lose privileges
  as a result. Only the explicitly named revokees are visible.
- **Column-level privilege details** — `Privileges.column_list()` exists
  (grant_revoke.md) but column-level privilege tracking is a significant
  additional model complexity that may be out of scope for v0.5.0.

---

## OWNER TO — Ownership Transfer

`OWNER TO` is a cross-cutting node appearing in `AlterTable`, `AlterSchema`,
`AlterFunction`, `AlterDatabase`, `AlterSequence`, `AlterView`,
`AlterMaterializedView`, `AlterDomain`, `AlterType`, and many others.

All share the same accessor:
```rust
pub fn owner_to(&self) -> Option<OwnerTo>
// OwnerTo:
pub fn role_ref(&self) -> Option<RoleRef>
```

**Ownership relevance for safe-migrate:**

1. **DROP ROLE prerequisite** — `DROP ROLE` fails if the role owns any
   objects. If `LocalState` tracks object ownership (via `ObjectId` →
   `owner: RoleFact`), it can detect when a migration drops a role that
   still owns objects in the current schema state.

2. **DEFAULT PRIVILEGES inheritance** — objects are created owned by the
   executing role, which affects which `ALTER DEFAULT PRIVILEGES FOR ROLE`
   rules apply to them (grant_revoke.md).

3. **SECURITY DEFINER functions** — the owner's privileges determine what
   the function can do at execution time.

**Ownership tracking model:**

```rust
// In LocalState or AnalysisState
object_owners: HashMap<ObjectId, RoleFact>,
```

Updated on every `OWNER TO` mutation. When a `DROP ROLE` is encountered,
the simulator should check whether `object_owners.values()` contains the
dropped role before applying the tombstone — flagging it as a guaranteed
PostgreSQL failure if any objects are still owned.

---

## RLS Security Model Interaction (policies.md)

Row-Level Security introduces a third privilege layer below table-level
grants:

```
Layer 1: Table-level GRANT/REVOKE (grant_revoke.md)
Layer 2: Row-Level Security ENABLE/DISABLE/FORCE (policies.md)
Layer 3: Individual RLS policies PERMISSIVE/RESTRICTIVE (policies.md)
```

All three layers must be consistent for a row to be accessible. The
simulator needs independent state for all three:

```rust
struct TableSecurityState {
    table_grants: Vec<PrivilegeFact>,
    rls_enabled: bool,
    rls_forced: bool,             // applies to owner too
    policies: Vec<PolicyFact>,    // each with permissive/restrictive flag
}
```

The most common safe-migrate-relevant case: a migration adds a RESTRICTIVE
policy to a table that already has permissive policies in place. The
combined effect narrows access (all restrictive policies AND-ed with the OR
of all permissive ones). This is a silent access-narrowing event — the
table is still accessible, just with stricter row filtering. Rules should
flag new RESTRICTIVE policies specifically, not all policy additions.

---

## Confidence Downgrade Decision Tree

When an operation in this security domain is encountered, the simulator
should apply this decision tree:

```
Privilege/auth operation encountered
├── Is the target role session-dependent (CURRENT_USER/CURRENT_ROLE)?
│   └── YES → Tainted (cannot resolve target)
│
├── Is the operation type determinable from the AST?
│   ├── NO (AlterUser only) → Tainted (cannot determine effect)
│   ├── AlterRole → resolve via rename_to()/role_option_list()/set_config_param()
│   └── YES → continue
│
├── Does the operation affect objects used later in the migration?
│   ├── YES (REVOKE from an app role used in subsequent statements)
│   │   └── Flag as probable runtime failure + Tainted
│   └── NO → continue
│
├── REVOKE ... CASCADE?
│   └── YES → Flag as high-risk (blast radius unknown) + Warning at minimum
│
├── ALTER DEFAULT PRIVILEGES → SET search_path?
│   └── YES → Tainted (future object permission context changed)
│
└── Otherwise → Exact confidence, record in PrivilegeState
```

---

## Guaranteed Failure Patterns (Tier-1 Candidates)

The following privilege/auth operations are provably going to fail at
execution time under specific conditions detectable from `LocalState`:

1. **`DROP ROLE r` where `r` owns objects** — fails unconditionally unless
   all owned objects are first transferred or dropped
2. **`REVOKE CONNECT ON DATABASE db FROM app_user` followed by any statement
   requiring `app_user` to execute** — the application connection breaks
3. **`GRANT ... TO role` where `role` does not exist** — fails if role was
   never created (or was dropped earlier in the same migration)
4. **`CREATE POLICY` on a table with `INSTEAD OF` timing** — invalid, only
   views support INSTEAD OF (policies.md)
5. **`REFRESH MATERIALIZED VIEW CONCURRENTLY` without a qualifying unique
   index** — fails unconditionally (materialized_views.md)

---

## Summary of Verified Grammar Gaps in This Domain

| Node | Gap | Implication |
|------|-----|-------------|
| `AlterUser` | Operation type not extractable | Cannot model role attribute changes (Tainted) |
| `AlterRole` | Operation type extractable | `rename_to()`/`role_option_list()`/`set_config_param()` expose RENAME / attribute / config changes |
| `RoleOption` | Full attribute surface (LOGIN/SUPERUSER/etc. via `*_token()`) | Attribute safety analysis possible; only NO-prefix negations absent |
| `SetConfigParam` | Value not captured | Cannot model `ALTER DATABASE SET search_path` value |
| `AlterPublication` | Action not extractable | Cannot model replication privilege changes |
| `AlterSubscription` | Action not extractable | Cannot model subscription state changes |
| `EnableTrigger`/`DisableTrigger` | Target trigger name not captured | Cannot assess integrity-trigger bypass risk |
| `AlterConstraint` | Constraint name not captured | Cannot track constraint deferral changes |

All of the above should default to `Confidence::Tainted` when encountered,
with a human-review recommendation in the report output.
