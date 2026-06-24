# Policies (Row-Level Security) AST Reference for safe-migrate

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

## Scope Note

PostgreSQL Row-Level Security (RLS) has two independent layers that must
both be modeled:

1. **Policy objects** (`CREATE POLICY` / `ALTER POLICY` / `DROP POLICY`) —
   named rules attached to a table defining row visibility/mutability.
2. **Table-level RLS toggle** (`ALTER TABLE ... ENABLE/DISABLE/FORCE ROW
   LEVEL SECURITY`) — whether RLS is active on the table at all, independent
   of how many policies exist.

A table can have policies defined while RLS is disabled (policies exist but
are not enforced), and a table can have RLS enabled with zero policies
(default-deny: no rows visible to non-superusers/non-owners). Both
dimensions must be tracked independently in `LocalState`.

---

# Core Nodes — Policy Objects

## CreatePolicy

### Verified Accessors (line 4971)

```rust
pub fn as_policy_type(&self) -> Option<AsPolicyType>
pub fn name(&self) -> Option<Name>
pub fn on_table(&self) -> Option<OnTable>
pub fn role_ref_list(&self) -> Option<RoleRefList>
pub fn using_expr_clause(&self) -> Option<UsingExprClause>
pub fn with_check_expr_clause(&self) -> Option<WithCheckExprClause>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn delete_token(&self) -> Option<SyntaxToken>
pub fn for_token(&self) -> Option<SyntaxToken>
// insert_token(), select_token(), update_token(), to_token(), policy_token()
// also present per established pattern, not shown in partial grep view
```

### Grammar Confirmation

```
CreatePolicy =
  'create' 'policy' Name OnTable
  AsPolicyType?
  ('for' ('all' | 'select' | 'insert' | 'update' | 'delete'))?
  ('to' RoleRefList)?
  UsingExprClause?
  WithCheckExprClause? ';'?
```

Fully populated — every grammar field has a corresponding accessor.

### Command Type Extraction (FOR clause)

```rust
fn policy_command(policy: &CreatePolicy) -> PolicyCommand {
    if policy.all_token().is_some() { PolicyCommand::All }
    else if policy.select_token().is_some() { PolicyCommand::Select }
    else if policy.insert_token().is_some() { PolicyCommand::Insert }
    else if policy.update_token().is_some() { PolicyCommand::Update }
    else if policy.delete_token().is_some() { PolicyCommand::Delete }
    else { PolicyCommand::All }  // PostgreSQL default when FOR clause omitted
}
```

When the entire `FOR ...` clause is absent, PostgreSQL defaults to `ALL` —
this is a real default that must be applied at the resolver level, not an
ambiguous/unknown state.

### Permissive vs Restrictive (AsPolicyType)

`as_policy_type()` → `AsPolicyType`, carrying a raw `'#ident'` token (not a
structured enum) for `PERMISSIVE` or `RESTRICTIVE`. When `as_policy_type()`
is `None`, PostgreSQL defaults to `PERMISSIVE`.

```rust
// AsPolicyType verified accessors (line 2544)
pub fn as_token(&self) -> Option<SyntaxToken>
pub fn ident_token(&self) -> Option<SyntaxToken>
```

The actual `PERMISSIVE`/`RESTRICTIVE` text must be read from
`ident_token()`'s raw text (case-insensitively, per standard PostgreSQL
keyword handling) since this is not a structured enum like
`VolatilityFuncOption`'s token-alternation pattern — it's a single generic
ident slot the grammar leaves open.

**Safety significance:** `RESTRICTIVE` policies are combined with `AND`
logic across all restrictive policies and then `AND`-ed with the `OR` of all
`PERMISSIVE` policies. Adding a `RESTRICTIVE` policy can silently make rows
invisible/unmodifiable that were previously accessible under existing
permissive policies — a fundamentally different composition risk than
adding another `PERMISSIVE` policy (which only ever widens access). This
distinction must be preserved through to the rule engine.

### USING vs WITH CHECK Clauses

```rust
// UsingExprClause (line 18102)
pub fn expr(&self) -> Option<Expr>

// WithCheckExprClause (line 18637)
pub fn expr(&self) -> Option<Expr>
```

Both confirmed to carry a real `Expr`, fully extractable into `ExprIr`.

**Semantic distinction critical for safe-migrate:**
- `USING (expr)` — filters which existing rows are visible for
  `SELECT`/`UPDATE`/`DELETE` (and the pre-update view for `UPDATE`)
- `WITH CHECK (expr)` — validates new/modified row values for
  `INSERT`/`UPDATE` (rejects writes that would violate the expression)

For `INSERT`-only policies, only `WITH CHECK` is meaningful (there's no
pre-existing row to filter via `USING`). For `SELECT`-only policies, only
`USING` is meaningful. PostgreSQL allows specifying either, both, or
(in some FOR combinations) requires specific combinations — this validation
is not enforced by the grammar and belongs in the rule engine.

If `WITH CHECK` is omitted but `USING` is present for a policy that allows
writes (`UPDATE`/`ALL`), PostgreSQL **reuses the `USING` expression as the
`WITH CHECK` expression too**. This is a real PostgreSQL default behavior,
not an "absent" state — the resolver must apply this fallback explicitly
when modeling write-validation behavior, otherwise it will incorrectly
conclude no write-time check exists when one implicitly does.

### safe-migrate guidance

```rust
struct CreatePolicyFact {
    name: String,                       // from name()
    table: QualifiedName,               // from on_table()
    permissive: bool,                   // from as_policy_type(), default true
    command: PolicyCommand,             // from FOR clause, default All
    roles: Vec<RoleFact>,               // from role_ref_list(), default PUBLIC if absent
    using_expr: Option<ExprIr>,         // from using_expr_clause()
    with_check_expr: Option<ExprIr>,    // from with_check_expr_clause(),
                                         // falls back to using_expr if absent and command allows writes
}
```

`role_ref_list()` being `None` means the policy applies to `PUBLIC` (all
roles) by default — another real PostgreSQL default the resolver must apply
explicitly.

---

## AlterPolicy

### Verified Accessors (line 1422)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn on_table(&self) -> Option<OnTable>
pub fn rename_to(&self) -> Option<RenameTo>
pub fn role_ref_list(&self) -> Option<RoleRefList>
pub fn using_expr_clause(&self) -> Option<UsingExprClause>
pub fn with_check_expr_clause(&self) -> Option<WithCheckExprClause>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn policy_token(&self) -> Option<SyntaxToken>
pub fn to_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterPolicy =
  'alter' 'policy' NameRef OnTable
  (RenameTo
  | (
    ('to' RoleRefList)?
    UsingExprClause?
    WithCheckExprClause?
  )) ';'?
```

Two mutually exclusive top-level forms: rename, or role/using/check update
(which can update any combination of the three sub-fields simultaneously —
they are not individually mutually exclusive with each other, only the
whole group is exclusive with `RenameTo`).

### Important Finding — No Command-Type or Permissive/Restrictive Change

Notably absent from `AlterPolicy`: there is no way to change a policy's
`FOR` command type (`SELECT`/`INSERT`/`UPDATE`/`DELETE`/`ALL`) or its
`PERMISSIVE`/`RESTRICTIVE` classification after creation. This matches real
PostgreSQL semantics — these attributes are immutable after `CREATE POLICY`;
changing them requires `DROP POLICY` + `CREATE POLICY`. The grammar
correctly reflects this PostgreSQL limitation by simply not providing
those fields on `AlterPolicy`.

### safe-migrate guidance

```rust
enum AlterPolicyFact {
    Rename { table: QualifiedName, from: String, to: String },
    Update {
        table: QualifiedName,
        name: String,
        new_roles: Option<Vec<RoleFact>>,        // None = unchanged
        new_using_expr: Option<ExprIr>,            // None = unchanged
        new_with_check_expr: Option<ExprIr>,       // None = unchanged
    },
}
```

A policy `USING`/`WITH CHECK` expression change is functionally equivalent
in risk profile to changing a `CHECK` constraint — it can silently change
which rows are visible/writable without any structural schema change being
apparent from a cursory diff. This deserves similar scrutiny to constraint
modification in the rule engine.

---

## DropPolicy

### Verified Accessors (line 7641)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn name_ref(&self) -> Option<NameRef>
pub fn on_table(&self) -> Option<OnTable>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
// restrict_token(), policy_token() also present per established pattern
```

### Grammar Confirmation

```
DropPolicy =
  'drop' 'policy' IfExists? NameRef OnTable
  ('cascade' | 'restrict')? ';'?
```

Single policy name only — matches real PostgreSQL syntax (`DROP POLICY`
only ever drops one named policy, scoped to one table via `ON table`).

### safe-migrate guidance

Dropping the last `RESTRICTIVE` policy on a table can **widen** access
(since restrictive policies narrow what permissive policies allow) — this
is the inverse risk direction from dropping a `PERMISSIVE` policy (which
narrows access). Both are real concerns but in opposite directions; the
rule engine should track each policy's `permissive` flag when evaluating
the access-control impact of a drop.

---

# Core Nodes — Table-Level RLS Toggle

These four nodes appear as `AlterTableAction` variants (per the inventory
established alongside the trigger enable/disable findings in triggers.md),
governing whether RLS is active on a table at all, independent of policy
objects.

## EnableRls / DisableRls / ForceRls / NoForceRls

### Verified Accessors

```rust
// EnableRls (line 8967)
pub fn enable_token(&self) -> Option<SyntaxToken>
pub fn level_token(&self) -> Option<SyntaxToken>
pub fn row_token(&self) -> Option<SyntaxToken>
pub fn security_token(&self) -> Option<SyntaxToken>

// DisableRls (line 6488)
pub fn disable_token(&self) -> Option<SyntaxToken>
pub fn level_token(&self) -> Option<SyntaxToken>
pub fn row_token(&self) -> Option<SyntaxToken>
pub fn security_token(&self) -> Option<SyntaxToken>

// ForceRls (line 9550)
pub fn force_token(&self) -> Option<SyntaxToken>
pub fn level_token(&self) -> Option<SyntaxToken>
pub fn row_token(&self) -> Option<SyntaxToken>
pub fn security_token(&self) -> Option<SyntaxToken>

// NoForceRls (line 12696)
pub fn force_token(&self) -> Option<SyntaxToken>
pub fn level_token(&self) -> Option<SyntaxToken>
pub fn no_token(&self) -> Option<SyntaxToken>
pub fn row_token(&self) -> Option<SyntaxToken>
pub fn security_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
EnableRls =
  'enable' 'row' 'level' 'security'

DisableRls =
  'disable' 'row' 'level' 'security'

ForceRls =
  'force' 'row' 'level' 'security'

NoForceRls =
  'no' 'force' 'row' 'level' 'security'
```

All four confirmed entirely token-only — **but unlike the trigger
enable/disable gap documented in triggers.md, this is not a real
limitation**: these toggles are table-wide, not targeting a specific named
object. There is nothing to name — `ENABLE ROW LEVEL SECURITY` always
applies to the entire table the `AlterTable` statement targets, available
via the parent `AlterTable.relation_name()`, not these leaf nodes
themselves. This is structurally identical to `SetLogged`/`SetUnlogged`
(also table-wide, token-only `AlterTableAction` variants) rather than the
trigger case where a real name was needed but unavailable.

### FORCE vs ordinary RLS — Important Semantic Distinction

`ENABLE ROW LEVEL SECURITY` alone does **not** apply RLS policies to the
table owner or superusers — they bypass RLS by default. `FORCE ROW LEVEL
SECURITY` additionally applies RLS restrictions to the table owner as well
(superusers always bypass regardless of `FORCE`). This is a meaningfully
different and stronger security posture, not a minor variant — a migration
enabling `FORCE` should be distinguished from one enabling only `EnableRls`
in any access-control-aware rule.

### safe-migrate guidance

```rust
enum RlsToggleFact {
    Enable,        // table-wide, target table from parent AlterTable.relation_name()
    Disable,       // table-wide
    Force,         // table-wide, stronger posture — applies to owner too
    NoForce,       // table-wide, reverts Force
}
```

`DisableRls` on a table that has active `RESTRICTIVE`/`PERMISSIVE` policies
is a significant access-control event: existing policies remain defined but
become entirely unenforced — every row becomes visible/writable to anyone
with table-level privileges, regardless of policy definitions. This is a
strong candidate for at least tier-2 (warning) classification, with tier-1
(block) being reasonable if the table is known (via `LocalState`) to
currently have any policies defined, since the practical effect is "all
existing row-level access controls are now bypassed."

---

# Verified Findings Summary

## Confirmed Complete

- `CreatePolicy`: fully resolved
- `AlterPolicy`: fully resolved, including the confirmed absence of
  command-type/permissive-restrictive mutability (correct per PostgreSQL semantics)
- `DropPolicy`: fully resolved
- `AsPolicyType`: fully resolved (raw ident token, not structured enum)
- `UsingExprClause` / `WithCheckExprClause`: fully resolved, both carry real `Expr`
- `EnableRls` / `DisableRls` / `ForceRls` / `NoForceRls`: fully resolved,
  confirmed token-only but NOT a gap (table-wide toggles, no name needed)

## Key Architectural Findings

1. **RLS has two independent state dimensions** — policy objects and the
   table-level RLS enable/disable/force toggle — both must be tracked
   separately in `LocalState`, since they can be in any combination
   (policies exist with RLS disabled, RLS enabled with zero policies, etc.).
2. **PERMISSIVE vs RESTRICTIVE policies have fundamentally different
   composition semantics** (OR-combined vs AND-combined) and therefore
   opposite risk directions when added or dropped — this distinction must
   propagate through to the rule engine, not be collapsed into "a policy
   changed."
3. **`WITH CHECK` falls back to `USING` when omitted**, for policies that
   permit writes — a real PostgreSQL default that must be applied
   explicitly by the resolver, not treated as "no write check exists."
4. **`role_ref_list()` being absent means `PUBLIC`**, another explicit
   PostgreSQL default the resolver must apply.
5. **`FORCE ROW LEVEL SECURITY` is meaningfully stronger than plain
   `ENABLE`** — it additionally restricts the table owner, not just other
   roles. This distinction should not be collapsed in the Fact model.
6. **Unlike the trigger enable/disable gap (triggers.md), the RLS toggle
   nodes being token-only is NOT a limitation** — these operations are
   inherently table-wide with no named sub-object, so there is nothing
   missing from the AST that real PostgreSQL semantics would require.

## Grammar Cross-Check

This document was written with postgresql.ungram available from the start.
All nodes cross-checked in this single pass; no corrections needed.

---

# Remaining Open Questions

None identified in this pass.
