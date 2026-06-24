# Transactions AST Reference for safe-migrate

## Status

Inspection status: complete for all transaction control nodes.

This document is derived from direct inspection of squawk.rs and should be treated as the
current source of truth for safe-migrate transaction handling.

All claims are AST-verified via grep and line-range inspection.

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Architectural Context

safe-migrate is a deterministic PostgreSQL schema execution simulator, not a linter.
This document supports `analysis/transaction.rs` and `TransactionFrame` from the blueprint:

```rust
pub struct TransactionFrame {
    pub undo_log: Vec<StateChange>,
}
```

The nodes documented here are what the AST Visitor extracts to drive transaction
frame push/pop and `StateChange` undo-log construction in `LocalState`.

---

## Handwritten Extension Policy

No handwritten extensions exist for any transaction control node.

Verified by exhaustive grep documented in `columns.md`.
No transaction-related nodes appear in the complete handwritten extension inventory.

---

# High-Level Transaction Model

The verified AST surface exposes:

**Transaction boundary nodes:**
- `Begin` — starts a transaction block
- `Commit` — ends a transaction block successfully
- `Rollback` — ends a transaction block, discarding changes
- `PrepareTransaction` — two-phase commit prepare

**Savepoint nodes:**
- `Savepoint` — creates a savepoint
- `ReleaseSavepoint` — releases a savepoint
- `Rollback` (with `to_token()` + `savepoint_token()`) — rollback to savepoint

**Transaction characteristic nodes:**
- `SetTransaction` — sets isolation level / access mode for current or future transactions
- `TransactionModeList` / `TransactionMode` (8-member enum)
- `SetConstraints` — deferred constraint checking control

---

# Transaction Boundary Nodes

## Begin

### Verified Accessors (line 2693)

```rust
pub fn transaction_mode_list(&self) -> Option<TransactionModeList>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn begin_token(&self) -> Option<SyntaxToken>
pub fn start_token(&self) -> Option<SyntaxToken>
pub fn transaction_token(&self) -> Option<SyntaxToken>
pub fn work_token(&self) -> Option<SyntaxToken>
```

### Meaning

Covers both forms:

```sql
BEGIN [WORK | TRANSACTION] [transaction_mode_list]
START TRANSACTION [transaction_mode_list]
```

Detection: `begin_token().is_some()` vs `start_token().is_some()` distinguishes the
two syntactic forms; both have identical semantics.

### safe-migrate guidance

```rust
StateChange::TransactionBegin {
    modes: Vec<TransactionModeFact>,  // from transaction_mode_list()
}
```

On `Begin`, the engine pushes a new `TransactionFrame` onto `LocalState.transactions`.

Critical for safe-migrate: **statements that cannot run inside a transaction block**
(e.g. `CREATE INDEX CONCURRENTLY`, `ALTER TYPE ... ADD VALUE` in some PG versions,
`VACUUM`) must be checked against whether a `Begin` frame is currently open.

---

## Commit

### Verified Accessors (line 3656)

```rust
pub fn literal(&self) -> Option<Literal>          // for COMMIT PREPARED 'gid'
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn and_token(&self) -> Option<SyntaxToken>
pub fn chain_token(&self) -> Option<SyntaxToken>
pub fn commit_token(&self) -> Option<SyntaxToken>
pub fn no_token(&self) -> Option<SyntaxToken>
pub fn prepared_token(&self) -> Option<SyntaxToken>
pub fn transaction_token(&self) -> Option<SyntaxToken>
pub fn work_token(&self) -> Option<SyntaxToken>
```

### Meaning

Covers three forms:

```sql
COMMIT [WORK | TRANSACTION]
COMMIT AND [NO] CHAIN
COMMIT PREPARED 'transaction_id'
```

**PREPARED detection:** `prepared_token().is_some()` → two-phase commit completion,
`literal()` gives the transaction identifier.

**CHAIN detection:** `and_token()` + `chain_token()` present → `COMMIT AND CHAIN`.
`no_token()` additionally present → `COMMIT AND NO CHAIN`.
CHAIN immediately starts a new transaction with the same characteristics.

### safe-migrate guidance

```rust
StateChange::TransactionCommit {
    chain: bool,    // from and_token + chain_token + no_token.is_none()
}
```

On `Commit` without CHAIN, the engine pops the current `TransactionFrame` and
discards its undo log (changes are now permanent in the simulation).
On `Commit AND CHAIN`, pop and immediately push a new frame.

---

## Rollback

### Verified Accessors (line 15769)

```rust
pub fn literal(&self) -> Option<Literal>      // for ROLLBACK PREPARED 'gid'
pub fn name_ref(&self) -> Option<NameRef>     // for ROLLBACK TO SAVEPOINT name
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn abort_token(&self) -> Option<SyntaxToken>
pub fn and_token(&self) -> Option<SyntaxToken>
pub fn chain_token(&self) -> Option<SyntaxToken>
pub fn no_token(&self) -> Option<SyntaxToken>
pub fn prepared_token(&self) -> Option<SyntaxToken>
pub fn rollback_token(&self) -> Option<SyntaxToken>
pub fn savepoint_token(&self) -> Option<SyntaxToken>
pub fn to_token(&self) -> Option<SyntaxToken>
pub fn transaction_token(&self) -> Option<SyntaxToken>
pub fn work_token(&self) -> Option<SyntaxToken>
```

### Meaning

Single node covers four distinct forms:

```sql
ROLLBACK [WORK | TRANSACTION]                    -- full rollback
ROLLBACK AND [NO] CHAIN
ROLLBACK PREPARED 'transaction_id'                -- two-phase commit abort
ROLLBACK [WORK | TRANSACTION] TO [SAVEPOINT] name -- partial rollback
ABORT                                             -- alias for ROLLBACK
```

### Form Detection Table

| Form | Detection |
|------|-----------|
| Full rollback | `to_token().is_none()` and `prepared_token().is_none()` |
| ROLLBACK TO SAVEPOINT | `to_token().is_some()`, name via `name_ref()` |
| ROLLBACK PREPARED | `prepared_token().is_some()`, id via `literal()` |
| ABORT alias | `abort_token().is_some()` |
| AND CHAIN | `and_token()` + `chain_token()` present |

### Important Finding

`Rollback` is a single polymorphic node, not an enum split by form.
This mirrors the `SequenceOption` pattern seen in sequences.md — token combination
logic is required to determine which form is present.

### safe-migrate guidance

```rust
enum RollbackForm {
    Full { chain: bool },
    ToSavepoint { name: String },
    Prepared { gid: String },
}
```

**Critical for the simulator:** `ROLLBACK TO SAVEPOINT name` must replay the
undo log only back to the matching savepoint frame, not the entire transaction.
Full `ROLLBACK` pops and discards the entire `TransactionFrame` stack down to
(and including) the outermost `Begin`, replaying the full undo log to restore
`LocalState` to its pre-transaction state.

---

## PrepareTransaction

### Verified Accessors (line 14405)

```rust
pub fn literal(&self) -> Option<Literal>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn prepare_token(&self) -> Option<SyntaxToken>
pub fn transaction_token(&self) -> Option<SyntaxToken>
```

### Meaning

```sql
PREPARE TRANSACTION 'transaction_id'
```

Two-phase commit prepare phase. `literal()` gives the transaction identifier.

### safe-migrate guidance

This statement neither commits nor rolls back in the simulator's local sense —
it hands off to external coordination. Treat as a frame-pop without state
finalization, or flag as opaque/unsupported depending on simulator scope.

---

# Savepoint Nodes

## Savepoint

### Verified Accessors (line 15946)

```rust
pub fn name(&self) -> Option<Name>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn savepoint_token(&self) -> Option<SyntaxToken>
```

### Meaning

```sql
SAVEPOINT name
```

### safe-migrate guidance

```rust
StateChange::SavepointCreate {
    name: String,    // from name()
}
```

Pushes a named checkpoint within the current `TransactionFrame`'s undo log,
marking the position to which `ROLLBACK TO SAVEPOINT name` can rewind.

---

## ReleaseSavepoint

### Verified Accessors (line 14984)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn release_token(&self) -> Option<SyntaxToken>
pub fn savepoint_token(&self) -> Option<SyntaxToken>
```

### Meaning

```sql
RELEASE [SAVEPOINT] name
```

Removes a savepoint marker without rolling back. Changes made since the
savepoint remain part of the transaction.

### safe-migrate guidance

```rust
StateChange::SavepointRelease {
    name: String,    // from name_ref()
}
```

Merges the undo-log segment since the named savepoint into the parent segment
(does not discard it — the changes are kept, only the rollback boundary is removed).

---

# Transaction Characteristics

## SetTransaction

### Verified Accessors (line 17043)

```rust
pub fn literal(&self) -> Option<Literal>                          // for SET TRANSACTION SNAPSHOT
pub fn transaction_mode_list(&self) -> Option<TransactionModeList>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn as_token(&self) -> Option<SyntaxToken>
pub fn characteristics_token(&self) -> Option<SyntaxToken>
pub fn session_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>
pub fn snapshot_token(&self) -> Option<SyntaxToken>
pub fn transaction_token(&self) -> Option<SyntaxToken>
```

### Meaning

Covers three forms:

```sql
SET TRANSACTION transaction_mode_list
SET SESSION CHARACTERISTICS AS TRANSACTION transaction_mode_list
SET TRANSACTION SNAPSHOT 'snapshot_id'
```

**Session-level detection:** `session_token()` + `characteristics_token()` present
→ affects all future transactions in the session, not just the current one.

**Snapshot detection:** `snapshot_token().is_some()` → `literal()` gives snapshot id.

### safe-migrate guidance

```rust
StateChange::TransactionModeSet {
    modes: Vec<TransactionModeFact>,
    session_scope: bool,   // from session_token + characteristics_token presence
}
```

---

## TransactionModeList / TransactionMode

### TransactionModeList (line 17718)

```rust
pub fn transaction_modes(&self) -> AstChildren<TransactionMode>
```

### TransactionMode Enum (8 members, all token-only nodes)

```rust
pub enum TransactionMode {
    Deferrable(Deferrable),
    NotDeferrable(NotDeferrable),
    ReadCommitted(ReadCommitted),
    ReadOnly(ReadOnly),
    ReadUncommitted(ReadUncommitted),
    ReadWrite(ReadWrite),
    RepeatableRead(RepeatableRead),
    Serializable(Serializable),
}
```

Fully verified via `AstNode for TransactionMode` cast match and `From<X>` impls.
Each variant is a token-presence-only node (no payload beyond keyword tokens).

### safe-migrate guidance

```rust
enum TransactionModeFact {
    IsolationLevel(IsolationLevel),  // ReadCommitted | ReadUncommitted | RepeatableRead | Serializable
    AccessMode(AccessMode),          // ReadOnly | ReadWrite
    Deferrable(bool),                // Deferrable | NotDeferrable
}
```

**Significant for safe-migrate:** `SERIALIZABLE` isolation level combined with
concurrent DDL can produce different danger profiles than `READ COMMITTED`.
`READ ONLY` transactions cannot execute any DDL — a migration containing DDL
inside a `READ ONLY` transaction block is a guaranteed runtime failure and
should be a tier-1 block.

---

## SetConstraints

### Verified Accessors (line 16590)

```rust
pub fn paths(&self) -> AstChildren<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn constraints_token(&self) -> Option<SyntaxToken>
pub fn deferred_token(&self) -> Option<SyntaxToken>
pub fn immediate_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>
```

### Meaning

```sql
SET CONSTRAINTS ALL DEFERRED
SET CONSTRAINTS name1, name2 IMMEDIATE
```

`all_token().is_some()` → applies to all deferrable constraints.
Otherwise `paths()` gives the specific constraint names.

**DEFERRED vs IMMEDIATE:** `deferred_token()` vs `immediate_token()` presence.

### safe-migrate guidance

```rust
StateChange::ConstraintCheckTimingSet {
    targets: ConstraintCheckTarget,   // All | Named(Vec<QualifiedName>)
    timing: CheckTiming,              // Deferred | Immediate
}
```

**Significant for safe-migrate:** setting constraints to `IMMEDIATE` inside a
transaction forces immediate validation, which can surface lock contention or
validation failures that would otherwise be deferred to `COMMIT`. This affects
the simulator's ability to predict when a constraint violation will manifest.

---

# Verified Findings Summary

## Confirmed Complete

- `Begin`: fully resolved
- `Commit`: fully resolved including PREPARED and CHAIN forms
- `Rollback`: fully resolved including all four forms (token combination required)
- `PrepareTransaction`: fully resolved
- `Savepoint`: fully resolved
- `ReleaseSavepoint`: fully resolved
- `SetTransaction`: fully resolved including session-scope and snapshot forms
- `TransactionModeList`: fully resolved
- `TransactionMode` enum: all 8 members verified
- `SetConstraints`: fully resolved

## Confirmed Partial

None — this file has no unresolved accessor surfaces.

## Grammar Cross-Check

This document has been cross-checked against postgresql.ungram. All transaction
control node shapes (`Begin`, `Commit`, `Rollback`, `SetTransaction`, `Reset`,
`SetConstraints`, `Savepoint`, `ReleaseSavepoint`, `PrepareTransaction`) match
exactly between the generated accessor surface and the formal grammar. No
corrections were required.

## Architectural Note

`Rollback` and `SetTransaction` both follow the single-polymorphic-node pattern
also seen in `SequenceOption` (sequences.md): one struct, multiple semantic
forms distinguished by which keyword tokens are present. The resolver must
implement explicit token-combination dispatch logic for these nodes rather
than relying on enum variant matching.

---

# Remaining Open Questions

None identified in this pass. All transaction control nodes have fully
verified accessor surfaces sufficient for `TransactionFrame` and `StateChange`
extraction as specified in the blueprint.
