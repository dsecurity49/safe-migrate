# Materialized Views Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

---

## Documentation Contract

1. Only document AST behavior that has been directly verified (here, via
   cross-reference to views.md's verified findings).
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. This document does not duplicate accessor bodies already fully documented
   in views.md — see that file for the underlying verification work.

---

## Relationship to views.md

Materialized views share their core lifecycle nodes with regular views in
this AST (`CreateViewLike` unifies both), but have meaningfully different
PostgreSQL semantics: a materialized view physically stores its query
result as data on disk, requiring explicit `REFRESH` to update, whereas a
regular view is purely a stored query re-executed on every access. This
document exists to surface that semantic distinction clearly for
safe-migrate's rule engine, since the AST documentation in views.md
necessarily treats both view kinds together for accessor purposes.

All accessor verification for the four nodes below was completed in
views.md and is referenced here, not repeated:

| Node | Verified in views.md |
|------|------------------------|
| `CreateMaterializedView` | Yes — fully resolved |
| `AlterMaterializedView` | Yes — fully resolved, including all 6 `AlterMaterializedViewAction` variants |
| `DropMaterializedView` | Yes — fully resolved |
| `Refresh` | Yes — fully resolved |

---

# Lifecycle Summary

## CreateMaterializedView

See views.md for full accessor documentation. Key fields for safe-migrate's
materialized-view-specific analysis:

```rust
column_list()      // explicit output column names, optional
path()             // materialized view's own qualified name
query()            // the underlying SELECT — same SelectVariant type
                    // used by regular views, tables, etc.
using_method()     // storage access method (e.g. heap)
tablespace()       // explicit tablespace placement
with_data()        // WITH DATA — populate immediately on creation
with_no_data()     // WITH NO DATA — create empty, unpopulated shell
with_params()      // storage parameters
```

### Critical Distinction: WITH DATA vs WITH NO DATA

A materialized view created `WITH NO DATA` is **unscannable** until the
first `REFRESH MATERIALIZED VIEW` — querying it before that first refresh
raises an error (`materialized view "x" has not been populated`). This is
fundamentally different from a regular view or a `WITH DATA` (the default)
materialized view, both of which are immediately queryable.

```rust
fn initial_population_state(node: &CreateMaterializedView) -> PopulationState {
    if node.with_no_data().is_some() {
        PopulationState::Empty  // unscannable until first REFRESH
    } else {
        PopulationState::Populated  // default behavior, or explicit WITH DATA
    }
}
```

**safe-migrate must track this state per materialized view in `LocalState`.**
If a migration creates a materialized view `WITH NO DATA` and a later
statement in the same migration (or a dependent object) attempts to query
it without an intervening `REFRESH MATERIALIZED VIEW`, that is a guaranteed
PostgreSQL failure — a strong tier-1 (block) candidate, and one that is
fully detectable through sequential simulation given the simulator's
statement-by-statement execution model.

### Materialized View Creation Cost

Populating a materialized view (the default `WITH DATA` behavior, or any
subsequent `REFRESH`) executes the full underlying query and writes the
entire result set to disk. For a materialized view over a large base table
or a complex/expensive query, this is a substantial operation — comparable
in cost profile to `CREATE TABLE AS SELECT`. This is relevant context for
any size/cost-aware tiering safe-migrate applies (consistent with the
blueprint's approximate-table-size extraction from pg_catalog).

---

## AlterMaterializedView

See views.md for full accessor documentation, including the complete
resolution of all 6 `AlterMaterializedViewAction` variants
(`DependsOnExtension`, `NoDependsOnExtension`, `RenameColumn`, `RenameTo`,
`SetSchema`, and the `AlterTableAction`-wrapping catch-all).

### Materialized-View-Specific Risk Notes

Most `AlterTableAction` members wrapped through
`AlterMaterializedViewAction::AlterTableAction` are not valid for
materialized views in real PostgreSQL even though the grammar permits
parsing them (see views.md's "grammar permissive, PostgreSQL semantics
stricter" finding). The subset that **is** semantically valid for
materialized views in PostgreSQL includes things like `SetAccessMethod`,
`ClusterOn`/`SetWithoutCluster`, `OwnerTo`, `SetTablespace`, and
column-storage/statistics actions (`AlterColumn` with `SetStatistics`/
`SetStorage`/`SetCompression` sub-options, per columns.md). Structural
actions like `AddColumn`, `DropColumn`, `AddConstraint`, partition actions,
etc. are not valid against a materialized view (materialized views do not
support arbitrary column/constraint mutation the way base tables do — their
columns are derived entirely from the underlying query) and represent a
guaranteed PostgreSQL failure if parsed as targeting one. This validation
must happen in the rule engine using `LocalState`'s knowledge of which
`ObjectId` is a materialized view vs. a base table, since the AST alone
cannot make this distinction — `AlterMaterializedView` simply allows the
full `AlterTableAction` surface structurally.

---

## DropMaterializedView

See views.md for full accessor documentation. Key finding already
established there: `DropMaterializedView` supports **multiple** view names
per statement (`paths()`, plural) — in 2.58.0 this is now symmetric with
`DropView`, which also supports multiple names via `paths()`.

---

## Refresh (REFRESH MATERIALIZED VIEW)

See views.md for full accessor documentation:

```rust
path()                // target materialized view
concurrently_token()  // CONCURRENTLY modifier
with_data()           // WITH DATA — perform the refresh (default)
with_no_data()        // WITH NO DATA — clear the view back to unpopulated state
```

### CONCURRENTLY Requirement

`REFRESH MATERIALIZED VIEW CONCURRENTLY` requires the materialized view to
have at least one `UNIQUE` index covering all columns used in the query's
output (no expressions, no partial index) — without this, PostgreSQL
rejects the `CONCURRENTLY` refresh at execution time. This is not enforced
by the grammar at all (`concurrently_token()` is a simple presence check)
and is not something the AST can validate — it requires resolver-level
knowledge of the materialized view's index set, tracked via the dependency
graph established for indexes.md.

```rust
fn validate_concurrent_refresh(
    target: &ObjectId,
    state: &LocalState,
) -> Result<(), RuleViolation> {
    if !state.has_unique_index_covering_all_columns(target) {
        return Err(RuleViolation::ConcurrentRefreshWithoutUniqueIndex);
    }
    Ok(())
}
```

This is a clean example of the blueprint's separation of concerns in
practice: the AST Visitor extracts "a CONCURRENTLY refresh was requested
against materialized view X" as a Fact; the Resolver/Rule layer, consulting
`LocalState.relations` and the dependency graph's index tracking, determines
whether the precondition (a qualifying unique index) is actually met.

### REFRESH ... WITH NO DATA — Returning to the Unpopulated State

`REFRESH MATERIALIZED VIEW x WITH NO DATA` clears the materialized view's
data and returns it to the same unscannable state as `CREATE MATERIALIZED
VIEW ... WITH NO DATA` (see above). This means a previously-populated
materialized view can be made unscannable again mid-migration — the
`PopulationState` tracked in `LocalState` must be updated on every `Refresh`
statement processed, not just set once at creation time and forgotten.

```rust
fn apply_refresh_to_state(refresh: &RefreshFact, state: &mut LocalState) {
    let new_population_state = if refresh.with_no_data {
        PopulationState::Empty
    } else {
        PopulationState::Populated
    };
    state.relations.get_mut(&refresh.target).unwrap().population_state = new_population_state;
}
```

---

# Verified Findings Summary

## Confirmed Complete

All four materialized-view lifecycle nodes (`CreateMaterializedView`,
`AlterMaterializedView`, `DropMaterializedView`, `Refresh`) are fully
resolved, per the complete verification work done in views.md (now itself
at zero open questions after this session's cross-check pass).

## Key Materialized-View-Specific Findings (Beyond Pure AST Verification)

1. **`WITH NO DATA` creates an unscannable object** — this is a state that
   must be tracked across the simulator's `LocalState` and checked before
   any later statement queries the materialized view, fully detectable
   given the simulator's sequential execution model.
2. **`REFRESH ... CONCURRENTLY` has an unenforceable-at-AST-level
   precondition** (a qualifying unique index must exist) — a clean example
   requiring Resolver/Rule-layer validation against `LocalState`, not
   something the AST Visitor can determine in isolation.
3. **Population state is mutable across the migration**, not fixed at
   creation — `REFRESH ... WITH NO DATA` can revert a populated materialized
   view back to unscannable, meaning `LocalState` must update this field on
   every `Refresh` statement, not just initialize it once.
4. **Most `AlterTableAction` variants reachable through
   `AlterMaterializedViewAction` are not semantically valid** against a
   materialized view in real PostgreSQL, despite being structurally
   parseable — validation requires `LocalState`'s object-kind tracking, not
   AST-level rejection.

## Grammar Cross-Check

No new grammar cross-check was required for this document — all underlying
AST verification was completed in views.md during this session's earlier
cross-check pass, including full resolution of the previously-open
`AlterMaterializedViewAction` variant question.

---

# Remaining Open Questions

None remaining.
