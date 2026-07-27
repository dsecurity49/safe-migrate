# Safe-Migrate Live Tests

This directory contains the exhaustive end-to-end integration test suite for the `safe-migrate` engine. It validates the exact behavior of the AST parser, state machine, and rule evaluators against realistic PostgreSQL migration scripts.

## Structure

The suite is organized into subdirectories for each implemented rule. Inside each directory:
- **`safe_*.sql`**: Migration scripts that are expected to **PASS** (emit 0 violations for the target rule).
- **`[0-9]*.sql`**: Migration scripts that are expected to **FAIL** (emit >= 1 violation for the target rule).

## How to Run

The test runner (`run.sh`) is a fast bash script that executes the local `safe-migrate` binary against the `.sql` fixtures and parses the output JSON to verify the correct rules fired.

### Live Differential Harness

The ignored live differential harness rebuilds `differential_baseline.sql` before
each enabled fixture and compares normalized simulator state with PostgreSQL:

```bash
DATABASE_URL='host=/path/to/socket dbname=postgres user=my_user' \
    scripts/live-differential -vv
```

Verbosity is cumulative: `-v` reports lifecycle and fixture outcomes, `-vv`
adds cache and normalized-state counts, and `-vvv` dumps complete normalized
live and simulator projections. CI runs this harness against an isolated
PostgreSQL 16 service. Locally, use a disposable database: the harness rebuilds
its canonical baseline before every fixture and executes the fixtures. It does
not use the frozen cache.

Run a newly enabled rule by itself before the cumulative manifest:

```bash
scripts/live-differential -vv --rule rule_01_irreversible-migration
scripts/live-differential -v
```

Run one qualified fixture while debugging a mismatch:

```bash
scripts/live-differential --fixture rule_01_irreversible-migration/001_drop_table.sql
```

### Basic Usage
```bash
./run.sh
```
This runs the entire suite silently, printing a green/red summary line for each directory and a final tally at the bottom.

### CLI Flags
You can target specific tests or increase verbosity using the following flags:

* **`-v, --verbose`**
  Prints the `[PASS]`, `[FAIL]`, or `[SKIP]` status for every single `.sql` file in the suite, rather than just the directory summaries.
* **`-d, --dir <DIRECTORY>`**
  Run the tests for a specific rule directory only. 
  *Example:* `./run.sh -d rule_19_concurrent-in-transaction`
* **`-t, --test <FILE>`**
  Run the test runner against exactly one file. Great for rapidly debugging a single failing edge-case.
  *Example:* `./run.sh -t rule_01_irreversible-migration/001_drop_table.sql`
* **`--offline`**
  Passes the `--no-cache` flag to `safe-migrate`. This evaluates the migration files completely blindly, simulating a run where the user cannot connect to a baseline database. (Note: State-dependent rules like `schema-drift` will behave differently in offline mode).

## Rules Tested

The suite currently runs exhaustive coverage against all 26 core rules:

1. `irreversible-migration`
2. `drop-database`
3. `drop-schema-cascade`
4. `destructive-general-cascade`
5. `destructive-cascade`
6. `create-table-as-select`
7. `size-aware-add-column`
8. `type-change-rewrite`
9. `blocking-constraint`
10. `require-concurrent-index`
11. `blocking-mat-view-refresh`
12. `blocking-partition-mutation`
13. `partition-strategy-mismatch`
14. `restrictive-policy`
15. `disable-trigger`
16. `broken-compute`
17. `function-volatility-change`
18. `missing-idempotency`
19. `concurrent-in-transaction`
20. `alter-type-add-value-txn`
21. `vacuum-full`
22. `opaque-dynamic-sql`
23. `volatile-default`
24. `overbroad-grant`
25. `schema-drift`
26. `chain-conflict`

## The Database Cache

To ensure the CI/CD pipeline runs flawlessly without requiring a live PostgreSQL instance, this directory bundles a frozen `.safe-migrate.cache` binary file. 

The tests are strictly written against the baseline schema contained within this specific cache artifact. If you add new tests that require specific table structures, constraints, or partition strategies, you must manually deploy those structures to a local PostgreSQL instance, run `safe-migrate sync`, and copy the resulting cache back into this directory.
