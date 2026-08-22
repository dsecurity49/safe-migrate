# Live Tests

These SQL fixtures feed two suites:

- `run.sh` lints fixtures against the frozen local cache. It does not execute
  SQL in PostgreSQL.
- `scripts/live-differential` compares safe-migrate's modeled result with a
  disposable PostgreSQL database for fixtures enabled in
  `differential_manifest.json`.
- `scripts/live-catalog-sync` seeds routines, publications, and a disconnected
  subscription, then verifies their Cache V6 representation and connection
  redaction.

For expected PostgreSQL failures, the manifest records the SQLSTATE and required
safe-migrate rule. The harness fails if either differs.

## Fixture convention

- `safe_*.sql` must not emit the directory's target rule.
- `[0-9]*.sql` must emit the directory's target rule.

The frozen `.safe-migrate.cache` is part of the test corpus. Update it only
when fixtures require a different baseline, and regenerate it with
`safe-migrate sync`; do not edit it in place.

## Cached fixture suite

From this directory:

```bash
./run.sh
./run.sh -v
./run.sh -d rule_25_schema-drift
./run.sh -t rule_01_irreversible-migration/001_drop_table.sql
./run.sh --offline
```

`--offline` passes `--no-cache`, so baseline-dependent findings can differ.
Most directories lint each file independently; chain-conflict fixtures use
`lint-chain`.

## PostgreSQL differential suite

Run from the repository root with a disposable local database:

```bash
export DATABASE_URL='host=/path/to/socket dbname=safe_migrate user=my_user'
scripts/live-differential -v
scripts/live-catalog-sync
```

Both live suites accept only a local database named `safe_migrate` and execute
DDL. The differential harness rebuilds `differential_baseline.sql` before each
enabled fixture. Never point either suite at a shared or production database.

## Sourced differential cases

These fixtures reduce patterns from public migrations and incident reports.
`scripts/live-differential` compares safe-migrate's model with a disposable
PostgreSQL database.

### Stage foreign-key validation

GitLab documents adding foreign keys without validating existing rows and
validating them later. PostgreSQL documents that `NOT VALID` skips the initial
scan while enforcing the constraint for new writes; `VALIDATE CONSTRAINT`
performs the later scan with a less restrictive lock.

Expected behavior:

- `NOT VALID` does not emit `blocking-constraint`.
- The simulator records the foreign key as unvalidated.
- `VALIDATE CONSTRAINT` updates the same constraint to validated.

Fixtures:

- `rule_09_blocking-constraint/safe_011_foreign_key_not_valid.sql`
- `rule_09_blocking-constraint/safe_012_foreign_key_validate_later.sql`

Sources:

- [GitLab foreign-key guidance](https://docs.gitlab.com/development/database/foreign_keys/)
- [PostgreSQL 18 `ALTER TABLE`](https://www.postgresql.org/docs/18/sql-altertable.html)

### Reject a foreign key on a missing column

A GitLab 12 upgrade failed when a migration created a foreign key on an absent
`parent_id` column. Static state simulation can detect this ordering error
without reading table data.

Expected behavior:

- PostgreSQL returns SQLSTATE `42703` (`undefined_column`).
- safe-migrate emits `chain-conflict` and does not apply the foreign-key
  mutation.

Fixture:

- `rule_26_chain-conflict/011_missing_fk_source_column.sql`

Source:

- [GitLab migration failure: missing foreign-key column](https://gitlab.com/gitlab-org/gitlab-ce/-/issues/63612)

### Attach a prebuilt unique index

GitLab and Discourse use `... USING INDEX ...` while changing primary-key
topology. PostgreSQL documents building a unique index concurrently and then
attaching it as a `UNIQUE` or `PRIMARY KEY` constraint to avoid a blocking index
build.

Expected behavior:

- `UNIQUE ... USING INDEX` becomes an index-backed constraint.
- Attaching the existing index does not emit `blocking-index-constraint`.
- The simulator and PostgreSQL agree on constraint kind and validation state.

Fixture:

- `rule_09_blocking-constraint/safe_013_unique_using_index.sql`

Sources:

- [GitLab primary-key conversion](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/189882)
- [Discourse bigint primary-key swap](https://github.com/discourse/discourse/blob/main/db/migrate/20240820123405_swap_big_int_notifications_id.rb)
- [PostgreSQL 18 `ALTER TABLE`](https://www.postgresql.org/docs/18/sql-altertable.html)

`PRIMARY KEY` attachment may still scan nullable indexed columns. This fixture
covers `UNIQUE` only.

### Data-dependent validation

safe-migrate does not cache row data. It can model an unvalidated constraint and
its validation transition, but it cannot determine whether existing rows will
pass validation.

- [GitLab foreign-key validation failure](https://gitlab.com/gitlab-org/gitlab/-/issues/353266)

Run the sourced cases:

```bash
scripts/live-differential -vv --rule rule_09_blocking-constraint
scripts/live-differential -vv --fixture rule_26_chain-conflict/011_missing_fk_source_column.sql
```

Useful selectors:

```bash
scripts/live-differential -vv --rule rule_01_irreversible-migration
scripts/live-differential --fixture rule_01_irreversible-migration/001_drop_table.sql
```

Verbosity is cumulative:

- `-v` shows lifecycle and fixture outcomes.
- `-vv` adds cache and normalized-state counts.
- `-vvv` prints complete normalized PostgreSQL and simulator projections.

CI runs the enabled manifest against PostgreSQL 14, 15, 16, 17, and 18 and
uploads one verbose log per version. Excluded fixtures remain documented in
`differential_manifest.json` with their reasons.
