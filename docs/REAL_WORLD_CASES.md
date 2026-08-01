# Real-world-inspired migration cases

These cases are independently minimized from public PostgreSQL migration
documentation, incident reports, and open-source migrations. They are not user
submissions, and the SQL is not copied from a production migration.

Each admitted case has three requirements:

1. A public source establishes that the pattern occurs in real migration work.
2. PostgreSQL documentation establishes the database behavior being tested.
3. A focused fixture compares safe-migrate's result with a disposable PostgreSQL
   database.

## RWI-001: stage foreign-key validation

GitLab documents adding foreign keys without validating existing rows and
validating them later. PostgreSQL specifies that `NOT VALID` skips the initial
table scan while still enforcing the constraint for new writes; `VALIDATE
CONSTRAINT` performs the later scan with a less restrictive lock.

Hypothesis:

- Adding a foreign key with `NOT VALID` must not emit `blocking-constraint`.
- The simulator must record the new foreign key as unvalidated.
- A later `VALIDATE CONSTRAINT` must change the same constraint to validated.

Fixtures:

- `rule_09_blocking-constraint/safe_011_foreign_key_not_valid.sql`
- `rule_09_blocking-constraint/safe_012_foreign_key_validate_later.sql`

Sources:

- [GitLab foreign-key guidance](https://docs.gitlab.com/development/database/foreign_keys/)
- [PostgreSQL 18 `ALTER TABLE`](https://www.postgresql.org/docs/18/sql-altertable.html)

## RWI-002: foreign key references a missing column

A GitLab 12 upgrade failed when a migration attempted to create a foreign key
on `parent_id` although that column was absent. This is a schema-ordering
failure that static state simulation can detect without inspecting table data.

Hypothesis:

- PostgreSQL must reject the minimized statement with SQLSTATE `42703`
  (`undefined_column`).
- safe-migrate must emit `chain-conflict` and must not apply the foreign-key
  mutation.

Fixture:

- `rule_26_chain-conflict/011_missing_fk_source_column.sql`

Source:

- [GitLab migration failure: missing foreign-key column](https://gitlab.com/gitlab-org/gitlab-ce/-/issues/63612)

The differential manifest records both the expected SQLSTATE and the expected
safe-migrate rule. An unexpected PostgreSQL success, a different SQLSTATE, or a
missing finding fails the harness.

## RWI-003: convert a prebuilt unique index into a constraint

GitLab and Discourse both use `... USING INDEX ...` while changing primary-key
topology. PostgreSQL recommends first building a unique index concurrently and
then converting it to a `UNIQUE` or `PRIMARY KEY` constraint to avoid a long
blocking index build.

Hypothesis:

- A `UNIQUE ... USING INDEX` action must be represented as an index-backed
  constraint instead of an ordinary index-building constraint.
- It must not emit `blocking-index-constraint` merely for attaching the
  already-built index.
- The simulator and PostgreSQL must agree on the resulting constraint kind and
  validation state.

Fixture:

- `rule_09_blocking-constraint/safe_013_unique_using_index.sql`

Sources:

- [GitLab primary-key conversion](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/189882)
- [Discourse bigint primary-key swap](https://github.com/discourse/discourse/blob/main/db/migrate/20240820123405_swap_big_int_notifications_id.rb)
- [PostgreSQL 18 `ALTER TABLE`](https://www.postgresql.org/docs/18/sql-altertable.html)

PostgreSQL can still scan columns when attaching a primary key if the indexed
columns are nullable. The current fixture uses `UNIQUE`, for which PostgreSQL
documents the attachment as a fast operation; it does not generalize that claim
to every primary-key conversion.

## Reviewed patterns that did not add fixtures

Discourse consistently pairs concurrent index operations with
`disable_ddl_transaction!`. safe-migrate already has positive and negative
coverage for concurrent index operations and explicit transaction blocks, so
adding framework-syntax copies would not exercise a new SQL behavior.

Public incidents also show `VALIDATE CONSTRAINT` failing because old rows
violate a foreign key. That depends on table contents, which safe-migrate does
not cache or inspect. These reports establish an important boundary, not a
static-analysis result: safe-migrate can model an unvalidated constraint and
its validation transition, but it cannot promise that existing data will pass
validation.

- [GitLab foreign-key validation failure](https://gitlab.com/gitlab-org/gitlab/-/issues/353266)

## Reproducing the proof

Run the focused cases against a disposable local PostgreSQL database:

```bash
scripts/live-differential -vv --rule rule_09_blocking-constraint
scripts/live-differential -vv --fixture rule_26_chain-conflict/011_missing_fk_source_column.sql
```

The ordinary frozen-cache fixture runner remains useful for checking diagnostic
expectations:

```bash
live_tests/run.sh -v -d rule_09_blocking-constraint
live_tests/run.sh -v -d rule_26_chain-conflict
```
