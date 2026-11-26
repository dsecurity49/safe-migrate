# Live Tests

These SQL fixtures feed three test suites:

1. **`./run.sh`**: lints every fixture directory offline against the frozen
   `live_tests/.safe-migrate.cache` (`Cache V12.1`).
2. **`scripts/live-differential`**: executes enabled fixtures from
   `differential_manifest.json` against a disposable local PostgreSQL database
   (`safe_migrate`) and verifies that safe-migrate's simulated schema state,
   catalog dependencies, and expected PostgreSQL error SQLSTATEs match live
   PostgreSQL 14–18.
3. **`scripts/live-catalog-sync`**: seeds routines, types, publications, and a
   disconnected subscription, then verifies their Cache V12.1 round-trip and
   secret redaction.

## Fixture conventions

- `safe_*.sql` must **not** emit the directory's target rule.
- `[0-9]*.sql` **must** emit the directory's target rule.
- Most directories lint each file independently (`safe-migrate lint -f <file>`);
  `rule_26_chain-conflict` also runs `lint-chain`.

### Regenerating `.safe-migrate.cache`

The frozen `.safe-migrate.cache` is part of the test corpus. Update it only when
`differential_baseline.sql` or the cache format changes:

```bash
psql "$DATABASE_URL" -f live_tests/differential_baseline.sql
psql "$DATABASE_URL" -c "ANALYZE;"
cargo run --locked -- sync --out live_tests/.safe-migrate.cache
```

## Running the suites

```bash
# 1. Offline cached fixtures
cd live_tests
./run.sh
./run.sh -v -d rule_26_chain-conflict
./run.sh --offline

# 2. Live PostgreSQL differential suite (run from repository root)
export DATABASE_URL='postgres://postgres@127.0.0.1:5432/safe_migrate'
scripts/live-differential -v
scripts/live-differential -vv --rule rule_09_blocking-constraint
scripts/live-differential -vv --fixture rule_26_chain-conflict/011_missing_fk_source_column.sql
scripts/live-catalog-sync
```

Verbosity flags for `scripts/live-differential`:
- `-v`: per-fixture lifecycle and pass/fail status.
- `-vv`: cache and normalized-state object counts.
- `-vvv`: full normalized PostgreSQL vs. simulator state dumps.

## Sourced real-world cases

- **Stage foreign-key validation (`NOT VALID` + `VALIDATE CONSTRAINT`)**:
  `rule_09_blocking-constraint/safe_011_foreign_key_not_valid.sql` and
  `safe_012_foreign_key_validate_later.sql`
  ([GitLab FK guide](https://docs.gitlab.com/development/database/foreign_keys/),
  [PostgreSQL 18 `ALTER TABLE`](https://www.postgresql.org/docs/18/sql-altertable.html)).
- **Reject foreign key on a missing column (SQLSTATE `42703` -> `chain-conflict`)**:
  `rule_26_chain-conflict/011_missing_fk_source_column.sql`
  ([GitLab issue #63612](https://gitlab.com/gitlab-org/gitlab-ce/-/issues/63612)).
- **Attach prebuilt unique index (`UNIQUE ... USING INDEX`)**:
  `rule_09_blocking-constraint/safe_013_unique_using_index.sql`
  ([GitLab MR !189882](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/189882),
  [Discourse migration](https://github.com/discourse/discourse/blob/main/db/migrate/20240820123405_swap_big_int_notifications_id.rb)).
