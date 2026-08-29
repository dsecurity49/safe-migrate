# Release checklist

Use this checklist for every safe-migrate release. Run it against the exact
commit that will be tagged; do not treat a passing development worktree as
proof that the packaged release contents pass.

## Version and contract updates

- [ ] Set the same version in `Cargo.toml` and the `safe-migrate` package entry
  in `Cargo.lock`.
- [ ] Update the exact-version expectation in `scripts/test-action-contract`.
- [ ] Update exact Action references in `README.md` and
  `docs/GITHUB_ACTIONS.md`.
- [ ] Recheck `docs/CONTRACT.md`; document any CLI, JSON, Markdown, cache, exit
  status, or Action behavior change before release.
- [ ] Add the dated, user-visible release entry to `CHANGELOG.md`.
- [ ] Confirm the intended tag is exactly `v` followed by the Cargo package
  version. The release workflow independently rejects a mismatch.

## Validation from the release commit

- [ ] Run `cargo fmt -- --check`.
- [ ] Run `cargo build --locked` and `cargo test --locked`.
- [ ] Run `cargo clippy --all-targets --locked -- -D warnings`.
- [ ] Run `cargo audit` with the pinned CI tool version.
- [ ] Run `scripts/fuzz` and `live_tests/run.sh`.
- [ ] Run `scripts/test-install-dry-run` and `scripts/test-action-contract`.
- [ ] Run the PostgreSQL 14–18 sync, encryption, automatic-sync, catalog, and
  differential matrix in CI.
- [ ] Confirm Rust 1.94 and current stable jobs pass.
- [ ] Confirm Linux, macOS, Windows, and Termux runtime/install coverage passes.
- [ ] Run `cargo package --locked`, inspect `cargo package --list --locked`, and
  test the resulting `.crate` rather than an uncommitted source tree.
- [ ] Confirm diagnostics and artifacts contain no database URL, cache key,
  subscription connection string, credentials, or private database data.

## Publication

- [ ] Create and push the exact `v<version>` tag only after every required gate
  is green.
- [ ] Verify the GitHub release contains every supported archive and SHA-256
  checksum and that installer smoke tests use those assets.
- [ ] Publish the exact verified package with `cargo publish --locked` so the
  documented `cargo install safe-migrate --locked` path remains supported.
- [ ] Verify the crates.io version, GitHub tag, binary `--version`, and Action
  reference all agree before announcing the release.
