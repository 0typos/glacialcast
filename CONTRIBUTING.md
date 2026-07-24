# Contributing to Glacialcast

## Commit Structure

Keep commits focused and independently reviewable. Separate unrelated features,
fixes, refactors, tests, and documentation changes.

This repository uses Conventional Commits:

```text
<type>[(optional scope)][!]: <imperative description>
```

Examples:

```text
feat(viewer): recover live DASH playback
fix(capture): retain DMA-BUF until conversion completes
test(browser): cover Firefox history seeking
docs: document VA-API prerequisites
```

Scopes are encouraged when they clarify the affected subsystem, but are not
required. Common scopes include `client`, `server`, `protocol`, `viewer`,
`capture`, `browser`, `scripts`, `docs`, `build`, and `ci`.

Supported types are:

- `feat` for user-visible functionality
- `fix` for defect corrections
- `perf` for performance improvements
- `refactor` for behavior-preserving restructuring
- `test` for test-only changes
- `docs` for documentation-only changes
- `build` for dependencies or build-system changes
- `ci` for continuous-integration changes
- `chore` for other repository maintenance
- `revert` for reverting an earlier commit

Use an imperative, concise subject without a trailing period. Mark breaking
changes with `!` and add a `BREAKING CHANGE:` footer when further explanation is
needed.

Commit messages must not contain AI attribution, AI-assistance statements,
generated-by notices, or AI co-author trailers. Commit signing and
`Signed-off-by` trailers are not currently required.

## Versioning

Glacialcast uses Semantic Versioning derived from Conventional Commits:

- `fix` increments the patch version.
- `feat` increments the minor version.
- Breaking changes increment the major version at or above `1.0.0`.
- Breaking changes increment the minor version below `1.0.0`.

Other commit types do not increment the version unless they introduce a
breaking change. Changelog generation and release tags are not currently part
of the release process.

## Before Committing

Run the checks relevant to the change. The complete local quality gate is:

```sh
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
bash -n scripts/*.sh
scripts/verify-dash-e2e.sh
```

The Wayland, VA-API, and browser gates require the host capabilities documented
in `README.md`. Never commit build output, retained stream data, test reports,
credentials, or local configuration containing secrets.
