# Contributing to GlacialCast

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

GlacialCast uses Semantic Versioning derived from Conventional Commits:

- `fix` increments the patch version.
- `feat` increments the minor version.
- Breaking changes increment the major version at or above `1.0.0`.
- Breaking changes increment the minor version below `1.0.0`.

Other commit types do not increment the version unless they introduce a
breaking change. Changelog generation and release tags are not currently part
of the release process.

## Documentation Standard

Documentation is part of the compatibility and security surface.

- Every crate must have crate-level rustdoc. Library crates must additionally
  deny missing documentation for public items.
- Every public type, field, variant, constant, and function must explain its
  purpose. Document units, size limits, ownership, ordering, error behavior,
  and security-sensitive invariants where they are not obvious from the type.
- Explain why a non-obvious algorithm or unsafe boundary is correct near the
  implementation. Do not use comments that merely restate the code.
- Add a compiling rustdoc example when a public API has a non-obvious usage
  contract. Examples are tested by `cargo test --doc`.
- User-visible flags and configuration keys must have CLI help or adjacent
  example-configuration comments.
- Update `docs/architecture-v0.2.md` when wire formats, trust boundaries,
  retention, encryption, or supported media behavior changes.
- Update `docs/internet-deployment.md` when an operational default, public
  listener, credential, proxy, backup, or monitoring behavior changes.
- Update `docs/testing-demo-guide.md` when a gate, prerequisite, or manual
  acceptance procedure changes.
- Do not copy volatile test counts, performance values, or environment-specific
  paths into multiple documents unless they are explicitly identified as a
  dated observation.

Strict rustdoc is enforced by the standard quality profile:

```sh
env RUSTDOCFLAGS="-D warnings -D missing-docs" cargo doc --workspace --no-deps
```

## Testing Standard

Every behavior change must include evidence at the narrowest useful layer:

- Unit tests cover pure transformations, state machines, boundary values, and
  malformed inputs.
- A bug fix includes a regression test that fails for the original defect.
- Parsers and authenticated formats cover maximum sizes, truncation, trailing
  data, inconsistent metadata, and authentication failure.
- Async and multi-process tests use explicit deadlines and readiness checks;
  they must not rely on an unbounded sleep.
- Tests use unique temporary paths and loopback ports, clean up child
  processes, and never use production credentials or retained data.
- The deterministic `dash-test` source is preferred when portal or GPU behavior
  is not the subject of the test.
- Browser changes cover Firefox first and Chromium second. Cursor changes must
  prove paint, movement, hide, and restore independently of video cadence.
- Wayland, portal, cursor-metadata, VA-API, and DMA-BUF changes run the matching
  host gate on representative hardware before release.
- Security changes include a negative test proving the protected action or
  malformed input is rejected.

Do not weaken an assertion, increase a deadline, skip a platform, or lower a
performance floor solely to make a failure disappear. Record the cause and
justify any intentional threshold change in the commit.

Coverage is a diagnostic rather than a quota:

```sh
cargo llvm-cov --workspace --all-features --summary-only
```

Use it to find untested branches in changed code. Process orchestration and
hardware integrations may be better covered by the repository's explicit
multi-process and host gates than by a line-percentage target.

## Quality Gates

The normal commit gate is:

```sh
scripts/verify-quality.sh standard
```

It enforces formatting, all Rust tests, warning-free Clippy, strict rustdoc,
dependency policy, shell syntax, and viewer-core tests.

Before merging or releasing behavior changes, run:

```sh
scripts/verify-quality.sh full
```

The full profile includes the standard profile plus synthetic encrypted
DASH/offline playback, forced-crash ingest recovery, Internet authorization and
hardening, and release performance floors.

Environment-specific gates remain explicit:

```sh
scripts/verify-internet-browser.sh
scripts/verify-wayland-cursor-metadata.sh
scripts/verify-wayland-video-hardware.sh
```

The browser gate requires Docker and Playwright. Wayland and hardware gates
must run inside the target graphical session; see
`docs/testing-demo-guide.md`.

Documentation-only changes may run the standard gate. Rust behavior, protocol,
security, storage, or viewer changes require the full gate plus any affected
environment-specific gate.

## Repository Hygiene

Never commit build output, retained stream data, test reports, credentials, or
local configuration containing secrets. Before committing, review both
`git status --short` and the staged diff. Preserve unrelated user changes and
keep generated test artifacts outside the repository.
