# Contributing to GlacialCast

## Commits and versions

Keep commits focused and use Conventional Commits:

```text
<type>[(optional scope)][!]: <imperative description>
```

Examples include `feat(viewer): add retained seek control`,
`fix(protocol): reject a substituted envelope recipient`, and
`docs(deploy): explain signed relay admission`. Use `feat`, `fix`, `perf`,
`refactor`, `test`, `docs`, `build`, `ci`, `chore`, or `revert`. Mark breaking
changes with `!` and a `BREAKING CHANGE:` footer when needed. Do not include AI
attribution or co-author trailers.

Semantic Versioning follows the commit: `fix` is patch, `feat` is minor, and a
breaking change is major at/above 1.0 or minor below 1.0. Do not generate a
changelog, release commit, or tag unless explicitly requested.

## Documentation

Documentation is part of the security and compatibility surface. Library
crates deny missing rustdoc for public APIs. Document units, bounds, ordering,
errors, ownership, and security invariants rather than restating names. Every
unsafe block needs a directly preceding `SAFETY:` comment stating the concrete
soundness invariant.

Update `docs/architecture.md` for protocol/trust/retention changes,
`docs/internet-deployment.md` for listener/credential/operational changes, and
`docs/testing-demo-guide.md` for gate or acceptance changes. Update CLI help and
example TOML for every user-visible flag or setting.

## Testing

Every behavior change needs evidence at the narrowest useful layer. Bug fixes
need a regression test. Security changes need a negative rejection test.
Parsers cover bounds, every truncation, trailing data, inconsistent metadata,
and authentication failure. Async/process tests use deadlines, readiness
checks, unique temporary paths and loopback ports.

Run the normal gate before a normal commit:

```sh
scripts/verify-quality.sh standard
```

Run the full gate for behavior, protocol, security, storage, publisher, or
viewer work:

```sh
scripts/verify-quality.sh full
```

The full profile adds real native relay/publisher/viewer process orchestration,
an end-to-end decrypting protocol test, and packaging. Parser changes also run:

```sh
GLACIALCAST_FUZZ_SECONDS=30 scripts/verify-fuzz.sh
```

Wayland, portal, cursor, decoder, and hardware behavior must additionally be
tested inside a representative graphical session. Compilation or synthetic
capture is not target-platform evidence. Do not weaken assertions, extend
deadlines, skip a platform, or lower a performance floor only to hide a failure.

## Repository hygiene

Never commit build output, retained streams, credentials, private state, or
local configuration. Review staged diffs for secrets, generated artifacts, and
unrelated edits. Preserve changes that belong to another contributor.
