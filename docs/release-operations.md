# Release operations

Run `scripts/verify-quality.sh full` from a clean checkout, then build the
reproducible archive with `scripts/build-release.sh`. The archive contains
`gcpub`, `gcrelay`, `gcview`, configuration examples, operator documentation,
and an SPDX SBOM. It does not contain browser assets or an offline viewer.

Deploy the relay first. Preserve its Noise identity and data directory, install
the new `relay.toml`, and verify both listeners. Version 1 DASH history is moved
to an incompatible quarantine location rather than migrated or deleted.

Then deploy publisher and viewer devices together. Protocol v8 is a clean break
and mixed v7/v8 operation is unsupported. Back up device identities and
approval state as secrets. Never transfer an offline CA private key to a relay.

For rollback, stop v8 processes before restoring prior binaries and their data.
The quarantined v1 store is the only supported source for a v7 rollback; v8
native objects cannot be translated by the relay because it has no media keys.
