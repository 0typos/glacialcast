# Release operations

Run `scripts/verify-quality.sh full` from a clean checkout, then build the
reproducible archive with `scripts/build-release.sh`. Build installable Debian
and RPM packages with `scripts/build-packages.sh` and inspect them with
`packaging/verify-packages.sh`. The archive contains
`gcpub`, `gcrelay`, `gcview`, configuration examples, operator documentation,
and an SPDX SBOM. It does not contain browser assets or an offline viewer.

Deploy the relay first. Preserve its Noise identity and data directory, install
the new `relay.toml`, and verify both listeners. Version 1 DASH history is moved
to an incompatible quarantine location rather than migrated or deleted.

Then deploy publisher and viewer devices together. Protocol v9 is a clean break
from v7 and v8, and mixed-protocol operation is unsupported. Back up device
identities and approval state as secrets. Never transfer an offline CA private
key to a relay.

For rollback, stop every v9 process before restoring a complete, matching
backup of the prior binaries, configuration, identity, approval state, and
relay data. Do not point an older binary at a store already opened by a newer
release. The quarantined v1 store is retained only to permit an operator-led
legacy rollback; the relay cannot translate encrypted media between formats.
