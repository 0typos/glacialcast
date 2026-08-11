# GlacialCast Release Operations

This runbook covers the binary archive currently produced for Linux. Releases
are manual: the repository does not create tags or publish to a package
registry. The archive includes the server, Wayland client, self-contained
offline viewer, deployment examples, operator documentation, an SPDX 2.3 SBOM,
and a sibling SHA-256 checksum.

## Release acceptance

Start from a clean `main` worktree at the intended version. Run:

```sh
scripts/verify-quality.sh full
GLACIALCAST_SOAK_SECONDS=1800 scripts/verify-quality.sh soak
```

Then run the Firefox/Chromium matrix and the Wayland cursor and video gates on
each platform claimed in `docs/support-matrix.md`. A synthetic or compile-only
pass does not promote a compositor or GPU row from pending to supported.

Build and inspect the archive:

```sh
scripts/verify-packaging.sh
ls -l dist/
```

`verify-packaging.sh` builds twice with independent Cargo target and output
directories, compares the archives, validates the checksum, requires the exact
workspace version from all three packaged binaries, checks revision provenance,
the SPDX Cargo/native-runtime inventory and systemd unit, and confirms required
documentation. Local dirty-tree artifacts are labeled with a `-dirty` revision
in the SBOM instead of claiming clean provenance. Set
`GLACIALCAST_REQUIRE_CLEAN=1` to reject them.

The compiler is fixed by `rust-toolchain.toml`; CI helper tools and GitHub
Actions are pinned as well. The manual **Release archive** GitHub workflow runs
the full deterministic and Firefox/Chromium live/offline acceptance gates for
the selected commit before a separate clean packaging job uploads the files as
a workflow artifact.

## Checksums and optional signatures

On a receiving host, keep the archive and checksum together:

```sh
sha256sum --check glacialcast-v0.5.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf glacialcast-v0.5.0-x86_64-unknown-linux-gnu.tar.gz
```

The checksum detects accidental corruption but is not an identity proof.
GlacialCast does not currently publish a project signing key. A release
operator with an established Minisign key can create a detached signature
during the build:

```sh
GLACIALCAST_MINISIGN_SECRET_KEY=/secure/path/release.key \
  scripts/build-release.sh
```

Publish the public key through a separately authenticated channel and verify
with `minisign -Vm <archive> -P <public-key>`. Never store the secret signing
key in the repository or CI artifact.

## Backup before upgrade

Stop writes before taking a portable backup:

```sh
sudo systemctl stop gcrelay
sudo tar -C / -czf glacialcast-backup-$(date +%Y%m%d%H%M%S).tar.gz \
  etc/glacialcast \
  var/lib/glacialcast
```

The data directory is one recovery unit. It contains the SQLite stream
catalog, retained object catalogs and journals, managed viewer-token hashes,
the HTTP session key, and the Noise ingest identity. Do not copy individual
files while the service is running. Keep `/etc/glacialcast` with it because it
contains bootstrap access and ingest credentials. The E2EE viewer key remains
publisher/viewer state and is not recoverable from the relay backup.

Test restoration on a non-production host when the retained history matters.
Protect backups as credentials even though media payloads are normally
end-to-end encrypted -- and unconditionally, if any publisher on the relay used
`--no-encryption`, since those payloads are stored in the clear.

## Upgrade

After verifying the archive:

1. Keep the relay stopped after the backup.
2. Install `bin/gcrelay` to `/usr/local/bin` using mode `0755`.
3. Review, then install the packaged service and configuration examples; do not
   overwrite the active private configuration with the example.
4. Run `systemctl daemon-reload`, start the relay, and request
   `/health/ready`.
5. Confirm the persistent Noise public key has not changed, a publisher
   reconnects to its prior stream, administrator metrics load, and a scoped
   viewer can play retained and new objects.
6. Upgrade publisher and offline binaries after the relay is healthy.

Wire, object, and retained-storage compatibility rules live in
`docs/compatibility.md`. Read release notes before crossing a future format
version.

## Rollback

If readiness, ingest, or playback acceptance fails, stop the service and
preserve its logs. For a code-only regression with no documented storage
migration, reinstall the previous binary and service file, then retest. If the
new release changed or may have partially changed retained state, restore the
complete pre-upgrade `/var/lib/glacialcast` and `/etc/glacialcast` snapshot
before starting the previous binary. Do not mix an old SQLite catalog with new
object catalogs or vice versa.

Restoring the prior HTTP session key preserves sessions that were valid at
backup time; rotate it if the backup may have escaped custody. Restoring the
Noise identity avoids repinning publishers. Restore managed enrollments and
bootstrap configuration together so revocation state does not regress
silently.

## Offline receiver operations

Transfer completed `.gco` files and immutable
`glacialcast-transfer-chunk-*.json` indexes, then transfer
`glacialcast-transfer.json` last and run:

```sh
glacialcast-offline verify --input /media/glacialcast-transfer
```

Missing filenames may be copied in any order and verification rerun. A checksum
or object-metadata mismatch is corruption, not an item to skip. After a clean
verification, the directory may be mounted read-only and passed to
`glacialcast-offline serve`.
