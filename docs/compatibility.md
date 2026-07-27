# Compatibility Policy

GlacialCast is pre-1.0 software. Its supported compatibility unit is the whole
release: publisher, relay, live viewer assets, offline mirror, and offline
viewer should use the same minor version unless a release note explicitly
states otherwise. Rolling upgrades and mixed-minor operation are not yet a
compatibility promise.

## Versioned boundaries

GlacialCast has separate version checks because each boundary evolves for a
different reason:

- `PROTOCOL_VERSION` covers the Postcard publisher/relay messages carried by
  Noise. Peers reject any unequal version before normal ingest.
- `DASH_FORMAT_VERSION` covers authenticated object metadata and the portable
  `GCO1` representation. The relay and offline tools reject unknown versions.
- The JSON transfer index has an independent version. Writers publish a compact
  v2 root manifest plus immutable v1 chunk files; readers continue to accept
  the legacy v1 root manifest. An unknown root or chunk version is rejected.
- Epoch descriptors carry their own format version and cryptographic
  parameters. Viewers reject a descriptor they cannot validate.
- The constrained fMP4/CENC profile is standards-based but intentionally
  narrow. Any change must still pass Firefox-first and Chromium playback gates.
- The catalog snapshot and journal are relay-internal recovery formats. A
  release must either read the previous durable format or provide an explicit
  migration and rollback procedure.

The relay cannot translate encrypted media or cursor payloads because it does
not have the viewer key. Compatibility shims therefore belong at the
publisher/viewer boundary, not in the opaque relay.

## Change rules

An incompatible wire, portable-object, epoch, or retained-storage change below
1.0 requires:

1. A minor Semantic Versioning increment and the applicable format constant
   increment.
2. A clear error for the prior version; silent reinterpretation is forbidden.
3. Updated architecture and deployment documentation, including retained-data
   and rollback consequences.
4. Updated golden vectors and parser fuzz targets.
5. Full live, recovery, offline-transfer, Firefox, and Chromium gates.

Appending a field to a Rust type is not assumed compatible with Postcard.
Changing field order, enum variant order, integer representation, canonical
authentication bytes, key derivation, MIME meaning, or timing units requires
the same explicit review.

Additive HTTP JSON fields are compatible when existing fields retain their
meaning and clients ignore unknown fields. Removing or redefining a field,
route, authorization rule, or configuration default is incompatible.

## Protocol version history

| Version | Change |
| --- | --- |
| 6 | `StreamHello.source_label`, so one authenticated publisher can own several durable stream identities. |
| 7 | `StreamHello.viewer_key_salt`, the public per-publisher salt a viewer needs to turn a key phrase into the viewer key. `PublicStream` gained `publisher` and `viewer_key_salt` alongside it. |

Version 7 also changes how a viewer key is shared, without changing what a
viewer key is. Key material is still 32 bytes and the epoch derivation is
untouched, so retained objects and portable files are unaffected. A publisher
whose key file predates the change keeps sharing raw base64 and sends no salt;
its viewers are unaffected. `--new-viewer-key` opts into a phrase and, by
design, invalidates keys already shared.

## Golden vectors and fuzzing

[`test-vectors/protocol-v7.json`](../test-vectors/protocol-v7.json) fixes the
derived keys and exact portable bytes for deterministic test inputs. The
workspace test decodes and authenticates it on every normal test run.

The six fuzz targets cover portable objects, cursor envelopes, Noise segment
headers, epoch descriptors, relay catalog-journal records, and both generations
of transfer-index JSON. Transfer-index compatibility is additionally fixed by
unit vectors that exercise legacy v1, chunked v2, checksum failure, duplicate
metadata, symlink rejection, and size limits:

```sh
GLACIALCAST_FUZZ_SECONDS=30 scripts/verify-fuzz.sh
```

Fuzzing uses the repository-pinned nightly and a temporary working corpus.
Crashing inputs are retained under `fuzz/artifacts/` and uploaded by the
nightly workflow; generated corpus growth is not committed automatically.
