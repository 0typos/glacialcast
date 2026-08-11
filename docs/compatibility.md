# Compatibility Policy

GlacialCast is pre-1.0 software. Its supported compatibility unit is the whole
release: `gcpub`, `gcrelay`, and `gcview` use the same minor version unless a
release note explicitly says otherwise. Rolling upgrades and mixed-minor
operation are not yet compatibility promises.

## Versioned boundaries

GlacialCast version-checks each boundary that can otherwise be silently
misinterpreted:

- `PROTOCOL_VERSION` covers bounded Postcard publisher/relay, viewer/relay, and
  relayed publisher/viewer pairing messages carried by Noise XX.
- `STREAM_FORMAT_VERSION` covers canonical signed object headers, AEAD
  associated data, key envelopes, stream descriptors, and codec identifiers.
- Native identity documents, credentials, revocation lists, known-relay state,
  and publisher/viewer private state each carry an independent version.
- The relay catalog snapshot and checksummed journal are internal durable
  formats. A release either reads the preceding format or performs a documented,
  fail-closed migration/quarantine operation.

The relay cannot translate encrypted media, cursor payloads, or key envelopes
because it has no content key and cannot forge publisher signatures.
Compatibility shims therefore belong at the publisher/viewer boundary, not in
the opaque relay.

## Change rules

An incompatible wire, stream-object, credential, identity, or retained-storage
change below 1.0 requires:

1. a minor Semantic Versioning increment and the applicable format constant
   increment;
2. a clear error for the prior version—silent reinterpretation is forbidden;
3. updated architecture, security, deployment, and retained-data documentation;
4. updated golden vectors and bounded parser fuzz targets;
5. full live, malicious-relay, credential, recovery, native-viewer, and
   representative Wayland gates.

Appending a field to a Rust type is not assumed compatible with Postcard.
Changing field or enum-variant order, integer representation, canonical signing
bytes, AEAD associated data, transcript construction, domain labels, key
derivation, nonce construction, timing units, role meaning, or codec identifier
requires the same explicit review.

Additive configuration keys are compatible when old behavior remains safe.
Removing or redefining a key, policy, default, binary, or listener is
incompatible. Removed security-sensitive keys produce actionable errors rather
than being silently ignored.

## Version history

| Release/protocol | Change |
| --- | --- |
| 0.5 / v7 | Browser DASH/CENC format, publisher viewer-key salt, portable `GCO1` objects, and Noise NK publisher ingest. |
| 0.6 / v8 | Native `gcpub`/`gcrelay`/`gcview`; Noise XX relay transports; persistent device identities; native credentials; verified pairing; publisher-signed AEAD stream format v2; HPKE viewer envelopes; H.264 Annex-B payloads. Browser and portable formats are removed. |

Version 8 is a clean break. Version 7 peers are rejected before normal traffic.
The relay does not migrate version 1 DASH history. On first 0.6 startup it moves
the old store to an explicitly named incompatible quarantine path without
deleting it, creates an empty version 2 store, and logs the rollback consequence.

## Golden vectors and fuzzing

Protocol v8 vectors fix canonical identities, credentials, pairing transcripts,
short authentication strings, signatures, key envelopes, encrypted stream
objects, and exact Postcard messages for deterministic test keys. No production
secret or random fixture is committed.

Fuzz targets cover every untrusted binary or structured boundary, including
Noise segmentation, native credentials and revocation lists, pairing messages,
encrypted stream headers, key envelopes, and H.264 epoch payloads. Parsers must
cover maximum sizes, truncation, trailing data,
unknown versions, invalid enums, inconsistent lengths, and authentication
failure.

Run the bounded suite with:

```sh
GLACIALCAST_FUZZ_SECONDS=30 scripts/verify-fuzz.sh
```

Crashing inputs are retained under `fuzz/artifacts/` and uploaded by the nightly
workflow. Generated corpus growth is not committed automatically.
