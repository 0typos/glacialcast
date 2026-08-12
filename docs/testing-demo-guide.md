# Testing and demo guide

## Automated gates

Normal changes run:

```sh
scripts/verify-quality.sh standard
```

Protocol, security, storage, publisher, or viewer changes run:

```sh
scripts/verify-quality.sh full
```

The standard profile checks formatting, workspace tests, strict Clippy,
rustdoc, dependency policy, shell syntax and lint, and that every fuzz target
still compiles. The full profile adds the native process/protocol E2E gate and
release archive validation. Parser changes also run:

```sh
GLACIALCAST_FUZZ_SECONDS=30 scripts/verify-fuzz.sh
```

`verify-native-e2e.sh` uses a deterministic 64×64 OpenH264 test source. It
starts real `gcrelay`, `gcpub`, and `gcview --headless` processes with unique
temporary state and loopback ports. A relay integration test separately proves
manual two-sided pairing, durable offline queues, publisher signatures, HPKE
key delivery, retained subscription, and successful epoch/media decryption.

## Interactive demo

In three terminals:

```sh
gcrelay --no-config --data-dir /tmp/glacialcast-demo-relay
gcpub --foreground --no-config --capture test --encoder openh264 \
  --width 640 --height 360 --ingest-addr 127.0.0.1:8900
gcview 127.0.0.1:8899
```

Pair through the viewer and use `gcpub requests` followed by `gcpub approve`.
Verify the yes/no authentication string cannot be skipped. Exercise layouts
1/2/4/6, Enter/Escape fullscreen, left/right stream switching, retained slider,
and return-to-live.

For a target-host capture check, replace `--capture test` with
`--capture wayland`. Confirm the portal chooser, image content, cursor behavior,
reconnect behavior, and four concurrent streams on the actual compositor. The
viewer should be checked in both Wayland and X11 sessions when support for both
is claimed. These environment-specific observations are not inferred from a
headless CI run.

## Security acceptance

- Change a learned relay key and confirm publisher/viewer fail closed.
- Use an absent, expired, wrong-role, wrong-Noise-key, or revoked credential and
  confirm signed admission reveals no catalog.
- Tamper with descriptors, envelopes, ciphertext, sequence, or stream identity
  and confirm the viewer rejects it.
- Confirm a manual publisher decision is impossible before viewer confirmation.
- Revoke an active viewer and confirm the next group uses a new key and IDR.
- Restart each peer during pairing/history and confirm durable state resumes.
- Confirm files containing identities, approvals, credentials, and retained
  keys reject symlinks and non-private permissions.

## Release checklist

- `scripts/verify-quality.sh full` passes.
- Native test and real Wayland capture both display expected pixels.
- Four-stream viewing is responsive; six-tile layout remains usable.
- The release archive contains only `gcpub`, `gcrelay`, and `gcview` binaries.
- Config examples match current CLI help and default ports/retention.
- Any platform without target-host evidence is described as experimental.
