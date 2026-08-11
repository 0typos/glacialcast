# GlacialCast

GlacialCast is a native Linux screen-streaming system with three programs:

- `gcpub` captures Wayland screens, encrypts them end to end, and approves viewers.
- `gcrelay` stores and forwards opaque history without receiving media keys.
- `gcview` is an egui viewer for 1, 2, 4, or 6 streams on Wayland or X11.

There are no shared stream passphrases. Every device keeps an Ed25519/X25519
identity, every relay hop uses Noise XX, and publishers send signed HPKE key
envelopes only to approved viewer identities. A changed relay TOFU key fails
closed. The relay can delay or drop data, but cannot decrypt or forge a stream.

## Quick start

Build and start a public-admission relay (stream names are public; media is not):

```sh
cargo build --release --workspace
target/release/gcrelay --no-config --data-dir ./relay-data
```

Publish the desktop:

```sh
target/release/gcpub --foreground --capture wayland \
  --ingest-addr relay.example:8900
```

Connect the viewer:

```sh
target/release/gcview relay.example:8899
```

Select a stream and click **Pair**. Compare the three words and two digits shown
by viewer and publisher through an independent channel. The viewer must answer
yes, then the publisher lists and accepts the confirmed request:

```sh
target/release/gcpub --relay relay.example:8900 requests
target/release/gcpub --relay relay.example:8900 approve REQUEST_PREFIX
# or approve every request that has already completed viewer confirmation
target/release/gcpub --relay relay.example:8900 approve-all
```

Approval is permanent for that viewer identity on the requested stream only.
`gcpub revoke VIEWER_PREFIX --stream STREAM_UUID` removes that grant
immediately; an active publisher rotates the group key and forces a new IDR
before publishing more.

The viewer exposes **History**, a retained-range slider, **Go**, and **Live**.
Newly approved viewers receive retained key envelopes newest-first, so older
history can become playable after live playback starts.

## Configuration

The relay reads `relay.toml`; see `packaging/server.toml.example`. Defaults are
ports 8900/8899 and 100 MiB or 24 hours retained per stream. `[access]` may be
`public` or `signed`. Signed mode accepts only CA credentials bound to the
device identity, Noise key, role, validity, and current revocation list. The
`[limits]` section bounds connections, handshakes, idle sessions, live queues,
streams, group objects and bytes, envelopes, and global/per-publisher storage.
In signed mode the relay reloads a valid replacement CRL within one second.

The publisher reads private `client.toml`; see
`packaging/client.toml.example`. `history_bytes` and `history_seconds` bound the
private group-key history used to authorize a new viewer. Defaults are 100 MiB
and 24 hours.

Viewer approval policy lives in the publisher state directory as private
`config.toml`; see `packaging/publisher.toml.example`. The running publisher
reloads this policy and its revocation list while it polls for requests:

```toml
[viewers]
policy = "required" # required, open, or trusted_ca
# trusted_authority_file = "/secure/viewer-ca.pub"
# trusted_revocations_file = "/secure/viewer-ca.crl"
```

`open` approves every requesting identity. It preserves wire encryption but a
malicious relay can request approval as a viewer, so use it only when that is
the intended policy. `trusted_ca` automatically approves a valid viewer
credential embedded in its signed pairing request.

Create and use an offline CA with `gcrelay pki create-ca`, device
`credential-request` commands, `gcrelay pki issue`, and `gcrelay pki revoke`.
Exact arguments are available through `--help`.

## Verification and documentation

```sh
scripts/verify-quality.sh standard
scripts/verify-quality.sh full
scripts/verify-native-e2e.sh
```

The native E2E gate starts real relay, publisher, and viewer-diagnostic
processes. Its protocol integration test also performs both sides of pairing,
opens an HPKE envelope, and decrypts retained signed media.

See [architecture](docs/architecture.md), [Internet deployment](docs/internet-deployment.md),
[testing](docs/testing-demo-guide.md), and [compatibility](docs/compatibility.md).
