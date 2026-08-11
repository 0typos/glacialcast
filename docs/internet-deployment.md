# Internet deployment

Expose the two native TCP listeners directly or through a TCP load balancer:
publisher port 8900 and viewer port 8899. HTTP, HTTPS, WebSocket, reverse-proxy
headers, browser cookies, and Caddy are not part of the native protocol. Noise
XX encrypts and mutually authenticates each connection; stream ciphertext has
an independent publisher-to-viewer security boundary.

For an Internet relay, use signed admission:

```toml
[listeners]
publisher = "0.0.0.0:8900"
viewer = "0.0.0.0:8899"

[retention]
bytes_per_stream = 104857600
seconds_per_stream = 86400

[access]
mode = "signed"
authority_file = "/etc/glacialcast/relay-ca.pub"
revocations_file = "/etc/glacialcast/relay.crl"
```

Keep config, CA material, relay identity, SQLite state, and device credentials
as bounded regular files on local storage. Secret files and directories must
not be group/world accessible. Back up the relay Noise key if clients rely on
TOFU; replacing it otherwise requires every device to explicitly forget and
relearn the relay.

Create the CA offline, have `gcpub` and `gcview` create role-specific signed
requests, issue credentials offline, and install only the public CA and signed
revocation list at the relay. Credentials are bound to the requested role,
application identity, and Noise static key. The relay hides the catalog until
credential validation succeeds. Distribute an explicit relay Noise pin when
possible; TOFU is intentionally the low-friction fallback.

Public admission is a supported policy. It reveals stream names and lets any
Noise peer connect, but does not reveal media keys. Publisher approval remains
separate. With publisher policy `required`, a malicious relay cannot substitute
a viewer because both endpoints must confirm the same signed transcript. With
publisher policy `open`, the relay can request a viewer key by design.

Firewall each listener to the populations that need it, bound concurrent peers
at the network edge, monitor disk consumption and repeated credential failures,
and keep host time synchronized for credential and revocation validity. A
malicious relay can censor, delay, replay, and observe sizes/timing; E2EE does
not provide availability or traffic-analysis resistance.

Revoking relay admission requires a new signed CRL and relay restart. Revoking
stream access uses `gcpub revoke VIEWER_PREFIX --stream STREAM_UUID`; the
running publisher detects the per-stream approval-state change, rotates the
content key immediately, and forces an IDR. Keys already delivered cannot be
clawed back.
