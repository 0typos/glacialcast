# Internet Deployment

GlacialCast has an Internet deployment profile in which the Rust relay listens
for browser traffic only on loopback and Caddy owns the public HTTPS endpoint.
The publisher endpoint remains a separate Noise-encrypted TCP service. Do not
publish the relay's plaintext HTTP port.

## Trust boundaries

- Caddy terminates TLS, renews the public certificate, overwrites
  `X-Forwarded-For`, and proxies HTTP and WebSocket traffic to
  `127.0.0.1:8899`.
- The relay authenticates browser access itself. Viewer sessions are signed,
  `HttpOnly`, `Secure`, and `SameSite=Strict`; state changes additionally
  require an exact origin and a session-bound CSRF value.
- Viewer principals can read only streams published by configured ingest
  identities. Administrators can read and delete every stream and inspect
  relay counters.
- Publisher traffic on port 8900 is encrypted to the client's pinned Noise
  server key before credentials are sent. Internet-facing ingest requires a
  strong token.
- CENC and cursor encryption remain end to end. TLS and relay authorization do
  not give the relay the viewer key.

The relay still observes stream timing, dimensions, object sizes, client IP
addresses, and availability. GlacialCast does not attempt traffic-analysis
resistance.

## Host setup

Build the release binaries, create a dedicated service account, and install the
server:

```sh
cargo build --workspace --release
sudo useradd --system --home-dir /var/lib/glacialcast --shell /usr/sbin/nologin glacialcast
sudo install -D -o root -g root -m 0755 \
  target/release/glacialcast-server /usr/local/bin/glacialcast-server
sudo install -d -o glacialcast -g glacialcast -m 0700 /var/lib/glacialcast
sudo install -d -o glacialcast -g glacialcast -m 0700 /etc/glacialcast
sudo install -o glacialcast -g glacialcast -m 0600 \
  deploy/server.internet.toml.example /etc/glacialcast/server.toml
sudo install -o root -g root -m 0644 \
  deploy/glacialcast-server.service /etc/systemd/system/glacialcast-server.service
```

Generate independent values for every token:

```sh
openssl rand -base64 32
```

Edit `/etc/glacialcast/server.toml`, set `security.public_origin` to the final
HTTPS origin, and replace every example token. Token names and publisher scopes
accept only letters, digits, dot, dash, and underscore. A viewer's
`publishers` entries refer to ingest token names.

Install Caddy using its supported package for the host, copy
`deploy/Caddyfile.example` to the distribution's Caddyfile location, and set
`GLACIALCAST_DOMAIN` in Caddy's service environment. Caddy obtains and renews
the certificate when public DNS points at the host and ports 80 and 443 are
reachable. If another CDN or proxy sits in front of Caddy, configure Caddy's
global trusted-proxy policy instead of forwarding arbitrary client-supplied
addresses.

The application validates the browser `Origin` against `public_origin`, so the
scheme, hostname, and non-default port must match exactly.

Enable the services:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now glacialcast-server caddy
curl --fail https://cast.example.com/health/ready
```

Expose only:

- TCP 80 and 443 to Caddy; and
- TCP 8900 to authenticated publishers.

Keep TCP 8899 blocked from every non-loopback interface. The server refuses a
non-loopback HTTP bind unless the operator supplies the explicitly unsafe
`--allow-insecure-http` escape hatch.

## Publisher setup

Print and record the persistent relay identity:

```sh
sudo -u glacialcast /usr/local/bin/glacialcast-server \
  --config /etc/glacialcast/server.toml \
  --control-addr 127.0.0.1:8899 \
  --ingest-addr 0.0.0.0:8900 \
  --data-dir /var/lib/glacialcast \
  --print-ingest-server-key
```

Configure the publisher with the Internet hostname and port, the pinned public
key, its ingest token, and its separate viewer key:

```toml
client_id = "workstation"
display_name = "Workstation"
ingest_token = "publisher-token"
ingest_server_key = "pinned-relay-public-key"
viewer_key_b64 = "out-of-band-e2e-viewer-key"
```

`--ingest-addr` accepts DNS names such as `cast.example.com:8900`. Connection
and Noise handshakes are timed out, and reconnects use capped exponential
backoff with jitter.

## Viewer enrollment and revocation

Give each person or device its own access token and an appropriate publisher
scope. Deliver that token and the E2EE viewer key over an authenticated channel
separate from GlacialCast. The access token permits retrieval; the viewer key
decrypts the selected stream. Neither belongs in a URL.

For a staged access-token rotation:

1. Generate the replacement.
2. Put the old value in `previous_tokens` and the new value in `token`.
3. Restart the relay and update the viewer.
4. Remove the old value and restart after the migration window.

The session key persists in `/var/lib/glacialcast/http-session.key`. Changes to
a principal's token set, role, or publisher scope invalidate that principal's
existing signed sessions after restart. Removing the principal revokes it
entirely. Replacing the session-key file logs out every viewer.

Ingest tokens use the same `previous_tokens` process. The publisher reconnects
to its existing stream identity after the relay restart.

Rotate the E2EE viewer key by restarting the publisher with a new
`viewer_key_b64`. This creates a new capture epoch. Keep the prior key only as
long as access to its retained or exported objects is required. An authorized
viewer can extract any key provided to the browser; Clear Key is not DRM.

Back up the Noise identity and session key with the data directory. A lost
Noise identity requires repinning every publisher. Never copy an ingest token,
access token, viewer key, session key, or Noise private key into logs or URLs.

## Operations

Unauthenticated probes:

```text
GET /health/live
GET /health/ready
```

An administrator can retrieve bounded process counters with:

```sh
curl --fail \
  -H "Authorization: Bearer $GLACIALCAST_ACCESS_TOKEN" \
  https://cast.example.com/api/admin/metrics
```

The counters include HTTP overload/timeouts, login failures and throttling,
active/rejected WebSockets, and active/rejected ingest connections. Alert on
readiness failures, repeated authentication failures, rate-limit growth,
restart loops, storage exhaustion, and certificate-renewal failures. Caddy's
example access log is JSON and rotates locally; ship it using the host's normal
log pipeline without recording request bodies or authorization headers.

Before an upgrade, back up `/var/lib/glacialcast`, deploy the new binary,
restart the relay, confirm readiness, and run:

```sh
scripts/verify-internet-security.sh
scripts/verify-ingest-recovery.sh
scripts/verify-dash-e2e.sh
cargo deny check
```

## Fail-closed behavior

Internet mode refuses to start when:

- `public_origin` is not a path-free HTTPS origin;
- the HTTP backend is not loopback;
- the credential configuration is not a non-symlinked regular file with mode
  `0600`;
- no access token exists;
- ingest authentication is optional;
- a token is weak, duplicated, or malformed; or
- a concurrency, timeout, or rate limit is zero or outside its safe range.

Unknown configuration keys are rejected so misspelled security settings do not
silently use defaults.
