# Internet Deployment

GlacialCast has an Internet deployment profile in which the Rust relay listens
for browser traffic only on loopback and Caddy owns the public HTTPS endpoint.
The publisher endpoint remains a separate Noise-encrypted TCP service. Do not
publish the relay's plaintext HTTP port.

## Trust boundaries

- Caddy terminates TLS, renews the public certificate, overwrites
  `X-Forwarded-For`, and proxies HTTP and WebSocket traffic to
  `127.0.0.1:8899`.
- The relay authenticates browser access itself. Viewer sessions use a signed
  `__Host-` cookie with `HttpOnly`, `Secure`, and `SameSite=Strict`; state
  changes additionally require an exact origin and a session-bound CSRF value.
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

Build and verify the release archive, create a dedicated service account, and
install the server:

```sh
scripts/verify-packaging.sh
tar -xzf dist/glacialcast-v*-x86_64-unknown-linux-gnu.tar.gz
sudo useradd --system --home-dir /var/lib/glacialcast --shell /usr/sbin/nologin glacialcast
sudo install -D -o root -g root -m 0755 \
  glacialcast-v*/bin/glacialcast-server /usr/local/bin/glacialcast-server
# /var/lib/glacialcast is created by the unit's StateDirectory=; /etc is made
# here because the configuration has to be in place before the first start.
sudo install -d -o root -g glacialcast -m 0750 /etc/glacialcast
sudo install -o glacialcast -g glacialcast -m 0600 \
  glacialcast-v*/deploy/server.internet.toml.example /etc/glacialcast/server.toml
sudo install -o root -g root -m 0644 \
  glacialcast-v*/deploy/glacialcast-server.service /etc/systemd/system/glacialcast-server.service
```

Verify the archive checksum before extracting it. See the
[release operations runbook](release-operations.md) for SBOM, optional
signature, backup, upgrade, and rollback procedures.

> [!CAUTION]
> **The packaged configurations ship working example secrets.** The relay's
> tokens and the publisher's `viewer_key_phrase` are both published — in this
> repository, in the README, and in every copy of the package. A deployment
> reachable by anyone else must replace all of them before it is exposed.
>
> The two are independent. The relay never receives a viewer key, so rotating
> ingest and access tokens does nothing for a stream still published under the
> example phrase: an observer who knows it can decrypt everything the relay
> carries, whatever the relay is configured with. Change
> `viewer_key_phrase` in the publisher's `client.toml`, or delete the line so a
> private one is generated. The publisher warns on every start until you do.

Generate independent values for every token:

```sh
openssl rand -base64 32
```

The unit passes no `--config`: `/etc/glacialcast/server.toml` is one of the
standard locations it searches. To keep the configuration elsewhere, add a
drop-in setting `Environment=GLACIALCAST_CONFIG=/path/to/server.toml` rather
than editing the unit.

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

Sign in as an administrator and use **Viewer access** on the relay dashboard to
create one scoped identity for each person or device. The generated access
token is shown exactly once. The relay persists only its SHA-256 hash in
`access-enrollments.json`, with mode `0600`; revoking the identity immediately
invalidates both its token and existing browser sessions. Enrollment state is
bounded to 4,096 viewers, 256 publisher scopes per viewer, and a 1 MiB durable
file. Mutations that would exceed a bound fail before replacing the last valid
file. Debug formatting redacts configured and newly generated access tokens.

The dashboard-generated secret is a **relay access token**: it permits retrieval
of the named publishers' opaque objects. It is not the **E2EE viewer key**, which
decrypts one publisher's media and cursor objects and is never sent to the
relay. Deliver those two secrets separately through authenticated channels.
Neither belongs in a URL, screenshot, issue, or chat log. The wildcard scope
`*` authorizes every publisher and should be reserved for trusted operators or
dedicated overview displays.

Configured TOML identities remain useful for the bootstrap administrator and
automation. For a staged configured-token rotation:

1. Generate the replacement.
2. Put the old value in `previous_tokens` and the new value in `token`.
3. Restart the relay and update the viewer.
4. Remove the old value and restart after the migration window.

The session key persists in `/var/lib/glacialcast/http-session.key`. Changes to
a configured principal's token set, role, or publisher scope invalidate that
principal's existing signed sessions after restart. Removing the principal
revokes it entirely. Dashboard revocation takes effect without a restart.
Replacing the session-key file logs out every viewer.

Ingest tokens use the same `previous_tokens` process. The publisher reconnects
to its existing stream identity after the relay restart.

Rotate the E2EE viewer key by restarting the publisher with a new
`viewer_key_b64`. This creates a new capture epoch. Keep the prior key only as
long as access to its retained or exported objects is required. An authorized
viewer can extract any key provided to the browser; Clear Key is not DRM.

Back up the Noise identity and session key with the complete data directory.
The per-stream `catalog.json` snapshots, `catalog.journal` files, and object
directories form one recovery unit and must not be copied independently while
the service is writing. Stop the service or use a filesystem snapshot. A lost
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
active/rejected WebSockets, active/rejected ingest connections, and opaque
ingest application bytes partitioned by stream and object kind. Traffic
contains lifetime process counters and a bounded rolling 60-second window.
Noise, TCP, HTTP, and TLS framing is intentionally excluded; use host network
telemetry when exact on-the-wire usage matters. The administrator dashboard
renders the same rolling media, cursor, per-stream, connection, and HTTP
counters.

Alert on readiness failures, repeated authentication failures, rate-limit
growth, unexpected bandwidth growth, restart loops, storage exhaustion, and
certificate-renewal failures. Caddy's example access log is JSON and rotates
locally; ship it using the host's normal log pipeline without recording request
bodies or authorization headers.

Before an upgrade, back up `/var/lib/glacialcast`, deploy the new binary,
restart the relay, confirm readiness, and run:

```sh
scripts/verify-internet-security.sh
scripts/verify-internet-browser.sh
scripts/verify-ingest-recovery.sh
scripts/verify-dash-e2e.sh
cargo deny -L error check
```

## Fail-closed behavior

Internet mode refuses to start when:

- `public_origin` is not a path-free HTTPS origin;
- the HTTP backend is not loopback;
- the credential configuration is not a non-symlinked, owner-private regular
  file with mode `0600`;
- no access token exists;
- ingest authentication is optional;
- a token is weak, duplicated, or malformed; or
- a concurrency, timeout, or rate limit is zero or outside its safe range.

Unknown configuration keys are rejected so misspelled security settings do not
silently use defaults.
