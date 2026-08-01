# Security Policy

GlacialCast carries the contents of someone's screen. A break in it is a break
in whatever they had open, so please treat findings here as sensitive.

## Reporting a vulnerability

Report privately through GitHub's [private vulnerability
reporting](https://github.com/0typos/glacialcast/security/advisories/new). Do
not open a public issue for anything that affects confidentiality of a stream,
authentication to the relay, or the integrity of published objects.

Include the version or commit, the platform and compositor, and enough detail
to reproduce. A failing script under `scripts/` is the most useful form a
report can take.

This is a pre-1.0 project maintained on a best-effort basis. There is no paid
bounty and no guaranteed response time.

## Supported versions

Only the tip of `main` is supported. Fixes land there; there are no maintained
release branches before 1.0.

## What is in scope

The security properties GlacialCast actually claims, and therefore the ones
worth reporting against:

- **The relay cannot read a stream.** Media is CENC-encrypted and cursor
  batches are AES-GCM sealed under a viewer key the relay never receives. Any
  path by which an operator of the relay recovers screen content or cursor
  positions is in scope. This is the claim for a stream published normally; a
  publisher that passed `--no-encryption` has deliberately given it up, and
  that case is covered under "out of scope" below.
- **Encryption cannot be stripped from a stream that has it.** A relay refuses
  an unencrypted epoch unless started with `--trusted-lan`, which is itself
  refused alongside `security.public_origin`. A viewer holding a key for a
  stream refuses an epoch served in the clear on it, rather than playing
  whatever arrives. Any path by which a hostile relay downgrades a stream a
  viewer holds a key for — or by which an unencrypted epoch is accepted by a
  relay that did not opt in — is in scope.
- **Ingest is authenticated and pinned.** The publisher pins the relay's Noise
  NK public key. Any path by which an unpinned or substituted server accepts
  ingest, or by which an unauthenticated party publishes to a stream, is in
  scope.
- **A publisher cannot impersonate another.** Durable identity is
  `{principal}:{source_label}` and labels are sanitized. Any label or hello
  field that lets one publisher claim another's identity, or lets a scope
  authorize a publisher it should not, is in scope.
- **Authorization is enforced on the viewer surface.** Session and bearer
  authentication, publisher-scoped viewing, CSRF and origin enforcement, and
  the request and connection limits are all in scope, particularly under the
  fail-closed Internet profile in `docs/internet-deployment.md`.
- **Objects are integrity-checked.** Retained and offline `.gco` objects are
  authenticated; forging one that a viewer accepts is in scope.

Memory-safety faults reachable from untrusted input — a hostile relay
answering a publisher, a hostile publisher feeding a relay, or a malformed
`.gco` file — are in scope. `fuzz/` exists for exactly this.

## What is out of scope

These are design limits, not bugs. They are documented so a report does not
have to rediscover them:

- **A stream published with `--no-encryption` is readable, by design.** The
  media and cursor batches are plaintext to the relay, to anything that can
  reach its HTTP surface, and to anything on the network path TLS does not
  cover. Such objects also carry no authentication tag, because there is no key
  to derive one from: a viewer can check an object against its own SHA-256 but
  cannot tell who produced it. Integrity is hop-by-hop — Noise for ingest, TLS
  to the browser — and not end to end. The mode exists because WebKit offers
  FairPlay and never ClearKey, so an iPhone can play no other kind. Reports that
  an unencrypted stream is readable are not findings; reports that one can be
  published to a relay that did not opt in, or served to a viewer holding a key,
  are.
- **The viewer key unlocks everything the publisher casts.** One key covers
  every screen from one publisher, by design. Sharing it shares all of them.
- **A key phrase carries 70 bits, not 256.** A viewing key is seven words from
  a 1024-word list, stretched into 32 bytes with PBKDF2-HMAC-SHA-256 at 600,000
  iterations over a per-publisher salt. That the derived key has less entropy
  than a random 32-byte key is the deliberate trade for a key a person can
  actually transfer. Reports that the phrase space is smaller than 2^256 are not
  findings; a flaw in the derivation, the salt handling, or the word decoding
  very much is.
- **An unlocked key is stored in `localStorage`, on disk in the browser
  profile.** It is plaintext there, readable by any script already running on
  the page, and it survives a restart rather than ending with the tab. That is a
  deliberate trade for entering the key once instead of on every reload;
  **Forget keys** erases it and is the right thing to use on a shared machine.
  Script injection into the viewer is in scope; the storage choice itself is
  not, since such a script could equally read the key from memory.
- **The relay learns metadata.** Stream existence, display names, object sizes,
  and timing are visible to it. Traffic analysis of a screen stream is not
  something this design defends against.
- **A compromised publisher or viewer host.** If the machine capturing or
  displaying the screen is compromised, GlacialCast cannot help.
- **Anything requiring a desktop-session foothold**, such as reading the viewer
  key file at `$XDG_STATE_HOME/glacialcast/` — it is mode 0600, and an attacker
  already inside that session can read the screen directly.
- **Denial of service against your own relay** by an authorized publisher.
- Missing hardening headers or similar findings on a relay deliberately run
  without the Internet profile, which is documented as LAN-only.

## Cryptography

GlacialCast composes existing primitives — Noise NK, AES-GCM, CENC,
PBKDF2-SHA-256, HKDF — rather than implementing them. Reports of misuse of
those primitives are very much in scope; the composition is where the bugs
would be.
