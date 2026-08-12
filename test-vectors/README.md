# Protocol Golden Vectors

`protocol-v9.json` fixes deterministic native stream and pairing encodings for
independent implementations and accidental-format-change tests. It contains
test-only identities and keys and must never be used for a real stream.

The protocol and pairing unit tests consume this vector directly. Review any
byte-level difference deliberately and increment the affected format version
when the canonical representation changes.
