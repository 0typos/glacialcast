# Protocol Golden Vectors

`protocol-v6.json` fixes one deterministic key-derivation and portable-object
example for independent implementations and accidental-format-change tests.
It contains test-only keys and must never be used for a real stream.

Regenerate the vector after an intentional protocol-version change:

```sh
cargo run --quiet -p glacialcast-protocol --example generate_golden_vectors
```

Review the byte-level difference, update the checked-in JSON deliberately, and
run the full quality profile. A changed result without a corresponding format
version and compatibility-policy review is a regression.
