//! Native GlacialCast viewer entry point.
//!
//! The networking, decoding, and graphical shell are introduced in later
//! native-protocol checkpoints. This crate reserves the installed `gcview`
//! command while the publisher and relay are renamed independently.

#![deny(missing_docs)]

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(version, about = "View GlacialCast streams from a native relay")]
struct Args {
    /// Relay endpoint in `host[:port]` form.
    relay: String,
}

/// Parses the native viewer command line.
///
/// # Errors
///
/// Returns an error until the native relay protocol is implemented. Keeping
/// that failure explicit prevents this preparatory binary from pretending it
/// connected successfully.
pub fn run() -> Result<()> {
    let args = Args::parse();
    anyhow::bail!(
        "native viewer connection to {} is not implemented yet",
        args.relay
    )
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser;

    #[test]
    fn viewer_requires_exactly_one_relay_endpoint() {
        assert!(Args::try_parse_from(["gcview"]).is_err());
        let args = Args::try_parse_from(["gcview", "relay.example:8899"]).unwrap();
        assert_eq!(args.relay, "relay.example:8899");
        assert!(Args::try_parse_from(["gcview", "one", "two"]).is_err());
    }
}
