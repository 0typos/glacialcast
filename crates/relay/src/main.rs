//! Installed GlacialCast authenticated relay.

fn main() -> anyhow::Result<()> {
    glacialcast_relay::native_runtime::run()
}
