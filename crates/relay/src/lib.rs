//! GlacialCast native end-to-end encrypted relay.
//!
//! The relay authenticates Noise XX peers, stores opaque signed stream
//! objects, and forwards per-viewer key envelopes without learning media keys.

#![deny(missing_docs)]

pub mod native_access;
pub mod native_pki;
pub mod native_runtime;
pub mod native_service;
pub mod native_store;
pub mod pairing_store;
