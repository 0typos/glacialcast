//! Operating-system entropy for keys, serials, and nonces.

/// Fills `bytes` from the operating-system entropy source.
pub(crate) fn fill(bytes: &mut [u8]) {
    getrandom::fill(bytes).expect("operating-system entropy source");
}

/// Returns entropy resampled until nonzero, keeping the all-zero value free
/// as an invalid sentinel for keys and identifiers.
pub(crate) fn random_nonzero<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    while bytes == [0; N] {
        fill(&mut bytes);
    }
    bytes
}
