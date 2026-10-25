//! Randomness for keys, nonces, indices and transaction ids: the OS's with
//! std, or the source a board installs (its hardware RNG).

static SOURCE: spin::Once<fn(&mut [u8])> = spin::Once::new();

/// Fill buffers from `source` from now on (without std, before anything
/// makes a key). The first call wins.
pub fn set_source(source: fn(&mut [u8])) {
    SOURCE.call_once(|| source);
}

/// Fill `bytes` with random bytes.
pub fn fill(bytes: &mut [u8]) {
    if let Some(source) = SOURCE.get() {
        return source(bytes);
    }
    #[cfg(feature = "std")]
    return rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, bytes);
    #[cfg(not(feature = "std"))]
    panic!("no randomness: call mesh_core::random::set_source first")
}

pub fn u32() -> u32 {
    let mut bytes = [0u8; 4];
    fill(&mut bytes);
    u32::from_le_bytes(bytes)
}

pub fn u64() -> u64 {
    let mut bytes = [0u8; 8];
    fill(&mut bytes);
    u64::from_le_bytes(bytes)
}
