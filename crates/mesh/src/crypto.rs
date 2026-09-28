//! The primitives both Noise protocols (ts2021 control and WireGuard) are
//! built from: BLAKE2s hashing, its HMAC and HKDF, ChaCha20-Poly1305, and
//! X25519.

use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag, XChaCha20Poly1305, XNonce};

use crate::keys::{PrivateKey, PublicKey};

pub const HASH_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

/// BLAKE2s-256 over the concatenation of `parts`.
pub fn hash(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut h = Blake2s256::new();
    for part in parts {
        Digest::update(&mut h, part);
    }
    h.finalize().into()
}

/// HMAC-BLAKE2s (RFC 2104 over BLAKE2s-256, as Noise and WireGuard use it).
pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..HASH_LEN].copy_from_slice(&hash(&[key]));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Blake2s256::new();
    Digest::update(&mut inner, ipad);
    for part in parts {
        Digest::update(&mut inner, part);
    }
    let inner: [u8; HASH_LEN] = inner.finalize().into();
    hash(&[&opad, &inner])
}

/// Noise's HKDF: `n` (1..=3) outputs from the chaining key and input.
pub fn hkdf<const N: usize>(chaining_key: &[u8; HASH_LEN], input: &[u8]) -> [[u8; HASH_LEN]; N] {
    assert!((1..=3).contains(&N));
    let prk = hmac(chaining_key, &[input]);
    let mut out = [[0u8; HASH_LEN]; N];
    let mut prev: &[u8] = &[];
    let mut last = [0u8; HASH_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        last = hmac(&prk, &[prev, &[i as u8 + 1]]);
        *slot = last;
        prev = &last;
    }
    let _ = last;
    out
}

/// Keyed BLAKE2s with a 16-byte output (WireGuard's MAC1/MAC2).
pub fn mac16(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <Blake2sMac<blake2::digest::consts::U16> as KeyInit>::new_from_slice(key)
        .expect("key of at most 32 bytes");
    Update::update(&mut m, data);
    m.finalize_fixed().into()
}

/// How a 64-bit counter becomes the 96-bit ChaCha20-Poly1305 nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceOrder {
    /// 4 zero bytes, then the counter little-endian (Noise, WireGuard).
    Little,
    /// 4 zero bytes, then the counter big-endian (Tailscale's controlbase).
    Big,
}

fn nonce(counter: u64, order: NonceOrder) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&match order {
        NonceOrder::Little => counter.to_le_bytes(),
        NonceOrder::Big => counter.to_be_bytes(),
    });
    n.into()
}

/// Encrypt `buf` in place and append the tag.
pub fn seal(key: &[u8; 32], counter: u64, order: NonceOrder, ad: &[u8], buf: &mut Vec<u8>) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(&nonce(counter, order), ad, buf)
        .expect("chacha20poly1305 cannot fail to encrypt");
    buf.extend_from_slice(&tag);
}

/// Decrypt `buf` (ciphertext followed by its tag) in place, dropping the tag.
pub fn open(
    key: &[u8; 32],
    counter: u64,
    order: NonceOrder,
    ad: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    let n = buf.len().checked_sub(TAG_LEN).ok_or(CryptoError)?;
    let tag = Tag::clone_from_slice(&buf[n..]);
    buf.truncate(n);
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt_in_place_detached(&nonce(counter, order), ad, buf, &tag)
        .map_err(|_| CryptoError)
}

/// XChaCha20-Poly1305 (WireGuard's cookie reply).
pub fn xseal(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], buf: &mut Vec<u8>) {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), ad, buf)
        .expect("xchacha20poly1305 cannot fail to encrypt");
    buf.extend_from_slice(&tag);
}

pub fn xopen(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ad: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    let n = buf.len().checked_sub(TAG_LEN).ok_or(CryptoError)?;
    let tag = Tag::clone_from_slice(&buf[n..]);
    buf.truncate(n);
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt_in_place_detached(XNonce::from_slice(nonce), ad, buf, &tag)
        .map_err(|_| CryptoError)
}

/// X25519. Fails on a low-order point (an all-zero shared secret).
pub fn dh(private: &PrivateKey, public: &PublicKey) -> Result<[u8; 32], CryptoError> {
    let shared = private
        .secret()
        .diffie_hellman(&x25519_dalek::PublicKey::from(public.0));
    if !shared.was_contributory() {
        return Err(CryptoError);
    }
    Ok(shared.to_bytes())
}

/// Authentication or key agreement failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cryptographic check failed")]
pub struct CryptoError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_the_hmac_crate() {
        use hmac::Mac;
        use hmac::SimpleHmac;
        let mut m =
            <SimpleHmac<Blake2s256> as hmac::digest::KeyInit>::new_from_slice(b"key").unwrap();
        hmac::Mac::update(&mut m, b"message");
        let expected: [u8; 32] = m.finalize().into_bytes().into();
        assert_eq!(hmac(b"key", &[b"mess", b"age"]), expected);
        // Keys longer than a block are hashed first.
        let long = [9u8; 100];
        let mut m =
            <SimpleHmac<Blake2s256> as hmac::digest::KeyInit>::new_from_slice(&long).unwrap();
        hmac::Mac::update(&mut m, b"x");
        let expected: [u8; 32] = m.finalize().into_bytes().into();
        assert_eq!(hmac(&long, &[b"x"]), expected);
    }

    #[test]
    fn seal_open_round_trip_and_nonce_order_matters() {
        let key = [7u8; 32];
        let mut buf = b"hello".to_vec();
        seal(&key, 1, NonceOrder::Big, b"ad", &mut buf);
        assert_eq!(buf.len(), 5 + TAG_LEN);
        let mut wrong = buf.clone();
        assert!(open(&key, 1, NonceOrder::Little, b"ad", &mut wrong).is_err());
        open(&key, 1, NonceOrder::Big, b"ad", &mut buf).unwrap();
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn hkdf_outputs_chain() {
        let ck = [1u8; 32];
        let [a, b] = hkdf::<2>(&ck, b"input");
        let prk = hmac(&ck, &[b"input"]);
        assert_eq!(a, hmac(&prk, &[&[1]]));
        assert_eq!(b, hmac(&prk, &[&a, &[2]]));
    }
}
