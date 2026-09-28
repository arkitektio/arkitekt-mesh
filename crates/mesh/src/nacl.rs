//! NaCl `crypto_box` (X25519 + XSalsa20-Poly1305), as DERP and disco seal
//! their messages: `nonce(24) ‖ tag(16) ‖ ciphertext`.

use crypto_box::aead::AeadInPlace;
use crypto_box::{Nonce, SalsaBox, Tag};
use rand_core::{OsRng, RngCore};

use crate::crypto::CryptoError;
use crate::keys::{PrivateKey, PublicKey};

pub const NONCE_LEN: usize = 24;
pub const OVERHEAD: usize = NONCE_LEN + 16;

/// A precomputed box between our private key and a peer's public key.
pub struct SharedBox(SalsaBox);

impl SharedBox {
    pub fn new(ours: &PrivateKey, theirs: &PublicKey) -> Self {
        let secret = crypto_box::SecretKey::from(*ours.as_bytes());
        let public = crypto_box::PublicKey::from(theirs.0);
        Self(SalsaBox::new(&public, &secret))
    }

    /// Seal with a fresh random nonce.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        self.seal_with_nonce(&nonce, plaintext)
    }

    fn seal_with_nonce(&self, nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
        let mut body = plaintext.to_vec();
        let tag = self
            .0
            .encrypt_in_place_detached(Nonce::from_slice(nonce), &[], &mut body)
            .expect("xsalsa20poly1305 cannot fail to encrypt");
        let mut out = Vec::with_capacity(OVERHEAD + body.len());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&body);
        out
    }

    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() < OVERHEAD {
            return Err(CryptoError);
        }
        let (nonce, rest) = sealed.split_at(NONCE_LEN);
        let (tag, body) = rest.split_at(16);
        let mut body = body.to_vec();
        self.0
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                &[],
                &mut body,
                Tag::from_slice(tag),
            )
            .map_err(|_| CryptoError)?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (PrivateKey, PrivateKey) {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        for i in 0..32 {
            a[i] = i as u8 + 1;
            b[i] = 100 + i as u8;
        }
        (PrivateKey::from_bytes(a), PrivateKey::from_bytes(b))
    }

    /// From tests/harness/vectors_test.go (Go's golang.org/x/crypto/nacl/box).
    #[test]
    fn matches_go() {
        let (a, b) = keys();
        let mut nonce = [0u8; 24];
        for (i, n) in nonce.iter_mut().enumerate() {
            *n = 200 + i as u8;
        }
        let sealed = SharedBox::new(&a, &b.public()).seal_with_nonce(&nonce, b"hello derp");
        assert_eq!(
            hex::encode(&sealed[NONCE_LEN..]),
            "6ca723aa76816b53446a85f2fe515edd3d99a8919262b7677b3d"
        );
        assert_eq!(
            SharedBox::new(&b, &a.public()).open(&sealed).unwrap(),
            b"hello derp"
        );
    }

    #[test]
    fn tampering_fails() {
        let (a, b) = keys();
        let mut sealed = SharedBox::new(&a, &b.public()).seal(b"x");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(SharedBox::new(&b, &a.public()).open(&sealed).is_err());
    }
}
