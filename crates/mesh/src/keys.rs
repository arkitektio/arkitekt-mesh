//! Curve25519 keys and their Tailscale text forms (`nodekey:<hex>`,
//! `mkey:<hex>`, `discokey:<hex>`, `privkey:<hex>`).
//!
//! A node has three key pairs: the machine key (the device, used for the
//! control connection), the node key (the WireGuard identity; peers address
//! it by this) and the disco key (path discovery, rotated every start).

use std::fmt;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A Curve25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct PublicKey(pub [u8; 32]);

/// A Curve25519 private key; wiped on drop.
#[derive(Clone)]
pub struct PrivateKey([u8; 32]);

impl PrivateKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    /// Clamped, as X25519 uses it.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.secret()).to_bytes())
    }

    pub(crate) fn secret(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(self.0)
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey({})", self.public().short())
    }
}

impl PublicKey {
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }

    /// The first 5 hex bytes, as tailscale logs keys.
    pub fn short(&self) -> String {
        hex::encode(&self.0[..5])
    }

    fn parse(prefix: &'static str, text: &str) -> Result<Self, KeyError> {
        let hex_part = text.strip_prefix(prefix).ok_or(KeyError::Prefix(prefix))?;
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_part, &mut out).map_err(|_| KeyError::Hex)?;
        Ok(Self(out))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.short())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("the key does not start with {0:?}")]
    Prefix(&'static str),
    #[error("the key is not 64 hex digits")]
    Hex,
}

/// Public keys that serialize with a fixed text prefix.
macro_rules! public_key_kind {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub struct $name(pub PublicKey);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn text(&self) -> String {
                format!("{}{}", $prefix, hex::encode(self.0 .0))
            }

            pub fn parse(text: &str) -> Result<Self, KeyError> {
                PublicKey::parse($prefix, text).map(Self)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0.short())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.text())
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.text())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                // Go marshals the zero key as the bare prefix or "".
                if text.is_empty() || text == $prefix {
                    return Ok(Self::default());
                }
                Self::parse(&text).map_err(serde::de::Error::custom)
            }
        }
    };
}

public_key_kind!(
    /// A machine's public key (`mkey:`).
    MachinePublic,
    "mkey:"
);
public_key_kind!(
    /// A node's public key (`nodekey:`): its WireGuard identity.
    NodePublic,
    "nodekey:"
);
public_key_kind!(
    /// A node's disco public key (`discokey:`).
    DiscoPublic,
    "discokey:"
);

/// A private key that persists as `privkey:<hex>`.
#[derive(Clone, Debug)]
pub struct StoredKey(pub PrivateKey);

impl StoredKey {
    pub const PREFIX: &'static str = "privkey:";
}

impl Serialize for StoredKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!(
            "{}{}",
            Self::PREFIX,
            hex::encode(self.0.as_bytes())
        ))
    }
}

impl<'de> Deserialize<'de> for StoredKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let key = PublicKey::parse(Self::PREFIX, &text).map_err(serde::de::Error::custom)?;
        Ok(Self(PrivateKey::from_bytes(key.0)))
    }
}

/// What makes a node itself across restarts: its machine and node keys.
/// The disco key is not persisted; a fresh one is made every start.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub machine: StoredKey,
    pub node: StoredKey,
}

impl NodeIdentity {
    pub fn generate() -> Self {
        Self {
            machine: StoredKey(PrivateKey::generate()),
            node: StoredKey(PrivateKey::generate()),
        }
    }

    pub fn machine_public(&self) -> MachinePublic {
        MachinePublic(self.machine.0.public())
    }

    pub fn node_public(&self) -> NodePublic {
        NodePublic(self.node.0.public())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_forms_round_trip() {
        let key = NodePublic(PrivateKey::generate().public());
        let text = key.text();
        assert!(text.starts_with("nodekey:") && text.len() == 8 + 64);
        assert_eq!(NodePublic::parse(&text).unwrap(), key);
        assert_eq!(
            serde_json::from_str::<NodePublic>(&serde_json::to_string(&key).unwrap()).unwrap(),
            key
        );
        assert!(NodePublic::parse(&key.0.short()).is_err());
        assert!(MachinePublic::parse(&text).is_err());
    }

    #[test]
    fn zero_keys_deserialize_from_go_forms() {
        for zero in ["\"\"", "\"discokey:\""] {
            assert!(serde_json::from_str::<DiscoPublic>(zero)
                .unwrap()
                .0
                .is_zero());
        }
    }

    #[test]
    fn identity_persists() {
        let id = NodeIdentity::generate();
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.contains("privkey:"));
        let back: NodeIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(back.node_public(), id.node_public());
        assert_eq!(back.machine_public(), id.machine_public());
    }

    #[test]
    fn x25519_agrees() {
        let (a, b) = (PrivateKey::generate(), PrivateKey::generate());
        assert_eq!(
            crate::crypto::dh(&a, &b.public()).unwrap(),
            crate::crypto::dh(&b, &a.public()).unwrap()
        );
    }
}
