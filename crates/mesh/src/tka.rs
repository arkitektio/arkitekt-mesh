//! Tailnet lock (TKA, "tailnet key authority"): docs/rfc5-tailnet-lock.md.
//!
//! In a locked tailnet a set of trusted keys (held by admins, not by
//! control) signs every node key, and every node drops peers whose key is
//! not signed. The trusted keys and their changes form a chain of signed
//! updates (AUMs) that each node verifies itself; control only relays it.
//!
//! This module is the sans-IO core, following `tailscale.com/tka`:
//! - a strict reader for the CBOR subset these messages use. Hashes are taken
//!   over the bytes as received, so they match Go's byte for byte with no
//!   canonical encoder of our own;
//! - [`Aum`], [`Key`], [`State`] and [`NodeKeySignature`];
//! - an [`Authority`]: a verified chain, from a checkpoint (the genesis) to
//!   the head, and the state it arrives at.
//!
//! Not implemented: resolving forks (Go's weighted pick between competing
//! children), compaction, disablement (argon2 with 16 MiB), and signing.

use std::fmt;

use blake2::{Blake2s256, Digest};
use ed25519_dalek::{Signature, VerifyingKey};

/// BLAKE2s-256 of a serialized AUM.
pub type AumHash = [u8; 32];

/// `AUMHash.String()`: base32 (standard alphabet), no padding.
pub fn hash_text(hash: &AumHash) -> String {
    base32(hash)
}

pub fn parse_hash_text(text: &str) -> Option<AumHash> {
    let bytes = unbase32(text)?;
    bytes.try_into().ok()
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TkaError {
    #[error("malformed CBOR: {0}")]
    Cbor(&'static str),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("signature: {0}")]
    Signature(String),
}

fn invalid(msg: impl Into<String>) -> TkaError {
    TkaError::Invalid(msg.into())
}

// --- CBOR: the subset Go's tka writes (CTAP2 canonical) ----------------------

/// Go's decoder limits.
const MAX_DEPTH: usize = 16;
const MAX_ITEMS: u64 = 4096;

#[derive(Debug, Clone, PartialEq)]
enum Value<'a> {
    Uint(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Value<'a>>),
    /// Pairs, each with the raw bytes of key and value together.
    Map(Vec<(Value<'a>, Value<'a>, &'a [u8])>),
    Bool(bool),
    Null,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TkaError> {
        let end = self.pos.checked_add(n).ok_or(TkaError::Cbor("length"))?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or(TkaError::Cbor("truncated"))?;
        self.pos = end;
        Ok(s)
    }

    fn argument(&mut self, info: u8) -> Result<u64, TkaError> {
        Ok(match info {
            0..=23 => info as u64,
            24 => self.take(1)?[0] as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            // 31 is indefinite length: forbidden, as in Go's decoder.
            _ => return Err(TkaError::Cbor("indefinite or reserved length")),
        })
    }

    fn value(&mut self, depth: usize) -> Result<Value<'a>, TkaError> {
        if depth > MAX_DEPTH {
            return Err(TkaError::Cbor("nested too deeply"));
        }
        let head = self.take(1)?[0];
        let (major, info) = (head >> 5, head & 0x1f);
        match major {
            0 => Ok(Value::Uint(self.argument(info)?)),
            2 => {
                let n = self.argument(info)? as usize;
                Ok(Value::Bytes(self.take(n)?))
            }
            3 => {
                let n = self.argument(info)? as usize;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| TkaError::Cbor("text"))?;
                Ok(Value::Text(s))
            }
            4 => {
                let n = self.argument(info)?;
                if n > MAX_ITEMS {
                    return Err(TkaError::Cbor("array too long"));
                }
                (0..n)
                    .map(|_| self.value(depth + 1))
                    .collect::<Result<_, _>>()
                    .map(Value::Array)
            }
            5 => {
                let n = self.argument(info)?;
                if n > 1024 {
                    return Err(TkaError::Cbor("map too long"));
                }
                let mut pairs: Vec<(Value<'a>, Value<'a>, &'a [u8])> =
                    Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let start = self.pos;
                    let key = self.value(depth + 1)?;
                    let value = self.value(depth + 1)?;
                    if pairs.iter().any(|(k, _, _)| *k == key) {
                        return Err(TkaError::Cbor("duplicate map key"));
                    }
                    pairs.push((key, value, &self.data[start..self.pos]));
                }
                Ok(Value::Map(pairs))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(TkaError::Cbor("unsupported simple value")),
            },
            // Negative integers, tags (forbidden in Go's decoder): not used.
            _ => Err(TkaError::Cbor("unsupported major type")),
        }
    }
}

fn parse(data: &[u8]) -> Result<Value<'_>, TkaError> {
    let mut r = Reader { data, pos: 0 };
    let v = r.value(0)?;
    if r.pos != data.len() {
        return Err(TkaError::Cbor("trailing bytes"));
    }
    Ok(v)
}

fn map_header(n: usize) -> Vec<u8> {
    match n {
        0..=23 => vec![0xa0 | n as u8],
        24..=0xff => vec![0xb8, n as u8],
        _ => {
            let mut v = vec![0xb9];
            v.extend_from_slice(&(n as u16).to_be_bytes());
            v
        }
    }
}

/// The bytes of a top-level map without its integer key `drop`: what Go
/// serializes after setting that field to its zero value (omitempty).
fn without_field(data: &[u8], drop: u64) -> Result<Vec<u8>, TkaError> {
    let Value::Map(pairs) = parse(data)? else {
        return Err(TkaError::Cbor("not a map"));
    };
    let kept: Vec<&[u8]> = pairs
        .iter()
        .filter(|(k, _, _)| *k != Value::Uint(drop))
        .map(|(_, _, raw)| *raw)
        .collect();
    let mut out = map_header(kept.len());
    for raw in kept {
        out.extend_from_slice(raw);
    }
    Ok(out)
}

fn blake2s(data: &[u8]) -> [u8; 32] {
    Blake2s256::digest(data).into()
}

struct Fields<'v, 'a>(&'v [(Value<'a>, Value<'a>, &'a [u8])]);

impl<'v, 'a> Fields<'v, 'a> {
    fn of(v: &'v Value<'a>) -> Result<Self, TkaError> {
        match v {
            Value::Map(pairs) => Ok(Self(pairs)),
            _ => Err(TkaError::Cbor("expected a map")),
        }
    }

    fn get(&self, key: u64) -> Option<&'v Value<'a>> {
        self.0
            .iter()
            .find(|(k, _, _)| *k == Value::Uint(key))
            .map(|(_, v, _)| v)
            .filter(|v| **v != Value::Null)
    }

    fn raw(&self, key: u64) -> Option<&'a [u8]> {
        let (k, _, raw) = self
            .0
            .iter()
            .find(|(k, v, _)| *k == Value::Uint(key) && *v != Value::Null)?;
        // The pair minus its key: keys here are single-byte integers.
        let _ = k;
        Some(&raw[1..])
    }

    fn uint(&self, key: u64) -> Result<Option<u64>, TkaError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Uint(n)) => Ok(Some(*n)),
            Some(_) => Err(TkaError::Cbor("expected an integer")),
        }
    }

    fn bytes(&self, key: u64) -> Result<Option<&'a [u8]>, TkaError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Bytes(b)) => Ok(Some(b)),
            Some(_) => Err(TkaError::Cbor("expected bytes")),
        }
    }

    fn meta(&self, key: u64) -> Result<Option<Vec<(String, String)>>, TkaError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Map(pairs)) => pairs
                .iter()
                .map(|(k, v, _)| match (k, v) {
                    (Value::Text(k), Value::Text(v)) => Ok((k.to_string(), v.to_string())),
                    _ => Err(TkaError::Cbor("meta must map text to text")),
                })
                .collect::<Result<_, _>>()
                .map(Some),
            Some(_) => Err(TkaError::Cbor("expected a map")),
        }
    }
}

// --- Keys and state ---------------------------------------------------------

/// A trusted key (only ed25519 exists).
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    pub votes: u64,
    pub public: [u8; 32],
    pub meta: Vec<(String, String)>,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Key(tlpub:{}, votes {})",
            hex::encode(self.public),
            self.votes
        )
    }
}

impl Key {
    fn from_value(v: &Value<'_>) -> Result<Self, TkaError> {
        let f = Fields::of(v)?;
        if f.uint(1)? != Some(1) {
            return Err(invalid("unknown key kind"));
        }
        let votes = f.uint(2)?.unwrap_or(0);
        if votes == 0 || votes > 4096 {
            return Err(invalid(format!("key votes out of range: {votes}")));
        }
        let public: [u8; 32] = f
            .bytes(3)?
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid("an ed25519 key is 32 bytes"))?;
        let meta = f.meta(12)?.unwrap_or_default();
        if meta.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() > 512 {
            return Err(invalid("key metadata too big"));
        }
        Ok(Self {
            votes,
            public,
            meta,
        })
    }

    /// The key id is the public key itself.
    pub fn id(&self) -> &[u8; 32] {
        &self.public
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let (Ok(key), Ok(sig)) = (
            VerifyingKey::from_bytes(&self.public),
            Signature::from_slice(signature),
        ) else {
            return false;
        };
        key.verify_strict(message, &sig).is_ok()
    }
}

/// What the chain arrives at: the trusted keys, and the disablement values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    pub last_aum_hash: Option<AumHash>,
    pub disablement_values: Vec<Vec<u8>>,
    pub keys: Vec<Key>,
    pub state_id1: u64,
    pub state_id2: u64,
}

impl State {
    fn from_value(v: &Value<'_>) -> Result<Self, TkaError> {
        let f = Fields::of(v)?;
        let last_aum_hash = match f.bytes(1)? {
            None => None,
            Some(b) => Some(b.try_into().map_err(|_| invalid("bad state hash"))?),
        };
        let disablement_values = match f.get(2) {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|i| match i {
                    Value::Bytes(b) => Ok(b.to_vec()),
                    _ => Err(TkaError::Cbor("disablement values are bytes")),
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(TkaError::Cbor("expected an array")),
        };
        let keys = match f.get(3) {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(Key::from_value)
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(TkaError::Cbor("expected an array")),
        };
        Ok(Self {
            last_aum_hash,
            disablement_values,
            keys,
            state_id1: f.uint(4)?.unwrap_or(0),
            state_id2: f.uint(5)?.unwrap_or(0),
        })
    }

    /// Go's `staticValidateCheckpoint`.
    fn validate_checkpoint(&self) -> Result<(), TkaError> {
        if self.last_aum_hash.is_some() {
            return Err(invalid("a checkpoint cannot name a parent"));
        }
        if self.disablement_values.is_empty() || self.disablement_values.len() > 32 {
            return Err(invalid("1 to 32 disablement values are required"));
        }
        if self.disablement_values.iter().any(|d| d.len() != 32) {
            return Err(invalid("disablement values are 32 bytes"));
        }
        if self.keys.is_empty() || self.keys.len() > 512 {
            return Err(invalid("1 to 512 keys are required"));
        }
        for (i, k) in self.keys.iter().enumerate() {
            if self.keys[..i].iter().any(|o| o.public == k.public) {
                return Err(invalid("duplicate key"));
            }
        }
        Ok(())
    }

    pub fn key(&self, id: &[u8]) -> Option<&Key> {
        self.keys.iter().find(|k| k.public[..] == *id)
    }
}

// --- AUMs -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AumKind {
    AddKey,
    RemoveKey,
    NoOp,
    UpdateKey,
    Checkpoint,
    /// Unknown kinds apply as no-ops (as in Go).
    Other(u64),
}

/// An update to the authority's state, signed by trusted keys.
#[derive(Debug, Clone)]
pub struct Aum {
    pub kind: AumKind,
    pub prev: Option<AumHash>,
    pub key: Option<Key>,
    pub key_id: Option<Vec<u8>>,
    pub state: Option<State>,
    pub votes: Option<u64>,
    pub meta: Option<Vec<(String, String)>>,
    /// (key id, ed25519 signature over [`sig_hash`](Self::sig_hash)).
    pub signatures: Vec<(Vec<u8>, Vec<u8>)>,
    raw: Vec<u8>,
    hash: AumHash,
    sig_hash: [u8; 32],
}

impl Aum {
    pub fn parse(raw: &[u8]) -> Result<Self, TkaError> {
        let v = parse(raw)?;
        let f = Fields::of(&v)?;
        let kind = match f.uint(1)?.unwrap_or(0) {
            1 => AumKind::AddKey,
            2 => AumKind::RemoveKey,
            3 => AumKind::NoOp,
            4 => AumKind::UpdateKey,
            5 => AumKind::Checkpoint,
            0 => return Err(invalid("invalid AUM kind")),
            n => AumKind::Other(n),
        };
        let prev = match f.bytes(2)? {
            None => None,
            Some(b) => Some(b.try_into().map_err(|_| invalid("bad parent hash"))?),
        };
        let signatures = match f.get(23) {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|s| {
                    let sf = Fields::of(s)?;
                    let id = sf.bytes(1)?.unwrap_or_default();
                    let sig = sf.bytes(2)?.unwrap_or_default();
                    if id.len() != 32 || sig.len() != 64 {
                        return Err(invalid("malformed AUM signature"));
                    }
                    Ok((id.to_vec(), sig.to_vec()))
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(TkaError::Cbor("expected an array")),
        };
        let aum = Self {
            kind,
            prev,
            key: f.get(3).map(Key::from_value).transpose()?,
            key_id: f.bytes(4)?.map(<[u8]>::to_vec),
            state: f.get(5).map(State::from_value).transpose()?,
            votes: f.uint(6)?,
            meta: f.meta(7)?,
            signatures,
            hash: blake2s(raw),
            sig_hash: blake2s(&without_field(raw, 23)?),
            raw: raw.to_vec(),
        };
        aum.validate()?;
        Ok(aum)
    }

    /// Go's `StaticValidate`.
    fn validate(&self) -> Result<(), TkaError> {
        if let Some(state) = &self.state {
            state.validate_checkpoint()?;
        }
        let only = |ok: bool, msg: &str| if ok { Ok(()) } else { Err(invalid(msg)) };
        match self.kind {
            AumKind::AddKey => only(
                self.key.is_some()
                    && self.key_id.is_none()
                    && self.state.is_none()
                    && self.votes.is_none()
                    && self.meta.is_none(),
                "AddKey AUMs carry exactly a key",
            ),
            AumKind::RemoveKey => only(
                self.key_id.as_ref().is_some_and(|k| !k.is_empty())
                    && self.key.is_none()
                    && self.state.is_none()
                    && self.votes.is_none()
                    && self.meta.is_none(),
                "RemoveKey AUMs carry exactly a key id",
            ),
            AumKind::UpdateKey => only(
                self.key_id.as_ref().is_some_and(|k| !k.is_empty())
                    && (self.votes.is_some() || self.meta.is_some())
                    && self.key.is_none()
                    && self.state.is_none(),
                "UpdateKey AUMs carry a key id and votes or metadata",
            ),
            AumKind::Checkpoint => only(
                self.state.is_some()
                    && self.key.is_none()
                    && self.key_id.is_none()
                    && self.votes.is_none()
                    && self.meta.is_none(),
                "Checkpoint AUMs carry exactly a state",
            ),
            _ => Ok(()),
        }
    }

    pub fn hash(&self) -> AumHash {
        self.hash
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// What its signatures sign: the hash without them.
    pub fn sig_hash(&self) -> [u8; 32] {
        self.sig_hash
    }

    /// Every signature valid and by a key of `state` (Go's `aumVerify`).
    fn verify(&self, state: &State) -> Result<(), TkaError> {
        if self.signatures.is_empty() {
            return Err(TkaError::Signature("unsigned AUM".into()));
        }
        for (i, (id, sig)) in self.signatures.iter().enumerate() {
            let key = state.key(id).ok_or_else(|| {
                TkaError::Signature(format!("signature {i} is by an untrusted key"))
            })?;
            if !key.verify(&self.sig_hash, sig) {
                return Err(TkaError::Signature(format!(
                    "signature {i} does not verify"
                )));
            }
        }
        if self.kind == AumKind::RemoveKey
            && state.keys.len() == 1
            && self.key_id.as_deref() == Some(&state.keys[0].public[..])
        {
            return Err(invalid("cannot remove the last key"));
        }
        Ok(())
    }

    /// Go's `applyVerifiedAUM`.
    fn apply(&self, state: &State) -> Result<State, TkaError> {
        if state.last_aum_hash.is_some() && state.last_aum_hash != self.prev {
            return Err(invalid("parent AUM hash mismatch"));
        }
        let mut out = state.clone();
        match self.kind {
            AumKind::Checkpoint => {
                let next = self.state.as_ref().expect("validated");
                if (next.state_id1, next.state_id2) != (state.state_id1, state.state_id2) {
                    return Err(invalid("checkpoint has another state id"));
                }
                out = next.clone();
            }
            AumKind::AddKey => {
                let key = self.key.clone().expect("validated");
                if state.key(&key.public).is_some() {
                    return Err(invalid("key already exists"));
                }
                out.keys.push(key);
            }
            AumKind::UpdateKey => {
                let id = self.key_id.as_deref().expect("validated");
                let key = out
                    .keys
                    .iter_mut()
                    .find(|k| k.public[..] == *id)
                    .ok_or_else(|| invalid("no such key"))?;
                if let Some(votes) = self.votes {
                    if votes == 0 || votes > 4096 {
                        return Err(invalid("key votes out of range"));
                    }
                    key.votes = votes;
                }
                if let Some(meta) = &self.meta {
                    key.meta = meta.clone();
                }
            }
            AumKind::RemoveKey => {
                let id = self.key_id.as_deref().expect("validated");
                let before = out.keys.len();
                out.keys.retain(|k| k.public[..] != *id);
                if out.keys.len() == before {
                    return Err(invalid("no such key"));
                }
            }
            AumKind::NoOp | AumKind::Other(_) => {}
        }
        out.last_aum_hash = Some(self.hash);
        Ok(out)
    }
}

// --- Node-key signatures ----------------------------------------------------

/// Go's `NodePublic.MarshalBinary`: `"np"` and the 32 key bytes.
fn node_key_binary(key: &[u8; 32]) -> [u8; 34] {
    let mut out = [0u8; 34];
    out[..2].copy_from_slice(b"np");
    out[2..].copy_from_slice(key);
    out
}

fn node_key_from_binary(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.strip_prefix(b"np")?.try_into().ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigKind {
    Direct,
    Rotation,
    Credential,
}

/// A signature over a node key (Go's `NodeKeySignature`).
#[derive(Debug, Clone)]
pub struct NodeKeySignature {
    pub kind: SigKind,
    pub pubkey: Option<Vec<u8>>,
    pub key_id: Option<Vec<u8>>,
    pub signature: Vec<u8>,
    pub nested: Option<Box<NodeKeySignature>>,
    pub wrapping_pubkey: Option<Vec<u8>>,
    sig_hash: [u8; 32],
}

impl NodeKeySignature {
    pub fn parse(raw: &[u8]) -> Result<Self, TkaError> {
        Self::parse_depth(raw, 0)
    }

    fn parse_depth(raw: &[u8], depth: usize) -> Result<Self, TkaError> {
        if depth > 8 {
            return Err(TkaError::Cbor("signature nested too deeply"));
        }
        let v = parse(raw)?;
        let f = Fields::of(&v)?;
        let kind = match f.uint(1)? {
            Some(1) => SigKind::Direct,
            Some(2) => SigKind::Rotation,
            Some(3) => SigKind::Credential,
            _ => return Err(invalid("unknown signature kind")),
        };
        let nested = match f.raw(5) {
            None => None,
            Some(nested_raw) => Some(Box::new(Self::parse_depth(nested_raw, depth + 1)?)),
        };
        Ok(Self {
            kind,
            pubkey: f.bytes(2)?.map(<[u8]>::to_vec),
            key_id: f.bytes(3)?.map(<[u8]>::to_vec),
            signature: f.bytes(4)?.unwrap_or_default().to_vec(),
            nested,
            wrapping_pubkey: f.bytes(6)?.map(<[u8]>::to_vec),
            sig_hash: blake2s(&without_field(raw, 4)?),
        })
    }

    /// What its signature signs: the hash without it.
    pub fn sig_hash(&self) -> [u8; 32] {
        self.sig_hash
    }

    fn wrapping_public(&self) -> Option<&[u8]> {
        if let Some(w) = self.wrapping_pubkey.as_deref().filter(|w| !w.is_empty()) {
            return Some(w);
        }
        match (self.kind, &self.nested) {
            (SigKind::Rotation, Some(n)) => n.wrapping_public(),
            _ => None,
        }
    }

    /// The node key this signs (`None` for a credential).
    pub fn node_key(&self) -> Option<[u8; 32]> {
        self.pubkey.as_deref().and_then(node_key_from_binary)
    }

    /// The trusted key that (ultimately) signed this.
    pub fn authorizing_key_id(&self) -> Option<&[u8]> {
        match self.kind {
            SigKind::Direct | SigKind::Credential => {
                self.key_id.as_deref().filter(|k| !k.is_empty())
            }
            SigKind::Rotation => self.nested.as_ref()?.authorizing_key_id(),
        }
    }

    /// The node keys this rotation replaced (for dropping obsolete peers).
    pub fn previous_node_keys(&self) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        let mut cur = self.nested.as_deref();
        while let Some(n) = cur {
            if let Some(k) = n.pubkey.as_deref().and_then(node_key_from_binary) {
                out.push(k);
            }
            if n.kind != SigKind::Rotation {
                break;
            }
            cur = n.nested.as_deref();
        }
        out
    }

    /// Go's `verifySignature`.
    fn verify(&self, node_key: Option<&[u8; 32]>, key: &Key) -> Result<(), TkaError> {
        let fail = |m: &str| Err(TkaError::Signature(m.into()));
        if self.kind != SigKind::Credential
            && self.pubkey.as_deref() != node_key.map(node_key_binary).as_ref().map(|k| &k[..])
        {
            return fail("the signature is for another node key");
        }
        match self.kind {
            SigKind::Rotation => {
                let Some(nested) = &self.nested else {
                    return fail("a rotation signature must nest one");
                };
                let Some(rotation_key) = nested.wrapping_public() else {
                    return fail("missing rotation key");
                };
                let Ok(rotation_key) = <[u8; 32]>::try_from(rotation_key) else {
                    return fail("bad rotation key length");
                };
                let rot = Key {
                    votes: 1,
                    public: rotation_key,
                    meta: Vec::new(),
                };
                if !rot.verify(&self.sig_hash, &self.signature) {
                    return fail("invalid rotation signature");
                }
                let nested_key: Option<[u8; 32]> = match nested.kind {
                    SigKind::Credential => None,
                    _ => Some(
                        nested
                            .pubkey
                            .as_deref()
                            .and_then(node_key_from_binary)
                            .ok_or_else(|| TkaError::Signature("nested pubkey".into()))?,
                    ),
                };
                nested.verify(nested_key.as_ref(), key)
            }
            SigKind::Direct | SigKind::Credential => {
                if self.nested.is_some() {
                    return fail("this kind of signature cannot nest another");
                }
                if key.verify(&self.sig_hash, &self.signature) {
                    Ok(())
                } else {
                    fail("invalid signature")
                }
            }
        }
    }
}

// --- The authority ----------------------------------------------------------

/// A verified chain of AUMs and the state it arrives at.
#[derive(Debug, Clone)]
pub struct Authority {
    /// From the oldest known checkpoint (the genesis) to the head.
    chain: Vec<Aum>,
    state: State,
}

impl Authority {
    /// Start from control's genesis AUM: a checkpoint signed by its own keys.
    pub fn bootstrap(genesis: &[u8]) -> Result<Self, TkaError> {
        let aum = Aum::parse(genesis)?;
        if aum.kind != AumKind::Checkpoint {
            return Err(invalid("the genesis must be a checkpoint"));
        }
        let mut state = aum.state.clone().expect("validated");
        aum.verify(&state)?;
        // Adopted as is (Go's `computeStateAt`), not applied on top of an
        // empty state: a genesis carries its own (random) state ids.
        state.last_aum_hash = Some(aum.hash);
        Ok(Self {
            chain: vec![aum],
            state,
        })
    }

    /// Restore a persisted chain (as [`to_bytes`](Self::to_bytes) wrote it),
    /// verifying every step again.
    pub fn restore(chain: &[Vec<u8>]) -> Result<Self, TkaError> {
        let (genesis, rest) = chain.split_first().ok_or_else(|| invalid("empty chain"))?;
        let mut authority = Self::bootstrap(genesis)?;
        authority.inform(rest)?;
        Ok(authority)
    }

    /// The chain, oldest first, for persisting.
    pub fn to_bytes(&self) -> Vec<Vec<u8>> {
        self.chain.iter().map(|a| a.raw.clone()).collect()
    }

    pub fn head(&self) -> AumHash {
        self.state
            .last_aum_hash
            .expect("a bootstrapped authority has a head")
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// What we offer control to sync: our head, and ancestors at doubling
    /// distances back (Go's `SyncOffer`), ending at the oldest.
    pub fn sync_offer(&self) -> (AumHash, Vec<AumHash>) {
        let mut ancestors = Vec::new();
        let mut skip = 4;
        for (i, aum) in self.chain.iter().rev().enumerate() {
            if i > 0 && i % skip == 0 {
                ancestors.push(aum.hash);
                skip <<= 2;
            }
        }
        let oldest = self.chain[0].hash;
        if ancestors.last() != Some(&oldest) {
            ancestors.push(oldest);
        }
        (self.head(), ancestors)
    }

    /// Apply updates control sent (each verified against the state before
    /// it). They may come in any order but must extend our head in one line;
    /// updates we already have are skipped. Returns how many were applied.
    pub fn inform(&mut self, updates: &[Vec<u8>]) -> Result<usize, TkaError> {
        let mut pending: Vec<Aum> = updates
            .iter()
            .map(|u| Aum::parse(u))
            .collect::<Result<_, _>>()?;
        pending.retain(|a| !self.chain.iter().any(|c| c.hash == a.hash));
        let mut applied = 0;
        while !pending.is_empty() {
            let head = self.head();
            let Some(i) = pending.iter().position(|a| a.prev == Some(head)) else {
                return Err(invalid(format!(
                    "{} update(s) do not extend our head (a fork, which is not supported)",
                    pending.len()
                )));
            };
            let aum = pending.remove(i);
            aum.verify(&self.state)?;
            self.state = aum.apply(&self.state)?;
            self.chain.push(aum);
            applied += 1;
        }
        Ok(applied)
    }

    /// Whether `secret` disables this authority (Go's `checkDisablement`:
    /// Argon2i of the secret, compared with the state's disablement values).
    /// It needs 16 MiB, so small builds leave it out (feature `tka-disable`).
    #[cfg(feature = "tka-disable")]
    pub fn valid_disablement(&self, secret: &[u8]) -> bool {
        use argon2::{Algorithm, Argon2, Params, Version};
        let params = Params::new(16 * 1024, 4, 4, Some(32)).expect("valid parameters");
        let mut derived = [0u8; 32];
        if Argon2::new(Algorithm::Argon2i, Version::V0x13, params)
            .hash_password_into(
                secret,
                b"tailscale network-lock disablement salt",
                &mut derived,
            )
            .is_err()
        {
            return false;
        }
        self.state
            .disablement_values
            .iter()
            .any(|v| v.as_slice() == derived)
    }

    /// Whether `node_key` is signed by a trusted key (Go's
    /// `NodeKeyAuthorized`). A rotation signature also names the keys it
    /// replaced ([`NodeKeySignature::previous_node_keys`]).
    pub fn authorize(
        &self,
        node_key: &[u8; 32],
        signature: &[u8],
    ) -> Result<NodeKeySignature, TkaError> {
        if signature.is_empty() {
            return Err(TkaError::Signature("unsigned".into()));
        }
        let sig = NodeKeySignature::parse(signature)?;
        // A credential (a signed pre-auth key) proves nothing about a node
        // key until the node wraps it in a rotation signature with the
        // credential's wrapping key; alone it would pass for any node key.
        if sig.kind == SigKind::Credential {
            return Err(TkaError::Signature(
                "credential signatures cannot authorize nodes on their own".into(),
            ));
        }
        let id = sig
            .authorizing_key_id()
            .ok_or_else(|| TkaError::Signature("no authorizing key".into()))?;
        let key = self
            .state
            .key(id)
            .ok_or_else(|| TkaError::Signature("signed by an untrusted key".into()))?;
        sig.verify(Some(node_key), key)?;
        Ok(sig)
    }
}

// --- base32 (RFC 4648, no padding) ------------------------------------------

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn unbase32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0);
    for c in text.bytes() {
        let v = B32.iter().position(|&x| x == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trips() {
        let h = [7u8; 32];
        let t = hash_text(&h);
        assert_eq!(t.len(), 52);
        assert!(!t.contains('='));
        assert_eq!(parse_hash_text(&t), Some(h));
        assert_eq!(parse_hash_text("not base32!"), None);
    }

    #[test]
    fn dropping_a_field_keeps_the_rest_byte_for_byte() {
        // {1: 1, 4: h'aa', 5: {1: 2}}
        let raw = [0xa3, 0x01, 0x01, 0x04, 0x41, 0xaa, 0x05, 0xa1, 0x01, 0x02];
        assert_eq!(
            without_field(&raw, 4).unwrap(),
            vec![0xa2, 0x01, 0x01, 0x05, 0xa1, 0x01, 0x02]
        );
        assert_eq!(without_field(&raw, 9).unwrap(), raw.to_vec());
    }

    #[test]
    fn the_reader_refuses_what_go_refuses() {
        assert!(parse(&[0xbf, 0xff]).is_err(), "indefinite map");
        assert!(parse(&[0xc1, 0x00]).is_err(), "tag");
        assert!(
            parse(&[0xa2, 0x01, 0x01, 0x01, 0x02]).is_err(),
            "duplicate key"
        );
        assert!(parse(&[0x01, 0x02]).is_err(), "trailing bytes");
        let mut deep = vec![0x81; 20];
        deep.push(0x00);
        assert!(parse(&deep).is_err(), "too deep");
    }
}
