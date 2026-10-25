//! Tailnet lock as a node keeps it (docs/rfc5-tailnet-lock.md): the
//! verified authority, persisted through a [`LockStore`], and the judgement
//! of every peer. Syncing it with control is the driver's.
//!
//! The chain is persisted: otherwise a node would take a new genesis from
//! control on every start, and a compromised control could swap the trusted
//! keys.

use alloc::sync::Arc;

use hashbrown::{HashMap, HashSet};

#[allow(unused_imports)]
use crate::prelude::*;

use crate::control::netmap::Peer;
use crate::control::types::TkaInfo;
use crate::keys::NodePublic;
use crate::tka::{hash_text, AumHash, Authority};

pub mod sync;

/// Where a node keeps its tailnet-lock chain between runs.
pub trait LockStore: Send + Sync + 'static {
    /// The chain as last saved (oldest first), if any.
    fn load(&self) -> Option<Vec<Vec<u8>>>;
    fn save(&self, chain: &[Vec<u8>]);
    /// Forget it (tailnet lock was disabled).
    fn clear(&self);
}

/// The node's view of tailnet lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockStatus {
    /// The tailnet is not locked.
    Unlocked,
    Locked {
        /// Our head, as `AUMHash` text.
        head: String,
        trusted_keys: usize,
        /// Peers hidden because their node key is not signed.
        hidden_peers: usize,
        /// Our own node key is not signed: peers will not talk to us until
        /// someone holding a trusted key signs it (`tailscale lock sign`).
        locked_out: bool,
    },
    /// Control says the tailnet is locked, but its chain could not be
    /// fetched or verified: every peer is hidden until it can.
    Unverified(String),
}

/// A peer's last judgement: its key, a hash of its signature, the head it
/// was judged at, and whether it is trusted.
type Verdict = (NodePublic, [u8; 32], AumHash, bool);

fn fingerprint(signature: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    Blake2s256::digest(signature).into()
}

#[derive(Default, Clone)]
pub struct Lock {
    pub authority: Option<Authority>,
    pub store: Option<Arc<dyn LockStore>>,
    /// Control announced a lock we could not verify: trust nobody.
    pub unverified: Option<String>,
    pub hidden: usize,
    pub locked_out: bool,
    /// Each peer's last verdict, so a delta does not re-verify every
    /// signature: (key, signature, head it was judged at, trusted).
    verdicts: HashMap<i64, Verdict>,
}

impl Lock {
    pub fn new(store: Option<Arc<dyn LockStore>>) -> Self {
        let authority = store.as_ref().and_then(|s| s.load()).and_then(|chain| {
            Authority::restore(&chain)
                .map_err(|e| tracing::warn!("the saved tailnet-lock chain does not verify: {e}"))
                .ok()
        });
        Self {
            authority,
            store,
            ..Self::default()
        }
    }

    /// Whether control's announcement needs a sync: a different head, a
    /// disablement, or a lock we have not verified yet.
    pub fn needs_sync(&self, info: &TkaInfo) -> bool {
        info.disabled || self.unverified.is_some() || self.head_text() != info.head
    }

    /// Our head, for map requests (`TKAHead`).
    pub fn head_text(&self) -> String {
        self.authority
            .as_ref()
            .map(|a| hash_text(&a.head()))
            .unwrap_or_default()
    }

    /// Whether `peer` may stay in the netmap.
    pub fn trusts(&mut self, peer: &Peer) -> bool {
        if self.unverified.is_some() {
            return false;
        }
        let Some(authority) = &self.authority else {
            return true;
        };
        if peer.unsigned_peer_api_only {
            return true;
        }
        let head = authority.head();
        let sig = fingerprint(&peer.key_signature);
        if let Some((key, cached, at, ok)) = self.verdicts.get(&peer.id) {
            if *key == peer.key && *cached == sig && *at == head {
                return *ok;
            }
        }
        let ok = match authority.authorize(&peer.key.0 .0, &peer.key_signature) {
            Ok(_) => true,
            Err(e) => {
                tracing::info!("tailnet lock hides peer {} ({}): {e}", peer.name, peer.id);
                false
            }
        };
        self.verdicts.insert(peer.id, (peer.key, sig, head, ok));
        ok
    }

    /// Forget verdicts about peers no longer in the netmap.
    pub fn forget_except(&mut self, ids: impl Iterator<Item = i64>) {
        let keep: HashSet<i64> = ids.collect();
        self.verdicts.retain(|id, _| keep.contains(id));
    }

    /// Judge our own node key.
    pub fn judge_self(&mut self, me: Option<&Peer>) {
        self.locked_out = match (&self.authority, me) {
            (Some(authority), Some(me)) => authority
                .authorize(&me.key.0 .0, &me.key_signature)
                .is_err(),
            _ => false,
        };
    }

    pub fn status(&self) -> LockStatus {
        if let Some(reason) = &self.unverified {
            return LockStatus::Unverified(reason.clone());
        }
        match &self.authority {
            None => LockStatus::Unlocked,
            Some(a) => LockStatus::Locked {
                head: hash_text(&a.head()),
                trusted_keys: a.state().keys.len(),
                hidden_peers: self.hidden,
                locked_out: self.locked_out,
            },
        }
    }

    /// Take `authority` (verified by the caller) and persist it.
    pub fn adopt(&mut self, authority: Authority) {
        if let Some(store) = &self.store {
            store.save(&authority.to_bytes());
        }
        self.authority = Some(authority);
        self.unverified = None;
    }
}
