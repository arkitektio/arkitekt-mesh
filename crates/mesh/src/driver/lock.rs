//! Tailnet lock in the driver (docs/rfc5-tailnet-lock.md): keeping the
//! authority in step with control, persisting it, and judging peers.
//!
//! Control announces the tailnet's lock head in map responses (`TKAInfo`).
//! The node then:
//! - fetches the genesis the first time (`/machine/tka/bootstrap`);
//! - syncs updates when the heads differ (`/machine/tka/sync/offer`, then
//!   `sync/send`);
//! - verifies every update itself before applying it;
//! - hides every peer whose node key the trusted keys have not signed.
//!
//! The chain is persisted through a [`LockStore`]. Otherwise a node would take
//! a new genesis from control on every start, and a compromised control could
//! swap the trusted keys.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::control::{ControlClient, ControlError};
use crate::control::netmap::Peer;
use crate::control::types::{TkaInfo, CAPABILITY_VERSION};
use crate::keys::NodePublic;
use crate::tka::{hash_text, parse_hash_text, AumHash, Authority};

/// Where a node keeps its tailnet-lock chain between runs.
pub trait LockStore: Send + Sync + 'static {
    /// The chain as last saved (oldest first), if any.
    fn load(&self) -> Option<Vec<Vec<u8>>>;
    fn save(&self, chain: &[Vec<u8>]);
    /// Forget it (tailnet lock was disabled).
    fn clear(&self);
}

/// A [`LockStore`] in a JSON file (e.g. `tka.json` in a state directory).
pub struct FileLockStore(pub PathBuf);

#[derive(Serialize, Deserialize)]
struct Stored {
    aums: Vec<String>,
}

impl LockStore for FileLockStore {
    fn load(&self) -> Option<Vec<Vec<u8>>> {
        let stored: Stored = serde_json::from_slice(&std::fs::read(&self.0).ok()?).ok()?;
        stored
            .aums
            .iter()
            .map(|a| base64::engine::general_purpose::STANDARD.decode(a).ok())
            .collect()
    }

    fn save(&self, chain: &[Vec<u8>]) {
        let stored = Stored {
            aums: chain
                .iter()
                .map(|a| base64::engine::general_purpose::STANDARD.encode(a))
                .collect(),
        };
        let tmp = self.0.with_extension("tmp");
        let written = std::fs::write(&tmp, serde_json::to_vec(&stored).expect("serializes"))
            .and_then(|()| std::fs::rename(&tmp, &self.0));
        if let Err(e) = written {
            tracing::warn!(
                "could not save the tailnet-lock chain to {}: {e}",
                self.0.display()
            );
        }
    }

    fn clear(&self) {
        let _ = std::fs::remove_file(&self.0);
    }
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
pub(super) struct Lock {
    pub(super) authority: Option<Authority>,
    pub(super) store: Option<Arc<dyn LockStore>>,
    /// Control announced a lock we could not verify: trust nobody.
    pub(super) unverified: Option<String>,
    pub(super) hidden: usize,
    pub(super) locked_out: bool,
    /// Each peer's last verdict, so a delta does not re-verify every
    /// signature: (key, signature, head it was judged at, trusted).
    verdicts: HashMap<i64, Verdict>,
}

impl Lock {
    pub(super) fn new(store: Option<Arc<dyn LockStore>>) -> Self {
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
    pub(super) fn needs_sync(&self, info: &TkaInfo) -> bool {
        info.disabled || self.unverified.is_some() || self.head_text() != info.head
    }

    /// Our head, for map requests (`TKAHead`).
    pub(super) fn head_text(&self) -> String {
        self.authority
            .as_ref()
            .map(|a| hash_text(&a.head()))
            .unwrap_or_default()
    }

    /// Whether `peer` may stay in the netmap.
    pub(super) fn trusts(&mut self, peer: &Peer) -> bool {
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
    pub(super) fn forget_except(&mut self, ids: impl Iterator<Item = i64>) {
        let keep: std::collections::HashSet<i64> = ids.collect();
        self.verdicts.retain(|id, _| keep.contains(id));
    }

    /// Judge our own node key.
    pub(super) fn judge_self(&mut self, me: Option<&Peer>) {
        self.locked_out = match (&self.authority, me) {
            (Some(authority), Some(me)) => authority
                .authorize(&me.key.0 .0, &me.key_signature)
                .is_err(),
            _ => false,
        };
    }

    pub(super) fn status(&self) -> LockStatus {
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

    fn adopt(&mut self, authority: Authority) {
        if let Some(store) = &self.store {
            store.save(&authority.to_bytes());
        }
        self.authority = Some(authority);
        self.unverified = None;
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct BootstrapRequest<'a> {
    version: u16,
    node_key: &'a NodePublic,
    #[serde(skip_serializing_if = "str::is_empty")]
    head: &'a str,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct BootstrapResponse {
    #[serde(rename = "GenesisAUM")]
    genesis_aum: Option<String>,
    disablement_secret: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SyncOfferRequest<'a> {
    version: u16,
    node_key: &'a NodePublic,
    head: String,
    ancestors: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct SyncOfferResponse {
    head: String,
    #[serde(rename = "MissingAUMs")]
    missing_aums: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SyncSendRequest<'a> {
    version: u16,
    node_key: &'a NodePublic,
    head: String,
    #[serde(rename = "MissingAUMs")]
    missing_aums: Vec<String>,
    interactive: bool,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct SyncSendResponse {
    head: String,
}

fn unb64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("bad base64: {e}"))
}

/// Bring `lock` in step with what control announced. Errors leave the lock
/// fail-closed: when control says the tailnet is locked and we cannot
/// verify its chain, every peer is hidden.
pub(super) async fn sync(
    client: &ControlClient,
    node_key: &NodePublic,
    info: &TkaInfo,
    lock: &mut Lock,
) {
    match sync_inner(client, node_key, info, lock).await {
        Ok(()) => {}
        Err(e) if lock.authority.is_none() => {
            tracing::warn!("tailnet lock: {e}; no peer is trusted until it can be verified");
            lock.unverified = Some(e);
        }
        // With an authority we keep trusting what it verified.
        Err(e) => tracing::warn!("tailnet lock sync: {e}"),
    }
}

async fn sync_inner(
    client: &ControlClient,
    node_key: &NodePublic,
    info: &TkaInfo,
    lock: &mut Lock,
) -> Result<(), String> {
    let rpc = |e: ControlError| e.to_string();
    if info.disabled {
        let Some(authority) = &lock.authority else {
            return Ok(());
        };
        let head = hash_text(&authority.head());
        let resp: BootstrapResponse = client
            .call(
                "/machine/tka/bootstrap",
                node_key,
                &BootstrapRequest {
                    version: CAPABILITY_VERSION,
                    node_key,
                    head: &head,
                },
            )
            .await
            .map_err(rpc)?;
        let secret = unb64(resp.disablement_secret.as_deref().unwrap_or_default())?;
        if disablement_valid(authority, &secret) {
            tracing::info!("tailnet lock disabled (the disablement secret verifies)");
            if let Some(store) = &lock.store {
                store.clear();
            }
            lock.authority = None;
            lock.unverified = None;
            return Ok(());
        }
        return Err(
            "control says tailnet lock is disabled, but its secret does not verify; staying locked"
                .into(),
        );
    }

    if lock.authority.is_none() {
        let resp: BootstrapResponse = client
            .call(
                "/machine/tka/bootstrap",
                node_key,
                &BootstrapRequest {
                    version: CAPABILITY_VERSION,
                    node_key,
                    head: "",
                },
            )
            .await
            .map_err(rpc)?;
        let genesis = unb64(
            resp.genesis_aum
                .as_deref()
                .ok_or("control sent no genesis")?,
        )?;
        let authority = Authority::bootstrap(&genesis).map_err(|e| format!("genesis: {e}"))?;
        tracing::info!(
            "tailnet lock: bootstrapped at {}",
            hash_text(&authority.head())
        );
        lock.adopt(authority);
    }

    let authority = lock.authority.as_ref().expect("bootstrapped");
    if parse_hash_text(&info.head) == Some(authority.head()) {
        return Ok(());
    }
    let (head, ancestors) = authority.sync_offer();
    let offer: SyncOfferResponse = client
        .call(
            "/machine/tka/sync/offer",
            node_key,
            &SyncOfferRequest {
                version: CAPABILITY_VERSION,
                node_key,
                head: hash_text(&head),
                ancestors: ancestors.iter().map(hash_text).collect(),
            },
        )
        .await
        .map_err(rpc)?;
    let updates: Vec<Vec<u8>> = offer
        .missing_aums
        .unwrap_or_default()
        .iter()
        .map(|a| unb64(a))
        .collect::<Result<_, _>>()?;
    let mut next = authority.clone();
    if !updates.is_empty() {
        let applied = next
            .inform(&updates)
            .map_err(|e| format!("updates from control: {e}"))?;
        tracing::info!(
            "tailnet lock: {applied} update(s), head {}",
            hash_text(&next.head())
        );
    }
    lock.adopt(next);

    // Tell control where we landed (we author no updates). Some servers
    // do not serve it (tailscale's test control): not an error.
    let head = lock.head_text();
    match client
        .call::<_, SyncSendResponse>(
            "/machine/tka/sync/send",
            node_key,
            &SyncSendRequest {
                version: CAPABILITY_VERSION,
                node_key,
                head: head.clone(),
                missing_aums: Vec::new(),
                interactive: false,
            },
        )
        .await
    {
        Ok(resp) if resp.head != head => {
            tracing::warn!(
                "tailnet lock: control's head is {} after sync, ours {head}",
                resp.head
            )
        }
        Ok(_) => {}
        Err(e) => tracing::debug!("tailnet lock sync/send: {e}"),
    }
    if offer.head != head {
        tracing::debug!(
            "tailnet lock: control offered head {}, we are at {head}",
            offer.head
        );
    }
    Ok(())
}

fn disablement_valid(authority: &Authority, secret: &[u8]) -> bool {
    #[cfg(feature = "tka-disable")]
    return authority.valid_disablement(secret);
    #[cfg(not(feature = "tka-disable"))]
    {
        let _ = (authority, secret);
        tracing::warn!(
            "this build cannot verify a tailnet-lock disablement (feature `tka-disable`)"
        );
        false
    }
}
