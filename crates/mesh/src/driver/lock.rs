//! Tailnet lock in the driver (docs/rfc5-tailnet-lock.md): keeping the
//! authority in step with control, and a file to keep it in. The lock's
//! state and its judgement of peers are the core's (`mesh_core::lock`).
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

use std::path::PathBuf;

use base64::Engine;
use serde::{Deserialize, Serialize};

pub use mesh_core::lock::{Lock, LockStatus, LockStore};

use super::control::{ControlClient, ControlError};
use crate::control::types::{TkaInfo, CAPABILITY_VERSION};
use crate::keys::NodePublic;
use crate::tka::{hash_text, parse_hash_text, Authority};

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
