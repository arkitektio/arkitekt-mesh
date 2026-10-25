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

use super::control::ControlClient;
use crate::control::types::TkaInfo;
use crate::keys::NodePublic;
use mesh_core::lock::sync::{LockSync, Step};

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

/// Bring `lock` in step with what control announced ([`LockSync`], the
/// core's): its calls made over `client`. Errors leave the lock
/// fail-closed: when control says the tailnet is locked and we cannot
/// verify its chain, every peer is hidden.
pub(super) async fn sync(
    client: &ControlClient,
    node_key: &NodePublic,
    info: &TkaInfo,
    lock: &mut Lock,
) {
    let (mut sync, mut step) = LockSync::start(*node_key, info.clone(), core::mem::take(lock));
    loop {
        match step {
            Step::Call(call) => {
                let answered = client.call_whole(&call).await.map_err(|e| e.to_string());
                step = sync.answer(answered);
            }
            Step::Done(synced) => {
                *lock = synced;
                return;
            }
        }
    }
}
