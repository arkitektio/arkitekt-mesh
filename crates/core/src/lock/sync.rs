//! Keeping tailnet lock in step with control, without I/O: the RPCs one at
//! a time, as [`Call`]s, each answered by the driver, ending in the lock
//! to install (docs/rfc5-tailnet-lock.md).
//!
//! - The first announcement fetches the genesis (`/machine/tka/bootstrap`).
//! - Different heads sync updates (`sync/offer`), verified before they
//!   apply, then tell control where we landed (`sync/send`).
//! - A disablement holds only if its secret verifies.
//!
//! Errors leave the lock fail-closed: without a verified authority every
//! peer is hidden; with one, it is kept.

#[allow(unused_imports)]
use crate::prelude::*;

use serde::{Deserialize, Serialize};

use super::Lock;
use crate::control::api::{self, Call};
use crate::control::types::{TkaInfo, CAPABILITY_VERSION};
use crate::keys::NodePublic;
use crate::tka::{hash_text, parse_hash_text, Authority};

const BOOTSTRAP: &str = "/machine/tka/bootstrap";
const OFFER: &str = "/machine/tka/sync/offer";
const SEND: &str = "/machine/tka/sync/send";

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

/// What to do next.
pub enum Step {
    /// Make this call and pass its answer to [`LockSync::answer`].
    Call(Call),
    /// Synced (or failed closed): install this lock.
    Done(Lock),
}

/// The answer to a [`Step::Call`]: status and body, or why there is none.
pub type Answered = Result<(u16, Vec<u8>), String>;

enum Waiting {
    Disablement,
    Genesis,
    Offer,
    Send { offered: String },
}

/// See the module docs.
pub struct LockSync {
    node_key: NodePublic,
    info: TkaInfo,
    lock: Lock,
    waiting: Option<Waiting>,
}

impl LockSync {
    /// Sync `lock` (a copy: the node keeps judging by the old one until
    /// this is done) with what control announced in `info`.
    pub fn start(node_key: NodePublic, info: TkaInfo, lock: Lock) -> (Self, Step) {
        let mut sync = Self {
            node_key,
            info,
            lock,
            waiting: None,
        };
        let step = if sync.info.disabled {
            match &sync.lock.authority {
                None => sync.finish(Ok(())),
                Some(authority) => {
                    let head = hash_text(&authority.head());
                    sync.call(
                        Waiting::Disablement,
                        BOOTSTRAP,
                        &BootstrapRequest {
                            version: CAPABILITY_VERSION,
                            node_key: &node_key,
                            head: &head,
                        },
                    )
                }
            }
        } else if sync.lock.authority.is_none() {
            sync.call(
                Waiting::Genesis,
                BOOTSTRAP,
                &BootstrapRequest {
                    version: CAPABILITY_VERSION,
                    node_key: &node_key,
                    head: "",
                },
            )
        } else {
            sync.offer()
        };
        (sync, step)
    }

    /// The answer to the last [`Step::Call`].
    pub fn answer(&mut self, answered: Answered) -> Step {
        match self.waiting.take() {
            Some(Waiting::Disablement) => self.on_disablement(answered),
            Some(Waiting::Genesis) => self.on_genesis(answered),
            Some(Waiting::Offer) => self.on_offer(answered),
            Some(Waiting::Send { offered }) => self.on_send(answered, &offered),
            None => self.finish(Err("an answer nobody asked for".into())),
        }
    }

    fn on_disablement(&mut self, answered: Answered) -> Step {
        let resp: BootstrapResponse = match parse(BOOTSTRAP, answered) {
            Ok(r) => r,
            Err(e) => return self.finish(Err(e)),
        };
        let secret = match unb64(resp.disablement_secret.as_deref().unwrap_or_default()) {
            Ok(s) => s,
            Err(e) => return self.finish(Err(e)),
        };
        let authority = self
            .lock
            .authority
            .as_ref()
            .expect("disablements need an authority");
        if disablement_valid(authority, &secret) {
            tracing::info!("tailnet lock disabled (the disablement secret verifies)");
            if let Some(store) = &self.lock.store {
                store.clear();
            }
            self.lock.authority = None;
            self.lock.unverified = None;
            return self.finish(Ok(()));
        }
        self.finish(Err(
            "control says tailnet lock is disabled, but its secret does not verify; staying locked"
                .into(),
        ))
    }

    fn on_genesis(&mut self, answered: Answered) -> Step {
        let resp: BootstrapResponse = match parse(BOOTSTRAP, answered) {
            Ok(r) => r,
            Err(e) => return self.finish(Err(e)),
        };
        let genesis = match resp.genesis_aum.as_deref() {
            Some(g) => match unb64(g) {
                Ok(g) => g,
                Err(e) => return self.finish(Err(e)),
            },
            None => return self.finish(Err("control sent no genesis".into())),
        };
        match Authority::bootstrap(&genesis) {
            Ok(authority) => {
                tracing::info!(
                    "tailnet lock: bootstrapped at {}",
                    hash_text(&authority.head())
                );
                self.lock.adopt(authority);
                self.offer()
            }
            Err(e) => self.finish(Err(format!("genesis: {e}"))),
        }
    }

    /// Our head against control's: equal, done; else offer ours.
    fn offer(&mut self) -> Step {
        let authority = self.lock.authority.as_ref().expect("bootstrapped");
        if parse_hash_text(&self.info.head) == Some(authority.head()) {
            return self.finish(Ok(()));
        }
        let (head, ancestors) = authority.sync_offer();
        let node_key = self.node_key;
        self.call(
            Waiting::Offer,
            OFFER,
            &SyncOfferRequest {
                version: CAPABILITY_VERSION,
                node_key: &node_key,
                head: hash_text(&head),
                ancestors: ancestors.iter().map(hash_text).collect(),
            },
        )
    }

    fn on_offer(&mut self, answered: Answered) -> Step {
        let offer: SyncOfferResponse = match parse(OFFER, answered) {
            Ok(r) => r,
            Err(e) => return self.finish(Err(e)),
        };
        let updates: Result<Vec<Vec<u8>>, String> = offer
            .missing_aums
            .unwrap_or_default()
            .iter()
            .map(|a| unb64(a))
            .collect();
        let updates = match updates {
            Ok(u) => u,
            Err(e) => return self.finish(Err(e)),
        };
        let mut next = self.lock.authority.clone().expect("bootstrapped");
        if !updates.is_empty() {
            match next.inform(&updates) {
                Ok(applied) => tracing::info!(
                    "tailnet lock: {applied} update(s), head {}",
                    hash_text(&next.head())
                ),
                Err(e) => return self.finish(Err(format!("updates from control: {e}"))),
            }
        }
        self.lock.adopt(next);
        // Tell control where we landed (we author no updates).
        let head = self.lock.head_text();
        let node_key = self.node_key;
        self.call(
            Waiting::Send {
                offered: offer.head,
            },
            SEND,
            &SyncSendRequest {
                version: CAPABILITY_VERSION,
                node_key: &node_key,
                head,
                missing_aums: Vec::new(),
                interactive: false,
            },
        )
    }

    fn on_send(&mut self, answered: Answered, offered: &str) -> Step {
        let head = self.lock.head_text();
        // Some servers do not serve it (tailscale's test control): not an error.
        match parse::<SyncSendResponse>(SEND, answered) {
            Ok(resp) if resp.head != head => {
                tracing::warn!(
                    "tailnet lock: control's head is {} after sync, ours {head}",
                    resp.head
                )
            }
            Ok(_) => {}
            Err(e) => tracing::debug!("tailnet lock sync/send: {e}"),
        }
        if offered != head {
            tracing::debug!("tailnet lock: control offered head {offered}, we are at {head}");
        }
        self.finish(Ok(()))
    }

    fn call<T: Serialize>(&mut self, waiting: Waiting, path: &str, body: &T) -> Step {
        self.waiting = Some(waiting);
        Step::Call(Call::rpc(path, &self.node_key, body))
    }

    fn finish(&mut self, result: Result<(), String>) -> Step {
        let mut lock = core::mem::take(&mut self.lock);
        match result {
            Ok(()) => {}
            Err(e) if lock.authority.is_none() => {
                tracing::warn!("tailnet lock: {e}; no peer is trusted until it can be verified");
                lock.unverified = Some(e);
            }
            // With an authority we keep trusting what it verified.
            Err(e) => tracing::warn!("tailnet lock sync: {e}"),
        }
        Step::Done(lock)
    }
}

fn parse<T: serde::de::DeserializeOwned>(path: &str, answered: Answered) -> Result<T, String> {
    let (status, body) = answered?;
    api::parse_rpc(path, status, &body).map_err(|e| e.to_string())
}

fn unb64(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("bad base64: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PublicKey;

    fn key() -> NodePublic {
        NodePublic(PublicKey([7; 32]))
    }

    fn info(head: &str, disabled: bool) -> TkaInfo {
        TkaInfo {
            head: head.into(),
            disabled,
        }
    }

    #[test]
    fn an_unreachable_bootstrap_fails_closed() {
        let (mut sync, step) = LockSync::start(key(), info("abc", false), Lock::default());
        let Step::Call(call) = step else {
            panic!("a bootstrap first")
        };
        assert_eq!((call.method, call.path.as_str()), ("GET", BOOTSTRAP));
        let Step::Done(lock) = sync.answer(Err("connection reset".into())) else {
            panic!("done")
        };
        assert!(lock.unverified.is_some());
        assert!(matches!(
            lock.status(),
            super::super::LockStatus::Unverified(_)
        ));
    }

    #[test]
    fn a_bootstrap_without_genesis_or_refused_fails_closed() {
        let (mut sync, _) = LockSync::start(key(), info("abc", false), Lock::default());
        let Step::Done(lock) = sync.answer(Ok((200, b"{}".to_vec()))) else {
            panic!()
        };
        assert_eq!(lock.unverified.as_deref(), Some("control sent no genesis"));
        let (mut sync, _) = LockSync::start(key(), info("abc", false), Lock::default());
        let Step::Done(lock) = sync.answer(Ok((404, b"not here".to_vec()))) else {
            panic!()
        };
        assert!(lock.unverified.is_some());
    }

    #[test]
    fn disabled_without_an_authority_is_nothing_to_do() {
        let (_, step) = LockSync::start(key(), info("", true), Lock::default());
        let Step::Done(lock) = step else {
            panic!("no calls")
        };
        assert!(lock.unverified.is_none());
        assert!(lock.authority.is_none());
    }
}
