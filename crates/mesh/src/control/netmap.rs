//! The netmap: this node and its peers as control describes them, kept
//! current by applying each map response (full or delta) in Go's order.
//!
//! Peers are stored compactly ([`Peer`]): what routing, naming and path
//! discovery need, parsed out of each node as it arrives, nothing else. A
//! large tailnet costs a few hundred bytes per peer.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde::Deserialize;

use super::types::{prefix_addr, DerpMap, DerpRegion, MapResponse, Node};
use crate::keys::{DiscoPublic, NodePublic};
use crate::paths::{Directory, PeerInfo};

/// A node of the tailnet, as much of it as this client uses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "Node")]
pub struct Peer {
    pub id: i64,
    pub key: NodePublic,
    pub disco_key: DiscoPublic,
    /// The FQDN without its trailing dot, lowercased (a bare hostname if
    /// control gives no domain).
    pub name: Box<str>,
    pub addresses: Box<[IpAddr]>,
    /// Prefixes it routes beyond its own addresses (subnet routers).
    pub routes: Box<[(IpAddr, u8)]>,
    pub endpoints: Arc<[SocketAddr]>,
    pub home_region: Option<i32>,
    pub online: Option<bool>,
    /// Its node key's tailnet-lock signature (empty: unsigned).
    pub key_signature: Box<[u8]>,
    /// Exempt from tailnet lock (Funnel ingress nodes).
    pub unsigned_peer_api_only: bool,
}

impl From<Node> for Peer {
    fn from(n: Node) -> Self {
        let addresses: Box<[IpAddr]> = n.addresses.iter().filter_map(|a| prefix_addr(a)).collect();
        let routes = n
            .allowed_ips
            .unwrap_or_default()
            .iter()
            .filter_map(|p| parse_prefix(p))
            .filter(|(ip, bits)| !(addresses.contains(ip) && *bits == full_bits(ip)))
            .collect();
        let name = if n.name.is_empty() {
            n.hostinfo.hostname
        } else {
            n.name
        };
        Self {
            id: n.id,
            key: n.key,
            disco_key: n.disco_key,
            name: name.trim_end_matches('.').to_ascii_lowercase().into(),
            addresses,
            routes,
            endpoints: n.endpoints.iter().filter_map(|e| e.parse().ok()).collect(),
            home_region: home_region(n.home_derp, &n.legacy_derp),
            online: n.online,
            key_signature: n.key_signature,
            unsigned_peer_api_only: n.unsigned_peer_api_only,
        }
    }
}

impl Peer {
    /// The bare hostname (the first label of the name).
    pub fn hostname(&self) -> &str {
        self.name.split('.').next().unwrap_or_default()
    }

    /// Whether traffic for `ip` belongs to this peer.
    pub fn owns(&self, ip: IpAddr) -> bool {
        self.addresses.contains(&ip)
            || self
                .routes
                .iter()
                .any(|&(net, bits)| prefix_contains(net, bits, ip))
    }

    /// Its IPv4 address if it has one, else any.
    pub fn primary_address(&self) -> Option<IpAddr> {
        self.addresses
            .iter()
            .find(|ip| ip.is_ipv4())
            .or(self.addresses.first())
            .copied()
    }
}

fn home_region(home_derp: i32, legacy: &str) -> Option<i32> {
    if home_derp != 0 {
        return Some(home_derp);
    }
    legacy
        .strip_prefix("127.3.3.40:")
        .and_then(|r| r.parse().ok())
        .filter(|r| *r != 0)
}

impl Peer {
    fn path_info(&self) -> PeerInfo {
        PeerInfo {
            node_key: self.key,
            disco_key: self.disco_key,
            home_region: self.home_region,
            endpoints: self.endpoints.clone(),
        }
    }
}

/// Path selection looks peers up here, instead of keeping its own copy.
impl Directory for NetMap {
    fn peer(&self, key: &NodePublic) -> Option<PeerInfo> {
        self.peer_by_key(key).map(Peer::path_info)
    }

    fn peer_by_disco(&self, disco: &DiscoPublic) -> Option<PeerInfo> {
        self.peers
            .iter()
            .find(|p| p.disco_key == *disco)
            .map(Peer::path_info)
    }
}

#[derive(Debug, Default, Clone)]
pub struct NetMap {
    pub self_node: Option<Peer>,
    /// Sorted by id: control sends them in that order, so a parsed list is
    /// adopted as is (no second copy while converting).
    peers: Vec<Peer>,
    /// Peers tailnet lock rejects (sorted by id). Invisible to every lookup,
    /// but kept, so later changes (e.g. a new signature) still reach them.
    untrusted: Vec<Peer>,
    pub derp_regions: BTreeMap<i32, DerpRegion>,
    pub domain: String,
}

impl NetMap {
    /// Apply one map response. Returns whether anything changed.
    pub fn apply(&mut self, resp: MapResponse) -> bool {
        if resp.keep_alive {
            return false;
        }
        if let Some(node) = resp.node {
            self.self_node = Some(node);
        }
        if let Some(DerpMap {
            regions: Some(regions),
        }) = resp.derp_map
        {
            self.derp_regions = regions
                .into_iter()
                .filter_map(|(id, region)| Some((id, region?)))
                .collect();
        }
        if !resp.domain.is_empty() {
            self.domain = resp.domain;
        }
        if !resp.peers.is_empty() {
            // A full list replaces everything, and other deltas are ignored.
            self.peers = Vec::new(); // before sorting, so both are not held longer
            self.untrusted = Vec::new();
            let mut peers = resp.peers;
            peers.sort_unstable_by_key(|p| p.id);
            peers.dedup_by_key(|p| p.id);
            peers.shrink_to_fit();
            self.peers = peers;
            return true;
        }
        for id in resp.peers_removed {
            if let Ok(i) = self.index(id) {
                self.peers.remove(i);
            }
            if let Ok(i) = self.untrusted.binary_search_by_key(&id, |p| p.id) {
                self.untrusted.remove(i);
            }
        }
        for peer in resp.peers_changed {
            // Changed peers are judged again (the next `retain`).
            if let Ok(i) = self.untrusted.binary_search_by_key(&peer.id, |p| p.id) {
                self.untrusted.remove(i);
            }
            match self.index(peer.id) {
                Ok(i) => self.peers[i] = peer,
                Err(i) => self.peers.insert(i, peer),
            }
        }
        for (id, online) in resp.online_change {
            if let Some(p) = self.peer_mut(id) {
                p.online = Some(online);
            }
        }
        for change in resp.peers_changed_patch {
            let Some(p) = self.peer_mut(change.node_id) else {
                continue;
            };
            if change.derp_region != 0 {
                p.home_region = Some(change.derp_region);
            }
            if let Some(endpoints) = change.endpoints {
                p.endpoints = endpoints.iter().filter_map(|e| e.parse().ok()).collect();
            }
            if let Some(key) = change.key {
                p.key = key;
            }
            if let Some(disco) = change.disco_key {
                p.disco_key = disco;
            }
            if let Some(online) = change.online {
                p.online = Some(online);
            }
            if let Some(signature) = change.key_signature {
                p.key_signature = signature;
            }
        }
        true
    }

    /// Keep only the peers `trusted` accepts; the rest become invisible
    /// until a later call accepts them. Returns how many are hidden.
    pub fn retain_trusted(&mut self, mut trusted: impl FnMut(&Peer) -> bool) -> usize {
        let mut all = std::mem::take(&mut self.peers);
        all.append(&mut self.untrusted);
        all.sort_unstable_by_key(|p| p.id);
        let (keep, hide): (Vec<Peer>, Vec<Peer>) = all.into_iter().partition(|p| trusted(p));
        self.peers = keep;
        self.untrusted = hide;
        self.untrusted.len()
    }

    /// The peers tailnet lock hides.
    pub fn untrusted(&self) -> &[Peer] {
        &self.untrusted
    }

    fn index(&self, id: i64) -> Result<usize, usize> {
        self.peers.binary_search_by_key(&id, |p| p.id)
    }

    fn peer_mut(&mut self, id: i64) -> Option<&mut Peer> {
        if let Ok(i) = self.index(id) {
            return Some(&mut self.peers[i]);
        }
        let i = self.untrusted.binary_search_by_key(&id, |p| p.id).ok()?;
        Some(&mut self.untrusted[i])
    }

    /// All peers, by id.
    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }

    pub fn peer(&self, id: i64) -> Option<&Peer> {
        self.index(id).ok().map(|i| &self.peers[i])
    }

    pub fn self_addresses(&self) -> &[IpAddr] {
        self.self_node
            .as_ref()
            .map(|n| &*n.addresses)
            .unwrap_or_default()
    }

    pub fn peer_by_key(&self, key: &NodePublic) -> Option<&Peer> {
        self.peers.iter().find(|p| p.key == *key)
    }

    /// The peer owning tailnet address `ip`.
    pub fn peer_by_ip(&self, ip: IpAddr) -> Option<&Peer> {
        self.peers.iter().find(|p| p.owns(ip))
    }

    /// Look a peer up by name: its FQDN (with or without the trailing dot),
    /// or its bare hostname.
    pub fn peer_by_name(&self, name: &str) -> Option<&Peer> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.peers.iter().find(|p| *p.name == *name).or_else(|| {
            let bare = name.split('.').next().unwrap_or_default();
            let in_domain = name == bare
                || name
                    .strip_prefix(bare)
                    .and_then(|rest| rest.strip_prefix('.'))
                    == Some(self.domain.trim_end_matches('.'));
            in_domain
                .then(|| {
                    self.peers
                        .iter()
                        .find(|p| p.hostname().eq_ignore_ascii_case(bare))
                })
                .flatten()
        })
    }
}

fn full_bits(ip: &IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

/// `"ip/bits"`.
fn parse_prefix(prefix: &str) -> Option<(IpAddr, u8)> {
    let (net, bits) = prefix.split_once('/')?;
    let ip: IpAddr = net.parse().ok()?;
    let bits: u8 = bits.parse().ok()?;
    (bits <= full_bits(&ip)).then_some((ip, bits))
}

fn prefix_contains(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::types::PeerChange;

    fn peer(id: i64, name: &str, ip: &str) -> Peer {
        Peer::from(Node {
            id,
            name: name.into(),
            addresses: vec![format!("{ip}/32")],
            ..Default::default()
        })
    }

    #[test]
    fn full_then_deltas() {
        let mut nm = NetMap::default();
        nm.apply(MapResponse {
            domain: "tail".into(),
            peers: vec![
                peer(1, "a.tail.", "100.64.0.1"),
                peer(2, "b.tail.", "100.64.0.2"),
            ],
            ..Default::default()
        });
        assert_eq!(nm.peers().len(), 2);
        nm.apply(MapResponse {
            peers_removed: vec![1],
            peers_changed: vec![peer(3, "c.tail.", "100.64.0.3")],
            peers_changed_patch: vec![PeerChange {
                node_id: 2,
                derp_region: 7,
                endpoints: Some(vec!["1.2.3.4:5".into()]),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert!(nm.peer(1).is_none());
        assert_eq!(nm.peer(2).unwrap().home_region, Some(7));
        assert_eq!(
            &*nm.peer(2).unwrap().endpoints,
            &["1.2.3.4:5".parse().unwrap()]
        );
        assert_eq!(
            nm.peers().iter().map(|p| p.id).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(!nm.apply(MapResponse {
            keep_alive: true,
            ..Default::default()
        }));
    }

    #[test]
    fn name_and_ip_lookup() {
        let mut nm = NetMap::default();
        nm.apply(MapResponse {
            domain: "tail-scale.ts.net".into(),
            peers: vec![
                peer(1, "peer.tail-scale.ts.net.", "100.64.0.1"),
                peer(2, "other", "100.64.0.9"),
            ],
            ..Default::default()
        });
        for name in [
            "peer",
            "PEER",
            "peer.tail-scale.ts.net",
            "peer.tail-scale.ts.net.",
        ] {
            assert_eq!(nm.peer_by_name(name).map(|p| p.id), Some(1), "{name}");
        }
        assert_eq!(nm.peer_by_name("other").map(|p| p.id), Some(2));
        assert!(nm.peer_by_name("peer.elsewhere.com").is_none());
        assert_eq!(
            nm.peer_by_ip("100.64.0.9".parse().unwrap()).map(|p| p.id),
            Some(2)
        );
    }

    #[test]
    fn routes_exclude_own_addresses() {
        let router = Peer::from(Node {
            id: 1,
            name: "router".into(),
            addresses: vec!["100.64.0.5/32".into()],
            allowed_ips: Some(vec!["100.64.0.5/32".into(), "10.0.0.0/8".into()]),
            ..Default::default()
        });
        assert_eq!(&*router.routes, &[("10.0.0.0".parse().unwrap(), 8)]);
        assert!(router.owns("10.1.2.3".parse().unwrap()));
        assert!(router.owns("100.64.0.5".parse().unwrap()));
        assert!(!router.owns("100.64.0.6".parse().unwrap()));
    }
}
