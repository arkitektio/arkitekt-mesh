//! The control protocol's JSON, with the Go field names (`tailcfg`).
//!
//! Only what this client uses is modelled; unknown fields are ignored.
//! Key-typed fields are never sent as `""` (the zero key is sent instead),
//! because Go servers reject malformed keys outright.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use super::netmap::Peer;
use crate::keys::{DiscoPublic, MachinePublic, NodePublic};

/// The capability version this client speaks (tailscale 1.102, capver 142):
/// Noise, delta netmaps, `HomeDERP`, implicit `AllowedIPs`.
pub const CAPABILITY_VERSION: u16 = 142;

/// `GET /key?v=N`.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerKeys {
    #[serde(rename = "publicKey")]
    pub public_key: MachinePublic,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterRequest {
    pub version: u16,
    pub node_key: NodePublic,
    pub old_node_key: NodePublic,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<RegisterAuth>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub followup: String,
    pub hostinfo: Hostinfo,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterAuth {
    pub auth_key: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RegisterResponse {
    pub node_key_expired: bool,
    pub machine_authorized: bool,
    #[serde(rename = "AuthURL", deserialize_with = "nullable")]
    pub auth_url: String,
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Hostinfo {
    #[serde(
        rename = "IPNVersion",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub ipn_version: String,
    #[serde(
        rename = "OS",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub os: String,
    #[serde(
        rename = "Hostname",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub hostname: String,
    #[serde(
        rename = "GoArch",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub arch: String,
    #[serde(
        rename = "App",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub app: String,
    #[serde(
        rename = "RequestTags",
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "nullable"
    )]
    pub request_tags: Vec<String>,
    #[serde(rename = "NetInfo", skip_serializing_if = "Option::is_none")]
    pub net_info: Option<NetInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetInfo {
    #[serde(rename = "PreferredDERP")]
    pub preferred_derp: i32,
    /// Measured latency per region, `"<region>-v4"` to seconds.
    #[serde(rename = "DERPLatency", skip_serializing_if = "BTreeMap::is_empty")]
    pub derp_latency: BTreeMap<String, f64>,
}

/// How an endpoint was found (`tailcfg.EndpointType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointType {
    Local = 1,
    Stun = 2,
    /// A mapping the gateway granted (PCP, NAT-PMP).
    Portmapped = 3,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MapRequest {
    pub version: u16,
    pub node_key: NodePublic,
    pub disco_key: DiscoPublic,
    pub stream: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub keep_alive: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub omit_peers: bool,
    pub hostinfo: Hostinfo,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<SocketAddr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoint_types: Vec<u8>,
    /// Our tailnet-lock head (`AUMHash` text), if the tailnet is locked.
    #[serde(rename = "TKAHead", skip_serializing_if = "String::is_empty")]
    pub tka_head: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct MapResponse {
    pub keep_alive: bool,
    pub node: Option<Peer>,
    #[serde(rename = "DERPMap")]
    pub derp_map: Option<DerpMap>,
    /// Peers are compacted one by one as they parse (see [`Peer`]).
    #[serde(deserialize_with = "nullable")]
    pub peers: Vec<Peer>,
    #[serde(deserialize_with = "nullable")]
    pub peers_changed: Vec<Peer>,
    #[serde(deserialize_with = "nullable")]
    pub peers_removed: Vec<i64>,
    #[serde(deserialize_with = "nullable")]
    pub peers_changed_patch: Vec<PeerChange>,
    #[serde(deserialize_with = "nullable")]
    pub online_change: BTreeMap<i64, bool>,
    #[serde(deserialize_with = "nullable")]
    pub domain: String,
    /// The tailnet's ACLs for inbound packets: the whole set (`None`:
    /// unchanged; empty: deny everything new).
    pub packet_filter: Option<Vec<crate::filter::FilterRule>>,
    /// Tailnet lock: control's head, or that it was disabled.
    #[serde(rename = "TKAInfo")]
    pub tka_info: Option<TkaInfo>,
    /// Named sets replacing parts of it (`"*": null` clears all).
    pub packet_filters: Option<BTreeMap<String, Option<Vec<crate::filter::FilterRule>>>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "Name", deserialize_with = "nullable")]
    pub name: String,
    #[serde(rename = "Key")]
    pub key: NodePublic,
    #[serde(rename = "Machine")]
    pub machine: MachinePublic,
    #[serde(rename = "DiscoKey")]
    pub disco_key: DiscoPublic,
    #[serde(rename = "Addresses", deserialize_with = "nullable")]
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Option<Vec<String>>,
    #[serde(rename = "Endpoints", deserialize_with = "nullable")]
    pub endpoints: Vec<String>,
    /// Legacy home DERP: `"127.3.3.40:<region>"`.
    #[serde(rename = "DERP", deserialize_with = "nullable")]
    pub legacy_derp: String,
    #[serde(rename = "HomeDERP")]
    pub home_derp: i32,
    #[serde(rename = "Hostinfo", deserialize_with = "nullable")]
    pub hostinfo: PeerHostinfo,
    /// Its node key's tailnet-lock signature (CBOR; empty: unsigned).
    #[serde(rename = "KeySignature", deserialize_with = "base64_bytes")]
    pub key_signature: Box<[u8]>,
    /// Not subject to tailnet lock (Funnel ingress nodes).
    #[serde(rename = "UnsignedPeerAPIOnly")]
    pub unsigned_peer_api_only: bool,
    #[serde(rename = "Online")]
    pub online: Option<bool>,
    #[serde(rename = "Expired")]
    pub expired: bool,
}

impl Node {
    /// The node's tailnet addresses (prefixes stripped).
    pub fn ips(&self) -> Vec<IpAddr> {
        self.addresses
            .iter()
            .filter_map(|a| prefix_addr(a))
            .collect()
    }

    /// Parsed endpoints, skipping any that do not parse.
    pub fn endpoint_addrs(&self) -> Vec<SocketAddr> {
        self.endpoints
            .iter()
            .filter_map(|e| e.parse().ok())
            .collect()
    }

    /// The home DERP region, from `HomeDERP` or the legacy string.
    pub fn home_region(&self) -> Option<i32> {
        if self.home_derp != 0 {
            return Some(self.home_derp);
        }
        self.legacy_derp
            .strip_prefix("127.3.3.40:")
            .and_then(|r| r.parse().ok())
            .filter(|r| *r != 0)
    }
}

/// Of a peer's Hostinfo, only the hostname is kept.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PeerHostinfo {
    #[serde(rename = "Hostname", deserialize_with = "nullable")]
    pub hostname: String,
}

/// Go writes nil slices, maps and pointers as `null`; read those as empty.
/// Go's `[]byte` in JSON: standard base64 (or null).
fn base64_bytes<'de, D>(d: D) -> Result<Box<[u8]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use base64::Engine;
    match Option::<String>::deserialize(d)? {
        None => Ok(Box::default()),
        Some(s) => base64::engine::general_purpose::STANDARD
            .decode(s)
            .map(Into::into)
            .map_err(serde::de::Error::custom),
    }
}

fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// `"100.64.0.1/32"` -> `100.64.0.1`.
pub fn prefix_addr(prefix: &str) -> Option<IpAddr> {
    prefix.split('/').next()?.parse().ok()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PeerChange {
    #[serde(rename = "NodeID")]
    pub node_id: i64,
    #[serde(rename = "DERPRegion")]
    pub derp_region: i32,
    #[serde(rename = "Endpoints")]
    pub endpoints: Option<Vec<String>>,
    #[serde(rename = "Key")]
    pub key: Option<NodePublic>,
    #[serde(rename = "DiscoKey")]
    pub disco_key: Option<DiscoPublic>,
    #[serde(rename = "Online")]
    pub online: Option<bool>,
    #[serde(rename = "KeySignature", deserialize_with = "base64_opt", default)]
    pub key_signature: Option<Box<[u8]>>,
}

fn base64_opt<'de, D>(d: D) -> Result<Option<Box<[u8]>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    base64_bytes(d).map(Some)
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TkaInfo {
    pub head: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DerpMap {
    #[serde(rename = "Regions")]
    pub regions: Option<BTreeMap<i32, Option<DerpRegion>>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct DerpRegion {
    #[serde(rename = "RegionID")]
    pub region_id: i32,
    #[serde(rename = "RegionCode", deserialize_with = "nullable")]
    pub region_code: String,
    #[serde(rename = "Avoid")]
    pub avoid: bool,
    #[serde(rename = "NoMeasureNoHome")]
    pub no_measure_no_home: bool,
    #[serde(rename = "Nodes", deserialize_with = "nullable")]
    pub nodes: Vec<DerpNode>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct DerpNode {
    #[serde(rename = "Name", deserialize_with = "nullable")]
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: i32,
    #[serde(rename = "HostName", deserialize_with = "nullable")]
    pub host_name: String,
    #[serde(rename = "CertName", deserialize_with = "nullable")]
    pub cert_name: String,
    #[serde(rename = "IPv4", deserialize_with = "nullable")]
    pub ipv4: String,
    #[serde(rename = "IPv6", deserialize_with = "nullable")]
    pub ipv6: String,
    /// 0 = 3478, -1 = none.
    #[serde(rename = "STUNPort")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly")]
    pub stun_only: bool,
    /// 0 = 443.
    #[serde(rename = "DERPPort")]
    pub derp_port: i32,
    #[serde(rename = "InsecureForTests")]
    pub insecure_for_tests: bool,
    #[serde(rename = "STUNTestIP", deserialize_with = "nullable")]
    pub stun_test_ip: String,
}

impl DerpNode {
    /// Where to dial the node's DERP server: its IPv4, else its IPv6, else
    /// its hostname (resolved). A non-IP value such as `"none"` disables
    /// that family.
    pub fn derp_dial_host(&self) -> String {
        if let Ok(ip) = self.ipv4.parse::<std::net::Ipv4Addr>() {
            return ip.to_string();
        }
        if let Ok(ip) = self.ipv6.parse::<std::net::Ipv6Addr>() {
            return ip.to_string();
        }
        self.host_name.clone()
    }

    /// The name the server's certificate must carry: `CertName`, else the
    /// hostname. `None` for a pinned self-signed cert (`sha256-raw:…`),
    /// which this client does not verify (DERP payloads are end-to-end
    /// encrypted and the handshake is sealed to the server's key).
    pub fn derp_cert_name(&self) -> Option<String> {
        if self.cert_name.starts_with("sha256-raw:") {
            return None;
        }
        Some(if self.cert_name.is_empty() {
            self.host_name.clone()
        } else {
            self.cert_name.clone()
        })
    }

    pub fn derp_port(&self) -> u16 {
        if self.derp_port > 0 {
            self.derp_port as u16
        } else {
            443
        }
    }

    /// The STUN server's addresses: the one [`stun_addr`](Self::stun_addr)
    /// gives, and its IPv6 address if it has one.
    pub fn stun_addrs(&self) -> Vec<(String, u16)> {
        let Some((host, port)) = self.stun_addr() else {
            return Vec::new();
        };
        let mut out = vec![(host.clone(), port)];
        if self.ipv6.parse::<std::net::Ipv6Addr>().is_ok() && self.ipv6 != host {
            out.push((self.ipv6.clone(), port));
        }
        out
    }

    /// The STUN server, unless disabled.
    pub fn stun_addr(&self) -> Option<(String, u16)> {
        let port = match self.stun_port {
            -1 => return None,
            0 => 3478,
            p => p as u16,
        };
        let host = [&self.stun_test_ip, &self.ipv4]
            .into_iter()
            .find(|h| h.parse::<IpAddr>().is_ok())
            .cloned()
            .unwrap_or_else(|| self.host_name.clone());
        Some((host, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derp_nodes_dial_the_ip_and_verify_the_name() {
        let node = DerpNode {
            host_name: "derp1.example.com".into(),
            ipv4: "1.2.3.4".into(),
            ..Default::default()
        };
        assert_eq!(node.derp_dial_host(), "1.2.3.4");
        assert_eq!(node.derp_cert_name().as_deref(), Some("derp1.example.com"));
        let node = DerpNode {
            ipv4: "none".into(),
            ipv6: "2001:db8::1".into(),
            ..node
        };
        assert_eq!(node.derp_dial_host(), "2001:db8::1");
        let node = DerpNode {
            ipv6: String::new(),
            cert_name: "sha256-raw:ab".into(),
            ..node
        };
        assert_eq!(node.derp_dial_host(), "derp1.example.com");
        assert_eq!(node.derp_cert_name(), None);
    }

    #[test]
    fn register_request_uses_go_names_and_zero_keys() {
        let req = RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: NodePublic(crate::keys::PrivateKey::generate().public()),
            auth: Some(RegisterAuth {
                auth_key: "tskey-x".into(),
            }),
            hostinfo: Hostinfo {
                hostname: "me".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Version"], 142);
        assert_eq!(json["Auth"]["AuthKey"], "tskey-x");
        assert_eq!(json["Hostinfo"]["Hostname"], "me");
        assert_eq!(json["OldNodeKey"], format!("nodekey:{}", "0".repeat(64)));
        assert!(json.get("Followup").is_none());
    }

    #[test]
    fn map_response_parses_go_json() {
        let json = r#"{
            "Node": {"ID": 1, "Name": "me.tail.", "Key": "nodekey:0000000000000000000000000000000000000000000000000000000000000001",
                     "Addresses": ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"], "Endpoints": null, "Hostinfo": null, "AllowedIPs": null},
            "Peers": [{"ID": 2, "Name": "peer.tail.", "DERP": "127.3.3.40:1", "Endpoints": ["127.0.0.1:41641", "[::1]:41641"],
                       "DiscoKey": "discokey:0000000000000000000000000000000000000000000000000000000000000002"}],
            "DERPMap": {"Regions": {"1": {"RegionID": 1, "Nodes": [{"Name": "t1", "HostName": "127.0.0.1", "IPv4": "127.0.0.1",
                        "IPv6": "none", "STUNPort": 3479, "DERPPort": 4443, "InsecureForTests": true}]}}},
            "Domain": "tail", "SomethingNew": {"x": 1},
            "PeersChanged": null, "PeersRemoved": null, "OnlineChange": null
        }"#;
        let resp: MapResponse = serde_json::from_str(json).unwrap();
        let node = resp.node.unwrap();
        assert_eq!(node.addresses.len(), 2);
        assert_eq!(node.hostname(), "me");
        let peer = &resp.peers[0];
        assert_eq!(peer.home_region, Some(1));
        assert_eq!(peer.endpoints.len(), 2);
        let region = resp.derp_map.unwrap().regions.unwrap()[&1].clone().unwrap();
        assert_eq!(region.nodes[0].derp_port(), 4443);
        assert_eq!(
            region.nodes[0].stun_addr(),
            Some(("127.0.0.1".into(), 3479))
        );
    }
}
