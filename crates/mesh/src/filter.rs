//! The tailnet's ACLs, enforced on inbound packets (docs/rfc8-packet-filter.md).
//!
//! Control sends each node a packet filter: rules saying which sources may
//! reach which of our ports over which protocols. Like tailscaled, we check
//! what *opens* a flow and let the rest of it through:
//! - **TCP:** a SYN (without ACK) needs a rule. Other segments pass, because a
//!   connection cannot exist without an allowed SYN; our own dials' SYN-ACKs
//!   are not SYNs.
//! - **UDP:** a datagram needs a rule, unless it answers a flow we started
//!   (a small table of recent outbound flows).
//! - **ICMP:** echo requests need a rule; replies and errors pass.
//! - **Anything else** needs a rule for its protocol.
//!
//! Sans-IO like the rest of the core: packets and time in, a verdict out.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Deserialize;

/// How long a UDP flow we started keeps its replies allowed.
const UDP_FLOW_TIMEOUT: Duration = Duration::from_secs(120);

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP4: u8 = 1;
const ICMP6: u8 = 58;
const SCTP: u8 = 132;

/// One rule, as control sends it (`tailcfg.FilterRule`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FilterRule {
    #[serde(rename = "SrcIPs")]
    pub src_ips: Vec<String>,
    #[serde(rename = "DstPorts")]
    pub dst_ports: Vec<NetPortRange>,
    /// IP protocol numbers; empty means TCP, UDP and ICMP.
    #[serde(rename = "IPProto")]
    pub ip_proto: Vec<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NetPortRange {
    #[serde(rename = "IP")]
    pub ip: String,
    #[serde(rename = "Ports")]
    pub ports: PortRange,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct PortRange {
    #[serde(rename = "First")]
    pub first: u16,
    #[serde(rename = "Last")]
    pub last: u16,
}

impl Default for PortRange {
    fn default() -> Self {
        Self {
            first: 0,
            last: u16::MAX,
        }
    }
}

/// A set of addresses: `*`, an address, a CIDR prefix, or a range `a-b`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Addrs {
    Any,
    Prefix(IpAddr, u8),
    Range(IpAddr, IpAddr),
}

impl Addrs {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw == "*" {
            return Some(Self::Any);
        }
        if let Some((a, b)) = raw.split_once('-') {
            let (a, b): (IpAddr, IpAddr) = (a.parse().ok()?, b.parse().ok()?);
            return (a.is_ipv4() == b.is_ipv4()).then_some(Self::Range(a, b));
        }
        let (ip, bits) = match raw.split_once('/') {
            Some((ip, bits)) => (ip.parse::<IpAddr>().ok()?, bits.parse::<u8>().ok()?),
            None => {
                let ip: IpAddr = raw.parse().ok()?;
                (ip, if ip.is_ipv4() { 32 } else { 128 })
            }
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        (bits <= max).then_some(Self::Prefix(ip, bits))
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match *self {
            Self::Any => true,
            Self::Prefix(net, bits) => prefix_contains(net, bits, ip),
            Self::Range(a, b) => match (a, b, ip) {
                (IpAddr::V4(a), IpAddr::V4(b), IpAddr::V4(ip)) => (a..=b).contains(&ip),
                (IpAddr::V6(a), IpAddr::V6(b), IpAddr::V6(ip)) => (a..=b).contains(&ip),
                _ => false,
            },
        }
    }
}

fn prefix_contains(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = u32::MAX.checked_shl(32 - bits as u32).unwrap_or(0);
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = u128::MAX.checked_shl(128 - bits as u32).unwrap_or(0);
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

#[derive(Debug, Clone)]
struct Rule {
    sources: Vec<Addrs>,
    dests: Vec<(Addrs, u16, u16)>,
    protos: Vec<u8>,
}

/// The rules control sent, compiled for matching.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    rules: Vec<Rule>,
}

impl Filter {
    /// Compile control's rules; entries that do not parse are skipped.
    pub fn new(rules: &[FilterRule]) -> Self {
        let rules = rules
            .iter()
            .map(|r| Rule {
                sources: r.src_ips.iter().filter_map(|s| Addrs::parse(s)).collect(),
                dests: r
                    .dst_ports
                    .iter()
                    .filter_map(|d| Some((Addrs::parse(&d.ip)?, d.ports.first, d.ports.last)))
                    .collect(),
                protos: if r.ip_proto.is_empty() {
                    vec![TCP, UDP, ICMP4, ICMP6]
                } else {
                    r.ip_proto
                        .iter()
                        .filter_map(|&p| u8::try_from(p).ok())
                        .collect()
                },
            })
            .filter(|r| !r.sources.is_empty() && !r.dests.is_empty())
            .collect();
        Self { rules }
    }

    /// Whether a packet opening a flow from `src` to `dst:port` over `proto`
    /// is allowed (`port` is ignored for protocols without ports).
    pub fn allows(&self, src: IpAddr, dst: IpAddr, proto: u8, port: Option<u16>) -> bool {
        self.rules.iter().any(|rule| {
            rule.protos.contains(&proto)
                && rule.sources.iter().any(|s| s.contains(src))
                && rule.dests.iter().any(|&(ref d, first, last)| {
                    d.contains(dst) && port.is_none_or(|p| (first..=last).contains(&p))
                })
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// The rules in force, by name, as map responses update them: `PacketFilter`
/// (the whole set) or `PacketFilters` (named sets; `"*": null` clears all).
/// `None` means unchanged. Returns whether anything changed.
pub fn apply_update(
    sets: &mut std::collections::BTreeMap<String, Vec<FilterRule>>,
    whole: Option<Vec<FilterRule>>,
    named: Option<std::collections::BTreeMap<String, Option<Vec<FilterRule>>>>,
) -> bool {
    let mut changed = false;
    if let Some(rules) = whole {
        sets.clear();
        sets.insert("base".into(), rules);
        changed = true;
    }
    if let Some(named) = named {
        if matches!(named.get("*"), Some(None)) {
            sets.clear();
        }
        for (name, rules) in named {
            match rules {
                Some(rules) => {
                    sets.insert(name, rules);
                }
                None => {
                    sets.remove(&name);
                }
            }
        }
        changed = true;
    }
    changed
}

/// Compile every named set into one filter.
pub fn compile(sets: &std::collections::BTreeMap<String, Vec<FilterRule>>) -> Filter {
    let all: Vec<FilterRule> = sets.values().flatten().cloned().collect();
    Filter::new(&all)
}

/// What an IP packet says about its flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Flow {
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    /// TCP: SYN without ACK. ICMP: an echo request.
    opens: bool,
}

fn parse(packet: &[u8]) -> Option<Flow> {
    let (proto, src, dst, l4) = match packet.first()? >> 4 {
        4 => {
            let ihl = ((packet.first()? & 0x0f) as usize) * 4;
            if packet.len() < 20 || ihl < 20 {
                return None;
            }
            let src = IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?);
            let dst = IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?);
            // A later fragment carries no transport header: judge it by the
            // first (which smoltcp would need anyway to reassemble).
            let fragment_offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff;
            if fragment_offset != 0 {
                return Some(Flow {
                    proto: packet[9],
                    src,
                    dst,
                    src_port: 0,
                    dst_port: 0,
                    opens: false,
                });
            }
            (packet[9], src, dst, packet.get(ihl..)?)
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let src = IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
            let dst = IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
            // Extension headers are not followed: their next-header chains
            // are rare on a tailnet, and an unknown protocol needs a rule.
            (packet[6], src, dst, &packet[40..])
        }
        _ => return None,
    };
    let ports = |l4: &[u8]| -> Option<(u16, u16)> {
        Some((
            u16::from_be_bytes([*l4.first()?, *l4.get(1)?]),
            u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]),
        ))
    };
    let (src_port, dst_port, opens) = match proto {
        TCP => {
            let (s, d) = ports(l4)?;
            let flags = *l4.get(13)?;
            (s, d, flags & 0x02 != 0 && flags & 0x10 == 0)
        }
        UDP | SCTP => {
            let (s, d) = ports(l4)?;
            (s, d, true)
        }
        ICMP4 => (0, 0, *l4.first()? == 8),
        ICMP6 => (0, 0, *l4.first()? == 128),
        _ => (0, 0, true),
    };
    Some(Flow {
        proto,
        src,
        dst,
        src_port,
        dst_port,
        opens,
    })
}

/// The filter, plus the UDP flows we started (whose replies need no rule).
#[derive(Debug)]
pub struct Firewall {
    filter: Filter,
    /// Keyed as the reply will look: (their addr, their port, our addr, our port).
    udp_flows: HashMap<(IpAddr, u16, IpAddr, u16), Instant>,
    max_flows: usize,
    dropped: u64,
}

impl Firewall {
    /// Deny every new inbound flow until control sends a filter, as
    /// tailscaled does; `max_flows` caps the UDP flow table.
    pub fn new(max_flows: usize) -> Self {
        Self {
            filter: Filter::default(),
            udp_flows: HashMap::new(),
            max_flows: max_flows.max(1),
            dropped: 0,
        }
    }

    pub fn set_filter(&mut self, filter: Filter) {
        self.filter = filter;
    }

    /// Packets dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Note a packet we send: a UDP datagram allows its replies for a while.
    pub fn outbound(&mut self, packet: &[u8], now: Instant) {
        let Some(flow) = parse(packet) else { return };
        if flow.proto != UDP {
            return;
        }
        let key = (flow.dst, flow.dst_port, flow.src, flow.src_port);
        if !self.udp_flows.contains_key(&key) && self.udp_flows.len() >= self.max_flows {
            self.expire(now);
            if self.udp_flows.len() >= self.max_flows {
                // Still full: forget the oldest flow.
                if let Some(oldest) = self
                    .udp_flows
                    .iter()
                    .min_by_key(|(_, t)| **t)
                    .map(|(k, _)| *k)
                {
                    self.udp_flows.remove(&oldest);
                }
            }
        }
        self.udp_flows.insert(key, now);
    }

    /// Whether an inbound packet may reach the netstack.
    pub fn inbound(&mut self, packet: &[u8], now: Instant) -> bool {
        let allowed = match parse(packet) {
            None => false,
            Some(flow) if !flow.opens => true,
            Some(flow) => {
                let port = matches!(flow.proto, TCP | UDP | SCTP).then_some(flow.dst_port);
                self.filter.allows(flow.src, flow.dst, flow.proto, port)
                    || (flow.proto == UDP
                        && self
                            .udp_flows
                            .get(&(flow.src, flow.src_port, flow.dst, flow.dst_port))
                            .is_some_and(|&t| now.duration_since(t) < UDP_FLOW_TIMEOUT))
            }
        };
        if !allowed {
            self.dropped += 1;
        }
        allowed
    }

    fn expire(&mut self, now: Instant) {
        self.udp_flows
            .retain(|_, &mut t| now.duration_since(t) < UDP_FLOW_TIMEOUT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: [u8; 4] = [100, 64, 0, 1];
    const HUB: [u8; 4] = [100, 64, 0, 9];
    const APP: [u8; 4] = [100, 64, 0, 2];

    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(l4);
        p
    }

    fn tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut l4 = vec![0u8; 20];
        l4[..2].copy_from_slice(&sport.to_be_bytes());
        l4[2..4].copy_from_slice(&dport.to_be_bytes());
        l4[13] = flags;
        ipv4(TCP, src, dst, &l4)
    }

    fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut l4 = vec![0u8; 8];
        l4[..2].copy_from_slice(&sport.to_be_bytes());
        l4[2..4].copy_from_slice(&dport.to_be_bytes());
        ipv4(UDP, src, dst, &l4)
    }

    fn rules(json: &str) -> Filter {
        Filter::new(&serde_json::from_str::<Vec<FilterRule>>(json).unwrap())
    }

    const SYN: u8 = 0x02;
    const SYN_ACK: u8 = 0x12;
    const ACK: u8 = 0x10;

    #[test]
    fn addresses_parse_like_tailcfg() {
        assert!(Addrs::parse("*")
            .unwrap()
            .contains("100.1.2.3".parse().unwrap()));
        let net = Addrs::parse("100.64.0.0/10").unwrap();
        assert!(net.contains("100.127.255.255".parse().unwrap()));
        assert!(!net.contains("100.128.0.0".parse().unwrap()));
        let one = Addrs::parse("100.64.0.9").unwrap();
        assert!(one.contains("100.64.0.9".parse().unwrap()));
        assert!(!one.contains("100.64.0.8".parse().unwrap()));
        let range = Addrs::parse("100.64.0.5-100.64.0.7").unwrap();
        assert!(range.contains("100.64.0.6".parse().unwrap()));
        assert!(!range.contains("100.64.0.8".parse().unwrap()));
        assert!(Addrs::parse("fd7a:115c:a1e0::/48")
            .unwrap()
            .contains("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(Addrs::parse("100.64.0.0/33").is_none());
        assert!(Addrs::parse("nonsense").is_none());
    }

    #[test]
    fn only_allowed_sources_open_tcp_connections() {
        // lok's shape: the app may reach the hub, the hub never initiates.
        let mut fw = Firewall::new(16);
        fw.set_filter(rules(r#"[{"SrcIPs": ["100.64.0.2"], "DstPorts": [{"IP": "100.64.0.1", "Ports": {"First": 80, "Last": 80}}]}]"#));
        let now = Instant::now();
        assert!(fw.inbound(&tcp(APP, ME, 40000, 80, SYN), now));
        assert!(
            !fw.inbound(&tcp(APP, ME, 40000, 81, SYN), now),
            "wrong port"
        );
        assert!(
            !fw.inbound(&tcp(HUB, ME, 40000, 80, SYN), now),
            "wrong source"
        );
        // The rest of a connection passes; so do replies to our own dials.
        assert!(fw.inbound(&tcp(HUB, ME, 443, 50000, SYN_ACK), now));
        assert!(fw.inbound(&tcp(HUB, ME, 443, 50000, ACK), now));
        assert_eq!(fw.dropped(), 2);
    }

    #[test]
    fn udp_needs_a_rule_or_a_flow_we_started() {
        let mut fw = Firewall::new(16);
        let now = Instant::now();
        // No filter yet: nothing new comes in.
        assert!(!fw.inbound(&udp(HUB, ME, 7882, 5000), now));
        // We send to the hub from :5000; its replies are let in.
        fw.outbound(&udp(ME, HUB, 5000, 7882), now);
        assert!(fw.inbound(&udp(HUB, ME, 7882, 5000), now));
        assert!(
            !fw.inbound(&udp(HUB, ME, 7883, 5000), now),
            "another port of theirs"
        );
        assert!(!fw.inbound(&udp(APP, ME, 7882, 5000), now), "someone else");
        // ... until the flow goes quiet.
        assert!(!fw.inbound(&udp(HUB, ME, 7882, 5000), now + UDP_FLOW_TIMEOUT));
        // A rule allows it outright.
        fw.set_filter(rules(r#"[{"SrcIPs": ["*"], "DstPorts": [{"IP": "*", "Ports": {"First": 0, "Last": 65535}}], "IPProto": [17]}]"#));
        assert!(fw.inbound(&udp(APP, ME, 1, 2), now));
        assert!(
            !fw.inbound(&tcp(APP, ME, 1, 2, SYN), now),
            "the rule is UDP only"
        );
    }

    #[test]
    fn the_flow_table_is_bounded() {
        let mut fw = Firewall::new(2);
        let now = Instant::now();
        for port in 1..=3 {
            fw.outbound(
                &udp(ME, HUB, port, 7882),
                now + Duration::from_secs(port as u64),
            );
        }
        assert_eq!(fw.udp_flows.len(), 2);
        // The oldest (port 1) was forgotten.
        assert!(!fw.inbound(&udp(HUB, ME, 7882, 1), now + Duration::from_secs(4)));
        assert!(fw.inbound(&udp(HUB, ME, 7882, 3), now + Duration::from_secs(4)));
    }

    #[test]
    fn icmp_echo_needs_a_rule_but_replies_pass() {
        let mut fw = Firewall::new(4);
        let now = Instant::now();
        assert!(
            !fw.inbound(&ipv4(ICMP4, HUB, ME, &[8, 0, 0, 0]), now),
            "echo request"
        );
        assert!(
            fw.inbound(&ipv4(ICMP4, HUB, ME, &[0, 0, 0, 0]), now),
            "echo reply"
        );
        fw.set_filter(rules(
            r#"[{"SrcIPs": ["*"], "DstPorts": [{"IP": "*", "Ports": {"First": 0, "Last": 0}}]}]"#,
        ));
        assert!(
            fw.inbound(&ipv4(ICMP4, HUB, ME, &[8, 0, 0, 0]), now),
            "default protos include ICMP"
        );
    }

    #[test]
    fn named_sets_update_and_clear() {
        use std::collections::BTreeMap;
        let rule = |ip: &str| FilterRule {
            src_ips: vec![ip.into()],
            dst_ports: vec![NetPortRange {
                ip: "*".into(),
                ports: PortRange::default(),
            }],
            ip_proto: vec![],
        };
        let mut sets = BTreeMap::new();
        assert!(
            !apply_update(&mut sets, None, None),
            "nothing sent: unchanged"
        );
        apply_update(&mut sets, Some(vec![rule("100.64.0.2")]), None);
        let me = "100.64.0.1".parse().unwrap();
        assert!(compile(&sets).allows("100.64.0.2".parse().unwrap(), me, TCP, Some(80)));
        apply_update(
            &mut sets,
            None,
            Some(BTreeMap::from([(
                "extra".into(),
                Some(vec![rule("100.64.0.3")]),
            )])),
        );
        let f = compile(&sets);
        assert!(f.allows("100.64.0.2".parse().unwrap(), me, TCP, Some(80)));
        assert!(f.allows("100.64.0.3".parse().unwrap(), me, TCP, Some(80)));
        apply_update(&mut sets, None, Some(BTreeMap::from([("*".into(), None)])));
        assert!(compile(&sets).is_empty(), "\"*\": null clears everything");
    }

    #[test]
    fn garbage_is_dropped() {
        let mut fw = Firewall::new(4);
        assert!(!fw.inbound(&[0x45, 0], Instant::now()));
        assert!(!fw.inbound(&[], Instant::now()));
    }
}
