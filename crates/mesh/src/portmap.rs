//! NAT port mapping (docs/rfc3-nat-port-mapping.md): asking the gateway to
//! forward a public port to our UDP socket, so peers behind hard NATs can
//! still reach us directly. Two small UDP protocols, both on port 5351:
//! - **PCP** (RFC 6887), `MAP` requests;
//! - **NAT-PMP** (RFC 6886), its predecessor, which many gateways still speak.
//!
//! Sans-IO: requests to send, responses parsed. UPnP IGD is not done.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The port both protocols listen on.
pub const PORT: u16 = 5351;
/// What we ask for, in seconds (renewed at half).
pub const LIFETIME: u32 = 7200;

const UDP: u8 = 17;

/// A mapping the gateway granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub external: SocketAddr,
    /// Seconds it lasts.
    pub lifetime: u32,
    /// The gateway's epoch: seconds since its mapping table was last reset.
    /// Going backwards means it rebooted and forgot our mapping.
    pub epoch: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortmapError {
    #[error("malformed response")]
    Malformed,
    #[error("the gateway refused (result code {0})")]
    Refused(u16),
    #[error("a response to another request")]
    Mismatch,
}

// --- NAT-PMP (RFC 6886) -----------------------------------------------------

/// Ask for the gateway's public address (opcode 0).
pub fn natpmp_external_address_request() -> [u8; 2] {
    [0, 0]
}

/// Parse the public address response (opcode 128). Returns it and the epoch.
pub fn natpmp_parse_external_address(resp: &[u8]) -> Result<(Ipv4Addr, u32), PortmapError> {
    if resp.len() < 12 || resp[0] != 0 || resp[1] != 128 {
        return Err(PortmapError::Malformed);
    }
    let result = u16::from_be_bytes([resp[2], resp[3]]);
    if result != 0 {
        return Err(PortmapError::Refused(result));
    }
    let epoch = u32::from_be_bytes(resp[4..8].try_into().unwrap());
    Ok((Ipv4Addr::new(resp[8], resp[9], resp[10], resp[11]), epoch))
}

/// Map UDP `internal_port` for `lifetime` seconds (0 deletes the mapping).
pub fn natpmp_map_request(internal_port: u16, suggested_external: u16, lifetime: u32) -> [u8; 12] {
    let mut req = [0u8; 12];
    req[1] = 1; // map UDP
    req[4..6].copy_from_slice(&internal_port.to_be_bytes());
    req[6..8].copy_from_slice(&suggested_external.to_be_bytes());
    req[8..12].copy_from_slice(&lifetime.to_be_bytes());
    req
}

/// Parse a UDP map response (opcode 129) for `internal_port`, completing it
/// with the public address from [`natpmp_parse_external_address`].
pub fn natpmp_parse_map(
    resp: &[u8],
    internal_port: u16,
    public: Ipv4Addr,
) -> Result<Mapping, PortmapError> {
    if resp.len() < 16 || resp[0] != 0 || resp[1] != 129 {
        return Err(PortmapError::Malformed);
    }
    let result = u16::from_be_bytes([resp[2], resp[3]]);
    if result != 0 {
        return Err(PortmapError::Refused(result));
    }
    if u16::from_be_bytes([resp[8], resp[9]]) != internal_port {
        return Err(PortmapError::Mismatch);
    }
    Ok(Mapping {
        epoch: u32::from_be_bytes(resp[4..8].try_into().unwrap()),
        external: SocketAddr::new(IpAddr::V4(public), u16::from_be_bytes([resp[10], resp[11]])),
        lifetime: u32::from_be_bytes(resp[12..16].try_into().unwrap()),
    })
}

// --- PCP (RFC 6887) ---------------------------------------------------------

fn mapped(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// A MAP request for UDP `internal_port` from `client` (our address toward
/// the gateway) for `lifetime` seconds (0 deletes it). `nonce` must match in
/// the response and in later renewals.
pub fn pcp_map_request(
    client: IpAddr,
    internal_port: u16,
    suggested_external: Option<SocketAddr>,
    lifetime: u32,
    nonce: &[u8; 12],
) -> [u8; 60] {
    let mut req = [0u8; 60];
    req[0] = 2; // version
    req[1] = 1; // request, MAP
    req[4..8].copy_from_slice(&lifetime.to_be_bytes());
    req[8..24].copy_from_slice(&mapped(client));
    // The MAP opcode's payload.
    req[24..36].copy_from_slice(nonce);
    req[36] = UDP;
    req[40..42].copy_from_slice(&internal_port.to_be_bytes());
    let (port, ip) = match suggested_external {
        Some(s) => (s.port(), mapped(s.ip())),
        // No preference: the IPv4 wildcard, as an IPv4-mapped address.
        None => (0, mapped(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
    };
    req[42..44].copy_from_slice(&port.to_be_bytes());
    req[44..60].copy_from_slice(&ip);
    req
}

/// Parse a MAP response to the request with `nonce` for `internal_port`.
pub fn pcp_parse_map(
    resp: &[u8],
    internal_port: u16,
    nonce: &[u8; 12],
) -> Result<Mapping, PortmapError> {
    if resp.len() < 60 || resp[0] != 2 || resp[1] != 0x81 {
        return Err(PortmapError::Malformed);
    }
    if resp[3] != 0 {
        return Err(PortmapError::Refused(resp[3] as u16));
    }
    if resp[24..36] != nonce[..]
        || resp[36] != UDP
        || u16::from_be_bytes([resp[40], resp[41]]) != internal_port
    {
        return Err(PortmapError::Mismatch);
    }
    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&resp[44..60]).unwrap());
    Ok(Mapping {
        lifetime: u32::from_be_bytes(resp[4..8].try_into().unwrap()),
        epoch: u32::from_be_bytes(resp[8..12].try_into().unwrap()),
        external: SocketAddr::new(ip.to_canonical(), u16::from_be_bytes([resp[42], resp[43]])),
    })
}

/// The default IPv4 gateway from Linux's routing table (`/proc/net/route`
/// text): the route to 0.0.0.0/0 with the gateway flag.
pub fn linux_default_gateway(route_table: &str) -> Option<Ipv4Addr> {
    route_table.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (dest, gateway, flags) = (f.get(1)?, f.get(2)?, f.get(3)?);
        let flags = u16::from_str_radix(flags, 16).ok()?;
        // RTF_UP | RTF_GATEWAY, to the default route.
        if *dest != "00000000" || flags & 0x3 != 0x3 {
            return None;
        }
        // Little-endian hex.
        Some(Ipv4Addr::from(
            u32::from_str_radix(gateway, 16).ok()?.swap_bytes(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natpmp_requests_and_responses_follow_rfc_6886() {
        assert_eq!(natpmp_external_address_request(), [0, 0]);
        assert_eq!(
            natpmp_map_request(41641, 0, 7200),
            [0, 1, 0, 0, 0xa2, 0xa9, 0, 0, 0, 0, 0x1c, 0x20]
        );
        let addr = [0, 128, 0, 0, 0, 0, 0, 42, 198, 51, 100, 7];
        assert_eq!(
            natpmp_parse_external_address(&addr),
            Ok((Ipv4Addr::new(198, 51, 100, 7), 42))
        );
        let map = [
            0, 129, 0, 0, 0, 0, 0, 43, 0xa2, 0xa9, 0xc3, 0x50, 0, 0, 0x0e, 0x10,
        ];
        let m = natpmp_parse_map(&map, 41641, Ipv4Addr::new(198, 51, 100, 7)).unwrap();
        assert_eq!(m.external, "198.51.100.7:50000".parse().unwrap());
        assert_eq!((m.lifetime, m.epoch), (3600, 43));
        // Another port's answer, and a refusal (3: network failure).
        assert_eq!(
            natpmp_parse_map(&map, 1, Ipv4Addr::LOCALHOST),
            Err(PortmapError::Mismatch)
        );
        let mut refused = map;
        refused[3] = 3;
        assert_eq!(
            natpmp_parse_map(&refused, 41641, Ipv4Addr::LOCALHOST),
            Err(PortmapError::Refused(3))
        );
        assert_eq!(
            natpmp_parse_map(&map[..8], 41641, Ipv4Addr::LOCALHOST),
            Err(PortmapError::Malformed)
        );
    }

    #[test]
    fn pcp_map_round_trips_rfc_6887_layout() {
        let nonce = [7u8; 12];
        let req = pcp_map_request("192.168.1.20".parse().unwrap(), 41641, None, 7200, &nonce);
        assert_eq!(&req[..2], &[2, 1]);
        assert_eq!(&req[4..8], &7200u32.to_be_bytes());
        assert_eq!(
            &req[8..24],
            &Ipv4Addr::new(192, 168, 1, 20).to_ipv6_mapped().octets()
        );
        assert_eq!(&req[24..36], &nonce);
        assert_eq!(req[36], 17);
        assert_eq!(&req[40..42], &41641u16.to_be_bytes());

        // The gateway's answer: the request, turned around.
        let mut resp = req;
        resp[1] = 0x81;
        resp[3] = 0; // success
        resp[8..12].copy_from_slice(&99u32.to_be_bytes()); // epoch
        resp[12..24].fill(0);
        resp[42..44].copy_from_slice(&50000u16.to_be_bytes());
        resp[44..60].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped().octets());
        let m = pcp_parse_map(&resp, 41641, &nonce).unwrap();
        assert_eq!(m.external, "198.51.100.7:50000".parse().unwrap());
        assert_eq!((m.lifetime, m.epoch), (7200, 99));

        assert_eq!(
            pcp_parse_map(&resp, 41641, &[8; 12]),
            Err(PortmapError::Mismatch),
            "nonce"
        );
        let mut refused = resp;
        refused[3] = 2; // NOT_AUTHORIZED
        assert_eq!(
            pcp_parse_map(&refused, 41641, &nonce),
            Err(PortmapError::Refused(2))
        );
    }

    #[test]
    fn the_default_gateway_comes_from_the_routing_table() {
        let table =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     enp3s0\t0050A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
                     enp3s0\t00000000\t0150A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(
            linux_default_gateway(table),
            Some(Ipv4Addr::new(192, 168, 80, 1))
        );
        assert_eq!(linux_default_gateway("Iface\tDestination\n"), None);
    }
}
