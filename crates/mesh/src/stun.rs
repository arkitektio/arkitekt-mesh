//! STUN binding requests, as Tailscale sends them (RFC 5389 with
//! `SOFTWARE=tailnode` and a `FINGERPRINT`), and parsing the reply.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const BINDING_REQUEST: [u8; 2] = [0x00, 0x01];
const BINDING_SUCCESS: [u8; 2] = [0x01, 0x01];
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_XOR_MAPPED_ADDRESS_ALT: u16 = 0x8020;
const FINGERPRINT_XOR: u32 = 0x5354_554e;

pub type TxId = [u8; 12];

/// The 40-byte binding request.
pub fn request(tx: &TxId) -> Vec<u8> {
    let mut b = Vec::with_capacity(48);
    b.extend_from_slice(&BINDING_REQUEST);
    b.extend_from_slice(&20u16.to_be_bytes());
    b.extend_from_slice(&MAGIC_COOKIE);
    b.extend_from_slice(tx);
    b.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    b.extend_from_slice(&8u16.to_be_bytes());
    b.extend_from_slice(b"tailnode");
    let crc = crc32(&b) ^ FINGERPRINT_XOR;
    b.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    b.extend_from_slice(&4u16.to_be_bytes());
    b.extend_from_slice(&crc.to_be_bytes());
    b
}

/// Whether `packet` is a STUN message (as opposed to WireGuard or disco).
pub fn is_stun(packet: &[u8]) -> bool {
    packet.len() >= 20 && packet[0] & 0xc0 == 0 && packet[4..8] == MAGIC_COOKIE
}

/// The transaction id of a STUN message.
pub fn transaction(packet: &[u8]) -> Option<TxId> {
    is_stun(packet).then(|| packet[8..20].try_into().expect("12"))
}

/// Parse a binding success: `(transaction, our address as the server saw it)`.
pub fn parse_response(packet: &[u8]) -> Option<(TxId, SocketAddr)> {
    if !is_stun(packet) || packet[..2] != BINDING_SUCCESS {
        return None;
    }
    let tx: TxId = packet[8..20].try_into().ok()?;
    let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let mut attrs = packet.get(20..20 + len)?;
    let (mut xor, mut plain) = (None, None);
    while attrs.len() >= 4 {
        let kind = u16::from_be_bytes([attrs[0], attrs[1]]);
        let alen = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        let value = attrs.get(4..4 + alen)?;
        match kind {
            ATTR_XOR_MAPPED_ADDRESS | ATTR_XOR_MAPPED_ADDRESS_ALT => {
                xor = xor.or(address(value, Some(&tx)))
            }
            ATTR_MAPPED_ADDRESS => plain = plain.or(address(value, None)),
            _ => {}
        }
        let padded = (4 + alen + 3) & !3;
        attrs = attrs.get(padded.min(attrs.len())..)?;
    }
    Some((tx, xor.or(plain)?))
}

fn address(v: &[u8], xor_tx: Option<&TxId>) -> Option<SocketAddr> {
    let family = *v.get(1)?;
    let mut port = u16::from_be_bytes(v.get(2..4)?.try_into().ok()?);
    let mut key = MAGIC_COOKIE.to_vec();
    if let Some(tx) = xor_tx {
        key.extend_from_slice(tx);
        port ^= 0x2112;
    }
    let mut ip = v.get(4..)?.to_vec();
    if xor_tx.is_some() {
        for (b, k) in ip.iter_mut().zip(key.iter()) {
            *b ^= k;
        }
    }
    let ip = match (family, ip.len()) {
        (1, 4) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(ip).ok()?)),
        (2, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip).ok()?)),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// CRC-32 (IEEE), as STUN's FINGERPRINT uses.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn request_layout() {
        let r = request(&[7; 12]);
        assert_eq!(r.len(), 40);
        assert!(is_stun(&r));
        assert_eq!(&r[24..32], b"tailnode");
    }

    /// A response like tailscale's stun server writes: one XOR-MAPPED-ADDRESS.
    fn response(tx: &TxId, addr: SocketAddr) -> Vec<u8> {
        let mut attr = vec![0];
        let mut key = MAGIC_COOKIE.to_vec();
        key.extend_from_slice(tx);
        let ip: Vec<u8> = match addr.ip() {
            IpAddr::V4(v4) => {
                attr.push(1);
                v4.octets().to_vec()
            }
            IpAddr::V6(v6) => {
                attr.push(2);
                v6.octets().to_vec()
            }
        };
        attr.extend_from_slice(&(addr.port() ^ 0x2112).to_be_bytes());
        attr.extend(ip.iter().zip(key.iter()).map(|(b, k)| b ^ k));
        let mut r = BINDING_SUCCESS.to_vec();
        r.extend_from_slice(&((4 + attr.len()) as u16).to_be_bytes());
        r.extend_from_slice(&MAGIC_COOKIE);
        r.extend_from_slice(tx);
        r.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        r.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        r.extend_from_slice(&attr);
        r
    }

    #[test]
    fn parses_xor_mapped_addresses() {
        for addr in ["203.0.113.9:41641", "[2001:db8::7]:1234"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let tx = [9; 12];
            assert_eq!(parse_response(&response(&tx, addr)), Some((tx, addr)));
        }
    }
}
