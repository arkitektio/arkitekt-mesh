//! The Geneve header (RFC 8926, its fixed eight bytes) that wraps disco and
//! WireGuard on their way through a peer relay: the relay forwards by the
//! virtual network identifier (VNI) it handed both peers, without opening
//! what is inside.
//!
//! ```text
//! |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//! |        Virtual Network Identifier (VNI)       |    Reserved   |
//! ```

#[allow(unused_imports)]
use crate::prelude::*;

pub const HEADER_LEN: usize = 8;
/// The protocol types tailscale took for what it sends through a relay.
const PROTOCOL_DISCO: u16 = 0x7a11;
const PROTOCOL_WIREGUARD: u16 = 0x7a12;
/// A VNI is 24 bits.
pub const VNI_MAX: u32 = 0x00ff_ffff;

/// What a Geneve datagram carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Disco,
    WireGuard,
}

/// A Geneve header as this client reads and writes it: version 0, no options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub protocol: Protocol,
    pub vni: u32,
    /// The control bit: set on the messages of the bind handshake with the
    /// relay itself, which it must not forward.
    pub control: bool,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let protocol = match self.protocol {
            Protocol::Disco => PROTOCOL_DISCO,
            Protocol::WireGuard => PROTOCOL_WIREGUARD,
        };
        let mut out = [0u8; HEADER_LEN];
        if self.control {
            out[1] = 0x80;
        }
        out[2..4].copy_from_slice(&protocol.to_be_bytes());
        out[4..8].copy_from_slice(&((self.vni & VNI_MAX) << 8).to_be_bytes());
        out
    }

    /// `payload` behind this header.
    pub fn wrap(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(&self.encode());
        out.extend_from_slice(payload);
        out
    }
}

/// The header of `datagram` and what follows it, if it is one of ours:
/// version 0, no options, the reserved bits clear, disco or WireGuard inside.
///
/// Told apart from what else arrives on the socket as tailscale does: a
/// naked WireGuard message has zeros where the protocol type is, naked disco
/// its magic there, and a STUN binding a set bit among the reserved ones.
/// A header that says disco over something that is not is no Geneve.
pub fn unwrap(datagram: &[u8]) -> Option<(Header, &[u8])> {
    if datagram.len() < HEADER_LEN
        || datagram[0] != 0 // version 0, and no options to skip
        || datagram[1] & 0x3f != 0
        || datagram[7] != 0
    {
        return None;
    }
    let payload = &datagram[HEADER_LEN..];
    let protocol = match u16::from_be_bytes([datagram[2], datagram[3]]) {
        PROTOCOL_DISCO if crate::disco::looks_like_disco(payload) => Protocol::Disco,
        PROTOCOL_WIREGUARD => Protocol::WireGuard,
        _ => return None,
    };
    let vni = u32::from_be_bytes([0, datagram[4], datagram[5], datagram[6]]);
    Some((
        Header {
            protocol,
            vni,
            control: datagram[1] & 0x80 != 0,
        },
        payload,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tailscale's own encoding (tests/harness/vectors_test.go).
    #[test]
    fn headers_are_tailscale_s() {
        let header = |protocol, vni, control| Header {
            protocol,
            vni,
            control,
        };
        let disco = header(Protocol::Disco, 0x00ab_cdef, false);
        assert_eq!(hex::encode(disco.encode()), "00007a11abcdef00");
        let control = header(Protocol::Disco, 0x00ab_cdef, true);
        assert_eq!(hex::encode(control.encode()), "00807a11abcdef00");
        let wireguard = header(Protocol::WireGuard, 1, false);
        assert_eq!(hex::encode(wireguard.encode()), "00007a1200000100");

        assert_eq!(
            unwrap(&wireguard.wrap(&[4, 0, 0, 0, 9])),
            Some((wireguard, &[4u8, 0, 0, 0, 9][..]))
        );
    }

    /// What else the socket sees is not taken for Geneve, and Geneve not
    /// for it.
    #[test]
    fn told_apart_from_naked_packets() {
        // WireGuard: zeros where the protocol type would be.
        assert_eq!(unwrap(&[4, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]), None);
        assert_eq!(unwrap(&[1, 0, 0, 0, 0, 0, 0, 0, 0]), None);
        // Disco: its magic there.
        let mut disco = crate::disco::MAGIC.to_vec();
        disco.resize(80, 0);
        assert_eq!(unwrap(&disco), None);
        // A STUN binding request: a set bit among the reserved ones.
        let stun = crate::stun::request(&[7; 12]);
        assert_eq!(unwrap(&stun), None);
        // Options we do not read, a version we do not know, a short one.
        assert_eq!(unwrap(&[0x01, 0, 0x7a, 0x12, 0, 0, 1, 0, 9]), None);
        assert_eq!(unwrap(&[0x40, 0, 0x7a, 0x12, 0, 0, 1, 0, 9]), None);
        assert_eq!(unwrap(&[0, 0, 0x7a, 0x12, 0, 0, 1]), None);
        // Disco announced, something else inside.
        assert_eq!(unwrap(&[0, 0, 0x7a, 0x11, 0, 0, 1, 0, 9, 9, 9]), None);

        // And the other way: a wrapped WireGuard message is neither naked
        // WireGuard nor disco nor STUN.
        let wrapped = Header {
            protocol: Protocol::WireGuard,
            vni: 0x2112a4, // the bytes of STUN's magic cookie, as far as they fit
            control: false,
        }
        .wrap(&[4, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!crate::wg::is_wireguard(&wrapped));
        assert!(!crate::disco::looks_like_disco(&wrapped));
        assert!(!crate::stun::is_stun(&wrapped));
    }
}
