//! Tailscale's control Noise (`controlbase`), sans-IO:
//! `Noise_IK_25519_ChaChaPoly_BLAKE2s` from the machine key to the control
//! server's key, then records of `0x04 ‖ u16 BE length ‖ ciphertext` with a
//! big-endian nonce counter.

use crate::crypto::{self, hash, hkdf, NonceOrder, HASH_LEN, TAG_LEN};
use crate::keys::{MachinePublic, PrivateKey, PublicKey};

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const TYPE_INITIATION: u8 = 1;
const TYPE_RESPONSE: u8 = 2;
const TYPE_ERROR: u8 = 3;
const TYPE_RECORD: u8 = 4;

pub const INITIATION_LEN: usize = 5 + 96;
pub const RESPONSE_LEN: usize = 3 + 48;
/// A record, header included, is at most this long.
pub const MAX_MESSAGE: usize = 4096;
const MAX_PLAINTEXT: usize = MAX_MESSAGE - 3 - TAG_LEN;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoiseError {
    #[error("the control server refused the handshake: {0}")]
    Refused(String),
    #[error("malformed control handshake or record")]
    Malformed,
    #[error("control handshake or record failed authentication")]
    Crypto,
}

impl From<crypto::CryptoError> for NoiseError {
    fn from(_: crypto::CryptoError) -> Self {
        NoiseError::Crypto
    }
}

/// The client half of the handshake, waiting for the server's response.
pub struct ClientHandshake {
    machine: PrivateKey,
    ephemeral: PrivateKey,
    h: [u8; HASH_LEN],
    ck: [u8; HASH_LEN],
}

impl ClientHandshake {
    /// Start a handshake; returns the 101-byte initiation to send.
    pub fn start(
        machine: &PrivateKey,
        control: &MachinePublic,
        version: u16,
    ) -> Result<(Self, Vec<u8>), NoiseError> {
        let control = control.0;
        let mut h = hash(&[PROTOCOL_NAME]);
        let mut ck = h;
        let prologue = format!("Tailscale Control Protocol v{version}");
        h = hash(&[&h, prologue.as_bytes()]);
        h = hash(&[&h, &control.0]);

        let ephemeral = PrivateKey::generate();
        let e_pub = ephemeral.public();
        h = hash(&[&h, &e_pub.0]);

        let mut msg = Vec::with_capacity(INITIATION_LEN);
        msg.extend_from_slice(&version.to_be_bytes());
        msg.push(TYPE_INITIATION);
        msg.extend_from_slice(&96u16.to_be_bytes());
        msg.extend_from_slice(&e_pub.0);

        // es
        let [ck2, k] = hkdf::<2>(&ck, &crypto::dh(&ephemeral, &control)?);
        ck = ck2;
        let mut machine_pub = machine.public().0.to_vec();
        crypto::seal(&k, 0, NonceOrder::Big, &h, &mut machine_pub);
        h = hash(&[&h, &machine_pub]);
        msg.extend_from_slice(&machine_pub);

        // ss
        let [ck3, k] = hkdf::<2>(&ck, &crypto::dh(machine, &control)?);
        ck = ck3;
        let mut tag = Vec::new();
        crypto::seal(&k, 0, NonceOrder::Big, &h, &mut tag);
        h = hash(&[&h, &tag]);
        msg.extend_from_slice(&tag);

        Ok((
            Self {
                machine: machine.clone(),
                ephemeral,
                h,
                ck,
            },
            msg,
        ))
    }

    /// Bytes needed before [`finish`](Self::finish) can run: the 3-byte
    /// header, then the length it announces.
    pub fn response_len(header: &[u8; 3]) -> usize {
        3 + u16::from_be_bytes([header[1], header[2]]) as usize
    }

    /// Complete the handshake with the server's response.
    pub fn finish(self, response: &[u8]) -> Result<Transport, NoiseError> {
        if response.len() < 3 {
            return Err(NoiseError::Malformed);
        }
        let len = u16::from_be_bytes([response[1], response[2]]) as usize;
        let body = response.get(3..3 + len).ok_or(NoiseError::Malformed)?;
        match response[0] {
            TYPE_RESPONSE if len == 48 => {}
            TYPE_ERROR => {
                return Err(NoiseError::Refused(
                    String::from_utf8_lossy(body).into_owned(),
                ))
            }
            _ => return Err(NoiseError::Malformed),
        }
        let e_r = PublicKey(body[..32].try_into().expect("32"));
        let mut h = hash(&[&self.h, &e_r.0]);
        // ee: only the chaining key matters.
        let [ck, _] = hkdf::<2>(&self.ck, &crypto::dh(&self.ephemeral, &e_r)?);
        // se
        let [ck, k] = hkdf::<2>(&ck, &crypto::dh(&self.machine, &e_r)?);
        let mut tag = body[32..48].to_vec();
        crypto::open(&k, 0, NonceOrder::Big, &h, &mut tag)?;
        h = hash(&[&h, &body[32..48]]);
        let [tx, rx] = hkdf::<2>(&ck, &[]);
        Ok(Transport {
            tx,
            rx,
            tx_counter: 0,
            rx_counter: 0,
            handshake_hash: h,
        })
    }
}

/// The established connection's record layer.
pub struct Transport {
    tx: [u8; 32],
    rx: [u8; 32],
    tx_counter: u64,
    rx_counter: u64,
    pub handshake_hash: [u8; HASH_LEN],
}

impl Transport {
    /// Encrypt `plaintext` into as many records as it takes.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut Vec<u8>) {
        for chunk in plaintext.chunks(MAX_PLAINTEXT) {
            let mut body = chunk.to_vec();
            crypto::seal(&self.tx, self.tx_counter, NonceOrder::Big, &[], &mut body);
            self.tx_counter += 1;
            out.push(TYPE_RECORD);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
            out.extend_from_slice(&body);
        }
    }

    /// Take one complete record off the front of `buf` and decrypt it.
    /// `Ok(None)` means more bytes are needed.
    pub fn open(&mut self, buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, NoiseError> {
        if buf.len() < 3 {
            return Ok(None);
        }
        if buf[0] != TYPE_RECORD {
            return Err(NoiseError::Malformed);
        }
        let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if 3 + len > MAX_MESSAGE {
            return Err(NoiseError::Malformed);
        }
        if buf.len() < 3 + len {
            return Ok(None);
        }
        let mut body: Vec<u8> = buf[3..3 + len].to_vec();
        buf.drain(..3 + len);
        let counter = self.rx_counter;
        self.rx_counter += 1;
        crypto::open(&self.rx, counter, NonceOrder::Big, &[], &mut body)?;
        Ok(Some(body))
    }
}

/// The server's optional first message: `FF FF FF 'T' 'S' ‖ u32 BE len ‖ JSON`.
pub const EARLY_PAYLOAD_MAGIC: &[u8; 5] = b"\xff\xff\xffTS";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The server half, only for tests: enough to check both sides agree.
    pub(crate) fn server_respond(
        control: &PrivateKey,
        init: &[u8],
    ) -> (Transport, Vec<u8>, PublicKey) {
        let version = u16::from_be_bytes([init[0], init[1]]);
        assert_eq!(init[2], TYPE_INITIATION);
        let mut h = hash(&[PROTOCOL_NAME]);
        let mut ck = h;
        h = hash(&[
            &h,
            format!("Tailscale Control Protocol v{version}").as_bytes(),
        ]);
        h = hash(&[&h, &control.public().0]);
        let e_i = PublicKey(init[5..37].try_into().unwrap());
        h = hash(&[&h, &e_i.0]);
        let [ck2, k] = hkdf::<2>(&ck, &crypto::dh(control, &e_i).unwrap());
        ck = ck2;
        let mut machine = init[37..85].to_vec();
        crypto::open(&k, 0, NonceOrder::Big, &h, &mut machine).unwrap();
        h = hash(&[&h, &init[37..85]]);
        let machine = PublicKey(machine.try_into().unwrap());
        let [ck3, k] = hkdf::<2>(&ck, &crypto::dh(control, &machine).unwrap());
        ck = ck3;
        let mut tag = init[85..101].to_vec();
        crypto::open(&k, 0, NonceOrder::Big, &h, &mut tag).unwrap();
        h = hash(&[&h, &init[85..101]]);

        let e_r = PrivateKey::generate();
        let mut resp = vec![TYPE_RESPONSE];
        resp.extend_from_slice(&48u16.to_be_bytes());
        resp.extend_from_slice(&e_r.public().0);
        h = hash(&[&h, &e_r.public().0]);
        let [ck4, _] = hkdf::<2>(&ck, &crypto::dh(&e_r, &e_i).unwrap());
        let [ck5, k] = hkdf::<2>(&ck4, &crypto::dh(&e_r, &machine).unwrap());
        let mut tag = Vec::new();
        crypto::seal(&k, 0, NonceOrder::Big, &h, &mut tag);
        resp.extend_from_slice(&tag);
        let [k1, k2] = hkdf::<2>(&ck5, &[]);
        (
            Transport {
                tx: k2,
                rx: k1,
                tx_counter: 0,
                rx_counter: 0,
                handshake_hash: h,
            },
            resp,
            machine,
        )
    }

    #[test]
    fn handshake_and_records() {
        let machine = PrivateKey::generate();
        let control = PrivateKey::generate();
        let (client, init) =
            ClientHandshake::start(&machine, &MachinePublic(control.public()), 142).unwrap();
        assert_eq!(init.len(), INITIATION_LEN);
        assert_eq!(&init[..5], &[0, 142, 1, 0, 96]);

        let (mut server, resp, seen_machine) = server_respond(&control, &init);
        assert_eq!(seen_machine, machine.public());
        assert_eq!(resp.len(), RESPONSE_LEN);
        let mut client = client.finish(&resp).unwrap();

        // Large writes are chunked into records of at most 4096 bytes.
        let big = vec![7u8; 10_000];
        let mut wire = Vec::new();
        client.seal(&big, &mut wire);
        assert!(wire.len() > big.len());
        let mut got = Vec::new();
        while let Some(chunk) = server.open(&mut wire).unwrap() {
            got.extend(chunk);
        }
        assert_eq!(got, big);

        let mut wire = Vec::new();
        server.seal(b"pong", &mut wire);
        wire.truncate(wire.len() - 1);
        let mut partial = wire.clone();
        assert_eq!(client.open(&mut partial).unwrap(), None);
    }

    #[test]
    fn error_frames_surface_their_message() {
        let machine = PrivateKey::generate();
        let control = PrivateKey::generate();
        let (client, _) =
            ClientHandshake::start(&machine, &MachinePublic(control.public()), 142).unwrap();
        let mut err = vec![TYPE_ERROR, 0, 4];
        err.extend_from_slice(b"nope");
        assert_eq!(
            client.finish(&err).err(),
            Some(NoiseError::Refused("nope".into()))
        );
    }
}
