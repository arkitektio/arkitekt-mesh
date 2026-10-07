//! The userspace TCP/IP stack (smoltcp) that runs over the tunnel: IP
//! packets in and out, TCP sockets on top. Sans-IO like the rest of the core.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
#[cfg(feature = "udp")]
use smoltcp::socket::udp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

/// Tailscale's MTU for the tunnel.
pub const MTU: usize = 1280;
/// TCP buffer size, each way, per socket, unless set otherwise.
pub const TCP_BUFFER: usize = 64 * 1024;

/// How a TCP sender holds back when packets are lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Congestion {
    /// Send whatever the receiver's window takes: after a loss the whole
    /// window is sent again, into the queue that just overflowed.
    #[default]
    None,
    Reno,
    Cubic,
}

/// Datagrams queued each way per UDP socket.
#[cfg(feature = "udp")]
pub const UDP_PACKETS: usize = 64;
/// The largest UDP payload that fits the tunnel MTU (IPv6 header; there is
/// no fragmentation).
#[cfg(feature = "udp")]
pub const MAX_UDP_PAYLOAD: usize = MTU - 40 - 8;

/// The tailnet's address ranges; peers are on-link within them.
const CGNAT_PREFIX: u8 = 10;
const ULA_PREFIX: u8 = 48;

/// A TCP/IP stack with this node's tailnet addresses.
pub struct Netstack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: Queues,
    epoch: Instant,
    next_port: u16,
    tcp_buffer: usize,
    listen_buffer: usize,
    congestion: Congestion,
}

impl Netstack {
    pub fn new(addresses: &[IpAddr], now: Instant) -> Self {
        let mut device = Queues::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand_core::RngCore::next_u64(&mut rand_core::OsRng);
        let epoch = now;
        let mut iface = Interface::new(config, &mut device, smoltcp::time::Instant::ZERO);
        let mut stack = Self {
            iface: {
                iface.set_any_ip(false);
                iface
            },
            sockets: SocketSet::new(Vec::new()),
            device,
            epoch,
            next_port: 49152 + (rand_core::RngCore::next_u32(&mut rand_core::OsRng) % 16000) as u16,
            tcp_buffer: TCP_BUFFER,
            listen_buffer: TCP_BUFFER,
            congestion: Congestion::None,
        };
        stack.set_addresses(addresses);
        stack
    }

    /// The TCP buffer size (each way) for sockets opened from now on.
    pub fn set_tcp_buffer(&mut self, bytes: usize) {
        self.tcp_buffer = bytes.max(1024);
    }

    /// The TCP buffer size (each way) for listening sockets, and the
    /// connections they accept, from now on.
    pub fn set_listen_buffer(&mut self, bytes: usize) {
        self.listen_buffer = bytes.max(1024);
    }

    /// The congestion control of sockets opened from now on.
    pub fn set_congestion(&mut self, congestion: Congestion) {
        self.congestion = congestion;
    }

    /// Replace this node's addresses (from the netmap).
    pub fn set_addresses(&mut self, addresses: &[IpAddr]) {
        self.iface.update_ip_addrs(|cidrs| {
            cidrs.clear();
            for addr in addresses {
                let cidr = match addr {
                    IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(*v4), CGNAT_PREFIX),
                    IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(*v6), ULA_PREFIX),
                };
                let _ = cidrs.push(cidr);
            }
        });
    }

    fn now(&self, now: Instant) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(
            now.saturating_duration_since(self.epoch).as_micros() as i64
        )
    }

    fn tcp_socket(&self, buffer: usize) -> tcp::Socket<'static> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; buffer]),
            tcp::SocketBuffer::new(vec![0; buffer]),
        );
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(match self.congestion {
            Congestion::None => tcp::CongestionControl::None,
            Congestion::Reno => tcp::CongestionControl::Reno,
            Congestion::Cubic => tcp::CongestionControl::Cubic,
        });
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
        socket
    }

    /// Open a TCP connection to `remote`.
    pub fn connect(&mut self, remote: SocketAddr) -> Result<SocketHandle, tcp::ConnectError> {
        let mut socket = self.tcp_socket(self.tcp_buffer);
        let port = self.take_port();
        socket.connect(self.iface.context(), remote, port)?;
        Ok(self.sockets.add(socket))
    }

    /// A socket waiting for one connection on `port` (on any of our addresses).
    pub fn listen(&mut self, port: u16) -> Result<SocketHandle, tcp::ListenError> {
        // Allocated while waiting: its own (often smaller) size.
        let mut socket = self.tcp_socket(self.listen_buffer);
        socket.listen(port)?;
        Ok(self.sockets.add(socket))
    }

    /// The next ephemeral port.
    fn take_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if self.next_port >= 65000 {
            49152
        } else {
            self.next_port + 1
        };
        port
    }

    pub fn socket(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(handle)
    }

    /// Bind a UDP socket on `port` (0 picks an ephemeral one); returns it
    /// and the port.
    #[cfg(feature = "udp")]
    pub fn bind_udp(&mut self, port: u16) -> Result<(SocketHandle, u16), udp::BindError> {
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; UDP_PACKETS * MAX_UDP_PAYLOAD],
            )
        };
        let mut socket = udp::Socket::new(buffer(), buffer());
        let port = if port == 0 { self.take_port() } else { port };
        socket.bind(port)?;
        Ok((self.sockets.add(socket), port))
    }

    #[cfg(feature = "udp")]
    pub fn udp_socket(&mut self, handle: SocketHandle) -> &mut udp::Socket<'static> {
        self.sockets.get_mut::<udp::Socket>(handle)
    }

    pub fn remove(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
    }

    /// An IP packet from the tunnel.
    pub fn input(&mut self, packet: Vec<u8>) {
        self.device.rx.push_back(packet);
    }

    /// Process input and timers; returns IP packets to send into the tunnel.
    /// At most `room` of them are the sockets' own (the rest waits in their
    /// buffers, as behind a full interface queue); answers to what arrived
    /// always go out.
    pub fn poll(&mut self, now: Instant, room: usize) -> Vec<Vec<u8>> {
        let now = self.now(now);
        self.device.room = room;
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.device.tx.drain(..).collect()
    }

    /// When [`poll`](Self::poll) should run next, if nothing arrives before.
    pub fn poll_at(&mut self, now: Instant) -> Option<Instant> {
        let at = self.iface.poll_at(self.now(now), &self.sockets)?;
        Some(self.epoch + std::time::Duration::from_micros(at.total_micros().max(0) as u64))
    }
}

/// The device smoltcp sees: two packet queues.
#[derive(Default)]
struct Queues {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    /// How many packets `tx` may hold before the sockets must wait.
    room: usize,
}

impl Device for Queues {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx, Tx<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        (self.tx.len() < self.room).then_some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

struct Rx(Vec<u8>);

impl smoltcp::phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let r = f(&mut packet);
        self.0.push_back(packet);
        r
    }
}

/// The source address of an IP packet, if it parses.
pub fn source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?)),
        6 if packet.len() >= 40 => Some(IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
        _ => None,
    }
}

/// The destination address of an IP packet, if it parses.
pub fn destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?)),
        6 if packet.len() >= 40 => Some(IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two stacks wired back to back complete a TCP exchange.
    #[test]
    fn two_stacks_talk_tcp() {
        let a_ip: IpAddr = "100.64.0.1".parse().unwrap();
        let b_ip: IpAddr = "100.64.0.2".parse().unwrap();
        let t0 = Instant::now();
        let mut a = Netstack::new(&[a_ip], t0);
        let mut b = Netstack::new(&[b_ip], t0);

        let mut listener = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        listener.listen(7).unwrap();
        let server = b.sockets.add(listener);
        let client = a.connect(SocketAddr::new(b_ip, 7)).unwrap();

        let mut sent = false;
        let mut got = Vec::new();
        for step in 0..200 {
            let now = t0 + std::time::Duration::from_millis(step);
            for p in a.poll(now, usize::MAX) {
                assert_eq!(destination(&p), Some(b_ip));
                b.input(p);
            }
            for p in b.poll(now, usize::MAX) {
                a.input(p);
            }
            let c = a.socket(client);
            if c.can_send() && !sent {
                c.send_slice(b"ping").unwrap();
                sent = true;
            }
            let s = b.socket(server);
            if s.can_recv() {
                let mut buf = [0u8; 16];
                let n = s.recv_slice(&mut buf).unwrap();
                s.send_slice(&buf[..n]).unwrap();
            }
            let c = a.socket(client);
            if c.can_recv() {
                let mut buf = [0u8; 16];
                let n = c.recv_slice(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
            }
            if got == b"ping" {
                return;
            }
        }
        panic!("no echo; got {got:?}");
    }

    /// Two stacks wired back to back exchange datagrams; unbound ports get
    /// nothing.
    #[cfg(feature = "udp")]
    #[test]
    fn two_stacks_talk_udp() {
        let a_ip: IpAddr = "100.64.0.1".parse().unwrap();
        let b_ip: IpAddr = "100.64.0.2".parse().unwrap();
        let t0 = Instant::now();
        let mut a = Netstack::new(&[a_ip], t0);
        let mut b = Netstack::new(&[b_ip], t0);
        let (client, client_port) = a.bind_udp(0).unwrap();
        let (server, _) = b.bind_udp(7).unwrap();

        a.udp_socket(client)
            .send_slice(b"ping", SocketAddr::new(b_ip, 7))
            .unwrap();
        a.udp_socket(client)
            .send_slice(b"lost", SocketAddr::new(b_ip, 8))
            .unwrap();
        let mut got = Vec::new();
        for step in 0..20 {
            let now = t0 + std::time::Duration::from_millis(step);
            for p in a.poll(now, usize::MAX) {
                assert_eq!(destination(&p), Some(b_ip));
                b.input(p);
            }
            for p in b.poll(now, usize::MAX) {
                a.input(p);
            }
            let s = b.udp_socket(server);
            while let Ok((n, meta)) = s.recv_slice(&mut [0u8; 64]) {
                assert_eq!(n, 4);
                assert_eq!(meta.endpoint.port, client_port);
                s.send_slice(b"pong", meta.endpoint).unwrap();
            }
            let mut buf = [0u8; 64];
            while let Ok((n, meta)) = a.udp_socket(client).recv_slice(&mut buf) {
                assert_eq!(meta.endpoint, SocketAddr::new(b_ip, 7).into());
                got.push(buf[..n].to_vec());
            }
        }
        assert_eq!(got, vec![b"pong".to_vec()]);
    }
}
