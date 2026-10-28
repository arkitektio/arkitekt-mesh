//! A DERP slot's task: the connection to the region the core asked for
//! ([`DerpConn`] over a stream from the app), reconnected with
//! [`Backoff`], until the slot is given another region or none.

use alloc::format;
use alloc::string::String;
use alloc::vec;

use embassy_futures::select::{select, select3, Either, Either3};
use embedded_io_async::{Read, Write};

use mesh_core::control::types::{DerpNode, DerpRegion};
use mesh_core::derp::conn::{Backoff, DerpConn, WEBSOCKET_PROTOCOL};
use mesh_core::derp::Event;

use crate::{at, now, Dial, Mesh, Tls};

impl Mesh {
    pub(crate) async fn slot_task<D: Dial>(&self, i: usize, dial: &D) -> core::convert::Infallible {
        let mut backoff = Backoff::default();
        loop {
            // The region this slot is for, when there is one.
            let assigned = {
                let inner = self.inner.borrow();
                let s = &inner.slots[i];
                s.region
                    .clone()
                    .map(|(region, info, home)| (s.generation, region, info, home))
            };
            let Some((generation, region, info, home)) = assigned else {
                self.slot_wake[i].wait().await;
                continue;
            };
            match self
                .derp_session(i, generation, region, &info, home, dial)
                .await
            {
                Ok(()) => backoff.reset(),
                Err(e) => tracing::debug!("DERP region {region}: {e}"),
            }
            let was_up = core::mem::replace(&mut self.inner.borrow_mut().slots[i].up, false);
            if was_up {
                backoff.reset();
            }
            if self.inner.borrow().slots[i].generation != generation {
                continue;
            }
            // Wait before reconnecting, unless the slot is given another region.
            let delay = backoff.next_delay();
            let _ = select(
                embassy_time::Timer::after(embassy_time::Duration::from_micros(
                    delay.as_micros() as u64
                )),
                self.slot_wake[i].wait(),
            )
            .await;
        }
    }

    /// One connection to the region: its nodes in turn until one answers,
    /// then packets both ways. `Ok` when the slot moved on.
    async fn derp_session<D: Dial>(
        &self,
        i: usize,
        generation: u32,
        region: i32,
        info: &DerpRegion,
        home: bool,
        dial: &D,
    ) -> Result<(), String> {
        let mut last = String::from("the region has no DERP nodes");
        for node in info.nodes.iter().filter(|n| !n.stun_only) {
            match self
                .derp_node(i, generation, region, node, home, dial)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
            if self.inner.borrow().slots[i].generation != generation {
                return Ok(());
            }
        }
        Err(last)
    }

    async fn derp_node<D: Dial>(
        &self,
        i: usize,
        generation: u32,
        region: i32,
        node: &DerpNode,
        home: bool,
        dial: &D,
    ) -> Result<(), String> {
        let host = node.derp_dial_host();
        let port = node.derp_port();
        let name = node.derp_cert_name();
        let tls = match &name {
            Some(name) if !node.insecure_for_tests => Tls::Verify(name),
            _ => Tls::Unverified(&node.host_name),
        };
        // Dialing and the handshake take at most this long (then the
        // region's next node), as in the tokio driver.
        let handshake_by = embassy_time::Instant::now() + embassy_time::Duration::from_secs(10);
        let authority = if port == 443 {
            node.host_name.clone()
        } else {
            format!("{}:{port}", node.host_name)
        };
        // A slot given another region (or none) meanwhile gives up the dial:
        // its TLS handshake is seconds of a board's CPU, for a region the
        // core no longer wants (the default home, rehomed a moment later).
        let (opened, mut conn) = if D::WEBSOCKET {
            // By name: the WebSocket's TLS checks the certificate for it.
            let url = format!("wss://{authority}/derp");
            let dialing =
                embassy_time::with_deadline(handshake_by, dial.websocket(&url, WEBSOCKET_PROTOCOL));
            let Either::First(opened) = select(dialing, self.moved_on(i, generation)).await else {
                return Ok(());
            };
            (
                opened,
                DerpConn::upgraded(self.config().node_key.clone(), home, now()),
            )
        } else {
            let dialing = embassy_time::with_deadline(handshake_by, dial.dial(&host, port, tls));
            let Either::First(opened) = select(dialing, self.moved_on(i, generation)).await else {
                return Ok(());
            };
            (
                opened,
                DerpConn::new(&authority, self.config().node_key.clone(), home, now()),
            )
        };
        let mut stream = opened
            .map_err(|_| format!("connecting to {host} timed out"))?
            .map_err(|e| format!("{host}: {e}"))?;
        let mut buf = vec![0u8; 4096];
        loop {
            if self.inner.borrow().slots[i].generation != generation {
                return Ok(());
            }
            // Queued packets go once the handshake is done.
            if conn.is_up() {
                let mut inner = self.inner.borrow_mut();
                inner.slots[i].up = true;
                while let Some((peer, data)) = inner.slots[i].queue.pop_front() {
                    conn.send_packet(&peer, &data);
                }
            }
            if let Some(out) = conn.poll_transmit() {
                stream
                    .write_all(&out)
                    .await
                    .map_err(|e| format!("write: {e:?}"))?;
                stream.flush().await.map_err(|e| format!("flush: {e:?}"))?;
                // Room in the queue again: the node may send on.
                self.node_wake.signal(());
            }
            let quiet = if conn.is_up() {
                at(conn.poll_timeout())
            } else {
                handshake_by.min(at(conn.poll_timeout()))
            };
            match select3(
                stream.read(&mut buf),
                self.slot_wake[i].wait(),
                embassy_time::Timer::at(quiet),
            )
            .await
            {
                Either3::First(Ok(0)) => {
                    return Err(String::from("the DERP server closed the connection"))
                }
                Either3::First(Ok(n)) => {
                    conn.handle_input(now(), &buf[..n])
                        .map_err(|e| format!("{e}"))?;
                    self.derp_events(&mut conn, region);
                }
                Either3::First(Err(e)) => return Err(format!("read: {e:?}")),
                Either3::Second(()) => {}
                Either3::Third(())
                    if !conn.is_up() && embassy_time::Instant::now() >= handshake_by =>
                {
                    return Err(format!("the handshake with {host} timed out"));
                }
                Either3::Third(()) => conn.handle_timeout(now()).map_err(|e| format!("{e}"))?,
            }
        }
    }

    /// Packets from the server into the core.
    /// Done once slot `i` is no longer at `generation`.
    async fn moved_on(&self, i: usize, generation: u32) {
        while self.inner.borrow().slots[i].generation == generation {
            self.slot_wake[i].wait().await;
        }
    }

    fn derp_events(&self, conn: &mut DerpConn, region: i32) {
        let mut inner = self.inner.borrow_mut();
        let inner = &mut *inner;
        while let Some(event) = conn.poll_event() {
            let Event::Packet { from, data } = event else {
                continue;
            };
            let Some(core) = inner.core.as_mut() else {
                continue;
            };
            let transmits = core.handle_derp(now(), region, from, &data);
            core.link_derp_for(&transmits);
            // The slots first: a packet for a region just linked waits in
            // its queue instead of being dropped.
            self.events(inner);
            self.dispatch(inner, transmits);
        }
        self.node_wake.signal(());
    }
}
