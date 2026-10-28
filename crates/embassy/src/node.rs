//! The node task: UDP in and out, the core's timers, and where its
//! transmits and events go (UDP, a DERP slot's queue, the session).

use alloc::vec;
use alloc::vec::Vec;

use embassy_futures::select::{select3, Either3};

use mesh_core::node::Event;
use mesh_core::paths::{Transmit, Via};

use crate::{at, now, Inner, Mesh, Udp};

impl Mesh {
    pub(crate) async fn node_task<U: Udp>(&self, udp: &U) -> core::convert::Infallible {
        // A WireGuard packet at the tunnel MTU, or a disco/STUN message.
        let mut buf = vec![0u8; 2048];
        let mut ports_set = false;
        loop {
            let deadline = 'pass: {
                let mut guard = self.inner.borrow_mut();
                let inner = &mut *guard;
                let t = now();
                let room = self.derp_room(inner);
                let Some(core) = inner.core.as_mut() else {
                    break 'pass None;
                };
                if !ports_set {
                    core.set_udp_ports(udp.local_port(), None);
                    ports_set = true;
                }
                let pumped = core.pump(t, room);
                let stun = if core.stun_due(t) {
                    core.stun(t, udp.local_endpoint(), None)
                } else {
                    Vec::new()
                };
                core.link_derp_for(&pumped.transmits);
                inner.udp_out.extend(stun);
                // The slots first: a packet for a region just linked waits
                // in its queue instead of being dropped.
                self.events(inner);
                self.dispatch(inner, pumped.transmits);
                let core = inner.core.as_mut().expect("core");
                core.after_pass(t);
                Some(core.poll_timeout(t, pumped.held_back))
            };
            // Send with the state released.
            loop {
                let next = self.inner.borrow_mut().udp_out.pop_front();
                let Some((to, data)) = next else { break };
                if to.is_ipv4() {
                    if let Err(e) = udp.send_to(&data, to).await {
                        tracing::trace!("UDP to {to}: {e:?}");
                    }
                }
            }
            let timer = async {
                match deadline {
                    Some(t) => embassy_time::Timer::at(at(t)).await,
                    None => core::future::pending().await,
                }
            };
            let woke = select3(udp.recv_from(&mut buf), self.node_wake.wait(), timer).await;
            if let Either3::First(Ok((n, src))) = woke {
                let mut inner = self.inner.borrow_mut();
                let inner = &mut *inner;
                if let Some(core) = inner.core.as_mut() {
                    let transmits = core.handle_datagram(now(), src, &buf[..n]);
                    core.link_derp_for(&transmits);
                    self.events(inner);
                    self.dispatch(inner, transmits);
                }
            }
        }
    }

    /// What the fullest connected DERP queue still takes.
    fn derp_room(&self, inner: &Inner) -> usize {
        let cap = self.config().derp_queue.max(1);
        inner
            .slots
            .iter()
            .filter(|s| s.up)
            .map(|s| cap.saturating_sub(s.queue.len()))
            .min()
            .unwrap_or(usize::MAX)
    }

    /// Each transmit to UDP or to its region's DERP slot (dropped when the
    /// slot's queue is full, as the core counts).
    pub(crate) fn dispatch(&self, inner: &mut Inner, transmits: Vec<Transmit>) {
        let cap = self.config().derp_queue.max(1);
        for t in transmits {
            match t.via {
                Via::Udp(to) => inner
                    .udp_out
                    .push_back((mesh_core::node::canonical(to), t.data)),
                Via::Derp { region, peer } => {
                    let slot = inner
                        .slots
                        .iter()
                        .position(|s| s.region.as_ref().is_some_and(|(r, _, _)| *r == region));
                    match slot {
                        Some(i) if inner.slots[i].queue.len() < cap => {
                            inner.slots[i].queue.push_back((peer, t.data));
                            self.slot_wake[i].signal(());
                        }
                        _ => {
                            if let Some(core) = inner.core.as_mut() {
                                core.count_derp_dropped();
                            }
                        }
                    }
                }
            }
        }
    }

    /// The core's events: DERP slots to (re)assign, what control hears.
    pub(crate) fn events(&self, inner: &mut Inner) {
        loop {
            let Some(event) = inner.core.as_mut().and_then(|c| c.poll_event()) else {
                return;
            };
            match event {
                Event::ConnectDerp { region, info, home } => {
                    // The region's slot, a free one, else one not home (its
                    // region closed, as far as the core knows: it asks
                    // again when it needs it). Home always keeps one.
                    let is_home = |s: &crate::Slot| s.region.as_ref().is_some_and(|(_, _, h)| *h);
                    let slot = inner
                        .slots
                        .iter()
                        .position(|s| s.region.as_ref().is_some_and(|(r, _, _)| *r == region))
                        .or_else(|| inner.slots.iter().position(|s| s.region.is_none()))
                        .or_else(|| inner.slots.iter().position(|s| !is_home(s)))
                        .or_else(|| home.then_some(0));
                    let Some(i) = slot else {
                        // Not linked after all: the core asks again when needed.
                        tracing::debug!("no DERP slot for region {region}");
                        if let Some(core) = inner.core.as_mut() {
                            core.derp_closed(region);
                        }
                        continue;
                    };
                    if let Some((old, _, _)) = inner.slots[i].region.take() {
                        if old != region {
                            if let Some(core) = inner.core.as_mut() {
                                core.derp_closed(old);
                            }
                        }
                    }
                    let s = &mut inner.slots[i];
                    s.region = Some((region, info, home));
                    s.generation += 1;
                    s.queue.clear();
                    s.up = false;
                    self.slot_wake[i].signal(());
                }
                Event::DropDerp { region } => {
                    for (i, s) in inner.slots.iter_mut().enumerate() {
                        if s.region.as_ref().is_some_and(|(r, _, _)| *r == region) {
                            s.region = None;
                            s.generation += 1;
                            s.queue.clear();
                            s.up = false;
                            self.slot_wake[i].signal(());
                        }
                    }
                }
                Event::Endpoints(endpoints) => {
                    inner.session.set_endpoints(endpoints);
                    self.control_wake.signal(());
                }
                Event::Home(report) => {
                    inner.session.set_home(report);
                    self.control_wake.signal(());
                }
            }
        }
    }
}
