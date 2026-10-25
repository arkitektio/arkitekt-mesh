//! arkitekt-mesh in the browser (and node): the embassy driver
//! (`arkitekt-mesh-embassy`) on the JS event loop, with control and DERP
//! over WebSockets. A browser has no UDP, so it is DERP only; its sockets
//! are those of the mesh's netstack, as on a board
//! (docs/rfc9-sans-io-runtimes.md).
//!
//! ```ignore
//! let mesh = mesh_web::start(mesh_web::config(url, machine_key, node_key));
//! mesh.joined().await;
//! let stream = mesh.connect((mesh.resolve("peer").unwrap(), 80).into()).await?;
//! ```
//!
//! Empty on anything but wasm32.

#![cfg(target_arch = "wasm32")]
#![allow(async_fn_in_trait)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::poll_fn;
use core::net::SocketAddr;
use core::task::{Poll, Waker};

use embedded_io_async::{ErrorKind, ErrorType, Read, Write};
use mesh_core::keys::PrivateKey;
use mesh_core::time::Duration;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{BinaryType, CloseEvent, Event, MessageEvent, WebSocket};

pub use mesh_embassy::{Config, Mesh, MeshError, TcpError, TcpStream};

#[wasm_bindgen]
extern "C" {
    /// The global `fetch` (a window's, a worker's, node's).
    #[wasm_bindgen(js_name = fetch)]
    fn global_fetch(url: &str) -> js_sys::Promise;
}

/// embassy-time's clock and timers on JS: `performance.now()` and
/// `setTimeout`, as in a page, a worker and node alike.
mod clock {
    use core::task::Waker;

    use embassy_time_driver::{Driver, TICK_HZ};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = performance, js_name = now)]
        fn performance_now() -> f64;
        #[wasm_bindgen(js_name = setTimeout)]
        fn set_timeout(callback: &js_sys::Function, ms: f64) -> JsValue;
    }

    struct JsClock;

    impl Driver for JsClock {
        fn now(&self) -> u64 {
            (performance_now() * TICK_HZ as f64 / 1000.0) as u64
        }

        fn schedule_wake(&self, at: u64, waker: &Waker) {
            if at == u64::MAX {
                return;
            }
            let ticks = at.saturating_sub(self.now());
            // setTimeout takes at most 2^31 - 1 ms; a longer wait wakes early,
            // and the timer schedules again.
            let ms = (ticks as f64 * 1000.0 / TICK_HZ as f64).min(2_147_483_647.0);
            let waker = waker.clone();
            let callback = Closure::once_into_js(move || waker.wake());
            set_timeout(callback.unchecked_ref(), ms);
        }
    }

    embassy_time_driver::time_driver_impl!(static CLOCK: JsClock = JsClock);
}

/// Where randomness and the wall clock come from: `crypto.getRandomValues`
/// and `Date.now`. Once, before any key is made ([`start`] does it).
pub fn install() {
    mesh_core::random::set_source(|bytes| {
        getrandom::getrandom(bytes).expect("crypto.getRandomValues")
    });
    mesh_core::time::set_wall_clock(|| Duration::from_millis(js_sys::Date::now() as u64));
}

/// A node's config for the browser: [`Config::small`] without direct paths.
pub fn config(control_url: String, machine_key: PrivateKey, node_key: PrivateKey) -> Config {
    let mut config = Config::small(control_url, machine_key, node_key);
    config.settings.direct = false;
    config.settings.ipv4 = false;
    config.settings.netcheck_interval = None;
    config
}

/// Start a node on the event loop; it runs until control will not have it.
pub fn start(config: Config) -> Rc<Mesh> {
    install();
    let mesh = Rc::new(Mesh::new(config));
    let node = mesh.clone();
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = node.run(&NoUdp, &WebDial).await {
            tracing::warn!("the mesh node ended: {e}");
        }
    });
    mesh
}

/// No UDP in a browser: nothing arrives, and nothing is sent (the node
/// runs DERP only).
pub struct NoUdp;

impl mesh_embassy::Udp for NoUdp {
    type Error = ();

    async fn send_to(&self, _data: &[u8], _to: SocketAddr) -> Result<(), ()> {
        Ok(())
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr), ()> {
        core::future::pending().await
    }

    fn local_port(&self) -> u16 {
        0
    }
}

/// Control and DERP by WebSocket, `/key` by `fetch`.
pub struct WebDial;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsError(pub String);

impl core::fmt::Display for WsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for WsError {}

impl embedded_io_async::Error for WsError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

fn js_error(what: &str, e: JsValue) -> mesh_embassy::DialError {
    mesh_embassy::DialError(alloc::format!("{what}: {e:?}"))
}

impl mesh_embassy::Dial for WebDial {
    type Conn<'a> = WsConn;

    const WEBSOCKET: bool = true;

    async fn dial(
        &self,
        host: &str,
        port: u16,
        _tls: mesh_embassy::Tls<'_>,
    ) -> Result<WsConn, mesh_embassy::DialError> {
        Err(mesh_embassy::DialError(alloc::format!(
            "no raw TCP in a browser ({host}:{port})"
        )))
    }

    async fn websocket(
        &self,
        url: &str,
        protocol: &str,
    ) -> Result<WsConn, mesh_embassy::DialError> {
        WsConn::open(url, protocol).await
    }

    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), mesh_embassy::DialError> {
        let response = wasm_bindgen_futures::JsFuture::from(global_fetch(url))
            .await
            .map_err(|e| js_error(url, e))?;
        let response: web_sys::Response = response.dyn_into().map_err(|e| js_error(url, e))?;
        let status = response.status();
        let body = response.array_buffer().map_err(|e| js_error(url, e))?;
        let body = wasm_bindgen_futures::JsFuture::from(body)
            .await
            .map_err(|e| js_error(url, e))?;
        Ok((status, js_sys::Uint8Array::new(&body).to_vec()))
    }
}

#[derive(Default)]
struct Incoming {
    bytes: VecDeque<u8>,
    open: bool,
    /// Why it closed (or failed to open).
    closed: Option<String>,
    waker: Option<Waker>,
}

impl Incoming {
    fn wake(&mut self) {
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }
}

/// A WebSocket as a byte stream: each write one binary message, reads the
/// messages' bytes in order. Reads are cancel-safe (the bytes wait here).
pub struct WsConn {
    ws: WebSocket,
    incoming: Rc<RefCell<Incoming>>,
    _onmessage: Closure<dyn FnMut(MessageEvent)>,
    _onopen: Closure<dyn FnMut(Event)>,
    _onerror: Closure<dyn FnMut(Event)>,
    _onclose: Closure<dyn FnMut(CloseEvent)>,
}

impl WsConn {
    async fn open(url: &str, protocol: &str) -> Result<Self, mesh_embassy::DialError> {
        let ws = WebSocket::new_with_str(url, protocol).map_err(|e| js_error(url, e))?;
        ws.set_binary_type(BinaryType::Arraybuffer);
        let incoming = Rc::new(RefCell::new(Incoming::default()));

        let i = incoming.clone();
        let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if let Ok(buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                let mut i = i.borrow_mut();
                i.bytes.extend(js_sys::Uint8Array::new(&buffer).to_vec());
                i.wake();
            }
        });
        let i = incoming.clone();
        let onopen = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
            let mut i = i.borrow_mut();
            i.open = true;
            i.wake();
        });
        let i = incoming.clone();
        let onerror = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
            let mut i = i.borrow_mut();
            i.closed
                .get_or_insert_with(|| String::from("the WebSocket failed"));
            i.wake();
        });
        let i = incoming.clone();
        let onclose = Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
            let mut i = i.borrow_mut();
            i.closed.get_or_insert_with(|| {
                alloc::format!("closed ({}): {}", event.code(), event.reason())
            });
            i.wake();
        });
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
        let conn = Self {
            ws,
            incoming,
            _onmessage: onmessage,
            _onopen: onopen,
            _onerror: onerror,
            _onclose: onclose,
        };
        poll_fn(|cx| {
            let mut i = conn.incoming.borrow_mut();
            if let Some(reason) = &i.closed {
                return Poll::Ready(Err(mesh_embassy::DialError(alloc::format!(
                    "{url}: {reason}"
                ))));
            }
            if i.open {
                return Poll::Ready(Ok(()));
            }
            i.waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await?;
        Ok(conn)
    }
}

impl ErrorType for WsConn {
    type Error = WsError;
}

impl Read for WsConn {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, WsError> {
        poll_fn(|cx| {
            let mut i = self.incoming.borrow_mut();
            if !i.bytes.is_empty() {
                let n = buf.len().min(i.bytes.len());
                for (slot, byte) in buf.iter_mut().zip(i.bytes.drain(..n)) {
                    *slot = byte;
                }
                return Poll::Ready(Ok(n));
            }
            if i.closed.is_some() {
                return Poll::Ready(Ok(0));
            }
            i.waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

impl Write for WsConn {
    async fn write(&mut self, data: &[u8]) -> Result<usize, WsError> {
        if let Some(reason) = &self.incoming.borrow().closed {
            return Err(WsError(reason.clone()));
        }
        self.ws
            .send_with_u8_array(data)
            .map_err(|e| WsError(alloc::format!("{e:?}")))?;
        Ok(data.len())
    }

    async fn flush(&mut self) -> Result<(), WsError> {
        Ok(())
    }
}

impl Drop for WsConn {
    fn drop(&mut self) {
        self.ws.set_onmessage(None);
        self.ws.set_onopen(None);
        self.ws.set_onerror(None);
        self.ws.set_onclose(None);
        let _ = self.ws.close();
    }
}
