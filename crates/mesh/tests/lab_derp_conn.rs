//! The core's DERP connection (`DerpConn`) against the mesh lab's
//! ionskale: one client by the HTTP upgrade (as the tokio and embassy
//! drivers connect), one by WebSocket (as a browser does), relaying to
//! each other over TLS.

mod mesh_lab;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use mesh::derp::conn::{DerpConn, WEBSOCKET_PROTOCOL};
use mesh::derp::Event;
use mesh::driver::net::{self, BaseUrl, Tls};
use mesh::keys::{NodePublic, PrivateKey};
use mesh_core::time as clock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

enum Wire {
    Stream(net::BoxIo),
    Ws(Box<tokio_tungstenite::WebSocketStream<net::BoxIo>>),
}

struct Client {
    conn: DerpConn,
    wire: Wire,
    key: NodePublic,
}

impl Client {
    async fn flush(&mut self) {
        if let Some(out) = self.conn.poll_transmit() {
            match &mut self.wire {
                Wire::Stream(io) => io.write_all(&out).await.unwrap(),
                Wire::Ws(ws) => ws.send(Message::binary(out)).await.unwrap(),
            }
        }
    }

    async fn recv(&mut self) {
        let data = match &mut self.wire {
            Wire::Stream(io) => {
                let mut buf = vec![0u8; 16 << 10];
                let n = io.read(&mut buf).await.unwrap();
                assert!(n > 0, "the DERP server closed the connection");
                buf.truncate(n);
                buf
            }
            Wire::Ws(ws) => loop {
                match ws.next().await.expect("the WebSocket ended").unwrap() {
                    Message::Binary(data) => break data.to_vec(),
                    Message::Close(frame) => {
                        panic!("the DERP server closed the WebSocket: {frame:?}")
                    }
                    _ => {}
                }
            },
        };
        self.conn.handle_input(clock::now(), &data).unwrap();
    }

    async fn until_up(&mut self) {
        while !self.conn.is_up() {
            self.flush().await;
            self.recv().await;
        }
        self.flush().await;
    }

    /// The next packet relayed to us.
    async fn packet(&mut self) -> (NodePublic, Vec<u8>) {
        loop {
            while let Some(event) = self.conn.poll_event() {
                if let Event::Packet { from, data } = event {
                    return (from, data);
                }
            }
            self.flush().await;
            self.recv().await;
        }
    }
}

async fn tls(base: &BaseUrl) -> net::BoxIo {
    // The lab's certificate is the lab CA's (ARKITEKT_MESH_CA_FILE).
    net::connect(&base.host, base.port, Tls::Verify)
        .await
        .unwrap()
}

#[tokio::test]
async fn http_upgrade_and_websocket_clients_relay_to_each_other() {
    let Some(lab) = mesh_lab::lab() else { return };
    let base = BaseUrl::parse(&lab.url).unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        let a_key = PrivateKey::generate();
        let mut a = Client {
            conn: DerpConn::new(&base.authority(), a_key.clone(), true, clock::now()),
            wire: Wire::Stream(tls(&base).await),
            key: NodePublic(a_key.public()),
        };

        let b_key = PrivateKey::generate();
        let mut request = format!("wss://{}/derp", base.authority())
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            WEBSOCKET_PROTOCOL.parse().unwrap(),
        );
        let (ws, _) = tokio_tungstenite::client_async(request, tls(&base).await)
            .await
            .unwrap();
        let mut b = Client {
            conn: DerpConn::upgraded(b_key.clone(), false, clock::now()),
            wire: Wire::Ws(Box::new(ws)),
            key: NodePublic(b_key.public()),
        };

        a.until_up().await;
        b.until_up().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let b_pub = b.key;
        a.conn.send_packet(&b_pub, b"to b");
        a.flush().await;
        assert_eq!(b.packet().await, (a.key, b"to b".to_vec()));

        let a_pub = a.key;
        b.conn.send_packet(&a_pub, b"to a");
        b.flush().await;
        assert_eq!(a.packet().await, (b.key, b"to a".to_vec()));
    })
    .await
    .expect("timed out");
}
