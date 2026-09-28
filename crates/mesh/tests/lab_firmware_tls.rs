//! The ESP32 firmware's TLS setup against the mesh lab, on the host: the
//! pure-Rust `rustls-rustcrypto` provider, only the lab CA trusted (no
//! public roots), `Limits::small()`, DERP only (as over PPP). A test binary
//! of its own: it installs the process's TLS provider.

mod mesh_lab;
use mesh_lab as lab;

use lab::{eventually, get, lab};
use mesh::driver::{Limits, Node};

#[tokio::test]
async fn the_firmware_tls_stack_joins_ionskale_and_relays_over_derp() {
    let Some(lab) = lab() else { return };
    let Ok(ca) = std::env::var("ARKITEKT_MESH_CA_FILE") else {
        eprintln!("skipping: ARKITEKT_MESH_CA_FILE is not set (lab.sh env sets it)");
        return;
    };
    let _ = rustls_rustcrypto::provider().install_default();
    // As the firmware does: the embedded CA, instead of the public roots.
    mesh::driver::net::add_trust_roots_pem(&std::fs::read(ca).unwrap()).unwrap();
    mesh::driver::net::trust_public_roots(false);

    let mut config = lab.config(&lab.hostname("firmware-tls"), false);
    config.limits = Limits::small();
    let node = Node::start(config).await.unwrap();
    eventually(30, "HTTP over DERP", || get(&node, &lab.peer)).await;
    assert_eq!(
        node.direct_path(lab.peer_ip.parse().unwrap()),
        None,
        "DERP only"
    );
}
