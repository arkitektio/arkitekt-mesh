#![no_main]
//! Datagrams from anyone: none of these may panic, whatever arrives.

use libfuzzer_sys::fuzz_target;
use mesh_core::keys::PrivateKey;
use mesh_core::portmap::{self, upnp};
use mesh_core::time::Instant;
use mesh_core::{disco, stun, wg};

fuzz_target!(|data: &[u8]| {
    let _ = stun::is_stun(data);
    let _ = stun::parse_response(data);

    let _ = disco::looks_like_disco(data);
    let _ = disco::sender(data);
    let _ = disco::open(&PrivateKey::generate(), data);

    // A tunnel that knows no peer: the path every stranger's packet takes.
    let mut tunnel = wg::Tunnel::new(PrivateKey::generate());
    let _ = wg::is_wireguard(data);
    let _ = tunnel.decapsulate_allowing(data, Instant::ZERO, |_| true);

    let _ = portmap::natpmp_parse_external_address(data);
    let _ = upnp::ssdp_location(data);
    let _ = upnp::http_complete(data);
    let _ = upnp::http_response(data);
    let _ = upnp::parse_external_ip(200, data);
    let _ = upnp::soap_result(500, data);
    if let (Ok(text), Some(location)) = (
        core::str::from_utf8(data),
        upnp::Url::parse("http://192.168.1.1:5000/rootDesc.xml"),
    ) {
        let _ = upnp::control_url(text, &location);
        let _ = upnp::Url::parse(text);
        let _ = location.join(text);
        let _ = portmap::linux_default_gateway(text);
    }
});
