#![no_main]
//! Bytes of a stream whose far end has proven nothing yet.

use libfuzzer_sys::fuzz_target;
use mesh_core::control::api::MapFrames;
use mesh_core::control::http1;
use mesh_core::derp;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((head, used))) = http1::parse_head(data) {
        let _ = http1::body(&head, data[used..].to_vec());
    }
    let _ = http1::dechunk(data);

    let mut buf = data.to_vec();
    while let Ok(Some((kind, payload))) = derp::take_frame(&mut buf) {
        let _ = derp::parse_server_key(kind, &payload);
        let _ = derp::parse_event(kind, payload);
    }

    // In two pieces: a frame split across reads is the usual case.
    let mut frames = MapFrames::new();
    let (first, rest) = data.split_at(data.len() / 2);
    if frames.feed(first).is_ok() && frames.feed(rest).is_ok() {
        while frames.pop().is_some() {}
        let _ = frames.finish();
    }
});
