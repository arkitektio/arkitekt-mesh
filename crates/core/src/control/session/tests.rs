//! The control loop's rules, as the tokio driver kept them, checked on
//! the session alone.

use super::*;
use crate::keys::{PrivateKey, PublicKey};

fn config() -> SessionConfig {
    SessionConfig {
        node_key: NodePublic(PublicKey([1; 32])),
        disco_key: DiscoPublic(PrivateKey::generate().public()),
        hostinfo: Hostinfo {
            hostname: "rusty".into(),
            ..Default::default()
        },
        auth_key: Some("tskey-x".into()),
        ephemeral: true,
    }
}

fn at(secs: u64) -> Instant {
    Instant::from_micros(secs * 1_000_000)
}

fn events(s: &mut ControlSession) -> Vec<Event> {
    core::iter::from_fn(|| s.poll_event()).collect()
}

/// The calls asked for, as (id, path, stream, request body).
fn sends(events: &[Event]) -> Vec<(CallId, String, bool, Vec<u8>)> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Send { id, call, stream } => {
                Some((*id, call.path.clone(), *stream, call.body.clone()))
            }
            _ => None,
        })
        .collect()
}

fn registered() -> Answer {
    Answer::Whole {
        status: 200,
        body: br#"{"MachineAuthorized":true}"#.to_vec(),
    }
}

fn map(json: &str) -> Answer {
    Answer::Map(Box::new(serde_json::from_str(json).unwrap()))
}

fn request(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap()
}

/// A session past register with its stream open: (session, stream id, update id).
fn streaming(now: Instant) -> (ControlSession, CallId, CallId) {
    let mut s = ControlSession::new(config(), String::new(), now);
    assert!(matches!(events(&mut s)[..], [Event::Connect]));
    s.connected(now);
    let register = sends(&events(&mut s))[0].0;
    s.answer(now, register, registered());
    let ev = events(&mut s);
    assert!(matches!(ev[0], Event::Registered));
    let calls = sends(&ev);
    assert_eq!(calls.len(), 2, "the stream, then the first update");
    (s, calls[0].0, calls[1].0)
}

#[test]
fn connect_register_then_stream_and_a_first_update() {
    let now = at(0);
    let mut s = ControlSession::new(config(), "tka-head".into(), now);
    assert!(matches!(events(&mut s)[..], [Event::Connect]));
    s.connected(now);
    let calls = sends(&events(&mut s));
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "/machine/register");
    let reg = request(&calls[0].3);
    assert_eq!(reg["Auth"]["AuthKey"], "tskey-x");
    assert_eq!(reg["Ephemeral"], true);
    assert_eq!(reg["Hostinfo"]["Hostname"], "rusty");

    s.answer(now, calls[0].0, registered());
    let ev = events(&mut s);
    let calls = sends(&ev);
    let stream = request(&calls[0].3);
    assert_eq!((calls[0].1.as_str(), calls[0].2), ("/machine/map", true));
    assert_eq!(stream["Stream"], true);
    assert_eq!(stream["TKAHead"], "tka-head");
    assert!(stream.get("Endpoints").is_none());
    let update = request(&calls[1].3);
    assert_eq!(update["Stream"], false);
    assert_eq!(update["OmitPeers"], true);
}

#[test]
fn refusals_before_the_first_registration_end_it_in_order() {
    let cases: [(&str, Refusal); 4] = [
        (
            r#"{"Error":"invalid authkey","NodeKeyExpired":true}"#,
            Refusal::Refused("invalid authkey".into()),
        ),
        (
            r#"{"NodeKeyExpired":true,"AuthURL":"https://x"}"#,
            Refusal::KeyExpired,
        ),
        (
            r#"{"AuthURL":"https://login","MachineAuthorized":true}"#,
            Refusal::NeedsLogin(Some("https://login".into())),
        ),
        (r#"{}"#, Refusal::NeedsLogin(None)),
    ];
    for (body, refusal) in cases {
        let now = at(0);
        let mut s = ControlSession::new(config(), String::new(), now);
        events(&mut s);
        s.connected(now);
        let id = sends(&events(&mut s))[0].0;
        s.answer(
            now,
            id,
            Answer::Whole {
                status: 200,
                body: body.as_bytes().to_vec(),
            },
        );
        let ev = events(&mut s);
        assert!(
            matches!(&ev[..], [Event::Ended(SessionError::Refused(r))] if *r == refusal),
            "{body}: {ev:?}"
        );
        assert!(s.is_ended());
    }
    // Unreachable at the start ends it too.
    let mut s = ControlSession::new(config(), String::new(), at(0));
    events(&mut s);
    s.connect_failed(at(0), "connection refused");
    assert!(matches!(
        &events(&mut s)[..],
        [Event::Ended(SessionError::Unreachable(_))]
    ));
}

#[test]
fn keepalives_are_not_forwarded_but_keep_the_stream_alive() {
    let (mut s, stream, _) = streaming(at(0));
    s.answer(at(100), stream, map(r#"{"KeepAlive":true}"#));
    assert!(events(&mut s).is_empty());
    // Heard at 100 s: quiet only at 220 s.
    assert_eq!(s.poll_timeout(), Some(at(220)));
    s.answer(at(110), stream, map(r#"{"Domain":"tail"}"#));
    assert!(matches!(&events(&mut s)[..], [Event::Map(r)] if r.domain == "tail"));
}

#[test]
fn a_quiet_stream_reconnects_with_backoff_doubling_to_thirty_seconds() {
    let (mut s, _, _) = streaming(at(0));
    s.handle_timeout(at(119));
    assert!(events(&mut s).is_empty());
    s.handle_timeout(at(120));
    assert!(matches!(events(&mut s)[..], [Event::Disconnect]));
    // 1 s, then each failed attempt doubles: 2, 4, ... 30.
    let mut now = at(120);
    let mut waits = Vec::new();
    for _ in 0..7 {
        let at_ = s.poll_timeout().unwrap();
        waits.push((at_.as_micros() - now.as_micros()) / 1_000_000);
        now = at_;
        s.handle_timeout(now);
        assert!(matches!(events(&mut s)[..], [Event::Connect]));
        s.connect_failed(now, "down");
    }
    assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30]);
}

#[test]
fn any_response_resets_the_backoff_and_a_rebind_makes_it_short() {
    let (mut s, stream, _) = streaming(at(0));
    // Two failures, then a stream that answers: back to 1 s.
    s.disconnected(at(1));
    for _ in 0..2 {
        let t = s.poll_timeout().unwrap();
        s.handle_timeout(t);
        s.connect_failed(t, "down");
    }
    let t = s.poll_timeout().unwrap();
    s.handle_timeout(t);
    events(&mut s);
    s.connected(t);
    let register = sends(&events(&mut s))[0].0;
    s.answer(t, register, registered());
    let stream2 = sends(&events(&mut s))[0].0;
    assert_ne!(stream2, stream);
    s.answer(t, stream2, map(r#"{"KeepAlive":true}"#));
    s.answer(t, stream2, Answer::MapEnded);
    assert_eq!(s.poll_timeout(), Some(t + Duration::from_secs(1)));

    // A rebind: disconnect, and 100 ms.
    let (mut s, _, _) = streaming(at(0));
    s.rebind(at(5));
    assert!(matches!(events(&mut s)[..], [Event::Disconnect]));
    assert_eq!(s.poll_timeout(), Some(at(5) + Duration::from_millis(100)));
}

#[test]
fn a_reconnect_registers_again_and_streams_the_current_head() {
    let (mut s, stream, _) = streaming(at(0));
    s.set_tka_head("new-head".into());
    events(&mut s);
    s.answer(at(1), stream, Answer::Failed(ApiError("reset".into())));
    assert!(matches!(events(&mut s)[..], [Event::Disconnect]));
    s.handle_timeout(at(2));
    assert!(matches!(events(&mut s)[..], [Event::Connect]));
    s.connected(at(2));
    let calls = sends(&events(&mut s));
    assert_eq!(calls[0].1, "/machine/register");
    s.answer(at(2), calls[0].0, registered());
    let ev = events(&mut s);
    assert!(matches!(ev[0], Event::Registered));
    let calls = sends(&ev);
    assert_eq!(request(&calls[0].3)["TKAHead"], "new-head");
    // And an update after every reconnect.
    assert_eq!(request(&calls[1].3)["Stream"], false);
    // A refusal now is retried, not the end.
    s.answer(at(3), calls[0].0, Answer::MapEnded);
    events(&mut s);
    // No response on that stream: the wait stayed doubled (2 s).
    let t = s.poll_timeout().unwrap();
    assert_eq!(t, at(5));
    s.handle_timeout(t);
    events(&mut s);
    s.connected(t);
    let register = sends(&events(&mut s))[0].0;
    s.answer(
        t,
        register,
        Answer::Whole {
            status: 200,
            body: br#"{"Error":"invalid authkey"}"#.to_vec(),
        },
    );
    assert!(matches!(events(&mut s)[..], [Event::Disconnect]));
    assert!(!s.is_ended());
}

#[test]
fn updates_are_coalesced_one_in_flight_latest_wins() {
    let (mut s, _, first) = streaming(at(0));
    let a: SocketAddr = "1.2.3.4:41641".parse().unwrap();
    let b: SocketAddr = "5.6.7.8:41641".parse().unwrap();
    // While the first is in flight, changes wait and merge.
    s.set_endpoints(vec![(a, EndpointType::Stun)]);
    s.set_endpoints(vec![(b, EndpointType::Stun)]);
    s.set_home((Some(3), Default::default()));
    assert!(sends(&events(&mut s)).is_empty());
    // Its stream answers are drained; its end lets the next go.
    s.answer(at(1), first, map(r#"{"Domain":"ignored"}"#));
    assert!(events(&mut s).is_empty());
    s.answer(at(1), first, Answer::MapEnded);
    let calls = sends(&events(&mut s));
    assert_eq!(calls.len(), 1);
    let body = request(&calls[0].3);
    assert_eq!(body["Endpoints"], serde_json::json!(["5.6.7.8:41641"]));
    assert_eq!(body["Hostinfo"]["NetInfo"]["PreferredDERP"], 3);
    // Nothing changed: nothing more.
    s.answer(at(2), calls[0].0, Answer::MapEnded);
    s.set_endpoints(vec![(b, EndpointType::Stun)]);
    assert!(sends(&events(&mut s)).is_empty());
}

#[test]
fn answers_of_a_dropped_connection_are_ignored() {
    let (mut s, stream, _) = streaming(at(0));
    s.handle_timeout(at(120));
    events(&mut s);
    s.answer(at(121), stream, map(r#"{"Domain":"late"}"#));
    assert!(events(&mut s).is_empty());
}
