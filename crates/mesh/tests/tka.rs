//! Tailnet lock against vectors made by tailscale's own `tka` package
//! (tests/harness/tka_vectors_test.go writes tests/fixtures/tka_vectors.json).

use base64::Engine;
use mesh::tka::{hash_text, parse_hash_text, Authority, NodeKeySignature};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/tka_vectors.json")).unwrap()
}

fn b64(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap())
        .unwrap()
}

fn chain(v: &Value) -> (Authority, Vec<Vec<u8>>) {
    let updates: Vec<Vec<u8>> = v["updates"].as_array().unwrap().iter().map(b64).collect();
    let mut authority = Authority::bootstrap(&b64(&v["genesis"])).unwrap();
    assert_eq!(authority.inform(&updates).unwrap(), 3);
    (authority, updates)
}

#[test]
fn hashes_match_go() {
    let v = vectors();
    let genesis = mesh::tka::Aum::parse(&b64(&v["genesis"])).unwrap();
    assert_eq!(hash_text(&genesis.hash()), v["hashes"][0]);
    assert_eq!(genesis.sig_hash().to_vec(), b64(&v["genesis_sighash"]));
    let direct = NodeKeySignature::parse(&b64(&v["signatures"]["direct"])).unwrap();
    assert_eq!(direct.sig_hash().to_vec(), b64(&v["direct_sighash"]));
    for (i, update) in v["updates"].as_array().unwrap().iter().enumerate() {
        let aum = mesh::tka::Aum::parse(&b64(update)).unwrap();
        assert_eq!(hash_text(&aum.hash()), v["hashes"][i + 1]);
    }
}

#[test]
fn the_chain_arrives_at_gos_head_and_keys() {
    let v = vectors();
    let (authority, _) = chain(&v);
    assert_eq!(hash_text(&authority.head()), v["head"]);
    let trusted: Vec<Vec<u8>> = v["trusted_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(b64)
        .collect();
    let keys: Vec<Vec<u8>> = authority
        .state()
        .keys
        .iter()
        .map(|k| k.public.to_vec())
        .collect();
    assert_eq!(keys, trusted, "second removed, third added");
    assert_eq!(authority.state().keys[1].votes, 3, "third's votes updated");
    assert_eq!(
        parse_hash_text(v["head"].as_str().unwrap()),
        Some(authority.head())
    );
}

#[test]
fn updates_apply_in_any_order_but_not_out_of_line() {
    let v = vectors();
    let (_, mut updates) = chain(&v);
    updates.reverse();
    let mut authority = Authority::bootstrap(&b64(&v["genesis"])).unwrap();
    assert_eq!(authority.inform(&updates).unwrap(), 3);
    assert_eq!(hash_text(&authority.head()), v["head"]);
    // Already known: nothing to do.
    assert_eq!(authority.inform(&updates).unwrap(), 0);
    // A gap (the first update missing) is refused.
    let mut authority = Authority::bootstrap(&b64(&v["genesis"])).unwrap();
    assert!(authority.inform(&updates[..2]).is_err());
}

#[test]
fn tampering_is_detected() {
    let v = vectors();
    let genesis = b64(&v["genesis"]);
    // Flip a bit inside the (signed) state: the genesis no longer verifies.
    let mut bad = genesis.clone();
    bad[20] ^= 1;
    assert!(Authority::bootstrap(&bad).is_err());
    // An update flipped in its signature bytes (the last bytes).
    let mut updates: Vec<Vec<u8>> = v["updates"].as_array().unwrap().iter().map(b64).collect();
    let last = updates[0].len() - 1;
    updates[0][last] ^= 1;
    let mut authority = Authority::bootstrap(&genesis).unwrap();
    assert!(authority.inform(&updates).is_err());
}

#[test]
fn a_persisted_chain_restores_and_is_reverified() {
    let v = vectors();
    let (authority, _) = chain(&v);
    let restored = Authority::restore(&authority.to_bytes()).unwrap();
    assert_eq!(restored.head(), authority.head());
    let mut chain = authority.to_bytes();
    chain.swap(1, 2);
    // Out of order on disk is fine (inform sorts it out)...
    assert!(Authority::restore(&chain).is_ok());
    // ...a missing genesis is not.
    assert!(Authority::restore(&chain[1..]).is_err());
}

#[test]
fn node_key_signatures_verify_like_go() {
    let v = vectors();
    let (authority, _) = chain(&v);
    // Go's NodePublic.MarshalBinary: "np" and the key.
    let key = |name: &str| -> [u8; 32] { b64(&v[name])[2..].try_into().unwrap() };
    let node = key("node_key");
    let sig = |name: &str| b64(&v["signatures"][name]);

    authority.authorize(&node, &sig("direct")).unwrap();
    let rotated = authority.authorize(&node, &sig("rotation")).unwrap();
    let old = key("old_node_key");
    assert_eq!(
        rotated.previous_node_keys(),
        vec![old],
        "the rotation replaced the old key"
    );
    authority.authorize(&node, &sig("credential")).unwrap();
    // The credential alone (not wrapped for this node key) authorizes nothing.
    let bare = authority
        .authorize(&node, &sig("bare_credential"))
        .unwrap_err();
    assert!(bare.to_string().contains("on their own"), "{bare}");

    // Signed by a key the chain has since removed.
    assert!(authority.authorize(&node, &sig("by_removed_key")).is_err());
    // Bytes of a valid signature, altered to claim another key.
    let forged = sig("forged");
    let forged_key = NodeKeySignature::parse(&forged)
        .unwrap()
        .node_key()
        .unwrap();
    assert!(authority.authorize(&forged_key, &forged).is_err());
    // The right signature for another node.
    assert!(authority.authorize(&old, &sig("direct")).is_err());
    assert!(authority.authorize(&node, &[]).is_err());
}

#[test]
fn sync_offers_end_at_the_oldest() {
    let v = vectors();
    let (authority, _) = chain(&v);
    let (head, ancestors) = authority.sync_offer();
    assert_eq!(head, authority.head());
    assert_eq!(hash_text(ancestors.last().unwrap()), v["hashes"][0]);
}

#[cfg(feature = "tka-disable")]
#[test]
fn the_disablement_secret_verifies_like_go() {
    let v = vectors();
    let (authority, _) = chain(&v);
    assert!(authority.valid_disablement(&b64(&v["disablement_secret"])));
    assert!(!authority.valid_disablement(b"not the secret"));
}
