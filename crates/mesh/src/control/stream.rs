//! Reading a map response without holding it: a JSON scanner fed the frame
//! in chunks. Each element of `Peers`/`PeersChanged` is compacted into a
//! [`Peer`] as soon as it is complete; members this client does not use
//! (`UserProfiles`, DNS, SSH policy, ...) are skipped unbuffered. The packet
//! filter is kept: the node enforces it (docs/rfc8-packet-filter.md). Only the small remainder is parsed as a [`MapResponse`].
//!
//! Memory is one peer's JSON plus the remainder, however large the tailnet.

use super::netmap::Peer;
use super::types::MapResponse;

/// Top-level members kept (besides the streamed peer lists).
const KEEP: &[&str] = &[
    "KeepAlive",
    "Node",
    "DERPMap",
    "PeersRemoved",
    "PeersChangedPatch",
    "OnlineChange",
    "Domain",
    "PacketFilter",
    "PacketFilters",
    "TKAInfo",
];
const STREAMED: &[&str] = &["Peers", "PeersChanged"];

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("malformed map response JSON at byte {0}")]
    Syntax(usize),
    #[error("bad map response: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Before the top-level `{`.
    Start,
    /// Inside the top-level object, before a key (or `}`).
    Key,
    /// Reading a key's characters.
    KeyString { escape: bool },
    /// After a key, before `:`.
    Colon,
    /// After `:`, before the value's first character.
    ValueStart,
    /// Inside a value; `depth` counts open brackets within it.
    Value {
        depth: u32,
        string: bool,
        escape: bool,
        scalar: bool,
    },
    /// Inside a streamed array, between elements.
    Array,
    /// Inside one element of a streamed array.
    Element {
        depth: u32,
        string: bool,
        escape: bool,
    },
    /// After the top-level `}`.
    Done,
}

/// Parses one map response frame fed in pieces.
pub struct MapReader {
    state: State,
    offset: usize,
    key: Vec<u8>,
    /// The kept members, re-assembled as a JSON object.
    rest: Vec<u8>,
    /// Whether the current value is kept (copied into `rest`).
    keep: bool,
    /// The element being collected, and which list it goes to.
    element: Vec<u8>,
    changed: bool,
    peers: Vec<Peer>,
    peers_changed: Vec<Peer>,
}

impl Default for MapReader {
    fn default() -> Self {
        Self::new()
    }
}

impl MapReader {
    pub fn new() -> Self {
        Self {
            state: State::Start,
            offset: 0,
            key: Vec::new(),
            rest: b"{".to_vec(),
            keep: false,
            element: Vec::new(),
            changed: false,
            peers: Vec::new(),
            peers_changed: Vec::new(),
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<(), StreamError> {
        for &b in data {
            self.byte(b)?;
            self.offset += 1;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<MapResponse, StreamError> {
        if self.state != State::Done {
            return Err(StreamError::Syntax(self.offset));
        }
        self.rest.push(b'}');
        let mut resp: MapResponse = serde_json::from_slice(&self.rest)?;
        resp.peers = self.peers;
        resp.peers_changed = self.peers_changed;
        Ok(resp)
    }

    fn syntax(&self) -> StreamError {
        StreamError::Syntax(self.offset)
    }

    fn start_member(&mut self) {
        if self.rest.len() > 1 {
            self.rest.push(b',');
        }
        self.rest.push(b'"');
        self.rest.extend_from_slice(&self.key);
        self.rest.extend_from_slice(b"\":");
    }

    fn byte(&mut self, b: u8) -> Result<(), StreamError> {
        match self.state {
            State::Start => match b {
                b'{' => self.state = State::Key,
                b if b.is_ascii_whitespace() => {}
                _ => return Err(self.syntax()),
            },
            State::Key => match b {
                b'"' => {
                    self.key.clear();
                    self.state = State::KeyString { escape: false };
                }
                b'}' => self.state = State::Done,
                b',' => {}
                b if b.is_ascii_whitespace() => {}
                _ => return Err(self.syntax()),
            },
            State::KeyString { escape } => {
                if escape {
                    self.key.push(b);
                    self.state = State::KeyString { escape: false };
                } else if b == b'\\' {
                    self.key.push(b);
                    self.state = State::KeyString { escape: true };
                } else if b == b'"' {
                    self.state = State::Colon;
                } else {
                    self.key.push(b);
                }
            }
            State::Colon => match b {
                b':' => self.state = State::ValueStart,
                b if b.is_ascii_whitespace() => {}
                _ => return Err(self.syntax()),
            },
            State::ValueStart => {
                if b.is_ascii_whitespace() {
                    return Ok(());
                }
                let key = std::str::from_utf8(&self.key).unwrap_or_default();
                if b == b'[' && STREAMED.contains(&key) {
                    self.changed = key == "PeersChanged";
                    self.state = State::Array;
                    return Ok(());
                }
                self.keep = KEEP.contains(&key);
                if self.keep {
                    self.start_member();
                    self.rest.push(b);
                }
                self.state = match b {
                    b'{' | b'[' => State::Value {
                        depth: 1,
                        string: false,
                        escape: false,
                        scalar: false,
                    },
                    b'"' => State::Value {
                        depth: 0,
                        string: true,
                        escape: false,
                        scalar: false,
                    },
                    _ => State::Value {
                        depth: 0,
                        string: false,
                        escape: false,
                        scalar: true,
                    },
                };
            }
            State::Value {
                depth,
                string,
                escape,
                scalar,
            } => {
                if scalar {
                    // Numbers and literals end at the next delimiter, which
                    // is then read as what follows the value.
                    if matches!(b, b',' | b'}') || b.is_ascii_whitespace() {
                        self.state = State::Key;
                        return self.byte(b);
                    }
                    if self.keep {
                        self.rest.push(b);
                    }
                    return Ok(());
                }
                if self.keep {
                    self.rest.push(b);
                }
                let (mut depth, mut string, mut escape) = (depth, string, escape);
                if string {
                    if escape {
                        escape = false;
                    } else if b == b'\\' {
                        escape = true;
                    } else if b == b'"' {
                        string = false;
                    }
                } else {
                    match b {
                        b'"' => string = true,
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => depth = depth.checked_sub(1).ok_or_else(|| self.syntax())?,
                        _ => {}
                    }
                }
                self.state = if depth == 0 && !string {
                    State::Key // `,` or `}` follows; Key handles both.
                } else {
                    State::Value {
                        depth,
                        string,
                        escape,
                        scalar: false,
                    }
                };
            }
            State::Array => match b {
                b'{' => {
                    self.element.clear();
                    self.element.push(b);
                    self.state = State::Element {
                        depth: 1,
                        string: false,
                        escape: false,
                    };
                }
                b']' => self.state = State::Key,
                b',' => {}
                b if b.is_ascii_whitespace() => {}
                // `null` elements do not occur; anything else is malformed.
                _ => return Err(self.syntax()),
            },
            State::Element {
                depth,
                string,
                escape,
            } => {
                self.element.push(b);
                let (mut depth, mut string, mut escape) = (depth, string, escape);
                if string {
                    if escape {
                        escape = false;
                    } else if b == b'\\' {
                        escape = true;
                    } else if b == b'"' {
                        string = false;
                    }
                } else {
                    match b {
                        b'"' => string = true,
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => depth = depth.checked_sub(1).ok_or_else(|| self.syntax())?,
                        _ => {}
                    }
                }
                if depth == 0 && !string {
                    let peer: Peer = serde_json::from_slice(&self.element)?;
                    if self.changed {
                        self.peers_changed.push(peer);
                    } else {
                        self.peers.push(peer);
                    }
                    self.element.clear();
                    if self.element.capacity() > 64 << 10 {
                        // One huge node should not pin memory for the rest.
                        self.element = Vec::new();
                    }
                    self.state = State::Array;
                } else {
                    self.state = State::Element {
                        depth,
                        string,
                        escape,
                    };
                }
            }
            State::Done => {
                if !b.is_ascii_whitespace() {
                    return Err(self.syntax());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#" {
        "KeepAlive": false,
        "UserProfiles": [{"ID": 1, "LoginName": "a}b\"[", "DisplayName": "x"}],
        "Node": {"ID": 1, "Name": "me.tail.", "Addresses": ["100.64.0.2/32"],
                 "Hostinfo": {"Hostname": "me", "Services": [{"Proto": "tcp", "Port": 22}]}},
        "Peers": [
            {"ID": 2, "Name": "peer-{a}.tail.", "Addresses": ["100.64.0.3/32"], "DERP": "127.3.3.40:1",
             "Hostinfo": {"Hostname": "p", "OSVersion": "\"quoted\" ]"}},
            {"ID": 3, "Name": "q.tail.", "Addresses": ["100.64.0.4/32"], "HomeDERP": 2, "Endpoints": null}
        ],
        "PeersChanged": null,
        "PacketFilter": [{"SrcIPs": ["*"], "DstPorts": [{"IP": "*", "Ports": {"First": 0, "Last": 65535}}]}],
        "DERPMap": {"Regions": {"1": {"RegionID": 1, "Nodes": [{"Name": "t1", "HostName": "d"}]}}},
        "Domain": "tail",
        "PeersRemoved": [9, 10],
        "ControlTime": "2026-09-28T12:00:00Z",
        "Debug": {"x": [1, {"y": "}"}]}
    } "#;

    fn in_pieces(json: &str, size: usize) -> MapResponse {
        let mut r = MapReader::new();
        for chunk in json.as_bytes().chunks(size) {
            r.feed(chunk).unwrap();
        }
        r.finish().unwrap()
    }

    #[test]
    fn matches_a_whole_parse_in_any_chunking() {
        let whole: MapResponse = serde_json::from_str(SAMPLE).unwrap();
        for size in [1, 2, 7, 64, 4096] {
            let r = in_pieces(SAMPLE, size);
            assert_eq!(r.peers, whole.peers, "chunks of {size}");
            assert_eq!(r.node, whole.node);
            assert_eq!(r.domain, "tail");
            assert_eq!(r.peers_removed, vec![9, 10]);
            assert!(r.derp_map.is_some());
            assert!(!r.keep_alive);
        }
        let r = in_pieces(SAMPLE, 5);
        assert_eq!(r.peers.len(), 2);
        assert_eq!(&*r.peers[0].name, "peer-{a}.tail");
        assert_eq!(r.peers[1].home_region, Some(2));
    }

    #[test]
    fn skipped_members_are_not_kept() {
        let mut r = MapReader::new();
        r.feed(SAMPLE.as_bytes()).unwrap();
        let rest = String::from_utf8(r.rest.clone()).unwrap();
        assert!(!rest.contains("UserProfiles") && !rest.contains("Debug"));
        // Enforced by the node, so kept.
        assert!(rest.contains("PacketFilter"));
        assert!(!rest.contains("peer-{a}"), "peers are streamed, not kept");
    }

    #[test]
    fn keepalives_and_deltas() {
        assert!(in_pieces(r#"{"KeepAlive":true}"#, 3).keep_alive);
        let r = in_pieces(
            r#"{"PeersChanged":[{"ID":5,"Name":"n"}],"OnlineChange":{"5":true}}"#,
            4,
        );
        assert_eq!(r.peers_changed.len(), 1);
        assert_eq!(r.online_change.get(&5), Some(&true));
    }

    #[test]
    fn malformed_input_is_an_error() {
        for bad in [r#"["#, r#"{"Peers":[1]}"#, r#"{"A" 1}"#, r#"{"A":1} x"#] {
            let mut r = MapReader::new();
            let fed = r.feed(bad.as_bytes());
            assert!(fed.is_err() || r.finish().is_err(), "{bad}");
        }
    }
}
