//! HPACK (RFC 7541): header compression for HTTP/2.
//!
//! The decoder is complete: the static and dynamic tables, table size
//! updates, every literal form, Huffman-coded strings (Go's encoder indexes
//! into the dynamic table and Huffman-codes whenever that is shorter). The
//! encoder uses only the static table and plain literals, never indexing,
//! so it keeps no state: the decoder on the other side keeps none for us
//! either.

use alloc::collections::VecDeque;

#[allow(unused_imports)]
use crate::prelude::*;

#[cfg(test)]
use super::huffman_table::CODES;
use super::huffman_table::{COUNTS, SYMBOLS};

/// A header field: name and value as bytes (names are lowercase in HTTP/2).
pub type Header = (Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HpackError {
    #[error("hpack: truncated header block")]
    Truncated,
    #[error("hpack: integer overflow")]
    Integer,
    #[error("hpack: index {0} out of range")]
    Index(usize),
    #[error("hpack: bad Huffman code")]
    Huffman,
    #[error("hpack: a table size update to {0} over the limit")]
    TableSize(usize),
    #[error("hpack: a table size update after the first field")]
    LateSizeUpdate,
    #[error("hpack: the header list is over {0} bytes")]
    ListTooLarge(usize),
}

/// RFC 7541 Appendix A.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// What an entry costs in the dynamic table (RFC 7541 §4.1).
fn entry_size(name: &[u8], value: &[u8]) -> usize {
    name.len() + value.len() + 32
}

/// The decoding side of one HTTP/2 connection.
pub struct Decoder {
    /// Newest first.
    table: VecDeque<Header>,
    size: usize,
    /// The table's size now (the encoder may lower it, up to `limit`).
    max_size: usize,
    /// What we allow (our SETTINGS_HEADER_TABLE_SIZE).
    limit: usize,
}

impl Decoder {
    pub fn new(limit: usize) -> Self {
        Self {
            table: VecDeque::new(),
            size: 0,
            max_size: limit,
            limit,
        }
    }

    /// Decode one complete header block (HEADERS plus CONTINUATIONs).
    /// `max_list`: the most the decoded list may take (names, values and
    /// 32 bytes each, as SETTINGS_MAX_HEADER_LIST_SIZE counts).
    pub fn decode(&mut self, mut block: &[u8], max_list: usize) -> Result<Vec<Header>, HpackError> {
        let mut headers = Vec::new();
        let mut list = 0usize;
        while let Some(&first) = block.first() {
            let header = if first & 0x80 != 0 {
                // Indexed field.
                let index = integer(&mut block, 7)?;
                self.get(index)?
            } else if first & 0xe0 == 0x20 {
                // Dynamic table size update: only before the first field.
                if !headers.is_empty() {
                    return Err(HpackError::LateSizeUpdate);
                }
                let size = integer(&mut block, 5)?;
                if size > self.limit {
                    return Err(HpackError::TableSize(size));
                }
                self.max_size = size;
                self.evict(0);
                continue;
            } else {
                // A literal: with incremental indexing (01), without (0000)
                // or never indexed (0001).
                let (prefix, index) = if first & 0xc0 == 0x40 {
                    (6, true)
                } else {
                    (4, false)
                };
                let name_index = integer(&mut block, prefix)?;
                let name = if name_index == 0 {
                    string(&mut block)?
                } else {
                    self.get(name_index)?.0
                };
                let value = string(&mut block)?;
                if index {
                    self.insert(name.clone(), value.clone());
                }
                (name, value)
            };
            list += entry_size(&header.0, &header.1);
            if list > max_list {
                return Err(HpackError::ListTooLarge(max_list));
            }
            headers.push(header);
        }
        Ok(headers)
    }

    fn get(&self, index: usize) -> Result<Header, HpackError> {
        match index {
            0 => Err(HpackError::Index(0)),
            1..=61 => {
                let (n, v) = STATIC[index - 1];
                Ok((n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            }
            _ => self
                .table
                .get(index - 62)
                .cloned()
                .ok_or(HpackError::Index(index)),
        }
    }

    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let size = entry_size(&name, &value);
        // An entry larger than the table empties it and is not added.
        self.evict(size);
        if size <= self.max_size {
            self.size += size;
            self.table.push_front((name, value));
        }
    }

    /// Evict until `room` more fits (or the table is empty).
    fn evict(&mut self, room: usize) {
        while self.size + room > self.max_size {
            match self.table.pop_back() {
                Some((n, v)) => self.size -= entry_size(&n, &v),
                None => break,
            }
        }
    }

    /// The dynamic table's size now.
    #[cfg(test)]
    pub fn table_size(&self) -> usize {
        self.size
    }
}

/// Encode a header block: static-table indices where they match, plain
/// literals without indexing otherwise.
pub fn encode(headers: &[(&str, &str)], out: &mut Vec<u8>) {
    for &(name, value) in headers {
        if let Some(i) = STATIC.iter().position(|&e| e == (name, value)) {
            put_integer(out, 0x80, 7, i + 1);
            continue;
        }
        // Literal without indexing, the name indexed if the table has it.
        match STATIC.iter().position(|&(n, _)| n == name) {
            Some(i) => put_integer(out, 0x00, 4, i + 1),
            None => {
                out.push(0x00);
                put_string(out, name.as_bytes());
            }
        }
        put_string(out, value.as_bytes());
    }
}

/// An integer with an `n`-bit prefix (RFC 7541 §5.1).
fn integer(block: &mut &[u8], n: u8) -> Result<usize, HpackError> {
    let (&first, rest) = block.split_first().ok_or(HpackError::Truncated)?;
    *block = rest;
    let max = (1usize << n) - 1;
    let mut value = usize::from(first) & max;
    if value < max {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let (&b, rest) = block.split_first().ok_or(HpackError::Truncated)?;
        *block = rest;
        // Anything past 28 bits is more than any table or length here.
        if shift > 21 {
            return Err(HpackError::Integer);
        }
        value += usize::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

fn put_integer(out: &mut Vec<u8>, flags: u8, n: u8, value: usize) {
    let max = (1usize << n) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = value - max;
    while rest >= 0x80 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

fn string(block: &mut &[u8]) -> Result<Vec<u8>, HpackError> {
    let huffman = block.first().ok_or(HpackError::Truncated)? & 0x80 != 0;
    let len = integer(block, 7)?;
    if block.len() < len {
        return Err(HpackError::Truncated);
    }
    let (data, rest) = block.split_at(len);
    *block = rest;
    if huffman {
        huffman_decode(data)
    } else {
        Ok(data.to_vec())
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    put_integer(out, 0x00, 7, s.len());
    out.extend_from_slice(s);
}

/// Decode a Huffman-coded string: canonical decoding, bit by bit, from the
/// count of codes per length. The padding is at most 7 bits, all ones (a
/// prefix of EOS); EOS itself is an error.
fn huffman_decode(data: &[u8]) -> Result<Vec<u8>, HpackError> {
    let mut out = Vec::with_capacity(data.len() * 8 / 5);
    // The code read so far, its length, and where codes of that length
    // start (as a code, and as an index into SYMBOLS).
    let (mut code, mut len) = (0u32, 0usize);
    let (mut first, mut index) = (0u32, 0usize);
    for &byte in data {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            first <<= 1;
            let count = u32::from(*COUNTS.get(len).ok_or(HpackError::Huffman)?);
            if code - first < count {
                let symbol = SYMBOLS[index + (code - first) as usize];
                if symbol == 256 {
                    return Err(HpackError::Huffman);
                }
                out.push(symbol as u8);
                (code, len, first, index) = (0, 0, 0, 0);
            } else {
                first += count;
                index += count as usize;
            }
        }
    }
    // Padding: fewer than 8 bits, all ones.
    if len > 7 || code != (1 << len) - 1 {
        return Err(HpackError::Huffman);
    }
    Ok(out)
}

/// Huffman-code `s` (the tests' encoder; ours sends plain literals).
#[cfg(test)]
pub fn huffman_encode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u64, 0u32);
    for &b in s {
        let (code, len) = CODES[usize::from(b)];
        acc = (acc << len) | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (8 - bits)) as u8) | (0xff >> bits));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        hex::decode(s).unwrap()
    }

    fn pairs(headers: &[Header]) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|(n, v)| {
                (
                    String::from_utf8(n.clone()).unwrap(),
                    String::from_utf8(v.clone()).unwrap(),
                )
            })
            .collect()
    }

    fn owned(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn the_code_is_canonical() {
        // Rebuild every code from the lengths alone: the decoder relies on it.
        let mut code = 0u32;
        let mut prev = 0u8;
        for (i, &s) in SYMBOLS.iter().enumerate() {
            let (c, l) = CODES[usize::from(s)];
            if i > 0 {
                code = (code + 1) << (l - prev);
            }
            prev = l;
            assert_eq!(code, c, "symbol {s}");
        }
    }

    #[test]
    fn rfc_huffman_examples() {
        // RFC 7541 C.4.1–C.4.3.
        assert_eq!(
            huffman_encode(b"www.example.com"),
            hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff")
        );
        assert_eq!(huffman_encode(b"no-cache"), hex("a8eb 1064 9cbf"));
        assert_eq!(huffman_encode(b"custom-key"), hex("25a8 49e9 5ba9 7d7f"));
        assert_eq!(
            huffman_encode(b"custom-value"),
            hex("25a8 49e9 5bb8 e8b4 bf")
        );
        for s in ["www.example.com", "no-cache", "custom-key", "custom-value"] {
            assert_eq!(
                huffman_decode(&huffman_encode(s.as_bytes())).unwrap(),
                s.as_bytes()
            );
        }
    }

    #[test]
    fn huffman_round_trips_every_byte() {
        let all: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
        assert_eq!(huffman_decode(&huffman_encode(&all)).unwrap(), all);
        assert_eq!(huffman_decode(&[]).unwrap(), b"");
    }

    #[test]
    fn huffman_padding_and_eos_are_checked() {
        // 'a' is 00011 (5 bits): three padding ones complete the byte.
        assert_eq!(huffman_decode(&[0b0001_1111]).unwrap(), b"a");
        // Padding with a zero.
        assert_eq!(huffman_decode(&[0b0001_1110]), Err(HpackError::Huffman));
        // A whole byte of padding is too much.
        assert_eq!(
            huffman_decode(&[0b0001_1111, 0xff]),
            Err(HpackError::Huffman)
        );
        // EOS (30 ones) inside the string.
        assert_eq!(
            huffman_decode(&[0xff, 0xff, 0xff, 0xff]),
            Err(HpackError::Huffman)
        );
    }

    #[test]
    fn rfc_requests_with_huffman_share_the_dynamic_table() {
        // RFC 7541 C.4: three requests on one connection.
        let mut d = Decoder::new(4096);
        let first = d
            .decode(&hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"), 1 << 16)
            .unwrap();
        assert_eq!(
            pairs(&first),
            owned(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ])
        );
        assert_eq!(d.table_size(), 57);
        let second = d
            .decode(&hex("8286 84be 5886 a8eb 1064 9cbf"), 1 << 16)
            .unwrap();
        assert_eq!(
            pairs(&second),
            owned(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ])
        );
        assert_eq!(d.table_size(), 110);
        let third = d
            .decode(
                &hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"),
                1 << 16,
            )
            .unwrap();
        assert_eq!(
            pairs(&third),
            owned(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ])
        );
        assert_eq!(d.table_size(), 164);
    }

    #[test]
    fn eviction_and_size_updates() {
        // A 64-byte table holds one 'k'/'v' pair (34 bytes) but not two.
        let mut d = Decoder::new(64);
        // Literal with indexing, new name: 40 01 'a' 01 'b'.
        d.decode(&[0x40, 1, b'a', 1, b'b'], 1 << 16).unwrap();
        d.decode(&[0x40, 1, b'c', 1, b'd'], 1 << 16).unwrap();
        assert_eq!(d.table_size(), 34);
        // Index 62 is the newest: c: d. 63 is gone.
        assert_eq!(
            pairs(&d.decode(&[0x80 | 62], 1 << 16).unwrap()),
            owned(&[("c", "d")])
        );
        assert_eq!(d.decode(&[0x80 | 63], 1 << 16), Err(HpackError::Index(63)));
        // A size update to 0 empties it; over the limit is an error, and so
        // is one after a field.
        d.decode(&[0x20], 1 << 16).unwrap();
        assert_eq!(d.table_size(), 0);
        assert_eq!(
            d.decode(&[0x3f, 0x22], 1 << 16),
            Err(HpackError::TableSize(65))
        );
        assert_eq!(
            d.decode(&[0x82, 0x20], 1 << 16),
            Err(HpackError::LateSizeUpdate)
        );
        // Back up to the limit, then an entry that does not fit is not kept.
        d.decode(&[0x3f, 0x21], 1 << 16).unwrap();
        let big = [0x40, 1, b'x', 0x7f, 0x01];
        let mut block = big.to_vec();
        block.extend(core::iter::repeat_n(b'y', 128));
        d.decode(&block, 1 << 16).unwrap();
        assert_eq!(d.table_size(), 0);
    }

    #[test]
    fn integers_and_limits() {
        // RFC 7541 C.1.2: 1337 with a 5-bit prefix.
        let mut b: &[u8] = &[0x1f, 0x9a, 0x0a];
        assert_eq!(integer(&mut b, 5).unwrap(), 1337);
        let mut out = Vec::new();
        put_integer(&mut out, 0, 5, 1337);
        assert_eq!(out, [0x1f, 0x9a, 0x0a]);
        let mut b: &[u8] = &[0x1f, 0xff, 0xff, 0xff, 0xff, 0x0f];
        assert_eq!(integer(&mut b, 5), Err(HpackError::Integer));
        let mut d = Decoder::new(4096);
        assert_eq!(
            d.decode(&[0x82, 0x86], 40),
            Err(HpackError::ListTooLarge(40))
        );
        assert_eq!(
            d.decode(&[0x40, 3, b'a'], 1 << 16),
            Err(HpackError::Truncated)
        );
    }

    #[test]
    fn what_we_encode_decodes() {
        let headers = [
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/machine/map"),
            (":authority", "control.example"),
            ("content-type", "application/json"),
            ("ts-lb", "nodekey:abcd"),
        ];
        let mut block = Vec::new();
        encode(&headers, &mut block);
        let mut d = Decoder::new(4096);
        assert_eq!(pairs(&d.decode(&block, 1 << 16).unwrap()), owned(&headers));
        // Stateless: nothing went into the table.
        assert_eq!(d.table_size(), 0);
    }
}
