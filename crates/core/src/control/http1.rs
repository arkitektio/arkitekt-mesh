//! The little HTTP/1.1 control and DERP need before their own protocols
//! take over: a request line and headers out, a response head in (and the
//! bytes after it kept: an upgraded protocol may start in the same read),
//! a small body read to the end.

#[allow(unused_imports)]
use crate::prelude::*;

/// The most a response head may take.
pub const MAX_HEAD: usize = 64 << 10;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Http1Error {
    #[error("the response head is over {MAX_HEAD} bytes")]
    HeadTooLarge,
    #[error("a malformed response head")]
    Malformed,
    #[error("a malformed chunked body")]
    Chunked,
}

/// A response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A request head (`extra`: whole header lines without CRLF).
pub fn request(method: &str, path: &str, authority: &str, extra: &[&str]) -> Vec<u8> {
    let mut r =
        format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: arkitekt-mesh\r\n");
    for line in extra {
        r.push_str(line);
        r.push_str("\r\n");
    }
    r.push_str("\r\n");
    r.into_bytes()
}

/// The response head at the start of `buf`, and the bytes it took;
/// `Ok(None)` while it is incomplete.
pub fn parse_head(buf: &[u8]) -> Result<Option<(Head, usize)>, Http1Error> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() > MAX_HEAD {
            Err(Http1Error::HeadTooLarge)
        } else {
            Ok(None)
        };
    };
    let text = core::str::from_utf8(&buf[..end]).map_err(|_| Http1Error::Malformed)?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .filter(|l| l.starts_with("HTTP/1."))
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or(Http1Error::Malformed)?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Ok(Some((Head { status, headers }, end + 4)))
}

/// A body read to the connection's end, as `head` frames it: chunked,
/// cut at Content-Length, or all of it.
pub fn body(head: &Head, mut raw: Vec<u8>) -> Result<Vec<u8>, Http1Error> {
    if head
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        return dechunk(&raw);
    }
    if let Some(len) = head
        .header("content-length")
        .and_then(|l| l.parse::<usize>().ok())
    {
        raw.truncate(len);
    }
    Ok(raw)
}

/// A chunked body, whole.
pub fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, Http1Error> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(Http1Error::Chunked)?;
        let size_text = core::str::from_utf8(&body[..line_end]).map_err(|_| Http1Error::Chunked)?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| Http1Error::Chunked)?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(body.get(..size).ok_or(Http1Error::Chunked)?);
        body = body.get(size + 2..).ok_or(Http1Error::Chunked)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_keep_what_follows() {
        let raw = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\n\x02\x00";
        assert_eq!(parse_head(&raw[..20]).unwrap(), None);
        let (head, used) = parse_head(raw).unwrap().unwrap();
        assert_eq!(head.status, 101);
        assert_eq!(head.header("upgrade"), Some("x"));
        assert_eq!(&raw[used..], b"\x02\x00");
        assert_eq!(parse_head(b"SSH-2.0\r\n\r\n"), Err(Http1Error::Malformed));
        assert_eq!(
            parse_head(&vec![b'a'; MAX_HEAD + 1]),
            Err(Http1Error::HeadTooLarge)
        );
    }

    #[test]
    fn bodies() {
        let head = |h: &[(&str, &str)]| Head {
            status: 200,
            headers: h
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };
        let chunked = head(&[("Transfer-Encoding", "chunked")]);
        assert_eq!(
            body(&chunked, b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n".to_vec()).unwrap(),
            b"abcde"
        );
        assert_eq!(
            body(&chunked, b"5\r\nab".to_vec()),
            Err(Http1Error::Chunked)
        );
        assert_eq!(
            body(&head(&[("content-length", "2")]), b"abcd".to_vec()).unwrap(),
            b"ab"
        );
        assert_eq!(body(&head(&[]), b"abcd".to_vec()).unwrap(), b"abcd");
    }

    #[test]
    fn requests() {
        assert_eq!(
            request("GET", "/key?v=1", "c.example", &["Connection: close"]),
            b"GET /key?v=1 HTTP/1.1\r\nHost: c.example\r\nUser-Agent: arkitekt-mesh\r\nConnection: close\r\n\r\n"
        );
    }
}
