//! UPnP IGD (docs/rfc3-nat-port-mapping.md), sans-IO: the SSDP search for
//! the gateway, its description, and the SOAP calls that map a port. Many
//! home routers speak only this.
//!
//! 1. An SSDP `M-SEARCH` (UDP, to the gateway's port 1900 or the multicast
//!    group); the answer's `LOCATION` is the description's URL.
//! 2. `GET` the description; its WAN connection service has a control URL.
//! 3. SOAP `GetExternalIPAddress`, then `AddPortMapping` for our UDP port.
//!
//! Just enough HTTP/1.1 and XML for what routers send: fields are found by
//! their tags, no parser.

#[allow(unused_imports)]
use crate::prelude::*;
use core::net::{Ipv4Addr, SocketAddr};

/// The SSDP port; also the multicast group's.
pub const SSDP_PORT: u16 = 1900;
/// Where SSDP searches go when the gateway itself does not answer them.
pub const SSDP_MULTICAST: SocketAddr = SocketAddr::new(
    core::net::IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
    SSDP_PORT,
);

/// The devices searched for, newest first.
pub const GATEWAYS: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
];

/// The services that map ports, in the order they are preferred.
const SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

/// `AddPortMapping`'s fault when the external port is someone else's.
pub const CONFLICT: u16 = 718;
/// `AddPortMapping`'s fault when only leases of 0 (permanent) are taken.
pub const ONLY_PERMANENT: u16 = 725;

/// What a mapping is called on the router's page.
const DESCRIPTION: &str = "arkitekt-mesh";
/// Responses larger than this are not a router's.
pub const MAX_RESPONSE: usize = 64 << 10;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpnpError {
    #[error("malformed response")]
    Malformed,
    #[error("HTTP status {0}")]
    Http(u16),
    #[error("UPnP error {0}")]
    Fault(u16),
}

/// An `http://` URL (UPnP is plain HTTP on the LAN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    /// With its query, starting with `/`.
    pub path: String,
}

impl Url {
    pub fn parse(url: &str) -> Option<Self> {
        let rest = strip_prefix_ignore_case(url.trim(), "http://")?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (authority, 80),
        };
        if host.is_empty() {
            return None;
        }
        Some(Self {
            host: host.to_owned(),
            port,
            path: path.to_owned(),
        })
    }

    /// `reference` (absolute, or a path) resolved against this URL.
    pub fn join(&self, reference: &str) -> Option<Self> {
        let reference = reference.trim();
        if reference.is_empty() {
            return None;
        }
        if strip_prefix_ignore_case(reference, "http://").is_some() {
            return Self::parse(reference);
        }
        let path = if reference.starts_with('/') {
            reference.to_owned()
        } else {
            // Relative to the directory of this URL's path.
            let dir = &self.path[..self.path.rfind('/').map_or(0, |i| i + 1)];
            format!("{}{reference}", if dir.is_empty() { "/" } else { dir })
        };
        Some(Self {
            host: self.host.clone(),
            port: self.port,
            path,
        })
    }

    fn host_header(&self) -> String {
        if self.port == 80 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

// --- SSDP -------------------------------------------------------------------

/// An `M-SEARCH` for the device type `target` (one of [`GATEWAYS`]).
pub fn ssdp_search(target: &str) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 1\r\n\
         ST: {target}\r\n\r\n"
    )
    .into_bytes()
}

/// The description's URL from an answer to [`ssdp_search`].
pub fn ssdp_location(answer: &[u8]) -> Option<Url> {
    let text = core::str::from_utf8(answer).ok()?;
    let mut lines = text.split("\r\n");
    let status = lines.next()?;
    if !status.starts_with("HTTP/1.") || status.split_whitespace().nth(1) != Some("200") {
        return None;
    }
    lines
        .find_map(|line| header(line, "location"))
        .and_then(Url::parse)
}

fn header<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
}

// --- HTTP/1.1 ---------------------------------------------------------------

/// `GET url`, the connection closed after the response.
pub fn http_get(url: &Url) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url.path,
        url.host_header()
    )
    .into_bytes()
}

/// Whether `raw` holds a whole response: its headers and the body their
/// `Content-Length` or chunks announce. Without either, only the server
/// closing ends it.
pub fn http_complete(raw: &[u8]) -> bool {
    let Some((head, body)) = split_head(raw) else {
        return false;
    };
    match framing(head) {
        Framing::Length(n) => body.len() >= n,
        Framing::Chunked => unchunk(body).is_some(),
        Framing::Close => false,
    }
}

/// A whole response (read until [`http_complete`], or until the server
/// closed): its status and body.
pub fn http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), UpnpError> {
    let (head, body) = split_head(raw).ok_or(UpnpError::Malformed)?;
    let status_line = head.split("\r\n").next().ok_or(UpnpError::Malformed)?;
    if !status_line.starts_with("HTTP/1.") {
        return Err(UpnpError::Malformed);
    }
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(UpnpError::Malformed)?;
    let body = match framing(head) {
        Framing::Length(n) => body.get(..n).ok_or(UpnpError::Malformed)?.to_vec(),
        Framing::Chunked => unchunk(body).ok_or(UpnpError::Malformed)?,
        Framing::Close => body.to_vec(),
    };
    Ok((status, body))
}

enum Framing {
    Length(usize),
    Chunked,
    Close,
}

fn split_head(raw: &[u8]) -> Option<(&str, &[u8])> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some((core::str::from_utf8(&raw[..end]).ok()?, &raw[end + 4..]))
}

fn framing(head: &str) -> Framing {
    let mut length = None;
    for line in head.split("\r\n").skip(1) {
        if header(line, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
            return Framing::Chunked;
        }
        if let Some(n) = header(line, "content-length").and_then(|v| v.parse().ok()) {
            length = Some(n);
        }
    }
    length.map_or(Framing::Close, Framing::Length)
}

/// A chunked body joined; `None` until its last chunk arrived.
fn unchunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let size_line = core::str::from_utf8(&body[..line_end]).ok()?;
        let size = usize::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}

// --- The description --------------------------------------------------------

/// The gateway's port-mapping service: its type and control URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub service: String,
    pub url: Url,
}

/// The preferred WAN connection service in a description fetched from
/// `location`.
pub fn control_url(description: &str, location: &Url) -> Option<Control> {
    let base = tag(description, "URLBase")
        .and_then(Url::parse)
        .unwrap_or_else(|| location.clone());
    let services: Vec<(&str, &str)> = elements(description, "service")
        .filter_map(|s| Some((tag(s, "serviceType")?.trim(), tag(s, "controlURL")?)))
        .collect();
    SERVICES.iter().find_map(|wanted| {
        let (service, control) = services.iter().find(|(t, _)| t == wanted)?;
        Some(Control {
            service: (*service).to_owned(),
            url: base.join(&unescape(control))?,
        })
    })
}

/// The text of the first `<name>` element (or `<prefix:name>`).
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    elements(xml, name).next()
}

/// The contents of every `<name>…</name>` (any namespace prefix).
fn elements<'a>(xml: &'a str, name: &str) -> impl Iterator<Item = &'a str> + 'a {
    let name = name.to_owned();
    let mut rest = xml;
    core::iter::from_fn(move || loop {
        let open = rest.find('<')?;
        rest = &rest[open + 1..];
        let end = rest.find('>')?;
        let opening = &rest[..end];
        let element = opening.split_whitespace().next().unwrap_or("");
        let local = element.rsplit(':').next().unwrap_or("");
        if opening.starts_with('/') || local != name || opening.ends_with('/') {
            continue;
        }
        let body = &rest[end + 1..];
        let close = closing(body, element)?;
        rest = &body[close..];
        return Some(&body[..close]);
    })
}

/// Where `</element>` starts in `body`.
fn closing(body: &str, element: &str) -> Option<usize> {
    body.find(&format!("</{element}>"))
}

fn unescape(s: &str) -> String {
    s.trim()
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

// --- SOAP -------------------------------------------------------------------

fn soap(control: &Control, action: &str, args: &[(&str, String)]) -> Vec<u8> {
    let mut arguments = String::new();
    for (name, value) in args {
        arguments.push_str(&format!("<{name}>{value}</{name}>"));
    }
    let body = format!(
        "<?xml version=\"1.0\"?>\r\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{service}\">{arguments}</u:{action}></s:Body>\
         </s:Envelope>\r\n",
        service = control.service,
    );
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{service}#{action}\"\r\n\
         Content-Length: {length}\r\n\
         Connection: close\r\n\r\n{body}",
        path = control.url.path,
        host = control.url.host_header(),
        service = control.service,
        length = body.len(),
    )
    .into_bytes()
}

/// Ask for the gateway's public address.
pub fn get_external_ip(control: &Control) -> Vec<u8> {
    soap(control, "GetExternalIPAddress", &[])
}

/// Forward UDP `external` on the gateway to `client:internal` for `lease`
/// seconds (0: until deleted, for gateways that take nothing else).
pub fn add_port_mapping(
    control: &Control,
    external: u16,
    internal: u16,
    client: Ipv4Addr,
    lease: u32,
) -> Vec<u8> {
    soap(
        control,
        "AddPortMapping",
        &[
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external.to_string()),
            ("NewProtocol", "UDP".into()),
            ("NewInternalPort", internal.to_string()),
            ("NewInternalClient", client.to_string()),
            ("NewEnabled", "1".into()),
            ("NewPortMappingDescription", DESCRIPTION.into()),
            ("NewLeaseDuration", lease.to_string()),
        ],
    )
}

/// Remove the mapping of UDP `external`.
pub fn delete_port_mapping(control: &Control, external: u16) -> Vec<u8> {
    soap(
        control,
        "DeletePortMapping",
        &[
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external.to_string()),
            ("NewProtocol", "UDP".into()),
        ],
    )
}

/// A SOAP call's outcome from its response's status and body.
pub fn soap_result(status: u16, body: &[u8]) -> Result<(), UpnpError> {
    let text = core::str::from_utf8(body).map_err(|_| UpnpError::Malformed)?;
    if status == 200 {
        return Ok(());
    }
    match tag(text, "errorCode").and_then(|c| c.trim().parse().ok()) {
        Some(code) => Err(UpnpError::Fault(code)),
        None => Err(UpnpError::Http(status)),
    }
}

/// The address in a `GetExternalIPAddress` response.
pub fn parse_external_ip(status: u16, body: &[u8]) -> Result<Ipv4Addr, UpnpError> {
    soap_result(status, body)?;
    let text = core::str::from_utf8(body).map_err(|_| UpnpError::Malformed)?;
    tag(text, "NewExternalIPAddress")
        .and_then(|ip| ip.trim().parse().ok())
        .ok_or(UpnpError::Malformed)
}

/// Whether a gateway's "public" address is one peers can reach: not
/// private, shared (CGNAT) or unspecified, as behind a second NAT. (No
/// router's is loopback; the tests' fake gateway's is.)
pub fn is_public(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    let shared = a == 100 && (64..128).contains(&b);
    !(ip.is_private() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast() || shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// miniupnpd's answer to an M-SEARCH.
    const SSDP_MINIUPNPD: &str = "HTTP/1.1 200 OK\r\n\
        CACHE-CONTROL: max-age=120\r\n\
        ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
        USN: uuid:6e6f2a5d-a37f-4b2e-a4a7-1f3c7a2f9c11::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
        EXT:\r\n\
        SERVER: OpenWRT/22.03 UPnP/1.1 MiniUPnPd/2.3.3\r\n\
        LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\
        OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n\r\n";

    /// A Fritz!Box's (lower-case header, port 49000).
    const SSDP_FRITZBOX: &str = "HTTP/1.1 200 OK\r\n\
        Location: http://192.168.178.1:49000/igddesc.xml\r\n\
        Server: FRITZ!Box 7590 UPnP/1.0 AVM FRITZ!Box 7590 154.07.57\r\n\
        Cache-Control: max-age=1800\r\n\
        Ext:\r\n\
        ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";

    /// miniupnpd's description, trimmed to its devices and services.
    const DESC_MINIUPNPD: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<specVersion><major>1</major><minor>1</minor></specVersion>
<device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<serviceList><service>
<serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
<serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId>
<controlURL>/ctl/L3F</controlURL>
</service></serviceList>
<deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
<controlURL>/ctl/IPConn</controlURL>
<eventSubURL>/evt/IPConn</eventSubURL>
<SCPDURL>/WANIPCn.xml</SCPDURL>
</service></serviceList>
</device></deviceList>
</device></deviceList>
</device>
</root>"#;

    /// A Fritz!Box's: a PPP and an IP connection, URLBase-less, paths
    /// without the leading slash in one case.
    const DESC_FRITZBOX: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<device><deviceList><device><deviceList><device>
<serviceList>
<service>
<serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
<controlURL>/igdupnp/control/WANPPPConn1</controlURL>
</service>
<service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>igdupnp/control/WANIPConn1</controlURL>
</service>
</serviceList>
</device></deviceList></device></deviceList></device>
</root>"#;

    #[test]
    fn a_search_names_its_target() {
        let search = String::from_utf8(ssdp_search(GATEWAYS[1])).unwrap();
        assert!(search.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(search.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(search.contains(&format!("ST: {}\r\n", GATEWAYS[1])));
        assert!(search.ends_with("\r\n\r\n"));
    }

    #[test]
    fn answers_give_the_description_url() {
        assert_eq!(
            ssdp_location(SSDP_MINIUPNPD.as_bytes()),
            Url::parse("http://192.168.1.1:5000/rootDesc.xml")
        );
        let fritz = ssdp_location(SSDP_FRITZBOX.as_bytes()).unwrap();
        assert_eq!(
            (fritz.host.as_str(), fritz.port, fritz.path.as_str()),
            ("192.168.178.1", 49000, "/igddesc.xml")
        );
        // A search (not an answer), and an error status.
        assert_eq!(ssdp_location(&ssdp_search(GATEWAYS[0])), None);
        assert_eq!(
            ssdp_location(b"HTTP/1.1 404 Not Found\r\nLOCATION: http://a/b\r\n\r\n"),
            None
        );
    }

    #[test]
    fn urls_parse_and_join() {
        let base = Url::parse("http://192.168.1.1:5000/dir/rootDesc.xml").unwrap();
        assert_eq!(base.join("/ctl/IPConn").unwrap().path, "/ctl/IPConn");
        assert_eq!(base.join("ctl/IPConn").unwrap().path, "/dir/ctl/IPConn");
        let other = base.join("http://10.0.0.1/c").unwrap();
        assert_eq!((other.host.as_str(), other.port), ("10.0.0.1", 80));
        assert_eq!(Url::parse("http://host").unwrap().path, "/");
        assert_eq!(Url::parse("https://host/"), None);
        assert_eq!(Url::parse("http://:80/"), None);
    }

    #[test]
    fn the_wan_ip_connection_is_found() {
        let location = Url::parse("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        let control = control_url(DESC_MINIUPNPD, &location).unwrap();
        assert_eq!(control.service, SERVICES[1]);
        assert_eq!(control.url, location.join("/ctl/IPConn").unwrap());

        // IP is preferred over PPP; a relative path joins the location's.
        let location = Url::parse("http://192.168.178.1:49000/igddesc.xml").unwrap();
        let control = control_url(DESC_FRITZBOX, &location).unwrap();
        assert_eq!(control.service, SERVICES[1]);
        assert_eq!(control.url.path, "/igdupnp/control/WANIPConn1");

        // URLBase wins over the location; PPP when it is all there is.
        let ppp = r#"<root><URLBase>http://10.1.1.1:2869/</URLBase><service>
            <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
            <controlURL>upnp/control?a=1&amp;b=2</controlURL></service></root>"#;
        let control = control_url(ppp, &location).unwrap();
        assert_eq!(control.service, SERVICES[2]);
        assert_eq!(
            (
                control.url.host.as_str(),
                control.url.port,
                control.url.path.as_str()
            ),
            ("10.1.1.1", 2869, "/upnp/control?a=1&b=2")
        );

        // No WAN connection at all.
        assert_eq!(
            control_url(
                "<root><service><serviceType>x</serviceType></service></root>",
                &location
            ),
            None
        );
    }

    #[test]
    fn soap_requests_carry_the_action_and_its_arguments() {
        let control = Control {
            service: SERVICES[1].into(),
            url: Url::parse("http://192.168.1.1:5000/ctl/IPConn").unwrap(),
        };
        let raw = add_port_mapping(&control, 41641, 41641, Ipv4Addr::new(192, 168, 1, 20), 7200);
        let (head, body) = split_head(&raw).unwrap();
        assert!(head.starts_with("POST /ctl/IPConn HTTP/1.1\r\nHost: 192.168.1.1:5000\r\n"));
        assert!(head.contains(&format!("SOAPAction: \"{}#AddPortMapping\"", SERVICES[1])));
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        let body = core::str::from_utf8(body).unwrap();
        for field in [
            "<NewExternalPort>41641</NewExternalPort>",
            "<NewProtocol>UDP</NewProtocol>",
            "<NewInternalClient>192.168.1.20</NewInternalClient>",
            "<NewLeaseDuration>7200</NewLeaseDuration>",
        ] {
            assert!(body.contains(field), "{field}");
        }
        assert!(body.contains(&format!("<u:AddPortMapping xmlns:u=\"{}\">", SERVICES[1])));
        let delete = String::from_utf8(delete_port_mapping(&control, 41641)).unwrap();
        assert!(delete.contains("#DeletePortMapping\""));
        assert!(delete.contains("<NewExternalPort>41641</NewExternalPort>"));
    }

    #[test]
    fn responses_whole_chunked_or_until_closed() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert!(http_complete(plain));
        assert!(!http_complete(&plain[..plain.len() - 1]));
        assert_eq!(http_response(plain), Ok((200, b"hello".to_vec())));

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6; x=y\r\n world\r\n0\r\n\r\n";
        assert!(http_complete(chunked));
        assert!(!http_complete(&chunked[..chunked.len() - 5]));
        assert_eq!(http_response(chunked), Ok((200, b"hello world".to_vec())));

        let closed = b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\n<root/>";
        assert!(!http_complete(closed));
        assert_eq!(http_response(closed), Ok((200, b"<root/>".to_vec())));

        assert_eq!(http_response(b"garbage"), Err(UpnpError::Malformed));
    }

    #[test]
    fn soap_answers_and_faults() {
        let ok = br#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"#;
        assert_eq!(
            parse_external_ip(200, ok),
            Ok(Ipv4Addr::new(198, 51, 100, 7))
        );

        let fault = |code: u16| {
            format!(
                "<s:Envelope><s:Body><s:Fault><faultcode>s:Client</faultcode>\
                 <faultstring>UPnPError</faultstring><detail>\
                 <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
                 <errorCode>{code}</errorCode><errorDescription>x</errorDescription>\
                 </UPnPError></detail></s:Fault></s:Body></s:Envelope>"
            )
        };
        assert_eq!(
            soap_result(500, fault(CONFLICT).as_bytes()),
            Err(UpnpError::Fault(718))
        );
        assert_eq!(
            soap_result(500, fault(ONLY_PERMANENT).as_bytes()),
            Err(UpnpError::Fault(725))
        );
        assert_eq!(soap_result(404, b"not found"), Err(UpnpError::Http(404)));
        assert_eq!(soap_result(200, b""), Ok(()));
    }

    #[test]
    fn a_second_nat_is_not_public() {
        assert!(is_public(Ipv4Addr::new(198, 51, 100, 7)));
        for ip in [
            Ipv4Addr::new(192, 168, 0, 2),
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::UNSPECIFIED,
        ] {
            assert!(!is_public(ip), "{ip}");
        }
    }
}
