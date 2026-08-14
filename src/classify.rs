//! "what is this?" from the opening bytes of a message.
//!
//! deliberately shallow. the goal is to turn a screen of hex into one line
//! that tells you where to look next, not to decode the protocol. the single
//! highest-value thing in here is pulling SNI out of a TLS ClientHello: an
//! unknown binary names the host it wanted before any key exchange happens,
//! so you learn its destination without terminating anything.

use std::fmt::Write as _;

/// a short human-readable guess, or None when nothing is recognisable.
pub fn classify(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    tls(data)
        .or_else(|| http(data))
        .or_else(|| dns(data))
        .or_else(|| other(data))
}

// ---------------------------------------------------------------- TLS

fn tls_version(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "TLS ?",
    }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn tls(d: &[u8]) -> Option<String> {
    // record header: 0x16 handshake, version, length
    if *d.first()? != 0x16 || *d.get(1)? != 0x03 {
        return None;
    }
    // handshake header: 0x01 ClientHello, 24-bit length
    if *d.get(5)? != 0x01 {
        // still a handshake record, just not a hello we parse
        return Some(format!("{} handshake", tls_version(be16(d, 1)?)));
    }

    let legacy = be16(d, 9)?;
    let mut p = 11 + 32; // client_version + random

    let sid_len = *d.get(p)? as usize;
    p += 1 + sid_len;

    let cs_len = be16(d, p)? as usize;
    let cipher_count = cs_len / 2;
    p += 2 + cs_len;

    let comp_len = *d.get(p)? as usize;
    p += 1 + comp_len;

    let mut out = String::new();
    let mut sni = None;
    let mut alpn: Vec<String> = Vec::new();
    let mut supported_max = legacy;

    // extensions are optional in the wire format
    if let Some(ext_total) = be16(d, p) {
        p += 2;
        let end = (p + ext_total as usize).min(d.len());
        while p + 4 <= end {
            let etype = be16(d, p)?;
            let elen = be16(d, p + 2)? as usize;
            let body = d.get(p + 4..p + 4 + elen)?;
            match etype {
                0x0000 => sni = parse_sni(body),
                0x0010 => alpn = parse_alpn(body),
                0x002b => {
                    // supported_versions: 1-byte list length, then u16 versions
                    if let Some(&n) = body.first() {
                        let mut i = 1;
                        while i + 2 <= (1 + n as usize).min(body.len()) {
                            let v = be16(body, i)?;
                            // skip GREASE values (0x?a?a)
                            if v & 0x0f0f != 0x0a0a && v > supported_max {
                                supported_max = v;
                            }
                            i += 2;
                        }
                    }
                }
                _ => {}
            }
            p += 4 + elen;
        }
    }

    let _ = write!(out, "{} ClientHello", tls_version(supported_max));
    if let Some(s) = &sni {
        let _ = write!(out, " sni={s}");
    }
    if !alpn.is_empty() {
        let _ = write!(out, " alpn={}", alpn.join(","));
    }
    let _ = write!(out, " ciphers={cipher_count}");
    Some(out)
}

fn parse_sni(b: &[u8]) -> Option<String> {
    // server_name_list: u16 len, then entries of { u8 type, u16 len, bytes }
    let mut p = 2;
    while p + 3 <= b.len() {
        let ntype = *b.get(p)?;
        let nlen = be16(b, p + 1)? as usize;
        let name = b.get(p + 3..p + 3 + nlen)?;
        if ntype == 0 {
            return Some(String::from_utf8_lossy(name).into_owned());
        }
        p += 3 + nlen;
    }
    None
}

fn parse_alpn(b: &[u8]) -> Vec<String> {
    // u16 list length, then entries of { u8 len, bytes }
    let mut out = Vec::new();
    let mut p = 2;
    while p < b.len() {
        let len = b[p] as usize;
        let Some(proto) = b.get(p + 1..p + 1 + len) else {
            break;
        };
        out.push(String::from_utf8_lossy(proto).into_owned());
        p += 1 + len;
    }
    out
}

// ---------------------------------------------------------------- HTTP

const METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT",
];

fn http(d: &[u8]) -> Option<String> {
    let head = &d[..d.len().min(8192)];
    let line_end = find(head, b"\r\n").or_else(|| find(head, b"\n"))?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;

    let method = METHODS
        .iter()
        .find(|m| line.starts_with(*m) && line.as_bytes().get(m.len()) == Some(&b' '))?;
    if !line.contains("HTTP/") {
        return None;
    }
    let target = line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .chars()
        .take(80)
        .collect::<String>();

    let mut out = format!("HTTP {method} {target}");
    if let Some(host) = header(head, "host") {
        let _ = write!(out, " host={host}");
    }
    if let Some(ua) = header(head, "user-agent") {
        let _ = write!(out, " ua={:.60}", ua);
    }
    Some(out)
}

/// case-insensitive header lookup over the raw request head.
fn header(head: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n").skip(1).take(64) {
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            return Some(v.trim().to_string());
        }
    }
    None
}

// ---------------------------------------------------------------- DNS

fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        other => format!("TYPE{other}"),
    }
}

fn dns(d: &[u8]) -> Option<String> {
    if d.len() < 12 {
        return None;
    }
    let flags = be16(d, 2)?;
    let qdcount = be16(d, 4)?;
    // a query: QR clear, opcode 0, exactly one question, no answers
    if flags & 0x8000 != 0 || (flags >> 11) & 0x0f != 0 || qdcount != 1 || be16(d, 6)? != 0 {
        return None;
    }

    let mut p = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *d.get(p)? as usize;
        if len == 0 {
            p += 1;
            break;
        }
        // compression pointers do not belong in a question section
        if len & 0xc0 != 0 || labels.len() > 63 {
            return None;
        }
        let label = d.get(p + 1..p + 1 + len)?;
        if !label.iter().all(|c| c.is_ascii_graphic()) {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        p += 1 + len;
    }
    if labels.is_empty() {
        return None;
    }
    let qtype = be16(d, p)?;
    Some(format!("DNS query {} {}", qtype_name(qtype), labels.join(".")))
}

// ---------------------------------------------------------------- fallback

fn other(d: &[u8]) -> Option<String> {
    if d.starts_with(b"SSH-") {
        let v = d
            .iter()
            .take(64)
            .take_while(|c| **c != b'\r' && **c != b'\n')
            .map(|c| *c as char)
            .collect::<String>();
        return Some(format!("SSH banner {v}"));
    }
    let trimmed: &[u8] = {
        let start = d.iter().position(|c| !c.is_ascii_whitespace())?;
        &d[start..]
    };
    if trimmed.starts_with(b"{") || trimmed.starts_with(b"[") {
        return Some("JSON-ish".into());
    }
    if trimmed.starts_with(b"<?xml") || trimmed.starts_with(b"<") {
        return Some("XML/markup-ish".into());
    }

    let sample = &d[..d.len().min(512)];
    let printable = sample
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ' || **b == b'\r' || **b == b'\n' || **b == b'\t')
        .count();
    if printable * 10 >= sample.len() * 9 {
        Some("text/ascii".into())
    } else {
        None
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// assemble a minimal but wire-legal ClientHello with SNI and ALPN.
    fn client_hello(host: &str) -> Vec<u8> {
        let mut ext = Vec::new();

        // server_name
        let mut sni = vec![0x00];
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        let mut sni_body = (sni.len() as u16).to_be_bytes().to_vec();
        sni_body.extend_from_slice(&sni);
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_body);

        // alpn: h2, http/1.1
        let mut protos = Vec::new();
        for p in ["h2", "http/1.1"] {
            protos.push(p.len() as u8);
            protos.extend_from_slice(p.as_bytes());
        }
        let mut alpn_body = (protos.len() as u16).to_be_bytes().to_vec();
        alpn_body.extend_from_slice(&protos);
        ext.extend_from_slice(&0x0010u16.to_be_bytes());
        ext.extend_from_slice(&(alpn_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&alpn_body);

        // supported_versions: GREASE then TLS 1.3
        let sv = [0x04u8, 0x0a, 0x0a, 0x03, 0x04];
        ext.extend_from_slice(&0x002bu16.to_be_bytes());
        ext.extend_from_slice(&(sv.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sv);

        let mut hs = Vec::new();
        hs.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy version
        hs.extend_from_slice(&[0x11; 32]); // random
        hs.push(0); // session id len
        hs.extend_from_slice(&4u16.to_be_bytes()); // 2 cipher suites
        hs.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
        hs.push(1); // compression methods
        hs.push(0);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&((hs.len() + 4) as u16).to_be_bytes());
        rec.push(0x01);
        rec.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]); // 24-bit
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn pulls_sni_and_alpn_out_of_a_client_hello() {
        let got = classify(&client_hello("api.example.com")).unwrap();
        assert!(got.contains("sni=api.example.com"), "{got}");
        assert!(got.contains("alpn=h2,http/1.1"), "{got}");
        assert!(got.contains("TLS 1.3"), "{got}");
        assert!(got.contains("ciphers=2"), "{got}");
    }

    #[test]
    fn truncated_client_hello_does_not_panic() {
        let full = client_hello("example.com");
        for n in 0..full.len() {
            let _ = classify(&full[..n]);
        }
    }

    #[test]
    fn http_request_with_host() {
        let req = b"GET /v1/status HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: curl/8.5.0\r\n\r\n";
        let got = classify(req).unwrap();
        assert!(got.starts_with("HTTP GET /v1/status"), "{got}");
        assert!(got.contains("host=api.example.com"), "{got}");
        assert!(got.contains("ua=curl/8.5.0"), "{got}");
    }

    #[test]
    fn dns_query() {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["telemetry", "example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&28u16.to_be_bytes()); // AAAA
        q.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            classify(&q).unwrap(),
            "DNS query AAAA telemetry.example.com"
        );
    }

    #[test]
    fn dns_response_is_not_reported_as_a_query() {
        let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1]);
        let got = classify(&r);
        assert!(got.as_deref() != Some("DNS query A example"), "{got:?}");
    }

    #[test]
    fn ssh_and_json_and_binary() {
        assert!(
            classify(b"SSH-2.0-OpenSSH_9.6p1\r\n")
                .unwrap()
                .starts_with("SSH banner SSH-2.0-OpenSSH_9.6p1")
        );
        assert_eq!(classify(b"{\"id\":1}").unwrap(), "JSON-ish");
        assert_eq!(classify(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]), None);
    }

    #[test]
    fn empty_input() {
        assert_eq!(classify(&[]), None);
    }
}
