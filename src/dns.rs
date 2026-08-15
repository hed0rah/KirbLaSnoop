//! enough DNS to answer a query.
//!
//! the rest of the profile system sends fixed bytes, which cannot work here:
//! a reply has to echo the query's transaction id and question section or the
//! client discards it. so this builds a response from the request.
//!
//! the point is not to be a resolver. it is to keep a device functional while
//! you watch it, and to steer every name at an address you control, so that
//! the connections that follow arrive at a listener with the hostname already
//! known.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const HEADER_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct Answer {
    pub a: Option<Ipv4Addr>,
    pub aaaa: Option<Ipv6Addr>,
    pub ttl: u32,
}

pub struct Query {
    pub id: u16,
    pub flags: u16,
    pub qtype: u16,
    pub qclass: u16,
    /// byte range of the question section within the message
    pub question: std::ops::Range<usize>,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// parse a single-question query. returns None for anything that is not one,
/// including responses, so we never answer an answer.
pub fn parse(msg: &[u8]) -> Option<Query> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let id = be16(msg, 0)?;
    let flags = be16(msg, 2)?;
    // QR clear (a query), standard opcode, exactly one question
    if flags & 0x8000 != 0 || (flags >> 11) & 0x0f != 0 || be16(msg, 4)? != 1 {
        return None;
    }

    // walk the qname to find where the question ends. the name itself is not
    // kept: the classifier already reports it, and building a String here
    // would allocate on every datagram for nothing.
    let mut p = HEADER_LEN;
    let start = p;
    let mut labels = 0;
    loop {
        let len = *msg.get(p)? as usize;
        if len == 0 {
            p += 1;
            break;
        }
        // a compression pointer has no business in a question
        if len & 0xc0 != 0 || labels > 127 {
            return None;
        }
        msg.get(p + 1..p + 1 + len)?;
        labels += 1;
        p += 1 + len;
    }
    let qtype = be16(msg, p)?;
    let qclass = be16(msg, p + 2)?;
    p += 4;

    Some(Query {
        id,
        flags,
        qtype,
        qclass,
        question: start..p,
    })
}

/// build a reply to `msg`. None when the input is not a query we can answer.
///
/// a query we understand but hold no record for gets NOERROR with zero
/// answers, not NXDOMAIN: that stops the client retrying without telling it
/// the name does not exist.
pub fn reply(msg: &[u8], ans: &Answer) -> Option<Vec<u8>> {
    let q = parse(msg)?;

    let rdata: Option<Vec<u8>> = if q.qclass != CLASS_IN {
        None
    } else {
        match q.qtype {
            TYPE_A => ans.a.map(|ip| ip.octets().to_vec()),
            TYPE_AAAA => ans.aaaa.map(|ip| ip.octets().to_vec()),
            _ => None,
        }
    };

    let mut out = Vec::with_capacity(msg.len() + 32);
    out.extend_from_slice(&q.id.to_be_bytes());
    // QR set, opcode and RD copied from the query, RA set, rcode 0
    let flags = 0x8000 | (q.flags & 0x7800) | (q.flags & 0x0100) | 0x0080;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&(rdata.is_some() as u16).to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount
    out.extend_from_slice(msg.get(q.question.clone())?);

    if let Some(rd) = rdata {
        // name as a compression pointer back to the question at offset 12
        out.extend_from_slice(&[0xc0, HEADER_LEN as u8]);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ans.ttl.to_be_bytes());
        out.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        out.extend_from_slice(&rd);
    }
    Some(out)
}

/// dns over tcp frames each message with a 2-byte length prefix.
pub fn reply_tcp(msg: &[u8], ans: &Answer) -> Option<Vec<u8>> {
    let declared = be16(msg, 0)? as usize;
    let body = msg.get(2..2 + declared.min(msg.len().saturating_sub(2)))?;
    let inner = reply(body, ans)?;
    let mut out = Vec::with_capacity(inner.len() + 2);
    out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    out.extend_from_slice(&inner);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn answer() -> Answer {
        Answer {
            a: Some(Ipv4Addr::new(192, 0, 2, 1)),
            aaaa: None,
            ttl: 60,
        }
    }

    #[test]
    fn parses_a_query() {
        let msg = query("api.example.com", TYPE_A);
        let q = parse(&msg).unwrap();
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.id, 0x1234);
        // question range must cover qname + qtype + qclass exactly
        assert_eq!(q.question, 12..msg.len());
    }

    #[test]
    fn reply_echoes_id_and_question_and_carries_the_address() {
        let msg = query("api.example.com", TYPE_A);
        let r = reply(&msg, &answer()).unwrap();
        assert_eq!(&r[0..2], &msg[0..2], "transaction id must be echoed");
        assert_eq!(r[2] & 0x80, 0x80, "QR must be set");
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 1, "qdcount");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "ancount");
        assert_eq!(&r[12..msg.len()], &msg[12..], "question copied verbatim");
        // answer: pointer, type, class, ttl, rdlength, rdata
        let a = &r[msg.len()..];
        assert_eq!(&a[0..2], &[0xc0, 0x0c]);
        assert_eq!(u16::from_be_bytes([a[2], a[3]]), TYPE_A);
        assert_eq!(u32::from_be_bytes([a[6], a[7], a[8], a[9]]), 60);
        assert_eq!(u16::from_be_bytes([a[10], a[11]]), 4);
        assert_eq!(&a[12..16], &[192, 0, 2, 1]);
    }

    #[test]
    fn unconfigured_type_gets_noerror_with_no_answers() {
        // AAAA asked for, only an A record configured
        let r = reply(&query("api.example.com", TYPE_AAAA), &answer()).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "ancount must be 0");
        assert_eq!(r[3] & 0x0f, 0, "rcode must be NOERROR, not NXDOMAIN");
    }

    #[test]
    fn aaaa_is_answered_when_configured() {
        let ans = Answer {
            a: None,
            aaaa: Some("2001:db8::1".parse().unwrap()),
            ttl: 30,
        };
        let msg = query("v6.example.com", TYPE_AAAA);
        let r = reply(&msg, &ans).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
        let a = &r[msg.len()..];
        assert_eq!(u16::from_be_bytes([a[10], a[11]]), 16, "rdlength for AAAA");
    }

    #[test]
    fn never_answers_a_response() {
        let mut resp = query("api.example.com", TYPE_A);
        resp[2] |= 0x80; // set QR
        assert!(parse(&resp).is_none());
        assert!(reply(&resp, &answer()).is_none());
    }

    #[test]
    fn tcp_framing_round_trips() {
        let inner = query("api.example.com", TYPE_A);
        let mut framed = (inner.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&inner);
        let r = reply_tcp(&framed, &answer()).unwrap();
        let declared = u16::from_be_bytes([r[0], r[1]]) as usize;
        assert_eq!(declared, r.len() - 2, "length prefix must match the body");
        assert_eq!(&r[2..4], &inner[0..2], "id echoed inside the frame");
    }

    #[test]
    fn garbage_is_not_answered() {
        assert!(reply(&[], &answer()).is_none());
        assert!(reply(&[0xde, 0xad], &answer()).is_none());
        let truncated = query("api.example.com", TYPE_A);
        for n in 0..truncated.len() {
            let _ = reply(&truncated[..n], &answer());
        }
    }
}
