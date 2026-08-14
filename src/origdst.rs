//! recover the pre-NAT destination of a redirected connection.
//!
//! when netfilter REDIRECTs a connection to us, the socket's local address is
//! our own listener, but conntrack still remembers where the peer was actually
//! headed. SO_ORIGINAL_DST asks for that tuple back, which is what turns a
//! single listener into a catch-all: the program under test tells us the host
//! and port it wanted without us having to guess either.
//!
//! getsockopt is declared here rather than pulled in with a crate; it is one
//! symbol out of libc, which is already linked.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

const SOL_IP: i32 = 0;
const SOL_IPV6: i32 = 41;
const SO_ORIGINAL_DST: i32 = 80;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

unsafe extern "C" {
    fn getsockopt(
        sockfd: i32,
        level: i32,
        optname: i32,
        optval: *mut core::ffi::c_void,
        optlen: *mut u32,
    ) -> i32;
}

/// the address the peer was trying to reach, if netfilter rewrote it.
/// None means the connection arrived directly, which is not an error.
pub fn original_dst<F: AsRawFd>(sock: &F, local: SocketAddr) -> Option<SocketAddr> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let fd = sock.as_raw_fd();

    // a v6 socket may be carrying a v4-mapped connection, so try both levels.
    let orig = if local.is_ipv6() {
        query(fd, SOL_IPV6).or_else(|| query(fd, SOL_IP))
    } else {
        query(fd, SOL_IP)
    }?;

    // with no conntrack entry the kernel hands back our own local address.
    // that means "not redirected", the common case, and must stay silent
    // rather than reporting a bogus original destination.
    if same_endpoint(orig, local) {
        return None;
    }
    Some(orig)
}

fn query(fd: i32, level: i32) -> Option<SocketAddr> {
    // big enough for sockaddr_in6 (28 bytes); sockaddr_in needs 16
    let mut buf = [0u8; 28];
    let mut len: u32 = buf.len() as u32;
    // SAFETY: fd is owned by the live socket the caller lent us, and
    // buf/len describe a writable region of exactly the advertised size.
    let rc = unsafe {
        getsockopt(
            fd,
            level,
            SO_ORIGINAL_DST,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    decode(&buf[..(len as usize).min(buf.len())])
}

/// sockaddr_in  { u16 family; u16 port_be; u32 addr_be; u8 pad[8] }
/// sockaddr_in6 { u16 family; u16 port_be; u32 flow; u8 addr[16]; u32 scope }
fn decode(b: &[u8]) -> Option<SocketAddr> {
    let family = u16::from_ne_bytes(b.get(0..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(b.get(2..4)?.try_into().ok()?);
    match family {
        AF_INET => {
            let o: [u8; 4] = b.get(4..8)?.try_into().ok()?;
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(o), port)))
        }
        AF_INET6 => {
            let o: [u8; 16] = b.get(8..24)?.try_into().ok()?;
            Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(o), port, 0, 0)))
        }
        _ => None,
    }
}

fn same_endpoint(a: SocketAddr, b: SocketAddr) -> bool {
    if a.port() != b.port() {
        return false;
    }
    // a 0.0.0.0 / [::] listener matches any address on that port
    a.ip() == b.ip() || b.ip().is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_sockaddr_in() {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        b[2..4].copy_from_slice(&443u16.to_be_bytes());
        b[4..8].copy_from_slice(&[192, 0, 2, 1]);
        assert_eq!(
            decode(&b).unwrap(),
            "192.0.2.1:443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn decodes_sockaddr_in6() {
        let mut b = [0u8; 28];
        b[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        b[2..4].copy_from_slice(&8883u16.to_be_bytes());
        b[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            decode(&b).unwrap(),
            "[2001:db8::1]:8883".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn unspecified_listener_swallows_any_address_on_its_port() {
        let orig = "10.0.0.5:9999".parse().unwrap();
        let local = "0.0.0.0:9999".parse().unwrap();
        assert!(same_endpoint(orig, local));

        let elsewhere = "10.0.0.5:443".parse().unwrap();
        assert!(!same_endpoint(elsewhere, local));
    }

    #[test]
    fn truncated_input_is_rejected_not_panicked() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[2, 0]).is_none());
        let mut short = [0u8; 6];
        short[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        assert!(decode(&short).is_none());
    }
}
