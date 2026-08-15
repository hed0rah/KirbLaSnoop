//! pin a socket to a network interface.
//!
//! binding to an address is not the same as binding to an interface. an
//! interface can carry several addresses, and ipv6 privacy addressing rotates
//! them, so an address-bound listener on a wireless interface is aimed at a
//! moving target. SO_BINDTODEVICE names the device instead and survives that.
//!
//! it does not require privileges on a modern kernel, and for udp it takes
//! effect after bind, which is why this is a setsockopt rather than a
//! hand-rolled socket/bind sequence.

use anyhow::{Result, bail};
use std::os::fd::AsRawFd;

const SOL_SOCKET: i32 = 1;
const SO_BINDTODEVICE: i32 = 25;
/// IFNAMSIZ; the kernel rejects anything longer
const IFNAMSIZ: usize = 16;

unsafe extern "C" {
    fn setsockopt(
        sockfd: i32,
        level: i32,
        optname: i32,
        optval: *const core::ffi::c_void,
        optlen: u32,
    ) -> i32;
}

pub fn bind_to_device<F: AsRawFd>(sock: &F, iface: &str) -> Result<()> {
    if iface.is_empty() || iface.len() >= IFNAMSIZ {
        bail!("interface name {iface:?} must be 1 to {} characters", IFNAMSIZ - 1);
    }
    let mut name = [0u8; IFNAMSIZ];
    name[..iface.len()].copy_from_slice(iface.as_bytes());

    // SAFETY: fd is a live socket owned by the caller, and name is a
    // NUL-terminated buffer of exactly the length we pass.
    let rc = unsafe {
        setsockopt(
            sock.as_raw_fd(),
            SOL_SOCKET,
            SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.len() as u32,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        bail!("binding to interface {iface:?}: {e}");
    }
    Ok(())
}
