//! Machine-wide single-instance guard via an exclusively-bound loopback UDP port.
//!
//! An alternative to the filesystem [`crate::lock::InstanceLock`] for the case
//! where the guarantee is "one process per *machine*" and a root-writable lock
//! path (`/var/run`) — and therefore root — is undesirable. Binding a UDP socket
//! to a fixed loopback port is machine-wide by nature, needs no filesystem and no
//! privileges, and behaves identically on Linux, macOS, and Windows.
//!
//! The guard is the bound socket: it is held for the process lifetime and the OS
//! releases the port when the fd closes on exit or crash, so there is no stale
//! state to wedge a restart (UDP has no `TIME_WAIT`, so the port is immediately
//! re-bindable). `std::net::UdpSocket::bind` sets neither `SO_REUSEADDR` nor
//! `SO_REUSEPORT`, so a second bind to the same `127.0.0.1:PORT` reliably fails
//! with [`io::ErrorKind::AddrInUse`] on all three platforms.
//!
//! Callers must bind IPv4 `127.0.0.1` (never `0.0.0.0` or `::`) to keep the guard
//! strictly machine-local. Core owns the mechanics; the caller picks the port,
//! mirroring how [`crate::lock::InstanceLock`] takes a path.
//!
//! Unlike the file lock, this leaves no artifact recording the holder's PID. To
//! find which process holds the port, query the OS socket table:
//! `ss -lunp 'sport = :<port>'` or `lsof -iUDP:<port>` (Linux/macOS),
//! `netstat -ano -p udp` (Windows).
//!
//! Residual risk (acceptable under this project's "catch accidental
//! misconfiguration" trust model): an unrelated app squatting the port yields a
//! false "already running".

use anyhow::{Context, Result};
use std::io;
use std::net::{SocketAddr, UdpSocket};

/// Holds a UDP socket bound to a loopback address for the lifetime of the
/// process. The single-instance guarantee *is* the exclusive bind; the port is
/// released when this is dropped.
pub struct UdpInstanceLock {
    #[allow(dead_code)] // kept bound to hold the port; released on drop
    socket: UdpSocket,
}

impl UdpInstanceLock {
    /// Acquire the singleton by exclusively binding `addr` (a loopback address).
    /// Returns `contended_msg` if the port is already bound (another instance is
    /// running), or the underlying error with context otherwise.
    pub fn acquire(addr: SocketAddr, contended_msg: &str) -> Result<Self> {
        match UdpSocket::bind(addr) {
            Ok(socket) => {
                log::debug!("Acquired UDP single-instance lock on {addr}");
                Ok(Self { socket })
            }
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => anyhow::bail!("{contended_msg}"),
            Err(e) => Err(e)
                .with_context(|| format!("Failed to bind the single-instance UDP socket ({addr})")),
        }
    }

    /// The address the guard is bound to (for tests and operator introspection).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    /// While the port is held, a second bind to the same address must be rejected;
    /// after the first guard is dropped, binding succeeds again.
    #[test]
    fn second_bind_rejected_then_succeeds_after_drop() {
        // Port 0 => the OS assigns a free ephemeral port, unique per run, so
        // concurrent `cargo test` processes never collide on a fixed number.
        let ephemeral = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let first = UdpInstanceLock::acquire(ephemeral, "held").expect("first acquire");

        // Re-target the actual assigned port for the contention check.
        let addr = first.local_addr().expect("local_addr");
        assert!(
            UdpInstanceLock::acquire(addr, "held").is_err(),
            "a second bind must fail while the port is held"
        );

        drop(first);
        // UDP has no TIME_WAIT: the port is immediately re-bindable.
        assert!(
            UdpInstanceLock::acquire(addr, "held").is_ok(),
            "bind should succeed after the guard is released"
        );
    }
}
