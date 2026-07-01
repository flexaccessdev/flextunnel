//! Machine-wide single-instance lock for the agent: only one
//! `flextunnel-agent` process per machine.
//!
//! The guarantee is "one agent per machine". This is the machine-local
//! counterpart to the server's duplicate-machine-id block: the lock stops a
//! second *local* process; the server block catches two *different* machines
//! colliding on one machine id.
//!
//! It is enforced by a loopback-UDP singleton ([`UdpInstanceLock`]): the agent
//! exclusively binds a fixed `127.0.0.1` UDP port, which is machine-wide by
//! nature and — unlike a lock file under `/var/run` — needs no filesystem and no
//! root. It works identically on Linux, macOS, and Windows. The port is released
//! automatically when the process exits or crashes, so a stale lock never wedges
//! a restart. See [`flextunnel_core::udp_lock`] for the mechanics.

use anyhow::Result;
use flextunnel_core::udp_lock::UdpInstanceLock;

/// Fixed loopback UDP port for the machine-wide agent singleton. Arbitrary but
/// fixed, chosen in the private/dynamic range (49152-65535).
pub const AGENT_SINGLETON_PORT: u16 = 59274;

/// Acquire the machine-wide single-instance lock, held for the process lifetime.
/// Machine-wide by nature (a fixed loopback UDP port), needs no root, and is
/// released automatically on exit or crash. Fails if another agent already holds
/// the port.
pub fn acquire() -> Result<UdpInstanceLock> {
    UdpInstanceLock::acquire(
        AGENT_SINGLETON_PORT,
        "Another flextunnel-agent is already running. Only one agent per machine is allowed.",
    )
}
