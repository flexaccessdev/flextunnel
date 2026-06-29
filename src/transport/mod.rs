//! QUIC transport configuration shared by client and server endpoint setup.
//!
//! Unlike the ezvpn VPN this is derived from, the data path here is reliable
//! QUIC bi-streams (not unreliable datagrams), so there is no datagram-buffer,
//! congestion-controller, or flow-control-window tuning — just keep-alive,
//! idle timeout, and a larger initial MTU.

pub mod endpoint;

use anyhow::{Context, Result};
use iroh::endpoint::QuicTransportConfig;
use std::time::Duration;

/// QUIC keep-alive interval. Active connections send pings at this interval to
/// keep NAT mappings alive and detect dead peers promptly. Matches iroh's relay
/// ping interval (15s), comfortably under the 30s idle timeout.
pub const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// QUIC idle timeout. A connection with no activity (data or keep-alive) for
/// this long is considered dead and closed, resolving `Connection::closed()`.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Initial QUIC path MTU (UDP payload bytes) before MTU discovery completes.
/// 1452 is the IPv6-safe maximum for a standard 1500-byte Ethernet path
/// (`1500 − 40 IPv6 − 8 UDP`) and matches quinn's DPLPMTUD upper-bound default.
pub const QUIC_INITIAL_MTU: u16 = 1452;

/// Build a QUIC transport config with keep-alive, idle timeout, and a larger
/// initial MTU. Shared by client and server endpoint creation so both sides
/// apply identical settings.
pub fn build_quic_transport_config() -> Result<QuicTransportConfig> {
    let mut transport_config = QuicTransportConfig::builder();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config = transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config = transport_config.keep_alive_interval(QUIC_KEEP_ALIVE_INTERVAL);
    transport_config = transport_config.initial_mtu(QUIC_INITIAL_MTU);
    Ok(transport_config.build())
}
