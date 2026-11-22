//! QUIC transport configuration shared by client and server endpoint setup.
//!
//! Unlike the ezvpn VPN this is derived from, the data path here is reliable
//! QUIC bi-streams (not unreliable datagrams), so there is no datagram-buffer
//! or congestion-controller tuning — the idle timeout, the app-level heartbeat
//! cadence, a larger initial MTU, and two settings that a single bulk stream
//! depends on: the flow-control windows ([`STREAM_RECEIVE_WINDOW`],
//! [`SEND_WINDOW`]) and how much reordering loss detection tolerates
//! ([`REORDERING_PACKET_THRESHOLD`], [`REORDERING_TIME_THRESHOLD`]).

pub mod endpoint;
pub mod paths;

use anyhow::{Context, Result};
use iroh::endpoint::QuicTransportConfig;
use std::time::Duration;

/// QUIC idle timeout. A connection with no activity for this long is considered
/// dead and closed, resolving `Connection::closed()`.
///
/// There is deliberately **no QUIC-level keep-alive**: the app-level heartbeat
/// below is the sole periodic sender, so an idle connection costs exactly one
/// radio wake per heartbeat instead of two overlapping ping schedules. On
/// cellular every transmission buys ~10s of high-power radio tail, so the
/// heartbeat cadence — not payload size — is the battery cost. The timeout must
/// comfortably exceed the widest heartbeat cadence
/// ([`HEARTBEAT_INTERVAL_IDLE`], 60s) so a healthy-but-quiet connection never
/// idles out; a genuinely dead one is detected sooner by the heartbeat's own
/// liveness window while active, with this as the backstop while idle.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Initial QUIC path MTU (UDP payload bytes) before MTU discovery completes.
/// 1452 is the IPv6-safe maximum for a standard 1500-byte Ethernet path
/// (`1500 − 40 IPv6 − 8 UDP`) and matches quinn's DPLPMTUD upper-bound default.
pub const QUIC_INITIAL_MTU: u16 = 1452;

/// Flow-control window of one stream: how much the peer may send on it ahead
/// of what the application has read.
///
/// A stream cannot carry more than a window per round trip, whatever the path
/// could take, so this caps a transfer at `window / RTT`. iroh's default of
/// 1.25 MB is 100 Mbit/s at 100 ms; over a path with 53 ms round trips and
/// room for far more, a forward measured 180 Mbit/s with it in either
/// direction, and with this 370–450 down and 560–680 up. A larger window
/// would only matter on a path both faster and longer than that, and the
/// window is also what a stream buffers when its reader stalls or is merely
/// slower than the path. That is its price: 70 stalled readers on one
/// connection took a client to 570–690 MB of memory and 95 to 900 MB, about
/// 9 MB each, where the default window held under 2 MB each (QUIC's default
/// limit of 100 streams stands). Halving the window halves that and the cap
/// alike: with 50 ms added to a 3 ms path and the UDP buffer limits raised, an
/// upload ran at 1040 Mbit/s with this window, 560 with 4 MiB, 290 with 2 MiB.
///
/// The connection as a whole stays unlimited all the same, as it is by
/// default. A connection-wide limit is shared by every stream, the control
/// stream included, and comes back an eighth at a time as readers read. With
/// one of 128 MiB, 18 stalled readers left the heartbeat unanswered and the
/// client dropped the link with every tunnel on it; 24 readers that were only
/// slow (100 kB/s each) made a new stream wait 3–15 s for its first 100 kB,
/// or time out, where without the limit it took 12 ms.
///
/// What bounds the memory where it has to be bounded is a smaller window of
/// the stream's own, which leaves every other stream and the heartbeat their
/// credit. The iOS client is the one build the system kills for the memory it
/// holds, so there the window is iroh's default, as it has always been: its
/// downloads stay capped at 100 Mbit/s per 100 ms of round trip, and its
/// streams at the under 2 MB each they held before. The window is each
/// side's own, so a server still offers that client the full one for uploads.
pub const STREAM_RECEIVE_WINDOW: u32 = if cfg!(target_os = "ios") {
    1_250_000
} else {
    8 * 1024 * 1024
};

/// How much sent-but-unacknowledged stream data a connection holds, across its
/// streams. Twice the widest stream window a peer offers (8 MiB, whatever
/// this build's own [`STREAM_RECEIVE_WINDOW`]), so one stream can fill its
/// window while others still send.
pub const SEND_WINDOW: u64 = 16 * 1024 * 1024;

/// How many later packets must be acknowledged before an unacknowledged one
/// is declared lost on that ground alone (QUIC's packet reordering threshold,
/// 3 by default).
///
/// The default mistakes reordering for loss, and a sender on a multi-queue NIC
/// reorders its own packets: the kernel picks the transmit queue by the CPU a
/// packet is sent from, and the task sending a connection's packets moves
/// between runtime threads, so consecutive batches leave through different
/// queues and overtake each other by milliseconds. A server on such a NIC
/// (four queues) declared 9–12% of a download's packets lost when all of them
/// had arrived, resent them, and shrank its congestion window thousands of
/// times over. At that rate a millisecond is a hundred packets, hence a
/// threshold in the hundreds: with this one and [`REORDERING_TIME_THRESHOLD`]
/// the download ran 14% faster, as fast as with the kernel made to use one
/// queue. A real loss in a bulk transfer is still noticed promptly, once this
/// many packets have followed it; in a trickle the time threshold decides, as
/// it always has.
pub const REORDERING_PACKET_THRESHOLD: u32 = 256;

/// How long an unacknowledged packet is waited for, as a multiple of the
/// round-trip time, once a later packet has been acknowledged (QUIC's time
/// reordering threshold, 9/8 by default).
///
/// The companion of [`REORDERING_PACKET_THRESHOLD`]: on a short path 9/8 of
/// the round trip leaves a fraction of a millisecond for a reordered packet to
/// turn up, less than transmit queues drift apart, so the time rule alone kept
/// most of the spurious losses. The cost is in a stream too slow for the
/// packet threshold to apply: a packet lost in mid-flight is resent after two
/// round trips rather than one and an eighth.
pub const REORDERING_TIME_THRESHOLD: f32 = 2.0;

/// App-level heartbeat interval while the client is **active** (foregrounded,
/// or a non-mobile embedder). After the auth handshake the control stream is
/// kept open and the client sends a `Heartbeat` this often; the server replies
/// with a `HeartbeatAck`. The heartbeat is both the liveness probe (a missing
/// ack within [`liveness_window`] means a dead link) and, with no QUIC
/// keep-alive configured, the traffic that keeps NAT mappings and the idle
/// timeout refreshed.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// App-level heartbeat interval while the client is **idle in the background**
/// (a mobile embedder reported the app backgrounded — see
/// `ProxyClient::set_background`). One send per minute keeps the cellular radio
/// in its low-power state almost the whole time (anything periodic under
/// ~15–20s keeps it high continuously), matching where battery-conscious peers
/// converged: Tailscale stops idle-session heartbeats entirely, DERP relays
/// keepalive at 60s, and Apple's historical background-heartbeat floor was 10
/// minutes. Liveness detection widens to [`liveness_window`] of this — a dead
/// link found within ~3 minutes is fine for a backgrounded session, and the
/// foreground flip snaps the cadence (and detection) back immediately.
pub const HEARTBEAT_INTERVAL_IDLE: Duration = Duration::from_secs(60);

/// Grace added to the heartbeat liveness window so a heartbeat delayed by
/// scheduler/network jitter isn't misread as a dead connection right at the
/// 3×-interval boundary.
const LIVENESS_GRACE: Duration = Duration::from_secs(3);

/// Liveness window for an app-level heartbeat cadence: 3× the interval
/// (tolerating a couple of dropped heartbeats) plus [`LIVENESS_GRACE`], so a
/// late-but-valid heartbeat doesn't race the timeout at exactly 3× the
/// interval. The client sizes the window from the cadence it is actually using.
pub const fn liveness_window(interval: Duration) -> Duration {
    Duration::from_secs(interval.as_secs() * 3 + LIVENESS_GRACE.as_secs())
}

/// The server's liveness window for client heartbeats. A connection whose
/// control stream produces no heartbeat for this long is treated as dead. Sized
/// for the **widest** client cadence ([`HEARTBEAT_INTERVAL_IDLE`]) because the
/// server cannot know which cadence a client is on; an active client going
/// silent is still closed by the QUIC idle timeout, just later than its own
/// 3×10s window would have been. Slower server-side reaping only delays
/// duplicate-id detection and registry cleanup for genuinely dead clients.
pub const LIVENESS_WINDOW: Duration = liveness_window(HEARTBEAT_INTERVAL_IDLE);

/// QUIC ALPN protocol identifier for flextunnel.
///
/// A plain protocol-negotiation label, sent unencrypted in the TLS/QUIC
/// handshake — it is not a secret and provides no access control. Both peers
/// must offer the same ALPN or negotiation fails; access control is enforced by
/// the keypair auth handshake, not by this value.
pub const ALPN: &[u8] = b"flextunnel/1";

/// QUIC ALPN protocol identifier for **quick-mode** client connections
/// (`client start --quick` ↔ `server start --quick`).
///
/// The ALPN carries the peer's *role* (quick client vs keypair client) so the
/// two paths can be told apart at the transport layer; like [`ALPN`] it is not
/// a credential. The credential is the server's endpoint-id allowlist (the
/// single client id entered on the quick server), enforced natively at the TLS
/// handshake by [`endpoint::AllowlistHook`]. No auth keypair is involved —
/// iroh's handshake authenticates the endpoint id, so it needs no further
/// proof. After the handshake a quick client is served exactly like a keypair
/// client.
pub const QUICK_ALPN: &[u8] = b"flextunnel-quick/1";

/// Build a QUIC transport config with the idle timeout, a larger initial MTU,
/// the flow-control windows and the reordering thresholds — and **no transport
/// keep-alive** (see [`QUIC_IDLE_TIMEOUT`]; the app-level heartbeat is the sole
/// periodic sender). Shared by client and server endpoint creation so both
/// sides apply identical settings: each side's windows bound what the other
/// sends, and each side's thresholds judge its own packets.
pub fn build_quic_transport_config() -> Result<QuicTransportConfig> {
    let mut transport_config = QuicTransportConfig::builder();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config = transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config = transport_config.initial_mtu(QUIC_INITIAL_MTU);
    transport_config = transport_config.stream_receive_window(STREAM_RECEIVE_WINDOW.into());
    transport_config = transport_config.send_window(SEND_WINDOW);
    transport_config = transport_config.packet_threshold(REORDERING_PACKET_THRESHOLD);
    transport_config = transport_config.time_threshold(REORDERING_TIME_THRESHOLD);
    Ok(transport_config.build())
}
