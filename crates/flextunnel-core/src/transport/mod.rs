//! QUIC transport configuration shared by client and server endpoint setup.
//!
//! Unlike the ezvpn VPN this is derived from, the data path here is reliable
//! QUIC bi-streams (not unreliable datagrams), so there is no datagram-buffer
//! or congestion-controller tuning — the idle timeout, the app-level heartbeat
//! cadence, a larger initial MTU, and two settings that a single bulk stream
//! depends on: flow-control windows that grow with the stream's reader
//! ([`STREAM_RECEIVE_WINDOW`], [`STREAM_RECEIVE_WINDOW_MAX`],
//! [`STREAM_WINDOW_BUDGET`], [`SEND_WINDOW`]) and how much reordering loss
//! detection tolerates ([`REORDERING_PACKET_THRESHOLD`],
//! [`REORDERING_TIME_THRESHOLD`]).
//!
//! The stack underneath is forks of iroh, noq and netwatch carrying the
//! changes ezvpn's forks do, patched in by the workspace manifest, whose
//! comments say what each carries.

pub mod endpoint;
pub mod paths;

use anyhow::{Context, Result};
use iroh::endpoint::{QuicTransportConfig, Side};
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

/// Flow-control window every stream starts with: how much the peer may send
/// on it ahead of what the application has read. iroh's default.
///
/// A stream cannot carry more than a window per round trip, whatever the path
/// could take, so a window caps a transfer at `window / RTT`: this one at
/// 100 Mbit/s per 100 ms. But the window is also what a stream buffers when
/// its reader stalls or is merely slower than the path, and QUIC credit cannot
/// be taken back once granted. So no stream is given more than this up front.
/// A stream whose reader keeps up earns more, up to
/// [`STREAM_RECEIVE_WINDOW_MAX`]; one that is read slowly or not at all, and
/// the control stream, stay here. So does every stream of the iOS client.
pub const STREAM_RECEIVE_WINDOW: u32 = 1_250_000;

/// The most a stream's window grows to.
///
/// The noq fork widens a stream's window as the stream is read
/// (`max_stream_receive_window`): each time half the window has been read
/// within two round trips, the reader is keeping up with a sender the window
/// is holding back, and the window doubles. A round trip counts as 5 ms at
/// least: on a shorter path what the window has to cover is how late the
/// receiving process runs, and held to the starting window a 3.7 Gbit/s
/// transfer between two machines 0.3 ms apart lost 3–5%. It never shrinks
/// again, since the credit behind it stays out until the peer has used it.
///
/// At this size a stream carries 1.2 Gbit/s at 53 ms. Every stream used to be
/// given it from the start, on every build but iOS, and that was the price:
/// 95 stalled readers on one connection took a client past 1 GB of memory,
/// about 12 MB each, where streams held to [`STREAM_RECEIVE_WINDOW`] took
/// under 2 MB each.
///
/// The iOS client's windows do not grow. A reader that was fast and then
/// stalls keeps the window it earned, so with growth an ordinary download can
/// leave a stream holding several times the 1.25 MB that build has always
/// held its streams to, and iOS is the one build the system kills for the
/// memory it holds: what budget is safe on a device has not been measured.
/// Its downloads stay capped at 100 Mbit/s per 100 ms of round trip. The
/// window is each side's own, so a server still grows the one it offers that
/// client for uploads.
pub const STREAM_RECEIVE_WINDOW_MAX: u32 = if cfg!(target_os = "ios") {
    STREAM_RECEIVE_WINDOW
} else {
    WIDEST_STREAM_WINDOW
};

/// The widest window a stream grows to on any build, which is what a peer may
/// offer whatever this build's own [`STREAM_RECEIVE_WINDOW_MAX`].
const WIDEST_STREAM_WINDOW: u32 = 8 * 1024 * 1024;

/// What the streams of one connection may hold between them beyond their
/// starting windows (the noq fork's `stream_receive_window_budget`): enough
/// for nine at [`STREAM_RECEIVE_WINDOW_MAX`]. A stream takes what its window
/// grows by out of this and returns it when it ends.
///
/// It bounds what a peer can be made to buffer: a connection carries the 100
/// bidirectional streams a server grants its client and no others
/// ([`build_quic_transport_config`]), so `100 × STREAM_RECEIVE_WINDOW` plus
/// this, about 183 MiB at either end, where the starting windows alone are
/// the 119 MiB it always could.
///
/// It is not QUIC's own limit across a connection's streams, which stays
/// unlimited as it is by default. That limit is credit every stream draws on,
/// the control stream included, and it comes back an eighth at a time as
/// readers read: with one of 128 MiB on 8 MiB streams, 18 stalled readers left
/// the heartbeat unanswered and the client dropped the link with every tunnel
/// on it, and 24 readers that were only slow (100 kB/s each) made a new stream
/// wait 3–15 s for its first 100 kB, or time out, where without the limit it
/// took 12 ms. A stream this budget has nothing left for keeps the window it
/// has and its own credit, whatever the other streams' readers do.
pub const STREAM_WINDOW_BUDGET: u64 = 64 * 1024 * 1024;

/// How much sent-but-unacknowledged stream data a connection holds, across its
/// streams. Twice the widest window a peer offers a stream (8 MiB, whatever
/// this build's own [`STREAM_RECEIVE_WINDOW_MAX`]), so one stream can fill its
/// window while others still send.
pub const SEND_WINDOW: u64 = 2 * WIDEST_STREAM_WINDOW as u64;

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
///
/// The netwatch fork has since removed that cause where it can: it sends to a
/// busy peer on a connected socket, whose transmit queue the kernel keeps
/// fixed (Linux and Apple platforms, up to 64 peers). Between two Linux VMs
/// with six queues each, the upstream socket with these thresholds still lost
/// over 2% of a transfer's packets and took 10 spurious congestion events a
/// second; the peer socket brought that to under 1% and none. What reordering
/// is left is this threshold's to absorb: with the peer socket and QUIC's
/// defaults there were 2–3 spurious events a second, with these 0.1.
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
/// sides apply the same settings: each side's windows bound what the other
/// sends, and each side's thresholds judge its own packets.
///
/// What differs by `side` is the streams a peer is granted, which are the
/// ones tunnels use and no others: a client opens bidirectional streams to
/// its server, so a server grants QUIC's default of 100 and a client grants
/// none, and neither grants unidirectional ones. Each stream QUIC would
/// otherwise allow (100 of each kind, from either end) is a stream receive
/// window more that a peer could have this side hold.
///
/// The window growth settings exist only in the noq fork the workspace builds
/// against, and reach here through the iroh fork's builder.
pub fn build_quic_transport_config(side: Side) -> Result<QuicTransportConfig> {
    let mut transport_config = QuicTransportConfig::builder();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config = transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config = transport_config.initial_mtu(QUIC_INITIAL_MTU);
    transport_config = transport_config.stream_receive_window(STREAM_RECEIVE_WINDOW.into());
    transport_config = transport_config.max_stream_receive_window(STREAM_RECEIVE_WINDOW_MAX.into());
    transport_config = transport_config.stream_receive_window_budget(STREAM_WINDOW_BUDGET);
    transport_config = transport_config.send_window(SEND_WINDOW);
    transport_config = transport_config.max_concurrent_uni_streams(0u32.into());
    if side == Side::Client {
        transport_config = transport_config.max_concurrent_bidi_streams(0u32.into());
    }
    transport_config = transport_config.packet_threshold(REORDERING_PACKET_THRESHOLD);
    transport_config = transport_config.time_threshold(REORDERING_TIME_THRESHOLD);
    Ok(transport_config.build())
}
