//! flextunnel
//!
//! A SOCKS5-over-QUIC proxy via iroh P2P connections. The client runs a local
//! SOCKS5 listener; each CONNECT is tunneled as a reliable QUIC bi-stream to the
//! server, which resolves DNS and connects to the target from its own network.
//! Uses a fixed ALPN for protocol selection, auth tokens for access control, and
//! TLS 1.3/QUIC for encryption. Neither side needs admin/root (no TUN device).
//!
//! This is the reusable core library, consumed by the `flextunnel` CLI binary
//! (`flextunnel-cli`), the `flextunnel-agent` binary, and the iOS C FFI staticlib
//! (`flextunnel-ffi`).

pub mod app;
pub mod auth;
pub mod blocklist;
pub mod config;
pub mod error;
pub mod lock;
pub mod machine_id;
pub mod proxy;
pub mod secret;
pub mod transport;
