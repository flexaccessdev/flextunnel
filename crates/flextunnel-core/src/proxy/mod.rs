//! The SOCKS5-over-QUIC proxy: signaling, SOCKS5, client, and server.

pub mod client;
pub mod dial;
pub mod server;
pub mod signaling;
pub mod socks5;
pub mod whitelist;

#[cfg(test)]
mod e2e_tests;

pub use client::{ClientConfig, ProxyClient, TunnelRoutes};
pub use server::ProxyServer;
pub use whitelist::Whitelist;
