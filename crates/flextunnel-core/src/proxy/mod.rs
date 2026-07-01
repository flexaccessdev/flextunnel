//! The SOCKS5-over-QUIC proxy: signaling, SOCKS5, client, server, and agent.

pub mod agent;
pub mod client;
pub mod dial;
pub mod server;
pub mod routed_set;
pub mod signaling;
pub mod socks5;

#[cfg(test)]
mod e2e_tests;

pub use agent::{AgentConfig, ProxyAgent};
pub use client::{ClientConfig, ProxyClient, TunnelRoutes};
pub use routed_set::RoutedSet;
pub use server::ProxyServer;
