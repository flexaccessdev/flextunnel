//! The proxy over QUIC: signaling, SOCKS5 and HTTP front-ends, client, and
//! server.

pub mod client;
pub mod client_status;
pub mod destination;
pub mod dial;
pub mod forward;
pub mod http;
pub mod reserved;
pub mod route_table;
pub mod server;
pub mod server_routes;
pub mod routed_set;
pub mod signaling;
pub mod socks5;
pub mod status_page;

#[cfg(test)]
mod e2e_tests;

pub use client::{
    ClientConfig, ClientStatus, LocalListeners, ProxyClient, TunnelDialer, TunnelStream,
};
pub use destination::{
    ClientAuth, DestinationConfig, DestinationState, DestinationStatus, EndpointProvider,
};
pub use forward::{ForwardManager, ForwardSpec, ForwardState, ForwardStatus};
pub use route_table::{Route, RouteSpec, RouteTable, validate_destination_host};
pub use routed_set::RoutedSet;
pub use server::{ProxyServer, ProxyServerParams};
pub use server_routes::{ServerRoutes, fetch_server_routes};
