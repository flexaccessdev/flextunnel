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
pub mod routed_set;
pub mod server;
pub mod server_routes;
pub mod signaling;
pub mod socks5;
mod splice;
pub mod status_page;

#[cfg(test)]
mod e2e_tests;

pub use client::{
    ClientConfig, ClientStatus, HeldDestination, LocalListeners, ProxyClient, TunnelDialer,
    TunnelStream,
};
pub use destination::{
    ClientAuth, DestinationConfig, DestinationState, DestinationStatus, EndpointProvider,
};
pub use forward::{ForwardManager, ForwardSpec, ForwardState, ForwardStatus};
pub use route_table::{Route, RouteSpec, RouteTable, validate_destination_name};
pub use routed_set::RoutedSet;
pub use server::{ProxyServer, ProxyServerParams};
pub use server_routes::{ServerRoutes, fetch_server_routes};
