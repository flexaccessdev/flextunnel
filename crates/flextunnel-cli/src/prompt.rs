//! Interactive prompts for quick mode (`client start --quick` and
//! `server start --quick`), used when the user opts into entering connection
//! details on a terminal. Fills only the values not already supplied on the
//! command line; nothing is persisted.

use anyhow::{Context, Result};
use std::io::{self, Write};

use flextunnel_core::iroh::EndpointId;

/// What `client start --quick` needs to know that the command line may not
/// have said.
pub struct QuickClient {
    /// The quick server to connect to.
    pub server_id: EndpointId,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
}

/// Prompt (on the terminal) for the quick client's connection details: always
/// the server's EndpointId, and each proxy port not already given on the
/// command line. Never writes a config file — the collected values live only
/// for this session. No auth keypair is involved: the quick client's
/// credential is its endpoint id, entered on the quick server.
pub fn quick_client(socks_port: Option<u16>, http_port: Option<u16>) -> Result<QuickClient> {
    // EndpointId of the server to connect to (printed by `server start --quick`).
    let server_id =
        prompt_endpoint_id("Server EndpointId (shown by `flextunnel server start --quick`)")?;

    // Optional loopback proxy listeners; blank leaves them disabled.
    let socks_port = match socks_port {
        Some(port) => Some(port),
        None => prompt_optional_port("SOCKS5 port (blank = disabled)")?,
    };
    let http_port = match http_port {
        Some(port) => Some(port),
        None => prompt_optional_port("HTTP proxy port (blank = disabled)")?,
    };

    Ok(QuickClient {
        server_id,
        socks_port,
        http_port,
    })
}

/// Prompt for an `EndpointId` under `label`, re-asking until it parses. Shared
/// by the quick client (the server's id) and the quick server (the client's id
/// to allowlist) — ids are public, so no masking is needed.
pub fn prompt_endpoint_id(label: &str) -> Result<EndpointId> {
    loop {
        print!("{label}: ");
        io::stdout().flush().context("Failed to write prompt")?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .context("Failed to read input")?;
        let value = line.trim();
        if value.is_empty() {
            eprintln!("A value is required.");
            continue;
        }
        match value.parse::<EndpointId>() {
            Ok(id) => return Ok(id),
            Err(err) => eprintln!("Invalid EndpointId: {err}"),
        }
    }
}

/// Prompt for an optional `u16` port; a blank line means "disabled" (`None`).
fn prompt_optional_port(label: &str) -> Result<Option<u16>> {
    loop {
        print!("{label}: ");
        io::stdout().flush().context("Failed to write prompt")?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .context("Failed to read input")?;
        let value = line.trim();
        if value.is_empty() {
            return Ok(None);
        }
        match value.parse::<u16>() {
            Ok(port) => return Ok(Some(port)),
            Err(_) => eprintln!("Enter a port number (1-65535) or leave blank."),
        }
    }
}
