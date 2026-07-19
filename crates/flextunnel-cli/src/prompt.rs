//! Interactive first-run prompts for `flextunnel client start`, used when no
//! config file exists (and stdin is a terminal). Fills only the values not
//! already supplied on the command line; nothing is persisted.

use anyhow::{Context, Result};
use std::io::{self, Write};

use flextunnel_core::auth;
use flextunnel_core::config::ClientConfig;
use flextunnel_core::iroh::EndpointId;

/// Prompt (on the terminal) for any client values still missing from `cli`,
/// mutating it in place. Never writes a config file — the collected values live
/// only for this session.
pub fn fill_client_config(cli: &mut ClientConfig) -> Result<()> {
    println!("No client config found. Enter connection details (nothing is saved):");

    // EndpointId of the server to connect to (from `flextunnel show-server-id`).
    if cli.server_node_id.is_none() {
        cli.server_node_id = Some(prompt_server_id()?);
    }

    // Auth token for this client. A `--auth-token-file` supplied on the CLI
    // already satisfies "exactly one of auth_token/auth_token_file", so only
    // prompt when neither is set.
    if cli.auth_token.is_none() && cli.auth_token_file.is_none() {
        cli.auth_token = Some(prompt_auth_token()?);
    }

    // Optional loopback proxy listeners; blank leaves them disabled.
    if cli.socks_port.is_none() {
        cli.socks_port = prompt_optional_port("SOCKS5 port (blank = disabled)")?;
    }
    if cli.http_port.is_none() {
        cli.http_port = prompt_optional_port("HTTP proxy port (blank = disabled)")?;
    }

    Ok(())
}

/// Prompt for the server EndpointId, re-asking until it parses (the same check
/// the client runs when it connects).
fn prompt_server_id() -> Result<String> {
    loop {
        print!("Server EndpointId (from `flextunnel show-server-id`): ");
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
            Ok(_) => return Ok(value.to_string()),
            Err(err) => eprintln!("Invalid EndpointId: {err}"),
        }
    }
}

/// Prompt for a masked auth token, re-asking until it has a valid client-token
/// shape (`ftc…`).
fn prompt_auth_token() -> Result<String> {
    loop {
        let token = rpassword::prompt_password("Auth token (hidden): ")
            .context("Failed to read auth token")?;
        let token = token.trim().to_string();
        match auth::validate_client_token(&token) {
            Ok(()) => return Ok(token),
            Err(err) => eprintln!("Invalid token: {err}"),
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
