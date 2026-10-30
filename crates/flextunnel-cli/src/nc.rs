//! `flextunnel client nc`: relay stdin/stdout through one tunnel to a
//! server-side `host:port` — an SSH `ProxyCommand` without a SOCKS listener or
//! an external netcat. The tunnel is opened by the *running* client for the
//! profile over its control socket (see `ipc.rs`), so it rides that client's
//! live connection, and like a port forward the server enforces its routed set
//! and resolves the host.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::instance;
use crate::ipc::IpcClient;

pub fn run(
    config_path: Option<PathBuf>,
    server_node_id: Option<String>,
    host: String,
    port: u16,
) -> Result<()> {
    let instance::Located { key, profile } =
        instance::locate(config_path, server_node_id, "client nc")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let res = rt.block_on(async {
        let Some(client) = IpcClient::connect(&key).await? else {
            anyhow::bail!("The flextunnel client for {profile} is not running.");
        };
        let tunnel = client.open_tunnel(&host, port).await?;
        relay(tunnel).await
    });
    // Tokio reads stdin on a blocking thread that cannot be cancelled; a
    // tunnel the far side closed first leaves that read pending, so don't wait
    // for it on the way out.
    rt.shutdown_background();
    res
}

/// Copy stdin into the tunnel and the tunnel into stdout. Ends when the far
/// side closes; stdin reaching EOF only half-closes the tunnel, so the reply
/// still drains. (A Windows named pipe has no half-close, so there the far side
/// does not see that EOF — nothing an SSH session relies on.)
async fn relay<S>(tunnel: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut from_tunnel, mut to_tunnel) = tokio::io::split(tunnel);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let upload = async {
        tokio::io::copy(&mut stdin, &mut to_tunnel).await?;
        to_tunnel.shutdown().await
    };
    let download = async {
        tokio::io::copy(&mut from_tunnel, &mut stdout).await?;
        stdout.flush().await
    };
    tokio::pin!(download);

    tokio::select! {
        res = &mut download => res.context("Failed to relay the tunnel to stdout"),
        res = upload => {
            res.context("Failed to relay stdin into the tunnel")?;
            (&mut download).await.context("Failed to relay the tunnel to stdout")
        }
    }
}
