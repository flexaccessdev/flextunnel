//! `flextunnel client nc`: relay stdin/stdout through one tunnel to a
//! `host:port` behind one of the client's destinations — an SSH `ProxyCommand`
//! without a SOCKS listener or an external netcat. The tunnel is opened by the
//! *running* client over its control socket (see `ipc.rs`), which routes HOST
//! like a port forward: the destination that routes it connects if it is idle
//! (this command waits while it does), and its server enforces its routed set
//! and resolves the host. A destination's
//! `<name>.localhost.flextunnel.internal` is its server's loopback, so
//! `ProxyCommand flextunnel client nc %h %p` under a `Host` whose `HostName`
//! is `machine1.localhost.flextunnel.internal` reaches that machine's sshd.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::instance;
use crate::ipc::{self, IpcClient};

pub fn run(
    config_path: Option<PathBuf>,
    name: Option<String>,
    host: String,
    port: u16,
) -> Result<()> {
    let located = instance::locate(config_path, name)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let res = rt.block_on(async {
        let Some(client) = IpcClient::connect(&located.name).await? else {
            return Err(located.not_running());
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

/// Copy stdin into the tunnel (as frames, ending in the EOF frame) and the
/// tunnel into stdout. Ends when the far side closes; stdin reaching EOF only
/// half-closes the tunnel, so the reply still drains. The EOFs travel in the
/// protocol rather than as a transport half-close, which a Windows named pipe
/// lacks (see `ipc.rs`).
async fn relay<S>(tunnel: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut from_tunnel, mut to_tunnel) = tokio::io::split(tunnel);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let upload = ipc::copy_to_frames(&mut stdin, &mut to_tunnel);
    let download = async {
        match tokio::io::copy(&mut from_tunnel, &mut stdout).await {
            // A closed Windows pipe can read as broken rather than as EOF.
            Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => return Err(e),
            _ => {}
        }
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
