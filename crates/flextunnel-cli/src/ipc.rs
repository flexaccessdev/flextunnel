//! Local control channel between a running `flextunnel client start` and the
//! commands that attach to it: `flextunnel client control` and
//! `flextunnel client nc`.
//!
//! Transport: a Unix domain socket (`~/.config/flextunnel/client-<key>.sock`)
//! or a Windows named pipe (`\\.\pipe\flextunnel-client-<key>`), where `<key>`
//! is the server-id-prefix instance key (see `instance.rs`). Protocol:
//! JSON Lines, strict request → response over a long-lived connection. Both
//! ends are this one binary and the repo has a no-compatibility policy, so
//! there is no protocol version field.
//!
//! A connection either carries status requests (status and connection-path
//! snapshots), or opens with one [`Request::Connect`] and, once answered with
//! [`Response::Connected`], turns into one tunnel to a server-side target —
//! `client nc`'s stdio relay. From there the client sends length-prefixed
//! frames ending in an empty one (see [`copy_to_frames`]) and the session sends
//! the target's raw bytes, closing the connection when the target closes. A
//! Windows named pipe has no half-close, so neither end of the tunnel may rely
//! on one to carry an EOF. The snapshots describe the
//! user's network and a tunnel reaches into it, so the Unix socket is chmod'd
//! 0600 (owner only), in a 0700 directory. Windows pipe names are global and
//! the default pipe descriptor lets Everyone read, so each pipe instance gets
//! an owner-only descriptor and attaching commands refuse a pipe another user
//! owns (see `pipe_security.rs`).
//!
//! The socket is not the single-instance lock — see `lock.rs` for why. But
//! *because* the caller holds that lock, unconditionally removing a stale
//! socket file before bind is safe: no other live client of this instance can
//! own it.
//!
//! macOS caps `sun_path` around 104 bytes; with the socket under
//! `~/.config/flextunnel/` and the 16-char key, only a pathological home path
//! overflows — that surfaces as a clear bind error.

use anyhow::{Context, Result};
use flextunnel_core::forwards::validate_remote_host;
use flextunnel_core::proxy::ServerForwarder;
use flextunnel_core::proxy::signaling::Target;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

// Windows derives everything from the pipe name; only the Unix socket path
// lives under the instance dir.
#[cfg(unix)]
use crate::instance;
#[cfg(windows)]
use crate::pipe_security;

/// Cap on one JSON line in either direction.
const MAX_LINE: usize = 1024 * 1024;
/// Client-side timeout for connect and for each request round trip.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// Client-side timeout for a [`Request::Connect`] answer: past the core's own
/// 30 s bound on opening a tunnel, so the client's error arrives first.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(35);
/// Largest payload of one client-to-session tunnel frame.
const MAX_FRAME: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// On-demand connection-path + custom-relay-health snapshot (mirrors the
    /// desktop modal / iOS sheet). Kept off the polled `Status` because the
    /// custom-relay `/healthz` probe does on-demand HTTP.
    ConnPath,
    /// Open a tunnel to `host:port` on the server side, like a port forward:
    /// the server enforces its routed set and resolves the host. Answered with
    /// [`Response::Connected`], after which the connection is that tunnel's
    /// byte stream, or with [`Response::Error`].
    Connect { host: String, port: u16 },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "resp", rename_all = "snake_case")]
pub enum Response {
    Status(Box<StatusSnapshot>),
    ConnPath(WireConnSnapshot),
    Connected,
    Error { message: String },
}

/// One declared forward as the panel sees it (the config entry, normalized).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireForward {
    #[serde(default)]
    pub label: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

impl WireForward {
    /// Label if set, otherwise `host:port` — mirrors `PortForward::display_name`.
    pub fn display_name(&self) -> String {
        let label = self.label.trim();
        if label.is_empty() {
            flextunnel_core::forwards::format_host_port(&self.remote_host, self.remote_port)
        } else {
            label.to_string()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Connecting => "connecting",
            Phase::Connected => "connected",
            Phase::Reconnecting => "reconnecting",
            Phase::Failed => "failed",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusSnapshot {
    /// The server-id-prefix instance key (see `instance.rs`).
    pub instance: String,
    /// Friendly profile name from the config ("aws", "home network"), if set.
    pub name: Option<String>,
    pub phase: Phase,
    /// Uptime of the current connection, if connected.
    pub connected_secs: Option<u64>,
    pub server_node_id: String,
    pub client_node_id: String,
    pub socks_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
    /// Reserved host that is always tunneled to the server's status page.
    pub status_page_host: String,
    /// Reserved host that is always tunneled to the server's own loopback.
    pub localhost_host: String,
    /// Consecutive failed connection attempts in the current outage (0 while
    /// connected).
    pub failed_attempts: u32,
    /// Seconds until the next connection attempt is due while backing off;
    /// `Some(0)` while an attempt is in progress, `None` when none is pending.
    pub next_attempt_secs: Option<u64>,
    /// What the last connection attempt failed with, while the tunnel is down.
    pub last_error: Option<String>,
    pub routes: WireRoutes,
    pub forwards: Vec<ForwardRow>,
}

/// On-demand connection snapshot served for [`Request::ConnPath`]: the live iroh
/// path(s) plus custom-relay `/healthz` health. Both are empty while the tunnel
/// link is down.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WireConnSnapshot {
    pub paths: Vec<WireConnPath>,
    pub custom_relays: Vec<WireCustomRelay>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WireCustomRelay {
    pub url: String,
    /// `Some(true)` = up (2xx), `Some(false)` = down, `None` = check not run.
    pub working: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WireRoutes {
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    /// alias → target, resolved server-side.
    pub host_aliases: Vec<(String, String)>,
    /// suffix → upstream servers.
    pub dns_forwards: Vec<(String, Vec<String>)>,
    pub bridges: Vec<WireBridge>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WireBridge {
    pub name: String,
    pub endpoint_id: String,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WireConnPath {
    /// "direct" | "relay" | "other".
    pub kind: String,
    pub display: String,
    pub selected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardRowState {
    /// Switched off after its listener failed to bind (see `error`).
    Stopped,
    Starting,
    Listening,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForwardRow {
    #[serde(flatten)]
    pub forward: WireForward,
    pub state: ForwardRowState,
    /// Bind-failure reason — including the retained reason of a forward that
    /// was auto-disabled after its listener failed to bind.
    pub error: Option<String>,
    /// Live relayed connections.
    pub active: usize,
    pub last_conn_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Session-side command plumbing
// ---------------------------------------------------------------------------

/// What a connection task asks of the client session loop.
pub enum IpcCmd {
    Status(oneshot::Sender<StatusSnapshot>),
    ConnPath(oneshot::Sender<WireConnSnapshot>),
}

/// Opens the tunnels [`Request::Connect`] asks for: the session's
/// [`ServerForwarder`], or an in-memory stand-in in tests.
pub trait TunnelOpener: Clone + Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;
    fn open(&self, target: Target) -> impl Future<Output = Result<Self::Stream>> + Send;
}

impl TunnelOpener for ServerForwarder {
    type Stream = tokio::io::Join<
        flextunnel_core::iroh::endpoint::RecvStream,
        flextunnel_core::iroh::endpoint::SendStream,
    >;

    async fn open(&self, target: Target) -> Result<Self::Stream> {
        self.connect(&target).await
    }
}

// ---------------------------------------------------------------------------
// Naming
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn socket_path(key: &str) -> Result<std::path::PathBuf> {
    Ok(instance::instance_dir()?.join(format!("client-{key}.sock")))
}

#[cfg(windows)]
fn pipe_name(key: &str) -> String {
    format!(r"\\.\pipe\flextunnel-client-{key}")
}

// ---------------------------------------------------------------------------
// Server side (runs inside the client session)
// ---------------------------------------------------------------------------

/// Owns the accept task; dropping it stops serving and (Unix) removes the
/// socket file.
pub struct IpcServerGuard {
    task: JoinHandle<()>,
    #[cfg(unix)]
    socket: std::path::PathBuf,
}

impl Drop for IpcServerGuard {
    fn drop(&mut self) {
        self.task.abort();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Start serving the control channel for `instance`, opening `client nc`
/// tunnels through `opener`. The caller must already hold the instance lock
/// (that is what makes the stale-socket removal safe).
pub fn spawn_ipc_server(
    key: &str,
    tx: mpsc::Sender<IpcCmd>,
    opener: impl TunnelOpener,
) -> Result<IpcServerGuard> {
    #[cfg(unix)]
    {
        spawn_unix(socket_path(key)?, tx, opener)
    }
    #[cfg(windows)]
    {
        spawn_pipe(pipe_name(key), tx, opener)
    }
}

#[cfg(unix)]
fn spawn_unix(
    socket: std::path::PathBuf,
    tx: mpsc::Sender<IpcCmd>,
    opener: impl TunnelOpener,
) -> Result<IpcServerGuard> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    // Owner-only directory before the bind: the socket is created with umask
    // permissions and only chmod'd below, so the directory is what keeps other
    // users out in between. It usually exists already (the instance lock
    // creates it with umask permissions), so tighten it rather than only
    // creating it that way.
    if let Some(dir) = socket.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Failed to set permissions on {}", dir.display()))?;
    }
    // Safe unconditionally: the instance lock guarantees no live owner.
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)
        .with_context(|| format!("Failed to bind control socket {}", socket.display()))?;
    // Owner-only: the snapshots describe the user's network layout.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set permissions on {}", socket.display()))?;
    log::info!("Control socket listening on {}", socket.display());

    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(serve_connection(stream, tx.clone(), opener.clone()));
                }
                Err(e) => {
                    log::warn!("Control socket accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(IpcServerGuard { task, socket })
}

#[cfg(windows)]
fn spawn_pipe(
    name: String,
    tx: mpsc::Sender<IpcCmd>,
    opener: impl TunnelOpener,
) -> Result<IpcServerGuard> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let sid = pipe_security::current_user_sid().context("Failed to read the current user's SID")?;
    // `first_pipe_instance` makes creation fail if another process already
    // owns the name — defense in depth on top of the instance lock, and what
    // keeps another user's squatted pipe from being joined.
    let mut first = ServerOptions::new();
    first.first_pipe_instance(true);
    let mut server = pipe_security::create_owner_only(&first, &name, &sid)
        .with_context(|| format!("Failed to create control pipe {name}"))?;
    log::info!("Control pipe listening on {name}");

    let task = tokio::spawn(async move {
        loop {
            if let Err(e) = server.connect().await {
                log::warn!("Control pipe connect failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            // Create the next pipe instance *before* serving the connected one
            // so the name never briefly disappears for a concurrent attacher.
            // A transient creation failure must not disable IPC for the rest
            // of the session — retry until it succeeds (the guard aborts this
            // task on shutdown, which bounds the loop).
            let next = loop {
                match pipe_security::create_owner_only(&ServerOptions::new(), &name, &sid) {
                    Ok(next) => break next,
                    Err(e) => {
                        log::warn!("Failed to re-create control pipe {name}: {e}; retrying");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            };
            let conn = std::mem::replace(&mut server, next);
            tokio::spawn(serve_connection(conn, tx.clone(), opener.clone()));
        }
    });
    Ok(IpcServerGuard { task })
}

/// Serve one attached command: read a JSON-line request, forward it to the
/// session loop, write the JSON-line response; repeat until EOF. A malformed
/// line gets `Response::Error` and the connection stays open; a closed session
/// channel ends the connection. A [`Request::Connect`] hands the connection
/// over to [`serve_tunnel`] for good.
async fn serve_connection<S>(stream: S, tx: mpsc::Sender<IpcCmd>, opener: impl TunnelOpener)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);
    let mut line = Vec::new();
    loop {
        line.clear();
        match read_line_capped(&mut stream, &mut line).await {
            Ok(0) => return, // EOF: the TUI detached.
            Ok(_) => {}
            Err(e) => {
                log::debug!("Control connection read failed: {e}");
                return;
            }
        }

        let response = match serde_json::from_slice::<Request>(&line) {
            Ok(Request::Connect { host, port }) => {
                return serve_tunnel(stream, &opener, host, port).await;
            }
            Ok(request) => match dispatch(request, &tx).await {
                Some(response) => response,
                None => return, // Session loop gone: client is shutting down.
            },
            Err(e) => Response::Error {
                message: format!("Bad request: {e}"),
            },
        };
        if let Err(e) = write_response(&mut stream, &response).await {
            log::debug!("Control connection write failed: {e}");
            return;
        }
    }
}

/// Open the tunnel a [`Request::Connect`] asked for, answer it, and on success
/// relay it: the caller's frames into the tunnel, ending in a half-close of the
/// tunnel at the empty frame, and the tunnel's bytes back raw. The connection
/// closes when the target closes, which is how the caller sees that EOF.
/// `stream` is read through the buffered reader the request came in on, so
/// frames the caller sent right behind the request are not lost.
async fn serve_tunnel<S>(
    mut stream: BufReader<S>,
    opener: &impl TunnelOpener,
    host: String,
    port: u16,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = format!("{host}:{port}");
    let opened = match validate_remote_host(&host) {
        Ok(_) if port == 0 => Err(anyhow::anyhow!("port must be 1-65535")),
        Ok(host) => opener.open(Target::Domain(host, port)).await,
        Err(e) => Err(anyhow::anyhow!(e)),
    };
    let mut tunnel = match opened {
        Ok(tunnel) => tunnel,
        Err(e) => {
            log::debug!("nc tunnel to {target} failed: {e:#}");
            let message = format!("{target}: {e:#}");
            let _ = write_response(&mut stream, &Response::Error { message }).await;
            return;
        }
    };
    if let Err(e) = write_response(&mut stream, &Response::Connected).await {
        log::debug!("Control connection write failed: {e}");
        return;
    }
    log::debug!("nc tunnel to {target} opened");
    let (mut from_caller, mut to_caller) = tokio::io::split(stream);
    let (mut from_tunnel, mut to_tunnel) = tokio::io::split(&mut tunnel);
    let upload = async {
        copy_from_frames(&mut from_caller, &mut to_tunnel).await?;
        to_tunnel.shutdown().await
    };
    let download = async {
        tokio::io::copy(&mut from_tunnel, &mut to_caller).await?;
        to_caller.flush().await
    };
    tokio::pin!(download);
    // The target closing ends the relay even while the caller still has input;
    // the caller's EOF only half-closes the tunnel, so the reply still drains.
    let res = tokio::select! {
        res = &mut download => res,
        res = upload => match res {
            Ok(()) => (&mut download).await,
            Err(e) => Err(e),
        },
    };
    if let Err(e) = res {
        log::debug!("nc tunnel to {target} ended: {e}");
    }
}

/// Copy `reader` into `writer` as tunnel frames — a 4-byte big-endian length,
/// then that many bytes — ending with an empty frame at `reader`'s EOF.
pub async fn copy_to_frames<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 4 + MAX_FRAME];
    loop {
        let n = reader.read(&mut buf[4..]).await?;
        buf[..4].copy_from_slice(&(n as u32).to_be_bytes());
        writer.write_all(&buf[..4 + n]).await?;
        if n == 0 {
            return writer.flush().await;
        }
    }
}

/// Copy tunnel frames from `reader` into `writer` until the empty frame.
async fn copy_from_frames<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        let len = reader.read_u32().await? as usize;
        if len == 0 {
            return Ok(());
        }
        if len > MAX_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tunnel frame of {len} bytes exceeds {MAX_FRAME}"),
            ));
        }
        reader.read_exact(&mut buf[..len]).await?;
        writer.write_all(&buf[..len]).await?;
    }
}

/// Write one JSON-line response.
async fn write_response<W>(writer: &mut W, response: &Response) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = serde_json::to_vec(response).map_err(std::io::Error::other)?;
    buf.push(b'\n');
    writer.write_all(&buf).await
}

async fn dispatch(request: Request, tx: &mpsc::Sender<IpcCmd>) -> Option<Response> {
    let (cmd, pending) = build_cmd(request)?;
    tx.send(cmd).await.ok()?;
    pending.into_response().await
}

/// Run one request against the session loop over the in-process command channel,
/// blocking the current thread for the reply. Used by the self-contained quick
/// panel (`client start --quick`), which drives its own session directly instead
/// of over a socket. Returns `None` once the session loop is gone (its receiver
/// dropped, or the reply sender dropped), which signals the panel to exit — and
/// for a [`Request::Connect`], which the panel never sends.
pub fn blocking_request(tx: &mpsc::Sender<IpcCmd>, request: Request) -> Option<Response> {
    let (cmd, pending) = build_cmd(request)?;
    tx.blocking_send(cmd).ok()?;
    pending.blocking_into_response()
}

/// The reply half of an [`IpcCmd`], kept separate from sending it so the command
/// can be awaited either async (the socket accept loop) or blocking (the
/// in-process quick panel) while the request → command mapping stays in one
/// place ([`build_cmd`]).
enum PendingReply {
    Status(oneshot::Receiver<StatusSnapshot>),
    ConnPath(oneshot::Receiver<WireConnSnapshot>),
}

impl PendingReply {
    async fn into_response(self) -> Option<Response> {
        Some(match self {
            PendingReply::Status(rx) => Response::Status(Box::new(rx.await.ok()?)),
            PendingReply::ConnPath(rx) => Response::ConnPath(rx.await.ok()?),
        })
    }

    fn blocking_into_response(self) -> Option<Response> {
        Some(match self {
            PendingReply::Status(rx) => Response::Status(Box::new(rx.blocking_recv().ok()?)),
            PendingReply::ConnPath(rx) => Response::ConnPath(rx.blocking_recv().ok()?),
        })
    }
}

/// The session-loop command for a status request; `None` for a
/// [`Request::Connect`], which is no session query (see [`serve_tunnel`]).
fn build_cmd(request: Request) -> Option<(IpcCmd, PendingReply)> {
    Some(match request {
        Request::Status => {
            let (reply, rx) = oneshot::channel();
            (IpcCmd::Status(reply), PendingReply::Status(rx))
        }
        Request::ConnPath => {
            let (reply, rx) = oneshot::channel();
            (IpcCmd::ConnPath(reply), PendingReply::ConnPath(rx))
        }
        Request::Connect { .. } => return None,
    })
}

/// Read one `\n`-terminated line into `buf`, rejecting lines over [`MAX_LINE`]
/// (`read_line` alone would buffer without bound). Returns the number of bytes
/// read (0 on clean EOF); the trailing newline is stripped.
async fn read_line_capped<R>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    let mut total = 0usize;
    loop {
        let read = (&mut *reader)
            .take((MAX_LINE + 1 - buf.len()) as u64)
            .read_until(b'\n', buf)
            .await?;
        total += read;
        if read == 0 || buf.last() == Some(&b'\n') {
            while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
                buf.pop();
            }
            return Ok(total);
        }
        if buf.len() > MAX_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "control message exceeds the 1 MiB line cap",
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Client side (used by `flextunnel client control` and `flextunnel client nc`)
// ---------------------------------------------------------------------------

#[cfg(unix)]
type ClientStream = tokio::net::UnixStream;
#[cfg(windows)]
type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

pub struct IpcClient {
    /// Kept so a request that had to discard its stream (see [`request`]) can
    /// reconnect on the next call.
    ///
    /// [`request`]: IpcClient::request
    key: String,
    /// `None` after a timed-out request left a half-consumed response on the
    /// wire; the next request reconnects before sending.
    stream: Option<BufReader<ClientStream>>,
}

impl IpcClient {
    /// Connect to the running client for the given instance key. `Ok(None)`
    /// means nothing is listening — the client is not running.
    pub async fn connect(key: &str) -> Result<Option<Self>> {
        match tokio::time::timeout(REQUEST_TIMEOUT, Self::open(key)).await {
            Ok(Ok(stream)) => Ok(Some(Self {
                key: key.to_string(),
                stream: Some(BufReader::new(stream)),
            })),
            Ok(Err(e)) if is_not_running(&e) => Ok(None),
            Ok(Err(e)) => Err(e).context("Failed to connect to the control socket"),
            Err(_) => anyhow::bail!("Timed out connecting to the control socket"),
        }
    }

    #[cfg(unix)]
    async fn open(key: &str) -> std::io::Result<ClientStream> {
        let path = socket_path(key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        tokio::net::UnixStream::connect(path).await
    }

    #[cfg(windows)]
    async fn open(key: &str) -> std::io::Result<ClientStream> {
        use tokio::net::windows::named_pipe::ClientOptions;

        const ERROR_PIPE_BUSY: i32 = 231;
        let name = pipe_name(key);
        let sid = pipe_security::current_user_sid()?;
        // All pipe instances can be momentarily busy between one attacher
        // connecting and the server pre-creating the next instance; retry
        // briefly (the outer connect() timeout still bounds the wait).
        loop {
            match ClientOptions::new().open(&name) {
                // Only a pipe this user's client created is the client.
                Ok(stream) => {
                    pipe_security::check_owner(&stream, &sid)?;
                    return Ok(stream);
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// One request → response round trip, bounded by [`REQUEST_TIMEOUT`].
    ///
    /// On timeout the stream is discarded rather than reused: a response may
    /// still be in flight, and pairing it with the *next* request would return
    /// a stale answer. The next call reconnects through [`Self::open`] first.
    pub async fn request(&mut self, request: &Request) -> Result<Response> {
        if self.stream.is_none() {
            self.reconnect().await?;
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, self.round_trip(request)).await {
            Ok(result) => result,
            Err(_) => {
                self.stream = None;
                Err(anyhow::anyhow!("Timed out waiting for the client's response"))
            }
        }
    }

    /// Re-establish the connection after a prior request discarded its stream.
    async fn reconnect(&mut self) -> Result<()> {
        match tokio::time::timeout(REQUEST_TIMEOUT, Self::open(&self.key)).await {
            Ok(Ok(stream)) => {
                self.stream = Some(BufReader::new(stream));
                Ok(())
            }
            Ok(Err(e)) => Err(e).context("Failed to reconnect to the control socket"),
            Err(_) => anyhow::bail!("Timed out reconnecting to the control socket"),
        }
    }

    async fn round_trip(&mut self, request: &Request) -> Result<Response> {
        let stream = self
            .stream
            .as_mut()
            .expect("stream reconnected before round_trip");
        round_trip(stream, request).await
    }

    /// Turn this connection into a tunnel to `host:port` on the server side
    /// (see [`Request::Connect`]): write to it in frames ([`copy_to_frames`]);
    /// it reads back the target's bytes, starting with any the target sent
    /// before this call returned, and ends when the target closes.
    pub async fn open_tunnel(
        mut self,
        host: &str,
        port: u16,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin + use<>> {
        let mut stream = match self.stream.take() {
            Some(stream) => stream,
            None => BufReader::new(Self::open(&self.key).await?),
        };
        let request = Request::Connect {
            host: host.to_string(),
            port,
        };
        let response = tokio::time::timeout(CONNECT_TIMEOUT, round_trip(&mut stream, &request))
            .await
            .map_err(|_| anyhow::anyhow!("Timed out waiting for the client to open the tunnel"))??;
        match response {
            Response::Connected => Ok(stream),
            Response::Error { message } => Err(anyhow::anyhow!(message)),
            other => anyhow::bail!("Unexpected response to a connect request: {other:?}"),
        }
    }
}

/// Send one JSON-line request on `stream` and read its JSON-line response.
async fn round_trip<S>(stream: &mut BufReader<S>, request: &Request) -> Result<Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = serde_json::to_vec(request)?;
    buf.push(b'\n');
    stream.get_mut().write_all(&buf).await?;

    let mut line = Vec::new();
    let read = read_line_capped(stream, &mut line).await?;
    if read == 0 {
        anyhow::bail!("The client closed the control connection");
    }
    serde_json::from_slice(&line).context("Malformed control response")
}

fn is_not_running(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_forward() -> WireForward {
        WireForward {
            label: "db".into(),
            local_port: 5432,
            remote_host: "db.internal".into(),
            remote_port: 5432,
        }
    }

    fn snapshot() -> StatusSnapshot {
        StatusSnapshot {
            instance: "62e463a6d67fdeac".into(),
            name: Some("aws".into()),
            phase: Phase::Connected,
            connected_secs: Some(61),
            server_node_id: "server".into(),
            client_node_id: "client".into(),
            socks_addr: Some("127.0.0.1:1080".parse().unwrap()),
            http_addr: None,
            status_page_host: "flextunnel.internal".into(),
            localhost_host: "localhost.flextunnel.internal".into(),
            failed_attempts: 0,
            next_attempt_secs: None,
            last_error: None,
            routes: WireRoutes {
                domains: vec!["*.internal".into()],
                cidrs: vec![],
                host_aliases: vec![("nas.internal".into(), "10.0.0.7".into())],
                dns_forwards: vec![("test.example".into(), vec!["10.22.33.10".into()])],
                bridges: vec![WireBridge {
                    name: "kube1".into(),
                    endpoint_id: "abc".into(),
                    domains: vec!["*.svc".into()],
                    cidrs: vec![],
                }],
            },
            forwards: vec![ForwardRow {
                forward: wire_forward(),
                state: ForwardRowState::Listening,
                error: None,
                active: 2,
                last_conn_error: None,
            }],
        }
    }

    #[test]
    fn wire_types_roundtrip() {
        let connect = Request::Connect {
            host: "workstation.internal".into(),
            port: 22,
        };
        for request in [Request::Status, Request::ConnPath, connect] {
            let json = serde_json::to_string(&request).unwrap();
            let _: Request = serde_json::from_str(&json).unwrap();
        }

        let json = serde_json::to_string(&Response::Status(Box::new(snapshot()))).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        match back {
            Response::Status(s) => {
                assert_eq!(s.phase, Phase::Connected);
                assert_eq!(s.forwards.len(), 1);
                assert_eq!(s.forwards[0].forward.local_port, 5432);
                assert_eq!(s.forwards[0].state, ForwardRowState::Listening);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// Stub session loop: answers Status and ConnPath with canned snapshots.
    fn stub_session() -> mpsc::Sender<IpcCmd> {
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    IpcCmd::Status(reply) => {
                        let _ = reply.send(snapshot());
                    }
                    IpcCmd::ConnPath(reply) => {
                        let _ = reply.send(WireConnSnapshot {
                            paths: vec![WireConnPath {
                                kind: "direct".into(),
                                display: "Direct 1.2.3.4:52186 (rtt 1ms)".into(),
                                selected: true,
                            }],
                            custom_relays: vec![WireCustomRelay {
                                url: "https://relay.example/".into(),
                                working: Some(true),
                                error: None,
                            }],
                        });
                    }
                }
            }
        });
        tx
    }

    /// Spin up the real platform transport (UDS here, named pipe on Windows)
    /// against the stub session and drive it through the real `IpcClient`.
    #[tokio::test]
    async fn loopback_status_and_conn_path() {
        // Unique per test run: instance names (and thus pipe names on
        // Windows) are global, and parallel `cargo test` runs must not collide.
        let instance = format!("test-ipc-{}", std::process::id());

        #[cfg(unix)]
        let (_dir, guard) = {
            // Keep the socket out of the real ~/.config: bind at a temp path
            // through the same internal entry point the public API uses.
            let dir = tempfile::tempdir().unwrap();
            let guard = spawn_unix(
                dir.path().join(format!("client-{instance}.sock")),
                stub_session(),
                EchoOpener,
            )
            .unwrap();
            (dir, guard)
        };
        #[cfg(windows)]
        let guard = spawn_pipe(pipe_name(&instance), stub_session(), EchoOpener).unwrap();

        #[cfg(unix)]
        let mut client = {
            let path = _dir.path().join(format!("client-{instance}.sock"));
            IpcClient {
                key: instance.clone(),
                stream: Some(BufReader::new(
                    tokio::net::UnixStream::connect(path).await.unwrap(),
                )),
            }
        };
        #[cfg(windows)]
        let mut client = IpcClient::connect(&instance).await.unwrap().expect("running");

        // Status.
        match client.request(&Request::Status).await.unwrap() {
            Response::Status(s) => {
                assert_eq!(s.instance, "62e463a6d67fdeac");
                assert_eq!(s.name.as_deref(), Some("aws"));
            }
            other => panic!("expected Status, got {other:?}"),
        }

        // The on-demand snapshot...
        match client.request(&Request::ConnPath).await.unwrap() {
            Response::ConnPath(s) => assert_eq!(s.paths.len(), 1),
            other => panic!("expected ConnPath, got {other:?}"),
        }

        // ...and a malformed line gets an error while the connection stays open.
        let stream = client.stream.as_mut().unwrap();
        stream.get_mut().write_all(b"{\"cmd\":\"nope\"}\n").await.unwrap();
        let mut line = Vec::new();
        read_line_capped(stream, &mut line).await.unwrap();
        match serde_json::from_slice::<Response>(&line).unwrap() {
            Response::Error { message } => assert!(message.contains("Bad request"), "{message}"),
            other => panic!("expected Error, got {other:?}"),
        }
        match client.request(&Request::Status).await.unwrap() {
            Response::Status(_) => {}
            other => panic!("expected Status, got {other:?}"),
        }

        drop(guard);
    }

    /// Stand-in for the session's forwarder: each tunnel is an in-memory pipe
    /// whose far end greets first (as an SSH server does), then echoes until
    /// EOF. `refused.internal` is turned away, as an off-list target would be.
    #[derive(Clone)]
    struct EchoOpener;

    impl TunnelOpener for EchoOpener {
        type Stream = tokio::io::DuplexStream;

        async fn open(&self, target: Target) -> Result<Self::Stream> {
            if matches!(&target, Target::Domain(host, _) if host == "refused.internal") {
                anyhow::bail!("server rejected target: connection not allowed by ruleset");
            }
            let (near, far) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let (mut from_near, mut to_near) = tokio::io::split(far);
                to_near.write_all(b"SSH-2.0-echo\r\n").await?;
                tokio::io::copy(&mut from_near, &mut to_near).await?;
                to_near.shutdown().await
            });
            Ok(near)
        }
    }

    /// Serve the real platform transport against the stub session and return
    /// a way to attach fresh connections to it.
    struct Served {
        guard: IpcServerGuard,
        #[cfg(unix)]
        _dir: tempfile::TempDir,
        #[cfg(unix)]
        path: std::path::PathBuf,
        #[cfg(windows)]
        instance: String,
    }

    impl Served {
        fn start(name: &str) -> Self {
            let instance = format!("test-{name}-{}", std::process::id());
            #[cfg(unix)]
            {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join(format!("client-{instance}.sock"));
                let guard = spawn_unix(path.clone(), stub_session(), EchoOpener).unwrap();
                Self {
                    guard,
                    _dir: dir,
                    path,
                }
            }
            #[cfg(windows)]
            {
                let guard = spawn_pipe(pipe_name(&instance), stub_session(), EchoOpener).unwrap();
                Self { guard, instance }
            }
        }

        async fn attach(&self) -> IpcClient {
            #[cfg(unix)]
            {
                IpcClient {
                    key: String::new(),
                    stream: Some(BufReader::new(
                        tokio::net::UnixStream::connect(&self.path).await.unwrap(),
                    )),
                }
            }
            #[cfg(windows)]
            {
                IpcClient::connect(&self.instance).await.unwrap().expect("running")
            }
        }
    }

    #[tokio::test]
    async fn connect_turns_the_connection_into_the_tunnel() {
        let served = Served::start("nc");
        let mut tunnel = served
            .attach()
            .await
            .open_tunnel("echo.internal", 22)
            .await
            .unwrap();

        // The greeting the far end sent before the reply was read is not lost.
        let mut banner = [0u8; 14];
        tunnel.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-echo\r\n");

        // Our input, then its EOF as the empty frame: the far end echoes it
        // and closes, and that close ends the connection — EOF both ways with
        // no transport half-close, as on a Windows named pipe.
        let (mut from_tunnel, mut to_tunnel) = tokio::io::split(tunnel);
        copy_to_frames(&mut &b"hello\n"[..], &mut to_tunnel).await.unwrap();
        let mut echo = Vec::new();
        from_tunnel.read_to_end(&mut echo).await.unwrap();
        assert_eq!(echo, b"hello\n");

        drop(served.guard);
    }

    #[tokio::test]
    async fn frames_round_trip_and_cap_their_size() {
        let input: Vec<u8> = (0..3 * MAX_FRAME + 17).map(|i| i as u8).collect();
        let mut framed = Vec::new();
        copy_to_frames(&mut &input[..], &mut framed).await.unwrap();
        assert!(framed.ends_with(&[0, 0, 0, 0]), "ends with the empty frame");
        let mut output = Vec::new();
        copy_from_frames(&mut &framed[..], &mut output).await.unwrap();
        assert_eq!(output, input);

        let oversized = ((MAX_FRAME + 1) as u32).to_be_bytes();
        let err = copy_from_frames(&mut &oversized[..], &mut Vec::new()).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socket_dir_is_tightened_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let socket_dir = dir.path().join("flextunnel");
        std::fs::create_dir(&socket_dir).unwrap();
        std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let guard = spawn_unix(socket_dir.join("client-test.sock"), stub_session(), EchoOpener)
            .unwrap();
        let mode = std::fs::metadata(&socket_dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        drop(guard);
    }

    #[tokio::test]
    async fn connect_failures_come_back_as_errors() {
        let served = Served::start("nc-err");
        for (host, port, expected) in [
            ("refused.internal", 22, "refused.internal:22: server rejected target"),
            ("echo.internal", 0, "port must be 1-65535"),
            ("bad..host", 22, "bad..host:22"),
        ] {
            let err = match served.attach().await.open_tunnel(host, port).await {
                Ok(_) => panic!("{host}:{port} should fail"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains(expected), "{host}:{port}: {err}");
        }
        drop(served.guard);
    }

    #[tokio::test]
    async fn not_running_is_none() {
        // No client is serving this instance name.
        let missing = format!("test-missing-{}", std::process::id());
        assert!(IpcClient::connect(&missing).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_line_is_rejected() {
        let mut input = vec![b'a'; MAX_LINE + 10];
        input.push(b'\n');
        let mut reader = BufReader::new(std::io::Cursor::new(input));
        let mut buf = Vec::new();
        let err = read_line_capped(&mut reader, &mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn capped_reader_handles_lines_and_eof() {
        let mut reader = BufReader::new(std::io::Cursor::new(b"hello\nworld".to_vec()));
        let mut buf = Vec::new();
        assert_eq!(read_line_capped(&mut reader, &mut buf).await.unwrap(), 6);
        assert_eq!(buf, b"hello");
        buf.clear();
        // Final unterminated chunk, then clean EOF.
        assert_eq!(read_line_capped(&mut reader, &mut buf).await.unwrap(), 5);
        assert_eq!(buf, b"world");
        buf.clear();
        assert_eq!(read_line_capped(&mut reader, &mut buf).await.unwrap(), 0);
    }
}
