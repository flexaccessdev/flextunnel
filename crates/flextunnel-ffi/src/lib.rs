//! C FFI surface for the iOS app (`aarch64-apple-ios`).
//!
//! The app links `libflextunnel.xcframework` (containing `libflextunnel.a`
//! slices) and drives the in-process SOCKS5 proxy primarily with these calls:
//!
//! 1. [`flextunnel_start`] — parse the JSON config, create an iroh endpoint,
//!    bind a loopback SOCKS5 listener on a **fixed** port, and spawn the
//!    connect/auth/serve loop on an embedded runtime. Returns an opaque handle
//!    and writes `{"socks_port": N}` to the caller's buffer so the app can point
//!    `WKWebsiteDataStore.proxyConfigurations` at `127.0.0.1:N`. At most **one**
//!    instance may run at a time (a process-global guard rejects a second).
//! 2. [`flextunnel_health`] — cheap liveness probe: is the serve loop still
//!    running, or did it give up (bad node id / auth / unreachable server)?
//! 3. [`flextunnel_routes`] — snapshot the server-pushed split-tunnel set for UI.
//! 4. [`flextunnel_stop`] — abort the loop, close the endpoint, free the handle.
//!
//! Unlike the ezvpn FFI there is **no VPN / Network Extension and no `utun` fd**:
//! flextunnel is pure-userspace SOCKS5-over-QUIC, so the listener runs entirely
//! inside the app process. The app is expected to work only in the foreground —
//! when iOS suspends it the runtime freezes and the QUIC connection idle-times
//! out; the reconnect loop re-establishes on return to the foreground.
//!
//! All functions are null-safe and never unwind across the FFI boundary (the
//! release profile is `panic = "abort"`, so a panic terminates the process
//! rather than crossing into Swift).
//!
//! ## Config JSON (input to `flextunnel_start`)
//!
//! `auth_token` and `server_node_id` are required; the rest are optional. The
//! routed set (the *tunnel set* that decides split-tunneling) is configured on
//! the server and pushed to the client during the handshake, so the app sends
//! no routed set of its own.
//!
//! ```json
//! {
//!   "server_node_id": "<iroh endpoint id>",
//!   "auth_token": "<flextunnel auth token>",
//!   "socks_port": 18080,
//!   "relay_urls": ["https://relay.example/"],
//!   "dns_server": null
//! }
//! ```
//!
//! ## Result JSON (output of `flextunnel_start` on success)
//!
//! ```json
//! { "socks_port": 49152 }
//! ```

use std::ffi::{CStr, c_char, c_int};
use std::net::{Ipv4Addr, SocketAddr};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use tokio::net::TcpListener;

use flextunnel_core::error::ProxyResult;
use flextunnel_core::proxy::{ClientConfig, ProxyClient, TunnelRoutes};
use flextunnel_core::transport::endpoint::create_client_endpoint;

/// Loopback SOCKS5 port used when the config omits `socks_port`. Fixed (not an
/// OS-assigned ephemeral port) so the proxy is always reachable at a known
/// address — easier to point tools at and to debug.
const DEFAULT_SOCKS_PORT: u16 = 18080;

/// Process-global guard enforcing **at most one** running proxy instance. A
/// second [`flextunnel_start`] while one is live is rejected rather than racing
/// for the fixed port. Claimed on a successful start, released by
/// [`flextunnel_stop`] (or any start failure path).
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Opaque handle owned by the Swift side. Created by [`flextunnel_start`], freed
/// by [`flextunnel_stop`].
pub struct FlextunnelHandle {
    runtime: tokio::runtime::Runtime,
    /// Kept so [`flextunnel_stop`] can close it gracefully before drop.
    endpoint: iroh::Endpoint,
    /// The running connect/serve loop.
    task: tokio::task::JoinHandle<ProxyResult<()>>,
    /// Live tunnel set (split-tunnel domains/CIDRs the server pushed), refreshed
    /// by the serve loop on each (re)connect. Read by [`flextunnel_routes`].
    routes: Arc<Mutex<TunnelRoutes>>,
}

#[derive(Deserialize)]
struct FfiConfig {
    server_node_id: String,
    auth_token: String,
    /// Fixed loopback port to bind (defaults to [`DEFAULT_SOCKS_PORT`]).
    #[serde(default)]
    socks_port: Option<u16>,
    #[serde(default)]
    relay_urls: Vec<String>,
    #[serde(default)]
    dns_server: Option<String>,
}

/// Initialize logging (stderr -> unified log / Console). Honors `RUST_LOG`,
/// otherwise keeps flextunnel's own crates at `info` while quieting noisy
/// dependencies (iroh and friends) to `warn`. Idempotent; safe to call more
/// than once.
///
/// # Safety
/// No arguments; always safe to call.
#[unsafe(no_mangle)]
pub extern "C" fn flextunnel_init_logging() {
    flextunnel_core::app::init_logger(
        "warn,flextunnel_core=info,flextunnel_ffi=info,flextunnel_cli=info",
    );
}

/// Start the in-process SOCKS5 proxy.
///
/// Returns a non-null handle on success and writes `{"socks_port": N}` to
/// `out_buf`. On failure returns null and writes an error message to `out_buf`.
/// If `out_buf` is too small for the result JSON, that is treated as a failure
/// (null returned, no handle leaked) — retry with a larger buffer.
///
/// # Safety
/// - `config_json` must be a valid, NUL-terminated UTF-8 C string.
/// - `out_buf` must point to at least `out_len` writable bytes (may be null only
///   if `out_len` is 0).
/// - The returned pointer must be freed exactly once with [`flextunnel_stop`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_start(
    config_json: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> *mut FlextunnelHandle {
    if config_json.is_null() {
        write_cstr(out_buf, out_len, "config_json is null");
        return ptr::null_mut();
    }
    let json = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            write_cstr(out_buf, out_len, "config_json is not valid UTF-8");
            return ptr::null_mut();
        }
    };

    // Enforce a single running instance. Claim the guard before doing any work;
    // every failure path below releases it so a later start can succeed.
    if RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        write_cstr(
            out_buf,
            out_len,
            "a flextunnel proxy is already running; stop it first",
        );
        return ptr::null_mut();
    }

    match start_inner(json) {
        Ok((handle, result_json)) => {
            // Refuse to hand back a handle if the result JSON did not fit: the
            // caller would not learn the port. Stop the loop, free, and signal
            // failure so the caller retries with a larger buffer.
            if write_cstr(out_buf, out_len, &result_json) {
                Box::into_raw(Box::new(handle))
            } else {
                stop_handle(handle);
                RUNNING.store(false, Ordering::Release);
                write_cstr(out_buf, out_len, "out_buf too small for result JSON");
                ptr::null_mut()
            }
        }
        Err(msg) => {
            RUNNING.store(false, Ordering::Release);
            write_cstr(out_buf, out_len, &msg);
            ptr::null_mut()
        }
    }
}

fn start_inner(json: &str) -> Result<(FlextunnelHandle, String), String> {
    // The proxy holds a socket per connection; lift the app process's soft fd
    // limit (per-process, best-effort) before serving.
    flextunnel_core::app::raise_fd_limit();

    let cfg: FfiConfig =
        serde_json::from_str(json).map_err(|e| format!("invalid config JSON: {e}"))?;

    let runtime = flextunnel_core::app::build_runtime()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

    // Bind the loopback listener on the fixed port. The listener backlog queues
    // the WKWebView's first connections until the connect/auth handshake
    // completes and the serve loop starts accepting. A bind failure here is
    // almost always "port already in use" — e.g. a stale instance.
    let port = cfg.socks_port.unwrap_or(DEFAULT_SOCKS_PORT);
    let listener = runtime
        .block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, port)))
        .map_err(|e| format!("failed to bind 127.0.0.1:{port} (already in use?): {e}"))?;

    let endpoint = runtime
        .block_on(create_client_endpoint(&cfg.relay_urls, cfg.dns_server.as_deref()))
        .map_err(|e| format!("failed to create iroh endpoint: {e}"))?;

    let client = ProxyClient::new(ClientConfig {
        server_node_id: cfg.server_node_id,
        auth_token: cfg.auth_token,
        // Unused: the listener is already bound above and passed in directly.
        socks_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        // iOS uses run_with_listener (SOCKS5 only); no HTTP front-end exposed.
        http_listen: None,
        relay_urls: cfg.relay_urls,
        auto_reconnect: true,
        max_reconnect_attempts: None,
    });

    // Share the live tunnel set out of the client before it moves into the task,
    // so `flextunnel_routes` can read what the server pushes on connect.
    let routes = client.routes();

    // Clone the endpoint into the task; the original stays in the handle so
    // `flextunnel_stop` can close it after aborting the task.
    let ep = endpoint.clone();
    let task = runtime.spawn(async move { client.run_with_listener(&ep, listener).await });

    let result_json = serde_json::json!({ "socks_port": port }).to_string();
    Ok((
        FlextunnelHandle {
            runtime,
            endpoint,
            task,
            routes,
        },
        result_json,
    ))
}

/// Stop the proxy and free the handle. After this call `handle` is invalid and
/// must not be used again. Passing null is a safe no-op.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not
/// already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_stop(handle: *mut FlextunnelHandle) {
    if handle.is_null() {
        return;
    }
    stop_handle(*unsafe { Box::from_raw(handle) });
    // Release the single-instance guard so a subsequent start can succeed.
    RUNNING.store(false, Ordering::Release);
}

/// Liveness probe for the running proxy.
///
/// Returns `1` while the connect/serve loop is still running, `0` once it has
/// ended (it gives up on a fatal error — bad node id, auth failure, or an
/// unreachable server on the *first* connect; transient drops after a successful
/// connect keep retrying and stay `1`), and `-1` for a null handle.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. Passing null returns `-1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_health(handle: *const FlextunnelHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    if handle.task.is_finished() { 0 } else { 1 }
}

/// Snapshot the tunnel's current forwarding set as JSON into `out_buf`:
///
/// ```json
/// { "connected": true, "domains": ["*.example.com"], "cidrs": ["10.0.0.0/8"],
///   "host_aliases": [["nas.internal", "192.168.1.9"]],
///   "agent_aliases": ["workstation.internal"] }
/// ```
///
/// This is the required split-tunnel set the server pushes during the handshake
/// — the domains/CIDRs routed through the tunnel. The caller owns the split:
/// off-list targets must bypass the proxy and be connected directly from the
/// caller side, because the server rejects any off-list target sent through the
/// SOCKS proxy. Before the first successful handshake, `connected` is false and
/// the lists are empty. The set becomes available shortly after start, once the
/// handshake completes, so the caller should poll it.
///
/// `host_aliases` (`[alias, target]` pairs) and `agent_aliases` (reverse-routing
/// alias names) are informational, for display in status UIs only — the server
/// resolves both itself, so there is nothing to enforce caller-side.
///
/// Returns `1` on success (full JSON written), `0` if `out_buf` was too small
/// (the JSON is truncated; retry with a larger buffer), and `-1` for a null
/// handle or if the route snapshot could not be read (internal lock error).
/// `out_buf` is always NUL-terminated when usable (non-null, `out_len > 0`):
/// the error returns write an empty string.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. `out_buf` must point to at least `out_len`
/// writable bytes (may be null only if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_routes(
    handle: *const FlextunnelHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        write_cstr(out_buf, out_len, "");
        return -1;
    }
    let handle = unsafe { &*handle };
    let json = match handle.routes.lock() {
        Ok(routes) => serde_json::json!({
            "connected": routes.connected,
            "domains": routes.domains,
            "cidrs": routes.cidrs,
            "host_aliases": routes.host_aliases,
            "agent_aliases": routes.agent_aliases,
        })
        .to_string(),
        Err(_) => {
            write_cstr(out_buf, out_len, "");
            return -1;
        }
    };
    if write_cstr(out_buf, out_len, &json) { 1 } else { 0 }
}

/// Abort the serve loop, close the endpoint gracefully, and shut the runtime
/// down. Factored out so [`flextunnel_start`] can also use it on the
/// buffer-too-small path without going through a raw pointer.
fn stop_handle(handle: FlextunnelHandle) {
    handle.task.abort();
    // Close the endpoint before it drops. Skipping this makes iroh tear down its
    // relay tasks ungracefully (a JoinSet abort that panics — fatal under
    // panic=abort). `block_on` is safe here: the task is already aborted.
    handle.runtime.block_on(handle.endpoint.close());
    handle.runtime.shutdown_background();
}

/// Write `s` (always NUL-terminated) into the caller buffer. Returns `true` if
/// the full string fit, `false` if it was truncated or the buffer was unusable.
fn write_cstr(buf: *mut c_char, len: usize, s: &str) -> bool {
    if buf.is_null() || len == 0 {
        return false;
    }
    let bytes = s.as_bytes();
    // Reserve one byte for the trailing NUL.
    let copy = bytes.len().min(len - 1);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, copy);
        *buf.add(copy) = 0;
    }
    copy == bytes.len()
}
