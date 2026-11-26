//! C FFI surface for the iOS app (`aarch64-apple-ios`), and through the same
//! safe Rust beneath it, the JNI surface for the Android app (`android`
//! module, `target_os = "android"` only; the same JSON shapes, as the
//! `external fun`s of `dev.flexaccess.flextunnel.FlextunnelNative`).
//!
//! The iOS app links `libflextunnel.xcframework` (containing `libflextunnel.a`
//! slices) and drives the in-process client primarily with these calls:
//!
//! 1. [`flextunnel_start`] — parse the JSON config, optionally bind a loopback
//!    SOCKS5 listener, and spawn the client on an embedded runtime. Returns an
//!    opaque handle and writes `{"socks_port": N|null}` to the caller's buffer
//!    so the app can point `WKWebsiteDataStore.proxyConfigurations` at
//!    `127.0.0.1:N`. **Nothing is connected by starting**: each destination's
//!    server is dialed when something is first sent to it. At most **one**
//!    instance may run at a time (a process-global guard rejects a second).
//! 2. [`flextunnel_set_forwards`] — reconcile local port forwards.
//! 3. [`flextunnel_health`] — cheap liveness probe: is the client still
//!    serving, or did it lose a local listener for good?
//! 4. [`flextunnel_status`] — snapshot every destination's connection state
//!    and routes for UI.
//! 5. [`flextunnel_conn_path`] — snapshot one destination's live iroh path(s)
//!    (relay/direct) for an on-demand "connection path" status readout.
//! 6. [`flextunnel_close_listeners`] — one-way suspend-side close of every
//!    local listener, so backlogged clients get refused instead of hanging.
//! 7. [`flextunnel_set_background`] — scene-lifecycle hint: backgrounded, the
//!    core's heartbeat slows from 10s to 60s so a connected session wakes the
//!    cellular radio once a minute instead of six times.
//! 8. [`flextunnel_set_network_available`] — path hint (`NWPathMonitor`): while
//!    no path is usable nothing is dialed, instead of burning retries into a
//!    dead network, and waiting destinations dial immediately when a path
//!    returns.
//! 9. [`flextunnel_stop`] — stop the client, close its endpoints, free the
//!    handle.
//!
//! Apart from a session, [`flextunnel_fetch_server_routes`] asks a server what
//! it routes, for the app to offer while a destination is set up.
//!
//! Unlike the ezvpn FFI there is **no VPN / Network Extension and no `utun` fd**:
//! flextunnel is pure-userspace proxying and forwarding over QUIC, so its
//! optional proxy and forwarding listeners run entirely inside the app
//! process. The app is expected to work only in the foreground —
//! when iOS suspends it the runtime freezes and the QUIC connections idle-time
//! out. The app calls [`flextunnel_close_listeners`] just before an unavoidable
//! suspension (so local clients get refused instead of hanging on a frozen
//! backlog) and relaunches the session on return to the foreground.
//!
//! All functions are null-safe and never unwind across the FFI boundary (the
//! release profile is `panic = "abort"`, so a panic terminates the process
//! rather than crossing into Swift).
//!
//! ## Config JSON (input to `flextunnel_start`)
//!
//! `auth_key` (the client's `ed25519-sec:...` secret key, whose public half
//! must be on each server's authorized-keys file) and at least one entry in
//! `destinations` are required; the rest is optional.
//!
//! A destination gives a server a `name`: one DNS label (letters, digits and
//! inner hyphens, up to 63, case-insensitive), unique within the config.
//! `<name>.localhost.flextunnel.internal:<port>` through the client reaches
//! that port on the server's own loopback. Its optional
//! `routed_domains` / `routed_cidrs` are further targets sent through that
//! server (which must route them too — its own routed set is the allowlist).
//! Routing is entirely this config's: a session learns nothing from a server,
//! and a target on no destination's list is connected directly from the device.
//!
//! `idle_timeout_secs` is how long a destination's connection is kept with no
//! stream open on it: absent means the default (300), `0` means never close
//! one for idleness.
//!
//! `relay_quic_addr_discovery` says whether the custom relays serve QUIC
//! address discovery, all of them or none: absent or `null` means they do
//! (the default); `false` is for relays behind a Cloudflare Tunnel or another
//! HTTP-only front, which otherwise delay each start by up to 3 s. Only valid
//! with custom `relay_urls`.
//!
//! ```json
//! {
//!   "auth_key": "ed25519-sec:...",
//!   "socks_port": null,
//!   "relay_urls": ["https://relay-a.example/", "https://relay-b.example/"],
//!   "relay_auth_token": null,
//!   "relay_quic_addr_discovery": null,
//!   "idle_timeout_secs": 300,
//!   "destinations": [
//!     { "name": "machine1", "server_node_id": "<iroh endpoint id>",
//!       "routed_domains": ["*.corp.example"], "routed_cidrs": ["10.0.0.0/8"] }
//!   ]
//! }
//! ```
//!
//! ## Result JSON (output of `flextunnel_start` on success)
//!
//! ```json
//! { "socks_port": null }
//! ```

use std::collections::HashSet;
use std::ffi::{CStr, c_char, c_int};
use std::net::Ipv4Addr;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::net::TcpListener;

#[cfg(target_os = "android")]
mod android;

use flextunnel_core::config::DEFAULT_IDLE_TIMEOUT;
use flextunnel_core::error::ProxyResult;
use flextunnel_core::proxy::signaling::Target;
use flextunnel_core::proxy::{
    ClientAuth, ClientConfig, DestinationConfig, ForwardManager, ForwardSpec, ForwardState,
    LocalListeners, ProxyClient,
};
use flextunnel_core::transport::endpoint::relay_config;
use flextunnel_core::transport::paths::ConnPathKind;

/// The thread a routes request runs on (see
/// [`flextunnel_fetch_server_routes`]).
const ROUTES_THREAD_NAME: &str = "flextunnel-routes";

/// How long [`flextunnel_stop`] waits for the graceful close of the client's
/// endpoints. Closing waits out an endpoint still being built (see
/// `ProxyClient::close`), which in the worst case takes as long as the relay
/// probes plus the online wait; the app's calling thread must not hang on
/// that. A close that takes longer is not given up on: it is finished on a
/// thread of its own, which keeps the runtime until then (see [`stop_handle`]).
const STOP_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Name of the thread that finishes a close [`flextunnel_stop`] stopped
/// waiting for.
const CLOSE_THREAD_NAME: &str = "flextunnel-close";

/// Process-global guard enforcing **at most one** running proxy instance. A
/// second [`flextunnel_start`] while one is live is rejected rather than racing.
/// Claimed on a successful start, released by [`flextunnel_stop`] (or any start
/// failure path).
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Opaque handle owned by the app (Swift, or Kotlin through JNI). Created by
/// [`flextunnel_start`], freed by [`flextunnel_stop`].
pub struct FlextunnelHandle {
    runtime: tokio::runtime::Runtime,
    /// The client. Shared with the spawned `task` (which holds a clone) so
    /// status callers can snapshot it, and kept so [`flextunnel_stop`] can
    /// close its endpoints gracefully before drop.
    client: Arc<ProxyClient>,
    /// The running client session (listeners + destination managers).
    task: tokio::task::JoinHandle<ProxyResult<()>>,
    /// Local forward listeners, reconciled from Swift.
    forwards: Mutex<ForwardManager>,
}

#[derive(Deserialize)]
struct FfiConfig {
    /// The client's secret key (`ed25519-sec:...`); the app stores it
    /// in the iOS keychain and passes it here at start.
    auth_key: String,
    /// Loopback SOCKS5 port to bind. `None` disables the SOCKS5 front-end;
    /// `Some(0)` binds an OS-assigned ephemeral port (the result JSON reports
    /// the port bound). A nonzero port is required: if it is already in use
    /// the start fails.
    #[serde(default)]
    socks_port: Option<u16>,
    #[serde(default)]
    relay_urls: Vec<String>,
    /// Shared bearer token sent to every custom relay's WebSocket upgrade. Only
    /// valid with custom `relay_urls`; rejected with the default iroh relays.
    #[serde(default)]
    relay_auth_token: Option<String>,
    /// Whether the custom relays serve QUIC address discovery, all of them or
    /// none. Absent: they do. Only valid with custom `relay_urls`.
    #[serde(default)]
    relay_quic_addr_discovery: Option<bool>,
    /// Seconds a destination's connection is kept with no stream open on it.
    /// Absent: the default; `0`: never closed for idleness.
    #[serde(default)]
    idle_timeout_secs: Option<u64>,
    /// The servers this client reaches. At least one.
    destinations: Vec<FfiDestination>,
}

#[derive(Deserialize)]
struct FfiDestination {
    /// The destination's name; `<name>.localhost.flextunnel.internal:<port>`
    /// is the server's own loopback.
    name: String,
    server_node_id: String,
    /// Further domains sent through this server.
    #[serde(default)]
    routed_domains: Vec<String>,
    /// Further networks or bare IPs sent through this server.
    #[serde(default)]
    routed_cidrs: Vec<String>,
}

/// Input of [`flextunnel_fetch_server_routes`]: a server, and the key and
/// relays a destination for it would use.
#[derive(Deserialize)]
struct FfiRoutesRequest {
    auth_key: String,
    server_node_id: String,
    #[serde(default)]
    relay_urls: Vec<String>,
    #[serde(default)]
    relay_auth_token: Option<String>,
    #[serde(default)]
    relay_quic_addr_discovery: Option<bool>,
}

#[derive(Deserialize)]
struct FfiForward {
    id: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    enabled: bool,
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

/// Generate a fresh client authentication keypair. Writes
/// `{"created":"<UTC>","public_key":"ed25519-pub:...","secret_key":"ed25519-sec:..."}`
/// to `out_buf`. The app stores the secret key in the keychain and shows the
/// public key (never a secret) for the user to put on the server's
/// authorized-keys file. Returns 1 on success, 0 if `out_buf` is too small.
///
/// # Safety
/// `out_buf` must point to at least `out_len` writable bytes (may be null only
/// if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_generate_client_key(
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    match generate_client_key_json() {
        Ok(json) => c_int::from(write_cstr(out_buf, out_len, &json)),
        Err(message) => {
            write_cstr(out_buf, out_len, &message);
            0
        }
    }
}

/// The [`flextunnel_generate_client_key`] JSON for a fresh keypair.
fn generate_client_key_json() -> Result<String, String> {
    let key = flextunnel_core::auth::ClientKey::generate().map_err(|e| format!("{e:#}"))?;
    Ok(serde_json::json!({
        "created": flextunnel_core::flexaccess_keys::rfc3339_utc(std::time::SystemTime::now()),
        "public_key": key.public_str(),
        "secret_key": key.secret_str(),
    })
    .to_string())
}

/// Derive the public key (`ed25519-pub:...`) of a stored secret key, so
/// the app can display it unmasked without persisting it separately. Writes
/// the public key string to `out_buf` on success (returns 1), or an error
/// message (returns 0) for an invalid secret. A too-small `out_buf` also
/// returns 0, but then holds the truncated output rather than a diagnostic.
///
/// # Safety
/// - `secret_key` must be a valid, NUL-terminated UTF-8 C string.
/// - `out_buf` must point to at least `out_len` writable bytes (may be null
///   only if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_client_public_key(
    secret_key: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if secret_key.is_null() {
        write_cstr(out_buf, out_len, "secret_key is null");
        return 0;
    }
    let secret = match unsafe { CStr::from_ptr(secret_key) }.to_str() {
        Ok(secret) => secret,
        Err(_) => {
            write_cstr(out_buf, out_len, "secret_key is not valid UTF-8");
            return 0;
        }
    };
    match client_public_key_str(secret) {
        Ok(public) => c_int::from(write_cstr(out_buf, out_len, &public)),
        Err(message) => {
            write_cstr(out_buf, out_len, &message);
            0
        }
    }
}

/// The public key (`ed25519-pub:...`) of the secret key `secret`.
fn client_public_key_str(secret: &str) -> Result<String, String> {
    flextunnel_core::auth::ClientKey::from_secret_str(secret.trim())
        .map(|key| key.public_str())
        .map_err(|e| format!("invalid secret key: {e:#}"))
}

/// Start the in-process client, optionally with a SOCKS5 front-end. Validates
/// the config (key, relays, destinations and their routes) and binds the
/// listener; it does not connect to any server — a destination connects on
/// first use.
///
/// Returns a non-null handle on success and writes `{"socks_port": N|null}` to
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

    match start_session(json) {
        Ok((handle, result_json)) => {
            // Refuse to hand back a handle if the result JSON did not fit: the
            // caller would not learn the port. Stop the loop, free, and signal
            // failure so the caller retries with a larger buffer.
            if write_cstr(out_buf, out_len, &result_json) {
                Box::into_raw(Box::new(handle))
            } else {
                stop_session(handle);
                write_cstr(out_buf, out_len, "out_buf too small for result JSON");
                ptr::null_mut()
            }
        }
        Err(msg) => {
            write_cstr(out_buf, out_len, &msg);
            ptr::null_mut()
        }
    }
}

/// Claim the single-instance guard and start a session from `json`; the
/// guard is released again on failure. A started session ends with
/// [`stop_session`], which releases it.
fn start_session(json: &str) -> Result<(FlextunnelHandle, String), String> {
    // Enforce a single running instance. Claim the guard before doing any work;
    // the failure path releases it so a later start can succeed.
    if RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("a flextunnel proxy is already running; stop it first".to_string());
    }
    start_inner(json).inspect_err(|_| RUNNING.store(false, Ordering::Release))
}

/// Stop a session [`start_session`] started and release the single-instance
/// guard, so a subsequent start can succeed.
fn stop_session(handle: FlextunnelHandle) {
    stop_handle(handle);
    RUNNING.store(false, Ordering::Release);
}

/// Bind the browser's loopback SOCKS listener. A nonzero `requested` port is a
/// requirement, not a preference: the app replays its session's OS-assigned
/// port on relaunch and the WKWebView proxy config names it for the session's
/// lifetime, so a relaunch that lands elsewhere would leave the browser pointed
/// at a dead port. If another process took it, the start fails instead.
async fn bind_socks_listener(requested: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, requested)).await
}

fn start_inner(json: &str) -> Result<(FlextunnelHandle, String), String> {
    // The proxy holds a socket per connection; lift the app process's soft fd
    // limit (per-process, best-effort) before serving. Not under Miri, which
    // has no getrlimit.
    #[cfg(not(miri))]
    flextunnel_core::app::raise_fd_limit();

    let cfg: FfiConfig =
        serde_json::from_str(json).map_err(|e| format!("invalid config JSON: {e}"))?;

    let runtime = flextunnel_core::app::build_runtime()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

    // Browser sessions bind a SOCKS listener; forwarding-only sessions pass
    // null and have no local proxy front-end at all.
    let (listener, port) = match cfg.socks_port {
        Some(requested) => {
            let listener = runtime
                .block_on(bind_socks_listener(requested))
                .map_err(|e| format!("failed to bind a loopback SOCKS port: {e}"))?;
            let port = listener
                .local_addr()
                .map_err(|e| format!("failed to read bound SOCKS port: {e}"))?
                .port();
            (Some(listener), Some(port))
        }
        None => (None, None),
    };

    let relay = relay_config(
        &cfg.relay_urls,
        cfg.relay_auth_token,
        cfg.relay_quic_addr_discovery,
    )
    .map_err(|e| format!("invalid relay configuration: {e}"))?;
    let client_key = flextunnel_core::auth::ClientKey::from_secret_str(cfg.auth_key.trim())
        .map_err(|e| format!("invalid auth key: {e:#}"))?;
    let idle_timeout = match cfg.idle_timeout_secs {
        None => Some(DEFAULT_IDLE_TIMEOUT),
        Some(0) => None,
        Some(secs) => Some(Duration::from_secs(secs)),
    };
    let mut destinations = Vec::with_capacity(cfg.destinations.len());
    for destination in cfg.destinations {
        let server_id = destination.server_node_id.trim().parse().map_err(|e| {
            format!(
                "destination {:?}: invalid server_node_id: {e}",
                destination.name
            )
        })?;
        destinations.push(DestinationConfig {
            name: destination.name,
            server_id,
            auth: ClientAuth::Key(Box::new(client_key.clone())),
            relay: relay.clone(),
            routed_domains: destination.routed_domains,
            routed_cidrs: destination.routed_cidrs,
            keep_connected: false,
        });
    }
    // Validates the destinations (names, routes, one entry per server).
    // Nothing is dialed: a destination connects on first use.
    let client = Arc::new(
        ProxyClient::new(ClientConfig {
            destinations,
            idle_timeout,
        })
        .map_err(|e| e.to_string())?,
    );

    let forwards = Mutex::new(ForwardManager::new(
        runtime.handle().clone(),
        client.dialer(),
        &[],
    ));

    // The client is shared (Arc) so the handle keeps a clone for the status
    // calls — and to close its endpoints at stop — while the task serves.
    let client_task = client.clone();
    let task = runtime.spawn(async move {
        // iOS exposes no HTTP front-end.
        client_task.run(LocalListeners::tcp(listener, None)).await
    });

    let result_json = serde_json::json!({ "socks_port": port }).to_string();
    Ok((
        FlextunnelHandle {
            runtime,
            client,
            task,
            forwards,
        },
        result_json,
    ))
}

/// Ask a server what it routes — its own `routed_domains` and `routed_cidrs`
/// — so a destination being set up can be filled in to match. One connection
/// made for the question and closed again, on an endpoint and a thread of its
/// own: it needs no handle and touches no running session.
///
/// `request_json` names the server and how to reach it, as a destination for
/// it would:
///
/// ```json
/// { "auth_key": "ed25519-sec:...", "server_node_id": "<iroh endpoint id>",
///   "relay_urls": [], "relay_auth_token": null,
///   "relay_quic_addr_discovery": null }
/// ```
///
/// `relay_urls`, `relay_auth_token` and `relay_quic_addr_discovery` are
/// optional, with the rules they have in a session's config. The server must
/// already authorize the key's public half. The server's answer is
///
/// ```json
/// { "routed_domains": ["*.corp.example"], "routed_cidrs": ["10.0.0.0/8"] }
/// ```
///
/// with both lists empty for a server that routes nothing beyond itself.
///
/// Returns the number of bytes that JSON needs **including the trailing NUL**
/// once the server has answered — like [`flextunnel_forward_statuses`], the
/// buffer holds the complete JSON iff the return value is `<= out_len`, and on
/// a larger return it holds a NUL-terminated truncation: call again with a
/// buffer of at least the returned size (which asks the server again). Returns
/// -1, with an error message in `out_buf`, for an invalid request, an
/// unreachable server or a key it refuses — a failure a larger buffer does not
/// change.
///
/// **Blocks** until the server has answered or an attempt has failed — a few
/// seconds as a rule, about a minute against a server that never answers — so
/// call it off the main thread. Nothing is retried. The request's endpoint
/// closes after the answer, on the request's own thread: the call does not
/// wait for it.
///
/// # Safety
/// - `request_json` must be a valid, NUL-terminated UTF-8 C string.
/// - `out_buf` must point to at least `out_len` writable bytes (may be null
///   only if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_fetch_server_routes(
    request_json: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> isize {
    if request_json.is_null() {
        write_cstr(out_buf, out_len, "request_json is null");
        return -1;
    }
    let json = match unsafe { CStr::from_ptr(request_json) }.to_str() {
        Ok(json) => json,
        Err(_) => {
            write_cstr(out_buf, out_len, "request_json is not valid UTF-8");
            return -1;
        }
    };
    match fetch_server_routes_inner(json) {
        Ok(routes) => write_sized(out_buf, out_len, &routes),
        Err(message) => {
            write_cstr(out_buf, out_len, &message);
            -1
        }
    }
}

fn fetch_server_routes_inner(json: &str) -> Result<String, String> {
    let request: FfiRoutesRequest =
        serde_json::from_str(json).map_err(|e| format!("invalid request JSON: {e}"))?;
    let relay = relay_config(
        &request.relay_urls,
        request.relay_auth_token,
        request.relay_quic_addr_discovery,
    )
    .map_err(|e| format!("invalid relay configuration: {e}"))?;
    let key = flextunnel_core::auth::ClientKey::from_secret_str(request.auth_key.trim())
        .map_err(|e| format!("invalid auth key: {e:#}"))?;
    let server_id = request
        .server_node_id
        .trim()
        .parse()
        .map_err(|e| format!("invalid server_node_id: {e}"))?;

    // The request has a thread of its own, which stays to close the endpoint
    // once this one has the answer.
    let routes =
        flextunnel_core::proxy::fetch_server_routes(ROUTES_THREAD_NAME, server_id, key, relay)
            .blocking_recv()
            .map_err(|_| "the routes request could not be started".to_string())?
            .map_err(|e| e.to_string())?;
    serde_json::to_string(&routes).map_err(|e| format!("failed to encode the routes: {e}"))
}

/// Replace the complete desired forward set.
///
/// `forwards_json` is a JSON array of
/// `{id,local_port,remote_host,remote_port,enabled}` objects. Enabled forwards
/// bind `127.0.0.1` and `::1`; every accepted connection is sent through the
/// destination that routes `remote_host` (connecting it first if it is idle),
/// whose server rejects targets off its own list. `remote_host` is routed like
/// a proxy request — a destination's `<name>.localhost.flextunnel.internal`
/// is that server's loopback —
/// except that a forward never connects directly: an enabled forward whose
/// host no destination routes is invalid input.
///
/// Returns 1 on success, 0 for invalid input, and -1 for a null handle.
///
/// # Safety
/// - `forwards_json` must be a valid, NUL-terminated JSON C string (required by
///   `CStr::from_ptr`); it may be null, which is treated as invalid input.
/// - `out_buf` must be valid for `out_len` bytes when non-null, and the handle
///   must still be owned by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_set_forwards(
    handle: *const FlextunnelHandle,
    forwards_json: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        write_cstr(out_buf, out_len, "null handle or forwards_json");
        return -1;
    }
    if forwards_json.is_null() {
        write_cstr(out_buf, out_len, "null handle or forwards_json");
        return 0;
    }
    let json = match unsafe { CStr::from_ptr(forwards_json) }.to_str() {
        Ok(json) => json,
        Err(_) => {
            write_cstr(out_buf, out_len, "forwards_json is not valid UTF-8");
            return 0;
        }
    };
    match unsafe { &*handle }.set_forwards(json) {
        Ok(()) => {
            write_cstr(out_buf, out_len, "");
            1
        }
        Err(message) => {
            write_cstr(out_buf, out_len, &message);
            0
        }
    }
}

/// Snapshot forward states as JSON.
///
/// Returns the number of bytes the JSON needs **including the trailing NUL**,
/// or -1 for a null handle or internal lock failure. The buffer holds the
/// complete JSON iff the return value is `<= out_len`; on a larger return the
/// buffer holds a NUL-terminated truncation and the caller must call again
/// with a buffer of at least the returned size.
///
/// # Safety
/// The handle must still be owned by the caller, and `out_buf` must be valid
/// for `out_len` bytes when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_forward_statuses(
    handle: *const FlextunnelHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> isize {
    if handle.is_null() {
        write_cstr(out_buf, out_len, "");
        return -1;
    }
    match unsafe { &*handle }.forward_statuses_json() {
        Some(json) => write_sized(out_buf, out_len, &json),
        None => {
            write_cstr(out_buf, out_len, "");
            -1
        }
    }
}

/// Close every local listener — the SOCKS5 front-end and all forward
/// listeners — while keeping the session handle alive.
///
/// One-way, for the moment iOS is about to suspend the app: a frozen process's
/// listeners keep accepting into the kernel backlog and then serve nothing, so
/// local clients hang instead of failing. Closing first turns that into an
/// immediate connection-refused. There is no reopen for this handle: on return
/// to the foreground the app relaunches the session ([`flextunnel_stop`] +
/// [`flextunnel_start`]) and re-applies its forwards, which rebinds everything.
/// [`flextunnel_health`] stays `1` after this call, and a later
/// [`flextunnel_set_forwards`] would bind its listeners again — don't call it
/// between close and relaunch.
///
/// Returns 1 on success, 0 for an internal lock failure (front-end listeners
/// are closed regardless), and -1 for a null handle.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. Passing null returns `-1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_close_listeners(handle: *const FlextunnelHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    c_int::from(unsafe { &*handle }.close_listeners())
}

/// Report the app's scene state so the core can pace itself: `1` when the app
/// is backgrounded, `0` when foregrounded. Backgrounded, the app-level
/// heartbeat — the connection's only periodic traffic — slows from 10s to 60s,
/// keeping the cellular radio in its low-power state almost the whole time; the
/// foreground flip snaps it back and sends any overdue beat immediately, and a
/// destination sitting out a retry backoff (up to 60s once a long outage has
/// pushed it to the cap) ends that wait and attempts at once with a fresh
/// backoff series. Idempotent; safe to call with the same value
/// repeatedly.
///
/// Returns 1 on success and -1 for a null handle.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. Passing null returns `-1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_set_background(
    handle: *const FlextunnelHandle,
    background: c_int,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    handle.client.set_background(background != 0);
    1
}

/// Report whether the device currently has a usable network path (`1`/`0`),
/// e.g. from `NWPathMonitor`. While unavailable no destination dials — instead
/// of waking the radio for attempts that cannot succeed — and a flip back to
/// available gives every destination with requests waiting an immediate
/// attempt with a fresh backoff series. Defaults to available if never called.
///
/// Returns 1 on success and -1 for a null handle.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. Passing null returns `-1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_set_network_available(
    handle: *const FlextunnelHandle,
    available: c_int,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    handle.client.set_network_available(available != 0);
    1
}

/// Stop the proxy and free the handle. After this call `handle` is invalid and
/// must not be used again. Passing null is a safe no-op.
///
/// Blocks for the close of the endpoints in use, for at most
/// [`STOP_CLOSE_TIMEOUT`]. A close that takes longer is finished on a thread
/// of its own after this returns; the session is stopped either way, and
/// [`flextunnel_start`] can be called again at once.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not
/// already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_stop(handle: *mut FlextunnelHandle) {
    if handle.is_null() {
        return;
    }
    stop_session(*unsafe { Box::from_raw(handle) });
}

/// Liveness probe for the running proxy.
///
/// Returns `1` while the client is still serving, `0` once it has ended, and
/// `-1` for a null handle. The client ends only when a local listener is lost
/// for good (its port taken by another process after the OS invalidated the
/// socket). No destination's trouble ends it: an unreachable server, a dropped
/// connection or a rejected key is that destination's state — see
/// [`flextunnel_status`] — and the client keeps serving the rest.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. Passing null returns `-1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_health(handle: *const FlextunnelHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    c_int::from(unsafe { &*handle }.is_serving())
}

/// Snapshot the client's destinations as JSON into `out_buf`:
///
/// ```json
/// { "idle_timeout_secs": 300,
///   "destinations": [
///     { "name": "machine1", "server_node_id": "…",
///       "state": "connected", "connected_secs": 42,
///       "open_streams": 1, "waiting": 0, "client_node_id": "…",
///       "failed_attempts": 0, "next_attempt_secs": null, "last_error": null,
///       "routed_domains": ["*.corp.example"], "routed_cidrs": ["10.0.0.0/8"],
///       "relay_urls": [] } ] }
/// ```
///
/// One entry per configured destination, in config order. `state` is one of:
///
/// - `"idle"` — not connected and nothing is asking for it. The resting state:
///   a destination connects when something is first sent to it and goes back
///   to idle after `idle_timeout_secs` without an open stream (`null`: never).
/// - `"connecting"` — building its endpoint, connecting or authenticating.
/// - `"connected"` — `connected_secs` is the connection's age.
/// - `"backoff"` — the last attempt failed and requests are still waiting;
///   `next_attempt_secs` is when it retries.
/// - `"failed"` — the server refused this client (e.g. an unauthorized key);
///   requests fail at once until `next_attempt_secs`.
///
/// `open_streams` / `waiting` count the streams open on the connection and the
/// requests held while it connects. `client_node_id` is this client's endpoint
/// id toward that server, `null` while idle (the endpoint exists only while
/// the destination is in use). `failed_attempts` and `last_error` describe the
/// current outage and are cleared by a successful connection; an idle
/// destination with `failed_attempts > 0` retries on its next use, not before.
///
/// `routed_domains` / `routed_cidrs` echo the destination's configured routes,
/// for display: the local SOCKS proxy owns the split — a target a destination
/// routes uses that destination's tunnel, everything else connects directly
/// from the device — so the caller has nothing to enforce. A server's own view
/// (its routed set, host aliases) is its status page,
/// reachable through the SOCKS proxy at
/// `http://flextunnel.internal/servers/<name>/status.json`.
///
/// Reading this never causes a connection.
///
/// Returns `1` on success (full JSON written), `0` if `out_buf` was too small
/// (the JSON is truncated; retry with a larger buffer), and `-1` for a null
/// handle. `out_buf` is always NUL-terminated when usable (non-null,
/// `out_len > 0`): the null-handle return writes an empty string.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. `out_buf` must point to at least `out_len`
/// writable bytes (may be null only if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_status(
    handle: *const FlextunnelHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        write_cstr(out_buf, out_len, "");
        return -1;
    }
    let json = unsafe { &*handle }.status_json();
    c_int::from(write_cstr(out_buf, out_len, &json))
}

/// The [`flextunnel_status`] JSON for `status` as of `now`.
fn status_json(status: &flextunnel_core::proxy::ClientStatus, now: Instant) -> String {
    let destinations: Vec<_> = status
        .destinations
        .iter()
        .map(|d| {
            serde_json::json!({
                "name": d.name,
                "server_node_id": d.server_node_id,
                "state": d.state.as_str(),
                "connected_secs": d
                    .connected_since
                    .map(|at| now.saturating_duration_since(at).as_secs()),
                "open_streams": d.open_streams,
                "waiting": d.waiting,
                "client_node_id": d.client_node_id,
                "failed_attempts": d.failed_attempts,
                "next_attempt_secs": d
                    .next_attempt_at
                    .map(|at| at.saturating_duration_since(now).as_secs()),
                "last_error": d.last_error,
                "routed_domains": d.routed_domains,
                "routed_cidrs": d.routed_cidrs,
                "relay_urls": d.relay_urls,
            })
        })
        .collect();
    serde_json::json!({
        "idle_timeout_secs": status.idle_timeout.map(|idle| idle.as_secs()),
        "destinations": destinations,
    })
    .to_string()
}

/// Snapshot the iroh path(s) of the connection to the destination called `name`
/// as JSON into `out_buf`, mirroring `ezvpn client status` / the desktop's
/// "connection path" readout:
///
/// ```json
/// { "paths": [
///     {"kind":"direct","display":"Direct 1.2.3.4:52186 (rtt 1ms)","selected":true},
///     {"kind":"relay","display":"Relay https://relay.example/ (rtt 42ms)","selected":false}
///   ],
///   "udp_tx_datagrams": 1234, "udp_rx_datagrams": 1201 }
/// ```
///
/// `udp_tx_datagrams`/`udp_rx_datagrams` count the UDP datagrams the live
/// connection has sent/received since it was established (0 while not
/// connected). On cellular, energy is per-wakeup rather than per-byte, so
/// sampling the tx count across an interval — e.g. across a backgrounded stint
/// — is the cheap proxy for the tunnel's radio cost.
///
/// This is a **point-in-time** snapshot of how the client currently reaches that
/// server, showing *all* discovered paths (not just the selected one); `kind` is
/// `"direct"`, `"relay"`, or `"other"` (a forward-compatible catch-all) and
/// `selected` marks the path iroh routes over right now. The whole snapshot is
/// **empty** while the destination is not connected — idle, connecting, or
/// backing off — or when `name` names no destination, so callers should only
/// offer this for a destination [`flextunnel_status`] reports `"connected"`.
/// Asking never connects it.
///
/// `custom_relays` reports each configured custom relay's health from an
/// on-demand GET of its `/healthz` endpoint (checked in parallel, only when this
/// snapshot is requested). `working` is `true` on a 2xx, `false` when
/// unreachable/timed-out/non-2xx, and `null` if the check could not run; `error`
/// carries the failure detail. The array is empty when the default relays are
/// used. `/healthz` is unauthenticated: it confirms the relay is up, not that a
/// `relay_auth_token` is accepted.
///
/// Returns `1` on success (full JSON written), `0` if `out_buf` was too small
/// (the JSON is truncated; retry with a larger buffer), and `-1` for a null
/// handle or an unusable `name` (null or not UTF-8). `out_buf` is always
/// NUL-terminated when usable (non-null, `out_len > 0`): the `-1` returns
/// write an empty string.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. `name` must be a valid, NUL-terminated C
/// string (or null). `out_buf` must point to at least `out_len` writable bytes
/// (may be null only if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_conn_path(
    handle: *const FlextunnelHandle,
    name: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() || name.is_null() {
        write_cstr(out_buf, out_len, "");
        return -1;
    }
    let Ok(name) = unsafe { CStr::from_ptr(name) }.to_str() else {
        write_cstr(out_buf, out_len, "");
        return -1;
    };
    let json = unsafe { &*handle }.conn_path_json(name);
    c_int::from(write_cstr(out_buf, out_len, &json))
}

/// The session operations behind the C ABI above, as safe Rust: the same
/// checks and JSON, without the pointers and buffers. The Android JNI layer
/// calls them too.
impl FlextunnelHandle {
    /// [`flextunnel_set_forwards`]: replace the forward set with `json`, a JSON
    /// array of [`FfiForward`]s. An error is invalid input.
    fn set_forwards(&self, json: &str) -> Result<(), String> {
        let configured: Vec<FfiForward> =
            serde_json::from_str(json).map_err(|e| format!("invalid forwards JSON: {e}"))?;
        let mut ids = HashSet::new();
        let mut ports = HashSet::new();
        let mut specs = Vec::new();
        for forward in configured.into_iter().filter(|forward| forward.enabled) {
            if forward.id.is_empty() || !ids.insert(forward.id.clone()) {
                return Err("forward ids must be non-empty and unique".to_string());
            }
            if forward.local_port == 0 || !ports.insert(forward.local_port) {
                return Err("enabled forward local ports must be nonzero and unique".to_string());
            }
            let remote_host = forward.remote_host.trim();
            if remote_host.is_empty() || forward.remote_port == 0 {
                return Err("forward targets require a host and nonzero port".to_string());
            }
            specs.push(ForwardSpec {
                id: forward.id,
                local_port: forward.local_port,
                target: Target::Domain(remote_host.to_string(), forward.remote_port),
            });
        }
        let dialer = self.client.dialer();
        for spec in &specs {
            if dialer.destination_for(&spec.target).is_none() {
                let Target::Domain(host, _) = &spec.target else {
                    unreachable!("forward targets are built in domain form above");
                };
                return Err(format!("no destination routes {host}"));
            }
        }
        self.forwards
            .lock()
            .map_err(|_| "forward manager lock failed".to_string())?
            .apply(&specs);
        Ok(())
    }

    /// [`flextunnel_forward_statuses`]' JSON, or `None` if the forward
    /// manager's lock is poisoned.
    fn forward_statuses_json(&self) -> Option<String> {
        let statuses = self.forwards.lock().ok()?.statuses();
        let statuses: Vec<_> = statuses
            .into_iter()
            .map(|status| {
                let (state, error) = match status.state {
                    ForwardState::Starting => ("starting", None),
                    ForwardState::Listening => ("listening", None),
                    ForwardState::Failed(error) => ("failed", Some(error)),
                };
                serde_json::json!({
                    "id": status.id,
                    "state": state,
                    "error": error,
                    "active": status.active,
                    "last_conn_error": status.last_conn_error,
                })
            })
            .collect();
        Some(serde_json::json!({ "forwards": statuses }).to_string())
    }

    /// [`flextunnel_close_listeners`]: `false` if the forward manager's lock
    /// is poisoned (the front-end listeners are closed regardless).
    fn close_listeners(&self) -> bool {
        self.client.close_local_listeners();
        match self.forwards.lock() {
            Ok(mut manager) => {
                manager.apply(&[]);
                true
            }
            Err(_) => false,
        }
    }

    /// [`flextunnel_health`]: whether the client is still serving.
    fn is_serving(&self) -> bool {
        !self.task.is_finished()
    }

    /// [`flextunnel_status`]' JSON, as of now.
    fn status_json(&self) -> String {
        status_json(&self.client.status(), Instant::now())
    }

    /// [`flextunnel_conn_path`]'s JSON for the destination called `name`.
    fn conn_path_json(&self, name: &str) -> String {
        // The relay health check performs on-demand HTTP, so drive the async
        // snapshot on the embedded runtime. Called from the app's own thread
        // (never a runtime worker), so `block_on` is safe and does not stall
        // the running tunnel task.
        let snapshot = self
            .runtime
            .block_on(self.client.connection_snapshot(name.trim()));
        let paths: Vec<_> = snapshot
            .paths
            .into_iter()
            .map(|p| {
                let kind = match p.kind {
                    ConnPathKind::Direct => "direct",
                    ConnPathKind::Relay => "relay",
                    ConnPathKind::Other => "other",
                };
                serde_json::json!({ "kind": kind, "display": p.display, "selected": p.selected })
            })
            .collect();
        let custom_relays: Vec<_> = snapshot
            .custom_relays
            .into_iter()
            .map(|r| serde_json::json!({ "url": r.url, "working": r.working, "error": r.error }))
            .collect();
        serde_json::json!({
            "paths": paths,
            "custom_relays": custom_relays,
            "udp_tx_datagrams": snapshot.udp_tx_datagrams,
            "udp_rx_datagrams": snapshot.udp_rx_datagrams,
        })
        .to_string()
    }
}

/// Stop the client session, close its endpoints gracefully, and shut the
/// runtime down. Factored out so [`flextunnel_start`] can also use it on the
/// buffer-too-small path without going through a raw pointer.
fn stop_handle(handle: FlextunnelHandle) {
    let FlextunnelHandle {
        runtime,
        client,
        task,
        forwards,
    } = handle;
    drop(forwards);
    task.abort();
    // Close the endpoints of the destinations in use before they drop.
    // Skipping this makes iroh tear down its relay tasks ungracefully (a
    // JoinSet abort that panics — fatal under panic=abort). The session task is
    // awaited first so nothing is still using them; `block_on` is safe here,
    // on the app's own thread. The wait is bounded — the close waits out an
    // endpoint build in flight, and stopping must not hang the caller on a
    // slow one — but only the wait: the close is a task of its own, and one
    // still running when the wait is up is finished on a thread of its own,
    // which keeps the runtime until then. Shutting the runtime down here would
    // cut the close short, with the build or a relay probe still on it.
    let mut closing = runtime.spawn(async move {
        let _ = task.await;
        client.close().await;
    });
    let closed = runtime.block_on(async {
        tokio::time::timeout(STOP_CLOSE_TIMEOUT, &mut closing)
            .await
            .is_ok()
    });
    if closed {
        runtime.shutdown_background();
        return;
    }
    log::warn!(
        "Closing the client's endpoints is taking long; stopped, and the close goes on in \
         the background"
    );
    // If the thread cannot be spawned its closure is dropped, and the runtime
    // with it: the close is cut short, as it would be without the thread.
    let spawned = std::thread::Builder::new()
        .name(CLOSE_THREAD_NAME.into())
        .spawn(move || {
            let _ = runtime.block_on(closing);
            runtime.shutdown_background();
        });
    if let Err(e) = spawned {
        log::warn!("Could not finish closing the client's endpoints: {e}");
    }
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
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), copy);
        *buf.add(copy) = 0;
    }
    copy == bytes.len()
}

/// [`write_cstr`] for a result of no fixed size: returns the bytes `s` needs
/// **including the trailing NUL**, so the caller can tell a complete write
/// (the return is `<= len`) from a truncated one and size its next buffer.
fn write_sized(buf: *mut c_char, len: usize, s: &str) -> isize {
    write_cstr(buf, len, s);
    (s.len() + 1) as isize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn requested_socks_port_fails_when_taken() {
        let occupier = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let taken = occupier.local_addr().unwrap().port();
        let err = bind_socks_listener(taken).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn requested_socks_port_is_bound_when_free() {
        // Find a port that is free by binding-then-releasing an ephemeral one.
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let listener = bind_socks_listener(port).await.unwrap();
        assert_eq!(listener.local_addr().unwrap().port(), port);
    }

    fn start_error(json: &str) -> String {
        match start_inner(json) {
            Ok((handle, _)) => {
                stop_handle(handle);
                panic!("expected the start to fail");
            }
            Err(message) => message,
        }
    }

    fn config(destinations: serde_json::Value) -> String {
        let key = flextunnel_core::auth::ClientKey::generate().unwrap();
        serde_json::json!({ "auth_key": key.secret_str(), "destinations": destinations })
            .to_string()
    }

    fn node_id(seed: u8) -> String {
        flextunnel_core::iroh::SecretKey::from_bytes(&[seed; 32])
            .public()
            .to_string()
    }

    /// Starting validates the config and connects nothing: every destination
    /// reports idle, and stopping right away has no endpoint to close.
    #[test]
    fn start_is_lazy_and_reports_idle_destinations() {
        let json = config(serde_json::json!([
            { "name": "Machine1", "server_node_id": node_id(1),
              "routed_domains": ["*.corp.example"], "routed_cidrs": ["10.0.0.0/8"] },
            { "name": "m2", "server_node_id": node_id(2) },
        ]));
        let (handle, result) = start_inner(&json).expect("starts");
        assert_eq!(result, r#"{"socks_port":null}"#);

        let status: serde_json::Value =
            serde_json::from_str(&status_json(&handle.client.status(), Instant::now())).unwrap();
        assert_eq!(status["idle_timeout_secs"], DEFAULT_IDLE_TIMEOUT.as_secs());
        let destinations = status["destinations"].as_array().unwrap();
        assert_eq!(destinations.len(), 2);
        assert_eq!(destinations[0]["name"], "machine1");
        assert_eq!(destinations[0]["server_node_id"], node_id(1));
        assert_eq!(destinations[0]["routed_domains"][0], "*.corp.example");
        assert_eq!(destinations[0]["routed_cidrs"][0], "10.0.0.0/8");
        for destination in destinations {
            assert_eq!(destination["state"], "idle");
            assert!(destination["client_node_id"].is_null());
            assert!(destination["connected_secs"].is_null());
            assert_eq!(destination["open_streams"], 0);
        }
        assert!(!handle.task.is_finished(), "the session keeps serving");
        stop_handle(handle);
    }

    /// `relay_quic_addr_discovery` is taken with custom relays, set or left
    /// out, and refused with the default relays, which it cannot apply to.
    #[test]
    fn start_takes_the_relay_quic_addr_discovery_setting() {
        let key = flextunnel_core::auth::ClientKey::generate().unwrap();
        let config = |relay_urls: &[&str], discovery: Option<bool>| {
            let mut json = serde_json::json!({
                "auth_key": key.secret_str(),
                "relay_urls": relay_urls,
                "destinations": [{ "name": "m1", "server_node_id": node_id(1) }],
            });
            if let Some(discovery) = discovery {
                json["relay_quic_addr_discovery"] = discovery.into();
            }
            json.to_string()
        };
        for discovery in [None, Some(true), Some(false)] {
            let (handle, _) =
                start_inner(&config(&["https://only.example"], discovery)).expect("starts");
            stop_handle(handle);
        }
        for discovery in [true, false] {
            let Err(message) = start_inner(&config(&[], Some(discovery))) else {
                panic!("the default relays take no setting");
            };
            assert!(message.contains("invalid relay configuration"), "{message}");
        }
    }

    /// One custom relay starts a session (reduced-redundancy mode).
    #[test]
    fn start_accepts_a_single_custom_relay() {
        let key = flextunnel_core::auth::ClientKey::generate().unwrap();
        let json = serde_json::json!({
            "auth_key": key.secret_str(),
            "relay_urls": ["https://only.example"],
            "destinations": [{ "name": "m1", "server_node_id": node_id(1) }],
        })
        .to_string();
        let (handle, _) = start_inner(&json).expect("starts");
        let status: serde_json::Value =
            serde_json::from_str(&status_json(&handle.client.status(), Instant::now())).unwrap();
        assert_eq!(
            status["destinations"][0]["relay_urls"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        stop_handle(handle);
    }

    #[test]
    fn idle_timeout_zero_means_never() {
        let key = flextunnel_core::auth::ClientKey::generate().unwrap();
        let json = serde_json::json!({
            "auth_key": key.secret_str(),
            "idle_timeout_secs": 0,
            "destinations": [{ "name": "m1", "server_node_id": node_id(1) }],
        })
        .to_string();
        let (handle, _) = start_inner(&json).expect("starts");
        let status: serde_json::Value =
            serde_json::from_str(&status_json(&handle.client.status(), Instant::now())).unwrap();
        assert!(status["idle_timeout_secs"].is_null());
        stop_handle(handle);
    }

    /// A result of no fixed size reports what it needs, whether it fit or not.
    #[test]
    fn a_sized_write_reports_the_bytes_it_needs() {
        let json = r#"{"routed_domains":[],"routed_cidrs":[]}"#;
        let read = |buf: &[c_char]| {
            unsafe { CStr::from_ptr(buf.as_ptr()) }
                .to_str()
                .unwrap()
                .to_owned()
        };

        let mut exact = vec![0 as c_char; json.len() + 1];
        assert_eq!(
            write_sized(exact.as_mut_ptr(), exact.len(), json),
            exact.len() as isize
        );
        assert_eq!(read(&exact), json);

        // One byte short: truncated, NUL-terminated, and the size to retry with.
        let mut short = vec![0 as c_char; json.len()];
        let needed = write_sized(short.as_mut_ptr(), short.len(), json);
        assert_eq!(needed, json.len() as isize + 1);
        assert!(needed > short.len() as isize);
        assert_eq!(read(&short), &json[..json.len() - 1]);
        assert_eq!(write_sized(ptr::null_mut(), 0, json), needed);
    }

    /// A failed routes request is -1 whatever the buffer: never a size to
    /// retry with, which would ask the server again for the same failure.
    #[test]
    fn a_failed_routes_request_is_not_a_short_buffer() {
        let request = std::ffi::CString::new("{").unwrap();
        let mut tiny = [0 as c_char; 8];
        let status = unsafe {
            flextunnel_fetch_server_routes(request.as_ptr(), tiny.as_mut_ptr(), tiny.len())
        };
        assert_eq!(status, -1);
        let mut roomy = [0 as c_char; 256];
        let status = unsafe {
            flextunnel_fetch_server_routes(request.as_ptr(), roomy.as_mut_ptr(), roomy.len())
        };
        assert_eq!(status, -1);
        let message = unsafe { CStr::from_ptr(roomy.as_ptr()) }.to_str().unwrap();
        assert!(message.contains("invalid request JSON"), "{message}");
        assert_eq!(
            unsafe { flextunnel_fetch_server_routes(ptr::null(), ptr::null_mut(), 0) },
            -1
        );
    }

    /// A routes request that cannot be acted on is refused before anything is
    /// bound or dialed.
    #[test]
    fn invalid_routes_requests_are_rejected() {
        let key = flextunnel_core::auth::ClientKey::generate()
            .unwrap()
            .secret_str();
        let request = |value: serde_json::Value| fetch_server_routes_inner(&value.to_string());
        let err = |value: serde_json::Value| request(value).expect_err("rejected");

        assert!(
            fetch_server_routes_inner("{")
                .unwrap_err()
                .contains("invalid request JSON")
        );
        assert!(err(serde_json::json!({ "auth_key": key })).contains("server_node_id"));
        assert!(
            err(serde_json::json!({ "auth_key": key, "server_node_id": "nope" }))
                .contains("invalid server_node_id")
        );
        assert!(
            err(serde_json::json!({ "auth_key": "nope", "server_node_id": node_id(1) }))
                .contains("invalid auth key")
        );
        let bad_relay = serde_json::json!({
            "auth_key": key,
            "server_node_id": node_id(1),
            "relay_urls": ["not a url"],
        });
        assert!(err(bad_relay).contains("invalid relay configuration"));
        // The QUIC address discovery setting needs custom relays, as in a
        // session's config.
        let stray_discovery = serde_json::json!({
            "auth_key": key,
            "server_node_id": node_id(1),
            "relay_quic_addr_discovery": false,
        });
        assert!(err(stray_discovery).contains("invalid relay configuration"));
    }

    // Byte the caller-side buffers below start out holding, so a test can tell
    // a byte the call wrote from one it left alone.
    const FILL: c_char = 0x55;

    /// The NUL-terminated string at the start of `buf`; panics if `buf` holds
    /// no NUL, so it reads only inside the buffer (unlike `CStr::from_ptr`).
    fn cstr(buf: &[c_char]) -> &str {
        // SAFETY: `c_char` and `u8` have the same size and alignment.
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len()) };
        CStr::from_bytes_until_nul(bytes)
            .expect("no NUL inside the buffer")
            .to_str()
            .expect("not UTF-8")
    }

    // Every buffer below is allocated at exactly the length passed, so under
    // Miri a write past it is reported rather than landing in spare capacity.
    #[test]
    fn write_cstr_stays_inside_the_buffer() {
        let mut exact = vec![FILL; 7];
        assert!(write_cstr(exact.as_mut_ptr(), exact.len(), "abcdef"));
        assert_eq!(cstr(&exact), "abcdef");

        let mut short = vec![FILL; 7];
        assert!(!write_cstr(short.as_mut_ptr(), short.len(), "abcdefg"));
        assert_eq!(cstr(&short), "abcdef");

        let mut nul_only = vec![FILL; 1];
        assert!(!write_cstr(nul_only.as_mut_ptr(), nul_only.len(), "abc"));
        assert_eq!(nul_only[0], 0);
        assert!(write_cstr(nul_only.as_mut_ptr(), nul_only.len(), ""));

        // Unusable buffers are left alone.
        let mut untouched = vec![FILL; 4];
        assert!(!write_cstr(untouched.as_mut_ptr(), 0, "abc"));
        assert_eq!(untouched, vec![FILL; 4]);
        assert!(!write_cstr(ptr::null_mut(), 8, "abc"));
    }

    /// The key exports through their buffer contracts: a buffer of exactly the
    /// right size, one byte short, room for only the NUL, none at all, and
    /// refused secrets — so under Miri a write past `out_len` (or a read past
    /// the secret's NUL) is reported as undefined behavior.
    #[test]
    fn key_exports_keep_to_their_buffers() {
        let mut doc = vec![FILL; 512];
        assert_eq!(
            unsafe { flextunnel_generate_client_key(doc.as_mut_ptr(), doc.len()) },
            1
        );
        let doc: serde_json::Value = serde_json::from_str(cstr(&doc)).unwrap();
        let secret = std::ffi::CString::new(doc["secret_key"].as_str().unwrap()).unwrap();
        let public = doc["public_key"].as_str().unwrap();
        let public_key = |out: &mut [c_char]| unsafe {
            flextunnel_client_public_key(secret.as_ptr(), out.as_mut_ptr(), out.len())
        };

        let mut exact = vec![FILL; public.len() + 1];
        assert_eq!(public_key(&mut exact), 1);
        assert_eq!(cstr(&exact), public);

        // One byte short: truncated, and the NUL still lands inside.
        let mut short = vec![FILL; public.len()];
        assert_eq!(public_key(&mut short), 0);
        assert_eq!(cstr(&short), &public[..public.len() - 1]);

        let mut nul_only = vec![FILL; 1];
        assert_eq!(
            unsafe { flextunnel_generate_client_key(nul_only.as_mut_ptr(), nul_only.len()) },
            0
        );
        assert_eq!(nul_only[0], 0);
        assert_eq!(
            unsafe { flextunnel_generate_client_key(ptr::null_mut(), 0) },
            0
        );
        assert_eq!(public_key(&mut []), 0);

        let mut err = vec![FILL; 128];
        let refused = |secret: *const c_char, err: &mut [c_char]| {
            let status =
                unsafe { flextunnel_client_public_key(secret, err.as_mut_ptr(), err.len()) };
            assert_eq!(status, 0);
            cstr(err).to_owned()
        };
        assert_eq!(refused(ptr::null(), &mut err), "secret_key is null");
        let not_utf8 = [0xffu8 as c_char, 0];
        assert_eq!(
            refused(not_utf8.as_ptr(), &mut err),
            "secret_key is not valid UTF-8"
        );
        let message = refused(c"not-a-key".as_ptr(), &mut err);
        assert!(message.starts_with("invalid secret key"), "{message}");
    }

    /// Every handle call refuses a null handle without touching anything but
    /// the caller's buffer, which it leaves NUL-terminated.
    #[test]
    fn null_handles_are_refused() {
        let null = ptr::null::<FlextunnelHandle>();
        let mut out = vec![FILL; 64];
        let (buf, len) = (out.as_mut_ptr(), out.len());
        unsafe {
            assert_eq!(flextunnel_set_forwards(null, c"[]".as_ptr(), buf, len), -1);
            assert_eq!(flextunnel_forward_statuses(null, buf, len), -1);
            assert_eq!(flextunnel_status(null, buf, len), -1);
            assert_eq!(cstr(&out), "");
            assert_eq!(flextunnel_conn_path(null, c"m1".as_ptr(), buf, len), -1);
            assert_eq!(flextunnel_close_listeners(null), -1);
            assert_eq!(flextunnel_set_background(null, 1), -1);
            assert_eq!(flextunnel_set_network_available(null, 0), -1);
            assert_eq!(flextunnel_health(null), -1);
            flextunnel_stop(ptr::null_mut());
        }
        let mut out = vec![FILL; 64];
        let status = unsafe { flextunnel_start(ptr::null(), out.as_mut_ptr(), out.len()) };
        assert!(status.is_null());
        assert_eq!(cstr(&out), "config_json is null");
    }

    /// A session driven from the C side, start to stop: the handle the start
    /// boxes is borrowed by every call and freed by the stop, and each output
    /// lands inside a buffer of exactly the length passed. The only test that
    /// goes through `flextunnel_start`, whose single-instance guard is
    /// process-wide.
    #[test]
    fn a_session_runs_through_its_handle() {
        let json = std::ffi::CString::new(config(serde_json::json!([
            { "name": "m1", "server_node_id": node_id(1), "routed_domains": ["*.corp.example"] },
        ])))
        .unwrap();
        let result = r#"{"socks_port":null}"#;

        // Too small for the result: no handle, and the guard is released.
        let mut short = vec![FILL; result.len()];
        let handle = unsafe { flextunnel_start(json.as_ptr(), short.as_mut_ptr(), short.len()) };
        assert!(handle.is_null());
        assert_eq!(
            cstr(&short),
            &"out_buf too small for result JSON"[..result.len() - 1]
        );

        let mut out = vec![FILL; result.len() + 1];
        let handle = unsafe { flextunnel_start(json.as_ptr(), out.as_mut_ptr(), out.len()) };
        assert!(!handle.is_null());
        assert_eq!(cstr(&out), result);

        let mut out = vec![FILL; 128];
        let second = unsafe { flextunnel_start(json.as_ptr(), out.as_mut_ptr(), out.len()) };
        assert!(second.is_null());
        assert!(cstr(&out).contains("already running"), "{}", cstr(&out));

        unsafe {
            assert_eq!(flextunnel_health(handle), 1);
            assert_eq!(flextunnel_set_background(handle, 1), 1);
            assert_eq!(flextunnel_set_network_available(handle, 0), 1);
            assert_eq!(flextunnel_set_network_available(handle, 1), 1);
        }

        let mut status = vec![FILL; 1024];
        assert_eq!(
            unsafe { flextunnel_status(handle, status.as_mut_ptr(), status.len()) },
            1
        );
        let full = cstr(&status).to_owned();
        let status: serde_json::Value = serde_json::from_str(&full).unwrap();
        assert_eq!(status["destinations"][0]["state"], "idle");
        let mut short = vec![FILL; full.len()];
        assert_eq!(
            unsafe { flextunnel_status(handle, short.as_mut_ptr(), short.len()) },
            0
        );
        assert_eq!(cstr(&short), &full[..full.len() - 1]);

        let mut out = vec![FILL; 128];
        let set_forwards = |forwards: &std::ffi::CStr, out: &mut [c_char]| unsafe {
            flextunnel_set_forwards(handle, forwards.as_ptr(), out.as_mut_ptr(), out.len())
        };
        assert_eq!(set_forwards(c"[]", &mut out), 1);
        assert_eq!(cstr(&out), "");
        let unrouted = cr#"[{"id":"a","local_port":1,"remote_host":"elsewhere.example","remote_port":22,"enabled":true}]"#;
        assert_eq!(set_forwards(unrouted, &mut out), 0);
        assert_eq!(cstr(&out), "no destination routes elsewhere.example");
        assert_eq!(set_forwards(c"{", &mut out), 0);
        assert!(
            cstr(&out).starts_with("invalid forwards JSON"),
            "{}",
            cstr(&out)
        );

        let forwards = r#"{"forwards":[]}"#;
        let mut exact = vec![FILL; forwards.len() + 1];
        assert_eq!(
            unsafe { flextunnel_forward_statuses(handle, exact.as_mut_ptr(), exact.len()) },
            exact.len() as isize
        );
        assert_eq!(cstr(&exact), forwards);

        // Not connected, so the snapshot is empty; an unknown name likewise.
        for name in [c"m1", c"nope"] {
            let mut paths = vec![FILL; 256];
            assert_eq!(
                unsafe {
                    flextunnel_conn_path(handle, name.as_ptr(), paths.as_mut_ptr(), paths.len())
                },
                1
            );
            let paths: serde_json::Value = serde_json::from_str(cstr(&paths)).unwrap();
            assert_eq!(paths["paths"], serde_json::json!([]));
        }

        unsafe {
            assert_eq!(flextunnel_close_listeners(handle), 1);
            assert_eq!(flextunnel_health(handle), 1);
            flextunnel_stop(handle);
        }

        // The stop released the guard.
        let mut out = vec![FILL; result.len() + 1];
        let handle = unsafe { flextunnel_start(json.as_ptr(), out.as_mut_ptr(), out.len()) };
        assert!(!handle.is_null());
        unsafe { flextunnel_stop(handle) };
    }

    #[test]
    fn invalid_configs_are_rejected_at_start() {
        // The single-server schema is gone: `destinations` is required.
        let key = flextunnel_core::auth::ClientKey::generate().unwrap();
        let old = serde_json::json!({ "auth_key": key.secret_str(), "server_node_id": node_id(1) });
        assert!(start_error(&old.to_string()).contains("destinations"));

        assert!(start_error(&config(serde_json::json!([]))).contains("no destinations"));
        let bad_id = config(serde_json::json!([{ "name": "m1", "server_node_id": "nope" }]));
        let message = start_error(&bad_id);
        assert!(
            message.contains("\"m1\"") && message.contains("server_node_id"),
            "{message}"
        );
        for bad_name in ["m1.internal", "10.0.0.1", "my_host", "-m1"] {
            let bad =
                config(serde_json::json!([{ "name": bad_name, "server_node_id": node_id(1) }]));
            assert!(
                start_error(&bad).contains("Destination name"),
                "{bad_name:?}"
            );
        }
        let same_name = config(serde_json::json!([
            { "name": "m1", "server_node_id": node_id(1) },
            { "name": "M1", "server_node_id": node_id(2) },
        ]));
        assert!(start_error(&same_name).contains("more than once"));
        let same_server = config(serde_json::json!([
            { "name": "m1", "server_node_id": node_id(1) },
            { "name": "m2", "server_node_id": node_id(1) },
        ]));
        assert!(start_error(&same_server).contains("same server"));
    }
}
