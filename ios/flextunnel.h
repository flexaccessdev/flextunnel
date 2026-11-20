/*
 * flextunnel.h — C interface to libflextunnel.xcframework for the iOS app.
 *
 * Build the static library slices with ./build-ios.sh (produces
 * dist/ios/libflextunnel.xcframework alongside a copy of this header).
 *
 * Unlike a VPN, there is no Network Extension and no utun fd. Browser sessions
 * may run a SOCKS5 listener for WKWebView; forwarding-only sessions omit it and
 * use local forward listeners owned by the Rust core.
 *
 * One client reaches any number of servers — its "destinations", each a host
 * name for one server — and connects to a server only when something is first
 * sent to it, closing the connection again once it has gone unused. Starting a
 * session therefore connects nothing.
 *
 * Lifecycle:
 *
 *   1. flextunnel_init_logging()                          (once, optional)
 *   2. flextunnel_start(configJson, buf, len) -> handle   (or NULL on error)
 *        On success `buf` holds {"socks_port": N|null};
 *        configure the WKWebView proxy with NWEndpoint host 127.0.0.1, port N.
 *        On error `buf` holds the error message. At most ONE instance may run
 *        at a time; a second start while one is live returns NULL.
 *   3. flextunnel_health(handle) -> 1 running / 0 ended / -1 null  (poll)
 *   -  flextunnel_status(handle, buf, len)                (per-destination state; poll)
 *   -  flextunnel_conn_path(handle, host, buf, len)       (on-demand path readout)
 *   -  flextunnel_set_background(handle, 1|0)             (scene-phase changes)
 *   -  flextunnel_set_network_available(handle, 1|0)      (NWPathMonitor updates)
 *   -  flextunnel_close_listeners(handle)                 (just before suspension)
 *   4. flextunnel_stop(handle)                            (on teardown)
 *
 * Pass a numeric "socks_port" to bind the browser's loopback SOCKS5 listener
 * (0 requests an OS-assigned port, read back from the result JSON; a nonzero
 * port is required — if it is in use the start fails). Pass null or omit it
 * for a forwarding-only session with no SOCKS5 listener.
 *
 * All functions are NULL-safe and never unwind into Swift.
 */
#ifndef FLEXTUNNEL_H
#define FLEXTUNNEL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque session handle. Created by flextunnel_start, freed by flextunnel_stop. */
typedef struct FlextunnelHandle FlextunnelHandle;

/*
 * Initialize logging (stderr -> unified log / Console). Honors RUST_LOG;
 * otherwise flextunnel's own crates log at "info" and their dependencies at
 * "warn". Idempotent; safe to call more than once.
 */
void flextunnel_init_logging(void);

/*
 * Generate a fresh client authentication keypair. Writes
 *   {"created":"<UTC>","public_key":"ed25519-pub:...",
 *    "secret_key":"ed25519-sec:..."}
 * to out_buf. Store the secret key in the keychain; show the public key (never
 * a secret) for the user to put on the server's authorized-keys file.
 * Returns 1 on success, 0 if out_buf is too small.
 */
int flextunnel_generate_client_key(char *out_buf, size_t out_len);

/*
 * Derive the public key ("ed25519-pub:...") of a stored secret key, so the
 * app can display it unmasked without persisting it separately. On success
 * writes the public key to out_buf and returns 1. For an invalid secret it
 * writes an error message and returns 0. If out_buf is too small it also
 * returns 0, but out_buf then holds the truncated (NUL-terminated) output —
 * no diagnostic text — so retry with a larger buffer.
 */
int flextunnel_client_public_key(const char *secret_key, char *out_buf, size_t out_len);

/*
 * Start the in-process client: validate the config, optionally bind a
 * loopback SOCKS5 listener, and start serving. No server is contacted — a
 * destination connects on first use (see flextunnel_status).
 *
 * config_json : NUL-terminated UTF-8 JSON, e.g.
 *   {"auth_key":"ed25519-sec:...","socks_port":0,
 *    "relay_urls":[],"relay_auth_token":null,"idle_timeout_secs":300,
 *    "destinations":[
 *      {"host":"machine1.internal","server_node_id":"<id>",
 *       "routed_domains":["*.corp.example"],"routed_cidrs":["10.0.0.0/8"]}]}
 *   auth_key is this client's secret key (from flextunnel_generate_client_key
 *   or `flexaccess-keys generate-auth-key`); its public half must be on each
 *   server's authorized_keys_file.
 *   socks_port is optional; null/omitted disables SOCKS5, 0 requests an
 *   OS-assigned port (read the bound port from the result JSON), and a nonzero
 *   port is required (an in-use port fails the start).
 *   relay_auth_token is optional: a shared bearer token sent to every custom
 *   relay's WebSocket upgrade; it is only valid with custom relay_urls
 *   (rejected with the default iroh relays). Custom relays need at least two
 *   URLs.
 *   idle_timeout_secs is optional: how long a destination's connection is kept
 *   with no stream open on it. Omitted means 300; 0 means never close one for
 *   idleness.
 *   destinations is required, with at least one entry. host names the server:
 *   "<host>:<port>" through the client is that port on the server's own
 *   loopback. Any host name except an IP address, "localhost", or one under
 *   "flextunnel.internal"; hosts and server ids must each be unique.
 *   routed_domains (exact name, "*.suffix", or "*") and routed_cidrs (network
 *   or bare IP) are optional further targets sent through that server, which
 *   must route them too — its own routed set is the allowlist. The same rule
 *   on two destinations is an error; otherwise the most specific rule wins.
 *   Routing is entirely this config's: nothing is learned from a server, and
 *   a target on no destination's list connects directly from the device.
 * out_buf/out_len : caller buffer. On success receives {"socks_port":N|null};
 *   on failure receives an error message. Always NUL-terminated. If out_buf is
 *   too small for the success JSON, this is treated as a failure (returns NULL,
 *   no handle leaked) — retry with a larger buffer.
 *
 * Returns a non-NULL handle on success, NULL on failure (including when another
 * instance is already running).
 */
FlextunnelHandle *flextunnel_start(const char *config_json, char *out_buf, size_t out_len);

/*
 * Replace the complete local-forward set. forwards_json must be a valid
 * NUL-terminated JSON string holding an array of objects:
 *   [{"id":"uuid","local_port":8080,"remote_host":"db.internal",
 *     "remote_port":5432,"enabled":true}]
 *
 * Enabled listeners bind loopback only (127.0.0.1 and ::1). Each accepted TCP
 * connection opens a QUIC data stream through the destination that routes
 * remote_host — connecting that destination first if it is idle; no SOCKS5
 * proxy is involved. remote_host is routed like a proxy request (a
 * destination's own host is that server's loopback), and the server enforces
 * its routed-set whitelist. A forward never connects directly: an enabled
 * forward whose remote_host no destination routes is invalid input.
 *
 * Returns 1 on success, 0 for invalid input, and -1 for a NULL handle.
 * out_buf receives an error message on failure.
 */
int flextunnel_set_forwards(const FlextunnelHandle *handle, const char *forwards_json,
                           char *out_buf, size_t out_len);

/*
 * Snapshot forward states:
 *   {"forwards":[{"id":"uuid","state":"listening","error":null,
 *     "active":1,"last_conn_error":null}]}
 * Returns the byte count the JSON needs including the trailing NUL, or -1 for
 * NULL/lock error. out_buf holds the complete JSON iff the return value is
 * <= out_len; on a larger return it holds a NUL-terminated truncation and the
 * call must be repeated with a buffer of at least the returned size.
 */
ptrdiff_t flextunnel_forward_statuses(const FlextunnelHandle *handle,
                                      char *out_buf, size_t out_len);

/*
 * Close every local listener — the SOCKS5 front-end and all forward
 * listeners — while keeping the session handle alive. One-way: call it
 * when suspension is imminent, so local clients get an immediate
 * connection-refused instead of hanging on the frozen process's backlog. There
 * is no reopen — relaunch the session (flextunnel_stop + flextunnel_start, then
 * re-apply forwards) on return to the foreground. flextunnel_health stays 1
 * after this call; don't call flextunnel_set_forwards between close and
 * relaunch (it would bind listeners again).
 *
 * Returns 1 on success, 0 for an internal lock failure (the proxy front-end is
 * closed regardless), and -1 for a NULL handle.
 */
int flextunnel_close_listeners(const FlextunnelHandle *handle);

/*
 * Report the app's scene state: 1 when backgrounded, 0 when foregrounded.
 * Backgrounded, the core's app-level heartbeat — the connection's only periodic
 * traffic — slows from 10s to 60s so a connected session wakes the cellular
 * radio once a minute instead of six times; the foreground flip snaps it back
 * and sends any overdue beat immediately, and ends any destination's retry
 * backoff in progress (up to 60s once a long outage has pushed it to the cap)
 * so the next attempt runs at once with a fresh backoff series. Idempotent.
 *
 * Returns 1 on success and -1 for a NULL handle.
 */
int flextunnel_set_background(const FlextunnelHandle *handle, int background);

/*
 * Report whether the device has a usable network path (from NWPathMonitor):
 * 1 available, 0 unavailable. While unavailable no destination dials, instead
 * of burning retries into a dead network; the flip back to available gives
 * every destination with requests waiting an immediate attempt with a fresh
 * backoff series. Defaults to available if never called.
 *
 * Returns 1 on success and -1 for a NULL handle.
 */
int flextunnel_set_network_available(const FlextunnelHandle *handle, int available);

/*
 * Liveness probe. Returns 1 while the client is serving, 0 once it has ended,
 * and -1 for a NULL handle. The client ends only when a local listener is lost
 * for good. No destination's trouble ends it — an unreachable server, a
 * dropped connection or a rejected key is that destination's state (see
 * flextunnel_status), and the client keeps serving the rest.
 */
int flextunnel_health(const FlextunnelHandle *handle);

/*
 * Snapshot the client's destinations as JSON into out_buf:
 *   {"idle_timeout_secs":300,
 *    "destinations":[
 *     {"host":"machine1.internal","server_node_id":"…",
 *      "state":"connected","connected_secs":42,
 *      "open_streams":1,"waiting":0,"client_node_id":"…",
 *      "failed_attempts":0,"next_attempt_secs":null,"last_error":null,
 *      "routed_domains":["*.corp.example"],"routed_cidrs":["10.0.0.0/8"],
 *      "relay_urls":[]}]}
 * One entry per configured destination, in config order. state is one of:
 *   "idle"        not connected and nothing is asking for it — the resting
 *                 state. A destination connects when something is first sent
 *                 to it and returns to idle after idle_timeout_secs without an
 *                 open stream (null: never).
 *   "connecting"  building its endpoint, connecting or authenticating.
 *   "connected"   connected_secs is the connection's age.
 *   "backoff"     the last attempt failed and requests are still waiting;
 *                 next_attempt_secs is when it retries.
 *   "failed"      the server refused this client (e.g. an unauthorized key);
 *                 requests fail at once until next_attempt_secs.
 * open_streams / waiting count the streams open on the connection and the
 * requests held while it connects. client_node_id is this client's endpoint id
 * toward that server, null while idle. failed_attempts and last_error describe
 * the current outage and are cleared by a successful connection; an idle
 * destination with failed_attempts > 0 retries on its next use, not before.
 *
 * routed_domains / routed_cidrs echo the destination's configured routes, for
 * display. The local SOCKS proxy owns the split: a target a destination routes
 * uses that destination's tunnel, everything else connects directly from the
 * device, so the caller has nothing to enforce. A server's own view (its
 * routed set, host aliases, DNS forwards, bridges) is its status page,
 * reachable through the SOCKS proxy at
 *   http://flextunnel.internal/servers/<host>/status.json
 * and the client's own at http://flextunnel.internal/status.json.
 *
 * Reading this never causes a connection.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the JSON
 * is truncated; retry larger), and -1 for a NULL handle. out_buf is always
 * NUL-terminated when usable (non-NULL, out_len > 0): the NULL-handle return
 * writes an empty string.
 */
int flextunnel_status(const FlextunnelHandle *handle, char *out_buf, size_t out_len);

/*
 * Snapshot the iroh path(s) of the connection to the destination named `host`
 * as JSON into out_buf, mirroring `ezvpn client status`:
 *   {"paths":[
 *     {"kind":"direct","display":"Direct 1.2.3.4:52186 (rtt 1ms)","selected":true},
 *     {"kind":"relay","display":"Relay https://relay.example/ (rtt 42ms)","selected":false}],
 *    "custom_relays":[
 *     {"url":"https://relay.example/","working":true,"error":null}],
 *    "udp_tx_datagrams":1234,"udp_rx_datagrams":1201}
 * A point-in-time snapshot of how the client currently reaches that server,
 * showing ALL discovered paths (not just the selected one). kind is "direct",
 * "relay", or "other" (forward-compatible catch-all); selected marks the path
 * iroh routes over right now. The whole snapshot is EMPTY while the destination
 * is not connected (idle, connecting, backing off) or when `host` names no
 * destination, so only offer this for a destination flextunnel_status reports
 * "connected". Asking never connects it.
 *
 * custom_relays reports each configured custom relay's health from an on-demand
 * GET of its /healthz endpoint (checked in parallel, only when this snapshot is
 * requested). working is true on a 2xx, false when unreachable/timed-out/non-2xx,
 * and null if the check could not run; error carries the failure detail. The
 * array is empty when the default relays are used. /healthz is unauthenticated:
 * it confirms the relay is up, not that a relay_auth_token is accepted.
 *
 * udp_tx_datagrams/udp_rx_datagrams count the UDP datagrams the live connection
 * has sent/received since it was established (0 while not connected). On cellular
 * energy is per-wakeup rather than per-byte, so sampling the tx count over an
 * interval is the cheap proxy for the tunnel's radio cost.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the JSON
 * is truncated; retry larger), and -1 for a NULL handle or an unusable `host`
 * (NULL or not UTF-8). out_buf is always NUL-terminated when usable (non-NULL,
 * out_len > 0); the -1 returns write an empty string.
 */
int flextunnel_conn_path(const FlextunnelHandle *handle, const char *host,
                         char *out_buf, size_t out_len);

/*
 * Stop the client, close the endpoints of the destinations in use, and free
 * the handle. After this call the handle is invalid. Passing NULL is a safe
 * no-op.
 */
void flextunnel_stop(FlextunnelHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* FLEXTUNNEL_H */
