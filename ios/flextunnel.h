/*
 * flextunnel.h — C interface to libflextunnel.xcframework for the iOS app.
 *
 * Build the static library slices with ./build-ios.sh (produces
 * dist/ios/libflextunnel.xcframework alongside a copy of this header).
 *
 * Unlike a VPN, there is no Network Extension and no utun fd: flextunnel runs a
 * SOCKS5 listener entirely inside the app process. Point a WKWebView at it via
 * WKWebsiteDataStore.proxyConfigurations (iOS 17+).
 *
 * Lifecycle:
 *
 *   1. flextunnel_init_logging()                          (once, optional)
 *   2. flextunnel_start(configJson, buf, len) -> handle   (or NULL on error)
 *        On success `buf` holds {"socks_port": N} (the ACTUAL bound port);
 *        configure the WKWebView proxy with NWEndpoint host 127.0.0.1, port N.
 *        On error `buf` holds the error message. At most ONE instance may run
 *        at a time; a second start while one is live returns NULL.
 *   3. flextunnel_health(handle) -> 1 running / 0 ended / -1 null  (poll)
 *   -  flextunnel_conn_path(handle, buf, len)             (on-demand path readout)
 *   4. flextunnel_stop(handle)                            (on teardown)
 *
 * The SOCKS5 listener binds an OS-assigned EPHEMERAL loopback port by default
 * (omit "socks_port" or pass 0) — unpredictable, so it isn't a fixed target for
 * other local processes. Read the chosen port from the result JSON. A caller
 * may still pin a specific port via "socks_port".
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
 * Initialize logging (stderr -> unified log / Console). Honors RUST_LOG,
 * defaults to "info". Idempotent; safe to call more than once.
 */
void flextunnel_init_logging(void);

/*
 * Start the in-process SOCKS5 proxy: create the iroh endpoint, bind a loopback
 * listener on a FIXED port (default 18080, or "socks_port" in the config), and
 * spawn the connect/auth/serve loop.
 *
 * config_json : NUL-terminated UTF-8 JSON, e.g.
 *   {"server_node_id":"<id>","auth_token":"<token>",
 *    "socks_port":0,"relay_urls":[],"dns_server":null}
 *   socks_port is optional; omit or 0 for an OS-assigned ephemeral port (read the
 *   actual port from the result JSON). The split-tunnel routed set (the tunnel
 *   set) is configured on the server and pushed to the client during the
 *   handshake, so the app sends no routed set of its own.
 * out_buf/out_len : caller buffer. On success receives {"socks_port":N};
 *   on failure receives an error message. Always NUL-terminated. If out_buf is
 *   too small for the success JSON, this is treated as a failure (returns NULL,
 *   no handle leaked) — retry with a larger buffer.
 *
 * Returns a non-NULL handle on success, NULL on failure (including when another
 * instance is already running).
 */
FlextunnelHandle *flextunnel_start(const char *config_json, char *out_buf, size_t out_len);

/*
 * Liveness probe. Returns 1 while the connect/serve loop is running, 0 once it
 * has ended (gave up on a fatal error: bad node id, auth failure, or an
 * unreachable server on the first connect), and -1 for a NULL handle.
 */
int flextunnel_health(const FlextunnelHandle *handle);

/*
 * Snapshot the tunnel's current forwarding set as JSON into out_buf:
 *   {"connected":true,"domains":["*.example.com"],"cidrs":["10.0.0.0/8"],
 *    "host_aliases":[["nas.internal","192.168.1.9"]],
 *    "agent_aliases":[{"name":"workstation.internal","status":"connected"}],
 *    "dns_forwards":[{"suffix":"corp.example.com","servers":["10.1.0.10:5353"]}],
 *    "bridges":[{"name":"lab","endpoint_id":"…","domains":["*.svc"],"cidrs":["fd34::/64"]}]}
 * This is the required split-tunnel set the server pushes during the handshake
 * — the domains/CIDRs routed through the tunnel (off-list targets connect
 * directly). Before the first successful handshake, connected is false and the
 * lists are empty. The set becomes available shortly after start once the
 * handshake completes, so poll it. host_aliases ([alias, target] pairs) and
 * agent_aliases are informational, for display only — the server resolves both
 * itself. Each agent_aliases entry is {"name","status"} where status is
 * "connected", "disconnected", or "unknown"; it rides the heartbeat control
 * stream (refreshed every ~10s) and reads "unknown" before the first update,
 * while the tunnel is down, or when the view has gone stale. dns_forwards is the
 * server's conditional DNS-forwarding table, also informational: each entry is
 * {"suffix","servers"} — names under suffix resolve via servers instead of the
 * server's system resolver. Empty when none are configured. bridges is the
 * server's outbound bridge-route table (targets it forwards to another
 * flextunnel server), also informational: each entry is
 * {"name","endpoint_id","domains","cidrs"}; the bridged rules are already part
 * of the routed set. Empty when none are configured.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the JSON
 * is truncated; retry larger), and -1 for a NULL handle or if the route snapshot
 * could not be read. out_buf is always NUL-terminated when usable (non-NULL,
 * out_len > 0): the error returns write an empty string.
 */
int flextunnel_routes(const FlextunnelHandle *handle, char *out_buf, size_t out_len);

/*
 * Snapshot the live connection's iroh path(s) as JSON into out_buf, mirroring
 * `ezvpn client status`:
 *   {"paths":[
 *     {"kind":"direct","display":"Direct 1.2.3.4:52186 (rtt 1ms)","selected":true},
 *     {"kind":"relay","display":"Relay https://relay.example/ (rtt 42ms)","selected":false}]}
 * A point-in-time snapshot of how the client currently reaches the server,
 * showing ALL discovered paths (not just the selected one). kind is "direct",
 * "relay", or "other" (forward-compatible catch-all); selected marks the path
 * iroh routes over right now. The array is EMPTY while disconnected (during a
 * drop/backoff or before the first connect), so only offer this once the tunnel
 * link is up.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the JSON
 * is truncated; retry larger), and -1 for a NULL handle. out_buf is always
 * NUL-terminated when usable (non-NULL, out_len > 0); the NULL-handle return
 * writes an empty string.
 */
int flextunnel_conn_path(const FlextunnelHandle *handle, char *out_buf, size_t out_len);

/*
 * Stop the proxy and free the handle. After this call the handle is invalid.
 * Passing NULL is a safe no-op.
 */
void flextunnel_stop(FlextunnelHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* FLEXTUNNEL_H */
