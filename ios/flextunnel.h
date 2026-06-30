/*
 * flextunnel.h — C interface to libflextunnel.a for the iOS app.
 *
 * Build the static library with ./build-ios.sh (produces
 * dist/ios/libflextunnel.a alongside a copy of this header).
 *
 * Unlike a VPN, there is no Network Extension and no utun fd: flextunnel runs a
 * SOCKS5 listener entirely inside the app process. Point a WKWebView at it via
 * WKWebsiteDataStore.proxyConfigurations (iOS 17+).
 *
 * Lifecycle:
 *
 *   1. flextunnel_init_logging()                          (once, optional)
 *   2. flextunnel_start(configJson, buf, len) -> handle   (or NULL on error)
 *        On success `buf` holds {"socks_port": N}; configure the WKWebView
 *        proxy with NWEndpoint host 127.0.0.1, port N.
 *        On error `buf` holds the error message. At most ONE instance may run
 *        at a time; a second start while one is live returns NULL.
 *   3. flextunnel_health(handle) -> 1 running / 0 ended / -1 null  (poll)
 *   4. flextunnel_stop(handle)                            (on teardown)
 *
 * The SOCKS5 listener binds a FIXED loopback port (default 18080, or
 * "socks_port" in the config) for predictable debugging.
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
 *    "socks_port":18080,"relay_urls":[],"dns_server":null}
 *   socks_port is optional (defaults to 18080). The split-tunnel whitelist (the
 *   tunnel set) is configured on the server and pushed to the client during the
 *   handshake, so the app sends no whitelist of its own.
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
 *   {"connected":true,"domains":["*.example.com"],"cidrs":["10.0.0.0/8"]}
 * This is the split-tunnel set the server pushes during the handshake — the
 * domains/CIDRs routed through the tunnel (off-list targets connect directly).
 * An empty domains+cidrs while connected==true means the server runs no
 * whitelist and everything is tunneled. The set becomes available shortly after
 * start once the handshake completes, so poll it.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the JSON
 * is truncated; retry larger), and -1 for a NULL handle or if the route snapshot
 * could not be read. out_buf is always NUL-terminated when usable (non-NULL,
 * out_len > 0): the error returns write an empty string.
 */
int flextunnel_routes(const FlextunnelHandle *handle, char *out_buf, size_t out_len);

/*
 * Stop the proxy and free the handle. After this call the handle is invalid.
 * Passing NULL is a safe no-op.
 */
void flextunnel_stop(FlextunnelHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* FLEXTUNNEL_H */
