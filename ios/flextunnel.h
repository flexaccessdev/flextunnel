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
 * Stop the proxy and free the handle. After this call the handle is invalid.
 * Passing NULL is a safe no-op.
 */
void flextunnel_stop(FlextunnelHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* FLEXTUNNEL_H */
