# Roadmap: HTTP proxy support

This file tracks only the remaining HTTP proxy work.

## Open Work

### Shared Local-Connection Concurrency Cap

The client currently spawns one task per accepted SOCKS5 or HTTP proxy
connection. Add a shared cap across both local listeners so a local connection
flood cannot grow tasks and sockets without bound.

Expected shape:

- Introduce one shared limiter in `crates/flextunnel-core/src/proxy/client.rs`.
- Apply it before spawning per-connection handlers for both SOCKS5 and HTTP.
- Preserve current behavior under normal load: both listeners stay bound across
  reconnects, off-list targets can still direct-connect, and on-list targets
  still return a clean proxy error while the tunnel is down.
- Decide what local clients see when the cap is full: backpressure in `accept`,
  immediate proxy failure, or a bounded wait.

### Centralized Reply-Code Mapping

HTTP and SOCKS5 reply handling currently map flextunnel `rep` codes separately:
HTTP status mapping lives in `http::write_reply`, while SOCKS5 reply handling
lives in `socks5.rs`. Centralize the mapping policy so these surfaces cannot
drift.

Expected shape:

- Keep the wire `rep` values equal to RFC 1928 SOCKS5 reply codes.
- Define one shared mapping from `rep` to semantic failure categories.
- Have SOCKS5 and HTTP translate those categories to their own protocol replies.
- Cover at least `REP_NOT_ALLOWED`, unreachable/refused/timeout-style failures,
  and generic failure.

### Plain-HTTP Keep-Alive Forwarding

Absolute-URI plain-HTTP forwarding currently opens one upstream tunnel per
request and forces `Connection: close`. Add keep-alive support only if the extra
complexity is worth the connection reuse benefit.

Expected shape:

- Parse enough HTTP/1.x framing to know where each request and response ends.
- Support multiple plain-HTTP requests on one client-to-proxy connection.
- Reuse an upstream connection only when the same origin and routing decision
  still apply.
- Continue stripping hop-by-hop headers correctly on every forwarded request.
- Preserve request-smuggling defenses: reject obs-fold, control-byte injection,
  malformed headers, and ambiguous framing.

Open design questions:

- Whether to add a real HTTP parser dependency or keep extending the current
  minimal parser.
- Whether upstream reuse should apply only to direct split-tunnel connections,
  only to tunneled connections, or both.
- Whether the performance gain is meaningful enough for flextunnel's expected
  plain-HTTP traffic.
