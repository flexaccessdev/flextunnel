# Roadmap: HTTP proxy support

Status: **Phases 1–2 implemented** (HTTP `CONNECT` tunneling + absolute-URI
plain-HTTP forwarding), plus part of Phase 3's hardening (header-size cap,
shared handshake timeout, request-smuggling defenses, docs). The remaining
Phase 3 items — a centralized `rep`→status mapping, a shared concurrency cap,
and keep-alive forwarding — are still open. The client exposes a
**SOCKS5** listener
(`crates/flextunnel-core/src/proxy/socks5.rs`) and, when `--http-listen` is set,
an **HTTP proxy** front-end (`crates/flextunnel-core/src/proxy/http.rs`) —
both handled by the shared routing core in
`crates/flextunnel-core/src/proxy/client.rs` via the `LocalProto` trait.

## Motivation / gap analysis

A SOCKS5-only client leaves a real gap: many common tools either can't speak
SOCKS5 at all, or only speak it with **client-side DNS** — which is
fundamentally incompatible with flextunnel's model, where routed names
(`routed_domains` / `[host_aliases]`, e.g. `networking.internal`) resolve
**only on the server**. HTTP `CONNECT` always sends the hostname to the proxy,
so DNS happens server-side — exactly what flextunnel needs. The gap, by tier:

- **No SOCKS5 at all → only reachable via an HTTP proxy:** `wget` (verified:
  `socks5h://` → `Unsupported scheme`), Docker daemon / `docker build` image
  pulls (HTTP/HTTPS only), npm / yarn, .NET Framework (pre-.NET-6).
- **SOCKS5 works only with an extra install:** Python `requests`/`pip`
  (needs `requests[socks]`/PySocks; HTTP proxy works out of the box); Go
  `net/http` (honors `socks5://` via `ALL_PROXY` but historically no `socks5h`
  remote DNS).
- **SOCKS5 supported but client-side DNS breaks flextunnel:** JVM
  `socksProxyHost` (Gradle, JDBC drivers), .NET 6+ SOCKS (no `socks5h`). These
  resolve the hostname locally, so internal names fail even though "SOCKS is
  supported."
- **Already fine (no gap):** `apt` (`socks5h://`), curl, ssh, browsers.

### What HTTP proxy does *not* cover

An HTTP proxy only helps clients that speak HTTP (CONNECT or absolute-URI).
**Raw-TCP apps — databases via JDBC/native clients, RDP, SSH —
do not speak HTTP CONNECT**, so they still need SOCKS5 (with the client-DNS
caveat) or a `socat` port forward. See
[`docs/proxy-usage.md`](proxy-usage.md) for those recipes. HTTP proxy
*complements* the `socat` approach rather than replacing it.

## Key insight: the wire protocol does not change

The client↔server protocol is front-end-agnostic. A SOCKS5 `CONNECT` is already
reduced to a `signaling::Target` (`Ip` or `Domain`) and tunneled over one QUIC
bi-stream via `signaling::write_request` → `signaling::read_reply` → byte pipe
(`crates/flextunnel-core/src/proxy/signaling.rs`). The **server** (`crates/flextunnel-core/src/proxy/server.rs`) only ever sees
a `Target`, resolves DNS, and connects from its own network — it neither knows
nor cares whether the client spoke SOCKS5 or HTTP.

**Consequence:** HTTP proxy support is almost entirely a *client-side* feature.
No server changes, no new wire messages, no `Target` changes for the tunneling
(CONNECT) path. This keeps the addition low-risk and avoids a wire-protocol
migration.

## Background: the two HTTP proxy modes

1. **`CONNECT` tunneling** (HTTPS and any TCP): the client sends
   `CONNECT host:port HTTP/1.1`, the proxy opens a tunnel, replies
   `200 Connection Established`, then relays raw bytes. Semantically identical to
   SOCKS5 `CONNECT` — maps 1:1 onto our existing tunnel.
2. **Absolute-URI forwarding** (plain HTTP): the client sends
   `GET http://host/path HTTP/1.1` with a `Host` header. The proxy must parse the
   request, open a tunnel to `host:80`, rewrite the request line to origin-form
   (`GET /path`), forward it, and relay the response — ideally reusing the
   upstream connection across keep-alive requests.

Mode 1 is cheap (reuses everything). Mode 2 needs real HTTP/1.x message parsing.

## Phase 1 — HTTP `CONNECT` tunneling (MVP) — ✅ implemented

Shipped as `--http-listen <ADDR>` (off by default). The SOCKS5 and HTTP
front-ends share the routing core through a `LocalProto` trait in `client.rs`
(parse → `Target`, then reply-for-`rep`); `proxy/http.rs` holds the CONNECT
parser + status-line replies. Non-CONNECT methods get `501`; malformed/oversized
requests get `400`. The notes below record the original design.

Goal: an HTTP proxy that handles `CONNECT` (covers all HTTPS browsing and most
`HTTP_PROXY`/`https_proxy` use). Plain-HTTP `GET`/`POST` with absolute URIs is
explicitly rejected with `501 Not Implemented` until Phase 2.

### Refactor first (prep, no behavior change)
- Make the per-connection tunnel plumbing reusable by both front-ends. Today
  `open_tunnel(conn, target) -> (SendStream, RecvStream, u8)` and the
  reply-then-`copy_bidirectional` tail live inside `crates/flextunnel-core/src/proxy/client.rs`. Extract
  a shared helper, e.g.
  `tunnel::dial(conn, &Target) -> io::Result<(SendStream, RecvStream, rep)>`,
  used by both the SOCKS5 and HTTP handlers.
- Generalize the accept loop. `ProxyClient::run` currently binds one
  `socks_listen` and spawns `handle_local_conn` per accept. Allow binding an
  optional second listener (`http_listen`) and dispatch accepted sockets to the
  HTTP handler. The QUIC `Connection` and reconnect logic are shared unchanged;
  both listeners multiplex over the same connection.

### New module: `crates/flextunnel-core/src/proxy/http.rs`
- `negotiate(stream) -> HttpReq`: read the request line + headers (until
  `\r\n\r\n`), bounded by a max header size (mirror `MAX_HANDSHAKE_SIZE`-style
  cap) and a read timeout (mirror `HANDSHAKE_TIMEOUT` in proxy/client.rs).
- If method is `CONNECT`: parse `host:port` from the request target into a
  `signaling::Target` (host → `Target::Domain`, literal IP → `Target::Ip`), dial
  the tunnel, then:
  - on `rep == REP_SUCCESS`: write `HTTP/1.1 200 Connection Established\r\n\r\n`
    and `copy_bidirectional` (exactly like the SOCKS5 success path).
  - otherwise: map the `rep` code to an HTTP status (e.g. `502 Bad Gateway`,
    `504` for timeout) and close.
- If method is anything else: respond `501 Not Implemented` (Phase 1 scope).
- Errors before the tunnel is established must still send an HTTP response
  (`400`/`502`), never a silent drop — same principle as the SOCKS5 handler now
  sending a reply on `open_tunnel` failure.

### CLI / config (`crates/flextunnel-cli/src/main.rs`)
- Add `--http-listen <ADDR>` to `client` (e.g. `127.0.0.1:8081`), optional.
- At least one of `--socks-listen` / `--http-listen` must be enabled; allow both
  simultaneously. Thread an `http_listen: Option<SocketAddr>` into `ClientConfig`.

### Tests
- Unit: `CONNECT example.com:443` request parsing → expected `Target`; malformed
  request line / oversized headers → `400`; non-CONNECT → `501`.
- E2E (extend `scratchpad` harness): `curl -p -x http://127.0.0.1:8081 https://example.com`
  (curl `-p` forces CONNECT) and the server-localhost reachability case.

## Phase 2 — Absolute-URI plain HTTP forwarding — ✅ implemented

Goal: handle `GET http://host/path HTTP/1.1` (and other methods) so plain-HTTP
clients work without TLS.

Shipped in `proxy/http.rs` as a second arm of the same request parser
(`read_request -> HttpRequest::{Connect, Forward}`); the shared routing core
gained an optional *upstream preamble* (the rewritten head, written upstream
instead of a local success reply) so the tunnel and direct split-tunnel paths
both forward unchanged. As designed:

- The absolute-form request target derives `Target::Domain(host, 80)` (or the
  URI's explicit port); literal IPs become `Target::Ip`, as with CONNECT.
- The request line is rewritten to origin-form with `Host` regenerated from the
  URI; hop-by-hop headers (`Proxy-Connection`, `Connection` and any header it
  names, `Keep-Alive`, `Proxy-Authorization`, etc.) are stripped per RFC 9110
  §7.6.1.
- One tunnel bi-stream per request with a forced `Connection: close`: after the
  rewritten head is written upstream, the body and the whole response relay
  **verbatim** (the same byte splice as CONNECT), and the origin closing the
  connection ends the exchange. Keep-alive reuse remains future work (Phase 3
  territory) — a client that tries to reuse the socket sees a clean close and
  retries on a fresh connection.
- **Decision (parser):** no `httparse` dependency. The verbatim relay means
  body framing (`Content-Length`/chunked) is never interpreted, so the existing
  hand-parsed request-line + header-line reader — where a real parser would
  have earned its keep — covers everything Phase 2 needs.
- Rejections: non-absolute (origin-form) targets, `https://` absolute URIs
  (must use CONNECT), userinfo in the target, and obs-fold headers get `400`;
  non-HTTP/1.x versions get `505`. The former blanket `501` for non-CONNECT
  methods is gone.

## Phase 3 — Hardening & polish

- **Proxy authentication:** out of scope. Both listeners are expected to bind
  loopback only (the SOCKS5 default is deliberately no-auth for the same
  reason), so there's no untrusted network to authenticate against.
- **Request-smuggling / header-injection defenses — ✅ done.** `read_request`
  rejects (`400`) a request line with any control byte, a header value carrying
  a bare CR/LF/NUL, and obs-fold continuation lines; header names have
  tolerated-but-invalid whitespace before the colon stripped (RFC 9112 §5.1)
  rather than replayed. This keeps a smuggled byte from being reintroduced into
  the rewritten upstream head. (`crates/flextunnel-core/src/proxy/http.rs`.)
- **Limits — partially done.** Max header size (`MAX_HTTP_HEADER`, 64 KiB) and a
  request timeout are shipped — the request head is read under the shared
  `LOCAL_HANDSHAKE_TIMEOUT` in `client.rs`, the same bound the SOCKS5 handshake
  uses. A **concurrency cap** shared with the SOCKS5 path is **not** implemented
  (each accepted connection is spawned unbounded).
- **Status-code mapping table — not done.** `rep` → HTTP status still lives in
  `http::write_reply` and `rep` → SOCKS5 reply in `socks5.rs`, each mapping the
  codes itself. Centralizing the two so they can't drift apart is still open.
- **Keep-alive forwarding — not done.** Each forwarded plain-HTTP request opens
  one tunnel and forces `Connection: close`; reusing one client↔proxy socket
  across multiple forwarded requests remains future work.
- **Docs — ✅ done.** `README.md` has an HTTP-proxy section with `https_proxy=`
  usage, and [`docs/proxy-usage.md`](proxy-usage.md) covers which listener each
  tool needs.

## Non-goals (for now)

- HTTP/2 or HTTP/3 proxy semantics (h2 `CONNECT`, prior-knowledge h2c). The
  listener speaks HTTP/1.1; HTTPS *content* tunnels opaquely through `CONNECT`.
- TLS interception / MITM. flextunnel never decrypts tunneled TLS.
- Caching, request rewriting beyond what forwarding requires.

## Affected files (summary)

| File | Change |
|---|---|
| `crates/flextunnel-core/src/proxy/http.rs` | **new** — HTTP listener + `CONNECT`/forward handlers |
| `crates/flextunnel-core/src/proxy/mod.rs` | export the new module |
| `crates/flextunnel-core/src/proxy/client.rs` | extract shared `dial`/pipe helper; bind + dispatch the HTTP listener in `run` |
| `crates/flextunnel-core/src/proxy/signaling.rs` | unchanged (reuse `Target`, `write_request`, `read_reply`, `REP_*`) |
| `crates/flextunnel-core/src/proxy/server.rs` | **unchanged** |
| `crates/flextunnel-cli/src/main.rs` | `--http-listen` flag, `ClientConfig.http_listen` |
| `README.md` | document HTTP proxy usage |
