# Roadmap: HTTP proxy support

Status: **Phase 1 implemented** (HTTP `CONNECT` tunneling). Phases 2–3 remain
proposed. The client exposes a **SOCKS5** listener
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

An HTTP proxy only helps clients that speak HTTP (CONNECT or, in Phase 2,
absolute-URI). **Raw-TCP apps — databases via JDBC/native clients, RDP, SSH —
do not speak HTTP CONNECT**, so they still need SOCKS5 (with the client-DNS
caveat) or a `socat` port forward. See
[`docs/socks5-usage.md`](socks5-usage.md) for those recipes. HTTP proxy
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

## Phase 2 — Absolute-URI plain HTTP forwarding

Goal: handle `GET http://host/path HTTP/1.1` (and other methods) so plain-HTTP
clients work without TLS.

- Parse the absolute-form request target; derive `Target::Domain(host, 80)` (or
  the URI's explicit port).
- Rewrite the request line to origin-form and ensure a correct `Host` header;
  strip hop-by-hop headers (`Proxy-Connection`, `Connection`, `Keep-Alive`,
  `Proxy-Authorization`, etc.) per RFC 7230 §6.1.
- Stream the request body (honor `Content-Length` / `Transfer-Encoding: chunked`)
  to the tunnel, then relay the response.
- **Decision needed:** adopt a vetted HTTP/1.x parser (e.g. `httparse`) rather
  than hand-rolling header/chunk parsing. Add it as a dependency gated to this
  feature. (Phase 1 needs only request-line + headers, which is small enough to
  hand-parse; Phase 2's body framing is where a real parser earns its keep.)
- Connection reuse / keep-alive across requests on one client↔proxy socket is a
  sub-goal; the simplest correct first cut is one tunnel bi-stream per request
  with `Connection: close`.

## Phase 3 — Hardening & polish

- **Proxy authentication:** out of scope. Both listeners are expected to bind
  loopback only (the SOCKS5 default is deliberately no-auth for the same
  reason), so there's no untrusted network to authenticate against.
- **Status-code mapping table:** centralize `rep` → HTTP status and
  `rep` → SOCKS5 reply so both front-ends stay consistent.
- **Limits:** max header size, request timeout, and a concurrency cap shared with
  the SOCKS5 path.
- **Docs:** add an HTTP-proxy section to `README.md` with `https_proxy=` usage.

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
