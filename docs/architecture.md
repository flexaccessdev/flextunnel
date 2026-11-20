# Architecture

flextunnel carries TCP connections over iroh QUIC streams. A client names its
servers as *destinations* and routes each request by its own static table: a
target a destination routes goes through that destination's server, and
anything else connects from the client. Port forwards and `client nc` always go
through a destination. Tunneled hostnames are resolved from the server's
network. Neither role needs a TUN device or admin/root.

The connection to a server is made on demand — on the first request for its
destination — and closed when it has gone unused.

## High-level flow

```
local app ──SOCKS5/HTTP──► flextunnel client                    flextunnel server
                      (optional SOCKS5/HTTP listeners)           (no root, no TUN)
                          │  route table: target → destination       │
                          │                                          │
                          │   per destination, opened on first use:  │
                          │   one iroh QUIC Connection               │
                          │   (fixed ALPN + TLS 1.3)                 │
                          │                                          │
                          ├── control bi-stream ───────────────────►│  verify client keypair
                          │      Hello / HelloResponse, heartbeats   │
                          │                                          │
   per routed request ────┼── data bi-stream #1 ───────────────────►│  resolve DNS, TcpStream::connect
                          │      [request hdr][reply][raw bytes]     │      ───► target host:port
                          ├── data bi-stream #2 ───────────────────►│           (server's network)
                          └── data bi-stream #N ───────────────────►│
                          └── unrouted targets: direct connect from client
```

All streams to one server multiplex over a **single** QUIC `Connection`; a
client holds one such connection per destination in use, each on its own
endpoint. The control stream authenticates once; each subsequent data bi-stream
carries one proxied TCP connection or accepted port-forward connection. Direct
connections never touch a server.

## Module map

Core paths below are relative to `crates/flextunnel-core/src/`.

| Module | Responsibility |
| --- | --- |
| `app.rs`, `config.rs` | Runtime options, TOML parsing, CLI/file/default merging and validation |
| `server.rs` | Shared CLI/desktop server preparation, per-identity lock, endpoint binding and serving |
| `auth.rs`, `secret.rs` | Flextunnel auth context and identity-key commands; shared key parsing and auth primitives come from `flexaccess-keys` and `flexaccess-iroh` |
| `blocklist.rs`, `error.rs` | Persisted duplicate-id records and recoverable/permanent errors |
| `transport/mod.rs` | Flextunnel ALPNs, QUIC tuning and heartbeat timing |
| `transport/endpoint.rs` | Endpoint allowlist hook and rebuildable `ClientEndpoint`, using the shared endpoint builder |
| `transport/paths.rs` | Direct/relay path snapshots and on-demand relay health checks |
| `proxy/signaling.rs` | Handshakes, control frames, stream-request codec and reply codes |
| `proxy/client.rs` | Local proxy listeners, request routing, the `TunnelDialer` for forwards and `nc`, heartbeats |
| `proxy/route_table.rs` | The client's routing table: target → destination, with load-time validation |
| `proxy/destination.rs` | One destination: its endpoint, lazy connection, idle close and retry policy |
| `proxy/client_status.rs` | The client's `flextunnel.internal` status endpoint and its per-server proxy |
| `proxy/socks5.rs`, `proxy/http.rs` | Local proxy protocol parsing and replies |
| `proxy/routed_set.rs` | Domain/CIDR matching on client and server |
| `proxy/server.rs`, `proxy/dial.rs` | Connection handling, routed-set checks and outbound TCP connections |
| `proxy/reserved.rs`, `proxy/status_page.rs` | The reserved `flextunnel.internal` namespace; the server status page and shared HTTP plumbing |
| `proxy/bridge.rs`, `proxy/dns_forward.rs` | Server-to-server bridges and conditional DNS resolution |
| `forwards.rs`, `proxy/forward.rs` | Forward definitions and loopback forward listeners |

`crates/flextunnel-cli/src/` holds command dispatch, client supervision, IPC and
the read-only terminal panel. `flextunnel-desktop` embeds core directly;
`flextunnel-ffi` exposes it to the iOS app.

Bridges forward matching targets from server A to server B over a persistent
`BRIDGE_ALPN` connection. B must allow A's persistent endpoint id in
`allowed_bridge_servers`; B then checks its own routed set, applies its
aliases/DNS forwards and connects from its network. Incoming bridge streams are
never bridged again, so forwarding is single-hop. Startup validation requires
A's routed set to cover its bridge rules.

## Connection lifecycle

### 1. ALPN
Clients connect with the fixed constant `flextunnel/1` (`transport::ALPN`);
bridging servers connect with `flextunnel-bridge/1` (`transport::BRIDGE_ALPN`);
quick-mode clients connect with `flextunnel-quick/1` (`transport::QUICK_ALPN`).
The ALPN is a protocol-negotiation label sent **unencrypted** in the TLS/QUIC
handshake, not a secret: it carries the peer's *role*, never a credential.
Keypair-client access control is the auth handshake below; bridge and quick-client
access control is an endpoint-id allowlist (`allowed_bridge_servers`, or the
single client id entered on a quick server), enforced **natively at the TLS
handshake** by an iroh `EndpointHooks::after_handshake` hook
(`transport::endpoint::AllowlistHook` over `EndpointAllowlists`) — a
non-allowlisted peer's connection is closed with the reason before it ever
reaches the accept loop, and the id needs no further proof because iroh's
handshake authenticates it. An empty set disables its ALPN entirely (a normal
server rejects every quick dial; a no-bridging server rejects every bridge).

### 2. Auth handshake (control stream)
The protocol version is `PROTOCOL_VERSION = 14`. On the first bi-stream a
client sends
`Hello { version, auth?, client_instance_nonce, duplicate_server_observed }`
where `auth` is `ClientAuthPayload { public_key, endpoint_id, signature }`
(a bridge sends the minimal `BridgeHello { version }` — its authentication
already happened at the TLS handshake) and the server replies
`HelloResponse { version, accepted, reject_reason, server_instance_nonce }`,
both length-prefixed JSON via `signaling::write_message` / `read_message` (4-byte
big-endian length + payload, capped at `MAX_HANDSHAKE_SIZE` = 64 KiB). On the
client ALPN `auth` is required: the server checks that the claimed
`endpoint_id` equals the connection's TLS-authenticated `remote_id()`, that the
ed25519 `signature` (over a domain-separated hash of that id) verifies under
`public_key`, and that `public_key` is on the server's authorized-keys file —
binding the credential to this connection so a captured `Hello` cannot be
replayed from another endpoint. The signature does not name the server, and
needs not to: a client uses a different endpoint, hence a different id, for
each destination. On the quick ALPN `auth` is absent — the allowlist hook
already authenticated the endpoint id, and everything after the handshake
(duplicate detection, heartbeats, data streams) is identical for both. The
response carries no routing: each side configures its own (see
[Routing](#routing-client)). On rejection the server closes the connection gracefully
(with a short drain) carrying the reason. Nothing in the payload is secret, so
`Hello` derives `Debug` plainly.

The `*_instance_nonce` fields are random per-process ids (distinct from the iroh
node id) that drive duplicate-id detection (see below); `duplicate_server_observed`
is a client advisory. The handshake bi-stream stays open after the exchange to
carry heartbeats (§6).

The server bounds accepting/reading the client `Hello` with a 10s timeout, and
the client bounds waiting for the server `HelloResponse` with the same timeout
(`HANDSHAKE_TIMEOUT` in `client.rs` / `server.rs`), so a peer that connects but
never speaks is dropped promptly instead of holding a task until the 180s QUIC
idle timeout (heartbeats only start after the handshake).

### 3. Per-request data streams
For each local request routed to a destination, the client opens a new
bi-stream on that destination's connection and writes a compact request header,
reads a two-byte reply header, then pipes raw bytes:

```
Request (client→server):  [ver=1][kind]…
    connect   0x01 IPv4 → 4 bytes + [port:u16 BE]
              0x03 DOMAIN → [len:u8][host] + [port:u16 BE]
              0x04 IPv6 → 16 bytes + [port:u16 BE]
    loopback  0x10 → [port:u16 BE]     the server's own loopback
    status    0x11                     the server's status page
Reply   (server→client):  [ver=1][rep]      then raw bytes both ways
```

The connect kinds reuse the SOCKS5 address types; `signaling::StreamRequest`
is the enum behind all three. `rep` values are deliberately equal to RFC 1928
SOCKS5 reply codes (`REP_SUCCESS=0x00`, `REP_HOST_UNREACHABLE=0x04`, …), so the
client forwards the server's reply byte straight into its SOCKS5 reply to the
local app with no translation table. The header is parsed with `read_exact`
(the kind fixes the length; domains ≤ 255 bytes).

### 4. Server-side resolve + connect
The server reads the `StreamRequest`. Two kinds are served outside the
routed-set whitelist, bridges and host aliases: **loopback** is dialed as the
server's own `localhost` on the requested port, and **status** answers the HTTP
request that follows with the server status page. Both are refused on a stream
that arrived over a bridge — a bridging server forwards its clients' routed
targets, nothing else.

A **connect** request is checked against the routed set before selecting a
bridge or applying a host alias; a name in the reserved `flextunnel.internal`
namespace is refused before that check, so no `routed_domains = ["*"]` can
capture it (the client answers that namespace itself and never sends it). A
matching bridge receives the original target; otherwise the server applies any
alias and dials locally. Hostnames use a matching conditional DNS forward or
the server's system resolver, and the server tries the resolved addresses in
turn until one accepts. Loopback targets try both IPv4 and IPv6; other literal
IPs are dialed as given. DNS and TCP connection share a 10s timeout in
`proxy/dial.rs`. Connect failures map to SOCKS5 reply codes through
`signaling::map_io_err`.

### 5. Byte piping
Both ends join the iroh `(SendStream, RecvStream)` halves with
`tokio::io::join` and run `tokio::io::copy_bidirectional` against the `TcpStream`.
This propagates half-close correctly (EOF on one side → `shutdown`, which quinn
maps to a stream FIN). Per-stream errors stay per-stream — the shared QUIC
`Connection` is never closed for a single failed proxied connection.

### 6. Heartbeat & liveness (control stream)

The client sends `ControlMsg::Heartbeat { seq }`; the server replies with
`HeartbeatAck { seq }`. Frames use the length-prefixed control codec with a
16 KiB cap. There is no QUIC transport keep-alive configured.

Client heartbeats run every 10s in the foreground and every 60s when an
embedding app reports background mode. The client's acknowledgement timeout is
three intervals plus 3s: 33s or 183s respectively. The server always allows
183s between heartbeats because it does not know the client's current cadence.
The QUIC idle timeout is 180s and can close a silent connection sooner.

Heartbeats refresh the server's duplicate-detection registry. A missing
heartbeat or acknowledgement ends the connection; the client then follows its
[connection policy](#connection-policy-client). Heartbeats run only while a
connection is up, so an idle destination sends nothing at all.

## Duplicate-id detection

A guard rail against *accidental misconfiguration* (not an adversary defense —
see the security model). Both roles carry a random per-process **instance nonce**
that is distinct from the iroh node id, exchanged in the handshake.

**Duplicate client (server-side).** Client identity is ephemeral, so independent
processes normally have different node ids. The server keeps a
registry keyed by client node id, and within it by connection, refreshed by the
heartbeat. Two live connections for one node id with **different** instance nonces
are a confirmed duplicate (a benign same-process reconnect reuses the *same*
nonce and is ignored). On confirmation the server tears down the offending
connections and records the node id in the persisted blocklist (`blocklist.rs`);
a blocklisted node id is rejected up-front. Because ephemeral ids never recur,
the persisted client entry is largely an audit record.

**Duplicate server (self-block).** Server identity is persistent, so two servers
sharing one secret key is a plausible misconfiguration. This detector needs
both to be reachable by the same client; it cannot observe two instances on
isolated networks. Each server emits a stable `server_instance_nonce`; a restart yields a
fresh nonce that never reappears, whereas a client bouncing between two concurrent
same-id servers sees a previously-seen nonce **reappear** after a different one.
The client keeps this nonce history per destination, for the life of the
process (idle periods included). On that reappearance it latches an advisory
(`duplicate_server_observed`) into its next `Hello` to that server — a
non-privileged observation, not a command. The server,
on receiving it from any active client, records its **own** `EndpointId` in the
blocklist and shuts down; on the next start it refuses to run while its id is
listed. Detection is best-effort and delayed (it needs client churn to observe
both instances); prompt, robust detection would require a signaling server. See
[`duplicate-detection-roadmap.md`](./duplicate-detection-roadmap.md).

The blocklist is a JSON file at the fixed path
`~/.config/flextunnel/blocklist.json`. It is deliberately not configurable:
relocating this guard rail would let it be bypassed. It is written atomically
(temp + rename) and loaded at startup.

## Concurrency model

The server accepts up to 1024 concurrent QUIC connections and spawns a task
per data stream. Authorized keys are loaded at startup.

The client runs its local listeners independently of its destinations, so they
stay bound whatever any connection is doing. Each destination is managed by its
own future inside `ProxyClient::run`. Each proxy listener allows 256 active
handlers, with at most 64 requests held while a destination connects — up to
8 of them set aside for each destination, the rest shared, so retries toward a
server that is down cannot use up the holds an idle destination needs for its
first request. At
capacity, accepting pauses; excess holds are refused (the destination is still
asked to connect). Each forward has its own 128-connection cap, within which
its connections are held the same way.

## Routing (client)

`proxy/route_table.rs` holds the client's static table, built and validated
once in `ProxyClient::new` from the configured destinations. `RouteTable::route`
maps a target to one of:

1. the client's own status endpoint (`flextunnel.internal`), or a 404 for
   another `*.flextunnel.internal` name;
2. a destination's loopback, for the destination's own `host` (sent as a
   loopback stream request);
3. a destination, for the most specific routed-set match across all of them —
   exact domain, then the longest `*.suffix`, then `*`; longest prefix for IPs
   (`RoutedSet::specificity`);
4. direct.

Validation rejects what precedence cannot resolve: a duplicate host, the same
rule on two destinations, a destination's host listed as a routed domain, a
rule in the reserved namespace, and a host that is an IP literal, `localhost`
or reserved. `ProxyClient::new` additionally rejects two destinations for one
server.

The proxy listeners act on all four outcomes. The `TunnelDialer` used by port
forwards and `nc` accepts only the tunnel outcomes: an unrouted target is an
error there, never a direct connection.

## Connection policy (client)

`proxy/destination.rs` gives each destination a small state machine, driven by
`Destination::run`:

```
           a request arrives                  authenticated
  Idle ───────────────────────▶ Dialing ───────────────────────▶ Connected
   ▲                              │  ▲                              │
   │ nobody is waiting            │  │ retry time reached,          │ dropped
   │                              ▼  │ someone still waiting        │
   ├────────────────────────── Backoff ◀────────────────────────────┤
   │                                                                │
   └──────── no stream open for the idle timeout ───────────────────┘
```

**Demand.** A request calls `Destination::acquire`, which registers it as a
waiter and holds it for up to 45s (`TUNNEL_RECOVERY_HOLD`) until the connection
is published; the request then keeps a lease for as long as its stream is open.
The link, the waiter count and the stream count live in one `watch` value, so
leasing the connection and the idle check closing it cannot interleave. A
waiter is what makes the destination dial; `kick` asks for one attempt with
nobody waiting (used when a request could not be held, and by embedders that
want an attempt up front).

**Endpoint.** A destination's endpoint exists only while the destination is in
use: built on the first dial with the shared `create_client_endpoint` (relay
probe, bind, online wait), closed when the destination goes idle. It is built
in a detached task so that tearing the client down mid-build never drops a
bound endpoint; `ProxyClient::close` waits for a build in flight and then
closes what it produced. Normal clients get a new ephemeral id each time; quick
mode binds its session secret so it remains allowlisted.

**Failures.** `ConnectionLost`, `Network` and `Signaling` errors — including a
failed first attempt and an endpoint that could not be built — are recoverable:
the destination backs off (1s doubling to 60s plus up to 500ms jitter) and
tries again **if a request is still waiting**. The connect attempt can take
another 30s and the auth handshake another 10s; the 60s cap is a delay between
attempts, not a guarantee of one attempt per minute. With nobody waiting the
destination goes idle and the next request redials, after whatever remains of
the backoff — the outage's attempt count and retry time survive idle periods,
so a down server is probed at most once per step however requests arrive.
`AuthenticationFailed` is permanent for the moment: the link becomes `Failed`
and requests fail at once until the retry time, instead of each waiting out a
doomed dial. No destination error ends `ProxyClient::run`.

**Rebuild.** While an endpoint is kept across attempts (requests keep waiting),
the third consecutive failure rebuilds it through `ClientEndpoint::rebuild`.
Further rebuilds during that outage are at least 30 minutes apart; other
retries call `Endpoint::network_change()`. The old endpoint is closed
gracefully, with a bounded wait before leaving shutdown in the background. The
rebuild skips the relay probe, so it returns to the full configured relay set,
and it tolerates the online-wait failing, so a partial outage never blocks
recovery. It is rate-limited because it repairs only the endpoint: a rebuilt
endpoint that still cannot connect has ruled that out. A successful connection
resets the rebuild schedule. This is why endpoints are per destination: a
rebuild for one unreachable server must not sever the connections to the
others, and relay settings are endpoint-wide.

**Idle.** A connection with no waiter and no lease for the client's idle
timeout is closed, and the endpoint with it. With no idle timeout it stays
until it drops. A destination marked `keep_connected` (quick mode) is always
wanted: it dials at start, is never idle, and retries for as long as the client
runs.

Embedders can report network availability and background state. No-path
reports park every destination's attempts until a path returns. A returning
path or a foreground transition resets the delay for an immediate attempt.

Status displays read each destination's state, uptime, open streams, waiting
requests, failed attempts, last error and next attempt time through
`ProxyClient::status`, which never causes a connection.

## Relay failover (server, custom relays)

`RunningServer::serve` in `crates/flextunnel-core/src/server.rs` runs
`ProxyServer::run` alongside `flexaccess-iroh`'s `fail_over_home_relay`. The CLI
and desktop use this same server lifecycle.

Relay configuration, startup probes, discovery, authentication tokens and
in-place home-relay failover belong to the shared crate. See
[flexaccess-iroh docs](https://github.com/flexaccessdev/flexaccess-iroh/tree/main/docs),
including its [relay-failover design](https://github.com/flexaccessdev/flexaccess-iroh/blob/main/docs/relay-failover.md).
The client's endpoint rebuild described above is implemented in flextunnel.

Callers close endpoints after serving stops, including error and cancellation
paths: a server with `endpoint.close().await`, a client with
`ProxyClient::close().await`, which closes the endpoint of every destination in
use. Dropping an endpoint without closing it
tears down iroh's relay tasks ungracefully, a `JoinSet` panic that aborts the
process under the release profile's `panic = "abort"`.

## Security model & trust boundaries

Servers and admitted clients are trusted. Flextunnel provides encrypted access
to the server's network; it is not a multi-tenant isolation layer. Routed-set
checks enforce the configured routing policy, while duplicate-id detection
catches accidental identity reuse.

- Normal clients authenticate with an Ed25519 signature bound to their
  TLS-authenticated endpoint id under flextunnel's auth context. Key encoding
  and files use [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys).
- Bridges and quick-mode clients authenticate through endpoint-id allowlists.
  ALPN labels select the protocol role and carry no credential.
- Every admitted client can reach the server's own loopback services (a
  loopback stream request, which a client sends for a destination's own host)
  and its status page, whatever the routed set says. Authorize keys
  accordingly.
- A server only ever sees the targets a client chose to send it. The client's
  routes are local configuration; the server's routed set is its own
  whitelist. Neither is transmitted.
- Proxy listeners are unauthenticated and bind only to `127.0.0.1`;
  forwards bind `127.0.0.1` and `::1`. Local callers share the
  authenticated client's access.
- QUIC/TLS encrypts payloads end to end. Relay/discovery services can observe
  connection metadata.

## Reference constants

| Constant | Value | Where |
|---|---|---|
| `QUIC_IDLE_TIMEOUT` | 180s | `transport/mod.rs` |
| `QUIC_INITIAL_MTU` | 1452 | `transport/mod.rs` |
| `HEARTBEAT_INTERVAL` / `HEARTBEAT_INTERVAL_IDLE` | 10s / 60s | `transport/mod.rs` |
| `liveness_window(interval)` / server `LIVENESS_WINDOW` | 3 × interval + 3s / 183s | `transport/mod.rs` |
| `REBUILD_CLOSE_TIMEOUT` (client endpoint rebuild, old endpoint close) | 5s | `transport/endpoint.rs` |
| `IDLE_CLOSE_TIMEOUT` (idle destination, endpoint close) | 5s | `proxy/destination.rs` |
| `DEFAULT_IDLE_TIMEOUT` (unused connection kept) | 300s | `config.rs` |
| `CONNECT_TIMEOUT` (client server connect) | 30s | `proxy/client.rs` |
| `HANDSHAKE_TIMEOUT` | 10s | `proxy/client.rs`, `proxy/server.rs`, `proxy/bridge.rs` |
| `REQUEST_READ_TIMEOUT` / `REQUEST_HEAD_LIMIT` (status requests) | 5s / 64 KiB | `proxy/status_page.rs` |
| `LOCAL_HANDSHAKE_TIMEOUT` | 10s | `proxy/client.rs` |
| `TUNNEL_OPEN_TIMEOUT` | 30s | `proxy/client.rs` |
| `CONNECT_TIMEOUT` (server dial) | 10s | `proxy/dial.rs` |
| `MAX_CONCURRENT_CONNECTIONS` | 1024 | `proxy/server.rs` |
| retry backoff | 1s → 60s + ≤500ms jitter | `proxy/client.rs` |
| `REBUILD_ENDPOINT_ATTEMPTS` / `REBUILD_ENDPOINT_MIN_INTERVAL` (client endpoint rebuild) | After 3 failures, then ≥30 min apart | `proxy/client.rs` |
| `MAX_ACTIVE_LOCAL_CONNS` / `MAX_HELD_CONNS` (per proxy listener) | 256 / 64 | `proxy/client.rs` |
| `TUNNEL_RECOVERY_HOLD` | 45s | `proxy/client.rs` |
| `MAX_HANDSHAKE_SIZE` | 64 KiB | `proxy/signaling.rs` |
| `MAX_CONTROL_MSG_SIZE` | 16 KiB | `proxy/signaling.rs` |
| `MAX_HTTP_HEADER` | 64 KiB | `proxy/http.rs` |
| `PROTOCOL_VERSION` | 14 | `proxy/signaling.rs` |
| client key encoding | ed25519, base64url (32-byte keys, 64-byte sigs) | flexaccess-keys, flexaccess-iroh `auth` |
| `ALPN` | `flextunnel/1` | `transport/mod.rs` |
| `BRIDGE_ALPN` | `flextunnel-bridge/1` | `transport/mod.rs` |
| `QUICK_ALPN` | `flextunnel-quick/1` | `transport/mod.rs` |

## Relation to ezvpn

flextunnel reuses ezvpn's iroh transport and
secret-key identity, but replaces the IP-over-QUIC-datagrams + TUN data path
(which needs root) with SOCKS5/HTTP proxy front-ends over reliable QUIC streams
(which don't). See the project `README.md` for the user-facing comparison.

## Roadmap

HTTP proxy support is implemented on the client side; the wire protocol and
server remain front-end-agnostic. See
[`http-proxy-roadmap.md`](./http-proxy-roadmap.md).

Future work on duplicate-id detection — non-ephemeral client ids and their
pitfalls, the signaling-server path for prompt server-dup detection, and
client-side dup acknowledgement/flagging — is in
[`duplicate-detection-roadmap.md`](./duplicate-detection-roadmap.md).
