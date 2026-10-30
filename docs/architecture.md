# Architecture

flextunnel carries TCP connections over iroh QUIC streams. Optional client-side
SOCKS5/HTTP listeners split traffic using the server-pushed tunnel set: matching
targets go through the server, and off-list targets connect from the client.
Port forwards send every connection to a fixed server-side target, subject to
the server's routed set. Tunneled hostnames are resolved from the server's
network. Neither role needs a TUN device or admin/root.

## High-level flow

```
local app ──SOCKS5/HTTP──► flextunnel client                    flextunnel server
                      (optional SOCKS5/HTTP listeners)           (no root, no TUN)
                          │                                          │
                          │   one iroh QUIC Connection               │
                          │   (fixed ALPN + TLS 1.3)                 │
                          │                                          │
                          ├── control bi-stream ───────────────────►│  verify client keypair
                          │      Hello / HelloResponse               │
                          │                                          │
   per routed request ────┼── data bi-stream #1 ───────────────────►│  resolve DNS, TcpStream::connect
                          │      [request hdr][reply][raw bytes]     │      ───► target host:port
                          ├── data bi-stream #2 ───────────────────►│           (server's network)
                          └── data bi-stream #N ───────────────────►│
                          └── off-list targets: direct connect from client
```

All streams from one client multiplex over a **single** QUIC `Connection`. The
control stream authenticates once; each subsequent data bi-stream carries one
proxied TCP connection or accepted port-forward connection. Direct off-list
connections never touch the server.

## Module map

Core paths below are relative to `crates/flextunnel-core/src/`.

| Module | Responsibility |
| --- | --- |
| `app.rs`, `config.rs` | Runtime options, TOML parsing, CLI/file/default merging and validation |
| `server.rs` | Shared CLI/desktop server preparation, per-user lock, endpoint binding and serving |
| `auth.rs`, `secret.rs` | Flextunnel auth context and identity-key commands; shared key parsing and auth primitives come from `flexaccess-keys` and `flexaccess-iroh` |
| `blocklist.rs`, `error.rs` | Persisted duplicate-id records and recoverable/permanent errors |
| `transport/mod.rs` | Flextunnel ALPNs, QUIC tuning and heartbeat timing |
| `transport/endpoint.rs` | Endpoint allowlist hook and rebuildable `ClientEndpoint`, using the shared endpoint builder |
| `transport/paths.rs` | Direct/relay path snapshots and on-demand relay health checks |
| `proxy/signaling.rs` | Handshakes, control frames, target codec and reply codes |
| `proxy/client.rs` | Local proxy listeners, split routing, heartbeats and reconnect loop |
| `proxy/socks5.rs`, `proxy/http.rs` | Local proxy protocol parsing and replies |
| `proxy/routed_set.rs` | Domain/CIDR matching on client and server |
| `proxy/server.rs`, `proxy/dial.rs` | Connection handling, routed-set checks and outbound TCP connections |
| `proxy/reserved.rs`, `proxy/status_page.rs` | Built-in status and server-loopback names |
| `proxy/bridge.rs`, `proxy/dns_forward.rs` | Server-to-server bridges and conditional DNS resolution |
| `forwards.rs`, `proxy/forward.rs` | Forward definitions and server-direct loopback listeners |

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
The protocol version is `PROTOCOL_VERSION = 13`. On the first bi-stream a
client sends
`Hello { version, auth?, client_instance_nonce, duplicate_server_observed }`
where `auth` is `ClientAuthPayload { public_key, endpoint_id, signature }`
(a bridge sends the minimal `BridgeHello { version }` — its authentication
already happened at the TLS handshake) and the server replies
`HelloResponse { version, accepted, reject_reason, server_instance_nonce, routed_*, host_aliases, dns_forwards, bridges }`,
both length-prefixed JSON via `signaling::write_message` / `read_message` (4-byte
big-endian length + payload, capped at `MAX_HANDSHAKE_SIZE` = 64 KiB). On the
client ALPN `auth` is required: the server checks that the claimed
`endpoint_id` equals the connection's TLS-authenticated `remote_id()`, that the
ed25519 `signature` (over a domain-separated hash of that id) verifies under
`public_key`, and that `public_key` is on the server's authorized-keys file —
binding the credential to this connection so a captured `Hello` cannot be
replayed from another endpoint. On the quick ALPN `auth` is absent — the
allowlist hook already authenticated the endpoint id, and everything after the
handshake (routed set, duplicate detection, heartbeats, data streams) is
identical for both. On rejection the server closes the connection gracefully
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
For each on-list local request that needs the tunnel, the client opens a new
bi-stream and writes a compact request header, reads a two-byte reply header,
then pipes raw bytes:

```
Request (client→server):  [ver=1][atyp][addr][port:u16 BE]
    atyp 0x01 IPv4 → 4 bytes   0x03 DOMAIN → [len:u8][host]   0x04 IPv6 → 16 bytes
Reply   (server→client):  [ver=1][rep]      then raw bytes both ways
```

`rep` values are deliberately equal to RFC 1928 SOCKS5 reply codes
(`REP_SUCCESS=0x00`, `REP_HOST_UNREACHABLE=0x04`, …), so the client forwards the
server's reply byte straight into its SOCKS5 reply to the local app with no
translation table. The header is parsed with `read_exact` (ATYP fixes the
length; domains ≤ 255 bytes).

### 4. Server-side resolve + connect
The server reads the requested `Target`. The reserved `flextunnel.internal`
namespace is handled first, bypassing the routed-set whitelist, bridges and
host aliases: `flextunnel.internal` is the status page and
`localhost.flextunnel.internal` is dialed as the server's own `localhost`.
For other targets, the server checks the requested name/IP against its routed
set before selecting a bridge or applying a host alias. A matching bridge
receives the original target; otherwise the server applies any alias and dials
locally. Hostnames use a matching conditional DNS forward or the server's
system resolver, and the server tries the resolved addresses in turn until one
accepts. Loopback targets try both IPv4 and IPv6; other literal IPs are dialed
as given. DNS and TCP connection share a 10s timeout in
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
heartbeat or acknowledgement ends the connection; recoverable client failures
enter the reconnect loop.

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
On that reappearance the client latches an advisory (`duplicate_server_observed`)
into its next `Hello` — a non-privileged observation, not a command. The server,
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

The client runs its local listeners independently of the connection manager,
so they stay bound across reconnects. Each proxy listener allows 256 active
handlers, with at most 64 requests held for tunnel recovery. At capacity,
accepting pauses; excess recovery holds are refused. Each server-direct
forward has its own 128-connection cap.

## Reconnect policy (client)

`ProxyClient::handle_failure` retries `ConnectionLost`, `Network` and
`Signaling` errors, including a failed first connection. Delays double from 1s
to 60s plus up to 500ms jitter. The connect attempt can take another 30s and
the auth handshake another 10s; the 60s cap is a delay between attempts, not a
guarantee of one attempt per minute.

Retries continue indefinitely unless auto-reconnect is disabled or the retry
limit is reached. `Config`, `AuthenticationFailed` and `DuplicateServerId`
errors end the session. Status displays can read failed attempts, the last
error and the next attempt time through `reconnect_status`.

After three consecutive failures, the next attempt rebuilds `ClientEndpoint`.
Further rebuilds during that outage are at least 30 minutes apart. Other
retries call `Endpoint::network_change()`. Rebuilding replaces the endpoint
and generates a new ephemeral id for normal clients; quick mode keeps its
session id so it remains allowlisted. The old endpoint is closed gracefully,
with a bounded wait before leaving shutdown in the background. The rebuild
skips the startup relay probe, so it returns to the full configured relay set
(a client endpoint otherwise keeps probe-failed relays out for its lifetime),
and it tolerates the online-wait failing, so a partial outage never blocks
recovery. It is rate-limited because it repairs only the endpoint: a rebuilt
endpoint that still cannot connect has ruled that out. A successful connection
resets the rebuild schedule.

Embedders can report network availability and background state. No-path
reports park backoff retries until a path returns. A returning path or a
foreground transition resets the delay for an immediate attempt.

Once the routed set is known, off-list requests continue connecting directly
during an outage. On-list requests wait up to 45s for a tunnel, then receive a
network-unreachable reply. Before the first handshake, requests wait for the
initial route policy under the same hold limit; unclassified requests never
connect directly.

## Relay failover (server, custom relays)

`RunningServer::serve` in `crates/flextunnel-core/src/server.rs` runs
`ProxyServer::run` alongside `flexaccess-iroh`'s `fail_over_home_relay`. The CLI
and desktop use this same server lifecycle.

Relay configuration, startup probes, discovery, authentication tokens and
in-place home-relay failover belong to the shared crate. See
[iroh-common-architecture](https://github.com/flexaccessdev/iroh-common-architecture),
including its [relay-failover design](https://github.com/flexaccessdev/iroh-common-architecture/blob/main/relay-failover.md).
The client's endpoint rebuild described above is implemented in flextunnel.

Callers close endpoints with `endpoint.close().await` after serving stops,
including error and cancellation paths. Dropping an endpoint without closing it
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
- Every admitted client can reach the server's own loopback services through
  `localhost.flextunnel.internal`, whatever the routed set says. Authorize keys
  accordingly.
- Proxy listeners are unauthenticated and bind only to `127.0.0.1`;
  server-direct forwards bind `127.0.0.1` and `::1`. Local callers share the
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
| `CONNECT_TIMEOUT` (client server connect) | 30s | `proxy/client.rs` |
| `HANDSHAKE_TIMEOUT` | 10s | `proxy/client.rs`, `proxy/server.rs`, `proxy/bridge.rs` |
| `LOCAL_HANDSHAKE_TIMEOUT` | 10s | `proxy/client.rs` |
| `TUNNEL_OPEN_TIMEOUT` | 30s | `proxy/client.rs` |
| `CONNECT_TIMEOUT` (server dial) | 10s | `proxy/dial.rs` |
| `MAX_CONCURRENT_CONNECTIONS` | 1024 | `proxy/server.rs` |
| reconnect backoff | 1s → 60s + ≤500ms jitter | `proxy/client.rs` |
| `REBUILD_ENDPOINT_ATTEMPTS` / `REBUILD_ENDPOINT_MIN_INTERVAL` (client endpoint rebuild) | After 3 failures, then ≥30 min apart | `proxy/client.rs` |
| `MAX_ACTIVE_LOCAL_CONNS` / `MAX_HELD_CONNS` (per proxy listener) | 256 / 64 | `proxy/client.rs` |
| `TUNNEL_RECOVERY_HOLD` | 45s | `proxy/client.rs` |
| `MAX_HANDSHAKE_SIZE` | 64 KiB | `proxy/signaling.rs` |
| `MAX_CONTROL_MSG_SIZE` | 16 KiB | `proxy/signaling.rs` |
| `MAX_HTTP_HEADER` | 64 KiB | `proxy/http.rs` |
| `PROTOCOL_VERSION` | 13 | `proxy/signaling.rs` |
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
