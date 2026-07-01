# Architecture

flextunnel is a **SOCKS5-over-QUIC proxy**: a local SOCKS5 listener on the
**client** forwards each TCP `CONNECT` over a reliable QUIC bi-stream to the
**server**, which performs DNS resolution and the outbound connection *from its
own network*. Transport, NAT traversal, relay fallback, and TLS 1.3 encryption
come from [iroh](https://www.iroh.computer/). Neither side needs a TUN device or
admin/root — it is ordinary userspace sockets end to end.

## High-level flow

```
local app ──SOCKS5──► flextunnel client                        flextunnel server
                      (127.0.0.1:1080)                          (no root, no TUN)
                          │                                          │
                          │   one iroh QUIC Connection               │
                          │   (fixed ALPN + TLS 1.3)                 │
                          │                                          │
                          ├── control bi-stream ───────────────────►│  validate auth token
                          │      Hello / HelloResponse               │
                          │                                          │
   per CONNECT  ──────────┼── data bi-stream #1 ───────────────────►│  resolve DNS, TcpStream::connect
                          │      [request hdr][reply][raw bytes]     │      ───► target host:port
                          ├── data bi-stream #2 ───────────────────►│           (server's network)
                          └── data bi-stream #N ───────────────────►│
```

All streams from one client multiplex over a **single** QUIC `Connection`. The
control stream authenticates once; each subsequent bi-stream carries one proxied
TCP connection.

## Module map (`src/`)

| Module | Responsibility |
|---|---|
| `main.rs` | clap CLI, command dispatch, logger/runtime, graceful `endpoint.close()`, shutdown signal |
| `config.rs` | TOML config files (`-c`/`--default-config`), `deny_unknown_fields`, CLI>file>default merge, `~` expansion |
| `auth.rs` | auth-token generation/validation/file-loading (CRC16-checksummed Base64URL tokens); separate client (`ftc`) and agent (`fta`) prefixes |
| `blocklist.rs` | persisted duplicate-id blocklist (JSON): confirmed duplicate client ids, duplicate agent machine ids, + the server's own conflicted id |
| `secret.rs` | server secret-key (iroh identity) generation and loading; prints the `EndpointId` |
| `error.rs` | `ProxyError` (`Network`/`Config`/`Signaling`/`AuthenticationFailed`/`ConnectionLost`) + `is_recoverable()` |
| `transport/mod.rs` | QUIC transport config, ALPN, heartbeat/liveness timing |
| `transport/endpoint.rs` | iroh `Endpoint` creation (relay mode, DNS discovery), secret/relay helpers |
| `proxy/signaling.rs` | length-prefixed `Hello`/`HelloResponse`, control frames, per-stream `Target` codec, `REP_*` codes |
| `proxy/socks5.rs` | client-side RFC 1928: method negotiation + `CONNECT` parsing + replies |
| `proxy/client.rs` | connect + auth + SOCKS5 listener + reconnect loop |
| `proxy/server.rs` | accept + auth + per-stream DNS/connect/pipe; agent registry + reverse routing |
| `proxy/agent.rs` | reverse-routing exit point: dial + auth (`role=Agent`, machine id) + accept server-opened streams + dial loopback |
| `proxy/dial.rs` | `Target` → TCP dial + `connect_and_pipe` (the shared server/agent exit-point body) |

The reverse-routing agent ships as a **separate binary crate** (`flextunnel-agent`,
Linux/macOS/Windows, not in the module map above): it reads the OS-native machine
id (via the `machine-uid` crate — `/etc/machine-id`, `IOPlatformUUID`, or
`MachineGuid`), holds a single-instance file lock, and drives
`proxy::agent::ProxyAgent` over an ephemeral `create_client_endpoint`.

## Connection lifecycle

### 1. ALPN
The ALPN value is the fixed constant `flextunnel/1` (`transport::ALPN`). It is a
protocol-negotiation label sent **unencrypted** in the TLS/QUIC handshake, not a
secret: both peers must offer the same ALPN or negotiation fails. Access control
is enforced by the auth handshake below, not by the ALPN.

### 2. Auth handshake (control stream)
The protocol version is `PROTOCOL_VERSION = 4`. On the first bi-stream the
connecting peer sends
`Hello { version, auth_token, client_instance_nonce, duplicate_server_observed, role, machine_id }`
and the server replies
`HelloResponse { version, accepted, reject_reason, server_instance_nonce, routed_* }`,
both length-prefixed JSON via `signaling::write_message` / `read_message` (4-byte
big-endian length + payload, capped at `MAX_HANDSHAKE_SIZE` = 64 KiB). The server
checks the token against the role's accepted set (`ftc` client tokens or `fta`
agent tokens). Clients send `role = Client` with no machine id; agents send
`role = Agent` plus their stable machine id. On rejection it closes the
connection gracefully (with a short drain) carrying the reason. `Hello`'s
`Debug` impl redacts `auth_token`.

The `*_instance_nonce` fields are random per-process ids (distinct from the iroh
node id) that drive duplicate-id detection (see below); `duplicate_server_observed`
is a client advisory. Unlike earlier versions the handshake bi-stream is **not
closed** after the exchange — it stays open as the control stream carrying
heartbeats (§6).

The server bounds accepting/reading the client `Hello` with a 10s timeout, and
the client bounds waiting for the server `HelloResponse` with the same timeout
(`HANDSHAKE_TIMEOUT` in `client.rs` / `server.rs`), because QUIC keep-alive
otherwise prevents the idle timeout from firing on a peer that connects but
never speaks.

### 3. Per-CONNECT data streams
For each accepted SOCKS5 `CONNECT`, the client opens a new bi-stream and writes a
compact request header, then reads a one-byte reply, then pipes raw bytes:

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
The server reads the `Target`, then (bounded by `CONNECT_TIMEOUT` = 10s) either
`TcpStream::connect`s a literal address or, for a domain, calls
`tokio::net::lookup_host` and connects to the first address that accepts —
**DNS happens on the server**, which is what lets clients reach names/IPs that
only resolve or route from the server's network. Connect failures map to SOCKS5
reply codes via `signaling::map_io_err`.

### 5. Byte piping
Both ends join the iroh `(SendStream, RecvStream)` halves with
`tokio::io::join` and run `tokio::io::copy_bidirectional` against the `TcpStream`.
This propagates half-close correctly (EOF on one side → `shutdown`, which quinn
maps to a stream FIN). Per-stream errors stay per-stream — the shared QUIC
`Connection` is never closed for a single failed proxied connection.

### 6. Heartbeat & liveness (control stream)
After the handshake the control bi-stream stays open. The client sends a
`ControlMsg::Heartbeat { seq }` every `HEARTBEAT_INTERVAL` (10s) and the server
replies `HeartbeatAck { seq }`, framed with the same length-prefixed helpers
(capped at `MAX_CONTROL_MSG_SIZE`). This is an app-level liveness signal *on top
of* QUIC keep-alive: it lets each side notice a dead peer within
`LIVENESS_WINDOW` (33s: three heartbeat intervals plus 3s grace), with the 30s
QUIC idle timeout still acting as the backstop for a silent peer. On the server,
heartbeats also refresh the per-client connection registry used for duplicate
detection (below). A missing heartbeat surfaces as a recoverable
`ConnectionLost`, so the client's normal reconnect path applies. The heartbeat
runs concurrently with the SOCKS5 stream loop via `tokio::select!` on both sides.

## Duplicate-id detection

A guard rail against *accidental misconfiguration* (not an adversary defense —
see the security model). Both roles carry a random per-process **instance nonce**
that is distinct from the iroh node id, exchanged in the handshake.

**Duplicate client (server-side).** Client identity is ephemeral (a fresh key per
process), so two *different* client processes never share a node id; a node id
seen on two concurrently-live connections is a rare bug. The server keeps a
registry keyed by client node id, and within it by connection, refreshed by the
heartbeat. Two live connections for one node id with **different** instance nonces
are a confirmed duplicate (a benign same-process reconnect reuses the *same*
nonce and is ignored). On confirmation the server tears down the offending
connections and records the node id in the persisted blocklist (`blocklist.rs`);
a blocklisted node id is rejected up-front. Because ephemeral ids never recur,
the persisted client entry is largely an audit record.

**Duplicate agent (server-side).** An agent's iroh id is ephemeral and irrelevant
to its identity — it is identified by its stable, OS-native **machine id**
(`/etc/machine-id` on Linux, `IOPlatformUUID` on macOS, `MachineGuid` on Windows).
A single-instance file lock in the `flextunnel-agent` binary already guarantees one
agent *process* per machine, so the server needs no nonce/liveness machinery: it
tracks the one active connection per machine id, and a *second concurrent*
connection presenting the same id is necessarily a **different machine** (e.g. a
cloned VM image whose `/etc/machine-id` was never regenerated). On that collision
the server tears both down and records the machine id in the blocklist
(`blocked_agents`). Because a machine id is stable (unlike an ephemeral client id),
that block keeps rejecting the id until the operator fixes the duplicate and clears
the entry. A benign reconnect is not a collision: its prior connection is already
gone (the reconnect backoff outlasts QUIC dead-connection detection), so it
registers fresh.

**Duplicate server (self-block).** Server identity is persistent, so two servers
sharing one secret key is a plausible misconfiguration — but only observable when
both are reachable by the *same client over a shared discovery/relay path*
(same-id servers on isolated networks that no client can reach both of are not a
conflict). Each server emits a stable `server_instance_nonce`; a restart yields a
fresh nonce that never reappears, whereas a client bouncing between two concurrent
same-id servers sees a previously-seen nonce **reappear** after a different one.
On that reappearance the client latches an advisory (`duplicate_server_observed`)
into its next `Hello` — a non-privileged observation, not a command. The server,
on receiving it from any active client, records its **own** `EndpointId` in the
blocklist and shuts down; on the next start it refuses to run while its id is
listed. Detection is best-effort and delayed (it needs client churn to observe
both instances); prompt, robust detection would require a signaling server. See
[`duplicate-detection-roadmap.md`](./duplicate-detection-roadmap.md).

The blocklist is a JSON file (default `~/.config/flextunnel/blocklist.json`,
overridable via `blocklist_file`), written atomically (temp + rename) and loaded
at startup.

## Concurrency model

- **Server:** one tokio task per accepted iroh connection (`handle_connection`),
  and within it one task per accepted bi-stream (`handle_socks_stream`). No
  shared mutable state on the data path; the accepted-token set is read-only.
- **Client:** one task per accepted local TCP connection (`handle_local_conn`),
  all sharing the single `Connection` clone. The SOCKS5 listener and the QUIC
  connection liveness are raced with `tokio::select!` so a dropped connection
  breaks the accept loop into the reconnect path.

## Reconnect policy (client)

Implemented in `ProxyClient::run` / `handle_failure`:

- The **first** connection must succeed; if it fails (even a transient error),
  the client exits — a bad node id, wrong relay, or down server is not worth
  retrying blindly.
- After at least one success, transient drops (`ConnectionLost` / `Network` /
  `Signaling` — see `ProxyError::is_recoverable`) are retried with **exponential
  backoff + jitter** (1s → 60s), indefinitely, unless `--max-reconnect-attempts`
  caps it or `--no-auto-reconnect` disables it.
- Permanent errors (`AuthenticationFailed` / `Config`) never retry.
- The local SOCKS5 listener stays bound across reconnects, so local apps queue
  rather than get connection-refused during the gap.

On every exit path both `run_server` and `run_client` call
`endpoint.close().await` before the `Endpoint` drops; skipping it makes iroh tear
down its relay tasks ungracefully (a `JoinSet` panic that is fatal under the
release profile's `panic = "abort"`).

## Security model & trust boundaries

**Purpose & threat model.** flextunnel exists to let a set of **trusted clients**
reach resources on the **server's** side of the network — names and addresses that
only resolve or route from where the server sits. Both ends of the deployment are
operated by the same trusted party: whoever runs the server also decides which
clients get tokens. flextunnel is *not* a multi-tenant service and does not defend
the server against the clients it admits — a client with a valid token is, by
design, allowed to reach whatever the server's network can reach. The threats it
does address are **on-path attackers** (defeated by QUIC/TLS 1.3 encryption and
per-client tokens) and **accidental misconfiguration** — the duplicate-id
detection (see "Duplicate-id detection" above) catches, e.g., two clients or two
servers started with the same identity, blocking the conflicted id and refusing a
self-blocked server's restart. These are guard rails for operators, not adversary
defenses.

- **One shared secret:** a per-client auth token (checked in the handshake), a
  CRC16-checksummed Base64URL credential generated by the CLI. The QUIC ALPN
  (`flextunnel/1`) is a fixed protocol identifier, not a credential. All payload
  is encrypted by QUIC/TLS 1.3.
- **The server is the exit point.** Anyone with valid tokens can reach whatever
  the server's network can reach (including its `localhost`). Treat token
  distribution accordingly; scope server network access if needed.
- **The local SOCKS5 listener is unauthenticated** and binds to loopback by
  default — access control lives at the QUIC layer, not in SOCKS5. Binding it
  off-loopback exposes an open proxy on the LAN; don't, unless you add auth.
- iroh's relay/discovery operators can see connection *metadata* (which endpoints
  talk), never the encrypted payload.

## Reference constants

| Constant | Value | Where |
|---|---|---|
| `QUIC_KEEP_ALIVE_INTERVAL` | 15s | `transport/mod.rs` |
| `QUIC_IDLE_TIMEOUT` | 30s | `transport/mod.rs` |
| `QUIC_INITIAL_MTU` | 1452 | `transport/mod.rs` |
| `HEARTBEAT_INTERVAL` | 10s | `transport/mod.rs` |
| `LIVENESS_WINDOW` | 33s | `transport/mod.rs` |
| `RELAY_CONNECT_TIMEOUT` (`endpoint.online()`) | 10s | `transport/endpoint.rs` |
| `HANDSHAKE_TIMEOUT` | 10s | `proxy/client.rs`, `proxy/server.rs`, `proxy/agent.rs` |
| `CONNECT_TIMEOUT` (server/agent dial) | 10s | `proxy/dial.rs` |
| reconnect backoff | 1s → 60s + ≤500ms jitter | `proxy/client.rs` |
| `MAX_HANDSHAKE_SIZE` | 64 KiB | `proxy/signaling.rs` |
| `MAX_CONTROL_MSG_SIZE` | 1 KiB | `proxy/signaling.rs` |
| `PROTOCOL_VERSION` | 4 | `proxy/signaling.rs` |
| auth token length | 49 chars | `auth.rs` |
| `ALPN` | `flextunnel/1` | `transport/mod.rs` |

## Relation to ezvpn

flextunnel reuses ezvpn's iroh transport, auth-token scheme, and
secret-key identity, but replaces the IP-over-QUIC-datagrams + TUN data path
(which needs root) with SOCKS5 over reliable QUIC streams (which doesn't). See
the project `README.md` for the user-facing comparison.

## Roadmap

HTTP proxy support is planned; the wire protocol and server are unaffected. See
[`http-proxy-roadmap.md`](./http-proxy-roadmap.md).

Reverse routing is loopback-only in v1. A follow-up will let one agent (machine
id) expose several hostnames each mapped to a chosen host/IP on the agent's own
network (an `agent_ip` target, default `127.0.0.1`); the server already rewrites
the routed target before opening the agent stream, so this is a server-side
config + rewrite change with no agent-side protocol change.

Future work on duplicate-id detection — non-ephemeral client ids and their
pitfalls, the signaling-server path for prompt server-dup detection, and
client-side dup acknowledgement/flagging — is in
[`duplicate-detection-roadmap.md`](./duplicate-detection-roadmap.md).
