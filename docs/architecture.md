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
| `auth.rs` | auth-token generation/validation/file-loading (CRC16-checksummed Base64URL tokens) |
| `secret.rs` | server secret-key (iroh identity) generation and loading; prints the `EndpointId` |
| `error.rs` | `ProxyError` (`Network`/`Config`/`Signaling`/`AuthenticationFailed`/`ConnectionLost`) + `is_recoverable()` |
| `transport/mod.rs` | QUIC transport config (keep-alive, idle timeout, initial MTU) |
| `transport/endpoint.rs` | iroh `Endpoint` creation (relay mode, DNS discovery), secret/relay helpers |
| `proxy/signaling.rs` | fixed `ALPN` constant, length-prefixed `Hello`/`HelloResponse`, per-stream `Target` codec, `REP_*` codes |
| `proxy/socks5.rs` | client-side RFC 1928: method negotiation + `CONNECT` parsing + replies |
| `proxy/client.rs` | connect + auth + SOCKS5 listener + reconnect loop |
| `proxy/server.rs` | accept + auth + per-stream DNS/connect/pipe |

## Connection lifecycle

### 1. ALPN
The ALPN value is the fixed constant `flextunnel/1` (`signaling::ALPN`). It is a
protocol identifier, not a secret: both peers must offer the same ALPN or the
QUIC/TLS handshake fails **before any stream opens**. Access control is enforced
by the auth handshake below, not by the ALPN.

### 2. Auth handshake (control stream)
On the first bi-stream the client sends `Hello { version, auth_token }` and the
server replies `HelloResponse { version, accepted, reject_reason }`, both
length-prefixed JSON via `signaling::write_message` / `read_message` (4-byte
big-endian length + payload, capped at `MAX_HANDSHAKE_SIZE` = 16 KiB). The server
checks the token against its accepted set (`auth::load_auth_tokens`). On rejection
it closes the connection gracefully (with a short drain) carrying the reason.
`Hello`'s `Debug` impl redacts `auth_token`.

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
| `RELAY_CONNECT_TIMEOUT` (`endpoint.online()`) | 10s | `transport/endpoint.rs` |
| `HANDSHAKE_TIMEOUT` | 10s | `proxy/client.rs`, `proxy/server.rs` |
| `CONNECT_TIMEOUT` (server dial) | 10s | `proxy/server.rs` |
| reconnect backoff | 1s → 60s + ≤500ms jitter | `proxy/client.rs` |
| `MAX_HANDSHAKE_SIZE` | 16 KiB | `proxy/signaling.rs` |
| auth token length | 47 chars | `auth.rs` |
| `ALPN` | `flextunnel/1` | `proxy/signaling.rs` |

## Relation to ezvpn

flextunnel reuses ezvpn's iroh transport, auth-token scheme, and
secret-key identity, but replaces the IP-over-QUIC-datagrams + TUN data path
(which needs root) with SOCKS5 over reliable QUIC streams (which doesn't). See
the project `README.md` for the user-facing comparison.

## Roadmap

HTTP proxy support is planned; the wire protocol and server are unaffected. See
[`http-proxy-roadmap.md`](./http-proxy-roadmap.md).
