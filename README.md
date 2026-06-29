# flextunnel

A SOCKS5-over-QUIC proxy. The **client** runs a local SOCKS5 listener; each
`CONNECT` is tunneled as a reliable QUIC bi-stream to the **server**, which
performs **DNS resolution and the outbound TCP connection from its own
network**, then pipes bytes back.

This lets you reach hosts that are only reachable from the server side — a
private network, the server's own `localhost`, or names that only resolve via
the server's DNS — without a VPN. Because it uses ordinary userspace sockets
(no TUN device), **neither the client nor the server needs admin/root**.

Transport, NAT traversal, relay fallback, and TLS 1.3 encryption are provided by
[iroh](https://www.iroh.computer/): the client dials the server by its
`EndpointId`, so the server needs no public inbound port or port forwarding.

```
local app ──SOCKS5──► flextunnel client (127.0.0.1:1080)
                          │  one iroh QUIC connection (fixed ALPN + auth handshake)
                          │  ├─ control stream:  Hello / HelloResponse
                          │  └─ N data streams:  [target header][reply][raw bytes]
                          ▼
                      flextunnel server  (no root, no TUN)
                          │  per stream: resolve DNS ─► TcpStream::connect
                          ▼
                      target host:port  (reachable from the SERVER's network)
```

## Scope

- **TCP `CONNECT` only.** No UDP `ASSOCIATE`, no `BIND`.
- The local SOCKS5 listener is **no-auth** and binds to loopback by default;
  access control is enforced by the QUIC layer (auth token), not by SOCKS5.

## Security model

A per-client auth token gates every connection:

- **Auth token** — sent in the connection handshake and checked against the
  server's accepted set. Per-client, like an API key.

The QUIC ALPN is a fixed protocol identifier (`flextunnel/1`), not a secret: it
ensures both peers speak the flextunnel protocol but provides no access control
on its own.

All payload is end-to-end encrypted by QUIC/TLS 1.3.

## Install

Prebuilt binaries (Linux amd64/arm64, macOS arm64, Windows amd64) are published
on the [GitHub Releases](https://github.com/andrewtheguy/flextunnel/releases)
page. The install scripts download the latest release, verify its SHA-256
checksum, and install to a per-user location (`~/.local/bin` on Linux/macOS,
`%LOCALAPPDATA%\Programs\flextunnel` on Windows) — **no admin required**.

**Linux / macOS:**

```sh
curl -sSL https://andrewtheguy.github.io/flextunnel/install.sh | bash
```

**Windows (PowerShell):**

```powershell
irm https://andrewtheguy.github.io/flextunnel/install.ps1 | iex
```

Options: append `-s -- --prerelease` (bash) / `-PreRelease` (pwsh) for the
latest prerelease, a release tag to pin a version, or `--download-only` /
`-DownloadOnly` to fetch the binary without installing. A container image is
also published to `ghcr.io/andrewtheguy/flextunnel`.

## Build from source

```sh
cargo build --release
# binary: target/release/flextunnel
```

Requires a recent Rust toolchain (edition 2024). To cross-build static Linux
binaries for amd64 + arm64 via Docker, use `./build-linux.sh`.

## Quick start

### 1. Generate credentials (once)

```sh
flextunnel generate-server-key -o server.key   # prints the server's EndpointId
flextunnel show-server-id --secret-file server.key   # re-print the EndpointId
flextunnel generate-auth-token                  # a client auth token
```

Keep `server.key` private (written `0600` on Unix). Share the **EndpointId**
and the **auth token** with clients.

### 2. Run the server (no root needed)

```sh
flextunnel server start \
    --secret-file server.key \
    --auth-token  <AUTH_TOKEN>
```

It prints `flextunnel server Node ID: <ENDPOINT_ID>` — give that to clients.

### 3. Run the client (no root needed)

```sh
flextunnel client start \
    --server-node-id <ENDPOINT_ID> \
    --auth-token     <AUTH_TOKEN> \
    --socks-listen   127.0.0.1:1080
```

### 4. Use it

Point any SOCKS5 client at `127.0.0.1:1080`. Use `socks5h://` so the **server**
resolves DNS (the whole point — names resolve from the server's network):

```sh
# DNS + external, resolved server-side
curl -x socks5h://127.0.0.1:1080 https://example.com

# a service on the SERVER's own localhost
curl -x socks5h://127.0.0.1:1080 http://127.0.0.1:8000/

# SSH through the proxy
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@internal-host
```

## Commands

| Command | Description |
|---|---|
| `server start` | Run the proxy server. |
| `client start` | Run the proxy client (local SOCKS5 listener). |
| `generate-server-key -o <FILE> [--force]` | Generate the server identity key. |
| `show-server-id --secret-file <FILE>` | Print the EndpointId for a key. |
| `generate-auth-token [-c N]` | Generate N auth tokens. |

### `server start`

| Flag | Description |
|---|---|
| `-c, --config <FILE>` | Load options from a TOML file (CLI flags override it). |
| `--default-config` | Load `~/.config/flextunnel/server.toml`. |
| `--secret-file <FILE>` | Server identity key. |
| `--auth-token <TOKEN>` | Accepted client token (repeatable). |
| `--auth-tokens-file <FILE>` | File of accepted tokens, one per line. |
| `--relay-url <URL>` | Custom relay URL(s) for failover (repeatable). |
| `--dns-server <URL>` | Custom discovery DNS server, or `none` to disable. |

### `client start`

| Flag | Description |
|---|---|
| `-c, --config <FILE>` | Load options from a TOML file (CLI flags override it). |
| `--default-config` | Load `~/.config/flextunnel/client.toml`. |
| `-n, --server-node-id <ID>` | Server EndpointId. |
| `--socks-listen <ADDR>` | Local SOCKS5 bind address (default `127.0.0.1:1080`). |
| `--auth-token <TOKEN>` / `--auth-token-file <FILE>` | Client auth token (one required). |
| `--relay-url <URL>` | Custom relay URL(s) for failover (repeatable). |
| `--dns-server <URL>` | Custom discovery DNS server, or `none` to disable. |
| `--auto-reconnect` | Force auto-reconnect on (overrides `auto_reconnect = false` in the config). |
| `--no-auto-reconnect` | Exit on the first disconnection instead of reconnecting. |
| `--max-reconnect-attempts <N>` | Cap reconnect attempts between successful connections (unlimited if unset). |

## Configuration files

Instead of passing everything on the command line, `server start` and
`client start` can read a TOML file:

```sh
flextunnel server start -c server.toml
flextunnel client start --default-config   # ~/.config/flextunnel/client.toml
```

Precedence is **CLI flag > config file > built-in default**, so you can keep a
file and override individual settings on the command line. Unknown/misspelled
keys are rejected (`deny_unknown_fields`) rather than silently ignored. Paths
support `~` expansion.

See [`server.toml.example`](server.toml.example) and
[`client.toml.example`](client.toml.example) for the full set of keys. A minimal
client file:

```toml
server_node_id = "<server endpoint id>"
socks_listen   = "127.0.0.1:1080"
auth_token     = "v…"          # or: auth_token_file = "~/.config/flextunnel/token.txt"
```

Secrets may be inline (as above) or kept in separate files via the `*_file`
keys. CLI flags still work and override any of these.

## Reconnect behavior

Auto-reconnect is **enabled by default** (`auto_reconnect = true`); pass
`--no-auto-reconnect` (or set `auto_reconnect = false`) to disable it, and
`--auto-reconnect` to force it on over a config that disabled it.

- The **first** connection must succeed. If it fails — bad node id, wrong
  relay, server down, or a rejected token — the client **exits immediately**
  rather than retrying blindly.
- Once connected at least once, a transient drop triggers reconnection with
  **exponential backoff + jitter** (1s → 60s), indefinitely, unless
  `--max-reconnect-attempts` caps it or auto-reconnect is disabled.
- A permanent error (auth/config) never retries.
- The local SOCKS5 listener stays bound across reconnects, so local apps queue
  briefly instead of seeing connection-refused during the gap.

## Logging

Logging uses `env_logger`. The default is `info` with iroh/tracing quieted to
`warn`. Override with `RUST_LOG`, e.g. `RUST_LOG=flextunnel=debug`.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — how it works: connection
  lifecycle (fixed ALPN, auth handshake, per-stream protocol), module map,
  concurrency model, reconnect policy, security boundaries, and reference
  constants.
- [`docs/http-proxy-roadmap.md`](docs/http-proxy-roadmap.md) — planned HTTP
  proxy front-end (CONNECT tunneling, then absolute-URI forwarding).

## How it relates to ezvpn

flextunnel is modeled on the sibling project **ezvpn** (an IP-over-QUIC VPN),
reusing its iroh transport, auth-token scheme, and secret-key
identity. The difference: ezvpn creates a TUN device and ships IP packets over
unreliable QUIC datagrams (and needs root); flextunnel exposes a SOCKS5 listener
and tunnels TCP over reliable QUIC streams (and needs no root).
