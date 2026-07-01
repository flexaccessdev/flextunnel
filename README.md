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

flextunnel lets a set of **trusted clients** reach resources on the **server's**
side of the network. Both ends are run by the same trusted party: whoever runs
the server decides which clients get tokens. It is **not** a multi-tenant service
and does not defend the server against the clients it admits — a client with a
valid token can, by design, reach whatever the server's network can reach
(including the server's own `localhost`). Distribute tokens accordingly, and
scope the server's network access if that reach is too broad. The threats it does
address are on-path attackers (encryption + per-client tokens) and accidental
misconfiguration (e.g. duplicate-id detection catching two clients or servers
started with the same identity — an operator guard rail, not an adversary
defense).

A per-client auth token gates every connection:

- **Auth token** — sent in the connection handshake and checked against the
  server's accepted set. Per-client, like an API key.

The QUIC ALPN is a fixed protocol identifier (`flextunnel/1`), not a secret: it
ensures both peers speak the flextunnel protocol but provides no access control
on its own.

All payload is end-to-end encrypted by QUIC/TLS 1.3.

## Install

Prebuilt release assets are published on the
[GitHub Releases](https://github.com/andrewtheguy/flextunnel/releases) page.
Stable releases include `flextunnel` and `flextunnel-agent` for Linux
amd64/arm64, macOS arm64, and Windows amd64, plus the iOS xcframework asset.
Automated prereleases currently include Linux amd64/arm64, macOS arm64, and the
iOS xcframework, but skip Windows. The install scripts download the latest
binary, verify its SHA-256 checksum, and install to a per-user location
(`~/.local/bin` on Linux/macOS, `%LOCALAPPDATA%\Programs\flextunnel` on Windows)
— **no admin required**.

**`flextunnel` (server / client) — Linux / macOS:**

```sh
curl -sSL https://andrewtheguy.github.io/flextunnel/install.sh | bash
```

**`flextunnel` (server / client) — Windows (PowerShell):**

```powershell
irm https://andrewtheguy.github.io/flextunnel/install.ps1 | iex
```

**`flextunnel-agent` (reverse-routing agent) — Linux / macOS:**

```sh
curl -sSL https://andrewtheguy.github.io/flextunnel/install-agent.sh | bash
```

**`flextunnel-agent` (reverse-routing agent) — Windows (PowerShell):**

```powershell
irm https://andrewtheguy.github.io/flextunnel/install-agent.ps1 | iex
```

Options: append `-s -- --prerelease` (bash) for the latest prerelease, a release
tag to pin a version, or `--download-only` / `-DownloadOnly` to fetch the binary
without installing. `-PreRelease` is also accepted by the Windows installer when
the selected prerelease includes a Windows asset. A container image is also
published to `ghcr.io/andrewtheguy/flextunnel`.

## Build from source

```sh
cargo build --release
# binaries: target/release/flextunnel, target/release/flextunnel-agent
```

Requires a recent Rust toolchain (edition 2024). A bare `cargo build --release`
uses the workspace's default members and builds the CLI and the agent, but not
the iOS static library. To cross-build static Linux binaries for amd64 + arm64
via Docker, use `./build-linux.sh`.

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
flextunnel server \
    --secret-file server.key \
    --auth-token  <AUTH_TOKEN>
```

It prints `flextunnel server Node ID: <ENDPOINT_ID>` — give that to clients.

### 3. Run the client (no root needed)

```sh
flextunnel client \
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

For apps that can't speak SOCKS5 (databases, RDP, most GUIs), put a plain local
TCP port in front of the proxy — see
[`docs/port-forwarding.md`](docs/port-forwarding.md) for `socat` and `ssh`
recipes.

## Commands

| Command | Description |
|---|---|
| `server` | Run the proxy server. |
| `client` | Run the proxy client (local SOCKS5 listener). |
| `generate-server-key -o <FILE> [--force]` | Generate the server identity key. |
| `show-server-id --secret-file <FILE>` | Print the EndpointId for a key. |
| `generate-auth-token [-c N]` | Generate N client auth tokens (prefix `ftc`). |

The reverse-routing **agent** is a separate binary, `flextunnel-agent`
(subcommands `run` and `generate-token`) — see
[Reverse-routing agent](#reverse-routing-agent) below.

### `server`

| Flag | Description |
|---|---|
| `-c, --config <FILE>` | Load options from a TOML file (CLI flags override it). |
| `--default-config` | Load `~/.config/flextunnel/server.toml`. |
| `--secret-file <FILE>` | Server identity key. |
| `--auth-token <TOKEN>` | Accepted client token (repeatable). |
| `--auth-tokens-file <FILE>` | File of accepted client tokens, one per line. |
| `--agent-auth-token <TOKEN>` | Accepted agent token (repeatable). Separate pool from clients. |
| `--agent-auth-tokens-file <FILE>` | File of accepted agent tokens, one per line. |
| `--relay-url <URL>` | Custom relay URL(s) for failover (repeatable). |
| `--dns-server <URL>` | Custom discovery DNS server, or `none` to disable. |

### `client`

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

Instead of passing everything on the command line, `server` and
`client` can read a TOML file:

```sh
flextunnel server -c server.toml
flextunnel client --default-config   # ~/.config/flextunnel/client.toml
```

Precedence is **CLI flag > config file > built-in default**, so you can keep a
file and override settings on the command line. Credential groups are replaced
as a unit: for example, if the CLI supplies either `--auth-token` or
`--auth-token-file`, the config file's client token fields are ignored. Unknown
or misspelled keys are rejected (`deny_unknown_fields`) rather than silently
ignored. Paths support `~` expansion.

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

## Host aliases (server-side)

The server config can map hostnames to addresses on its own network, so a client
can reach the server's loopback or internal hosts by a real name. Add a
`[host_aliases]` table to `server.toml` (config-file only — there is no CLI flag):

```toml
[host_aliases]
"server.homelab" = "127.0.0.1"      # the server's own loopback
"node2.homelab"  = "192.168.1.50"   # another host on the server's network
```

When a requested hostname matches a key (case-insensitive), the server rewrites
it to the value — an IP or another hostname — keeping the requested port, then
resolves and connects like any other target. Only domain targets are aliased;
literal IPs pass through unchanged.

This is also the clean way around Firefox refusing to proxy literal
`localhost` / `127.0.0.1`: alias `server.homelab` → `127.0.0.1` on the server and
browse to `http://server.homelab:8000/`. Use `socks5h://` (or set Firefox's
`network.proxy.socks_remote_dns = true`) so the name is resolved by the server,
not locally.

## Reverse-routing agent

Where a `[host_aliases]` entry resolves to a host on the **server's** network, an
`[agent_routes]` entry resolves to a connected **agent** — a `flextunnel-agent`
process on some other machine. The agent dials the server (like a client) but runs
no SOCKS5 listener; instead it accepts the streams the server opens back to it and
connects each to `127.0.0.1` on its own machine. This lets a client reach a service
behind NAT that the server cannot dial directly: the agent makes the outbound
connection, and the server pushes streams back over it. Reverse routing is
**loopback-only** in v1.

The agent is a **separate binary** (`flextunnel-agent`, for Linux, macOS, and
Windows) and identifies itself by a stable **network id** (`ftm1…`) — a one-way
hash, with a version prefix, of its OS-native machine id (`/etc/machine-id` on
Linux, `IOPlatformUUID` on macOS, `MachineGuid` on Windows; no elevation needed).
The raw machine id never leaves the host; only the network id is sent. Its iroh
node id is ephemeral, so there is no key file to manage. Only one agent runs per
machine (enforced by a machine-wide loopback-UDP singleton lock, so no elevated
privileges are needed). It authenticates with its **own** token pool
(prefix `fta`, separate from client `ftc` tokens).

```sh
# On the agent host: get this agent's network id to reserve on the server.
flextunnel-agent machine-id              # -> shows the raw id + derived ftm1… id
# On the server host: generate an agent token (add to agent_auth_tokens).
flextunnel-agent generate-token          # -> fta…
```

```toml
# server.toml
agent_auth_tokens = ["fta…"]
routed_domains    = ["web.homelab", "*.example.com"]   # the alias must be on the routed set

[agent_routes]
"web.homelab" = { machine_id = "ftm1…" }   # from `flextunnel-agent machine-id`
```

```sh
# On the agent host (Linux/macOS/Windows):
flextunnel-agent run --server-node-id <server id> --auth-token fta…
# then from a client: curl -x socks5h://127.0.0.1:1080 http://web.homelab:8000/
```

A second agent presenting the **same** network id (e.g. a cloned VM image whose
machine id was never regenerated) is rejected and the network id is recorded
in the blocklist — fix the duplicate id and clear the entry to recover. See
[`agent.toml.example`](agent.toml.example).

## Routed-set split-tunneling

The routed set (the **tunnel set**) is a VPN-style split-tunnel "included routes"
list that decides which destinations traverse the tunnel. Targets not on it are
**not** rejected — the client falls back to a direct connection for them. It is
useful when a client must send *all* its traffic to the local SOCKS5 proxy (e.g.
an iOS WebView, whose proxy config is global) but only some hosts should actually
be tunneled. It is **required** and configured on the **server only** (config-file
only — there is no CLI flag); the client configures nothing:

```toml
# server.toml
routed_domains = ["*.example.com", "httpbin.org"]
routed_cidrs   = ["10.0.0.0/8", "192.168.1.5"]
```

The tunnel set is required: a server started with an empty set **refuses to
start**, and a client that receives an empty set from a (misconfigured or old)
server **aborts the handshake** rather than silently direct-connecting
everything. To route **all** traffic through the tunnel (full tunnel), use the
catch-alls:

```toml
routed_domains = ["*"]
routed_cidrs   = ["0.0.0.0/0", "::/0"]
```

The server is the single source of truth. It **pushes** the list to every client
in the handshake response, so there is no client list to keep in sync:

- **Client** — on connect it learns the server's list. It tunnels only matching
  targets and connects everything else **directly** from its own network
  (split-tunneling). The direct path is independent of the tunnel, so off-list
  targets keep connecting even while the tunnel is down; an on-list target during
  a drop/backoff gets a SOCKS5 network-unreachable reply (`0x03`) rather than
  hanging.
- **Server** — it also enforces the same list independently as a **whitelist**,
  **rejecting** any tunnel request for a target not on it (SOCKS5 reply `0x02`).
  This is a defense-in-depth boundary against a misconfigured or untrusted
  client. (Note the asymmetry: the client falls back to a direct connection for
  off-list targets, whereas the server rejects them outright.)

Matching: domain entries are exact (`example.com`), wildcard (`*.example.com`,
which matches subdomains only — not the bare apex), or `*` (matches every
hostname), case-insensitive; CIDR entries match IP targets, accept a bare IP as a
single host, and a default route (`0.0.0.0/0` / `::/0`) matches every IP.
Hostnames are matched only against `routed_domains` and IPs only against
`routed_cidrs`. A numeric IP literal is always gated by `routed_cidrs` even
when a client sends it in hostname form (SOCKS5 `ATYP_DOMAIN`), so `*` never lets
a raw IP through — it can only route real hostnames.

Only the **combined** set must be non-empty — setting just one list is fine. The
two never cross: an omitted/empty list means that whole category is off-list and
always direct-connected. So `routed_domains` alone (no `routed_cidrs`)
tunnels those hostnames but direct-connects every bare-IP target, and
`routed_cidrs` alone tunnels those IPs but direct-connects every hostname.

### Roadmap

- **Client blocking mode.** Today the client **always direct-connects** every
  off-list target (split-tunneling), and this is
  the same for the desktop and iOS clients (they share the same core). A future
  client option — likely `routed_mode = "block" | "direct"` (default
  `"direct"`) — will let a client instead **refuse** an off-list connection,
  returning a SOCKS5 error to the local app rather than falling back to a direct
  connection. This is aimed mainly at the desktop client, where blocking off-list
  traffic can be preferable to letting it leak out directly; the iOS client keeps
  defaulting to direct-connect. (The server's `0x02` rejection above is a
  separate, server-side control and is unaffected.)
- **Richer agent routes.** Reverse routing is loopback-only in v1: every
  `[agent_routes]` entry dials `127.0.0.1` on the agent. A follow-up will let one
  agent (one machine id) expose several hostnames, each mapped to a chosen host/IP
  on the agent's own network (an `agent_ip` field, default `127.0.0.1`) — likely
  either per-domain entries or a grouped `[[agent]]` array-of-tables.

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
- [`docs/port-forwarding.md`](docs/port-forwarding.md) — expose a plain local
  TCP port through the SOCKS5 client (`socat`, `ssh -L`/`-D`) for apps that
  don't speak SOCKS5.

## How it relates to ezvpn

flextunnel is modeled on the sibling project **ezvpn** (an IP-over-QUIC VPN),
reusing its iroh transport, auth-token scheme, and secret-key
identity. The difference: ezvpn creates a TUN device and ships IP packets over
unreliable QUIC datagrams (and needs root); flextunnel exposes a SOCKS5 listener
and tunnels TCP over reliable QUIC streams (and needs no root).
