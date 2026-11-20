# flextunnel

A TCP tunnel over QUIC with optional local SOCKS5/HTTP proxies and port
forwards. A client names the servers it can reach as **destinations** —
`machine1.internal` is one server, `machine2.internal` another — and a request
for a destination goes through that **server**, which resolves DNS and connects
from its own network. Requests for anything else connect directly from the
client. Port forwards and `flextunnel client nc` always go through a
destination.

This lets you reach hosts that are only reachable from a server's side — the
server's own `localhost`, a private network behind it, or names that only
resolve via its DNS — without a VPN. Because it uses ordinary userspace sockets
(no TUN device), **neither the client nor the server needs admin/root**.

Connections are **made on demand**: the client connects to a server when
something is first sent to it, and closes the connection again once it has gone
unused for a while. A client configured with twenty destinations holds no
connection until one is used.

Transport, NAT traversal, relay fallback, and TLS 1.3 encryption are provided by
[iroh](https://www.iroh.computer/): the client dials each server by its
`EndpointId`, so a server needs no public inbound port or port forwarding.

```
local app ──SOCKS5/HTTP──► flextunnel client (optional listeners, e.g. 127.0.0.1:1080 / :8081)
                          │  routes each request by its own table:
                          │    machine1.internal, *.corp.example ─► server 1
                          │    machine2.internal, 10.0.0.0/8     ─► server 2
                          │    anything else                     ─► direct, from the client
                          │
                          │  per server, opened on first use and closed when idle:
                          │  one iroh QUIC connection (fixed ALPN + auth handshake)
                          │  ├─ control stream:  Hello / HelloResponse, then heartbeats
                          │  └─ N data streams:  [request header][reply][raw bytes]
                          ▼
                      flextunnel server  (no root, no TUN)
                          │  per stream: resolve DNS ─► TcpStream::connect
                          ▼
                      target host:port  (reachable from the SERVER's network)
```

## Scope

- **SOCKS5 `CONNECT` only.** No UDP `ASSOCIATE`, no `BIND`. The optional HTTP
  proxy supports HTTP `CONNECT` plus absolute-URI plain-HTTP forwarding.
- The local SOCKS5 and HTTP proxy listeners are **unauthenticated**, and each is
  disabled unless explicitly configured. Any local user or process that can reach
  them can use the tunnel, so they **bind `127.0.0.1` only** (you configure just
  the port, like the desktop client) and flextunnel assumes a **trusted,
  single-user host**. The client keypair authenticates the client *process* to
  the server; it does **not** authenticate local callers of the proxy
  front-ends, and is no substitute for OS-level access control on a shared
  machine.

## Security model

flextunnel lets a set of **trusted clients** reach resources on the **server's**
side of the network. Both ends are run by the same trusted party: whoever runs
the server decides which client keys it authorizes. It is **not** a multi-tenant
service and does not defend the server against the clients it admits — a client
with an authorized key can, by design, reach whatever the server's network can
reach (including the server's own `localhost`). Authorize keys accordingly, and
scope the server's network access if that reach is too broad. The threats it does
address are on-path attackers (encryption + per-client keypairs) and accidental
misconfiguration (e.g. duplicate-id detection catching two clients or servers
started with the same identity — an operator guard rail, not an adversary
defense).

Normal client connections authenticate with an ed25519 keypair:

- **Client keypair** — each client generates a keypair in the shared
  [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys) format
  (`flexaccess-keys generate-auth-key`); the server keeps the public keys in an
  ssh-style authorized-keys file. In the handshake the client sends its public
  key, its (ephemeral) iroh endpoint id, and a signature over that id; the
  server accepts only if the claimed id matches the connection's
  TLS-authenticated id, the signature verifies, and the key is authorized —
  the secret never leaves the client, and a captured handshake cannot be
  replayed from another endpoint.

(The keyless exceptions are server-to-server bridges and `--quick` sessions,
whose credential is the peer's TLS-authenticated **EndpointId**, checked
natively against an allowlist at the handshake — the `authorized_keys` model.)

The QUIC ALPN is a fixed protocol identifier (`flextunnel/1`), not a secret: it
ensures both peers speak the flextunnel protocol but provides no access control
on its own.

All payload is end-to-end encrypted by QUIC/TLS 1.3.

## Install

Prebuilt release assets are published on the
[GitHub Releases](https://github.com/flexaccessdev/flextunnel/releases) page.
Stable releases include `flextunnel` for Linux
amd64/arm64, macOS arm64, and Windows amd64, plus the iOS xcframework asset.
Automated prereleases currently include Linux amd64/arm64, macOS arm64, and the
iOS xcframework, but skip Windows. The install scripts download the latest
binary and verify its SHA-256 checksum. On Linux/macOS this installs to a
per-user location (`~/.local/bin`, no root required). On Windows this installs
system-wide to `C:\Program Files\flextunnel` and updates the machine PATH,
which **requires an elevated (Administrator) PowerShell session** — running
the installed binary afterward does not.

**`flextunnel` (server / client) — Linux / macOS:**

```sh
curl -sSL https://flexaccessdev.github.io/flextunnel/install.sh | bash
```

**`flextunnel` (server / client) — Windows (PowerShell):**

```powershell
irm https://flexaccessdev.github.io/flextunnel/install.ps1 | iex
```

Options: append `-s -- --prerelease` (bash) for the latest prerelease, a release
tag to pin a version, or `--download-only` / `-DownloadOnly` to fetch the binary
without installing. `-PreRelease` is also accepted by the Windows installer when
the selected prerelease includes a Windows asset. A container image is also
published to `ghcr.io/flexaccessdev/flextunnel`.

### Desktop app (tray GUI, server and client)

Stable releases also include the desktop app
(`flextunnel-desktop-macos-arm64.dmg` and
`flextunnel-desktop-windows-amd64.msi`), a tray app with two roles of equal
weight, either one optional: a client of any number of servers elsewhere
(one destination per server, connected on demand), and this computer's own server (a generated identity, then the
clients you authorize). See [its README](crates/flextunnel-desktop/README.md).
The installers are **unsigned** — if you'd rather not apply the workarounds
below, build it yourself instead:

```sh
cargo build --release -p flextunnel-desktop
# binary: target/release/flextunnel-desktop — locally built binaries are not
# quarantined, so no workaround is needed
```

That produces the bare executable, **not** a `.app` bundle — so on macOS it has
no `Info.plist` and will show a Dock icon instead of running as a pure menu-bar
app. For the proper bundle, build it the way CI does with `cargo-packager`
(macOS only):

```sh
cargo install cargo-packager   # or: cargo binstall cargo-packager
cargo packager --release -p flextunnel-desktop --formats app
# bundle: target/release/flextunnel.app  (locally built → not quarantined,
# so no Gatekeeper workaround needed)
```

For the drag-to-Applications disk image instead, run `./build-macos-dmg.sh`
(also needs `brew install create-dmg`); it writes
`dist/macos/flextunnel-desktop-macos-arm64.dmg`.

Otherwise:

**macOS:** because the app is not notarized, Gatekeeper quarantines the
download and shows *"flextunnel" is damaged and can't be opened*.

The cleanest fix is to avoid the quarantine flag in the first place: browsers
set `com.apple.quarantine` on downloads, but command-line tools like `curl` and
`wget` do not. Download the disk image from the terminal instead:

```sh
# Replace vX.Y.Z with the release tag from the Releases page.
curl -fL -o flextunnel-desktop.dmg \
  https://github.com/flexaccessdev/flextunnel/releases/download/vX.Y.Z/flextunnel-desktop-macos-arm64.dmg
```

Then in Finder: double-click the `.dmg` to open it, drag `flextunnel.app` onto
the **Applications** shortcut in the window (choose **Replace** if an older copy
is already there), then eject the mounted image.

> **macOS zsh note:** the shell snippets in this README include `#` comment
> lines. zsh (the macOS default shell) treats `#` as a comment on an
> interactive prompt only after `setopt interactivecomments`; without it,
> pasting a `#` line reports `command not found`. Run `setopt interactivecomments`
> once per session, or just omit the comment lines when pasting.

If you already downloaded the `.dmg` via a browser, the quarantine flag
propagates to the app you copy out of it; remove it after installing (into
`/Applications`) instead:

```sh
xattr -cr /Applications/flextunnel.app
```

Alternatively, right-click the app and choose **Open** the first time.

**Windows:** SmartScreen's *"Windows protected your PC"* warning is triggered by
the Mark of the Web (the `Zone.Identifier` stream), which — like macOS
quarantine — is set by browsers but not by command-line tools. Avoid it the same
way: download with `curl.exe` (bundled in Windows 10+) or PowerShell instead of a
browser. Replace `vX.Y.Z` with the release tag from the Releases page:

```powershell
curl.exe -fL -o flextunnel-desktop.msi `
  https://github.com/flexaccessdev/flextunnel/releases/download/vX.Y.Z/flextunnel-desktop-windows-amd64.msi
# or: Invoke-WebRequest -OutFile flextunnel-desktop.msi `
#   https://github.com/flexaccessdev/flextunnel/releases/download/vX.Y.Z/flextunnel-desktop-windows-amd64.msi
```

If you already downloaded via a browser, strip the mark instead:
`Unblock-File .\flextunnel-desktop-windows-amd64.msi` (or right-click →
Properties → **Unblock**). Otherwise click **More info → Run anyway**.

## Build from source

```sh
cargo build --release
# binary: target/release/flextunnel
```

Requires a recent Rust toolchain (edition 2024). A bare `cargo build --release`
uses the workspace's default members and builds the CLI, but not
the iOS static library. To cross-build the CLI for Linux amd64 + arm64 via
Docker, use `./build-linux.sh`.

## Quick start

### 1. Generate credentials (once)

```sh
flextunnel generate-iroh-key -o server.key   # prints the server's EndpointId
flextunnel show-iroh-id --secret-file server.key   # re-print the EndpointId
```

Client authentication keys are managed by the standalone
[`flexaccess-keys`](https://github.com/flexaccessdev/flexaccess-keys) CLI.
Install it with its one-line installer:

```sh
# macOS / Linux
curl -sSL https://flexaccessdev.github.io/flexaccess-keys/install.sh | bash
```

```powershell
# Windows (PowerShell)
irm https://flexaccessdev.github.io/flexaccess-keys/install.ps1 | iex
```

Then:

```sh
# On each client machine: generate that client's keypair, then derive its
# public authorized-key entry. Send only the public entry to the server admin.
flexaccess-keys generate-auth-key "alice laptop" -o client.key
flexaccess-keys show-auth-key --private-key-file client.key
```

Without `-o`, the generate commands print the key file to stdout instead.
Keep `server.key` and each `client.key` private (written `0600` on Unix; both
key files carry `# Created:` / `# Public key:` comments). Share
the server's **EndpointId** with clients, and collect each client's printed
**authorized-key entry** (`ed25519-pub:…` — not a secret) into the server's
authorized-keys file, one per line with an optional trailing comment, ssh
`authorized_keys` style:

```text
# ./authorized_keys
ed25519-pub:XXXXXXXX alice laptop
ed25519-pub:YYYYYYYY build server
```

All commands above accept `--json` for machine-readable output (QA automation).

### 2. Configure and run the server (no root needed)

A server needs only its identity and the clients it authorizes. That is enough
for clients to reach the machine it runs on: its own `localhost`, on any port.

```toml
secret_file = "./server.key"

# Authorized client public keys — always a file (ssh authorized_keys style).
authorized_keys_file = "./authorized_keys"

# Optional: what else clients may reach through this server. This example
# allows everything; narrow it to specific domains/CIDRs if you prefer.
routed_domains = ["*"]
routed_cidrs = ["0.0.0.0/0", "::/0"]
```

```sh
flextunnel server start -c server.toml
```

It prints `flextunnel server Node ID: <ENDPOINT_ID>` — give that to clients.

### 3. Configure and run the client (no root needed)

The client's config names each server as a destination. `host` is a name of
your choosing; `<host>:<port>` then reaches that port on the server machine
itself.

```toml
# client.toml
socks_port    = 1080          # SOCKS5 on 127.0.0.1:1080 (loopback only)
auth_key_file = "./client.key"

[[destinations]]
host           = "machine1.internal"
server_node_id = "<ENDPOINT_ID>"
# Optional: send more than the machine itself through this server. The server
# must allow these too (its routed_domains / routed_cidrs above).
routed_domains = ["*.corp.example"]
routed_cidrs   = ["10.0.0.0/8"]

# More servers are more [[destinations]] tables.
```

```sh
flextunnel client start -c client.toml
```

Starting the client connects nothing. It connects to a server when something
is first sent to it.

### 4. Use it

Point any SOCKS5 client at `127.0.0.1:1080`. Use `socks5h://` so hostnames
reach flextunnel as names — that is what routes them, and routed names are then
resolved on the server side:

```sh
# The destination's own name is the server machine: here, its port 8000.
curl -x socks5h://127.0.0.1:1080 http://machine1.internal:8000/

# A routed name: resolved and connected by that server.
curl -x socks5h://127.0.0.1:1080 https://wiki.corp.example/

# Not on any destination's list: connected directly from this machine.
curl -x socks5h://127.0.0.1:1080 https://example.com

# SSH through a destination (see `client nc`; needs no proxy port): the
# destination's name reaches that machine's own sshd.
ssh -o ProxyCommand='flextunnel client nc -c client.toml %h %p' user@machine1.internal
```

The first request to a destination waits while the client connects to it;
later ones reuse the connection until it has been idle for five minutes (see
[Connection lifecycle](#connection-lifecycle)).

#### Quick ephemeral tunnel (no setup)

For a throwaway "route everything through this box for a few minutes" session,
`--quick` skips all of the above — no key files, no config. There is
no keypair auth at all: each side enters the **other side's EndpointId**. The
client's id becomes the server's one-entry allowlist (enforced natively at the
TLS handshake, like bridge allowlisting), and dialing the server's id is itself
what authenticates the server:

```sh
# On the client host: prints this client's EndpointId (enter it on the server)
# and prompts for the server EndpointId, then shows a live control panel in
# this terminal. Needs an interactive terminal.
flextunnel client start --quick

# On the server host: prompts for the client EndpointId printed above and
# allowlists it as the only allowed client, then prints this server's
# EndpointId to enter at the client prompt. Full-tunnels all traffic; exits on
# its own if the client doesn't connect within 5 minutes. Nothing is persisted.
flextunnel server start --quick
```

Either side can start first — both block at their prompt until the other's id
is entered.

The quick server runs a full tunnel (`routed_domains = ["*"]`,
`routed_cidrs = ["0.0.0.0/0", "::/0"]`); enter a SOCKS5/HTTP port at the client
prompt to open a local proxy listener. The quick client has one destination,
named `quick.internal`, which routes everything — so every proxied request goes
through the quick server, and `quick.internal:<port>` is the server's own
loopback. Unlike a regular client it connects at once and stays connected (the
quick server is waiting for it). Both sides are fully ephemeral: neither
takes the single-instance lock (so a quick session can run alongside a real one,
or another quick one), and both forget everything on exit.

The quick client is **self-contained**: after the prompt it runs the same live
panel as [`client control`](#client-control) right in that terminal — but it
opens **no control socket** (nothing else can attach to it), and quitting the
panel (`q`) **disconnects** the tunnel and exits, rather than detaching. A
quick client reads no config, so it has no port forwards.

#### Status pages

`flextunnel.internal` is reserved by flextunnel and answered by the **client
itself**, through either proxy listener. It shows the client's destinations and
what each is doing — idle, connecting, connected, retrying — without connecting
to anything. The browser view is HTML; `/status.txt` is plain text and
`/status.json` is structured JSON for scripts:

```sh
# plain-text status through a SOCKS5 listener configured on port 1080
curl -sS -x socks5h://127.0.0.1:1080 http://flextunnel.internal/status.txt

# JSON status through the same listener
curl -sS -x socks5h://127.0.0.1:1080 http://flextunnel.internal/status.json

# same endpoint through the optional HTTP proxy listener
curl -sS -x http://127.0.0.1:8081 http://flextunnel.internal/status.json
```

The JSON response includes `version`, `socks_listen`, `http_listen`,
`idle_timeout_secs`, and one entry per destination under `destinations`:
`host`, `server_node_id`, `state` (`idle`, `connecting`, `connected`,
`backoff` or `failed`), `connected_secs`, `open_streams`, `waiting`,
`client_node_id`, `failed_attempts`, `next_attempt_secs`, `last_error`,
`routed_domains`, `routed_cidrs`, `relay_urls`, and `server_status`.

Each **server's** own status page is under `/servers/<destination>/`, with the
same `/status.txt` and `/status.json` variants. Fetching it connects to that
server if it is not connected:

```sh
curl -sS -x socks5h://127.0.0.1:1080 http://flextunnel.internal/servers/machine1.internal/status.json
```

That JSON includes `version`, `server_node_id`, `routed_domains`,
`routed_cidrs`, `host_aliases`, `dns_forwards`, `bridges`, `inbound_bridges`,
and duplicate-id blocklist counts under `duplicate_id_blocklist`.

Other `*.flextunnel.internal` names are reserved and answer with an HTTP 404.

#### A server's loopback

A destination's `host` **is** the server machine: `machine1.internal:8000` is
port 8000 on that server's own `localhost`. No server config is needed — it
bypasses the server's routed set, bridges and host aliases — and it is dialed
on both `127.0.0.1` and `::1`, so a service bound to only one of them is still
reached. It works from the proxies, as a forward's `remote_host`, and with
`client nc`:

```sh
# a web app listening on machine1's loopback port 8000
curl -sS -x socks5h://127.0.0.1:1080 http://machine1.internal:8000/
```

Only the exact host maps to loopback: `foo.machine1.internal` is a different
name, routed (or not) like any other.

For more ways to use the proxy — `curl`/`git`/browser recipes, `ssh` through the
tunnel, and putting a plain local TCP port in front of it for apps that can't
speak SOCKS5 (databases, RDP, most GUIs) — see
[`docs/proxy-usage.md`](docs/proxy-usage.md).

#### HTTP proxy front-end (optional)

Add `--http-port <PORT>` to also run an HTTP proxy alongside SOCKS5 — useful
for the many tools that only speak an HTTP proxy or whose SOCKS5 support
resolves DNS client-side (`wget`, Docker pulls, npm/yarn, JVM/JDBC). It
handles HTTPS (and any TCP) via `CONNECT` tunneling and plain-HTTP via
absolute-URI forwarding; either way the hostname goes to the proxy, so routed
names are still resolved on their server.

```sh
flextunnel client start -c client.toml --http-port 8081

# HTTPS tunnels via CONNECT; plain HTTP is forwarded
https_proxy=http://127.0.0.1:8081 curl https://wiki.corp.example/
http_proxy=http://127.0.0.1:8081  curl http://machine1.internal:8000/
```

See [`docs/http-proxy-roadmap.md`](docs/http-proxy-roadmap.md) for remaining
HTTP proxy work. Apps without proxy support can use built-in port forwards.

## Commands

| Command | Description |
|---|---|
| `server start` | Run the proxy server. |
| `client start` | Run the proxy client (optional SOCKS5 and HTTP proxy listeners, plus the destinations and port forwards declared in its config). |
| `client control` | Attach the read-only terminal control panel to a running client. |
| `client nc` | Relay stdin/stdout through a running client to a `host:port` behind one of its destinations (SSH `ProxyCommand`). |
| `client help` | Show the client subcommands and their help. |
| `generate-iroh-key [-o <FILE>] [--force] [--json]` | Generate the server's iroh identity key (stdout without `-o`). |
| `show-iroh-id --secret-file <FILE> [--json]` | Print the iroh id (EndpointId) for a key. |

Client auth keypairs are generated with the standalone
[`flexaccess-keys`](https://github.com/flexaccessdev/flexaccess-keys) CLI
(`generate-auth-key` / `show-auth-key`), not by `flextunnel` itself.

### `server start`

| Flag | Description |
|---|---|
| `-c, --config <FILE>` | Load options from a TOML file (CLI flags override it). |
| `--default-config` | Load `~/.config/flextunnel/server.toml`. |
| `--secret-file <FILE>` | Server identity key. |
| `--authorized-keys-file <FILE>` | File of authorized client public keys, one `ed25519-pub:…` per line (optional trailing comment, ssh `authorized_keys` style). |
| `--relay-url <URL>` | Custom relay URLs (repeatable; at least two distinct URLs). See the [shared relay guide](https://github.com/flexaccessdev/flexaccess-iroh/blob/main/docs/relays-and-address-lookup.md) for discovery and dialing requirements. |
| `--relay-auth-token <TOKEN>` | Shared bearer token sent to every custom relay's WebSocket upgrade. Only valid with `--relay-url` (rejected with the default relays). |
| `--quick` | Ephemeral one-off server: prompt for the client's EndpointId (shown by `client start --quick`) and natively allowlist it as the only allowed client — no auth keypair — then mint an in-memory identity, full-tunnel all traffic, print this server's EndpointId, and exit if the client doesn't connect within 5 minutes. Needs an interactive terminal. Takes no single-instance lock; nothing is persisted. Conflicts with `-c`/`--secret-file`/`--authorized-keys-file`. |

The server takes a single-instance lock keyed by the prefix of its own
EndpointId (`~/.config/flextunnel/server-<key>.lock`). So one server runs per
identity per user: servers with different identity keys — including the
desktop app's — run side by side without any extra configuration, while a
second start of the same identity is refused.

### `client start`

| Flag | Description |
|---|---|
| `-c, --config <FILE>` | Load options from a TOML file (CLI flags override it). Without it, `~/.config/flextunnel/client.toml` is used if present. |
| `--socks-port <PORT>` | Optional SOCKS5 listener port, e.g. `1080`. Binds `127.0.0.1` only. Disabled unless set. |
| `--http-port <PORT>` | Optional HTTP proxy listener port (CONNECT + plain-HTTP forwarding). Binds `127.0.0.1` only. |
| `--auth-key <SECRET>` / `--auth-key-file <FILE>` | Client auth keypair for every destination that names no key file of its own: the inline `ed25519-sec:…` secret, or the key file from `flexaccess-keys generate-auth-key`. |
| `--relay-url <URL>` | Custom relay URLs (repeatable; at least two distinct URLs, matching the servers' set), for every destination that names no relays of its own. See the shared relay guide above. |
| `--relay-auth-token <TOKEN>` | Shared bearer token sent to every custom relay's WebSocket upgrade. Only valid with `--relay-url` (rejected with the default relays). |
| `--idle-timeout <SECS>` | How long a destination's connection is kept with nothing using it (default 300; `0` never closes an idle connection). |
| `--quick` | Self-contained ephemeral session (pairs with `server start --quick`): ignore any saved config, print this client's EndpointId (enter it at the quick server's prompt — that allowlist entry is the credential; no auth keypair), prompt for the server EndpointId, then run the live control panel in this terminal. Needs an interactive terminal. Takes no lock and opens no control socket; quitting the panel disconnects. Nothing is persisted. Conflicts with `-c`/`--auth-key(-file)`/`--idle-timeout`. |

The servers a client reaches are the `[[destinations]]` tables of its config;
there is no flag for them. So `client start` always runs off a config (except
`--quick`): `-c <FILE>`, or `~/.config/flextunnel/client.toml`, which is loaded
when `client start` is given any other flag (`flextunnel client start
--socks-port 1080`). Run with no arguments, it prints help. `--quick` ignores
any saved config, prints this client's EndpointId (its credential — enter it on
the quick server; there is no auth keypair), and prompts (on an interactive
terminal) for the server EndpointId and optional proxy ports, then runs the
self-contained control panel described under [`client control`](#client-control)
right in that terminal — but with no control socket exposed, and quitting the
panel disconnects instead of detaching. Nothing is saved.

Each `[[destinations]]` table (see [`client.toml.example`](client.toml.example))
has a `host` and a `server_node_id`, and optionally `routed_domains` /
`routed_cidrs` (see [Routing](#routing)) and its own `auth_key_file`,
`relay_urls` and `relay_auth_token`, which override the top-level ones for that
destination. Hosts and server ids must each be unique. The config is validated
at startup; an invalid destination or an ambiguous route stops the client
before anything is bound.

Port forwards are declared in the config as `[[forwards]]` tables: each listens
on `localhost:<local_port>` and opens a stream to `<remote_host>:<remote_port>`
through the destination that routes `remote_host`, connecting that server on
the first forwarded connection. They are validated at startup (nonzero ports,
valid host, unique local ports, a destination that routes the host) and all
come up with the client. There is no CLI flag and nothing can be changed live:
to change the set, edit the config and restart the client.

**A forward always goes through a destination — never directly.** That is the
one way a forward's `remote_host` is routed differently from a proxy request,
and it makes a host that no destination routes a startup error
(`forward #1: no destination routes example.org`).

**Forwarding to a server's loopback** uses the destination's own host. With
ssh, `-L 8080:localhost:80` reaches the remote's own port 80; the flextunnel
equivalent is `remote_host = "machine1.internal"`, which always means that
server's own loopback and needs no server config. Any other spelling is an
ordinary routed target: a destination must route it, and its server must allow
it. What that takes depends on how `remote_host` is written:

| `remote_host` | Client config needed | Server config needed |
| --- | --- | --- |
| a destination's `host`, e.g. `machine1.internal` | none (it is the destination) | none |
| `127.0.0.1` / `::1` | a loopback CIDR in that destination's `routed_cidrs` | the same CIDR in the server's `routed_cidrs`, e.g. `["127.0.0.0/8", "::1"]` |
| `localhost` | `"localhost"` (or `"*"`) in that destination's `routed_domains` (it is a hostname) | `"localhost"` (or `"*"`) in the server's `routed_domains` |
| a server `[host_aliases]` name, e.g. `server.internal` → `127.0.0.1` | the name in that destination's `routed_domains` | the name in the server's `routed_domains` |

When the server refuses a target, nothing is dialed: the client logs
`Forward localhost:<port>: … rejected target: connection not allowed` and the
local connection closes.

With neither `--socks-port` nor `--http-port` (nor the config keys) the client
runs in **port-forward-only mode**: it serves the port forwards, `client nc`
and the control panel.

A client's on-disk identity — the single-instance lock and the control socket
— is keyed by its **name**: the optional `name` key in its config, or
`default`. One client reaches every server you configure, so a single unnamed
client is the usual setup; give a second config a different `name` to run two
clients side by side (they need different proxy and forward ports too). (A
`--quick` client is exempt: it takes neither — no lock, no socket.)

### `client control`

```sh
flextunnel client control                # the client from ~/.config/flextunnel/client.toml
flextunnel client control -c work.toml   # the client started from a specific config
flextunnel client control -n work        # or by client name directly
```

Attaches a **read-only** terminal control panel to a **running** client, over
its control socket (`~/.config/flextunnel/client-<name>.sock`; a named pipe on
Windows). It lists the client's **destinations** with their live state — idle,
connecting, connected with its uptime and open streams, or retrying with the
failed attempts so far and when the next one is due. Select one (`↑`/`↓`) to see
its server and client node ids, the last error, what it routes, and — with `p`
— its connection paths (direct/relay). Below are the **port forwards** declared
in the client's config with their live state (listening, active connections, or
switched off with the bind-failure reason) and the destination each goes
through.

Looking never connects anything: a destination shown as idle stays idle.

Nothing about the client can be changed from the panel: destinations and
forwards are fixed by the config for the life of the client (edit the config
and restart to change them), and the channel carries no mutations. It runs as
the same user as the client — no elevated privilege on either end.

Detaching (`q`) never affects the client; several panels can attach at once.

### `client nc`

```sh
flextunnel client nc <HOST> <PORT>                # the client from ~/.config/flextunnel/client.toml
flextunnel client nc -c work.toml <HOST> <PORT>   # the client started from a specific config
flextunnel client nc -n work <HOST> <PORT>        # or by client name directly
```

Opens one tunnel to `<HOST>:<PORT>` through a **running** client (picked the
same way as for `client control`, over the same control socket) and relays it
to stdin/stdout — a built-in netcat for SSH's `ProxyCommand`. `<HOST>` is routed
like a port forward, so a destination's own name reaches that machine itself:

```
Host machine1.internal machine2.internal
    ProxyCommand flextunnel client nc %h %p
```

With that, `ssh machine1.internal` reaches machine1's own sshd through its
server, and `ssh machine2.internal` reaches machine2's — one client, one line
of ssh config.

If the destination is not connected, `nc` waits while the client connects to
it (up to 45s); otherwise the tunnel opens at once. It works with no SOCKS or
HTTP port configured. Like a port forward, the target goes to the destination's
server, which enforces its routed set and resolves the host; a host that no
destination routes is refused rather than connected directly. It fails with the
reason (client not running, no destination routes the host, server unreachable,
target refused), which ssh prints. It reaches clients started with `client
start`; the desktop app's client has no control socket, so reach it
through its SOCKS port instead
(`ProxyCommand nc -X 5 -x 127.0.0.1:<port> %h %p`).

## Configuration files

Instead of passing everything on the command line, `server start` and
`client start` can read a TOML file:

```sh
flextunnel server start -c server.toml
flextunnel client start -c client.toml
flextunnel client start --socks-port 1080  # loads ~/.config/flextunnel/client.toml
```

Precedence is **CLI flag > config file > built-in default**, so you can keep a
file and override settings on the command line. Credential groups are replaced
as a unit: for example, if the CLI supplies either `--auth-key` or
`--auth-key-file`, the config file's `auth_key_file` is ignored. Unknown
or misspelled keys are rejected (`deny_unknown_fields`) rather than silently
ignored. Paths support `~` expansion.

See [`server.toml.example`](server.toml.example) and
[`client.toml.example`](client.toml.example) for the full set of keys. A minimal
client file:

```toml
socks_port    = 1080          # SOCKS5 on 127.0.0.1:1080 (loopback only)
auth_key_file = "~/.config/flextunnel/client.key"

[[destinations]]
host           = "machine1.internal"
server_node_id = "<server endpoint id>"
```

Private keys are always file references in a config (`secret_file`,
`auth_key_file`) — there are no inline-key config keys. CLI flags still work
and override any of these (`--auth-key` exists only as a CLI flag).

The client's `[[destinations]]` and `[[forwards]]` are config-file only, as are
the server's `routed_domains`, `routed_cidrs`, `host_aliases`, `dns_forwards`,
outbound `[bridges.<name>]`, and inbound `allowed_bridge_servers`: they
describe routing policy. Bridges carry no keypair: a bridging server
authenticates by its TLS-authenticated endpoint id, which the receiving server
must list in `allowed_bridge_servers` (enforced natively at the handshake).

## Host aliases (server-side)

The server config can map hostnames to addresses on its own network, so a client
can reach the server's loopback or internal hosts by a real name. Add a
`[host_aliases]` table to `server.toml` (config-file only — there is no CLI flag):

```toml
[host_aliases]
"server.internal" = "127.0.0.1"      # the server's own loopback
"node2.internal"  = "192.168.1.50"   # another host on the server's network
```

When a requested hostname matches a key (case-insensitive), the server rewrites
it to the value — an IP or another hostname — keeping the requested port, then
resolves and connects like any other target. Only domain targets are aliased;
literal IPs pass through unchanged.

For the server's own loopback no alias is needed: the name a client gives the
server as a destination (see [A server's loopback](#a-servers-loopback)) always
maps there, which also sidesteps Firefox refusing to proxy literal
`localhost` / `127.0.0.1`. Aliases are for other hosts on the server's network.
An alias only takes effect for a name that reaches the server — the client must
route it (`routed_domains` on that destination) and the server must allow it
(its own `routed_domains`). Either way, use `socks5h://` (or set Firefox's
`network.proxy.socks_remote_dns = true`) so the name is resolved by the server,
not locally.

## Routing

Routing has two halves, each configured where it applies. Nothing about it
crosses the connection — which is what lets a client decide where a request
goes without being connected to anything.

**The client decides which server a request goes to**, from its
`[[destinations]]`:

```toml
# client.toml
[[destinations]]
host           = "machine1.internal"
server_node_id = "<endpoint id 1>"
routed_domains = ["*.corp.example", "httpbin.org"]
routed_cidrs   = ["10.0.0.0/8", "192.168.1.5"]

[[destinations]]
host           = "machine2.internal"
server_node_id = "<endpoint id 2>"
routed_domains = ["*.dev.corp.example"]
```

For each request, the most specific match wins:

1. `flextunnel.internal` — the client's own [status pages](#status-pages).
2. A destination's own `host` — that server's loopback.
3. An exact `routed_domains` entry, then the longest `*.suffix`, then `*`. For
   an IP target, the `routed_cidrs` entry with the longest prefix.
4. Nothing matches — the proxy listeners connect **directly** from the client
   (split-tunneling); a port forward or `client nc` is refused.

So with the config above, `api.corp.example` goes to server 1 and
`x.dev.corp.example` to server 2. Destinations may nest like that, but the
*same* rule on two destinations is ambiguous and rejected at startup, as is
listing a destination's `host` under `routed_domains`.

This suits a client that must send *all* its traffic to the local proxy (for
example a WebView with a global proxy config) when only some hosts should be
tunneled. To route **all** traffic through one server (full tunnel), give its
destination the catch-alls:

```toml
routed_domains = ["*"]
routed_cidrs   = ["0.0.0.0/0", "::/0"]
```

**The server decides what it will connect to**, from its own lists:

```toml
# server.toml
routed_domains = ["*.corp.example", "httpbin.org"]
routed_cidrs   = ["10.0.0.0/8", "192.168.1.5"]
```

It enforces them as a **whitelist**, **rejecting** any request for a target not
on them (SOCKS5 reply `0x02`). So a route must be on both sides to work: on the
client's destination, to be sent to the server at all, and on the server, to be
accepted. A route the client lists and the server does not is answered
"connection not allowed"; one the server lists and the client does not is
simply never sent — it connects directly. The server's whitelist enforces
routing policy for trusted clients and catches accidental misconfiguration; it
is not an isolation boundary for untrusted clients.

Two things reach a server **outside** its lists: its own loopback, under the
destination's `host`, and its [status page](#status-pages). So a server with
both lists omitted is valid — clients reach just the machine itself through it.
An empty list never means "tunnel everything".

Matching is the same on both sides: domain entries are exact (`example.com`),
wildcard (`*.example.com`, which matches subdomains only — not the bare apex),
or `*` (matches every hostname), case-insensitive; CIDR entries match IP
targets, accept a bare IP as a single host, and a default route (`0.0.0.0/0` /
`::/0`) matches every IP. Hostnames are matched only against `routed_domains`
and IPs only against `routed_cidrs`. A numeric IP literal is always gated by
`routed_cidrs` even when it arrives in hostname form (SOCKS5 `ATYP_DOMAIN`), so
`*` never lets a raw IP through — it can only route real hostnames.

Either list, or both, may be omitted. The two never cross: an omitted/empty
list means that whole category is not routed. So `routed_domains` alone (no
`routed_cidrs`) tunnels those hostnames but direct-connects every bare-IP
target, and `routed_cidrs` alone tunnels those IPs but direct-connects every
hostname.

### Roadmap

- **Client blocking mode.** Today the proxy listeners **always direct-connect**
  a target that no destination routes (split-tunneling), and this is the same
  for the desktop and iOS clients (they share the same core). A future client
  option — likely `routed_mode = "block" | "direct"` (default `"direct"`) — will
  let a client instead **refuse** such a connection, returning a SOCKS5 error to
  the local app rather than falling back to a direct connection. This is aimed
  mainly at the desktop client, where blocking unrouted traffic can be
  preferable to letting it leak out directly; the iOS client keeps defaulting to
  direct-connect. (The server's `0x02` rejection above is a separate,
  server-side control and is unaffected.)

## Connection lifecycle

A client holds **no connection** to a server until something is sent to it,
and gives the connection up again once it is unused.

- **First use connects.** A request for a destination that is not connected —
  through a proxy listener, a port forward, or `client nc` — makes the client
  connect to that server, and is **held** while it does, for up to 45s. The
  request then proceeds as if the connection had been there all along. Only a
  connection that never lands gets a failure: network-unreachable from the
  proxies (SOCKS5 reply `0x03`; the HTTP front-end maps it to `502 Bad
  Gateway`), an error from a forward or `nc`.
- **Idle disconnects.** A connection with no open stream for `idle_timeout_secs`
  (default 300; `--idle-timeout`) is closed. An open stream — an ssh session, a
  long download — keeps it up for as long as it lasts. `idle_timeout_secs = 0`
  never closes an idle connection.
- **A lost connection is redialed only if wanted.** If requests are waiting,
  the client retries with **exponential backoff + jitter** (1s doubling to
  60s) until one succeeds or they give up waiting. If nothing is waiting, the
  destination just goes idle, and the next request redials — after whatever is
  left of the backoff, so a server that is down is still probed at most once
  per step. There is no background reconnect loop, and no flag to turn one
  off.
- **A down server is not a reason to exit.** A destination whose server is
  unreachable, or not up yet, only fails the requests for it; the client keeps
  running and the other destinations are unaffected.
- **A rejected key fails fast.** If a server refuses the client (an
  unauthorized key), requests for that destination fail at once instead of
  waiting, and the client tries again only after a backoff step. The client
  keeps running here too.
- **Each destination has its own endpoint**, created when it connects and
  closed when it goes idle. After three consecutive failed attempts in one
  outage, the next attempt rebuilds that endpoint; further rebuilds are at
  least 30 minutes apart during that outage. See the
  [connection policy](docs/architecture.md#connection-policy-client).
- **Targets that no destination routes** keep connecting directly, whatever
  state the destinations are in.

The first request after an idle period pays for a fresh endpoint and
connection. With the default relays that is a bind plus a relay connection;
with custom relays every relay is probed first, and one that is down holds the
probe to its 10s limit — on every such first request, where it used to be once
at startup. If that shows, raise `idle_timeout_secs`.

The control panel and the [status page](#status-pages) show each destination's
state: failed attempts so far, the last error, and when the next attempt is
due.

Server home-relay failover is provided by `flexaccess-iroh`; see the
[shared failover design](https://github.com/flexaccessdev/flexaccess-iroh/blob/main/docs/relay-failover.md).

## Logging

Logging uses `env_logger`. The default is `info` with iroh/tracing quieted to
`warn`. Override with `RUST_LOG`, e.g. `RUST_LOG=flextunnel=debug`.

## Documentation

- [flexaccess-iroh docs](https://github.com/flexaccessdev/flexaccess-iroh/tree/main/docs) —
  the iroh transport layer shared with [tunnel-rs](https://github.com/andrewtheguy/tunnel-rs)
  and [ezvpn](https://github.com/flexaccessdev/ezvpn):
  [relays and address lookup](https://github.com/flexaccessdev/flexaccess-iroh/blob/main/docs/relays-and-address-lookup.md)
  (default vs custom relays, relay hints, the per-relay startup probe, relay auth
  tokens) and
  [self-hosting](https://github.com/flexaccessdev/flexaccess-iroh/blob/main/docs/self-hosting.md)
  (running your own iroh relay).
- [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys) — the
  app-independent Ed25519 key format and tooling shared with tunnel-rs: the
  `ed25519-sec:` / `ed25519-pub:` tokens, key files, authorized-keys documents
  ([key-format specification](https://github.com/flexaccessdev/flexaccess-keys/blob/main/docs/key-format.md)),
  and the `generate-auth-key` / `show-auth-key` CLI. flextunnel links against
  the same crate for parsing and verification and retains only its own
  domain-separated authentication transcript.
- [`docs/architecture.md`](docs/architecture.md) — how it works: connection
  lifecycle (fixed ALPN, auth handshake, per-stream protocol), module map,
  concurrency model, the client's per-destination connection policy, security
  boundaries, and reference constants.
- [`docs/local-ci.md`](docs/local-ci.md) — clippy and tests on all three host
  platforms via `ci/all.sh`; Linux/macOS run natively on the current host and
  the other platforms use SSH.
- [`docs/systemd.md`](docs/systemd.md) — running the CLI client under systemd:
  one unit for all your servers, the control panel and journald logging.
- [`docs/http-proxy-roadmap.md`](docs/http-proxy-roadmap.md) — remaining HTTP
  proxy work.
- [`docs/proxy-usage.md`](docs/proxy-usage.md) — using the SOCKS5 and HTTP
  proxies: which listener a tool needs, native SOCKS5 clients (`curl`, `git`,
  browsers), HTTP-proxy-only tools (`wget`, Docker, JVM/JDBC), `ssh`
  through the tunnel, and `socat`/`ssh -L`/`-D` forwards for apps that speak
  neither.

## How it relates to ezvpn

flextunnel is modeled on the sibling project **ezvpn** (an IP-over-QUIC VPN),
reusing its iroh transport and secret-key identity (client access control is
flextunnel's own ed25519 keypair scheme). The difference: ezvpn creates a TUN device and ships IP packets over
unreliable QUIC datagrams (and needs root); flextunnel exposes SOCKS5/HTTP proxy
listeners and tunnels TCP over reliable QUIC streams (and needs no root).

## License

MIT — see [LICENSE](LICENSE).
