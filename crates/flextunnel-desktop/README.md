# flextunnel-desktop

The native desktop app for [flextunnel](../..) — a system-tray app for **macOS
and Windows** with two roles of equal weight, either one optional: a
**client** of any number of flextunnel servers elsewhere, and this computer's
own **server**, run in-process. Nothing ever needs a terminal.

It embeds [`flextunnel-core`](../flextunnel-core) directly (no FFI layer) and is
built on [iced](https://iced.rs/)'s daemon runtime: the process lives in the
menu bar / system tray and keeps running with no window open, so closing the
window loses nothing — the tray owns the lifecycle and re-opens it on demand.

```
┌── tray / menu bar ─────────────────┐   ┌──────────── window ─────────────────┐
│ Open flextunnel…                    │   │ CLIENT            Client ● running  │
│ Client running · 1 of 2 connected   │   │ ● Proxy & forwards   [Enabled ◉]    │
│ Disable Client                      │   │ DESTINATIONS  +   PROXIES           │
│ Server running · 2 clients connected│ ⇄ │ ● nas.internal    SOCKS5 127.0.0.1… │
│ Disable Server                      │   │ ○ lab.internal    PORT FORWARDS     │
│ Copy Endpoint ID                    │   │ SERVER            ● db  5432  via   │
│ ☑ Open at Login                     │   │ ● This computer        nas.internal │
│ Quit flextunnel                     │   │ Keys · Logs                         │
└─────────────────────────────────────┘   └─────────────────────────────────────┘
```

## First launch

With nothing set up, the window opens with nothing selected, pointing at the
sidebar: there is no role to pick. Either is set up from there whenever wanted
— "+" next to Destinations, or "Set up server…", which opens the server's
welcome first.

## The client

The app runs one client — the desktop equivalent of a `client.toml`: two
optional local proxies, any number of port forwards, and the **destinations**
they reach. It is one session for all of them.

- **Destinations** — each is a **host** name for one server (`nas.internal`),
  the server's `EndpointId`, and an auth key. `<host>:<port>` through the
  proxy, or as a forward's remote host, reaches that port on the server
  machine itself. *Routed domains* and *Routed CIDRs* are optional further
  targets to send through that server (which must allow them in its own tunnel
  set). *Fetch from server* fills both with the server's own tunnel set: it
  connects once to ask, so the server must already authorize the picked key,
  and replaces what the two fields held — review the result, then save. It is
  a copy as of that moment; a later change on the server is not followed.
  Where two destinations overlap, the more specific rule wins; the same
  rule on two destinations is refused. The form and the destination's pane
  list each such overlap, and which destination takes it. Once a destination
  has connected, its pane also marks each rule the server routes only in part,
  or not at all, as the server said on that connection. A proxy request no
  destination routes connects directly from this computer; a port forward
  never does (see *Port forwards* below).
- **Connects on demand** — a running client only listens. A destination is
  connected when something is first sent to it — the request waits while it
  connects — and disconnected again once nothing has used it for five minutes,
  when it shows **idle**. A dropped connection is likewise re-established when
  something next needs it, not before. *Connect now* on a destination's pane
  asks for one attempt right away, to see whether the server is reachable.
- **Enabled** — the client's only on/off control: a switch on its pane (and
  *Enable/Disable Client* in the tray). An enabled client runs: it starts with
  the app (at login or by hand), and as soon as it becomes startable — its
  first destination added. Disabling stops it and keeps it stopped across
  launches. After a failure (a local port already taken), change what failed,
  or switch it off and on to retry.
- **Restart to apply** — the client runs with the proxy ports and destinations
  it started with. After a change to either — or to a key a destination uses —
  its pane and every destination's offer *Restart now*, which closes the
  connections that are open. A destination added or edited since shows
  **restart to apply** until then. Port forwards are the exception: they apply
  at once.
- **A refused key** — a server that does not authorize a destination's key
  fails that destination alone, which shows **refused** with the server's
  reason; the others keep working, and it is tried again when next needed.
- **Shared auth keys** — the Keys pane holds this computer's client keypairs;
  any number of destinations can use the same one. Each server a key connects
  to must authorize its public half.
- **Local SOCKS5 / HTTP proxies** — enable either or both; point any
  proxy-aware app at `127.0.0.1:<port>` and its traffic to a destination's
  host or routes rides that destination. Use the SOCKS5 proxy with remote name
  resolution (`socks5h://`), so the destination names reach it.
- **Port forwards** — bind a local port to a `host:port` reached through a
  destination, so tools that can't use a proxy reach private services as if
  local. A forward never connects directly, so its remote host must be a
  destination's host or one of its routes: its row says which destination
  carries it (**via nas.internal**), or shows a **no route** badge.
- **Status pages** — `http://flextunnel.internal/` through either proxy is the
  client's own status, answered locally without connecting anything;
  `http://flextunnel.internal/servers/<host>/` is that server's, with its
  tunnel set, host aliases and DNS forwards (opening it connects the
  destination). Both are listed in the window.
- **Connection path** — a modal that reports whether a connected destination
  is reached directly (hole-punched) or via relay.
- **Export / import** — move the destinations and forwards between machines
  via native save/open dialogs; the proxy ports stay behind. (Secrets are
  re-entered on import: neither an auth key nor a custom-relay auth token is
  written to the export file. An imported destination whose server is already
  here replaces that destination and keeps its key — and its relay token,
  unless the import changes its relays, in which case the token is cleared and
  the import says so. An imported forward replaces the one on the same local
  port. An import is all or nothing: a file that names a host or a server
  twice, or whose hosts or routes clash with the ones here, is refused whole.)

## The server

The app hosts one server. Its single-instance lock is keyed by the server's
identity and shared with the CLI, so a `flextunnel server` with the same
identity key cannot run at the same time; one with a different key can. Until
one is set up, "Set up server…" (in the sidebar or the tray) opens a welcome:
what a server is for and the three steps ahead — an identity, authorized
clients, what they reach — with a single *Set up server*.
Setup is then one step, the identity — a fresh one generated (*Regenerate*
rolls another), or an existing one imported to move a server here, either way
showing the endpoint id it gives — and *Create server* goes straight on to authorizing the first client.

- **Enabled** — the server's only on/off control: a switch in the server
  pane (and *Enable/Disable Server* in the tray); there is no separate
  Start/Stop. An enabled server runs: it starts with the app (at login or by
  hand), and as soon as it becomes startable — its first client authorized, a
  lost identity re-imported. Disabling stops it and keeps it stopped across
  launches until it is enabled again; after a failure, switching it off and
  on retries. *Delete server…* removes it and its identity for good.

- **Endpoint ID** — the server's public identity, shown in full at the top of
  its pane in a selectable field with a Copy button (and "Copy Endpoint ID" in
  the tray): it is what clients enter as the server node id.
- **Authorized clients** — a named list of client public keys
  (`ed25519-pub:…`, never a secret). Paste a key — or a whole authorized-key
  entry as `flexaccess-keys show-auth-key` prints it, whose comment then names
  the client — or pick one of this app's own keys. While the server runs, each
  client shows whether it is connected.
- **Identity** — the secret behind the endpoint id is generated at setup and
  never shown. Right under the endpoint id, *Replace identity…* generates or
  imports another, warning first that clients must then switch to the new
  endpoint id, and *Export key…* copies it to the clipboard (two clicks) to move
  the server to another computer. If the keychain loses it, the same place
  offers both ways on: *Import key…* to restore it and keep the endpoint id,
  or *Generate new identity…* when it is gone for good (clients then switch to
  the new endpoint id).
- **Tunnel set & relays** — the routed domains/CIDRs clients may reach through
  this server, enforced here, plus custom relays; optional, and edited any
  time. Clients route by their own lists, so a client must also list a route
  to send it here. This computer's own `localhost` is always reachable by its
  clients, under the host name each gives this server.
- **Restart to apply** — the server runs with the settings it started with;
  after a change (a client authorized, the tunnel set edited, a new identity)
  its pane offers *Restart now*. Removing a client applies at once: the server
  restarts without it (or stops, when it was the last one), so a revoked
  client can't keep connecting.

## Tray

Once the client has destinations, the menu shows its status line — running,
and how many destinations are connected right now — with Enable/Disable
Client; then the server's status line with Enable/Disable Server and Copy
Endpoint ID (or "Set Up Server…" while there is none). With an enabled server,
the icon shows the server's state — dimmed while it is down, a **dot** while
it is starting or stopping, and a **checkmark** while it runs (how many
clients are connected shows in the menu and the server pane); the client
doesn't change it then. Without a server, or with a disabled one, the app is
client-only: the icon is at full strength (dark on macOS) while the client is
running and dimmed otherwise, with no badge — except an **empty circle** for a
disabled server while the client is down. A running client counts as up
whether or not a destination is connected at the moment.

- **Live logs** — an in-app Logs pane; every log line (core internals
  included) is attributed to the client or the server, and can be filtered to
  either.
- **Start at login** — on by default: the first launch registers the app as a
  per-user login item (a LaunchAgent plist in `~/Library/LaunchAgents` on
  macOS, a `HKCU\…\CurrentVersion\Run` value on Windows — the same
  registrations the OS's own Login Items / Startup apps pages list and can
  switch off), and a checkbox in the tray menu ("Open at Login" on macOS,
  "Start with Windows") toggles it afterwards. Launched that way, the app
  starts in the tray without opening its window. A dev store
  (`FLEXTUNNEL_DEV_CONFIG` or `FLEXTUNNEL_KEYCHAIN=mock`) never touches the
  login item, so a debug or test binary neither becomes one nor re-points a
  real install's at itself.

## Where settings live

Settings live in `profiles.json` in the platform's local data directory.
Hosts, endpoint ids, routes, ports, forwards, relay URLs and public keys are
plaintext.
Auth-key secrets, the server identity key and relay auth tokens are sealed in
that file with AES-256-GCM. Only the random master key is kept in the system
keychain (macOS Keychain or Windows Credential Manager), under "Flextunnel Safe
Storage".

If the store cannot be loaded or unsealed, or its sealed format version differs,
the app blocks saves and offers **Quit** or **Start fresh**. Quit preserves the
file for recovery; Start fresh saves the reset state. A sealed-format mismatch
clears secrets and requires re-entering them; to keep them, quit and run the
build that wrote the file. If the store does not unseal because the Safe
Storage entry was deleted or replaced, quit and restore that entry.

> **Development escape hatch:** setting `FLEXTUNNEL_DEV_CONFIG` (to `1` or to an
> explicit file path) stores everything, secrets included, in a single plaintext
> JSON file, so an unsigned rebuild loop doesn't trigger the keychain access
> prompt on every launch. **Never set it for a real install** — the secrets are
> stored unencrypted.

> **Mock keychain for end-to-end tests:** `FLEXTUNNEL_KEYCHAIN=mock` keeps the
> real sealed store but holds its master key in an in-memory keychain instead
> of the system one, so an e2e or QA run never blocks on a keychain prompt
> (macOS asks again after every unsigned rebuild). The key is gone when the app
> quits, so the run uses a `mock-profiles.json` of its own, emptied at every
> start; the real keychain and `profiles.json` are never touched. Any other
> value is refused, and it can't be combined with `FLEXTUNNEL_DEV_CONFIG`.

## Install

Prebuilt, **unsigned** installers ship with each stable flextunnel release —
`flextunnel-desktop-macos-arm64.dmg` and `flextunnel-desktop-windows-amd64.msi`
on the [Releases page](https://github.com/flexaccessdev/flextunnel/releases).
Because they're unsigned you'll need to work around Gatekeeper (macOS) or
SmartScreen (Windows); the [main README](../../README.md#desktop-app-tray-gui-server-and-client)
covers the exact steps (the short version: download with `curl` rather than a
browser to avoid the quarantine / mark-of-the-web flag).

## Build from source

macOS and Windows only — the crate depends on platform keychain and tray
backends, its dependencies are gated to those targets, and its `build.rs`
refuses any other target. It is kept out of the workspace default members so a
server-side `cargo build` on Linux never touches it. Build it explicitly:

```sh
cargo build --release -p flextunnel-desktop
# binary: target/release/flextunnel-desktop
# locally built binaries aren't quarantined — no Gatekeeper/SmartScreen workaround needed
```

That produces the bare executable, **not** an app bundle — on macOS it will show
a Dock icon instead of running as a pure menu-bar app because it has no
`Info.plist`. For the proper bundle, build it the way CI does with
[`cargo-packager`](https://github.com/crabnebula-dev/cargo-packager) (macOS
`.app`/`.dmg`, Windows `.msi`):

```sh
cargo install cargo-packager        # or: cargo binstall cargo-packager
cargo packager --release -p flextunnel-desktop --formats app   # or wix
# bundle: target/release/flextunnel.app
```

The macOS `.dmg` comes from [`build-macos-dmg.sh`](../../build-macos-dmg.sh)
at the repo root (needs `brew install create-dmg`), which wraps that `.app` and
gives the mounted volume [`icons/dmg-volume.icns`](icons/dmg-volume.icns) — a
drive with the app icon on it. Regenerate that icon with
`uv run icons/make-dmg-volume-icon.py` after changing the app icon.

Requires a recent Rust toolchain (edition 2024).

## How it fits together

```
src/main.rs     entry point; boots the iced daemon and the tray
   app.rs       the daemon state machine (sidebar + detail pane + tray glue)
   view.rs      the window UI (sidebar, client + destination + server panes, modals)
   tray.rs      system-tray icon + client/server status menu
   server_session.rs  the in-process server: one session, connected clients
   autostart.rs login-item registration (LaunchAgent / Run key)
   tunnel.rs    background controller: the client session + the server session
   config.rs    settings persistence (profiles.json + the keychain master key)
   icon.rs      tray glyph rendered at runtime
   style.rs     iced theme
   logging.rs   log ring + file, lines attributed to client or server
```

For the tunnel protocol, transport, and security model, see the
[flextunnel README](../../README.md).
