# flextunnel-desktop

The native desktop app for [flextunnel](../..) — a system-tray app for **macOS
and Windows** with two roles of equal weight, either one optional:
**connections** to any number of flextunnel servers elsewhere, and this
computer's own **server**, run in-process. Nothing ever needs a terminal.

It embeds [`flextunnel-core`](../flextunnel-core) directly (no FFI layer) and is
built on [iced](https://iced.rs/)'s daemon runtime: the process lives in the
menu bar / system tray and keeps running with no window open, so closing the
window loses nothing — the tray owns the lifecycle and re-opens it on demand.

```
┌── tray / menu bar ─────────────────┐   ┌──────────── window ─────────────────┐
│ Open flextunnel…                    │   │ CONNECTIONS   +   home-lab ● conn.  │
│ Connections: 1 of 2 connected       │   │ ● home-lab        SOCKS 1080        │
│ Server running · 2 clients connected│ ⇄ │ ○ staging         PORT FORWARDS     │
│ Disable Server                      │   │ SERVER            ● db  5432        │
│ Copy Endpoint ID                    │   │ ● This computer                     │
│ ☑ Open at Login                     │   │ Keys · Logs                         │
│ Quit flextunnel                     │   │                                     │
└─────────────────────────────────────┘   └─────────────────────────────────────┘
```

## First launch

With nothing set up, the window opens with nothing selected, pointing at the
sidebar: there is no role to pick. Either is set up from there whenever wanted
— "+" next to Connections, or "Set up server…", which opens the server's
welcome first.

## Client connections

Each **connection profile** is the desktop equivalent of a `client.toml` — a
server `EndpointId`, an auth key, and the local front-ends you want. Profiles are
independent: any number can be connected at once, and each runs its own tunnel
session with its own optional local **SOCKS5** and **HTTP** proxy listeners plus
its own **server-direct port forwards**. Connecting is always manual.

- **Shared auth keys** — the Keys pane holds this computer's client keypairs;
  any number of profiles can use the same one. Each server a key connects to
  must authorize its public half.
- **Local SOCKS5 / HTTP proxies** — enable either or both per profile; point any
  proxy-aware app at `127.0.0.1:<port>` and its traffic to routed targets rides
  the tunnel.
- **Port forwards** — bind a local port to any `host:port` on the server's
  network so tools that can't use a proxy reach private services as if local.
- **Connection path** — a modal that reports whether a connected profile is
  reaching the server directly (hole-punched) or via relay.
- **Export / import** — move profiles between machines via native save/open
  dialogs. (Secrets are re-entered on import: neither the auth token nor the
  custom-relay auth token is written to the export file. Importing over an
  existing profile — matched by server id — keeps that profile's secrets.)
- **Auto-reconnect** — sessions re-establish the tunnel when the path drops.

## The server

The app hosts one server per user — the per-user server lock is shared with the
CLI, so a `flextunnel server` running on the same account counts too. Until
one is set up, "Set up server…" (in the sidebar or the tray) opens a welcome:
what a server is for and the three steps ahead — an identity, authorized
clients, what they reach — with *Set up server* and *Move a server here…*.
Setup is then one step, the identity — a fresh one generated, or an existing
one imported to move a server here, either way showing the endpoint id it
gives — and *Create server* goes straight on to authorizing the first client.

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
- **Tunnel set & relays** — the routed domains/CIDRs pushed to clients and
  enforced here, plus custom relays; optional, and edited any time.
- **Restart to apply** — the server runs with the settings it started with;
  after a change (a client authorized, the tunnel set edited, a new identity)
  its pane offers *Restart now*. Removing a client applies at once: the server
  restarts without it (or stops, when it was the last one), so a revoked
  client can't keep connecting.

## Tray

The menu shows the connections' aggregate line, then the server's status line
with Enable/Disable Server and Copy Endpoint ID (or "Set Up Server…" while
there is none). With an enabled server, the icon shows the server's state —
dimmed while it is down, a **dot** while it is starting or stopping, and a
**checkmark** while it runs (how many clients are connected shows in the menu
and the server pane); client connections don't change it then. Without a
server, or with a disabled one, the app is client-only: the icon is at full
strength (dark on macOS) while a connection is up and dimmed otherwise, with no
badge — except an **empty circle** for a disabled server while no connection is up.

- **Live logs** — an in-app Logs pane; every session's log lines (core
  internals included) are attributed to the server or their profile.
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

Everything is stored in one `profiles.json` in the platform's local data
directory. Non-secret data (names, server ids, ports, forwards, relay URLs,
public keys — the server's endpoint id and authorized clients included) is
plaintext. The **secrets** — auth-key secrets, the server's
identity key, and the custom-relay auth tokens of profiles and the server —
are sealed in the same file with AES-256-GCM under a random master key that is
the one entry kept in the system keychain (**macOS Keychain** or the **Windows
Credential Manager**), named "Flextunnel Safe Storage". The sealed secrets
carry a format version: an update that changes what is sealed bumps it, and
then starts every secret fresh — re-enter the auth-key secrets, the server
identity and the relay tokens — rather than loading some and not others.

> **Development escape hatch:** setting `FLEXTUNNEL_DEV_CONFIG` (to `1` or to an
> explicit file path) stores everything, tokens included, in a single plaintext
> JSON file, so an unsigned rebuild loop doesn't trigger the keychain access
> prompt on every launch. **Never set it for a real install** — the tokens are
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
cargo packager --release -p flextunnel-desktop --formats app   # or dmg / wix
# bundle: target/release/flextunnel.app
```

Requires a recent Rust toolchain (edition 2024).

## How it fits together

```
src/main.rs     entry point; boots the iced daemon and the tray
   app.rs       the daemon state machine (sidebar + detail pane + tray glue)
   view.rs      the window UI (sidebar, server + profile panes, modals)
   tray.rs      system-tray icon + connections/server status menu
   server_session.rs  the in-process server: one session, connected clients
   autostart.rs login-item registration (LaunchAgent / Run key)
   tunnel.rs    background controller: the server + one session per profile
   config.rs    profile persistence (profiles.json + keychain tokens)
   icon.rs      tray glyph rendered at runtime
   style.rs     iced theme
   logging.rs   per-profile log attribution
```

For the tunnel protocol, transport, and security model, see the
[flextunnel README](../../README.md).
