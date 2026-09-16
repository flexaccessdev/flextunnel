# Running the CLI client under systemd

The CLI client is strictly **one process per server**: a `client.toml` holds a
single `server_node_id`, and that id's prefix keys the client's on-disk
identity — the single-instance lock and the control socket — so clients for
different servers coexist with no extra configuration. The natural systemd shape for that is a **template unit**: one
`flextunnel-client@<name>` instance per server, each reading its own config
file. (This mirrors what the desktop app does inside one process — one
independent session per connected profile — the CLI just packages each session
as its own process.)

Everything here is a **user** unit; the client needs no root.

## Setup

One config file per server, named after the instance:

```
~/.config/flextunnel/aws.toml
~/.config/flextunnel/home.toml
```

Each is an ordinary client config (see
[`client.toml.example`](../client.toml.example)); the optional `name` key is a
good place to repeat the instance name so control panels and statuses label
themselves. Profiles can share one `auth_key_file` — the server side
authorizes the key, not the profile.

The template unit, at `~/.config/systemd/user/flextunnel-client@.service`:

```ini
[Unit]
Description=flextunnel client (%i)

[Service]
ExecStart=%h/.local/bin/flextunnel client start -c %h/.config/flextunnel/%i.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Then:

```sh
systemctl --user daemon-reload
systemctl --user enable --now flextunnel-client@aws flextunnel-client@home

# Start at boot instead of at first login, and survive logout:
loginctl enable-linger "$USER"
```

## Why `Restart=on-failure` is the whole restart policy

The client already supervises itself where it matters:

- Auto-reconnect (on by default) retries every failed connection attempt and
  every lost connection internally with exponential backoff (1s doubling to
  60s), indefinitely — the first attempt included. A server that is down
  when the unit starts, or a network that isn't up yet at boot, is waited
  out, not exited on: the client connects when the server appears, and there
  is no user-manager `network-online.target` to order against nor any need
  for one. A long outage costs one bounded connect attempt a minute.
  Reconnects that keep failing escalate to rebuilding the iroh
  endpoint from scratch (after the third failure, then at most every 30
  minutes) — the in-process equivalent of a unit restart, covering wedges (a
  dead relay link, stale path state) that only a fresh endpoint repairs. The
  process does not exit, so systemd never gets involved. Don't disable
  `auto_reconnect` or set `max_reconnect_attempts` under systemd — that just
  replaces the client's backoff with unit restarts, which re-bind listeners
  and drop held proxy requests.
- The client **exits nonzero** only on a permanent error: a rejected key, a
  bad node id, a malformed config, a proxy port taken by another process.
  `Restart=on-failure` + `RestartSec` will keep retrying that every
  `RestartSec` — harmless but noisy, and it never fixes itself. If an
  instance is flapping, read the reason with
  `journalctl --user -u flextunnel-client@<name>`; a client that is merely
  waiting for its server is not flapping, it is running, and
  `flextunnel client control` shows how far its retry loop has got.

## Interacting with a running instance

The control panel attaches over the client's control socket, which is keyed by
the server id — systemd isn't involved:

```sh
flextunnel client control -c ~/.config/flextunnel/aws.toml
```

The `-c` is not optional here: a bare `flextunnel client control` reads only
`~/.config/flextunnel/client.toml`, which this layout deliberately does not
have — each instance's profile is `<instance>.toml`. (Running it bare says so,
and lists the profile files it found.) `-n <server EndpointId>` attaches
without any config file.

Detaching (`q`) never affects the tunnel — the panel is read-only. Port
forwards are declared in the instance's config (`[[forwards]]` tables) and come
up with the unit; to change the set, edit the config and
`systemctl --user restart flextunnel-client@<name>`.

## Duplicate configs

Pointing two instance configs at the same `server_node_id` is the
misconfiguration the single-instance lock exists to catch: the second instance
fails to start (and, under `Restart=on-failure`, keeps retrying until the
first stops). Fix the config rather than relying on that takeover behavior.

## Logging

Logging goes to stderr and lands in the journal:

```sh
journalctl --user -u flextunnel-client@aws -f
```

Raise verbosity per instance with a drop-in
(`systemctl --user edit flextunnel-client@aws`):

```ini
[Service]
Environment=RUST_LOG=flextunnel=debug
```
