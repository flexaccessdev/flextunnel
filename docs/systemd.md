# Running the CLI client under systemd

One user unit runs one client, and one client reaches every server you list as
a destination in its config — connecting to each only when it is used. So a
single unit is the usual setup, however many servers you have.

## Setup

Create the client config at `~/.config/flextunnel/client.toml`, with a
`[[destinations]]` table per server. See
[`client.toml.example`](../client.toml.example). Destinations share the
top-level `auth_key_file` unless one names its own; every server must
authorize the key its destination uses.

Save this as `~/.config/systemd/user/flextunnel-client.service`, adjusting the
executable path if needed:

```ini
[Unit]
Description=flextunnel client

[Service]
ExecStart=%h/.local/bin/flextunnel client start -c %h/.config/flextunnel/client.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now flextunnel-client

# Start at boot and keep running after logout:
loginctl enable-linger "$USER"
```

### More than one client

A second client is only needed for a second set of local ports — say, a
separate SOCKS port for another browser profile. Each client needs its own
`name` in its config (it keys the lock and the control socket; the default is
`default`) and its own proxy and forward ports. A template unit keeps them
apart, one config per instance:

```ini
# ~/.config/systemd/user/flextunnel-client@.service
[Unit]
Description=flextunnel client (%i)

[Service]
ExecStart=%h/.local/bin/flextunnel client start -c %h/.config/flextunnel/%i.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

with `name = "work"` in `work.toml` and `name = "home"` in `home.toml`, then
`systemctl --user enable --now flextunnel-client@work flextunnel-client@home`.
Two instances with the same `name` contend for the same lock: the second fails
and systemd retries it until the conflict is resolved.

## Connections and process restarts

The client starts without connecting to anything, so the unit needs no ordering
on `network-online.target` (which a user manager cannot order against anyway).
A destination connects on its first use and disconnects again after
`idle_timeout_secs` without an open stream.

A server that is unreachable does not stop the process: requests for that
destination wait and are retried with backoff (delays double from 1s to 60s
plus jitter; connection and handshake time add to that), and fail if it does
not come back in time, while the other destinations carry on. A server that
rejects the client's key fails that destination's requests at once, and the
process still keeps running. See the
[connection policy](architecture.md#connection-policy-client).

`Restart=on-failure` restarts a process that exits unsuccessfully — which now
means something that needs operator action: an invalid config, an unreadable
key file, or an occupied listener port. If a unit repeatedly restarts, inspect
its journal. A server outage or a rejected key never shows up as a restart;
look at the control panel or the status page for those.

## Control panel and config changes

```sh
flextunnel client control
```

A bare `client control` finds the client from
`~/.config/flextunnel/client.toml`. For a client started from another config,
name that config with `-c`, or the client's name with `-n`:

```sh
flextunnel client control -c ~/.config/flextunnel/work.toml
flextunnel client control -n work
```

The same goes for `client nc`, for example as an SSH `ProxyCommand`:

```
ProxyCommand flextunnel client nc %h %p
```

The panel is read-only; `q` detaches without stopping the client. It shows each
destination's state — idle is normal: nothing has used it lately. The same
information is at `http://flextunnel.internal/status.txt` through the client's
proxy port.

To change destinations, ports, forwards or other settings, edit the config and
restart the unit:

```sh
systemctl --user restart flextunnel-client
```

## Logging

```sh
journalctl --user -u flextunnel-client -f
```

For debug logs, run `systemctl --user edit flextunnel-client` and add:

```ini
[Service]
Environment=RUST_LOG=flextunnel=debug
```
