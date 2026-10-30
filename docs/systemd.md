# Running the CLI client under systemd

Run one user-unit instance per server. The CLI derives its lock and control
socket from the server id, so clients for different servers can coexist.

## Setup

Create one client config per instance, for example
`~/.config/flextunnel/aws.toml` and `~/.config/flextunnel/home.toml`. See
[`client.toml.example`](../client.toml.example). The optional `name` labels the
control panel; profiles may share an `auth_key_file` if each server authorizes
that key.

Save this template as `~/.config/systemd/user/flextunnel-client@.service`,
adjusting the executable path if needed:

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

```sh
systemctl --user daemon-reload
systemctl --user enable --now flextunnel-client@aws flextunnel-client@home

# Start at boot and keep running after logout:
loginctl enable-linger "$USER"
```

## Reconnects and process restarts

Leave `auto_reconnect` enabled and `max_reconnect_attempts` unset. The client
retries transient connection failures indefinitely, including the first
attempt, without exiting or rebinding its listeners. Retry delays double from
1s to 60s plus jitter; connection and handshake time add to that delay.
Repeated failures can rebuild the client endpoint. See the
[reconnect policy](architecture.md#reconnect-policy-client). Because the first
attempt is retried too, the unit needs no ordering on `network-online.target`
(which a user manager cannot order against anyway).

`Restart=on-failure` restarts a process that exits unsuccessfully. It also
retries errors that need operator action, such as an invalid config, rejected
key or occupied listener port. If a unit repeatedly restarts, inspect its
journal; an ordinary server outage should leave the process running in its
reconnect loop.

## Control panel and config changes

```sh
flextunnel client control -c ~/.config/flextunnel/aws.toml
```

Specify the instance config: a bare `client control` looks for
`~/.config/flextunnel/client.toml`, not `<instance>.toml`. Alternatively, use
`-n <server EndpointId>` to attach by server id. The same goes for
`client nc`, for example as an SSH `ProxyCommand`:

```
ProxyCommand flextunnel client nc -c ~/.config/flextunnel/aws.toml %h %p
```

The panel is read-only; `q` detaches without stopping the tunnel. To change
ports, forwards or other settings, edit the config and restart the instance:

```sh
systemctl --user restart flextunnel-client@aws
```

Two instances targeting the same server contend for the same lock. The second
fails and systemd retries it until the conflict is resolved; each instance
should target a different server.

## Logging

```sh
journalctl --user -u flextunnel-client@aws -f
```

For debug logs, run `systemctl --user edit flextunnel-client@aws` and add:

```ini
[Service]
Environment=RUST_LOG=flextunnel=debug
```
