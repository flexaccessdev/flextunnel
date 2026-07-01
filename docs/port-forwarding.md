# Port forwarding through the flextunnel client

The flextunnel client exposes a local **SOCKS5** listener (default
`127.0.0.1:1080`) and tunnels only TCP `CONNECT`. Plenty of tools speak SOCKS5
natively (`curl -x socks5h://…`, Firefox, `git` with `ALL_PROXY`), but many
don't — database clients, RDP, JDBC drivers, `psql`, most GUI apps. For those,
put a small adapter in front of the SOCKS5 listener that presents a **plain
local TCP port** and forwards it through the proxy.

This guide covers two mainstream ways to do that:

1. **`socat`** — a plain local `host:port` → remote, no SSH account needed.
2. **`ssh`** — tunnel an SSH session *through* the proxy, then use SSH's own
   `-L` / `-D` forwards.

## The one rule: let the server resolve names

flextunnel's whole point is that DNS and the outbound connection happen on the
**server's** network. The server only accepts targets in its `routed_domains`
set and maps some of them via `[host_aliases]` (e.g. `networking.homelab` →
`127.0.0.1` on the server). Those names usually **do not resolve on the client
at all**.

So the adapter must send the target **hostname** to the proxy and let flextunnel
resolve it — the `socks5h` behavior. Never pre-resolve the name to an IP on the
client, and don't attach a client-side resolver. Both tools below do the right
thing by default; the notes call out where you could accidentally break it.

## 1. `socat` — plain TCP port forward

`socat`'s `SOCKS5-CONNECT` address dials a target *through* a SOCKS5 proxy and
sends the target as a **domain name** (verified: it emits SOCKS5 `ATYP=DOMAIN`,
so flextunnel resolves it server-side).

Address form:

```
SOCKS5-CONNECT:<socks-host>:<socks-port>:<target-host>:<target-port>
```

Example — expose the server-side `networking.homelab:80` as a local
`http://localhost:8080/`:

```sh
socat TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:networking.homelab:80
```

Then, with the flextunnel client running:

```sh
curl http://localhost:8080/
# or open http://localhost:8080/ in a browser
```

Example — expose a server-side Postgres as a local port:

```sh
socat TCP-LISTEN:5432,bind=127.0.0.1,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:nas.homelab:5432
# then: psql -h 127.0.0.1 -p 5432 …
```

Options that matter:

- **`fork`** — serve each incoming connection in its own child. Without it
  `socat` handles one connection and exits; browsers and most clients open
  several in parallel, so `fork` is effectively required.
- **`reuseaddr`** — lets you restart immediately without "address already in
  use".
- **`bind=127.0.0.1`** — keep the forward loopback-only. Drop it
  (`TCP-LISTEN:5432,reuseaddr,fork`) only if you deliberately want other
  machines on your LAN to reach it.
- **`SOCKS5`** is just an alias for `SOCKS5-CONNECT`.
- Add `-d -d` for verbose logs when debugging; `-T5` sets an idle timeout so
  stuck streams drop.

### Caveat: HTTP `Host` header

When you browse to `http://localhost:8080/`, the browser sends
`Host: localhost:8080`. A server that vhosts on `networking.homelab` may not
match. Either send the header explicitly:

```sh
curl -H 'Host: networking.homelab' http://localhost:8080/
```

…or skip the port forward entirely and use the SOCKS5-native path, which
preserves the real hostname:

```sh
curl -x socks5h://127.0.0.1:1080 http://networking.homelab:8080/
```

(or point the browser's SOCKS proxy at `127.0.0.1:1080` with remote DNS
enabled).

## 2. `ssh` through the SOCKS5 proxy

To reach an SSH server that only listens on the server's network, run SSH's
connection *through* the proxy with a `ProxyCommand`. OpenBSD `nc` (`netcat`)
speaks SOCKS5 with `-X 5 -x`:

```sh
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@workstation.homelab
```

`%h`/`%p` expand to the target host/port; `nc` sends `%h` as a hostname to the
proxy, so flextunnel resolves `workstation.homelab` server-side.

Make it permanent in `~/.ssh/config` so plain `ssh workstation` just works:

```
Host workstation
    HostName workstation.homelab
    User user
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

### Combine with SSH's own forwards

Once the SSH session rides the tunnel, you get SSH's forwarding for free — a
second hop *from the SSH host's* network:

```sh
# Local forward: localhost:5432 -> db.internal:5432, as seen from workstation.homelab
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' \
    -L 127.0.0.1:5432:db.internal:5432 user@workstation.homelab

# Dynamic (SOCKS) forward: a second SOCKS5 proxy scoped to the SSH host's network
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' \
    -D 127.0.0.1:1081 user@workstation.homelab
```

Here `db.internal` is resolved by `workstation.homelab`, not by flextunnel —
useful for reaching hosts that the flextunnel server itself can't see but the
SSH box can.

### `socat` vs `ssh`

- **`socat`** needs no account on the target — just the flextunnel proxy. Best
  for exposing a single service port (DB, web, RDP) to a local app.
- **`ssh`** needs an SSH account on a reachable host, but then gives you a
  shell plus arbitrary `-L`/`-D` forwards and an extra network hop.
```
