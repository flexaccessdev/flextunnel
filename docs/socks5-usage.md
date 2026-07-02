# Using the flextunnel SOCKS5 proxy

The flextunnel client exposes a local **SOCKS5** listener (default
`127.0.0.1:1080`) and tunnels TCP `CONNECT`. Anything that speaks SOCKS5 can be
pointed straight at it; anything that can't gets a small adapter in front.

> If a tool only speaks an **HTTP proxy** (or its SOCKS5 support resolves DNS
> client-side, which breaks routed internal names), run the client with
> `--http-listen 127.0.0.1:8081` and point the tool at `http://127.0.0.1:8081`
> — e.g. `https_proxy=http://127.0.0.1:8081`. Note this front-end currently
> tunnels **HTTPS (and other `CONNECT`) traffic only**; plain-HTTP requests are
> answered `501 Not Implemented`, so setting `http_proxy` won't help yet — use
> `socks5h://` (or a `socat` forward) for plain HTTP. See
> [`http-proxy-roadmap.md`](http-proxy-roadmap.md).

This guide covers, in order:

1. **The one rule** — always let the *server* resolve names.
2. **Programs that speak SOCKS5 natively** — `curl`, `wget`, `git`, `ssh`,
   browsers, and other common tools.
3. **`ssh` through the proxy** — reach an internal SSH host, then use SSH's own
   `-L` / `-D` forwards for a second hop.
4. **Adapters for programs that don't speak SOCKS5** — put a plain local TCP
   port in front of the proxy with `socat`.

## The one rule: let the server resolve names

flextunnel's whole point is that DNS and the outbound connection happen on the
**server's** network. The server only accepts targets in its `routed_domains`
set and maps some of them via `[host_aliases]` (e.g. `networking.internal` →
`127.0.0.1` on the server). Those names usually **do not resolve on the client
at all**.

So whatever you use must send the target **hostname** to the proxy and let
flextunnel resolve it — the `socks5h` behavior (the `h` means "resolve host at
the proxy"). Never pre-resolve the name to an IP on the client, and don't attach
a client-side resolver.

The single most common mistake is using `socks5://` (client-side DNS) where you
want `socks5h://` (proxy-side DNS). With flextunnel, **you almost always want
the `h`.**

## 1. Programs that speak SOCKS5 natively

### `curl`

```sh
# DNS + connection resolved server-side (note socks5h)
curl -x socks5h://127.0.0.1:1080 https://example.com

# a service on the SERVER's own localhost
curl -x socks5h://127.0.0.1:1080 http://127.0.0.1:8000/

# a host alias defined on the server
curl -x socks5h://127.0.0.1:1080 http://networking.internal/
```

You can also set it for a whole shell session via the standard proxy env vars
(most tools built on libcurl honor these):

```sh
export ALL_PROXY=socks5h://127.0.0.1:1080
curl https://example.com
```

### `wget` — no SOCKS support

GNU `wget` (tested with 1.25.0) **cannot use a SOCKS5 proxy**. Its `*_proxy`
environment variables only accept HTTP/HTTPS proxies — pointing them at the
SOCKS listener fails immediately:

```sh
$ https_proxy=socks5h://127.0.0.1:1080 wget http://networking.internal/
Error parsing proxy URL socks5h://127.0.0.1:1080: Unsupported scheme.
```

Use `curl -x socks5h://…` for one-off downloads, or a `socat` port forward
(section 3) if you specifically need `wget`:

```sh
socat TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:networking.internal:80 &
wget --header 'Host: networking.internal' -O file http://localhost:8080/file
```

### `git`

Git routes differently depending on the remote's transport — this catches
people out:

| Remote type | How to route through flextunnel |
|---|---|
| `http://` / `https://` | `ALL_PROXY` (git's libcurl transport honors it) |
| `ssh://` / `git@host:…` | SSH `ProxyCommand` — **`ALL_PROXY` is ignored** |

**HTTP(S) remotes** — `ALL_PROXY` works:

```sh
ALL_PROXY=socks5h://127.0.0.1:1080 git clone https://networking.internal/repo.git
```

Make it permanent for a host:

```sh
git config --global http.https://networking.internal/.proxy socks5h://127.0.0.1:1080
```

**SSH remotes** — `ALL_PROXY` does *nothing* here; git shells out to `ssh`,
which does its own DNS and would fail with `Could not resolve hostname`. Route
through SSH's `ProxyCommand` instead:

```sh
GIT_SSH_COMMAND='ssh -o "ProxyCommand=nc -X 5 -x 127.0.0.1:1080 %h %p"' \
  git clone ssh://networking.internal/repo.git
```

Or make it permanent in `~/.ssh/config` (see section 2) so plain
`git clone ssh://networking.internal/repo.git` just works:

```
Host networking.internal
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

### Web browsers

Point the browser's SOCKS proxy at `127.0.0.1:1080` **with remote DNS enabled**
so hostnames resolve on the server:

- **Firefox** — set a manual SOCKS v5 proxy of `127.0.0.1:1080` in its network
  settings, and enable the option to proxy DNS through SOCKS v5 so hostnames
  resolve on the server rather than locally.
- **Chrome / Chromium** — configure a SOCKS5 proxy of `127.0.0.1:1080` (Chrome
  sends the hostname to the proxy, so DNS happens server-side).

For per-site control instead of a system-wide switch, a browser extension like
FoxyProxy lets you route only the internal domains through `127.0.0.1:1080`.

> These browser paths were not tested here; verify the exact settings in your
> browser version.

### Other tools worth knowing

- **`nc` (OpenBSD netcat)** — `nc -X 5 -x 127.0.0.1:1080 host port` dials
  through SOCKS5 (used as the SSH `ProxyCommand` below).
- **`proxychains-ng`** — wraps programs that have no proxy option of their own
  by hooking libc. Point it at `127.0.0.1:1080`. It can miss statically linked
  or Go binaries, where a `socat` port forward is more reliable. (Not tested
  here.)
- **Package managers / language toolchains** (`pip`, `npm`, `cargo`, `apt`)
  generally honor the `ALL_PROXY` / `https_proxy` environment variables; prefer
  the `socks5h://` form. (Not tested here — consult each tool's proxy docs.)

## 2. `ssh` through the SOCKS5 proxy

To reach an SSH server that only listens on the server's network, run SSH's
connection *through* the proxy with a `ProxyCommand`. OpenBSD `nc` (`netcat`)
speaks SOCKS5 with `-X 5 -x`:

```sh
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@workstation.internal
```

`%h`/`%p` expand to the target host/port; `nc` sends `%h` as a hostname to the
proxy, so flextunnel resolves `workstation.internal` server-side.

Make it permanent in `~/.ssh/config` so plain `ssh workstation` just works (and
so `git@workstation:…` remotes route through the tunnel too):

```
Host workstation
    HostName workstation.internal
    User user
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

### Combine with SSH's own forwards

Once the SSH session rides the tunnel, you get SSH's forwarding for free — a
second hop *from the SSH host's* network:

```sh
# Local forward: localhost:5432 -> db.internal:5432, as seen from workstation.internal
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' \
    -L 127.0.0.1:5432:db.internal:5432 user@workstation.internal

# Dynamic (SOCKS) forward: a second SOCKS5 proxy scoped to the SSH host's network
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' \
    -D 127.0.0.1:1081 user@workstation.internal
```

Here `db.internal` is resolved by `workstation.internal`, not by flextunnel —
useful for reaching hosts that the flextunnel server itself can't see but the
SSH box can.

## 3. Adapters for programs that don't speak SOCKS5

Database clients, RDP, JDBC drivers, `psql`, and many GUI apps have no SOCKS5
option. Put `socat` in front of the proxy to present a **plain local TCP port**
that forwards through it.

`socat`'s `SOCKS5-CONNECT` address dials a target *through* a SOCKS5 proxy and
sends the target as a **domain name** (it emits SOCKS5 `ATYP=DOMAIN`, so
flextunnel resolves it server-side).

Address form:

```
SOCKS5-CONNECT:<socks-host>:<socks-port>:<target-host>:<target-port>
```

Example — expose the server-side `networking.internal:80` as a local
`http://localhost:8080/`:

```sh
socat TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:networking.internal:80
```

Then, with the flextunnel client running:

```sh
curl http://localhost:8080/
# or open http://localhost:8080/ in a browser
```

Example — expose a server-side Postgres as a local port:

```sh
socat TCP-LISTEN:5432,bind=127.0.0.1,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:nas.internal:5432
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
`Host: localhost:8080`. A server that vhosts on `networking.internal` may not
match. Either send the header explicitly:

```sh
curl -H 'Host: networking.internal' http://localhost:8080/
```

…or skip the port forward entirely and use the SOCKS5-native path, which
preserves the real hostname:

```sh
curl -x socks5h://127.0.0.1:1080 http://networking.internal:8080/
```

(or point the browser's SOCKS proxy at `127.0.0.1:1080` with remote DNS
enabled).

### `socat` vs `ssh`

- **`socat`** needs no account on the target — just the flextunnel proxy. Best
  for exposing a single service port (DB, web, RDP) to a local app.
- **`ssh`** needs an SSH account on a reachable host, but then gives you a
  shell plus arbitrary `-L`/`-D` forwards and an extra network hop.
