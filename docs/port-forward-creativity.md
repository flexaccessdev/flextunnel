# Port-forwarding creativity: adapters aren't limited to localhost

Status: **documentation only — nothing here is a flextunnel feature.** These are
manual, OS-level tricks an operator can apply today using ordinary tools.

flextunnel's own local front-ends all bind **loopback only** — the SOCKS5 and
HTTP proxies listen on `127.0.0.1`, and server-direct forwards hardcode
`127.0.0.1`/`::1` (`crates/flextunnel-core/src/proxy/forward.rs`). That is a
deliberately conservative default, not a limit on what you can build *in front
of* the proxy.

The adapters from ["Adapters for programs that don't speak either
proxy"](proxy-usage.md) — `socat` and `ssh -L` — take an **arbitrary local bind
address**, not just `127.0.0.1`. Once you realize the listener address is a free
variable, a lot of otherwise-awkward situations become one-liners:

- run *several* remotes that each demand the **same fixed port** (SMB's 445,
  a hardcoded RDP 3389, a database that only knows one port) — give each its own
  local IP;
- keep a **stable, memorable IP per service** so `/etc/hosts` names map cleanly;
- coexist with a **local service already holding that port**;
- **share** a forward with other machines on your LAN.

The bind address just has to be one the OS will let you listen on. That's a
surprisingly large space.

## The address space you can bind

### `127.0.0.0/8` — the whole loopback block

The entire `127.0.0.0/8` is loopback, not just `127.0.0.1`. That's ~16.7M
addresses that can never leave the machine.

- **Linux** — the whole `/8` already routes to `lo` with **no setup at all**.
  `127.0.0.2`, `127.0.0.3`, `127.9.9.9` … are all immediately bindable.
- **macOS/BSD** — only `127.0.0.1` is configured by default; alias each extra
  address onto `lo0` first (see below).
- **Windows** — does **not** hand you the whole `/8` the way Linux does; binding
  a listener to `127.0.0.2` etc. is unreliable and version-dependent. For extra
  local addresses use the Microsoft KM-TEST Loopback Adapter, or the built-in
  `netsh interface portproxy` forwarder (both below).

Prefer `127.x.y.z` addresses whenever they'll do: they behave identically for
this purpose, can never escape the box, and can't collide with anything *on the
network*. (They can still clash *locally* — a process already holding that
address/port, or a wildcard listener on the same port; see the collision caveat
below.)

### `169.254.0.0/16` — link-local

RFC 3927 link-local addresses always stay on the same link — they are never
routed beyond it — but *how far* one reaches depends on which interface it's
assigned to:

- **host-local** — assigned to `lo` (Linux) or the KM-TEST loopback adapter
  (Windows), a `169.254.x.x` address is reachable only from this machine, just
  like a `127.x` one. On **Windows**, where `127.x` aliasing is awkward, this
  (or a spare private address on KM-TEST) is often the *easier* choice than a
  loopback alias.
- **LAN-shared** — to make the forward reachable from *another box* on the link,
  assign the address to the actual **LAN interface** instead of `lo`/KM-TEST
  (e.g. `sudo ip addr add 169.254.10.10/24 dev eth0`).

Either way it's the IPv4 autoconfiguration range, so a real interface may
self-assign a `169.254.x.x` address when DHCP fails and collide with yours;
reach for `127.x.y.z` unless you specifically need on-link reachability.

### A real LAN address

Binding the adapter to your machine's LAN IP (or `0.0.0.0`) exposes the forward
to **other machines**. That turns your laptop into a small gateway into the
tunnel — convenient, but there is no auth on the adapter, so only do it on a
network you trust.

## Creating a vanity IP

- **macOS** — alias the loopback interface (not persistent across reboot; use a
  LaunchDaemon to re-add at boot):

  ```sh
  sudo ifconfig lo0 alias 127.0.0.2 255.255.255.255    # add
  sudo ifconfig lo0 -alias 127.0.0.2                   # remove
  ```

- **Linux** — `127.x.y.z` needs nothing. For a `169.254.x.x` address:

  ```sh
  sudo ip addr add 169.254.10.10/32 dev lo
  ```

- **Windows** — there is no `lo0`-style alias for `127.x`. Add a virtual NIC —
  the **Microsoft KM-TEST Loopback Adapter** (Device Manager → *Add legacy
  hardware* → *Network adapters* → *Microsoft* → *KM-TEST Loopback Adapter*, or
  scripted with `pnputil` / `devcon install`) — then assign addresses to it:

  ```bat
  netsh interface ipv4 add address "Ethernet 2" 169.254.10.10 255.255.0.0
  ```

  Replace `"Ethernet 2"` with the adapter's name from
  `netsh interface show interface`. A link-local or spare private address suits
  this adapter better than a `127.x` one.

### Windows without a loopback adapter: `netsh portproxy`

Windows ships a built-in TCP forwarder, `netsh interface portproxy`, that
listens on an arbitrary local address/port and forwards to another IP:port (it
needs the IP Helper service, `iphlpsvc`, running). It **can't speak SOCKS5**, so
it can't do the tunnel hop itself — chain it in front of an adapter that can.
`ssh -L` is built into Windows OpenSSH; `socat` comes via MSYS2 / Cygwin / WSL.

For the "vanity IP on a fixed port" case, let `ssh -L` do the SOCKS hop on a
high loopback port, then have portproxy remap the vanity IP's fixed port onto
it:

```bat
rem  ssh -L 127.0.0.1:10445:nas-a.internal:445  (in a WSL/OpenSSH session)
netsh interface portproxy add v4tov4 ^
  listenaddress=169.254.10.10 listenport=445 ^
  connectaddress=127.0.0.1 connectport=10445
```

(`netsh interface portproxy show all` lists rules; `delete v4tov4
listenaddress=… listenport=…` removes one.)

> The Windows paths here were not tested; loopback-bind behavior in particular
> varies by build, so verify on your version.

## Pattern: many remotes, one fixed port

Some protocols dictate their port and their clients can't be told otherwise —
the canonical example is SMB: macOS Finder's `smb://host/` only ever connects to
port 445. To reach *several* remote SMB hosts through flextunnel at once, give
each remote its own local IP, all listening on the same fixed port:

```sh
# each server-side host gets its own loopback IP, all on :445
socat TCP-LISTEN:445,bind=127.0.0.2,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:nas-a.internal:445
socat TCP-LISTEN:445,bind=127.0.0.3,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:nas-b.internal:445
```

Then `smb://127.0.0.2/` and `smb://127.0.0.3/` reach the two different servers,
each on the port the client insists on. Add `/etc/hosts` entries
(`127.0.0.2 nas-a`, `127.0.0.3 nas-b`) and it's `smb://nas-a/` and `smb://nas-b/`.

`ssh -L` does the same with its `bindaddr:port:host:port` form:

```sh
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' \
    -L 127.0.0.2:445:nas-a.internal:445 \
    -L 127.0.0.3:445:nas-b.internal:445 \
    user@jump.internal
```

### The fixed-port collision caveat

If the host system already runs its own service on that fixed port bound to the
**wildcard** (`0.0.0.0:445` — macOS File Sharing, Samba on Linux, the SMB server
on Windows), your specific-IP listener must coexist with it in the kernel socket
table:

- **macOS/BSD** — works cleanly. BSD routes by most-specific match, and a new
  socket with `SO_REUSEADDR` (which `socat`'s `reuseaddr` and Tokio both set)
  can bind `127.0.0.2:445` while smbd holds `0.0.0.0:445`.
- **Linux** — the overlap is only permitted when **both** sockets set
  `SO_REUSEADDR`, so you depend on the system daemon's socket options (Samba
  happens to set it). The deterministic fix is taking the system service off the
  wildcard (`bind interfaces only = yes` + `interfaces = …` in `smb.conf`),
  which is intrusive. Picking a port the host *isn't* already serving sidesteps
  the whole issue.
- **Windows** — no coexistence with SMB. The SMB server binds `445` in-kernel
  (via `srv2.sys`), so you cannot put a second listener on `445` alongside it —
  not even on a different local address. Use a **different port** and remap it
  with `netsh portproxy` (above), which is why the vanity-IP-on-a-fixed-port
  trick on Windows always routes through a high port.

Also: on Unix, ports below 1024 are privileged, so binding `:445` needs root
(macOS has no `setcap`; on Linux use `setcap cap_net_bind_service=+ep` on the
binary or lower `net.ipv4.ip_unprivileged_port_start`). Windows has no such
low-port restriction — any user can bind `445` — but you still hit SMB's
in-kernel bind above. Where the client lets you choose the port, a high port on
`127.0.0.1` avoids both the collision and the privilege problem.

## Pattern: a stable IP per service

Loopback aliases give each service a fixed address independent of whatever high
port the adapter happens to use. Map them in `/etc/hosts` and your tools address
services by name, with no port to remember:

```
127.0.0.10  db.internal
127.0.0.11  cache.internal
```

```sh
socat TCP-LISTEN:5432,bind=127.0.0.10,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:db.internal:5432
# then: psql -h db.internal      (resolves to 127.0.0.10 locally)
```

## Pattern: coexist with a local service on the same port

If you already run Postgres locally on `127.0.0.1:5432` but also want the
server-side Postgres on its native port, bind the adapter to a *different*
loopback IP instead of picking a new port:

```sh
socat TCP-LISTEN:5432,bind=127.0.0.20,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:nas.internal:5432
# local DB stays at 127.0.0.1:5432; the tunneled one is 127.0.0.20:5432
```

## Recap

| | macOS | Linux | Windows |
|---|---|---|---|
| Extra `127.x.y.z` | `ifconfig lo0 alias …` (not persistent) | free, no setup | unreliable — use a loopback adapter or `netsh portproxy` |
| `169.254.x.x` | `ifconfig lo0 alias …` | `ip addr add … dev lo` | KM-TEST loopback adapter + `netsh … add address` |
| Same fixed port, N remotes | one loopback IP per remote | same | one vanity IP per remote, each remapped via `netsh portproxy` |
| Wildcard-port collision | clean (new socket's `SO_REUSEADDR` suffices) | needs both sockets' `SO_REUSEADDR`, or move the system service | for SMB, blocked by its in-kernel `445` bind — use a different port + `portproxy` |
| Privileged port (<1024) | needs root | root, `setcap`, or lower `ip_unprivileged_port_start` | no low-port restriction |
| SOCKS-capable adapter | `socat`, `ssh -L` | `socat`, `ssh -L` | `ssh -L` (built-in OpenSSH); `socat` via MSYS2/Cygwin/WSL |

All of this rides on the flextunnel SOCKS5 proxy exactly as
[proxy-usage.md](proxy-usage.md) describes — the adapter is just choosing a more
interesting address than `127.0.0.1` to listen on.
