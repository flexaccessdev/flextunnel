# Custom bind addresses for port forwards

Flextunnel binds proxies to `127.0.0.1` and built-in forwards to `127.0.0.1`
and `::1`. An external TCP adapter can expose a forward on another local
address, for example to give two remote databases the same local port or to
share one service with another machine.

Start with built-in forwards, whose targets must be in the server's routed
set:

```toml
[[forwards]]
local_port = 15432
remote_host = "db-a.internal"
remote_port = 5432

[[forwards]]
local_port = 25432
remote_host = "db-b.internal"
remote_port = 5432
```

Adapters below connect to these local ports. They do not perform SOCKS5
handshakes or change the forwards' server-direct routing.

## Multiple local addresses on Unix

On Linux, additional `127.x.y.z` loopback addresses can be bound directly. On
macOS, configure the addresses on `lo0` first:

```sh
sudo ifconfig lo0 alias 127.0.0.2 255.255.255.255
sudo ifconfig lo0 alias 127.0.0.3 255.255.255.255
```

Run one adapter per service, each in its own terminal:

```sh
socat TCP-LISTEN:5432,bind=127.0.0.2,reuseaddr,fork TCP:127.0.0.1:15432
socat TCP-LISTEN:5432,bind=127.0.0.3,reuseaddr,fork TCP:127.0.0.1:25432
```

Clients can now use `127.0.0.2:5432` and `127.0.0.3:5432`. Optional
`/etc/hosts` entries give them memorable names. Remove macOS aliases with:

```sh
sudo ifconfig lo0 -alias 127.0.0.2
sudo ifconfig lo0 -alias 127.0.0.3
```

These aliases do not persist across reboot; re-add them from a LaunchDaemon if
needed.

## Windows TCP adapter

Windows `netsh interface portproxy` forwards TCP between addresses and ports;
see [Microsoft's command reference](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy).
It cannot perform a SOCKS5 handshake, but can connect to a built-in flextunnel
forward.

Portproxy rules only take effect while the IP Helper service (`iphlpsvc`) is
running.

For example, in an elevated Command Prompt, expose the first database on an
address already assigned to this Windows machine (replace `192.168.1.10`):

```bat
netsh interface portproxy add v4tov4 ^
  listenaddress=192.168.1.10 listenport=15432 ^
  connectaddress=127.0.0.1 connectport=15432

netsh interface portproxy show all
```

For extra host-local addresses, add the Microsoft KM-TEST Loopback Adapter
(Device Manager → *Add legacy hardware* → *Network adapters* → *Microsoft* →
*KM-TEST Loopback Adapter*) and assign addresses to it, using the adapter's
name from `netsh interface show interface`:

```bat
netsh interface ipv4 add address "Ethernet 2" 169.254.10.10 255.255.0.0
```

Remote access also needs an appropriate Windows Firewall rule. Remove the
adapter when finished:

```bat
netsh interface portproxy delete v4tov4 listenaddress=192.168.1.10 listenport=15432
```

## Address, port and access constraints

- The adapter's listen address must be usable on the local host. Assigning a
  private or link-local address does not by itself guarantee host-only access;
  interface, routing and firewall settings determine reachability.
- Binding a LAN address or `0.0.0.0` exposes the service beyond loopback. The
  adapter adds no authentication; callers use the running client's tunnel.
- An existing wildcard listener can prevent binding a specific address on the
  same port. `reuseaddr` and `portproxy` do not guarantee coexistence. In
  particular, remapping a high port to `445` still requires portproxy to bind
  `445`; it does not bypass an existing SMB listener.
- Low-port permissions and reserved ports depend on the OS. On Linux, binding
  below 1024 needs root, `setcap cap_net_bind_service=+ep` on the adapter
  binary, or a lower `net.ipv4.ip_unprivileged_port_start`. Prefer unoccupied
  high ports when the client lets you choose one.

For proxy-aware apps, direct SOCKS5/HTTP use avoids the adapter. For a temporary
adapter that performs its own SOCKS5 handshake, see
[proxy usage](proxy-usage.md#adapters-for-programs-that-dont-speak-either-proxy).
