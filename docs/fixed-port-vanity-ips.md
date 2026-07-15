# Fixed-port protocols on vanity IPs (manual workarounds)

Status: **documentation only — nothing here is implemented in flextunnel.**
These are manual, OS-level workarounds an operator can apply today.

Some protocols dictate their port and their clients cannot be told otherwise —
the canonical example is SMB: macOS Finder's `smb://host/` only ever connects
to port 445. To expose *several* remote SMB hosts through flextunnel forwards
on one machine, each remote needs its own local **vanity IP** (e.g. loopback
aliases like `169.254.10.10` or `127.0.0.2`) all answering on the same fixed
port.

The complication is that the host system may already run its own SMB server
bound to the wildcard (`0.0.0.0:445` — macOS File Sharing, Samba on Linux).
The vanity-IP listener must be **separate from that wildcard bind**. That
separation can happen at two layers, both achievable by hand.

## Prerequisite: create the vanity IP

- **macOS** — alias the loopback interface (not persistent across reboot; use
  a LaunchDaemon to re-add at boot):

  ```sh
  sudo ifconfig lo0 alias 169.254.10.10 255.255.255.255   # add
  sudo ifconfig lo0 -alias 169.254.10.10                  # remove
  ```

- **Linux** — the whole `127.0.0.0/8` already routes to loopback, so
  `127.0.0.2` needs **no setup at all**. For a `169.254.x.x` address:

  ```sh
  sudo ip addr add 169.254.10.10/32 dev lo
  ```

Prefer `127.x.y.z` addresses where possible: they behave identically for this
purpose but can never leave the box and cannot collide with a real link-local
address that an interface self-assigns when DHCP fails (`169.254.0.0/16` is
the IPv4 autoconfiguration range).

## Layer 1: the kernel socket table (specific-IP bind next to the wildcard)

The listener binds the fixed port on the vanity IP directly, coexisting with
the system service's wildcard socket.

- **macOS/BSD: works cleanly.** BSD semantics let a *new* socket with
  `SO_REUSEADDR` bind `169.254.10.10:445` even while smbd holds
  `0.0.0.0:445` — the kernel routes by most-specific match. Tokio sets
  `SO_REUSEADDR` by default on Unix, so a plain loopback-alias bind coexists
  with system SMB.
- **Linux: fragile.** Linux only permits the wildcard/specific overlap when
  **both** sockets set `SO_REUSEADDR` — yours *and* the pre-existing
  daemon's. Samba happens to set it, so it often works, but you're depending
  on the other service's socket options. The deterministic fix at this layer
  is reconfiguring the system service off the wildcard
  (`bind interfaces only = yes` + `interfaces = ...` in smb.conf), which is
  intrusive.

Two additional caveats at this layer:

- Ports below 1024 are privileged: the process binding `:445` needs root
  (macOS has no `setcap`; Linux can use
  `setcap cap_net_bind_service=+ep` on the binary or
  `sysctl net.ipv4.ip_unprivileged_port_start`).
- flextunnel's forward listeners currently bind loopback only
  (`crates/flextunnel-core/src/proxy/forward.rs` hardcodes `127.0.0.1`/`::1`),
  so using layer 1 with flextunnel would require per-forward bind-address
  support — **not implemented**. Layer 2 needs no app changes.

## Layer 2: rewrite packets before socket lookup (NAT)

Nothing ever binds the fixed port. The forward listens on an ordinary high
port (e.g. `127.0.0.1:10445`), and a firewall rule rewrites
`vanity-ip:445 → 127.0.0.1:10445` *before* the kernel consults the socket
table — so the system's wildcard `:445` socket never sees those packets. This
works with flextunnel's existing loopback listeners as-is.

- **macOS** — pf `rdr`. Local connections to a loopback alias traverse `lo0`:

  ```
  rdr pass on lo0 inet proto tcp from any to 169.254.10.10 port 445 -> 127.0.0.1 port 10445
  ```

  Add the rule (or an anchor) to `/etc/pf.conf` and load with
  `sudo pfctl -ef /etc/pf.conf`.

- **Linux** — nftables DNAT. Note the rule must be in the **`output`** hook
  (not just `prerouting`) for connections originating on the same machine,
  which is the typical `mount -t cifs` / file-manager case; for a
  loopback-scoped vanity IP only local traffic can reach it, so `output`
  alone suffices:

  ```
  table ip flextunnel {
      chain output {
          type nat hook output priority -100;
          ip daddr 169.254.10.10 tcp dport 445 dnat to 127.0.0.1:10445
      }
  }
  ```

This is the most robust "shared kernel" approach — no dependence on anyone's
socket options, no privileged-port bind, no app changes — at the cost of a
root-installed firewall rule.

## Recap

| | macOS | Linux |
|---|---|---|
| Vanity IP | `ifconfig lo0 alias` (not persistent) | `127.x.y.z` free; `ip addr add … dev lo` otherwise |
| Layer 1 (direct bind) | works (`SO_REUSEADDR` on the new socket suffices) | fragile (both sockets need `SO_REUSEADDR`) |
| Layer 2 (NAT to high port) | pf `rdr` | nftables `output`-hook DNAT |
| Works with current flextunnel | layer 2 only | layer 2 only |
