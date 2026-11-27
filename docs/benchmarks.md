# Benchmarks

What a port forward or `client nc` can carry, what limits it, the one host
setting worth changing, and the measurements behind all three. The
measurements are kept to compare flextunnel with itself: one version against
another, on the same machines. They show proportions, not what your hardware
will do. How the data path is built is in
[architecture.md](architecture.md#5-byte-piping).

## v0.0.113 against v0.0.108

Mbit/s, down / up, one TCP connection through a port forward, 2026-11-26. In
each column the rows were measured in turn, round after round; the numbers
are medians. Each flextunnel row ran that version's release binary at both
ends.

| | Linux pair, as installed | UDP offload on | UDP buffer limit raised | Limit raised, offload on | macOS client | Windows client |
|---|---:|---:|---:|---:|---:|---:|
| No tunnel | 21141 / 21214 | 21229 / 21177 | 21048 / 21294 | 21307 / 21237 | 1946 / 2353 | 2102 / 2362 |
| flextunnel v0.0.108 | 2041 / 2032 | 2970 / 2912 | 2691 / 2682 | 3749 / 3728 | 1886 / 1295 | 1836 / 1658 |
| **flextunnel v0.0.113** | **2045 / 2037** | **2936 / 2930** | **2699 / 2644** | **3843 / 3766** | **1893 / 1310** | **1733 / 1661** |

Nothing between the two versions changes what carries a stream. What changed
is what a stream may buffer: its flow-control window now starts at 1.25 MB
and grows to 8 MiB while its reader keeps up, where v0.0.108 gave every
stream 8 MiB at once, and a peer is granted no streams it has no use for.
That is for memory, and [Long paths](#long-paths) has what it measured. The
rest of the five releases is around the data path: relay settings, a client
reconfigured in place, how an endpoint is closed. The table is here to show
what all of it costs, which is nothing that these machines can tell: the two
versions are within 2.5% of each other in every Linux column and neither is
ahead throughout. The macOS client's medians are within 1.2%. The Windows
client's downloads are 6% apart, on runs that ranged over a quarter of their
value for either version, and v0.0.113 was ahead in four rounds of ten
([Results](#macos-and-windows-clients-against-the-linux-server)).

## What sets the ceiling

A client holds one QUIC connection per destination, and a connection's
packets are built, encrypted and sent through one lock. Everything through a
destination — every forward, every `nc`, every proxied request — shares it,
so several transfers at once split what one would get rather than adding up.

Neither end of the Linux pair was short of CPU in any of its columns: each
process used 0.9 of a core as installed, 1.1 at 2.7 Gbit/s with the limit
raised and at most 1.25 at 3.8 Gbit/s, on machines of six. As installed, what
holds a transfer between two Linux machines is the kernel's limit on UDP
socket buffers, which the next section raises: the receiving kernel refused a
few hundred receives per run for want of buffer, and none once the limit was
raised ([Results](#results)). A connection that iroh has to carry over a
relay instead of directly is limited by the relay instead.

`client nc` runs behind a forward on the same path, 1.55 Gbit/s down and
1.75 up where the forward moved 2.1: its bytes make one more hop, between the
running client and the `nc` process.

## Linux: raise the UDP buffer limit

iroh asks the kernel for 7 MB UDP socket buffers. Linux grants at most
`net.core.rmem_max` / `net.core.wmem_max`, which default to 208 KB — about two
milliseconds of a gigabit. On a fast path the receive buffer then overflows
whenever the process is a moment late, QUIC sees loss, and the transfer slows
down. Between the two virtual machines here, raising the limits on both took
a transfer from 2.0 to 2.7 Gbit/s, and with 53 ms of round trip added between
them from 0.7 to 1.06 Gbit/s.

```sh
sudo sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000
```

To keep it across reboots:

```sh
printf 'net.core.rmem_max=7500000\nnet.core.wmem_max=7500000\n' | sudo tee /etc/sysctl.d/90-udp-buffers.conf
```

Restart flextunnel afterwards: the buffers are sized when its sockets open.
This is the only step here that needs root, and flextunnel runs without it —
only slower on paths fast enough to fill the default.

The limit can also be left alone and lifted for flextunnel only: a process
that holds `CAP_NET_ADMIN` gets the full buffers whatever the limit says.
flextunnel needs the capability for nothing else, and it is a broad one (it
covers the machine's network configuration), so grant it only where changing
the sysctl is not an option. In a systemd system unit that is
`AmbientCapabilities=CAP_NET_ADMIN` beside `User=`; a user unit cannot grant
it.

## Long paths

The two virtual machines are 0.4 ms apart, so nothing in the table shows what
distance costs. For this section each machine delayed its outgoing packets by
26.5 ms (`netem`, under the NIC's own transmit queues), which made the round
trip 53.5 ms; everything else is as in [Setup](#setup-2026-11-26). Runs of
20 s, in turn:

| 53 ms round trip, down / up | As installed | UDP buffer limit raised |
|---|---:|---:|
| flextunnel v0.0.108 | 745 / 732 | 1047 / 1076 |
| flextunnel v0.0.113 | 725 / 703 | 1054 / 1064 |

Fifteen rounds as installed, where a run's speed is set by when it loses
packets to the receive buffer (the ranges are under
[Results](#53-ms-round-trip)), and five with the limit raised.

A stream sends at most one flow-control window per round trip. Every stream
starts with a window of 1.25 MB, and the window doubles, up to 8 MiB, each
time half of it was read within two round trips (of 5 ms at least): that is,
while the reader keeps up with a sender the window is holding back. A bulk
transfer is therefore capped at 8 MiB ÷ RTT, about 1.2 Gbit/s at 53 ms, 640 Mbit/s at
100 ms, 320 Mbit/s at 200 ms, once three doublings have taken its window
there. Over this path that start cost nothing a 20 s run shows: with the
limit raised, where the window is what caps the rate, the two versions are
within 1.1% of each other.

The window is earned rather than given because it is also memory. A stream
whose reader is slower than the path, or has stopped reading, holds up to a
window of received data until it is read, and credit once granted cannot be
taken back. v0.0.108 granted every stream 8 MiB:

| Client memory, readers on one connection | v0.0.108 | v0.0.113 |
|---|---:|---:|
| 95 that never read | 1100–1247 MB | 185–188 MB |
| 95 that never read, 53 ms round trip | 1087–1174 MB | 213–262 MB |
| 30 that read 60 MB each at full speed and then stop, 53 ms round trip | 515–587 MB | 364–438 MB |

The client's resident memory after the readers had sat for 30 s, two runs of
each version in turn; an idle client holds about 20 MB. A reader is a TCP
connection to a forward whose far end sends for as long as it is taken, with
the reader's own socket buffer held to 256 KiB so that what piles up does so
in the tunnel.

What a connection's streams hold beyond their starting windows is limited to
64 MiB between them, returned as streams end. A connection carries the 100
bidirectional streams a server grants its client and no others: a client
grants its server none, and neither grants unidirectional ones. So either
end can be made to buffer about 183 MiB of stream data and no more.
A stream there is nothing left for keeps the window it has, and goes on
receiving at that.

The second row is that bound being approached, at 25–75 MB over the first:
on a long path the first megabytes of a stream go into the reader's socket
buffers within two round trips, which counts as keeping up, so streams that
then stall have grown first. How far depends on how much the sockets between
the client and its readers take. With the kernel's limit on TCP memory
(`net.ipv4.tcp_mem`) raised threefold on both machines, so that they took
more, both rows read 296–342 MB for v0.0.113, which is the 64 MiB spent, and
1196–1252 MB for v0.0.108.

The iOS client is the exception: the system ends an app that holds too much
memory, and a window that grew stays grown when its reader stalls, so its
windows stay at 1.25 MB until a device has been measured. Its downloads are
capped at 1.25 MB ÷ RTT (190 Mbit/s at 53 ms, 100 at 100 ms) and its streams
hold under 2 MB each. Uploads from it are not affected, since the window that
caps a direction is the receiver's.

QUIC's own limit across a connection's streams is not used. It is credit
that every stream draws on, the heartbeat included, so slow readers would
hold up the rest: enough stalled readers would take the heartbeat's credit
too, and with it the connection and every tunnel on it.

Congestion control is CUBIC, which grows its window by the clock rather than
by the round trip. After a loss on a long path it takes seconds to tens of
seconds to return to full speed, so a transfer that starts right after
another one in the opposite direction on the same destination can begin slow
and speed up as it goes.

## Setup (2026-11-26)

| | |
|---|---|
| Machines | `test1` (server, `10.22.40.61`) and `test2` (client, `10.22.40.62`): two KVM guests on the same physical host, joined by a virtual bridge |
| Host CPU | Intel Core i5-8400T (6 cores, no SMT); each guest has 6 vCPUs, so the two guests together overcommit the host 2:1 |
| Guest | Debian 13, kernel 6.12.118, 2 GB RAM |
| NIC | `virtio_net`, 6 queues (multi-queue), XPS at its default of one transmit queue per CPU, `tx-udp-segmentation` off by default |
| Kernel UDP buffer limit | `net.core.rmem_max` and `wmem_max` at their default of 212992 bytes, or raised to 7500000 where a column says so |
| flextunnel | v0.0.108 and v0.0.113 as released (the binaries of their GitHub releases), the same version at both ends, run as an unprivileged user; direct path, Cubic |
| Tool | iperf3 3.18, one TCP connection, 6 s per run after a 1 s warm-up; "up" is client to server, "down" is server to client (`-R`) |

A flextunnel run goes through a port forward: `iperf3 -s` listens on the
server's loopback, the client forwards a local port to it at
`<destination>.localhost.flextunnel.internal`, and `iperf3 -c` connects to
that local port. So the bytes cross a loopback TCP connection on each machine
and one QUIC stream between them. The "no tunnel" row connects to the
server's address on the bridge.

One test ran at a time, and the rows of a table were taken in turn, one
round after another: no tunnel, then the two versions, in an order that
alternated by round. Server and client were both restarted for every
flextunnel run, a run being one direction, and the destination was connected
before the run by reading a banner through a second forward, so that no bulk
went ahead of it. Every flextunnel run was on a direct path to the server's
address on the bridge, read off the client's log before the run and again
after it. That address was IPv4 or IPv6 as iroh chose: IPv4 for nearly every
run without the delay, either with it.

Anything else running on the physical host moves every row, and something
there runs on the quarter-hour: for two to three minutes from each one, every
row read 15–60% low, the no-tunnel one included. No run was started that
would reach into the four minutes around a quarter-hour, and the sixteen
rounds of a first pass that had were taken again in full.

## Results

Mbit/s, medians of ten rounds in the Linux pair's four tables. "Dropped" is
the median count of receives the receiving machine's kernel refused for want
of socket buffer during a run (`UdpRcvbufErrors`), on the client for a
download and on the server for an upload. One of them can be a batch of
datagrams. "CPU" is the flextunnel process's CPU time over a run divided by
the run's length, in cores, on the client and on the server.

### Linux pair, as installed

| | Down | Up | Dropped (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---:|---:|---:|---:|---:|
| No tunnel (TCP with TSO over the bridge) | 21141 | 21214 | | | |
| flextunnel v0.0.108 | 2041 | 2032 | 344 / 378 | 0.86 / 0.91 | 0.91 / 0.85 |
| flextunnel v0.0.113 | 2045 | 2037 | 344 / 242 | 0.86 / 0.90 | 0.90 / 0.85 |

Downloads ranged from 1963 to 2121 for v0.0.108 and from 2018 to 2141 for
v0.0.113, uploads from 1899 to 2139 and from 1956 to 2110.

### Linux pair, `tx-udp-segmentation` on

| | Down | Up | Dropped (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---:|---:|---:|---:|---:|
| No tunnel | 21229 | 21177 | | | |
| flextunnel v0.0.108 | 2970 | 2912 | 116 / 116 | 0.99 / 1.03 | 1.01 / 0.98 |
| flextunnel v0.0.113 | 2936 | 2930 | 108 / 100 | 0.99 / 1.03 | 1.02 / 0.98 |

`virtio_net` supports UDP segmentation offload but leaves it off by default
(`ethtool -K eth0 tx-udp-segmentation on`). With it on, a UDP GSO batch
crosses to the host as one buffer instead of being segmented in the guest.
It is a setting of the underlay NIC, outside any tunnel's control. The
buffer limit is at its default here. Downloads ranged from 2220 to 3059 for
v0.0.108 and from 2295 to 3081 for v0.0.113, uploads from 2233 to 2992 and
from 2410 to 3070: the low ends are the first two rounds, which were slow in
every row.

### Linux pair, UDP buffer limit raised

`net.core.rmem_max` and `net.core.wmem_max` at 7500000 on both machines, the
setting [recommended above](#linux-raise-the-udp-buffer-limit).

| | Down | Up | Dropped (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---:|---:|---:|---:|---:|
| No tunnel | 21048 | 21294 | | | |
| flextunnel v0.0.108 | 2691 | 2682 | 0 / 0 | 1.13 / 1.09 | 1.09 / 1.12 |
| flextunnel v0.0.113 | 2699 | 2644 | 0 / 0 | 1.12 / 1.10 | 1.08 / 1.11 |

Downloads ranged from 2635 to 2759 for v0.0.108 and from 2564 to 2799 for
v0.0.113, uploads from 2591 to 2791 and from 2554 to 2699. v0.0.108's upload
is nine rounds: in one its path moved to the machines' Tailscale address
during the run (1546), and that run is left out.

In this column an upload's path usually moved from IPv4 to IPv6 during the
run, on the same bridge: nine of v0.0.113's ten and four of v0.0.108's nine.
v0.0.108's four read 2630 against 2731 for its five that stayed on IPv4, and
v0.0.113's nine read 2647: a few percent at most, on four runs.

### Linux pair, buffer limit raised and `tx-udp-segmentation` on

| | Down | Up | CPU down (client / server) | CPU up (client / server) |
|---|---:|---:|---:|---:|
| No tunnel | 21307 | 21237 | | |
| flextunnel v0.0.108 | 3749 | 3728 | 1.13 / 1.25 | 1.25 / 1.12 |
| flextunnel v0.0.113 | 3843 | 3766 | 1.14 / 1.25 | 1.24 / 1.13 |

Nothing was dropped for want of buffer in any flextunnel run. Downloads
ranged from 3190 to 3910 for v0.0.108 and from 3038 to 3915 for v0.0.113,
uploads from 3162 to 3830 and from 3613 to 3903.

### 53 ms round trip

The delay of [Long paths](#long-paths) on both machines, runs of 20 s.

| | As installed (down / up) | Dropped (down / up) | Buffer limit raised (down / up) |
|---|---:|---:|---:|
| flextunnel v0.0.108 | 745 / 732 | 43 / 43 | 1047 / 1076 |
| flextunnel v0.0.113 | 725 / 703 | 57 / 68 | 1054 / 1064 |

As installed, fifteen rounds: downloads ranged from 583 to 866 for v0.0.108
and from 648 to 774 for v0.0.113, uploads from 540 to 857 and from 541 to
881. The medians are 3% and 4% apart inside ranges ten times that. With the
limit raised, five rounds: downloads from 942 to 1077 and from 985 to 1102,
uploads from 1011 to 1106 and from 987 to 1117. One v0.0.113 upload there
went to the Tailscale address (168) and was taken again. Each process used
0.3 of a core as installed and 0.3–0.4 with the limit raised.

### `client nc`

A 1500 MiB pipe of zeros through `flextunnel client nc` in each direction,
timed whole, with the forward measured in the same round for comparison.
Linux pair as installed, three rounds in turn:

| | Forward (down / up) | `client nc` (down / up) |
|---|---:|---:|
| flextunnel v0.0.108 | 2090 / 2113 | 1536 / 1782 |
| flextunnel v0.0.113 | 2116 / 2097 | 1557 / 1751 |

`nc`'s bytes make one more hop than a forward's, between the running client
and the `nc` process, and its figure includes attaching to the client and
opening the stream.

### macOS and Windows clients against the Linux server

One client at a time against the flextunnel server on `test1`, both ends as
installed. Unlike the Linux pair these cross a real network, and the "no
tunnel" row is what that path carries for one TCP connection, so read each
tunnel number against its own baseline.

| Client | | Down | Up | Client CPU, cores (down / up) |
|---|---|---:|---:|---:|
| macOS 26.7 VM (Apple M2 Max host, 8 vCPUs, arm64), behind its host's NAT | No tunnel | 1946 | 2353 | |
| | flextunnel v0.0.108 | 1886 | 1295 | 1.32 / 1.25 |
| | flextunnel v0.0.113 | 1893 | 1310 | 1.38 / 1.24 |
| Windows VM (build 26100, Hyper-V, 4 vCPUs, 2 GB, 2.5 Gbit/s link, another host) | No tunnel | 2102 | 2362 | |
| | flextunnel v0.0.108 | 1836 | 1658 | 1.31 / 1.12 |
| | flextunnel v0.0.113 | 1733 | 1661 | 1.23 / 1.10 |

Fifteen rounds for the macOS client and ten for the Windows one, taken as
the Linux pair's were, with iperf3 run on the client (3.21 on macOS, 3.22.1
on Windows). Every tunnel run was on a direct path to the server's own
address. Five macOS runs whose path went by the router's public address
instead were taken again.

Neither client tells the versions apart. On macOS v0.0.113 was ahead in
eight rounds of fifteen on downloads and nine on uploads. On Windows it was
ahead in four of ten on downloads and six on uploads: its downloads ranged
from 1435 to 1993 and v0.0.108's from 1547 to 2018, and the uploads from
1526 to 1735 and from 1478 to 1751.

What moves a macOS upload is the address family, which iroh picks per
connection. v0.0.108 read 1314 over IPv4 (eleven runs) and 1118 over IPv6
(four), v0.0.113 read 1316 (ten) and 1082 (five), and no run of one family
reached the other's range. Downloads did not show it. The macOS no-tunnel
download was within 0.6% on every run, which suggests a cap in the VM's NAT
path, and both versions' downloads are within 4% of it.

During an upload the server's kernel refused a median of 2759 receives for
want of socket buffer from the v0.0.108 macOS client and 2372 from the
v0.0.113 one, and 218 and 180 from the Windows client: a Linux client's
upload costs it a few hundred.

## Opportunities left

What these runs left open, with what is known about each. None of it is
scheduled work.

- **The receive buffer with neither the sysctl nor a capability.** As
  installed, a transfer is held at about 2 Gbit/s by a 208 KB socket buffer,
  and the full buffer is worth another 30%. Both ways to get it need root
  once. Nothing was tried for a process that has neither, such as draining
  the socket from a thread of its own so that less waits in the kernel.
- **Where the time goes.** Neither end is short of CPU at any rate measured
  here (1.1 cores a side at 2.7 Gbit/s), so what bounds a transfer once the
  loss is gone is how quickly data is handed from task to task: the splice,
  the connection's driver, the endpoint's driver, and the same three on the
  far side for the ACK that lets the next window go. It was not profiled.
- **Sends filled to the UDP payload.** The noq fork sends up to 32 datagrams
  per UDP send. For ezvpn, about 45 (what one UDP payload holds) measured 3%
  to 5% above that; the fork's byte bound would still need to respect the
  relay frame limit. Not measured for flextunnel.
- **Worker count off these VMs.** The runtime has two workers, chosen on
  guests that overcommit their host two to one. A dedicated machine, or a
  server with many busy clients, may want a different number;
  `TOKIO_WORKER_THREADS` is the knob.
- **macOS uploads.** A macOS client's upload is 1.3 Gbit/s on a path that
  carries 2.35, at 1.25 cores, and 1.1 when its path is IPv6. It was not
  profiled. The server refuses ten times the receives during one that it
  does for a Linux client, so its buffer limit may be part of it; that was
  not measured with the limit raised. ezvpn's notes on the same machine put
  what is left of a macOS sender's time in one `sendmsg` per datagram, which
  has no batched form there.
- **Windows is not profiled.** Its download is 1.7–1.8 Gbit/s on a path
  that carries 2.1 and its upload 1.66 on one that carries 2.36, at 1.1–1.3
  cores. Nothing is known about where its time goes.
- **iOS is unmeasured.** The library runs on the same forks and worker
  count, and nothing here ran on a device. That is also why its stream
  windows do not grow: how much a device lets the app hold before the system
  ends it would say what budget, if any, it could be given.

## Reproducing

Start a server on one machine with `iperf3 -s -B 127.0.0.1` beside it, and on
the other a client whose config forwards a local port to it. The client needs
a key the server authorizes: generate one with
`flexaccess-keys generate-auth-key "bench" -o client.key`, and add the public
entry that `flexaccess-keys show-auth-key --private-key-file client.key`
prints to the server's authorized-keys file (the README's
[quick start](../README.md#quick-start) has both configs in full).

```toml
auth_key_file = "./client.key"

[[destinations]]
name = "t1"
server_node_id = "<server endpoint id>"

[[forwards]]
local_port = 5301
remote_host = "t1.localhost.flextunnel.internal"
remote_port = 5201
```

Then, on the client machine:

```bash
iperf3 -t 6 -O 1 -c 127.0.0.1 -p 5301        # up
iperf3 -t 6 -O 1 -c 127.0.0.1 -p 5301 -R     # down
```

The first connection through the forward is what connects to the server, and
it may start on a relay. Connect it first and wait for a direct path: with
`RUST_LOG=info,iroh=warn,tracing=warn,flextunnel_core::transport::paths=debug`
the client logs a `Connection: Direct …` line when it has one. A run that
begins on a relay measures the relay. These runs connected it through a
second forward, to the server's sshd, by reading its banner, so that no bulk
went ahead of a run.

The host settings behind the columns:

```bash
sudo sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000   # buffer limit raised
sudo ethtool -K eth0 tx-udp-segmentation on                           # UDP offload on
```

Restart flextunnel after the first: the buffers are sized when its sockets
open.

The `client nc` rows piped `head -c 1500M /dev/zero` into
`flextunnel client nc <host> <port>` toward a listener that discards
(`nc -l -d >/dev/null`), and read the same amount back from one that sends it
(`head -c 1500M /dev/zero | nc -l -N`) with `client nc`'s stdin held open,
because that listener stops sending once it sees the client's half-close.

The 53 ms rows delayed each machine's outgoing packets under the NIC's
transmit queues, so that those stay as they are:

```bash
sudo tc qdisc replace dev eth0 root handle 1: mq
for q in 1 2 3 4 5 6; do sudo tc qdisc replace dev eth0 parent 1:$q netem delay 26.5ms limit 200000; done
sudo tc qdisc del dev eth0 root    # afterwards
```

If the machines share another network (these are also on a tailnet), iroh
may take that as its direct path, at the start or during a run, and more
readily once the two are equally far. Check the address in the last
`Connection: Direct …` line after a run as well as before it.

The memory rows need a second forward, to a listener on the server machine
that writes to every connection for as long as it is taken. Open the readers
against that forward with a small `SO_RCVBUF`, read as much as the row says
and then stop without closing, and read the client's `VmRSS` from
`/proc/<pid>/status` once it has stopped climbing.

`nstat -az UdpRcvbufErrors Udp6RcvbufErrors` before and after a run gives
the dropped count, and the process's CPU time is the sum of the 14th and
15th fields of `/proc/<pid>/stat`, in clock ticks.
