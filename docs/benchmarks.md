# Benchmarks

What a port forward or `client nc` can carry, what limits it, the one host
setting worth changing, and the measurements behind all three. The
measurements are kept to compare flextunnel with itself: one version against
the next, and one technique against another, on the same machines. They show
proportions, not what your hardware will do. How the data path is built is in
[architecture.md](architecture.md#5-byte-piping).

## v0.0.109 against v0.0.108

Mbit/s, down / up, one TCP connection through a port forward, 2026-11-23. In
each column the rows were measured in turn, round after round; the numbers
are medians. Each flextunnel row ran that version at both ends.

| | Linux pair, as installed | UDP offload on | UDP buffer limit raised | Limit raised, offload on | macOS client | Windows client |
|---|---:|---:|---:|---:|---:|---:|
| No tunnel | 21399 / 20768 | 20770 / 20679 | 20846 / 20576 | 21065 / 20965 | 1946 / 2353 | 2098 / 2369 |
| flextunnel v0.0.108 | 2067 / 2104 | 2892 / 2899 | 2632 / 2620 | 3766 / 3724 | 1844 / 1300 | 1862 / 1677 |
| **flextunnel v0.0.109** | **2011 / 2032** | **2929 / 2896** | **2622 / 2504** | **3611 / 3718** | **1862 / 1272** | **1944 / 1711** |

v0.0.109 changes what a stream may buffer, not what carries it. A stream's
flow-control window now starts at 1.25 MB and grows to 8 MiB while its reader
keeps up, where v0.0.108 gave every stream 8 MiB at once. That is for the
client's memory, and [Long paths](#long-paths) has what it measured. The
table is here to show what it costs: over all their rounds the two versions
are within 5% of each other in every column and neither is ahead throughout.
A single session put them further apart than that, by up to 7% in these
columns' Linux sessions, 15% on macOS uploads and 13% over a 53 ms path, and
the next session did not repeat it ([Results](#results)); two builds that behave the same were up to 2.4% apart
themselves
([Windows that grow on a short path too](#windows-that-grow-on-a-short-path-too)).

What the numbers themselves are made of came with v0.0.107: forks of iroh,
noq and netwatch carrying the changes ezvpn's forks do (the same commits, on
flextunnel's own branches), and two runtime worker threads where v0.0.106 ran
one per core. The netwatch fork's connected socket per peer is what the first
column is owed to, and all of what the macOS client gained; the other two
forks show once the NIC takes whole UDP batches or the kernel's limit on UDP
socket buffers is out of the way. Each is under "What the measurements
showed" below, measured against v0.0.106.

## What sets the ceiling

A client holds one QUIC connection per destination, and a connection's
packets are built, encrypted and sent through one lock. Everything through a
destination — every forward, every `nc`, every proxied request — shares it,
so several transfers at once split what one would get rather than adding up:
four streams through one forward moved what one did (the numbers are under
[More runtime threads were slower](#more-runtime-threads-were-slower)).

Neither end was short of CPU in any column of the table above (about one core
a side at 2.6 Gbit/s). As installed, what holds a transfer between two Linux
machines is the kernel's limit on UDP socket buffers, which the next section
raises. A connection that iroh has to carry over a relay instead of directly
is limited by the relay instead.

`client nc` runs behind a forward on the same path, 1.7 Gbit/s each way
where the forward moved 2.0: its bytes make one more hop, between the running
client and the `nc` process.

## Linux: raise the UDP buffer limit

iroh asks the kernel for 7 MB UDP socket buffers. Linux grants at most
`net.core.rmem_max` / `net.core.wmem_max`, which default to 208 KB — about two
milliseconds of a gigabit. On a fast path the receive buffer then overflows
whenever the process is a moment late, QUIC sees loss, and the transfer slows
down. Between the two virtual machines here, raising the limits on both took
a transfer from 2.0 to 2.6 Gbit/s, and with 53 ms of round trip added between
them from 677 to 1057 Mbit/s.

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
it. It measured the same as the raised limit
([The buffers without the sysctl](#the-buffers-without-the-sysctl)).

## Long paths

The two virtual machines are 0.4 ms apart, so nothing in the table shows what
distance costs. For this section each machine delayed its outgoing packets by
26.5 ms (`netem`, under the NIC's own transmit queues), which made the round
trip 53.5 ms; everything else is as in [Setup](#setup-2026-11-23). Runs of
20 s, in turn:

| 53 ms round trip, down / up | As installed | UDP buffer limit raised |
|---|---:|---:|
| flextunnel v0.0.108 | 653 / 658 | 1055 / 1075 |
| flextunnel v0.0.109 | 677 / 668 | 1057 / 1067 |

Fifteen rounds as installed, where a run's speed is set by when it loses
packets to the receive buffer (the ranges are under
[Results](#53-ms-round-trip)), and five with the limit raised.

A stream sends at most one flow-control window per round trip. Every stream
starts with a window of 1.25 MB, and the window doubles, up to 8 MiB, each
time half of it was read within two round trips (of 5 ms at least): that is,
while the reader keeps up with a sender the window is holding back. A bulk
transfer is
therefore capped at 8 MiB ÷ RTT, about 1.2 Gbit/s at 53 ms, 640 Mbit/s at
100 ms, 320 Mbit/s at 200 ms, and it has its 8 MiB within its first second:
second by second, a v0.0.109 transfer over this path was not told apart from
a v0.0.108 one.

The window is earned rather than given because it is also memory. A stream
whose reader is slower than the path, or has stopped reading, holds up to a
window of received data until it is read, and credit once granted cannot be
taken back. v0.0.108 granted every stream 8 MiB:

| Client memory, readers on one connection | v0.0.108 | v0.0.109 |
|---|---:|---:|
| 95 that never read | 1146–1169 MB | 173–190 MB |
| 95 that never read, 53 ms round trip | 1105–1139 MB | 255–262 MB |
| 30 that read 60 MB each at full speed and then stop, 53 ms round trip | 374–387 MB | 232–276 MB |

The client's resident memory after the readers had sat for 20 s or more, two
runs of each version in turn; an idle client holds about 20 MB. A reader is a
TCP connection to a forward whose far end sends for as long as it is taken,
with the reader's own socket buffer held to 256 KiB so that what piles up
does so in the tunnel.

What a connection's streams hold beyond their starting windows is limited to
64 MiB between them, returned as streams end. A connection carries the 100
bidirectional streams a server grants its client and no others: a client
grants its server none, and neither grants unidirectional ones. So either
end can be made to buffer about 183 MiB of stream data and no more.
The second row is presumably that bound being met, at about
70 MB over the first: on a long path the first megabytes of a stream go into
the reader's socket buffers within two round trips, which counts as keeping
up, so streams that then stall have grown until the 64 MiB was spent. A
stream there is nothing left for keeps the window it has, and goes on
receiving at that.

The iOS client is the exception: the system ends an app that holds too much
memory, and a window that grew stays grown when its reader stalls, so its
windows stay at 1.25 MB until a device has been measured. Its downloads are
capped at 1.25 MB ÷ RTT (190 Mbit/s at 53 ms, 100 at 100 ms) and its streams
hold under 2 MB each. Uploads from it are not affected, since the window that
caps a direction is the receiver's.

QUIC's own limit across a connection's streams is not used. It is credit
that every stream draws on, the heartbeat included, so slow readers would
hold up the rest: with such a limit of 128 MiB (v0.0.106, every stream at
8 MiB), 18 stalled readers made the client drop the connection and every
tunnel on it, and 24 readers taking 100 kB/s each made a new stream wait
3–15 s where it otherwise took 12 ms.

Congestion control is CUBIC, which grows its window by the clock rather than
by the round trip. After a loss on a long path it takes seconds to tens of
seconds to return to full speed, so a transfer that starts right after
another one in the opposite direction on the same destination can begin slow
and speed up as it goes.

## Setup (2026-11-23)

| | |
|---|---|
| Machines | `test1` (server, `10.22.40.61`) and `test2` (client, `10.22.40.62`): two KVM guests on the same physical host, joined by a virtual bridge |
| Host CPU | Intel Core i5-8400T (6 cores, no SMT); each guest has 6 vCPUs, so the two guests together overcommit the host 2:1 |
| Guest | Debian 13, kernel 6.12.117, 2 GB RAM |
| NIC | `virtio_net`, 6 queues (multi-queue), XPS at its default of one transmit queue per CPU, `tx-udp-segmentation` off by default |
| Kernel UDP buffer limit | `net.core.rmem_max` and `wmem_max` at their default of 212992 bytes, or raised to 7500000 where a column says so |
| flextunnel | v0.0.108 and v0.0.109, the same version at both ends, run as an unprivileged user; direct path, Cubic |
| Tool | iperf3 3.18, one TCP connection, 6 s per run after a 1 s warm-up; "up" is client to server, "down" is server to client (`-R`) |

A flextunnel run goes through a port forward: `iperf3 -s` listens on the
server's loopback, the client forwards a local port to it at
`<destination>.localhost.flextunnel.internal`, and `iperf3 -c` connects to
that local port. So the bytes cross a loopback TCP connection on each machine
and one QUIC stream between them. The "no tunnel" row connects to the
server's address on the bridge.

One test ran at a time. Anything else running on the physical host moves
every row (a busy moment halves all of them for a round), so the rows of a
table were taken in turn, one round after another, and the tunnel was
restarted for every flextunnel run. Every flextunnel run was on a direct
path, read off the client's log before the run began.

## Results

Mbit/s, medians. The Linux pair's tables are fifteen rounds each, from two
sessions of five and of ten, because five could not tell the versions apart:
in the sessions of five either was ahead by up to 7% (v0.0.109 by 6.6% on
downloads with offload on, v0.0.108 by 5.5% on uploads as installed), and
the sessions of ten had them within 3%. "Dropped"
is the median count of receives the receiving machine's kernel refused for
want of socket buffer during a run (`UdpRcvbufErrors`), on the client for a
download and on the server for an upload. One of them can be a batch of
datagrams.

### Linux pair, as installed

| | Down | Up | Dropped (down / up) |
|---|---:|---:|---:|
| No tunnel (TCP with TSO over the bridge) | 21399 | 20768 | |
| flextunnel v0.0.108 | 2067 | 2104 | 429 / 1126 |
| flextunnel v0.0.109 | 2011 | 2032 | 379 / 1021 |

The session of five had v0.0.109 behind (1969 / 2002 against 2060 / 2118)
and the session of ten had them level (2070 / 2042 against 2070 / 2039).

### Linux pair, `tx-udp-segmentation` on

| | Down | Up | Dropped (down / up) |
|---|---:|---:|---:|
| No tunnel | 20770 | 20679 | |
| flextunnel v0.0.108 | 2892 | 2899 | 111 / 171 |
| flextunnel v0.0.109 | 2929 | 2896 | 101 / 169 |

`virtio_net` supports UDP segmentation offload but leaves it off by default
(`ethtool -K eth0 tx-udp-segmentation on`). With it on, a UDP GSO batch
crosses to the host as one buffer instead of being segmented in the guest.
It is a setting of the underlay NIC, outside any tunnel's control. The
buffer limit is at its default here. By session: 2941 / 2881 against 2760 /
2856 in the five, 2908 / 2900 against 2906 / 2937 in the ten.

### Linux pair, UDP buffer limit raised

`net.core.rmem_max` and `net.core.wmem_max` at 7500000 on both machines, the
setting [recommended above](#linux-raise-the-udp-buffer-limit).

| | Down | Up | Dropped (down / up) |
|---|---:|---:|---:|
| No tunnel | 20846 | 20576 | |
| flextunnel v0.0.108 | 2632 | 2620 | 0 / 0 |
| flextunnel v0.0.109 | 2622 | 2504 | 0 / 0 |

By session: 2598 / 2477 against 2653 / 2586 in the five, 2644 / 2581 against
2626 / 2654 in the ten. Uploads ranged from 1596 to 2775 for v0.0.109 and
from 1730 to 2824 for v0.0.108.

### Linux pair, buffer limit raised and `tx-udp-segmentation` on

| | Down | Up |
|---|---:|---:|
| No tunnel | 21065 | 20965 |
| flextunnel v0.0.108 | 3766 | 3724 |
| flextunnel v0.0.109 | 3611 | 3718 |

Nothing was dropped for want of buffer in any flextunnel run. By session:
3583 / 3623 against 3772 / 3695 in the five, 3684 / 3718 against 3704 / 3765
in the ten. The no-tunnel row is the five.

### 53 ms round trip

The delay of [Long paths](#long-paths) on both machines, runs of 20 s.

| | As installed (down / up) | Dropped (down / up) | Buffer limit raised (down / up) |
|---|---:|---:|---:|
| flextunnel v0.0.108 | 653 / 658 | 53 / 25 | 1055 / 1075 |
| flextunnel v0.0.109 | 677 / 668 | 51 / 27 | 1057 / 1067 |

As installed, fifteen rounds: downloads ranged from 330 to 839 for v0.0.108
and from 465 to 815 for v0.0.109, and by session the versions read 640 / 618
against 735 / 664 in the five and 684 / 676 against 630 / 627 in the ten:
v0.0.109's downloads 13% behind in one session and 9% ahead in the other.
With the limit raised, five rounds, all within 9% of each other.

### `client nc`

A 1500 MiB pipe of zeros through `flextunnel client nc` in each direction,
timed whole, with the forward measured in the same run for comparison. Linux
pair as installed, three rounds in turn:

| | Forward (down / up) | `client nc` (down / up) |
|---|---:|---:|
| flextunnel v0.0.108 | 2084 / 2039 | 1590 / 1724 |
| flextunnel v0.0.109 | 1974 / 2088 | 1677 / 1739 |

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
| | flextunnel v0.0.108 | 1844 | 1300 | 1.3 / 1.3 |
| | flextunnel v0.0.109 | 1862 | 1272 | 1.4 / 1.3 |
| Windows VM (build 26100, Hyper-V, 4 vCPUs, 2 GB, 2.5 Gbit/s link, another host) | No tunnel | 2098 | 2369 | |
| | flextunnel v0.0.108 | 1862 | 1677 | 1.3 / 1.1 |
| | flextunnel v0.0.109 | 1944 | 1711 | 1.3 / 1.1 |

Thirteen rounds for the macOS client and five for the Windows one, iperf3
run on the client (3.21 on macOS, 3.22.1 on Windows). Every tunnel run used a
direct path. The CPU column is the client process's CPU time over a run
divided by the run's 7 s.

Neither client tells the versions apart. The macOS uploads ranged from 889
to 1414 for v0.0.109 and from 984 to 1340 for v0.0.108, and the first five
rounds alone had read 1114 against 1304; the Windows ranges overlap in both
directions. The macOS no-tunnel download was identical on every run, which
suggests a cap in the VM's NAT path, and both versions' downloads are within
6% of it.

## What the measurements showed

All but the last of these are what v0.0.107 changed, measured against
v0.0.106 on the same machines when it was made.

### The limit was loss, not CPU

At 1.4 Gbit/s v0.0.106 used 0.85 of a core on each machine, spread over five
or six threads at 0.15–0.25 each, and no thread was near full. What held it
there was the congestion controller. The sending side's QUIC statistics,
sampled once a second during a transfer, showed over 2% of its packets
declared lost and 70 congestion events a second, with the congestion window
hovering around 220–280 KB (the first row below).

| Two workers, as installed, one stream | Mbit/s (down / up) | Packets declared lost | Congestion events / s | Of them spurious / s |
|---|---:|---:|---:|---:|
| Upstream iroh, noq and netwatch | 1499 / 1512 | 2.3% | 70 | 11 |
| noq fork | 1493 / 1489 | 2.2% | 55 | 7 |
| noq and netwatch forks | 1937 / 1987 | 0.8–0.9% | 22 | 0.2 |
| noq, netwatch and iroh forks | 1889 / 1967 | 0.4–0.9% | 16–25 | 0.1 |

Four rounds, the variants taken in turn, each built from the v0.0.106 source
with only the dependencies changed.

Two things were losing the packets, and the rows separate them.

**Reordering.** With XPS, the kernel picks the transmit queue of a datagram
sent on an unconnected UDP socket from the CPU the sending thread is on. The
task that sends a connection's packets moves between runtime threads, so
consecutive batches leave on different queues and overtake each other.
v0.0.106 already told loss detection to tolerate reordering (256 packets,
two round trips), and on this pair that was not enough: a round trip here is
0.3 ms, and two of them is evidently less than the queues drift apart. The
netwatch fork removes the cause instead. It sends to a busy peer on a
connected socket, whose transmit queue the kernel keeps fixed, and with it
the spurious congestion events all but stop and the loss falls by two
thirds. That one change is nearly all of the first column's gain, 1.5 to
1.95 Gbit/s on two workers; the rest is the worker count, below.

**The receive buffer.** What loss is left is real. iroh asks for 7 MB UDP
socket buffers and an unprivileged process gets `net.core.rmem_max`, 208 KB
by default, which at 2 Gbit/s is about a millisecond of data. Whenever the
receiving process is a millisecond late the kernel drops what does not fit,
a few hundred to over a thousand times per 6 s run. The window cannot grow
past what the buffer absorbs, so it stays at 300–400 KB.

With the limit raised the drops stop. The window grows to megabytes, loss
falls to a few tens of packets a second, and the transfer runs at what the
two processes can move:

| Two workers, buffer limit raised, one stream | Mbit/s (down / up) | Packets declared lost | Congestion events / s |
|---|---:|---:|---:|
| Upstream iroh, noq and netwatch | 1478 / 1562 | 1.1% | 50 |
| noq and netwatch forks | 2090 / 2118 | under 0.02% | 2 |
| noq, netwatch and iroh forks | 2475 / 2677 | under 0.02% | 1–2 |

Three rounds. The upstream build does not move: its loss was never the
buffer's. The iroh fork's part shows here and not in the table above. When
the socket cannot take a transmit, upstream iroh discards it and reports it
sent, which the connection finds out as loss; the fork keeps the transmit for
noq to retry.

At 2.6 Gbit/s v0.0.107 uses 1.1 cores on each machine, about 0.55 on each of
its two threads, so it is still not short of CPU.

### macOS charged every datagram a connect

The macOS client's gain is the connected socket again, for a different
reason. XNU connects and disconnects the socket around every UDP send that
names a destination, which a connected socket skips; the kernel behaviour
and ezvpn's measurements of it are in
[flexaccess-iroh's docs](https://github.com/flexaccessdev/flexaccess-iroh/blob/main/docs/nat-traversal-and-transport.md)
under "Performance characteristics". The macOS client built from the
v0.0.106 source with only the dependencies changed, on two workers, against
the v0.0.107 server, four rounds in turn:

| macOS client | Down | Up | Client CPU, cores (down / up) |
|---|---:|---:|---:|
| Upstream iroh, noq and netwatch | 490 | 229 | 1.8 / 1.1 |
| noq fork | 487 | 223 | 1.8 / 1.2 |
| noq and netwatch forks | 1889 | 1253 | 1.4 / 1.2 |
| noq, netwatch and iroh forks | 1851 | 1071 | 1.4 / 1.3 |

The last two rows differ by address family, not by build: iroh picks a
direct path per connection, and with either build an upload over IPv4 ran at
1230–1280 and one over IPv6 at 1060–1080. Downloads did not show it.
v0.0.106 itself, on a worker per core, used 2.3 cores for its 400 Mbit/s
download.

### The buffers without the sysctl

The netwatch fork asks for its socket buffers with `SO_RCVBUFFORCE` and
`SO_SNDBUFFORCE` first, which ignore the kernel's limit for a process that
holds `CAP_NET_ADMIN`. v0.0.107 as the same unprivileged user, as installed,
with and without that one capability as an ambient capability at both ends,
four rounds in turn:

| | Down | Up | Dropped (down / up) |
|---|---:|---:|---:|
| v0.0.107 | 1932 | 1867 | 136 / 697 |
| v0.0.107 with `CAP_NET_ADMIN` | 2666 | 2628 | 0 / 0 |

That is the raised limit's result without changing the limit for the rest of
the machine. The process ran as the same user with an effective capability
set of `CAP_NET_ADMIN` alone, and its two iroh sockets showed 14 MB receive
buffers (the kernel doubles the 7 MiB asked for).

### Ten datagrams per send

A transmit is one `sendmsg` with UDP GSO, so its trip through the network
stack is shared by the datagrams in it, and with `tx-udp-segmentation` on it
also reaches the host as one buffer. Upstream noq caps a transmit at 10
datagrams whatever the socket takes; the fork sends up to 32. Two workers,
buffer limit raised, three rounds in turn:

| | Offload off (down / up) | Offload on (down / up) |
|---|---:|---:|
| Upstream iroh, noq and netwatch | 1478 / 1562 | 2107 / 2206 |
| noq fork | not measured | 2621 / 2604 |
| noq and netwatch forks | 2090 / 2118 | 2931 / 2775 |
| noq, netwatch and iroh forks | 2475 / 2677 | 3668 / 3664 |

With the offload on, the larger sends alone are worth about a fifth, and
each further fork adds to them. With it off and the buffer at its default
they are worth nothing here (1493 / 1489 against 1499 / 1512, in the table
under "The limit was loss, not CPU"): the guest segments the batch itself
either way, and that transfer was held by loss. ezvpn's own measurements of
the cap, including what happens above 32, are in its
[benchmarks](https://github.com/flexaccessdev/ezvpn/blob/main/docs/Benchmarks.md).

### More runtime threads were slower

One stream, all three forks, as installed, four rounds, by Tokio worker
threads on both ends:

| Workers | Down | Up |
|---:|---:|---:|
| 1 | 2239 | 1990 |
| 2 | 1932 | 2038 |
| 6 (v0.0.106's default: one per core) | 1856 | 1893 |

The upstream build ranked the same way and further apart (1767 / 1781 on one
worker, 1527 / 1505 on two, 1387 / 1393 on six), presumably because more
threads also meant more transmit queues for its packets to be reordered
across.

A second stream does not use a second thread. Four streams at once through
one forward, on one connection, with the buffer limit raised and the offload
on, three rounds, sum of the four:

| Workers | Down | Up |
|---:|---:|---:|
| 1 | 3244 | 3630 |
| 2 | 3451 | 3443 |
| 3 | 3284 | 3336 |
| 6 | 3027 | 3232 |

One stream in that configuration moved 3668 / 3664 on two workers and 3144 /
3146 on six. A connection encrypts and sends through one lock, and its
streams share it.

Connections are what spread over threads. Three clients downloading or
uploading at once through one server (each client on two workers), same host
settings, aggregate Mbit/s, three rounds:

| Server workers | Down | Up |
|---:|---:|---:|
| 1 | 3796 | 4099 |
| 2 | 5068 | 4788 |
| 3 | 5124 | 4697 |
| 6 | 4669 | 4635 |

The CLI, the desktop app's server and the iOS library now run two workers.
These guests overcommit their host, which makes cross-thread wakeups dearer
than on bare metal, so the penalty for extra workers is probably larger here
than on a dedicated machine; `TOKIO_WORKER_THREADS` overrides the count to
check.

### What made no difference, or made it worse

All three forks, two workers, as installed, three rounds in turn:

| | Down | Up |
|---|---:|---:|
| As shipped (Cubic, reordering thresholds 256 packets and 2 round trips) | 1878 | 1955 |
| BBRv3 | 811 | 999 |
| QUIC's default reordering thresholds (3 packets, 9/8 of a round trip) | 1996 | 1892 |
| An ACK per 16 packets requested from the peer | 2025 | 2058 |

BBRv3 moved half as much as Cubic or less, and was slower than Cubic on the
upstream stack too (1207 / 1254). Why was not looked into.

The reordering thresholds no longer decide the rate. With QUIC's defaults the
spurious congestion events came back at 2–3 a second, against 0.1 with the
wider ones, so they stay: they cover what the connected socket does not (a
sender on Windows, which has none; a server with more busy peers than it
keeps sockets for; a network that reorders by itself).

ezvpn asks its peer for an ACK per 16 packets where QUIC's default is every
other one. Here that changed nothing: the receiving side was already sending
an ACK only when its connection task ran, about one per 50–70 packets
(2,100–2,900 ACKs a second for 150,000 packets).

v0.0.109 also grants a peer no unidirectional streams, where QUIC's default
is 100: flextunnel opens none, and each is a stream window more that a peer
could have a connection hold. The v0.0.109 rows above were taken before that
was added. Against a build with it, twenty rounds in two sessions of ten,
and in the second session a build of the same source with the constant back
at 100:

| | As installed (down / up) | Limit raised, offload on (down / up) |
|---|---:|---:|
| v0.0.109 as measured above (100 granted) | 2027 / 2032 | 3674 / 3650 |
| None granted, as shipped | 1989 / 2038 | 3616 / 3582 |
| The same source with 100 granted, ten rounds | 2012 / 1990 | 3635 / 3586 |

Within 2% over the twenty. The first session had the shipped build behind by
1–4% in all four figures (1969 / 2022 against 2037 / 2039, 3526 / 3574
against 3670 / 3658); the second had it level with or ahead of both others
(2059 / 2050 and 3666 / 3666, against 2020 / 2019 and 3674 / 3641, and the
third row). A build that differs in that constant alone was not faster, so
this is the difference between sessions and builds again, not the setting.

A client grants its server no bidirectional streams either, since only the
client opens them. With that added, against the build above it, ten rounds
in turn: 2067 / 2079 against 2093 / 2030 as installed, and 3687 / 3627
against 3698 / 3609 with the limit raised and the offload on. The last
leaves out one round of the ten, in which the new build's direct path was
the machines' Tailscale address (607 / 496); with it the medians are 3685 /
3544.

### No false MTU black hole

ezvpn's long transfers used to stall when noq took congestion loss for an MTU
black hole and dropped the path MTU to 1200. The noq fork carries the fix, so
this was checked on the upstream stack before taking it: a 120 s transfer in
each direction on v0.0.106's dependencies, at 1.6% loss throughout, kept the
path MTU at 1452 with no black hole reported in any second. Nothing here
shows flextunnel was affected.

### Windows that grow on a short path too

v0.0.109's windows grow when half a window was read within two round trips.
Between these machines a round trip is 0.3 ms, no reader is that fast, and
judged that way no window grew: every stream stayed at 1.25 MB, which at
3.7 Gbit/s leaves the sender without credit whenever the receiving process
is 3 ms late. On a path that short the round trip is not what a window has
to cover, so one counts as 5 ms at least. Three builds of one source that
differ in a constant each, with the buffer limit raised and the offload on,
ten rounds in turn with the two releases:

| | Down | Up |
|---|---:|---:|
| Every stream at 8 MiB from the start | 3718 | 3676 |
| Windows that grow, a round trip counted as 5 ms at least | 3683 | 3701 |
| Windows that grow, judged against the round trip alone | 3602 | 3581 |
| v0.0.108 | 3704 | 3765 |
| v0.0.109 | 3684 | 3718 |

The first row behaves as v0.0.108 does and the second is what v0.0.109
ships. Each of those pairs is one behaviour built twice, and they are up to
2.4% apart: that is what a different build is worth here, and the size of
the differences between the versions in the table at the top. Judged against
the round trip alone the transfer was 2–3% slower in this session, and 5–8%
slower on download in two earlier ones against v0.0.108 (3570 against 3763,
3497 against 3790). In the three slower columns the same build was not told
apart from v0.0.108.

On loopback, where the tests run, a window reaches its 8 MiB at an average
of 20–35 MB/s: delivery in bursts is enough to read half a window within
10 ms a few times over. So a short path's windows are earned more easily
than its average rate suggests, and what bounds them is the 64 MiB a
connection has to give.

## Opportunities left

What these runs left open, with what is known about each. None of it is
scheduled work.

- **The receive buffer with neither the sysctl nor a capability.** As
  installed, a transfer is held at about 2 Gbit/s by a 208 KB socket buffer,
  and the full buffer is worth another 30%. Both ways to get it need root
  once. Nothing was tried for a process that has neither, such as draining
  the socket from a thread of its own so that less waits in the kernel.
- **Where the time goes.** Neither end is short of CPU at any rate measured
  here (1.1 cores a side at 2.6 Gbit/s on two threads), so what bounds a
  transfer once the loss is gone is how quickly data is handed from task to
  task: the splice, the connection's driver, the endpoint's driver, and the
  same three on the far side for the ACK that lets the next window go. It
  was not profiled.
- **Sends filled to the UDP payload.** The noq fork sends up to 32 datagrams
  per UDP send. For ezvpn, about 45 (what one UDP payload holds) measured 3%
  to 5% above that; the fork's byte bound would still need to respect the
  relay frame limit. Not measured for flextunnel.
- **Worker count off these VMs.** Two runtime workers was chosen on guests
  that overcommit their host two to one, with at most three clients. A
  dedicated machine, or a server with many busy clients, may want a
  different number; `TOKIO_WORKER_THREADS` is the knob.
- **macOS uploads.** A macOS client's upload is 1.3 Gbit/s on a path that
  carries 2.35, at 1.3 cores. It was not profiled. ezvpn's notes on the same
  machine put what is left of a macOS sender's time in one `sendmsg` per
  datagram, which has no batched form there.
- **Windows is not profiled.** Its download did not change with the forks
  and sits within 12% of the path, so the path may be what holds it; its
  upload gained a quarter then and nothing is known about where the rest of
  its time goes.
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
it may start on a relay. Run a short test first and wait for a direct path:
with `RUST_LOG=info,iroh=warn,tracing=warn,flextunnel_core::transport::paths=debug`
the client logs a `Connection: Direct …` line when it has one. A run that
begins on a relay measures the relay.

The four-stream rows are `iperf3 -P 4` through the same forward. The
three-client rows need three clients and three listeners, because one
`iperf3 -s` serves one test at a time: on the server, a listener per port
(`iperf3 -s -D -B 127.0.0.1 -p 5201`, `-p 5211`, `-p 5212`); on the client
machine, three client configs with different `name` values, each forwarding
its own local port to one of the three, started together. The aggregate is
the sum of the three receiver rates. Worker counts were set with
`TOKIO_WORKER_THREADS` on each process.

The host settings behind the columns:

```bash
sudo sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000   # buffer limit raised
sudo ethtool -K eth0 tx-udp-segmentation on                           # UDP offload on
```

Restart flextunnel after the first: the buffers are sized when its sockets
open. The capability rows started each process as its own user with
`CAP_NET_ADMIN` and nothing else:

```bash
sudo setpriv --reuid=<user> --regid=<group> --init-groups \
  --inh-caps=+net_admin --ambient-caps=+net_admin \
  env HOME=<home> flextunnel server start -c server.toml
```

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
may take that as its direct path once the two are equally far, so check the
address in the `Connection: Direct …` line.

The memory rows need a second forward, to a listener on the server machine
that writes to every connection for as long as it is taken. Open the readers
against that forward with a small `SO_RCVBUF`, read as much as the row says
and then stop without closing, and read the client's `VmRSS` from
`/proc/<pid>/status` once it has stopped climbing.

`nstat -az UdpRcvbufErrors Udp6RcvbufErrors` before and after a run gives
the dropped count, and `cat /sys/class/net/<dev>/queues/tx-*/xps_cpus` shows
whether XPS is active.
