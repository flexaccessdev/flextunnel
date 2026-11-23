# Throughput

What a port forward or `client nc` can carry, what limits it, and the one
host setting worth changing. The numbers show proportions, not what your
hardware will do; how they were measured, and what each change to the data
path was worth, is in [benchmarks.md](benchmarks.md). How the data path is
built is in [architecture.md](architecture.md#5-byte-piping).

## What sets the ceiling

A client holds one QUIC connection per destination, and a connection's
packets are built, encrypted and sent through one lock. Everything through a
destination — every forward, every `nc`, every proxied request — shares it,
so several transfers at once split what one would get rather than adding up:
four streams through one forward moved what one did.

Between two Linux virtual machines on one host, 0.4 ms apart, with `iperf3`
through a forward and a 1.5 GB pipe through `nc`:

| Host settings | Forward, down / up | `client nc`, down / up |
|---|---|---|
| As installed | 2.0 / 2.0 Gbit/s | 1.6 / 1.7 Gbit/s |
| UDP buffer limit raised (below) | 2.6 / 2.6 Gbit/s | not measured |
| The limit raised and the NIC's UDP segmentation offload on | 3.7 / 3.6 Gbit/s | not measured |

Download is the server sending. Neither end was short of CPU in any of these
(about one core a side at 2.6 Gbit/s). As installed, what holds a transfer is
the kernel's limit on UDP socket buffers, which the next section raises. A
connection that iroh has to carry over a relay instead of directly is limited
by the relay instead.

Against the same Linux server from another machine, a macOS client moved
1.8 Gbit/s down and 1.1 up on a path that carries 1.9 and 2.4 without a
tunnel, and a Windows client 1.8 and 1.7 on one that carries 2.1 and 2.4.

`nc` runs behind a forward on the same path: its bytes make one more hop,
between the running client and the `nc` process.

## Linux: raise the UDP buffer limit

iroh asks the kernel for 7 MB UDP socket buffers. Linux grants at most
`net.core.rmem_max` / `net.core.wmem_max`, which default to 208 KB — about two
milliseconds of a gigabit. On a fast path the receive buffer then overflows
whenever the process is a moment late, QUIC sees loss, and the transfer slows
down. Between the two virtual machines above, raising the limits on both
took a transfer from 2.0 to 2.6 Gbit/s; over a path across the internet with
53 ms round trips it took an upload from 540 to 1080 Mbit/s (v0.0.106).

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
it. Between the two virtual machines it measured the same as the raised
limit.

## Long paths

A stream sends at most one flow-control window per round trip. The window is
8 MiB, so the cap is 8 MiB ÷ RTT: about 1.2 Gbit/s at 53 ms, 640 Mbit/s at
100 ms, 320 Mbit/s at 200 ms.

The window is also memory: a stream whose reader is slower than the path, or
has stopped reading, holds up to 8 MiB of received data until it is read —
about 9 MB of process memory each when measured, so 70 stalled readers on one
connection took a client to 570–690 MB and 95 to 900 MB (a connection carries
at most 100 streams). A window half the size would halve that, and the cap
above with it: at 53 ms an upload ran at 1040 Mbit/s with 8 MiB, 560 with
4 MiB and 290 with 2 MiB.

The iOS client is the exception: the system ends an app that holds too much
memory, so its window stays at 1.25 MB. Its downloads are capped at 1.25 MB ÷
RTT (190 Mbit/s at 53 ms, 100 at 100 ms) and its streams hold under 2 MB
each. Uploads from it are not affected, since the window that caps a
direction is the receiver's.

There is no limit across a connection's streams, because slow readers would
then hold up every other stream, the heartbeat included. With a 128 MiB limit,
18 stalled readers made the client drop the connection and every tunnel on it,
and 24 readers taking 100 kB/s each made a new stream wait 3–15 s where it
otherwise took 12 ms.

Congestion control is CUBIC, which grows its window by the clock rather than
by the round trip. After a loss on a long path it takes seconds to tens of
seconds to return to full speed, so a transfer that starts right after
another one in the opposite direction on the same destination can begin slow
and speed up as it goes.
