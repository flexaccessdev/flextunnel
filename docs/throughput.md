# Throughput

What a port forward or `client nc` can carry, what limits it, and the one
host setting worth changing. The numbers were measured between Linux virtual
machines, with `iperf3` through a forward and a 1.5 GB pipe through `nc`; they
show proportions, not what your hardware will do. How the data path is built
is in [architecture.md](architecture.md#5-byte-piping).

## What sets the ceiling

A client holds one QUIC connection per destination, and one connection
encrypts and sends on about one CPU core. Everything through a destination —
every forward, every `nc`, every proxied request — shares it, so several
transfers at once split what one would get rather than adding up.

| Path | Forward, down / up | `client nc`, down / up |
|---|---|---|
| Two VMs on one host, 0.5 ms round trip | 1.6 / 1.6 Gbit/s | 1.35 / 1.4 Gbit/s |
| Across the internet, direct, 3 ms | 1.0 / 1.4 Gbit/s | 1.0 / 1.4 Gbit/s |
| The same with 50 ms added | 0.37–0.45 / 0.56–0.68 Gbit/s | not measured |

Download is the server sending. Across the internet the path was not the
limit in either direction: plain TCP did 2.1 Gbit/s up and 2.3 down over it. A
connection that iroh has to carry over a relay instead of directly is limited
by the relay instead.

`nc` runs a little behind a forward on the same path: its bytes make one more
hop, between the running client and the `nc` process.

## Linux: raise the UDP buffer limit

iroh asks the kernel for 7 MB UDP socket buffers. Linux grants at most
`net.core.rmem_max` / `net.core.wmem_max`, which default to 208 KB — about two
milliseconds of a gigabit. On a fast path the receive buffer then overflows
whenever the process is a moment late, QUIC sees loss, and the transfer slows
down. Over the 53 ms path above, raising the limits on both machines took an
upload from 540 to 1080 Mbit/s.

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
