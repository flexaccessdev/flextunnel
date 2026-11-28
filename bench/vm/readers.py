#!/usr/bin/env python3
"""readers.py N PORT READ_BYTES HOLD_SECS: on the client VM, N connections to a forward,
each read for READ_BYTES (0: never) and then left unread; the client's memory while they sit."""
import socket, subprocess, sys, threading, time

n, port, read_bytes, hold = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
pid = int(subprocess.check_output(["pgrep", "-x", "flextunnel"]).split()[0])


def rss():
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS"):
            return int(line.split()[1]) // 1024
    return -1


def read(s, want):
    got = 0
    while got < want:
        b = s.recv(min(1 << 20, want - got))
        if not b:
            break
        got += len(b)


before = rss()
socks = []
for _ in range(n):
    s = socket.socket()
    # Keep what the kernel holds for an unread socket small, so the tunnel is what buffers.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
    s.connect(("127.0.0.1", port))
    socks.append(s)
t0 = time.time()
if read_bytes:
    ts = [threading.Thread(target=read, args=(s, read_bytes)) for s in socks]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
took = time.time() - t0
samples = []
end = time.time() + hold
while time.time() < end:
    time.sleep(1)
    samples.append(rss())
rate = f" read {n}x{read_bytes >> 20}MB in {took:.1f}s ({n * read_bytes * 8 / took / 1e6:.0f} Mbit/s)" if read_bytes else ""
print(f"rss_mb before={before} peak={max(samples)} final={samples[-1]}{rate}")
