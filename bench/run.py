#!/usr/bin/env python3
"""run.py LABEL KIND[:ROUNDS] ...: run the measurements of a session that bench/stage.py staged.

KIND is a Linux-pair column (installed, offload, rmem, both), a 53 ms column (wan,
wan-rmem), nc, mem, mac or win. A column's rows are taken in turn, round after round:
no tunnel, Tailscale, then the session's versions in an order that alternates by round.
A row is one flow down and up, then four flows down and up (one flow only on the 53 ms
columns), every tunnel run on a freshly started server and client. One JSON line per
run in target/bench/LABEL/KIND.jsonl.

Runs are kept clear of the scheduled jobs of the machines' physical host, read from
~/.config/flextunnel-bench/quiet.json, which stays outside the repo:
    {"probe": "<shell command printing the host's load, logged every round>",
     "jobs": [{"tz": "UTC", "at": "02:00", "minutes": 10},
              {"tz": "UTC", "at": "12:30", "minutes": 45, "weekday": 6}]}
A job blocks [start - 60 s, start + 1.25 x minutes + 2 min); weekday is 0 for Monday."""
import datetime as dt, json, os, re, subprocess, sys, time
from zoneinfo import ZoneInfo

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.join(REPO, "bench")
LABEL = sys.argv[1]
OUT = os.path.join(REPO, "target/bench", LABEL)
S = json.load(open(os.path.join(OUT, "session.json")))
VERSIONS = S["versions"]
SRV, CLI, MAC, WIN = (S["hosts"][k] for k in ("server", "client", "mac", "win"))
F = "~/codes/staging-area/flextunnel-bench/ftb.sh"
B = "~/codes/staging-area/flextunnel-bench"
CM = os.path.expanduser("~/.ssh/cm/ftb-%C")
QUIET = os.path.expanduser("~/.config/flextunnel-bench/quiet.json")
MAC_TS = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
DEFAULT_BUF, RAISED_BUF = 212992, 7500000
TCP_MEM_DEFAULT = "21780 29041 43560"
NETEM_ON = ("sudo tc qdisc replace dev eth0 root handle 1: mq; "
            "for q in $(seq $(ls -d /sys/class/net/eth0/queues/tx-* | wc -l)); do "
            "sudo tc qdisc replace dev eth0 parent 1:$q netem delay 26.5ms limit 200000; done")
NETEM_OFF = "sudo tc qdisc del dev eth0 root 2>/dev/null; true"  # back to the default mq
# name: (buffer limit, tx-udp-segmentation, netem, seconds per run, flows, with no-tunnel and Tailscale rows)
COLUMNS = {
    "installed": (DEFAULT_BUF, "off", False, 6, (1, 4), True),
    "offload": (DEFAULT_BUF, "on", False, 6, (1, 4), True),
    "rmem": (RAISED_BUF, "off", False, 6, (1, 4), True),
    "both": (RAISED_BUF, "on", False, 6, (1, 4), True),
    "wan": (DEFAULT_BUF, "off", True, 20, (1,), False),
    "wan-rmem": (RAISED_BUF, "off", True, 20, (1,), False),
}
os.makedirs(os.path.dirname(CM), exist_ok=True)


def ssh(host, cmd, timeout=180):
    try:
        p = subprocess.run(["ssh", "-o", "ControlMaster=auto", "-o", f"ControlPath={CM}", "-o", "ControlPersist=900",
                            "-o", "BatchMode=yes", host, cmd], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "ERR ssh timed out"
    return p.stdout + p.stderr


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def emit(name, rec):
    rec.update(kind=name, ts=time.time())
    with open(os.path.join(OUT, f"{name}.jsonl"), "a") as f:
        f.write(json.dumps(rec) + "\n")


# --- host load -----------------------------------------------------------------------------

def quiet():
    try:
        return json.load(open(QUIET))
    except FileNotFoundError:
        return {"jobs": []}


def blocked_until(start, length, jobs):
    """The end of the latest job window that [start, start + length) reaches into, or None."""
    end = None
    for j in jobs:
        tz = ZoneInfo(j["tz"])
        hh, mm = map(int, j["at"].split(":"))
        local = dt.datetime.fromtimestamp(start, tz)
        for day in (-1, 0, 1):
            d = (local + dt.timedelta(days=day)).date()
            if "weekday" in j and d.weekday() != j["weekday"]:
                continue
            t0 = dt.datetime(d.year, d.month, d.day, hh, mm, tzinfo=tz).timestamp()
            w0, w1 = t0 - 60, t0 + 1.25 * j["minutes"] * 60 + 120
            if start < w1 and start + length > w0:
                end = max(end or 0, w1)
    return end


def gate(length):
    """Wait until a run of `length` seconds would stay clear of every job window."""
    jobs = quiet()["jobs"]
    while (until := blocked_until(time.time(), length, jobs)) is not None:
        log(f"waiting {until - time.time():.0f}s for a scheduled job on the host to pass")
        time.sleep(until - time.time() + 1)


def probe(name, rnd):
    cmd = quiet().get("probe")
    if cmd:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        emit(f"{name}-host", {"round": rnd, "probe": (p.stdout + p.stderr).strip()})


# --- Linux pair ----------------------------------------------------------------------------

def settings(buf, gso, netem):
    for h in (SRV, CLI):
        out = ssh(h, "export PATH=$PATH:/usr/sbin; "
                     f"sudo sysctl -q -w net.core.rmem_max={buf} net.core.wmem_max={buf}; "
                     f"sudo ethtool -K eth0 tx-udp-segmentation {gso}; "
                     f"{NETEM_ON if netem else NETEM_OFF}; "
                     "sysctl -n net.core.rmem_max net.core.wmem_max; "
                     "ethtool -k eth0 | grep tx-udp-segmentation; "
                     "echo $(( $(tc qdisc show dev eth0 | grep -c netem) > 0 ))")
        want = [str(buf), str(buf), "tx-udp-segmentation:", gso, "1" if netem else "0"]
        if out.split() != want:
            raise SystemExit(f"settings not applied on {h}: {out!r}")
    log(f"settings: buf={buf} gso={gso} netem={netem}")


def parse_stat(line):
    d = dict(kv.split("=") for kv in line.split()[1:])
    return int(d["drops"]), int(d["cpu"]), float(d["t"])


def measure(direction, secs, flows, host, port):
    """One iperf3 run from the client VM; server-side counters taken around it."""
    s0 = parse_stat(ssh(SRV, f"{F} stat").strip())
    out = ssh(CLI, f"{F} run {direction} {secs} {flows} {host} {port}", timeout=secs + 120)
    s1 = parse_stat(ssh(SRV, f"{F} stat").strip())
    head, _, body = out.partition("{")
    stats = [parse_stat(l) for l in head.splitlines() if l.startswith("STAT")]
    if "ERR" in head or not body or len(stats) < 2:
        return {"error": out[:300]}
    j = json.loads("{" + body)
    c0, c1 = stats[-2], stats[-1]
    return {
        "mbps": round(j["end"]["sum_received"]["bits_per_second"] / 1e6, 1),
        "retr": j["end"]["sum_sent"].get("retransmits"),
        "drops_client": c1[0] - c0[0], "drops_server": s1[0] - s0[0],
        "cpu_client": round((c1[1] - c0[1]) / 100 / (c1[2] - c0[2]), 2),
        "cpu_server": round((s1[1] - s0[1]) / 100 / (s1[2] - s0[2]), 2),
        "retries": sum(l.startswith("RETRY") for l in head.splitlines()),
    }


def on_bridge(path):
    """A direct path to the server's own address on the bridge, of either family."""
    return f"Direct {S['server4']}:" in path or any(f"{a}]:" in path for a in S["server6"])


def start(v):
    last = ""
    for attempt in range(6):
        o = ssh(SRV, f"{F} server {v}")
        if "ERR" in o:
            last = o; continue
        o = ssh(CLI, f"{F} client {v}")
        path = next((l for l in o.splitlines() if l.startswith("PATH")), "")
        if "ERR" not in o and on_bridge(path):
            return path[len("PATH Connection: "):], attempt
        last = o
    raise SystemExit(f"could not get a direct path on the bridge for {v}: {last!r}")


def lastpath():
    return ssh(CLI, f"{F} lastpath").strip()[len("PATH Connection: "):]


def tunnel_run(name, rnd, v, d, secs, flows, port=5301):
    for redo in range(4):
        gate(secs + 25)
        path, attempts = start(v)
        r = measure(d, secs, flows, "127.0.0.1", port)
        after = lastpath()
        if on_bridge(after) and "error" not in r:
            break
        # The path left the server's bridge address mid-run (the machines share a tailnet): not a result.
        emit("left-out", {"block": name, "round": rnd, "variant": v, "dir": d, "flows": flows,
                          "path": path, "path_after": after, **r})
        log(f"{name} r{rnd} {v} {d} x{flows} left out: {r.get('mbps', r)} [{after}]")
    rec = {"round": rnd, "variant": v, "dir": d, "flows": flows, "path": path, "path_after": after,
           "start_attempts": attempts, **r}
    emit(name, rec)
    log(f"{name} r{rnd} {v} {d} x{flows} {r.get('mbps', r)} retr {r.get('retr')} drops c/s "
        f"{r.get('drops_client')}/{r.get('drops_server')} cpu c/s {r.get('cpu_client')}/{r.get('cpu_server')} [{after}]")


def column(name, rounds):
    buf, gso, netem, secs, flows, baselines = COLUMNS[name]
    settings(buf, gso, netem)
    for rnd in range(1, rounds + 1):
        probe(name, rnd)
        if baselines:
            ssh(SRV, f"{F} stop"); ssh(CLI, f"{F} stop")
            rows = [("none", S["server4"])] + ([("tailscale", S["tailscale4"])] if S["tailscale4"] else [])
            for variant, host in rows:
                tspath = ssh(CLI, f"{F} tspath {host}").strip() if variant == "tailscale" else None
                for n in flows:
                    for d in ("down", "up"):
                        gate(secs + 10)
                        r = measure(d, secs, n, host, 5201)
                        emit(name, {"round": rnd, "variant": variant, "dir": d, "flows": n,
                                    **({"path": tspath} if tspath else {}), **r})
                        log(f"{name} r{rnd} {variant} {d} x{n} {r.get('mbps', r)} retr {r.get('retr')}")
        for v in (VERSIONS if rnd % 2 else VERSIONS[::-1]):
            for n in flows:
                for d in (("down", "up") if rnd % 2 else ("up", "down")):
                    tunnel_run(name, rnd, v, d, secs, n)
    ssh(CLI, f"{F} stop"); ssh(SRV, f"{F} stop")


def nc(rounds):
    """Linux pair as installed: a forward and `client nc`, each direction on a fresh tunnel."""
    settings(DEFAULT_BUF, "off", False)
    for rnd in range(1, rounds + 1):
        probe("nc", rnd)
        for v in (VERSIONS if rnd % 2 else VERSIONS[::-1]):
            for d in ("down", "up"):
                gate(35)
                start(v)
                r = measure(d, 6, 1, "127.0.0.1", 5301)
                emit("nc", {"round": rnd, "variant": v, "what": "forward", "dir": d, **r})
                log(f"nc r{rnd} {v} forward {d} {r.get('mbps', r)}")
            for d in ("down", "up"):
                gate(40)
                ssh(SRV, f"{F} listen off; {F} listen {'zeros' if d == 'down' else 'sink'}", timeout=30)
                start(v)
                o = ssh(CLI, f"{B}/nc.sh {v} {d}", timeout=300).strip()
                after = lastpath()
                rec = {"round": rnd, "variant": v, "what": "nc", "dir": d, "path_after": after}
                rec.update({"mbps": float(o)} if re.fullmatch(r"[0-9.]+", o) else {"error": o[-300:]})
                emit("nc", rec)
                log(f"nc r{rnd} {v} nc {d} {o} [{after}]")
    ssh(SRV, f"{F} listen off"); ssh(CLI, f"{F} stop"); ssh(SRV, f"{F} stop")


def mem(runs):
    """Client resident memory with readers that stall, the versions in turn. tcp_mem at its default."""
    rows = [  # name, netem, readers, bytes each reads first
        ("95-never", False, 95, 0),
        ("95-never-wan", True, 95, 0),
        ("30-read-60mb-wan", True, 30, 60 << 20),
    ]
    for h in (SRV, CLI):
        ssh(h, f"sudo /usr/sbin/sysctl -q -w net.ipv4.tcp_mem='{TCP_MEM_DEFAULT}'")
    try:
        for row, netem, n, nbytes in rows:
            settings(DEFAULT_BUF, "off", netem)
            for run in range(1, runs + 1):
                probe("mem", run)
                for v in VERSIONS:
                    gate(120)
                    ssh(SRV, f"{F} listen off; {F} listen source", timeout=30)
                    start(v)
                    o = ssh(CLI, f"cd {B} && ~/.local/bin/uv run --python 3.13 readers.py {n} 5302 {nbytes} 30",
                            timeout=600).strip()
                    after = lastpath()
                    m = re.search(r"before=(\d+) peak=(\d+) final=(\d+)(.*)", o)
                    rec = {"row": row, "run": run, "variant": v, "path_after": after}
                    rec.update({"before": int(m[1]), "peak": int(m[2]), "final": int(m[3]), "note": m[4].strip()}
                               if m else {"error": o[-300:]})
                    emit("mem", rec)
                    log(f"mem {row} run{run} {v} {o} [{after}]")
                    ssh(CLI, f"{F} stop"); ssh(SRV, f"{F} stop")
    finally:
        ssh(SRV, f"{F} listen off")


# --- macOS and Windows clients against the Linux server ------------------------------------

seq = 0


def client_run(plat, v, d, n):
    global seq
    if plat == "win":
        p = subprocess.run(["pwsh", "-NoLogo", "-NoProfile", "-Command",
                            f"Invoke-Command -HostName {WIN} -SSHTransport -FilePath '{HERE}/win/wb.ps1' "
                            f"-ArgumentList {v},{d},{n} 2>&1"], capture_output=True, text=True, timeout=180)
        out = p.stdout + p.stderr
    else:
        # A window of the macsandbox tmux session, spawned and waited for (never send-keys).
        seq += 1
        job = f"ftb-{os.getpid()}-{seq}"
        ssh(MAC, "/opt/homebrew/bin/tmux new-window -d -t macsandbox "
                 f"\"{B}/mb.sh {v} {d} {n} > /tmp/{job}.log 2>&1; "
                 f"echo \\$? > /tmp/{job}.status; /opt/homebrew/bin/tmux wait-for -S {job}\" \\; wait-for {job}")
        out = ssh(MAC, f"cat /tmp/{job}.log; rm -f /tmp/{job}.log /tmp/{job}.status")
    line = next((l for l in out.splitlines() if l.startswith("{")), None)
    return json.loads(line) if line else {"variant": v, "dir": d, "flows": n, "error": out[-400:]}


def server_stat():
    return parse_stat(ssh(SRV, f"{F} stat").strip())


def remote(plat, rounds):
    """The client on macOS or Windows; the server and its settings as installed."""
    settings(DEFAULT_BUF, "off", False)
    baselines = ["none"] + (["tailscale"] if plat == "mac" and S["tailscale4"] else [])
    if "tailscale" in baselines:
        # Normally stopped on the Mac: up for this column's rounds only.
        log(f"tailscale up on {MAC}: {ssh(MAC, f'{MAC_TS} up 2>&1; sleep 5; {MAC_TS} status | head -1').strip()}")
    try:
        remote_rounds(plat, rounds, baselines)
    finally:
        if "tailscale" in baselines:
            log(f"tailscale down on {MAC}: {ssh(MAC, f'{MAC_TS} down 2>&1; {MAC_TS} status | head -1').strip()}")
        ssh(SRV, f"{F} stop")


def remote_rounds(plat, rounds, baselines):
    for rnd in range(1, rounds + 1):
        probe(plat, rnd)
        ssh(SRV, f"{F} stop")
        for variant in baselines:
            for n in (1, 4):
                for d in ("down", "up"):
                    gate(20)
                    r = client_run(plat, variant, d, n)
                    emit(plat, {"round": rnd, **r})
                    log(f"{plat} r{rnd} {variant} {d} x{n} {r.get('mbps', r)} retr {r.get('retr')} {r.get('path_after', '')}")
        for v in (VERSIONS if rnd % 2 else VERSIONS[::-1]):
            for n in (1, 4):
                for d in (("down", "up") if rnd % 2 else ("up", "down")):
                    r = {}
                    for attempt in range(5):
                        gate(40)
                        o = ssh(SRV, f"{F} server {v}")
                        if "ERR" in o:
                            r = {"variant": v, "dir": d, "flows": n, "error": o}; continue
                        s0 = server_stat()
                        r = client_run(plat, v, d, n)
                        s1 = server_stat()
                        if "error" not in r and not (on_bridge(r["path"]) and on_bridge(r["path_after"])):
                            emit("left-out", {"block": plat, "round": rnd, **r})
                            log(f"{plat} r{rnd} {v} {d} x{n} left out: {r['mbps']} [{r['path']} -> {r['path_after']}]")
                            r = {"variant": v, "dir": d, "flows": n, "error": "path off the server's address"}
                            continue
                        if "error" not in r:
                            r.update(drops_server=s1[0] - s0[0], cpu_server=round((s1[1] - s0[1]) / 100 / (s1[2] - s0[2]), 2),
                                     start_attempts=attempt)
                            break
                    emit(plat, {"round": rnd, **r})
                    log(f"{plat} r{rnd} {v} {d} x{n} {r.get('mbps', r)} retr {r.get('retr')} cpu c/s "
                        f"{r.get('cpu_client')}/{r.get('cpu_server')} [{r.get('path_after')}]")


def main():
    for spec in sys.argv[2:]:
        name, _, n = spec.partition(":")
        if name in COLUMNS:
            column(name, int(n or 10))
        elif name == "nc":
            nc(int(n or 3))
        elif name == "mem":
            mem(int(n or 2))
        elif name in ("mac", "win"):
            remote(name, int(n or 10))
        else:
            raise SystemExit(f"unknown kind {name}")
    settings(DEFAULT_BUF, "off", False)
    log("done")


if __name__ == "__main__":
    main()
