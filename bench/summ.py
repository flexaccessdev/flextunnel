#!/usr/bin/env python3
"""summ.py LABEL [KIND ...]: medians per kind, variant, flow count and direction, the
range, how often each version was ahead of the other in a round, and the runs to look at."""
import glob, json, os, statistics as st, sys
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "target/bench", sys.argv[1])
S = json.load(open(os.path.join(OUT, "session.json")))
skip = ("left-out",)
kinds = sys.argv[2:] or sorted(os.path.basename(p)[:-6] for p in glob.glob(f"{OUT}/*.jsonl")
                               if not os.path.basename(p)[:-6].endswith("-host") and os.path.basename(p)[:-6] not in skip)


def med(xs):
    xs = [x for x in xs if x is not None]
    return st.median(xs) if xs else None


def fmt(x, p=0):
    return "-" if x is None else f"{x:.{p}f}"


for kind in kinds:
    rows = [json.loads(l) for l in open(f"{OUT}/{kind}.jsonl")]
    errs = [r for r in rows if "error" in r]
    print(f"== {kind}: {len(rows) - len(errs)} runs, {len(errs)} errors")
    if kind == "mem":
        g = defaultdict(list)
        for r in rows:
            if "peak" in r:
                g[(r["row"], r["variant"])].append(r["final"])
        for (row, v), xs in sorted(g.items()):
            print(f"  {row:18} {v:6} final MB {sorted(xs)}")
        continue
    rows = [r for r in rows if "mbps" in r]
    g = defaultdict(list)
    for r in rows:
        g[(r.get("what", ""), r.get("flows", 1), r["variant"], r["dir"])].append(r)
    for key in sorted(g, key=lambda k: (k[0], k[1], k[2] not in ("none", "tailscale"), k[2], k[3])):
        what, n, v, d = key
        rs = g[key]
        m = [r["mbps"] for r in rs]
        recv = "drops_client" if d == "down" else "drops_server"
        print(f"  {what:7} x{n} {v:9} {d:4} n={len(m):2} med={med(m):6.0f} min={min(m):6.0f} max={max(m):6.0f} "
              f"retr={fmt(med([r.get('retr') for r in rs]))} drops={fmt(med([r.get(recv) for r in rs]))} "
              f"cpu c/s={fmt(med([r.get('cpu_client') for r in rs]), 2)}/{fmt(med([r.get('cpu_server') for r in rs]), 2)}")
    if len(S["versions"]) == 2:
        a, b = S["versions"]
        for (what, n, v, d) in sorted({k for k in g if k[2] == b}):
            ra = {r["round"]: r["mbps"] for r in g.get((what, n, a, d), [])}
            rb = {r["round"]: r["mbps"] for r in g[(what, n, b, d)]}
            both = sorted(set(ra) & set(rb))
            if both:
                ahead = sum(rb[x] > ra[x] for x in both)
                print(f"  {what:7} x{n} {d:4}: {b} ahead of {a} in {ahead} of {len(both)} rounds, "
                      f"median {100 * (med(list(rb.values())) / med(list(ra.values())) - 1):+.1f}%")
    odd = [r for r in rows if r["variant"] not in ("none", "tailscale")
           and (r.get("retries") or r.get("start_attempts")
                or ("Direct " + S["server4"] + ":") not in (r.get("path_after") or ""))]
    for r in odd:
        print("  note:", {k: r.get(k) for k in ("round", "variant", "dir", "flows", "mbps", "path", "path_after",
                                                "retries", "start_attempts")})
lo = os.path.join(OUT, "left-out.jsonl")
if os.path.exists(lo):
    print(f"== left out: {sum(1 for _ in open(lo))} runs whose path left the server's address (see left-out.jsonl)")
