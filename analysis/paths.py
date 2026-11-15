"""E4 and E5: path episodes per peer from ds3sm run databases.

Usage (run from the repo root; paths are arguments):

    python -I analysis/paths.py RUN.sqlite [RUN2.sqlite ...]
        [--settle-s 5] [--min-samples 10] [--home-lat LAT --home-lon LON]
        [--salt TEXT] [--json OUT.json]

No capture is needed: everything comes from what ds3sm logs.

Episodes. A peer's session is cut into episodes wherever its path changes:
- the path kind: `tcp` (Steam's TCP fallback), `relay` (any enabled relay
  detector fired, as logged in `relay_evidence`, or Steam's own relay flag in
  older runs), or `direct`;
- the IP of Steam's reported remote endpoint (so a failover from one relay
  site to another starts a new episode, but a direct path re-punched on a new
  port does not);
- the session going inactive.
Change points come from `p2p_state` (logged on change), `relay_evidence` and
`tcp_fallback`/`tcp_fallback_end` events. The first `settle` seconds of each
episode are skipped for the statistics (path transitions are noisy).

Per episode: RTT minimum, median and p95 (ETW STUN samples, or TCP's own
samples on the fallback), the median inbound jitter of the peer's dominant
inbound stream, the STUN no-reply share (`nrep`) with a 95 % Wilson interval,
and the median inbound packets/s.

E4 (relay cost): for each peer seen on more than one path kind in a run, the
median RTT and jitter of each kind and their difference.

E5 (inflation over the fiber bound): for each peer on a direct internet path
with a geolocation, the great-circle distance, the fiber bound (2/3 c, there
and back) and the inflation ratio `min RTT / bound` (and `median / bound`).
The bound comes from the run's `geo` table, or is recomputed from the stored
coordinates when `--home-lat/--home-lon` are given. A geolocation whose
accuracy radius exceeds half the distance is flagged `coarse`.

Privacy: Steam IDs are shown as salted SHA-256 pseudonyms (the same
construction as ds3sm's export; the salt is random per invocation unless
`--salt` is given, so pseudonyms match across the runs of one invocation)
and endpoints as /24, or `LAN` for private addresses.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import sqlite3
import statistics
import sys
from dataclasses import asdict, dataclass, field

C_KM_S = 299_792.458
FIBER_FRACTION = 2.0 / 3.0
EARTH_RADIUS_KM = 6_371.0088
S = 1_000_000_000

EVIDENCE = re.compile(r"^(\d+) .*\brelayed=([01]) remote=(\S+)$")
ID_REMOTE = re.compile(r"^(\d+) (\S+)$")


# ---------------------------------------------------------------- helpers


def pseudonym(salt: str, steam_id: int) -> str:
    h = hashlib.sha256(salt.encode() + steam_id.to_bytes(8, "little"))
    return h.hexdigest()[:12]


NON_PUBLIC = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "0.0.0.0/32", "255.255.255.255/32",
)]


def is_private(ip: str | None) -> bool:
    """The same ranges as `geo::is_non_public` in ds3sm (Python's own
    `is_private` also covers the documentation ranges, which ds3sm doesn't)."""
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return a.version == 4 and any(a in n for n in NON_PUBLIC)


def mask(ip: str | None) -> str:
    if not ip:
        return "-"
    if is_private(ip):
        return "LAN"
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return "?"


def pct(xs: list[float], q: float) -> float | None:
    """Linear-interpolated percentile, q in [0, 1]."""
    if not xs:
        return None
    s = sorted(xs)
    k = (len(s) - 1) * q
    lo = math.floor(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def med(xs: list[float]) -> float | None:
    return statistics.median(xs) if xs else None


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n <= 0:
        return None
    p = min(1.0, max(0.0, k / n))
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def great_circle_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(h)))


def fiber_bound_ms(distance_km: float) -> float:
    return 2 * distance_km / (C_KM_S * FIBER_FRACTION) * 1000


def ip_of(endpoint: str | None) -> str | None:
    if not endpoint or endpoint == "-":
        return None
    return endpoint.rsplit(":", 1)[0]


# ---------------------------------------------------------------- timeline


@dataclass
class PeerState:
    active: bool = False
    relayed: bool = False
    on_tcp: bool = False
    remote: str | None = None  # "ip:port"

    def path(self) -> str | None:
        if not self.active:
            return None
        if self.on_tcp:
            return "tcp"
        return "relay" if self.relayed else "direct"

    def key(self) -> tuple | None:
        # The remote's IP, not its port: Steam re-punches a direct path on a
        # new port without the path changing; a relay failover changes the IP.
        p = self.path()
        return None if p is None else (p, ip_of(self.remote))


@dataclass
class Episode:
    run: str
    peer: int
    path: str
    remote: str | None
    start_ns: int
    end_ns: int
    stats: dict = field(default_factory=dict)


def has_table(db: sqlite3.Connection, name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def changes(db: sqlite3.Connection) -> dict[int, list[tuple[int, str, dict]]]:
    """Per peer, time-ordered change points: (t, kind, fields)."""
    out: dict[int, list[tuple[int, str, dict]]] = {}
    for t, sid, active, connecting, relay, ip, port in db.execute(
        "SELECT t_ns, steam_id, active, connecting, using_relay, remote_ip, remote_port FROM p2p_state ORDER BY t_ns"
    ):
        remote = f"{ip}:{port}" if ip else None
        out.setdefault(sid, []).append(
            (t, "state", {"active": bool(active) and not connecting, "flag": bool(relay), "remote": remote})
        )
    for t, kind, detail in db.execute(
        "SELECT t_ns, kind, detail FROM event WHERE kind IN "
        "('relay_evidence', 'tcp_fallback', 'tcp_fallback_end', 'peer_left') ORDER BY t_ns"
    ):
        if kind == "relay_evidence":
            m = EVIDENCE.match(detail)
            if m:
                rem = None if m.group(3) == "-" else m.group(3)
                out.setdefault(int(m.group(1)), []).append((t, "evidence", {"relayed": m.group(2) == "1", "remote": rem}))
        elif kind == "peer_left":
            if detail.strip().isdigit():
                out.setdefault(int(detail), []).append((t, "left", {}))
        else:
            m = ID_REMOTE.match(detail)
            if m:
                out.setdefault(int(m.group(1)), []).append((t, "tcp", {"on": kind == "tcp_fallback"}))
    for v in out.values():
        v.sort(key=lambda c: c[0])
    return out


def episodes_for_peer(run: str, peer: int, points: list[tuple[int, str, dict]], end_ns: int) -> list[Episode]:
    st = PeerState()
    seen_evidence = False
    eps: list[Episode] = []
    cur: Episode | None = None

    def close(t: int) -> None:
        nonlocal cur
        if cur is not None:
            cur.end_ns = t
            if cur.end_ns > cur.start_ns:
                eps.append(cur)
            cur = None

    i = 0
    while i < len(points):
        t = points[i][0]
        # Apply every change at the same instant before deciding the state.
        while i < len(points) and points[i][0] == t:
            _, kind, f = points[i]
            if kind == "state":
                st.active = f["active"]
                st.remote = f["remote"]
                if not seen_evidence:
                    st.relayed = f["flag"]
            elif kind == "evidence":
                seen_evidence = True
                st.relayed = f["relayed"]
                if f["remote"]:
                    st.remote = f["remote"]
            elif kind == "tcp":
                st.on_tcp = f["on"]
            elif kind == "left":
                st = PeerState()
            i += 1
        k = st.key()
        if cur is not None and (cur.path, ip_of(cur.remote)) == k:
            continue
        close(t)
        if k is not None:
            cur = Episode(run, peer, k[0], st.remote, t, t)
    close(end_ns)
    return eps


# ---------------------------------------------------------------- statistics


def episode_stats(db: sqlite3.Connection, ep: Episode, settle_ns: int) -> dict:
    lo, hi = ep.start_ns + settle_ns, ep.end_ns
    d: dict = {"duration_s": (ep.end_ns - ep.start_ns) / S}
    if hi <= lo:
        return d
    src = "tcp_estats" if ep.path == "tcp" else "etw_stun"
    rtt = [r for (r,) in db.execute(
        "SELECT rtt_ms FROM rtt WHERE steam_id = ? AND source = ? AND t_ns BETWEEN ? AND ?",
        (ep.peer, src, lo, hi),
    )]
    d["rtt_source"] = src
    d["n_rtt"] = len(rtt)
    d["rtt_min"], d["rtt_p50"], d["rtt_p95"] = min(rtt, default=None), med(rtt), pct(rtt, 0.95)
    if not has_table(db, "traffic"):
        return d
    cols = {r[1] for r in db.execute("PRAGMA table_info(traffic)")}
    jit_col = "jit_in_ms" if "jit_in_ms" in cols else "NULL"
    rows = db.execute(
        f"SELECT t_ns, remote_ip, remote_port, pps_in, {jit_col} FROM traffic "
        "WHERE steam_id = ? AND t_ns BETWEEN ? AND ? ORDER BY t_ns",
        (ep.peer, lo, hi),
    ).fetchall()
    # The dominant inbound stream at each logging instant carries the jitter.
    best: dict[int, tuple] = {}
    for r in rows:
        if r[0] not in best or r[3] > best[r[0]][3]:
            best[r[0]] = r
    d["pps_in"] = med([r[3] for r in best.values()])
    d["jit_in_ms"] = med([r[4] for r in best.values() if r[4] is not None])
    # On the TCP fallback Steam's UDP checks go unanswered by design, so their
    # no-reply share says nothing about the path in use.
    if {"stun_req", "stun_matched"} <= cols and ep.path != "tcp":
        req = mat = 0
        for ip, port in {(r[1], r[2]) for r in rows}:
            c = db.execute(
                "SELECT stun_req, stun_matched FROM traffic WHERE steam_id = ? AND remote_ip = ? AND remote_port = ? "
                "AND t_ns BETWEEN ? AND ? AND stun_req IS NOT NULL ORDER BY t_ns",
                (ep.peer, ip, port, lo, hi),
            ).fetchall()
            if len(c) >= 2:
                req += c[-1][0] - c[0][0]
                mat += c[-1][1] - c[0][1]
        if req > 0:
            k = req - mat
            d["stun_req"] = req
            d["nrep"] = max(0.0, k / req)
            d["nrep_ci95"] = wilson(k, req)
    return d


def run_end_ns(db: sqlite3.Connection) -> int:
    ts = [r[0] for r in (
        db.execute("SELECT max(t_ns) FROM event").fetchone(),
        db.execute("SELECT max(t_ns) FROM rtt").fetchone(),
        db.execute("SELECT max(t_ns) FROM p2p_state").fetchone(),
    ) if r[0] is not None]
    return max(ts) if ts else 0


def load_run(path: str, settle_ns: int) -> tuple[str, list[Episode], dict[int, dict]]:
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        meta = dict(db.execute("SELECT key, value FROM meta"))
        run = meta.get("label") or os.path.splitext(os.path.basename(path))[0]
        end = run_end_ns(db)
        eps: list[Episode] = []
        for peer, pts in changes(db).items():
            for ep in episodes_for_peer(run, peer, pts, end):
                ep.stats = episode_stats(db, ep, settle_ns)
                eps.append(ep)
        eps.sort(key=lambda e: (e.peer, e.start_ns))
        geo: dict[int, dict] = {}
        if has_table(db, "geo"):
            cols = {r[1] for r in db.execute("PRAGMA table_info(geo)")}
            where = "WHERE subject = 'peer'" if "subject" in cols else ""
            for sid, cc, lat, lon, acc, dist, bound in db.execute(
                f"SELECT steam_id, country, lat, lon, accuracy_km, distance_km, fiber_bound_ms FROM geo {where}"
            ):
                geo[sid] = {"country": cc, "lat": lat, "lon": lon, "accuracy_km": acc,
                            "distance_km": dist, "bound_ms": bound}
        return run, eps, geo
    finally:
        db.close()


# ---------------------------------------------------------------- E4 and E5


def relay_cost(eps: list[Episode], min_samples: int) -> list[dict]:
    """Per (run, peer) seen on two or more path kinds: each kind's median RTT and jitter."""
    groups: dict[tuple[str, int], dict[str, list[Episode]]] = {}
    for e in eps:
        if e.stats.get("n_rtt", 0) >= min_samples:
            groups.setdefault((e.run, e.peer), {}).setdefault(e.path, []).append(e)
    out = []
    for (run, peer), by in groups.items():
        if len(by) < 2:
            continue
        row: dict = {"run": run, "peer": peer}
        for kind, es in by.items():
            row[kind] = {
                "episodes": len(es),
                "rtt_p50": med([x.stats["rtt_p50"] for x in es]),
                "jit_in_ms": med([x.stats["jit_in_ms"] for x in es if x.stats.get("jit_in_ms") is not None]),
                "nrep": med([x.stats["nrep"] for x in es if "nrep" in x.stats]),
            }
        if "direct" in row:
            for kind in ("relay", "tcp"):
                if kind in row and row[kind]["rtt_p50"] is not None:
                    row[f"{kind}_minus_direct_rtt"] = row[kind]["rtt_p50"] - row["direct"]["rtt_p50"]
        out.append(row)
    return out


def inflation(eps: list[Episode], geo: dict[tuple[str, int], dict], home: tuple[float, float] | None,
              min_samples: int) -> list[dict]:
    """Per peer (pooled over its direct internet episodes): distance, bound and inflation."""
    pooled: dict[int, dict] = {}
    for e in eps:
        if e.path != "direct" or is_private(ip_of(e.remote)) or e.stats.get("n_rtt", 0) < min_samples:
            continue
        g = geo.get((e.run, e.peer))
        if not g:
            continue
        dist, bound = g["distance_km"], g["bound_ms"]
        if home and g["lat"] is not None and g["lon"] is not None:
            dist = great_circle_km(home[0], home[1], g["lat"], g["lon"])
            bound = fiber_bound_ms(dist)
        if not bound:
            continue
        p = pooled.setdefault(e.peer, {"peer": e.peer, "country": g["country"], "distance_km": dist,
                                       "bound_ms": bound, "accuracy_km": g["accuracy_km"],
                                       "rtt_min": math.inf, "p50s": [], "n_rtt": 0})
        p["rtt_min"] = min(p["rtt_min"], e.stats["rtt_min"])
        p["p50s"].append(e.stats["rtt_p50"])
        p["n_rtt"] += e.stats["n_rtt"]
    out = []
    for p in pooled.values():
        p50 = med(p.pop("p50s"))
        p["rtt_p50"] = p50
        p["inflation_min"] = p["rtt_min"] / p["bound_ms"]
        p["inflation_p50"] = p50 / p["bound_ms"]
        acc = p["accuracy_km"]
        p["coarse"] = bool(acc is not None and p["distance_km"] and acc > p["distance_km"] / 2)
        out.append(p)
    out.sort(key=lambda r: r["distance_km"] or 0)
    return out


# ---------------------------------------------------------------- output


def _f(x, nd: int = 1) -> str:
    if x is None:
        return "-"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def print_report(eps: list[Episode], cost: list[dict], infl: list[dict], name) -> None:
    print("Episodes (stats skip each episode's settle time)")
    print(f"{'run':<22} {'peer':<12} {'path':<6} {'remote':<18} {'dur s':>7} {'n':>5} "
          f"{'min':>7} {'p50':>7} {'p95':>7} {'jit':>6} {'nrep%':>6} {'pps':>5}")
    for e in eps:
        s = e.stats
        nrep = s.get("nrep")
        print(f"{e.run[:22]:<22} {name(e.peer):<12} {e.path:<6} {mask(ip_of(e.remote)):<18} "
              f"{_f(s.get('duration_s'), 0):>7} {_f(s.get('n_rtt')):>5} {_f(s.get('rtt_min')):>7} "
              f"{_f(s.get('rtt_p50')):>7} {_f(s.get('rtt_p95')):>7} {_f(s.get('jit_in_ms'), 2):>6} "
              f"{_f(None if nrep is None else 100 * nrep):>6} {_f(s.get('pps_in'), 0):>5}")
    print("\nE4: same peer on more than one path kind (medians of episode medians, ms)")
    if not cost:
        print("  none")
    for r in cost:
        parts = [f"{k} rtt {_f(r[k]['rtt_p50'])} jit {_f(r[k]['jit_in_ms'], 2)} (n={r[k]['episodes']})"
                 for k in ("direct", "relay", "tcp") if k in r]
        extra = "".join(f"  {k} {r[k]:+.1f}" for k in ("relay_minus_direct_rtt", "tcp_minus_direct_rtt") if k in r)
        print(f"  {r['run'][:22]:<22} {name(r['peer']):<12} " + "; ".join(parts) + extra)
    print("\nE5: direct internet peers with a geolocation")
    if not infl:
        print("  none (needs direct internet peers and a geo row with a fiber bound or --home-lat/--home-lon)")
        return
    print(f"  {'peer':<12} {'cc':<3} {'km':>7} {'bound':>7} {'min':>7} {'p50':>7} {'x min':>6} {'x p50':>6}  note")
    for r in infl:
        note = "coarse" if r["coarse"] else ""
        print(f"  {name(r['peer']):<12} {r['country'] or '-':<3} {_f(r['distance_km'], 0):>7} "
              f"{_f(r['bound_ms']):>7} {_f(r['rtt_min']):>7} {_f(r['rtt_p50']):>7} "
              f"{_f(r['inflation_min'], 2):>6} {_f(r['inflation_p50'], 2):>6}  {note}")
    xs = [r["inflation_min"] for r in infl if not r["coarse"]]
    if xs:
        print(f"  inflation (min RTT / bound), {len(xs)} peers not coarse: median {med(xs):.2f}, "
              f"p25 {pct(xs, 0.25):.2f}, p75 {pct(xs, 0.75):.2f}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("runs", nargs="+", help="ds3sm run databases (runs/<time>.sqlite)")
    ap.add_argument("--settle-s", type=float, default=5.0, help="seconds skipped at each episode start")
    ap.add_argument("--min-samples", type=int, default=10, help="RTT samples an episode needs for E4/E5")
    ap.add_argument("--home-lat", type=float)
    ap.add_argument("--home-lon", type=float)
    ap.add_argument("--salt", help="pseudonym salt (default: random per invocation)")
    ap.add_argument("--json", help="write the full result (pseudonymised) to this file")
    a = ap.parse_args(argv)
    if (a.home_lat is None) != (a.home_lon is None):
        ap.error("--home-lat and --home-lon go together")
    salt = a.salt if a.salt is not None else os.urandom(16).hex()

    def name(sid: int) -> str:
        return pseudonym(salt, sid)

    eps: list[Episode] = []
    geo: dict[tuple[str, int], dict] = {}
    for path in a.runs:
        run, e, g = load_run(path, int(a.settle_s * S))
        eps += e
        geo.update({(run, sid): v for sid, v in g.items()})
    home = (a.home_lat, a.home_lon) if a.home_lat is not None else None
    cost = relay_cost(eps, a.min_samples)
    infl = inflation(eps, geo, home, a.min_samples)
    print_report(eps, cost, infl, name)
    if a.json:
        def anon(d: dict) -> dict:
            d = dict(d)
            if "peer" in d:
                d["peer"] = name(d["peer"])
            if "remote" in d:
                d["remote"] = mask(ip_of(d["remote"]))
            return d
        out = {
            "episodes": [anon(asdict(e)) for e in eps],
            "relay_cost": [anon(r) for r in cost],
            "inflation": [anon(r) for r in infl],
        }
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
