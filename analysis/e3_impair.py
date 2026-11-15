"""E3: does ds3sm track injected delay and loss? Per-condition comparison.

Usage (run from the repo root; paths are arguments):

    python -I analysis/e3_impair.py CAPTURE.pcapng RUN.sqlite MARKS.txt
        [--endpoint IP:PORT] [--settle-s 10] [--json OUT.json]

Inputs:
- CAPTURE: an Npcap capture taken on the same PC during the run.
- RUN: the ds3sm run database (`runs/<time>.sqlite`), from a ds3sm build
  that logs jitter and STUN counters in its `traffic` rows.
- MARKS: one line per impairment change, written the moment it was applied:
  `<ISO 8601 time with offset> <label>`, e.g. from PowerShell
  `"$(Get-Date -Format o) lag 50 both" | Add-Content runs\\e3_marks.txt`.
  Labels: `base`, `off`, `end`, `lag <ms> <both|in|out>`,
  `drop <percent> <both|in|out>`; anything else is kept as a free label.

Why the capture is ground truth: the impairment tool (WinDivert, used by
clumsy) sits between the transport layer, where ETW timestamps packets, and
the network adapter, where Npcap captures them. Outbound packets are delayed
or dropped before Npcap sees them, inbound ones after. So the capture sees
the network as it is, without the injected delay, and:
- ETW RTT - capture RTT = the injected round-trip delay (both directions);
- requests ds3sm saw but the capture didn't = outbound drops;
- replies the capture saw but ds3sm didn't = inbound drops.

For each condition (from 'settle' seconds after its mark to 2 s before the
next) it reports: ETW and capture RTT, their difference against the injected
delay, ds3sm's `nrep%` (from the logged STUN counters, with a 95 % Wilson
interval) against the injected loss, the measured drop rate each way,
inbound jitter (ds3sm's logged value and the capture estimator) and inbound
packets/s. Endpoints are printed cut to /24.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sqlite3
import statistics
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# `python -I` leaves the script's folder off sys.path; add it for the sibling module.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2_validate as ev  # noqa: E402

END_GUARD_NS = 2_000_000_000


@dataclass
class Mark:
    t_ns: int
    label: str


@dataclass
class Condition:
    kind: str  # "base", "lag", "drop" or "other"
    value: float = 0.0  # ms for lag, fraction for drop
    dirs: str = ""  # "both", "in" or "out"

    def expected_rtt_add_ms(self) -> float:
        if self.kind != "lag":
            return 0.0
        return self.value * (2 if self.dirs == "both" else 1)

    def expected_loss(self) -> float:
        """Share of our checks that should go unanswered: a check fails if the
        request is dropped on the way out or the reply on the way in."""
        if self.kind != "drop":
            return 0.0
        return 1 - (1 - self.value) ** 2 if self.dirs == "both" else self.value


LABEL = re.compile(r"^(lag|drop)\s+([0-9.]+)\s*%?\s+(both|in|out)$", re.I)


def parse_condition(label: str) -> Condition:
    s = label.strip().lower()
    if s in ("base", "off", "baseline"):
        return Condition("base")
    m = LABEL.match(s)
    if not m:
        return Condition("other")
    kind, v, dirs = m.group(1), float(m.group(2)), m.group(3)
    return Condition(kind, v if kind == "lag" else v / 100.0, dirs)


def parse_marks(text: str) -> list[Mark]:
    out = []
    for line in text.splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        ts, _, label = line.partition(" ")
        t = datetime.fromisoformat(ts)
        if t.tzinfo is None:
            raise SystemExit(f"mark time needs a UTC offset (use Get-Date -Format o): {line}")
        out.append(Mark((t - EPOCH) // timedelta(microseconds=1) * 1000, label.strip()))
    out.sort(key=lambda m: m.t_ns)
    return out


def segments(marks: list[Mark], settle_ns: int, last_ns: int) -> list[tuple[Mark, int, int]]:
    """(mark, start, end) per mark except `end`; the last one runs to `last_ns`."""
    out = []
    for i, m in enumerate(marks):
        if m.label.strip().lower() == "end":
            continue
        nxt = marks[i + 1].t_ns if i + 1 < len(marks) else last_ns
        lo, hi = m.t_ns + settle_ns, nxt - END_GUARD_NS
        if hi > lo:
            out.append((m, lo, hi))
    return out


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n <= 0:
        return None
    # A reply to a request just before the window can be matched inside it, so
    # k can be -1 on a lossless segment; clamp for the interval only.
    p = min(1.0, max(0.0, k / n))
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def counters_at(rows: list[tuple[int, int, int, int]], t_ns: int) -> tuple[int, int, int, int] | None:
    """ds3sm's running STUN counters from the last row at or before t: (row time, req, matched, lost)."""
    best = None
    for row in rows:
        if row[0] > t_ns:
            break
        best = row
    return best


def med(xs: list[float]) -> float | None:
    return statistics.median(xs) if xs else None


def analyse_segment(
    cond: Condition,
    lo: int,
    hi: int,
    etw: list[ev.EtwSample],
    pairs: list[ev.Pair],
    cap_req_t: list[int],
    traffic: list[tuple],
    track: list[tuple[int, float]],
) -> dict:
    e_rtt = [s.rtt_ms for s in etw if lo <= s.t_ns <= hi]
    c_rtt = [p.rtt_ms for p in pairs if lo <= p.t_reply <= hi]
    stun_rows = [(r[0], r[1], r[2], r[3]) for r in traffic if r[1] is not None]
    a, b = counters_at(stun_rows, lo), counters_at(stun_rows, hi)
    d: dict = {
        "label": "",
        "kind": cond.kind,
        "duration_s": (hi - lo) / 1e9,
        "expected_rtt_add_ms": cond.expected_rtt_add_ms(),
        "expected_loss": cond.expected_loss(),
        "etw_rtt_ms": ev.summarize(e_rtt),
        "capture_rtt_ms": ev.summarize(c_rtt),
        "rtt_add_ms": (med(e_rtt) - med(c_rtt)) if e_rtt and c_rtt else None,
    }
    # Loss is counted between the two traffic rows bracketing the condition,
    # and the capture over the same interval, so the counts line up.
    if a and b and b[1] > a[1]:
        ta, tb = a[0], b[0]
        n_req, n_mat = b[1] - a[1], b[2] - a[2]
        k = n_req - n_mat
        d["ds3sm_requests"] = n_req
        d["ds3sm_nrep"] = k / n_req
        d["ds3sm_nrep_ci95"] = wilson(k, n_req)
        n_cap_req = sum(1 for t in cap_req_t if ta < t <= tb)
        d["capture_requests"] = n_cap_req
        d["measured_drop_out"] = 1 - n_cap_req / n_req
        n_cap_pairs = sum(1 for p in pairs if ta < p.t_req <= tb)
        d["capture_answered"] = n_cap_pairs
        d["measured_drop_in"] = (1 - n_mat / n_cap_pairs) if n_cap_pairs else None
    jit = [r[4] for r in traffic if lo <= r[0] <= hi and r[4] is not None]
    d["ds3sm_jit_ms"] = med(jit)
    d["capture_jit_ms"] = med([v for t, v in track if lo <= t <= hi])
    d["pps_in"] = med([r[5] for r in traffic if lo <= r[0] <= hi])
    d["max_gap_in_ms"] = max((r[6] for r in traffic if lo <= r[0] <= hi), default=None)
    return d


def load_traffic(db: sqlite3.Connection, ep: tuple[str, int]) -> list[tuple]:
    cols = {r[1] for r in db.execute("PRAGMA table_info(traffic)")}
    need = {"stun_req", "stun_matched", "stun_lost", "jit_in_ms"}
    if not need <= cols:
        raise SystemExit("this run database has no STUN counters/jitter in `traffic`; use a newer ds3sm build")
    return db.execute(
        "SELECT t_ns, stun_req, stun_matched, stun_lost, jit_in_ms, pps_in, max_gap_in_ms FROM traffic "
        "WHERE remote_ip = ? AND remote_port = ? ORDER BY t_ns",
        (ep[0], ep[1]),
    ).fetchall()


def analyse(capture: str, db_path: str, marks_path: str, endpoint: tuple[str, int] | None, settle_s: float) -> dict:
    with open(marks_path, encoding="utf-8-sig") as f:
        marks = parse_marks(f.read())
    if not marks:
        raise SystemExit("no marks")
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        ep, kind = (endpoint, "given") if endpoint else ev.db_endpoint(db)
        etw = ev.load_etw(db, ep)
        traffic = load_traffic(db, ep)
    finally:
        db.close()
    udps = [u for u in (ev.decode_udp(fr) for fr in ev.read_capture(capture)) if u is not None]
    dg = ev.to_dgrams(udps, ep)
    truth = ev.pair_by_txid(dg)
    cap_req_t = [g.t_ns for g in dg if ev.is_req(g)]
    inbound = sorted((u.t_ns, u.size) for u in udps if u.src == ep)
    _, track = ev.jitter_track(inbound)
    last = max(dg[-1].t_ns if dg else 0, traffic[-1][0] if traffic else 0)
    out = []
    for m, lo, hi in segments(marks, int(settle_s * 1e9), last):
        d = analyse_segment(parse_condition(m.label), lo, hi, etw, truth.pairs, cap_req_t, traffic, track)
        d["label"] = m.label
        out.append(d)
    return {"endpoint": ev.mask(ep), "endpoint_kind": kind, "settle_s": settle_s, "conditions": out}


def _p(x, nd=1, pct=False):
    if x is None:
        return "-"
    return f"{100 * x:.{nd}f}" if pct else f"{x:.{nd}f}"


def print_report(r: dict) -> None:
    print(f"Endpoint: {r['endpoint']} ({r['endpoint_kind']}); each condition from {r['settle_s']:.0f} s after its mark")
    print(
        f"{'condition':<18} {'s':>4} | {'ETW med':>8} {'cap med':>8} {'added':>7} {'expect':>7} | "
        f"{'nrep%':>6} {'95% CI':>13} {'expect':>6} {'n':>4} {'out%':>5} {'in%':>5} | "
        f"{'jit':>5} {'capJ':>5} {'pps':>5} {'gap':>6}"
    )
    for d in r["conditions"]:
        ci = d.get("ds3sm_nrep_ci95")
        ci_s = f"{100 * ci[0]:.1f}-{100 * ci[1]:.1f}" if ci else "-"
        e, c = d["etw_rtt_ms"], d["capture_rtt_ms"]
        print(
            f"{d['label'][:18]:<18} {d['duration_s']:>4.0f} | "
            f"{_p(e['median'] if e else None, 2):>8} {_p(c['median'] if c else None, 2):>8} "
            f"{_p(d['rtt_add_ms'], 1):>7} {_p(d['expected_rtt_add_ms'], 0):>7} | "
            f"{_p(d.get('ds3sm_nrep'), 1, True):>6} {ci_s:>13} {_p(d['expected_loss'], 1, True):>6} "
            f"{d.get('ds3sm_requests', '-'):>4} {_p(d.get('measured_drop_out'), 1, True):>5} "
            f"{_p(d.get('measured_drop_in'), 1, True):>5} | "
            f"{_p(d['ds3sm_jit_ms'], 2):>5} {_p(d['capture_jit_ms'], 2):>5} {_p(d['pps_in'], 0):>5} "
            f"{_p(d['max_gap_in_ms'], 0):>6}"
        )
    print(
        "\nadded = ETW RTT median - capture RTT median (the capture doesn't see injected delay); "
        "out%/in% = drops measured as requests ds3sm saw but the capture didn't / replies the capture saw "
        "but ds3sm didn't; jit = ds3sm's logged inbound jitter, capJ = the same estimator on the capture "
        "(before inbound delay/drops); gap = largest inbound gap ds3sm logged (running maximum)."
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture")
    ap.add_argument("run_db")
    ap.add_argument("marks")
    ap.add_argument("--endpoint", help="IP:PORT (default: from the run database)")
    ap.add_argument("--settle-s", type=float, default=10.0)
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    r = analyse(a.capture, a.run_db, a.marks, ev.parse_endpoint(a.endpoint) if a.endpoint else None, a.settle_s)
    print_report(r)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
