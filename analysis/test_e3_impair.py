"""Unit tests for e3_impair.py on synthetic data.

Run from the repo root:  python -I analysis/test_e3_impair.py
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import e2_validate as ev  # noqa: E402
import e3_impair as e3  # noqa: E402
from test_e2_validate import LOCAL, PEER, T0, stun_payload, txid, udp_frame, write_pcapng  # noqa: E402

S = 1_000_000_000
MS = 1_000_000


class Labels(unittest.TestCase):
    def test_conditions(self):
        c = e3.parse_condition("lag 50 both")
        self.assertEqual((c.kind, c.value, c.dirs), ("lag", 50.0, "both"))
        self.assertEqual(c.expected_rtt_add_ms(), 100.0)
        self.assertEqual(e3.parse_condition("lag 50 out").expected_rtt_add_ms(), 50.0)
        d = e3.parse_condition("drop 10 both")
        self.assertAlmostEqual(d.expected_loss(), 0.19)
        self.assertAlmostEqual(e3.parse_condition("drop 10% in").expected_loss(), 0.10)
        self.assertEqual(e3.parse_condition("base").kind, "base")
        self.assertEqual(e3.parse_condition("waved at PC-B").kind, "other")

    def test_marks_and_segments(self):
        text = "\ufeff2026-11-14T22:00:00.1234567-08:00 base\n\n2026-11-14T22:02:00-08:00 lag 25 both\n" \
               "2026-11-14T22:04:00-08:00 end\n"
        m = e3.parse_marks(text)
        self.assertEqual([x.label for x in m], ["base", "lag 25 both", "end"])
        self.assertEqual(m[1].t_ns - m[0].t_ns, 120 * S - 123_456_000)
        seg = e3.segments(m, 10 * S, m[-1].t_ns + 60 * S)
        self.assertEqual(len(seg), 2)
        self.assertEqual(seg[0][1], m[0].t_ns + 10 * S)
        self.assertEqual(seg[1][2], m[2].t_ns - e3.END_GUARD_NS)

    def test_marks_need_an_offset(self):
        with self.assertRaises(SystemExit):
            e3.parse_marks("2026-11-14T22:00:00 base")

    def test_wilson(self):
        lo, hi = e3.wilson(19, 100)
        self.assertLess(lo, 0.19)
        self.assertGreater(hi, 0.19)
        self.assertAlmostEqual(lo, 0.1251, places=3)
        self.assertIsNone(e3.wilson(0, 0))
        # One extra match at a window edge: k = -1 must not crash.
        self.assertEqual(e3.wilson(-1, 300)[0], 0.0)


class EndToEnd(unittest.TestCase):
    """Base 60 s, then 'lag 50 both' 60 s with every 5th reply dropped inbound."""

    def test_delay_and_inbound_drops(self):
        frames, etw, rows = [], [], []
        n_req = n_mat = 0
        mark2 = T0 + 60 * S
        for i in range(240):  # one check every 500 ms for 120 s
            t = T0 + i * 500 * MS
            lagged = t >= mark2
            add = 50 * MS if lagged else 0
            # ETW sees the request at t; the capture after the outbound delay.
            frames.append((t + add, udp_frame(LOCAL, PEER, stun_payload(0, txid(i), 56))))
            reply_nic = t + add + 300_000
            frames.append((reply_nic, udp_frame(PEER, LOCAL, stun_payload(2, txid(i), 68))))
            n_req += 1
            if lagged and i % 5 == 0:
                continue  # dropped inbound, after the capture saw it
            n_mat += 1
            etw.append((reply_nic + add, (reply_nic + add - t) / 1e6))
            if (i + 1) % 10 == 0:
                rows.append((t + 100 * MS, n_req, n_mat, n_req - n_mat))
        # 12 Hz inbound stream for the jitter columns.
        for k in range(int(120 * 12)):
            frames.append((T0 + k * 83_333_333, udp_frame(PEER, LOCAL, b"\0" * 85)))
        frames.sort()
        with tempfile.TemporaryDirectory() as d:
            cap, db = os.path.join(d, "c.pcapng"), os.path.join(d, "r.sqlite")
            write_pcapng(cap, frames, tsresol=9)
            c = sqlite3.connect(db)
            c.executescript(
                "CREATE TABLE meta (key TEXT, value TEXT);"
                "CREATE TABLE p2p_state (t_ns INTEGER, steam_id INTEGER, remote_ip TEXT, remote_port INTEGER);"
                "CREATE TABLE event (t_ns INTEGER, kind TEXT, detail TEXT);"
                "CREATE TABLE rtt (t_ns INTEGER, steam_id INTEGER, remote_ip TEXT, remote_port INTEGER, rtt_ms REAL);"
                "CREATE TABLE traffic (t_ns INTEGER, remote_ip TEXT, remote_port INTEGER, pps_in REAL,"
                " max_gap_in_ms REAL, jit_in_ms REAL, stun_req INTEGER, stun_matched INTEGER, stun_lost INTEGER);"
            )
            c.execute("INSERT INTO p2p_state VALUES (1, 7, ?, ?)", PEER)
            c.executemany("INSERT INTO rtt VALUES (?, 7, ?, ?, ?)", [(t, PEER[0], PEER[1], r) for t, r in etw])
            c.executemany(
                "INSERT INTO traffic VALUES (?, ?, ?, 19.0, 90.0, 0.4, ?, ?, ?)",
                [(t, PEER[0], PEER[1], a, b, l) for t, a, b, l in rows],
            )
            c.commit()
            c.close()
            marks = os.path.join(d, "m.txt")
            from datetime import datetime, timezone

            def iso(t):
                return datetime.fromtimestamp(t / 1e9, timezone.utc).isoformat()

            with open(marks, "w", encoding="utf-8") as f:
                f.write(f"{iso(T0)} base\n{iso(mark2)} lag 50 both\n{iso(T0 + 120 * S)} end\n")
            r = e3.analyse(cap, db, marks, None, settle_s=10)
        base, lag = r["conditions"]
        self.assertAlmostEqual(base["rtt_add_ms"], 0.0, places=6)
        self.assertAlmostEqual(lag["rtt_add_ms"], 100.0, places=6)
        self.assertEqual(lag["expected_rtt_add_ms"], 100.0)
        self.assertAlmostEqual(base["ds3sm_nrep"], 0.0)
        self.assertAlmostEqual(lag["ds3sm_nrep"], 0.2, places=2)
        self.assertAlmostEqual(lag["measured_drop_out"], 0.0, places=2)
        self.assertAlmostEqual(lag["measured_drop_in"], 0.2, delta=0.03)
        self.assertLess(lag["capture_jit_ms"], 0.01)
        self.assertEqual(lag["ds3sm_jit_ms"], 0.4)
        self.assertEqual(r["endpoint"], ev.mask(PEER))


if __name__ == "__main__":
    unittest.main(verbosity=1)
