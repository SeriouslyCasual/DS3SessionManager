"""Unit tests for paths.py on a synthetic run database.

Run from the repo root:  python -I analysis/test_paths.py
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import paths  # noqa: E402

S = 1_000_000_000
PEER = 76561190000000001
LAN = "192.168.1.15"
RELAY = "203.0.113.75"  # TEST-NET-3 stands in for a relay
WAN = "198.51.100.20"  # TEST-NET-2 stands in for an internet peer

SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE p2p_state (t_ns INTEGER, steam_id INTEGER, active INTEGER, connecting INTEGER, error INTEGER,
    using_relay INTEGER, bytes_queued INTEGER, packets_queued INTEGER, remote_ip TEXT, remote_port INTEGER);
CREATE TABLE rtt (t_ns INTEGER, steam_id INTEGER, remote_ip TEXT, remote_port INTEGER, rtt_ms REAL, source TEXT);
CREATE TABLE event (t_ns INTEGER, kind TEXT, detail TEXT);
CREATE TABLE geo (steam_id INTEGER, country TEXT, city TEXT, lat REAL, lon REAL, accuracy_km INTEGER,
    distance_km REAL, fiber_bound_ms REAL, subject TEXT NOT NULL DEFAULT 'peer', site TEXT);
CREATE TABLE traffic (t_ns INTEGER, steam_id INTEGER, remote_ip TEXT, remote_port INTEGER, role TEXT,
    pps_in REAL, pps_out REAL, pkts_in INTEGER, pkts_out INTEGER, bytes_in INTEGER, bytes_out INTEGER,
    payload_in INTEGER, payload_out INTEGER, max_gap_in_ms REAL, jit_in_ms REAL, stream_in_size INTEGER,
    period_in_ms REAL, jit_out_ms REAL, stream_out_size INTEGER, period_out_ms REAL,
    stun_req INTEGER, stun_matched INTEGER, stun_lost INTEGER);
"""


def make_run(path: str, peer_ip: str = LAN, geo: tuple | None = None) -> None:
    """Direct 0-60 s (1 ms), relay 60-120 s (20 ms, 10 % no-reply), TCP 120-180 s (40 ms), direct port 2 180-240 s."""
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    db.execute("INSERT INTO meta VALUES ('label', 'synthetic')")

    def state(t, ip, port, active=1, relay=0):
        db.execute("INSERT INTO p2p_state VALUES (?,?,?,0,0,?,0,0,?,?)", (t, PEER, active, relay, ip, port))

    def ev(t, kind, detail):
        db.execute("INSERT INTO event VALUES (?,?,?)", (t, kind, detail))

    state(0, peer_ip, 1000)
    ev(0, "relay_evidence", f"{PEER} F=0 P=0 A=0 L=0 relayed=0 remote={peer_ip}:1000")
    state(60 * S, RELAY, 4379)
    ev(60 * S, "relay_evidence", f"{PEER} F=0 P=0 A=1 L=1 relayed=1 remote={RELAY}:4379")
    state(120 * S, peer_ip, 1000)
    ev(120 * S, "relay_evidence", f"{PEER} F=0 P=0 A=0 L=0 relayed=0 remote={peer_ip}:1000")
    ev(120 * S, "tcp_fallback", f"{PEER} {peer_ip}:1000")
    ev(180 * S, "tcp_fallback_end", f"{PEER} {peer_ip}:1000")
    state(180 * S, peer_ip, 2000)  # re-punched on a new port: same episode kind and IP
    state(240 * S, peer_ip, 2000, active=0)
    ev(250 * S, "stop", "")

    req = mat = 0
    for sec in range(240):
        t = sec * S + S // 2
        if sec < 60:
            v, ip, port, src = 1.0 + (sec % 3) * 0.1, peer_ip, 1000, "etw_stun"
        elif sec < 120:
            v, ip, port, src = 20.0 + (sec % 5), RELAY, 4379, "etw_stun"
        elif sec < 180:
            v, ip, port, src = 40.0, peer_ip, 1000, "tcp_estats"
        else:
            v, ip, port, src = 1.0, peer_ip, 2000, "etw_stun"
        db.execute("INSERT INTO rtt VALUES (?,?,?,?,?,?)", (t, PEER, ip, port, v, src))
        if sec % 5 == 0:
            req_ep = (ip, port)
            if sec in (0, 60, 120, 180):
                req = mat = 0
            req += 10
            mat += 9 if 60 <= sec < 120 else 10
            jit = 2.0 if 60 <= sec < 120 else 0.3
            db.execute(
                "INSERT INTO traffic (t_ns, steam_id, remote_ip, remote_port, role, pps_in, pps_out, pkts_in, "
                "pkts_out, bytes_in, bytes_out, max_gap_in_ms, jit_in_ms, stun_req, stun_matched, stun_lost) "
                "VALUES (?,?,?,?,?,?,?,0,0,0,0,0,?,?,?,0)",
                (t, PEER, req_ep[0], req_ep[1], "peer", 18.0, 36.0, jit, req, mat),
            )
            # A quieter second endpoint of the same peer must not supply the jitter.
            db.execute(
                "INSERT INTO traffic (t_ns, steam_id, remote_ip, remote_port, role, pps_in, pps_out, pkts_in, "
                "pkts_out, bytes_in, bytes_out, max_gap_in_ms, jit_in_ms) VALUES (?,?,?,?,?,1,1,0,0,0,0,0,99)",
                (t, PEER, req_ep[0], 9999, "peer"),
            )
    if geo:
        db.execute("INSERT INTO geo VALUES (?,?,?,?,?,?,?,?, 'peer', NULL)", (PEER, *geo))
    db.commit()
    db.close()


class Helpers(unittest.TestCase):
    def test_mask_and_private(self):
        self.assertEqual(paths.mask("192.168.1.15"), "LAN")
        self.assertEqual(paths.mask("203.0.113.75"), "203.0.113.0/24")
        self.assertEqual(paths.mask(None), "-")
        self.assertEqual(paths.ip_of("203.0.113.75:4379"), "203.0.113.75")
        self.assertIsNone(paths.ip_of("-"))

    def test_pseudonym_matches_the_rust_construction(self):
        # Same construction as src/anon.rs: SHA-256(salt || id as 8 LE bytes), first 6 bytes in hex.
        a = paths.pseudonym("s1", 76561197960287930)
        self.assertEqual(len(a), 12)
        self.assertEqual(a, paths.pseudonym("s1", 76561197960287930))
        self.assertNotEqual(a, paths.pseudonym("s2", 76561197960287930))

    def test_fiber_bound(self):
        # 1000 km: 2 * 1000 / (299792.458 * 2/3) s = 10.007 ms.
        self.assertAlmostEqual(paths.fiber_bound_ms(1000), 10.007, places=3)
        # Quarter of the equator.
        self.assertAlmostEqual(paths.great_circle_km(0, 0, 0, 90), 10007.5, delta=1)

    def test_percentile_and_wilson(self):
        self.assertEqual(paths.pct([1, 2, 3, 4, 5], 0.5), 3)
        self.assertAlmostEqual(paths.pct([0, 10], 0.95), 9.5)
        self.assertIsNone(paths.pct([], 0.5))
        lo, hi = paths.wilson(10, 100)
        self.assertLess(lo, 0.1)
        self.assertGreater(hi, 0.1)


class Episodes(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.dir.name, "run.sqlite")

    def tearDown(self):
        self.dir.cleanup()

    def test_lan_run(self):
        make_run(self.db)
        run, eps, geo = paths.load_run(self.db, 5 * S)
        self.assertEqual(run, "synthetic")
        self.assertEqual([e.path for e in eps], ["direct", "relay", "tcp", "direct"])
        self.assertEqual([round(e.stats["duration_s"]) for e in eps], [60, 60, 60, 60])
        d, r, t, d2 = (e.stats for e in eps)
        self.assertEqual(d["rtt_source"], "etw_stun")
        self.assertAlmostEqual(d["rtt_min"], 1.0)
        self.assertAlmostEqual(r["rtt_p50"], 22.0)
        self.assertEqual(t["rtt_source"], "tcp_estats")
        self.assertAlmostEqual(t["rtt_p50"], 40.0)
        self.assertNotIn("nrep", t)  # UDP checks say nothing on the TCP fallback
        self.assertAlmostEqual(r["jit_in_ms"], 2.0)  # the dominant stream, not the 99 ms one
        self.assertAlmostEqual(r["nrep"], 0.1)
        self.assertEqual(d["nrep"], 0.0)
        self.assertEqual(geo, {})

        cost = paths.relay_cost(eps, 10)
        self.assertEqual(len(cost), 1)
        self.assertAlmostEqual(cost[0]["relay_minus_direct_rtt"], 22.0 - 1.05)  # direct: median of 1.1 and 1.0
        self.assertAlmostEqual(cost[0]["tcp_minus_direct_rtt"], 40.0 - 1.05)
        self.assertEqual(cost[0]["direct"]["episodes"], 2)
        # LAN peers never enter E5.
        self.assertEqual(paths.inflation(eps, {}, None, 10), [])

    def test_e5_inflation(self):
        # 1000 km away, accuracy 20 km: bound 10.007 ms; min RTT 1.0 is below it here, the ratio is still computed.
        make_run(self.db, peer_ip=WAN, geo=("CA", "X", 49.0, -123.0, 20, 1000.0, 10.007))
        run, eps, geo = paths.load_run(self.db, 5 * S)
        infl = paths.inflation(eps, {(run, k): v for k, v in geo.items()}, None, 10)
        self.assertEqual(len(infl), 1)
        r = infl[0]
        self.assertAlmostEqual(r["rtt_min"], 1.0)
        self.assertAlmostEqual(r["inflation_min"], 1.0 / 10.007, places=4)
        self.assertFalse(r["coarse"])
        # --home-lat/--home-lon recomputes the distance from the stored coordinates.
        infl = paths.inflation(eps, {(run, k): v for k, v in geo.items()}, (49.0, -122.9), 10)
        self.assertAlmostEqual(infl[0]["distance_km"], paths.great_circle_km(49, -122.9, 49, -123), places=6)
        self.assertTrue(infl[0]["coarse"])  # 20 km accuracy vs ~7 km distance

    def test_main_writes_pseudonymised_json(self):
        make_run(self.db)
        out = os.path.join(self.dir.name, "out.json")
        self.assertEqual(paths.main([self.db, "--salt", "t", "--json", out]), 0)
        with open(out, encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn(str(PEER), text)
        self.assertNotIn(LAN, text)
        self.assertIn(paths.pseudonym("t", PEER), text)


if __name__ == "__main__":
    unittest.main(verbosity=1)
