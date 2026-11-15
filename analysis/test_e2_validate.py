"""Unit tests for e2_validate.py on synthetic packets.

Run from the repo root:  python -I analysis/test_e2_validate.py
"""

import os
import sqlite3
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import e2_validate as ev  # noqa: E402

LOCAL = ("192.0.2.10", 50000)  # TEST-NET addresses only
PEER = ("198.51.100.7", 27015)
OTHER = ("203.0.113.1", 4380)
MS = 1_000_000
T0 = 1_800_000_000 * 1_000_000_000  # an arbitrary Unix time in ns


def txid(n: int) -> bytes:
    return n.to_bytes(12, "big")


def stun_payload(cls: int, tx: bytes, size: int, method: int = ev.BINDING) -> bytes:
    """A STUN message padded with one attribute so the payload is `size` bytes."""
    body = size - 20
    attr = struct.pack(">HH", 0x8022, body - 4) + b"\0" * (body - 4) if body >= 4 else b""
    return ev.stun_header(method, cls, tx, len(attr)) + attr


def udp_frame(src, dst, payload: bytes) -> bytes:
    """Ethernet + IPv4 + UDP around `payload`."""
    udp = struct.pack(">HHHH", src[1], dst[1], 8 + len(payload), 0) + payload
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
        bytes(map(int, src[0].split("."))), bytes(map(int, dst[0].split("."))),
    )
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + udp


def write_pcapng(path: str, frames, tsresol: int = 6) -> None:
    """Write a minimal little-endian pcapng: SHB, one IDB (with if_tsresol), EPBs."""

    def block(btype: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        n = len(body) + 12
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    opt = struct.pack("<HHB", 9, 1, tsresol) + b"\0\0\0" + struct.pack("<HH", 0, 0)
    out += block(1, struct.pack("<HHI", 1, 0, 65535) + opt)
    for t_ns, data in frames:
        ts = t_ns // 10 ** (9 - tsresol)
        out += block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data)) + data)
    with open(path, "wb") as f:
        f.write(out)


def dg(t_ms, d, size, stun=None):
    return ev.Dgram(T0 + int(t_ms * MS), d, size, stun)


def req(t_ms, n, size=56):
    return dg(t_ms, ev.SEND, size, ev.Stun(0, ev.BINDING, 0, txid(n), True))


def resp(t_ms, n, size=68):
    return dg(t_ms, ev.RECV, size, ev.Stun(0, ev.BINDING, 2, txid(n), True))


class StunParsing(unittest.TestCase):
    def test_round_trip_classes(self):
        for cls in range(4):
            s = ev.parse_stun(stun_payload(cls, txid(7), 56))
            self.assertIsNotNone(s)
            self.assertEqual((s.method, s.cls, s.txid, s.offset), (ev.BINDING, cls, txid(7), 0))
            self.assertTrue(s.exact_len)

    def test_known_binding_types(self):
        # RFC 8489: 0x0001 binding request, 0x0101 success, 0x0111 error.
        for t, cls in ((0x0001, 0), (0x0101, 2), (0x0111, 3), (0x0011, 1)):
            p = struct.pack(">HHI", t, 0, ev.STUN_COOKIE) + txid(1)
            s = ev.parse_stun(p)
            self.assertEqual((s.method, s.cls), (ev.BINDING, cls))

    def test_rejects_non_stun(self):
        self.assertIsNone(ev.parse_stun(b"\0" * 56))
        bad = bytearray(stun_payload(0, txid(1), 56))
        bad[0] |= 0xC0  # top two bits must be zero
        self.assertIsNone(ev.parse_stun(bytes(bad)))
        self.assertIsNone(ev.parse_stun(stun_payload(0, txid(1), 20)[:19]))

    def test_classic_rfc3489_steam_layout(self):
        # Layout seen in E2: request 0x0001 + USERNAME(32) = 56 B;
        # response 0x0101 + USERNAME(32) + MAPPED-ADDRESS(8) = 68 B.
        tx = bytes(range(16))
        user = struct.pack(">HH", 0x0006, 32) + b"u" * 32
        mapped = struct.pack(">HH", 0x0001, 8) + bytes([0, 1, 0x1F, 0x90, 192, 0, 2, 10])
        rq = struct.pack(">HH", 0x0001, len(user)) + tx + user
        rs = struct.pack(">HH", 0x0101, len(user + mapped)) + tx + user + mapped
        self.assertEqual((len(rq), len(rs)), (56, 68))
        a, b = ev.parse_stun(rq), ev.parse_stun(rs)
        self.assertEqual((a.rfc, a.cls, a.txid), (3489, 0, tx))
        self.assertEqual((b.rfc, b.cls, b.txid), (3489, 2, tx))

    def test_classic_round_trip_helper(self):
        s = ev.parse_stun(stun_payload(2, bytes(16), 68))
        self.assertEqual((s.rfc, s.cls, len(s.txid)), (3489, 2, 16))

    def test_classic_rejects_near_misses(self):
        good = stun_payload(0, bytes(range(16)), 56)
        wrong_len = good[:2] + struct.pack(">H", 40) + good[4:]
        self.assertIsNone(ev.parse_stun(wrong_len))
        ragged = good[:20] + struct.pack(">HH", 0x0006, 40) + good[24:]  # attr overruns the payload
        self.assertIsNone(ev.parse_stun(ragged))
        other_method = struct.pack(">H", 0x0003) + good[2:]
        self.assertIsNone(ev.parse_stun(other_method))
        # Game packets start 00 xx xx with random bytes after: not STUN.
        self.assertIsNone(ev.parse_stun(b"\x00\x02\x05" + bytes(range(94))))

    def test_wrapped_header_is_found_by_scan(self):
        p = b"\xAB" * 8 + stun_payload(0, txid(3), 40)
        s = ev.parse_stun(p)
        self.assertEqual((s.offset, s.txid), (8, txid(3)))
        self.assertIsNone(ev.parse_stun(p, scan=False))


class CaptureReading(unittest.TestCase):
    def test_pcapng_round_trip_and_direction(self):
        frames = [
            (T0, udp_frame(LOCAL, PEER, stun_payload(0, txid(1), 56))),
            (T0 + 2 * MS, udp_frame(PEER, LOCAL, stun_payload(2, txid(1), 68))),
            (T0 + 3 * MS, udp_frame(LOCAL, OTHER, b"x" * 30)),
        ]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcapng")
            write_pcapng(path, frames)
            info = ev.CaptureInfo()
            udps = [ev.decode_udp(f) for f in ev.read_capture(path, info)]
        self.assertEqual((info.fmt, info.frames, info.tsresol_ns), ("pcapng", 3, 1000.0))
        self.assertEqual(udps[0].t_ns, T0)
        self.assertEqual(udps[1].size, 68)
        g = ev.to_dgrams(udps, PEER)
        self.assertEqual([(x.dir, x.size) for x in g], [(ev.SEND, 56), (ev.RECV, 68)])
        self.assertEqual(g[1].stun.txid, txid(1))

    def test_nanosecond_resolution(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcapng")
            write_pcapng(path, [(T0 + 123, udp_frame(LOCAL, PEER, b"a"))], tsresol=9)
            f = next(ev.read_capture(path))
        self.assertEqual(f.t_ns, T0 + 123)


class Pairing(unittest.TestCase):
    def test_txid_pairs_out_of_order_responses(self):
        g = [req(0, 1), req(10, 2), resp(15, 2), resp(30, 1)]
        t = ev.pair_by_txid(g)
        rtts = sorted(p.rtt_ms for p in t.pairs)
        self.assertEqual(rtts, [5.0, 30.0])
        # Two checks in flight (the newest rule's documented limit): it gets
        # the first reply right and has nothing left for the second.
        rule, lost, unmatched = ev.size_rule_pairs(g)
        acc = ev.pairing_accuracy(rule, t)
        self.assertEqual((acc["correct"], acc["wrong_request"], lost, unmatched), (1, 0, 1, 1))
        # The old rule pairs by age, so both of its pairs are wrong here.
        old, _, _ = ev.size_rule_pairs(g, policy="oldest")
        acc = ev.pairing_accuracy(old, t)
        self.assertEqual((acc["correct"], acc["wrong_request"]), (0, 2))

    def test_lost_reply(self):
        # Reply to request 1 is lost.
        g = [req(0, 1), req(500, 2), resp(503, 2), req(1000, 3), resp(1003, 3)]
        t = ev.pair_by_txid(g)
        self.assertEqual((len(t.pairs), t.unanswered), (2, 1))
        # Newest rule: both pairs right, the loss counted.
        rule, lost, _ = ev.size_rule_pairs(g)
        acc = ev.pairing_accuracy(rule, t)
        self.assertEqual((acc["correct"], acc["wrong_request"], lost), (2, 0, 1))
        self.assertAlmostEqual(rule[0].rtt_ms, 3.0)
        # Old rule: shifted by one check for the rest of the run, no loss seen.
        old, old_lost, _ = ev.size_rule_pairs(g, policy="oldest")
        acc = ev.pairing_accuracy(old, t)
        self.assertEqual((acc["wrong_request"], old_lost), (2, 0))
        self.assertAlmostEqual(old[0].rtt_ms, 503.0)

    def test_timeout_drops_stale_request(self):
        g = [req(0, 1), req(2500, 2), resp(2503, 2)]
        rule, lost, _ = ev.size_rule_pairs(g)
        self.assertEqual(lost, 1)
        self.assertAlmostEqual(rule[0].rtt_ms, 3.0)
        acc = ev.pairing_accuracy(rule, ev.pair_by_txid(g))
        self.assertEqual(acc["correct"], 1)

    def test_retransmit_uses_first_send(self):
        g = [req(0, 1), req(100, 1), resp(102, 1)]
        t = ev.pair_by_txid(g)
        self.assertEqual((t.retransmitted, t.pairs[0].sends), (1, 2))
        self.assertAlmostEqual(t.pairs[0].rtt_ms, 102.0)

    def test_inbound_requests_are_not_ours(self):
        g = [dg(0, ev.RECV, 56, ev.Stun(0, ev.BINDING, 0, txid(9), True)),
             dg(1, ev.SEND, 68, ev.Stun(0, ev.BINDING, 2, txid(9), True))]
        self.assertEqual(ev.pair_by_txid(g).pairs, [])


class SizeRule(unittest.TestCase):
    def test_precision_recall_and_missed_sizes(self):
        g = [
            req(0, 1),                   # TP request
            resp(1, 1),                  # TP reply
            dg(2, ev.SEND, 56),          # FP: 56-byte non-STUN
            req(3, 2, size=60),          # FN: STUN request of another size
            resp(4, 2, size=80),         # FN reply
            dg(5, ev.RECV, 68),          # FP reply
            dg(6, ev.RECV, 56, ev.Stun(0, ev.BINDING, 0, txid(5), True)),  # inbound request: ignored
        ]
        q = ev.size_rule_quality(g)
        self.assertEqual((q["request"]["tp"], q["request"]["fp"], q["request"]["fn"]), (1, 1, 1))
        self.assertEqual(q["request"]["missed_sizes"], {60: 1})
        self.assertEqual(q["request"]["false_positive_kinds"], {"non-STUN": 1})
        self.assertEqual(q["reply"]["missed_sizes"], {80: 1})
        self.assertAlmostEqual(q["reply"]["precision"], 0.5)


class EtwMatching(unittest.TestCase):
    def test_offset_and_rtt_difference(self):
        pairs = [ev.Pair(T0 + k * 500 * MS, T0 + k * 500 * MS + 2 * MS, 2 * k, 2 * k + 1) for k in range(20)]
        off = 3 * MS + 250_000  # ETW clock 3.25 ms ahead
        etw = [ev.EtwSample(p.t_reply + off, p.rtt_ms + 0.01) for p in pairs[2:18]]
        r = ev.match_etw(etw, pairs)
        self.assertEqual((r["matched"], r["etw_unmatched"], r["capture_unmatched_in_window"]), (16, 0, 0))
        self.assertAlmostEqual(r["clock_offset_ms"], 3.25)
        self.assertAlmostEqual(r["rtt_diff_ms"]["median"], 0.01, places=6)
        self.assertAlmostEqual(r["clock_drift_ppm"], 0.0, places=6)

    def test_sample_without_pair_is_unmatched(self):
        pairs = [ev.Pair(T0, T0 + MS, 0, 1), ev.Pair(T0 + 500 * MS, T0 + 501 * MS, 2, 3)]
        etw = [ev.EtwSample(T0 + MS, 1.0), ev.EtwSample(T0 + 250 * MS, 1.0), ev.EtwSample(T0 + 501 * MS, 1.0)]
        r = ev.match_etw(etw, pairs)
        self.assertEqual((r["matched"], r["etw_unmatched"]), (2, 1))


def attr(t: int, value: bytes, pad: bool = True) -> bytes:
    return struct.pack(">HH", t, len(value)) + value + (b"\0" * (-len(value) % 4) if pad else b"")


def gturn(t: int, inner: bytes, outbound: bool) -> bytes:
    """A relay-wrapped packet in the E2 layout (data indication or send request).

    As in the real capture, the final DATA attribute isn't padded.
    """
    data = attr(0x0013, inner, pad=False)
    if outbound:  # send request: cookie, username(16), destination(8), data
        body = attr(0x000F, b"\x72\xc6\x4b\xc6") + attr(0x0006, b"u" * 16) + attr(0x0011, bytes(8)) + data
    else:  # data indication: cookie, source address(8), data
        body = attr(0x000F, b"\x72\xc6\x4b\xc6") + attr(0x0012, bytes(8)) + data
    return struct.pack(">HH", t, len(body)) + bytes(16) + body


class RelayWrapping(unittest.TestCase):
    def test_wrapper_sizes_match_e2(self):
        game = b"g" * 85
        ind = gturn(0x0115, game, outbound=False)
        self.assertEqual(len(ind) - len(game), 44)
        t, inner = ev.unwrap_gturn(ind)
        self.assertEqual((t, inner), (0x0115, game))
        reply = stun_payload(2, bytes(range(16)), 68)
        req = gturn(0x0004, reply, outbound=True)
        self.assertEqual(len(req) - len(reply), 64)
        self.assertEqual(ev.unwrap_gturn(req)[1], reply)

    def test_rejects_plain_stun_and_game_data(self):
        self.assertIsNone(ev.unwrap_gturn(stun_payload(0, bytes(range(16)), 56)))  # no DATA/cookie
        self.assertIsNone(ev.unwrap_gturn(b"\x00\x02\x05" + bytes(94)))
        bad = bytearray(gturn(0x0115, b"g" * 85, outbound=False))
        bad[3] += 4  # length field no longer matches
        self.assertIsNone(ev.unwrap_gturn(bytes(bad)))

    def test_sibling_report_unwraps_and_times_relayed_checks(self):
        relay_stun, relay_wrap = ("203.0.113.148", 4379), ("203.0.113.148", 4380)
        udps = []
        for k in range(5):
            t = T0 + k * 500 * MS
            tx = k.to_bytes(16, "big")
            udps.append(ev.Udp(t, relay_wrap, LOCAL, 100, gturn(0x0115, stun_payload(0, tx, 56), False)))
            udps.append(ev.Udp(t + MS // 10, LOCAL, relay_wrap, 132, gturn(0x0004, stun_payload(2, tx, 68), True)))
            udps.append(ev.Udp(t + 2 * MS, relay_wrap, LOCAL, 129, gturn(0x0115, b"g" * 85, False)))
            udps.append(ev.Udp(t + 3 * MS, LOCAL, relay_stun, 97, b"x" * 97))  # the analysed endpoint itself
        (sib,) = ev.sibling_report(udps, relay_stun)
        self.assertEqual(sib["endpoint"], "203.0.113.x:4380")
        self.assertEqual(sib["recv"]["overhead_bytes"], {44: 10})
        self.assertEqual(sib["send"]["overhead_bytes"], {64: 5})
        self.assertEqual(sib["recv"]["inner_sizes"], {"56": 5, "85": 5})
        self.assertEqual(sib["relayed_check_turnaround_ms"]["n"], 5)
        self.assertAlmostEqual(sib["relayed_check_turnaround_ms"]["median"], 0.1)


class EndpointChoice(unittest.TestCase):
    def make_db(self, d, events, states, rtt_eps):
        path = os.path.join(d, "r.sqlite")
        c = sqlite3.connect(path)
        c.executescript(
            "CREATE TABLE event (t_ns INTEGER, kind TEXT, detail TEXT);"
            "CREATE TABLE p2p_state (t_ns INTEGER, steam_id INTEGER, active INTEGER, connecting INTEGER,"
            " error INTEGER, using_relay INTEGER, bytes_queued INTEGER, packets_queued INTEGER,"
            " remote_ip TEXT, remote_port INTEGER);"
            "CREATE TABLE rtt (t_ns INTEGER, steam_id INTEGER, remote_ip TEXT, remote_port INTEGER,"
            " rtt_ms REAL, source TEXT);"
        )
        c.executemany("INSERT INTO event VALUES (0, ?, ?)", events)
        c.executemany("INSERT INTO p2p_state VALUES (0,1,1,0,0,?,0,0,?,?)", states)
        for (ip, port), n in rtt_eps.items():
            c.executemany("INSERT INTO rtt VALUES (0,1,?,?,1.0,'etw_stun')", [(ip, port)] * n)
        c.commit()
        return c

    def test_e2_mode_reported_remote_is_the_relay(self):
        with tempfile.TemporaryDirectory() as d:
            c = self.make_db(
                d,
                [("relay_evidence", "1 F=0 P=1 A=? L=1 relayed=1 remote=203.0.113.148:4379"),
                 ("relay_attributed", "1 203.0.113.148:4380")],
                [(0, "203.0.113.148", 4379)],
                {("203.0.113.148", 4379): 50},
            )
            self.assertEqual(ev.db_endpoint(c), (("203.0.113.148", 4379), "relay"))
            c.close()

    def test_e1_mode_and_direct(self):
        with tempfile.TemporaryDirectory() as d:
            c = self.make_db(
                d,
                [("relay_attributed", "1 203.0.113.134:4380"), ("relay_attributed", "1 203.0.113.134:4381")],
                [(1, "198.51.100.20", 27015)],
                {("203.0.113.134", 4380): 40},
            )
            self.assertEqual(ev.db_endpoint(c), (("203.0.113.134", 4380), "relay"))
            c.close()
        with tempfile.TemporaryDirectory() as d:
            c = self.make_db(d, [], [(0, PEER[0], PEER[1])], {PEER: 10})
            self.assertEqual(ev.db_endpoint(c), (PEER, "peer"))
            c.close()


class EndToEnd(unittest.TestCase):
    def test_capture_and_run_database(self):
        frames, rows = [], []
        for k in range(10):
            t = T0 + k * 500 * MS
            frames.append((t, udp_frame(LOCAL, PEER, stun_payload(0, txid(k), 56))))
            frames.append((t + 1 * MS, udp_frame(LOCAL, PEER, b"g" * 97)))
            frames.append((t + 4 * MS, udp_frame(PEER, LOCAL, stun_payload(2, txid(k), 68))))
            rows.append((t + 4 * MS + 2 * MS, None, PEER[0], PEER[1], 4.0, "etw_stun"))
        with tempfile.TemporaryDirectory() as d:
            cap, db = os.path.join(d, "c.pcapng"), os.path.join(d, "r.sqlite")
            write_pcapng(cap, frames)
            c = sqlite3.connect(db)
            c.executescript(
                "CREATE TABLE meta (key TEXT, value TEXT);"
                "CREATE TABLE event (t_ns INTEGER, kind TEXT, detail TEXT);"
                "CREATE TABLE p2p_state (t_ns INTEGER, steam_id INTEGER, active INTEGER, connecting INTEGER,"
                " error INTEGER, using_relay INTEGER, bytes_queued INTEGER, packets_queued INTEGER,"
                " remote_ip TEXT, remote_port INTEGER);"
                "CREATE TABLE rtt (t_ns INTEGER, steam_id INTEGER, remote_ip TEXT, remote_port INTEGER,"
                " rtt_ms REAL, source TEXT);"
            )
            c.execute("INSERT INTO meta VALUES ('label', 'synthetic')")
            c.execute("INSERT INTO p2p_state VALUES (?,1,1,0,0,0,0,0,?,?)", (T0, PEER[0], PEER[1]))
            c.executemany("INSERT INTO rtt VALUES (?,?,?,?,?,?)", rows)
            c.commit()
            c.close()
            r = ev.analyse(cap, db, None, 50.0)
        self.assertEqual(r["endpoint"], "198.51.100.x:27015")
        self.assertEqual(r["truth"]["pairs"], 10)
        self.assertEqual(r["size_rule"]["request"]["precision"], 1.0)
        self.assertEqual(r["size_rule"]["reply"]["recall"], 1.0)
        self.assertEqual(r["pairing"]["correct"], 10)
        self.assertEqual(r["etw"]["matched"], 10)
        self.assertAlmostEqual(r["etw"]["clock_offset_ms"], 2.0)
        self.assertAlmostEqual(r["etw"]["rtt_abs_diff_ms"]["max"], 0.0, places=9)
        self.assertAlmostEqual(r["profile"]["send"]["sizes"]["97"]["count"], 10)


class StreamJitterMirror(unittest.TestCase):
    """Same cases as src/jitter.rs, so the two estimators agree."""

    MS = 1_000_000
    T = 83 * MS + MS // 3

    def feed(self, n, delay=lambda i: 0, size=85, skip=lambda i: False):
        return [(i * self.T + delay(i), size) for i in range(n) if not skip(i)]

    def test_perfect_clock(self):
        j, _ = ev.jitter_track(self.feed(200))
        self.assertEqual(j.size, 85)
        self.assertAlmostEqual(j.period_ms(), 83.333, places=2)
        self.assertLess(j.value(), 1e-6)

    def test_alternating_delay_converges_to_transit_change(self):
        j, _ = ev.jitter_track(self.feed(400, lambda i: self.MS if i % 2 == 0 else -self.MS))
        self.assertAlmostEqual(j.value(), 2.0, places=2)

    def test_lost_packet_is_not_jitter(self):
        j, _ = ev.jitter_track(self.feed(200, skip=lambda i: i % 10 == 5))
        self.assertLess(j.value(), 1e-6)

    def test_extra_packet_counts_as_offset(self):
        p = self.feed(101)
        p.insert(100, (99 * self.T + 15 * self.MS, 85))
        j, _ = ev.jitter_track(p)
        want = 15 / 16 + 15 * (1 - 1 / 16) / 16
        self.assertAlmostEqual(j.value(), want, places=6)

    def test_new_dominant_size_restarts(self):
        p = self.feed(20, lambda i: self.MS if i % 2 == 0 else -self.MS)
        p += [(30 * self.T + i * self.T, 129) for i in range(60)]
        j, _ = ev.jitter_track(p)
        self.assertEqual(j.size, 129)
        self.assertLess(j.value(), 1e-6)

    def test_compare_matches_delayed_rows_and_skips_settling(self):
        # Capture J after each packet (every 100 ms); each row holds the value
        # from 700 ms before it (ETW delivered late) and is written on the second.
        track = [(i * 100_000_000, 0.01 * i) for i in range(1000)]
        rows = [(t, track[t // 100_000_000 - 7][1]) for t in range(1_000_000_000, 100_000_000_000, 1_000_000_000)]
        c = ev.compare_jitter(track, rows)
        self.assertEqual(c["rows"], len([r for r in rows if r[0] >= rows[0][0] + ev.JIT_SETTLE_NS]))
        self.assertAlmostEqual(c["abs_diff_ms"]["max"], 0.0, places=9)
        self.assertAlmostEqual(c["implied_lag_ms"]["median"], 700.0)
        self.assertAlmostEqual(c["at_row_time_diff_ms"]["median"], -0.07)


if __name__ == "__main__":
    unittest.main(verbosity=1)
