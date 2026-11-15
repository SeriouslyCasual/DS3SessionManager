"""E2: validate ds3sm's ETW STUN timing (method A) against a packet capture (method B).

Usage (run from the repo root; paths are arguments):

    python -I analysis/e2_validate.py CAPTURE.pcapng RUN.sqlite [--endpoint IP:PORT]
        [--json OUT.json] [--baseline OTHER.json] [--tol-ms 50]

Inputs:
- CAPTURE: a Wireshark/Npcap capture (pcapng or classic pcap) taken on the
  same PC while `ds3sm monitor` ran.
- RUN: the matching ds3sm run database (`runs/<time>.sqlite`). Optional
  (`-` skips it); without it only the capture-side checks run.

What it reports:
1. STUN messages found in the capture, paired request -> response by
   transaction ID. That is the ground truth. RFC 8489 messages are found by
   the magic cookie 0x2112A442 (96-bit ID); classic RFC 3489 messages (no
   cookie, 128-bit ID) by a strict header and attribute check. E2's first
   capture showed Steam's checks use the classic format.
2. Precision and recall of ds3sm's size rule ("a 56-byte send is a STUN
   request, a 68-byte receive is a reply"), and the STUN sizes it misses.
3. The size rule's pairing (newest request before the reply, 2 s timeout;
   the older oldest-request rule is reported alongside) replayed
   on the capture and checked against the transaction IDs: how often it
   picks the wrong request.
4. ETW RTT samples from the run database matched to the capture pairs by
   reply time; the RTT difference (ETW minus capture) and the clock offset
   and drift between the two sources.
5. A traffic profile per direction (packets/s by payload size), to
   characterise relayed sessions; `--baseline` prints the per-size change
   against a previous run's JSON.
6. For relayed runs, the other ports on the relay's IP: relay-wrapped
   packets are unwrapped and profiled by their inner size, and the local
   turnaround for the other player's relayed checks is measured.

The endpoint comes from the run database: of the endpoints Steam reported
and those ds3sm attributed to a relay, the one with the most RTT samples.
`--endpoint` overrides it.

Only the Python standard library is used. Printed endpoints are cut to /24
(`a.b.c.x`), because captures and run databases hold real addresses; the
JSON keeps the same masking.
"""

from __future__ import annotations

import argparse
import bisect
import ipaddress
import json
import sqlite3
import statistics
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Iterator

STUN_COOKIE = 0x2112A442
COOKIE_BYTES = STUN_COOKIE.to_bytes(4, "big")
BINDING = 0x001
CLASS_NAMES = {0: "request", 1: "indication", 2: "success", 3: "error"}

# ds3sm defaults (src/stun.rs)
REQ_SIZE = 56
REPLY_SIZE = 68
TIMEOUT_NS = 2_000_000_000


# ---------------------------------------------------------------------------
# Capture reading (pcap and pcapng)
# ---------------------------------------------------------------------------


@dataclass
class Frame:
    t_ns: int
    linktype: int
    data: bytes


@dataclass
class CaptureInfo:
    fmt: str = ""
    tsresol_ns: float = 0.0  # declared timestamp resolution
    frames: int = 0


def _ts_to_ns(ts: int, tsresol: int) -> int:
    """Convert a pcapng timestamp in `if_tsresol` units to nanoseconds."""
    if tsresol & 0x80:
        return (ts * 1_000_000_000) >> (tsresol & 0x7F)
    exp = tsresol
    if exp <= 9:
        return ts * 10 ** (9 - exp)
    return ts // 10 ** (exp - 9)


def _tsresol_ns(tsresol: int) -> float:
    if tsresol & 0x80:
        return 1e9 / (1 << (tsresol & 0x7F))
    return 1e9 / 10**tsresol


def read_capture(path: str, info: CaptureInfo | None = None) -> Iterator[Frame]:
    """Yield frames with Unix-nanosecond timestamps from a pcap or pcapng file."""
    info = info if info is not None else CaptureInfo()
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("capture file too short")
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        info.fmt = "pcapng"
        yield from _read_pcapng(data, info)
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        info.fmt = "pcap"
        yield from _read_pcap(data, info)
    else:
        raise ValueError("not a pcap or pcapng file")


def _read_pcap(data: bytes, info: CaptureInfo) -> Iterator[Frame]:
    m = data[:4]
    e = "<" if m in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = m in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    info.tsresol_ns = 1.0 if nano else 1000.0
    linktype = struct.unpack_from(e + "I", data, 20)[0] & 0x0FFFFFFF
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack_from(e + "IIII", data, off)
        off += 16
        pkt = data[off : off + incl]
        off += incl
        t = sec * 1_000_000_000 + (frac if nano else frac * 1000)
        info.frames += 1
        yield Frame(t, linktype, pkt)


def _read_pcapng(data: bytes, info: CaptureInfo) -> Iterator[Frame]:
    e = "<"
    ifaces: list[tuple[int, int, int]] = []  # (linktype, tsresol, tsoffset_s)
    off = 0
    while off + 12 <= len(data):
        btype = struct.unpack_from(e + "I", data, off)[0]
        if btype == 0x0A0D0D0A:  # Section Header Block: byte order may change
            bom = data[off + 8 : off + 12]
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
        blen = struct.unpack_from(e + "I", data, off + 4)[0]
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8 : off + blen - 4]
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack_from(e + "H", body, 0)[0]
            tsresol, tsoffset = 6, 0
            p = 8
            while p + 4 <= len(body):
                code, olen = struct.unpack_from(e + "HH", body, p)
                val = body[p + 4 : p + 4 + olen]
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    tsresol = val[0]
                elif code == 14 and olen == 8:
                    tsoffset = struct.unpack(e + "q", val)[0]
                p += 4 + ((olen + 3) & ~3)
            ifaces.append((linktype, tsresol, tsoffset))
            if not info.tsresol_ns:
                info.tsresol_ns = _tsresol_ns(tsresol)
        elif btype in (6, 2):  # Enhanced Packet Block / obsolete Packet Block
            if btype == 6:
                iface, hi, lo, caplen, _orig = struct.unpack_from(e + "IIIII", body, 0)
                pkt = body[20 : 20 + caplen]
            else:
                iface, _drops, hi, lo, caplen, _orig = struct.unpack_from(e + "HHIIII", body, 0)
                pkt = body[20 : 20 + caplen]
            if iface < len(ifaces):
                linktype, tsresol, tsoffset = ifaces[iface]
                t = _ts_to_ns((hi << 32) | lo, tsresol) + tsoffset * 1_000_000_000
                info.frames += 1
                yield Frame(t, linktype, pkt)
        off += blen


# ---------------------------------------------------------------------------
# Link, IPv4 and UDP decoding
# ---------------------------------------------------------------------------


@dataclass
class Udp:
    t_ns: int
    src: tuple[str, int]
    dst: tuple[str, int]
    size: int  # UDP payload size on the wire (from the UDP length field)
    payload: bytes  # captured payload bytes (may be truncated by snaplen)


def _ip_payload(linktype: int, d: bytes) -> bytes | None:
    """Return the IPv4 packet inside a link-layer frame, or None."""
    if linktype == 1:  # Ethernet, with optional VLAN tags
        p, etype = 12, None
        while p + 2 <= len(d):
            etype = struct.unpack_from(">H", d, p)[0]
            if etype in (0x8100, 0x88A8):
                p += 4
                continue
            p += 2
            break
        return d[p:] if etype == 0x0800 else None
    if linktype == 0:  # BSD loopback (Npcap loopback adapter)
        if len(d) < 4:
            return None
        fam = struct.unpack_from("<I", d, 0)[0]
        return d[4:] if fam == 2 else None
    if linktype in (12, 14, 101, 228):  # raw IP
        return d
    if linktype == 113:  # Linux cooked v1
        return d[16:] if len(d) >= 16 and struct.unpack_from(">H", d, 14)[0] == 0x0800 else None
    if linktype == 276:  # Linux cooked v2
        return d[20:] if len(d) >= 20 and struct.unpack_from(">H", d, 0)[0] == 0x0800 else None
    return None


def decode_udp(fr: Frame) -> Udp | None:
    ip = _ip_payload(fr.linktype, fr.data)
    if ip is None or len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17 or len(ip) < ihl + 8:
        return None
    if struct.unpack_from(">H", ip, 6)[0] & 0x1FFF:  # later fragment: no UDP header
        return None
    src = str(ipaddress.IPv4Address(ip[12:16]))
    dst = str(ipaddress.IPv4Address(ip[16:20]))
    sport, dport, ulen = struct.unpack_from(">HHH", ip, ihl)
    return Udp(fr.t_ns, (src, sport), (dst, dport), max(ulen - 8, 0), ip[ihl + 8 : ihl + ulen])


# ---------------------------------------------------------------------------
# STUN parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Stun:
    offset: int  # where the 20-byte header starts in the UDP payload (RFC: 0)
    method: int
    cls: int
    txid: bytes
    exact_len: bool  # header length field + 20 == bytes after the header start
    rfc: int = 8489  # 8489 (magic cookie, 96-bit ID) or 3489 (classic, 128-bit ID)


def _attrs_fill(payload: bytes, start: int) -> bool:
    """True if type-length-value attributes from `start` end exactly at the payload end."""
    i = start
    while i + 4 <= len(payload):
        alen = struct.unpack_from(">H", payload, i + 2)[0]
        i += 4 + ((alen + 3) & ~3)
    return i == len(payload)


def parse_stun_classic(payload: bytes) -> Stun | None:
    """Parse a classic RFC 3489 STUN message (no magic cookie, 128-bit transaction ID).

    E2 showed that Steam's 56/68-byte connectivity checks use this older
    format. Without a cookie a random packet could look like a header, so
    this is strict: binding method, length field matching the payload
    exactly, and attributes that tile the body exactly.
    """
    if len(payload) < 20:
        return None
    t, mlen = struct.unpack_from(">HH", payload, 0)
    if t & 0xC000 or mlen % 4 or mlen + 20 != len(payload):
        return None
    method = ((t & 0x3E00) >> 2) | ((t & 0x00E0) >> 1) | (t & 0x000F)
    if method != BINDING or not _attrs_fill(payload, 20):
        return None
    cls = ((t & 0x0100) >> 7) | ((t & 0x0010) >> 4)
    return Stun(0, method, cls, bytes(payload[4:20]), True, 3489)


def parse_stun(payload: bytes, scan: bool = True) -> Stun | None:
    """Parse a STUN header: RFC 8489 first, then classic RFC 3489.

    The RFC 8489 header normally starts at payload offset 0 (cookie at
    offset 4). If `scan` is set and it isn't there, the payload is searched
    for the cookie in case Steam wraps the message in its own framing.
    """
    s = _parse_stun_8489(payload, scan)
    return s if s is not None else parse_stun_classic(payload)


def _parse_stun_8489(payload: bytes, scan: bool) -> Stun | None:
    starts = [0]
    if scan:
        i = payload.find(COOKIE_BYTES, 5)
        while i != -1:
            starts.append(i - 4)
            i = payload.find(COOKIE_BYTES, i + 1)
    for off in starts:
        if off < 0 or off + 20 > len(payload):
            continue
        t, mlen, cookie = struct.unpack_from(">HHI", payload, off)
        if cookie != STUN_COOKIE or t & 0xC000:
            continue
        method = ((t & 0x3E00) >> 2) | ((t & 0x00E0) >> 1) | (t & 0x000F)
        cls = ((t & 0x0100) >> 7) | ((t & 0x0010) >> 4)
        txid = bytes(payload[off + 8 : off + 20])
        return Stun(off, method, cls, txid, mlen % 4 == 0 and off + 20 + mlen == len(payload))
    return None


def stun_header(method: int, cls: int, txid: bytes, body_len: int = 0) -> bytes:
    """Build a STUN header (used by the tests to make synthetic packets).

    A 12-byte `txid` gives an RFC 8489 header (with the magic cookie); a
    16-byte one gives a classic RFC 3489 header.
    """
    t = (method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2)
    t |= ((cls & 1) << 4) | ((cls & 2) << 7)
    if len(txid) == 16:
        return struct.pack(">HH", t, body_len) + txid
    return struct.pack(">HHI", t, body_len, STUN_COOKIE) + txid


# ---------------------------------------------------------------------------
# Relay wrapping (E2 relay mode)
# ---------------------------------------------------------------------------
# On a relayed session in E2 mode, the other player's packets arrive from a
# second port on the relay's IP, wrapped in a pre-TURN relay message in the
# RFC 3489 style (as in libjingle's GTURN): a data indication (type 0x0115)
# carrying a relay cookie (0x000F), the source address (0x0012) and the
# original packet in a DATA attribute (0x0013). Packets sent that way are
# send requests (0x0004) with cookie, username (0x0006), destination
# (0x0011) and DATA.

GTURN_DATA = 0x0013
GTURN_COOKIE_ATTR = 0x000F


def unwrap_gturn(payload: bytes) -> tuple[int, bytes] | None:
    """Return (message type, inner packet) for a relay-wrapped packet, else None.

    Strict: exact length field, attributes that tile the body, and both a
    relay cookie and a DATA attribute present. Steam's relay doesn't pad the
    last attribute to 4 bytes (a 129-byte packet carries 85 bytes of data),
    so the final attribute may end unpadded.
    """
    if len(payload) < 20:
        return None
    t, mlen = struct.unpack_from(">HH", payload, 0)
    if t & 0xC000 or mlen + 20 != len(payload):
        return None
    i, data, cookie = 20, None, False
    while i < len(payload):
        if i + 4 > len(payload):
            return None
        at, alen = struct.unpack_from(">HH", payload, i)
        end = i + 4 + alen
        if end > len(payload):
            return None
        if at == GTURN_DATA:
            data = payload[i + 4 : end]
        elif at == GTURN_COOKIE_ATTR:
            cookie = True
        i = end if end == len(payload) else i + 4 + ((alen + 3) & ~3)
    if i != len(payload) or data is None or not cookie:
        return None
    return t, bytes(data)


def sibling_report(udps: list[Udp], endpoint: tuple[str, int]) -> list[dict]:
    """Profile the other ports on the endpoint's IP (relay siblings).

    For each: packets/s each way, raw and unwrapped size histograms, wrapper
    overhead, message types, and the local turnaround for relayed checks
    (the other player's binding request, unwrapped, to our response, by
    transaction ID).
    """
    by_port: dict[tuple[str, int], list[tuple[int, str, Udp]]] = defaultdict(list)
    for u in udps:
        if u.dst[0] == endpoint[0] and u.dst != endpoint:
            by_port[u.dst].append((u.t_ns, SEND, u))
        elif u.src[0] == endpoint[0] and u.src != endpoint:
            by_port[u.src].append((u.t_ns, RECV, u))
    out = []
    for ep, pk in sorted(by_port.items()):
        pk.sort(key=lambda x: x[0])
        dur = max((pk[-1][0] - pk[0][0]) / 1e9, 1e-9)
        d: dict = {"endpoint": mask(ep), "duration_s": dur}
        pending: dict[bytes, int] = {}
        turnaround = []
        for direction in (SEND, RECV):
            raw: Counter[int] = Counter()
            inner: Counter[int] = Counter()
            types: Counter[str] = Counter()
            overhead: Counter[int] = Counter()
            for _, dd, u in pk:
                if dd != direction:
                    continue
                raw[u.size] += 1
                w = unwrap_gturn(u.payload)
                if w is None:
                    types["unwrapped"] += 1
                    continue
                t, data = w
                types[f"0x{t:04x}"] += 1
                inner[len(data)] += 1
                overhead[u.size - len(data)] += 1
            n = sum(raw.values())
            d[direction] = {
                "packets": n,
                "pps": n / dur,
                "types": dict(types),
                "overhead_bytes": dict(overhead),
                "raw_sizes": {str(s): c for s, c in raw.most_common(10)},
                "inner_sizes": {str(s): c for s, c in inner.most_common(10)},
            }
        for t_ns, dd, u in pk:
            w = unwrap_gturn(u.payload)
            s = parse_stun(w[1], scan=False) if w else None
            if s is None:
                continue
            if dd == RECV and s.cls == 0:
                pending.setdefault(s.txid, t_ns)
            elif dd == SEND and s.cls == 2 and s.txid in pending:
                turnaround.append((t_ns - pending.pop(s.txid)) / 1e6)
        d["relayed_check_turnaround_ms"] = summarize(turnaround)
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# Per-endpoint datagrams
# ---------------------------------------------------------------------------

SEND, RECV = "send", "recv"


@dataclass
class Dgram:
    t_ns: int
    dir: str
    size: int
    stun: Stun | None


def to_dgrams(udps: Iterable[Udp], endpoint: tuple[str, int]) -> list[Dgram]:
    """Keep packets to/from `endpoint`, as sends/receives seen from this PC."""
    out = []
    for u in udps:
        if u.dst == endpoint:
            d = SEND
        elif u.src == endpoint:
            d = RECV
        else:
            continue
        out.append(Dgram(u.t_ns, d, u.size, parse_stun(u.payload)))
    out.sort(key=lambda g: g.t_ns)
    return out


def is_req(g: Dgram) -> bool:
    return g.dir == SEND and g.stun is not None and g.stun.cls == 0 and g.stun.method == BINDING


def is_resp(g: Dgram) -> bool:
    return g.dir == RECV and g.stun is not None and g.stun.cls in (2, 3) and g.stun.method == BINDING


# ---------------------------------------------------------------------------
# Ground truth: pairing by transaction ID
# ---------------------------------------------------------------------------


@dataclass
class Pair:
    t_req: int
    t_reply: int
    req_idx: int
    reply_idx: int
    sends: int = 1  # how many requests carried this transaction ID (retransmits)

    @property
    def rtt_ms(self) -> float:
        return (self.t_reply - self.t_req) / 1e6


@dataclass
class TruthResult:
    pairs: list[Pair] = field(default_factory=list)
    unanswered: int = 0  # requests whose transaction ID never got a response
    orphan_responses: int = 0  # responses with no earlier request of that ID
    retransmitted: int = 0  # transaction IDs sent more than once


def pair_by_txid(dg: list[Dgram]) -> TruthResult:
    """Pair our outbound binding requests with inbound responses by transaction ID.

    For a retransmitted request the first send is used (what ds3sm's
    old oldest-outstanding rule would also pick) and the pair is marked.
    """
    first: dict[bytes, int] = {}
    count: Counter[bytes] = Counter()
    res = TruthResult()
    answered: set[bytes] = set()
    for i, g in enumerate(dg):
        if is_req(g):
            assert g.stun is not None
            first.setdefault(g.stun.txid, i)
            count[g.stun.txid] += 1
        elif is_resp(g):
            assert g.stun is not None
            tx = g.stun.txid
            if tx in first and tx not in answered:
                j = first[tx]
                res.pairs.append(Pair(dg[j].t_ns, g.t_ns, j, i, count[tx]))
                answered.add(tx)
            else:
                res.orphan_responses += 1
    res.unanswered = sum(1 for tx in first if tx not in answered)
    res.retransmitted = sum(1 for c in count.values() if c > 1)
    return res


# ---------------------------------------------------------------------------
# ds3sm's size rule, replayed on the capture
# ---------------------------------------------------------------------------


def size_rule_pairs(
    dg: list[Dgram],
    req_size: int = REQ_SIZE,
    reply_size: int = REPLY_SIZE,
    timeout_ns: int = TIMEOUT_NS,
    policy: str = "newest",
) -> tuple[list[Pair], int, int]:
    """Replicate src/stun.rs's size-rule pairing.

    `policy="newest"` (ds3sm since the relay tests): pair each reply with the
    newest request sent before it; older outstanding requests count as lost.
    `policy="oldest"` (ds3sm before): pair with the oldest outstanding
    request; kept to show how it fails after a lost reply. In both, requests
    older than the timeout count as lost.

    Returns (pairs, lost_requests, unmatched_replies).
    """
    if policy not in ("newest", "oldest"):
        raise ValueError(policy)
    q: list[int] = []  # indices of pending requests, oldest first
    pairs: list[Pair] = []
    lost = unmatched = 0
    for i, g in enumerate(dg):
        if g.dir == SEND and g.size == req_size:
            q.append(i)
        elif g.dir == RECV and g.size == reply_size:
            while q and g.t_ns - dg[q[0]].t_ns > timeout_ns:
                q.pop(0)
                lost += 1
            eligible = [k for k, j in enumerate(q) if dg[j].t_ns <= g.t_ns]
            if not eligible:
                unmatched += 1
                continue
            k = eligible[-1] if policy == "newest" else eligible[0]
            if policy == "newest":
                lost += k  # older outstanding requests were never answered
                j = q[k]
                del q[: k + 1]
            else:
                j = q.pop(k)
            pairs.append(Pair(dg[j].t_ns, g.t_ns, j, i))
    return pairs, lost, unmatched


def prf(tp: int, fp: int, fn: int) -> dict:
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def size_rule_quality(dg: list[Dgram], req_size: int = REQ_SIZE, reply_size: int = REPLY_SIZE) -> dict:
    """Packet-level precision/recall of the size rule, and what it misses."""
    out = {}
    for name, truth_fn, pred_fn in (
        ("request", is_req, lambda g: g.dir == SEND and g.size == req_size),
        ("reply", is_resp, lambda g: g.dir == RECV and g.size == reply_size),
    ):
        tp = fp = fn = 0
        missed: Counter[int] = Counter()
        false_pos: Counter[str] = Counter()
        for g in dg:
            t, p = truth_fn(g), pred_fn(g)
            if t and p:
                tp += 1
            elif p:
                fp += 1
                false_pos[_describe(g)] += 1
            elif t:
                fn += 1
                missed[g.size] += 1
        r = prf(tp, fp, fn)
        r["missed_sizes"] = dict(sorted(missed.items()))
        r["false_positive_kinds"] = dict(false_pos.most_common())
        out[name] = r
    return out


def _describe(g: Dgram) -> str:
    if g.stun is None:
        return "non-STUN"
    m = "binding" if g.stun.method == BINDING else f"method 0x{g.stun.method:03x}"
    return f"STUN {m} {CLASS_NAMES[g.stun.cls]}"


def stun_inventory(dg: list[Dgram]) -> dict:
    """Every STUN message kind seen, by direction and size."""
    kinds: Counter[tuple[str, str, int]] = Counter()
    offsets: Counter[int] = Counter()
    rfcs: Counter[str] = Counter()
    exact = total = 0
    for g in dg:
        if g.stun is None:
            continue
        total += 1
        exact += g.stun.exact_len
        offsets[g.stun.offset] += 1
        rfcs[f"RFC {g.stun.rfc}"] += 1
        kinds[(g.dir, _describe(g), g.size)] += 1
    return {
        "messages": total,
        "formats": dict(rfcs),
        "header_offsets": dict(offsets),
        "length_field_exact": exact,
        "kinds": [{"dir": d, "kind": k, "size": s, "count": c} for (d, k, s), c in sorted(kinds.items())],
    }


def pairing_accuracy(rule: list[Pair], truth: TruthResult) -> dict:
    """Compare the size rule's pairs with the transaction-ID pairs."""
    truth_by_reply = {p.reply_idx: p for p in truth.pairs}
    correct = wrong = not_stun = 0
    errs = []
    for p in rule:
        t = truth_by_reply.get(p.reply_idx)
        if t is None:
            not_stun += 1
        elif t.req_idx == p.req_idx:
            correct += 1
        else:
            wrong += 1
            errs.append(p.rtt_ms - t.rtt_ms)
    found = {p.reply_idx for p in rule}
    return {
        "rule_pairs": len(rule),
        "truth_pairs": len(truth.pairs),
        "correct": correct,
        "wrong_request": wrong,
        "reply_not_stun": not_stun,
        "truth_missed": sum(1 for p in truth.pairs if p.reply_idx not in found),
        "precision": correct / len(rule) if rule else None,
        "recall": correct / len(truth.pairs) if truth.pairs else None,
        "wrong_pair_rtt_error_ms": summarize(errs),
    }


# ---------------------------------------------------------------------------
# ETW samples from the run database
# ---------------------------------------------------------------------------


@dataclass
class EtwSample:
    t_ns: int  # reply time (Unix ns, from ETW's FILETIME)
    rtt_ms: float


def db_endpoint(db: sqlite3.Connection) -> tuple[tuple[str, int], str]:
    """Pick the endpoint to analyse: the one carrying the RTT samples.

    Candidates are the endpoints Steam reported for peers and every endpoint
    ds3sm attributed to a relay (`relay_attributed`, detail `<id> <ip:port>`).
    The one with the most RTT rows wins. It's labelled "relay" if ds3sm
    attributed it, or judged Steam's reported remote to be a relay
    (`relay_evidence ... relayed=1 remote=<ip:port>`, E2 mode).
    """
    relay_eps = {
        r[0].split()[1]
        for r in db.execute("SELECT detail FROM event WHERE kind = 'relay_attributed'")
        if len(r[0].split()) >= 2
    }
    for (d,) in db.execute("SELECT detail FROM event WHERE kind = 'relay_evidence'"):
        parts = dict(p.split("=", 1) for p in d.split() if "=" in p)
        remote_is_relay = any(parts.get(k) == "1" for k in ("P", "A", "L"))
        if parts.get("relayed") == "1" and remote_is_relay and parts.get("remote", "-") != "-":
            relay_eps.add(parts["remote"])
    cands = {f"{ip}:{port}" for ip, port in db.execute(
        "SELECT DISTINCT remote_ip, remote_port FROM p2p_state WHERE remote_ip IS NOT NULL"
    )}
    cands |= relay_eps
    if not cands:
        raise SystemExit("no peer or relay endpoint in the run database; pass --endpoint")

    def n_rtt(ep: str) -> int:
        ip, port = parse_endpoint(ep)
        return db.execute("SELECT COUNT(*) FROM rtt WHERE remote_ip = ? AND remote_port = ?", (ip, port)).fetchone()[0]

    best = max(sorted(cands), key=n_rtt)
    return parse_endpoint(best), "relay" if best in relay_eps else "peer"


def load_etw(db: sqlite3.Connection, ep: tuple[str, int]) -> list[EtwSample]:
    rows = db.execute(
        "SELECT t_ns, rtt_ms FROM rtt WHERE remote_ip = ? AND remote_port = ? ORDER BY t_ns", (ep[0], ep[1])
    ).fetchall()
    return [EtwSample(int(t), float(r)) for t, r in rows]


# ---------------------------------------------------------------------------
# Matching ETW samples to capture pairs
# ---------------------------------------------------------------------------


def match_etw(etw: list[EtwSample], pairs: list[Pair], tol_ns: int = 50_000_000, search_ns: int = 250_000_000) -> dict:
    """Match ETW samples to capture pairs by reply time.

    The two clocks can differ by a constant offset, so it is estimated first
    (median of nearest-reply differences within `search_ns`), then each ETW
    sample is matched one-to-one to the closest unused pair within `tol_ns`
    after removing the offset.
    """
    pairs = sorted(pairs, key=lambda p: p.t_reply)
    times = [p.t_reply for p in pairs]
    res: dict = {"etw_samples": len(etw), "capture_pairs": len(pairs)}
    if not etw or not pairs:
        res["matched"] = 0
        return res

    def nearest(t: int) -> int | None:
        k = bisect.bisect_left(times, t)
        best = None
        for j in (k - 1, k):
            if 0 <= j < len(times) and (best is None or abs(times[j] - t) < abs(times[best] - t)):
                best = j
        return best

    diffs = []
    for s in etw:
        j = nearest(s.t_ns)
        if j is not None and abs(s.t_ns - times[j]) <= search_ns:
            diffs.append(s.t_ns - times[j])
    offset = int(statistics.median(diffs)) if diffs else 0

    used: set[int] = set()
    matched: list[tuple[EtwSample, Pair]] = []
    for s in etw:
        t = s.t_ns - offset
        k = bisect.bisect_left(times, t)
        cands = [j for j in range(max(k - 2, 0), min(k + 2, len(times))) if j not in used]
        cands = [j for j in cands if abs(times[j] - t) <= tol_ns]
        if cands:
            j = min(cands, key=lambda j: abs(times[j] - t))
            used.add(j)
            matched.append((s, pairs[j]))

    lo, hi = etw[0].t_ns - offset - tol_ns, etw[-1].t_ns - offset + tol_ns
    in_window = sum(1 for p in pairs if lo <= p.t_reply <= hi)
    resid = [(s.t_ns - offset - p.t_reply) / 1e3 for s, p in matched]  # microseconds
    rtt_diff = [s.rtt_ms - p.rtt_ms for s, p in matched]
    res.update(
        {
            "clock_offset_ms": offset / 1e6,
            "matched": len(matched),
            "etw_unmatched": len(etw) - len(matched),
            "capture_unmatched_in_window": in_window - len(matched),
            "reply_time_residual_us": summarize(resid),
            "clock_drift_ppm": _drift_ppm(matched, offset),
            "rtt_diff_ms": summarize(rtt_diff),
            "rtt_abs_diff_ms": summarize([abs(x) for x in rtt_diff]),
            "etw_rtt_ms": summarize([s.rtt_ms for s, _ in matched]),
            "capture_rtt_ms": summarize([p.rtt_ms for _, p in matched]),
        }
    )
    return res


def _drift_ppm(matched: list[tuple[EtwSample, Pair]], offset: int) -> float | None:
    """Least-squares slope of the reply-time residual against time, in ppm."""
    if len(matched) < 3:
        return None
    xs = [p.t_reply for _, p in matched]
    ys = [s.t_ns - offset - p.t_reply for s, p in matched]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    if not sxx:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx * 1e6


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------


def pct(xs: list[float], q: float) -> float:
    s = sorted(xs)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * q
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def summarize(xs: list[float]) -> dict | None:
    if not xs:
        return None
    return {
        "n": len(xs),
        "min": min(xs),
        "p5": pct(xs, 0.05),
        "median": pct(xs, 0.5),
        "mean": statistics.fmean(xs),
        "p95": pct(xs, 0.95),
        "max": max(xs),
        "sd": statistics.pstdev(xs),
    }


def resolution_ns(ts: list[int]) -> int | None:
    """Smallest non-zero gap between distinct timestamps (an upper bound on the clock tick)."""
    u = sorted(set(ts))
    gaps = [b - a for a, b in zip(u, u[1:]) if b > a]
    return min(gaps) if gaps else None


def etw_tick_ns(etw: list[EtwSample]) -> int | None:
    """ETW times are 100 ns FILETIME ticks; check what the stored times are multiples of."""
    from math import gcd

    g = 0
    for s in etw:
        g = gcd(g, s.t_ns)
    return g or None


def profile(dg: list[Dgram], top: int = 15) -> dict:
    """Packets/s per direction and per payload size."""
    if not dg:
        return {}
    dur = max((dg[-1].t_ns - dg[0].t_ns) / 1e9, 1e-9)
    out: dict = {"duration_s": dur}
    for d in (SEND, RECV):
        sizes = Counter(g.size for g in dg if g.dir == d)
        n = sum(sizes.values())
        out[d] = {
            "packets": n,
            "pps": n / dur,
            "bytes_per_s": sum(s * c for s, c in sizes.items()) / dur,
            "sizes": {str(s): {"count": c, "pps": c / dur} for s, c in sizes.most_common(top)},
        }
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def parse_endpoint(s: str) -> tuple[str, int]:
    ip, _, port = s.rpartition(":")
    ipaddress.IPv4Address(ip)
    return ip, int(port)


def mask(ep: tuple[str, int]) -> str:
    a = ep[0].split(".")
    return f"{a[0]}.{a[1]}.{a[2]}.x:{ep[1]}"


def _f(x, nd=3) -> str:
    return "-" if x is None else f"{x:.{nd}f}"


def _line(name: str, s: dict | None, unit: str, nd: int = 3) -> str:
    if not s:
        return f"  {name}: none"
    return (
        f"  {name} (n={s['n']}, {unit}): min {_f(s['min'], nd)}  median {_f(s['median'], nd)}  "
        f"mean {_f(s['mean'], nd)}  p95 {_f(s['p95'], nd)}  max {_f(s['max'], nd)}  sd {_f(s['sd'], nd)}"
    )


def print_report(r: dict, baseline: dict | None) -> None:
    p = print
    p(f"Endpoint: {r['endpoint']} ({r['endpoint_kind']})")
    c = r["capture"]
    p(f"Capture: {c['format']}, {c['frames']} frames, {c['udp_to_endpoint']} UDP packets to/from endpoint, "
      f"declared resolution {_f(c['declared_resolution_ns'], 0)} ns, smallest gap {c['smallest_gap_ns']} ns")
    inv = r["stun"]
    p(f"\nSTUN in capture: {inv['messages']} messages {inv['formats']}, header offsets {inv['header_offsets']}, "
      f"length field exact in {inv['length_field_exact']}")
    for k in inv["kinds"]:
        p(f"  {k['dir']:<4} {k['kind']:<28} {k['size']:>4} B  x{k['count']}")
    t = r["truth"]
    p(f"\nGround truth (transaction ID): {t['pairs']} pairs, {t['unanswered']} unanswered requests, "
      f"{t['orphan_responses']} orphan responses, {t['retransmitted']} retransmitted IDs")
    p(_line("capture RTT", t["rtt_ms"], "ms"))
    p("\nSize rule, packet level:")
    for name, q in r["size_rule"].items():
        p(f"  {name}: precision {_f(q['precision'], 4)}  recall {_f(q['recall'], 4)}  "
          f"(TP {q['tp']}, FP {q['fp']}, FN {q['fn']})")
        if q["missed_sizes"]:
            p(f"    STUN sizes missed: {q['missed_sizes']}")
        if q["false_positive_kinds"]:
            p(f"    false positives: {q['false_positive_kinds']}")
    a = r["pairing"]
    p(f"\nSize rule pairing replayed on the capture: {a['rule_pairs']} pairs, {a['correct']} correct, "
      f"{a['wrong_request']} wrong request, {a['reply_not_stun']} reply not STUN, "
      f"{a['truth_missed']} truth pairs missed; lost {a['lost_requests']}, unmatched replies {a['unmatched_replies']}")
    p(f"  pair precision {_f(a['precision'], 4)}  recall {_f(a['recall'], 4)}  (newest-request rule)")
    o = r.get("pairing_oldest_rule")
    if o:
        p(f"  old oldest-request rule: {o['correct']} correct, {o['wrong_request']} wrong, "
          f"precision {_f(o['precision'], 4)}  recall {_f(o['recall'], 4)}")
    if a["wrong_pair_rtt_error_ms"]:
        p(_line("wrong-pair RTT error", a["wrong_pair_rtt_error_ms"], "ms"))
    e = r.get("etw")
    if e:
        p(f"\nETW vs capture: {e['etw_samples']} ETW samples during the capture "
          f"({e['etw_outside_capture']} more outside it, not compared), matched {e['matched']}, "
          f"ETW unmatched {e.get('etw_unmatched', '-')}, capture pairs unmatched in window "
          f"{e.get('capture_unmatched_in_window', '-')}")
        if e.get("matched"):
            p(f"  clock offset (ETW - capture) {_f(e['clock_offset_ms'])} ms, drift {_f(e['clock_drift_ppm'], 2)} ppm, "
              f"ETW time tick {e.get('etw_tick_ns')} ns")
            p(_line("reply-time residual", e["reply_time_residual_us"], "us", 1))
            p(_line("RTT diff ETW - capture", e["rtt_diff_ms"], "ms", 4))
            p(_line("|RTT diff|", e["rtt_abs_diff_ms"], "ms", 4))
            p(_line("ETW RTT", e["etw_rtt_ms"], "ms"))
            p(_line("capture RTT", e["capture_rtt_ms"], "ms"))
    pr = r["profile"]
    if pr:
        p(f"\nTraffic profile over {pr['duration_s']:.1f} s:")
        for d in (SEND, RECV):
            x = pr[d]
            p(f"  {d}: {x['pps']:.2f} pps, {x['bytes_per_s']:.0f} B/s")
            for s, v in x["sizes"].items():
                p(f"    {s:>5} B  {v['pps']:6.2f} pps  ({v['count']})")
    for sib in r.get("siblings", []):
        # Skip incidental chatter (e.g. mDNS from a LAN peer); the JSON keeps it.
        wrapped = any(k != "unwrapped" for d in (SEND, RECV) for k in sib[d]["types"])
        total = sib[SEND]["packets"] + sib[RECV]["packets"]
        if not wrapped and total / max(pr.get("duration_s", 1.0), 1.0) < 1.0:
            continue
        p(f"\nOther port on the endpoint's IP: {sib['endpoint']} over {sib['duration_s']:.1f} s")
        for d in (SEND, RECV):
            x = sib[d]
            if not x["packets"]:
                continue
            p(f"  {d}: {x['pps']:.2f} pps, message types {x['types']}, wrapper bytes {x['overhead_bytes']}")
            p(f"    raw sizes   {x['raw_sizes']}")
            if x["inner_sizes"]:
                p(f"    inner sizes {x['inner_sizes']}")
        if sib["relayed_check_turnaround_ms"]:
            p(_line("local turnaround for relayed checks", sib["relayed_check_turnaround_ms"], "ms", 4))
    if baseline and baseline.get("profile"):
        p("\nChange against baseline (pps, this minus baseline):")
        for d in (SEND, RECV):
            a_, b_ = pr.get(d, {}), baseline["profile"].get(d, {})
            p(f"  {d}: total {a_.get('pps', 0) - b_.get('pps', 0):+.2f}")
            keys = set(a_.get("sizes", {})) | set(b_.get("sizes", {}))
            rows = []
            for k in keys:
                da = a_.get("sizes", {}).get(k, {}).get("pps", 0.0)
                db = b_.get("sizes", {}).get(k, {}).get("pps", 0.0)
                rows.append((abs(da - db), k, da, db))
            for _, k, da, db in sorted(rows, reverse=True)[:10]:
                p(f"    {k:>5} B  {db:6.2f} -> {da:6.2f}  ({da - db:+.2f})")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def analyse(capture: str, db_path: str | None, endpoint: tuple[str, int] | None, tol_ms: float) -> dict:
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) if db_path else None
    try:
        return _analyse(capture, db, endpoint, tol_ms)
    finally:
        if db is not None:
            db.close()


def _analyse(capture: str, db: sqlite3.Connection | None, endpoint: tuple[str, int] | None, tol_ms: float) -> dict:
    kind = "given"
    if endpoint is None:
        if db is None:
            raise SystemExit("without a run database, --endpoint is required")
        endpoint, kind = db_endpoint(db)
    info = CaptureInfo()
    udps = [u for u in (decode_udp(f) for f in read_capture(capture, info)) if u is not None]
    dg = to_dgrams(udps, endpoint)
    truth = pair_by_txid(dg)
    rule, lost, unmatched = size_rule_pairs(dg)
    acc = pairing_accuracy(rule, truth)
    acc["lost_requests"], acc["unmatched_replies"] = lost, unmatched
    # The pre-2026-11-14 rule, for comparison.
    old, old_lost, old_unmatched = size_rule_pairs(dg, policy="oldest")
    acc_old = pairing_accuracy(old, truth)
    acc_old["lost_requests"], acc_old["unmatched_replies"] = old_lost, old_unmatched
    r: dict = {
        "endpoint": mask(endpoint),
        "endpoint_kind": kind,
        "capture": {
            "format": info.fmt,
            "frames": info.frames,
            "udp_to_endpoint": len(dg),
            "declared_resolution_ns": info.tsresol_ns,
            "smallest_gap_ns": resolution_ns([g.t_ns for g in dg]),
        },
        "stun": stun_inventory(dg),
        "truth": {
            "pairs": len(truth.pairs),
            "unanswered": truth.unanswered,
            "orphan_responses": truth.orphan_responses,
            "retransmitted": truth.retransmitted,
            "rtt_ms": summarize([p.rtt_ms for p in truth.pairs]),
        },
        "size_rule": size_rule_quality(dg),
        "pairing": acc,
        "pairing_oldest_rule": acc_old,
        "profile": profile(dg),
        "siblings": sibling_report(udps, endpoint),
    }
    if db is not None:
        etw_all = load_etw(db, endpoint)
        # Only samples whose reply fell inside the capture can be checked
        # (the run and the capture rarely start and stop together).
        if dg:
            slack = int(tol_ms * 1e6)  # allows for a small clock offset
            lo, hi = dg[0].t_ns - slack, dg[-1].t_ns + slack
            etw = [s for s in etw_all if lo <= s.t_ns <= hi]
        else:
            etw = etw_all
        # Compare against the capture's ground truth; if the capture shows no
        # RFC STUN at all, fall back to the size rule's pairs so the timing
        # comparison still says something (reported as such).
        ref = truth.pairs if truth.pairs else rule
        e = match_etw(etw, ref, tol_ns=int(tol_ms * 1e6))
        e["reference"] = "transaction_id" if truth.pairs else "size_rule"
        e["etw_outside_capture"] = len(etw_all) - len(etw)
        e["etw_tick_ns"] = etw_tick_ns(etw)
        label = db.execute("SELECT value FROM meta WHERE key = 'label'").fetchone()
        r["run_label"] = label[0] if label else None
        r["etw"] = e
    return r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture", help="pcapng or pcap file")
    ap.add_argument("run_db", help="ds3sm run database (runs/<time>.sqlite), or - for none")
    ap.add_argument("--endpoint", help="IP:PORT to analyse (default: from the run database)")
    ap.add_argument("--tol-ms", type=float, default=50.0, help="reply-time matching tolerance (default 50)")
    ap.add_argument("--json", help="write the full results here")
    ap.add_argument("--baseline", help="JSON from an earlier run to compare traffic profiles with")
    a = ap.parse_args(argv)
    ep = parse_endpoint(a.endpoint) if a.endpoint else None
    r = analyse(a.capture, None if a.run_db == "-" else a.run_db, ep, a.tol_ms)
    base = None
    if a.baseline:
        with open(a.baseline, encoding="utf-8") as f:
            base = json.load(f)
    print_report(r, base)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
