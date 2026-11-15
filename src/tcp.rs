//! Telemetry for Steam's TCP fallback, kept apart from the UDP method.
//!
//! # The networking idea
//!
//! When every UDP path between two players is impaired, Steam's legacy P2P
//! moves the session to a **direct TCP connection** between the two Steam
//! clients (found in E3 C2, 2026-11-15). It is the same endpoint
//! `GetP2PSessionState` reports, it isn't relayed, and it carries the same
//! datagrams as before, each with a **2-byte length prefix**: the 85 B game
//! stream arrives as 87 B, Steam's 56 B / 68 B connectivity checks as
//! 58 B / 70 B. What carries over, as validated against a capture in E3-T3:
//! - **jitter**: a [`StreamJitter`] on the dominant inbound size (87 B).
//!   Kernel receive events come one per TCP segment with accurate
//!   timestamps (median +0.016 ms vs the capture), and ds3sm's TCP jitter
//!   matched the capture's to 0.0006 ms. It includes TCP's own effects
//!   (sender coalescing, resend delay): 4.2–4.5 ms on the LAN in E3-T3,
//!   against ~0.35 ms on UDP. That is what the game gets on this path.
//! - **loss**: TCP never loses a check (it resends), so `nrep%` would read
//!   ~0. Instead the kernel's **retransmit** events give the share of
//!   outbound segments sent again. Inbound loss isn't visible.
//! - **rates and check counts** (a [`StunMatcher`] on 58/70 B, counts only).
//!
//! What does **not** carry over is RTT. Kernel TCP *send* events come one
//! per message but are stamped when the data is **acknowledged** (median
//! +0.46 ms, p95 +51 ms after the wire in E3-T3). The peer's check reply
//! carries that acknowledgement, so "send" and "reply" land microseconds
//! apart, and pairing them read 0.009 ms against a true 0.232 ms. So no RTT
//! is produced on TCP; the send events' own `startime`/`endtime` fields are
//! logged in `tcp_seg` to see whether a send start can be recovered.
//!
//! A segment can hold more than one message (TCP coalescing; 186 B = 99 + 87
//! was seen). Such segments don't match a known size and are simply not used
//! for jitter, never guessed.
//!
//! # Separation from the UDP method
//!
//! Nothing here touches the UDP matcher, traffic maps or relay detectors:
//! this module has its own state, fed only from the TCP channel, and its
//! traffic rows carry their own role (`peer_tcp`).

use std::collections::HashMap;
use std::net::SocketAddrV4;

use crate::etw::{TcpKind, TcpSegment};
use crate::jitter::StreamJitter;
use crate::monitor::RateWindow;
use crate::stun::{Datagram, Direction, StunConfig, StunMatcher};

/// Bytes Steam adds in front of each datagram on the TCP fallback.
pub const FRAME_BYTES: u32 = 2;

/// One TCP fallback connection (keyed by the peer's endpoint).
#[derive(Default, Clone)]
pub struct TcpPath {
    pub pkts_in: u64,
    pub pkts_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub retransmits: u64,
    pub rate_in: RateWindow,
    pub rate_out: RateWindow,
    pub rate_retx: RateWindow,
    pub jit_in: StreamJitter,
    pub jit_out: StreamJitter,
    pub max_gap_in_ns: i128,
    last_in_ns: i128,
    /// Kernel receive events seen on this connection; until one is, the
    /// copy-to-application events stand in for them.
    saw_recv: bool,
    pub copies: u64,
}

impl TcpPath {
    /// Outbound retransmits as a share of segments sent, over the rate
    /// window, or `None` when nothing was sent.
    pub fn retransmit_share(&self, t_now: i128) -> Option<f64> {
        let out = self.rate_out.rate(t_now);
        (out > 0.0).then(|| (self.rate_retx.rate(t_now) / out).min(1.0))
    }
}

/// All TCP fallback state: per-endpoint paths and the framed-size matcher.
pub struct TcpPaths {
    paths: HashMap<SocketAddrV4, TcpPath>,
    matcher: StunMatcher,
}

impl TcpPaths {
    /// `req_size` / `reply_size` are the UDP check sizes; the TCP matcher
    /// uses them plus the 2-byte frame.
    pub fn new(req_size: u32, reply_size: u32) -> Self {
        Self {
            paths: HashMap::new(),
            matcher: StunMatcher::new(StunConfig {
                request_size: req_size + FRAME_BYTES,
                reply_size: reply_size + FRAME_BYTES,
                ..Default::default()
            }),
        }
    }

    /// Feed one segment to a known peer endpoint. The check matcher only
    /// counts requests and replies here; its RTT is discarded because send
    /// timestamps are acknowledgement times (see the module docs).
    pub fn observe(&mut self, s: &TcpSegment) {
        let p = self.paths.entry(s.remote).or_default();
        let kind = match s.kind {
            TcpKind::Copy => {
                p.copies += 1;
                if p.saw_recv {
                    return;
                }
                TcpKind::Recv
            }
            TcpKind::Recv => {
                p.saw_recv = true;
                TcpKind::Recv
            }
            k => k,
        };
        let dir = match kind {
            TcpKind::Retransmit => {
                p.retransmits += 1;
                p.rate_retx.push(s.t_ns);
                return;
            }
            TcpKind::Send => {
                p.pkts_out += 1;
                p.bytes_out += s.size as u64;
                p.rate_out.push(s.t_ns);
                p.jit_out.observe(s.size, s.t_ns);
                Direction::Send
            }
            TcpKind::Recv | TcpKind::Copy => {
                p.pkts_in += 1;
                p.bytes_in += s.size as u64;
                p.rate_in.push(s.t_ns);
                p.jit_in.observe(s.size, s.t_ns);
                if p.last_in_ns != 0 {
                    p.max_gap_in_ns = p.max_gap_in_ns.max(s.t_ns - p.last_in_ns);
                }
                p.last_in_ns = s.t_ns;
                Direction::Recv
            }
        };
        let _ = self.matcher.observe(&Datagram {
            t_ns: s.t_ns,
            dir,
            remote: s.remote,
            size: s.size,
        });
    }

    pub fn path(&self, ep: &SocketAddrV4) -> Option<&TcpPath> {
        self.paths.get(ep)
    }

    pub fn paths(&self) -> impl Iterator<Item = (&SocketAddrV4, &TcpPath)> {
        self.paths.iter()
    }

    pub fn counters(&self, ep: &SocketAddrV4) -> crate::stun::EndpointCounters {
        self.matcher.counters(ep)
    }

    /// Whether data is arriving on the TCP path to `ep` (inbound rate over
    /// the same 5 s window as UDP).
    pub fn receiving(&self, ep: &SocketAddrV4, t_now: i128) -> bool {
        self.paths
            .get(ep)
            .is_some_and(|p| p.rate_in.rate(t_now) > 0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const MS: i128 = 1_000_000;
    const T: i128 = 83 * MS + MS / 3;

    fn peer() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 15), 49202)
    }

    fn seg(t_ns: i128, kind: TcpKind, size: u32) -> TcpSegment {
        TcpSegment {
            t_ns,
            pid: 1,
            kind,
            remote: peer(),
            size,
            send_times: None,
        }
    }

    /// Framed checks (58 out, 70 in) are counted; unframed sizes (56/68)
    /// aren't.
    #[test]
    fn framed_checks_are_counted() {
        let mut p = TcpPaths::new(56, 68);
        p.observe(&seg(0, TcpKind::Send, 58));
        p.observe(&seg(3 * MS, TcpKind::Recv, 70));
        p.observe(&seg(10 * MS, TcpKind::Send, 56));
        p.observe(&seg(12 * MS, TcpKind::Recv, 68));
        let c = p.counters(&peer());
        assert_eq!((c.requests, c.replies), (1, 1));
    }

    /// The framed 87 B game stream gives jitter; a coalesced segment
    /// (186 = 99 + 87) and other sizes don't disturb it.
    #[test]
    fn framed_stream_gives_jitter_and_ignores_coalesced_segments() {
        let mut p = TcpPaths::new(56, 68);
        for i in 0..300 {
            p.observe(&seg(i * T, TcpKind::Recv, 87));
            if i % 7 == 0 {
                p.observe(&seg(i * T + 5 * MS, TcpKind::Recv, 186));
            }
        }
        let path = p.path(&peer()).unwrap();
        assert_eq!(path.jit_in.size(), Some(87));
        assert!(path.jit_in.jitter_ms().unwrap() < 1e-6);
        assert!(p.receiving(&peer(), 299 * T + 2_000 * MS));
    }

    /// Copy events count as receives only on a connection without kernel
    /// receive events; once a receive is seen, copies are only counted.
    #[test]
    fn copies_stand_in_until_receives_appear() {
        let mut p = TcpPaths::new(56, 68);
        p.observe(&seg(0, TcpKind::Send, 58));
        p.observe(&seg(2 * MS, TcpKind::Copy, 70));
        assert_eq!(p.counters(&peer()).replies, 1);
        p.observe(&seg(10 * MS, TcpKind::Recv, 87));
        p.observe(&seg(11 * MS, TcpKind::Copy, 87));
        let path = p.path(&peer()).unwrap();
        assert_eq!((path.pkts_in, path.copies), (2, 2));
    }

    /// Retransmits count against segments sent, over the rate window.
    #[test]
    fn retransmit_share_over_the_window() {
        let mut p = TcpPaths::new(56, 68);
        for i in 0..100 {
            p.observe(&seg(i * 50 * MS, TcpKind::Send, 99));
            if i % 10 == 0 {
                p.observe(&seg(i * 50 * MS + MS, TcpKind::Retransmit, 99));
            }
        }
        let path = p.path(&peer()).unwrap();
        assert_eq!(path.retransmits, 10);
        let share = path.retransmit_share(100 * 50 * MS).unwrap();
        assert!((share - 0.1).abs() < 0.02, "{share}");
        assert!(TcpPath::default().retransmit_share(0).is_none());
    }
}
