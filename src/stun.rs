//! Turns observed UDP packets into round-trip-time (RTT) samples.
//!
//! # The networking idea
//!
//! Players behind home routers (NATs) can't simply connect to each other.
//! Steam uses ICE (RFC 8445): it repeatedly sends small **STUN** (RFC 8489)
//! "binding request" packets and receives "binding response" packets. These
//! connectivity checks keep running for the whole session to keep the NAT's
//! port mapping open. So the game constantly produces request/response
//! pairs for free: time from request to response is one RTT sample.
//!
//! The catch: kernel ETW tells us a packet's **size, endpoints and time**,
//! but not its contents. We can't read the STUN header to confirm a packet
//! *is* STUN, or match a response to its request by transaction ID. Following
//! the technique documented by DS3ConnectionInfo (reimplemented here, no code
//! copied), Steam's checks are recognised **by payload size alone**: 56-byte
//! requests and 68-byte replies by default. The sizes are configurable,
//! because they're an empirical observation that can change. Packet captures,
//! where the STUN header can be read, are the way to check them.
//!
//! # Matching policy
//!
//! Requests to each peer are queued in time order. When a reply arrives:
//! 1. requests older than `timeout` are discarded and counted as **lost**;
//! 2. the reply is paired with the **oldest** remaining request.
//!
//! Without transaction IDs some ambiguity is unavoidable: if one reply is
//! lost, the next reply could be paired with the wrong request. The counters
//! below make that measurable rather than hidden.
//!
//! # The Rust idea
//!
//! A small *state machine*: `StunMatcher` owns per-peer queues and counters,
//! and `observe()` updates them one packet at a time. It does no I/O, so the
//! tests can feed it made-up packets.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddrV4;

/// Tunable parameters for packet matching.
#[derive(Clone, Copy, Debug)]
pub struct StunConfig {
    /// Payload size (bytes) treated as a STUN request.
    pub request_size: u32,
    /// Payload size (bytes) treated as a STUN reply.
    pub reply_size: u32,
    /// Requests older than this (nanoseconds) count as lost.
    pub timeout_ns: i128,
}

// `Default` lets callers write `StunConfig::default()` or use struct-update
// syntax: `StunConfig { request_size: 60, ..Default::default() }`.
impl Default for StunConfig {
    fn default() -> Self {
        Self {
            request_size: 56,
            reply_size: 68,
            // Underscores in number literals are just for readability: 2 s.
            timeout_ns: 2_000_000_000,
        }
    }
}

/// Whether we sent the packet or received it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Send,
    Recv,
}

/// One UDP packet observation, already filtered to the game's process.
#[derive(Clone, Copy, Debug)]
pub struct Datagram {
    /// When it was sent or received (Unix nanoseconds).
    pub t_ns: i128,
    pub dir: Direction,
    /// The *other* end of the conversation: destination for sends, source for
    /// receives. Using the remote side as the key groups both directions of
    /// one conversation together.
    pub remote: SocketAddrV4,
    /// UDP payload size in bytes.
    pub size: u32,
}

/// A completed request/reply pair: one RTT sample.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Matched {
    pub remote: SocketAddrV4,
    /// Time of the reply.
    pub t_ns: i128,
    pub rtt_ms: f64,
}

/// Per-peer bookkeeping, used for the loss estimate and for checking how well
/// the heuristic works.
///
/// `#[derive(Default)]` makes `EndpointCounters::default()` return all zeros.
#[derive(Default, Debug, Clone, Copy)]
pub struct EndpointCounters {
    pub requests: u64,
    pub replies: u64,
    pub matched: u64,
    /// Requests that were never answered within the timeout.
    pub lost_requests: u64,
    /// Replies with no outstanding request.
    pub unmatched_replies: u64,
}

/// The matcher itself.
#[derive(Debug)]
pub struct StunMatcher {
    cfg: StunConfig,
    /// For each peer endpoint, a queue of send times of unanswered requests.
    pending: HashMap<SocketAddrV4, VecDeque<i128>>,
    /// For each peer endpoint, running totals.
    counters: HashMap<SocketAddrV4, EndpointCounters>,
}

impl StunMatcher {
    pub fn new(cfg: StunConfig) -> Self {
        Self {
            cfg,
            pending: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    /// Counters for one peer (all zeros if we've never seen it).
    ///
    /// `.get()` returns `Option<&EndpointCounters>`, `.copied()` turns that
    /// into `Option<EndpointCounters>` (the struct is `Copy`), and
    /// `.unwrap_or_default()` substitutes zeros for `None`.
    pub fn counters(&self, remote: &SocketAddrV4) -> EndpointCounters {
        self.counters.get(remote).copied().unwrap_or_default()
    }

    /// Feed one packet; returns an RTT sample when a reply completes a pair.
    pub fn observe(&mut self, d: &Datagram) -> Option<Matched> {
        // `match` with *guards* (`if ...`): an arm only matches when both the
        // pattern and the condition hold. `_` catches everything else (other
        // sizes are ordinary game traffic and are ignored here).
        match d.dir {
            Direction::Send if d.size == self.cfg.request_size => {
                // The *entry API*: find this peer's value, insert a default if
                // missing, then modify it. One hash lookup, no
                // "check-then-insert" dance.
                self.counters.entry(d.remote).or_default().requests += 1;
                self.pending.entry(d.remote).or_default().push_back(d.t_ns);
                None
            }
            Direction::Recv if d.size == self.cfg.reply_size => self.on_reply(d),
            _ => None,
        }
    }

    /// Handle a reply-sized packet. Private (no `pub`): an internal step.
    fn on_reply(&mut self, d: &Datagram) -> Option<Matched> {
        let c = self.counters.entry(d.remote).or_default();
        c.replies += 1;
        let q = self.pending.entry(d.remote).or_default();

        // Step 1: expire requests too old to be answered by this reply.
        // `while let` keeps looping as long as the pattern matches: here, as
        // long as the queue has a front element.
        while let Some(&t) = q.front() {
            if d.t_ns - t > self.cfg.timeout_ns {
                q.pop_front();
                c.lost_requests += 1;
            } else {
                break;
            }
        }

        // Step 2: pair with the oldest remaining request, if any.
        match q.pop_front() {
            // Normal case: the request happened before the reply.
            Some(t_req) if t_req <= d.t_ns => {
                c.matched += 1;
                Some(Matched {
                    remote: d.remote,
                    t_ns: d.t_ns,
                    // ns → ms: divide by one million.
                    rtt_ms: (d.t_ns - t_req) as f64 / 1e6,
                })
            }
            // Out-of-order timestamps (shouldn't happen, but don't produce a
            // negative RTT): put the request back and ignore this reply.
            Some(t_req) => {
                q.push_front(t_req);
                c.unmatched_replies += 1;
                None
            }
            // A reply with no request waiting.
            None => {
                c.unmatched_replies += 1;
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests: made-up packets with hand-computed expected RTTs.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const MS: i128 = 1_000_000;

    fn peer() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 27015)
    }

    fn dg(t_ms: i128, dir: Direction, size: u32) -> Datagram {
        Datagram {
            t_ns: t_ms * MS,
            dir,
            remote: peer(),
            size,
        }
    }

    #[test]
    fn simple_pair() {
        let mut m = StunMatcher::new(StunConfig::default());
        assert!(m.observe(&dg(1000, Direction::Send, 56)).is_none());
        let r = m.observe(&dg(1042, Direction::Recv, 68)).unwrap();
        assert!((r.rtt_ms - 42.0).abs() < 1e-9);
        assert_eq!(m.counters(&peer()).matched, 1);
    }

    #[test]
    fn other_sizes_ignored() {
        let mut m = StunMatcher::new(StunConfig::default());
        m.observe(&dg(0, Direction::Send, 300));
        assert!(m.observe(&dg(10, Direction::Recv, 68)).is_none());
        assert_eq!(m.counters(&peer()).unmatched_replies, 1);
    }

    #[test]
    fn stale_requests_count_as_lost() {
        let mut m = StunMatcher::new(StunConfig::default());
        m.observe(&dg(0, Direction::Send, 56));
        m.observe(&dg(5000, Direction::Send, 56));
        let r = m.observe(&dg(5030, Direction::Recv, 68)).unwrap();
        assert!((r.rtt_ms - 30.0).abs() < 1e-9);
        assert_eq!(m.counters(&peer()).lost_requests, 1);
    }

    #[test]
    fn oldest_outstanding_request_is_used() {
        let mut m = StunMatcher::new(StunConfig::default());
        m.observe(&dg(0, Direction::Send, 56));
        m.observe(&dg(20, Direction::Send, 56));
        let a = m.observe(&dg(50, Direction::Recv, 68)).unwrap();
        let b = m.observe(&dg(70, Direction::Recv, 68)).unwrap();
        assert!((a.rtt_ms - 50.0).abs() < 1e-9);
        assert!((b.rtt_ms - 50.0).abs() < 1e-9);
    }

    #[test]
    fn endpoints_are_independent() {
        let mut m = StunMatcher::new(StunConfig::default());
        let other = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 1);
        m.observe(&Datagram {
            t_ns: 0,
            dir: Direction::Send,
            remote: other,
            size: 56,
        });
        assert!(m.observe(&dg(10, Direction::Recv, 68)).is_none());
    }
}
