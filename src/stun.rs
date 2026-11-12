//! Pairs outgoing and incoming STUN-sized UDP datagrams into RTT samples.
//!
//! Kernel ETW reports a UDP payload's size, endpoints, PID and timestamp, but
//! not its contents. Following the technique documented by DS3ConnectionInfo
//! (reimplemented here, no code copied), Steam's connectivity checks are
//! recognised by payload size alone: by default 56-byte requests and 68-byte
//! replies. The sizes are configurable because experiment E2 checks them
//! against packet captures, where the STUN header can actually be parsed
//! (RFC 8489).
//!
//! Matching policy: a reply is paired with the **oldest** request to the same
//! endpoint that is still within `timeout`. Any older outstanding requests
//! are treated as lost. Without transaction IDs some ambiguity is unavoidable
//! under loss; E2 quantifies it.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddrV4;

#[derive(Clone, Copy, Debug)]
pub struct StunConfig {
    pub request_size: u32,
    pub reply_size: u32,
    pub timeout_ns: i128,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self {
            request_size: 56,
            reply_size: 68,
            timeout_ns: 2_000_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Send,
    Recv,
}

/// One UDP datagram observation, already filtered to the game's PID.
#[derive(Clone, Copy, Debug)]
pub struct Datagram {
    pub t_ns: i128,
    pub dir: Direction,
    /// The remote endpoint (destination for sends, source for receives).
    pub remote: SocketAddrV4,
    pub size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Matched {
    pub remote: SocketAddrV4,
    pub t_ns: i128,
    pub rtt_ms: f64,
}

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

#[derive(Debug)]
pub struct StunMatcher {
    cfg: StunConfig,
    pending: HashMap<SocketAddrV4, VecDeque<i128>>,
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

    pub fn counters(&self, remote: &SocketAddrV4) -> EndpointCounters {
        self.counters.get(remote).copied().unwrap_or_default()
    }

    /// Feed one datagram; returns an RTT sample when a reply completes a pair.
    pub fn observe(&mut self, d: &Datagram) -> Option<Matched> {
        match d.dir {
            Direction::Send if d.size == self.cfg.request_size => {
                self.counters.entry(d.remote).or_default().requests += 1;
                self.pending.entry(d.remote).or_default().push_back(d.t_ns);
                None
            }
            Direction::Recv if d.size == self.cfg.reply_size => self.on_reply(d),
            _ => None,
        }
    }

    fn on_reply(&mut self, d: &Datagram) -> Option<Matched> {
        let c = self.counters.entry(d.remote).or_default();
        c.replies += 1;
        let q = self.pending.entry(d.remote).or_default();
        // Expire requests too old to be answered by this reply.
        while let Some(&t) = q.front() {
            if d.t_ns - t > self.cfg.timeout_ns {
                q.pop_front();
                c.lost_requests += 1;
            } else {
                break;
            }
        }
        match q.pop_front() {
            Some(t_req) if t_req <= d.t_ns => {
                c.matched += 1;
                Some(Matched {
                    remote: d.remote,
                    t_ns: d.t_ns,
                    rtt_ms: (d.t_ns - t_req) as f64 / 1e6,
                })
            }
            Some(t_req) => {
                // Out-of-order timestamps: put it back and ignore this reply.
                q.push_front(t_req);
                c.unmatched_replies += 1;
                None
            }
            None => {
                c.unmatched_replies += 1;
                None
            }
        }
    }
}

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
