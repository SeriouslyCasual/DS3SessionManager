//! Inferring which Valve relay endpoint carries a relayed peer's traffic.
//!
//! # The problem
//!
//! When Steam relays a session (Steam Datagram Relay), `GetP2PSessionState`
//! reports the **peer's own public address**, not the relay's. No packets go
//! to that address: the Steam client sends everything to a Valve relay
//! server instead, and Steam never says which one. Without the relay
//! endpoint, ds3sm (and DS3ConnectionInfo, which shows ping -1) can't measure
//! a relayed peer at all.
//!
//! # What was observed (E1, firewall-forced relay)
//!
//! steam.exe exchanged all the game traffic with one Valve address, at the
//! same rate as on the direct path, and the 56/68-byte connectivity checks
//! were still present. So the relay endpoint *looks like* the direct one:
//! game-rate traffic plus request/reply-sized packets.
//!
//! # The rule (deliberately conservative)
//!
//! Only when **exactly one** peer is relayed: pick the busiest steam.exe
//! endpoint that
//! 1. has carried both a request-sized send and a reply-sized receive,
//! 2. carries at least [`MIN_RELAY_PPS`] packets/second (game rate is ~55), and
//! 3. isn't already the endpoint of a direct peer.
//!
//! With several relayed peers they may share one relay server, so the
//! traffic can't be split per player: no endpoint is attributed, and the
//! relay endpoints are listed on their own instead. The table marks an
//! inferred attribution as `yes*`, so it's never presented as Steam's word.

use std::collections::HashSet;
use std::net::SocketAddrV4;

/// Minimum combined (in + out) packets/second for an endpoint to look like a
/// game session. DS3 co-op runs at roughly 55 packets/s; Steam's background
/// chatter with its servers is far below this.
pub const MIN_RELAY_PPS: f64 = 5.0;

/// One steam.exe endpoint that might be a relay.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Candidate {
    pub ep: SocketAddrV4,
    /// Packets/second, both directions combined.
    pub pps: f64,
    /// Has carried both a request-sized send and a reply-sized receive.
    pub stun_like: bool,
}

impl Candidate {
    /// Passes the rule's per-endpoint tests (1 and 2 above).
    pub fn looks_like_game(&self) -> bool {
        self.stun_like && self.pps >= MIN_RELAY_PPS
    }
}

/// Apply the rule. `relayed_peers` is how many live peers Steam reports as
/// relayed; `claimed` holds the endpoints of direct peers.
pub fn pick(
    relayed_peers: usize,
    candidates: &[Candidate],
    claimed: &HashSet<SocketAddrV4>,
) -> Option<SocketAddrV4> {
    if relayed_peers != 1 {
        return None;
    }
    candidates
        .iter()
        .filter(|c| c.looks_like_game() && !claimed.contains(&c.ep))
        .max_by(|a, b| a.pps.total_cmp(&b.pps))
        .map(|c| c.ep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ep(last: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, last), port)
    }

    fn c(last: u8, pps: f64, stun_like: bool) -> Candidate {
        Candidate {
            ep: ep(last, 4380),
            pps,
            stun_like,
        }
    }

    #[test]
    fn one_relayed_peer_gets_the_busiest_game_like_endpoint() {
        let cands = [c(1, 3.0, true), c(2, 60.0, true), c(3, 90.0, false)];
        assert_eq!(pick(1, &cands, &HashSet::new()), Some(ep(2, 4380)));
    }

    #[test]
    fn no_attribution_unless_exactly_one_relayed_peer() {
        let cands = [c(2, 60.0, true)];
        assert_eq!(pick(0, &cands, &HashSet::new()), None);
        assert_eq!(pick(2, &cands, &HashSet::new()), None);
    }

    #[test]
    fn direct_peer_endpoints_are_never_picked() {
        let cands = [c(2, 60.0, true), c(4, 40.0, true)];
        let claimed: HashSet<_> = [ep(2, 4380)].into();
        assert_eq!(pick(1, &cands, &claimed), Some(ep(4, 4380)));
    }

    #[test]
    fn background_traffic_is_not_a_relay() {
        // Too slow, or never carried request/reply-sized packets.
        let cands = [c(1, 2.0, true), c(2, 80.0, false)];
        assert_eq!(pick(1, &cands, &HashSet::new()), None);
    }
}
