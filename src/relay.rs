//! Detecting relayed sessions and finding the Valve relay endpoints that
//! carry them.
//!
//! # The problem
//!
//! When Steam relays a session, the game's packets go through a Valve relay
//! server instead of straight to the other player. Steam reports this in two
//! different ways (both seen on the same PCs, experiments E1 and E2):
//!
//! | mode | Steam's relay flag | Steam's remote address | where the packets go |
//! |------|--------------------|------------------------|----------------------|
//! | E1   | **yes**            | the player's own public IP (no packets go there) | one relay endpoint, never named |
//! | E2   | **no**             | a relay endpoint       | that endpoint carries our sends and the STUN replies; the player's traffic arrives from a **second port** on the same relay IP, wrapped in a relay header |
//!
//! So Steam's flag alone isn't reliable, and in both modes some or all of
//! the traffic sits on endpoints Steam never names.
//!
//! # Four detectors
//!
//! Each is evaluated for every peer on every poll and logged (event
//! `relay_evidence`), so their agreement can be measured:
//!
//! - **F**, Steam's flag: `using_relay`.
//! - **P**, traffic pattern: another steam.exe port on the reported remote's
//!   IP carries game-rate traffic. A direct peer talks over one port; the E2
//!   relay layout uses two.
//! - **A**, ASN database: the optional DB-IP ASN file says the remote IP
//!   belongs to Valve's network (AS32590).
//! - **L**, built-in list: the remote IP is in Valve's announced address
//!   space or at a listed Steam relay site, including partner-hosted ones
//!   (`valve.rs`).
//!
//! `--relay-detect` chooses which of them decide; a peer is treated as
//! relayed if any deciding detector fires.
//!
//! # Attribution by relay IP
//!
//! Once a relay IP is known, **every** steam.exe endpoint on that IP counts
//! for the peer, but only while exactly one live peer uses that relay IP:
//! with several, one relay server may carry them all and the traffic can't
//! be split per player. The relay IP comes from:
//! - E2 mode (P, A or L fired on Steam's remote): Steam's remote IP itself;
//! - E1 mode (only the flag fired): the rule in [`pick`], which finds the
//!   busiest game-like steam.exe endpoint. It's only used when exactly one
//!   peer is in this mode.
//!
//! Inferred attributions are shown as `yes*`, so they're never presented as
//! Steam's word.

use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

/// Minimum combined (in + out) packets/second for an endpoint to look like a
/// game session. DS3 co-op runs at roughly 55 packets/s; Steam's background
/// chatter with its servers is far below this.
pub const MIN_RELAY_PPS: f64 = 5.0;

/// Relay header added to each packet the relay delivers on a wrapped port
/// (E2: a data indication with cookie, source-address and data attributes).
pub const WRAP_IN_BYTES: u64 = 44;
/// Relay header added to each packet sent on a wrapped port (E2: a send
/// request with cookie, username, destination and data attributes).
pub const WRAP_OUT_BYTES: u64 = 64;

// ---------------------------------------------------------------------------
// Detectors and evidence
// ---------------------------------------------------------------------------

/// Which detectors decide whether a peer counts as relayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Detectors {
    pub flag: bool,
    pub pattern: bool,
    pub asn: bool,
    pub list: bool,
}

impl Detectors {
    pub const ALL: Detectors = Detectors {
        flag: true,
        pattern: true,
        asn: true,
        list: true,
    };
}

/// Parses `"F,P,A,L"` (any subset, any order, case-insensitive; the full
/// names `flag`, `pattern`, `asn`, `list` work too). Implementing the
/// standard `FromStr` trait is what lets clap parse it from the command line.
impl FromStr for Detectors {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut d = Detectors {
            flag: false,
            pattern: false,
            asn: false,
            list: false,
        };
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part.to_ascii_lowercase().as_str() {
                "f" | "flag" => d.flag = true,
                "p" | "pattern" => d.pattern = true,
                "a" | "asn" => d.asn = true,
                "l" | "list" => d.list = true,
                other => return Err(format!("unknown relay detector '{other}' (use F, P, A, L)")),
            }
        }
        Ok(d)
    }
}

impl fmt::Display for Detectors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v = Vec::new();
        for (on, c) in [
            (self.flag, "F"),
            (self.pattern, "P"),
            (self.asn, "A"),
            (self.list, "L"),
        ] {
            if on {
                v.push(c);
            }
        }
        write!(f, "{}", v.join(","))
    }
}

/// What each detector says about one peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Evidence {
    pub flag: bool,
    pub pattern: bool,
    /// `None` when no ASN database is loaded.
    pub asn: Option<bool>,
    pub list: bool,
}

impl Evidence {
    /// Evidence that Steam's **reported remote is itself a relay** (P, A or
    /// L), as opposed to the flag, which says nothing about the address.
    pub fn remote_is_relay(&self, d: &Detectors) -> bool {
        (d.pattern && self.pattern) || (d.asn && self.asn == Some(true)) || (d.list && self.list)
    }

    /// Whether the peer counts as relayed under the deciding detectors.
    pub fn relayed(&self, d: &Detectors) -> bool {
        (d.flag && self.flag) || self.remote_is_relay(d)
    }

    /// The detectors that fired, e.g. `"PAL"`, or `"-"` for none.
    pub fn letters(&self) -> String {
        let s: String = [
            (self.flag, 'F'),
            (self.pattern, 'P'),
            (self.asn == Some(true), 'A'),
            (self.list, 'L'),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, c)| *c)
        .collect();
        if s.is_empty() { "-".into() } else { s }
    }

    /// Log form, e.g. `"F=0 P=1 A=? L=1"` (`?` = no ASN database).
    pub fn log_detail(&self) -> String {
        let b = |x: bool| if x { '1' } else { '0' };
        let a = match self.asn {
            Some(x) => b(x),
            None => '?',
        };
        format!(
            "F={} P={} A={} L={}",
            b(self.flag),
            b(self.pattern),
            a,
            b(self.list)
        )
    }
}

// ---------------------------------------------------------------------------
// Endpoint rules
// ---------------------------------------------------------------------------

/// One steam.exe endpoint that might be (part of) a relay.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Candidate {
    pub ep: SocketAddrV4,
    /// Packets/second, both directions combined.
    pub pps: f64,
    /// Has carried both a request-sized send and a reply-sized receive.
    pub stun_like: bool,
}

impl Candidate {
    /// Game-rate traffic with the 56/68-byte checks: what a relay endpoint
    /// carrying a session looks like.
    pub fn looks_like_game(&self) -> bool {
        self.stun_like && self.pps >= MIN_RELAY_PPS
    }
}

/// E1-mode rule: the busiest game-like steam.exe endpoint, only when exactly
/// one peer needs it. `flag_only_peers` counts live peers Steam flags as
/// relayed whose reported remote isn't a relay; `claimed` holds endpoints
/// Steam reports for peers.
pub fn pick(
    flag_only_peers: usize,
    candidates: &[Candidate],
    claimed: &HashSet<SocketAddrV4>,
) -> Option<SocketAddrV4> {
    if flag_only_peers != 1 {
        return None;
    }
    candidates
        .iter()
        .filter(|c| c.looks_like_game() && !claimed.contains(&c.ep))
        .max_by(|a, b| a.pps.total_cmp(&b.pps))
        .map(|c| c.ep)
}

/// Detector P: does another port on `remote`'s IP carry game-rate traffic?
/// `claimed` holds endpoints Steam reports for *other* peers, which never
/// count as a sibling.
pub fn pattern(
    remote: SocketAddrV4,
    candidates: &[Candidate],
    claimed: &HashSet<SocketAddrV4>,
) -> bool {
    candidates.iter().any(|c| {
        c.ep.ip() == remote.ip()
            && c.ep.port() != remote.port()
            && c.pps >= MIN_RELAY_PPS
            && !claimed.contains(&c.ep)
    })
}

/// The standard STUN server port (RFC 8489). The relay hosts also run a
/// STUN server there, which Steam queries for its own NAT discovery even on
/// direct sessions (seen in the relay-detection test 1: a 20-byte request
/// and 56-byte reply now and then). That's not the session's traffic.
pub const STUN_SERVER_PORT: u16 = 3478;

/// All endpoints on `relay_ip` among `keys`, except `exclude` (Steam's own
/// reported remote, already counted), endpoints claimed by other peers, and
/// the STUN server port. Sorted, so comparing with the previous attribution
/// is a plain `==`.
pub fn group(
    relay_ip: Ipv4Addr,
    keys: impl IntoIterator<Item = SocketAddrV4>,
    exclude: Option<SocketAddrV4>,
    claimed: &HashSet<SocketAddrV4>,
) -> Vec<SocketAddrV4> {
    let mut v: Vec<SocketAddrV4> = keys
        .into_iter()
        .filter(|ep| {
            *ep.ip() == relay_ip
                && ep.port() != STUN_SERVER_PORT
                && Some(*ep) != exclude
                && !claimed.contains(ep)
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    v.sort();
    v
}

/// What a relay endpoint carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Carries the 56/68-byte connectivity checks (and so the RTT samples).
    Stun,
    /// Carries relay-wrapped traffic (E2: the other player's packets).
    Wrapped,
}

impl Role {
    pub fn of(stun_like: bool) -> Self {
        if stun_like { Role::Stun } else { Role::Wrapped }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Stun => "relay_stun",
            Role::Wrapped => "relay_wrapped",
        }
    }
}

/// Estimated game payload bytes (in, out) on a wrapped endpoint: raw bytes
/// minus the relay header per packet. `None` for a `Stun` endpoint, whose
/// packets aren't wrapped. The header sizes were measured in E2 mode only.
pub fn payload_estimate(
    role: Role,
    bytes_in: u64,
    pkts_in: u64,
    bytes_out: u64,
    pkts_out: u64,
) -> Option<(u64, u64)> {
    match role {
        Role::Stun => None,
        Role::Wrapped => Some((
            bytes_in.saturating_sub(WRAP_IN_BYTES * pkts_in),
            bytes_out.saturating_sub(WRAP_OUT_BYTES * pkts_out),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn cp(e: SocketAddrV4, pps: f64, stun_like: bool) -> Candidate {
        Candidate {
            ep: e,
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

    #[test]
    fn detectors_parse_letters_and_names() {
        let d: Detectors = "f, Pattern ,L".parse().unwrap();
        assert_eq!(
            d,
            Detectors {
                flag: true,
                pattern: true,
                asn: false,
                list: true
            }
        );
        assert_eq!(d.to_string(), "F,P,L");
        assert_eq!("F,P,A,L".parse::<Detectors>().unwrap(), Detectors::ALL);
        assert!("F,X".parse::<Detectors>().is_err());
    }

    #[test]
    fn evidence_decides_only_with_enabled_detectors() {
        let e2 = Evidence {
            flag: false,
            pattern: true,
            asn: Some(true),
            list: true,
        };
        assert!(e2.relayed(&Detectors::ALL));
        assert!(e2.remote_is_relay(&Detectors::ALL));
        let only_flag: Detectors = "F".parse().unwrap();
        assert!(!e2.relayed(&only_flag));
        assert_eq!(e2.letters(), "PAL");
        assert_eq!(e2.log_detail(), "F=0 P=1 A=1 L=1");

        let e1 = Evidence {
            flag: true,
            ..Default::default()
        };
        assert!(e1.relayed(&Detectors::ALL));
        assert!(!e1.remote_is_relay(&Detectors::ALL));
        assert_eq!(e1.letters(), "F");
        assert_eq!(e1.log_detail(), "F=1 P=0 A=? L=0");
        assert_eq!(Evidence::default().letters(), "-");
    }

    #[test]
    fn pattern_fires_on_a_busy_sibling_port() {
        // E2 layout: Steam reports :4379; the other player's traffic is on :4380.
        let reported = ep(148, 4379);
        let cands = [
            cp(ep(148, 4379), 35.0, true),
            cp(ep(148, 4380), 20.0, false),
        ];
        assert!(pattern(reported, &cands, &HashSet::new()));
    }

    #[test]
    fn pattern_ignores_direct_peers_and_quiet_or_foreign_ports() {
        let reported = ep(15, 58864);
        // Only the reported port itself is busy: a direct peer.
        assert!(!pattern(
            reported,
            &[cp(reported, 57.0, true)],
            &HashSet::new()
        ));
        // A sibling below game rate (e.g. a brief ICE probe).
        assert!(!pattern(
            reported,
            &[cp(ep(15, 50000), 1.0, false)],
            &HashSet::new()
        ));
        // A busy port on another IP.
        assert!(!pattern(
            reported,
            &[cp(ep(16, 58864), 50.0, true)],
            &HashSet::new()
        ));
        // A sibling that is another peer's reported endpoint.
        let other = ep(15, 50001);
        let claimed: HashSet<_> = [other].into();
        assert!(!pattern(reported, &[cp(other, 50.0, true)], &claimed));
    }

    #[test]
    fn group_takes_every_port_on_the_relay_ip() {
        let ip = Ipv4Addr::new(203, 0, 113, 148);
        let keys = [
            ep(148, 4380),
            ep(148, 4379),
            ep(148, 4380),
            ep(9, 4380),
            ep(148, 27015),
            ep(148, STUN_SERVER_PORT),
        ];
        let claimed: HashSet<_> = [ep(148, 27015)].into();
        assert_eq!(
            group(ip, keys, Some(ep(148, 4379)), &claimed),
            vec![ep(148, 4380)]
        );
        assert_eq!(
            group(ip, keys, None, &HashSet::new()),
            vec![ep(148, 4379), ep(148, 4380), ep(148, 27015)]
        );
    }

    #[test]
    fn payload_estimate_strips_relay_headers_on_wrapped_ports() {
        // 10 packets of 129 B in (85 B inside), 2 of 132 B out (68 B inside).
        assert_eq!(
            payload_estimate(Role::Wrapped, 1290, 10, 264, 2),
            Some((850, 136))
        );
        assert_eq!(payload_estimate(Role::Stun, 1290, 10, 264, 2), None);
        assert_eq!(payload_estimate(Role::Wrapped, 10, 1, 0, 0), Some((0, 0)));
        assert_eq!(Role::of(true), Role::Stun);
        assert_eq!(Role::of(false).as_str(), "relay_wrapped");
    }
}
