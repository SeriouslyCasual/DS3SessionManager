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
//! | E2   | **no**             | a relay endpoint       | that endpoint carries our sends and the STUN replies; the player's traffic arrives **wrapped from another relay endpoint**, on the same relay host or a different one |
//!
//! The E2 layout fits two relay allocations, one per player: we send
//! unwrapped to the other player's allocation (which Steam then reports as
//! an ordinary address), and their traffic reaches us through our own
//! allocation, wrapped. The two can sit on different relay hosts (seen in
//! the relay tests: `:4379` on one Seattle host, `:4380` on another), and
//! for distant players presumably at different relay sites.
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
//! - **P**, traffic asymmetry (no lists involved): Steam's remote carries our
//!   game-rate sends but almost nothing back (only the ~2/s STUN replies),
//!   while another steam.exe endpoint receives game-rate inbound traffic. A
//!   direct peer sends its ~20/s back on the same endpoint.
//! - **A**, ASN database: the optional DB-IP ASN file says the remote IP
//!   belongs to Valve's network (AS32590).
//! - **L**, built-in list: the remote IP is in Valve's announced address
//!   space or at a listed Steam relay site, including partner-hosted ones
//!   (`valve.rs`).
//!
//! `--relay-detect` chooses which of them decide; a peer is treated as
//! relayed if any deciding detector fires.
//!
//! # Attribution
//!
//! While **exactly one** live peer is relayed, every steam.exe endpoint
//! that no other peer claims and that looks like part of the session counts
//! for it ([`relay_set`]): a relay address (lists or ASN) or an endpoint
//! receiving game-rate inbound traffic, at game rate, on any host or site.
//! With several relayed peers nothing is attributed: their relay traffic
//! can't be told apart without the packet contents. In E1 mode, where
//! Steam's remote carries no packets, [`pick`] also finds the busiest
//! game-like endpoint.
//!
//! The "relay host" shown and placed (`relay_ip` in the monitor) is the one
//! carrying the RTT: Steam's remote in E2 mode, the picked endpoint in E1.
//!
//! Inferred attributions are shown as `yes*`, so they're never presented as
//! Steam's word.

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddrV4;
use std::str::FromStr;

/// Minimum combined (in + out) packets/second for an endpoint to look like a
/// game session. DS3 co-op runs at roughly 55 packets/s; Steam's background
/// chatter with its servers is far below this.
pub const MIN_RELAY_PPS: f64 = 5.0;

/// Detector P: Steam's remote must carry at least this many sends/second
/// (game rate; E2 relay tests: ~33/s)...
pub const ASYM_MIN_OUT_PPS: f64 = 10.0;
/// ...but receive at most this many/second: only the STUN replies (~2/s),
/// with margin. A direct peer sends ~20/s back.
pub const ASYM_MAX_IN_PPS: f64 = 5.0;
/// Detector P and attribution: an endpoint receiving at least this many
/// packets/second carries inbound game traffic (E2 relay tests: ~18–21/s).
pub const GAME_IN_PPS: f64 = 8.0;

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
    /// Packets/second received from / sent to it.
    pub pps_in: f64,
    pub pps_out: f64,
    /// Has carried both a request-sized send and a reply-sized receive.
    pub stun_like: bool,
    /// Its IP is a relay address (built-in list or ASN database).
    pub relay_addr: bool,
}

impl Candidate {
    /// A candidate from per-direction rates.
    pub fn new(
        ep: SocketAddrV4,
        pps_in: f64,
        pps_out: f64,
        stun_like: bool,
        relay_addr: bool,
    ) -> Self {
        Self {
            ep,
            pps: pps_in + pps_out,
            pps_in,
            pps_out,
            stun_like,
            relay_addr,
        }
    }

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

/// Detector P: Steam's remote carries our game-rate sends but almost nothing
/// back, while another endpoint receives game-rate inbound traffic.
/// `claimed` holds endpoints Steam reports for *other* peers, which never
/// count as that other endpoint.
pub fn pattern(
    remote: SocketAddrV4,
    candidates: &[Candidate],
    claimed: &HashSet<SocketAddrV4>,
) -> bool {
    let Some(r) = candidates.iter().find(|c| c.ep == remote) else {
        return false;
    };
    r.pps_out >= ASYM_MIN_OUT_PPS
        && r.pps_in <= ASYM_MAX_IN_PPS
        && candidates.iter().any(|c| {
            c.ep != remote
                && c.ep.port() != STUN_SERVER_PORT
                && c.pps_in >= GAME_IN_PPS
                && !claimed.contains(&c.ep)
        })
}

/// The standard STUN server port (RFC 8489). The relay hosts also run a
/// STUN server there, which Steam queries for its own NAT discovery even on
/// direct sessions (seen in the relay-detection test 1: a 20-byte request
/// and 56-byte reply now and then). That's not the session's traffic.
pub const STUN_SERVER_PORT: u16 = 3478;

/// The endpoints that count for the one relayed peer, besides Steam's own
/// reported remote (`exclude`). Call it only when exactly one live peer is
/// relayed. An endpoint qualifies if no other peer claims it, it isn't the
/// STUN server port, and it's part of the session: a relay address (lists
/// or ASN) or an endpoint receiving game-rate inbound traffic, at game rate.
/// Endpoints already attributed (`previous`) stay while they carry any
/// traffic, so a short dip below game rate doesn't flap the attribution.
/// `e1_pick` (E1 mode) is always included. Sorted, so comparing with the
/// previous attribution is a plain `==`.
pub fn relay_set(
    candidates: &[Candidate],
    exclude: Option<SocketAddrV4>,
    claimed: &HashSet<SocketAddrV4>,
    previous: &[SocketAddrV4],
    e1_pick: Option<SocketAddrV4>,
) -> Vec<SocketAddrV4> {
    let mut v: Vec<SocketAddrV4> = candidates
        .iter()
        .filter(|c| {
            Some(c.ep) != exclude
                && c.ep.port() != STUN_SERVER_PORT
                && !claimed.contains(&c.ep)
                && (c.relay_addr || c.pps_in >= GAME_IN_PPS)
                && (c.pps >= MIN_RELAY_PPS || (previous.contains(&c.ep) && c.pps > 0.0))
        })
        .map(|c| c.ep)
        .chain(e1_pick.filter(|e| Some(*e) != exclude))
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
    use std::net::Ipv4Addr;

    fn ep(last: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, last), port)
    }

    fn c(last: u8, pps: f64, stun_like: bool) -> Candidate {
        Candidate::new(ep(last, 4380), pps / 2.0, pps / 2.0, stun_like, false)
    }

    /// A candidate with per-direction rates.
    fn cd(e: SocketAddrV4, pin: f64, pout: f64, stun_like: bool, relay_addr: bool) -> Candidate {
        Candidate::new(e, pin, pout, stun_like, relay_addr)
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
    fn pattern_fires_on_asymmetry_same_host_or_not() {
        // E2 layout: Steam reports :4379 (our sends, ~2/s replies back); the
        // other player's traffic arrives wrapped on :4380.
        let reported = ep(134, 4379);
        for wrapped in [ep(134, 4380), ep(148, 4380), ep(9, 27050)] {
            let cands = [
                cd(reported, 2.0, 33.0, true, true),
                cd(wrapped, 20.0, 2.0, false, true),
            ];
            assert!(pattern(reported, &cands, &HashSet::new()), "{wrapped}");
        }
    }

    #[test]
    fn pattern_is_false_for_direct_peers_and_quiet_or_claimed_endpoints() {
        let reported = ep(15, 58864);
        // A direct peer: ~19/s comes back on the same endpoint.
        let direct = cd(reported, 19.0, 37.0, true, false);
        let busy_other = cd(ep(16, 50000), 20.0, 2.0, false, false);
        assert!(!pattern(reported, &[direct, busy_other], &HashSet::new()));
        // Asymmetric, but nothing else receives game traffic.
        let asym = cd(reported, 2.0, 33.0, true, true);
        let quiet = cd(ep(16, 50000), 1.0, 0.5, false, true);
        assert!(!pattern(reported, &[asym, quiet], &HashSet::new()));
        // The busy endpoint is another peer's, or the STUN server port.
        let other = ep(16, 50001);
        let claimed: HashSet<_> = [other].into();
        assert!(!pattern(
            reported,
            &[asym, cd(other, 20.0, 2.0, false, true)],
            &claimed
        ));
        let stun = cd(ep(16, STUN_SERVER_PORT), 20.0, 2.0, false, true);
        assert!(!pattern(reported, &[asym, stun], &HashSet::new()));
        // Steam's remote carries no traffic at all (E1 mode): not P's case.
        assert!(!pattern(reported, &[busy_other], &HashSet::new()));
    }

    #[test]
    fn relay_set_takes_relay_endpoints_on_any_host() {
        let reported = ep(134, 4379);
        let cands = [
            cd(reported, 2.0, 33.0, true, true),
            cd(ep(148, 4380), 20.0, 2.0, false, true), // other host, wrapped
            cd(ep(148, STUN_SERVER_PORT), 0.2, 0.2, false, true), // NAT discovery
            cd(ep(77, 443), 0.5, 0.5, false, false),   // background chatter
            cd(ep(20, 4380), 20.0, 2.0, false, true),  // another peer's
        ];
        let claimed: HashSet<_> = [ep(20, 4380)].into();
        assert_eq!(
            relay_set(&cands, Some(reported), &claimed, &[], None),
            vec![ep(148, 4380)]
        );
    }

    #[test]
    fn relay_set_includes_unlisted_inbound_and_e1_pick() {
        // Not in any list, but receiving the inbound game traffic.
        let unlisted = cd(ep(50, 3000), 20.0, 2.0, false, false);
        assert_eq!(
            relay_set(&[unlisted], None, &HashSet::new(), &[], None),
            vec![ep(50, 3000)]
        );
        // Listed but too slow, and not previously attributed: left out.
        let slow = cd(ep(51, 4380), 1.0, 1.0, false, true);
        assert!(relay_set(&[slow], None, &HashSet::new(), &[], None).is_empty());
        // ...unless already attributed (no flapping on a short dip).
        assert_eq!(
            relay_set(&[slow], None, &HashSet::new(), &[ep(51, 4380)], None),
            vec![ep(51, 4380)]
        );
        // E1 mode: the picked endpoint always counts.
        assert_eq!(
            relay_set(&[], None, &HashSet::new(), &[], Some(ep(52, 4380))),
            vec![ep(52, 4380)]
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
