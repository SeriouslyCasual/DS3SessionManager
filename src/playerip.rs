//! Which public address belongs to which relayed player.
//!
//! In E2 mode Steam reports a Valve relay as the remote, but the player's own
//! address still reaches this PC (online capture, 2026-11-15):
//! - **direct stream** (most relayed sessions): Steam's IP sharing is
//!   one-sided. The player already knows this PC's address and sends its game
//!   stream, and its connectivity checks, straight here, while this PC must
//!   send through the relay. ETW sees the stream (addresses and timing only).
//! - **relay header**: otherwise the player's packets arrive wrapped by a
//!   nearby relay, whose header names the player's address (`gturn.rs`).
//!
//! Neither a stream nor a header carries a Steam ID. Links are made in this
//! order, the first two exact:
//! 1. **Steam's own report**: the public, non-relay address Steam gives for a
//!    player (while direct, or in E1 mode).
//! 2. **Session credential** (`gturn::check_username`): this PC's ICE
//!    credential for a session appears in the relay's answers on the
//!    endpoint Steam reports for that player, and in the checks the player
//!    sends straight here. Same credential, same session, so the address that
//!    sent those checks is that player's. Of the two exact sources, the one
//!    seen most recently wins.
//! 3. **Timing** (fallback, mainly for players whose packets only arrive
//!    wrapped, whose checks use other credentials): a sighting appears
//!    within a few seconds of a relayed player's relay episode starting.
//!    Conservative: a sighting is linked only when exactly one unlinked
//!    player started an episode within [`WINDOW_NS`] of it **and** that start
//!    matches exactly one unlinked address, judged once the sighting is
//!    [`SETTLE_NS`] old, repeated to a fixpoint (elimination). An exact link
//!    always replaces a timing link.
//!
//! The public build uses a link only for the player's region and distance;
//! the address itself is shown only in the developer build.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::gturn::Cred;
use crate::model::SteamId;

/// How far apart (ns) a sighting and a relay episode start may be. In the
/// Run 1b capture the player's stream (or first wrapped packet) came 2.4–4 s
/// *before* Steam reported the new relay episode (Steam is polled every
/// 0.5 s).
pub const WINDOW_NS: i128 = 5_000_000_000;
/// How old a sighting must be before it is judged. A competing sighting can
/// start up to two windows later and needs time to show up (the direct-stream
/// rate check covers 5 s and ends 1.5 s back; ETW delivers ~1 s late).
/// Judging earlier could link on incomplete information.
pub const SETTLE_NS: i128 = 2 * WINDOW_NS + 10_000_000_000;
/// How long starts, sightings and credentials are kept.
const HISTORY_NS: i128 = 15 * 60 * 1_000_000_000;

/// Where a player's address came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// Steam's own reported remote (direct path or E1-mode relay).
    Steam,
    /// The player's own connectivity checks, naming this PC's credential for
    /// the player's session (exact).
    Credential,
    /// An inbound-only game stream from the player's address (timing).
    Direct,
    /// The `0x0012` attribute of a relay's data indication (timing).
    Wrapper,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Steam => "steam",
            Source::Credential => "session_credential",
            Source::Direct => "direct_stream",
            Source::Wrapper => "relay_header",
        }
    }

    /// Exact sources need no timing.
    pub fn exact(self) -> bool {
        matches!(self, Source::Steam | Source::Credential)
    }
}

/// One new address seen at time `t_ns` (the stream's first packet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sighting {
    pub ep: SocketAddrV4,
    pub t_ns: i128,
    pub source: Source,
}

/// A player's address, and how it was found (`source.exact()` tells whether
/// timing was involved).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub ip: Ipv4Addr,
    pub source: Source,
}

#[derive(Default)]
pub struct Matcher {
    starts: Vec<(SteamId, i128)>,
    sightings: Vec<Sighting>,
    seen: HashSet<(SocketAddrV4, Source)>,
    /// Every address Steam reported, and each player's newest one (with time).
    steam_ips: HashSet<Ipv4Addr>,
    steam_latest: HashMap<SteamId, (Ipv4Addr, i128)>,
    /// This PC's credential per session → the player, from relay answers.
    cred_owner: HashMap<Cred, SteamId>,
    /// Credentials seen on endpoints of two different players: never trusted.
    cred_conflict: HashSet<Cred>,
    /// The newest endpoint whose checks named each credential.
    cred_ep: HashMap<Cred, (SocketAddrV4, i128)>,
    links: HashMap<SteamId, Link>,
}

impl Matcher {
    /// A relayed player's relay episode started (it became relayed, or Steam
    /// moved it to another relay endpoint).
    pub fn relay_start(&mut self, id: SteamId, t_ns: i128) {
        self.starts.push((id, t_ns));
    }

    /// Steam reported `ip` (a public, non-relay address) for `id`.
    pub fn steam_reported(&mut self, id: SteamId, ip: Ipv4Addr, t_ns: i128) {
        self.steam_ips.insert(ip);
        self.steam_latest.insert(id, (ip, t_ns));
    }

    /// A relay's answer naming this PC's credential `cred` arrived on an
    /// endpoint Steam reports for `id` alone (the caller checks that no other
    /// live player reports the same endpoint).
    pub fn relay_credential(&mut self, id: SteamId, cred: Cred) {
        if self.cred_conflict.contains(&cred) {
            return;
        }
        match self.cred_owner.insert(cred, id) {
            Some(o) if o != id => {
                self.cred_owner.remove(&cred);
                self.cred_conflict.insert(cred);
            }
            _ => {}
        }
    }

    /// A check naming this PC's credential `cred` arrived straight from `ep`.
    /// Returns `true` the first time this endpoint is seen with it.
    pub fn player_credential(&mut self, ep: SocketAddrV4, cred: Cred, t_ns: i128) -> bool {
        let new = self.cred_ep.get(&cred).is_none_or(|(e, _)| *e != ep);
        if new || self.cred_ep.get(&cred).is_some_and(|(_, t)| t_ns > *t) {
            self.cred_ep.insert(cred, (ep, t_ns));
        }
        new
    }

    /// Record a sighting; `false` if this endpoint was already seen this way.
    pub fn sighting(&mut self, s: Sighting) -> bool {
        if !self.seen.insert((s.ep, s.source)) {
            return false;
        }
        self.sightings.push(s);
        true
    }

    pub fn link(&self, id: SteamId) -> Option<Link> {
        self.links.get(&id).copied()
    }

    /// The endpoint a linked player's own packets arrive from (for its rates
    /// and jitter): the one sending its checks, else its newest direct stream.
    pub fn direct_endpoint(&self, id: SteamId) -> Option<SocketAddrV4> {
        let ip = self.links.get(&id)?.ip;
        let by_cred = self
            .cred_ep
            .iter()
            .filter(|(c, (e, _))| self.cred_owner.get(*c) == Some(&id) && *e.ip() == ip)
            .max_by_key(|(_, (_, t))| *t)
            .map(|(_, (e, _))| *e);
        by_cred.or_else(|| {
            self.sightings
                .iter()
                .filter(|s| s.source == Source::Direct && *s.ep.ip() == ip)
                .max_by_key(|s| s.t_ns)
                .map(|s| s.ep)
        })
    }

    /// The exact address for `id`, if any: the newest of Steam's report and
    /// a credential-linked endpoint.
    fn exact(&self, id: SteamId) -> Option<(Link, i128)> {
        let steam = self.steam_latest.get(&id).map(|&(ip, t)| {
            (
                Link {
                    ip,
                    source: Source::Steam,
                },
                t,
            )
        });
        let cred = self
            .cred_ep
            .iter()
            .filter(|(c, _)| self.cred_owner.get(*c) == Some(&id))
            .max_by_key(|(_, (_, t))| *t)
            .map(|(_, &(e, t))| {
                (
                    Link {
                        ip: *e.ip(),
                        source: Source::Credential,
                    },
                    t,
                )
            });
        [steam, cred].into_iter().flatten().max_by_key(|(_, t)| *t)
    }

    /// Link what can be linked; returns the links made or changed.
    pub fn resolve(&mut self, now_ns: i128) -> Vec<(SteamId, Link)> {
        self.starts.retain(|s| now_ns - s.1 <= HISTORY_NS);
        self.sightings.retain(|s| now_ns - s.t_ns <= HISTORY_NS);
        // Keep the duplicate filter as small as the history (an old stream
        // can't come back as new: the monitor only takes fresh streams).
        let live: HashSet<(SocketAddrV4, Source)> =
            self.sightings.iter().map(|s| (s.ep, s.source)).collect();
        self.seen.retain(|k| live.contains(k));
        self.cred_ep.retain(|_, (_, t)| now_ns - *t <= HISTORY_NS);
        let mut made = Vec::new();
        // Exact links first.
        let ids: HashSet<SteamId> = self
            .steam_latest
            .keys()
            .chain(self.cred_owner.values())
            .copied()
            .collect();
        for id in ids {
            if let Some((l, _)) = self.exact(id)
                && self.links.get(&id) != Some(&l)
            {
                self.links.insert(id, l);
                made.push((id, l));
            }
        }
        // Then timing, until nothing changes.
        loop {
            let mut linked_ips: HashSet<Ipv4Addr> = self.links.values().map(|l| l.ip).collect();
            linked_ips.extend(&self.steam_ips);
            let found = self.sightings.iter().find_map(|s| {
                if linked_ips.contains(s.ep.ip()) || now_ns - s.t_ns < SETTLE_NS {
                    return None;
                }
                let near = |t: i128| (t - s.t_ns).abs() <= WINDOW_NS;
                let peers: HashSet<SteamId> = self
                    .starts
                    .iter()
                    .filter(|(id, t)| near(*t) && !self.links.contains_key(id))
                    .map(|(id, _)| *id)
                    .collect();
                let [p] = peers.into_iter().collect::<Vec<_>>()[..] else {
                    return None;
                };
                // Every unlinked address near p's matching starts.
                let ips: HashSet<Ipv4Addr> = self
                    .starts
                    .iter()
                    .filter(|(id, t)| *id == p && near(*t))
                    .flat_map(|(_, t)| {
                        self.sightings
                            .iter()
                            .filter(move |o| (o.t_ns - t).abs() <= WINDOW_NS)
                            .map(|o| *o.ep.ip())
                    })
                    .filter(|ip| !linked_ips.contains(ip))
                    .collect();
                (ips.len() == 1).then_some((
                    p,
                    Link {
                        ip: *s.ep.ip(),
                        source: s.source,
                    },
                ))
            });
            let Some((p, l)) = found else { break };
            self.links.insert(p, l);
            made.push((p, l));
        }
        made
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i128 = 1_000_000_000;

    fn ep(last: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, last), port)
    }
    fn ip(last: u8) -> Ipv4Addr {
        *ep(last, 0).ip()
    }
    fn see(m: &mut Matcher, last: u8, port: u16, t: i128, source: Source) {
        m.sighting(Sighting {
            ep: ep(last, port),
            t_ns: t * S,
            source,
        });
    }
    fn cred(c: u8) -> Cred {
        [c; 16]
    }

    #[test]
    fn one_relayed_player_and_one_stream_link_by_timing() {
        let mut m = Matcher::default();
        m.relay_start(SteamId(1), 100 * S);
        see(&mut m, 20, 16597, 99, Source::Direct);
        // Not judged before it has settled (a competitor could still appear).
        assert!(m.resolve(110 * S).is_empty());
        let made = m.resolve(130 * S);
        assert_eq!(made.len(), 1);
        let l = m.link(SteamId(1)).unwrap();
        assert_eq!((l.ip, l.source), (ip(20), Source::Direct));
        assert!(!l.source.exact());
        assert_eq!(m.direct_endpoint(SteamId(1)), Some(ep(20, 16597)));
        // Nothing new the second time.
        assert!(m.resolve(131 * S).is_empty());
    }

    #[test]
    fn far_apart_or_ambiguous_does_not_link() {
        let mut m = Matcher::default();
        m.relay_start(SteamId(1), 100 * S);
        see(&mut m, 20, 1, 120, Source::Direct);
        assert!(m.resolve(200 * S).is_empty());
        // Two players start together, one stream: can't tell whose.
        let mut m = Matcher::default();
        m.relay_start(SteamId(1), 100 * S);
        m.relay_start(SteamId(2), 101 * S);
        see(&mut m, 20, 1, 100, Source::Direct);
        assert!(m.resolve(130 * S).is_empty());
        // One player, two addresses at once: can't tell which.
        let mut m = Matcher::default();
        m.relay_start(SteamId(1), 100 * S);
        see(&mut m, 20, 1, 100, Source::Direct);
        see(&mut m, 21, 1, 101, Source::Wrapper);
        assert!(m.resolve(130 * S).is_empty());
    }

    /// Run 1b at t ≈ 2990 s: two players start relay episodes together, one
    /// direct stream and one wrapped address appear. A later relay change of
    /// one player coincides with its wrapped port change, which links it; the
    /// other player then links by elimination.
    #[test]
    fn a_later_port_change_settles_both_by_elimination() {
        let mut m = Matcher::default();
        m.relay_start(SteamId(1), 2993 * S);
        m.relay_start(SteamId(2), 2993 * S);
        see(&mut m, 30, 53528, 2992, Source::Direct);
        see(&mut m, 31, 51385, 2989, Source::Wrapper);
        assert!(m.resolve(3020 * S).is_empty());
        m.relay_start(SteamId(1), 3128 * S);
        see(&mut m, 31, 56234, 3127, Source::Wrapper);
        let made = m.resolve(3150 * S);
        assert_eq!(made.len(), 2);
        assert_eq!(m.link(SteamId(1)).map(|l| l.ip), Some(ip(31)));
        assert_eq!(m.link(SteamId(2)).map(|l| l.ip), Some(ip(30)));
        assert_eq!(m.link(SteamId(2)).map(|l| l.source), Some(Source::Direct));
        assert_eq!(m.direct_endpoint(SteamId(1)), None, "wrapped, not direct");
    }

    /// Run 1b at t ≈ 2804 s: two players started 3 s apart, too close for
    /// timing. Their credentials link both at once, with no settling delay.
    #[test]
    fn credentials_link_exactly_where_timing_cannot() {
        let mut m = Matcher::default();
        m.relay_start(SteamId(1), 2804 * S);
        m.relay_start(SteamId(2), 2807 * S);
        see(&mut m, 40, 27016, 2801, Source::Direct);
        see(&mut m, 41, 56844, 2804, Source::Direct);
        m.relay_credential(SteamId(1), cred(1));
        m.relay_credential(SteamId(2), cred(2));
        assert!(m.player_credential(ep(40, 27016), cred(1), 2801 * S));
        assert!(m.player_credential(ep(41, 56844), cred(2), 2804 * S));
        assert!(
            !m.player_credential(ep(41, 56844), cred(2), 2805 * S),
            "known"
        );
        let made = m.resolve(2808 * S);
        assert_eq!(made.len(), 2);
        let l = m.link(SteamId(2)).unwrap();
        assert_eq!((l.ip, l.source), (ip(41), Source::Credential));
        assert!(l.source.exact());
        assert_eq!(m.direct_endpoint(SteamId(2)), Some(ep(41, 56844)));
    }

    #[test]
    fn a_credential_on_two_players_endpoints_is_never_trusted() {
        let mut m = Matcher::default();
        m.relay_credential(SteamId(1), cred(1));
        m.relay_credential(SteamId(2), cred(1));
        m.relay_credential(SteamId(1), cred(1));
        m.player_credential(ep(40, 1), cred(1), 10 * S);
        assert!(m.resolve(20 * S).is_empty());
        // A player's check with no relay answer to match links nothing either.
        m.player_credential(ep(41, 1), cred(9), 10 * S);
        assert!(m.resolve(21 * S).is_empty());
    }

    #[test]
    fn exact_links_replace_timing_and_the_newest_exact_source_wins() {
        let mut m = Matcher::default();
        m.relay_start(SteamId(1), 100 * S);
        see(&mut m, 20, 1, 100, Source::Direct);
        m.resolve(125 * S);
        assert_eq!(m.link(SteamId(1)).map(|l| l.source), Some(Source::Direct));
        // Steam reports the player's address while direct.
        m.steam_reported(SteamId(1), ip(40), 200 * S);
        assert_eq!(m.resolve(200 * S).len(), 1);
        assert_eq!(m.link(SteamId(1)).map(|l| l.ip), Some(ip(40)));
        // Later relayed again, from a new address seen by credential: newer wins.
        m.relay_credential(SteamId(1), cred(1));
        m.player_credential(ep(41, 7), cred(1), 300 * S);
        assert_eq!(m.resolve(300 * S).len(), 1);
        assert_eq!(
            m.link(SteamId(1)),
            Some(Link {
                ip: ip(41),
                source: Source::Credential
            })
        );
        // And when Steam reports again later, Steam's (newer) report wins.
        m.steam_reported(SteamId(1), ip(42), 400 * S);
        m.resolve(400 * S);
        assert_eq!(m.link(SteamId(1)).map(|l| l.ip), Some(ip(42)));
        assert!(m.resolve(401 * S).is_empty(), "stable");
        // A stream from a Steam-reported address can't link to anyone else.
        m.relay_start(SteamId(2), 500 * S);
        see(&mut m, 40, 9, 500, Source::Direct);
        m.resolve(525 * S);
        assert_eq!(m.link(SteamId(2)), None);
    }

    #[test]
    fn duplicate_sightings_are_ignored_and_history_expires() {
        let mut m = Matcher::default();
        assert!(m.sighting(Sighting {
            ep: ep(20, 1),
            t_ns: 0,
            source: Source::Direct
        }));
        assert!(!m.sighting(Sighting {
            ep: ep(20, 1),
            t_ns: S,
            source: Source::Direct
        }));
        m.relay_start(SteamId(1), 0);
        // 20 minutes later the old start and sighting are gone.
        assert!(m.resolve(20 * 60 * S).is_empty());
        assert_eq!(m.link(SteamId(1)), None);
    }
}
