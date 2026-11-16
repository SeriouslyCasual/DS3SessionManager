//! Which public address belongs to which relayed player.
//!
//! In E2 mode Steam reports a Valve relay as the remote, but the player's own
//! address still reaches this PC in one of two ways (online capture,
//! 2026-11-15):
//! - **direct stream** (most relayed sessions): Steam's IP sharing is
//!   one-sided. The player already knows this PC's address and sends its game
//!   stream straight here, while this PC must send through the relay. So an
//!   inbound-only, game-rate stream from a non-Valve address arrives at
//!   steam.exe. ETW sees it (addresses and timing only, no payload).
//! - **relay header**: the rest arrive wrapped by a nearby relay, whose header
//!   names the player's address (`gturn.rs`, read by `ndiscap.rs`).
//!
//! Neither carries a Steam ID, so addresses are linked to players by
//! **timing**: a stream (or a wrapped address) appears within a few seconds
//! of a relayed player's relay episode starting, and Steam moves a player to
//! a new relay port at the same moment the player's own port changes. The
//! rule is conservative. A sighting is linked only when exactly one unlinked
//! player started an episode within [`WINDOW_NS`] of it **and** that start
//! matches exactly one unlinked address. Repeating this to a fixpoint lets
//! one link settle another (elimination). An address Steam itself reported
//! for a player (while direct, or in E1 mode) links at once and overrides a
//! timing link.
//!
//! The public build uses a link only for the player's region and distance;
//! the address itself is shown only in the developer build.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};

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
/// How long starts and sightings are kept for matching.
const HISTORY_NS: i128 = 15 * 60 * 1_000_000_000;

/// Where an address was seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// Steam's own reported remote (direct path or E1-mode relay).
    Steam,
    /// An inbound-only game stream from the player's address.
    Direct,
    /// The `0x0012` attribute of a relay's data indication.
    Wrapper,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Steam => "steam",
            Source::Direct => "direct_stream",
            Source::Wrapper => "relay_header",
        }
    }
}

/// One new address seen at time `t_ns` (the stream's first packet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sighting {
    pub ep: SocketAddrV4,
    pub t_ns: i128,
    pub source: Source,
}

/// A player's address, and how it was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub ip: Ipv4Addr,
    pub source: Source,
    /// `true` when linked by timing, `false` when Steam reported it.
    pub by_timing: bool,
}

#[derive(Default)]
pub struct Matcher {
    starts: Vec<(SteamId, i128)>,
    sightings: Vec<Sighting>,
    seen: HashSet<(SocketAddrV4, Source)>,
    /// Every address Steam reported, and each player's newest one.
    steam_ips: HashMap<Ipv4Addr, SteamId>,
    steam_latest: HashMap<SteamId, Ipv4Addr>,
    links: HashMap<SteamId, Link>,
}

impl Matcher {
    /// A relayed player's relay episode started (it became relayed, or Steam
    /// moved it to another relay endpoint).
    pub fn relay_start(&mut self, id: SteamId, t_ns: i128) {
        self.starts.push((id, t_ns));
    }

    /// Steam reported `ip` (a public, non-relay address) for `id`.
    pub fn steam_reported(&mut self, id: SteamId, ip: Ipv4Addr) {
        self.steam_ips.insert(ip, id);
        self.steam_latest.insert(id, ip);
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

    /// The newest direct-stream endpoint of a linked player (for its rates and
    /// jitter), if its address arrives that way.
    pub fn direct_endpoint(&self, id: SteamId) -> Option<SocketAddrV4> {
        let ip = self.links.get(&id)?.ip;
        self.sightings
            .iter()
            .filter(|s| s.source == Source::Direct && *s.ep.ip() == ip)
            .max_by_key(|s| s.t_ns)
            .map(|s| s.ep)
    }

    /// Link what can be linked; returns the links made or changed.
    pub fn resolve(&mut self, now_ns: i128) -> Vec<(SteamId, Link)> {
        self.starts.retain(|s| now_ns - s.1 <= HISTORY_NS);
        self.sightings.retain(|s| now_ns - s.t_ns <= HISTORY_NS);
        let mut made = Vec::new();
        // Steam's own word first.
        for (id, ip) in &self.steam_latest {
            let l = Link {
                ip: *ip,
                source: Source::Steam,
                by_timing: false,
            };
            let keep = self.links.get(id).is_some_and(|o| !o.by_timing);
            if !keep && self.links.get(id) != Some(&l) {
                self.links.insert(*id, l);
                made.push((*id, l));
            }
        }
        // Then timing, until nothing changes.
        loop {
            let mut linked_ips: HashSet<Ipv4Addr> = self.links.values().map(|l| l.ip).collect();
            linked_ips.extend(self.steam_ips.keys());
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
                        by_timing: true,
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
    fn see(m: &mut Matcher, last: u8, port: u16, t: i128, source: Source) {
        m.sighting(Sighting {
            ep: ep(last, port),
            t_ns: t * S,
            source,
        });
    }

    #[test]
    fn one_relayed_player_and_one_stream_link() {
        let mut m = Matcher::default();
        m.relay_start(SteamId(1), 100 * S);
        see(&mut m, 20, 16597, 99, Source::Direct);
        // Not judged before it has settled (a competitor could still appear).
        assert!(m.resolve(110 * S).is_empty());
        let made = m.resolve(130 * S);
        assert_eq!(made.len(), 1);
        let l = m.link(SteamId(1)).unwrap();
        assert_eq!(
            (l.ip, l.source, l.by_timing),
            (*ep(20, 0).ip(), Source::Direct, true)
        );
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
        assert_eq!(m.link(SteamId(1)).map(|l| l.ip), Some(*ep(31, 0).ip()));
        assert_eq!(m.link(SteamId(2)).map(|l| l.ip), Some(*ep(30, 0).ip()));
        assert_eq!(m.link(SteamId(2)).map(|l| l.source), Some(Source::Direct));
        assert_eq!(m.direct_endpoint(SteamId(1)), None, "wrapped, not direct");
    }

    #[test]
    fn steam_reported_address_links_at_once_and_wins() {
        let mut m = Matcher::default();
        m.relay_start(SteamId(1), 100 * S);
        see(&mut m, 20, 1, 100, Source::Direct);
        m.resolve(125 * S);
        assert!(m.link(SteamId(1)).unwrap().by_timing);
        // Later the player goes direct and Steam reports another address.
        m.steam_reported(SteamId(1), *ep(40, 0).ip());
        let made = m.resolve(200 * S);
        assert_eq!(made.len(), 1);
        let l = m.link(SteamId(1)).unwrap();
        assert_eq!(
            (l.ip, l.source, l.by_timing),
            (*ep(40, 0).ip(), Source::Steam, false)
        );
        // A stream from a Steam-reported address can't link to anyone else.
        m.relay_start(SteamId(2), 300 * S);
        see(&mut m, 40, 9, 300, Source::Direct);
        m.resolve(325 * S);
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
