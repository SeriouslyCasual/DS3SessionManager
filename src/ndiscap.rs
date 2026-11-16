//! Reads relay wrapper headers from received packets with Windows' built-in
//! packet capture provider (`Microsoft-Windows-NDIS-PacketCapture`, the one
//! `netsh trace` and `pktmon` use). Windows only; needs administrator rights.
//!
//! Unlike the kernel UDP events in `etw.rs`, this provider delivers packet
//! **bytes**. Only connection metadata is read from them, never game data
//! (`gturn.rs` has the formats):
//! - from a Valve relay address: the wrapper's source address (which names
//!   the relayed player), and the credential in the relay's answers to this
//!   PC's connectivity checks;
//! - from any other public address: the credential in a connectivity check
//!   (a 56-byte binding request), which ties that address to a session.
//!
//! Every other byte, and every other packet, is dropped in the callback.
//! Nothing but [`Seen`] values (time, addresses, credentials) leaves it.
//!
//! Cost control:
//! - only receive-path packet events (`ut:ReceivePath`, event 1001) are
//!   enabled, since the wrapped packets are inbound;
//! - the monitor watches [`Capture::events`] and stops the capture while the
//!   PC receives more packets than [`MAX_EVENTS_PER_S`] (a download, say),
//!   then tries again later.
//!
//! Off with `monitor --no-relay-header`.

use std::net::SocketAddrV4;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, channel};

use anyhow::{Context, Result, anyhow};
use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;

use crate::{geo, gturn, valve};

/// `Microsoft-Windows-NDIS-PacketCapture`.
const PROVIDER: &str = "2ed6006e-4729-4609-b423-3ee7bcd678ef";
/// "Packet fragment": one event per captured frame (or frame piece).
const EVENT_FRAGMENT: u16 = 1001;
/// Media keywords (any of them) and the receive path (required).
const KW_MEDIA: u64 = 0x1 | 0x200 | 0x8000 | 0x1_0000; // 802.3, WWAN, tunnel, 802.11
const KW_RECEIVE: u64 = 0x2_0000_0000;
/// Packet events per second above which the capture is paused.
pub const MAX_EVENTS_PER_S: u64 = 5_000;
/// FILETIME of the Unix epoch, in 100 ns units (as in `etw.rs`).
const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

/// What one received packet tells about a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// A relay's data indication naming the player it came from.
    Wrapped { t_ns: i128, player: SocketAddrV4 },
    /// A relay's answer to this PC's check: `cred` is this PC's credential
    /// for the session carried on `relay`.
    RelayCred {
        relay: SocketAddrV4,
        cred: gturn::Cred,
    },
    /// A check sent straight from `player`, naming this PC's credential.
    PlayerCred {
        t_ns: i128,
        player: SocketAddrV4,
        cred: gturn::Cred,
    },
}

/// A running capture session. Stops when dropped.
pub struct Capture {
    _trace: UserTrace,
    pub rx: Receiver<Seen>,
    /// Packet events seen (all packets, before any filtering).
    pub events: Arc<AtomicU64>,
    /// Packets that produced a [`Seen`].
    pub wrapped: Arc<AtomicU64>,
}

fn is_player_ip(ip: std::net::Ipv4Addr) -> bool {
    !geo::is_non_public(ip.into()) && !valve::is_relay_address(ip)
}

/// What one captured frame tells, if anything. Pure, so the rule is easy to
/// follow and test.
fn classify(frame: &[u8], t_ns: i128) -> Option<Seen> {
    let u = gturn::frame_udp(frame)?;
    if valve::is_relay_address(*u.src.ip()) {
        if let Some(player) = gturn::source_address(u.payload) {
            return is_player_ip(*player.ip()).then_some(Seen::Wrapped { t_ns, player });
        }
        // The answer echoes the check's USERNAME: relay's credential, then ours.
        let (t, _, mine) = gturn::check_username(u.payload)?;
        return (t == gturn::BINDING_SUCCESS).then_some(Seen::RelayCred {
            relay: u.src,
            cred: mine,
        });
    }
    if !is_player_ip(*u.src.ip()) {
        return None;
    }
    // A check from the player: our credential first, then the player's.
    let (t, mine, _) = gturn::check_username(u.payload)?;
    (t == gturn::BINDING_REQUEST).then_some(Seen::PlayerCred {
        t_ns,
        player: u.src,
        cred: mine,
    })
}

pub fn start() -> Result<Capture> {
    let (tx, rx) = channel();
    let events = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicU64::new(0));
    let (ev, fd) = (Arc::clone(&events), Arc::clone(&found));
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        if record.event_id() != EVENT_FRAGMENT {
            return;
        }
        ev.fetch_add(1, Ordering::Relaxed);
        let Ok(schema) = locator.event_schema(record) else {
            return;
        };
        let p = Parser::create(record, &schema);
        let Ok(frame) = p.try_parse::<Vec<u8>>("Fragment") else {
            return;
        };
        let t_ns = (record.raw_timestamp() - FILETIME_UNIX_EPOCH) as i128 * 100;
        if let Some(seen) = classify(&frame, t_ns) {
            fd.fetch_add(1, Ordering::Relaxed);
            let _ = tx.send(seen);
        }
    };
    let provider = Provider::by_guid(PROVIDER)
        .any(KW_MEDIA)
        .all(KW_RECEIVE)
        .level(5)
        .add_filter(EventFilter::ByEventIds(vec![EVENT_FRAGMENT]))
        .add_callback(callback)
        .build();
    let trace = UserTrace::new()
        .named(format!("ds3sm-relayhdr-{}", std::process::id()))
        .enable(provider)
        .start_and_process()
        .map_err(|e| anyhow!("{e:?}"))
        .context("starting the NDIS packet capture trace (run as administrator)")?;
    Ok(Capture {
        _trace: trace,
        rx,
        events,
        wrapped: found,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gturn::tests::{check, ether, indication};
    use crate::gturn::{BINDING_REQUEST, BINDING_SUCCESS};
    use std::net::Ipv4Addr;

    fn relay() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(205, 196, 6, 1), 4380)
    }
    fn me() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 27036)
    }
    fn player() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 39246)
    }

    #[test]
    fn relay_indications_with_a_public_player_pass() {
        let ok = ether(relay(), me(), &indication(player(), &[0u8; 85]));
        assert_eq!(
            classify(&ok, 5),
            Some(Seen::Wrapped {
                t_ns: 5,
                player: player()
            })
        );
        // The same bytes from a non-Valve sender are not an indication.
        let other = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 99), 4380);
        assert_eq!(
            classify(&ether(other, me(), &indication(player(), &[0u8; 85])), 5),
            None
        );
        // A LAN or relay address in the header isn't a player.
        for bad in [
            Ipv4Addr::new(192, 168, 1, 15),
            Ipv4Addr::new(205, 196, 6, 9),
        ] {
            let f = ether(
                relay(),
                me(),
                &indication(SocketAddrV4::new(bad, 1), &[0u8; 8]),
            );
            assert_eq!(classify(&f, 5), None);
        }
    }

    #[test]
    fn credentials_come_from_relay_answers_and_player_checks_only() {
        let (mine, theirs, relays) = (
            *b"TdfXKimqlCIyGP8i",
            *b"1wACynUc9GzvttMh",
            *b"Es5/a79d6wWfAYY2",
        );
        let far = SocketAddrV4::new(Ipv4Addr::new(155, 133, 249, 180), 4379);
        // Relay answer: relay's credential, then ours.
        let ans = ether(far, me(), &check(BINDING_SUCCESS, &relays, &mine, true));
        assert_eq!(
            classify(&ans, 1),
            Some(Seen::RelayCred {
                relay: far,
                cred: mine
            })
        );
        // The player's own check: our credential, then the player's.
        let req = ether(
            player(),
            me(),
            &check(BINDING_REQUEST, &mine, &theirs, false),
        );
        assert_eq!(
            classify(&req, 2),
            Some(Seen::PlayerCred {
                t_ns: 2,
                player: player(),
                cred: mine
            })
        );
        // A relay's request, a player's answer, or a LAN check: nothing.
        let r = ether(far, me(), &check(BINDING_REQUEST, &mine, &relays, false));
        assert_eq!(classify(&r, 3), None);
        let a = ether(
            player(),
            me(),
            &check(BINDING_SUCCESS, &theirs, &mine, true),
        );
        assert_eq!(classify(&a, 3), None);
        let lan = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 15), 50000);
        let l = ether(lan, me(), &check(BINDING_REQUEST, &mine, &theirs, false));
        assert_eq!(classify(&l, 3), None);
    }
}
