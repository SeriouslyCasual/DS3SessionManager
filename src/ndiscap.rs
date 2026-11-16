//! Reads relay wrapper headers from received packets with Windows' built-in
//! packet capture provider (`Microsoft-Windows-NDIS-PacketCapture`, the one
//! `netsh trace` and `pktmon` use). Windows only; needs administrator rights.
//!
//! Unlike the kernel UDP events in `etw.rs`, this provider delivers packet
//! **bytes**. They are used for one thing only: in packets from a Valve relay
//! address, the wrapper's source-address attribute (`gturn.rs`), which names
//! the relayed player. Every other byte, and every other packet, is dropped
//! in the callback. Nothing but `(time, player address)` leaves it.
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

/// One wrapped packet's player address.
#[derive(Clone, Copy, Debug)]
pub struct Seen {
    pub t_ns: i128,
    pub player: SocketAddrV4,
}

/// A running capture session. Stops when dropped.
pub struct Capture {
    _trace: UserTrace,
    pub rx: Receiver<Seen>,
    /// Packet events seen (all packets, before any filtering).
    pub events: Arc<AtomicU64>,
    /// Packets that were a relay's data indication with a player address.
    pub wrapped: Arc<AtomicU64>,
}

/// The player address in one packet event, if it is a relay's data
/// indication. Pure apart from the parser, so the rule is easy to follow.
fn wrapped(frame: &[u8]) -> Option<SocketAddrV4> {
    let u = gturn::frame_udp(frame)?;
    if !valve::is_relay_address(*u.src.ip()) {
        return None;
    }
    let player = gturn::source_address(u.payload)?;
    let ip = *player.ip();
    (!geo::is_non_public(ip.into()) && !valve::is_relay_address(ip)).then_some(player)
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
        if let Some(player) = wrapped(&frame) {
            fd.fetch_add(1, Ordering::Relaxed);
            let t_ns = (record.raw_timestamp() - FILETIME_UNIX_EPOCH) as i128 * 100;
            let _ = tx.send(Seen { t_ns, player });
        }
    };
    let provider = Provider::by_guid(PROVIDER)
        .any(KW_MEDIA)
        .all(KW_RECEIVE)
        .level(4)
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
    use crate::gturn::tests::{ether, indication};
    use std::net::Ipv4Addr;

    #[test]
    fn only_relay_indications_with_a_public_player_pass() {
        let relay = SocketAddrV4::new(Ipv4Addr::new(205, 196, 6, 1), 4380);
        let me = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 27036);
        let player = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 39246);
        let ok = ether(relay, me, &indication(player, &[0u8; 85]));
        assert_eq!(wrapped(&ok), Some(player));
        // The same bytes from a non-Valve sender are ignored.
        let other = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 99), 4380);
        assert_eq!(
            wrapped(&ether(other, me, &indication(player, &[0u8; 85]))),
            None
        );
        // A LAN or relay address in the header isn't a player.
        for bad in [
            Ipv4Addr::new(192, 168, 1, 15),
            Ipv4Addr::new(205, 196, 6, 9),
        ] {
            let f = ether(relay, me, &indication(SocketAddrV4::new(bad, 1), &[0u8; 8]));
            assert_eq!(wrapped(&f), None);
        }
    }
}
