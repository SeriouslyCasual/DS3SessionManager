//! Reads connection metadata from packets with **Windows Packet Monitor**
//! (`pktmon`, built into Windows), through its ETW provider
//! `Microsoft-Windows-PktMon`. Windows only; needs administrator rights.
//!
//! Why Packet Monitor: the older NDIS capture provider
//! (`Microsoft-Windows-NDIS-PacketCapture`) delivered no packets at all on the
//! test PC, not even to Windows' own `netsh trace` or NetEventPacketCapture
//! sessions, while Packet Monitor captured every UDP packet with none lost
//! and its events reached ds3sm's own session (self-test, 2026-11-15).
//!
//! Unlike the kernel UDP events in `etw.rs`, this provider delivers packet
//! **bytes**. Only connection metadata is read from them, never game data
//! (`gturn.rs` has the formats):
//! - from a Valve relay address: the wrapper's source address (which names
//!   the relayed player), and the credential in the relay's answers to this
//!   PC's connectivity checks;
//! - from any other public address: the credential in a connectivity check
//!   (a 56-byte binding request), which ties that address to a session;
//! - **exact ping**: this PC's own checks (send path) and their answers,
//!   paired by the check's 16-byte transaction ID (see [`Pairer`]).
//!
//! Every other byte, and every other packet, is dropped in the callback.
//! Nothing but [`Seen`] values (time, addresses, credentials, RTT) leaves it.
//!
//! Cost control:
//! - Packet Monitor captures UDP only, 128 bytes per packet, at the network
//!   adapters only ([`Pktmon`]); only its packet event (160) is enabled, and
//!   frames are dropped unless they carry one of the formats above;
//! - the monitor watches [`Capture::events`] and stops the capture while the
//!   PC moves more packets than [`MAX_EVENTS_PER_S`] (a download, say),
//!   then tries again later.
//!
//! Off with `monitor --no-relay-header`.

use std::collections::HashMap;
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

/// `Microsoft-Windows-PktMon` (Windows Packet Monitor).
const PKTMON_PROVIDER: &str = "4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac";
/// Packet Monitor's packet event, with the (trimmed) frame in `Payload`.
const EVENT_PACKET: u16 = 160;
/// Its keyword for packet payload events.
const KW_PAYLOAD: u64 = 0x10;
/// How long a sent check waits for its answer. Beyond the ~487 ms check
/// interval that limits size-and-timing pairing: Run 1b had answers up to
/// 2.3 s.
const MAX_WAIT_NS: i128 = 5_000_000_000;
/// Bound on checks waiting for an answer (old ones are dropped first).
const MAX_PENDING: usize = 4096;
/// UDP packet events per second above which the capture is paused. Run 1d
/// (2026-11-16) averaged ~830/s with brief bursts to 9,000–15,000/s from
/// other programs' UDP (Steam's own peaked under 100/s), which a 5,000 limit
/// paused for minutes at a time. The callback's per-packet work is small; the
/// limit only stops runaway cost (a large UDP download, say).
pub const MAX_EVENTS_PER_S: u64 = 30_000;
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
    /// An exact round trip: this PC's check to `remote` (in the session using
    /// this PC's credential `cred`) and its answer, matched by transaction ID.
    Rtt {
        t_ns: i128,
        remote: SocketAddrV4,
        cred: gturn::Cred,
        rtt_ns: i128,
    },
}

/// Pairs this PC's checks with their answers by transaction ID.
///
/// Size-and-timing pairing (`stun.rs`) can't tell which request an answer
/// belongs to, so a round trip longer than Steam's ~487 ms check interval
/// reads as a short one (Run 1b: a VPN player at 506–511 ms read as a 28 ms
/// median), and two sessions on one relay endpoint get mixed. The ID makes
/// the pairing exact; the request's USERNAME names the session.
#[derive(Default)]
pub struct Pairer {
    pending: HashMap<[u8; 16], (i128, SocketAddrV4, gturn::Cred)>,
}

impl Pairer {
    /// A frame on the send path: remember this PC's checks.
    pub fn sent(&mut self, frame: &[u8], t_ns: i128) {
        let Some(u) = gturn::frame_udp(frame) else {
            return;
        };
        // A request names the receiver's credential, then ours.
        let Some((gturn::BINDING_REQUEST, _, mine)) = gturn::check_username(u.payload) else {
            return;
        };
        if self.pending.len() >= MAX_PENDING {
            self.pending.retain(|_, (t, _, _)| t_ns - *t <= MAX_WAIT_NS);
            if self.pending.len() >= MAX_PENDING {
                self.pending.clear();
            }
        }
        // The first sighting wins (a frame can be captured at two layers).
        self.pending
            .entry(txid(u.payload))
            .or_insert((t_ns, u.dst, mine));
    }

    /// A received datagram: an exact RTT if it answers a remembered check
    /// from the same endpoint in time.
    pub fn answered(&mut self, u: &gturn::Udp<'_>, t_ns: i128) -> Option<Seen> {
        let (gturn::BINDING_SUCCESS, _, _) = gturn::check_username(u.payload)? else {
            return None;
        };
        let (t0, dst, cred) = self.pending.remove(&txid(u.payload))?;
        let rtt_ns = t_ns - t0;
        (dst == u.src && (0..=MAX_WAIT_NS).contains(&rtt_ns)).then_some(Seen::Rtt {
            t_ns,
            remote: u.src,
            cred,
            rtt_ns,
        })
    }
}

/// The 16 bytes after the type and length: the classic STUN transaction ID
/// (which also covers an RFC 5389 cookie and 96-bit ID).
fn txid(p: &[u8]) -> [u8; 16] {
    let mut id = [0u8; 16];
    if let Some(b) = p.get(4..20) {
        id.copy_from_slice(b);
    }
    id
}

/// A running capture session. Stops when dropped.
pub struct Capture {
    _trace: UserTrace,
    /// Packet Monitor, if ds3sm started it; stopped after the trace.
    _pktmon: Option<Pktmon>,
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

/// Windows Packet Monitor, started and stopped by ds3sm when it isn't
/// already running (`pktmon.exe`, built into Windows 10 2004 and later).
///
/// Started with a UDP-only filter, packets trimmed to [`PKT_SIZE`] bytes, at
/// the network adapters only (one copy per packet instead of one per stack
/// layer), and an in-memory log, so it writes nothing while running. If
/// Packet Monitor was already running (someone else's capture), ds3sm only
/// listens and leaves it alone. Stopped when this value is dropped.
pub struct Pktmon {
    /// Whether ds3sm started it (and so must stop it).
    owned: bool,
    /// Whether ds3sm added the UDP filter (and so must remove filters).
    filtered: bool,
    log: std::path::PathBuf,
}

/// Bytes kept per packet: enough for IP/UDP headers, the relay header and a
/// 68-byte check answer, never much of the game's own data.
const PKT_SIZE: u32 = 128;

fn pktmon(args: &[&str]) -> Result<String> {
    let out = std::process::Command::new("pktmon")
        .args(args)
        .output()
        .context("running pktmon (Windows Packet Monitor)")?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let why = [err.as_ref(), text.as_str()]
            .iter()
            .flat_map(|t| t.lines())
            .rfind(|l| !l.trim().is_empty())
            .unwrap_or("failed")
            .trim()
            .to_owned();
        return Err(anyhow!("pktmon {}: {why}", args.join(" ")));
    }
    Ok(text)
}

impl Pktmon {
    pub fn start() -> Result<Self> {
        // Fails without administrator rights ("Access is denied"). A "not
        // running" answer may come with a failure code; that's no error.
        let status = match pktmon(&["status"]) {
            Err(e) if e.to_string().contains("not running") => String::new(),
            r => r?,
        };
        let log = std::env::temp_dir().join(format!("ds3sm-pktmon-{}.etl", std::process::id()));
        if status.contains("is running") || status.contains("Logger name") {
            return Ok(Self {
                owned: false,
                filtered: false,
                log,
            });
        }
        let filters = match pktmon(&["filter", "list"]) {
            Err(e) if e.to_string().contains("No filters") => String::new(),
            r => r?,
        };
        let filtered = filters.contains("No filters") || filters.trim().is_empty();
        if filtered {
            pktmon(&["filter", "add", "ds3sm", "-t", "UDP"])?;
        }
        let size = PKT_SIZE.to_string();
        let file = log.to_string_lossy().into_owned();
        let started = pktmon(&[
            "start",
            "--capture",
            "--comp",
            "nics",
            "--pkt-size",
            &size,
            "--log-mode",
            "memory",
            "--file-size",
            "16",
            "--file-name",
            &file,
        ]);
        if let Err(e) = started {
            if filtered {
                let _ = pktmon(&["filter", "remove"]);
            }
            return Err(e);
        }
        Ok(Self {
            owned: true,
            filtered,
            log,
        })
    }

    /// Whether ds3sm started Packet Monitor itself.
    pub fn owned(&self) -> bool {
        self.owned
    }
}

impl Drop for Pktmon {
    fn drop(&mut self) {
        if self.owned {
            let _ = pktmon(&["stop"]);
            let _ = std::fs::remove_file(&self.log);
        }
        if self.filtered {
            let _ = pktmon(&["filter", "remove"]);
        }
    }
}

/// Start Packet Monitor (unless it is running already) and read its packets.
pub fn start() -> Result<Capture> {
    let pm = Pktmon::start()?;
    let mut c = listen()?;
    c._pktmon = Some(pm);
    Ok(c)
}

/// Read Packet Monitor's packet events in this program's own ETW session.
/// Packet Monitor must be capturing (see [`Pktmon`]); its provider writes
/// each captured packet to every session that enables it.
pub fn listen() -> Result<Capture> {
    let (tx, rx) = channel();
    let events = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicU64::new(0));
    let (ev, fd) = (Arc::clone(&events), Arc::clone(&found));
    let mut pairer = Pairer::default();
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        if record.event_id() != EVENT_PACKET {
            return;
        }
        ev.fetch_add(1, Ordering::Relaxed);
        let Ok(schema) = locator.event_schema(record) else {
            return;
        };
        let p = Parser::create(record, &schema);
        let Ok(frame) = p.try_parse::<Vec<u8>>("Payload") else {
            return;
        };
        let t_ns = (record.raw_timestamp() - FILETIME_UNIX_EPOCH) as i128 * 100;
        let Some(u) = gturn::frame_udp(&frame) else {
            return;
        };
        // Direction from the addresses: this PC sits behind a home router,
        // so its own side is a private address. (A PC with a public address
        // of its own isn't supported by the exact features yet.)
        if geo::is_non_public((*u.src.ip()).into()) {
            pairer.sent(&frame, t_ns);
            return;
        }
        let rtt = pairer.answered(&u, t_ns);
        for seen in [classify(&frame, t_ns), rtt].into_iter().flatten() {
            fd.fetch_add(1, Ordering::Relaxed);
            let _ = tx.send(seen);
        }
    };
    let provider = Provider::by_guid(PKTMON_PROVIDER)
        .any(KW_PAYLOAD)
        .level(4)
        .add_filter(EventFilter::ByEventIds(vec![EVENT_PACKET]))
        .add_callback(callback)
        .build();
    let trace = UserTrace::new()
        .named(format!("ds3sm-pktmon-{}", std::process::id()))
        .enable(provider)
        .start_and_process()
        .map_err(|e| anyhow!("{e:?}"))
        .context("reading Packet Monitor's events (run as administrator)")?;
    Ok(Capture {
        _trace: trace,
        _pktmon: None,
        rx,
        events,
        wrapped: found,
    })
}

/// `ds3sm relay-header-test`: start the capture as the monitor does for a
/// few seconds while sending small UDP packets to a TEST-NET address
/// (RFC 5737, routed nowhere), and report what arrived. A control provider
/// shows whether this program's event session works at all.
pub fn self_test() -> Result<()> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let target = SocketAddrV4::new(std::net::Ipv4Addr::new(192, 0, 2, 1), 50002);
    let pump = |secs: u64| {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        while std::time::Instant::now() < end {
            let _ = sock.send_to(&[0u8; 37], target);
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    };
    println!("relay header self-test: {TEST_SECS} s each");
    println!("{:<44} {:>14} {:>10}", "source", "packet events", "useful");
    match start() {
        Ok(c) => {
            let owned = c._pktmon.as_ref().is_some_and(Pktmon::owned);
            pump(TEST_SECS);
            let mut useful = 0;
            while c.rx.try_recv().is_ok() {
                useful += 1;
            }
            println!(
                "{:<44} {:>14} {:>10}",
                if owned {
                    "Packet Monitor (started by ds3sm)"
                } else {
                    "Packet Monitor (already running)"
                },
                c.events.load(Ordering::Relaxed),
                useful
            );
        }
        Err(e) => println!("{:<44} failed: {e:#}", "Packet Monitor"),
    }
    // Control: a built-in provider that always logs network events.
    let control = (|| -> Result<u64> {
        let n = Arc::new(AtomicU64::new(0));
        let n2 = Arc::clone(&n);
        let provider = Provider::by_guid(TCPIP_PROVIDER)
            .any(u64::MAX)
            .level(5)
            .add_callback(move |_: &EventRecord, _: &SchemaLocator| {
                n2.fetch_add(1, Ordering::Relaxed);
            })
            .build();
        let _trace = UserTrace::new()
            .named(format!("ds3sm-control-{}", std::process::id()))
            .enable(provider)
            .start_and_process()
            .map_err(|e| anyhow!("{e:?}"))?;
        pump(TEST_SECS);
        Ok(n.load(Ordering::Relaxed))
    })();
    match control {
        Ok(n) => println!("{:<44} {:>14}", "control: Microsoft-Windows-TCPIP", n),
        Err(e) => println!("{:<44} failed: {e:#}", "control: Microsoft-Windows-TCPIP"),
    }
    println!(
        "\n'packet events' should be well above 0 (this test alone sends {} UDP packets).",
        TEST_SECS * 10
    );
    println!("'useful' counts Steam checks and relay headers, so it is 0 unless Steam is talking.");
    Ok(())
}

const TEST_SECS: u64 = 6;
/// `Microsoft-Windows-TCPIP`, the self-test's control provider.
const TCPIP_PROVIDER: &str = "2f07e2ee-15db-40f1-90ef-9d7ba282188a";

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

    /// Run 1b's VPN player: answers came 506–511 ms after each check, longer
    /// than the 487 ms check interval. Pairing by ID gets them right.
    #[test]
    fn checks_pair_with_answers_by_transaction_id_even_past_the_interval() {
        let (mine, relays) = (*b"PaQ7h7ockbCgChiS", *b"D0FXFIfnCe4dw9rS");
        let far = SocketAddrV4::new(Ipv4Addr::new(45, 121, 184, 21), 4379);
        let ms = 1_000_000i128;
        let mut p = Pairer::default();
        // Two checks 487 ms apart, each with its own ID.
        let req = |id: u8, t: i128, p: &mut Pairer| {
            let mut c = check(BINDING_REQUEST, &relays, &mine, false);
            c[4..20].copy_from_slice(&[id; 16]);
            p.sent(&ether(me(), far, &c), t);
        };
        req(1, 0, &mut p);
        req(2, 487 * ms, &mut p);
        req(2, 487 * ms + 50, &mut p); // the same frame again, another layer
        let mut ans = check(BINDING_SUCCESS, &relays, &mine, true);
        ans[4..20].copy_from_slice(&[1; 16]);
        let f = ether(far, me(), &ans);
        let u = gturn::frame_udp(&f).unwrap();
        // Arrives after the second check was sent, yet pairs with the first.
        assert_eq!(
            p.answered(&u, 510 * ms),
            Some(Seen::Rtt {
                t_ns: 510 * ms,
                remote: far,
                cred: mine,
                rtt_ns: 510 * ms
            })
        );
        // Answered once only; an unknown ID or a different sender pairs nothing.
        assert_eq!(p.answered(&u, 520 * ms), None);
        ans[4..20].copy_from_slice(&[2; 16]);
        let other = SocketAddrV4::new(Ipv4Addr::new(45, 121, 184, 22), 4379);
        let f2 = ether(other, me(), &ans);
        assert_eq!(p.answered(&gturn::frame_udp(&f2).unwrap(), 600 * ms), None);
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
