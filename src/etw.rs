//! Kernel packet timing with ETW (Event Tracing for Windows). Windows only;
//! needs administrator rights.
//!
//! # What ETW is
//!
//! ETW is Windows' built-in, high-speed logging system. *Providers* emit
//! events, *sessions* collect them, and *consumers* read them. The kernel's
//! TCP/IP provider (`EVENT_TRACE_FLAG_NETWORK_TCPIP`) emits a `UdpIp` event for
//! **every UDP packet** the PC sends or receives. Each event carries the
//! process ID, payload size, both IP addresses and ports, and a precise
//! timestamp, but **not** the packet contents. That's exactly what's needed
//! to time Steam's connectivity checks (see `stun.rs`).
//!
//! On Windows 8 and later, the `ferrisetw` crate starts the session in "system
//! logger" mode with its own name, so it doesn't take over Windows' single
//! classic "NT Kernel Logger" session that other tools may be using.
//!
//! # Timestamps
//!
//! ferrisetw sets the session clock to the high-resolution QPC timer, and ETW
//! delivers FILETIME values (100-ns ticks since 1601-01-01), which are converted
//! to Unix nanoseconds.
//!
//! # Byte-order self-calibration
//!
//! Network protocols store numbers big-endian, while x86 CPUs are
//! little-endian. Rather than *assume* how ETW reports addresses and ports,
//! [`calibrate`] sends one packet with known values to a TEST-NET address
//! (RFC 5737, guaranteed to go nowhere) and checks how ETW reports it.
//!
//! # Rust concepts: threads, closures, channels, atomics
//!
//! ferrisetw calls the program's closure **on its own background thread**, once per
//! event. Events travel to the main thread through a *channel* (a thread-safe
//! queue). The game's PID travels the other way through an *atomic* integer
//! shared with `Arc`. See `start()` for the details.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::provider::kernel_providers::KernelProvider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::KernelTrace;
use ferrisetw::{EventRecord, GUID};

use crate::stun::{Datagram, Direction};

/// `UdpIp` opcodes for IPv4 (kernel MOF class `UdpIp_TypeGroup1`).
// Opcode numbers identify the event type within the provider. These come from
// the kernel's published event schema (MOF class `UdpIp_TypeGroup1`).
const OP_SEND_V4: u8 = 10;
const OP_RECV_V4: u8 = 11;

/// Special `game_pid` value: forward UDP events from **every** process.
/// Used only by `probe`'s short per-process breakdown, to find out which
/// process actually carries a peer's traffic.
pub const ALL_PIDS: u32 = u32::MAX - 1;

/// The kernel's UDP event class (`UdpIp`), enabled by the TCP/IP flag.
///
/// One kernel flag (`EVENT_TRACE_FLAG_NETWORK_TCPIP`, 0x10000) turns on two
/// event classes with *different* provider GUIDs: `TcpIp` (9a280ac0-…) and
/// `UdpIp` (bf3a50c5-…). Both use opcodes 10/11 for send/receive, with the
/// same field names. ferrisetw only hands an event to a callback whose
/// provider GUID matches the event's, so the callback must be registered
/// under the **UdpIp** GUID. Registering it under ferrisetw's ready-made
/// `TCP_IP_PROVIDER` instead delivers TCP packets only, and no UDP at all.
static UDP_IP_PROVIDER: KernelProvider = KernelProvider::new(
    GUID::from_values(
        0xbf3a50c5,
        0xa9c9,
        0x4988,
        [0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80],
    ),
    0x0001_0000, // EVENT_TRACE_FLAG_NETWORK_TCPIP
);

/// The kernel's TCP event class (`TcpIp`), enabled by the **same** flag as
/// `UdpIp`, so the kernel already produces these events for the UDP trace;
/// they are only *read* when a callback is registered under this GUID, which
/// [`start_with`] does only when asked (`monitor --tcp`). Used to follow
/// Steam's TCP fallback (E3 C2): with every UDP path impaired, Steam carries
/// the same P2P datagrams over a direct TCP connection to the peer, each with
/// a 2-byte length prefix (see `tcp.rs`).
static TCP_IP_PROVIDER: KernelProvider = KernelProvider::new(
    GUID::from_values(
        0x9a280ac0,
        0xc8e0,
        0x11d1,
        [0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2],
    ),
    0x0001_0000, // EVENT_TRACE_FLAG_NETWORK_TCPIP
);

/// `TcpIp` opcodes for IPv4: send (`TcpIp_SendIPV4`), receive and
/// retransmit (`TcpIp_TypeGroup1`). All carry PID, size, daddr, saddr,
/// dport and sport, like the UDP events.
const OP_TCP_SEND_V4: u8 = 10;
const OP_TCP_RECV_V4: u8 = 11;
const OP_TCP_RETRANSMIT_V4: u8 = 14;

/// What a TCP event reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpKind {
    Send,
    Recv,
    /// A segment this PC sent again (a loss signal, outbound only).
    Retransmit,
}

/// One raw TCP event, before byte-order decoding. Same fields as [`RawUdp`].
#[derive(Clone, Copy, Debug)]
pub struct RawTcp {
    pub t_ns: i128,
    pub pid: u32,
    pub kind: TcpKind,
    pub daddr: u32,
    pub saddr: u32,
    pub dport: u16,
    pub sport: u16,
    pub size: u32,
}

/// A decoded TCP event: the remote side, as for UDP.
#[derive(Clone, Copy, Debug)]
pub struct TcpSegment {
    pub t_ns: i128,
    pub pid: u32,
    pub kind: TcpKind,
    pub remote: SocketAddrV4,
    pub size: u32,
}

/// FILETIME of the Unix epoch, in 100 ns units.
// FILETIME counts 100-ns ticks from 1601-01-01. This constant is how many
// ticks separate 1601-01-01 from 1970-01-01 (the Unix epoch), so
// (filetime - FILETIME_UNIX_EPOCH) * 100 = Unix nanoseconds.
const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

/// One raw UDP event, before byte-order decoding.
#[derive(Clone, Copy, Debug)]
// Kept "raw" (undecoded) so the background thread does as little work as
// possible. Decoding happens on the main thread once the byte order is known.
pub struct RawUdp {
    pub t_ns: i128,
    pub pid: u32,
    pub dir: Direction,
    pub daddr: u32,
    pub saddr: u32,
    pub dport: u16,
    pub sport: u16,
    pub size: u32,
}

/// How to turn raw fields into addresses, decided by [`calibrate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Decided once by `calibrate()`, then used to decode every event.
pub struct ByteOrder {
    pub swap_addr: bool,
    pub swap_port: bool,
}

impl ByteOrder {
    // `swap_bytes()` reverses the byte order of an integer (0x11223344 becomes
    // 0x44332211). `Ipv4Addr::from(u32)` reads the integer big-endian
    // (0xC0000201 → 192.0.2.1).
    fn addr(self, raw: u32) -> Ipv4Addr {
        Ipv4Addr::from(if self.swap_addr {
            raw.swap_bytes()
        } else {
            raw
        })
    }
    fn port(self, raw: u16) -> u16 {
        if self.swap_port {
            raw.swap_bytes()
        } else {
            raw
        }
    }

    /// Decode into a [`Datagram`] keyed by the remote endpoint.
    // For packets *sent*, the remote end is the destination; for packets
    // *receive*, it's the source. Keying by the remote end puts both directions
    // of a conversation under one key.
    pub fn decode(self, r: &RawUdp) -> Datagram {
        let remote = match r.dir {
            Direction::Send => SocketAddrV4::new(self.addr(r.daddr), self.port(r.dport)),
            Direction::Recv => SocketAddrV4::new(self.addr(r.saddr), self.port(r.sport)),
        };
        Datagram {
            t_ns: r.t_ns,
            dir: r.dir,
            remote,
            size: r.size,
        }
    }

    /// Decode a TCP event with the byte order learned from the UDP probe
    /// (same kernel provider, same field encoding).
    pub fn decode_tcp(self, r: &RawTcp) -> TcpSegment {
        let remote = match r.kind {
            TcpKind::Send | TcpKind::Retransmit => {
                SocketAddrV4::new(self.addr(r.daddr), self.port(r.dport))
            }
            TcpKind::Recv => SocketAddrV4::new(self.addr(r.saddr), self.port(r.sport)),
        };
        TcpSegment {
            t_ns: r.t_ns,
            pid: r.pid,
            kind: r.kind,
            remote,
            size: r.size,
        }
    }
}

/// A running kernel trace. Stops when dropped.
/// A running kernel trace. Dropping it stops the trace (ferrisetw's
/// `KernelTrace` implements `Drop`).
///
/// The field `_trace` starts with `_` because it's never read. It's only kept
/// it alive: if it were dropped, the trace would stop.
pub struct UdpTrace {
    _trace: KernelTrace,
    /// PIDs whose events are forwarded (the game, plus this process for calibration).
    pub game_pid: Arc<AtomicU32>,
    /// The Steam client's PID. DS3's peer-to-peer traffic (including the
    /// STUN checks) is sent and received by steam.exe, not by the game.
    pub steam_pid: Arc<AtomicU32>,
    pub rx: Receiver<RawUdp>,
    /// Counters for every place an event can be dropped (see [`Diag`]).
    pub diag: Arc<Diag>,
    /// TCP events from steam.exe, only when started with TCP enabled.
    pub tcp_rx: Option<Receiver<RawTcp>>,
    /// The TCP callback's own counters (its `udp_v4` field counts IPv4 TCP
    /// send/receive/retransmit events).
    pub tcp_diag: Option<Arc<Diag>>,
}

/// Diagnostic counters, filled on ferrisetw's thread.
///
/// The callback drops events silently at several points (wrong opcode,
/// missing schema, missing field, wrong PID). When calibration fails, these
/// counters show *where* events are lost: no events at all means the session
/// isn't delivering; events with schema errors mean TDH can't describe them;
/// and so on.
#[derive(Default)]
pub struct Diag {
    /// Every event the callback saw, of any opcode.
    pub total: AtomicU64,
    /// Events with the IPv4 UDP send/receive opcodes.
    pub udp_v4: AtomicU64,
    /// IPv4 UDP events whose schema couldn't be looked up.
    pub schema_err: AtomicU64,
    /// IPv4 UDP events missing a field (or with an unexpected field size).
    pub field_err: AtomicU64,
    /// IPv4 UDP events from this process (the calibration packets).
    pub self_pid: AtomicU64,
    /// One bit per opcode seen, to spot e.g. IPv6-only traffic (opcodes 26/27).
    pub opcodes: [AtomicU64; 4],
    /// The first schema or field error, verbatim.
    pub first_err: Mutex<Option<String>>,
}

impl Diag {
    fn note_err(&self, msg: String) {
        if let Ok(mut g) = self.first_err.lock() {
            g.get_or_insert(msg);
        }
    }

    /// One-line summary for error messages.
    pub fn summary(&self) -> String {
        let ops: Vec<String> = (0..256u32)
            .filter(|&op| {
                self.opcodes[(op / 64) as usize].load(Ordering::Relaxed) & (1u64 << (op % 64)) != 0
            })
            .map(|op| op.to_string())
            .collect();
        let first = self
            .first_err
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_else(|| "none".into());
        format!(
            "events seen={} udp_v4={} schema_err={} field_err={} own_pid={} opcodes=[{}] first_err={}",
            self.total.load(Ordering::Relaxed),
            self.udp_v4.load(Ordering::Relaxed),
            self.schema_err.load(Ordering::Relaxed),
            self.field_err.load(Ordering::Relaxed),
            self.self_pid.load(Ordering::Relaxed),
            ops.join(","),
            first
        )
    }
}

/// Turn one ETW event into a `RawUdp`, or `None` if it's not a UDP IPv4 event
/// from a process of interest.
///
/// Runs on ferrisetw's thread for *every* UDP packet on the PC, so it filters
/// early: wrong opcode → stop; wrong PID → stop.
///
/// Steps:
///   1. Check the opcode (send or receive).
///   2. Look up the event's schema (its field layout) and create a parser.
///   3. Read the `PID` field, and keep only the game's or this program's own (its own
///      packets are needed for calibration).
///   4. Read the remaining fields. `try_parse::<T>("name")` reads a named
///      field as type `T`; any failure is counted in `diag` and the event
///      is dropped.
fn parse_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    self_pid: u32,
    game_pid: u32,
    steam_pid: u32,
    diag: &Diag,
) -> Option<RawUdp> {
    let op = record.opcode();
    diag.total.fetch_add(1, Ordering::Relaxed);
    diag.opcodes[(op / 64) as usize].fetch_or(1u64 << (op % 64), Ordering::Relaxed);
    let dir = match op {
        OP_SEND_V4 => Direction::Send,
        OP_RECV_V4 => Direction::Recv,
        _ => return None,
    };
    diag.udp_v4.fetch_add(1, Ordering::Relaxed);
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            diag.schema_err.fetch_add(1, Ordering::Relaxed);
            diag.note_err(format!("schema: {e:?}"));
            return None;
        }
    };
    let p = Parser::create(record, &schema);
    // A small macro so each field failure records which field broke.
    macro_rules! field {
        ($name:literal) => {
            match p.try_parse($name) {
                Ok(v) => v,
                Err(e) => {
                    diag.field_err.fetch_add(1, Ordering::Relaxed);
                    diag.note_err(format!("field {}: {e:?}", $name));
                    return None;
                }
            }
        };
    }
    let pid: u32 = field!("PID");
    if pid == self_pid {
        diag.self_pid.fetch_add(1, Ordering::Relaxed);
    }
    if game_pid != ALL_PIDS && pid != game_pid && pid != steam_pid && pid != self_pid {
        return None;
    }
    let ft = record.raw_timestamp();
    Some(RawUdp {
        t_ns: (ft - FILETIME_UNIX_EPOCH) as i128 * 100,
        pid,
        dir,
        daddr: field!("daddr"),
        saddr: field!("saddr"),
        dport: field!("dport"),
        sport: field!("sport"),
        size: field!("size"),
    })
}

/// Turn one `TcpIp` event into a `RawTcp`, or `None` if it isn't an IPv4
/// send/receive/retransmit by steam.exe. Runs on ferrisetw's thread for every
/// TCP event on the PC, so, like [`parse_event`], it checks the opcode first
/// and drops other processes as soon as the PID is read.
fn parse_tcp_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    steam_pid: u32,
    diag: &Diag,
) -> Option<RawTcp> {
    let op = record.opcode();
    diag.total.fetch_add(1, Ordering::Relaxed);
    diag.opcodes[(op / 64) as usize].fetch_or(1u64 << (op % 64), Ordering::Relaxed);
    let kind = match op {
        OP_TCP_SEND_V4 => TcpKind::Send,
        OP_TCP_RECV_V4 => TcpKind::Recv,
        OP_TCP_RETRANSMIT_V4 => TcpKind::Retransmit,
        _ => return None,
    };
    if steam_pid == u32::MAX {
        return None;
    }
    diag.udp_v4.fetch_add(1, Ordering::Relaxed);
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            diag.schema_err.fetch_add(1, Ordering::Relaxed);
            diag.note_err(format!("tcp schema: {e:?}"));
            return None;
        }
    };
    let p = Parser::create(record, &schema);
    macro_rules! field {
        ($name:literal) => {
            match p.try_parse($name) {
                Ok(v) => v,
                Err(e) => {
                    diag.field_err.fetch_add(1, Ordering::Relaxed);
                    diag.note_err(format!("tcp field {}: {e:?}", $name));
                    return None;
                }
            }
        };
    }
    let pid: u32 = field!("PID");
    if pid != steam_pid {
        return None;
    }
    let ft = record.raw_timestamp();
    Some(RawTcp {
        t_ns: (ft - FILETIME_UNIX_EPOCH) as i128 * 100,
        pid,
        kind,
        daddr: field!("daddr"),
        saddr: field!("saddr"),
        dport: field!("dport"),
        sport: field!("sport"),
        size: field!("size"),
    })
}

/// Start the kernel UDP trace. Requires administrator rights.
// How the pieces connect:
//
//   ferrisetw thread                      main thread (monitor.rs)
//   ----------------                      ------------------------
//   callback(event) ──tx.send(RawUdp)──►  rx.try_recv() in the loop
//   gp.load()  ◄──── shared AtomicU32 ──  game_pid.store(pid)
//   sp.load()  ◄──── shared AtomicU32 ──  steam_pid.store(pid)
//
// - `channel()` creates a Sender (`tx`) and Receiver (`rx`). Sending *moves*
//   the value into the queue, so no locking is needed.
// - `Arc` = "atomically reference-counted": shared ownership across threads.
//   `Arc::clone` just bumps a counter; both handles point at the same atomic.
// - `AtomicU32` can be read and written from several threads without a lock.
//   `Ordering::Relaxed` is enough: only the latest PID is needed eventually,
//   not ordering with other memory.
// - `move |...| { ... }` makes the closure take ownership of `tx`, `gp` and
//   `self_pid`. That's required, because the closure outlives this function.
//   The compiler checks that everything it captures is safe to send to
//   another thread (`Send`).
// - `.map_err(...)` converts ferrisetw's error type into anyhow's, and
//   `.context(...)` adds the likely fix to the message.
pub fn start() -> Result<UdpTrace> {
    start_with(false)
}

/// Start the kernel trace; with `tcp`, also read steam.exe's TCP events (a
/// second provider on the same session, its own callback, channel and
/// counters). Without it, the trace is exactly the UDP-only one.
pub fn start_with(tcp: bool) -> Result<UdpTrace> {
    let (tx, rx): (Sender<RawUdp>, Receiver<RawUdp>) = channel();
    let game_pid = Arc::new(AtomicU32::new(u32::MAX));
    let steam_pid = Arc::new(AtomicU32::new(u32::MAX));
    let self_pid = std::process::id();
    let gp = Arc::clone(&game_pid);
    let sp = Arc::clone(&steam_pid);
    let diag = Arc::new(Diag::default());
    let d = Arc::clone(&diag);
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        if let Some(ev) = parse_event(
            record,
            locator,
            self_pid,
            gp.load(Ordering::Relaxed),
            sp.load(Ordering::Relaxed),
            &d,
        ) {
            let _ = tx.send(ev);
        }
    };
    let provider = Provider::kernel(&UDP_IP_PROVIDER)
        .add_callback(callback)
        .build();
    let mut builder = KernelTrace::new()
        .named(format!("ds3sm-udp-{self_pid}"))
        .enable(provider);
    let (mut tcp_rx, mut tcp_diag) = (None, None);
    if tcp {
        let (ttx, trx): (Sender<RawTcp>, Receiver<RawTcp>) = channel();
        let td = Arc::new(Diag::default());
        let (sp2, td2) = (Arc::clone(&steam_pid), Arc::clone(&td));
        let tcp_cb = move |record: &EventRecord, locator: &SchemaLocator| {
            if let Some(ev) = parse_tcp_event(record, locator, sp2.load(Ordering::Relaxed), &td2) {
                let _ = ttx.send(ev);
            }
        };
        builder = builder.enable(
            Provider::kernel(&TCP_IP_PROVIDER)
                .add_callback(tcp_cb)
                .build(),
        );
        tcp_rx = Some(trx);
        tcp_diag = Some(td);
    }
    let trace = builder
        .start_and_process()
        .map_err(|e| anyhow!("{e:?}"))
        .context("starting kernel ETW trace (run as administrator)")?;
    Ok(UdpTrace {
        _trace: trace,
        game_pid,
        steam_pid,
        rx,
        diag,
        tcp_rx,
        tcp_diag,
    })
}

/// TEST-NET-1 address (RFC 5737): never routed, safe to send to.
// --- Calibration -----------------------------------------------------------
const CAL_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// Port chosen so the swapped and unswapped values differ (0xC351 vs 0x51C3).
const CAL_PORT: u16 = 50001;
const CAL_SIZE: usize = 37;

/// Work out ETW's byte order by sending one known datagram.
/// Events seen meanwhile (other than the probe) are returned so none are lost.
// Steps:
//   1. Open a UDP socket on any free local port.
//   2. Every 500 ms, send a 37-byte packet to 192.0.2.1:50001.
//   3. Watch the channel for a 37-byte send from this program's own PID.
//   4. Compare its raw address and port with the known values, both as-is and
//      byte-swapped, to learn which interpretation is right.
// `recv_timeout` waits up to 100 ms for an event, so the loop stays
// responsive and can re-send.
pub fn calibrate(trace: &UdpTrace) -> Result<(ByteOrder, Vec<RawUdp>)> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let self_pid = std::process::id();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut kept = Vec::new();
    let mut next_send = Instant::now();
    let mut send_err: Option<String> = None;
    while Instant::now() < deadline {
        if Instant::now() >= next_send {
            // Don't stop on errors: some networks reject TEST-NET outright, and
            // the send event is what's needed. Keep the error for the report.
            if let Err(e) = sock.send_to(&[0u8; CAL_SIZE], SocketAddrV4::new(CAL_ADDR, CAL_PORT)) {
                send_err.get_or_insert(e.to_string());
            }
            next_send = Instant::now() + Duration::from_millis(500);
        }
        match trace.rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ev)
                if ev.pid == self_pid
                    && ev.dir == Direction::Send
                    && ev.size as usize == CAL_SIZE =>
            {
                let swap_addr = Ipv4Addr::from(ev.daddr.swap_bytes()) == CAL_ADDR;
                let plain_addr = Ipv4Addr::from(ev.daddr) == CAL_ADDR;
                let swap_port = ev.dport.swap_bytes() == CAL_PORT;
                let plain_port = ev.dport == CAL_PORT;
                if (swap_addr || plain_addr) && (swap_port || plain_port) {
                    return Ok((
                        ByteOrder {
                            swap_addr,
                            swap_port,
                        },
                        kept,
                    ));
                }
                return Err(anyhow!(
                    "ETW calibration packet had unexpected fields: daddr={:#x} dport={:#x}",
                    ev.daddr,
                    ev.dport
                ));
            }
            Ok(ev) if ev.pid != self_pid => kept.push(ev),
            Ok(_) => {}
            Err(_) => {}
        }
    }
    Err(anyhow!(
        "no ETW UDP event seen for the calibration packet within 5 s ({}; send_err={})",
        trace.diag.summary(),
        send_err.as_deref().unwrap_or("none")
    ))
}

// ---------------------------------------------------------------------------
// Unit test: decoding uses the remote side and applies the byte order.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// The callback must sit on the UdpIp class, not TcpIp (see `UDP_IP_PROVIDER`).
    #[test]
    fn provider_is_udpip_class() {
        assert_eq!(
            UDP_IP_PROVIDER.guid,
            GUID::from("bf3a50c5-a9c9-4988-a005-2df0b7c80f80")
        );
    }

    #[test]
    fn tcp_provider_is_tcpip_class_on_the_same_flag() {
        assert_eq!(
            TCP_IP_PROVIDER.guid,
            GUID::from("9a280ac0-c8e0-11d1-84e2-00c04fb998a2")
        );
        assert_eq!(TCP_IP_PROVIDER.flags, UDP_IP_PROVIDER.flags);
    }

    #[test]
    fn tcp_decode_uses_remote_side_for_each_kind() {
        let bo = ByteOrder {
            swap_addr: true,
            swap_port: true,
        };
        let peer = u32::from(Ipv4Addr::new(192, 0, 2, 15)).swap_bytes();
        let me = u32::from(Ipv4Addr::new(192, 0, 2, 9)).swap_bytes();
        let want = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 15), 49202);
        for (kind, daddr, saddr, dport, sport) in [
            (TcpKind::Send, peer, me, 49202u16, 53795u16),
            (TcpKind::Retransmit, peer, me, 49202, 53795),
            (TcpKind::Recv, me, peer, 53795, 49202),
        ] {
            let r = RawTcp {
                t_ns: 1,
                pid: 7,
                kind,
                daddr,
                saddr,
                dport: dport.swap_bytes(),
                sport: sport.swap_bytes(),
                size: 87,
            };
            let s = bo.decode_tcp(&r);
            assert_eq!(s.remote, want, "{kind:?}");
            assert_eq!((s.kind, s.size, s.pid), (kind, 87, 7));
        }
    }

    #[test]
    fn decode_uses_remote_side() {
        let bo = ByteOrder {
            swap_addr: true,
            swap_port: true,
        };
        let ip_be = u32::from(Ipv4Addr::new(203, 0, 113, 5)).swap_bytes();
        let r = RawUdp {
            t_ns: 1,
            pid: 1,
            dir: Direction::Recv,
            daddr: 0,
            saddr: ip_be,
            dport: 0,
            sport: 27015u16.swap_bytes(),
            size: 68,
        };
        let d = bo.decode(&r);
        assert_eq!(
            d.remote,
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 27015)
        );
    }
}
