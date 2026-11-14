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
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{Provider, kernel_providers};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::KernelTrace;

use crate::stun::{Datagram, Direction};

/// `UdpIp` opcodes for IPv4 (kernel MOF class `UdpIp_TypeGroup1`).
// Opcode numbers identify the event type within the provider. These come from
// the kernel's published event schema (MOF class `UdpIp_TypeGroup1`).
const OP_SEND_V4: u8 = 10;
const OP_RECV_V4: u8 = 11;

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
    pub rx: Receiver<RawUdp>,
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
///      field as type `T`, and `.ok()?` gives up on this event if any field
///      is missing.
fn parse_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    self_pid: u32,
    game_pid: u32,
) -> Option<RawUdp> {
    let dir = match record.opcode() {
        OP_SEND_V4 => Direction::Send,
        OP_RECV_V4 => Direction::Recv,
        _ => return None,
    };
    let schema = locator.event_schema(record).ok()?;
    let p = Parser::create(record, &schema);
    let pid: u32 = p.try_parse("PID").ok()?;
    if pid != game_pid && pid != self_pid {
        return None;
    }
    let ft = record.raw_timestamp();
    Some(RawUdp {
        t_ns: (ft - FILETIME_UNIX_EPOCH) as i128 * 100,
        pid,
        dir,
        daddr: p.try_parse("daddr").ok()?,
        saddr: p.try_parse("saddr").ok()?,
        dport: p.try_parse("dport").ok()?,
        sport: p.try_parse("sport").ok()?,
        size: p.try_parse("size").ok()?,
    })
}

/// Start the kernel UDP trace. Requires administrator rights.
// How the pieces connect:
//
//   ferrisetw thread                      main thread (monitor.rs)
//   ----------------                      ------------------------
//   callback(event) ──tx.send(RawUdp)──►  rx.try_recv() in the loop
//   gp.load()  ◄──── shared AtomicU32 ──  game_pid.store(pid)
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
    let (tx, rx): (Sender<RawUdp>, Receiver<RawUdp>) = channel();
    let game_pid = Arc::new(AtomicU32::new(u32::MAX));
    let self_pid = std::process::id();
    let gp = Arc::clone(&game_pid);
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        if let Some(ev) = parse_event(record, locator, self_pid, gp.load(Ordering::Relaxed)) {
            let _ = tx.send(ev);
        }
    };
    let provider = Provider::kernel(&kernel_providers::TCP_IP_PROVIDER)
        .add_callback(callback)
        .build();
    let trace = KernelTrace::new()
        .named(format!("ds3sm-udp-{self_pid}"))
        .enable(provider)
        .start_and_process()
        .map_err(|e| anyhow!("{e:?}"))
        .context("starting kernel ETW trace (run as administrator)")?;
    Ok(UdpTrace {
        _trace: trace,
        game_pid,
        rx,
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
    while Instant::now() < deadline {
        if Instant::now() >= next_send {
            // Ignore errors: some networks reject TEST-NET outright, and the
            // send event is what's needed.
            let _ = sock.send_to(&[0u8; CAL_SIZE], SocketAddrV4::new(CAL_ADDR, CAL_PORT));
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
        "no ETW UDP event seen for the calibration packet within 5 s"
    ))
}

// ---------------------------------------------------------------------------
// Unit test: decoding uses the remote side and applies the byte order.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

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
