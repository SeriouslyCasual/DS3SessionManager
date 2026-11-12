//! Kernel ETW capture of UDP send/receive events (Windows only, needs admin).
//!
//! Uses the NT kernel TCP/IP provider (`EVENT_TRACE_FLAG_NETWORK_TCPIP`),
//! whose `UdpIp` events carry PID, payload size and both endpoints, but not
//! the payload itself. On Windows 8 and later, ferrisetw starts the session in
//! "system logger" mode with its own name. That avoids taking the single
//! global "NT Kernel Logger" session other tools may be using.
//!
//! Timestamps: ferrisetw sets the session clock to QPC
//! (`Wnode.ClientContext = 1`), and ETW hands consumers FILETIME values
//! (100 ns units), which we convert to Unix nanoseconds.
//!
//! Byte order of the address and port fields is not trusted blindly. At
//! startup, [`calibrate`] sends one datagram to a TEST-NET address
//! (RFC 5737) from this process and checks how ETW reports it.

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
const OP_SEND_V4: u8 = 10;
const OP_RECV_V4: u8 = 11;

/// FILETIME of the Unix epoch, in 100 ns units.
const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

/// One raw UDP event, before byte-order decoding.
#[derive(Clone, Copy, Debug)]
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
pub struct ByteOrder {
    pub swap_addr: bool,
    pub swap_port: bool,
}

impl ByteOrder {
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
pub struct UdpTrace {
    _trace: KernelTrace,
    /// PIDs whose events are forwarded (the game, plus this process for calibration).
    pub game_pid: Arc<AtomicU32>,
    pub rx: Receiver<RawUdp>,
}

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
const CAL_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// Port chosen so the swapped and unswapped values differ (0xC351 vs 0x51C3).
const CAL_PORT: u16 = 50001;
const CAL_SIZE: usize = 37;

/// Work out ETW's byte order by sending one known datagram.
/// Events seen meanwhile (other than the probe) are returned so none are lost.
pub fn calibrate(trace: &UdpTrace) -> Result<(ByteOrder, Vec<RawUdp>)> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let self_pid = std::process::id();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut kept = Vec::new();
    let mut next_send = Instant::now();
    while Instant::now() < deadline {
        if Instant::now() >= next_send {
            // Ignore errors: some networks reject TEST-NET outright, and the
            // send event is what we need.
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
