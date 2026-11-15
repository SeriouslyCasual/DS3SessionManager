//! The `probe` and `monitor` commands: the glue that combines Steam session
//! state, ETW packet timing and GeoIP into a live table, logged to SQLite.
//!
//! # Data flow
//!
//! ```text
//!   Steam (steam.rs) ──► who, relay?, remote IP:port ─┐
//!                                                     ├─► join on IP:port ─► table + SQLite
//!   ETW (etw.rs) ──► packets ──► stun.rs ──► RTT ─────┘
//!                                    GeoIP (geo.rs) ──► country, distance, bound
//! ```
//!
//! # Structure
//!
//! `run()` owns all the state (maps, matcher, database). Helper functions
//! *borrow* just the pieces they need: `&mut` for what they change, `&` for
//! what they only read. A helper's signature therefore tells you exactly what
//! it can touch.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::MonitorArgs;
use crate::etw::{self, ByteOrder};
use crate::geo::{self, AsnDb, GeoDb, GeoInfo, LatLon};
use crate::jitter::StreamJitter;
use crate::model::{P2PState, Provenance, RttSample, RttSource, SteamId};
use crate::relay::{self, Detectors, Evidence, Role};
use crate::stats::Rolling;
use crate::steam::Steam;
use crate::store::{GeoRow, GeoSubject, Store, StreamStats, TrafficRow};
use crate::stun::{Direction, StunConfig, StunMatcher};
use crate::valve::{self, VALVE_ASN};
use crate::valve_data::Pop;
use crate::win;

/// Current wall-clock time in Unix nanoseconds. If the clock is somehow
/// before 1970, `duration_since` fails and the function falls back to 0 rather than
/// crashing.
fn now_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

/// `ds3sm probe`: check each prerequisite in turn and print what was found.
/// Every check reports its own failure instead of stopping the whole command,
/// so one run shows everything that needs fixing.
pub fn probe(geo_path: &Path, asn_path: &Path) -> Result<()> {
    println!("ds3sm probe");
    println!("  administrator:  {}", win::is_admin());
    match win::find_process(win::DS3_EXE) {
        Some(pid) => println!("  {}: running (pid {pid})", win::DS3_EXE),
        None => println!("  {}: not running", win::DS3_EXE),
    }
    match GeoDb::open(geo_path) {
        Ok(_) => println!("  GeoIP database: {}", geo_path.display()),
        Err(e) => println!("  GeoIP database: unavailable ({e:#})"),
    }
    let asndb = match AsnDb::open(asn_path) {
        Ok(a) => {
            println!("  ASN database: {}", asn_path.display());
            Some(a)
        }
        Err(e) => {
            println!("  ASN database: unavailable, relay detector A off ({e:#})");
            None
        }
    };
    // Remote IPs of live P2P sessions, for the per-process breakdown below.
    let mut peer_ips: Vec<std::net::Ipv4Addr> = Vec::new();
    let mut any_peer = false;
    match Steam::init() {
        Ok(mut s) => {
            s.run_callbacks();
            println!("  Steam: ok, local id {}", s.local_id());
            let coplay = s.coplay_list();
            println!("  coplay list: {} entries", coplay.len());
            let peers = s.active_peers();
            println!("  active/connecting P2P sessions: {}", peers.len());
            any_peer = !peers.is_empty();
            peer_ips.extend(
                peers
                    .iter()
                    .filter_map(|(_, st)| st.remote.map(|r| *r.ip())),
            );
            for (id, st) in peers {
                println!(
                    "    {id}  name={:?} active={} connecting={} relay={} err={} remote={:?}",
                    s.persona(id),
                    st.active,
                    st.connecting,
                    st.using_relay,
                    st.error,
                    st.remote
                );
                // Relay detectors L and A on Steam's reported remote (P
                // needs traffic, so only `monitor` evaluates it).
                if let Some(r) = st.remote {
                    let ip = *r.ip();
                    let site = valve::site(ip)
                        .map(|p| format!("{} {}", p.code, p.desc))
                        .unwrap_or_else(|| "-".into());
                    let asn = match &asndb {
                        Some(db) => db
                            .lookup(IpAddr::V4(ip))
                            .map(|(n, o)| format!("AS{n} {}", o.unwrap_or_default()))
                            .unwrap_or_else(|| "not found".into()),
                        None => "?".into(),
                    };
                    println!(
                        "      remote is a relay address (L): {}, relay site: {site}, ASN: {asn}",
                        valve::is_relay_address(ip)
                    );
                }
            }
        }
        Err(e) => println!("  Steam: {e:#}"),
    }
    if win::is_admin() {
        match etw::start().and_then(|t| etw::calibrate(&t).map(|(bo, _)| (t, bo))) {
            Ok((t, bo)) => {
                println!("  ETW kernel UDP trace: ok, byte order {bo:?}");
                if any_peer {
                    let steam_pid = win::find_process(win::STEAM_EXE).unwrap_or(u32::MAX);
                    peer_traffic_by_process(&t, bo, &peer_ips, steam_pid);
                }
            }
            Err(e) => println!("  ETW kernel UDP trace: {e:#}"),
        }
    } else {
        println!("  ETW kernel UDP trace: skipped (needs administrator)");
    }
    Ok(())
}

/// `probe` only: for 5 s, count UDP packets to and from each live peer's IP in
/// **every** process, and print which process carries them.
///
/// `monitor` only counts the game's own packets. If a peer shows up in Steam
/// but its pps stays at 0, its traffic is flowing through another process
/// (for example the Steam client), and this table shows which one. Matching
/// is by IP only, so a different port than Steam reports still shows up.
///
/// It also lists **steam.exe's busiest UDP endpoints** from the same sample.
/// For a relayed session, Steam reports the peer's own public address, but the
/// packets actually go to a Valve relay server; this list shows which one,
/// and the packet sizes Steam uses on that path.
fn peer_traffic_by_process(
    t: &etw::UdpTrace,
    bo: ByteOrder,
    peer_ips: &[std::net::Ipv4Addr],
    steam_pid: u32,
) {
    t.game_pid.store(etw::ALL_PIDS, Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(5);
    // (pid, remote endpoint) → (packets out, packets in, sizes seen)
    type Counts = HashMap<(u32, SocketAddrV4), (u64, u64, Vec<u32>)>;
    let mut to_peers: Counts = HashMap::new();
    let mut steam_all: Counts = HashMap::new();
    let add = |c: &mut Counts, pid: u32, d: &crate::stun::Datagram| {
        let e = c.entry((pid, d.remote)).or_default();
        match d.dir {
            Direction::Send => e.0 += 1,
            Direction::Recv => e.1 += 1,
        }
        if e.2.len() < 10 && !e.2.contains(&d.size) {
            e.2.push(d.size);
        }
    };
    while Instant::now() < deadline {
        if let Ok(raw) = t.rx.recv_timeout(Duration::from_millis(100)) {
            let d = bo.decode(&raw);
            if peer_ips.contains(d.remote.ip()) {
                add(&mut to_peers, raw.pid, &d);
            }
            if raw.pid == steam_pid {
                add(&mut steam_all, raw.pid, &d);
            }
        }
    }
    t.game_pid.store(u32::MAX, Ordering::Relaxed);
    let names = win::process_names();
    let print_rows = |c: Counts, limit: usize| {
        let mut rows: Vec<_> = c.into_iter().collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.1.0 + r.1.1));
        for ((pid, remote), (out, inn, mut sizes)) in rows.into_iter().take(limit) {
            sizes.sort_unstable();
            let name = names.get(&pid).map(String::as_str).unwrap_or("?");
            println!("    {name} (pid {pid}) <-> {remote}: out {out}, in {inn}, sizes {sizes:?}");
        }
    };
    println!("  UDP to/from P2P peers by process (5 s sample):");
    if to_peers.is_empty() {
        println!("    none seen in any process (relayed, IPv6, or not flowing)");
    } else {
        print_rows(to_peers, usize::MAX);
    }
    println!("  steam.exe busiest UDP endpoints (same sample, top 8):");
    if steam_all.is_empty() {
        println!("    none seen");
    } else {
        print_rows(steam_all, 8);
    }
}

/// Width of the packets/second window, ns.
const RATE_WINDOW_NS: i128 = 5_000_000_000;
/// How far behind "now" the window ends, ns. ETW hands events over in
/// batches, at best once per second (its minimum buffer flush interval), so
/// the most recent ~1 s is always incomplete. Ending the window 1.5 s back
/// means it only covers time whose packets have all arrived.
const RATE_LAG_NS: i128 = 1_500_000_000;

/// Recent packet timestamps for one direction of one endpoint.
///
/// Rates are computed from the packets' own **kernel timestamps**, not from
/// when the program happened to receive them. Counting "packets since the
/// last redraw" instead gives wrong numbers: with 500 ms redraws and 1 s ETW
/// batches, every other redraw shows double the true rate and the next shows
/// 0, and a delayed batch shows as a huge spike.
#[derive(Default, Clone)]
struct RateWindow {
    ts: std::collections::VecDeque<i128>,
}

impl RateWindow {
    fn push(&mut self, t_ns: i128) {
        self.ts.push_back(t_ns);
        // Drop timestamps too old to ever fall inside a window again.
        let keep = RATE_WINDOW_NS + RATE_LAG_NS + 1_000_000_000;
        while self.ts.front().is_some_and(|&f| t_ns - f > keep) {
            self.ts.pop_front();
        }
    }

    /// Packets per second over `[now - lag - window, now - lag]`.
    fn rate(&self, now_ns: i128) -> f64 {
        let end = now_ns - RATE_LAG_NS;
        let start = end - RATE_WINDOW_NS;
        let n = self.ts.iter().filter(|&&t| t > start && t <= end).count();
        n as f64 * 1e9 / RATE_WINDOW_NS as f64
    }
}

/// Per-remote-endpoint traffic counters (all packet sizes, not just STUN).
// Plain counters per remote endpoint, updated for every packet counted.
// `#[derive(Default)]` makes `Traffic::default()` all zeros, which lets the
// entry API create it on first sight (`.or_default()`).
#[derive(Default, Clone)]
struct Traffic {
    pkts_out: u64,
    pkts_in: u64,
    bytes_out: u64,
    bytes_in: u64,
    last_in_ns: i128,
    /// Largest gap between received packets, ns (a stall indicator).
    max_gap_in_ns: i128,
    /// Timestamps for the packets/second columns.
    rate_in: RateWindow,
    rate_out: RateWindow,
    /// RFC 3550 jitter of the dominant packet size each way (`jitter.rs`).
    /// Inbound is the network measure; outbound is this PC's own sending
    /// regularity, the floor the inbound value can be compared with.
    jit_in: StreamJitter,
    jit_out: StreamJitter,
    /// Has sent a request-sized packet / received a reply-sized packet
    /// (the 56/68-byte connectivity checks). Used to recognise relays.
    saw_req: bool,
    saw_reply: bool,
}

/// steam.exe traffic that no peer endpoint claims: Valve servers, and the
/// relay server carrying a relayed peer (see `relay.rs`). Kept apart from
/// the game's own `traffic` map so it never shows as "the game's" endpoints.
struct SteamSide {
    traffic: HashMap<SocketAddrV4, Traffic>,
    /// RTT samples per endpoint, for relay endpoints not attributed to a peer.
    rtt: HashMap<SocketAddrV4, Rolling>,
    window: usize,
}

/// Packets/second in and out for one endpoint, summed over the game-and-peer
/// map and the steam.exe map. An endpoint's packets move from one to the
/// other when a relay is attributed, so both are needed for a steady rate.
fn ep_rates(
    ep: &SocketAddrV4,
    traffic: &HashMap<SocketAddrV4, Traffic>,
    side: &SteamSide,
    t_now: i128,
) -> (f64, f64) {
    [traffic.get(ep), side.traffic.get(ep)]
        .into_iter()
        .flatten()
        .fold((0.0, 0.0), |(i, o), tr| {
            (i + tr.rate_in.rate(t_now), o + tr.rate_out.rate(t_now))
        })
}

/// An endpoint's inbound stream jitter. Its packets can sit in either map
/// (they move when a relay is attributed), so the entry that received the
/// tracked stream most recently wins.
fn ep_jitter<'a>(
    ep: &SocketAddrV4,
    traffic: &'a HashMap<SocketAddrV4, Traffic>,
    side: &'a SteamSide,
) -> Option<&'a StreamJitter> {
    [traffic.get(ep), side.traffic.get(ep)]
        .into_iter()
        .flatten()
        .map(|tr| &tr.jit_in)
        .filter(|j| j.jitter_ms().is_some())
        .max_by_key(|j| j.last_ns())
}

/// A peer's inbound jitter: that of its busiest inbound endpoint. For a
/// relayed peer in mode A that's the wrapped relay port carrying the
/// player's traffic, not Steam's remote (which only returns STUN replies).
fn peer_jitter(
    eps: &[SocketAddrV4],
    traffic: &HashMap<SocketAddrV4, Traffic>,
    side: &SteamSide,
    t_now: i128,
) -> Option<f64> {
    eps.iter()
        .filter_map(|e| {
            ep_jitter(e, traffic, side).map(|j| (ep_rates(e, traffic, side, t_now).0, j))
        })
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .and_then(|(_, j)| j.jitter_ms())
}

/// Everything the monitor remembers about one peer between polls.
struct PeerView {
    persona: Option<String>,
    state: P2PState,
    rtt: Rolling,
    /// The **player's** estimated location (never a relay's; see `relay_geo`).
    geo: Option<GeoInfo>,
    /// The address `geo` was looked up for, so a change triggers a new lookup
    /// and a relay address taken for the player can be recognised.
    geo_ip: Option<Ipv4Addr>,
    distance_km: Option<f64>,
    bound_ms: Option<f64>,
    last_logged_state: Option<P2PState>,
    /// What the four relay detectors say (`relay.rs`), and what was last logged.
    evidence: Evidence,
    logged_evidence: Option<Evidence>,
    /// The relay server's IP, once known.
    relay_ip: Option<Ipv4Addr>,
    /// steam.exe endpoints on the relay IP attributed to this peer, besides
    /// Steam's own reported remote. Sorted.
    relay_eps: Vec<SocketAddrV4>,
    /// Where the relay server is (not the player).
    relay_geo: Option<RelayGeo>,
}

/// A relay server's location: Steam's relay site if the address matches
/// one, plus the GeoIP estimate.
struct RelayGeo {
    site: Option<&'static Pop>,
    geo: Option<GeoInfo>,
    distance_km: Option<f64>,
    bound_ms: Option<f64>,
}

/// Read-only inputs to the relay logic, bundled to keep signatures short.
struct RelayCtx<'a> {
    detectors: Detectors,
    asn: Option<&'a AsnDb>,
    geodb: Option<&'a GeoDb>,
    home: Option<LatLon>,
}

impl PeerView {
    fn new(state: P2PState, window: usize) -> Self {
        Self {
            persona: None,
            state,
            rtt: Rolling::new(window),
            geo: None,
            geo_ip: None,
            distance_km: None,
            bound_ms: None,
            last_logged_state: None,
            evidence: Evidence::default(),
            logged_evidence: None,
            relay_ip: None,
            relay_eps: Vec::new(),
            relay_geo: None,
        }
    }

    /// Every endpoint whose traffic counts for this peer: Steam's reported
    /// remote and the attributed relay endpoints.
    fn endpoints(&self) -> Vec<SocketAddrV4> {
        let mut v: Vec<SocketAddrV4> = self.state.remote.into_iter().collect();
        v.extend(
            self.relay_eps
                .iter()
                .filter(|e| Some(**e) != self.state.remote),
        );
        v
    }

    /// Whether `ep` is one of this peer's relay endpoints: an attributed one,
    /// or Steam's reported remote when that is itself the relay (E2 mode).
    fn is_relay_endpoint(&self, ep: &SocketAddrV4) -> bool {
        self.relay_eps.contains(ep)
            || (self.state.remote == Some(*ep) && self.relay_ip == Some(*ep.ip()))
    }

    /// The endpoint carrying the 56/68-byte checks (most requests seen),
    /// i.e. the one the RTT samples come from.
    fn stun_endpoint(&self, matcher: &StunMatcher) -> Option<SocketAddrV4> {
        let eps = self.endpoints();
        eps.iter()
            .copied()
            .max_by_key(|e| matcher.counters(e).requests)
            .filter(|e| matcher.counters(e).requests > 0)
            .or_else(|| self.relay_eps.first().copied())
            .or(self.state.remote)
    }
}

// ===========================================================================
// `ds3sm monitor`
// ===========================================================================
// Startup steps:
//   1. Ctrl+C handler: set a shared flag instead of killing the process, so
//      the loop can finish cleanly and record a final "stop" event.
//   2. Open the run database and record metadata (version, label, settings).
//   3. Open the GeoIP database (optional: warn and carry on without it).
//   4. Wait for the game to start (no handle to the game is ever opened).
//   5. Connect to Steam.
//   6. Start ETW, calibrate the byte order, tell the trace which PID to watch.
//   7. Loop until Ctrl+C (see the numbered steps inside the loop).
pub fn run(args: MonitorArgs) -> Result<()> {
    // Step 1. The inner `{ }` block allows shadowing `stop` with a clone that
    // moves into the handler closure, while the outer `stop` stays usable here.
    // Make cmd.exe understand the table's clear-screen codes (see win.rs).
    win::enable_ansi();
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst))
            .context("installing Ctrl+C handler")?;
    }

    // Step 2. `unwrap_or_else` only builds the default path when `--db` wasn't
    // given. `env!("CARGO_PKG_VERSION")` is filled in at compile time from
    // Cargo.toml.
    let db_path = args
        .db
        .clone()
        .unwrap_or_else(|| format!("runs/{}.sqlite", now_ns() / 1_000_000_000).into());
    let store = Store::open(&db_path)?;
    store.set_meta("tool_version", env!("CARGO_PKG_VERSION"))?;
    store.set_meta("started_ns", &now_ns().to_string())?;
    store.set_meta("label", &args.label)?;
    store.set_meta("req_size", &args.req_size.to_string())?;
    store.set_meta("reply_size", &args.reply_size.to_string())?;

    // Step 3. `{e:#}` prints the error together with its context chain.
    let geodb = match GeoDb::open(&args.geo) {
        Ok(g) => Some(g),
        Err(e) => {
            eprintln!("warning: GeoIP disabled: {e:#}");
            None
        }
    };
    let home = match (args.home_lat, args.home_lon) {
        (Some(lat), Some(lon)) => Some(LatLon { lat, lon }),
        _ => None,
    };
    // Optional ASN database (relay detector A). Without it, A is logged as "?".
    let asndb = match AsnDb::open(&args.asn) {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("note: ASN lookups disabled (relay detector A off): {e:#}");
            None
        }
    };
    store.set_meta("relay_detect", &args.relay_detect.to_string())?;
    store.set_meta("asn_db", if asndb.is_some() { "yes" } else { "no" })?;
    let ctx = RelayCtx {
        detectors: args.relay_detect,
        asn: asndb.as_ref(),
        geodb: geodb.as_ref(),
        home,
    };

    // Step 4. `loop` with `break value` makes the loop itself an expression
    // that produces the PID.
    println!("waiting for {} ...", win::DS3_EXE);
    let mut game_pid = loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(pid) = win::find_process(win::DS3_EXE) {
            break pid;
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    store.event(now_ns(), "game_pid", &game_pid.to_string())?;

    // Step 5. The Steam client carries the game's P2P packets, so its PID is
    // needed as well. `u32::MAX` means "not found" and matches no packet.
    let mut steam = Steam::init()?;
    store.set_meta("local_steam_id", &steam.local_id().to_string())?;
    let mut steam_pid = win::find_process(win::STEAM_EXE).unwrap_or(u32::MAX);
    if steam_pid == u32::MAX {
        eprintln!(
            "warning: {} not found; peer traffic won't be counted",
            win::STEAM_EXE
        );
    }
    store.event(now_ns(), "steam_pid", &steam_pid.to_string())?;

    // Step 6. Both branches of the `if` produce a tuple of two `Option`s, so
    // `--no-etw` simply leaves both as `None`.
    let (trace, byte_order) = if args.no_etw {
        (None, None)
    } else {
        let t = etw::start()?;
        let (bo, _) = etw::calibrate(&t)?;
        store.event(now_ns(), "etw_byte_order", &format!("{bo:?}"))?;
        t.game_pid.store(game_pid, Ordering::Relaxed);
        t.steam_pid.store(steam_pid, Ordering::Relaxed);
        (Some(t), Some(bo))
    };

    // Loop state. The maps are keyed so the code can join Steam's view and ETW's view:
    //   peers:       SteamId  → what is known about that player
    //   by_endpoint: IP:port  → SteamId (filled from Steam, read when ETW
    //                gives an RTT for an endpoint)
    //   traffic:     IP:port  → packet counters and recent timestamps (for
    //                packets/second; see `RateWindow`)
    let mut matcher = StunMatcher::new(StunConfig {
        request_size: args.req_size,
        reply_size: args.reply_size,
        ..Default::default()
    });
    let mut peers: HashMap<SteamId, PeerView> = HashMap::new();
    let mut by_endpoint: HashMap<SocketAddrV4, SteamId> = HashMap::new();
    let mut traffic: HashMap<SocketAddrV4, Traffic> = HashMap::new();
    let mut side = SteamSide {
        traffic: HashMap::new(),
        rtt: HashMap::new(),
        window: args.window,
    };
    let interval = Duration::from_millis(args.interval_ms);
    let mut next_poll = Instant::now();
    let mut last_pid_check = Instant::now();
    let mut last_traffic_log = Instant::now();

    // Main loop. ETW events are drained every ~10 ms, but Steam is polled and
    // the table redrawn only every `interval` (default 500 ms). Packet
    // timestamps are taken by the kernel, so draining late never distorts
    // RTT. Steam state changes slowly, so polling it often would be wasted
    // work.
    while !stop.load(Ordering::SeqCst) {
        // 1. Drain ETW events.
        if let (Some(t), Some(bo)) = (&trace, byte_order) {
            drain_etw(
                t,
                bo,
                game_pid,
                steam_pid,
                (args.req_size, args.reply_size),
                &mut matcher,
                &mut traffic,
                &mut side,
                &by_endpoint,
                &mut peers,
                &store,
            )?;
        }

        if Instant::now() < next_poll {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        next_poll += interval;
        if Instant::now() > next_poll {
            next_poll = Instant::now() + interval;
        }

        // 2. Follow game restarts.
        if last_pid_check.elapsed() > Duration::from_secs(5) {
            last_pid_check = Instant::now();
            match win::find_process(win::DS3_EXE) {
                Some(pid) if pid != game_pid => {
                    game_pid = pid;
                    store.event(now_ns(), "game_pid", &pid.to_string())?;
                    if let Some(t) = &trace {
                        t.game_pid.store(pid, Ordering::Relaxed);
                    }
                }
                None => {
                    store.event(now_ns(), "game_exit", "")?;
                    println!("{} exited; stopping.", win::DS3_EXE);
                    break;
                }
                _ => {}
            }
            // Same for the Steam client (it can restart while the game runs).
            if let Some(pid) = win::find_process(win::STEAM_EXE)
                && pid != steam_pid
            {
                steam_pid = pid;
                store.event(now_ns(), "steam_pid", &pid.to_string())?;
                if let Some(t) = &trace {
                    t.steam_pid.store(pid, Ordering::Relaxed);
                }
            }
        }

        // 3. Poll Steam.
        steam.run_callbacks();
        let t = now_ns();
        // For each live peer: fetch the name, record that they were seen, update
        // the in-memory view, log the state only if it changed, and remember
        // which endpoint belongs to them. (Geolocation waits until the relay
        // step has decided whether that endpoint is the player or a relay.)
        // `or_insert_with(|| ...)` only builds the default `PeerView` when
        // the peer is new.
        let active = steam.active_peers();
        for (id, st) in &active {
            let persona = steam.persona(*id);
            store.upsert_peer(*id, persona.as_deref(), t)?;
            let view = peers
                .entry(*id)
                .or_insert_with(|| PeerView::new(st.clone(), args.window));
            if persona.is_some() {
                view.persona = persona;
            }
            view.state = st.clone();
            if view.last_logged_state.as_ref() != Some(st) {
                store.insert_state(t, *id, st)?;
                view.last_logged_state = Some(st.clone());
            }
            if let Some(remote) = st.remote {
                by_endpoint.insert(remote, *id);
            }
        }
        // `current` = the Steam IDs that are live right now.
        // Peers that left: log a final inactive state once.
        let current: Vec<SteamId> = active.iter().map(|(id, _)| *id).collect();
        for (id, view) in peers.iter_mut() {
            if !current.contains(id) && (view.state.active || view.state.connecting) {
                view.state.active = false;
                view.state.connecting = false;
                store.insert_state(t, *id, &view.state)?;
                view.last_logged_state = Some(view.state.clone());
                store.event(t, "peer_left", &id.to_string())?;
            }
        }

        // 4. Relays: run the detectors, attribute relay endpoints, place the relay.
        update_relays(
            &active,
            &mut peers,
            &mut by_endpoint,
            &mut traffic,
            &side,
            &ctx,
            &store,
            t,
        )?;

        // 5. Place the player, unless Steam's remote turned out to be a relay.
        for (id, st) in &active {
            let (Some(view), Some(remote)) = (peers.get_mut(id), st.remote) else {
                continue;
            };
            if view.evidence.remote_is_relay(&ctx.detectors) {
                // An address first taken for the player can turn out to be a
                // relay (pattern evidence needs a few seconds of traffic).
                if view.geo_ip == Some(*remote.ip()) {
                    view.geo = None;
                    view.geo_ip = None;
                    view.distance_km = None;
                    view.bound_ms = None;
                    store.delete_geo(*id, GeoSubject::Peer)?;
                    store.event(t, "geo_reclassified", &format!("{id} {remote} relay"))?;
                }
            } else if view.geo_ip != Some(*remote.ip()) {
                locate(view, *id, remote, geodb.as_ref(), home, &store)?;
            }
        }

        // 6. Traffic snapshot every 5 s.
        if last_traffic_log.elapsed() >= Duration::from_secs(5) {
            last_traffic_log = Instant::now();
            log_traffic(&traffic, &side, &by_endpoint, &peers, &matcher, &store, t)?;
        }

        if !args.quiet {
            draw(
                &peers,
                &current,
                &traffic,
                &side,
                &by_endpoint,
                &matcher,
                &ctx,
                trace.is_some(),
            );
        }
    }
    store.event(now_ns(), "stop", "")?;
    println!("run saved to {}", db_path.display());
    Ok(())
}

/// Whether an endpoint has carried both a request-sized send and a
/// reply-sized receive, in either traffic map.
fn stun_like(
    ep: &SocketAddrV4,
    traffic: &HashMap<SocketAddrV4, Traffic>,
    side: &SteamSide,
) -> bool {
    [traffic.get(ep), side.traffic.get(ep)]
        .into_iter()
        .flatten()
        .any(|tr| tr.saw_req && tr.saw_reply)
}

#[allow(clippy::too_many_arguments)]
/// The relay step, after each Steam poll (rules in `relay.rs`):
/// 1. run the four detectors for every live peer and log changes
///    (`relay_evidence`);
/// 2. decide each relayed peer's relay host, the one carrying the RTT
///    (Steam's remote in E2 mode, the `pick` rule in E1 mode);
/// 3. if exactly one peer is relayed, attribute to it every endpoint
///    `relay::relay_set` accepts, on any relay host or site. Added endpoints
///    go into `by_endpoint`, so from then on their packets count for the
///    peer (pps, bytes, STUN RTT) exactly like a direct peer's. Each change
///    is logged as `relay_attributed` / `relay_unattributed` (detail:
///    `<id> <ip:port>`);
/// 4. place the relay host (site and GeoIP) when it changes.
fn update_relays(
    active: &[(SteamId, P2PState)],
    peers: &mut HashMap<SteamId, PeerView>,
    by_endpoint: &mut HashMap<SocketAddrV4, SteamId>,
    traffic: &mut HashMap<SocketAddrV4, Traffic>,
    side: &SteamSide,
    ctx: &RelayCtx<'_>,
    store: &Store,
    t: i128,
) -> Result<()> {
    let det = ctx.detectors;
    let reported: HashMap<SteamId, SocketAddrV4> = active
        .iter()
        .filter_map(|(id, st)| st.remote.map(|r| (*id, r)))
        .collect();
    let all_reported: HashSet<SocketAddrV4> = reported.values().copied().collect();
    // Endpoints Steam reports for peers other than `id`.
    let others = |id: &SteamId| -> HashSet<SocketAddrV4> {
        reported
            .iter()
            .filter(|(o, _)| *o != id)
            .map(|(_, r)| *r)
            .collect()
    };

    // Candidates: steam.exe's unclaimed endpoints, endpoints already
    // attributed, and Steam's reported remotes (their packets may sit in
    // either map, so rates sum both).
    let mut keys: HashSet<SocketAddrV4> = side.traffic.keys().copied().collect();
    for v in peers.values() {
        keys.extend(v.relay_eps.iter().copied());
    }
    keys.extend(all_reported.iter().copied());
    // A relay address: built-in list, or the ASN database says Valve.
    let relay_addr = |ip: Ipv4Addr| {
        valve::is_relay_address(ip)
            || ctx.asn.is_some_and(|db| {
                db.lookup(IpAddr::V4(ip))
                    .is_some_and(|(n, _)| n == VALVE_ASN)
            })
    };
    let candidates: Vec<relay::Candidate> = keys
        .iter()
        .map(|&ep| {
            let (pin, pout) = ep_rates(&ep, traffic, side, t);
            relay::Candidate::new(
                ep,
                pin,
                pout,
                stun_like(&ep, traffic, side),
                relay_addr(*ep.ip()),
            )
        })
        .collect();

    // 1. Evidence.
    for (id, st) in active {
        let Some(view) = peers.get_mut(id) else {
            continue;
        };
        let ip = st.remote.map(|r| *r.ip());
        let ev = Evidence {
            flag: st.using_relay,
            pattern: st
                .remote
                .is_some_and(|r| relay::pattern(r, &candidates, &others(id))),
            asn: ctx.asn.map(|db| {
                ip.and_then(|ip| db.lookup(IpAddr::V4(ip)))
                    .is_some_and(|(n, _)| n == VALVE_ASN)
            }),
            list: ip.is_some_and(valve::is_relay_address),
        };
        view.evidence = ev;
        if view.logged_evidence != Some(ev) {
            let remote = st
                .remote
                .map(|r| r.to_string())
                .unwrap_or_else(|| "-".into());
            store.event(
                t,
                "relay_evidence",
                &format!(
                    "{id} {} relayed={} remote={remote}",
                    ev.log_detail(),
                    u8::from(ev.relayed(&det))
                ),
            )?;
            view.logged_evidence = Some(ev);
        }
    }

    // 2. Which peers are relayed, and the relay host shown for each (the
    //    one carrying the RTT).
    let relayed: Vec<SteamId> = active
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| peers.get(id).is_some_and(|v| v.evidence.relayed(&det)))
        .collect();
    let flag_only: Vec<SteamId> = active
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| {
            peers
                .get(id)
                .is_some_and(|v| v.evidence.relayed(&det) && !v.evidence.remote_is_relay(&det))
        })
        .collect();
    let e1_ep = relay::pick(flag_only.len(), &candidates, &all_reported);
    let mut want_ip: HashMap<SteamId, Ipv4Addr> = HashMap::new();
    for (id, st) in active {
        let Some(v) = peers.get(id) else { continue };
        if v.evidence.remote_is_relay(&det) {
            if let Some(r) = st.remote {
                want_ip.insert(*id, *r.ip());
            }
        } else if flag_only.first() == Some(id)
            && let Some(ep) = e1_ep
        {
            want_ip.insert(*id, *ep.ip());
        }
    }
    // 3 and 4. Attribute (only for the single relayed peer, if there is
    // exactly one), and place the relay. Peers that left get nothing.
    for (id, view) in peers.iter_mut() {
        let ip = want_ip.get(id).copied();
        let want = if relayed.len() == 1 && relayed[0] == *id {
            let pick = if flag_only.first() == Some(id) {
                e1_ep
            } else {
                None
            };
            relay::relay_set(
                &candidates,
                reported.get(id).copied(),
                &others(id),
                &view.relay_eps,
                pick,
            )
        } else {
            Vec::new()
        };
        if want != view.relay_eps {
            for old in view.relay_eps.iter().filter(|e| !want.contains(e)) {
                by_endpoint.remove(old);
                // Its counters were steam.exe's, not the game's: drop them so
                // the relay never shows up in the game's "unattributed" list.
                traffic.remove(old);
                store.event(t, "relay_unattributed", &format!("{id} {old}"))?;
            }
            for new in want.iter().filter(|e| !view.relay_eps.contains(e)) {
                by_endpoint.insert(*new, *id);
                store.event(t, "relay_attributed", &format!("{id} {new}"))?;
            }
            view.relay_eps = want;
        }
        if view.relay_ip != ip {
            view.relay_ip = ip;
            view.relay_geo = None;
            if let Some(ip) = ip {
                locate_relay(view, *id, ip, ctx, store)?;
            }
        }
    }
    Ok(())
}

/// Place a relay server: Steam's relay site if its /24 matches one (Valve's
/// published coordinates), plus the GeoIP estimate. Distance and bound are
/// to the **relay**, and stored as a `relay` geo row.
fn locate_relay(
    view: &mut PeerView,
    id: SteamId,
    ip: Ipv4Addr,
    ctx: &RelayCtx<'_>,
    store: &Store,
) -> Result<()> {
    let site = valve::site(ip);
    let g = ctx.geodb.and_then(|db| db.lookup(IpAddr::V4(ip)));
    let loc = site
        .map(|p| LatLon {
            lat: p.lat,
            lon: p.lon,
        })
        .or(g.as_ref().and_then(|g| g.location));
    let (distance_km, bound_ms) = match (ctx.home, loc) {
        (Some(h), Some(l)) => {
            let d = geo::great_circle_km(h, l);
            (Some(d), Some(geo::fiber_rtt_lower_bound_ms(d)))
        }
        _ => (None, None),
    };
    store.upsert_geo(
        id,
        GeoSubject::Relay,
        &GeoRow {
            country: g.as_ref().and_then(|g| g.country.as_deref()),
            city: g.as_ref().and_then(|g| g.city.as_deref()),
            lat: loc.map(|l| l.lat),
            lon: loc.map(|l| l.lon),
            // Site coordinates are Valve's own; GeoIP's radius doesn't apply.
            accuracy_km: if site.is_some() {
                None
            } else {
                g.as_ref().and_then(|g| g.accuracy_km)
            },
            distance_km,
            fiber_bound_ms: bound_ms,
            site: site.map(|p| p.code),
        },
    )?;
    view.relay_geo = Some(RelayGeo {
        site,
        geo: g,
        distance_km,
        bound_ms,
    });
    Ok(())
}

/// Write one `traffic` row per counted endpoint (peers, relays, the game's
/// other contacts): rates, running totals, the largest inbound gap, and for
/// wrapped relay endpoints the payload estimate. The STUN counters (running
/// totals) let `nrep%` be recomputed over any interval afterwards.
fn log_traffic(
    traffic: &HashMap<SocketAddrV4, Traffic>,
    side: &SteamSide,
    by_endpoint: &HashMap<SocketAddrV4, SteamId>,
    peers: &HashMap<SteamId, PeerView>,
    matcher: &StunMatcher,
    store: &Store,
    t: i128,
) -> Result<()> {
    for (ep, tr) in traffic {
        let owner = by_endpoint.get(ep).copied();
        let role = match owner.and_then(|id| peers.get(&id)) {
            Some(v) if v.is_relay_endpoint(ep) => Some(Role::of(stun_like(ep, traffic, side))),
            _ => None,
        };
        let role_str = match (role, owner) {
            (Some(r), _) => r.as_str(),
            (None, Some(_)) => "peer",
            (None, None) => "game",
        };
        let (pps_in, pps_out) = ep_rates(ep, traffic, side, t);
        store.insert_traffic(&TrafficRow {
            t_ns: t,
            steam_id: owner,
            remote: *ep,
            role: role_str,
            pps_in,
            pps_out,
            pkts_in: tr.pkts_in,
            pkts_out: tr.pkts_out,
            bytes_in: tr.bytes_in,
            bytes_out: tr.bytes_out,
            payload: role.and_then(|r| {
                relay::payload_estimate(r, tr.bytes_in, tr.pkts_in, tr.bytes_out, tr.pkts_out)
            }),
            max_gap_in_ms: tr.max_gap_in_ns as f64 / 1e6,
            jit_in: stream_stats(&tr.jit_in),
            jit_out: stream_stats(&tr.jit_out),
            stun: matcher.counters(ep),
        })?;
    }
    Ok(())
}

/// A stream's jitter, size and period for the log, once it has a value.
fn stream_stats(j: &StreamJitter) -> Option<StreamStats> {
    Some(StreamStats {
        jitter_ms: j.jitter_ms()?,
        size: j.size()?,
        period_ms: j.period_ms()?,
    })
}

/// The packet-selection rule described on [`drain_etw`], as a pure function
/// so it can be unit-tested: steam.exe packets count only for known peer
/// endpoints; the game's packets always count; everything else is ignored.
fn counts_packet(
    pid: u32,
    remote: SocketAddrV4,
    game_pid: u32,
    steam_pid: u32,
    by_endpoint: &HashMap<SocketAddrV4, SteamId>,
) -> bool {
    if pid == steam_pid {
        by_endpoint.contains_key(&remote)
    } else {
        pid == game_pid
    }
}

#[allow(clippy::too_many_arguments)]
/// Process every ETW event waiting in the channel (non-blocking).
///
/// `try_recv()` returns immediately: `Ok(event)` if one is queued, `Err` when
/// the queue is empty, which ends the `while let` loop. For each event:
/// decode it with the calibrated byte order, update packet counters, feed the
/// STUN matcher, and if that completes an RTT sample, store it and add it
/// to the peer's rolling statistics.
///
/// Which packets count:
/// - **steam.exe**: only packets to or from an endpoint Steam reports for a
///   live peer. The Steam client sends and receives the game's P2P traffic
///   (STUN checks included), but it also talks to Valve's servers, friends
///   chat and so on, which must stay out of the table.
/// - **the game**: every packet, so its other contacts (e.g. matchmaking
///   servers) still appear in the "unattributed" list.
/// - **steam.exe's other packets** go to `side` instead: that's where a
///   relayed peer's traffic shows up until its relay endpoint is attributed
///   (see `relay.rs`), and RTT samples there are kept per endpoint.
/// - anything else (this program's calibration packets): ignored.
fn drain_etw(
    t: &etw::UdpTrace,
    bo: ByteOrder,
    game_pid: u32,
    steam_pid: u32,
    sizes: (u32, u32),
    matcher: &mut StunMatcher,
    traffic: &mut HashMap<SocketAddrV4, Traffic>,
    side: &mut SteamSide,
    by_endpoint: &HashMap<SocketAddrV4, SteamId>,
    peers: &mut HashMap<SteamId, PeerView>,
    store: &Store,
) -> Result<()> {
    while let Ok(raw) = t.rx.try_recv() {
        let d = bo.decode(&raw);
        let counted = counts_packet(raw.pid, d.remote, game_pid, steam_pid, by_endpoint);
        let steam_other = !counted && raw.pid == steam_pid;
        if !counted && !steam_other {
            continue;
        }
        let map = if counted {
            &mut *traffic
        } else {
            &mut side.traffic
        };
        let tr = map.entry(d.remote).or_default();
        match d.dir {
            Direction::Send => {
                tr.pkts_out += 1;
                tr.bytes_out += d.size as u64;
                tr.rate_out.push(d.t_ns);
                tr.jit_out.observe(d.size, d.t_ns);
                tr.saw_req |= d.size == sizes.0;
            }
            Direction::Recv => {
                tr.pkts_in += 1;
                tr.bytes_in += d.size as u64;
                tr.rate_in.push(d.t_ns);
                tr.jit_in.observe(d.size, d.t_ns);
                tr.saw_reply |= d.size == sizes.1;
                if tr.last_in_ns != 0 {
                    tr.max_gap_in_ns = tr.max_gap_in_ns.max(d.t_ns - tr.last_in_ns);
                }
                tr.last_in_ns = d.t_ns;
            }
        }
        if let Some(m) = matcher.observe(&d) {
            let sample = RttSample {
                t_ns: m.t_ns,
                rtt_ms: m.rtt_ms,
                source: RttSource::EtwStun,
            };
            let id = if counted {
                by_endpoint.get(&m.remote).copied()
            } else {
                None
            };
            store.insert_rtt(id, m.remote, &sample)?;
            match id.and_then(|id| peers.get_mut(&id)) {
                Some(view) => view.rtt.push(m.rtt_ms),
                None if steam_other => side
                    .rtt
                    .entry(m.remote)
                    .or_insert_with(|| Rolling::new(side.window))
                    .push(m.rtt_ms),
                None => {}
            }
        }
    }
    Ok(())
}

/// Look up a peer's location once and store it, computing the distance and
/// speed-of-light bound if the user gave their own coordinates. Private and
/// LAN addresses are skipped (GeoIP can't place them).
/// `let Some(db) = geodb else { return Ok(()) };` is *let-else*: bind the
/// value if present, otherwise leave the function early.
fn locate(
    view: &mut PeerView,
    id: SteamId,
    remote: SocketAddrV4,
    geodb: Option<&GeoDb>,
    home: Option<LatLon>,
    store: &Store,
) -> Result<()> {
    let ip = IpAddr::V4(*remote.ip());
    // Remember the address even if the lookup finds nothing, so it isn't
    // retried on every poll; a new address triggers a new lookup.
    view.geo_ip = Some(*remote.ip());
    view.geo = None;
    view.distance_km = None;
    view.bound_ms = None;
    let Some(db) = geodb else { return Ok(()) };
    if geo::is_non_public(ip) {
        return Ok(());
    }
    if let Some(g) = db.lookup(ip) {
        if let (Some(h), Some(loc)) = (home, g.location) {
            let d = geo::great_circle_km(h, loc);
            view.distance_km = Some(d);
            view.bound_ms = Some(geo::fiber_rtt_lower_bound_ms(d));
        }
        store.upsert_geo(
            id,
            GeoSubject::Peer,
            &GeoRow {
                country: g.country.as_deref(),
                city: g.city.as_deref(),
                lat: g.location.map(|l| l.lat),
                lon: g.location.map(|l| l.lon),
                accuracy_km: g.accuracy_km,
                distance_km: view.distance_km,
                fiber_bound_ms: view.bound_ms,
                site: None,
            },
        )?;
        view.geo = Some(g);
    }
    Ok(())
}

/// Format an optional number with `prec` decimals, or "-" when unknown.
/// `{x:.prec$}` takes the precision from the variable `prec`.
fn opt(v: Option<f64>, prec: usize) -> String {
    v.map(|x| format!("{x:.prec$}"))
        .unwrap_or_else(|| "-".into())
}

#[allow(clippy::too_many_arguments)]
/// Redraw the live table.
///
/// The whole screen is built into one `String` and printed at once, which
/// avoids flicker. `\x1b[2J\x1b[H` is the ANSI escape sequence for "clear
/// screen, move cursor to top-left".
///
/// Below the peer table it lists, for relayed peers, the relay server and
/// each relay endpoint; then "unattributed" endpoints: addresses the game
/// exchanges packets with that no Steam session claims (matchmaking servers,
/// or peers missing from the coplay list).
fn draw(
    peers: &HashMap<SteamId, PeerView>,
    current: &[SteamId],
    traffic: &HashMap<SocketAddrV4, Traffic>,
    side: &SteamSide,
    by_endpoint: &HashMap<SocketAddrV4, SteamId>,
    matcher: &StunMatcher,
    ctx: &RelayCtx<'_>,
    etw_on: bool,
) {
    let det = &ctx.detectors;
    let t_now = now_ns();
    let mut out = String::new();
    out.push_str("\x1b[2J\x1b[H");
    out.push_str("DS3SessionManager - passive monitor (Ctrl+C to stop)\n");
    out.push_str(&format!(
        "RTT/jit/pps/nrep = {} (ETW); cc/km/bound/infl = {} (GeoIP); '-' = {}\n\
         sd/ipdv = RTT variation; jit = RFC 3550 jitter of the player's 12 Hz inbound stream (ms)\n\n",
        Provenance::Measured.as_str(),
        Provenance::Estimated.as_str(),
        Provenance::Unknown.as_str()
    ));
    out.push_str(&format!(
        "{:<17} {:<16} {:<3} {:<5} {:<4} {:<21} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5} {:>5} {:>7} {:>7} {:<6} {:>6} {:>6} {:>5}\n",
        "steam_id", "name", "st", "relay", "via", "remote", "last", "med", "p95", "sd", "ipdv",
        "jit", "nrep%", "pps_in", "pps_out", "cc", "km", "bound", "infl"
    ));
    for id in current {
        let Some(v) = peers.get(id) else { continue };
        let s = v.rtt.summary();
        let st = if v.state.active {
            "A"
        } else if v.state.connecting {
            "C"
        } else {
            "-"
        };
        // For a relayed peer, `remote` is the relay endpoint carrying the
        // checks (where RTT and nrep come from); pps sums every endpoint
        // counted for the peer.
        let stun_ep = v.stun_endpoint(matcher);
        let shown_ep = if v.relay_eps.is_empty() {
            v.state.remote
        } else {
            stun_ep
        };
        let remote = shown_ep
            .map(|r| r.to_string())
            .unwrap_or_else(|| "-".into());
        let relayed = v.evidence.relayed(det);
        let inferred = !v.relay_eps.is_empty() || v.evidence.remote_is_relay(det);
        let relay_col = match (relayed, inferred) {
            (true, true) => "yes*",
            (true, false) => "yes",
            _ => "no",
        };
        let noreply = stun_ep.and_then(|r| {
            let c = matcher.counters(&r);
            (c.requests > 0)
                .then(|| 100.0 * (c.requests.saturating_sub(c.matched)) as f64 / c.requests as f64)
        });
        let eps = v.endpoints();
        let (pin, pout) = if eps.is_empty() {
            (None, None)
        } else {
            let (i, o) = eps.iter().fold((0.0, 0.0), |(i, o), e| {
                let (a, b) = ep_rates(e, traffic, side, t_now);
                (i + a, o + b)
            });
            (Some(i), Some(o))
        };
        let jit = peer_jitter(&eps, traffic, side, t_now);
        // Geo: the player's if known; otherwise the relay's, marked "R:".
        let (cc, km, bound) = match (&v.geo, &v.relay_geo) {
            (Some(g), _) => (
                g.country.clone().unwrap_or_else(|| "-".into()),
                v.distance_km,
                v.bound_ms,
            ),
            (None, Some(r)) => {
                let tag = r
                    .site
                    .map(|p| p.code.to_string())
                    .or_else(|| r.geo.as_ref().and_then(|g| g.country.clone()))
                    .unwrap_or_else(|| "?".into());
                (format!("R:{tag}"), r.distance_km, r.bound_ms)
            }
            (None, None) => ("-".into(), None, None),
        };
        let infl = match (s, v.bound_ms, &v.geo) {
            (Some(s), Some(b), Some(_)) if b > 0.5 => Some(s.median / b),
            _ => None,
        };
        let name: String = v
            .persona
            .clone()
            .unwrap_or_else(|| "?".into())
            .chars()
            .take(16)
            .collect();
        out.push_str(&format!(
            "{:<17} {:<16} {:<3} {:<5} {:<4} {:<21} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5} {:>5} {:>7} {:>7} {:<6} {:>6} {:>6} {:>5}\n",
            id.to_string(),
            name,
            st,
            relay_col,
            v.evidence.letters(),
            remote,
            opt(s.map(|s| s.last), 1),
            opt(s.map(|s| s.median), 1),
            opt(s.map(|s| s.p95), 1),
            opt(s.map(|s| s.stddev), 1),
            opt(s.map(|s| s.ipdv), 1),
            opt(jit, 1),
            opt(noreply, 0),
            opt(pin, 0),
            opt(pout, 0),
            cc,
            opt(km, 0),
            opt(bound, 1),
            opt(infl, 1),
        ));
    }
    if current.is_empty() {
        out.push_str("(no active P2P sessions)\n");
    }
    let shown: Vec<(SteamId, &PeerView)> = current
        .iter()
        .filter_map(|id| peers.get(id).map(|v| (*id, v)))
        .collect();
    let any_relayed = shown.iter().any(|(_, v)| v.evidence.relayed(det));
    if any_relayed {
        out.push_str(&format!(
            "via: relay evidence (F Steam flag, P traffic pattern, A ASN, L Valve list; deciding: {det})\n\
             yes* = relayed, relay endpoints inferred by ds3sm; yes = Steam's flag only, relay not found\n"
        ));
    }
    if shown
        .iter()
        .any(|(_, v)| v.geo.is_none() && v.relay_geo.is_some())
    {
        out.push_str(
            "R:xxx = location of the Valve relay server (site code), NOT the player; km/bound are to the relay\n",
        );
    }

    // Relay details: the relay server and every endpoint counted for the peer.
    for (_, v) in shown.iter().filter(|(_, v)| v.relay_ip.is_some()) {
        let Some(rip) = v.relay_ip else { continue };
        let name = v.persona.clone().unwrap_or_else(|| "?".into());
        let place = match &v.relay_geo {
            Some(r) => {
                let site = r
                    .site
                    .map(|p| {
                        let host = if p.valve_hosted {
                            ""
                        } else {
                            ", partner-hosted"
                        };
                        format!("site {} {}{host}", p.code, p.desc)
                    })
                    .unwrap_or_else(|| "site unknown".into());
                let g = r
                    .geo
                    .as_ref()
                    .map(|g| {
                        format!(
                            "GeoIP {} {}",
                            g.country.as_deref().unwrap_or("?"),
                            g.city.as_deref().unwrap_or("")
                        )
                    })
                    .unwrap_or_default();
                format!("{site}; {g}")
            }
            None => "location unknown".into(),
        };
        out.push_str(&format!(
            "\nRelay for {name}: {rip} ({place}); evidence {}\n",
            v.evidence.log_detail()
        ));
        out.push_str(&format!(
            "  {:<21} {:<8} {:<5} {:>6} {:>6} {:>9} {:>9} {:>11} {:>11}\n",
            "endpoint",
            "role",
            "site",
            "pps_in",
            "out",
            "KB_in",
            "KB_out",
            "payload_in",
            "payload_out"
        ));
        // Every relay endpoint, on any host or site (the two allocations
        // of a relayed session can sit on different relay hosts).
        let mut eps: Vec<SocketAddrV4> = v
            .endpoints()
            .into_iter()
            .filter(|e| v.is_relay_endpoint(e))
            .collect();
        eps.sort();
        for e in eps {
            let (pin, pout) = ep_rates(&e, traffic, side, t_now);
            let (mut bi, mut bo, mut ni, mut no) = (0u64, 0u64, 0u64, 0u64);
            for tr in [traffic.get(&e), side.traffic.get(&e)]
                .into_iter()
                .flatten()
            {
                bi += tr.bytes_in;
                bo += tr.bytes_out;
                ni += tr.pkts_in;
                no += tr.pkts_out;
            }
            let role = Role::of(stun_like(&e, traffic, side));
            let pay = relay::payload_estimate(role, bi, ni, bo, no);
            let kb = |b: u64| format!("{:.1}", b as f64 / 1024.0);
            let tag = if Some(e) == v.state.remote {
                format!("{}(S)", if role == Role::Stun { "stun" } else { "wrap" })
            } else if role == Role::Stun {
                "stun".into()
            } else {
                "wrapped".into()
            };
            let site = valve::site(*e.ip()).map(|p| p.code).unwrap_or("-");
            out.push_str(&format!(
                "  {:<21} {:<8} {:<5} {:>6.0} {:>6.0} {:>9} {:>9} {:>11} {:>11}\n",
                e.to_string(),
                tag,
                site,
                pin,
                pout,
                kb(bi),
                kb(bo),
                pay.map(|p| kb(p.0)).unwrap_or_else(|| "-".into()),
                pay.map(|p| kb(p.1)).unwrap_or_else(|| "-".into()),
            ));
        }
        out.push_str(
            "  (S) = Steam's reported remote; payload = KB minus relay headers (44 B in, 64 B out per packet; estimated)\n",
        );
    }

    if etw_on && any_relayed {
        // Game-rate steam.exe endpoints that no peer claims (e.g. with
        // several relayed peers, whose relay traffic can't be split).
        let mut rows: Vec<(SocketAddrV4, f64, f64)> = side
            .traffic
            .keys()
            .filter(|ep| !by_endpoint.contains_key(ep) && ep.port() != relay::STUN_SERVER_PORT)
            .filter_map(|&ep| {
                let (pin, pout) = ep_rates(&ep, traffic, side, t_now);
                (pin + pout >= relay::MIN_RELAY_PPS).then_some((ep, pin, pout))
            })
            .collect();
        rows.sort_by(|a, b| (b.1 + b.2).total_cmp(&(a.1 + a.2)));
        if !rows.is_empty() {
            out.push_str("\nUnattributed relay-like endpoints (steam.exe, game-rate traffic):\n");
        }
        for (ep, pin, pout) in rows.into_iter().take(5) {
            let s = side.rtt.get(&ep).and_then(|r| r.summary());
            out.push_str(&format!(
                "  {:<21} pps in {:>4.0} out {:>4.0}  RTT med {:>6} p95 {:>6}\n",
                ep.to_string(),
                pin,
                pout,
                opt(s.map(|s| s.median), 1),
                opt(s.map(|s| s.p95), 1),
            ));
        }
    }
    if etw_on {
        // Endpoints the game talks to that no Steam session claims
        // (matchmaking servers, peers missing from the coplay list), with
        // the network that owns each address when the ASN database is loaded.
        let mut other: Vec<(&SocketAddrV4, &Traffic)> = traffic
            .iter()
            .filter(|(ep, _)| !by_endpoint.contains_key(ep))
            .collect();
        other.sort_by_key(|(_, t)| std::cmp::Reverse(t.pkts_in + t.pkts_out));
        if !other.is_empty() {
            out.push_str("\nOther UDP endpoints of the game (unattributed):\n");
            for (ep, t) in other.into_iter().take(6) {
                let owner = ctx
                    .asn
                    .and_then(|db| db.lookup(IpAddr::V4(*ep.ip())))
                    .map(|(n, org)| format!("  AS{n} {}", org.unwrap_or_default()))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "  {:<21} in {:>7} pkts  out {:>7} pkts  max_gap {:>6.0} ms{owner}\n",
                    ep.to_string(),
                    t.pkts_in,
                    t.pkts_out,
                    t.max_gap_in_ns as f64 / 1e6
                ));
            }
        }
    }
    print!("{out}");
}

// ---------------------------------------------------------------------------
// Unit tests: which packets count towards a peer.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const GAME: u32 = 100;
    const STEAM: u32 = 200;

    fn peer_map() -> (SocketAddrV4, HashMap<SocketAddrV4, SteamId>) {
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 15), 61060);
        let mut m = HashMap::new();
        m.insert(peer, SteamId(76561198000000001));
        (peer, m)
    }

    #[test]
    fn steam_packets_count_only_for_known_peers() {
        let (peer, m) = peer_map();
        let valve = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 27019);
        assert!(counts_packet(STEAM, peer, GAME, STEAM, &m));
        assert!(!counts_packet(STEAM, valve, GAME, STEAM, &m));
    }

    #[test]
    fn game_packets_always_count_others_never() {
        let (peer, m) = peer_map();
        let server = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 50003);
        assert!(counts_packet(GAME, server, GAME, STEAM, &m));
        assert!(counts_packet(GAME, peer, GAME, STEAM, &m));
        assert!(!counts_packet(999, peer, GAME, STEAM, &m));
    }

    #[test]
    fn missing_steam_pid_matches_nothing() {
        let (peer, m) = peer_map();
        assert!(!counts_packet(STEAM, peer, GAME, u32::MAX, &m));
    }
}

// ---------------------------------------------------------------------------
// Unit tests: the relay step on synthetic traffic (E1 and E2 layouts).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod relay_step_tests {
    use super::*;

    const T: i128 = 1_000_000_000_000_000;

    fn state(relay: bool, remote: SocketAddrV4) -> P2PState {
        P2PState {
            active: true,
            connecting: false,
            error: 0,
            using_relay: relay,
            bytes_queued: 0,
            packets_queued: 0,
            remote: Some(remote),
        }
    }

    /// Traffic at `pin`/`pout` packets/s over the 10 s before `T`.
    fn tr(pin: i128, pout: i128, stun: bool) -> Traffic {
        let mut t = Traffic {
            saw_req: stun,
            saw_reply: stun,
            ..Default::default()
        };
        for i in 0..(10 * pin) {
            t.rate_in.push(T - 10_000_000_000 + i * 1_000_000_000 / pin);
            t.pkts_in += 1;
            t.bytes_in += 129;
        }
        for i in 0..(10 * pout) {
            t.rate_out
                .push(T - 10_000_000_000 + i * 1_000_000_000 / pout);
            t.pkts_out += 1;
        }
        t
    }

    struct Rig {
        peers: HashMap<SteamId, PeerView>,
        by_endpoint: HashMap<SocketAddrV4, SteamId>,
        traffic: HashMap<SocketAddrV4, Traffic>,
        side: SteamSide,
        store: Store,
        dir: std::path::PathBuf,
    }

    impl Rig {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("ds3sm-relay-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let store = Store::open(&dir.join("run.sqlite")).unwrap();
            Rig {
                peers: HashMap::new(),
                by_endpoint: HashMap::new(),
                traffic: HashMap::new(),
                side: SteamSide {
                    traffic: HashMap::new(),
                    rtt: HashMap::new(),
                    window: 20,
                },
                store,
                dir,
            }
        }

        /// Register live peers as the poll loop does, then run the relay step.
        fn step(&mut self, active: &[(SteamId, P2PState)], det: &str) {
            for (id, st) in active {
                self.peers
                    .entry(*id)
                    .or_insert_with(|| PeerView::new(st.clone(), 20))
                    .state = st.clone();
                if let Some(r) = st.remote {
                    self.by_endpoint.insert(r, *id);
                }
            }
            let ctx = RelayCtx {
                detectors: det.parse().unwrap(),
                asn: None,
                geodb: None,
                home: Some(LatLon {
                    lat: 48.4,
                    lon: -123.4,
                }),
            };
            update_relays(
                active,
                &mut self.peers,
                &mut self.by_endpoint,
                &mut self.traffic,
                &self.side,
                &ctx,
                &self.store,
                T,
            )
            .unwrap();
        }

        fn events(&self, kind: &str) -> Vec<String> {
            let mut q = self
                .store
                .conn_for_tests()
                .prepare("SELECT detail FROM event WHERE kind = ?1 ORDER BY rowid")
                .unwrap();
            q.query_map([kind], |r| r.get(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A host in the Seattle relay site's /24 (not a real relay address).
    fn relay(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(205, 196, 6, 1), port)
    }

    #[test]
    fn e2_layout_attributes_the_wrapped_sibling_and_places_the_relay() {
        let mut r = Rig::new("e2");
        let id = SteamId(1);
        // Steam: "not relayed", remote = relay :4379 (sends + STUN replies).
        r.traffic.insert(relay(4379), tr(2, 33, true));
        // The other player's traffic, wrapped, from :4380 (not yet claimed).
        r.side.traffic.insert(relay(4380), tr(18, 2, false));
        r.step(&[(id, state(false, relay(4379)))], "F,P,A,L");

        let v = &r.peers[&id];
        assert_eq!(
            v.evidence,
            Evidence {
                flag: false,
                pattern: true,
                asn: None,
                list: true
            }
        );
        assert!(v.evidence.relayed(&Detectors::ALL));
        assert_eq!(v.relay_ip, Some(*relay(0).ip()));
        assert_eq!(v.relay_eps, vec![relay(4380)]);
        assert_eq!(r.by_endpoint.get(&relay(4380)), Some(&id));
        let g = v.relay_geo.as_ref().unwrap();
        assert_eq!(g.site.map(|p| p.code), Some("sea"));
        assert!(g.distance_km.unwrap() > 50.0); // Victoria to Seattle site
        assert_eq!(v.endpoints(), vec![relay(4379), relay(4380)]);
        assert_eq!(
            r.events("relay_attributed"),
            vec![format!("1 {}", relay(4380))]
        );
        assert_eq!(
            r.events("relay_evidence"),
            vec![format!(
                "1 F=0 P=1 A=? L=1 relayed=1 remote={}",
                relay(4379)
            )]
        );
        // A second identical poll logs nothing new.
        r.step(&[(id, state(false, relay(4379)))], "F,P,A,L");
        assert_eq!(r.events("relay_evidence").len(), 1);
        assert_eq!(r.events("relay_attributed").len(), 1);
    }

    #[test]
    fn pattern_alone_is_enough_when_it_is_the_only_detector() {
        let mut r = Rig::new("ponly");
        let id = SteamId(1);
        r.traffic.insert(relay(4379), tr(2, 33, true));
        r.side.traffic.insert(relay(4380), tr(18, 2, false));
        r.step(&[(id, state(false, relay(4379)))], "P");
        assert_eq!(r.peers[&id].relay_eps, vec![relay(4380)]);
        // With only F deciding, the same evidence isn't a relay.
        let mut r = Rig::new("fonly");
        r.traffic.insert(relay(4379), tr(2, 33, true));
        r.side.traffic.insert(relay(4380), tr(18, 2, false));
        r.step(&[(id, state(false, relay(4379)))], "F");
        assert!(r.peers[&id].relay_eps.is_empty());
        assert!(r.peers[&id].relay_ip.is_none());
    }

    /// Test 3b layout: Steam's remote on one relay host, the wrapped inbound
    /// on another host at the same site.
    #[test]
    fn e2_layout_across_two_relay_hosts() {
        let mut r = Rig::new("twohost");
        let id = SteamId(1);
        let other_host = SocketAddrV4::new(Ipv4Addr::new(205, 196, 6, 2), 4380);
        r.traffic.insert(relay(4379), tr(2, 33, true));
        r.side.traffic.insert(other_host, tr(18, 2, false));
        r.step(&[(id, state(false, relay(4379)))], "F,P,A,L");
        let v = &r.peers[&id];
        assert_eq!(v.evidence.letters(), "PL");
        assert_eq!(v.relay_eps, vec![other_host]);
        assert_eq!(v.relay_ip, Some(*relay(0).ip())); // the RTT-carrying host
        assert!(v.is_relay_endpoint(&relay(4379)) && v.is_relay_endpoint(&other_host));
        // P alone (no lists) finds it too.
        let mut r = Rig::new("twohost-p");
        r.traffic.insert(relay(4379), tr(2, 33, true));
        r.side.traffic.insert(other_host, tr(18, 2, false));
        r.step(&[(id, state(false, relay(4379)))], "P");
        assert_eq!(r.peers[&id].relay_eps, vec![other_host]);
    }

    /// A direct peer next to a relayed one: the direct peer's endpoint is
    /// never taken, and only the relayed peer gets relay endpoints.
    #[test]
    fn direct_peer_next_to_a_relayed_one() {
        let mut r = Rig::new("mixed");
        let lan = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 15), 58864);
        r.traffic.insert(lan, tr(19, 37, true));
        r.traffic.insert(relay(4379), tr(2, 33, true));
        r.side.traffic.insert(relay(4380), tr(18, 2, false));
        r.step(
            &[
                (SteamId(1), state(false, lan)),
                (SteamId(2), state(false, relay(4379))),
            ],
            "F,P,A,L",
        );
        assert!(r.peers[&SteamId(1)].relay_eps.is_empty());
        assert_eq!(r.peers[&SteamId(2)].relay_eps, vec![relay(4380)]);
        assert_eq!(r.by_endpoint.get(&lan), Some(&SteamId(1)));
    }

    #[test]
    fn two_peers_on_one_relay_ip_share_nothing() {
        let mut r = Rig::new("two");
        r.traffic.insert(relay(4379), tr(2, 33, true));
        r.traffic.insert(relay(4381), tr(2, 33, true));
        r.side.traffic.insert(relay(4380), tr(36, 4, false));
        r.step(
            &[
                (SteamId(1), state(false, relay(4379))),
                (SteamId(2), state(false, relay(4381))),
            ],
            "F,P,A,L",
        );
        for id in [SteamId(1), SteamId(2)] {
            assert!(r.peers[&id].relay_eps.is_empty(), "{id}");
            assert!(r.peers[&id].evidence.relayed(&Detectors::ALL));
        }
        assert!(!r.by_endpoint.contains_key(&relay(4380)));
    }

    #[test]
    fn direct_lan_peer_is_not_a_relay() {
        let mut r = Rig::new("lan");
        let id = SteamId(1);
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 15), 58864);
        r.traffic.insert(peer, tr(19, 37, true));
        r.step(&[(id, state(false, peer))], "F,P,A,L");
        let v = &r.peers[&id];
        assert_eq!(v.evidence, Evidence::default());
        assert!(v.relay_ip.is_none() && v.relay_eps.is_empty() && v.relay_geo.is_none());
    }

    #[test]
    fn e1_layout_finds_the_relay_from_traffic() {
        let mut r = Rig::new("e1");
        let id = SteamId(1);
        // Steam: relayed, remote = the player's public IP (no packets go there).
        let public = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 27015);
        r.side.traffic.insert(relay(4380), tr(23, 43, true));
        r.step(&[(id, state(true, public))], "F,P,A,L");
        let v = &r.peers[&id];
        assert_eq!(v.evidence.letters(), "F");
        assert_eq!(v.relay_ip, Some(*relay(0).ip()));
        assert_eq!(v.relay_eps, vec![relay(4380)]);
        // The relay is placed; the player's address isn't touched here.
        assert!(v.relay_geo.is_some());
        // Peer leaves: attribution removed and logged.
        r.step(&[], "F,P,A,L");
        assert!(r.peers[&id].relay_eps.is_empty());
        assert!(!r.by_endpoint.contains_key(&relay(4380)));
        assert_eq!(
            r.events("relay_unattributed"),
            vec![format!("1 {}", relay(4380))]
        );
    }
}

#[cfg(test)]
mod rate_tests {
    use super::*;

    /// 40 packets/s for 10 s; the window ends 1.5 s before "now".
    #[test]
    fn steady_rate_is_measured_from_kernel_timestamps() {
        let mut w = RateWindow::default();
        let start = 1_000_000_000_000i128;
        for i in 0..400 {
            w.push(start + i * 25_000_000);
        }
        let now = start + 10_000_000_000;
        let r = w.rate(now);
        assert!((r - 40.0).abs() < 0.5, "rate {r}");
    }

    /// Delivery timing doesn't matter: the same packets give the same rate
    /// whether "now" is checked right after a batch or just before the next.
    #[test]
    fn rate_ignores_batch_delivery() {
        let mut w = RateWindow::default();
        let start = 1_000_000_000_000i128;
        for i in 0..400 {
            w.push(start + i * 25_000_000);
        }
        let a = w.rate(start + 9_000_000_000);
        let b = w.rate(start + 9_500_000_000);
        assert!((a - b).abs() < 0.5, "{a} vs {b}");
    }

    #[test]
    fn rate_falls_to_zero_after_traffic_stops() {
        let mut w = RateWindow::default();
        let start = 1_000_000_000_000i128;
        for i in 0..40 {
            w.push(start + i * 25_000_000);
        }
        assert_eq!(w.rate(start + 20_000_000_000), 0.0);
    }
}
