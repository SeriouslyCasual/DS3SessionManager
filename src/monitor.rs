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
use std::net::{IpAddr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::MonitorArgs;
use crate::etw::{self, ByteOrder};
use crate::geo::{self, GeoDb, GeoInfo, LatLon};
use crate::model::{P2PState, Provenance, RttSample, RttSource, SteamId};
use crate::relay;
use crate::stats::Rolling;
use crate::steam::Steam;
use crate::store::{GeoRow, Store};
use crate::stun::{Direction, StunConfig, StunMatcher};
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
pub fn probe(geo_path: &Path) -> Result<()> {
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

/// Everything the monitor remembers about one peer between polls.
struct PeerView {
    persona: Option<String>,
    state: P2PState,
    rtt: Rolling,
    geo: Option<GeoInfo>,
    distance_km: Option<f64>,
    bound_ms: Option<f64>,
    last_logged_state: Option<P2PState>,
    /// For a relayed peer: the Valve relay endpoint inferred to carry its
    /// traffic (`relay.rs`). `None` for direct peers or when not inferable.
    relay_ep: Option<SocketAddrV4>,
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
        // the in-memory view, log the state only if it changed, remember which
        // endpoint belongs to them, and geolocate once. Relayed peers are skipped,
        // because a relay's IP says nothing about where the player is.
        // `or_insert_with(|| ...)` only builds the default `PeerView` when
        // the peer is new.
        let active = steam.active_peers();
        for (id, st) in &active {
            let persona = steam.persona(*id);
            store.upsert_peer(*id, persona.as_deref(), t)?;
            let view = peers.entry(*id).or_insert_with(|| PeerView {
                persona: None,
                state: st.clone(),
                rtt: Rolling::new(args.window),
                geo: None,
                distance_km: None,
                bound_ms: None,
                last_logged_state: None,
                relay_ep: None,
            });
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
                if view.geo.is_none() && !st.using_relay {
                    locate(view, *id, remote, geodb.as_ref(), home, &store)?;
                }
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

        // 4. Relayed peers: infer which relay endpoint carries the traffic.
        attribute_relay(
            &active,
            &mut peers,
            &mut by_endpoint,
            &mut traffic,
            &side,
            &store,
            t,
        )?;

        if !args.quiet {
            draw(
                &peers,
                &current,
                &traffic,
                &side,
                &by_endpoint,
                &matcher,
                trace.is_some(),
            );
        }
    }
    store.event(now_ns(), "stop", "")?;
    println!("run saved to {}", db_path.display());
    Ok(())
}

/// Re-evaluate the relay attribution after each Steam poll (rule in
/// `relay.rs`). When the chosen endpoint changes, the old one is removed from
/// `by_endpoint` and the new one added, so from then on its packets count
/// for the peer (pps, STUN RTT) exactly like a direct peer's. Each change is
/// logged as a `relay_attributed` / `relay_unattributed` event.
fn attribute_relay(
    active: &[(SteamId, P2PState)],
    peers: &mut HashMap<SteamId, PeerView>,
    by_endpoint: &mut HashMap<SocketAddrV4, SteamId>,
    traffic: &mut HashMap<SocketAddrV4, Traffic>,
    side: &SteamSide,
    store: &Store,
    t: i128,
) -> Result<()> {
    let relayed: Vec<SteamId> = active
        .iter()
        .filter(|(_, st)| st.using_relay)
        .map(|(id, _)| *id)
        .collect();
    let claimed: HashSet<SocketAddrV4> = active
        .iter()
        .filter(|(_, st)| !st.using_relay)
        .filter_map(|(_, st)| st.remote)
        .collect();
    // Candidates: steam.exe's unclaimed endpoints, plus any endpoint already
    // attributed (its packets now land in `traffic`, so rates sum both maps).
    let mut keys: HashSet<SocketAddrV4> = side.traffic.keys().copied().collect();
    keys.extend(peers.values().filter_map(|v| v.relay_ep));
    let candidates: Vec<relay::Candidate> = keys
        .into_iter()
        .map(|ep| {
            let (pin, pout) = ep_rates(&ep, traffic, side, t);
            let stun_like = [traffic.get(&ep), side.traffic.get(&ep)]
                .into_iter()
                .flatten()
                .any(|tr| tr.saw_req && tr.saw_reply);
            relay::Candidate {
                ep,
                pps: pin + pout,
                stun_like,
            }
        })
        .collect();
    let chosen = relay::pick(relayed.len(), &candidates, &claimed);
    for (id, view) in peers.iter_mut() {
        let want = match (relayed.first(), chosen) {
            (Some(r), Some(ep)) if r == id => Some(ep),
            _ => None,
        };
        if view.relay_ep == want {
            continue;
        }
        if let Some(old) = view.relay_ep {
            by_endpoint.remove(&old);
            // Its counters were steam.exe's, not the game's: drop them so the
            // relay never shows up in the game's "unattributed" list.
            traffic.remove(&old);
        }
        match want {
            Some(ep) => {
                by_endpoint.insert(ep, *id);
                store.event(t, "relay_attributed", &format!("{id} {ep}"))?;
            }
            None => store.event(t, "relay_unattributed", &id.to_string())?,
        }
        view.relay_ep = want;
    }
    Ok(())
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
                tr.saw_req |= d.size == sizes.0;
            }
            Direction::Recv => {
                tr.pkts_in += 1;
                tr.bytes_in += d.size as u64;
                tr.rate_in.push(d.t_ns);
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
            &GeoRow {
                country: g.country.as_deref(),
                city: g.city.as_deref(),
                lat: g.location.map(|l| l.lat),
                lon: g.location.map(|l| l.lon),
                accuracy_km: g.accuracy_km,
                distance_km: view.distance_km,
                fiber_bound_ms: view.bound_ms,
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
/// Below the peer table it lists "unattributed" endpoints: addresses the game
/// exchanges packets with that no Steam session claims (relays, matchmaking
/// servers, or peers missing from the coplay list).
fn draw(
    peers: &HashMap<SteamId, PeerView>,
    current: &[SteamId],
    traffic: &HashMap<SocketAddrV4, Traffic>,
    side: &SteamSide,
    by_endpoint: &HashMap<SocketAddrV4, SteamId>,
    matcher: &StunMatcher,
    etw_on: bool,
) {
    let t_now = now_ns();
    let mut out = String::new();
    out.push_str("\x1b[2J\x1b[H");
    out.push_str("DS3SessionManager - passive monitor (Ctrl+C to stop)\n");
    out.push_str(&format!(
        "RTT/pps/nrep = {} (ETW); cc/km/bound/infl = {} (GeoIP); '-' = {}\n\n",
        Provenance::Measured.as_str(),
        Provenance::Estimated.as_str(),
        Provenance::Unknown.as_str()
    ));
    out.push_str(&format!(
        "{:<17} {:<16} {:<3} {:<5} {:<21} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5} {:>7} {:>7} {:<3} {:>6} {:>6} {:>5}\n",
        "steam_id", "name", "st", "relay", "remote", "last", "med", "p95", "sd", "ipdv", "nrep%",
        "pps_in", "pps_out", "cc", "km", "bound", "infl"
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
        // For a relayed peer with an inferred relay endpoint, everything
        // measured (remote, pps, RTT, nrep) refers to that relay endpoint.
        let ep = v.relay_ep.or(v.state.remote);
        let remote = ep.map(|r| r.to_string()).unwrap_or_else(|| "-".into());
        let relay_col = match (v.relay_ep, v.state.using_relay) {
            (Some(_), _) => "yes*",
            (None, true) => "yes",
            (None, false) => "no",
        };
        let (pin, pout, noreply) = match ep {
            Some(r) => {
                let c = matcher.counters(&r);
                let nr = (c.requests > 0).then(|| {
                    100.0 * (c.requests.saturating_sub(c.matched)) as f64 / c.requests as f64
                });
                let (pin, pout) = ep_rates(&r, traffic, side, t_now);
                (Some(pin), Some(pout), nr)
            }
            None => (None, None, None),
        };
        let infl = match (s, v.bound_ms) {
            (Some(s), Some(b)) if b > 0.5 => Some(s.median / b),
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
            "{:<17} {:<16} {:<3} {:<5} {:<21} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5} {:>7} {:>7} {:<3} {:>6} {:>6} {:>5}\n",
            id.to_string(),
            name,
            st,
            relay_col,
            remote,
            opt(s.map(|s| s.last), 1),
            opt(s.map(|s| s.median), 1),
            opt(s.map(|s| s.p95), 1),
            opt(s.map(|s| s.stddev), 1),
            opt(s.map(|s| s.ipdv), 1),
            opt(noreply, 0),
            opt(pin, 0),
            opt(pout, 0),
            v.geo.as_ref().and_then(|g| g.country.clone()).unwrap_or_else(|| "-".into()),
            opt(v.distance_km, 0),
            opt(v.bound_ms, 1),
            opt(infl, 1),
        ));
    }
    if current.is_empty() {
        out.push_str("(no active P2P sessions)\n");
    }
    let shown: Vec<&PeerView> = current.iter().filter_map(|id| peers.get(id)).collect();
    if shown.iter().any(|v| v.relay_ep.is_some()) {
        out.push_str(
            "yes* = relayed; remote/RTT/pps are on the Valve relay endpoint inferred from steam.exe traffic\n",
        );
    }
    let relayed_unknown = shown
        .iter()
        .any(|v| v.state.using_relay && v.relay_ep.is_none());
    if relayed_unknown {
        out.push_str(
            "yes  = relayed; Steam reports the peer's public address, not the relay; no relay endpoint inferred\n",
        );
    }
    if etw_on && shown.iter().any(|v| v.state.using_relay) {
        // steam.exe endpoints that look like a game session through a relay
        // (game-rate traffic with request/reply-sized packets).
        let mut keys: HashSet<SocketAddrV4> = side.traffic.keys().copied().collect();
        keys.extend(shown.iter().filter_map(|v| v.relay_ep));
        let mut rows: Vec<(SocketAddrV4, f64, f64)> = keys
            .into_iter()
            .filter_map(|ep| {
                let (pin, pout) = ep_rates(&ep, traffic, side, t_now);
                let stun_like = [traffic.get(&ep), side.traffic.get(&ep)]
                    .into_iter()
                    .flatten()
                    .any(|tr| tr.saw_req && tr.saw_reply);
                let c = relay::Candidate {
                    ep,
                    pps: pin + pout,
                    stun_like,
                };
                c.looks_like_game().then_some((ep, pin, pout))
            })
            .collect();
        rows.sort_by(|a, b| (b.1 + b.2).total_cmp(&(a.1 + a.2)));
        out.push_str("\nRelay endpoints (steam.exe, game-rate traffic):\n");
        if rows.is_empty() {
            out.push_str("  none yet\n");
        }
        for (ep, pin, pout) in rows.into_iter().take(5) {
            let owner = by_endpoint.get(&ep).and_then(|id| peers.get(id));
            let s = match owner {
                Some(v) => v.rtt.summary(),
                None => side.rtt.get(&ep).and_then(|r| r.summary()),
            };
            let who = owner
                .and_then(|v| v.persona.clone())
                .map(|n| format!("-> {n}"))
                .unwrap_or_else(|| "(not attributed)".into());
            out.push_str(&format!(
                "  {:<21} pps in {:>4.0} out {:>4.0}  RTT med {:>6} p95 {:>6}  {}\n",
                ep.to_string(),
                pin,
                pout,
                opt(s.map(|s| s.median), 1),
                opt(s.map(|s| s.p95), 1),
                who
            ));
        }
    }
    if etw_on {
        // Endpoints the game talks to that no Steam session claims
        // (relays, matchmaking servers, peers missing from the coplay list).
        let mut other: Vec<(&SocketAddrV4, &Traffic)> = traffic
            .iter()
            .filter(|(ep, _)| !by_endpoint.contains_key(ep))
            .collect();
        other.sort_by_key(|(_, t)| std::cmp::Reverse(t.pkts_in + t.pkts_out));
        if !other.is_empty() {
            out.push_str("\nOther UDP endpoints of the game (unattributed):\n");
            for (ep, t) in other.into_iter().take(6) {
                out.push_str(&format!(
                    "  {:<21} in {:>7} pkts  out {:>7} pkts  max_gap {:>6.0} ms\n",
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
