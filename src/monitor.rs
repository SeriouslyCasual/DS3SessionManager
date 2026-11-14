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

use std::collections::HashMap;
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
    match Steam::init() {
        Ok(mut s) => {
            s.run_callbacks();
            println!("  Steam: ok, local id {}", s.local_id());
            let coplay = s.coplay_list();
            println!("  coplay list: {} entries", coplay.len());
            let peers = s.active_peers();
            println!("  active/connecting P2P sessions: {}", peers.len());
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
        match etw::start().and_then(|t| etw::calibrate(&t).map(|(bo, _)| bo)) {
            Ok(bo) => println!("  ETW kernel UDP trace: ok, byte order {bo:?}"),
            Err(e) => println!("  ETW kernel UDP trace: {e:#}"),
        }
    } else {
        println!("  ETW kernel UDP trace: skipped (needs administrator)");
    }
    Ok(())
}

/// Per-remote-endpoint traffic counters (all packet sizes, not just STUN).
#[derive(Default, Clone, Copy)]
// Plain counters per remote endpoint, updated for every packet of the game's.
// `#[derive(Default)]` makes `Traffic::default()` all zeros, which lets the
// entry API create it on first sight (`.or_default()`).
struct Traffic {
    pkts_out: u64,
    pkts_in: u64,
    bytes_out: u64,
    bytes_in: u64,
    last_in_ns: i128,
    /// Largest gap between received packets, ns (a stall indicator).
    max_gap_in_ns: i128,
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

    // Step 5.
    let mut steam = Steam::init()?;
    store.set_meta("local_steam_id", &steam.local_id().to_string())?;

    // Step 6. Both branches of the `if` produce a tuple of two `Option`s, so
    // `--no-etw` simply leaves both as `None`.
    let (trace, byte_order) = if args.no_etw {
        (None, None)
    } else {
        let t = etw::start()?;
        let (bo, _) = etw::calibrate(&t)?;
        store.event(now_ns(), "etw_byte_order", &format!("{bo:?}"))?;
        t.game_pid.store(game_pid, Ordering::Relaxed);
        (Some(t), Some(bo))
    };

    // Loop state. The maps are keyed so the code can join Steam's view and ETW's view:
    //   peers:       SteamId  → what is known about that player
    //   by_endpoint: IP:port  → SteamId (filled from Steam, read when ETW
    //                gives an RTT for an endpoint)
    //   traffic:     IP:port  → packet counters (prev_traffic = last poll's
    //                copy, used to compute packets/second)
    let mut matcher = StunMatcher::new(StunConfig {
        request_size: args.req_size,
        reply_size: args.reply_size,
        ..Default::default()
    });
    let mut peers: HashMap<SteamId, PeerView> = HashMap::new();
    let mut by_endpoint: HashMap<SocketAddrV4, SteamId> = HashMap::new();
    let mut traffic: HashMap<SocketAddrV4, Traffic> = HashMap::new();
    let mut prev_traffic: HashMap<SocketAddrV4, Traffic> = HashMap::new();
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
                &mut matcher,
                &mut traffic,
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

        if !args.quiet {
            draw(
                &peers,
                &current,
                &traffic,
                &prev_traffic,
                &by_endpoint,
                &matcher,
                interval,
                trace.is_some(),
            );
        }
        prev_traffic = traffic.clone();
    }
    store.event(now_ns(), "stop", "")?;
    println!("run saved to {}", db_path.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// Process every ETW event waiting in the channel (non-blocking).
///
/// `try_recv()` returns immediately: `Ok(event)` if one is queued, `Err` when
/// the queue is empty, which ends the `while let` loop. For each event:
/// decode it with the calibrated byte order, update packet counters, feed the
/// STUN matcher, and if that completes an RTT sample, store it and add it
/// to the peer's rolling statistics.
fn drain_etw(
    t: &etw::UdpTrace,
    bo: ByteOrder,
    game_pid: u32,
    matcher: &mut StunMatcher,
    traffic: &mut HashMap<SocketAddrV4, Traffic>,
    by_endpoint: &HashMap<SocketAddrV4, SteamId>,
    peers: &mut HashMap<SteamId, PeerView>,
    store: &Store,
) -> Result<()> {
    while let Ok(raw) = t.rx.try_recv() {
        if raw.pid != game_pid {
            continue; // calibration traffic from this process
        }
        let d = bo.decode(&raw);
        let tr = traffic.entry(d.remote).or_default();
        match d.dir {
            Direction::Send => {
                tr.pkts_out += 1;
                tr.bytes_out += d.size as u64;
            }
            Direction::Recv => {
                tr.pkts_in += 1;
                tr.bytes_in += d.size as u64;
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
            let id = by_endpoint.get(&m.remote).copied();
            store.insert_rtt(id, m.remote, &sample)?;
            if let Some(view) = id.and_then(|id| peers.get_mut(&id)) {
                view.rtt.push(m.rtt_ms);
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
    prev: &HashMap<SocketAddrV4, Traffic>,
    by_endpoint: &HashMap<SocketAddrV4, SteamId>,
    matcher: &StunMatcher,
    interval: Duration,
    etw_on: bool,
) {
    let secs = interval.as_secs_f64();
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
        let remote = v
            .state
            .remote
            .map(|r| r.to_string())
            .unwrap_or_else(|| "-".into());
        let (pin, pout, noreply) = match v.state.remote {
            Some(r) => {
                let now = traffic.get(&r).copied().unwrap_or_default();
                let before = prev.get(&r).copied().unwrap_or_default();
                let c = matcher.counters(&r);
                let nr = (c.requests > 0).then(|| {
                    100.0 * (c.requests.saturating_sub(c.matched)) as f64 / c.requests as f64
                });
                (
                    Some((now.pkts_in - before.pkts_in) as f64 / secs),
                    Some((now.pkts_out - before.pkts_out) as f64 / secs),
                    nr,
                )
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
            if v.state.using_relay { "yes" } else { "no" },
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
