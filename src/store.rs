//! Per-run SQLite logging and anonymized CSV export.
//!
//! # Why SQLite?
//!
//! SQLite is a whole database in a single file: no server to install, safe
//! against crashes, and easy to query later from Python (`sqlite3`, `pandas`)
//! to make graphs. The `rusqlite` crate wraps it. With its `bundled` feature,
//! SQLite itself is compiled into the program, so users need nothing extra.
//!
//! # Privacy
//!
//! Each `monitor` run writes one database under `runs/` (git-ignored). The
//! database holds raw identifiers (Steam IDs, IPs) because the live tool needs
//! them, so it stays on the user's PC. Only `export` output (pseudonymized,
//! /24-truncated, distance-rounded) is meant to be shared.
//!
//! # Tables
//!
//! | table       | one row per…                                   |
//! |-------------|------------------------------------------------|
//! | `meta`      | key/value fact about the run (version, label)  |
//! | `peer`      | Steam ID seen (name, first and last seen)      |
//! | `p2p_state` | *change* in a peer's Steam session state       |
//! | `rtt`       | RTT sample                                     |
//! | `geo`       | peer's estimated location                      |
//! | `event`     | notable happening (game restarted, peer left)  |
//! | `traffic`   | endpoint every 5 s (rates, gaps, jitter)       |
//! | `tcp_seg`   | steam.exe TCP segment to a peer (TCP fallback) |
//! | `tcp_estats`| TCP fallback connection stats per poll (TCP fallback)|

use crate::anon;
use crate::model::{P2PState, RttSample, SteamId};
use crate::stun::EndpointCounters;
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::net::Ipv4Addr;
use std::path::Path;

// The database layout, run once when the file is opened.
// `r#"..."#` is a *raw string literal*: backslashes and quotes inside need no
// escaping, which is handy for SQL. `IF NOT EXISTS` makes it safe to run on
// an existing file. `PRAGMA journal_mode = WAL` turns on write-ahead logging,
// which survives crashes well and lets readers work during writes.
const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peer (
    steam_id   INTEGER PRIMARY KEY,
    persona    TEXT,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS p2p_state (
    t_ns INTEGER NOT NULL,
    steam_id INTEGER NOT NULL,
    active INTEGER NOT NULL,
    connecting INTEGER NOT NULL,
    error INTEGER NOT NULL,
    using_relay INTEGER NOT NULL,
    bytes_queued INTEGER NOT NULL,
    packets_queued INTEGER NOT NULL,
    remote_ip TEXT,
    remote_port INTEGER
);
CREATE TABLE IF NOT EXISTS rtt (
    t_ns INTEGER NOT NULL,
    steam_id INTEGER,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    rtt_ms REAL NOT NULL,
    source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tcp_seg (
    t_ns INTEGER NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    send_start INTEGER,
    send_end INTEGER
);
CREATE TABLE IF NOT EXISTS tcp_estats (
    t_ns INTEGER NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    sample_rtt INTEGER NOT NULL,
    smoothed_rtt INTEGER NOT NULL,
    rtt_var INTEGER NOT NULL,
    min_rtt INTEGER NOT NULL,
    max_rtt INTEGER NOT NULL,
    sum_rtt INTEGER NOT NULL,
    count_rtt INTEGER NOT NULL,
    pkts_retrans INTEGER NOT NULL,
    timeouts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS geo (
    steam_id INTEGER NOT NULL,
    country TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    accuracy_km INTEGER,
    distance_km REAL,
    fiber_bound_ms REAL,
    subject TEXT NOT NULL DEFAULT 'peer',
    site TEXT,
    PRIMARY KEY (steam_id, subject)
);
CREATE TABLE IF NOT EXISTS event (
    t_ns INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS traffic (
    t_ns INTEGER NOT NULL,
    steam_id INTEGER,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    role TEXT NOT NULL,
    pps_in REAL NOT NULL,
    pps_out REAL NOT NULL,
    pkts_in INTEGER NOT NULL,
    pkts_out INTEGER NOT NULL,
    bytes_in INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    payload_in INTEGER,
    payload_out INTEGER,
    max_gap_in_ms REAL NOT NULL,
    jit_in_ms REAL,
    stream_in_size INTEGER,
    period_in_ms REAL,
    jit_out_ms REAL,
    stream_out_size INTEGER,
    period_out_ms REAL,
    stun_req INTEGER,
    stun_matched INTEGER,
    stun_lost INTEGER
);
CREATE INDEX IF NOT EXISTS traffic_by_ep ON traffic (remote_ip, remote_port, t_ns);
CREATE INDEX IF NOT EXISTS rtt_by_peer ON rtt (steam_id, t_ns);
CREATE INDEX IF NOT EXISTS state_by_peer ON p2p_state (steam_id, t_ns);
"#;

/// An open run database.
///
/// It owns one `rusqlite::Connection`. When the `Store` is dropped (goes out
/// of scope), the connection closes automatically. That's Rust's RAII
/// pattern, so there's no explicit `close()` to forget.
pub struct Store {
    conn: Connection,
}

/// Geographic fields stored for a peer.
// `GeoRow<'a>` has a *lifetime parameter*. Its `&'a str` fields borrow text
// that lives somewhere else (in the caller's `GeoInfo`) instead of copying it.
// The `'a` tells the compiler a `GeoRow` must not outlive the data it
// borrows. This struct is only used briefly to pass arguments, so borrowing
// avoids needless allocation.
pub struct GeoRow<'a> {
    pub country: Option<&'a str>,
    pub city: Option<&'a str>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub accuracy_km: Option<u16>,
    pub distance_km: Option<f64>,
    pub fiber_bound_ms: Option<f64>,
    /// Steam relay site code (e.g. "sea"), for a relay's row.
    pub site: Option<&'a str>,
}

/// Whose location a `geo` row describes. A relayed peer can have both: the
/// player's (when Steam reveals their address) and the relay server's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoSubject {
    Peer,
    Relay,
}

impl GeoSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            GeoSubject::Peer => "peer",
            GeoSubject::Relay => "relay",
        }
    }
}

/// One periodic traffic snapshot for one remote endpoint.
pub struct TrafficRow {
    pub t_ns: i128,
    pub steam_id: Option<SteamId>,
    pub remote: std::net::SocketAddrV4,
    /// "peer", "relay_stun", "relay_wrapped" or "game" (unattributed).
    pub role: &'static str,
    pub pps_in: f64,
    pub pps_out: f64,
    /// Running totals since the endpoint was first seen.
    pub pkts_in: u64,
    pub pkts_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Estimated game payload with relay headers removed (wrapped relay
    /// endpoints only).
    pub payload: Option<(u64, u64)>,
    pub max_gap_in_ms: f64,
    /// RFC 3550 jitter of the dominant packet size, in and out (`jitter.rs`).
    pub jit_in: Option<StreamStats>,
    pub jit_out: Option<StreamStats>,
    /// The STUN matcher's running counters for this endpoint.
    pub stun: EndpointCounters,
}

/// One direction's periodic stream: its jitter, packet size and period.
#[derive(Clone, Copy, Debug)]
pub struct StreamStats {
    pub jitter_ms: f64,
    pub size: u32,
    pub period_ms: f64,
}

impl Store {
    /// Open (or create) the database at `path` and make sure the tables exist.
    ///
    /// Steps: create the parent folder if needed → open the file → run the schema.
    /// `if let Some(dir) = path.parent()` only runs the block when the path
    /// actually has a parent folder.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening run database {}", path.display()))?;
        let old_geo = rename_old_geo(&conn)?;
        conn.execute_batch(SCHEMA)?;
        add_traffic_columns(&conn)?;
        add_tcp_seg_columns(&conn)?;
        if old_geo {
            conn.execute_batch(
                "INSERT INTO geo (steam_id, country, city, lat, lon, accuracy_km, distance_km, fiber_bound_ms)
                 SELECT steam_id, country, city, lat, lon, accuracy_km, distance_km, fiber_bound_ms FROM geo_v1;
                 DROP TABLE geo_v1;",
            )?;
        }
        Ok(Self { conn })
    }

    /// Store one key/value fact about the run.
    ///
    /// "Upsert" = insert, or update if the key already exists
    /// (`ON CONFLICT ... DO UPDATE`). `?1`, `?2` are *placeholders*: values are
    /// passed separately via `params![]`, never glued into the SQL text. This
    /// prevents SQL injection and quoting bugs. Always do it this way.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Record that a peer was seen at time `t_ns`.
    ///
    /// `COALESCE(excluded.persona, peer.persona)` keeps a previously known name
    /// if this time there is only `NULL` (Steam hadn't sent the name yet).
    /// SQLite stores integers as signed 64-bit, so `u64`/`i128` values are cast
    /// with `as i64`. Steam IDs and current timestamps fit comfortably.
    pub fn upsert_peer(&self, id: SteamId, persona: Option<&str>, t_ns: i128) -> Result<()> {
        let t = t_ns as i64;
        self.conn.execute(
            "INSERT INTO peer (steam_id, persona, first_seen_ns, last_seen_ns)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(steam_id) DO UPDATE SET
               last_seen_ns = excluded.last_seen_ns,
               persona = COALESCE(excluded.persona, peer.persona)",
            params![id.0 as i64, persona, t],
        )?;
        Ok(())
    }

    /// Append one `p2p_state` row. The monitor only calls this when the state
    /// actually changed, which keeps the file small.
    ///
    /// `s.remote.map(|a| a.ip().to_string())` turns `Option<SocketAddrV4>` into
    /// `Option<String>`. rusqlite stores `None` as SQL `NULL`.
    pub fn insert_state(&self, t_ns: i128, id: SteamId, s: &P2PState) -> Result<()> {
        self.conn.execute(
            "INSERT INTO p2p_state VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                t_ns as i64,
                id.0 as i64,
                s.active,
                s.connecting,
                s.error,
                s.using_relay,
                s.bytes_queued,
                s.packets_queued,
                s.remote.map(|a| a.ip().to_string()),
                s.remote.map(|a| a.port()),
            ],
        )?;
        Ok(())
    }

    /// Append one RTT sample. `id` is `Option` because ETW can time a packet to an
    /// endpoint that Steam hasn't (yet) reported as belonging to a peer.
    /// Log one steam.exe TCP event to a peer endpoint (TCP fallback
    /// only): kind is "send", "recv", "copy" or "retx", plus a send event's
    /// raw `startime`/`endtime` fields. Lets a capture check the kernel's
    /// event granularity and timing event by event.
    pub fn insert_tcp_seg(
        &self,
        t_ns: i128,
        remote: std::net::SocketAddrV4,
        kind: &str,
        size: u32,
        send_times: Option<(u32, u32)>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO tcp_seg (t_ns, remote_ip, remote_port, kind, size, send_start, send_end)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                t_ns as i64,
                remote.ip().to_string(),
                remote.port(),
                kind,
                size,
                send_times.map(|s| s.0),
                send_times.map(|s| s.1),
            ],
        )?;
        Ok(())
    }

    /// One reading of Windows' TCP statistics for a fallback connection
    /// (TCP fallback), in milliseconds and running counters, as read.
    #[cfg(windows)]
    pub fn insert_tcp_estats(
        &self,
        t_ns: i128,
        remote: std::net::SocketAddrV4,
        s: &crate::estats::PathStats,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO tcp_estats VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                t_ns as i64,
                remote.ip().to_string(),
                remote.port(),
                s.sample_rtt,
                s.smoothed_rtt,
                s.rtt_var,
                s.min_rtt,
                s.max_rtt,
                s.sum_rtt,
                s.count_rtt,
                s.pkts_retrans,
                s.timeouts,
            ],
        )?;
        Ok(())
    }

    pub fn insert_rtt(
        &self,
        id: Option<SteamId>,
        remote: std::net::SocketAddrV4,
        s: &RttSample,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO rtt VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                s.t_ns as i64,
                id.map(|i| i.0 as i64),
                remote.ip().to_string(),
                remote.port(),
                s.rtt_ms,
                s.source.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Store (or replace) a location estimate for a peer or its relay.
    pub fn upsert_geo(&self, id: SteamId, subject: GeoSubject, g: &GeoRow<'_>) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO geo (steam_id, country, city, lat, lon, accuracy_km,
                 distance_km, fiber_bound_ms, subject, site)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                id.0 as i64,
                g.country,
                g.city,
                g.lat,
                g.lon,
                g.accuracy_km,
                g.distance_km,
                g.fiber_bound_ms,
                subject.as_str(),
                g.site,
            ],
        )?;
        Ok(())
    }

    /// Remove a location row (used when an address first taken for the
    /// player turns out to be a relay).
    pub fn delete_geo(&self, id: SteamId, subject: GeoSubject) -> Result<()> {
        self.conn.execute(
            "DELETE FROM geo WHERE steam_id = ?1 AND subject = ?2",
            params![id.0 as i64, subject.as_str()],
        )?;
        Ok(())
    }

    /// The raw connection, so other modules' tests can check what was logged.
    #[cfg(test)]
    pub fn conn_for_tests(&self) -> &Connection {
        &self.conn
    }

    /// Append one traffic snapshot.
    pub fn insert_traffic(&self, r: &TrafficRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO traffic (t_ns, steam_id, remote_ip, remote_port, role, pps_in, pps_out,
                 pkts_in, pkts_out, bytes_in, bytes_out, payload_in, payload_out, max_gap_in_ms,
                 jit_in_ms, stream_in_size, period_in_ms, jit_out_ms, stream_out_size, period_out_ms,
                 stun_req, stun_matched, stun_lost)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
            params![
                r.t_ns as i64,
                r.steam_id.map(|i| i.0 as i64),
                r.remote.ip().to_string(),
                r.remote.port(),
                r.role,
                r.pps_in,
                r.pps_out,
                r.pkts_in as i64,
                r.pkts_out as i64,
                r.bytes_in as i64,
                r.bytes_out as i64,
                r.payload.map(|p| p.0 as i64),
                r.payload.map(|p| p.1 as i64),
                r.max_gap_in_ms,
                r.jit_in.map(|j| j.jitter_ms),
                r.jit_in.map(|j| j.size),
                r.jit_in.map(|j| j.period_ms),
                r.jit_out.map(|j| j.jitter_ms),
                r.jit_out.map(|j| j.size),
                r.jit_out.map(|j| j.period_ms),
                r.stun.requests as i64,
                r.stun.matched as i64,
                r.stun.lost_requests as i64,
            ],
        )?;
        Ok(())
    }

    /// Append a free-form event (e.g. "game_pid", "peer_left", "stop").
    pub fn event(&self, t_ns: i128, kind: &str, detail: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO event VALUES (?1, ?2, ?3)",
            params![t_ns as i64, kind, detail],
        )?;
        Ok(())
    }

    /// Write anonymized CSVs (`rtt.csv`, `state.csv`, `peers.csv`,
    /// `traffic.csv`) into `out_dir`.
    // Export works the same way for every file:
    //   1. create a CSV writer and write the header row;
    //   2. `prepare` a SELECT, then loop over the rows with `while let Some(r)`;
    //   3. replace identifiers (pseudonym, /24 network) before writing each row;
    //   4. `flush()` so everything reaches the disk.
    // `r.get::<_, i64>(2)?` reads column 2 as an `i64`. The `_` lets the compiler
    // infer the index type.
    pub fn export_anonymized(&self, out_dir: &Path, salt: &str, run_label: &str) -> Result<()> {
        std::fs::create_dir_all(out_dir)?;

        let mut w = csv::Writer::from_path(out_dir.join("rtt.csv"))?;
        w.write_record(["run", "t_ns", "peer", "remote_net", "rtt_ms", "source"])?;
        let mut q = self
            .conn
            .prepare("SELECT t_ns, steam_id, remote_ip, rtt_ms, source FROM rtt ORDER BY t_ns")?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            let t: i64 = r.get(0)?;
            let sid: Option<i64> = r.get(1)?;
            let ip: String = r.get(2)?;
            let rtt: f64 = r.get(3)?;
            let src: String = r.get(4)?;
            w.write_record([
                run_label.to_string(),
                t.to_string(),
                sid.map(|s| anon::pseudonym(salt, s as u64))
                    .unwrap_or_default(),
                net_of(&ip),
                format!("{rtt:.3}"),
                src,
            ])?;
        }
        w.flush()?;

        let mut w = csv::Writer::from_path(out_dir.join("state.csv"))?;
        w.write_record([
            "run",
            "t_ns",
            "peer",
            "active",
            "connecting",
            "error",
            "using_relay",
            "remote_net",
        ])?;
        let mut q = self.conn.prepare(
            "SELECT t_ns, steam_id, active, connecting, error, using_relay, remote_ip
             FROM p2p_state ORDER BY t_ns",
        )?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            let t: i64 = r.get(0)?;
            let sid: i64 = r.get(1)?;
            let ip: Option<String> = r.get(6)?;
            w.write_record([
                run_label.to_string(),
                t.to_string(),
                anon::pseudonym(salt, sid as u64),
                r.get::<_, i64>(2)?.to_string(),
                r.get::<_, i64>(3)?.to_string(),
                r.get::<_, i64>(4)?.to_string(),
                r.get::<_, i64>(5)?.to_string(),
                ip.as_deref().map(net_of).unwrap_or_default(),
            ])?;
        }
        w.flush()?;

        // Location is coarsened to country plus distance rounded to 50 km.
        // The relay's site and country aren't personal (they're Valve's), so
        // they're exported as-is next to the player's coarsened location.
        let mut w = csv::Writer::from_path(out_dir.join("peers.csv"))?;
        w.write_record([
            "run",
            "peer",
            "country",
            "distance_km_50",
            "fiber_bound_ms",
            "first_seen_ns",
            "last_seen_ns",
            "relay_site",
            "relay_country",
        ])?;
        let mut q = self.conn.prepare(
            "SELECT p.steam_id, g.country, g.distance_km, g.fiber_bound_ms,
                    p.first_seen_ns, p.last_seen_ns, r.site, r.country
             FROM peer p
             LEFT JOIN geo g ON g.steam_id = p.steam_id AND g.subject = 'peer'
             LEFT JOIN geo r ON r.steam_id = p.steam_id AND r.subject = 'relay'",
        )?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            let sid: i64 = r.get(0)?;
            let country: Option<String> = r.get(1)?;
            let dist: Option<f64> = r.get(2)?;
            let bound: Option<f64> = r.get(3)?;
            let site: Option<String> = r.get(6)?;
            let rcountry: Option<String> = r.get(7)?;
            w.write_record([
                run_label.to_string(),
                anon::pseudonym(salt, sid as u64),
                country.unwrap_or_default(),
                dist.map(|d| format!("{:.0}", (d / 50.0).round() * 50.0))
                    .unwrap_or_default(),
                bound.map(|b| format!("{b:.2}")).unwrap_or_default(),
                r.get::<_, i64>(4)?.to_string(),
                r.get::<_, i64>(5)?.to_string(),
                site.unwrap_or_default(),
                rcountry.unwrap_or_default(),
            ])?;
        }
        w.flush()?;

        let mut w = csv::Writer::from_path(out_dir.join("traffic.csv"))?;
        w.write_record([
            "run",
            "t_ns",
            "peer",
            "remote_net",
            "role",
            "pps_in",
            "pps_out",
            "pkts_in",
            "pkts_out",
            "bytes_in",
            "bytes_out",
            "payload_in",
            "payload_out",
            "max_gap_in_ms",
            "jit_in_ms",
            "stream_in_size",
            "period_in_ms",
            "jit_out_ms",
            "stream_out_size",
            "period_out_ms",
            "stun_req",
            "stun_matched",
            "stun_lost",
        ])?;
        let mut q = self.conn.prepare(
            "SELECT t_ns, steam_id, remote_ip, role, pps_in, pps_out, pkts_in, pkts_out,
                    bytes_in, bytes_out, payload_in, payload_out, max_gap_in_ms,
                    jit_in_ms, stream_in_size, period_in_ms, jit_out_ms, stream_out_size, period_out_ms,
                    stun_req, stun_matched, stun_lost
             FROM traffic ORDER BY t_ns",
        )?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            let sid: Option<i64> = r.get(1)?;
            let ip: String = r.get(2)?;
            let opt_i = |v: Option<i64>| v.map(|x| x.to_string()).unwrap_or_default();
            let opt_f = |v: Option<f64>| v.map(|x| format!("{x:.3}")).unwrap_or_default();
            w.write_record([
                run_label.to_string(),
                r.get::<_, i64>(0)?.to_string(),
                sid.map(|s| anon::pseudonym(salt, s as u64))
                    .unwrap_or_default(),
                net_of(&ip),
                r.get::<_, String>(3)?,
                format!("{:.2}", r.get::<_, f64>(4)?),
                format!("{:.2}", r.get::<_, f64>(5)?),
                r.get::<_, i64>(6)?.to_string(),
                r.get::<_, i64>(7)?.to_string(),
                r.get::<_, i64>(8)?.to_string(),
                r.get::<_, i64>(9)?.to_string(),
                opt_i(r.get(10)?),
                opt_i(r.get(11)?),
                format!("{:.1}", r.get::<_, f64>(12)?),
                opt_f(r.get(13)?),
                opt_i(r.get(14)?),
                opt_f(r.get(15)?),
                opt_f(r.get(16)?),
                opt_i(r.get(17)?),
                opt_f(r.get(18)?),
                opt_i(r.get(19)?),
                opt_i(r.get(20)?),
                opt_i(r.get(21)?),
            ])?;
        }
        w.flush()?;
        Ok(())
    }
}

/// Run databases from before relay geo (tool 0.1.0 up to E2) have a `geo`
/// table keyed by Steam ID alone. If this is one, rename it to `geo_v1` so
/// the schema can create the new table; `open` then copies the old rows in
/// as `subject = 'peer'`. Returns whether it renamed anything.
fn rename_old_geo(conn: &Connection) -> Result<bool> {
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('geo')")?
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    if cols.is_empty() || cols.iter().any(|c| c == "subject") {
        return Ok(false);
    }
    conn.execute_batch("ALTER TABLE geo RENAME TO geo_v1;")?;
    Ok(true)
}

/// Run databases from before stream jitter (or the STUN counters) have a
/// `traffic` table without those columns; add them (NULL for old rows).
/// `tcp_seg` gained the send-timing columns after the first TCP-fallback runs.
fn add_tcp_seg_columns(conn: &Connection) -> Result<()> {
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('tcp_seg')")?
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    for name in ["send_start", "send_end"] {
        if !cols.iter().any(|c| c == name) {
            conn.execute_batch(&format!("ALTER TABLE tcp_seg ADD COLUMN {name} INTEGER;"))?;
        }
    }
    Ok(())
}

fn add_traffic_columns(conn: &Connection) -> Result<()> {
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('traffic')")?
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    for (name, ty) in [
        ("jit_in_ms", "REAL"),
        ("stream_in_size", "INTEGER"),
        ("period_in_ms", "REAL"),
        ("jit_out_ms", "REAL"),
        ("stream_out_size", "INTEGER"),
        ("period_out_ms", "REAL"),
        ("stun_req", "INTEGER"),
        ("stun_matched", "INTEGER"),
        ("stun_lost", "INTEGER"),
    ] {
        if !cols.iter().any(|c| c == name) {
            conn.execute_batch(&format!("ALTER TABLE traffic ADD COLUMN {name} {ty};"))?;
        }
    }
    Ok(())
}

/// Convert a stored IP string into its /24 network, or "?" if it doesn't parse.
/// `.parse::<Ipv4Addr>()` uses the standard library's `FromStr` for addresses.
fn net_of(ip: &str) -> String {
    ip.parse::<Ipv4Addr>()
        .map(anon::ip_prefix24)
        .unwrap_or_else(|_| "?".into())
}

// ---------------------------------------------------------------------------
// Unit test: privacy guarantees deserve tests too. Build a tiny database with
// a known Steam ID, IP and name, export it, and check none of them leak.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RttSource;
    use std::net::SocketAddrV4;

    #[test]
    fn roundtrip_and_export_hides_identifiers() {
        let dir = std::env::temp_dir().join(format!("ds3sm-test-{}", std::process::id()));
        let db = dir.join("run.sqlite");
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::open(&db).unwrap();
        let id = SteamId(76561198000000001);
        let remote = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 50000);
        s.upsert_peer(id, Some("Solaire"), 1).unwrap();
        s.insert_state(
            2,
            id,
            &P2PState {
                active: true,
                connecting: false,
                error: 0,
                using_relay: false,
                bytes_queued: 0,
                packets_queued: 0,
                remote: Some(remote),
            },
        )
        .unwrap();
        s.insert_rtt(
            Some(id),
            remote,
            &RttSample {
                t_ns: 3,
                rtt_ms: 41.5,
                source: RttSource::EtwStun,
            },
        )
        .unwrap();
        let relay = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 148), 4380);
        s.insert_traffic(&TrafficRow {
            t_ns: 4,
            steam_id: Some(id),
            remote: relay,
            role: "relay_wrapped",
            pps_in: 18.0,
            pps_out: 2.0,
            pkts_in: 10,
            pkts_out: 2,
            bytes_in: 1290,
            bytes_out: 264,
            payload: Some((850, 136)),
            max_gap_in_ms: 120.0,
            jit_in: Some(StreamStats {
                jitter_ms: 2.6789,
                size: 129,
                period_ms: 83.333,
            }),
            jit_out: None,
            stun: EndpointCounters {
                requests: 12,
                matched: 11,
                lost_requests: 1,
                ..Default::default()
            },
        })
        .unwrap();
        let geo = |site| GeoRow {
            country: Some("US"),
            city: Some("Seattle"),
            lat: Some(47.6),
            lon: Some(-122.3),
            accuracy_km: None,
            distance_km: None,
            fiber_bound_ms: None,
            site,
        };
        s.upsert_geo(id, GeoSubject::Peer, &geo(None)).unwrap();
        s.upsert_geo(id, GeoSubject::Relay, &geo(Some("sea")))
            .unwrap();
        let out = dir.join("export");
        s.export_anonymized(&out, "salt", "r1").unwrap();
        let all = ["rtt.csv", "state.csv", "peers.csv", "traffic.csv"]
            .iter()
            .map(|f| std::fs::read_to_string(out.join(f)).unwrap())
            .collect::<String>();
        assert!(all.contains("203.0.113.0/24"));
        assert!(all.contains("41.500"));
        assert!(!all.contains("203.0.113.9"));
        assert!(!all.contains("76561198000000001"));
        assert!(!all.contains("Solaire"));
        // Traffic rows: /24 only, with the payload estimate.
        assert!(all.contains("198.51.100.0/24,relay_wrapped"));
        assert!(!all.contains("198.51.100.148"));
        assert!(all.contains(",850,136,"));
        assert!(all.contains(",2.679,129,83.333,,,,12,11,1"));
        // Peer and relay rows both kept; one peers.csv line carries both.
        let peers = std::fs::read_to_string(out.join("peers.csv")).unwrap();
        assert_eq!(peers.lines().count(), 2);
        assert!(peers.contains(",sea,US"));
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A run file from before relay geo opens, keeps its peer location, and
    /// can then store a relay location as well.
    #[test]
    fn old_geo_table_is_migrated() {
        let dir = std::env::temp_dir().join(format!("ds3sm-mig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("old.sqlite");
        {
            let c = Connection::open(&db).unwrap();
            c.execute_batch(
                "CREATE TABLE geo (steam_id INTEGER PRIMARY KEY, country TEXT, city TEXT,
                   lat REAL, lon REAL, accuracy_km INTEGER, distance_km REAL, fiber_bound_ms REAL);
                 INSERT INTO geo VALUES (7, 'CA', 'X', 1.0, 2.0, 5, 10.0, 0.1);",
            )
            .unwrap();
        }
        let s = Store::open(&db).unwrap();
        s.upsert_geo(
            SteamId(7),
            GeoSubject::Relay,
            &GeoRow {
                country: Some("US"),
                city: None,
                lat: None,
                lon: None,
                accuracy_km: None,
                distance_km: None,
                fiber_bound_ms: None,
                site: Some("sea"),
            },
        )
        .unwrap();
        let rows: Vec<(String, String)> = s
            .conn
            .prepare("SELECT subject, country FROM geo ORDER BY subject")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![("peer".into(), "CA".into()), ("relay".into(), "US".into())]
        );
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A run file from the first TCP-fallback builds gains the send-timing
    /// columns and accepts rows with and without them.
    #[test]
    fn old_tcp_seg_table_gains_send_times() {
        let dir = std::env::temp_dir().join(format!("ds3sm-mig-tcp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("old.sqlite");
        {
            let c = Connection::open(&db).unwrap();
            c.execute_batch(
                "CREATE TABLE tcp_seg (t_ns INTEGER NOT NULL, remote_ip TEXT NOT NULL,
                   remote_port INTEGER NOT NULL, kind TEXT NOT NULL, size INTEGER NOT NULL);
                 INSERT INTO tcp_seg VALUES (1, '192.0.2.15', 49202, 'send', 99);",
            )
            .unwrap();
        }
        let s = Store::open(&db).unwrap();
        let ep = std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(192, 0, 2, 15), 49202);
        s.insert_tcp_seg(2, ep, "send", 58, Some((10, 12))).unwrap();
        s.insert_tcp_seg(3, ep, "recv", 70, None).unwrap();
        let rows: Vec<(i64, Option<i64>, Option<i64>)> = s
            .conn
            .prepare("SELECT t_ns, send_start, send_end FROM tcp_seg ORDER BY t_ns")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![(1, None, None), (2, Some(10), Some(12)), (3, None, None)]
        );
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A run file from before stream jitter gains the jitter columns, keeps
    /// its rows (jitter NULL), and accepts new rows with jitter.
    #[test]
    fn old_traffic_table_gains_jitter_columns() {
        let dir = std::env::temp_dir().join(format!("ds3sm-mig-jit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("old.sqlite");
        {
            let c = Connection::open(&db).unwrap();
            c.execute_batch(
                "CREATE TABLE traffic (t_ns INTEGER NOT NULL, steam_id INTEGER,
                   remote_ip TEXT NOT NULL, remote_port INTEGER NOT NULL, role TEXT NOT NULL,
                   pps_in REAL NOT NULL, pps_out REAL NOT NULL, pkts_in INTEGER NOT NULL,
                   pkts_out INTEGER NOT NULL, bytes_in INTEGER NOT NULL, bytes_out INTEGER NOT NULL,
                   payload_in INTEGER, payload_out INTEGER, max_gap_in_ms REAL NOT NULL);
                 INSERT INTO traffic VALUES (1, 7, '192.0.2.1', 1, 'peer', 19.0, 37.0,
                   1, 1, 85, 97, NULL, NULL, 90.0);",
            )
            .unwrap();
        }
        let s = Store::open(&db).unwrap();
        let stream = |j| StreamStats {
            jitter_ms: j,
            size: 85,
            period_ms: 83.3,
        };
        s.insert_traffic(&TrafficRow {
            t_ns: 2,
            steam_id: Some(SteamId(7)),
            remote: std::net::SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 1),
            role: "peer",
            pps_in: 19.0,
            pps_out: 37.0,
            pkts_in: 2,
            pkts_out: 2,
            bytes_in: 170,
            bytes_out: 194,
            payload: None,
            max_gap_in_ms: 90.0,
            jit_in: Some(stream(0.4)),
            jit_out: Some(stream(0.1)),
            stun: EndpointCounters::default(),
        })
        .unwrap();
        let rows: Vec<(i64, Option<f64>, Option<f64>)> = s
            .conn
            .prepare("SELECT t_ns, jit_in_ms, jit_out_ms FROM traffic ORDER BY t_ns")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(rows, vec![(1, None, None), (2, Some(0.4), Some(0.1))]);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
